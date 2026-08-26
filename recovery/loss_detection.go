// Package recovery implements QUIC loss detection and congestion control
// per RFC 9002 (QUIC Loss Detection and Congestion Control).
//
// This file implements the loss detection portion (RFC 9002 §5-6):
//   - RTT estimation (latest_rtt, smoothed_rtt, rttvar, min_rtt) (§5)
//   - Probe Timeout (PTO) calculation and backoff (§6.2)
//   - Loss detection algorithms: packet threshold and time threshold (§6.1)
//   - Multi-modal loss detection timer (§6.2)
package recovery

import (
	"math"
	"sort"
	"sync"
	"time"
)

// PacketNumberSpace represents a QUIC packet number space (RFC 9002 §2).
type PacketNumberSpace int

const (
	PNSInitial PacketNumberSpace = iota
	PNSHandshake
	PNSApplicationData
)

// String returns the name of the packet number space.
func (pns PacketNumberSpace) String() string {
	switch pns {
	case PNSInitial:
		return "Initial"
	case PNSHandshake:
		return "Handshake"
	case PNSApplicationData:
		return "ApplicationData"
	default:
		return "Unknown"
	}
}

// Constants (RFC 9002 Appendix A.2, B.1).
const (
	// kPacketThreshold is the maximum reordering in packets before a
	// packet is declared lost (§6.1.1). RECOMMENDED value: 3.
	kPacketThreshold = 3

	// kTimeThreshold is the RTT multiplier used for the time threshold
	// (§6.1.2). RECOMMENDED value: 9/8.
	kTimeThreshold = 9.0 / 8.0

	// kGranularity is the timer granularity (§6.1.2). RECOMMENDED: 1 ms.
	kGranularity = 1 * time.Millisecond

	// kInitialRtt is the initial RTT estimate used before any samples
	// (§6.2.2). RECOMMENDED: 333 ms. Results in a starting PTO of 1 second.
	kInitialRtt = 333 * time.Millisecond

	// kLossReductionFactor is the congestion window reduction factor on loss
	// (§7.3.2). RECOMMENDED: 0.5.
	kLossReductionFactor = 0.5

	// kPersistentCongestionThreshold is the PTO multiplier for persistent
	// congestion (§7.6). RECOMMENDED: 3.
	kPersistentCongestionThreshold = 3

	// kInitialWindow multiplier for the initial congestion window (§7.2).
	kInitialWindowMultiplier = 10

	// kMinimumWindow multiplier for the minimum congestion window (§7.2).
	kMinimumWindowMultiplier = 2

	// kMaxDatagramSize is the default maximum datagram size (§7.2).
	// QUIC requires a minimum of 1200 bytes.
	kMaxDatagramSize = 1200
)

// SentPacket tracks a sent packet for loss detection and congestion control
// (RFC 9002 Appendix A.1.1).
type SentPacket struct {
	PacketNumber uint64
	TimeSent    time.Time
	AckEliciting bool
	InFlight     bool
	SentBytes    int
	PNSpace      PacketNumberSpace
}

// RTTStats holds RTT estimation state (RFC 9002 §5).
type RTTStats struct {
	// latest_rtt: most recent RTT measurement from an ACK
	LatestRTT time.Duration

	// smoothed_rtt: exponentially weighted moving average of RTT
	SmoothedRTT time.Duration

	// rttvar: mean deviation in RTT
	RTTVar time.Duration

	// min_rtt: minimum RTT observed over time, ignoring ack delay
	MinRTT time.Duration

	// first_rtt_sample: time of first RTT sample (0 = no samples yet)
	FirstRTTSample time.Time

	// max_ack_delay: peer's max acknowledgment delay (transport parameter)
	MaxAckDelay time.Duration

	// handshake_confirmed: whether the handshake has been confirmed
	handshakeConfirmed bool
}

// NewRTTStats creates a new RTTStats with initial values (RFC 9002 §5.3, Appendix A.4).
func NewRTTStats(maxAckDelay time.Duration) *RTTStats {
	return &RTTStats{
		LatestRTT:     0,
		SmoothedRTT:    kInitialRtt,
		RTTVar:         kInitialRtt / 2,
		MinRTT:         0,
		MaxAckDelay:    maxAckDelay,
	}
}

// SetHandshakeConfirmed updates whether the handshake is confirmed,
// which affects ack_delay handling (RFC 9002 §5.3).
func (r *RTTStats) SetHandshakeConfirmed(confirmed bool) {
	r.handshakeConfirmed = confirmed
}

// HasSamples returns true if at least one RTT sample has been received.
func (r *RTTStats) HasSamples() bool {
	return !r.FirstRTTSample.IsZero()
}

// UpdateRTT updates RTT estimates based on a new sample (RFC 9002 §5.3, Appendix A.7).
//
// Parameters:
//   - ackDelay: the acknowledgment delay reported by the peer in the ACK frame
//   - sendTime: the time the largest acknowledged packet was sent
//   - now: the current time
func (r *RTTStats) UpdateRTT(ackDelay time.Duration, sendTime time.Time, now time.Time) {
	r.LatestRTT = now.Sub(sendTime)
	if r.LatestRTT < 0 {
		r.LatestRTT = 0
	}

	// First RTT sample (RFC 9002 §5.3, Appendix A.7)
	if r.FirstRTTSample.IsZero() {
		r.MinRTT = r.LatestRTT
		r.SmoothedRTT = r.LatestRTT
		r.RTTVar = r.LatestRTT / 2
		r.FirstRTTSample = now
		return
	}

	// min_rtt ignores acknowledgment delay
	if r.LatestRTT < r.MinRTT {
		r.MinRTT = r.LatestRTT
	}

	// Limit ack_delay by max_ack_delay after handshake confirmation
	if r.handshakeConfirmed {
		if ackDelay > r.MaxAckDelay {
			ackDelay = r.MaxAckDelay
		}
	}

	// Adjust for acknowledgment delay if plausible
	adjustedRTT := r.LatestRTT
	if r.LatestRTT > r.MinRTT+ackDelay {
		adjustedRTT = r.LatestRTT - ackDelay
	}

	// EWMA update (RFC 9002 §5.3)
	r.RTTVar = (3*r.RTTVar + absDur(r.SmoothedRTT-adjustedRTT)) / 4
	r.SmoothedRTT = (7*r.SmoothedRTT + adjustedRTT) / 8
}

// PTO returns the probe timeout duration (RFC 9002 §6.2.1).
//
//   PTO = smoothed_rtt + max(4*rttvar, kGranularity) + max_ack_delay
//
// For Initial and Handshake spaces, max_ack_delay is 0.
func (r *RTTStats) PTO() time.Duration {
	pto := r.SmoothedRTT + maxDur(4*r.RTTVar, kGranularity)
	if r.handshakeConfirmed {
		pto += r.MaxAckDelay
	}
	if pto < kGranularity {
		pto = kGranularity
	}
	return pto
}

// absDur returns the absolute value of a duration.
func absDur(d time.Duration) time.Duration {
	if d < 0 {
		return -d
	}
	return d
}

// maxDur returns the larger of two durations.
func maxDur(a, b time.Duration) time.Duration {
	if a > b {
		return a
	}
	return b
}

// LossDetection manages loss detection state (RFC 9002 §6).
type LossDetection struct {
	mu sync.Mutex

	rtt *RTTStats

	// Per-space state
	sentPackets              [3]map[uint64]*SentPacket // PNSpace -> SentPacket
	largestAcked             [3]uint64                   // PNSpace -> largest acked PN
	lossTime                 [3]time.Time                // PNSpace -> time when next loss can be detected
	timeOfLastAckEliciting   [3]time.Time                // PNSpace -> time of last ack-eliciting packet

	// PTO state
	ptoCount    int
	lossDetectionTimer time.Time // When the timer should fire
	isClient     bool
	peerCompletedAddrValidation bool

	// Callback for sending probe packets
	onProbeNeeded func(pns PacketNumberSpace)

	// Callback for packets declared lost
	onPacketsLost func([]*SentPacket)

	// Congestion controller
	congestion *CongestionController

	// Whether we have handshake keys
	hasHandshakeKeys bool
}

// NewLossDetection creates a new LossDetection instance.
func NewLossDetection(maxAckDelay time.Duration, isClient bool) *LossDetection {
	ld := &LossDetection{
		rtt:      NewRTTStats(maxAckDelay),
		isClient: isClient,
	}
	for i := range ld.sentPackets {
		ld.sentPackets[i] = make(map[uint64]*SentPacket)
		ld.largestAcked[i] = math.MaxUint64
	}
	ld.congestion = NewCongestionController()
	return ld
}

// SetCongestionController sets a custom congestion controller.
func (ld *LossDetection) SetCongestionController(cc *CongestionController) {
	ld.mu.Lock()
	defer ld.mu.Unlock()
	ld.congestion = cc
}

// CongestionController returns the congestion controller.
func (ld *LossDetection) CongestionController() *CongestionController {
	ld.mu.Lock()
	defer ld.mu.Unlock()
	return ld.congestion
}

// RTTStats returns the RTT statistics.
func (ld *LossDetection) RTTStats() *RTTStats {
	return ld.rtt
}

// OnPacketSent records a sent packet (RFC 9002 Appendix A.5).
func (ld *LossDetection) OnPacketSent(p *SentPacket, now time.Time) {
	ld.mu.Lock()
	defer ld.mu.Unlock()

	p.TimeSent = now
	ld.sentPackets[p.PNSpace][p.PacketNumber] = p

	if p.InFlight {
		if p.AckEliciting {
			ld.timeOfLastAckEliciting[p.PNSpace] = now
		}
		ld.congestion.OnPacketSentCC(p.SentBytes)
	}

	ld.setLossDetectionTimer(now)
}

// OnAckReceived processes a received ACK frame (RFC 9002 Appendix A.7).
//
// Parameters:
//   - pnSpace: the packet number space of the ACK
//   - ackedPackets: list of newly acknowledged packet numbers
//   - largestAcked: the largest acknowledged packet number
//   - ackDelay: the acknowledgment delay reported by the peer
//   - now: the current time
func (ld *LossDetection) OnAckReceived(pnSpace PacketNumberSpace, ackedPNs []uint64, largestAcked uint64, ackDelay time.Duration, now time.Time) {
	ld.mu.Lock()
	defer ld.mu.Unlock()

	spaceIdx := int(pnSpace)

	// Update largest acknowledged
	if ld.largestAcked[spaceIdx] == math.MaxUint64 {
		ld.largestAcked[spaceIdx] = largestAcked
	} else if largestAcked > ld.largestAcked[spaceIdx] {
		ld.largestAcked[spaceIdx] = largestAcked
	}

	// Collect newly acked packets
	var newlyAcked []*SentPacket
	for _, pn := range ackedPNs {
		p, ok := ld.sentPackets[spaceIdx][pn]
		if !ok {
			continue
		}
		newlyAcked = append(newlyAcked, p)
		delete(ld.sentPackets[spaceIdx], pn)
	}

	if len(newlyAcked) == 0 {
		return
	}

	// Update RTT if the largest acknowledged is newly acked and
	// at least one ack-eliciting packet was newly acked
	var largestAckedPacket *SentPacket
	for _, p := range newlyAcked {
		if p.PacketNumber == largestAcked && largestAckedPacket == nil {
			largestAckedPacket = p
		}
		if p.PacketNumber == largestAcked {
			largestAckedPacket = p
		}
	}

	// Find the acked packet with the largest PN
	for _, p := range newlyAcked {
		if largestAckedPacket == nil || p.PacketNumber > largestAckedPacket.PacketNumber {
			largestAckedPacket = p
		}
	}

	hasAckEliciting := false
	for _, p := range newlyAcked {
		if p.AckEliciting {
			hasAckEliciting = true
			break
		}
	}

	if largestAckedPacket != nil && largestAckedPacket.PacketNumber == largestAcked && hasAckEliciting {
		ld.rtt.UpdateRTT(ackDelay, largestAckedPacket.TimeSent, now)
	}

	// Detect and remove lost packets
	lostPackets := ld.detectAndRemoveLostPackets(pnSpace, now)
	if len(lostPackets) > 0 && ld.onPacketsLost != nil {
		ld.onPacketsLost(lostPackets)
	}
	ld.congestion.OnPacketsLost(lostPackets)

	// Process congestion control acknowledgments
	ld.congestion.OnPacketsAcked(newlyAcked)

	// Reset pto_count unless the client is unsure if the server has
	// validated the client's address
	if ld.peerCompletedAddressValidation() {
		ld.ptoCount = 0
	}

	ld.setLossDetectionTimer(now)
}

// detectAndRemoveLostPackets identifies and removes lost packets (RFC 9002 Appendix A.10).
func (ld *LossDetection) detectAndRemoveLostPackets(pnSpace PacketNumberSpace, now time.Time) []*SentPacket {
	spaceIdx := int(pnSpace)

	if ld.largestAcked[spaceIdx] == math.MaxUint64 {
		return nil
	}

	ld.lossTime[spaceIdx] = time.Time{}

	lossDelay := time.Duration(kTimeThreshold * float64(maxDur(ld.rtt.LatestRTT, ld.rtt.SmoothedRTT)))
	if lossDelay < kGranularity {
		lossDelay = kGranularity
	}

	lostSendTime := now.Add(-lossDelay)

	var lostPackets []*SentPacket

	// Collect unacked packets sorted by packet number
	var unacked []*SentPacket
	for _, p := range ld.sentPackets[spaceIdx] {
		if p.PacketNumber <= ld.largestAcked[spaceIdx] {
			unacked = append(unacked, p)
		}
	}
	sort.Slice(unacked, func(i, j int) bool {
		return unacked[i].PacketNumber < unacked[j].PacketNumber
	})

	for _, p := range unacked {
		if p.PacketNumber > ld.largestAcked[spaceIdx] {
			continue
		}

		// Mark as lost if sent before lost_send_time, or
		// if >= kPacketThreshold packets have been acknowledged after it
		if p.TimeSent.Before(lostSendTime) || p.TimeSent.Equal(lostSendTime) ||
			ld.largestAcked[spaceIdx] >= p.PacketNumber+kPacketThreshold {
			delete(ld.sentPackets[spaceIdx], p.PacketNumber)
			lostPackets = append(lostPackets, p)
		} else {
			// Set the loss time for this packet
			expectedLossTime := p.TimeSent.Add(lossDelay)
			if ld.lossTime[spaceIdx].IsZero() || expectedLossTime.Before(ld.lossTime[spaceIdx]) {
				ld.lossTime[spaceIdx] = expectedLossTime
			}
		}
	}

	return lostPackets
}

// OnLossDetectionTimeout handles the loss detection timer firing (RFC 9002 Appendix A.9).
func (ld *LossDetection) OnLossDetectionTimeout(now time.Time) {
	ld.mu.Lock()
	defer ld.mu.Unlock()

	// Check for time-threshold loss detection first
	earliestLossTime, pnSpace := ld.getLossTimeAndSpace()
	if !earliestLossTime.IsZero() {
		lostPackets := ld.detectAndRemoveLostPackets(pnSpace, now)
		if len(lostPackets) > 0 && ld.onPacketsLost != nil {
			ld.onPacketsLost(lostPackets)
		}
		ld.congestion.OnPacketsLost(lostPackets)
		ld.setLossDetectionTimer(now)
		return
	}

	// PTO: send probe packets
	if !ld.hasAckElicitingInFlight() {
		// Anti-deadlock PTO
		if ld.onProbeNeeded != nil {
			if ld.hasHandshakeKeys {
				ld.onProbeNeeded(PNSHandshake)
			} else {
				ld.onProbeNeeded(PNSInitial)
			}
		}
	} else {
		// Regular PTO
		_, ptoSpace := ld.getPTOTimeAndSpace(now)
		if ld.onProbeNeeded != nil {
			ld.onProbeNeeded(ptoSpace)
		}
	}

	ld.ptoCount++
	ld.setLossDetectionTimer(now)
}

// getLossTimeAndSpace returns the earliest loss time and its packet number space.
func (ld *LossDetection) getLossTimeAndSpace() (time.Time, PacketNumberSpace) {
	earliestTime := ld.lossTime[PNSInitial]
	space := PNSInitial

	for _, pns := range []PacketNumberSpace{PNSHandshake, PNSApplicationData} {
		if earliestTime.IsZero() || (!ld.lossTime[pns].IsZero() && ld.lossTime[pns].Before(earliestTime)) {
			earliestTime = ld.lossTime[pns]
			space = pns
		}
	}

	return earliestTime, space
}

// getPTOTimeAndSpace returns the PTO timeout time and its packet number space.
func (ld *LossDetection) getPTOTimeAndSpace(now time.Time) (time.Time, PacketNumberSpace) {
	duration := ld.rtt.PTO() * time.Duration(int64(1)<<uint(ld.ptoCount))

	// Anti-deadlock PTO starts from current time
	if !ld.hasAckElicitingInFlight() {
		if ld.hasHandshakeKeys {
			return now.Add(duration), PNSHandshake
		}
		return now.Add(duration), PNSInitial
	}

	var ptoTimeout time.Time
	ptoSpace := PNSInitial

	for _, pns := range []PacketNumberSpace{PNSInitial, PNSHandshake, PNSApplicationData} {
		if !ld.hasAckElicitingInSpace(pns) {
			continue
		}
		if pns == PNSApplicationData {
			if !ld.rtt.handshakeConfirmed {
				return ptoTimeout, ptoSpace
			}
			// Include max_ack_delay for Application Data
			duration += ld.rtt.MaxAckDelay * time.Duration(int64(1)<<uint(ld.ptoCount))
		}

		t := ld.timeOfLastAckEliciting[pns].Add(duration)
		if ptoTimeout.IsZero() || t.Before(ptoTimeout) {
			ptoTimeout = t
			ptoSpace = pns
		}
	}

	return ptoTimeout, ptoSpace
}

// setLossDetectionTimer sets or updates the loss detection timer (RFC 9002 Appendix A.8).
func (ld *LossDetection) setLossDetectionTimer(now time.Time) {
	// Check for time-threshold loss detection
	earliestLossTime, _ := ld.getLossTimeAndSpace()
	if !earliestLossTime.IsZero() {
		ld.lossDetectionTimer = earliestLossTime
		return
	}

	// Server at anti-amplification limit: no timer
	if !ld.isClient && !ld.peerCompletedAddrValidation {
		// If server is at anti-amplification limit, cancel timer
		// (simplified: we assume not at limit for now)
	}

	// No ack-eliciting packets in flight and peer has completed address validation
	if !ld.hasAckElicitingInFlight() && ld.peerCompletedAddressValidation() {
		ld.lossDetectionTimer = time.Time{}
		return
	}

	timeout, _ := ld.getPTOTimeAndSpace(now)
	ld.lossDetectionTimer = timeout
}

// hasAckElicitingInFlight returns true if there are ack-eliciting packets
// in flight in any packet number space.
func (ld *LossDetection) hasAckElicitingInFlight() bool {
	for pns := range ld.sentPackets {
		if ld.hasAckElicitingInSpace(PacketNumberSpace(pns)) {
			return true
		}
	}
	return false
}

// hasAckElicitingInSpace returns true if there are ack-eliciting packets
// in flight in the given packet number space.
func (ld *LossDetection) hasAckElicitingInSpace(pns PacketNumberSpace) bool {
	for _, p := range ld.sentPackets[pns] {
		if p.AckEliciting && p.InFlight {
			return true
		}
	}
	return false
}

// peerCompletedAddressValidation returns true if the peer has completed
// address validation (RFC 9002 Appendix A.8).
func (ld *LossDetection) peerCompletedAddressValidation() bool {
	if !ld.isClient {
		return true // Server always validates client address
	}
	// Client: completed when server's address is validated
	return ld.peerCompletedAddrValidation
}

// SetPeerCompletedAddressValidation sets whether the peer has completed
// address validation.
func (ld *LossDetection) SetPeerCompletedAddressValidation(completed bool) {
	ld.mu.Lock()
	defer ld.mu.Unlock()
	ld.peerCompletedAddrValidation = completed
}

// SetHandshakeConfirmed marks the handshake as confirmed.
func (ld *LossDetection) SetHandshakeConfirmed(confirmed bool) {
	ld.mu.Lock()
	defer ld.mu.Unlock()
	ld.rtt.SetHandshakeConfirmed(confirmed)
}

// SetHasHandshakeKeys indicates whether handshake keys are available.
func (ld *LossDetection) SetHasHandshakeKeys(has bool) {
	ld.mu.Lock()
	defer ld.mu.Unlock()
	ld.hasHandshakeKeys = has
}

// SetProbeCallback sets the callback for when a probe packet needs to be sent.
func (ld *LossDetection) SetProbeCallback(cb func(PacketNumberSpace)) {
	ld.mu.Lock()
	defer ld.mu.Unlock()
	ld.onProbeNeeded = cb
}

// SetPacketsLostCallback sets the callback for when packets are declared lost.
func (ld *LossDetection) SetPacketsLostCallback(cb func([]*SentPacket)) {
	ld.mu.Lock()
	defer ld.mu.Unlock()
	ld.onPacketsLost = cb
}

// GetLossDetectionTimer returns when the loss detection timer should fire.
// Returns zero time if no timer is set.
func (ld *LossDetection) GetLossDetectionTimer() time.Time {
	ld.mu.Lock()
	defer ld.mu.Unlock()
	return ld.lossDetectionTimer
}

// OnPacketNumberSpaceDiscarded handles discarding a packet number space
// (RFC 9002 Appendix A.11).
func (ld *LossDetection) OnPacketNumberSpaceDiscarded(pnSpace PacketNumberSpace, now time.Time) {
	ld.mu.Lock()
	defer ld.mu.Unlock()

	spaceIdx := int(pnSpace)

	// Remove from bytes in flight
	var discarded []*SentPacket
	for _, p := range ld.sentPackets[spaceIdx] {
		discarded = append(discarded, p)
	}
	ld.congestion.RemoveFromBytesInFlight(discarded)

	ld.sentPackets[spaceIdx] = make(map[uint64]*SentPacket)
	ld.timeOfLastAckEliciting[spaceIdx] = time.Time{}
	ld.lossTime[spaceIdx] = time.Time{}
	ld.ptoCount = 0

	ld.setLossDetectionTimer(now)
}

// PTOCount returns the current PTO count.
func (ld *LossDetection) PTOCount() int {
	ld.mu.Lock()
	defer ld.mu.Unlock()
	return ld.ptoCount
}

// BytesInFlight returns the current bytes in flight.
func (ld *LossDetection) BytesInFlight() uint64 {
	ld.mu.Lock()
	defer ld.mu.Unlock()
	return ld.congestion.BytesInFlight()
}

// CongestionWindow returns the current congestion window.
func (ld *LossDetection) CongestionWindow() uint64 {
	ld.mu.Lock()
	defer ld.mu.Unlock()
	return ld.congestion.CongestionWindow()
}

// CanSend returns true if the congestion controller allows sending
// the given number of bytes.
func (ld *LossDetection) CanSend(bytes int) bool {
	ld.mu.Lock()
	defer ld.mu.Unlock()
	return ld.congestion.CanSend(bytes)
}
