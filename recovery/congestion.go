// Package recovery implements QUIC congestion control per RFC 9002 §7.
//
// This implementation follows the NewReno-like algorithm described in the RFC.
//
// Congestion control states (RFC 9002 §7.3):
//   - Slow Start: CW < ssthresh, exponential growth
//   - Congestion Avoidance: CW >= ssthresh, AIMD
//   - Recovery Period: after loss, CW reduced, no further reductions
//
// Key differences from TCP (RFC 9002 §4):
//   - Packet numbers are monotonically increasing, never reused
//   - Loss epoch is one per RTT (vs TCP's multiple RTTs)
//   - Min congestion window is 2 packets (vs TCP's 1)
//   - Handshake packet loss is treated as normal loss (not persistent congestion)
package recovery

import (
	"sync"
	"time"
)

// CongestionController implements a NewReno-like congestion controller
// for QUIC (RFC 9002 §7).
type CongestionController struct {
	mu sync.Mutex

	// max_datagram_size: sender's current max payload (min 1200 bytes)
	maxDatagramSize int

	// congestion_window: max bytes allowed in flight
	congestionWindow uint64

	// bytes_in_flight: sum of sent bytes not yet acked/lost
	bytesInFlight uint64

	// congestion_recovery_start_time: time current recovery period started
	congestionRecoveryStartTime time.Time

	// ssthresh: slow start threshold in bytes
	ssthresh uint64

	// ECN CE counters per packet number space
	ecnceCounters [3]uint64

	// Whether we are application-limited (§7.8)
	appLimited bool
}

// kInitialWindow calculates the initial congestion window (RFC 9002 §7.2).
//   kInitialWindow = 10 * max_datagram_size, limited to max(14720, 2*max_datagram_size)
func kInitialWindow(maxDgramSize int) uint64 {
	iw := uint64(kInitialWindowMultiplier * maxDgramSize)
	limit := uint64(14720)
	if limit < uint64(2*maxDgramSize) {
		limit = uint64(2 * maxDgramSize)
	}
	if iw > limit {
		iw = limit
	}
	return iw
}

// kMinimumWindow calculates the minimum congestion window (RFC 9002 §7.2).
//   kMinimumWindow = 2 * max_datagram_size
func kMinimumWindow(maxDgramSize int) uint64 {
	return uint64(kMinimumWindowMultiplier * maxDgramSize)
}

// NewCongestionController creates a new CongestionController with default settings.
func NewCongestionController() *CongestionController {
	cc := &CongestionController{
		maxDatagramSize: kMaxDatagramSize,
		ssthresh:        ^uint64(0), // max uint64 = "infinite"
	}
	cc.congestionWindow = kInitialWindow(cc.maxDatagramSize)
	return cc
}

// OnPacketSentCC handles congestion control state update when a packet is sent
// (RFC 9002 Appendix B.4).
func (cc *CongestionController) OnPacketSentCC(sentBytes int) {
	cc.mu.Lock()
	defer cc.mu.Unlock()
	cc.bytesInFlight += uint64(sentBytes)
}

// OnPacketsAcked handles congestion control state update when packets are
// acknowledged (RFC 9002 Appendix B.5).
func (cc *CongestionController) OnPacketsAcked(ackedPackets []*SentPacket) {
	cc.mu.Lock()
	defer cc.mu.Unlock()

	for _, p := range ackedPackets {
		cc.onPacketAcked(p)
	}
}

// onPacketAcked handles a single acknowledged packet (RFC 9002 Appendix B.5).
func (cc *CongestionController) onPacketAcked(ackedPacket *SentPacket) {
	if !ackedPacket.InFlight {
		return
	}

	// Remove from bytes in flight
	cc.bytesInFlight -= uint64(ackedPacket.SentBytes)

	// Do not increase congestion window if application limited
	// or flow control limited (§7.8)
	if cc.appLimited {
		return
	}

	// Do not increase congestion window in recovery period
	if cc.inCongestionRecovery(ackedPacket.TimeSent) {
		return
	}

	if cc.congestionWindow < cc.ssthresh {
		// Slow start: exponential growth
		cc.congestionWindow += uint64(ackedPacket.SentBytes)
	} else {
		// Congestion avoidance: AIMD
		// Increase CW by at most one max_datagram_size per CW acknowledged
		add := uint64(cc.maxDatagramSize) * uint64(ackedPacket.SentBytes) / cc.congestionWindow
		if add == 0 {
			add = 1
		}
		cc.congestionWindow += add
	}
}

// OnCongestionEvent handles a new congestion event (RFC 9002 Appendix B.6).
// This is called when packets are lost or ECN-CE count increases.
func (cc *CongestionController) OnCongestionEvent(sentTime time.Time) {
	cc.mu.Lock()
	defer cc.mu.Unlock()

	// No reaction if already in a recovery period
	if cc.inCongestionRecovery(sentTime) {
		return
	}

	// Enter recovery period
	cc.congestionRecoveryStartTime = time.Now()
	cc.ssthresh = uint64(float64(cc.congestionWindow) * kLossReductionFactor)
	minWindow := kMinimumWindow(cc.maxDatagramSize)
	if cc.ssthresh < minWindow {
		cc.ssthresh = minWindow
	}
	cc.congestionWindow = cc.ssthresh
}

// OnPacketsLost handles packets declared lost (RFC 9002 Appendix B.8).
func (cc *CongestionController) OnPacketsLost(lostPackets []*SentPacket) {
	cc.mu.Lock()
	defer cc.mu.Unlock()

	var sentTimeOfLastLoss time.Time
	// Remove lost packets from bytes in flight
	for _, p := range lostPackets {
		if p.InFlight {
			cc.bytesInFlight -= uint64(p.SentBytes)
			if p.TimeSent.After(sentTimeOfLastLoss) {
				sentTimeOfLastLoss = p.TimeSent
			}
		}
	}

	// Congestion event if in-flight packets were lost
	if !sentTimeOfLastLoss.IsZero() {
		cc.onCongestionEventLocked(sentTimeOfLastLoss)
	}

	// Check for persistent congestion (§7.6)
	// Only consider packets sent after getting an RTT sample
	// (simplified version: check if the duration between the first and last
	// lost packet exceeds the persistent congestion duration)
	if len(lostPackets) < 2 {
		return
	}

	// Find the earliest and latest sent times among in-flight lost packets
	var earliest, latest time.Time
	for _, p := range lostPackets {
		if !p.InFlight {
			continue
		}
		if earliest.IsZero() || p.TimeSent.Before(earliest) {
			earliest = p.TimeSent
		}
		if latest.IsZero() || p.TimeSent.After(latest) {
			latest = p.TimeSent
		}
	}

	if earliest.IsZero() || latest.IsZero() {
		return
	}

	// Persistent congestion duration
	// = (smoothed_rtt + max(4*rttvar, kGranularity) + max_ack_delay) * kPersistentCongestionThreshold
	// This is checked by the loss detection module, not here
}

// onCongestionEventLocked is the internal version of OnCongestionEvent
// that assumes the mutex is already held.
func (cc *CongestionController) onCongestionEventLocked(sentTime time.Time) {
	if cc.inCongestionRecovery(sentTime) {
		return
	}

	cc.congestionRecoveryStartTime = time.Now()
	cc.ssthresh = uint64(float64(cc.congestionWindow) * kLossReductionFactor)
	minWindow := kMinimumWindow(cc.maxDatagramSize)
	if cc.ssthresh < minWindow {
		cc.ssthresh = minWindow
	}
	cc.congestionWindow = cc.ssthresh
}

// inCongestionRecovery returns true if the given sent time is within the
// current recovery period (RFC 9002 Appendix B.5).
func (cc *CongestionController) inCongestionRecovery(sentTime time.Time) bool {
	return !cc.congestionRecoveryStartTime.IsZero() &&
		!sentTime.After(cc.congestionRecoveryStartTime)
}

// RemoveFromBytesInFlight removes discarded packets from bytes in flight
// (RFC 9002 Appendix B.9).
func (cc *CongestionController) RemoveFromBytesInFlight(discardedPackets []*SentPacket) {
	cc.mu.Lock()
	defer cc.mu.Unlock()

	for _, p := range discardedPackets {
		if p.InFlight {
			cc.bytesInFlight -= uint64(p.SentBytes)
		}
	}
}

// CongestionWindow returns the current congestion window.
func (cc *CongestionController) CongestionWindow() uint64 {
	cc.mu.Lock()
	defer cc.mu.Unlock()
	return cc.congestionWindow
}

// BytesInFlight returns the current bytes in flight.
func (cc *CongestionController) BytesInFlight() uint64 {
	cc.mu.Lock()
	defer cc.mu.Unlock()
	return cc.bytesInFlight
}

// SSThresh returns the current slow start threshold.
func (cc *CongestionController) SSThresh() uint64 {
	cc.mu.Lock()
	defer cc.mu.Unlock()
	return cc.ssthresh
}

// InRecovery returns true if currently in a recovery period.
func (cc *CongestionController) InRecovery() bool {
	cc.mu.Lock()
	defer cc.mu.Unlock()
	return !cc.congestionRecoveryStartTime.IsZero()
}

// CanSend returns true if the given number of bytes can be sent without
// exceeding the congestion window (RFC 9002 §7).
func (cc *CongestionController) CanSend(bytes int) bool {
	cc.mu.Lock()
	defer cc.mu.Unlock()
	return cc.bytesInFlight+uint64(bytes) <= cc.congestionWindow
}

// RemainingWindow returns the remaining congestion window.
func (cc *CongestionController) RemainingWindow() uint64 {
	cc.mu.Lock()
	defer cc.mu.Unlock()
	if cc.bytesInFlight >= cc.congestionWindow {
		return 0
	}
	return cc.congestionWindow - cc.bytesInFlight
}

// SetMaxDatagramSize sets the maximum datagram size and recalculates
// the initial and minimum congestion windows if needed.
func (cc *CongestionController) SetMaxDatagramSize(size int) {
	cc.mu.Lock()
	defer cc.mu.Unlock()
	cc.maxDatagramSize = size
}

// SetAppLimited sets whether the connection is application-limited (§7.8).
func (cc *CongestionController) SetAppLimited(limited bool) {
	cc.mu.Lock()
	defer cc.mu.Unlock()
	cc.appLimited = limited
}

// InSlowStart returns true if in slow start phase (CW < ssthresh).
func (cc *CongestionController) InSlowStart() bool {
	cc.mu.Lock()
	defer cc.mu.Unlock()
	return cc.congestionWindow < cc.ssthresh
}

// InCongestionAvoidance returns true if in congestion avoidance phase.
func (cc *CongestionController) InCongestionAvoidance() bool {
	cc.mu.Lock()
	defer cc.mu.Unlock()
	return cc.congestionWindow >= cc.ssthresh && !cc.InRecovery()
}

// ProcessECN handles ECN information from an ACK frame (RFC 9002 Appendix B.7).
func (cc *CongestionController) ProcessECN(pnSpace PacketNumberSpace, ceCounter uint64, sentTime time.Time) {
	cc.mu.Lock()
	defer cc.mu.Unlock()

	spaceIdx := int(pnSpace)
	if ceCounter > cc.ecnceCounters[spaceIdx] {
		cc.ecnceCounters[spaceIdx] = ceCounter
		cc.onCongestionEventLocked(sentTime)
	}
}

// ResetCongestionState resets the congestion controller to slow start
// (used after persistent congestion or new path, RFC 9002 §7.6).
func (cc *CongestionController) ResetCongestionState() {
	cc.mu.Lock()
	defer cc.mu.Unlock()

	cc.congestionWindow = kInitialWindow(cc.maxDatagramSize)
	cc.bytesInFlight = 0
	cc.congestionRecoveryStartTime = time.Time{}
	cc.ssthresh = ^uint64(0) // infinite
	for i := range cc.ecnceCounters {
		cc.ecnceCounters[i] = 0
	}
}

// MaxDatagramSize returns the current max datagram size.
func (cc *CongestionController) MaxDatagramSize() int {
	cc.mu.Lock()
	defer cc.mu.Unlock()
	return cc.maxDatagramSize
}
