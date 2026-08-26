// Package connection: recovery integration layer.
//
// This file wires the recovery package (RFC 9002) into the connection layer.
// It provides:
//   - RecoveryManager: wraps LossDetection + CongestionController
//   - OnPacketSent hook for tracking outgoing packets
//   - OnAckReceived hook for processing ACK frames
//   - Loss detection timer management with callbacks
//   - Packet retransmission queue for lost packets
//   - Congestion control gating (CanSend check)
//
// The RecoveryManager acts as the bridge between the connection's packet I/O
// path and the recovery algorithms defined in RFC 9002.
package connection

import (
	"sync"
	"time"

	"github.com/Cabbage4/quic-go/recovery"
)

// RecoveryManager integrates loss detection and congestion control
// into the connection lifecycle.
type RecoveryManager struct {
	mu sync.Mutex

	ld *recovery.LossDetection

	// Retransmission queue: packets that need to be retransmitted
	retransmitQueue []*QueuedFrame

	// Callbacks
	onProbeNeeded      func(PNSpace)
	onPacketsLost      func([]*recovery.SentPacket)
	onLossTimerExpired func()

	// Loss detection timer
	lossTimer *time.Timer

	// Whether handshake keys are available
	hasHandshakeKeys bool

	// Whether handshake is confirmed
	handshakeConfirmed bool

	// Whether peer has completed address validation
	peerCompletedAddrValidation bool

	// Whether this is a client
	isClient bool
}

// QueuedFrame represents a frame that needs to be (re)transmitted.
type QueuedFrame struct {
	FrameData    []byte // encoded frame bytes
	PNSpace      PNSpace
	AckEliciting bool
}

// NewRecoveryManager creates a new RecoveryManager.
//
// maxAckDelay is the peer's max_ack_delay from transport parameters.
// isClient indicates whether this is a client-side connection.
func NewRecoveryManager(maxAckDelay time.Duration, isClient bool) *RecoveryManager {
	rm := &RecoveryManager{
		ld:       recovery.NewLossDetection(maxAckDelay, isClient),
		isClient: isClient,
	}

	// Wire up loss detection callbacks
	rm.ld.SetProbeCallback(func(pns recovery.PacketNumberSpace) {
		rm.handleProbeNeeded(pns)
	})
	rm.ld.SetPacketsLostCallback(func(lost []*recovery.SentPacket) {
		rm.handlePacketsLost(lost)
	})

	return rm
}

// LossDetection returns the underlying LossDetection instance.
func (rm *RecoveryManager) LossDetection() *recovery.LossDetection {
	return rm.ld
}

// CongestionController returns the congestion controller.
func (rm *RecoveryManager) CongestionController() *recovery.CongestionController {
	return rm.ld.CongestionController()
}

// RTTStats returns the RTT statistics.
func (rm *RecoveryManager) RTTStats() *recovery.RTTStats {
	return rm.ld.RTTStats()
}

// OnPacketSent records a sent packet for loss detection and congestion control.
//
// Parameters:
//   - pn: packet number
//   - space: packet number space
//   - sentBytes: total packet size in bytes
//   - ackEliciting: whether the packet elicits an ACK
//   - inFlight: whether the packet counts toward bytes in flight
//   - now: timestamp the packet was sent
func (rm *RecoveryManager) OnPacketSent(pn uint64, space PNSpace, sentBytes int, ackEliciting, inFlight bool, now time.Time) {
	rm.mu.Lock()
	defer rm.mu.Unlock()

	sp := recovery.SentPacket{
		PacketNumber:  pn,
		TimeSent:      now,
		AckEliciting:  ackEliciting,
		InFlight:      inFlight,
		SentBytes:     sentBytes,
		PNSpace:       pnSpaceToRecovery(space),
	}

	rm.ld.OnPacketSent(&sp, now)
	rm.updateLossDetectionTimer(now)
}

// OnAckReceived processes a received ACK frame.
//
// Parameters:
//   - space: the packet number space of the ACK
//   - ackedPNs: list of newly acknowledged packet numbers
//   - largestAcked: the largest acknowledged packet number
//   - ackDelay: the acknowledgment delay reported by the peer
//   - now: current time
func (rm *RecoveryManager) OnAckReceived(space PNSpace, ackedPNs []uint64, largestAcked uint64, ackDelay time.Duration, now time.Time) {
	rm.mu.Lock()
	defer rm.mu.Unlock()

	rm.ld.OnAckReceived(
		pnSpaceToRecovery(space),
		ackedPNs,
		largestAcked,
		ackDelay,
		now,
	)
	rm.updateLossDetectionTimer(now)
}

// OnLossDetectionTimeout handles the loss detection timer firing.
func (rm *RecoveryManager) OnLossDetectionTimeout() {
	rm.mu.Lock()
	defer rm.mu.Unlock()

	now := time.Now()
	rm.ld.OnLossDetectionTimeout(now)
	rm.updateLossDetectionTimer(now)

	if rm.onLossTimerExpired != nil {
		rm.onLossTimerExpired()
	}
}

// CanSend returns true if the congestion controller allows sending
// the given number of bytes (RFC 9002 §7).
func (rm *RecoveryManager) CanSend(bytes int) bool {
	rm.mu.Lock()
	defer rm.mu.Unlock()
	return rm.ld.CanSend(bytes)
}

// CongestionWindow returns the current congestion window size.
func (rm *RecoveryManager) CongestionWindow() uint64 {
	return rm.ld.CongestionWindow()
}

// BytesInFlight returns the current bytes in flight.
func (rm *RecoveryManager) BytesInFlight() uint64 {
	return rm.ld.BytesInFlight()
}

// PTO returns the current probe timeout duration.
func (rm *RecoveryManager) PTO() time.Duration {
	return rm.ld.RTTStats().PTO()
}

// SmoothedRTT returns the smoothed RTT estimate.
func (rm *RecoveryManager) SmoothedRTT() time.Duration {
	return rm.ld.RTTStats().SmoothedRTT
}

// SetHandshakeConfirmed marks the handshake as confirmed.
// This affects:
//   - RTT: max_ack_delay is now applied
//   - Loss detection: Application data PTO includes max_ack_delay
//   - Key updates: allowed after confirmation
func (rm *RecoveryManager) SetHandshakeConfirmed(confirmed bool) {
	rm.mu.Lock()
	defer rm.mu.Unlock()
	rm.handshakeConfirmed = confirmed
	rm.ld.SetHandshakeConfirmed(confirmed)
}

// SetHasHandshakeKeys indicates whether handshake keys are available.
func (rm *RecoveryManager) SetHasHandshakeKeys(has bool) {
	rm.mu.Lock()
	defer rm.mu.Unlock()
	rm.hasHandshakeKeys = has
	rm.ld.SetHasHandshakeKeys(has)
}

// SetPeerCompletedAddressValidation sets whether the peer has completed
// address validation (affects PTO timer and anti-amplification).
func (rm *RecoveryManager) SetPeerCompletedAddressValidation(completed bool) {
	rm.mu.Lock()
	defer rm.mu.Unlock()
	rm.peerCompletedAddrValidation = completed
	rm.ld.SetPeerCompletedAddressValidation(completed)
}

// OnPacketNumberSpaceDiscarded handles discarding a PN space (RFC 9002 Appendix A.11).
func (rm *RecoveryManager) OnPacketNumberSpaceDiscarded(space PNSpace) {
	rm.mu.Lock()
	defer rm.mu.Unlock()
	rm.ld.OnPacketNumberSpaceDiscarded(pnSpaceToRecovery(space), time.Now())
}

// EnqueueRetransmission adds a frame to the retransmission queue.
func (rm *RecoveryManager) EnqueueRetransmission(frame *QueuedFrame) {
	rm.mu.Lock()
	defer rm.mu.Unlock()
	rm.retransmitQueue = append(rm.retransmitQueue, frame)
}

// DequeueRetransmission removes and returns the next frame to retransmit.
func (rm *RecoveryManager) DequeueRetransmission() *QueuedFrame {
	rm.mu.Lock()
	defer rm.mu.Unlock()

	if len(rm.retransmitQueue) == 0 {
		return nil
	}
	frame := rm.retransmitQueue[0]
	rm.retransmitQueue = rm.retransmitQueue[1:]
	return frame
}

// HasRetransmissionQueue returns true if there are frames to retransmit.
func (rm *RecoveryManager) HasRetransmissionQueue() bool {
	rm.mu.Lock()
	defer rm.mu.Unlock()
	return len(rm.retransmitQueue) > 0
}

// SetProbeCallback sets the callback for when a probe packet needs to be sent.
func (rm *RecoveryManager) SetProbeCallback(cb func(PNSpace)) {
	rm.mu.Lock()
	defer rm.mu.Unlock()
	rm.onProbeNeeded = cb
}

// SetPacketsLostCallback sets the callback for when packets are declared lost.
func (rm *RecoveryManager) SetPacketsLostCallback(cb func([]*recovery.SentPacket)) {
	rm.mu.Lock()
	defer rm.mu.Unlock()
	rm.onPacketsLost = cb
}

// SetLossTimerExpiredCallback sets the callback for when the loss timer fires.
func (rm *RecoveryManager) SetLossTimerExpiredCallback(cb func()) {
	rm.mu.Lock()
	defer rm.mu.Unlock()
	rm.onLossTimerExpired = cb
}

// handleProbeNeeded handles a probe packet request from loss detection.
func (rm *RecoveryManager) handleProbeNeeded(pns recovery.PacketNumberSpace) {
	if rm.onProbeNeeded != nil {
		rm.onProbeNeeded(recoveryPnSpaceToConnection(pns))
	}
}

// handlePacketsLost handles packets being declared lost.
func (rm *RecoveryManager) handlePacketsLost(lost []*recovery.SentPacket) {
	if rm.onPacketsLost != nil {
		rm.onPacketsLost(lost)
	}
}

// updateLossDetectionTimer manages the loss detection timer.
// It starts or resets the timer based on the current loss detection state.
func (rm *RecoveryManager) updateLossDetectionTimer(now time.Time) {
	timeout := rm.ld.GetLossDetectionTimer()

	if timeout.IsZero() {
		// Cancel timer if running
		if rm.lossTimer != nil {
			rm.lossTimer.Stop()
			rm.lossTimer = nil
		}
		return
	}

	// Calculate duration until timeout
	dur := timeout.Sub(now)
	if dur <= 0 {
		dur = time.Millisecond
	}

	if rm.lossTimer != nil {
		rm.lossTimer.Reset(dur)
	} else {
		rm.lossTimer = time.AfterFunc(dur, func() {
			rm.OnLossDetectionTimeout()
		})
	}
}

// Stop stops the loss detection timer and cleans up.
func (rm *RecoveryManager) Stop() {
	rm.mu.Lock()
	defer rm.mu.Unlock()

	if rm.lossTimer != nil {
		rm.lossTimer.Stop()
		rm.lossTimer = nil
	}
}

// ResetCongestionState resets the congestion controller (e.g., for new path).
func (rm *RecoveryManager) ResetCongestionState() {
	rm.mu.Lock()
	defer rm.mu.Unlock()
	rm.ld.CongestionController().ResetCongestionState()
}

// pnSpaceToRecovery converts connection.PNSpace to recovery.PacketNumberSpace.
func pnSpaceToRecovery(space PNSpace) recovery.PacketNumberSpace {
	switch space {
	case PNSpaceInitial:
		return recovery.PNSInitial
	case PNSpaceHandshake:
		return recovery.PNSHandshake
	case PNSpaceApplication:
		return recovery.PNSApplicationData
	default:
		return recovery.PNSInitial
	}
}

// recoveryPnSpaceToConnection converts recovery.PacketNumberSpace to connection.PNSpace.
func recoveryPnSpaceToConnection(space recovery.PacketNumberSpace) PNSpace {
	switch space {
	case recovery.PNSInitial:
		return PNSpaceInitial
	case recovery.PNSHandshake:
		return PNSpaceHandshake
	case recovery.PNSApplicationData:
		return PNSpaceApplication
	default:
		return PNSpaceInitial
	}
}
