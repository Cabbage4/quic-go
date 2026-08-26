// Package connection: ACK handler integration layer.
//
// This file wires the ack package into the connection layer.
// It provides:
//   - AckHandler: per-PN-space ACK trackers
//   - ReceivedPacket recording for incoming packets
//   - ACK frame generation for outgoing packets
//   - ACK frame parsing for incoming ACK frames
//
// The AckHandler manages three per-PN-space trackers (Initial, Handshake,
// Application) and provides a unified interface for the packet I/O path.
//
// RFC 9000 §13 — Acknowledgments are sent in ACK frames. Each ACK frame
// contains one or more ACK ranges. The receiver should send ACK frames
// frequently enough to enable the sender's loss detection to work.
package connection

import (
	"sync"
	"time"

	"github.com/Cabbage4/quic-go/ack"
	"github.com/Cabbage4/quic-go/frames"
)

// AckHandler manages per-PN-space ACK tracking and generation.
type AckHandler struct {
	mu sync.Mutex

	// Per-PN-space trackers
	trackers [3]*ack.Tracker

	// Time of last ACK sent per PN space (for ACK delay management)
	lastAckSent [3]time.Time

	// Whether ECN is enabled
	ecnEnabled bool
}

// NewAckHandler creates a new ACK handler with trackers for all three PN spaces.
func NewAckHandler() *AckHandler {
	return &AckHandler{
		trackers: [3]*ack.Tracker{
			ack.NewTracker(ack.PNSpaceInitial),
			ack.NewTracker(ack.PNSpaceHandshake),
			ack.NewTracker(ack.PNSpaceApplication),
		},
	}
}

// OnPacketReceived records an incoming packet for ACK tracking.
//
// Parameters:
//   - pn: packet number
//   - space: packet number space
//   - ackEliciting: whether the packet contains ACK-eliciting frames
func (h *AckHandler) OnPacketReceived(pn uint64, space PNSpace, ackEliciting bool) {
	h.mu.Lock()
	defer h.mu.Unlock()

	t := h.trackers[space]
	t.ReceivedPacket(pn)

	if ackEliciting {
		// Mark that we need to send an ACK for this space
		// The ShouldSendAck method will return true immediately for ack-eliciting
	}
}

// OnECNPacketReceived records an incoming packet with ECN markings.
func (h *AckHandler) OnECNPacketReceived(pn uint64, space PNSpace, ect0, ect1, ce bool) {
	h.mu.Lock()
	defer h.mu.Unlock()

	t := h.trackers[space]
	if !h.ecnEnabled {
		t.SetECNEnabled(true)
		h.ecnEnabled = true
	}
	t.ReceivedECNPacket(pn, ect0, ect1, ce)
}

// ShouldSendAck returns true if an ACK frame should be sent for the given PN space.
//
// An ACK should be sent when:
//   - There are pending unacknowledged packets
//   - An ACK-eliciting packet was received (immediate ACK)
//   - The ACK delay timer has expired
func (h *AckHandler) ShouldSendAck(space PNSpace, ackEliciting bool) bool {
	h.mu.Lock()
	defer h.mu.Unlock()

	t := h.trackers[space]
	return t.ShouldSendAck(ackEliciting)
}

// BuildAckFrame builds an ACK frame for the given PN space.
// Returns nil if there are no packets to acknowledge.
func (h *AckHandler) BuildAckFrame(space PNSpace) *frames.ACK {
	h.mu.Lock()
	defer h.mu.Unlock()

	t := h.trackers[space]
	data := t.BuildAckFrame()
	if data == nil {
		return nil
	}

	ackFrame := &frames.ACK{
		LargestAcked:  data.LargestAcked,
		ACKDelay:      data.AckDelay,
		FirstACKRange: data.FirstAckRange,
		HasECN:        data.ECNEnabled,
		ECT0Count:     data.ECT0Count,
		ECT1Count:     data.ECT1Count,
		ECNCECount:    data.CECount,
	}

	// Convert gap/range pairs
	for _, gr := range data.GapAndRanges {
		ackFrame.ACKRanges = append(ackFrame.ACKRanges, frames.ACKRange{
			Gap:         gr.Gap,
			ACKRangeLen: gr.RangeLength,
		})
	}

	// Mark as sent
	t.MarkAcked()
	h.lastAckSent[space] = time.Now()

	return ackFrame
}

// ParseAckFrame parses an incoming ACK frame and extracts acknowledged packet numbers.
//
// Returns the list of acknowledged packet numbers and the largest acknowledged.
func (h *AckHandler) ParseAckFrame(f *frames.ACK) (ackedPNs []uint64, largestAcked uint64) {
	largestAcked = f.LargestAcked

	// The first ACK range: [largestAcked - firstACKRange, largestAcked]
	low := largestAcked - f.FirstACKRange
	for pn := low; pn <= largestAcked; pn++ {
		ackedPNs = append(ackedPNs, pn)
	}

	// Subsequent ranges (with gaps)
	prevLow := low
	for _, r := range f.ACKRanges {
		// Gap: number of contiguous unacknowledged packets between ranges
		// After prevLow, gap packets are prevLow-1, prevLow-2, ..., prevLow-r.Gap
		// Next range starts at prevLow - r.Gap - 1 (highest acked in this range)
		rangeHi := prevLow - r.Gap - 1
		rangeLo := rangeHi - r.ACKRangeLen
		for pn := rangeLo; pn <= rangeHi; pn++ {
			ackedPNs = append(ackedPNs, pn)
		}
		prevLow = rangeLo
	}

	return ackedPNs, largestAcked
}

// IsDuplicate returns true if the given packet number was already received.
func (h *AckHandler) IsDuplicate(pn uint64, space PNSpace) bool {
	h.mu.Lock()
	defer h.mu.Unlock()
	return h.trackers[space].IsDuplicate(pn)
}

// SetAckDelayExponent sets the ACK delay exponent for a PN space.
func (h *AckHandler) SetAckDelayExponent(space PNSpace, exp uint8) {
	h.mu.Lock()
	defer h.mu.Unlock()
	h.trackers[space].SetAckDelayExponent(exp)
}

// SetMaxAckDelay sets the max ACK delay for a PN space.
func (h *AckHandler) SetMaxAckDelay(space PNSpace, d time.Duration) {
	h.mu.Lock()
	defer h.mu.Unlock()
	h.trackers[space].SetMaxAckDelay(d)
}

// SetECNEnabled enables or disables ECN count tracking.
func (h *AckHandler) SetECNEnabled(enabled bool) {
	h.mu.Lock()
	defer h.mu.Unlock()
	h.ecnEnabled = enabled
	for _, t := range h.trackers {
		t.SetECNEnabled(enabled)
	}
}

// DiscardPNSpace clears the tracker for the given PN space
// (called when keys for that space are discarded).
func (h *AckHandler) DiscardPNSpace(space PNSpace) {
	h.mu.Lock()
	defer h.mu.Unlock()
	h.trackers[space].Reset()
}

// GetAckDelay returns the ACK delay value to encode in an ACK frame.
// This is the time since the largest acknowledged packet was received,
// encoded using the ACK delay exponent.
func (h *AckHandler) GetAckDelay(space PNSpace) uint64 {
	h.mu.Lock()
	defer h.mu.Unlock()
	return h.trackers[space].GetAckDelay()
}

// LargestAcknowledged returns the highest packet number tracked for a space.
func (h *AckHandler) LargestAcknowledged(space PNSpace) (uint64, bool) {
	h.mu.Lock()
	defer h.mu.Unlock()
	return h.trackers[space].LargestAcknowledged()
}
