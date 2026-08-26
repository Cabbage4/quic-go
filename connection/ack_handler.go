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

	// processedAcked[space] remembers packet numbers we have already reported
	// as "newly acked" from a prior ACK frame. QUIC ACK frames are cumulative:
	// every ACK re-describes the full acknowledged set back to its gaps, so
	// without de-duplication the receiver would re-materialize and re-scan
	// O(cumulative acked) PNs on every ACK — an O(N^2) total cost that shows
	// up as per-request latency growing linearly with the request count.
	// By emitting only the delta (PNs not seen in a prior ACK) we make each
	// ACK O(newly-acked) and the whole run O(N).
	//
	// largestAckedEver[space] is the high-water mark of largestAcked seen so
	// far. Because cumulative ACK frames describe everything back to their
	// lowest gap, the first ACK range of a fresh ACK typically covers
	// [.., largestAcked] including all PNs we already reported. Tracking the
	// high-water mark lets us skip iterating that already-reported prefix
	// (the loop bounds start at max(low, largestAckedEver+1)) — otherwise the
	// de-dup set makes each *item* O(1) but the *iteration* over the full
	// cumulative range is still O(N) per ACK, i.e. O(N^2) overall.
	//
	// Memory is O(total distinct acked PNs); bounded in practice by the
	// connection lifetime and on the same order as the per-space received
	// tracker's range set. (Pruning entries below the largest contiguous
	// acked would bound it tighter; left as a future refinement.)
	processedAcked   [3]map[uint64]struct{}
	largestAckedEver [3]uint64
}

// NewAckHandler creates a new ACK handler with trackers for all three PN spaces.
func NewAckHandler() *AckHandler {
	return &AckHandler{
		trackers: [3]*ack.Tracker{
			ack.NewTracker(ack.PNSpaceInitial),
			ack.NewTracker(ack.PNSpaceHandshake),
			ack.NewTracker(ack.PNSpaceApplication),
		},
		processedAcked: [3]map[uint64]struct{}{
			{}, {}, {},
		},
	}
}

// OnPacketReceived records an incoming packet for ACK tracking.
//
// Parameters:
//   - pn: packet number
//   - space: packet number space
//   - ackEliciting: whether the packet contains ACK-eliciting frames
//
// Only ACK-eliciting packets arm the "pending ACK" latch (RFC 9000 §13.2).
// Pure-ACK packets are recorded for duplicate detection but do NOT cause an
// ACK to be generated — otherwise the two endpoints ACK each other's ACKs
// forever (an ACK ping-pong storm).
func (h *AckHandler) OnPacketReceived(pn uint64, space PNSpace, ackEliciting bool) {
	h.mu.Lock()
	defer h.mu.Unlock()

	t := h.trackers[space]
	t.ReceivedPacket(pn, ackEliciting)
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
// maxAckedPacketNumbers caps how many packet numbers ParseAckFrame will
// materialize from a single ACK frame. A well-formed peer ACKs at most as
// many packets as the connection has sent; anything beyond that indicates a
// malformed or hostile frame and would otherwise drive the slice build into
// an effectively unbounded (or uint64-underflowed) loop, pinning the receive
// goroutine.
const maxAckedPacketNumbers = 1 << 20 // 1,048,576

// Returns the list of acknowledged packet numbers and the largest acknowledged.
func (h *AckHandler) ParseAckFrame(f *frames.ACK) (ackedPNs []uint64, largestAcked uint64) {
	largestAcked = f.LargestAcked

	// guardSub returns lo clamped so that the range [lo, hi] is non-empty and
	// does not underflow uint64 arithmetic. If the claimed range would wrap
	// past zero (i.e. the peer claims a range straddling 0, which can only be
	// malformed), it clamps lo to 0.
	guardSub := func(hi, span uint64) (lo uint64, ok bool) {
		if span > hi {
			return 0, false // would underflow
		}
		return hi - span, true
	}

	// The first ACK range: [largestAcked - firstACKRange, largestAcked]
	low, ok := guardSub(largestAcked, f.FirstACKRange)
	if !ok {
		low = 0
	}
	for pn := low; pn <= largestAcked && len(ackedPNs) < maxAckedPacketNumbers; pn++ {
		ackedPNs = append(ackedPNs, pn)
	}

	// Subsequent ranges (with gaps)
	prevLow := low
	for _, r := range f.ACKRanges {
		if len(ackedPNs) >= maxAckedPacketNumbers {
			break
		}
		// rangeHi = prevLow - r.Gap - 1, computed as two guarded steps.
		rangeHi, ok := guardSub(prevLow, r.Gap)
		if !ok {
			break
		}
		rangeHi, ok = guardSub(rangeHi, 1)
		if !ok {
			break
		}
		rangeLo, ok := guardSub(rangeHi, r.ACKRangeLen)
		if !ok {
			// Malformed range straddling 0 — clamp to 0 rather than spin.
			rangeLo = 0
		}
		for pn := rangeLo; pn <= rangeHi && len(ackedPNs) < maxAckedPacketNumbers; pn++ {
			ackedPNs = append(ackedPNs, pn)
		}
		prevLow = rangeLo
	}

	return ackedPNs, largestAcked
}

// NewlyAckedFromFrame returns only the packet numbers acknowledged by f that
// have NOT been reported by a prior call to this method for the same PN space
// (the delta), plus the frame's largest acknowledged. Subsequent cumulative
// ACK frames re-describe the full acked set; without this de-duplication the
// caller would re-process every previously-acked PN on every ACK (O(N^2)).
//
// Callers that need the full acked set (e.g. tests) should use ParseAckFrame.
// The packet-processing path (handleAckFrame → recovery + sentFrames) should
// use this so both consumers do O(delta) work per ACK instead of O(cumulative).
func (h *AckHandler) NewlyAckedFromFrame(f *frames.ACK, space PNSpace) ([]uint64, uint64) {
	h.mu.Lock()
	defer h.mu.Unlock()

	seen := h.processedAcked[space]
	if seen == nil {
		seen = make(map[uint64]struct{})
		h.processedAcked[space] = seen
	}
	largestAcked := f.LargestAcked

	guardSub := func(hi, span uint64) (lo uint64, ok bool) {
		if span > hi {
			return 0, false
		}
		return hi - span, true
	}

	var newlyAcked []uint64
	emit := func(pn uint64) {
		if _, ok := seen[pn]; ok {
			return // already reported in a prior ACK
		}
		seen[pn] = struct{}{}
		newlyAcked = append(newlyAcked, pn)
	}

	// High-water mark: PNs <= largestAckedEver have been described by a prior
	// (cumulative) ACK and, if they were acked, are already in `seen`. The new
	// PNs this ACK can contribute in its first range are therefore
	// (largestAckedEver, largestAcked] — so start iterating at
	// max(low, largestAckedEver+1) instead of `low`. This turns the first
	// range from O(cumulative) into O(delta). Gap ranges below are scanned
	// normally (they're small/absent in the common no-loss case, and `seen`
	// de-dupes any already-reported ones).
	firstNew := h.largestAckedEver[space] + 1 // 1 if no prior ACK (wrap-safe: 0+1=1, PN 0 handled below)

	// First ACK range: [largestAcked - firstACKRange, largestAcked]
	low, ok := guardSub(largestAcked, f.FirstACKRange)
	if !ok {
		low = 0
	}
	start := low
	if firstNew > start {
		start = firstNew
	}
	for pn := start; pn <= largestAcked && len(newlyAcked) < maxAckedPacketNumbers; pn++ {
		emit(pn)
	}

	// Subsequent ranges (with gaps)
	prevLow := low
	for _, r := range f.ACKRanges {
		if len(newlyAcked) >= maxAckedPacketNumbers {
			break
		}
		rangeHi, ok := guardSub(prevLow, r.Gap)
		if !ok {
			break
		}
		rangeHi, ok = guardSub(rangeHi, 1)
		if !ok {
			break
		}
		rangeLo, ok := guardSub(rangeHi, r.ACKRangeLen)
		if !ok {
			rangeLo = 0
		}
		// Gap ranges sit below the first range. Skip any entirely below the
		// high-water mark (already reported); otherwise scan from
		// max(rangeLo, firstNew).
		if rangeHi >= firstNew {
			gStart := rangeLo
			if firstNew > gStart {
				gStart = firstNew
			}
			for pn := gStart; pn <= rangeHi && len(newlyAcked) < maxAckedPacketNumbers; pn++ {
				emit(pn)
			}
		}
		prevLow = rangeLo
	}

	if largestAcked > h.largestAckedEver[space] {
		h.largestAckedEver[space] = largestAcked
	}

	return newlyAcked, largestAcked
}

// IsDuplicate returns true if the given packet number was already received.
func (h *AckHandler) IsDuplicate(pn uint64, space PNSpace) bool {
	h.mu.Lock()
	defer h.mu.Unlock()
	return h.trackers[space].IsDuplicate(pn)
}

// LargestReceivedPN returns the largest packet number we have successfully
// received and decoded from the peer in the given PN space, or nil if none.
//
// This is the correct context for reconstructing the next incoming packet's
// truncated PN (RFC 9000 §17.3.2 / Appendix A.3 use "largest PN successfully
// processed in the current space" — i.e. the largest received, NOT the largest
// of our own sent packets that the peer has acked).
func (h *AckHandler) LargestReceivedPN(space PNSpace) *uint64 {
	h.mu.Lock()
	defer h.mu.Unlock()
	pn, ok := h.trackers[space].LargestReceived()
	if !ok {
		return nil
	}
	v := pn
	return &v
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
