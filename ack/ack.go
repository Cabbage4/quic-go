// Package ack implements QUIC ACK frame tracking and generation
// (RFC 9000, Section 13.1 and Section 19.3).
//
// ACK frames are sent by a receiver to inform the sender which packets
// have been received. They contain a series of ACK ranges, where each
// range describes a contiguous set of packet numbers that were received.
//
// Format (RFC 9000 §19.3):
//
//	ACK Frame {
//	  Type (i) = 0x02..0x03,
//	  Largest Acknowledged (i),
//	  ACK Delay (i),
//	  ACK Range Count (i),
//	  First ACK Range (i),
//	  ACK Range [] {
//	    Gap (i),
//	  ACK Range Length (i),
//	  },
//	[ECN Counts]  // only present if Type == 0x03
package ack

import (
	"fmt"
	"sort"
	"sync"
	"time"
)

// PNSpace represents a QUIC packet number space.
type PNSpace int

const (
	PNSpaceInitial     PNSpace = 0
	PNSpaceHandshake   PNSpace = 1
	PNSpaceApplication PNSpace = 2
)

// AckRange represents a range of acknowledged packet numbers.
// [Lo, Hi] inclusive.
type AckRange struct {
	Lo uint64
	Hi uint64
}

// Tracker tracks received packet numbers and generates ACK ranges
// for a single packet number space.
type Tracker struct {
	mu sync.Mutex

	space   PNSpace
	ranges  []AckRange // sorted by Lo, non-overlapping, non-adjacent

	// ACK delay exponent (from transport params, default 3)
	ackDelayExponent uint8
	// Max ACK delay in milliseconds (from transport params, default 25)
	maxAckDelay time.Duration

	// Whether ECN counts should be included
	ecnEnabled bool

	// ECN counts (only meaningful if ecnEnabled)
	ect0Count   uint64
	ect1Count   uint64
	ceCount     uint64

	// Whether the tracker has packets to ACK
	pending bool
}

// NewTracker creates a new ACK tracker for the given packet number space.
func NewTracker(space PNSpace) *Tracker {
	return &Tracker{
		space:            space,
		ackDelayExponent: 3, // default per RFC 9000 §18.2
		maxAckDelay:      25 * time.Millisecond,
	}
}

// SetAckDelayExponent sets the ACK delay exponent from transport parameters.
func (t *Tracker) SetAckDelayExponent(exp uint8) {
	t.mu.Lock()
	defer t.mu.Unlock()
	t.ackDelayExponent = exp
}

// SetMaxAckDelay sets the maximum ACK delay from transport parameters.
func (t *Tracker) SetMaxAckDelay(d time.Duration) {
	t.mu.Lock()
	defer t.mu.Unlock()
	t.maxAckDelay = d
}

// SetECNEnabled enables or disables ECN count tracking.
func (t *Tracker) SetECNEnabled(enabled bool) {
	t.mu.Lock()
	defer t.mu.Unlock()
	t.ecnEnabled = enabled
}

// ReceivedPacket records that a packet with the given number was received.
// This is the core method that maintains the set of received packets.
// Duplicate packets are silently ignored.
//
// Per RFC 9000 §13.2-§13.3, only ACK-eliciting packets cause the peer to send
// an ACK. Therefore the "pending ACK" latch is armed ONLY when ackEliciting
// is true. Arming it for every packet (including pure-ACK packets) causes an
// infinite ACK ping-pong: A sends ACK → B receives it, arms pending, sends
// ACK → A receives, arms pending, sends ACK → …, flooding the connection.
func (t *Tracker) ReceivedPacket(pn uint64, ackEliciting bool) {
	t.mu.Lock()
	defer t.mu.Unlock()

	// Check if pn is already in an existing range
	for _, r := range t.ranges {
		if pn >= r.Lo && pn <= r.Hi {
			return // already tracked
		}
	}

	// Try to extend an existing range
	for i := range t.ranges {
		r := &t.ranges[i]
		if pn == r.Lo-1 {
			r.Lo = pn
			t.mergeAdjacent()
			if ackEliciting {
				t.pending = true
			}
			return
		}
		if pn == r.Hi+1 {
			r.Hi = pn
			t.mergeAdjacent()
			if ackEliciting {
				t.pending = true
			}
			return
		}
	}

	// Insert new single-packet range
	t.ranges = append(t.ranges, AckRange{Lo: pn, Hi: pn})
	sort.Slice(t.ranges, func(i, j int) bool {
		return t.ranges[i].Lo < t.ranges[j].Lo
	})
	t.mergeAdjacent()
	if ackEliciting {
		t.pending = true
	}
}

// mergeAdjacent merges ranges that are now adjacent after an insert.
func (t *Tracker) mergeAdjacent() {
	if len(t.ranges) < 2 {
		return
	}
	merged := []AckRange{t.ranges[0]}
	for i := 1; i < len(t.ranges); i++ {
		last := &merged[len(merged)-1]
		if t.ranges[i].Lo <= last.Hi+1 {
			// Adjacent or overlapping — merge
			if t.ranges[i].Hi > last.Hi {
				last.Hi = t.ranges[i].Hi
			}
			if t.ranges[i].Lo < last.Lo {
				last.Lo = t.ranges[i].Lo
			}
		} else {
			merged = append(merged, t.ranges[i])
		}
	}
	t.ranges = merged
}

// ReceivedECNPacket records a received packet with ECN markings.
// ECN-CE-marked packets are treated as ACK-eliciting (the CE signal is
// congestion feedback the receiver should acknowledge promptly).
func (t *Tracker) ReceivedECNPacket(pn uint64, ect0, ect1, ce bool) {
	t.mu.Lock()
	if ect0 {
		t.ect0Count++
	}
	if ect1 {
		t.ect1Count++
	}
	if ce {
		t.ceCount++
	}
	t.mu.Unlock()
	t.ReceivedPacket(pn, ce)
}

// HasPending returns true if there are unacknowledged received packets.
func (t *Tracker) HasPending() bool {
	t.mu.Lock()
	defer t.mu.Unlock()
	return t.pending
}

// MarkAcked marks the current pending ACKs as sent (clears pending flag).
func (t *Tracker) MarkAcked() {
	t.mu.Lock()
	defer t.mu.Unlock()
	t.pending = false
}

// LargestReceived returns the largest packet number we have received from the
// peer in this PN space (the high end of the highest tracked received range),
// or (0,false) if no packets have been received yet.
//
// Despite living in the ACK tracker, this is the largest *received* packet,
// not the largest we have acked — it is the correct context for reconstructing
// the next incoming packet's truncated packet number (RFC 9000 §17.3.2 /
// Appendix A.3 use "largest packet number successfully processed in the current
// space"). Renamed from LargestAcknowledged to reflect what it actually returns.
func (t *Tracker) LargestReceived() (uint64, bool) {
	t.mu.Lock()
	defer t.mu.Unlock()
	if len(t.ranges) == 0 {
		return 0, false
	}
	return t.ranges[len(t.ranges)-1].Hi, true
}

// GetRanges returns the current ACK ranges, ordered from highest to lowest
// as they appear in an ACK frame (the first range contains the largest PN).
func (t *Tracker) GetRanges() []AckRange {
	t.mu.Lock()
	defer t.mu.Unlock()
	if len(t.ranges) == 0 {
		return nil
	}
	// ACK frames list ranges from largest to smallest
	result := make([]AckRange, len(t.ranges))
	for i := range t.ranges {
		result[i] = t.ranges[len(t.ranges)-1-i]
	}
	return result
}

// GetAckDelay returns the ACK delay in microseconds, encoded using
// the ACK delay exponent (right-shifted).
func (t *Tracker) GetAckDelay() uint64 {
	t.mu.Lock()
	defer t.mu.Unlock()
	// In a real implementation, this would be the time since the largest
	// acknowledged packet was received. For now, return 0 (no delay).
	return 0
}

// ECNCounts returns the ECN counts (ECT0, ECT1, CE) if ECN is enabled.
func (t *Tracker) ECNCounts() (ect0, ect1, ce uint64, enabled bool) {
	t.mu.Lock()
	defer t.mu.Unlock()
	return t.ect0Count, t.ect1Count, t.ceCount, t.ecnEnabled
}

// AckFrameData represents the data needed to build an ACK frame.
type AckFrameData struct {
	LargestAcked   uint64
	AckDelay       uint64
	RangeCount     uint64
	FirstAckRange  uint64   // count of packets in the first range (smallest gap)
	GapAndRanges   []GapRange // subsequent ranges
	ECNEnabled     bool
	ECT0Count      uint64
	ECT1Count      uint64
	CECount        uint64
}

// GapRange represents a gap + ACK range length pair after the first range.
type GapRange struct {
	Gap          uint64 // number of missing packets between ranges
	RangeLength  uint64 // count of packets in this range
}

// BuildAckFrame constructs the data needed to encode an ACK frame.
// Returns nil if no packets to acknowledge.
func (t *Tracker) BuildAckFrame() *AckFrameData {
	t.mu.Lock()
	defer t.mu.Unlock()

	if len(t.ranges) == 0 {
		return nil
	}

	// Ranges are stored sorted ascending; ACK frame lists them descending
	rangesDesc := make([]AckRange, len(t.ranges))
	for i := range t.ranges {
		rangesDesc[i] = t.ranges[len(t.ranges)-1-i]
	}

	data := &AckFrameData{
		LargestAcked: rangesDesc[0].Hi,
		AckDelay:     0,
		RangeCount:   uint64(len(rangesDesc) - 1),
		FirstAckRange: rangesDesc[0].Hi - rangesDesc[0].Lo,
		ECNEnabled:   t.ecnEnabled,
		ECT0Count:    t.ect0Count,
		ECT1Count:    t.ect1Count,
		CECount:      t.ceCount,
	}

	// Build gap + range pairs for subsequent ranges
	for i := 1; i < len(rangesDesc); i++ {
		prev := rangesDesc[i-1]
		curr := rangesDesc[i]
		// Gap = prev.Lo - curr.Hi - 2
		// (the -2 accounts for: one missing packet between ranges,
		//  and one for the range boundary itself)
		gap := uint64(0)
		if curr.Hi+2 <= prev.Lo {
			gap = prev.Lo - curr.Hi - 2
		}
		rangeLen := curr.Hi - curr.Lo
		data.GapAndRanges = append(data.GapAndRanges, GapRange{
			Gap:         gap,
			RangeLength: rangeLen,
		})
	}

	return data
}

// String returns a human-readable summary.
func (t *Tracker) String() string {
	t.mu.Lock()
	defer t.mu.Unlock()
	return fmt.Sprintf("ACKTracker(space=%d, ranges=%d, pending=%v)",
		int(t.space), len(t.ranges), t.pending)
}

// IsDuplicate returns true if the given packet number was already received.
func (t *Tracker) IsDuplicate(pn uint64) bool {
	t.mu.Lock()
	defer t.mu.Unlock()
	for _, r := range t.ranges {
		if pn >= r.Lo && pn <= r.Hi {
			return true
		}
	}
	return false
}

// ShouldSendAck returns true if an ACK should be sent immediately
// (rather than delayed). This happens when:
//  - Every packet in order has been received (no gaps)
//  - The ACK delay timer has expired
//  - An ACK eliciting packet was received
func (t *Tracker) ShouldSendAck(ackEliciting bool) bool {
	t.mu.Lock()
	defer t.mu.Unlock()
	if len(t.ranges) == 0 {
		return false
	}
	// Immediately ACK if this was an ACK-eliciting packet
	if ackEliciting {
		return true
	}
	return t.pending
}

// Reset clears all tracked state (used when discarding keys for a PN space).
func (t *Tracker) Reset() {
	t.mu.Lock()
	defer t.mu.Unlock()
	t.ranges = nil
	t.pending = false
	t.ect0Count = 0
	t.ect1Count = 0
	t.ceCount = 0
}
