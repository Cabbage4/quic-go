package ack

import (
	"testing"
)

func TestTrackerEmpty(t *testing.T) {
	tr := NewTracker(PNSpaceApplication)
	if tr.HasPending() {
		t.Error("new tracker should not have pending")
	}
	if data := tr.BuildAckFrame(); data != nil {
		t.Error("BuildAckFrame on empty tracker should return nil")
	}
}

func TestSinglePacket(t *testing.T) {
	tr := NewTracker(PNSpaceApplication)
	tr.ReceivedPacket(0, true)

	data := tr.BuildAckFrame()
	if data == nil {
		t.Fatal("expected ACK data, got nil")
	}
	if data.LargestAcked != 0 {
		t.Errorf("largest = %d, want 0", data.LargestAcked)
	}
	if data.RangeCount != 0 {
		t.Errorf("range count = %d, want 0", data.RangeCount)
	}
	if data.FirstAckRange != 0 {
		t.Errorf("first range = %d, want 0", data.FirstAckRange)
	}
}

func TestContiguousPackets(t *testing.T) {
	tr := NewTracker(PNSpaceApplication)
	for i := uint64(0); i < 5; i++ {
		tr.ReceivedPacket(i, true)
	}

	data := tr.BuildAckFrame()
	if data == nil {
		t.Fatal("expected ACK data")
	}
	if data.LargestAcked != 4 {
		t.Errorf("largest = %d, want 4", data.LargestAcked)
	}
	if data.RangeCount != 0 {
		t.Errorf("range count = %d, want 0", data.RangeCount)
	}
	if data.FirstAckRange != 4 {
		t.Errorf("first range = %d, want 4", data.FirstAckRange)
	}
	if len(data.GapAndRanges) != 0 {
		t.Errorf("gap ranges = %d, want 0", len(data.GapAndRanges))
	}
}

func TestGapDetection(t *testing.T) {
	tr := NewTracker(PNSpaceApplication)
	// Receive 0,1,2 then skip to 5,6,7
	tr.ReceivedPacket(0, true)
	tr.ReceivedPacket(1, true)
	tr.ReceivedPacket(2, true)
	tr.ReceivedPacket(5, true)
	tr.ReceivedPacket(6, true)
	tr.ReceivedPacket(7, true)

	data := tr.BuildAckFrame()
	if data == nil {
		t.Fatal("expected ACK data")
	}
	if data.LargestAcked != 7 {
		t.Errorf("largest = %d, want 7", data.LargestAcked)
	}
	// First range: [5,7] → range length = 2
	if data.FirstAckRange != 2 {
		t.Errorf("first range = %d, want 2", data.FirstAckRange)
	}
	// One gap: [0,2], missing packets 3,4 = 2 missing
	// RFC 9000 §19.3: Gap field = number of contiguous unacknowledged packets - 1
	// So gap = 2 - 1 = 1
	if len(data.GapAndRanges) != 1 {
		t.Fatalf("gap ranges = %d, want 1", len(data.GapAndRanges))
	}
	if data.GapAndRanges[0].Gap != 1 {
		t.Errorf("gap = %d, want 1", data.GapAndRanges[0].Gap)
	}
	if data.GapAndRanges[0].RangeLength != 2 {
		t.Errorf("range length = %d, want 2", data.GapAndRanges[0].RangeLength)
	}
}

func TestMultipleGaps(t *testing.T) {
	tr := NewTracker(PNSpaceApplication)
	// Receive: 0, 3, 6
	tr.ReceivedPacket(0, true)
	tr.ReceivedPacket(3, true)
	tr.ReceivedPacket(6, true)

	data := tr.BuildAckFrame()
	if data == nil {
		t.Fatal("expected ACK data")
	}
	if data.LargestAcked != 6 {
		t.Errorf("largest = %d, want 6", data.LargestAcked)
	}
	if data.FirstAckRange != 0 {
		t.Errorf("first range = %d, want 0", data.FirstAckRange)
	}
	// Two gaps
	if len(data.GapAndRanges) != 2 {
		t.Fatalf("gap ranges = %d, want 2", len(data.GapAndRanges))
	}
	// Gap 1: between 6 and 3 → gap = 6-3-2 = 1, range = 0
	if data.GapAndRanges[0].Gap != 1 {
		t.Errorf("gap1 = %d, want 1", data.GapAndRanges[0].Gap)
	}
	// Gap 2: between 3 and 0 → gap = 3-0-2 = 1, range = 0
	if data.GapAndRanges[1].Gap != 1 {
		t.Errorf("gap2 = %d, want 1", data.GapAndRanges[1].Gap)
	}
}

func TestDuplicateDetection(t *testing.T) {
	tr := NewTracker(PNSpaceApplication)
	tr.ReceivedPacket(5, true)

	if !tr.IsDuplicate(5) {
		t.Error("packet 5 should be duplicate")
	}
	if tr.IsDuplicate(4) {
		t.Error("packet 4 should not be duplicate")
	}

	// Receive it again — should be silently ignored
	tr.ReceivedPacket(5, true)
	data := tr.BuildAckFrame()
	if data.FirstAckRange != 0 {
		t.Errorf("first range = %d, want 0 (single packet)", data.FirstAckRange)
	}
}

func TestOutOfOrderFill(t *testing.T) {
	tr := NewTracker(PNSpaceApplication)
	// Receive 0,2,4 then fill in 1,3
	tr.ReceivedPacket(0, true)
	tr.ReceivedPacket(2, true)
	tr.ReceivedPacket(4, true)

	data := tr.BuildAckFrame()
	if data.RangeCount != 2 {
		t.Errorf("range count = %d, want 2", data.RangeCount)
	}

	// Fill the gaps
	tr.ReceivedPacket(1, true)
	tr.ReceivedPacket(3, true)

	data2 := tr.BuildAckFrame()
	if data2.RangeCount != 0 {
		t.Errorf("after filling gaps, range count = %d, want 0", data2.RangeCount)
	}
	if data2.FirstAckRange != 4 {
		t.Errorf("first range = %d, want 4", data2.FirstAckRange)
	}
}

func TestShouldSendAck(t *testing.T) {
	tr := NewTracker(PNSpaceApplication)

	// No packets → no ACK
	if tr.ShouldSendAck(false) {
		t.Error("should not send ACK when no packets received")
	}

	tr.ReceivedPacket(0, true)

	// ACK-eliciting packet → immediate ACK
	if !tr.ShouldSendAck(true) {
		t.Error("should send ACK for ACK-eliciting packet")
	}

	// Non-eliciting but pending → should send
	if !tr.ShouldSendAck(false) {
		t.Error("should send ACK when pending")
	}

	// After marking as acked → should not send
	tr.MarkAcked()
	if tr.HasPending() {
		t.Error("should not have pending after MarkAcked")
	}
}

func TestReset(t *testing.T) {
	tr := NewTracker(PNSpaceApplication)
	tr.ReceivedPacket(0, true)
	tr.ReceivedPacket(1, true)
	tr.ReceivedECNPacket(2, true, false, false)

	tr.Reset()
	if tr.HasPending() {
		t.Error("should not have pending after reset")
	}
	if data := tr.BuildAckFrame(); data != nil {
		t.Error("BuildAckFrame should return nil after reset")
	}
	ect0, _, _, _ := tr.ECNCounts()
	if ect0 != 0 {
		t.Errorf("ECT0 = %d after reset, want 0", ect0)
	}
}

func TestECNCounts(t *testing.T) {
	tr := NewTracker(PNSpaceApplication)
	tr.SetECNEnabled(true)

	tr.ReceivedECNPacket(0, true, false, false)  // ECT0
	tr.ReceivedECNPacket(1, false, true, false)  // ECT1
	tr.ReceivedECNPacket(2, false, false, true)  // CE
	tr.ReceivedECNPacket(3, true, false, false)  // ECT0 again

	data := tr.BuildAckFrame()
	if !data.ECNEnabled {
		t.Error("ECN should be enabled")
	}
	if data.ECT0Count != 2 {
		t.Errorf("ECT0 = %d, want 2", data.ECT0Count)
	}
	if data.ECT1Count != 1 {
		t.Errorf("ECT1 = %d, want 1", data.ECT1Count)
	}
	if data.CECount != 1 {
		t.Errorf("CE = %d, want 1", data.CECount)
	}
}
