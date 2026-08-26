package stream

import (
	"io"
	"testing"

	"github.com/Cabbage4/quic-go/frames"
)

func TestStreamWriteRead(t *testing.T) {
	s := New(0, 65536, 1048576)

	// Write data
	n, err := s.Write([]byte("hello world"))
	if err != nil {
		t.Fatalf("Write error: %v", err)
	}
	if n != 11 {
		t.Errorf("wrote %d bytes, want 11", n)
	}

	// The data should be in the send buffer, not recv buffer
	// We need to simulate receiving data
	err = s.ReceiveData(0, []byte("hello world"), false)
	if err != nil {
		t.Fatalf("ReceiveData error: %v", err)
	}

	// Read received data
	buf := make([]byte, 100)
	n, err = s.Read(buf)
	if err != nil && err != io.EOF {
		t.Fatalf("Read error: %v", err)
	}
	if n != 11 {
		t.Errorf("read %d bytes, want 11", n)
	}
	if string(buf[:n]) != "hello world" {
		t.Errorf("data = %q, want %q", string(buf[:n]), "hello world")
	}
}

func TestStreamFIN(t *testing.T) {
	s := New(0, 65536, 1048576)

	// Receive data with FIN
	err := s.ReceiveData(0, []byte("done"), true)
	if err != nil {
		t.Fatalf("ReceiveData error: %v", err)
	}

	buf := make([]byte, 100)
	n, err := s.Read(buf)
	if err != nil && err != io.EOF {
		t.Fatalf("Read error: %v", err)
	}
	if n != 4 {
		t.Errorf("read %d bytes, want 4", n)
	}
	if string(buf[:n]) != "done" {
		t.Errorf("data = %q, want %q", string(buf[:n]), "done")
	}

	// Next read should return EOF
	_, err = s.Read(buf)
	if err != io.EOF {
		t.Errorf("expected EOF, got %v", err)
	}
}

func TestStreamFlowControl(t *testing.T) {
	s := New(0, 10, 1048576) // max 10 bytes

	// Write 10 bytes should succeed
	n, err := s.Write([]byte("0123456789"))
	if err != nil {
		t.Fatalf("Write error: %v", err)
	}
	if n != 10 {
		t.Errorf("wrote %d bytes, want 10", n)
	}

	// Write more should be flow control blocked (0 bytes written, no error)
	n, err = s.Write([]byte("A"))
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	if n != 0 {
		t.Errorf("wrote %d bytes, want 0 (flow control blocked)", n)
	}

	// Update flow control limit
	s.UpdateSendMaxData(20)

	// Now write should succeed
	n, err = s.Write([]byte("A"))
	if err != nil {
		t.Fatalf("Write after update error: %v", err)
	}
	if n != 1 {
		t.Errorf("wrote %d bytes, want 1", n)
	}
}

func TestStreamCloseSending(t *testing.T) {
	s := New(0, 65536, 1048576)

	n, _ := s.Write([]byte("data"))
	if n != 4 {
		t.Fatalf("write failed")
	}

	err := s.CloseSending()
	if err != nil {
		t.Fatalf("CloseSending error: %v", err)
	}

	// Second close should error
	err = s.CloseSending()
	if err == nil {
		t.Errorf("expected error on second CloseSending")
	}
}

func TestStreamReset(t *testing.T) {
	s := New(0, 65536, 1048576)

	s.ReceiveData(0, []byte("some data"), false)

	err := s.Reset(1)
	if err != nil {
		t.Fatalf("Reset error: %v", err)
	}

	sendState, _ := s.State()
	if sendState != StateResetSent {
		t.Errorf("send state = %s, want %s", sendState, StateResetSent)
	}
}

func TestStreamManager(t *testing.T) {
	m := NewManager(false, // client
		1048576, // initialMaxData
		256000,  // initialMaxStreamDataBidiLocal
		256000,  // initialMaxStreamDataBidiRemote
		128000,  // initialMaxStreamDataUni
		100,     // maxStreamsBidi
		50,      // maxStreamsUni
	)

	// Client opens bidi stream (ID=0)
	s1, err := m.Open(true)
	if err != nil {
		t.Fatalf("Open bidi error: %v", err)
	}
	if s1.ID != 0 {
		t.Errorf("stream ID = %d, want 0", s1.ID)
	}

	// Client opens uni stream (ID=2)
	s2, err := m.Open(false)
	if err != nil {
		t.Fatalf("Open uni error: %v", err)
	}
	if s2.ID != 2 {
		t.Errorf("stream ID = %d, want 2", s2.ID)
	}

	// Server-initiated stream (ID=1) received by client
	s3, err := m.GetOrCreate(1)
	if err != nil {
		t.Fatalf("GetOrCreate error: %v", err)
	}
	if s3.ID != 1 {
		t.Errorf("stream ID = %d, want 1", s3.ID)
	}
	if !s3.Bidirectional {
		t.Errorf("stream should be bidirectional")
	}

	// Get existing stream
	s4, ok := m.Get(0)
	if !ok {
		t.Fatalf("Get(0) not found")
	}
	if s4 != s1 {
		t.Errorf("Get(0) returned different stream")
	}
}

func TestStreamManagerLimit(t *testing.T) {
	m := NewManager(false,
		1048576, 256000, 256000, 128000,
		2, // max 2 bidi streams
		1, // max 1 uni stream
	)

	// Open 2 bidi streams
	m.Open(true)
	m.Open(true)

	// Third should fail
	_, err := m.Open(true)
	if err == nil {
		t.Errorf("expected stream limit error")
	}

	// Open 1 uni stream
	m.Open(false)

	// Second should fail
	_, err = m.Open(false)
	if err == nil {
		t.Errorf("expected stream limit error")
	}
}

// === Flow Control Window Auto-Update Tests (§4.2) ===

func TestStreamWindowUpdateAfterRead(t *testing.T) {
	s := New(0, 100, 1048576) // maxStreamData = 100

	// Receive 60 bytes
	err := s.ReceiveData(0, make([]byte, 60), false)
	if err != nil {
		t.Fatalf("ReceiveData: %v", err)
	}

	// Read all 60 bytes — this should trigger window update pending
	// since consumedOffset (60) >= maxData/2 (50)
	buf := make([]byte, 100)
	n, err := s.Read(buf)
	if err != nil && err != io.EOF {
		t.Fatalf("Read: %v", err)
	}
	if n != 60 {
		t.Fatalf("Read n = %d, want 60", n)
	}

	if !s.NeedsWindowUpdate() {
		t.Error("expected NeedsWindowUpdate() = true after consuming half the window")
	}

	// Generate the MAX_STREAM_DATA frame
	msd := s.GenStreamWindowUpdate(100)
	if msd == nil {
		t.Fatal("expected MAX_STREAM_DATA frame, got nil")
	}
	if msd.StreamID != 0 {
		t.Errorf("StreamID = %d, want 0", msd.StreamID)
	}
	// newMax = consumedOffset (60) + windowIncrement (100) = 160
	if msd.MaximumData != 160 {
		t.Errorf("MaximumData = %d, want 160", msd.MaximumData)
	}

	// After generating, the pending flag should be cleared
	if s.NeedsWindowUpdate() {
		t.Error("expected NeedsWindowUpdate() = false after GenStreamWindowUpdate")
	}
}

func TestStreamNoWindowUpdateWhenNotEnough(t *testing.T) {
	s := New(0, 1000, 1048576)

	// Receive and read only 10 bytes — not enough to trigger update (need 500)
	s.ReceiveData(0, make([]byte, 10), false)
	buf := make([]byte, 10)
	s.Read(buf)

	if s.NeedsWindowUpdate() {
		t.Error("expected NeedsWindowUpdate() = false when consumed < maxData/2")
	}
}

func TestStreamGenStreamDataBlocked(t *testing.T) {
	s := New(0, 10, 1048576) // maxStreamData = 10

	// Write 10 bytes (fills the window)
	n, _ := s.Write(make([]byte, 10))
	if n != 10 {
		t.Fatalf("Write n = %d, want 10", n)
	}

	// Stream is now blocked on send side
	if !s.IsSendBlocked() {
		t.Error("expected IsSendBlocked() = true")
	}

	// Generate STREAM_DATA_BLOCKED frame
	sdb := s.GenStreamDataBlocked()
	if sdb == nil {
		t.Fatal("expected STREAM_DATA_BLOCKED frame, got nil")
	}
	if sdb.StreamID != 0 {
		t.Errorf("StreamID = %d, want 0", sdb.StreamID)
	}
	if sdb.MaximumData != 10 {
		t.Errorf("MaximumData = %d, want 10", sdb.MaximumData)
	}
}

func TestStreamNoStreamDataBlockedWhenNotBlocked(t *testing.T) {
	s := New(0, 1000, 1048576)
	s.Write(make([]byte, 10))

	sdb := s.GenStreamDataBlocked()
	if sdb != nil {
		t.Error("expected nil STREAM_DATA_BLOCKED when not blocked")
	}
}

func TestStreamGenDataBlocked(t *testing.T) {
	s := New(0, 100, 50) // connMaxData = 50

	// Write 50 bytes — fills connection-level window
	n, _ := s.Write(make([]byte, 50))
	if n != 50 {
		t.Fatalf("Write n = %d, want 50", n)
	}

	// Connection-level blocked
	db := s.GenDataBlocked()
	if db == nil {
		t.Fatal("expected DATA_BLOCKED frame, got nil")
	}
	if db.MaximumData != 50 {
		t.Errorf("MaximumData = %d, want 50", db.MaximumData)
	}
}

func TestManagerPendingWindowUpdates(t *testing.T) {
	m := NewManager(false, 100, 100, 100, 100, 10, 10)

	// Open a stream and simulate receiving + consuming data
	s, _ := m.Open(true)
	s.ReceiveData(0, make([]byte, 60), false)
	buf := make([]byte, 60)
	s.Read(buf) // triggers window update pending

	updates := m.PendingWindowUpdates(100, 100)
	if len(updates) == 0 {
		t.Fatal("expected at least one window update frame")
	}

	// Should contain a MAX_STREAM_DATA frame
	foundMSD := false
	for _, f := range updates {
		switch f.(type) {
		case *frames.MaxStreamData:
			foundMSD = true
		}
	}
	if !foundMSD {
		t.Error("expected MAX_STREAM_DATA frame in updates")
	}
}

// === ACK Integration Tests (§3) ===

func TestStreamMarkAckedTransition(t *testing.T) {
	s := New(0, 65536, 1048576)

	// Write data and send FIN
	s.Write([]byte("hello"))
	s.CloseSending()

	sendState, _ := s.State()
	if sendState != StateSendEnd {
		t.Fatalf("expected StateSendEnd, got %s", sendState)
	}

	// Mark all data as acknowledged (offset 5, FIN acked)
	s.MarkAcked(5, true)

	sendState, _ = s.State()
	if sendState != StateDataSent {
		t.Errorf("expected StateDataSent after all data acked, got %s", sendState)
	}

	if !s.AllDataAcked() {
		t.Error("expected AllDataAcked() = true")
	}
}

func TestStreamPartialAckedNoTransition(t *testing.T) {
	s := New(0, 65536, 1048576)

	s.Write([]byte("hello world")) // 11 bytes
	s.CloseSending()

	// Ack only first 5 bytes, no FIN ack
	s.MarkAcked(5, false)

	sendState, _ := s.State()
	if sendState == StateDataSent {
		t.Error("should not transition to DataSent with partial ack")
	}

	if s.AllDataAcked() {
		t.Error("expected AllDataAcked() = false with partial ack")
	}
}

func TestManagerProcessAckForStream(t *testing.T) {
	m := NewManager(false, 1048576, 65536, 65536, 65536, 10, 10)

	s, _ := m.Open(true) // stream ID 0
	s.Write([]byte("data"))
	s.CloseSending()

	// Process ack for stream 0
	m.ProcessAckForStream(0, 4, true) // 4 bytes + FIN acked

	// Should have transitioned to DataSent
	sendState, _ := s.State()
	if sendState != StateDataSent {
		t.Errorf("expected StateDataSent, got %s", sendState)
	}
}

func TestManagerProcessAckForNonexistentStream(t *testing.T) {
	m := NewManager(false, 1048576, 65536, 65536, 65536, 10, 10)

	// Should not panic for nonexistent stream
	m.ProcessAckForStream(999, 100, true)
}
