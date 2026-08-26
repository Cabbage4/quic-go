package stream

import (
	"io"
	"testing"
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
