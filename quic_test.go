package quic

import (
	"fmt"
	"net"
	"testing"
	"time"
)

func TestDefaultConfig(t *testing.T) {
	c := DefaultConfig()
	if c.MaxIdleTimeout != 30*time.Second {
		t.Errorf("expected 30s idle timeout, got %v", c.MaxIdleTimeout)
	}
	if c.MaxStreamData != 1<<20 {
		t.Errorf("expected 1MiB stream data, got %d", c.MaxStreamData)
	}
	if c.MaxConnectionData != 10<<20 {
		t.Errorf("expected 10MiB conn data, got %d", c.MaxConnectionData)
	}
	if c.MaxStreamsBidi != 100 {
		t.Errorf("expected 100 bidi streams, got %d", c.MaxStreamsBidi)
	}
	if c.ConnIDLength != 8 {
		t.Errorf("expected CID length 8, got %d", c.ConnIDLength)
	}
}

func TestToTransportParams(t *testing.T) {
	c := DefaultConfig()
	c.MaxIdleTimeout = 10 * time.Second
	tp := c.toTransportParams()
	if tp.MaxIdleTimeout != 10000 {
		t.Errorf("expected 10000ms, got %d", tp.MaxIdleTimeout)
	}
	if tp.InitialMaxData != 10<<20 {
		t.Errorf("expected 10MiB, got %d", tp.InitialMaxData)
	}
}

func TestListenAndDial(t *testing.T) {
	// Start a listener
	listener, err := Listen("udp", "127.0.0.1:0", &Config{
		MaxIdleTimeout:     5 * time.Second,
		MaxStreamData:      1 << 16,
		MaxConnectionData:  1 << 18,
		MaxStreamsBidi:     10,
		MaxStreamsUni:      10,
		ConnIDLength:       8,
	})
	if err != nil {
		t.Fatalf("Listen failed: %v", err)
	}
	defer listener.Close()

	addr := listener.Addr().(*net.UDPAddr)

	// Dial
	conn, err := Dial("udp", addr.String(), &Config{
		MaxIdleTimeout:     5 * time.Second,
		MaxStreamData:      1 << 16,
		MaxConnectionData:  1 << 18,
		MaxStreamsBidi:     10,
		MaxStreamsUni:      10,
		ConnIDLength:       8,
	})
	if err != nil {
		t.Fatalf("Dial failed: %v", err)
	}
	defer conn.Close()

	// Accept on server side
	serverConn, err := listener.Accept()
	if err != nil {
		t.Fatalf("Accept failed: %v", err)
	}
	defer serverConn.Close()

	if serverConn.IsClosed() {
		t.Error("server connection should not be closed")
	}

	if conn.IsClosed() {
		t.Error("client connection should not be closed")
	}
}

func TestStreamRoundTrip(t *testing.T) {
	// Set up listener and dialer
	listener, err := Listen("udp", "127.0.0.1:0", &Config{
		MaxIdleTimeout:     5 * time.Second,
		MaxStreamData:      1 << 16,
		MaxConnectionData:  1 << 18,
		MaxStreamsBidi:     10,
		MaxStreamsUni:      10,
		ConnIDLength:       8,
	})
	if err != nil {
		t.Fatalf("Listen failed: %v", err)
	}
	defer listener.Close()

	addr := listener.Addr().(*net.UDPAddr)

	// Dial
	clientConn, err := Dial("udp", addr.String(), &Config{
		MaxIdleTimeout:     5 * time.Second,
		MaxStreamData:      1 << 16,
		MaxConnectionData:  1 << 18,
		MaxStreamsBidi:     10,
		MaxStreamsUni:      10,
		ConnIDLength:       8,
	})
	if err != nil {
		t.Fatalf("Dial failed: %v", err)
	}
	defer clientConn.Close()

	// Accept on server
	serverConn, err := listener.Accept()
	if err != nil {
		t.Fatalf("Accept failed: %v", err)
	}
	defer serverConn.Close()

	// Give server time to process the initial
	time.Sleep(50 * time.Millisecond)

	// Client opens a bidirectional stream
	clientStream, err := clientConn.OpenStream()
	if err != nil {
		t.Fatalf("OpenStream failed: %v", err)
	}

	// Write data from client
	testData := []byte("Hello QUIC SDK!")
	n, err := clientStream.Write(testData)
	if err != nil {
		t.Fatalf("Write failed: %v", err)
	}
	if n != len(testData) {
		t.Fatalf("expected %d bytes written, got %d", len(testData), n)
	}

	// Server should accept the stream
	serverStream, err := serverConn.AcceptStream()
	if err != nil {
		t.Fatalf("AcceptStream failed: %v", err)
	}

	// Read data on server side
	buf := make([]byte, 1024)
	n, err = serverStream.Read(buf)
	if err != nil {
		t.Fatalf("Read failed: %v", err)
	}
	if string(buf[:n]) != string(testData) {
		t.Errorf("expected %q, got %q", string(testData), string(buf[:n]))
	}

	// Server sends data back on the same bidirectional stream
	replyData := []byte("Hi back from server!")
	n, err = serverStream.Write(replyData)
	if err != nil {
		t.Fatalf("Server Write failed: %v", err)
	}
	if n != len(replyData) {
		t.Fatalf("expected %d bytes written, got %d", len(replyData), n)
	}

	// Client reads the reply
	n, err = clientStream.Read(buf)
	if err != nil {
		t.Fatalf("Client Read failed: %v", err)
	}
	if string(buf[:n]) != string(replyData) {
		t.Errorf("expected %q, got %q", string(replyData), string(buf[:n]))
	}
}

func TestStreamCloseFIN(t *testing.T) {
	listener, err := Listen("udp", "127.0.0.1:0", nil)
	if err != nil {
		t.Fatalf("Listen failed: %v", err)
	}
	defer listener.Close()

	addr := listener.Addr().(*net.UDPAddr)

	clientConn, err := Dial("udp", addr.String(), nil)
	if err != nil {
		t.Fatalf("Dial failed: %v", err)
	}
	defer clientConn.Close()

	serverConn, err := listener.Accept()
	if err != nil {
		t.Fatalf("Accept failed: %v", err)
	}
	defer serverConn.Close()

	time.Sleep(50 * time.Millisecond)

	// Client opens stream, writes data, then closes (sends FIN)
	clientStream, err := clientConn.OpenStream()
	if err != nil {
		t.Fatalf("OpenStream failed: %v", err)
	}

	data := []byte("close test")
	clientStream.Write(data)
	clientStream.Close()

	// Server accepts stream
	serverStream, err := serverConn.AcceptStream()
	if err != nil {
		t.Fatalf("AcceptStream failed: %v", err)
	}

	// Read all data
	buf := make([]byte, 1024)
	n, _ := serverStream.Read(buf)
	if string(buf[:n]) != string(data) {
		t.Errorf("expected %q, got %q", string(data), string(buf[:n]))
	}
}

func TestMultipleStreams(t *testing.T) {
	listener, err := Listen("udp", "127.0.0.1:0", nil)
	if err != nil {
		t.Fatalf("Listen failed: %v", err)
	}
	defer listener.Close()

	addr := listener.Addr().(*net.UDPAddr)

	clientConn, err := Dial("udp", addr.String(), nil)
	if err != nil {
		t.Fatalf("Dial failed: %v", err)
	}
	defer clientConn.Close()

	serverConn, err := listener.Accept()
	if err != nil {
		t.Fatalf("Accept failed: %v", err)
	}
	defer serverConn.Close()

	time.Sleep(50 * time.Millisecond)

	// Open 5 streams
	for i := 0; i < 5; i++ {
		s, err := clientConn.OpenStream()
		if err != nil {
			t.Fatalf("OpenStream %d failed: %v", i, err)
		}
		msg := fmt.Sprintf("stream %d", i)
		s.Write([]byte(msg))
	}

	// Server should receive all 5
	for i := 0; i < 5; i++ {
		s, err := serverConn.AcceptStream()
		if err != nil {
			t.Fatalf("AcceptStream %d failed: %v", i, err)
		}
		buf := make([]byte, 1024)
		n, _ := s.Read(buf)
		if string(buf[:n]) != fmt.Sprintf("stream %d", i) {
			t.Errorf("stream %d: expected %q, got %q", i, fmt.Sprintf("stream %d", i), string(buf[:n]))
		}
	}
}

func TestUnidirectionalStream(t *testing.T) {
	listener, err := Listen("udp", "127.0.0.1:0", nil)
	if err != nil {
		t.Fatalf("Listen failed: %v", err)
	}
	defer listener.Close()

	addr := listener.Addr().(*net.UDPAddr)

	clientConn, err := Dial("udp", addr.String(), nil)
	if err != nil {
		t.Fatalf("Dial failed: %v", err)
	}
	defer clientConn.Close()

	serverConn, err := listener.Accept()
	if err != nil {
		t.Fatalf("Accept failed: %v", err)
	}
	defer serverConn.Close()

	time.Sleep(50 * time.Millisecond)

	// Client opens a unidirectional stream
	uniStream, err := clientConn.OpenUniStream()
	if err != nil {
		t.Fatalf("OpenUniStream failed: %v", err)
	}

	if uniStream.IsBidirectional() {
		t.Error("expected unidirectional stream")
	}

	data := []byte("one way data")
	uniStream.Write(data)
	uniStream.Close()

	// Server should accept
	serverStream, err := serverConn.AcceptStream()
	if err != nil {
		t.Fatalf("AcceptStream failed: %v", err)
	}

	buf := make([]byte, 1024)
	n, _ := serverStream.Read(buf)
	if string(buf[:n]) != string(data) {
		t.Errorf("expected %q, got %q", string(data), string(buf[:n]))
	}
}

func TestConnClose(t *testing.T) {
	listener, err := Listen("udp", "127.0.0.1:0", nil)
	if err != nil {
		t.Fatalf("Listen failed: %v", err)
	}
	defer listener.Close()

	addr := listener.Addr().(*net.UDPAddr)

	clientConn, err := Dial("udp", addr.String(), nil)
	if err != nil {
		t.Fatalf("Dial failed: %v", err)
	}

	serverConn, err := listener.Accept()
	if err != nil {
		t.Fatalf("Accept failed: %v", err)
	}
	defer serverConn.Close()

	time.Sleep(50 * time.Millisecond)

	// Close client
	clientConn.Close()
	time.Sleep(50 * time.Millisecond)

	if !clientConn.IsClosed() {
		t.Error("client should be closed")
	}
}

func TestConnAddr(t *testing.T) {
	listener, err := Listen("udp", "127.0.0.1:0", nil)
	if err != nil {
		t.Fatalf("Listen failed: %v", err)
	}
	defer listener.Close()

	if listener.Addr() == nil {
		t.Error("listener addr should not be nil")
	}

	addr := listener.Addr().(*net.UDPAddr)

	clientConn, err := Dial("udp", addr.String(), nil)
	if err != nil {
		t.Fatalf("Dial failed: %v", err)
	}
	defer clientConn.Close()

	if clientConn.LocalAddr() == nil {
		t.Error("client local addr should not be nil")
	}
	if clientConn.RemoteAddr() == nil {
		t.Error("client remote addr should not be nil")
	}
}

func TestListenerClose(t *testing.T) {
	listener, err := Listen("udp", "127.0.0.1:0", nil)
	if err != nil {
		t.Fatalf("Listen failed: %v", err)
	}

	err = listener.Close()
	if err != nil {
		t.Fatalf("Close failed: %v", err)
	}

	// Accept after close should return error
	_, err = listener.Accept()
	if err == nil {
		t.Error("expected error on Accept after Close")
	}
}

func TestStreamID(t *testing.T) {
	s := &Stream{id: 4, bidi: true}
	if s.ID() != 4 {
		t.Errorf("expected ID 4, got %d", s.ID())
	}
	if !s.IsBidirectional() {
		t.Error("expected bidirectional")
	}
}

func TestParseStreamFrame(t *testing.T) {
	// Build a STREAM frame manually
	// Type: 0x0e = 0b0000_1110 (STREAM with OFF=1, LEN=1, FIN=0)
	// Wait: 0x08 | 0x04 (OFF) | 0x02 (LEN) = 0x0e
	// Stream ID: 0 (varint 0x00)
	// Offset: 0 (varint 0x00)
	// Length: 5 (varint 0x05)
	// Data: "hello"

	frame := []byte{0x0e, 0x00, 0x00, 0x05, 'h', 'e', 'l', 'l', 'o'}

	s, consumed, err := parseStreamFrame(frame)
	if err != nil {
		t.Fatalf("parseStreamFrame failed: %v", err)
	}
	if consumed != len(frame) {
		t.Errorf("expected consumed %d, got %d", len(frame), consumed)
	}
	if s.StreamID != 0 {
		t.Errorf("expected stream ID 0, got %d", s.StreamID)
	}
	if s.Offset != 0 {
		t.Errorf("expected offset 0, got %d", s.Offset)
	}
	if string(s.Data) != "hello" {
		t.Errorf("expected 'hello', got %q", string(s.Data))
	}
	if s.FIN {
		t.Error("expected no FIN")
	}
}

func TestBuildConnectionCloseFrame(t *testing.T) {
	frame := buildConnectionCloseFrame(0, "test close")
	if len(frame) < 3 {
		t.Errorf("frame too short: %d", len(frame))
	}
	if frame[0] != 0x1c {
		t.Errorf("expected frame type 0x1c, got 0x%x", frame[0])
	}
}

func TestMatchBytes(t *testing.T) {
	if !matchBytes([]byte{1, 2, 3}, []byte{1, 2, 3}) {
		t.Error("expected match")
	}
	if matchBytes([]byte{1, 2}, []byte{1, 2, 3}) {
		t.Error("expected no match")
	}
	if matchBytes([]byte{1, 2, 3}, []byte{1, 2, 4}) {
		t.Error("expected no match")
	}
}

func TestNetMutex(t *testing.T) {
	m := newNetMutex()
	m.Lock()
	m.Unlock()

	// Should be able to lock again after unlock
	m.Lock()
	m.Unlock()
}

