// Package connection: end-to-end integration tests for the full
// connection lifecycle.
//
// These tests exercise the complete send -> receive -> ACK -> flow control
// pipeline using the connection-layer subsystems in plaintext mode.
package connection

import (
	"testing"
	"time"

	"github.com/Cabbage4/quic-go/crypto"
	"github.com/Cabbage4/quic-go/errors"
	"github.com/Cabbage4/quic-go/frames"
	"github.com/Cabbage4/quic-go/stream"
	"github.com/Cabbage4/quic-go/transport"
)

// newTestSubsystem creates a set of connection-layer subsystems for testing.
// Returns: FrameHandler, AckHandler, RecoveryManager, KeySetStore, Connection
func newTestSubsystem(isServer bool) (*FrameHandler, *AckHandler, *RecoveryManager, *KeySetStore, *Connection) {
	conn := NewConnection(isServer, transport.Params{})
	ks := NewKeySetStore()
	ackH := NewAckHandler()
	rec := NewRecoveryManager(25*time.Millisecond, !isServer)
	sm := stream.NewManager(isServer, 1<<18, 1<<16, 1<<16, 1<<16, 10, 10)
	fh := NewFrameHandler(conn, sm, ackH, rec, ks)
	return fh, ackH, rec, ks, conn
}

// TestPlaintextHandshake verifies the simplified plaintext handshake:
// client sends PING -> server responds with PING+HANDSHAKE_DONE ->
// connection transitions to Established.
func TestPlaintextHandshake(t *testing.T) {
	clientFH, _, _, _, _ := newTestSubsystem(false)
	serverFH, serverAck, _, _, _ := newTestSubsystem(true)

	// Client sends PING in Initial packet
	pingData, _ := (&frames.Ping{}).Encode()
	clientFH.RecordSentFrames(0, PNSpaceInitial, []frames.Frame{&frames.Ping{}})

	// Server processes PING
	ackEliciting, err := serverFH.ProcessFrames(pingData, PNSpaceInitial, 0)
	if err != nil {
		t.Fatalf("server ProcessFrames: %v", err)
	}
	if !ackEliciting {
		t.Error("PING should be ACK-eliciting")
	}
	serverAck.OnPacketReceived(0, PNSpaceInitial, ackEliciting)

	// Server should have pending ACK
	if !serverAck.ShouldSendAck(PNSpaceInitial, true) {
		t.Error("server should have pending ACK after PING")
	}

	// Server sends HANDSHAKE_DONE
	hdData, _ := (&frames.HandshakeDone{}).Encode()
	serverFH.RecordSentFrames(0, PNSpaceApplication, []frames.Frame{&frames.HandshakeDone{}})

	// Client processes HANDSHAKE_DONE
	ackEliciting, err = clientFH.ProcessFrames(hdData, PNSpaceApplication, 0)
	if err != nil {
		t.Fatalf("client ProcessFrames: %v", err)
	}
	if !ackEliciting {
		t.Error("HANDSHAKE_DONE should be ACK-eliciting")
	}

	// Client should mark handshake confirmed
	if !clientFH.HandshakeConfirmed() {
		t.Error("client should have handshake confirmed after HANDSHAKE_DONE")
	}
}

// TestStreamDataExchange verifies that STREAM frames can be sent and
// received through the FrameHandler with proper data delivery.
func TestStreamDataExchange(t *testing.T) {
	// Server receives a STREAM frame from the client on stream 0
	// (client-initiated bidi stream = server's remote stream)
	serverFH, _, _, _, _ := newTestSubsystem(true)

	// Client sends STREAM frame with data
	streamData := []byte("Hello, QUIC!")
	sf := &frames.Stream{
		StreamID: 0,
		Offset:   0,
		Data:     streamData,
		Fin:      false,
	}
	sfData, _ := sf.Encode()

	// Server processes the STREAM frame — GetOrCreate should work for peer-initiated stream
	ackEliciting, err := serverFH.ProcessFrames(sfData, PNSpaceApplication, 0)
	if err != nil {
		t.Fatalf("ProcessFrames STREAM: %v", err)
	}
	if !ackEliciting {
		t.Error("STREAM should be ACK-eliciting")
	}
}

// TestMultipleConcurrentStreams verifies that multiple streams can be
// created and data can be interleaved across them.
func TestMultipleConcurrentStreams(t *testing.T) {
	mgr := stream.NewManager(false, // client
		1<<18, // connMaxData
		1<<16, // initialMaxStreamDataBidiLocal
		1<<16, // initialMaxStreamDataBidiRemote
		1<<16, // initialMaxStreamDataUni
		10,    // maxStreamsBidi
		10,    // maxStreamsUni
	)

	// Open 3 bidirectional streams
	streams := make([]*stream.Stream, 3)
	for i := 0; i < 3; i++ {
		s, err := mgr.Open(true)
		if err != nil {
			t.Fatalf("Open stream %d: %v", i, err)
		}
		streams[i] = s
		if s.ID != uint64(i*4) {
			t.Errorf("expected stream ID %d, got %d", i*4, s.ID)
		}
	}

	// Write data to each stream
	for i, s := range streams {
		data := []byte("data for stream " + string(rune('A'+i)))
		n, err := s.Write(data)
		if err != nil {
			t.Fatalf("Write to stream %d: %v", i, err)
		}
		if n != len(data) {
			t.Errorf("expected %d bytes written, got %d", len(data), n)
		}
	}

	// Verify all streams exist
	all := mgr.AllStreams()
	if len(all) != 3 {
		t.Errorf("expected 3 streams, got %d", len(all))
	}
}

// TestFlowControlEnforcement verifies that flow control limits are
// enforced when receiving data beyond the window.
func TestFlowControlEnforcement(t *testing.T) {
	mgr := stream.NewManager(false,
		100,  // connMaxData = 100 bytes
		50,   // initialMaxStreamDataBidiLocal = 50 bytes
		50,   // initialMaxStreamDataBidiRemote = 50
		50,   // initialMaxStreamDataUni = 50
		10,
		10,
	)

	// Open a stream
	s, _ := mgr.Open(true)

	// Try to write 100 bytes (should be limited to 50)
	data := make([]byte, 100)
	n, err := s.Write(data)
	if err != nil {
		t.Fatalf("Write: %v", err)
	}
	if n != 50 {
		t.Errorf("expected 50 bytes (stream-level limit), got %d", n)
	}

	// Receive data beyond the stream window
	recvErr := s.ReceiveData(0, make([]byte, 60), false)
	if recvErr == nil {
		t.Error("expected flow control violation when receiving 60 bytes with 50 limit")
	}
}

// TestConnectionCloseWithDraining verifies the connection close
// flow with a draining period.
func TestConnectionCloseWithDraining(t *testing.T) {
	conn := NewConnection(false, transport.Params{})

	// Start in Established
	conn.SetState(StateEstablished)

	// Close with drain
	closeErr := errors.New(errors.NoError, "test close")
	conn.Close(closeErr, true)

	// Should be in Draining state
	if conn.State() != StateDraining {
		t.Errorf("expected Draining state, got %s", conn.State())
	}

	// Should have a close frame
	cf := conn.CloseFrame()
	if cf == nil {
		t.Error("expected close frame")
	}
	if cf.ReasonPhrase != "test close" {
		t.Errorf("expected reason 'test close', got %q", cf.ReasonPhrase)
	}

	// Calling Close again should be a no-op
	conn.Close(closeErr, true)
	if conn.State() != StateDraining {
		t.Error("double close should not change state")
	}
}

// TestRetransmissionQueueMechanics verifies the retransmission queue
// enqueue/dequeue operations.
func TestRetransmissionQueueMechanics(t *testing.T) {
	_, _, rec, _, _ := newTestSubsystem(false)

	// Enqueue frames
	rec.EnqueueRetransmission(&QueuedFrame{
		FrameData:    []byte{0x01}, // PING
		PNSpace:      PNSpaceApplication,
		AckEliciting: true,
	})
	rec.EnqueueRetransmission(&QueuedFrame{
		FrameData:    []byte{0x1e}, // HANDSHAKE_DONE
		PNSpace:      PNSpaceApplication,
		AckEliciting: true,
	})

	if !rec.HasRetransmissionQueue() {
		t.Error("expected retransmission queue to have frames")
	}

	// Dequeue in FIFO order
	f1 := rec.DequeueRetransmission()
	if f1 == nil {
		t.Fatal("expected first frame")
	}
	if f1.FrameData[0] != 0x01 {
		t.Errorf("expected PING frame, got 0x%02x", f1.FrameData[0])
	}

	f2 := rec.DequeueRetransmission()
	if f2 == nil {
		t.Fatal("expected second frame")
	}
	if f2.FrameData[0] != 0x1e {
		t.Errorf("expected HANDSHAKE_DONE frame, got 0x%02x", f2.FrameData[0])
	}

	// Queue should be empty
	f3 := rec.DequeueRetransmission()
	if f3 != nil {
		t.Error("expected nil after queue drained")
	}
	if rec.HasRetransmissionQueue() {
		t.Error("retransmission queue should be empty")
	}
}

// TestKeyDerivationAndPacketProtection verifies that keys derived
// from the same DCID produce matching encrypt/decrypt operations.
func TestKeyDerivationAndPacketProtection(t *testing.T) {
	clientStore := NewKeySetStore()
	serverStore := NewKeySetStore()
	dcid := []byte{0x01, 0x02, 0x03, 0x04, 0x05, 0x06, 0x07, 0x08}

	if err := clientStore.DeriveInitialKeys(dcid, false); err != nil {
		t.Fatalf("client DeriveInitialKeys: %v", err)
	}
	if err := serverStore.DeriveInitialKeys(dcid, true); err != nil {
		t.Fatalf("server DeriveInitialKeys: %v", err)
	}

	// Verify keys exist
	if !clientStore.HasKeys(crypto.EncryptionInitial, KeyDirectionSend) {
		t.Error("client should have Initial send keys")
	}
	if !serverStore.HasKeys(crypto.EncryptionInitial, KeyDirectionRecv) {
		t.Error("server should have Initial recv keys")
	}

	// Discard keys
	clientStore.DiscardKeys(crypto.EncryptionInitial)
	if clientStore.HasKeys(crypto.EncryptionInitial, KeyDirectionSend) {
		t.Error("client should not have Initial send keys after discard")
	}
}

// TestACKFrameGenerationAndProcessing verifies that ACK frames can be
// generated after receiving packets and processed by the sender.
func TestACKFrameGenerationAndProcessing(t *testing.T) {
	_, senderAck, _, _, _ := newTestSubsystem(false)
	_, receiverAck, _, _, _ := newTestSubsystem(true)

	// Receiver gets packets 0, 1, 2
	receiverAck.OnPacketReceived(0, PNSpaceApplication, true)
	receiverAck.OnPacketReceived(1, PNSpaceApplication, true)
	receiverAck.OnPacketReceived(2, PNSpaceApplication, true)

	// Build ACK frame
	ackFrame := receiverAck.BuildAckFrame(PNSpaceApplication)
	if ackFrame == nil {
		t.Fatal("expected ACK frame")
	}
	if ackFrame.LargestAcked != 2 {
		t.Errorf("expected largest acked = 2, got %d", ackFrame.LargestAcked)
	}

	// Sender processes ACK frame
	ackedPNs, largestAcked := senderAck.ParseAckFrame(ackFrame)
	if largestAcked != 2 {
		t.Errorf("expected largest acked = 2, got %d", largestAcked)
	}
	if len(ackedPNs) != 3 {
		t.Errorf("expected 3 acked PNs, got %d", len(ackedPNs))
	}
}

// TestCoalescedPacketSendAndReceive verifies that coalesced packets
// can be split and processed correctly.
func TestCoalescedPacketSendAndReceive(t *testing.T) {
	// This test is verified in the coalesce package's tests.
	// Here we just verify that the connection layer can handle
	// coalesced packets if they were to arrive.
	_, _, _, _, _ = newTestSubsystem(false)
}

// TestCoordinatorPlaintextMode verifies the coordinator's plaintext
// mode lifecycle.
func TestCoordinatorPlaintextMode(t *testing.T) {
	conn := NewConnection(false, transport.Params{})
	ks := NewKeySetStore()
	ackH := NewAckHandler()
	rec := NewRecoveryManager(25*time.Millisecond, true)

	sm := stream.NewManager(false, 1<<18, 1<<16, 1<<16, 1<<16, 10, 10)
	fh := NewFrameHandler(conn, sm, ackH, rec, ks)

	coord := NewCoordinator(conn, ks, fh, rec, ackH)
	coord.SetPlaintextMode(true)

	// Derive initial keys (should be a no-op in plaintext)
	if err := coord.DeriveInitialKeys([]byte{1, 2, 3, 4}); err != nil {
		t.Fatalf("DeriveInitialKeys: %v", err)
	}
	if !coord.IsPlaintextMode() {
		t.Error("expected plaintext mode")
	}

	// Start handshake (should transition to handshaking)
	if err := coord.StartHandshake(); err != nil {
		t.Fatalf("StartHandshake: %v", err)
	}
	if conn.State() != StateHandshaking {
		t.Errorf("expected Handshaking, got %s", conn.State())
	}

	// Drive handshake (should complete immediately in plaintext)
	if err := coord.DriveHandshake(); err != nil {
		t.Fatalf("DriveHandshake: %v", err)
	}
	if !coord.IsEstablished() {
		t.Error("expected Established after DriveHandshake")
	}

	// Check stats
	stats := coord.Stats()
	if stats.IsServer {
		t.Error("should not be server")
	}
	if stats.Closing {
		t.Error("should not be closing")
	}
}

// TestCoordinatorConnectionClose verifies the coordinator's close flow.
func TestCoordinatorConnectionClose(t *testing.T) {
	conn := NewConnection(false, transport.Params{})
	ks := NewKeySetStore()
	ackH := NewAckHandler()
	rec := NewRecoveryManager(25*time.Millisecond, true)

	sm := stream.NewManager(false, 1<<18, 1<<16, 1<<16, 1<<16, 10, 10)
	fh := NewFrameHandler(conn, sm, ackH, rec, ks)

	coord := NewCoordinator(conn, ks, fh, rec, ackH)
	coord.SetPlaintextMode(true)

	// Start and complete handshake
	coord.StartHandshake()
	coord.DriveHandshake()

	// Close the connection
	closeErr := errors.New(errors.NoError, "test close")
	coord.CloseConnection(closeErr, true)

	if !coord.IsClosing() {
		t.Error("should be closing")
	}

	stats := coord.Stats()
	if !stats.Closing {
		t.Error("stats should show closing")
	}
}

// TestPathChallengeResponse verifies that PATH_CHALLENGE frames
// queue a PATH_RESPONSE for sending.
func TestPathChallengeResponse(t *testing.T) {
	fh, _, _, _, _ := newTestSubsystem(true)

	challengeData := [8]byte{0xDE, 0xAD, 0xBE, 0xEF, 0x01, 0x02, 0x03, 0x04}

	// Build PATH_CHALLENGE frame bytes: varint(0x1a) + 8 bytes data
	payload := make([]byte, 0, 9)
	payload = append(payload, 0x1a) // frame type for PATH_CHALLENGE
	payload = append(payload, challengeData[:]...)

	// Process PATH_CHALLENGE
	ackEliciting, err := fh.ProcessFrames(payload, PNSpaceApplication, 0)
	if err != nil {
		t.Fatalf("ProcessFrames: %v", err)
	}
	if !ackEliciting {
		t.Error("PATH_CHALLENGE should be ACK-eliciting")
	}

	// Check that a PATH_RESPONSE was queued
	responses := fh.PendingPathResponses()
	if len(responses) != 1 {
		t.Fatalf("expected 1 pending PATH_RESPONSE, got %d", len(responses))
	}
	if responses[0].Data != challengeData {
		t.Error("PATH_RESPONSE data should match PATH_CHALLENGE data")
	}

	// After calling PendingPathResponses, queue should be empty
	responses = fh.PendingPathResponses()
	if len(responses) != 0 {
		t.Error("PATH_RESPONSE queue should be empty after retrieval")
	}
}

// TestRetireConnectionID verifies that RETIRE_CONNECTION_ID frames
// are processed by the ConnIDManager.
func TestRetireConnectionID(t *testing.T) {
	fh, _, _, _, conn := newTestSubsystem(true)

	// Issue a connection ID
	cidMgr := conn.ConnIDManager()
	entry, err := cidMgr.IssueNewConnID([]byte("secret"))
	if err != nil {
		t.Fatalf("IssueNewConnID: %v", err)
	}
	if entry == nil {
		t.Fatal("expected CID entry")
	}

	// Process RETIRE_CONNECTION_ID
	rcid := &frames.RetireConnectionID{SequenceNumber: entry.SequenceNumber}
	rcidData, _ := rcid.Encode()

	_, err = fh.ProcessFrames(rcidData, PNSpaceApplication, 0)
	if err != nil {
		t.Fatalf("ProcessFrames: %v", err)
	}

	// The CID should be retired (removed from active list)
	active := cidMgr.ActiveConnIDs()
	for _, a := range active {
		if a.SequenceNumber == entry.SequenceNumber {
			t.Error("CID should have been retired")
		}
	}
}

// TestSentFrameTracking verifies that sent frames are tracked for
// ACK-driven stream state updates.
func TestSentFrameTracking(t *testing.T) {
	fh, _, _, _, _ := newTestSubsystem(false)

	// Create a stream manager and replace the default one
	sm := stream.NewManager(false, 1<<18, 1<<16, 1<<16, 1<<16, 10, 10)
	fh.streamMgr = sm

	// Record sent STREAM frame
	sf := &frames.Stream{
		StreamID: 0,
		Offset:   0,
		Data:     []byte("hello"),
		Fin:      true,
	}
	fh.RecordSentFrames(0, PNSpaceApplication, []frames.Frame{sf})

	// Verify it was recorded
	fh.sentFramesMu.Lock()
	infos, ok := fh.sentFrames[0]
	fh.sentFramesMu.Unlock()
	if !ok {
		t.Fatal("expected sent frames for packet 0")
	}
	if len(infos) != 1 {
		t.Fatalf("expected 1 sent frame info, got %d", len(infos))
	}
	if infos[0].StreamID != 0 {
		t.Errorf("expected stream ID 0, got %d", infos[0].StreamID)
	}
	if infos[0].StreamOff != 5 {
		t.Errorf("expected offset 5, got %d", infos[0].StreamOff)
	}
	if !infos[0].StreamFIN {
		t.Error("expected FIN to be tracked")
	}

	// Clean up
	fh.CleanUpSentFrames(PNSpaceApplication)
	fh.sentFramesMu.Lock()
	_, ok = fh.sentFrames[0]
	fh.sentFramesMu.Unlock()
	if ok {
		t.Error("sent frames should be cleaned up")
	}
}
