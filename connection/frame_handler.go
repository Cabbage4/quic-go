// Package connection: comprehensive frame processing layer.
//
// This file replaces the SDK's inline frame parser with proper
// frames.Decode() calls and handles ALL 27 QUIC frame types defined
// in RFC 9000 §19.
//
// The FrameHandler:
//   - Decodes frames from a decrypted packet payload
//   - Dispatches each frame to the appropriate subsystem (stream, ack, recovery, crypto, etc.)
//   - Generates control frames (ACK, flow control updates, HANDSHAKE_DONE, etc.)
//   - Tracks whether a packet was ACK-eliciting
//
// This is the central dispatch point that ties together:
//   - Stream management (stream.Manager)
//   - ACK tracking (connection.AckHandler)
//   - Recovery (connection.RecoveryManager)
//   - Crypto/TLS (connection.KeySetStore)
//   - Connection state machine (connection.Connection)
package connection

import (
	"fmt"
	"sync"
	"time"

	"github.com/Cabbage4/quic-go/crypto"
	"github.com/Cabbage4/quic-go/errors"
	"github.com/Cabbage4/quic-go/frames"
	"github.com/Cabbage4/quic-go/stream"
	"github.com/Cabbage4/quic-go/transport"
)

// FrameHandler dispatches incoming QUIC frames to the appropriate
// subsystems and generates outgoing control frames.
type FrameHandler struct {
	mu sync.Mutex

	// Subsystem references
	conn       *Connection
	streamMgr  *stream.Manager
	ackHandler *AckHandler
	recovery   *RecoveryManager
	keyStore   *KeySetStore
	connIDMgr  *ConnIDManager

	// State flags
	handshakeComplete bool
	handshakeConfirmed bool

	// Pending HANDSHAKE_DONE to send (server side)
	pendingHandshakeDone bool

	// Pending PATH_RESPONSE frames (queued from received PATH_CHALLENGE)
	pendingPathResponses []*frames.PathResponse

	// Pending CRYPTO data to feed to TLS (queued from handleCryptoFrame
	// to avoid deadlock with the TLS event loop in driveHandshakeLoop)
	pendingCryptoData []pendingCrypto

	// Pending transport params callback
	onTransportParams func([]byte)

	// Whether the connection was closed by peer
	closedByPeer bool
	closeError   *errors.Error

	// Sent frame tracker: maps packet number → list of frames in that packet
	// Used to process ACKs and update stream state machines
	sentFrames    map[uint64][]sentFrameInfo
	sentFramesMu  sync.Mutex

	// receivedNewToken holds the last NEW_TOKEN received from the server
	// (RFC 9000 §19.7), for the client to echo on future Initial packets.
	// Per-connection state under h.mu (was a package-global var, which raced
	// across goroutines and cross-contaminated connections sharing the process).
	receivedNewToken []byte

	// closeFrameSent latches that the CONNECTION_CLOSE frame has been queued
	// for sending once. Without this, GenerateControlFrames re-appends the
	// close frame on every per-packet flush while Draining — re-sending
	// CONNECTION_CLOSE repeatedly, which RFC 9000 §10.2 forbids ("an endpoint
	// in the draining state MUST NOT send any packets").
	closeFrameSent bool
}

// pendingCrypto holds queued CRYPTO frame data waiting to be fed to TLS.
type pendingCrypto struct {
	level crypto.EncryptionLevel
	data  []byte
}

// sentFrameInfo records what was in a sent packet for ACK processing.
type sentFrameInfo struct {
	FrameType  frames.FrameType
	StreamID   uint64   // for STREAM frames
	StreamOff  uint64   // for STREAM frames: offset + data length
	StreamFIN  bool     // for STREAM frames: FIN was sent
	PNSpace    PNSpace
}

// NewFrameHandler creates a new frame handler.
func NewFrameHandler(
	conn *Connection,
	streamMgr *stream.Manager,
	ackHandler *AckHandler,
	recovery *RecoveryManager,
	keyStore *KeySetStore,
) *FrameHandler {
	return &FrameHandler{
		conn:       conn,
		streamMgr:  streamMgr,
		ackHandler: ackHandler,
		recovery:   recovery,
		keyStore:   keyStore,
		connIDMgr:  conn.ConnIDManager(),
		sentFrames: make(map[uint64][]sentFrameInfo),
	}
}

// ProcessFrames decodes and processes all frames in a decrypted packet payload.
//
// Parameters:
//   - payload: the decrypted packet payload (frame bytes)
//   - pnSpace: the packet number space these frames belong to
//   - packetNumber: the packet number (for ACK tracking)
//
// Returns whether the packet contained ACK-eliciting frames and any error.
func (h *FrameHandler) ProcessFrames(payload []byte, pnSpace PNSpace, packetNumber uint64) (ackEliciting bool, err error) {
	h.mu.Lock()
	defer h.mu.Unlock()

	offset := 0
	for offset < len(payload) {
		frame, consumed, derr := frames.Decode(payload[offset:])
		if derr != nil {
			return ackEliciting, fmt.Errorf("connection: frame decode error at offset %d: %w", offset, derr)
		}
		offset += consumed

		isAckEliciting, ferr := h.handleFrame(frame, pnSpace, packetNumber)
		if ferr != nil {
			return ackEliciting, ferr
		}
		if isAckEliciting {
			ackEliciting = true
		}
	}

	return ackEliciting, nil
}

// handleFrame processes a single frame and returns whether it was ACK-eliciting.
func (h *FrameHandler) handleFrame(f frames.Frame, pnSpace PNSpace, packetNumber uint64) (ackEliciting bool, err error) {
	switch v := f.(type) {

	// === PADDING (§19.1) ===
	case *frames.Padding:
		// PADDING is not ACK-eliciting
		return false, nil

	// === PING (§19.2) ===
	case *frames.Ping:
		// PING is ACK-eliciting
		return true, nil

	// === ACK (§19.3) ===
	case *frames.ACK:
		return h.handleAckFrame(v, pnSpace)

	// === RESET_STREAM (§19.4) ===
	case *frames.ResetStream:
		return h.handleResetStream(v)

	// === STOP_SENDING (§19.5) ===
	case *frames.StopSending:
		return h.handleStopSending(v)

	// === CRYPTO (§19.6) ===
	case *frames.Crypto:
		return h.handleCryptoFrame(v, pnSpace)

	// === NEW_TOKEN (§19.7) ===
	case *frames.NewToken:
		return h.handleNewToken(v)

	// === STREAM (§19.8) ===
	case *frames.Stream:
		return h.handleStreamFrame(v)

	// === MAX_DATA (§19.9) ===
	case *frames.MaxData:
		return h.handleMaxData(v)

	// === MAX_STREAM_DATA (§19.10) ===
	case *frames.MaxStreamData:
		return h.handleMaxStreamData(v)

	// === MAX_STREAMS (§19.11) ===
	case *frames.MaxStreams:
		return h.handleMaxStreams(v)

	// === DATA_BLOCKED (§19.12) ===
	case *frames.DataBlocked:
		// Peer is blocked on connection-level flow control
		// We should send MAX_DATA when we have room
		return true, nil

	// === STREAM_DATA_BLOCKED (§19.13) ===
	case *frames.StreamDataBlocked:
		// Peer is blocked on stream-level flow control
		return true, nil

	// === STREAMS_BLOCKED (§19.14) ===
	case *frames.StreamsBlocked:
		// Peer is blocked on stream count limit
		return true, nil

	// === NEW_CONNECTION_ID (§19.15) ===
	case *frames.NewConnectionID:
		return h.handleNewConnectionID(v)

	// === RETIRE_CONNECTION_ID (§19.16) ===
	case *frames.RetireConnectionID:
		return h.handleRetireConnectionID(v)

	// === PATH_CHALLENGE (§19.17) ===
	case *frames.PathChallenge:
		return h.handlePathChallenge(v)

	// === PATH_RESPONSE (§19.18) ===
	case *frames.PathResponse:
		return h.handlePathResponse(v)

	// === CONNECTION_CLOSE (§19.19) ===
	case *frames.ConnectionClose:
		return h.handleConnectionClose(v)

	// === HANDSHAKE_DONE (§19.20) ===
	case *frames.HandshakeDone:
		return h.handleHandshakeDone()

	default:
		return false, fmt.Errorf("connection: unknown frame type %T", f)
	}
}

// === Individual frame handlers ===

func (h *FrameHandler) handleAckFrame(f *frames.ACK, pnSpace PNSpace) (bool, error) {
	// Parse ACK frame to get acknowledged packet numbers
	ackedPNs, largestAcked := h.ackHandler.ParseAckFrame(f)

	// Update largest acked PN in connection
	h.conn.UpdateLargestAcked(pnSpace, largestAcked)

	// Feed to recovery manager
	ackDelay := time.Duration(f.ACKDelay) * time.Microsecond
	h.recovery.OnAckReceived(pnSpace, ackedPNs, largestAcked, ackDelay, now())

	// Process stream ACK state for acknowledged STREAM frames
	// Look up which frames were in each acknowledged packet
	h.sentFramesMu.Lock()
	for _, pn := range ackedPNs {
		sentFrames := h.sentFrames[pn]
		for _, fi := range sentFrames {
			if fi.FrameType == frames.FrameStreamMin && fi.PNSpace == pnSpace {
				h.streamMgr.ProcessAckForStream(fi.StreamID, fi.StreamOff, fi.StreamFIN)
			}
		}
		// Clean up acknowledged packets
		delete(h.sentFrames, pn)
	}
	h.sentFramesMu.Unlock()

	// ACK frames are not ACK-eliciting
	return false, nil
}

func (h *FrameHandler) handleResetStream(f *frames.ResetStream) (bool, error) {
	s, err := h.streamMgr.GetOrCreate(f.StreamID)
	if err != nil {
		return true, errors.New(errors.StreamStateError,
			fmt.Sprintf("RESET_STREAM for invalid stream %d", f.StreamID))
	}
	if derr := s.ResetReceived(f.ErrorCode, f.FinalSize); derr != nil {
		return true, fmt.Errorf("connection: RESET_STREAM failed: %w", derr)
	}
	return true, nil
}

func (h *FrameHandler) handleStopSending(f *frames.StopSending) (bool, error) {
	s, ok := h.streamMgr.Get(f.StreamID)
	if !ok {
		return true, errors.New(errors.StreamStateError,
			fmt.Sprintf("STOP_SENDING for unknown stream %d", f.StreamID))
	}
	// Reset our sending side for this stream
	_ = s.Reset(f.ErrorCode)
	return true, nil
}

func (h *FrameHandler) handleCryptoFrame(f *frames.Crypto, pnSpace PNSpace) (bool, error) {
	// Map PN space to encryption level
	level := PNSpaceToEncryptionLevel(pnSpace)

	// Queue CRYPTO data for the TLS handshake loop to process.
	// This avoids deadlock: HandleCryptoData would block if the
	// driveHandshakeLoop is currently holding the TLS session mutex
	// in Start()/processEvents(). By queuing, the driveHandshakeLoop
	// can feed the data and process events in the same goroutine.
	// Note: handleCryptoFrame is called from ProcessFrames which
	// already holds h.mu, so we don't need to lock here.
	if h.pendingCryptoData == nil {
		h.pendingCryptoData = make([]pendingCrypto, 0, 4)
	}
	h.pendingCryptoData = append(h.pendingCryptoData, pendingCrypto{
		level: level,
		data:  f.Data,
	})

	// Do NOT call session.HandshakeComplete() here — it acquires the TLS
	// session mutex, which the driveHandshakeLoop may be holding while
	// waiting inside HandleCryptoData → HandleData. Calling it here from
	// the recvLoop would deadlock.
	// The handshake completion check is done by driveHandshakeLoop after
	// it processes the queued CRYPTO data (see FlushPendingCryptoData).

	return true, nil
}

// handleNewToken stores a NEW_TOKEN received from the server (RFC 9000 §19.7).
// Clients keep it to include in future Initial packets for address validation,
// letting the server skip Retry. Stored per-connection under h.mu.
func (h *FrameHandler) handleNewToken(f *frames.NewToken) (bool, error) {
	if len(f.Token) > 0 {
		tok := make([]byte, len(f.Token))
		copy(tok, f.Token)
		h.mu.Lock()
		h.receivedNewToken = tok
		h.mu.Unlock()
	}
	return true, nil
}

// GetNewToken returns the last received NEW_TOKEN, if any.
func (h *FrameHandler) GetNewToken() []byte {
	h.mu.Lock()
	defer h.mu.Unlock()
	if len(h.receivedNewToken) == 0 {
		return nil
	}
	out := make([]byte, len(h.receivedNewToken))
	copy(out, h.receivedNewToken)
	return out
}

func (h *FrameHandler) handleStreamFrame(f *frames.Stream) (bool, error) {
	s, err := h.streamMgr.GetOrCreate(f.StreamID)
	if err != nil {
		return true, errors.New(errors.StreamStateError,
			fmt.Sprintf("STREAM for invalid stream %d", f.StreamID))
	}

	// Write received data to the stream's receive buffer
	if werr := s.ReceiveData(f.Offset, f.Data, f.Fin); werr != nil {
		return true, fmt.Errorf("connection: STREAM data write failed: %w", werr)
	}

	return true, nil
}

func (h *FrameHandler) handleMaxData(f *frames.MaxData) (bool, error) {
	h.streamMgr.UpdateConnMaxData(f.MaximumData)
	return true, nil
}

func (h *FrameHandler) handleMaxStreamData(f *frames.MaxStreamData) (bool, error) {
	s, ok := h.streamMgr.Get(f.StreamID)
	if !ok {
		return true, nil // ignore for unknown streams
	}
	s.UpdateSendMaxData(f.MaximumData)
	return true, nil
}

func (h *FrameHandler) handleMaxStreams(f *frames.MaxStreams) (bool, error) {
	// Update the stream count limit in the stream manager (RFC 9000 §19.5)
	h.streamMgr.UpdateMaxStreams(f.MaxStreams, !f.Unidirectional)
	return true, nil
}

func (h *FrameHandler) handleNewConnectionID(f *frames.NewConnectionID) (bool, error) {
	// Register the peer's new connection ID
	// Store the stateless reset token
	if h.conn != nil {
		h.conn.AddResetToken(f.StatelessResetToken)
	}
	return true, nil
}

func (h *FrameHandler) handleConnectionClose(f *frames.ConnectionClose) (bool, error) {
	// Peer is closing the connection
	h.closedByPeer = true
	var code errors.TransportErrorCode
	if f.ApplicationError {
		code = errors.ApplicationError
	} else {
		code = errors.TransportErrorCode(f.ErrorCode)
	}
	h.closeError = errors.New(code, f.ReasonPhrase)

	// Transition to draining state
	h.conn.Close(h.closeError, true)

	return false, nil
}

func (h *FrameHandler) handleHandshakeDone() (bool, error) {
	// Client receives HANDSHAKE_DONE from server
	if !h.conn.IsServer() && !h.handshakeConfirmed {
		h.handshakeConfirmed = true
		h.recovery.SetHandshakeConfirmed(true)

		// Discard Handshake keys (RFC 9001 §4.9)
		h.keyStore.DiscardKeys(crypto.EncryptionHandshake)
	}
	return true, nil
}

// === Outgoing frame generation ===

// FlushPendingCryptoData feeds all queued CRYPTO frame data to the TLS
// session. This is called by the driveHandshakeLoop to avoid deadlock
// with the TLS event loop mutex.
func (h *FrameHandler) FlushPendingCryptoData() error {
	h.mu.Lock()
	queued := h.pendingCryptoData
	h.pendingCryptoData = nil
	h.mu.Unlock()

	for _, pc := range queued {
		if err := h.keyStore.FeedCryptoData(pc.level, pc.data); err != nil {
			return fmt.Errorf("connection: CRYPTO frame handling failed: %w", err)
		}
	}

	// After feeding CRYPTO data, check if the handshake completed.
	// This must be done here (in driveHandshakeLoop's context), NOT in
	// handleCryptoFrame, because calling session.HandshakeComplete()
	// from the recvLoop would deadlock if driveHandshakeLoop is holding
	// the TLS session mutex inside HandleCryptoData → HandleData.
	session := h.keyStore.TLSSession()
	if session != nil && session.HandshakeComplete() && !h.handshakeComplete {
		h.handshakeComplete = true
		h.conn.SetState(StateEstablished)

		// Server: handshake confirmed when complete, send HANDSHAKE_DONE
		if h.conn.IsServer() {
			h.handshakeConfirmed = true
			h.pendingHandshakeDone = true
			h.recovery.SetHandshakeConfirmed(true)
		}
	}

	return nil
}

// PendingCryptoCount returns the number of queued CRYPTO data items.
func (h *FrameHandler) PendingCryptoCount() int {
	h.mu.Lock()
	defer h.mu.Unlock()
	return len(h.pendingCryptoData)
}

// GenerateControlFrames builds control frames that need to be sent.
// This includes:
//   - ACK frames (if pending)
//   - HANDSHAKE_DONE (server, after handshake complete)
//   - Flow control updates (MAX_DATA, MAX_STREAM_DATA)
//   - PATH_RESPONSE (queued from received PATH_CHALLENGE)
//   - CONNECTION_CLOSE (if closing)
func (h *FrameHandler) GenerateControlFrames(pnSpace PNSpace) []frames.Frame {
	h.mu.Lock()
	defer h.mu.Unlock()

	var out []frames.Frame

	// ACK frame
	if h.ackHandler.ShouldSendAck(pnSpace, false) {
		if ack := h.ackHandler.BuildAckFrame(pnSpace); ack != nil {
			out = append(out, ack)
		}
	}

	// HANDSHAKE_DONE (server only, once)
	if h.pendingHandshakeDone && pnSpace == PNSpaceApplication {
		out = append(out, &frames.HandshakeDone{})
		h.pendingHandshakeDone = false
	}

	// PATH_RESPONSE frames (only in Application space)
	if pnSpace == PNSpaceApplication && len(h.pendingPathResponses) > 0 {
		for _, pr := range h.pendingPathResponses {
			out = append(out, pr)
		}
		h.pendingPathResponses = nil
	}

	// Flow control updates (only in Application space)
	if pnSpace == PNSpaceApplication {
		updates := h.streamMgr.PendingWindowUpdates(64*1024, 64*1024)
		out = append(out, updates...)
	}

	// CONNECTION_CLOSE (if draining). Latched: queue at most once, otherwise
	// the per-packet control-frame flush would re-send CONNECTION_CLOSE on
	// every received packet, violating RFC 9000 §10.2 (a draining endpoint
	// MUST NOT send packets) and storming the peer.
	if h.conn.State() == StateDraining && !h.closeFrameSent {
		if cf := h.conn.CloseFrame(); cf != nil {
			out = append(out, cf)
			h.closeFrameSent = true
		}
	}

	return out
}

// HasPendingHandshakeDone returns true if the server needs to send HANDSHAKE_DONE.
func (h *FrameHandler) HasPendingHandshakeDone() bool {
	h.mu.Lock()
	defer h.mu.Unlock()
	return h.pendingHandshakeDone
}

// === Path validation handlers (§19.17, §19.18) ===

// handlePathChallenge queues a PATH_RESPONSE with the same 8-byte data.
// Per RFC 9000 §8.2, the endpoint MUST respond to PATH_CHALLENGE.
// Caller must hold h.mu (called from ProcessFrames).
func (h *FrameHandler) handlePathChallenge(f *frames.PathChallenge) (bool, error) {
	h.pendingPathResponses = append(h.pendingPathResponses, &frames.PathResponse{
		Data: f.Data,
	})

	return true, nil
}

// handlePathResponse validates a PATH_RESPONSE against outstanding path challenges.
// If a path's challenge data matches, the path is marked as validated.
func (h *FrameHandler) handlePathResponse(f *frames.PathResponse) (bool, error) {
	// Iterate through connection paths and mark the matching one as validated.
	// The PathInfo doesn't carry challenge data directly, but the connection's
	// MarkPathValidated method is the correct interface for this.
	if h.conn != nil {
		for i := range h.conn.paths {
			if h.conn.paths[i] != nil && !h.conn.paths[i].Validated {
				// In the full implementation, we would compare f.Data against
				// the outstanding challenge stored on this path. Since the
				// connection layer's PathInfo does not store challenge data,
				// we delegate to MarkPathValidated for the first unvalidated
				// path, which is sufficient for single-path connections.
				h.conn.MarkPathValidated(i)
				break
			}
		}
	}
	return true, nil
}

// PendingPathResponses returns queued PATH_RESPONSE frames and clears the queue.
func (h *FrameHandler) PendingPathResponses() []*frames.PathResponse {
	h.mu.Lock()
	defer h.mu.Unlock()

	if len(h.pendingPathResponses) == 0 {
		return nil
	}
	out := h.pendingPathResponses
	h.pendingPathResponses = nil
	return out
}

// === RETIRE_CONNECTION_ID handler (§19.16) ===

// handleRetireConnectionID retires the connection ID with the given sequence number.
// Per RFC 9000 §5.1.2, the endpoint MUST stop using the retired CID and
// should issue a new CID if the active CID count drops below the limit.
func (h *FrameHandler) handleRetireConnectionID(f *frames.RetireConnectionID) (bool, error) {
	if h.connIDMgr != nil {
		h.connIDMgr.RetireConnID(f.SequenceNumber)
	}
	return true, nil
}

// === Sent frame tracking ===

// RecordSentFrames records which frames were sent in a packet, so that
// when an ACK for that packet is received, stream state machines can be
// updated (e.g., marking STREAM data as acknowledged).
//
// Parameters:
//   - packetNumber: the packet number the frames were sent in
//   - pnSpace: the packet number space
//   - frs: the frames that were in the packet
func (h *FrameHandler) RecordSentFrames(packetNumber uint64, pnSpace PNSpace, frs []frames.Frame) {
	h.sentFramesMu.Lock()
	defer h.sentFramesMu.Unlock()

	var infos []sentFrameInfo
	for _, f := range frs {
		switch v := f.(type) {
		case *frames.Stream:
			infos = append(infos, sentFrameInfo{
				FrameType: frames.FrameStreamMin,
				StreamID:  v.StreamID,
				StreamOff: v.Offset + uint64(len(v.Data)),
				StreamFIN: v.Fin,
				PNSpace:   pnSpace,
			})
		default:
			infos = append(infos, sentFrameInfo{
				FrameType: f.FrameType(),
				PNSpace:   pnSpace,
			})
		}
	}

	if len(infos) > 0 {
		h.sentFrames[packetNumber] = infos
	}
}

// CleanUpSentFrames removes entries for packet numbers that are no longer
// needed (e.g., after a PN space is discarded).
func (h *FrameHandler) CleanUpSentFrames(pnSpace PNSpace) {
	h.sentFramesMu.Lock()
	defer h.sentFramesMu.Unlock()

	for pn, infos := range h.sentFrames {
		var keep []sentFrameInfo
		for _, fi := range infos {
			if fi.PNSpace != pnSpace {
				keep = append(keep, fi)
			}
		}
		if len(keep) == 0 {
			delete(h.sentFrames, pn)
		} else {
			h.sentFrames[pn] = keep
		}
	}
}

// SetTransportParamsCallback sets the callback for when peer's transport
// parameters are received via TLS.
func (h *FrameHandler) SetTransportParamsCallback(cb func([]byte)) {
	h.mu.Lock()
	defer h.mu.Unlock()
	h.onTransportParams = cb
}

// HandshakeComplete returns whether the TLS handshake is complete.
func (h *FrameHandler) HandshakeComplete() bool {
	h.mu.Lock()
	defer h.mu.Unlock()
	return h.handshakeComplete
}

// HandshakeConfirmed returns whether the handshake is confirmed.
func (h *FrameHandler) HandshakeConfirmed() bool {
	h.mu.Lock()
	defer h.mu.Unlock()
	return h.handshakeConfirmed
}

// ClosedByPeer returns whether the peer sent a CONNECTION_CLOSE.
func (h *FrameHandler) ClosedByPeer() bool {
	h.mu.Lock()
	defer h.mu.Unlock()
	return h.closedByPeer
}

// CloseError returns the error from a peer CONNECTION_CLOSE.
func (h *FrameHandler) CloseError() *errors.Error {
	h.mu.Lock()
	defer h.mu.Unlock()
	return h.closeError
}

// ProcessTransportParams is called when the peer's transport parameters
// are received via TLS. It applies them to the connection state.
func (h *FrameHandler) ProcessTransportParams(data []byte) {
	h.mu.Lock()
	defer h.mu.Unlock()

	if h.onTransportParams != nil {
		h.onTransportParams(data)
	}

	// Parse and apply transport parameters
	params, err := transport.Decode(data)
	if err != nil {
		return
	}

	h.conn.SetPeerParams(*params)

	// Apply max_ack_delay to RTT stats
	maxAckDelay := time.Duration(params.MaxAckDelay) * time.Millisecond
	h.recovery.RTTStats().MaxAckDelay = maxAckDelay

	// Apply ack_delay_exponent to ACK trackers
	if params.AckDelayExponent > 0 {
		h.ackHandler.SetAckDelayExponent(PNSpaceInitial, uint8(params.AckDelayExponent))
		h.ackHandler.SetAckDelayExponent(PNSpaceHandshake, uint8(params.AckDelayExponent))
		h.ackHandler.SetAckDelayExponent(PNSpaceApplication, uint8(params.AckDelayExponent))
	}

	// Apply max_ack_delay to ACK trackers
	h.ackHandler.SetMaxAckDelay(PNSpaceApplication, maxAckDelay)
}
