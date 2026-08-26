// Package stream implements QUIC stream management with flow control (RFC 9000, Sections 2-4).
//
// Streams are ordered sequences of bytes. Two types exist:
//   - Bidirectional streams (both endpoints send data)
//   - Unidirectional streams (single endpoint sends data)
//
// Stream IDs (RFC 9000, Section 2.1):
//   Bit 0: 0 = client-initiated, 1 = server-initiated
//   Bit 1: 0 = bidirectional, 1 = unidirectional
//   Bits 2+: stream count within the type
package stream

import (
	"errors"
	"fmt"
	"io"
	"sync"

	"github.com/Cabbage4/quic-go/frames"
)

// FlowControlUpdate represents a flow control frame that needs to be sent.
// It holds either a MAX_DATA, MAX_STREAM_DATA, DATA_BLOCKED, or STREAM_DATA_BLOCKED frame.
type FlowControlUpdate struct {
	Frame frames.Frame
}

// Stream type constants based on stream ID bits.
const (
	StreamTypeBidiClient  = 0x00 // client-initiated, bidirectional
	StreamTypeBidiServer  = 0x01 // server-initiated, bidirectional
	StreamTypeUniClient   = 0x02 // client-initiated, unidirectional
	StreamTypeUniServer   = 0x03 // server-initiated, unidirectional
)

// StreamState represents the state of a stream (RFC 9000, Section 3).
type StreamState int

// Stream states (RFC 9000, Sections 3.1 and 3.2).
const (
	StateReady         StreamState = iota // initial state
	StateSend                              // sending
	StateSendEnd                           // FIN sent
	StateDataSent                          // FIN acknowledged
	StateResetSent                         // RST_STREAM sent
	StateResetReceived                     // RST_STREAM received
	StateRecv                               // receiving
	StateSizeKnown                         // FIN received
	StateDataReceived                      // all data read
	StateResetRead                         // RST_STREAM received and read
	StateClosed                            // fully closed
)

func (s StreamState) String() string {
	switch s {
	case StateReady:
		return "Ready"
	case StateSend:
		return "Send"
	case StateSendEnd:
		return "SendEnd"
	case StateDataSent:
		return "DataSent"
	case StateResetSent:
		return "ResetSent"
	case StateResetReceived:
		return "ResetReceived"
	case StateRecv:
		return "Recv"
	case StateSizeKnown:
		return "SizeKnown"
	case StateDataReceived:
		return "DataReceived"
	case StateResetRead:
		return "ResetRead"
	case StateClosed:
		return "Closed"
	default:
		return fmt.Sprintf("Unknown(%d)", int(s))
	}
}

// SendState manages the sending side of a stream.
type SendState struct {
	mu           sync.Mutex
	state        StreamState
	sendBuf      []byte
	offset       uint64 // next byte offset to send
	finSent      bool
	maxData      uint64 // flow control limit for sending
	ackedOffset  uint64 // highest contiguous offset acknowledged
	ackedFin     bool  // whether FIN has been acknowledged

	// blockedNotified latches that a STREAM_DATA_BLOCKED frame has already
	// been emitted at the current send limit. Per RFC 9000 §19.10 a sender
	// SHOULD signal blockage — but emitting it on every control-frame flush
	// (once per received packet) creates an ack-eliciting ping-pong storm.
	// We emit at most once per maxData value, and re-arm when
	// UpdateSendMaxData raises the limit (or when the stream becomes
	// unblocked).
	blockedNotified bool
}

// RecvState manages the receiving side of a stream.
type RecvState struct {
	mu            sync.Mutex
	state         StreamState
	recvBuf       []byte
	recvOffset    uint64 // next expected byte offset (consumed by Read)
	recvNextOffset uint64 // highest contiguous offset received
	finReceived   bool
	finalSize     uint64
	maxData       uint64 // flow control limit for receiving
	consumedOffset uint64 // how much data has been consumed by Read()
	windowUpdatePending bool
}

// Stream represents a QUIC stream.
type Stream struct {
	mu sync.Mutex

	ID        uint64
	StreamType byte
	Bidirectional bool

	// Sending and receiving states
	send SendState
	recv RecvState

	// Flow control
	connDataSent     uint64 // total data sent on connection
	connMaxData      uint64 // connection-level flow control limit
	connDataReceived uint64
	// connBlockedNotified latches DATA_BLOCKED emission at the current
	// connection-level limit, for the same reason as SendState.blockedNotified.
	connBlockedNotified bool
}

// New creates a new stream with the given ID.
func New(id uint64, initialMaxData uint64, connMaxData uint64) *Stream {
	s := &Stream{
		ID:              id,
		StreamType:      byte(id & 0x03),
		Bidirectional:   (id & 0x02) == 0,
		connMaxData:     connMaxData,
	}
	s.send.maxData = initialMaxData
	s.recv.maxData = initialMaxData
	s.send.state = StateReady
	s.recv.state = StateReady
	return s
}

// Write appends data to the stream's send buffer (application-level).
// Returns the number of bytes written and an error if flow control is exceeded.
func (s *Stream) Write(data []byte) (int, error) {
	s.send.mu.Lock()
	defer s.send.mu.Unlock()

	if s.send.finSent {
		return 0, errors.New("stream: cannot write after FIN")
	}
	if s.send.state == StateResetSent || s.send.state == StateClosed {
		return 0, errors.New("stream: stream is closed for sending")
	}

	// Guard against uint64 underflow: if maxData < offset, flow control is violated
	if s.send.maxData < s.send.offset {
		return 0, errors.New("stream: flow control violation (maxData < offset)")
	}

	// Check stream-level flow control
	available := s.send.maxData - s.send.offset
	if available < uint64(len(data)) {
		data = data[:available]
	}

	if len(data) == 0 {
		return 0, nil // no flow control credit available, but not an error
	}

	// Check connection-level flow control
	if s.connMaxData < s.connDataSent {
		return 0, errors.New("stream: connection-level flow control violation")
	}
	connAvailable := s.connMaxData - s.connDataSent
	if connAvailable < uint64(len(data)) {
		data = data[:connAvailable]
	}

	if len(data) == 0 {
		return 0, nil
	}

	s.send.sendBuf = append(s.send.sendBuf, data...)
	s.send.offset += uint64(len(data))
	s.connDataSent += uint64(len(data))
	s.send.state = StateSend

	return len(data), nil
}

// CloseSending signals that no more data will be sent (sends FIN).
func (s *Stream) CloseSending() error {
	s.send.mu.Lock()
	defer s.send.mu.Unlock()
	if s.send.finSent {
		return errors.New("stream: FIN already sent")
	}
	s.send.finSent = true
	s.send.state = StateSendEnd
	return nil
}

// Read reads received data from the stream (application-level).
// After reading, it checks if a flow control window update should be sent.
func (s *Stream) Read(p []byte) (int, error) {
	s.recv.mu.Lock()
	defer s.recv.mu.Unlock()

	if len(s.recv.recvBuf) == 0 {
		if s.recv.finReceived {
			s.recv.state = StateDataReceived
			return 0, io.EOF
		}
		if s.recv.state == StateResetRead || s.recv.state == StateClosed {
			return 0, errors.New("stream: stream reset")
		}
		return 0, nil // no data available yet
	}

	n := copy(p, s.recv.recvBuf)
	s.recv.recvBuf = s.recv.recvBuf[n:]
	s.recv.recvOffset += uint64(n)
	s.recv.consumedOffset += uint64(n)

	// Check if we should send a window update (RFC 9000 §4.2)
	// When the consumed data exceeds a threshold, update the window
	if s.recv.maxData > 0 && s.recv.consumedOffset > 0 {
		// Update window when we've consumed more than half the window size
		windowSize := s.recv.maxData
		if s.recv.consumedOffset >= windowSize/2 {
			s.recv.windowUpdatePending = true
		}
	}

	if s.recv.finReceived && len(s.recv.recvBuf) == 0 {
		s.recv.state = StateDataReceived
		return n, io.EOF
	}

	s.recv.state = StateRecv
	return n, nil
}

// PushBack pushes data that was previously read back to the front of the
// receive buffer, so a subsequent Read returns it again. It reverses the
// offset/consumed bookkeeping that Read advanced. This is used by the SDK's
// deliverReceivedStreamData when it Read some bytes from the manager stream
// but then could not queue them on the stream's readCh (channel full) and
// must not lose them — putting them back lets the next delivery pass re-read.
//
// p must be exactly the slice (or equivalent bytes) most recently returned by
// Read; calling PushBack with arbitrary data will corrupt stream ordering.
func (s *Stream) PushBack(p []byte) {
	if len(p) == 0 {
		return
	}
	s.recv.mu.Lock()
	defer s.recv.mu.Unlock()
	// Prepend to recvBuf. recvBuf is a slice into a larger backing array
	// that has already been advanced past these bytes (Read did
	// recvBuf = recvBuf[n:]); we cannot safely reclaim that headroom in
	// general, so allocate a new prefix.
	s.recv.recvBuf = append(append([]byte{}, p...), s.recv.recvBuf...)
	// Reverse the bookkeeping Read advanced.
	s.recv.recvOffset -= uint64(len(p))
	s.recv.consumedOffset -= uint64(len(p))
}

// ReceiveData processes incoming STREAM frame data.
func (s *Stream) ReceiveData(offset uint64, data []byte, fin bool) error {
	s.recv.mu.Lock()
	defer s.recv.mu.Unlock()

	// Check if we already have this data or the stream is reset
	if s.recv.state == StateResetRead || s.recv.state == StateClosed {
		return errors.New("stream: cannot receive data on reset stream")
	}

	// Check flow control: offset + len(data) must not exceed maxData
	endOffset := offset + uint64(len(data))
	if endOffset > s.recv.maxData {
		return errors.New("stream: flow control violation")
	}

	// Check connection-level flow control
	if s.connMaxData < s.connDataReceived {
		return errors.New("stream: connection-level flow control violation")
	}
	if endOffset-s.recv.recvOffset+s.connDataReceived > s.connMaxData {
		return errors.New("stream: connection-level flow control violation")
	}

	// If FIN was already received, check finalSize consistency (RFC 9000 §4.5.2)
	if s.recv.finReceived && fin && endOffset != s.recv.finalSize {
		return errors.New("stream: final size mismatch (FINAL_SIZE_ERROR)")
	}
	if s.recv.finReceived && !fin && endOffset > s.recv.finalSize {
		return errors.New("stream: data exceeds previously signaled final size")
	}

	// Skip duplicate data (entirely before current position)
	if endOffset <= s.recv.recvOffset && len(data) > 0 {
		// Already received this data; skip
		return nil
	}

	// Handle partial overlap: trim data that's already received
	effOffset := offset
	effData := data
	if offset < s.recv.recvOffset {
		// Trim the already-received prefix
		overlap := s.recv.recvOffset - offset
		if overlap >= uint64(len(data)) {
			return nil // all data is duplicate
		}
		effOffset = s.recv.recvOffset
		effData = data[overlap:]
	}
	endOffset = effOffset + uint64(len(effData))

	// Write data into buffer at the right offset
	currentEnd := s.recv.recvOffset + uint64(len(s.recv.recvBuf))
	if endOffset > currentEnd {
		// Extend buffer to accommodate
		needed := int(endOffset - s.recv.recvOffset)
		if needed > len(s.recv.recvBuf) {
			s.recv.recvBuf = append(s.recv.recvBuf, make([]byte, needed-len(s.recv.recvBuf))...)
		}
	}
	if effOffset >= s.recv.recvOffset {
		copy(s.recv.recvBuf[int(effOffset-s.recv.recvOffset):], effData)
	}

	// Track total data received on connection
	s.connDataReceived += uint64(len(effData))

	// Track highest received offset
	if endOffset > s.recv.recvNextOffset {
		s.recv.recvNextOffset = endOffset
	}

	if fin {
		s.recv.finReceived = true
		s.recv.finalSize = endOffset
		s.recv.state = StateSizeKnown
	} else {
		s.recv.state = StateRecv
	}

	return nil
}

// UpdateSendMaxData updates the flow control limit for sending.
func (s *Stream) UpdateSendMaxData(maxData uint64) {
	s.send.mu.Lock()
	defer s.send.mu.Unlock()
	if maxData > s.send.maxData {
		s.send.maxData = maxData
		// Peer granted new credit — re-arm so a future block (if the new
		// window is still exhausted) can be signalled again.
		s.send.blockedNotified = false
	}
}

// UpdateRecvMaxData updates the flow control limit for receiving.
func (s *Stream) UpdateRecvMaxData(maxData uint64) {
	s.recv.mu.Lock()
	defer s.recv.mu.Unlock()
	if maxData > s.recv.maxData {
		s.recv.maxData = maxData
	}
}

// === Flow Control Window Auto-Update (RFC 9000 §4.2) ===

// NeedsWindowUpdate returns true if this stream's receive window should be updated.
// This happens when the application has consumed enough data that a
// MAX_STREAM_DATA frame should be sent to the peer.
func (s *Stream) NeedsWindowUpdate() bool {
	s.recv.mu.Lock()
	defer s.recv.mu.Unlock()
	return s.recv.windowUpdatePending
}

// GenStreamWindowUpdate generates a MAX_STREAM_DATA frame for this stream.
// The new window is set to consumedOffset + initialWindow (doubling the available window).
// Returns the frame and clears the pending flag.
func (s *Stream) GenStreamWindowUpdate(windowIncrement uint64) *frames.MaxStreamData {
	s.recv.mu.Lock()
	defer s.recv.mu.Unlock()

	newMax := s.recv.consumedOffset + windowIncrement
	if newMax <= s.recv.maxData {
		// No update needed
		s.recv.windowUpdatePending = false
		return nil
	}
	s.recv.maxData = newMax
	s.recv.windowUpdatePending = false
	return &frames.MaxStreamData{
		StreamID:    s.ID,
		MaximumData: newMax,
	}
}

// GenConnWindowUpdate generates a MAX_DATA frame for the connection.
// Called when the total consumed data on the connection warrants a window update.
func (s *Stream) GenConnWindowUpdate(connConsumed, connMaxData, windowIncrement uint64) *frames.MaxData {
	newMax := connConsumed + windowIncrement
	if newMax <= connMaxData {
		return nil
	}
	return &frames.MaxData{
		MaximumData: newMax,
	}
}

// === DATA_BLOCKED / STREAM_DATA_BLOCKED Frame Generation (§4.1) ===

// GenStreamDataBlocked generates a STREAM_DATA_BLOCKED frame if this stream
// is flow-control blocked on the send side.
// Returns nil if not blocked, or if a BLOCKED frame has already been emitted
// at the current send limit (avoids ack-eliciting ping-pong storms when the
// per-packet control-frame flush polls this generator repeatedly).
func (s *Stream) GenStreamDataBlocked() *frames.StreamDataBlocked {
	s.send.mu.Lock()
	defer s.send.mu.Unlock()

	// Not blocked — there is still send credit. Re-arm the latch so a future
	// block (after the window is exhausted again) gets signalled.
	if s.send.offset < s.send.maxData {
		s.send.blockedNotified = false
		return nil
	}
	// Blocked, but we already notified the peer at this limit — don't spam.
	if s.send.blockedNotified {
		return nil
	}
	s.send.blockedNotified = true
	return &frames.StreamDataBlocked{
		StreamID:    s.ID,
		MaximumData: s.send.maxData,
	}
}

// GenDataBlocked generates a DATA_BLOCKED frame if the connection-level
// flow control is blocking sends.
// Returns nil if not blocked, or if a DATA_BLOCKED frame has already been
// emitted at the current connection limit (avoids ack-eliciting ping-pong
// storms when the per-packet control-frame flush polls this generator).
func (s *Stream) GenDataBlocked() *frames.DataBlocked {
	s.mu.Lock()
	defer s.mu.Unlock()

	if s.connDataSent < s.connMaxData {
		// Not blocked at the connection level — re-arm the latch.
		s.connBlockedNotified = false
		return nil
	}
	if s.connBlockedNotified {
		return nil
	}
	s.connBlockedNotified = true
	return &frames.DataBlocked{
		MaximumData: s.connMaxData,
	}
}

// IsSendBlocked returns true if the stream is blocked by flow control
// on the sending side (either stream-level or connection-level).
func (s *Stream) IsSendBlocked() bool {
	s.send.mu.Lock()
	blocked := s.send.offset >= s.send.maxData
	s.send.mu.Unlock()
	if blocked {
		return true
	}
	s.mu.Lock()
	defer s.mu.Unlock()
	return s.connDataSent >= s.connMaxData
}

// === ACK Integration (§3 State Machine) ===

// MarkAcked updates the acknowledged offset for this stream's send side.
// When all sent data (including FIN) is acknowledged, transitions to StateDataSent.
func (s *Stream) MarkAcked(offset uint64, finAcked bool) {
	s.send.mu.Lock()
	defer s.send.mu.Unlock()

	if offset > s.send.ackedOffset {
		s.send.ackedOffset = offset
	}
	if finAcked {
		s.send.ackedFin = true
	}

	// State transition: StateSendEnd → StateDataSent when all data + FIN is acked
	if s.send.state == StateSendEnd && s.send.ackedFin && s.send.ackedOffset >= s.send.offset {
		s.send.state = StateDataSent
	}
}

// AckedOffset returns the highest contiguous acknowledged offset.
func (s *Stream) AckedOffset() uint64 {
	s.send.mu.Lock()
	defer s.send.mu.Unlock()
	return s.send.ackedOffset
}

// AllDataAcked returns true if all sent data (including FIN) has been acknowledged.
func (s *Stream) AllDataAcked() bool {
	s.send.mu.Lock()
	defer s.send.mu.Unlock()
	return s.send.ackedOffset >= s.send.offset && (!s.send.finSent || s.send.ackedFin)
}

// SendMaxData returns the current flow control limit for sending.
func (s *Stream) SendMaxData() uint64 {
	s.send.mu.Lock()
	defer s.send.mu.Unlock()
	return s.send.maxData
}

// SendOffset returns the current send offset.
func (s *Stream) SendOffset() uint64 {
	s.send.mu.Lock()
	defer s.send.mu.Unlock()
	return s.send.offset
}

// Reset sends a RESET_STREAM frame for this stream.
func (s *Stream) Reset(errorCode uint64) error {
	s.send.mu.Lock()
	defer s.send.mu.Unlock()
	s.send.state = StateResetSent
	return nil
}

// ResetReceived handles a RESET_STREAM frame from peer.
func (s *Stream) ResetReceived(errorCode uint64, finalSize uint64) error {
	s.recv.mu.Lock()
	defer s.recv.mu.Unlock()
	s.recv.state = StateResetRead
	s.recv.finReceived = true
	s.recv.finalSize = finalSize
	s.recv.recvBuf = nil // discard received data
	return nil
}

// State returns the combined stream state.
func (s *Stream) State() (StreamState, StreamState) {
	s.send.mu.Lock()
	sendState := s.send.state
	s.send.mu.Unlock()

	s.recv.mu.Lock()
	recvState := s.recv.state
	s.recv.mu.Unlock()

	return sendState, recvState
}

// String returns a human-readable representation.
func (s *Stream) String() string {
	sendState, recvState := s.State()
	return fmt.Sprintf("Stream(id=%d, type=0x%x, bidi=%v, send=%s, recv=%s)",
		s.ID, s.StreamType, s.Bidirectional, sendState, recvState)
}

// Manager manages multiple streams on a connection.
type Manager struct {
	mu      sync.Mutex
	streams map[uint64]*Stream

	nextClientBidi uint64 // 0, 4, 8, ...
	nextClientUni  uint64 // 2, 6, 10, ...
	nextServerBidi uint64 // 1, 5, 9, ...
	nextServerUni  uint64 // 3, 7, 11, ...

	// Flow control
	connMaxData uint64
	connDataSent     uint64
	connDataReceived uint64

	initialMaxStreamDataBidiLocal  uint64
	initialMaxStreamDataBidiRemote uint64
	initialMaxStreamDataUni        uint64

	maxStreamsBidi uint64
	maxStreamsUni  uint64

	openStreamsBidi uint64
	openStreamsUni  uint64

	isServer bool
}

// NewManager creates a new stream manager.
func NewManager(isServer bool, initialMaxData uint64,
	initialMaxStreamDataBidiLocal, initialMaxStreamDataBidiRemote,
	initialMaxStreamDataUni, maxStreamsBidi, maxStreamsUni uint64) *Manager {
	m := &Manager{
		streams:                       make(map[uint64]*Stream),
		connMaxData:                   initialMaxData,
		initialMaxStreamDataBidiLocal:  initialMaxStreamDataBidiLocal,
		initialMaxStreamDataBidiRemote: initialMaxStreamDataBidiRemote,
		initialMaxStreamDataUni:       initialMaxStreamDataUni,
		maxStreamsBidi:                maxStreamsBidi,
		maxStreamsUni:                 maxStreamsUni,
		isServer:                      isServer,
	}
	// Stream ID conventions (RFC 9000 Section 2.1):
	// Bit 0: 0=client, 1=server
	// Bit 1: 0=bidi, 1=uni
	// Client bidi: 0, 4, 8, 12, ...
	// Client uni:  2, 6, 10, 14, ...
	// Server bidi: 1, 5, 9, 13, ...
	// Server uni:  3, 7, 11, 15, ...
	if isServer {
		m.nextServerBidi = 1
		m.nextServerUni = 3
	} else {
		m.nextClientBidi = 0
		m.nextClientUni = 2
	}
	return m
}

// Open opens a new stream.
// bidi: true for bidirectional, false for unidirectional.
func (m *Manager) Open(bidi bool) (*Stream, error) {
	m.mu.Lock()
	defer m.mu.Unlock()

	if bidi {
		if m.openStreamsBidi >= m.maxStreamsBidi {
			return nil, errors.New("stream: maximum bidirectional streams exceeded")
		}
		m.openStreamsBidi++
	} else {
		if m.openStreamsUni >= m.maxStreamsUni {
			return nil, errors.New("stream: maximum unidirectional streams exceeded")
		}
		m.openStreamsUni++
	}

	var id uint64
	if bidi {
		if m.isServer {
			id = m.nextServerBidi
			m.nextServerBidi += 4
		} else {
			id = m.nextClientBidi
			m.nextClientBidi += 4
		}
	} else {
		if m.isServer {
			id = m.nextServerUni
			m.nextServerUni += 4
		} else {
			id = m.nextClientUni
			m.nextClientUni += 4
		}
	}

	var initialMaxData uint64
	if bidi {
		if m.isServer {
			initialMaxData = m.initialMaxStreamDataBidiLocal
		} else {
			initialMaxData = m.initialMaxStreamDataBidiRemote
		}
	} else {
		initialMaxData = m.initialMaxStreamDataUni
	}

	s := New(id, initialMaxData, m.connMaxData)
	m.streams[id] = s
	return s, nil
}

// GetOrCreate returns an existing stream or creates one for peer-initiated streams.
func (m *Manager) GetOrCreate(id uint64) (*Stream, error) {
	m.mu.Lock()
	defer m.mu.Unlock()

	if s, ok := m.streams[id]; ok {
		return s, nil
	}

	// Determine stream type
	isBidi := (id & 0x02) == 0
	isServerInitiated := (id & 0x01) == 1

	var initialMaxData uint64
	if isBidi {
		// For peer-initiated bidi streams
		if (m.isServer && isServerInitiated) || (!m.isServer && !isServerInitiated) {
			return nil, errors.New("stream: peer cannot open this stream type")
		}
		if m.isServer {
			initialMaxData = m.initialMaxStreamDataBidiRemote
		} else {
			initialMaxData = m.initialMaxStreamDataBidiLocal
		}
	} else {
		initialMaxData = m.initialMaxStreamDataUni
	}

	s := New(id, initialMaxData, m.connMaxData)
	m.streams[id] = s

	if isBidi {
		m.openStreamsBidi++
	} else {
		m.openStreamsUni++
	}

	return s, nil
}

// Get returns a stream by ID.
func (m *Manager) Get(id uint64) (*Stream, bool) {
	m.mu.Lock()
	defer m.mu.Unlock()
	s, ok := m.streams[id]
	return s, ok
}

// CloseStream closes a stream and removes it from the manager.
func (m *Manager) CloseStream(id uint64) {
	m.mu.Lock()
	defer m.mu.Unlock()
	if s, ok := m.streams[id]; ok {
		isBidi := (id & 0x02) == 0
		if isBidi {
			m.openStreamsBidi--
		} else {
			m.openStreamsUni--
		}
		_ = s
		delete(m.streams, id)
	}
}

// AllStreams returns all streams.
func (m *Manager) AllStreams() []*Stream {
	m.mu.Lock()
	defer m.mu.Unlock()
	result := make([]*Stream, 0, len(m.streams))
	for _, s := range m.streams {
		result = append(result, s)
	}
	return result
}

// UpdateConnMaxData updates the connection-level flow control limit.
// It raises the manager's limit AND propagates the new value to every stream
// (each Stream caches connMaxData for the send path); streams that were
// blocked at the old limit also get their DATA_BLOCKED latch re-armed so the
// new credit can be signalled if it is still insufficient.
func (m *Manager) UpdateConnMaxData(maxData uint64) {
	m.mu.Lock()
	defer m.mu.Unlock()
	if maxData > m.connMaxData {
		m.connMaxData = maxData
		for _, s := range m.streams {
			s.mu.Lock()
			if maxData > s.connMaxData {
				s.connMaxData = maxData
				s.connBlockedNotified = false // re-arm: new credit, may block again
			}
			s.mu.Unlock()
		}
	}
}

// UpdateMaxStreams updates the maximum number of streams the peer permits
// us to open (from a received MAX_STREAMS frame, RFC 9000 §19.5).
// If the new limit is larger, it raises the cap; if smaller, it is ignored
// (RFC 9000 §4.6: "A MAX_STREAMS frame ... cannot reduce the maximum ...
// below the value ... already opened").
func (m *Manager) UpdateMaxStreams(maxStreams uint64, bidi bool) {
	m.mu.Lock()
	defer m.mu.Unlock()
	if bidi {
		if maxStreams > m.maxStreamsBidi {
			m.maxStreamsBidi = maxStreams
		}
	} else {
		if maxStreams > m.maxStreamsUni {
			m.maxStreamsUni = maxStreams
		}
	}
}

// ConnDataSent returns total data sent on the connection.
func (m *Manager) ConnDataSent() uint64 {
	m.mu.Lock()
	defer m.mu.Unlock()
	return m.connDataSent
}

// AddConnDataSent adds to the total data sent.
func (m *Manager) AddConnDataSent(n uint64) {
	m.mu.Lock()
	defer m.mu.Unlock()
	m.connDataSent += n
}

// === Connection-Level Flow Control Window Update ===

// connConsumedOffset tracks total data consumed (read) across all streams.
// This is used to determine when to send MAX_DATA frames.
func (m *Manager) connConsumedOffset() uint64 {
	total := uint64(0)
	for _, s := range m.streams {
		s.recv.mu.Lock()
		total += s.recv.consumedOffset
		s.recv.mu.Unlock()
	}
	return total
}

// PendingWindowUpdates returns all flow control frames that need to be sent.
// This includes:
//   - MAX_STREAM_DATA for streams that have consumed enough data
//   - MAX_DATA for the connection if enough data has been consumed
//   - DATA_BLOCKED / STREAM_DATA_BLOCKED for blocked streams
func (m *Manager) PendingWindowUpdates(streamWindowIncrement, connWindowIncrement uint64) []frames.Frame {
	m.mu.Lock()
	defer m.mu.Unlock()

	var updates []frames.Frame

	// Check each stream for window updates and blocked frames
	for _, s := range m.streams {
		// Stream-level window update (MAX_STREAM_DATA)
		if s.NeedsWindowUpdate() {
			if msd := s.GenStreamWindowUpdate(streamWindowIncrement); msd != nil {
				updates = append(updates, msd)
			}
		}

		// Stream-level blocked (STREAM_DATA_BLOCKED)
		if sdb := s.GenStreamDataBlocked(); sdb != nil {
			updates = append(updates, sdb)
		}

		// Connection-level blocked (DATA_BLOCKED)
		if db := s.GenDataBlocked(); db != nil {
			updates = append(updates, db)
		}
	}

	// Connection-level window update (MAX_DATA)
	consumed := m.connConsumedOffset()
	if m.connMaxData > 0 && consumed >= m.connMaxData/2 {
		newMax := consumed + connWindowIncrement
		if newMax > m.connMaxData {
			m.connMaxData = newMax
			updates = append(updates, &frames.MaxData{
				MaximumData: newMax,
			})
		}
	}

	return updates
}

// RegisterLocalStream registers a locally-created stream in the manager.
// This is used when the SDK creates a stream directly and needs it
// tracked by the manager for receive-side operations.
func (m *Manager) RegisterLocalStream(id uint64, s *Stream) {
	m.mu.Lock()
	defer m.mu.Unlock()
	if _, ok := m.streams[id]; !ok {
		m.streams[id] = s
		isBidi := (id & 0x02) == 0
		if isBidi {
			m.openStreamsBidi++
		} else {
			m.openStreamsUni++
		}
	}
}

// ProcessAckForStream updates stream state machines when stream data is acknowledged.
// This handles the SendEnd → DataSent state transition (RFC 9000 §3.1).
func (m *Manager) ProcessAckForStream(streamID uint64, ackedOffset uint64, finAcked bool) {
	m.mu.Lock()
	s, ok := m.streams[streamID]
	m.mu.Unlock()
	if !ok {
		return
	}
	s.MarkAcked(ackedOffset, finAcked)
}

// PendingAcks returns all streams that have completed acknowledgement
// (all data + FIN acked), for state machine transitions.
func (m *Manager) PendingAckedStreams() []uint64 {
	m.mu.Lock()
	defer m.mu.Unlock()

	var ids []uint64
	for id, s := range m.streams {
		if s.AllDataAcked() {
			sendState, _ := s.State()
			if sendState == StateSendEnd || sendState == StateSend {
				ids = append(ids, id)
			}
		}
	}
	return ids
}
