// Package frames implements QUIC frame type encoding and decoding (RFC 9000, Section 19).
//
// Frame types:
//
//	0x00  PADDING
//	0x01  PING
//	0x02  ACK
//	0x03  ACK with ECN
//	0x04  RESET_STREAM
//	0x05  STOP_SENDING
//	0x06  CRYPTO
//	0x07  NEW_TOKEN
//	0x08-0x0f  STREAM
//	0x10  MAX_DATA
//	0x11  MAX_STREAM_DATA
//	0x12  MAX_STREAMS (bidirectional)
//	0x13  MAX_STREAMS (unidirectional)
//	0x14  DATA_BLOCKED
//	0x15  STREAM_DATA_BLOCKED
//	0x16  STREAMS_BLOCKED (bidirectional)
//	0x17  STREAMS_BLOCKED (unidirectional)
//	0x18  NEW_CONNECTION_ID
//	0x19  RETIRE_CONNECTION_ID
//	0x1a  PATH_CHALLENGE
//	0x1b  PATH_RESPONSE
//	0x1c  CONNECTION_CLOSE (transport)
//	0x1d  CONNECTION_CLOSE (application)
//	0x1e  HANDSHAKE_DONE
package frames

import (
	"errors"
	"fmt"

	"github.com/Cabbage4/quic-go/varint"
)

// FrameType represents a QUIC frame type.
type FrameType uint64

// Frame type constants (RFC 9000, Section 19).
const (
	FramePadding           FrameType = 0x00
	FramePing              FrameType = 0x01
	FrameAck               FrameType = 0x02
	FrameAckECN            FrameType = 0x03
	FrameResetStream       FrameType = 0x04
	FrameStopSending       FrameType = 0x05
	FrameCrypto            FrameType = 0x06
	FrameNewToken          FrameType = 0x07
	FrameStreamMin         FrameType = 0x08 // 0x08 - 0x0f
	FrameStreamMax         FrameType = 0x0f
	FrameMaxData           FrameType = 0x10
	FrameMaxStreamData     FrameType = 0x11
	FrameMaxStreamsBidi    FrameType = 0x12
	FrameMaxStreamsUni     FrameType = 0x13
	FrameDataBlocked       FrameType = 0x14
	FrameStreamDataBlocked FrameType = 0x15
	FrameStreamsBlockedBidi FrameType = 0x16
	FrameStreamsBlockedUni  FrameType = 0x17
	FrameNewConnectionID   FrameType = 0x18
	FrameRetireConnectionID FrameType = 0x19
	FramePathChallenge     FrameType = 0x1a
	FramePathResponse      FrameType = 0x1b
	FrameConnectionClose   FrameType = 0x1c
	FrameConnectionCloseApp FrameType = 0x1d
	FrameHandshakeDone     FrameType = 0x1e
)

// Frame is the interface that all QUIC frames implement.
type Frame interface {
	FrameType() FrameType
	Encode() ([]byte, error)
	fmt.Stringer
}

// Padding frame (type=0x00). No content.
type Padding struct {
	Length int // number of padding bytes (each is 0x00)
}

func (f *Padding) FrameType() FrameType { return FramePadding }
func (f *Padding) String() string       { return fmt.Sprintf("PADDING(len=%d)", f.Length) }
func (f *Padding) Encode() ([]byte, error) {
	if f.Length <= 0 {
		f.Length = 1
	}
	return make([]byte, f.Length), nil // all zeros = all padding bytes
}

// Ping frame (type=0x01). No content.
type Ping struct{}

func (f *Ping) FrameType() FrameType { return FramePing }
func (f *Ping) String() string       { return "PING" }
func (f *Ping) Encode() ([]byte, error) {
	return []byte{0x01}, nil
}

// ACK Range (RFC 9000, Section 19.3.1)
type ACKRange struct {
	Gap           uint64
	ACKRangeLen   uint64
}

// ACK frame (types 0x02 and 0x03).
type ACK struct {
	LargestAcked  uint64
	ACKDelay      uint64
	ACKRanges     []ACKRange // additional ranges after the first
	FirstACKRange uint64
	// ECN counts (only present when frame type is 0x03)
	ECT0Count     uint64
	ECT1Count     uint64
	ECNCECount    uint64
	HasECN        bool
}

func (f *ACK) FrameType() FrameType {
	if f.HasECN {
		return FrameAckECN
	}
	return FrameAck
}
func (f *ACK) String() string {
	return fmt.Sprintf("ACK(largest=%d, delay=%d, ranges=%d, ecn=%v)",
		f.LargestAcked, f.ACKDelay, len(f.ACKRanges), f.HasECN)
}
func (f *ACK) Encode() ([]byte, error) {
	buf := []byte{}
	var err error
	// Frame type
	ft := uint64(FrameAck)
	if f.HasECN {
		ft = uint64(FrameAckECN)
	}
	buf, err = varint.Append(buf, ft)
	if err != nil {
		return nil, err
	}
	// Largest Acknowledged
	buf, err = varint.Append(buf, f.LargestAcked)
	if err != nil {
		return nil, err
	}
	// ACK Delay
	buf, err = varint.Append(buf, f.ACKDelay)
	if err != nil {
		return nil, err
	}
	// ACK Range Count
	buf, err = varint.Append(buf, uint64(len(f.ACKRanges)))
	if err != nil {
		return nil, err
	}
	// First ACK Range
	buf, err = varint.Append(buf, f.FirstACKRange)
	if err != nil {
		return nil, err
	}
	// Additional ACK Ranges
	for _, r := range f.ACKRanges {
		buf, err = varint.Append(buf, r.Gap)
		if err != nil {
			return nil, err
		}
		buf, err = varint.Append(buf, r.ACKRangeLen)
		if err != nil {
			return nil, err
		}
	}
	// ECN counts
	if f.HasECN {
		buf, err = varint.Append(buf, f.ECT0Count)
		if err != nil {
			return nil, err
		}
		buf, err = varint.Append(buf, f.ECT1Count)
		if err != nil {
			return nil, err
		}
		buf, err = varint.Append(buf, f.ECNCECount)
		if err != nil {
			return nil, err
		}
	}
	return buf, nil
}

// ResetStream frame (type=0x04).
type ResetStream struct {
	StreamID     uint64
	ErrorCode    uint64
	FinalSize    uint64
}

func (f *ResetStream) FrameType() FrameType { return FrameResetStream }
func (f *ResetStream) String() string {
	return fmt.Sprintf("RESET_STREAM(id=%d, err=%d, size=%d)", f.StreamID, f.ErrorCode, f.FinalSize)
}
func (f *ResetStream) Encode() ([]byte, error) {
	buf, err := varint.Append([]byte{}, uint64(FrameResetStream))
	if err != nil {
		return nil, err
	}
	if buf, err = varint.Append(buf, f.StreamID); err != nil {
		return nil, err
	}
	if buf, err = varint.Append(buf, f.ErrorCode); err != nil {
		return nil, err
	}
	if buf, err = varint.Append(buf, f.FinalSize); err != nil {
		return nil, err
	}
	return buf, nil
}

// StopSending frame (type=0x05).
type StopSending struct {
	StreamID  uint64
	ErrorCode uint64
}

func (f *StopSending) FrameType() FrameType { return FrameStopSending }
func (f *StopSending) String() string {
	return fmt.Sprintf("STOP_SENDING(id=%d, err=%d)", f.StreamID, f.ErrorCode)
}
func (f *StopSending) Encode() ([]byte, error) {
	buf, err := varint.Append([]byte{}, uint64(FrameStopSending))
	if err != nil {
		return nil, err
	}
	if buf, err = varint.Append(buf, f.StreamID); err != nil {
		return nil, err
	}
	if buf, err = varint.Append(buf, f.ErrorCode); err != nil {
		return nil, err
	}
	return buf, nil
}

// Crypto frame (type=0x06).
type Crypto struct {
	Offset    uint64
	Data      []byte
}

func (f *Crypto) FrameType() FrameType { return FrameCrypto }
func (f *Crypto) String() string {
	return fmt.Sprintf("CRYPTO(offset=%d, len=%d)", f.Offset, len(f.Data))
}
func (f *Crypto) Encode() ([]byte, error) {
	buf, err := varint.Append([]byte{}, uint64(FrameCrypto))
	if err != nil {
		return nil, err
	}
	if buf, err = varint.Append(buf, f.Offset); err != nil {
		return nil, err
	}
	if buf, err = varint.Append(buf, uint64(len(f.Data))); err != nil {
		return nil, err
	}
	buf = append(buf, f.Data...)
	return buf, nil
}

// NewToken frame (type=0x07).
type NewToken struct {
	Token []byte
}

func (f *NewToken) FrameType() FrameType { return FrameNewToken }
func (f *NewToken) String() string {
	return fmt.Sprintf("NEW_TOKEN(len=%d)", len(f.Token))
}
func (f *NewToken) Encode() ([]byte, error) {
	buf, err := varint.Append([]byte{}, uint64(FrameNewToken))
	if err != nil {
		return nil, err
	}
	if buf, err = varint.Append(buf, uint64(len(f.Token))); err != nil {
		return nil, err
	}
	buf = append(buf, f.Token...)
	return buf, nil
}

// Stream frame (types 0x08-0x0f).
// The low 3 bits of the frame type encode:
//   bit 0: FIN flag
//   bit 1: LEN flag (1 = length present)
//   bit 2: OFF flag (1 = offset present)
type Stream struct {
	StreamID uint64
	Offset  uint64
	Data    []byte
	Fin     bool
}

func (f *Stream) FrameType() FrameType {
	var ft uint64 = 0x08
	if f.Offset > 0 {
		ft |= 0x04 // OFF bit
	}
	ft |= 0x02 // LEN bit: always set for clarity (we include length)
	if f.Fin {
		ft |= 0x01 // FIN bit
	}
	return FrameType(ft)
}
func (f *Stream) String() string {
	return fmt.Sprintf("STREAM(id=%d, off=%d, len=%d, fin=%v)",
		f.StreamID, f.Offset, len(f.Data), f.Fin)
}
func (f *Stream) Encode() ([]byte, error) {
	buf, err := varint.Append([]byte{}, uint64(f.FrameType()))
	if err != nil {
		return nil, err
	}
	if buf, err = varint.Append(buf, f.StreamID); err != nil {
		return nil, err
	}
	if f.Offset > 0 {
		if buf, err = varint.Append(buf, f.Offset); err != nil {
			return nil, err
		}
	}
	// Always include length (LEN bit is set)
	if buf, err = varint.Append(buf, uint64(len(f.Data))); err != nil {
		return nil, err
	}
	buf = append(buf, f.Data...)
	return buf, nil
}

// MaxData frame (type=0x10).
type MaxData struct {
	MaximumData uint64
}

func (f *MaxData) FrameType() FrameType { return FrameMaxData }
func (f *MaxData) String() string       { return fmt.Sprintf("MAX_DATA(max=%d)", f.MaximumData) }
func (f *MaxData) Encode() ([]byte, error) {
	buf, err := varint.Append([]byte{}, uint64(FrameMaxData))
	if err != nil {
		return nil, err
	}
	return varint.Append(buf, f.MaximumData)
}

// MaxStreamData frame (type=0x11).
type MaxStreamData struct {
	StreamID     uint64
	MaximumData  uint64
}

func (f *MaxStreamData) FrameType() FrameType { return FrameMaxStreamData }
func (f *MaxStreamData) String() string {
	return fmt.Sprintf("MAX_STREAM_DATA(id=%d, max=%d)", f.StreamID, f.MaximumData)
}
func (f *MaxStreamData) Encode() ([]byte, error) {
	buf, err := varint.Append([]byte{}, uint64(FrameMaxStreamData))
	if err != nil {
		return nil, err
	}
	if buf, err = varint.Append(buf, f.StreamID); err != nil {
		return nil, err
	}
	return varint.Append(buf, f.MaximumData)
}

// MaxStreams frame (types 0x12 and 0x13).
type MaxStreams struct {
	MaxStreams   uint64
	Unidirectional bool
}

func (f *MaxStreams) FrameType() FrameType {
	if f.Unidirectional {
		return FrameMaxStreamsUni
	}
	return FrameMaxStreamsBidi
}
func (f *MaxStreams) String() string {
	dir := "bidi"
	if f.Unidirectional {
		dir = "uni"
	}
	return fmt.Sprintf("MAX_STREAMS(%s, max=%d)", dir, f.MaxStreams)
}
func (f *MaxStreams) Encode() ([]byte, error) {
	ft := uint64(FrameMaxStreamsBidi)
	if f.Unidirectional {
		ft = uint64(FrameMaxStreamsUni)
	}
	buf, err := varint.Append([]byte{}, ft)
	if err != nil {
		return nil, err
	}
	return varint.Append(buf, f.MaxStreams)
}

// DataBlocked frame (type=0x14).
type DataBlocked struct {
	MaximumData uint64
}

func (f *DataBlocked) FrameType() FrameType { return FrameDataBlocked }
func (f *DataBlocked) String() string       { return fmt.Sprintf("DATA_BLOCKED(max=%d)", f.MaximumData) }
func (f *DataBlocked) Encode() ([]byte, error) {
	buf, err := varint.Append([]byte{}, uint64(FrameDataBlocked))
	if err != nil {
		return nil, err
	}
	return varint.Append(buf, f.MaximumData)
}

// StreamDataBlocked frame (type=0x15).
type StreamDataBlocked struct {
	StreamID    uint64
	MaximumData uint64
}

func (f *StreamDataBlocked) FrameType() FrameType { return FrameStreamDataBlocked }
func (f *StreamDataBlocked) String() string {
	return fmt.Sprintf("STREAM_DATA_BLOCKED(id=%d, max=%d)", f.StreamID, f.MaximumData)
}
func (f *StreamDataBlocked) Encode() ([]byte, error) {
	buf, err := varint.Append([]byte{}, uint64(FrameStreamDataBlocked))
	if err != nil {
		return nil, err
	}
	if buf, err = varint.Append(buf, f.StreamID); err != nil {
		return nil, err
	}
	return varint.Append(buf, f.MaximumData)
}

// StreamsBlocked frame (types 0x16 and 0x17).
type StreamsBlocked struct {
	MaximumStreams uint64
	Unidirectional bool
}

func (f *StreamsBlocked) FrameType() FrameType {
	if f.Unidirectional {
		return FrameStreamsBlockedUni
	}
	return FrameStreamsBlockedBidi
}
func (f *StreamsBlocked) String() string {
	dir := "bidi"
	if f.Unidirectional {
		dir = "uni"
	}
	return fmt.Sprintf("STREAMS_BLOCKED(%s, max=%d)", dir, f.MaximumStreams)
}
func (f *StreamsBlocked) Encode() ([]byte, error) {
	ft := uint64(FrameStreamsBlockedBidi)
	if f.Unidirectional {
		ft = uint64(FrameStreamsBlockedUni)
	}
	buf, err := varint.Append([]byte{}, ft)
	if err != nil {
		return nil, err
	}
	return varint.Append(buf, f.MaximumStreams)
}

// NewConnectionID frame (type=0x18).
type NewConnectionID struct {
	SequenceNumber      uint64
	RetirePriorTo       uint64
	ConnectionID        []byte
	StatelessResetToken [16]byte
}

func (f *NewConnectionID) FrameType() FrameType { return FrameNewConnectionID }
func (f *NewConnectionID) String() string {
	return fmt.Sprintf("NEW_CONNECTION_ID(seq=%d, retire=%d, cid_len=%d)",
		f.SequenceNumber, f.RetirePriorTo, len(f.ConnectionID))
}
func (f *NewConnectionID) Encode() ([]byte, error) {
	buf, err := varint.Append([]byte{}, uint64(FrameNewConnectionID))
	if err != nil {
		return nil, err
	}
	if buf, err = varint.Append(buf, f.SequenceNumber); err != nil {
		return nil, err
	}
	if buf, err = varint.Append(buf, f.RetirePriorTo); err != nil {
		return nil, err
	}
	buf = append(buf, byte(len(f.ConnectionID)))
	buf = append(buf, f.ConnectionID...)
	buf = append(buf, f.StatelessResetToken[:]...)
	return buf, nil
}

// RetireConnectionID frame (type=0x19).
type RetireConnectionID struct {
	SequenceNumber uint64
}

func (f *RetireConnectionID) FrameType() FrameType { return FrameRetireConnectionID }
func (f *RetireConnectionID) String() string {
	return fmt.Sprintf("RETIRE_CONNECTION_ID(seq=%d)", f.SequenceNumber)
}
func (f *RetireConnectionID) Encode() ([]byte, error) {
	buf, err := varint.Append([]byte{}, uint64(FrameRetireConnectionID))
	if err != nil {
		return nil, err
	}
	return varint.Append(buf, f.SequenceNumber)
}

// PathChallenge frame (type=0x1a).
type PathChallenge struct {
	Data [8]byte
}

func (f *PathChallenge) FrameType() FrameType { return FramePathChallenge }
func (f *PathChallenge) String() string       { return fmt.Sprintf("PATH_CHALLENGE(data=%x)", f.Data) }
func (f *PathChallenge) Encode() ([]byte, error) {
	buf, err := varint.Append([]byte{}, uint64(FramePathChallenge))
	if err != nil {
		return nil, err
	}
	return append(buf, f.Data[:]...), nil
}

// PathResponse frame (type=0x1b).
type PathResponse struct {
	Data [8]byte
}

func (f *PathResponse) FrameType() FrameType { return FramePathResponse }
func (f *PathResponse) String() string       { return fmt.Sprintf("PATH_RESPONSE(data=%x)", f.Data) }
func (f *PathResponse) Encode() ([]byte, error) {
	buf, err := varint.Append([]byte{}, uint64(FramePathResponse))
	if err != nil {
		return nil, err
	}
	return append(buf, f.Data[:]...), nil
}

// ConnectionClose frame (types 0x1c and 0x1d).
type ConnectionClose struct {
	ErrorCode          uint64
	TriggerFrameType   uint64 // the frame type that triggered the error (0 for application errors)
	ReasonPhrase       string
	ApplicationError   bool
}

func (f *ConnectionClose) FrameType() FrameType {
	if f.ApplicationError {
		return FrameConnectionCloseApp
	}
	return FrameConnectionClose
}
func (f *ConnectionClose) String() string {
	return fmt.Sprintf("CONNECTION_CLOSE(err=%d, frame=%d, reason=%q, app=%v)",
		f.ErrorCode, f.TriggerFrameType, f.ReasonPhrase, f.ApplicationError)
}
func (f *ConnectionClose) Encode() ([]byte, error) {
	ft := uint64(FrameConnectionClose)
	if f.ApplicationError {
		ft = uint64(FrameConnectionCloseApp)
	}
	buf, err := varint.Append([]byte{}, ft)
	if err != nil {
		return nil, err
	}
	if buf, err = varint.Append(buf, f.ErrorCode); err != nil {
		return nil, err
	}
	if !f.ApplicationError {
		if buf, err = varint.Append(buf, f.TriggerFrameType); err != nil {
			return nil, err
		}
	}
	reason := []byte(f.ReasonPhrase)
	if buf, err = varint.Append(buf, uint64(len(reason))); err != nil {
		return nil, err
	}
	buf = append(buf, reason...)
	return buf, nil
}

// HandshakeDone frame (type=0x1e).
type HandshakeDone struct{}

func (f *HandshakeDone) FrameType() FrameType { return FrameHandshakeDone }
func (f *HandshakeDone) String() string       { return "HANDSHAKE_DONE" }
func (f *HandshakeDone) Encode() ([]byte, error) {
	return []byte{0x1e}, nil
}

// Decode parses a single frame from the given byte slice.
// It returns the parsed Frame, the number of bytes consumed, and any error.
func Decode(data []byte) (Frame, int, error) {
	if len(data) == 0 {
		return nil, 0, errors.New("frames: empty data")
	}

	// Read the frame type varint
	ft, n, err := varint.Decode(data)
	if err != nil {
		return nil, 0, fmt.Errorf("frames: decode frame type: %w", err)
	}
	offset := n

	switch {
	case ft == 0: // PADDING
		// Count consecutive zero bytes
		end := offset
		for end < len(data) && data[end] == 0 {
			end++
		}
		return &Padding{Length: end}, end, nil

	case ft == 1: // PING
		return &Ping{}, offset, nil

	case ft == 2 || ft == 3: // ACK
		ack := &ACK{HasECN: ft == 3}
		ack.LargestAcked, n, err = varint.Decode(data[offset:])
		if err != nil {
			return nil, 0, err
		}
		offset += n
		ack.ACKDelay, n, err = varint.Decode(data[offset:])
		if err != nil {
			return nil, 0, err
		}
		offset += n
		var rangeCount uint64
		rangeCount, n, err = varint.Decode(data[offset:])
		if err != nil {
			return nil, 0, err
		}
		offset += n
		ack.FirstACKRange, n, err = varint.Decode(data[offset:])
		if err != nil {
			return nil, 0, err
		}
		offset += n
		for i := uint64(0); i < rangeCount; i++ {
			var gap, ackRangeLen uint64
			gap, n, err = varint.Decode(data[offset:])
			if err != nil {
				return nil, 0, err
			}
			offset += n
			ackRangeLen, n, err = varint.Decode(data[offset:])
			if err != nil {
				return nil, 0, err
			}
			offset += n
			ack.ACKRanges = append(ack.ACKRanges, ACKRange{Gap: gap, ACKRangeLen: ackRangeLen})
		}
		if ack.HasECN {
			ack.ECT0Count, n, err = varint.Decode(data[offset:])
			if err != nil {
				return nil, 0, err
			}
			offset += n
			ack.ECT1Count, n, err = varint.Decode(data[offset:])
			if err != nil {
				return nil, 0, err
			}
			offset += n
			ack.ECNCECount, n, err = varint.Decode(data[offset:])
			if err != nil {
				return nil, 0, err
			}
			offset += n
		}
		return ack, offset, nil

	case ft == 4: // RESET_STREAM
		rs := &ResetStream{}
		rs.StreamID, n, err = varint.Decode(data[offset:])
		if err != nil {
			return nil, 0, err
		}
		offset += n
		rs.ErrorCode, n, err = varint.Decode(data[offset:])
		if err != nil {
			return nil, 0, err
		}
		offset += n
		rs.FinalSize, n, err = varint.Decode(data[offset:])
		if err != nil {
			return nil, 0, err
		}
		offset += n
		return rs, offset, nil

	case ft == 5: // STOP_SENDING
		ss := &StopSending{}
		ss.StreamID, n, err = varint.Decode(data[offset:])
		if err != nil {
			return nil, 0, err
		}
		offset += n
		ss.ErrorCode, n, err = varint.Decode(data[offset:])
		if err != nil {
			return nil, 0, err
		}
		offset += n
		return ss, offset, nil

	case ft == 6: // CRYPTO
		cr := &Crypto{}
		cr.Offset, n, err = varint.Decode(data[offset:])
		if err != nil {
			return nil, 0, err
		}
		offset += n
		var length uint64
		length, n, err = varint.Decode(data[offset:])
		if err != nil {
			return nil, 0, err
		}
		offset += n
		if offset+int(length) > len(data) {
			return nil, 0, errors.New("frames: CRYPTO data too short")
		}
		cr.Data = make([]byte, length)
		copy(cr.Data, data[offset:offset+int(length)])
		offset += int(length)
		return cr, offset, nil

	case ft == 7: // NEW_TOKEN
		nt := &NewToken{}
		var length uint64
		length, n, err = varint.Decode(data[offset:])
		if err != nil {
			return nil, 0, err
		}
		offset += n
		if offset+int(length) > len(data) {
			return nil, 0, errors.New("frames: NEW_TOKEN data too short")
		}
		nt.Token = make([]byte, length)
		copy(nt.Token, data[offset:offset+int(length)])
		offset += int(length)
		return nt, offset, nil

	case ft >= 0x08 && ft <= 0x0f: // STREAM
		s := &Stream{}
		hasOff := ft&0x04 != 0
		hasLen := ft&0x02 != 0
		s.Fin = ft&0x01 != 0
		s.StreamID, n, err = varint.Decode(data[offset:])
		if err != nil {
			return nil, 0, err
		}
		offset += n
		if hasOff {
			s.Offset, n, err = varint.Decode(data[offset:])
			if err != nil {
				return nil, 0, err
			}
			offset += n
		}
		if hasLen {
			var length uint64
			length, n, err = varint.Decode(data[offset:])
			if err != nil {
				return nil, 0, err
			}
			offset += n
			if offset+int(length) > len(data) {
				return nil, 0, errors.New("frames: STREAM data too short")
			}
			s.Data = make([]byte, length)
			copy(s.Data, data[offset:offset+int(length)])
			offset += int(length)
		} else {
			// No length: rest of data is stream data
			s.Data = make([]byte, len(data)-offset)
			copy(s.Data, data[offset:])
			offset = len(data)
		}
		return s, offset, nil

	case ft == 0x10: // MAX_DATA
		md := &MaxData{}
		md.MaximumData, n, err = varint.Decode(data[offset:])
		if err != nil {
			return nil, 0, err
		}
		offset += n
		return md, offset, nil

	case ft == 0x11: // MAX_STREAM_DATA
		msd := &MaxStreamData{}
		msd.StreamID, n, err = varint.Decode(data[offset:])
		if err != nil {
			return nil, 0, err
		}
		offset += n
		msd.MaximumData, n, err = varint.Decode(data[offset:])
		if err != nil {
			return nil, 0, err
		}
		offset += n
		return msd, offset, nil

	case ft == 0x12 || ft == 0x13: // MAX_STREAMS
		ms := &MaxStreams{Unidirectional: ft == 0x13}
		ms.MaxStreams, n, err = varint.Decode(data[offset:])
		if err != nil {
			return nil, 0, err
		}
		offset += n
		return ms, offset, nil

	case ft == 0x14: // DATA_BLOCKED
		db := &DataBlocked{}
		db.MaximumData, n, err = varint.Decode(data[offset:])
		if err != nil {
			return nil, 0, err
		}
		offset += n
		return db, offset, nil

	case ft == 0x15: // STREAM_DATA_BLOCKED
		sdb := &StreamDataBlocked{}
		sdb.StreamID, n, err = varint.Decode(data[offset:])
		if err != nil {
			return nil, 0, err
		}
		offset += n
		sdb.MaximumData, n, err = varint.Decode(data[offset:])
		if err != nil {
			return nil, 0, err
		}
		offset += n
		return sdb, offset, nil

	case ft == 0x16 || ft == 0x17: // STREAMS_BLOCKED
		sb := &StreamsBlocked{Unidirectional: ft == 0x17}
		sb.MaximumStreams, n, err = varint.Decode(data[offset:])
		if err != nil {
			return nil, 0, err
		}
		offset += n
		return sb, offset, nil

	case ft == 0x18: // NEW_CONNECTION_ID
		ncid := &NewConnectionID{}
		ncid.SequenceNumber, n, err = varint.Decode(data[offset:])
		if err != nil {
			return nil, 0, err
		}
		offset += n
		ncid.RetirePriorTo, n, err = varint.Decode(data[offset:])
		if err != nil {
			return nil, 0, err
		}
		offset += n
		if offset >= len(data) {
			return nil, 0, errors.New("frames: NEW_CONNECTION_ID too short")
		}
		cidLen := int(data[offset])
		offset++
		if offset+cidLen > len(data) {
			return nil, 0, errors.New("frames: NEW_CONNECTION_ID CID too short")
		}
		ncid.ConnectionID = make([]byte, cidLen)
		copy(ncid.ConnectionID, data[offset:offset+cidLen])
		offset += cidLen
		if offset+16 > len(data) {
			return nil, 0, errors.New("frames: NEW_CONNECTION_ID token too short")
		}
		copy(ncid.StatelessResetToken[:], data[offset:offset+16])
		offset += 16
		return ncid, offset, nil

	case ft == 0x19: // RETIRE_CONNECTION_ID
		rcid := &RetireConnectionID{}
		rcid.SequenceNumber, n, err = varint.Decode(data[offset:])
		if err != nil {
			return nil, 0, err
		}
		offset += n
		return rcid, offset, nil

	case ft == 0x1a: // PATH_CHALLENGE
		pc := &PathChallenge{}
		if offset+8 > len(data) {
			return nil, 0, errors.New("frames: PATH_CHALLENGE too short")
		}
		copy(pc.Data[:], data[offset:offset+8])
		offset += 8
		return pc, offset, nil

	case ft == 0x1b: // PATH_RESPONSE
		pr := &PathResponse{}
		if offset+8 > len(data) {
			return nil, 0, errors.New("frames: PATH_RESPONSE too short")
		}
		copy(pr.Data[:], data[offset:offset+8])
		offset += 8
		return pr, offset, nil

	case ft == 0x1c || ft == 0x1d: // CONNECTION_CLOSE
		cc := &ConnectionClose{ApplicationError: ft == 0x1d}
		cc.ErrorCode, n, err = varint.Decode(data[offset:])
		if err != nil {
			return nil, 0, err
		}
		offset += n
		if !cc.ApplicationError {
			cc.TriggerFrameType, n, err = varint.Decode(data[offset:])
			if err != nil {
				return nil, 0, err
			}
			offset += n
		}
		var reasonLen uint64
		reasonLen, n, err = varint.Decode(data[offset:])
		if err != nil {
			return nil, 0, err
		}
		offset += n
		if offset+int(reasonLen) > len(data) {
			return nil, 0, errors.New("frames: CONNECTION_CLOSE reason too short")
		}
		cc.ReasonPhrase = string(data[offset : offset+int(reasonLen)])
		offset += int(reasonLen)
		return cc, offset, nil

	case ft == 0x1e: // HANDSHAKE_DONE
		return &HandshakeDone{}, offset, nil

	default:
		return nil, 0, fmt.Errorf("frames: unknown frame type 0x%x", ft)
	}
}
