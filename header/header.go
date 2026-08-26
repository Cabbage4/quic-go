// Package header implements QUIC packet header encoding and decoding (RFC 9000, Section 17).
//
// Packet formats:
//   - Long Header Packets (Section 17.2): Initial, 0-RTT, Handshake, Retry, Version Negotiation
//   - Short Header Packets (Section 17.3): 1-RTT
package header

import (
	"encoding/binary"
	"errors"
	"fmt"

	"github.com/Cabbage4/quic-go/varint"
)

// Version is the QUIC version 1 (RFC 9000).
const Version uint32 = 0x00000001

// PacketType represents the type of a long header packet.
type PacketType byte

// Long header packet types (RFC 9000, Section 17.2).
const (
	PacketTypeInitial  PacketType = 0x00
	PacketType0RTT     PacketType = 0x01
	PacketTypeHandshake PacketType = 0x02
	PacketTypeRetry    PacketType = 0x03
)

// LongHeader represents a QUIC long header (RFC 9000, Section 17.2).
//
// Long Header Packet {
//   Header Form (1) = 1,
//   Fixed Bit (1) = 1,
//   Long Packet Type (2),
//   Type-Specific Bits (4),
//   Version (32),
//   Destination Connection ID Length (8),
//   Destination Connection ID (0..160),
//   Source Connection ID Length (8),
//   Source Connection ID (0..160),
//   Type-Specific Payload (..),
// }
type LongHeader struct {
	Type              PacketType
	Version           uint32
	DestConnID       []byte
	SrcConnID        []byte
	Token             []byte   // only for Initial packets
	PacketNumber      uint64   // not for Retry or Version Negotiation
	PacketNumberLen   int      // 1-4 bytes, encoded in byte 0 bits 0-1
	Payload           []byte   // encrypted payload
	IsRetry           bool
}

// Encode serializes a long header packet into bytes.
func (h *LongHeader) Encode() ([]byte, error) {
	if len(h.DestConnID) > 255 || len(h.SrcConnID) > 255 {
		return nil, errors.New("header: connection ID too long (max 255 bytes)")
	}

	buf := make([]byte, 0, 64)

	// Byte 0: Header Form=1, Fixed Bit=1, Type (2 bits), Type-specific bits (4 bits)
	// For Initial/0-RTT/Handshake: type-specific bits include Reserved (2) + Packet Number Length (2)
	// For Retry: type-specific bits are unused (4 bits)
	firstByte := byte(0xc0) // 11000000: header form=1, fixed bit=1
	firstByte |= byte(h.Type) << 4
	if !h.IsRetry {
		// Encode packet number length in low 2 bits (value = length-1)
		pnLen := h.PacketNumberLen
		if pnLen < 1 {
			pnLen = 1
		}
		if pnLen > 4 {
			pnLen = 4
		}
		firstByte |= byte(pnLen-1) & 0x03
	}
	buf = append(buf, firstByte)

	// Version (4 bytes, big endian)
	ver := make([]byte, 4)
	binary.BigEndian.PutUint32(ver, h.Version)
	buf = append(buf, ver...)

	// Destination Connection ID
	buf = append(buf, byte(len(h.DestConnID)))
	buf = append(buf, h.DestConnID...)

	// Source Connection ID
	buf = append(buf, byte(len(h.SrcConnID)))
	buf = append(buf, h.SrcConnID...)

	if h.Type == PacketTypeInitial {
		// Token Length (varint) + Token
		tlen, err := varint.Encode(uint64(len(h.Token)))
		if err != nil {
			return nil, err
		}
		buf = append(buf, tlen...)
		buf = append(buf, h.Token...)
	}

	if !h.IsRetry {
		// Length (varint) = packet number length + payload length
		pnLen := h.PacketNumberLen
		if pnLen < 1 {
			pnLen = 1
		}
		if pnLen > 4 {
			pnLen = 4
		}
		lengthVal := uint64(pnLen + len(h.Payload))
		lenBytes, err := varint.Encode(lengthVal)
		if err != nil {
			return nil, err
		}
		buf = append(buf, lenBytes...)

		// Packet Number (truncated to pnLen bytes)
		for i := pnLen - 1; i >= 0; i-- {
			buf = append(buf, byte(h.PacketNumber>>(uint(i)*8)))
		}

		// Payload
		buf = append(buf, h.Payload...)
	} else {
		// Retry: token + 16-byte integrity tag
		buf = append(buf, h.Token...)
		// For demo purposes, we don't compute the real integrity tag (requires QUIC-TLS)
		// In a real implementation, this would be computed per Section 5.8 of [QUIC-TLS]
	}

	return buf, nil
}

// DecodeLongHeader parses a long header from the given byte slice.
// It returns the parsed header, the number of bytes consumed, and any error.
func DecodeLongHeader(data []byte) (*LongHeader, int, error) {
	if len(data) < 1 {
		return nil, 0, errors.New("header: data too short")
	}

	firstByte := data[0]
	// Check header form bit (MSB)
	if firstByte&0x80 == 0 {
		return nil, 0, errors.New("header: not a long header (header form bit = 0)")
	}

	offset := 0
	h := &LongHeader{}

	// Type from bits 4-5
	h.Type = PacketType((firstByte >> 4) & 0x03)
	h.IsRetry = h.Type == PacketTypeRetry

	// Packet number length from bits 0-1 (for non-retry)
	if !h.IsRetry {
		h.PacketNumberLen = int(firstByte&0x03) + 1
	} else {
		h.PacketNumberLen = 0
	}

	offset = 1

	// Version (4 bytes)
	if offset+4 > len(data) {
		return nil, 0, errors.New("header: version too short")
	}
	h.Version = binary.BigEndian.Uint32(data[offset:])
	offset += 4

	// Destination Connection ID
	if offset >= len(data) {
		return nil, 0, errors.New("header: missing DCID length")
	}
	dcidLen := int(data[offset])
	offset++
	if offset+dcidLen > len(data) {
		return nil, 0, errors.New("header: DCID too short")
	}
	h.DestConnID = make([]byte, dcidLen)
	copy(h.DestConnID, data[offset:offset+dcidLen])
	offset += dcidLen

	// Source Connection ID
	if offset >= len(data) {
		return nil, 0, errors.New("header: missing SCID length")
	}
	scidLen := int(data[offset])
	offset++
	if offset+scidLen > len(data) {
		return nil, 0, errors.New("header: SCID too short")
	}
	h.SrcConnID = make([]byte, scidLen)
	copy(h.SrcConnID, data[offset:offset+scidLen])
	offset += scidLen

	if h.Type == PacketTypeInitial {
		// Token Length (varint)
		tokenLen, n, err := varint.Decode(data[offset:])
		if err != nil {
			return nil, 0, fmt.Errorf("header: decode token length: %w", err)
		}
		offset += n
		if offset+int(tokenLen) > len(data) {
			return nil, 0, errors.New("header: token too short")
		}
		h.Token = make([]byte, tokenLen)
		copy(h.Token, data[offset:offset+int(tokenLen)])
		offset += int(tokenLen)
	}

	if !h.IsRetry {
		// Length (varint)
		length, n, err := varint.Decode(data[offset:])
		if err != nil {
			return nil, 0, fmt.Errorf("header: decode length: %w", err)
		}
		offset += n

		// Packet Number
		pnLen := h.PacketNumberLen
		if offset+pnLen > len(data) {
			return nil, 0, errors.New("header: packet number too short")
		}
		h.PacketNumber = 0
		for i := 0; i < pnLen; i++ {
			h.PacketNumber = (h.PacketNumber << 8) | uint64(data[offset])
			offset++
		}

		// Payload
		payloadLen := int(length) - pnLen
		if payloadLen < 0 {
			return nil, 0, errors.New("header: invalid length (less than packet number length)")
		}
		if offset+payloadLen > len(data) {
			payloadLen = len(data) - offset
		}
		h.Payload = make([]byte, payloadLen)
		copy(h.Payload, data[offset:offset+payloadLen])
		offset += payloadLen
	} else {
		// Retry: rest is token + 16-byte integrity tag
		if offset < len(data) {
			rest := data[offset:]
			if len(rest) > 16 {
				h.Token = rest[:len(rest)-16]
			} else {
				h.Token = rest
			}
			offset = len(data)
		}
	}

	return h, offset, nil
}

// ShortHeader represents a QUIC short header (RFC 9000, Section 17.3).
//
// 1-RTT Packet {
//   Header Form (1) = 0,
//   Fixed Bit (1) = 1,
//   Spin Bit (1),
//   Reserved Bits (2),
//   Key Phase (1),
//   Packet Number Length (2),
//   Destination Connection ID (0..160),
//   Packet Number (8..32),
//   Packet Payload (8..),
// }
type ShortHeader struct {
	SpinBit         bool
	KeyPhase        bool
	DestConnID      []byte
	PacketNumber    uint64
	PacketNumberLen int
	Payload         []byte
}

// Encode serializes a short header packet into bytes.
func (h *ShortHeader) Encode() ([]byte, error) {
	buf := make([]byte, 0, 32)

	// Byte 0: Header Form=0, Fixed Bit=1
	firstByte := byte(0x40) // 01000000
	if h.SpinBit {
		firstByte |= 0x20
	}
	if h.KeyPhase {
		firstByte |= 0x04
	}
	pnLen := h.PacketNumberLen
	if pnLen < 1 {
		pnLen = 1
	}
	if pnLen > 4 {
		pnLen = 4
	}
	firstByte |= byte(pnLen-1) & 0x03
	buf = append(buf, firstByte)

	// Destination Connection ID (no length prefix in short header)
	buf = append(buf, h.DestConnID...)

	// Packet Number (truncated)
	for i := pnLen - 1; i >= 0; i-- {
		buf = append(buf, byte(h.PacketNumber>>(uint(i)*8)))
	}

	// Payload
	buf = append(buf, h.Payload...)

	return buf, nil
}

// DecodeShortHeader parses a short header from the given byte slice.
// Note: DCID length must be known from connection context.
func DecodeShortHeader(data []byte, dcidLen int) (*ShortHeader, int, error) {
	if len(data) < 1 {
		return nil, 0, errors.New("header: data too short")
	}
	firstByte := data[0]
	if firstByte&0x80 != 0 {
		return nil, 0, errors.New("header: not a short header (header form bit = 1)")
	}
	if firstByte&0x40 == 0 {
		return nil, 0, errors.New("header: invalid fixed bit (must be 1)")
	}

	h := &ShortHeader{
		SpinBit:         firstByte&0x20 != 0,
		KeyPhase:        firstByte&0x04 != 0,
		PacketNumberLen: int(firstByte&0x03) + 1,
	}

	offset := 1

	// DCID (no length prefix; length known from context)
	if offset+dcidLen > len(data) {
		return nil, 0, errors.New("header: DCID too short")
	}
	h.DestConnID = make([]byte, dcidLen)
	copy(h.DestConnID, data[offset:offset+dcidLen])
	offset += dcidLen

	// Packet Number
	pnLen := h.PacketNumberLen
	if offset+pnLen > len(data) {
		return nil, 0, errors.New("header: packet number too short")
	}
	h.PacketNumber = 0
	for i := 0; i < pnLen; i++ {
		h.PacketNumber = (h.PacketNumber << 8) | uint64(data[offset])
		offset++
	}

	// Rest is payload
	h.Payload = make([]byte, len(data)-offset)
	copy(h.Payload, data[offset:])

	return h, len(data), nil
}

// VersionNegotiation represents a Version Negotiation packet (RFC 9000, Section 17.2.1).
//
// Version Negotiation Packet {
//   Header Form (1) = 1,
//   Unused (7),
//   Version (32) = 0,
//   Destination Connection ID Length (8),
//   Destination Connection ID (0..160),
//   Source Connection ID Length (8),
//   Source Connection ID (0..160),
//   Supported Version (32) ...,
// }
type VersionNegotiation struct {
	DestConnID  []byte
	SrcConnID   []byte
	Versions    []uint32
}

// Encode serializes a Version Negotiation packet.
func (v *VersionNegotiation) Encode() ([]byte, error) {
	buf := make([]byte, 0, 32)

	// Byte 0: Header Form=1, rest unused
	buf = append(buf, byte(0x80))

	// Version = 0 (indicates version negotiation)
	buf = append(buf, 0x00, 0x00, 0x00, 0x00)

	// DCID
	buf = append(buf, byte(len(v.DestConnID)))
	buf = append(buf, v.DestConnID...)

	// SCID
	buf = append(buf, byte(len(v.SrcConnID)))
	buf = append(buf, v.SrcConnID...)

	// Supported versions (4 bytes each)
	for _, ver := range v.Versions {
		verBytes := make([]byte, 4)
		binary.BigEndian.PutUint32(verBytes, ver)
		buf = append(buf, verBytes...)
	}

	return buf, nil
}

// DecodeVersionNegotiation parses a Version Negotiation packet.
func DecodeVersionNegotiation(data []byte) (*VersionNegotiation, int, error) {
	if len(data) < 7 {
		return nil, 0, errors.New("header: version negotiation packet too short")
	}

	offset := 1 // skip first byte

	// Version must be 0
	ver := binary.BigEndian.Uint32(data[offset:])
	if ver != 0 {
		return nil, 0, errors.New("header: version negotiation must have version=0")
	}
	offset += 4

	v := &VersionNegotiation{}

	// DCID
	dcidLen := int(data[offset])
	offset++
	if offset+dcidLen > len(data) {
		return nil, 0, errors.New("header: DCID too short")
	}
	v.DestConnID = make([]byte, dcidLen)
	copy(v.DestConnID, data[offset:offset+dcidLen])
	offset += dcidLen

	// SCID
	scidLen := int(data[offset])
	offset++
	if offset+scidLen > len(data) {
		return nil, 0, errors.New("header: SCID too short")
	}
	v.SrcConnID = make([]byte, scidLen)
	copy(v.SrcConnID, data[offset:offset+scidLen])
	offset += scidLen

	// Supported versions
	for offset+4 <= len(data) {
		ver := binary.BigEndian.Uint32(data[offset:])
		v.Versions = append(v.Versions, ver)
		offset += 4
	}

	return v, offset, nil
}
