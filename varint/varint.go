// Package varint implements QUIC variable-length integer encoding (RFC 9000, Section 16).
//
// The QUIC variable-length integer encoding reserves the two most significant bits
// of the first byte to encode the base-2 logarithm of the integer encoding length
// in bytes. The integer value is encoded on the remaining bits, in network byte order.
//
// Integers are encoded on 1, 2, 4, or 8 bytes and can encode 6-, 14-, 30-, or 62-bit
// values, respectively.
//
//	2MSB | Length | Usable Bits | Range
//	-----+--------+------------+----------------------
//	 00  |   1    |     6      | 0 - 63
//	 01  |   2    |    14      | 0 - 16383
//	 10  |   4    |    30      | 0 - 1073741823
//	 11  |   8    |    62      | 0 - 4611686018427387903
package varint

import (
	"encoding/binary"
	"errors"
	"io"
)

// MaxVarintLen is the maximum length of a varint in bytes.
const MaxVarintLen = 8

// MaxValue is the maximum value that can be encoded in a QUIC varint.
const MaxValue = 1<<62 - 1 // 4611686018427387903

// ErrVarintOverflow is returned when a varint value exceeds the maximum.
var ErrVarintOverflow = errors.New("quic: varint value exceeds maximum (2^62 - 1)")

// ErrVarintTooShort is returned when the input is too short to decode a varint.
var ErrVarintTooShort = errors.New("quic: varint input too short")

// ErrVarintTooLarge is returned when the encoded value exceeds 2^62 - 1.
var ErrVarintTooLarge = errors.New("quic: varint value too large to encode")

// Encode writes a variable-length integer to the given byte slice.
// It returns the number of bytes written.
// The value must not exceed MaxValue (2^62 - 1).
func Encode(v uint64) ([]byte, error) {
	if v > MaxValue {
		return nil, ErrVarintTooLarge
	}
	switch {
	case v <= 63: // 6 bits, 1 byte
		return []byte{byte(v)}, nil
	case v <= 16383: // 14 bits, 2 bytes
		b := make([]byte, 2)
		binary.BigEndian.PutUint16(b, uint16(v)|(0x40<<8))
		return b, nil
	case v <= 1073741823: // 30 bits, 4 bytes
		b := make([]byte, 4)
		binary.BigEndian.PutUint32(b, uint32(v)|(0x80<<24))
		return b, nil
	default: // 62 bits, 8 bytes
		b := make([]byte, 8)
		binary.BigEndian.PutUint64(b, v|(0xc0<<56))
		return b, nil
	}
}

// EncodeTo writes a variable-length integer into the given buffer.
// It returns the number of bytes written, or an error if the buffer is too small.
func EncodeTo(buf []byte, v uint64) (int, error) {
	b, err := Encode(v)
	if err != nil {
		return 0, err
	}
	if len(buf) < len(b) {
		return 0, io.ErrShortBuffer
	}
	copy(buf, b)
	return len(b), nil
}

// Decode reads a variable-length integer from the given byte slice.
// It returns the decoded value and the number of bytes consumed.
func Decode(data []byte) (uint64, int, error) {
	if len(data) == 0 {
		return 0, 0, ErrVarintTooShort
	}
	first := data[0]
	length := 1 << (first >> 6) // 1, 2, 4, or 8
	if len(data) < length {
		return 0, 0, ErrVarintTooShort
	}

	// Remove the two MSB from the first byte, then read remaining bytes.
	v := uint64(first & 0x3f)
	for i := 1; i < length; i++ {
		v = (v << 8) | uint64(data[i])
	}
	return v, length, nil
}

// DecodeFromReader reads a variable-length integer from an io.Reader.
func DecodeFromReader(r io.Reader) (uint64, error) {
	var first [1]byte
	if _, err := io.ReadFull(r, first[:]); err != nil {
		return 0, err
	}
	length := 1 << (first[0] >> 6)
	if length == 1 {
		return uint64(first[0] & 0x3f), nil
	}
	rest := make([]byte, length-1)
	if _, err := io.ReadFull(r, rest); err != nil {
		return 0, err
	}
	v := uint64(first[0] & 0x3f)
	for _, b := range rest {
		v = (v << 8) | uint64(b)
	}
	return v, nil
}

// Append appends a varint encoding of v to dst and returns the extended slice.
func Append(dst []byte, v uint64) ([]byte, error) {
	b, err := Encode(v)
	if err != nil {
		return dst, err
	}
	return append(dst, b...), nil
}
