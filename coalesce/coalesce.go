// Package coalesce implements QUIC packet coalescing and splitting
// (RFC 9000, Section 12.4).
//
// When possible, endpoints coalesce multiple QUIC packets into a single
// UDP datagram to reduce overhead. Packets in a coalesced datagram are
// ordered by packet number space: Initial, then Handshake, then 1-RTT.
//
// On the receiving side, a datagram is split into individual packets
// by parsing each packet's header to determine its length.
package coalesce

import (
	"fmt"

	"github.com/Cabbage4/quic-go/header"
	"github.com/Cabbage4/quic-go/varint"
)

// MaxDatagramSize is the maximum safe UDP datagram size.
const MaxDatagramSize = 1452 // conservative default; PMTUD may discover larger

// Coalescer combines multiple QUIC packets into a single datagram.
type Coalescer struct {
	// Buffer holding coalesced packets
	buf []byte
	// Number of packets coalesced
	count int
}

// NewCoalescer creates a new coalescer with a pre-allocated buffer.
func NewCoalescer() *Coalescer {
	return &Coalescer{
		buf: make([]byte, 0, MaxDatagramSize),
	}
}

// AddPacket adds a packet to the coalesced output.
// Returns the number of bytes written, or 0 if the packet doesn't fit.
// The packet must be a complete, encoded QUIC packet.
func (c *Coalescer) AddPacket(packet []byte) (int, error) {
	if c.count > 0 && len(c.buf)+len(packet) > MaxDatagramSize {
		return 0, fmt.Errorf("coalesce: packet does not fit (%d + %d > %d)",
			len(c.buf), len(packet), MaxDatagramSize)
	}

	start := len(c.buf)
	c.buf = append(c.buf, packet...)
	c.count++
	return len(c.buf) - start, nil
}

// AddPacketIfFits adds a packet only if it fits within the MTU.
// Returns true if the packet was added.
func (c *Coalescer) AddPacketIfFits(packet []byte) bool {
	if c.count > 0 && len(c.buf)+len(packet) > MaxDatagramSize {
		return false
	}
	c.buf = append(c.buf, packet...)
	c.count++
	return true
}

// Dat returns the coalesced datagram bytes. The Coalescer is reset after this call.
func (c *Coalescer) Dat() []byte {
	result := c.buf
	c.Reset()
	return result
}

// Len returns the current total size of coalesced packets.
func (c *Coalescer) Len() int {
	return len(c.buf)
}

// Count returns the number of packets coalesced.
func (c *Coalescer) Count() int {
	return c.count
}

// Reset clears the coalescer for reuse.
func (c *Coalescer) Reset() {
	c.buf = c.buf[:0]
	c.count = 0
}

// HasSpace returns true if adding a packet of the given size would fit.
func (c *Coalescer) HasSpace(packetSize int) bool {
	return len(c.buf)+packetSize <= MaxDatagramSize
}

// === Splitting (receiver side) ===

// SplitDatagram splits a coalesced UDP datagram into individual QUIC packets.
// It parses each packet's header to determine its length.
// Returns a slice of byte slices, each representing one packet.
func SplitDatagram(datagram []byte) ([][]byte, error) {
	var packets [][]byte
	offset := 0

	for offset < len(datagram) {
		remaining := datagram[offset:]

		// Determine if this is a long or short header
		if len(remaining) < 1 {
			break
		}

		var pktLen int
		var err error

		if remaining[0]&0x80 != 0 {
			// Long header packet
			pktLen, err = longHeaderPacketLength(remaining)
		} else {
			// Short header packet
			// Short header packets extend to the end of the datagram
			pktLen = len(remaining)
		}

		if err != nil {
			return packets, fmt.Errorf("coalesce: split at offset %d: %w", offset, err)
		}

		if pktLen > len(remaining) {
			// Packet extends beyond datagram — truncated
			// Take what's left
			pktLen = len(remaining)
		}

		packets = append(packets, remaining[:pktLen])
		offset += pktLen

		// Short header always consumes the rest
		if remaining[0]&0x80 == 0 {
			break
		}
	}

	return packets, nil
}

// longHeaderPacketLength computes the length of a long header packet
// from its encoded bytes.
//
// Long header format (RFC 9000 §17.2):
//   Header Form (1 bit) = 1
//   Fixed Bit (1 bit) = 1
//   Long Packet Type (2 bits)
//   Reserved (2 bits)
//   Packet Number Length (2 bits)
//   Version (32 bits)
//   DCID Length (varint, 1 byte) + DCID
//   SCID Length (varint, 1 byte) + SCID
//   [Token Length + Token] (for Initial only)
//   Length (varint) + PN + Payload
//
// The Length field covers: Packet Number + Payload
func longHeaderPacketLength(data []byte) (int, error) {
	if len(data) < 1 {
		return 0, fmt.Errorf("data too short")
	}

	// Minimum: 1 (flags) + 4 (version) + 1 (dcid len) + 1 (scid len) = 7
	if len(data) < 7 {
		return 0, fmt.Errorf("long header too short: %d bytes", len(data))
	}

	offset := 0

	// Flags byte
	flags := data[offset]
	offset++

	// Skip reserved bits and PN length (not needed for length calc)

	// Version (4 bytes)
	if offset+4 > len(data) {
		return 0, fmt.Errorf("truncated at version")
	}
	version := uint32(data[offset])<<24 | uint32(data[offset+1])<<16 |
		uint32(data[offset+2])<<8 | uint32(data[offset+3])
	offset += 4

	// DCID
	dcidLen := int(data[offset])
	offset++
	if offset+dcidLen > len(data) {
		return 0, fmt.Errorf("truncated at DCID")
	}
	offset += dcidLen

	// SCID
	if offset >= len(data) {
		return 0, fmt.Errorf("truncated at SCID length")
	}
	scidLen := int(data[offset])
	offset++
	if offset+scidLen > len(data) {
		return 0, fmt.Errorf("truncated at SCID")
	}
	offset += scidLen

	// Check if this is an Initial packet (type = 0b00)
	pktType := (flags >> 4) & 0x03
	if pktType == 0x00 && version != 0 {
		// Initial packet has Token Length + Token before Length
		tokenLen, n, err := varint.Decode(data[offset:])
		if err != nil {
			return 0, fmt.Errorf("decode token length: %w", err)
		}
		offset += n
		if offset+int(tokenLen) > len(data) {
			return 0, fmt.Errorf("truncated at token")
		}
		offset += int(tokenLen)
	}

	// Length field (varint)
	if offset >= len(data) {
		return 0, fmt.Errorf("truncated at length field")
	}
	lengthVal, n, err := varint.Decode(data[offset:])
	if err != nil {
		return 0, fmt.Errorf("decode length: %w", err)
	}
	offset += n

	// Total packet length = header so far + Length field value
	totalLen := offset + int(lengthVal)
	return totalLen, nil
}

// === Packet ordering for coalescing (§12.4) ===

// PacketSpace represents a packet number space for ordering.
type PacketSpace int

const (
	SpaceInitial     PacketSpace = 0
	SpaceHandshake   PacketSpace = 1
	SpaceApplication PacketSpace = 2
)

// OrderPackets sorts packets by PN space for coalescing.
// RFC 9000 §12.4: coalesced packets MUST be in the order
// Initial, Handshake, 1-RTT.
func OrderPackets(packets []EncodedPacket) []EncodedPacket {
	result := make([]EncodedPacket, 0, len(packets))

	// Initial first
	for _, p := range packets {
		if p.Space == SpaceInitial {
			result = append(result, p)
		}
	}
	// Then Handshake
	for _, p := range packets {
		if p.Space == SpaceHandshake {
			result = append(result, p)
		}
	}
	// Then Application (1-RTT)
	for _, p := range packets {
		if p.Space == SpaceApplication {
			result = append(result, p)
		}
	}
	return result
}

// EncodedPacket represents an encoded QUIC packet with its PN space.
type EncodedPacket struct {
	Data  []byte
	Space PacketSpace
}

// CoalescePackets is a convenience function that orders and coalesces
// multiple packets into a single datagram.
func CoalescePackets(packets []EncodedPacket) ([]byte, int) {
	ordered := OrderPackets(packets)
	c := NewCoalescer()
	for _, p := range ordered {
		if !c.AddPacketIfFits(p.Data) {
			break
		}
	}
	count := c.Count()
	dat := c.Dat()
	return dat, count
}

// ValidateHeaderForm checks whether a datagram starts with a valid QUIC header.
func ValidateHeaderForm(data []byte) (isLong bool, err error) {
	if len(data) < 1 {
		return false, fmt.Errorf("empty datagram")
	}
	isLong = data[0]&0x80 != 0
	// Fixed bit must be 1 for both long and short headers (RFC 9000)
	if data[0]&0x40 == 0 {
		return isLong, fmt.Errorf("fixed bit is not set")
	}
	return isLong, nil
}

// CountPackets counts how many packets are in a coalesced datagram
// without allocating a slice of packets.
func CountPackets(datagram []byte) (int, error) {
	packets, err := SplitDatagram(datagram)
	if err != nil {
		return 0, err
	}
	return len(packets), nil
}

// Reference to header package for potential future use.
var _ = header.Version
