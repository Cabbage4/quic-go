// Package packet implements QUIC packet number encoding and decoding (RFC 9000, Section 17.1).
//
// Packet numbers are integers in the range 0 to 2^62-1. When present in long or
// short packet headers, they are encoded in 1 to 4 bytes. Only the least
// significant bits of the packet number are included.
package packet

import "math"

// MaxPacketNumber is the maximum QUIC packet number (2^62 - 1).
const MaxPacketNumber = 1<<62 - 1

// EncodePacketNumber selects an appropriate truncated encoding for a packet number
// and returns the truncated value and the number of bytes used.
//
// Per RFC 9000 Appendix A.2:
//   - fullPN: the full packet number being sent
//   - largestAcked: the largest packet number acknowledged by the peer, or nil
//
// The number of bits must be at least one more than the base-2 logarithm of
// the number of contiguous unacknowledged packet numbers, including the new packet.
func EncodePacketNumber(fullPN uint64, largestAcked *uint64) (truncated uint64, numBytes int) {
	var numUnacked uint64
	if largestAcked == nil {
		numUnacked = fullPN + 1
	} else {
		numUnacked = fullPN - *largestAcked
	}

	// min_bits = floor(log2(num_unacked)) + 1, at minimum 1
	minBits := 1
	if numUnacked > 1 {
		minBits = bitsNeeded(numUnacked) + 1
	}

	// Number of bytes: ceil(minBits / 8)
	numBytes = (minBits + 7) / 8
	if numBytes < 1 {
		numBytes = 1
	}
	if numBytes > 4 {
		numBytes = 4
	}

	// Truncate to the least significant numBytes*8 bits
	mask := uint64(1)<<(uint(numBytes)*8) - 1
	return fullPN & mask, numBytes
}

// DecodePacketNumber reconstructs the full packet number from a truncated value.
//
// Per RFC 9000 Appendix A.3:
//   - largestPN: the largest packet number successfully processed in the current space
//   - truncatedPN: the value of the Packet Number field
//   - pnNbits: number of bits in the Packet Number field (8, 16, 24, or 32)
func DecodePacketNumber(largestPN, truncatedPN uint64, pnNbits int) uint64 {
	expectedPN := largestPN + 1
	pnWin := uint64(1) << uint(pnNbits)
	pnHwin := pnWin / 2
	pnMask := pnWin - 1

	// candidate_pn = (expected_pn & ~pn_mask) | truncated_pn
	candidatePN := (expectedPN & ^pnMask) | truncatedPN

	// The comparisons in the RFC pseudocode assume signed arithmetic.
	// We need to handle unsigned underflow carefully.
	//
	// "candidate_pn <= expected_pn - pn_hwin" means candidatePN is in the
	// lower half of the window, but only if expected_pn >= pn_hwin.
	// If expected_pn < pn_hwin, this condition can never be true
	// (there are no packet numbers below 0).
	if expectedPN >= pnHwin && candidatePN <= expectedPN-pnHwin && candidatePN < (1<<62)-pnWin {
		return candidatePN + pnWin
	}
	if candidatePN > expectedPN+pnHwin && candidatePN >= pnWin {
		return candidatePN - pnWin
	}
	return candidatePN
}

// bitsNeeded returns the number of bits needed to represent v (at least 1).
func bitsNeeded(v uint64) int {
	if v == 0 {
		return 1
	}
	bits := 0
	for v > 0 {
		bits++
		v >>= 1
	}
	return bits
}

// Log2 returns floor(log2(v)) for v > 0, using math.Log2.
// This is used internally and kept for reference.
func Log2(v uint64) float64 {
	return math.Log2(float64(v))
}
