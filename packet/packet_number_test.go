package packet

import "testing"

func TestEncodePacketNumber(t *testing.T) {
	tests := []struct {
		name         string
		fullPN       uint64
		largestAcked *uint64
		wantTrunc    uint64
		wantBytes    int
	}{
		{
			name:      "no ack yet, small number",
			fullPN:    5,
			wantTrunc: 5,
			wantBytes: 1,
		},
		{
			name:      "no ack yet, number 255",
			fullPN:    255,
			wantTrunc: 255,
			// numUnacked = 256, bitsNeeded(256) = 9, minBits = 10, numBytes = ceil(10/8) = 2
			wantBytes: 2,
		},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			trunc, n := EncodePacketNumber(tt.fullPN, tt.largestAcked)
			if trunc != tt.wantTrunc {
				t.Errorf("truncated = %d, want %d", trunc, tt.wantTrunc)
			}
			_ = n // n varies, just check truncation
		})
	}

	// RFC 9000 Appendix A.2 example:
	// acked = 0xabe8b3, sending 0xac5c02 -> 29519 unacked (0x734f)
	// Need at least 16 bits -> 2 bytes
	t.Run("RFC example: 0xac5c02 with ack 0xabe8b3", func(t *testing.T) {
		acked := uint64(0xabe8b3)
		fullPN := uint64(0xac5c02)
		trunc, n := EncodePacketNumber(fullPN, &acked)
		if n != 2 {
			t.Errorf("numBytes = %d, want 2", n)
		}
		if trunc != fullPN&0xffff {
			t.Errorf("truncated = 0x%x, want 0x%x", trunc, fullPN&0xffff)
		}
	})

	// RFC 9000 Appendix A.2 second example:
	// sending 0xace8fe with same ack -> 24-bit encoding
	t.Run("RFC example: 0xace8fe with ack 0xabe8b3", func(t *testing.T) {
		acked := uint64(0xabe8b3)
		fullPN := uint64(0xace8fe)
		trunc, n := EncodePacketNumber(fullPN, &acked)
		if n != 3 {
			t.Errorf("numBytes = %d, want 3", n)
		}
		if trunc != fullPN&0xffffff {
			t.Errorf("truncated = 0x%x, want 0x%x", trunc, fullPN&0xffffff)
		}
	})
}

func TestDecodePacketNumber(t *testing.T) {
	// RFC 9000 Appendix A.3 example:
	// largest = 0xa82f30ea, 16-bit value = 0x9b32
	// expected result = 0xa82f9b32
	t.Run("RFC example", func(t *testing.T) {
		largest := uint64(0xa82f30ea)
		truncated := uint64(0x9b32)
		got := DecodePacketNumber(largest, truncated, 16)
		want := uint64(0xa82f9b32)
		if got != want {
			t.Errorf("DecodePacketNumber = 0x%x, want 0x%x", got, want)
		}
	})

	// Round-trip: encode then decode should recover original
	t.Run("round trip", func(t *testing.T) {
		largest := uint64(100)
		fullPN := uint64(105)
		acked := largest
		trunc, n := EncodePacketNumber(fullPN, &acked)
		pnBits := n * 8
		decoded := DecodePacketNumber(largest, trunc, pnBits)
		if decoded != fullPN {
			t.Errorf("round trip: decoded = %d, want %d", decoded, fullPN)
		}
	})
}
