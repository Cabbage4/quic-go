package varint

import (
	"bytes"
	"testing"
)

func TestEncodeDecode(t *testing.T) {
	tests := []struct {
		name  string
		value uint64
		bytes []byte
	}{
		{"37 (1 byte)", 37, []byte{0x25}},
		{"15293 (2 bytes)", 15293, []byte{0x7b, 0xbd}},
		{"494878333 (4 bytes)", 494878333, []byte{0x9d, 0x7f, 0x3e, 0x7d}},
		{"151288809941952652 (8 bytes)", 151288809941952652, []byte{0xc2, 0x19, 0x7c, 0x5e, 0xff, 0x14, 0xe8, 0x8c}},
		{"max 1-byte (63)", 63, []byte{0x3f}},
		{"0", 0, []byte{0x00}},
		{"max 2-byte (16383)", 16383, []byte{0x7f, 0xff}},
		{"max 4-byte (1073741823)", 1073741823, []byte{0xbf, 0xff, 0xff, 0xff}},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			encoded, err := Encode(tt.value)
			if err != nil {
				t.Fatalf("Encode(%d) error: %v", tt.value, err)
			}
			if !bytes.Equal(encoded, tt.bytes) {
				t.Errorf("Encode(%d) = %x, want %x", tt.value, encoded, tt.bytes)
			}
			decoded, n, err := Decode(encoded)
			if err != nil {
				t.Fatalf("Decode(%x) error: %v", encoded, err)
			}
			if decoded != tt.value {
				t.Errorf("Decode(%x) = %d, want %d", encoded, decoded, tt.value)
			}
			if n != len(encoded) {
				t.Errorf("Decode consumed %d bytes, want %d", n, len(encoded))
			}
		})
	}
}

func TestDecodeFromReader(t *testing.T) {
	tests := []uint64{37, 15293, 494878333, 151288809941952652, 0, 63, 16383}
	for _, v := range tests {
		encoded, _ := Encode(v)
		r := bytes.NewReader(encoded)
		decoded, err := DecodeFromReader(r)
		if err != nil {
			t.Fatalf("DecodeFromReader error for %d: %v", v, err)
		}
		if decoded != v {
			t.Errorf("DecodeFromReader = %d, want %d", decoded, v)
		}
	}
}

func TestEncodeTooLarge(t *testing.T) {
	_, err := Encode(MaxValue + 1)
	if err != ErrVarintTooLarge {
		t.Errorf("expected ErrVarintTooLarge, got %v", err)
	}
}

func TestEncodeMaxValue(t *testing.T) {
	encoded, err := Encode(MaxValue)
	if err != nil {
		t.Fatalf("Encode(MaxValue) error: %v", err)
	}
	if len(encoded) != 8 {
		t.Fatalf("expected 8 bytes, got %d", len(encoded))
	}
	decoded, _, err := Decode(encoded)
	if err != nil {
		t.Fatalf("Decode error: %v", err)
	}
	if decoded != MaxValue {
		t.Errorf("decoded = %d, want %d", decoded, MaxValue)
	}
}

func TestDecodeEmpty(t *testing.T) {
	_, _, err := Decode([]byte{})
	if err != ErrVarintTooShort {
		t.Errorf("expected ErrVarintTooShort, got %v", err)
	}
}

func TestAppend(t *testing.T) {
	dst := []byte{0xff}
	dst, _ = Append(dst, 37)
	want := []byte{0xff, 0x25}
	if !bytes.Equal(dst, want) {
		t.Errorf("Append = %x, want %x", dst, want)
	}
}
