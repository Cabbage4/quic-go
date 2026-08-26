package header

import (
	"bytes"
	"testing"
)

func TestLongHeaderRoundTrip(t *testing.T) {
	dcid := []byte{0x01, 0x02, 0x03, 0x04, 0x05, 0x06, 0x07, 0x08}
	scid := []byte{0x08, 0x07, 0x06, 0x05, 0x04, 0x03, 0x02, 0x01}
	payload := []byte{0xAA, 0xBB, 0xCC, 0xDD}

	h := &LongHeader{
		Type:            PacketTypeInitial,
		Version:         Version,
		DestConnID:      dcid,
		SrcConnID:       scid,
		Token:           []byte{},
		PacketNumber:    42,
		PacketNumberLen: 2,
		Payload:         payload,
	}

	encoded, err := h.Encode()
	if err != nil {
		t.Fatalf("Encode error: %v", err)
	}

	decoded, n, err := DecodeLongHeader(encoded)
	if err != nil {
		t.Fatalf("Decode error: %v", err)
	}
	if n != len(encoded) {
		t.Errorf("consumed %d bytes, want %d", n, len(encoded))
	}

	if decoded.Type != h.Type {
		t.Errorf("Type = %d, want %d", decoded.Type, h.Type)
	}
	if decoded.Version != h.Version {
		t.Errorf("Version = 0x%x, want 0x%x", decoded.Version, h.Version)
	}
	if !bytes.Equal(decoded.DestConnID, h.DestConnID) {
		t.Errorf("DCID = %x, want %x", decoded.DestConnID, h.DestConnID)
	}
	if !bytes.Equal(decoded.SrcConnID, h.SrcConnID) {
		t.Errorf("SCID = %x, want %x", decoded.SrcConnID, h.SrcConnID)
	}
	if decoded.PacketNumber != h.PacketNumber {
		t.Errorf("PacketNumber = %d, want %d", decoded.PacketNumber, h.PacketNumber)
	}
	if decoded.PacketNumberLen != h.PacketNumberLen {
		t.Errorf("PacketNumberLen = %d, want %d", decoded.PacketNumberLen, h.PacketNumberLen)
	}
	if !bytes.Equal(decoded.Payload, h.Payload) {
		t.Errorf("Payload = %x, want %x", decoded.Payload, h.Payload)
	}
}

func TestShortHeaderRoundTrip(t *testing.T) {
	dcid := []byte{0x01, 0x02, 0x03, 0x04}
	payload := []byte{0x11, 0x22, 0x33}

	h := &ShortHeader{
		SpinBit:         true,
		KeyPhase:        false,
		DestConnID:      dcid,
		PacketNumber:    7,
		PacketNumberLen: 1,
		Payload:         payload,
	}

	encoded, err := h.Encode()
	if err != nil {
		t.Fatalf("Encode error: %v", err)
	}

	decoded, _, err := DecodeShortHeader(encoded, len(dcid))
	if err != nil {
		t.Fatalf("Decode error: %v", err)
	}

	if decoded.SpinBit != h.SpinBit {
		t.Errorf("SpinBit = %v, want %v", decoded.SpinBit, h.SpinBit)
	}
	if !bytes.Equal(decoded.DestConnID, h.DestConnID) {
		t.Errorf("DCID = %x, want %x", decoded.DestConnID, h.DestConnID)
	}
	if decoded.PacketNumber != h.PacketNumber {
		t.Errorf("PacketNumber = %d, want %d", decoded.PacketNumber, h.PacketNumber)
	}
	if !bytes.Equal(decoded.Payload, h.Payload) {
		t.Errorf("Payload = %x, want %x", decoded.Payload, h.Payload)
	}
}

func TestVersionNegotiationRoundTrip(t *testing.T) {
	dcid := []byte{0x01, 0x02, 0x03}
	scid := []byte{0x04, 0x05}

	vn := &VersionNegotiation{
		DestConnID: dcid,
		SrcConnID:  scid,
		Versions:   []uint32{0x00000001, 0xff000020},
	}

	encoded, err := vn.Encode()
	if err != nil {
		t.Fatalf("Encode error: %v", err)
	}

	decoded, _, err := DecodeVersionNegotiation(encoded)
	if err != nil {
		t.Fatalf("Decode error: %v", err)
	}

	if !bytes.Equal(decoded.DestConnID, vn.DestConnID) {
		t.Errorf("DCID = %x, want %x", decoded.DestConnID, vn.DestConnID)
	}
	if !bytes.Equal(decoded.SrcConnID, vn.SrcConnID) {
		t.Errorf("SCID = %x, want %x", decoded.SrcConnID, vn.SrcConnID)
	}
	if len(decoded.Versions) != len(vn.Versions) {
		t.Fatalf("Versions len = %d, want %d", len(decoded.Versions), len(vn.Versions))
	}
	for i, v := range decoded.Versions {
		if v != vn.Versions[i] {
			t.Errorf("Version[%d] = 0x%x, want 0x%x", i, v, vn.Versions[i])
		}
	}
}

func TestHandshakePacketType(t *testing.T) {
	h := &LongHeader{
		Type:            PacketTypeHandshake,
		Version:         Version,
		DestConnID:      []byte{0x01},
		SrcConnID:       []byte{0x02},
		Token:           nil,
		PacketNumber:    0,
		PacketNumberLen: 1,
		Payload:         []byte{0xAA},
	}
	encoded, _ := h.Encode()
	decoded, _, err := DecodeLongHeader(encoded)
	if err != nil {
		t.Fatalf("Decode error: %v", err)
	}
	if decoded.Type != PacketTypeHandshake {
		t.Errorf("Type = %d, want %d", decoded.Type, PacketTypeHandshake)
	}
}

// === Spin Bit Tests (§17.4) ===

func TestSpinBitManagerInitial(t *testing.T) {
	s := NewSpinBitManager()
	if s.SpinValue() != false {
		t.Error("initial spin value should be 0")
	}
	if s.PeerValue() != false {
		t.Error("initial peer value should be 0")
	}
}

func TestSpinBitToggleOnPeerChange(t *testing.T) {
	s := NewSpinBitManager()

	// Peer sends spin=1 (different from our peer value 0)
	// → toggle our spin to 1, update peer to 1
	s.OnPacketReceived(true)
	if s.SpinValue() != true {
		t.Error("spin should be 1 after peer changed from 0 to 1")
	}
	if s.PeerValue() != true {
		t.Error("peer should be 1 after receiving spin=1")
	}

	// Peer sends spin=1 again (same as current peer value)
	// → no toggle
	s.OnPacketReceived(true)
	if s.SpinValue() != true {
		t.Error("spin should still be 1 (no toggle on same peer value)")
	}

	// Peer sends spin=0 (different from current peer value 1)
	// → toggle our spin to 0, update peer to 0
	s.OnPacketReceived(false)
	if s.SpinValue() != false {
		t.Error("spin should be 0 after peer changed from 1 to 0")
	}
	if s.PeerValue() != false {
		t.Error("peer should be 0 after receiving spin=0")
	}
}

func TestSpinBitOnPacketSent(t *testing.T) {
	s := NewSpinBitManager()

	// Initially spin=0, so sent spin bit should be 0
	if s.OnPacketSent() != false {
		t.Error("sent spin bit should be 0 initially")
	}

	// Peer sends spin=1 → our spin toggles to 1
	s.OnPacketReceived(true)

	// Now sent spin bit should be 1
	if s.OnPacketSent() != true {
		t.Error("sent spin bit should be 1 after toggle")
	}
}

func TestSpinBitMultipleToggles(t *testing.T) {
	s := NewSpinBitManager()

	// Toggle sequence: peer sends 1, 0, 1, 0
	// Each change should toggle our spin
	expectedSpin := false

	for _, peerSpin := range []bool{true, false, true, false} {
		s.OnPacketReceived(peerSpin)
		expectedSpin = !expectedSpin // toggle each time peer changes
		if s.SpinValue() != expectedSpin {
			t.Errorf("after receiving %v, spin = %v, want %v", peerSpin, s.SpinValue(), expectedSpin)
		}
	}
}

// === Reserved Bits Validation Tests (§17.2, §17.3) ===

func TestValidateReservedBitsLong(t *testing.T) {
	// Valid: reserved bits (0x0c) are 0
	validByte := byte(0xC0 | 0x00) // header form=1, fixed=1, type=0, reserved=0, pn_len=0
	if !ValidateReservedBitsLong(validByte) {
		t.Error("expected valid when reserved bits are 0")
	}

	// Invalid: reserved bit 2 set (0x04)
	invalidByte := validByte | 0x04
	if ValidateReservedBitsLong(invalidByte) {
		t.Error("expected invalid when reserved bit is set")
	}

	// Invalid: reserved bit 3 set (0x08)
	invalidByte = validByte | 0x08
	if ValidateReservedBitsLong(invalidByte) {
		t.Error("expected invalid when reserved bit is set")
	}
}

func TestValidateReservedBitsShort(t *testing.T) {
	// Valid: reserved bits (0x18) are 0
	validByte := byte(0x40) // header form=0, fixed=1, spin=0, reserved=0, key_phase=0, pn_len=0
	if !ValidateReservedBitsShort(validByte) {
		t.Error("expected valid when reserved bits are 0")
	}

	// Invalid: reserved bit 3 set (0x08)
	invalidByte := validByte | 0x08
	if ValidateReservedBitsShort(invalidByte) {
		t.Error("expected invalid when reserved bit is set")
	}

	// Invalid: reserved bit 4 set (0x10)
	invalidByte = validByte | 0x10
	if ValidateReservedBitsShort(invalidByte) {
		t.Error("expected invalid when reserved bit is set")
	}
}

func TestShortHeaderRejectsReservedBits(t *testing.T) {
	dcid := []byte{0x01, 0x02, 0x03, 0x04}

	h := &ShortHeader{
		SpinBit:         false,
		KeyPhase:        false,
		DestConnID:      dcid,
		PacketNumber:    1,
		PacketNumberLen: 1,
		Payload:         []byte{0xAA},
	}

	encoded, err := h.Encode()
	if err != nil {
		t.Fatalf("Encode error: %v", err)
	}

	// Manually set a reserved bit (bit 3, mask 0x08)
	encoded[0] |= 0x08

	_, _, err = DecodeShortHeader(encoded, len(dcid))
	if err == nil {
		t.Error("expected error for non-zero reserved bits in short header")
	}
}

func TestLongHeaderRejectsReservedBits(t *testing.T) {
	h := &LongHeader{
		Type:            PacketTypeInitial,
		Version:         Version,
		DestConnID:      []byte{0x01},
		SrcConnID:       []byte{0x02},
		Token:           []byte{},
		PacketNumber:    1,
		PacketNumberLen: 1,
		Payload:         []byte{0xAA},
	}

	encoded, err := h.Encode()
	if err != nil {
		t.Fatalf("Encode error: %v", err)
	}

	// Manually set a reserved bit (bit 2, mask 0x04 in long header)
	encoded[0] |= 0x04

	_, _, err = DecodeLongHeader(encoded)
	if err == nil {
		t.Error("expected error for non-zero reserved bits in long header")
	}
}

func TestShortHeaderAcceptsValidSpinBit(t *testing.T) {
	// Spin bit is bit 5 (mask 0x20) — this is NOT a reserved bit
	dcid := []byte{0x01, 0x02, 0x03, 0x04}

	h := &ShortHeader{
		SpinBit:         true, // spin bit set
		KeyPhase:        false,
		DestConnID:      dcid,
		PacketNumber:    1,
		PacketNumberLen: 1,
		Payload:         []byte{0xAA},
	}

	encoded, err := h.Encode()
	if err != nil {
		t.Fatalf("Encode error: %v", err)
	}

	decoded, _, err := DecodeShortHeader(encoded, len(dcid))
	if err != nil {
		t.Fatalf("Decode error: %v", err)
	}
	if !decoded.SpinBit {
		t.Error("spin bit should be true")
	}
}
