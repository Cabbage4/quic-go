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
