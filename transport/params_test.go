package transport

import (
	"bytes"
	"testing"
)

func TestParamsRoundTrip(t *testing.T) {
	p := Default()
	p.MaxIdleTimeout = 30000
	p.InitialMaxData = 1048576
	p.InitialMaxStreamDataBidiLocal = 256000
	p.InitialMaxStreamDataBidiRemote = 256000
	p.InitialMaxStreamDataUni = 128000
	p.InitialMaxStreamsBidi = 100
	p.InitialMaxStreamsUni = 50
	p.AckDelayExponent = 3
	p.MaxAckDelay = 25
	p.ActiveConnectionIDLimit = 8
	p.InitialSourceConnID = []byte{0x01, 0x02, 0x03, 0x04}
	p.OriginalDestConnID = []byte{0x05, 0x06, 0x07, 0x08}
	p.HasStatelessResetToken = true
	p.StatelessResetToken = [16]byte{0, 1, 2, 3, 4, 5, 6, 7, 8, 9, 10, 11, 12, 13, 14, 15}
	p.DisableActiveMigration = true

	encoded, err := p.Encode()
	if err != nil {
		t.Fatalf("Encode error: %v", err)
	}

	decoded, err := Decode(encoded)
	if err != nil {
		t.Fatalf("Decode error: %v", err)
	}

	if decoded.MaxIdleTimeout != p.MaxIdleTimeout {
		t.Errorf("MaxIdleTimeout = %d, want %d", decoded.MaxIdleTimeout, p.MaxIdleTimeout)
	}
	if decoded.InitialMaxData != p.InitialMaxData {
		t.Errorf("InitialMaxData = %d, want %d", decoded.InitialMaxData, p.InitialMaxData)
	}
	if decoded.InitialMaxStreamDataBidiLocal != p.InitialMaxStreamDataBidiLocal {
		t.Errorf("InitialMaxStreamDataBidiLocal = %d, want %d", decoded.InitialMaxStreamDataBidiLocal, p.InitialMaxStreamDataBidiLocal)
	}
	if decoded.InitialMaxStreamsBidi != p.InitialMaxStreamsBidi {
		t.Errorf("InitialMaxStreamsBidi = %d, want %d", decoded.InitialMaxStreamsBidi, p.InitialMaxStreamsBidi)
	}
	if decoded.InitialMaxStreamsUni != p.InitialMaxStreamsUni {
		t.Errorf("InitialMaxStreamsUni = %d, want %d", decoded.InitialMaxStreamsUni, p.InitialMaxStreamsUni)
	}
	if decoded.ActiveConnectionIDLimit != p.ActiveConnectionIDLimit {
		t.Errorf("ActiveConnectionIDLimit = %d, want %d", decoded.ActiveConnectionIDLimit, p.ActiveConnectionIDLimit)
	}
	if !bytes.Equal(decoded.InitialSourceConnID, p.InitialSourceConnID) {
		t.Errorf("InitialSourceConnID = %x, want %x", decoded.InitialSourceConnID, p.InitialSourceConnID)
	}
	if !bytes.Equal(decoded.OriginalDestConnID, p.OriginalDestConnID) {
		t.Errorf("OriginalDestConnID = %x, want %x", decoded.OriginalDestConnID, p.OriginalDestConnID)
	}
	if decoded.HasStatelessResetToken != p.HasStatelessResetToken {
		t.Errorf("HasStatelessResetToken = %v, want %v", decoded.HasStatelessResetToken, p.HasStatelessResetToken)
	}
	if decoded.StatelessResetToken != p.StatelessResetToken {
		t.Errorf("StatelessResetToken = %x, want %x", decoded.StatelessResetToken, p.StatelessResetToken)
	}
	if decoded.DisableActiveMigration != p.DisableActiveMigration {
		t.Errorf("DisableActiveMigration = %v, want %v", decoded.DisableActiveMigration, p.DisableActiveMigration)
	}
}

func TestDefaultParams(t *testing.T) {
	p := Default()
	// Defaults should be set
	if p.MaxUDPPayloadSize != 65527 {
		t.Errorf("MaxUDPPayloadSize = %d, want 65527", p.MaxUDPPayloadSize)
	}
	if p.AckDelayExponent != 3 {
		t.Errorf("AckDelayExponent = %d, want 3", p.AckDelayExponent)
	}
	if p.MaxAckDelay != 25 {
		t.Errorf("MaxAckDelay = %d, want 25", p.MaxAckDelay)
	}
	if p.ActiveConnectionIDLimit != 2 {
		t.Errorf("ActiveConnectionIDLimit = %d, want 2", p.ActiveConnectionIDLimit)
	}
}

func TestEmptyParams(t *testing.T) {
	p := Default()
	encoded, err := p.Encode()
	if err != nil {
		t.Fatalf("Encode error: %v", err)
	}
	if len(encoded) != 0 {
		t.Errorf("default params should encode to empty, got %d bytes", len(encoded))
	}
	decoded, err := Decode(encoded)
	if err != nil {
		t.Fatalf("Decode error: %v", err)
	}
	if decoded.MaxUDPPayloadSize != 65527 {
		t.Errorf("MaxUDPPayloadSize = %d, want 65527", decoded.MaxUDPPayloadSize)
	}
}

func TestUnknownParameterIgnored(t *testing.T) {
	// Unknown parameters should be silently ignored (RFC 9000, Section 18.1)
	p := Default()
	p.MaxIdleTimeout = 10000
	encoded, _ := p.Encode()
	// Prepend an unknown parameter: ID=9999 (varint), length=3, value=0xABCDEF
	// varint encoding of 9999: 9999 <= 16383, so 2 bytes with prefix 01
	// 0x40 | (9999 >> 8) = 0x40 | 0x27 = 0x67, low byte = 0x0f
	// So: 0x67, 0x0f, 0x03, 0xAB, 0xCD, 0xEF
	unknown := []byte{0x67, 0x0f, 0x03, 0xAB, 0xCD, 0xEF}
	encoded = append(unknown, encoded...)
	decoded, err := Decode(encoded)
	if err != nil {
		t.Fatalf("Decode error: %v", err)
	}
	if decoded.MaxIdleTimeout != 10000 {
		t.Errorf("MaxIdleTimeout = %d, want 10000", decoded.MaxIdleTimeout)
	}
}
