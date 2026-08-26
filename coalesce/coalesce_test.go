package coalesce

import (
	"testing"
)

// Helper: create a minimal long header packet with given Length field value
// Uses type=0b10 (Handshake) to avoid needing a token field
func makeLongHeader(dcid, scid []byte, lengthVal uint64) []byte {
	// flags: 1101 0000 = 0xD0 (long=1, fixed=1, type=10=Handshake, reserved=00, pn_len=00=1byte)
	buf := []byte{0xD0, 0x00, 0x00, 0x00, 0x01}
	buf = append(buf, byte(len(dcid)))
	buf = append(buf, dcid...)
	buf = append(buf, byte(len(scid)))
	buf = append(buf, scid...)

	// Length field as varint (use simple 1-byte encoding for small values)
	if lengthVal < 64 {
		buf = append(buf, byte(lengthVal))
	} else {
		// 2-byte varint: 01xxxxxx xxxxxxxx
		buf = append(buf, byte(0x40|(lengthVal>>8)&0x3f))
		buf = append(buf, byte(lengthVal&0xff))
	}

	// Add payload of given length
	for i := uint64(0); i < lengthVal; i++ {
		buf = append(buf, 0xAA)
	}
	return buf
}

// makeInitialPacket creates a minimal Initial packet with a token
func makeInitialPacket(dcid, scid, token []byte, lengthVal uint64) []byte {
	buf := []byte{0xc0, 0x00, 0x00, 0x00, 0x01} // Initial: type=0, long header
	buf = append(buf, byte(len(dcid)))
	buf = append(buf, dcid...)
	buf = append(buf, byte(len(scid)))
	buf = append(buf, scid...)

	// Token length (varint, 1 byte for small values)
	buf = append(buf, byte(len(token)))
	buf = append(buf, token...)

	// Length field (varint, 1 byte for small values)
	if lengthVal < 64 {
		buf = append(buf, byte(lengthVal))
	} else {
		buf = append(buf, byte(0x40|(lengthVal>>8)&0x3f))
		buf = append(buf, byte(lengthVal&0xff))
	}

	// Payload
	for i := uint64(0); i < lengthVal; i++ {
		buf = append(buf, 0xBB)
	}
	return buf
}

func makeShortHeader(dcid []byte) []byte {
	buf := []byte{0x40 | 0x01} // short header, fixed bit set, pn len = 1
	buf = append(buf, dcid...)
	buf = append(buf, 0x01) // PN
	buf = append(buf, []byte("payload data here")...)
	return buf
}

func TestCoalesceEmpty(t *testing.T) {
	c := NewCoalescer()
	if c.Len() != 0 {
		t.Error("empty coalescer should have len 0")
	}
	if c.Count() != 0 {
		t.Error("empty coalescer should have count 0")
	}
}

func TestCoalesceSingle(t *testing.T) {
	c := NewCoalescer()
	pkt := []byte{0x01, 0x02, 0x03}
	n, err := c.AddPacket(pkt)
	if err != nil {
		t.Fatalf("AddPacket: %v", err)
	}
	if n != 3 {
		t.Errorf("wrote %d, want 3", n)
	}
	if c.Count() != 1 {
		t.Errorf("count = %d, want 1", c.Count())
	}
	if c.Len() != 3 {
		t.Errorf("len = %d, want 3", c.Len())
	}

	dat := c.Dat()
	if len(dat) != 3 {
		t.Errorf("datagram len = %d, want 3", len(dat))
	}
	// Coalescer should be reset after Dat()
	if c.Count() != 0 {
		t.Error("coalescer not reset after Dat()")
	}
}

func TestCoalesceMultiple(t *testing.T) {
	c := NewCoalescer()
	c.AddPacket([]byte{0x01})
	c.AddPacket([]byte{0x02, 0x03})
	c.AddPacket([]byte{0x04, 0x05, 0x06})

	if c.Count() != 3 {
		t.Errorf("count = %d, want 3", c.Count())
	}
	if c.Len() != 6 {
		t.Errorf("len = %d, want 6", c.Len())
	}

	dat := c.Dat()
	expected := []byte{0x01, 0x02, 0x03, 0x04, 0x05, 0x06}
	if len(dat) != len(expected) {
		t.Fatalf("datagram len = %d, want %d", len(dat), len(expected))
	}
	for i := range dat {
		if dat[i] != expected[i] {
			t.Errorf("byte %d = 0x%02x, want 0x%02x", i, dat[i], expected[i])
		}
	}
}

func TestCoalesceDoesNotFit(t *testing.T) {
	c := NewCoalescer()
	// Fill with large packet
	big := make([]byte, 1000)
	c.AddPacket(big)

	// Second packet that doesn't fit
	pkt := make([]byte, 500)
	_, err := c.AddPacket(pkt)
	if err == nil {
		t.Error("should error when packet doesn't fit")
	}
}

func TestAddPacketIfFits(t *testing.T) {
	c := NewCoalescer()
	c.AddPacket(make([]byte, 1000))

	if c.AddPacketIfFits(make([]byte, 500)) {
		t.Error("should not fit")
	}
	if c.AddPacketIfFits(make([]byte, 400)) {
		// Should fit (1000 + 400 = 1400 <= 1452)
	} else {
		t.Error("should fit")
	}
}

func TestHasSpace(t *testing.T) {
	c := NewCoalescer()
	c.AddPacket(make([]byte, 1000))

	if !c.HasSpace(400) {
		t.Error("should have space for 400")
	}
	if c.HasSpace(500) {
		t.Error("should not have space for 500")
	}
}

func TestReset(t *testing.T) {
	c := NewCoalescer()
	c.AddPacket([]byte{0x01, 0x02})
	c.Reset()

	if c.Count() != 0 || c.Len() != 0 {
		t.Error("reset should clear all state")
	}
}

func TestSplitSingleLongHeader(t *testing.T) {
	dcid := []byte{0x01, 0x02, 0x03, 0x04}
	scid := []byte{0x05, 0x06, 0x07, 0x08}
	pkt := makeLongHeader(dcid, scid, 10)

	packets, err := SplitDatagram(pkt)
	if err != nil {
		t.Fatalf("SplitDatagram: %v", err)
	}
	if len(packets) != 1 {
		t.Errorf("got %d packets, want 1", len(packets))
	}
	if len(packets[0]) != len(pkt) {
		t.Errorf("packet len = %d, want %d", len(packets[0]), len(pkt))
	}
}

func TestSplitMultipleLongHeaders(t *testing.T) {
	dcid := []byte{0x01, 0x02, 0x03, 0x04}
	scid := []byte{0x05, 0x06, 0x07, 0x08}

	pkt1 := makeLongHeader(dcid, scid, 10)
	pkt2 := makeLongHeader(dcid, scid, 20)

	datagram := append(pkt1, pkt2...)

	packets, err := SplitDatagram(datagram)
	if err != nil {
		t.Fatalf("SplitDatagram: %v", err)
	}
	if len(packets) != 2 {
		t.Fatalf("got %d packets, want 2", len(packets))
	}
	if len(packets[0]) != len(pkt1) {
		t.Errorf("packet 0 len = %d, want %d", len(packets[0]), len(pkt1))
	}
	if len(packets[1]) != len(pkt2) {
		t.Errorf("packet 1 len = %d, want %d", len(packets[1]), len(pkt2))
	}
}

func TestSplitWithShortHeader(t *testing.T) {
	dcid := []byte{0x01, 0x02, 0x03, 0x04}
	scid := []byte{0x05, 0x06, 0x07, 0x08}

	longPkt := makeLongHeader(dcid, scid, 10)
	shortPkt := makeShortHeader(dcid)

	datagram := append(longPkt, shortPkt...)

	packets, err := SplitDatagram(datagram)
	if err != nil {
		t.Fatalf("SplitDatagram: %v", err)
	}
	if len(packets) != 2 {
		t.Fatalf("got %d packets, want 2", len(packets))
	}
	if len(packets[0]) != len(longPkt) {
		t.Errorf("packet 0 len = %d, want %d", len(packets[0]), len(longPkt))
	}
	// Short header consumes the rest
	if len(packets[1]) != len(shortPkt) {
		t.Errorf("packet 1 len = %d, want %d", len(packets[1]), len(shortPkt))
	}
}

func TestSplitInitialWithToken(t *testing.T) {
	dcid := []byte{0x01, 0x02, 0x03, 0x04}
	scid := []byte{0x05, 0x06, 0x07, 0x08}
	token := []byte{0xAA, 0xBB, 0xCC}

	pkt := makeInitialPacket(dcid, scid, token, 10)

	packets, err := SplitDatagram(pkt)
	if err != nil {
		t.Fatalf("SplitDatagram: %v", err)
	}
	if len(packets) != 1 {
		t.Fatalf("got %d packets, want 1", len(packets))
	}
	if len(packets[0]) != len(pkt) {
		t.Errorf("packet len = %d, want %d", len(packets[0]), len(pkt))
	}
}

func TestOrderPackets(t *testing.T) {
	packets := []EncodedPacket{
		{Data: []byte{0x02}, Space: SpaceApplication},
		{Data: []byte{0x00}, Space: SpaceInitial},
		{Data: []byte{0x01}, Space: SpaceHandshake},
		{Data: []byte{0x03}, Space: SpaceApplication},
	}

	ordered := OrderPackets(packets)
	if ordered[0].Space != SpaceInitial {
		t.Error("first should be Initial")
	}
	if ordered[1].Space != SpaceHandshake {
		t.Error("second should be Handshake")
	}
	if ordered[2].Space != SpaceApplication {
		t.Error("third should be Application")
	}
	if ordered[3].Space != SpaceApplication {
		t.Error("fourth should be Application")
	}
}

func TestCoalescePacketsHelper(t *testing.T) {
	packets := []EncodedPacket{
		{Data: make([]byte, 100), Space: SpaceApplication},
		{Data: make([]byte, 100), Space: SpaceInitial},
	}

	dat, count := CoalescePackets(packets)
	if count != 2 {
		t.Errorf("count = %d, want 2", count)
	}
	if len(dat) != 200 {
		t.Errorf("datagram len = %d, want 200", len(dat))
	}
}

func TestCountPackets(t *testing.T) {
	dcid := []byte{0x01, 0x02, 0x03, 0x04}
	scid := []byte{0x05, 0x06, 0x07, 0x08}

	pkt1 := makeLongHeader(dcid, scid, 10)
	pkt2 := makeLongHeader(dcid, scid, 20)
	pkt3 := makeShortHeader(dcid)

	datagram := append(append(pkt1, pkt2...), pkt3...)

	n, err := CountPackets(datagram)
	if err != nil {
		t.Fatalf("CountPackets: %v", err)
	}
	if n != 3 {
		t.Errorf("count = %d, want 3", n)
	}
}

func TestValidateHeaderForm(t *testing.T) {
	// Long header (bit 7 set, bit 6 set)
	if _, err := ValidateHeaderForm([]byte{0xC0}); err != nil {
		t.Errorf("long header should be valid: %v", err)
	}

	// Short header (bit 7 clear, bit 6 set)
	if _, err := ValidateHeaderForm([]byte{0x40}); err != nil {
		t.Errorf("short header should be valid: %v", err)
	}

	// Fixed bit not set
	if _, err := ValidateHeaderForm([]byte{0x80}); err == nil {
		t.Error("should error when fixed bit not set")
	}
}
