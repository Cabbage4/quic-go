package version

import (
	"testing"

	"github.com/Cabbage4/quic-go/header"
)

func TestIsSupported(t *testing.T) {
	if !IsSupported(header.Version) {
		t.Error("QUIC v1 should be supported")
	}
	if IsSupported(0x99999999) {
		t.Error("unknown version should not be supported")
	}
}

func TestServerSupportedVersion(t *testing.T) {
	n := NewNegotiator(true) // server

	dcid := []byte{0x01, 0x02, 0x03, 0x04}
	scid := []byte{0x05, 0x06, 0x07, 0x08}

	// Server receives Initial with supported version
	vnData, err := n.HandleInitialPacket(dcid, scid, header.Version)
	if err != nil {
		t.Fatalf("HandleInitialPacket: %v", err)
	}
	if vnData != nil {
		t.Error("should not return VN packet for supported version")
	}
	if n.NegotiatedVersion() != header.Version {
		t.Errorf("negotiated = 0x%x, want 0x%x", n.NegotiatedVersion(), header.Version)
	}
}

func TestServerUnsupportedVersion(t *testing.T) {
	n := NewNegotiator(true) // server

	dcid := []byte{0x01, 0x02, 0x03, 0x04}
	scid := []byte{0x05, 0x06, 0x07, 0x08}

	// Server receives Initial with unsupported version
	vnData, err := n.HandleInitialPacket(dcid, scid, 0x99999999)
	if err != nil {
		t.Fatalf("HandleInitialPacket: %v", err)
	}
	if vnData == nil {
		t.Fatal("should return VN packet for unsupported version")
	}

	// Parse the VN packet to verify it
	vn, _, err := header.DecodeVersionNegotiation(vnData)
	if err != nil {
		t.Fatalf("DecodeVersionNegotiation: %v", err)
	}

	// VN DCID should echo client SCID
	if !bytesEqual(vn.DestConnID, scid) {
		t.Errorf("VN DCID = %x, want %x (client SCID)", vn.DestConnID, scid)
	}
	// VN SCID should echo client DCID
	if !bytesEqual(vn.SrcConnID, dcid) {
		t.Errorf("VN SCID = %x, want %x (client DCID)", vn.SrcConnID, dcid)
	}
	// Should list supported versions
	if len(vn.Versions) == 0 {
		t.Error("VN packet should list supported versions")
	}
}

func TestClientHandlesVN(t *testing.T) {
	serverN := NewNegotiator(true)
	clientN := NewNegotiator(false)

	dcid := []byte{0x01, 0x02, 0x03, 0x04}
	scid := []byte{0x05, 0x06, 0x07, 0x08}

	// Server generates VN packet for unsupported version
	vnData, _ := serverN.HandleInitialPacket(dcid, scid, 0x99999999)

	// Client receives and parses VN packet
	vn, _, err := header.DecodeVersionNegotiation(vnData)
	if err != nil {
		t.Fatalf("DecodeVersionNegotiation: %v", err)
	}

	// Client selects a version
	selected, err := clientN.HandleVNPacket(vn, dcid, scid)
	if err != nil {
		t.Fatalf("HandleVNPacket: %v", err)
	}
	if selected != header.Version {
		t.Errorf("selected = 0x%x, want 0x%x", selected, header.Version)
	}
}

func TestClientVNMismatchedDcid(t *testing.T) {
	clientN := NewNegotiator(false)

	dcid := []byte{0x01, 0x02, 0x03, 0x04}
	scid := []byte{0x05, 0x06, 0x07, 0x08}
	wrongScid := []byte{0xFF, 0xFF, 0xFF, 0xFF}

	vn := &header.VersionNegotiation{
		DestConnID: wrongScid, // wrong DCID
		SrcConnID:  dcid,
		Versions:   []uint32{header.Version},
	}

	_, err := clientN.HandleVNPacket(vn, dcid, scid)
	if err == nil {
		t.Error("should fail with mismatched DCID")
	}
}

func TestClientVNMismatchedScid(t *testing.T) {
	clientN := NewNegotiator(false)

	dcid := []byte{0x01, 0x02, 0x03, 0x04}
	scid := []byte{0x05, 0x06, 0x07, 0x08}
	wrongDcid := []byte{0xFF, 0xFF, 0xFF, 0xFF}

	vn := &header.VersionNegotiation{
		DestConnID: scid,
		SrcConnID:  wrongDcid, // wrong SCID
		Versions:   []uint32{header.Version},
	}

	_, err := clientN.HandleVNPacket(vn, dcid, scid)
	if err == nil {
		t.Error("should fail with mismatched SCID")
	}
}

func TestClientVnNoSupportedVersion(t *testing.T) {
	clientN := NewNegotiator(false)

	dcid := []byte{0x01, 0x02, 0x03, 0x04}
	scid := []byte{0x05, 0x06, 0x07, 0x08}

	vn := &header.VersionNegotiation{
		DestConnID: scid,
		SrcConnID:  dcid,
		Versions:   []uint32{0x99999999, 0x88888888},
	}

	_, err := clientN.HandleVNPacket(vn, dcid, scid)
	if err == nil {
		t.Error("should fail when no supported version found")
	}
}

func TestClientVnEmptyVersionList(t *testing.T) {
	clientN := NewNegotiator(false)

	dcid := []byte{0x01, 0x02, 0x03, 0x04}
	scid := []byte{0x05, 0x06, 0x07, 0x08}

	vn := &header.VersionNegotiation{
		DestConnID: scid,
		SrcConnID:  dcid,
		Versions:   []uint32{},
	}

	_, err := clientN.HandleVNPacket(vn, dcid, scid)
	if err == nil {
		t.Error("should fail with empty version list")
	}
}
