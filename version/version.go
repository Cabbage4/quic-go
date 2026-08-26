// Package version implements QUIC version negotiation logic
// (RFC 9000, Section 6).
//
// Version negotiation allows a server to respond to a client that has
// sent a packet with an unsupported version. The server sends a Version
// Negotiation (VN) packet listing the versions it does support.
package version

import (
	"fmt"

	"github.com/Cabbage4/quic-go/header"
)

// SupportedVersions lists the QUIC versions this endpoint supports.
// Currently only QUICv1 (RFC 9000).
var SupportedVersions = []uint32{
	header.Version, // 0x00000001 — QUIC v1
}

// IsSupported returns true if the given version is supported.
func IsSupported(version uint32) bool {
	for _, v := range SupportedVersions {
		if v == version {
			return true
		}
	}
	return false
}

// Negotiator handles version negotiation logic for both client and server.
type Negotiator struct {
	// Whether this endpoint is the server
	isServer bool
	// The version the client initially used
	clientVersion uint32
	// The negotiated version (0 if not yet negotiated)
	negotiatedVersion uint32
}

// NewNegotiator creates a new version negotiator.
func NewNegotiator(isServer bool) *Negotiator {
	return &Negotiator{isServer: isServer}
}

// HandleInitialPacket is called by the server when it receives an Initial
// packet. If the version is unsupported, it returns a VN packet to send
// back. If the version is supported, it returns nil (no VN needed).
//
// RFC 9000 §6.2: A server that receives a packet with an unsupported
// version SHOULD respond with a Version Negotiation packet.
func (n *Negotiator) HandleInitialPacket(clientDcid, clientScid []byte, version uint32) ([]byte, error) {
	if !n.isServer {
		return nil, fmt.Errorf("version: client should not handle initial packet")
	}

	if IsSupported(version) {
		n.negotiatedVersion = version
		return nil, nil // version is supported, no VN needed
	}

	// Build Version Negotiation packet
	vn := &header.VersionNegotiation{
		DestConnID: clientScid, // echo client's SCID as VN's DCID
		SrcConnID:  clientDcid, // echo client's DCID as VN's SCID
		Versions:   SupportedVersions,
	}

	data, err := vn.Encode()
	if err != nil {
		return nil, fmt.Errorf("version: encode VN packet: %w", err)
	}

	return data, nil
}

// HandleVNPacket is called by the client when it receives a VN packet.
// It validates the packet and selects a version from the list.
// Returns the selected version, or 0 if no compatible version is found.
//
// RFC 9000 §6.2: A client that receives a Version Negotiation packet
// MUST select the first version it supports from the list.
func (n *Negotiator) HandleVNPacket(vn *header.VersionNegotiation, clientDcid, clientScid []byte) (uint32, error) {
	if n.isServer {
		return 0, fmt.Errorf("version: server should not handle VN packet")
	}

	// Validate VN packet (RFC 9000 §7.2):
	// 1. VN DCID must match client's SCID
	if !bytesEqual(vn.DestConnID, clientScid) {
		return 0, fmt.Errorf("version: VN DCID does not match client SCID")
	}
	// 2. VN SCID must match client's DCID
	if !bytesEqual(vn.SrcConnID, clientDcid) {
		return 0, fmt.Errorf("version: VN SCID does not match client DCID")
	}
	// 3. VN must list at least one version
	if len(vn.Versions) == 0 {
		return 0, fmt.Errorf("version: VN packet has no supported versions")
	}

	// Select the first supported version
	for _, v := range vn.Versions {
		if IsSupported(v) {
			n.negotiatedVersion = v
			return v, nil
		}
	}

	return 0, fmt.Errorf("version: no supported version in VN packet")
}

// NegotiatedVersion returns the negotiated version (0 if not yet negotiated).
func (n *Negotiator) NegotiatedVersion() uint32 {
	return n.negotiatedVersion
}

// SetClientVersion sets the version the client initially used.
func (n *Negotiator) SetClientVersion(v uint32) {
	n.clientVersion = v
}

// bytesEqual compares two byte slices.
func bytesEqual(a, b []byte) bool {
	if len(a) != len(b) {
		return false
	}
	for i := range a {
		if a[i] != b[i] {
			return false
		}
	}
	return true
}

