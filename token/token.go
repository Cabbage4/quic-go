// Package token implements QUIC address validation tokens
// (RFC 9000, Section 8.1) and Retry packet integrity tags
// (RFC 9000, Section 17.2.5).
//
// Tokens are used to validate that a client can receive packets at
// the address it claims to be sending from, preventing IP address
// spoofing amplification attacks.
package token

import (
	"crypto/hmac"
	"crypto/sha256"
	"encoding/binary"
	"fmt"
	"net"
	"time"
)

// TokenLen is the default token length.
const TokenLen = 16

// MaxTokenLen is the maximum token length we'll accept.
const MaxTokenLen = 256

// Token represents an address validation token.
type Token struct {
	// Type: "retry" (issued in Retry packet) or "new" (issued in NEW_TOKEN frame)
	Type   string
	// Client IP address (for binding)
	ClientIP net.IP
	// Timestamp when the token was created (Unix milliseconds)
	CreatedAt int64
	// Random nonce to prevent token reuse
	Nonce [8]byte
	// HMAC signature
	Signature [16]byte
}

// Manager generates and validates address validation tokens.
type Manager struct {
	secret []byte // HMAC key
	maxAge time.Duration
}

// NewManager creates a new token manager with the given secret.
// The secret should be at least 32 bytes of random data.
func NewManager(secret []byte) *Manager {
	return &Manager{
		secret: secret,
		maxAge: 10 * time.Minute, // tokens expire after 10 minutes
	}
}

// SetMaxAge sets the token validity duration.
func (m *Manager) SetMaxAge(d time.Duration) {
	m.maxAge = d
}

// Generate creates a new address validation token for the given client IP.
// The token is bound to the IP address and has an expiration time.
func (m *Manager) Generate(clientIP net.IP, tokenType string) ([]byte, error) {
	if clientIP == nil {
		return nil, fmt.Errorf("token: client IP is required")
	}
	if tokenType != "retry" && tokenType != "new" {
		return nil, fmt.Errorf("token: invalid token type %q", tokenType)
	}

	var nonce [8]byte
	if _, err := readRandom(nonce[:]); err != nil {
		return nil, fmt.Errorf("token: generate nonce: %w", err)
	}

	created := time.Now().UnixMilli()

	// Build token payload: type(1) + IP(4 or 16) + timestamp(8) + nonce(8)
	payload := m.buildPayload(tokenType, clientIP, created, nonce[:])

	// Compute HMAC-SHA256 over the payload
	h := hmac.New(sha256.New, m.secret)
	h.Write(payload)
	sig := h.Sum(nil)

	// Token = payload + first 16 bytes of HMAC
	token := make([]byte, len(payload)+16)
	copy(token, payload)
	copy(token[len(payload):], sig[:16])

	return token, nil
}

// Validate validates a token and returns the token's details.
// Returns an error if the token is invalid, expired, or IP-bound to a
// different address.
func (m *Manager) Validate(token []byte, clientIP net.IP) (*Token, error) {
	if len(token) < 1+4+8+8+16 { // minimum: type + IPv4 + ts + nonce + sig
		return nil, fmt.Errorf("token: too short (%d bytes)", len(token))
	}

	// Parse the payload
	t, err := m.parsePayload(token)
	if err != nil {
		return nil, err
	}

	// Verify HMAC
	payloadLen := len(token) - 16
	if payloadLen < 0 {
		return nil, fmt.Errorf("token: missing signature")
	}

	h := hmac.New(sha256.New, m.secret)
	h.Write(token[:payloadLen])
	expectedSig := h.Sum(nil)[:16]

	if !hmac.Equal(token[payloadLen:], expectedSig) {
		return nil, fmt.Errorf("token: invalid signature")
	}

	// Check expiration
	created := time.UnixMilli(t.CreatedAt)
	if time.Since(created) > m.maxAge {
		return nil, fmt.Errorf("token: expired")
	}

	// Verify IP binding (if the token is IP-bound)
	if t.ClientIP != nil && clientIP != nil {
		if !t.ClientIP.Equal(clientIP) {
			return nil, fmt.Errorf("token: IP mismatch (token=%s, client=%s)",
				t.ClientIP, clientIP)
		}
	}

	return t, nil
}

// buildPayload constructs the token payload bytes.
// Format: typeLen(1) + type + ipLen(1) + ip + timestamp(8) + nonce(8)
func (m *Manager) buildPayload(tokenType string, ip net.IP, createdMs int64, nonce []byte) []byte {
	var buf []byte
	// Type: 1 byte ('r' for retry, 'n' for new)
	if tokenType == "retry" {
		buf = append(buf, 'r')
	} else {
		buf = append(buf, 'n')
	}

	// IP address: 1 byte length + raw bytes
	ipBytes := []byte(ip.To4())
	if ipBytes == nil {
		// IPv6
		ipBytes = []byte(ip.To16())
	}
	buf = append(buf, byte(len(ipBytes)))
	buf = append(buf, ipBytes...)

	// Timestamp: 8 bytes big-endian
	ts := make([]byte, 8)
	binary.BigEndian.PutUint64(ts, uint64(createdMs))
	buf = append(buf, ts...)

	// Nonce: 8 bytes
	buf = append(buf, nonce[:8]...)

	return buf
}

// parsePayload parses the token payload and returns token details.
func (m *Manager) parsePayload(token []byte) (*Token, error) {
	if len(token) < 1 {
		return nil, fmt.Errorf("token: empty")
	}

	offset := 0

	// Type
	typeByte := token[offset]
	offset++
	var tokenType string
	switch typeByte {
	case 'r':
		tokenType = "retry"
	case 'n':
		tokenType = "new"
	default:
		return nil, fmt.Errorf("token: invalid type byte 0x%02x", typeByte)
	}

	// IP length
	if offset >= len(token) {
		return nil, fmt.Errorf("token: truncated at IP length")
	}
	ipLen := int(token[offset])
	offset++

	// IP
	if offset+ipLen > len(token) {
		return nil, fmt.Errorf("token: truncated at IP")
	}
	clientIP := net.IP(token[offset : offset+ipLen])
	offset += ipLen

	// Timestamp
	if offset+8 > len(token) {
		return nil, fmt.Errorf("token: truncated at timestamp")
	}
	createdMs := int64(binary.BigEndian.Uint64(token[offset : offset+8]))
	offset += 8

	// Nonce
	if offset+8 > len(token) {
		return nil, fmt.Errorf("token: truncated at nonce")
	}
	var nonce [8]byte
	copy(nonce[:], token[offset:offset+8])
	offset += 8

	// Signature (remaining 16 bytes)
	if offset+16 > len(token) {
		return nil, fmt.Errorf("token: truncated at signature")
	}
	var sig [16]byte
	copy(sig[:], token[offset:offset+16])

	return &Token{
		Type:      tokenType,
		ClientIP:  clientIP,
		CreatedAt: createdMs,
		Nonce:     nonce,
		Signature: sig,
	}, nil
}

// === Retry Packet Integrity Tag (§17.2.5) ===

// RetryPacketAad constructs the Additional Authenticated Data (AAD) for
// the Retry packet integrity tag computation (RFC 9000 §17.2.5).
//
// The AAD is: DCID + SCID + Retry packet (without the integrity tag).
func RetryPacketAad(dcid, scid, retryPacketNoTag []byte) []byte {
	aad := make([]byte, 0, 1+len(dcid)+1+len(scid)+len(retryPacketNoTag))
	// DCID length + DCID
	aad = append(aad, byte(len(dcid)))
	aad = append(aad, dcid...)
	// SCID length + SCID
	aad = append(aad, byte(len(scid)))
	aad = append(aad, scid...)
	// Retry packet (without tag)
	aad = append(aad, retryPacketNoTag...)
	return aad
}

// ComputeRetryIntegrityTag computes the 16-byte Retry packet integrity tag
// (RFC 9000 §17.2.5).
//
// The tag is the first 16 bytes of AEAD_AES_128_GCM with a fixed key
// 0xbe0c8303b6945c4c850b8b563d3c3a13 and the AAD constructed from
// DCID + SCID + Retry packet (without tag).
func ComputeRetryIntegrityTag(dcid, scid, retryPacketNoTag []byte) [16]byte {
	// Fixed key per RFC 9000 §17.2.5
	key := [16]byte{
		0xbe, 0x0c, 0x83, 0x03, 0xb6, 0x94, 0x5c, 0x4c,
		0x85, 0x0b, 0x8b, 0x56, 0x3d, 0x3c, 0x3a, 0x13,
	}

	aad := RetryPacketAad(dcid, scid, retryPacketNoTag)

	// AES-128-GCM with all-zero nonce and all-zero plaintext
	// The integrity tag is the authentication tag of encrypting
	// an empty plaintext with the AAD.
	tag := computeAES128GCMTag(key[:], aad)

	var result [16]byte
	copy(result[:], tag[:16])
	return result
}

// readRandom is a variable for testing; default uses crypto/rand.
var readRandom = func(b []byte) (int, error) {
	return defaultRandRead(b)
}
