// Package crypto implements QUIC packet protection per RFC 9001 (Using TLS to Secure QUIC).
//
// This package provides:
//   - Key derivation using HKDF-Expand-Label (RFC 9001 §5.1-5.2)
//   - AEAD packet protection (RFC 9001 §5.3)
//   - Header Protection (RFC 9001 §5.4)
//   - Key Update and Key Phase (RFC 9001 §6)
//   - TLS 1.3 integration layer (RFC 9001 §4)
//
// All key derivation uses the TLS 1.3 HKDF-Expand-Label function with
// zero-length context as specified in RFC 9001 §5.1.
package crypto

import (
	"crypto/hmac"
	"crypto/sha256"
	"crypto/sha512"
	"hash"
)

// Label strings used in QUIC key derivation (RFC 9001 §5.1).
//
// All labels are ASCII-encoded without quotes or trailing NUL byte.
const (
	LabelKey     = "quic key"  // AEAD key
	LabelIV      = "quic iv"  // AEAD IV
	LabelHP      = "quic hp"  // Header protection key
	LabelKU      = "quic ku"  // Key update secret
	LabelClientIn = "client in" // Client initial secret
	LabelServerIn = "server in" // Server initial secret
)

// InitialSalt is the salt used for deriving initial secrets (RFC 9001 §5.2).
var InitialSalt = []byte{
	0x38, 0x76, 0x2c, 0xf7, 0xf5, 0x59, 0x34, 0xb3,
	0x4d, 0x17, 0x9a, 0xe6, 0xa4, 0xc8, 0x0c, 0xad,
	0xcc, 0xbb, 0x7f, 0x0a,
}

// MaxLabelLen is the maximum label length for HKDF-Expand-Label (RFC 8446 §7.1).
const MaxLabelLen = 255

// HashFunc returns the hash function for a given cipher suite.
type HashFunc func() hash.Hash

// CipherSuiteID identifies a TLS cipher suite used with QUIC.
type CipherSuiteID uint16

// TLS 1.3 cipher suites supported by QUIC (RFC 9001 §5.3).
const (
	CipherSuiteAES128GCM       CipherSuiteID = 0x1301 // TLS_AES_128_GCM_SHA256
	CipherSuiteAES256GCM       CipherSuiteID = 0x1302 // TLS_AES_256_GCM_SHA384
	CipherSuiteChaCha20Poly1305 CipherSuiteID = 0x1303 // TLS_CHACHA20_POLY1305_SHA256
)

// CipherSuiteInfo describes the parameters of a cipher suite.
type CipherSuiteInfo struct {
	ID            CipherSuiteID
	Hash          HashFunc    // Hash function for HKDF
	KeyLen        int         // AEAD key length in bytes
	IVLen         int         // AEAD IV length in bytes
	HPKeyLen      int         // Header protection key length in bytes
	AuthTagLen    int         // AEAD auth tag length in bytes
	HeaderProtection string  // "AES-ECB" or "ChaCha20"
}

// cipherSuites maps cipher suite IDs to their parameters.
var cipherSuites = map[CipherSuiteID]CipherSuiteInfo{
	CipherSuiteAES128GCM: {
		ID:               CipherSuiteAES128GCM,
		Hash:             sha256.New,
		KeyLen:           16,
		IVLen:            12,
		HPKeyLen:         16,
		AuthTagLen:       16,
		HeaderProtection: "AES-ECB",
	},
	CipherSuiteAES256GCM: {
		ID:               CipherSuiteAES256GCM,
		Hash:             sha512.New384,
		KeyLen:           32,
		IVLen:            12,
		HPKeyLen:         32,
		AuthTagLen:       16,
		HeaderProtection: "AES-ECB",
	},
	CipherSuiteChaCha20Poly1305: {
		ID:               CipherSuiteChaCha20Poly1305,
		Hash:             sha256.New,
		KeyLen:           32,
		IVLen:            12,
		HPKeyLen:         32,
		AuthTagLen:       16,
		HeaderProtection: "ChaCha20",
	},
}

// GetCipherSuite returns the parameters for a cipher suite.
func GetCipherSuite(id CipherSuiteID) (CipherSuiteInfo, bool) {
	cs, ok := cipherSuites[id]
	return cs, ok
}

// DefaultCipherSuite returns the default cipher suite (AES-128-GCM).
func DefaultCipherSuite() CipherSuiteInfo {
	return cipherSuites[CipherSuiteAES128GCM]
}

// HKDFExtract performs HKDF-Extract as defined in RFC 5869.
// It extracts a pseudorandom key (PRK) from the input keying material (IKM)
// and a salt using HMAC with the given hash.
func HKDFExtract(h func() hash.Hash, salt, ikm []byte) []byte {
	if salt == nil || len(salt) == 0 {
		salt = make([]byte, h().Size())
	}
	mac := hmac.New(h, salt)
	mac.Write(ikm)
	return mac.Sum(nil)
}

// HKDFExpand performs HKDF-Expand as defined in RFC 5869.
// It expands the PRK into output keying material of the given length.
func HKDFExpand(h func() hash.Hash, prk, info []byte, length int) []byte {
	hashLen := h().Size()
	n := (length + hashLen - 1) / hashLen
	if n > 255 {
		panic("crypto: HKDF-Expand length exceeds maximum")
	}

	t := make([]byte, 0, hashLen*n)
	var prev []byte
	mac := hmac.New(h, prk)

	for i := 0; i < n; i++ {
		mac.Reset()
		mac.Write(prev)
		mac.Write(info)
		mac.Write([]byte{byte(i + 1)})
		prev = mac.Sum(nil)
		t = append(t, prev...)
	}

	return t[:length]
}

// hkdfExpandLabel implements the HKDF-Expand-Label function from TLS 1.3
// (RFC 8446 §7.1), used by QUIC for all key derivation (RFC 9001 §5.1).
//
// Hkdf-Expand-Label(Secret, Label, Context, Length) =
//   HKDF-Expand(Secret, HkdfLabel, Length)
//
// where HkdfLabel is:
//   struct {
//     uint16 length = Length;
//     opaque label<7..255> = "tls13 " + Label;
//     opaque context<0..255> = Context;
//   } HkdfLabel;
//
// QUIC always uses zero-length Context (RFC 9001 §5.1).
func hkdfExpandLabel(h func() hash.Hash, secret []byte, label string, context []byte, length int) []byte {
	// Construct the HkdfLabel info field
	fullLabel := "tls13 " + label
	if len(fullLabel) > MaxLabelLen {
		panic("crypto: label too long for HKDF-Expand-Label")
	}

	info := make([]byte, 0, 4+len(fullLabel)+len(context))
	// Length (2 bytes, big-endian)
	info = append(info, byte(length>>8), byte(length&0xff))
	// Label length (1 byte) + label
	info = append(info, byte(len(fullLabel)))
	info = append(info, []byte(fullLabel)...)
	// Context length (1 byte) + context (empty for QUIC)
	info = append(info, byte(len(context)))
	info = append(info, context...)

	return HKDFExpand(h, secret, info, length)
}

// HKDFExpandLabel is the exported version of hkdfExpandLabel.
// It performs HKDF-Expand-Label as specified in TLS 1.3 / QUIC.
func HKDFExpandLabel(h func() hash.Hash, secret []byte, label string, context []byte, length int) []byte {
	return hkdfExpandLabel(h, secret, label, context, length)
}

// DeriveKey derives a key of the given length from a secret using
// HKDF-Expand-Label with the given label and zero-length context.
// This is the primary key derivation function for QUIC (RFC 9001 §5.1).
func DeriveKey(h func() hash.Hash, secret []byte, label string, length int) []byte {
	return hkdfExpandLabel(h, secret, label, nil, length)
}

// DeriveInitialSecret derives the initial secret from the client's
// destination connection ID (RFC 9001 §5.2).
//
//   initial_secret = HKDF-Extract(initial_salt, client_dst_connection_id)
func DeriveInitialSecret(clientDstConnID []byte) []byte {
	return HKDFExtract(sha256.New, InitialSalt, clientDstConnID)
}

// DeriveClientInitialSecret derives the client initial secret from
// the initial secret (RFC 9001 §5.2).
//
//   client_initial_secret = HKDF-Expand-Label(initial_secret, "client in", "", Hash.length)
func DeriveClientInitialSecret(initialSecret []byte) []byte {
	return hkdfExpandLabel(sha256.New, initialSecret, LabelClientIn, nil, sha256.Size)
}

// DeriveServerInitialSecret derives the server initial secret from
// the initial secret (RFC 9001 §5.2).
//
//   server_initial_secret = HKDF-Expand-Label(initial_secret, "server in", "", Hash.length)
func DeriveServerInitialSecret(initialSecret []byte) []byte {
	return hkdfExpandLabel(sha256.New, initialSecret, LabelServerIn, nil, sha256.Size)
}

// TrafficKeys holds the packet protection keys derived from a traffic secret.
type TrafficKeys struct {
	Key     []byte // AEAD key (label "quic key")
	IV      []byte // AEAD IV (label "quic iv")
	HPKey   []byte // Header protection key (label "quic hp")
}

// DeriveTrafficKeys derives the AEAD key, IV, and header protection key
// from a traffic secret using HKDF-Expand-Label (RFC 9001 §5.1).
func DeriveTrafficKeys(secret []byte, cs CipherSuiteInfo) TrafficKeys {
	h := cs.Hash
	return TrafficKeys{
		Key:   hkdfExpandLabel(h, secret, LabelKey, nil, cs.KeyLen),
		IV:    hkdfExpandLabel(h, secret, LabelIV, nil, cs.IVLen),
		HPKey: hkdfExpandLabel(h, secret, LabelHP, nil, cs.HPKeyLen),
	}
}

// DeriveKeyUpdateSecret derives the next-generation secret from the current
// secret using the "quic ku" label (RFC 9001 §6.1).
//
//   secret_<n+1> = HKDF-Expand-Label(secret_<n>, "quic ku", "", Hash.length)
func DeriveKeyUpdateSecret(secret []byte, h func() hash.Hash) []byte {
	return hkdfExpandLabel(h, secret, LabelKU, nil, h().Size())
}

// KeyDerivation holds the state for key derivation operations.
type KeyDerivation struct {
	hash func() hash.Hash
}

// NewKeyDerivation creates a new KeyDerivation instance with the given hash.
func NewKeyDerivation(h func() hash.Hash) *KeyDerivation {
	return &KeyDerivation{hash: h}
}

// ExpandLabel performs HKDF-Expand-Label using the configured hash.
func (kd *KeyDerivation) ExpandLabel(secret []byte, label string, context []byte, length int) []byte {
	return hkdfExpandLabel(kd.hash, secret, label, context, length)
}

// DeriveInitial derives the initial secrets from the client's destination
// connection ID. Returns client and server initial secrets.
func (kd *KeyDerivation) DeriveInitial(clientDstConnID []byte) (clientInitial, serverInitial []byte) {
	initialSecret := DeriveInitialSecret(clientDstConnID)
	clientInitial = DeriveClientInitialSecret(initialSecret)
	serverInitial = DeriveServerInitialSecret(initialSecret)
	return
}

// DeriveTrafficKeys derives traffic keys from a secret.
func (kd *KeyDerivation) DeriveTrafficKeys(secret []byte, cs CipherSuiteInfo) TrafficKeys {
	return DeriveTrafficKeys(secret, cs)
}
