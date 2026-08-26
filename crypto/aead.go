// Package crypto implements QUIC packet protection per RFC 9001.
//
// This file implements AEAD packet protection (RFC 9001 §5.3).
package crypto

import (
	"crypto/aes"
	"crypto/cipher"
	"encoding/binary"
	"errors"
	"fmt"
)

// EncryptionLevel represents the QUIC encryption level (RFC 9001 §4.1).
type EncryptionLevel int

const (
	EncryptionInitial EncryptionLevel = iota
	EncryptionHandshake
	EncryptionApplication
	EncryptionEarly // 0-RTT
)

// String returns the name of the encryption level.
func (el EncryptionLevel) String() string {
	switch el {
	case EncryptionInitial:
		return "Initial"
	case EncryptionHandshake:
		return "Handshake"
	case EncryptionApplication:
		return "Application"
	case EncryptionEarly:
		return "Early"
	default:
		return fmt.Sprintf("Unknown(%d)", int(el))
	}
}

// AEAD provides AEAD packet protection for QUIC (RFC 9001 §5.3).
//
// QUIC uses the AEAD function negotiated by TLS. The same packet protection
// process is applied to Initial, Handshake, 0-RTT, and 1-RTT packets.
//
// Order of operations when constructing packets:
//  1. AEAD encrypt the payload
//  2. Apply header protection
//
// Order of operations when processing packets:
//  1. Remove header protection
//  2. AEAD decrypt the payload
type AEAD struct {
	aead     cipher.AEAD
	key      []byte
	iv       []byte
	keyLen   int
	ivLen    int
	suiteID  CipherSuiteID

	// Packet counters for AEAD usage limits (RFC 2010 §6.6)
	txCount uint64 // number of packets encrypted with this key
	rxCount uint64 // number of packets that failed authentication
}

// NewAEAD creates a new AEAD instance from the given traffic keys and cipher suite.
func NewAEAD(keys TrafficKeys, suiteID CipherSuiteID) (*AEAD, error) {
	cs, ok := GetCipherSuite(suiteID)
	if !ok {
		return nil, fmt.Errorf("crypto: unknown cipher suite 0x%04x", suiteID)
	}

	var a cipher.AEAD

	switch suiteID {
	case CipherSuiteAES128GCM, CipherSuiteAES256GCM:
		block, err := aes.NewCipher(keys.Key)
		if err != nil {
			return nil, fmt.Errorf("crypto: failed to create AES cipher: %w", err)
		}
		a, err = cipher.NewGCM(block)
		if err != nil {
			return nil, fmt.Errorf("crypto: failed to create GCM AEAD: %w", err)
		}
	default:
		return nil, fmt.Errorf("crypto: cipher suite %s not yet implemented", cs.HeaderProtection)
	}

	// Ensure key material is copied so caller can't mutate it
	keyCopy := make([]byte, len(keys.Key))
	copy(keyCopy, keys.Key)
	ivCopy := make([]byte, len(keys.IV))
	copy(ivCopy, keys.IV)

	return &AEAD{
		aead:    a,
		key:     keyCopy,
		iv:      ivCopy,
		keyLen:  len(keyCopy),
		ivLen:   len(ivCopy),
		suiteID: suiteID,
	}, nil
}

// constructNonce builds the AEAD nonce by XORing the IV with the padded
// packet number (RFC 9001 §5.3).
//
// The 62 bits of the reconstructed QUIC packet number in network byte order
// are left-padded with zeros to the size of the IV. The exclusive OR of the
// padded packet number and the IV forms the AEAD nonce.
func (a *AEAD) constructNonce(packetNumber uint64) []byte {
	nonce := make([]byte, a.ivLen)
	copy(nonce, a.iv)

	// Write packet number as 8-byte big-endian, then XOR with IV
	// The packet number occupies the least significant bytes
	var pnBuf [8]byte
	binary.BigEndian.PutUint64(pnBuf[:], packetNumber)

	// XOR the last ivLen bytes of pnBuf with the IV
	offset := a.ivLen - 8
	if offset < 0 {
		offset = 0
	}
	for i := 0; i < a.ivLen && i < 8; i++ {
		nonce[a.ivLen-1-i] ^= pnBuf[7-i]
	}

	return nonce
}

// Encrypt encrypts the packet payload using AEAD (RFC 9001 §5.3).
//
// Parameters:
//   - packetNumber: the full (reconstructed) packet number
//   - header: the unprotected QUIC header bytes (first byte through packet number)
//   - plaintext: the packet payload (frames)
//
// Returns the ciphertext (plaintext length + auth tag length).
// The associated data is the unprotected header.
func (a *AEAD) Encrypt(packetNumber uint64, header, plaintext []byte) []byte {
	nonce := a.constructNonce(packetNumber)
	ciphertext := a.aead.Seal(nil, nonce, plaintext, header)
	a.txCount++
	return ciphertext
}

// Decrypt decrypts the packet payload using AEAD (RFC 9001 §5.3).
//
// Parameters:
//   - packetNumber: the full (reconstructed) packet number
//   - header: the unprotected QUIC header bytes (associated data)
//   - ciphertext: the encrypted payload (including auth tag)
//
// Returns the decrypted payload or an error if authentication fails.
func (a *AEAD) Decrypt(packetNumber uint64, header, ciphertext []byte) ([]byte, error) {
	nonce := a.constructNonce(packetNumber)
	plaintext, err := a.aead.Open(nil, nonce, ciphertext, header)
	if err != nil {
		a.rxCount++
		return nil, fmt.Errorf("crypto: AEAD decryption failed: %w", err)
	}
	return plaintext, nil
}

// Overhead returns the AEAD overhead (auth tag length) in bytes.
func (a *AEAD) Overhead() int {
	return a.aead.Overhead()
}

// Key returns a copy of the AEAD key.
func (a *AEAD) Key() []byte {
	k := make([]byte, len(a.key))
	copy(k, a.key)
	return k
}

// IV returns a copy of the AEAD IV.
func (a *AEAD) IV() []byte {
	iv := make([]byte, len(a.iv))
	copy(iv, a.iv)
	return iv
}

// CipherSuiteID returns the cipher suite ID.
func (a *AEAD) CipherSuiteID() CipherSuiteID {
	return a.suiteID
}

// TxCount returns the number of packets encrypted with this key.
func (a *AEAD) TxCount() uint64 {
	return a.txCount
}

// RxCount returns the number of failed authentications.
func (a *AEAD) RxCount() uint64 {
	return a.rxCount
}

// AEADLimitExceeded checks if the AEAD usage limits have been reached
// (RFC 9001 §6.6). Returns true if the key must be rotated or the
// connection must be closed.
func (a *AEAD) AEADLimitExceeded() bool {
	// Confidentiality limit for AES-GCM: 2^23 encrypted packets
	var confLimit uint64 = 1 << 23
	// Integrity limit for AES-GCM: 2^52 failed authentications
	var integLimit uint64 = uint64(1) << 52

	return a.txCount >= confLimit || a.rxCount >= integLimit
}

// Destroy zeroizes the key material.
func (a *AEAD) Destroy() {
	for i := range a.key {
		a.key[i] = 0
	}
	for i := range a.iv {
		a.iv[i] = 0
	}
}

// KeySet holds the complete set of keys for one direction (send or receive)
// at one encryption level.
type KeySet struct {
	AEAD  *AEAD
	HPKey []byte // Header protection key (does not change on key update)
}

// NewKeySet creates a KeySet from traffic keys and cipher suite.
func NewKeySet(keys TrafficKeys, suiteID CipherSuiteID, isHPKey bool) (*KeySet, error) {
	aead, err := NewAEAD(keys, suiteID)
	if err != nil {
		return nil, err
	}

	hpKey := make([]byte, len(keys.HPKey))
	copy(hpKey, keys.HPKey)

	return &KeySet{
		AEAD:  aead,
		HPKey: hpKey,
	}, nil
}

// ProtectPayload performs full packet protection: AEAD encrypt + header protect.
// This is the high-level API for outgoing packets.
//
// Parameters:
//   - packet: the unprotected packet (header + plaintext payload)
//   - pnOffset: byte offset of the packet number field in the packet
//   - pnLen: encoded packet number length (1-4 bytes)
//   - packetNumber: full reconstructed packet number
//   - isLongHeader: true for long headers, false for short headers
//
// Returns the protected packet.
func ProtectPayload(packet []byte, pnOffset, pnLen int, packetNumber uint64, isLongHeader bool, ks *KeySet) ([]byte, error) {
	if ks == nil || ks.AEAD == nil {
		return nil, errors.New("crypto: nil key set")
	}

	// Split packet into header and payload
	header := packet[:pnOffset+pnLen]
	plaintext := packet[pnOffset+pnLen:]

	// Step 1: AEAD encrypt the payload
	ciphertext := ks.AEAD.Encrypt(packetNumber, header, plaintext)

	// Construct the packet with ciphertext
	protected := make([]byte, len(header)+len(ciphertext))
	copy(protected, header)
	copy(protected[len(header):], ciphertext)

	// Step 2: Apply header protection
	if err := ApplyHeaderProtection(protected, pnOffset, pnLen, isLongHeader, ks.HPKey, ks.AEAD.suiteID); err != nil {
		return nil, fmt.Errorf("crypto: header protection failed: %w", err)
	}

	return protected, nil
}

// UnprotectPayload performs full packet unprotection: remove header protection + AEAD decrypt.
// This is the high-level API for incoming packets.
//
// Parameters:
//   - packet: the protected packet
//   - pnOffset: byte offset of the packet number field in the packet
//   - pnLen: encoded packet number length (1-4 bytes, may be updated after unprotection)
//   - packetNumber: full reconstructed packet number
//   - isLongHeader: true for long headers, false for short headers
//
// Returns the unprotected packet (header + plaintext payload).
func UnprotectPayload(packet []byte, pnOffset, pnLen int, packetNumber uint64, isLongHeader bool, ks *KeySet) ([]byte, error) {
	if ks == nil || ks.AEAD == nil {
		return nil, errors.New("crypto: nil key set")
	}

	// Make a copy to avoid mutating the input
	protected := make([]byte, len(packet))
	copy(protected, packet)

	// Step 1: Remove header protection
	if err := RemoveHeaderProtection(protected, pnOffset, pnLen, isLongHeader, ks.HPKey, ks.AEAD.suiteID); err != nil {
		return nil, fmt.Errorf("crypto: header protection removal failed: %w", err)
	}

	// Step 2: AEAD decrypt the payload
	header := protected[:pnOffset+pnLen]
	ciphertext := protected[pnOffset+pnLen:]

	plaintext, err := ks.AEAD.Decrypt(packetNumber, header, ciphertext)
	if err != nil {
		return nil, fmt.Errorf("crypto: AEAD decryption failed: %w", err)
	}

	// Construct the unprotected packet
	unprotected := make([]byte, len(header)+len(plaintext))
	copy(unprotected, header)
	copy(unprotected[len(header):], plaintext)

	return unprotected, nil
}
