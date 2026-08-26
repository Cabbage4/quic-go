package token

import (
	"crypto/aes"
	"crypto/cipher"
)

// computeAES128GCMTag computes the AES-128-GCM authentication tag
// for an empty plaintext with the given key and AAD.
// This is used for the Retry packet integrity tag (RFC 9000 §17.2.5).
func computeAES128GCMTag(key, aad []byte) []byte {
	block, err := aes.NewCipher(key)
	if err != nil {
		return nil
	}

	gcm, err := cipher.NewGCM(block)
	if err != nil {
		return nil
	}

	// Seal with empty plaintext and 12-byte all-zero nonce
	nonce := make([]byte, gcm.NonceSize()) // 12 bytes, all zeros
	sealed := gcm.Seal(nil, nonce, []byte{}, aad)

	// The authentication tag is the last 16 bytes of the sealed output
	// For an empty plaintext, the entire sealed output IS the tag.
	return sealed
}
