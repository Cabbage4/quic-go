package connection

import "crypto/rand"

// defaultRandRead uses crypto/rand for production use.
func defaultRandRead(b []byte) (int, error) {
	return rand.Read(b)
}
