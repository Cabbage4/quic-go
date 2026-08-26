// Package crypto implements QUIC key update per RFC 9001 §6.
//
// Key Update Mechanism:
//   - After handshake confirmation, either endpoint MAY initiate a key update
//   - The Key Phase bit in the short header indicates which keys are used
//   - Initially set to 0 for the first 1-RTT packets, toggles on each update
//   - Both endpoints update keys (unlike TLS where endpoints can update independently)
//   - This mechanism replaces the TLS KeyUpdate mechanism
//
// Key Update Process (RFC 9001 §6.1):
//   1. Update the packet protection write secret using "quic ku" label
//   2. Derive new key and IV from the new secret (per §5.1)
//   3. Header protection key is NOT updated
//   4. Toggle the Key Phase bit
//   5. Use updated key and IV for all subsequent packets
package crypto

import (
	"fmt"
	"sync"
)

// KeyPhase represents the current key phase (0 or 1).
type KeyPhase bool

const (
	KeyPhaseZero KeyPhase = false
	KeyPhaseOne  KeyPhase = true
)

// String returns "0" or "1".
func (kp KeyPhase) String() string {
	if kp == KeyPhaseZero {
		return "0"
	}
	return "1"
}

// Toggle returns the opposite key phase.
func (kp KeyPhase) Toggle() KeyPhase {
	return !kp
}

// KeyUpdateError represents an error during key update processing.
type KeyUpdateError struct {
	Msg string
}

func (e *KeyUpdateError) Error() string {
	return fmt.Sprintf("crypto: key update error: %s", e.Msg)
}

// KeyManager manages the packet protection keys for both directions
// (send and receive) at the Application (1-RTT) encryption level,
// including key updates and key phase tracking (RFC 9001 §6).
type KeyManager struct {
	mu sync.Mutex

	cipherSuite CipherSuiteInfo

	// Current traffic secrets
	txSecret []byte // current transmit secret
	rxSecret []byte // current receive secret

	// Current key sets
	txKeys *KeySet // current transmit keys
	rxKeys *KeySet // current receive keys

	// Next receive keys (pre-generated to avoid timing side channels, RFC 9001 §6.3)
	nextRxKeys *KeySet
	nextRxSecret []byte

	// Previous receive keys (retained for delayed packets, RFC 9001 §6.5)
	prevRxKeys   *KeySet
	prevRxExpiry int64 // monotonic time when previous keys should be discarded

	// Key phase tracking
	txKeyPhase KeyPhase // current transmit key phase
	rxKeyPhase KeyPhase // current receive key phase

	// Track the lowest PN sent in the current key phase (for key update eligibility)
	lowestPNSentCurrentPhase uint64
	// Track the highest acknowledged PN in 1-RTT space
	highestAckedPN uint64

	// Whether handshake is confirmed (key updates only allowed after confirmation)
	handshakeConfirmed bool

	// Whether a key update has been initiated but not yet acknowledged
	updateInFlight bool
}

// NewKeyManager creates a new KeyManager for the Application encryption level.
func NewKeyManager(txSecret, rxSecret []byte, cs CipherSuiteInfo) (*KeyManager, error) {
	txKeys, err := NewKeySet(DeriveTrafficKeys(txSecret, cs), cs.ID, true)
	if err != nil {
		return nil, fmt.Errorf("crypto: failed to create tx keys: %w", err)
	}
	rxKeys, err := NewKeySet(DeriveTrafficKeys(rxSecret, cs), cs.ID, true)
	if err != nil {
		return nil, fmt.Errorf("crypto: failed to create rx keys: %w", err)
	}

	// Pre-generate next receive keys (RFC 9001 §6.3)
	nextRxSecret := DeriveKeyUpdateSecret(rxSecret, cs.Hash)
	nextRxKeys, err := NewKeySet(DeriveTrafficKeys(nextRxSecret, cs), cs.ID, true)
	if err != nil {
		return nil, fmt.Errorf("crypto: failed to pre-generate next rx keys: %w", err)
	}

	return &KeyManager{
		cipherSuite:   cs,
		txSecret:       txSecret,
		rxSecret:       rxSecret,
		txKeys:         txKeys,
		rxKeys:         rxKeys,
		nextRxKeys:     nextRxKeys,
		nextRxSecret:   nextRxSecret,
		txKeyPhase:     KeyPhaseZero,
		rxKeyPhase:     KeyPhaseZero,
		highestAckedPN: 0,
	}, nil
}

// SetHandshakeConfirmed marks the handshake as confirmed, enabling key updates.
func (km *KeyManager) SetHandshakeConfirmed() {
	km.mu.Lock()
	defer km.mu.Unlock()
	km.handshakeConfirmed = true
}

// CanInitiateKeyUpdate returns true if a key update can be initiated.
//
// Per RFC 9001 §6.1:
//   - MUST NOT initiate before handshake confirmation
//   - MUST NOT initiate a subsequent update unless an ACK has been received
//     for a packet sent with keys from the current key phase
func (km *KeyManager) CanInitiateKeyUpdate() bool {
	km.mu.Lock()
	defer km.mu.Unlock()

	if !km.handshakeConfirmed {
		return false
	}

	if !km.updateInFlight {
		return true
	}

	// Check if we've received an ACK for a packet sent in the current phase
	return km.highestAckedPN >= km.lowestPNSentCurrentPhase
}

// InitiateKeyUpdate initiates a key update (RFC 9001 §6.1).
//
// This updates the transmit keys and toggles the Key Phase bit.
// It also updates the receive keys to the next generation.
func (km *KeyManager) InitiateKeyUpdate() error {
	km.mu.Lock()
	defer km.mu.Unlock()

	if !km.handshakeConfirmed {
		return &KeyUpdateError{Msg: "handshake not confirmed"}
	}

	if km.updateInFlight && km.highestAckedPN < km.lowestPNSentCurrentPhase {
		return &KeyUpdateError{Msg: "previous key update not yet acknowledged"}
	}

	// Check AEAD limits
	if km.txKeys.AEAD.AEADLimitExceeded() {
		return &KeyUpdateError{Msg: "AEAD limit reached, cannot update"}
	}

	// Save old receive keys as previous (for delayed packets)
	km.prevRxKeys = km.rxKeys
	// prevRxExpiry will be set by caller via SetPrevRxExpiry

	// Update transmit secret and keys
	km.txSecret = DeriveKeyUpdateSecret(km.txSecret, km.cipherSuite.Hash)
	newTxKeys, err := NewKeySet(DeriveTrafficKeys(km.txSecret, km.cipherSuite), km.cipherSuite.ID, true)
	if err != nil {
		return fmt.Errorf("crypto: failed to derive new tx keys: %w", err)
	}
	km.txKeys = newTxKeys

	// Update receive keys to next (pre-generated)
	km.rxSecret = km.nextRxSecret
	km.rxKeys = km.nextRxKeys

	// Pre-generate the next next receive keys
	km.nextRxSecret = DeriveKeyUpdateSecret(km.rxSecret, km.cipherSuite.Hash)
	km.nextRxKeys, err = NewKeySet(DeriveTrafficKeys(km.nextRxSecret, km.cipherSuite), km.cipherSuite.ID, true)
	if err != nil {
		return fmt.Errorf("crypto: failed to pre-generate next rx keys: %w", err)
	}

	// Toggle key phase
	km.txKeyPhase = km.txKeyPhase.Toggle()
	km.rxKeyPhase = km.rxKeyPhase.Toggle()

	// Reset tracking
	km.updateInFlight = true
	km.lowestPNSentCurrentPhase = 0

	return nil
}

// HandlePeerKeyUpdate handles a key update detected from the peer's
// Key Phase bit change (RFC 9001 §6.2).
//
// This is called when a packet is received with a Key Phase bit that
// differs from the last packet we sent.
func (km *KeyManager) HandlePeerKeyUpdate() error {
	km.mu.Lock()
	defer km.mu.Unlock()

	// Use the next receive keys to process the packet
	// If successful, update send keys to match
	km.prevRxKeys = km.rxKeys

	// Rotate receive keys
	km.rxSecret = km.nextRxSecret
	km.rxKeys = km.nextRxKeys

	// Also update transmit keys (both endpoints update, RFC 9001 §6)
	km.txSecret = DeriveKeyUpdateSecret(km.txSecret, km.cipherSuite.Hash)
	txKeys, err := NewKeySet(DeriveTrafficKeys(km.txSecret, km.cipherSuite), km.cipherSuite.ID, true)
	if err != nil {
		return fmt.Errorf("crypto: failed to update tx keys for peer key update: %w", err)
	}
	km.txKeys = txKeys

	// Pre-generate next receive keys
	km.nextRxSecret = DeriveKeyUpdateSecret(km.rxSecret, km.cipherSuite.Hash)
	km.nextRxKeys, err = NewKeySet(DeriveTrafficKeys(km.nextRxSecret, km.cipherSuite), km.cipherSuite.ID, true)
	if err != nil {
		return fmt.Errorf("crypto: failed to pre-generate next rx keys: %w", err)
	}

	// Toggle key phases
	km.txKeyPhase = km.txKeyPhase.Toggle()
	km.rxKeyPhase = km.rxKeyPhase.Toggle()

	// Reset tracking
	km.updateInFlight = false

	return nil
}

// TxKeyPhase returns the current transmit key phase.
func (km *KeyManager) TxKeyPhase() KeyPhase {
	km.mu.Lock()
	defer km.mu.Unlock()
	return km.txKeyPhase
}

// RxKeyPhase returns the current receive key phase.
func (km *KeyManager) RxKeyPhase() KeyPhase {
	km.mu.Lock()
	defer km.mu.Unlock()
	return km.rxKeyPhase
}

// TxKeys returns the current transmit key set.
func (km *KeyManager) TxKeys() *KeySet {
	km.mu.Lock()
	defer km.mu.Unlock()
	return km.txKeys
}

// RxKeys returns the current receive key set.
func (km *KeyManager) RxKeys() *KeySet {
	km.mu.Lock()
	defer km.mu.Unlock()
	return km.rxKeys
}

// NextRxKeys returns the next receive key set (for key update detection).
func (km *KeyManager) NextRxKeys() *KeySet {
	km.mu.Lock()
	defer km.mu.Unlock()
	return km.nextRxKeys
}

// PrevRxKeys returns the previous receive key set (for delayed packets).
func (km *KeyManager) PrevRxKeys() *KeySet {
	km.mu.Lock()
	defer km.mu.Unlock()
	return km.prevRxKeys
}

// RecordPacketSent records that a packet was sent at the current key phase.
func (km *KeyManager) RecordPacketSent(pn uint64) {
	km.mu.Lock()
	defer km.mu.Unlock()
	if km.lowestPNSentCurrentPhase == 0 || pn < km.lowestPNSentCurrentPhase {
		km.lowestPNSentCurrentPhase = pn
	}
}

// RecordAckedPN records the highest acknowledged packet number.
func (km *KeyManager) RecordAckedPN(pn uint64) {
	km.mu.Lock()
	defer km.mu.Unlock()
	if pn > km.highestAckedPN {
		km.highestAckedPN = pn
	}
}

// ShouldDiscardPrevKeys returns true if previous receive keys should be
// discarded (after 3 * PTO, RFC 9001 §6.5).
func (km *KeyManager) ShouldDiscardPrevKeys(now int64) bool {
	km.mu.Lock()
	defer km.mu.Unlock()
	if km.prevRxKeys == nil {
		return false
	}
	if km.prevRxExpiry == 0 {
		return false
	}
	return now >= km.prevRxExpiry
}

// SetPrevRxExpiry sets the time after which previous receive keys should be discarded.
func (km *KeyManager) SetPrevRxExpiry(expiryTime int64) {
	km.mu.Lock()
	defer km.mu.Unlock()
	km.prevRxExpiry = expiryTime
}

// DiscardPrevKeys discards the previous receive keys.
func (km *KeyManager) DiscardPrevKeys() {
	km.mu.Lock()
	defer km.mu.Unlock()
	if km.prevRxKeys != nil {
		km.prevRxKeys.AEAD.Destroy()
		km.prevRxKeys = nil
	}
}

// SelectRxKeys selects the appropriate receive key set based on the
// packet number and key phase (RFC 9001 §6.5).
//
// Returns the key set to use, or nil if no key set matches.
func (km *KeyManager) SelectRxKeys(pn uint64, phase KeyPhase) *KeySet {
	km.mu.Lock()
	defer km.mu.Unlock()

	if phase == km.rxKeyPhase {
		// Current key phase
		return km.rxKeys
	}

	// Different key phase — either previous or next
	// Use packet numbers to distinguish (RFC 9001 §6.5)
	if km.prevRxKeys != nil && pn < km.lowestPNSentCurrentPhase {
		// Previous key phase
		return km.prevRxKeys
	}

	// Next key phase
	return km.nextRxKeys
}

// AEADLimitReached checks if AEAD limits have been reached for the
// current transmit keys, requiring a key update or connection close.
func (km *KeyManager) AEADLimitReached() bool {
	km.mu.Lock()
	defer km.mu.Unlock()
	return km.txKeys.AEAD.AEADLimitExceeded()
}

// CloseKeyUpdate marks the current key update as acknowledged.
func (km *KeyManager) CloseKeyUpdate() {
	km.mu.Lock()
	defer km.mu.Unlock()
	km.updateInFlight = false
}

// GetCipherSuite returns the cipher suite used by this key manager.
func (km *KeyManager) GetCipherSuite() CipherSuiteInfo {
	return km.cipherSuite
}

// Destroy cleans up all key material.
func (km *KeyManager) Destroy() {
	km.mu.Lock()
	defer km.mu.Unlock()
	if km.txKeys != nil {
		km.txKeys.AEAD.Destroy()
	}
	if km.rxKeys != nil {
		km.rxKeys.AEAD.Destroy()
	}
	if km.nextRxKeys != nil {
		km.nextRxKeys.AEAD.Destroy()
	}
	if km.prevRxKeys != nil {
		km.prevRxKeys.AEAD.Destroy()
	}
}
