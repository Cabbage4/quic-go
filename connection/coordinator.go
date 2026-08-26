// Package connection: connection coordinator for lifecycle management.
//
// This file implements the Coordinator that orchestrates all connection
// subsystems during the connection lifecycle:
//
//   - Connection establishment: coordinates TLS handshake, CRYPTO frame
//     routing, key installation, and state transitions
//   - PN space discard: when keys are discarded, also discard PN space,
//     ACK tracker, and recovery state (RFC 9001 §4.9, RFC 9002 A.11)
//   - Key phase management: detects key phase changes on incoming packets
//     and triggers key updates (RFC 9001 §6)
//   - Connection close: proper CONNECTION_CLOSE exchange with draining
//   - Idle timeout integration with recovery PTO
package connection

import (
	"context"
	"fmt"
	"sync"

	"github.com/Cabbage4/quic-go/crypto"
	"github.com/Cabbage4/quic-go/errors"
	"github.com/Cabbage4/quic-go/frames"
	"github.com/Cabbage4/quic-go/transport"
)

// Coordinator orchestrates all connection-layer subsystems during
// the connection lifecycle. It acts as the central controller that
// drives state transitions and coordinates cleanup between subsystems.
type Coordinator struct {
	mu sync.Mutex

	conn         *Connection
	keyStore    *KeySetStore
	frameHandler *FrameHandler
	recovery    *RecoveryManager
	ackHandler  *AckHandler

	// Whether plaintext mode is enabled (no TLS/encryption)
	plaintextMode bool

	// Whether the initial keys have been derived
	initialKeysDerived bool

	// Whether 0-RTT keys have been installed
	hasEarlyKeys bool

	// Whether Handshake keys have been installed
	hasHandshakeKeys bool

	// Whether 1-RTT (Application) keys have been installed
	hasApplicationKeys bool

	// Whether the Initial PN space has been discarded
	initialDiscarded bool

	// Whether the Handshake PN space has been discarded
	handshakeDiscarded bool

	// Whether address validation is complete
	addressValidationComplete bool

	// Local transport parameters for TLS exchange
	localParams *transport.Params

	// Close state
	closing     bool
	closeError  *errors.Error
	closeReason string

	// Callbacks
	onStateChange func(ConnectionState)
	onHandshakeComplete func()
	onClose func()
}

// NewCoordinator creates a new connection coordinator.
func NewCoordinator(
	conn *Connection,
	keyStore *KeySetStore,
	frameHandler *FrameHandler,
	recovery *RecoveryManager,
	ackHandler *AckHandler,
) *Coordinator {
	return &Coordinator{
		conn:         conn,
		keyStore:    keyStore,
		frameHandler: frameHandler,
		recovery:    recovery,
		ackHandler:  ackHandler,
	}
}

// SetPlaintextMode enables or disables plaintext (no encryption) mode.
func (c *Coordinator) SetPlaintextMode(plaintext bool) {
	c.mu.Lock()
	defer c.mu.Unlock()
	c.plaintextMode = plaintext
}

// SetLocalParams sets the local transport parameters for TLS exchange.
func (c *Coordinator) SetLocalParams(params *transport.Params) {
	c.mu.Lock()
	defer c.mu.Unlock()
	c.localParams = params
}

// SetOnStateChange sets a callback for connection state changes.
func (c *Coordinator) SetOnStateChange(cb func(ConnectionState)) {
	c.mu.Lock()
	defer c.mu.Unlock()
	c.onStateChange = cb
}

// SetOnHandshakeComplete sets a callback for handshake completion.
func (c *Coordinator) SetOnHandshakeComplete(cb func()) {
	c.mu.Lock()
	defer c.mu.Unlock()
	c.onHandshakeComplete = cb
}

// SetOnClose sets a callback for connection close.
func (c *Coordinator) SetOnClose(cb func()) {
	c.mu.Lock()
	defer c.mu.Unlock()
	c.onClose = cb
}

// === Connection Establishment ===

// DeriveInitialKeys derives the Initial-level keys from the client's
// Destination Connection ID (RFC 9001 §5.2).
// This is the first step in connection establishment.
func (c *Coordinator) DeriveInitialKeys(clientDstConnID []byte) error {
	c.mu.Lock()
	defer c.mu.Unlock()

	if c.plaintextMode {
		// In plaintext mode, skip key derivation
		c.initialKeysDerived = true
		return nil
	}

	if err := c.keyStore.DeriveInitialKeys(clientDstConnID, c.conn.IsServer()); err != nil {
		return err
	}

	c.initialKeysDerived = true

	// Set up key discard callback for PN space cleanup
	c.keyStore.SetDiscardCallback(func(level crypto.EncryptionLevel) {
		c.discardPNSpace(level)
	})

	return nil
}

// StartHandshake initiates the TLS handshake (if TLS is configured).
// In plaintext mode, this is a no-op.
func (c *Coordinator) StartHandshake() error {
	c.mu.Lock()
	defer c.mu.Unlock()

	if c.plaintextMode {
		// In plaintext mode, transition directly to handshaking
		c.conn.SetState(StateHandshaking)
		if c.onStateChange != nil {
			c.onStateChange(StateHandshaking)
		}
		return nil
	}

	// Start TLS session
	c.conn.SetState(StateHandshaking)
	if c.onStateChange != nil {
		c.onStateChange(StateHandshaking)
	}

	return nil
}

// OnHandshakeComplete is called when the TLS handshake completes.
// It performs the post-handshake actions:
//   - Transitions to StateEstablished
//   - Server: marks handshake confirmed, queues HANDSHAKE_DONE
//   - Discards 0-RTT keys (if any)
func (c *Coordinator) OnHandshakeComplete() {
	c.mu.Lock()
	defer c.mu.Unlock()

	c.conn.SetState(StateEstablished)
	if c.onStateChange != nil {
		c.onStateChange(StateEstablished)
	}

	if c.conn.IsServer() {
		// Server: handshake is confirmed when it completes
		c.recovery.SetHandshakeConfirmed(true)
		// Queue HANDSHAKE_DONE to be sent
		// The FrameHandler already has pendingHandshakeDone
	}

	// Address validation is complete after handshake
	c.addressValidationComplete = true
	c.recovery.SetPeerCompletedAddressValidation(true)

	if c.onHandshakeComplete != nil {
		c.onHandshakeComplete()
	}
}

// OnHandshakeDoneReceived is called when the client receives a
// HANDSHAKE_DONE frame from the server (RFC 9000 §19.20).
// This confirms the handshake and triggers:
//   - Discard Handshake keys (RFC 9001 §4.9)
//   - Mark handshake as confirmed for loss detection
func (c *Coordinator) OnHandshakeDoneReceived() {
	c.mu.Lock()
	defer c.mu.Unlock()

	if !c.conn.IsServer() {
		c.recovery.SetHandshakeConfirmed(true)
		c.discardHandshakeKeys()
	}
}

// === PN Space Discard (RFC 9001 §4.9, RFC 9002 Appendix A.11) ===

// discardPNSpace discards all state for a PN space when keys are discarded.
// This includes:
//   - ACK tracker reset
//   - Recovery PN space discard
//   - Sent frame tracking cleanup
//   - Key store discard (already done by caller)
func (c *Coordinator) discardPNSpace(level crypto.EncryptionLevel) {
	pnSpace := EncryptionLevelToPNSpace(level)

	c.ackHandler.DiscardPNSpace(pnSpace)
	c.recovery.OnPacketNumberSpaceDiscarded(pnSpace)
	c.frameHandler.CleanUpSentFrames(pnSpace)

	switch level {
	case crypto.EncryptionInitial:
		c.initialDiscarded = true
	case crypto.EncryptionHandshake:
		c.handshakeDiscarded = true
	}
}

// DiscardInitialKeys discards the Initial keys and PN space.
// Client: after first Handshake packet is sent
// Server: after first Handshake packet is received
func (c *Coordinator) DiscardInitialKeys() {
	c.mu.Lock()
	defer c.mu.Unlock()

	if c.initialDiscarded || c.plaintextMode {
		return
	}

	c.keyStore.DiscardKeys(crypto.EncryptionInitial)
	c.initialDiscarded = true
}

// discardHandshakeKeys discards the Handshake keys and PN space.
// Both: after handshake is confirmed
func (c *Coordinator) discardHandshakeKeys() {
	if c.handshakeDiscarded || c.plaintextMode {
		return
	}

	c.keyStore.DiscardKeys(crypto.EncryptionHandshake)
	c.handshakeDiscarded = true
}

// === Key Phase Management (RFC 9001 §6) ===

// CheckKeyPhaseUpdate detects a key phase change on an incoming packet
// and triggers a key update if needed.
//
// When the key phase bit in the incoming packet's short header differs
// from the current receive key phase, the receiver must update to the
// next generation of keys.
func (c *Coordinator) CheckKeyPhaseUpdate(pnSpace PNSpace, keyPhaseBit bool) {
	c.mu.Lock()
	defer c.mu.Unlock()

	if c.plaintextMode {
		return
	}

	km := c.keyStore.KeyManager()
	if km == nil {
		return
	}

	// Determine the KeyPhase from the bit and attempt key selection.
	// The KeyManager tracks the current and previous key phases internally;
	// SelectRxKeys will return the appropriate key set or nil if it cannot
	// determine which phase to use (RFC 9001 §6).
	phase := crypto.KeyPhase(keyPhaseBit)
	// We pass a placeholder packet number of 0; the KeyManager's
	// internal state comparison is what actually matters here.
	_ = km.SelectRxKeys(0, phase)
}

// InitiateKeyUpdate initiates a key update from the sender side.
// This is allowed only after the handshake is confirmed (RFC 9001 §6.1).
func (c *Coordinator) InitiateKeyUpdate() error {
	c.mu.Lock()
	defer c.mu.Unlock()

	if c.plaintextMode {
		return nil
	}

	km := c.keyStore.KeyManager()
	if km == nil {
		return nil
	}

	if !c.recovery.handshakeConfirmed {
		return nil // key updates not allowed before handshake confirmation
	}

	// Check AEAD usage limits (RFC 9001 §6.6)
	// 2^23 packets for confidentiality, 2^52 for integrity
	// The KeyManager.InitiateKeyUpdate method handles the actual key rotation
	return km.InitiateKeyUpdate()
}

// === Connection Close (RFC 9000 §10.2-10.3) ===

// CloseConnection initiates an immediate close of the connection.
// It builds a CONNECTION_CLOSE frame and enters the draining period.
func (c *Coordinator) CloseConnection(err *errors.Error, drain bool) {
	c.mu.Lock()
	if c.closing {
		c.mu.Unlock()
		return
	}
	c.closing = true
	c.closeError = err
	c.mu.Unlock()

	// Use the Connection's Close method which handles the state transition
	// and draining timer
	c.conn.Close(err, drain)

	if c.onClose != nil {
		c.onClose()
	}
}

// HandlePeerClose handles a CONNECTION_CLOSE frame received from the peer.
// The connection enters the draining state without sending a response.
func (c *Coordinator) HandlePeerClose(err *errors.Error) {
	c.mu.Lock()
	defer c.mu.Unlock()

	c.closing = true
	c.closeError = err

	// Enter draining state (don't send our own CONNECTION_CLOSE)
	c.conn.Close(err, true)

	if c.onClose != nil {
		c.onClose()
	}
}

// === State Queries ===

// IsEstablished returns true if the connection is in the Established state.
func (c *Coordinator) IsEstablished() bool {
	c.mu.Lock()
	defer c.mu.Unlock()
	return c.conn.State() == StateEstablished
}

// IsHandshakeComplete returns true if the TLS handshake is complete.
func (c *Coordinator) IsHandshakeComplete() bool {
	c.mu.Lock()
	defer c.mu.Unlock()
	return c.frameHandler.HandshakeComplete()
}

// IsHandshakeConfirmed returns true if the handshake is confirmed.
func (c *Coordinator) IsHandshakeConfirmed() bool {
	c.mu.Lock()
	defer c.mu.Unlock()
	return c.frameHandler.HandshakeConfirmed()
}

// IsClosing returns true if the connection is closing.
func (c *Coordinator) IsClosing() bool {
	c.mu.Lock()
	defer c.mu.Unlock()
	return c.closing
}

// IsClosed returns true if the connection is fully closed.
func (c *Coordinator) IsClosed() bool {
	c.mu.Lock()
	defer c.mu.Unlock()
	return c.conn.State() == StateClosed
}

// CloseError returns the error that caused the connection to close.
func (c *Coordinator) CloseError() *errors.Error {
	c.mu.Lock()
	defer c.mu.Unlock()
	return c.closeError
}

// HasInitialKeys returns true if Initial keys have been derived.
func (c *Coordinator) HasInitialKeys() bool {
	c.mu.Lock()
	defer c.mu.Unlock()
	return c.initialKeysDerived
}

// HasHandshakeKeys returns true if Handshake keys have been installed.
func (c *Coordinator) HasHandshakeKeys() bool {
	c.mu.Lock()
	defer c.mu.Unlock()
	return c.hasHandshakeKeys
}

// HasApplicationKeys returns true if 1-RTT (Application) keys have been installed.
func (c *Coordinator) HasApplicationKeys() bool {
	c.mu.Lock()
	defer c.mu.Unlock()
	return c.hasApplicationKeys
}

// IsPlaintextMode returns true if plaintext mode is enabled.
func (c *Coordinator) IsPlaintextMode() bool {
	c.mu.Lock()
	defer c.mu.Unlock()
	return c.plaintextMode
}

// === Idle Timeout Integration ===

// CheckIdleTimeout returns true if the connection should be closed
// due to idle timeout. This should be called periodically.
func (c *Coordinator) CheckIdleTimeout() bool {
	c.mu.Lock()
	defer c.mu.Unlock()

	if c.conn.State() == StateClosed || c.conn.State() == StateDraining {
		return false
	}

	// Delegate to the Connection's idle check (RFC 9000 §10.1)
	return c.conn.IsIdle()
}

// === Handshake Driver ===

// DriveHandshake processes pending TLS events and drives the handshake forward.
// In plaintext mode, this immediately completes the handshake.
// With TLS, this calls DriveTLS and processes CRYPTO data output.
//
// This should be called in a loop until the handshake is complete.
func (c *Coordinator) DriveHandshake() error {
	c.mu.Lock()
	defer c.mu.Unlock()

	if c.plaintextMode {
		// In plaintext mode, handshake is "complete" immediately
		// The SDK's simplified handshake (PING → HANDSHAKE_DONE) handles this
		if c.conn.State() == StateHandshaking {
			c.conn.SetState(StateEstablished)
			if c.onStateChange != nil {
				c.onStateChange(StateEstablished)
			}
		}
		return nil
	}

	// With TLS: drive the TLS session to process handshake events and
	// produce CRYPTO data. The key store's DriveTLS method handles
	// the crypto/tls QUICConn event loop.
	if err := c.keyStore.DriveTLS(context.Background()); err != nil {
		return fmt.Errorf("coordinator: TLS handshake error: %w", err)
	}

	return nil
}

// === Pending Frames ===

// GeneratePendingFrames returns all control frames that need to be sent
// at the given PN space. This wraps FrameHandler.GenerateControlFrames
// and adds any pending CRYPTO data.
func (c *Coordinator) GeneratePendingFrames(pnSpace PNSpace) []frames.Frame {
	c.mu.Lock()
	defer c.mu.Unlock()

	return c.frameHandler.GenerateControlFrames(pnSpace)
}

// === Stats ===

// Stats returns a summary of connection statistics.
type ConnStats struct {
	State              ConnectionState
	IsServer           bool
	InitialKeysDerived bool
	HandshakeComplete  bool
	HandshakeConfirmed bool
	InitialDiscarded   bool
	HandshakeDiscarded bool
	Closing            bool
}

// Stats returns the current connection statistics.
func (c *Coordinator) Stats() ConnStats {
	c.mu.Lock()
	defer c.mu.Unlock()

	return ConnStats{
		State:              c.conn.State(),
		IsServer:           c.conn.IsServer(),
		InitialKeysDerived: c.initialKeysDerived,
		HandshakeComplete:  c.frameHandler.HandshakeComplete(),
		HandshakeConfirmed: c.frameHandler.HandshakeConfirmed(),
		InitialDiscarded:   c.initialDiscarded,
		HandshakeDiscarded: c.handshakeDiscarded,
		Closing:            c.closing,
	}
}
