// Package connection: crypto integration layer.
//
// This file wires the crypto package (RFC 9001) into the connection layer.
// It provides:
//   - KeySetStore: per-encryption-level, per-direction key storage
//   - Initial key derivation from the client's Destination Connection ID
//   - Packet protection pipeline (AEAD + header protection) for send/recv
//   - TLS session management: creating TLSSession, routing CRYPTO frames,
//     installing keys from TLS callbacks
//
// RFC 9001 §4 — TLS handshake data flows over CRYPTO frames at each
// encryption level. Keys are installed by TLS callbacks:
//   - QUICSetReadSecret → receive keys for a level
//   - QUICSetWriteSecret → transmit keys for a level
package connection

import (
	"context"
	"crypto/tls"
	"fmt"
	"sync"
	"time"

	"github.com/Cabbage4/quic-go/crypto"
	"github.com/Cabbage4/quic-go/transport"
)

// KeyDirection distinguishes send (transmit) vs. receive keys.
type KeyDirection int

const (
	KeyDirectionSend KeyDirection = iota
	KeyDirectionRecv
)

// keySlot uniquely identifies a key set by encryption level + direction.
type keySlot struct {
	level     crypto.EncryptionLevel
	direction KeyDirection
}

// KeySetStore holds per-encryption-level, per-direction KeySets.
// It manages the lifecycle of keys: installation, discard, lookup.
type KeySetStore struct {
	mu sync.Mutex

	keys map[keySlot]*crypto.KeySet

	// Initial keys derived from DCID (pre-TLS)
	initialDerivationDone bool

	// Cipher suite (negotiated by TLS, defaults to AES-128-GCM)
	cipherSuite crypto.CipherSuiteInfo

	// TLS session for key installation callbacks
	tlsSession *crypto.TLSSession

	// Key manager for Application-level keys (key update support)
	keyManager *crypto.KeyManager

	// Callback when keys are discarded (for PN space cleanup)
	onDiscardKeys func(crypto.EncryptionLevel)
}

// NewKeySetStore creates a new key store with the default cipher suite.
func NewKeySetStore() *KeySetStore {
	return &KeySetStore{
		keys:        make(map[keySlot]*crypto.KeySet),
		cipherSuite: crypto.DefaultCipherSuite(),
	}
}

// DeriveInitialKeys derives the Initial-level send and receive keys
// from the client's Destination Connection ID (RFC 9001 §5.2).
//
// This must be called before any Initial packets can be sent or received.
// For a client, the DCID is the server's address (random).
// For a server, the DCID is the client's chosen DCID from the Initial.
func (s *KeySetStore) DeriveInitialKeys(clientDstConnID []byte, isServer bool) error {
	s.mu.Lock()
	defer s.mu.Unlock()

	cs := crypto.DefaultCipherSuite()

	// Derive initial secrets
	initialSecret := crypto.DeriveInitialSecret(clientDstConnID)
	clientInitialSecret := crypto.DeriveClientInitialSecret(initialSecret)
	serverInitialSecret := crypto.DeriveServerInitialSecret(initialSecret)

	// Client uses client_initial_secret for sending, server_initial_secret for receiving
	// Server uses server_initial_secret for sending, client_initial_secret for receiving
	var txSecret, rxSecret []byte
	if isServer {
		txSecret = serverInitialSecret
		rxSecret = clientInitialSecret
	} else {
		txSecret = clientInitialSecret
		rxSecret = serverInitialSecret
	}

	// Derive traffic keys for both directions
	txTrafficKeys := crypto.DeriveTrafficKeys(txSecret, cs)
	rxTrafficKeys := crypto.DeriveTrafficKeys(rxSecret, cs)

	txKeySet, err := crypto.NewKeySet(txTrafficKeys, cs.ID, true)
	if err != nil {
		return fmt.Errorf("connection: failed to create tx initial key set: %w", err)
	}
	rxKeySet, err := crypto.NewKeySet(rxTrafficKeys, cs.ID, true)
	if err != nil {
		return fmt.Errorf("connection: failed to create rx initial key set: %w", err)
	}

	s.keys[keySlot{crypto.EncryptionInitial, KeyDirectionSend}] = txKeySet
	s.keys[keySlot{crypto.EncryptionInitial, KeyDirectionRecv}] = rxKeySet
	s.initialDerivationDone = true
	s.cipherSuite = cs

	return nil
}

// InstallKeys stores a KeySet for the given level + direction.
// Called by TLS callbacks (QUICSetWriteSecret → Send, QUICSetReadSecret → Recv).
func (s *KeySetStore) InstallKeys(level crypto.EncryptionLevel, dir KeyDirection, ks *crypto.KeySet) {
	s.mu.Lock()
	defer s.mu.Unlock()
	s.keys[keySlot{level, dir}] = ks
}

// GetKeys returns the KeySet for the given level + direction, or nil.
func (s *KeySetStore) GetKeys(level crypto.EncryptionLevel, dir KeyDirection) *crypto.KeySet {
	s.mu.Lock()
	defer s.mu.Unlock()
	return s.keys[keySlot{level, dir}]
}

// HasKeys returns true if keys exist for the given level + direction.
func (s *KeySetStore) HasKeys(level crypto.EncryptionLevel, dir KeyDirection) bool {
	s.mu.Lock()
	defer s.mu.Unlock()
	_, ok := s.keys[keySlot{level, dir}]
	return ok
}

// DiscardKeys removes keys for the given encryption level (RFC 9001 §4.9).
//
//   - Client discards Initial keys when it first sends a Handshake packet
//   - Server discards Initial keys when it first processes a Handshake packet
//   - Both discard Handshake keys when handshake is confirmed
//   - Client discards 0-RTT keys when 1-RTT keys are installed
func (s *KeySetStore) DiscardKeys(level crypto.EncryptionLevel) {
	s.mu.Lock()
	defer s.mu.Unlock()

	for dir := KeyDirectionSend; dir <= KeyDirectionRecv; dir++ {
		slot := keySlot{level, dir}
		if ks, ok := s.keys[slot]; ok {
			ks.AEAD.Destroy()
			delete(s.keys, slot)
		}
	}

	if s.onDiscardKeys != nil {
		s.onDiscardKeys(level)
	}
}

// SetDiscardCallback sets a callback invoked when keys are discarded
// for a level, allowing the connection to clean up PN-space state.
func (s *KeySetStore) SetDiscardCallback(cb func(crypto.EncryptionLevel)) {
	s.mu.Lock()
	defer s.mu.Unlock()
	s.onDiscardKeys = cb
}

// SetTLSSession associates a TLS session with this key store.
// The TLS session's key callbacks are wired to install keys into this store.
func (s *KeySetStore) SetTLSSession(session *crypto.TLSSession) {
	s.mu.Lock()
	defer s.mu.Unlock()
	s.tlsSession = session
}

// TLSSession returns the associated TLS session.
func (s *KeySetStore) TLSSession() *crypto.TLSSession {
	s.mu.Lock()
	defer s.mu.Unlock()
	return s.tlsSession
}

// SetKeyManager sets the Application-level key manager for key update support.
func (s *KeySetStore) SetKeyManager(km *crypto.KeyManager) {
	s.mu.Lock()
	defer s.mu.Unlock()
	s.keyManager = km
}

// KeyManager returns the Application-level key manager.
func (s *KeySetStore) KeyManager() *crypto.KeyManager {
	s.mu.Lock()
	defer s.mu.Unlock()
	return s.keyManager
}

// ProtectPacket protects an outgoing QUIC packet using the keys for the
// given encryption level (RFC 9001 §5.3-5.4).
//
// Parameters:
//   - packet: the unprotected packet (header + plaintext payload)
//   - pnOffset: byte offset of the packet number field
//   - pnLen: encoded packet number length (1-4 bytes)
//   - packetNumber: full reconstructed packet number
//   - isLongHeader: true for long headers, false for short headers
//   - level: encryption level to select keys
//
// Returns the protected packet or an error.
func (s *KeySetStore) ProtectPacket(packet []byte, pnOffset, pnLen int, packetNumber uint64, isLongHeader bool, level crypto.EncryptionLevel) ([]byte, error) {
	var ks *crypto.KeySet

	// For Application level, use the key manager's tx keys if available
	if level == crypto.EncryptionApplication {
		s.mu.Lock()
		if s.keyManager != nil {
			ks = s.keyManager.TxKeys()
		} else {
			ks = s.keys[keySlot{level, KeyDirectionSend}]
		}
		s.mu.Unlock()
	} else {
		ks = s.GetKeys(level, KeyDirectionSend)
	}

	if ks == nil {
		return nil, fmt.Errorf("connection: no send keys for level %s", level)
	}

	return crypto.ProtectPayload(packet, pnOffset, pnLen, packetNumber, isLongHeader, ks)
}

// UnprotectPacket removes protection from an incoming QUIC packet
// (RFC 9001 §5.3-5.4).
//
// Parameters:
//   - packet: the protected packet
//   - pnOffset: byte offset of the packet number field
//   - pnLen: encoded packet number length (1-4 bytes)
//   - packetNumber: full reconstructed packet number
//   - isLongHeader: true for long headers, false for short headers
//   - level: encryption level to select keys
//
// Returns the unprotected packet (header + plaintext payload) or an error.
func (s *KeySetStore) UnprotectPacket(packet []byte, pnOffset, pnLen int, packetNumber uint64, isLongHeader bool, level crypto.EncryptionLevel) ([]byte, error) {
	var ks *crypto.KeySet

	if level == crypto.EncryptionApplication {
		s.mu.Lock()
		if s.keyManager != nil {
			ks = s.keyManager.RxKeys()
		} else {
			ks = s.keys[keySlot{level, KeyDirectionRecv}]
		}
		s.mu.Unlock()
	} else {
		ks = s.GetKeys(level, KeyDirectionRecv)
	}

	if ks == nil {
		return nil, fmt.Errorf("connection: no recv keys for level %s", level)
	}

	return crypto.UnprotectPayload(packet, pnOffset, pnLen, packetNumber, isLongHeader, ks)
}

// StartTLS creates a TLS session and wires up key callbacks.
//
// Parameters:
//   - isClient: whether this is a client-side connection
//   - transportParams: serialized transport parameters to send
//   - alpnProtocols: supported ALPN protocols
//   - serverName: SNI (client only)
//   - onTransportParams: callback when peer's transport params are received
func (s *KeySetStore) StartTLS(
	isClient bool,
	transportParams []byte,
	alpnProtocols []string,
	serverName string,
	certificates []tls.Certificate,
	insecureSkipVerify bool,
	onTransportParams func([]byte),
) error {
	s.mu.Lock()
	defer s.mu.Unlock()

	tlsConfig := &crypto.TLSConfig{
		IsClient:            isClient,
		TransportParameters: transportParams,
		ALPNProtocols:       alpnProtocols,
		ServerName:          serverName,
		Certificates:        certificates,
		InsecureSkipVerify:  insecureSkipVerify,
	}

	session, err := crypto.NewTLSSession(tlsConfig)
	if err != nil {
		return fmt.Errorf("connection: failed to create TLS session: %w", err)
	}

	// Wire up key installation callbacks
	session.SetKeyCallbacks(
		func(level crypto.EncryptionLevel, ks *crypto.KeySet) {
			// Write secret → install send keys
			s.InstallKeys(level, KeyDirectionSend, ks)
		},
		func(level crypto.EncryptionLevel, ks *crypto.KeySet) {
			// Read secret → install recv keys
			s.InstallKeys(level, KeyDirectionRecv, ks)
		},
	)

	if onTransportParams != nil {
		session.SetTransportParamsCallback(onTransportParams)
	}

	s.tlsSession = session
	return nil
}

// DriveTLS starts the TLS handshake and processes initial events.
func (s *KeySetStore) DriveTLS(ctx context.Context) error {
	s.mu.Lock()
	session := s.tlsSession
	s.mu.Unlock()

	if session == nil {
		return fmt.Errorf("connection: no TLS session configured")
	}

	return session.Start(ctx)
}

// FeedCryptoData feeds received CRYPTO frame data to the TLS stack.
func (s *KeySetStore) FeedCryptoData(level crypto.EncryptionLevel, data []byte) error {
	s.mu.Lock()
	session := s.tlsSession
	s.mu.Unlock()

	if session == nil {
		return fmt.Errorf("connection: no TLS session configured")
	}

	return session.HandleCryptoData(level, data)
}

// GetCryptoData returns pending CRYPTO frame data to send at a level.
func (s *KeySetStore) GetCryptoData(level crypto.EncryptionLevel) []byte {
	s.mu.Lock()
	session := s.tlsSession
	s.mu.Unlock()

	if session == nil {
		return nil
	}

	return session.GetCryptoData(level)
}

// EncryptionLevelToPNSpace maps an encryption level to its packet number space.
func EncryptionLevelToPNSpace(level crypto.EncryptionLevel) PNSpace {
	switch level {
	case crypto.EncryptionInitial:
		return PNSpaceInitial
	case crypto.EncryptionHandshake:
		return PNSpaceHandshake
	case crypto.EncryptionApplication, crypto.EncryptionEarly:
		return PNSpaceApplication
	default:
		return PNSpaceInitial
	}
}

// PNSpaceToEncryptionLevel maps a packet number space to its encryption level.
func PNSpaceToEncryptionLevel(space PNSpace) crypto.EncryptionLevel {
	switch space {
	case PNSpaceInitial:
		return crypto.EncryptionInitial
	case PNSpaceHandshake:
		return crypto.EncryptionHandshake
	case PNSpaceApplication:
		return crypto.EncryptionApplication
	default:
		return crypto.EncryptionInitial
	}
}

// TransportParamsToBytes encodes transport parameters for TLS exchange.
func TransportParamsToBytes(params *transport.Params) ([]byte, error) {
	if params == nil {
		return nil, fmt.Errorf("connection: nil transport params")
	}
	return params.Encode()
}

// SetupApplicationKeyManager creates a KeyManager for Application-level keys
// after the TLS handshake provides the 1-RTT secrets.
func (s *KeySetStore) SetupApplicationKeyManager(txSecret, rxSecret []byte) error {
	s.mu.Lock()
	defer s.mu.Unlock()

	km, err := crypto.NewKeyManager(txSecret, rxSecret, s.cipherSuite)
	if err != nil {
		return fmt.Errorf("connection: failed to create key manager: %w", err)
	}
	s.keyManager = km
	return nil
}

// now returns the current time (helper for testability).
var now = func() time.Time {
	return time.Now()
}
