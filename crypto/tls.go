// Package crypto implements the TLS 1.3 integration layer for QUIC (RFC 9001 §4).
//
// This file uses Go's standard library crypto/tls QUICConn API (available since Go 1.21+)
// to perform the TLS handshake over QUIC CRYPTO frames.
//
// Key concepts (RFC 9001 §4):
//   - QUIC carries TLS handshake data in CRYPTO frames, not TLS records
//   - TLS record protection is NOT used; QUIC provides its own packet protection
//   - Four encryption levels: Initial, Early (0-RTT), Handshake, Application (1-RTT)
//   - Three packet number spaces: Initial, Handshake, Application
//   - TLS handshake completion ≠ handshake confirmation
//     - Complete: TLS has sent Finished AND verified peer's Finished
//     - Confirmed (server): when handshake completes; server sends HANDSHAKE_DONE
//     - Confirmed (client): when HANDSHAKE_DONE is received
package crypto

import (
	"context"
	"crypto/tls"
	"errors"
	"fmt"
	"sync"
	"sync/atomic"
)

// TLSConfig provides configuration for a QUIC TLS session.
type TLSConfig struct {
	// IsClient indicates whether this is a client-side configuration.
	IsClient bool

	// TransportParameters are the QUIC transport parameters to be sent
	// in the TLS handshake (ClientHello or EncryptedExtensions).
	TransportParameters []byte

	// ALPNProtocols is the list of supported application protocols.
	ALPNProtocols []string

	// ServerName is the SNI for client connections.
	ServerName string

	// Certificates for server-side TLS.
	Certificates []tls.Certificate

	// InsecureSkipVerify controls whether a client verifies the server's
	// certificate chain and host name. Only for testing.
	InsecureSkipVerify bool

	// RootCAs is the set of root certificate authorities for client-side
	// verification. If nil, the system roots are used.
	RootCAs interface{}
}

// TLSSession manages the TLS handshake state and CRYPTO frame data flow
// between QUIC and the TLS stack (RFC 9001 §4).
type TLSSession struct {
	mu sync.Mutex

	conn     *tls.QUICConn
	config   *TLSConfig
	isClient bool

	// CRYPTO data buffers for each encryption level
	// These accumulate outgoing CRYPTO frame data produced by TLS
	txCryptoData map[EncryptionLevel][]byte

	// Incoming CRYPTO data offsets (to track what's been delivered)
	rxCryptoOffset map[EncryptionLevel]uint64

	// Handshake state
	// handshakeComplete is stored as an atomic for lock-free reads from
	// handleIncoming (recvLoop) to avoid deadlocking with driveHandshakeLoop
	// which holds mu while inside HandleCryptoData → HandleData.
	handshakeComplete      atomic.Bool
	handshakeConfirmed     bool
	started                bool
	receivedTransportParams []byte
	negotiatedProtocol     string

	// Cipher suite negotiated by TLS
	cipherSuiteID CipherSuiteID

	// Error from TLS (if any)
	tlsErr error

	// Callbacks for key installation
	onWriteKeys func(EncryptionLevel, *KeySet)
	onReadKeys  func(EncryptionLevel, *KeySet)

	// Callback for transport parameters received from peer
	onTransportParams func([]byte)
}

// NewTLSSession creates a new TLS session.
//
// For client-side: config.IsClient must be true.
// For server-side: config.IsClient must be false.
func NewTLSSession(config *TLSConfig) (*TLSSession, error) {
	if config == nil {
		return nil, errors.New("crypto: config is required")
	}

	tlsConfig := &tls.Config{
		NextProtos:         config.ALPNProtocols,
		ServerName:         config.ServerName,
		MinVersion:         tls.VersionTLS13,
		MaxVersion:         tls.VersionTLS13,
		InsecureSkipVerify: config.InsecureSkipVerify,
	}

	if len(config.Certificates) > 0 {
		tlsConfig.Certificates = config.Certificates
	}

	// The QUIC transport parameters are delivered via SetTransportParameters
	// on the QUICConn, not through the TLS config.
	quicConfig := &tls.QUICConfig{
		TLSConfig: tlsConfig,
	}

	var conn *tls.QUICConn
	if config.IsClient {
		conn = tls.QUICClient(quicConfig)
	} else {
		conn = tls.QUICServer(quicConfig)
	}

	session := &TLSSession{
		conn:           conn,
		config:         config,
		isClient:       config.IsClient,
		txCryptoData:   make(map[EncryptionLevel][]byte),
		rxCryptoOffset: make(map[EncryptionLevel]uint64),
	}

	return session, nil
}

// Start initiates the TLS handshake.
// For a client, this starts the ClientHello.
// For a server, this begins waiting for the ClientHello.
//
// Transport parameters must be set via SetTransportParameters before Start
// (or in response to the QUICTransportParametersRequired event).
//
// Start may be called multiple times — only the first call actually invokes
// conn.Start(); subsequent calls just process pending TLS events.
func (s *TLSSession) Start(ctx context.Context) error {
	s.mu.Lock()
	defer s.mu.Unlock()

	if !s.started {
		// Set transport parameters if provided
		if len(s.config.TransportParameters) > 0 {
			s.conn.SetTransportParameters(s.config.TransportParameters)
		}

		if err := s.conn.Start(ctx); err != nil {
			return fmt.Errorf("crypto: TLS Start failed: %w", err)
		}
		s.started = true
		fmt.Printf("[TLS] Start: started=%v, isClient=%v\n", s.started, s.isClient)
	}

	return s.processEvents()
}

// HandleCryptoData feeds received CRYPTO frame data to the TLS stack.
//
// The data must be delivered in order for each encryption level.
// Returns any CRYPTO data that TLS produces in response.
func (s *TLSSession) HandleCryptoData(level EncryptionLevel, data []byte) error {
	s.mu.Lock()
	defer s.mu.Unlock()

	// Record the offset for this data
	offset := s.rxCryptoOffset[level]
	s.rxCryptoOffset[level] = offset + uint64(len(data))

	fmt.Printf("[TLS] HandleCryptoData: level=%s, offset=%d, len=%d\n", level, offset, len(data))

	// Feed the data to the TLS stack
	if err := s.conn.HandleData(tlsQUICLevel(level), data); err != nil {
		return fmt.Errorf("crypto: TLS HandleData failed: %w", err)
	}

	// Process any events TLS produces
	return s.processEvents()
}

// GetCryptoData returns the pending CRYPTO frame data to be sent at the
// given encryption level, and clears the buffer.
func (s *TLSSession) GetCryptoData(level EncryptionLevel) []byte {
	s.mu.Lock()
	defer s.mu.Unlock()

	data := s.txCryptoData[level]
	delete(s.txCryptoData, level)
	return data
}

// processEvents processes the TLS event queue and updates QUIC state accordingly.
// Must be called with the mutex held.
func (s *TLSSession) processEvents() error {
	for {
		event := s.conn.NextEvent()

		switch event.Kind {
		case tls.QUICNoEvent:
			return nil

		case tls.QUICSetReadSecret:
			level := tlsToQUICLevel(event.Level)
			secret := event.Data
			csID := CipherSuiteID(event.Suite)
			s.cipherSuiteID = csID
			cs, ok := GetCipherSuite(csID)
			if !ok {
				cs = DefaultCipherSuite()
			}
			keys := DeriveTrafficKeys(secret, cs)
			ks, err := NewKeySet(keys, cs.ID, true)
			if err != nil {
				return fmt.Errorf("crypto: failed to create read key set: %w", err)
			}
			fmt.Printf("[TLS] QUICSetReadSecret: level=%s, suite=%d\n", level, csID)
			if s.onReadKeys != nil {
				s.onReadKeys(level, ks)
			}

		case tls.QUICSetWriteSecret:
			level := tlsToQUICLevel(event.Level)
			secret := event.Data
			csID := CipherSuiteID(event.Suite)
			s.cipherSuiteID = csID
			cs, ok := GetCipherSuite(csID)
			if !ok {
				cs = DefaultCipherSuite()
			}
			keys := DeriveTrafficKeys(secret, cs)
			ks, err := NewKeySet(keys, cs.ID, true)
			if err != nil {
				return fmt.Errorf("crypto: failed to create write key set: %w", err)
			}
			fmt.Printf("[TLS] QUICSetWriteSecret: level=%s, suite=%d\n", level, csID)
			if s.onWriteKeys != nil {
				s.onWriteKeys(level, ks)
			}

		case tls.QUICWriteData:
			level := tlsToQUICLevel(event.Level)
			fmt.Printf("[TLS] QUICWriteData: level=%s, len=%d\n", level, len(event.Data))
			s.txCryptoData[level] = append(s.txCryptoData[level], event.Data...)

		case tls.QUICHandshakeDone:
			fmt.Printf("[TLS] QUICHandshakeDone\n")
			s.handshakeComplete.Store(true)
			// For a server, handshake is confirmed when complete
			if !s.isClient {
				s.handshakeConfirmed = true
			}

		case tls.QUICRejectedEarlyData:
			// 0-RTT was rejected; application should reset state
			// (RFC 9001 §4.6.2)

		case tls.QUICTransportParameters:
			fmt.Printf("[TLS] QUICTransportParameters: len=%d\n", len(event.Data))
			s.receivedTransportParams = event.Data
			if s.onTransportParams != nil {
				// Copy data since it's owned by crypto/tls
				paramsCopy := make([]byte, len(event.Data))
				copy(paramsCopy, event.Data)
				s.onTransportParams(paramsCopy)
			}

		case tls.QUICTransportParametersRequired:
			fmt.Printf("[TLS] QUICTransportParametersRequired\n")
			// We need to provide transport parameters
			if len(s.config.TransportParameters) > 0 {
				s.conn.SetTransportParameters(s.config.TransportParameters)
			}

		case tls.QUICErrorEvent:
			fmt.Printf("[TLS] QUICErrorEvent: %v\n", event.Err)
			s.tlsErr = event.Err
			return fmt.Errorf("crypto: TLS error: %w", event.Err)

		case tls.QUICResumeSession:
			// Session resumption event (client-side)
			// EnableSessionEvents must be true for this to fire

		case tls.QUICStoreSession:
			// Session storage event (client-side)
		}
	}
}

// SetKeyCallbacks sets callbacks for when TLS provides new keys.
// onWrite is called when new transmit keys are available.
// onRead is called when new receive keys are available.
func (s *TLSSession) SetKeyCallbacks(onWrite, onRead func(EncryptionLevel, *KeySet)) {
	s.mu.Lock()
	defer s.mu.Unlock()
	s.onWriteKeys = onWrite
	s.onReadKeys = onRead
}

// SetTransportParamsCallback sets a callback for when the peer's transport
// parameters are received.
func (s *TLSSession) SetTransportParamsCallback(cb func([]byte)) {
	s.mu.Lock()
	defer s.mu.Unlock()
	s.onTransportParams = cb
}

// HandshakeComplete returns true if the TLS handshake is complete
// (both Finished sent and verified, RFC 9001 §4.1.2).
// This uses an atomic read (no mutex) to allow lock-free access from
// the recvLoop without deadlocking with driveHandshakeLoop.
func (s *TLSSession) HandshakeComplete() bool {
	return s.handshakeComplete.Load()
}

// HandshakeConfirmed returns true if the handshake is confirmed.
// For a server: confirmed when handshake completes (server sends HANDSHAKE_DONE).
// For a client: confirmed when HANDSHAKE_DONE is received.
func (s *TLSSession) HandshakeConfirmed() bool {
	s.mu.Lock()
	defer s.mu.Unlock()
	return s.handshakeConfirmed
}

// SetHandshakeConfirmed marks the handshake as confirmed.
// Called when a HANDSHAKE_DONE frame is received (client) or
// when handshake completes (server).
func (s *TLSSession) SetHandshakeConfirmed() {
	s.mu.Lock()
	defer s.mu.Unlock()
	s.handshakeConfirmed = true
}

// GetTransportParameters returns the peer's QUIC transport parameters
// received during the TLS handshake.
func (s *TLSSession) GetTransportParameters() []byte {
	s.mu.Lock()
	defer s.mu.Unlock()
	return s.receivedTransportParams
}

// GetNegotiatedProtocol returns the negotiated ALPN protocol.
func (s *TLSSession) GetNegotiatedProtocol() string {
	s.mu.Lock()
	defer s.mu.Unlock()
	return s.negotiatedProtocol
}

// GetCipherSuiteID returns the negotiated cipher suite.
func (s *TLSSession) GetCipherSuiteID() CipherSuiteID {
	s.mu.Lock()
	defer s.mu.Unlock()
	return s.cipherSuiteID
}

// Close closes the TLS session.
func (s *TLSSession) Close() error {
	s.mu.Lock()
	defer s.mu.Unlock()
	return s.conn.Close()
}

// tlsQUICLevel converts our EncryptionLevel to tls.QUICEncryptionLevel.
func tlsQUICLevel(level EncryptionLevel) tls.QUICEncryptionLevel {
	switch level {
	case EncryptionInitial:
		return tls.QUICEncryptionLevelInitial
	case EncryptionEarly:
		return tls.QUICEncryptionLevelEarly
	case EncryptionHandshake:
		return tls.QUICEncryptionLevelHandshake
	case EncryptionApplication:
		return tls.QUICEncryptionLevelApplication
	default:
		return tls.QUICEncryptionLevelInitial
	}
}

// tlsToQUICLevel converts tls.QUICEncryptionLevel to our EncryptionLevel.
func tlsToQUICLevel(level tls.QUICEncryptionLevel) EncryptionLevel {
	switch level {
	case tls.QUICEncryptionLevelInitial:
		return EncryptionInitial
	case tls.QUICEncryptionLevelEarly:
		return EncryptionEarly
	case tls.QUICEncryptionLevelHandshake:
		return EncryptionHandshake
	case tls.QUICEncryptionLevelApplication:
		return EncryptionApplication
	default:
		return EncryptionInitial
	}
}

// DiscardKeys discards keys for the given encryption level (RFC 9001 §4.9).
//
//   - Client discards Initial keys when it first sends a Handshake packet
//   - Server discards Initial keys when it first successfully processes a Handshake packet
//   - Both discard Handshake keys when the TLS handshake is confirmed
//   - Client discards 0-RTT keys when 1-RTT keys are installed
func (s *TLSSession) DiscardKeys(level EncryptionLevel) {
	s.mu.Lock()
	defer s.mu.Unlock()

	// Clear any pending CRYPTO data for this level
	delete(s.txCryptoData, level)
	delete(s.rxCryptoOffset, level)

	// The actual key material is managed by the connection layer
}

// TLSErrorToQUICError converts a TLS alert to a QUIC transport error code
// (RFC 9001 §4.8).
//
// TLS alerts are converted to QUIC error codes by adding 0x0100 to the
// AlertDescription value, placing them in the CRYPTO_ERROR range.
func TLSErrorToQUICError(alertNum int) uint64 {
	return uint64(0x0100 + alertNum)
}

// IsFatalAlert returns true if the error is a fatal TLS alert.
func IsFatalAlert(err error) bool {
	var alertErr tls.AlertError
	return errors.As(err, &alertErr)
}

// GetAlertNumber extracts the TLS alert number from a tls.AlertError.
func GetAlertNumber(err error) (int, bool) {
	var alertErr tls.AlertError
	if errors.As(err, &alertErr) {
		return int(alertErr), true
	}
	return 0, false
}

// ConnectionState returns the current TLS connection state.
func (s *TLSSession) ConnectionState() tls.ConnectionState {
	s.mu.Lock()
	defer s.mu.Unlock()
	return s.conn.ConnectionState()
}

// IsClient returns whether this is a client-side session.
func (s *TLSSession) IsClient() bool {
	return s.isClient
}

// GetError returns any TLS error that occurred.
func (s *TLSSession) GetError() error {
	s.mu.Lock()
	defer s.mu.Unlock()
	return s.tlsErr
}
