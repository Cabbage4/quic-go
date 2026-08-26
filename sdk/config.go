// Package sdk provides a high-level QUIC SDK for building servers and clients.
//
// The SDK wraps the low-level protocol modules (connection, stream, frames,
// header, ack, path, token, etc.) into a simple API inspired by Go's net
// package:
//
// Server:
//
//	listener, err := sdk.Listen("udp", addr, &sdk.Config{...})
//	for {
//		conn, err := listener.Accept()
//		// handle conn
//	}
//
// Client:
//
//	conn, err := sdk.Dial("udp", serverAddr, &sdk.Config{...})
//	stream, err := conn.OpenStream()
//	stream.Write(data)
//
// The SDK uses the connection layer's PacketIO pipeline for packet
// send/receive, FrameHandler for frame processing, and stream.Manager
// for stream lifecycle management.
//
// In plaintext mode (default, TLSMode=false), packets are not encrypted —
// suitable for testing and learning.
//
// In TLS mode (TLSMode=true), the full RFC 9001 crypto pipeline is used:
// initial key derivation from DCID, TLS 1.3 handshake via crypto/tls
// QUICConn, AEAD packet protection + header protection, and key updates.
// See QUICKSTART.md for a TLS quick start guide.
package sdk

import (
	"crypto/tls"
	"net"
	"time"

	"github.com/Cabbage4/quic-go/connection"
	"github.com/Cabbage4/quic-go/stream"
	"github.com/Cabbage4/quic-go/transport"
)

// Config holds configuration for a QUIC listener or dialer.
type Config struct {
	// Local parameters to advertise to the peer.
	// If nil, DefaultConfig() is used.
	TransportParams *transport.Params

	// MaxIdleTimeout is the maximum idle timeout. If 0, no timeout.
	MaxIdleTimeout time.Duration

	// MaxStreamData is the initial flow control limit per stream.
	// Default: 1 MiB
	MaxStreamData uint64

	// MaxConnectionData is the initial connection-level flow control limit.
	// Default: 10 MiB
	MaxConnectionData uint64

	// MaxStreamsBidi is the maximum number of concurrent bidirectional streams.
	// Default: 100
	MaxStreamsBidi uint64

	// MaxStreamsUni is the maximum number of concurrent unidirectional streams.
	// Default: 100
	MaxStreamsUni uint64

	// ConnIDLength is the length of generated connection IDs.
	// Default: 8
	ConnIDLength int

	// === TLS Configuration ===
	//
	// TLSMode enables TLS 1.3 encryption (RFC 9001).
	// If false (default), the SDK operates in plaintext mode —
	// packets are not encrypted, suitable for testing and learning.
	// If true, the full crypto pipeline is used: initial key derivation,
	// TLS handshake via crypto/tls QUICConn, AEAD packet protection.
	TLSMode bool

	// TLSCertificates are the TLS certificates for server-side TLS.
	// Required for server-side TLSMode. Ignored for client-side.
	TLSCertificates []tls.Certificate

	// ALPNProtocols is the list of supported ALPN protocols.
	// Example: []string{"h3", "hq"}.
	ALPNProtocols []string

	// ServerName is the SNI for client-side TLS.
	// Should match the server's certificate hostname.
	ServerName string

	// InsecureSkipVerify controls whether a client verifies the server's
	// certificate chain and host name. Only for testing — do NOT use
	// in production.
	InsecureSkipVerify bool
}

// DefaultConfig returns a Config with sensible defaults.
func DefaultConfig() *Config {
	return &Config{
		MaxIdleTimeout:     30 * time.Second,
		MaxStreamData:      1 << 20,  // 1 MiB
		MaxConnectionData:  10 << 20, // 10 MiB
		MaxStreamsBidi:     100,
		MaxStreamsUni:      100,
		ConnIDLength:       8,
	}
}

// toTransportParams converts Config to transport.Params.
func (c *Config) toTransportParams() transport.Params {
	if c.TransportParams != nil {
		return *c.TransportParams
	}
	return transport.Params{
		MaxIdleTimeout:                  uint64(c.MaxIdleTimeout / time.Millisecond),
		MaxUDPPayloadSize:               65527,
		InitialMaxData:                  c.MaxConnectionData,
		InitialMaxStreamDataBidiLocal:   c.MaxStreamData,
		InitialMaxStreamDataBidiRemote:  c.MaxStreamData,
		InitialMaxStreamDataUni:         c.MaxStreamData,
		InitialMaxStreamsBidi:           c.MaxStreamsBidi,
		InitialMaxStreamsUni:            c.MaxStreamsUni,
		AckDelayExponent:                3,
		MaxAckDelay:                     25,
		ActiveConnectionIDLimit:         2,
	}
}

// === Public Types ===

// Listener is a QUIC server that accepts incoming connections.
type Listener struct {
	udpConn *net.UDPConn
	config  *Config

	// Connection table: DCID -> *Conn
	connTable     map[string]*Conn
	connTableMu   netMutex // lightweight mutex

	// Secret for stateless reset tokens and tokens
	secret []byte

	// Channel for accepted connections
	acceptCh chan *Conn

	// Shutdown
	done    chan struct{}
	closed  bool
}

// Conn is a QUIC connection (server or client side).
type Conn struct {
	conn      *connection.Connection
	connMgr   *connection.ConnIDManager
	udpConn   *net.UDPConn
	remoteAddr *net.UDPAddr
	listener   *Listener

	config *Config

	// Connection-layer subsystems
	packetIO   *connection.PacketIO
	frameHandler *connection.FrameHandler
	keyStore   *connection.KeySetStore
	recovery   *connection.RecoveryManager
	ackHandler  *connection.AckHandler
	streamMgr  *stream.Manager
	coordinator *connection.Coordinator

	// Pending frames to send
	sendQueue chan []byte

	// Incoming streams for AcceptStream
	acceptStreamCh chan *Stream

	// Connection close
	closeCh  chan struct{}
	closed   bool
	closeErr error

	// Is this a server-side connection?
	isServer bool

	// handshakeDone is closed when the TLS handshake completes.
	// Used by Accept() to block until the connection is ready.
	handshakeDone chan struct{}

	// Stream management (SDK-level wrappers)
	streams        map[uint64]*Stream
	streamsMu      netMutex
	nextClientBidi  uint64
	nextClientUni   uint64
	nextServerBidi  uint64
	nextServerUni   uint64
}

// Stream is a QUIC stream that implements io.ReadWriteCloser.
type Stream struct {
	id      uint64
	bidi    bool
	conn    *Conn
	// underlying stream from the stream package
	// We use the stream.Stream directly

	// Read buffer for incoming data
	readBuf  []byte
	readCh   chan []byte
	closeCh  chan struct{}
	closed   bool

	// Write side
	writeOffset uint64
	writeClosed bool
}

// netMutex is a simple wrapper around sync.Mutex for the connection table.
// We use a dedicated type to keep the import surface clean.
type netMutex struct {
	mu chan struct{}
}

func newNetMutex() netMutex {
	return netMutex{mu: make(chan struct{}, 1)}
}

func (m netMutex) Lock() {
	m.mu <- struct{}{}
}

func (m netMutex) Unlock() {
	<-m.mu
}
