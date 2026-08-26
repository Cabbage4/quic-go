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
// Since TLS 1.3 (RFC 9001) and loss detection (RFC 9002) are not implemented,
// the SDK operates in plaintext mode — packets are not encrypted and there is
// no retransmission. This is suitable for testing, learning, and environments
// where the transport layer is already reliable (e.g., localhost or wired
// connections with low loss).
package sdk

import (
	"net"
	"time"

	"github.com/Cabbage4/quic-go/connection"
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

	// Stream manager
	// We use the stream.Manager from the stream package

	// ACK trackers per PN space
	// ackTrackers [3]*ack.Tracker

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

	// Stream management
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
