// Package connection implements QUIC connection lifecycle management
// (RFC 9000, Sections 5 and 10).
//
// This file implements the Connection state machine, packet routing,
// idle timeout, immediate close, draining period, and stateless reset
// detection.
package connection

import (
	"fmt"
	"net"
	"sync"
	"time"

	"github.com/Cabbage4/quic-go/errors"
	"github.com/Cabbage4/quic-go/frames"
	"github.com/Cabbage4/quic-go/transport"
)

// ConnectionState represents the lifecycle state of a QUIC connection
// (RFC 9000, Section 10).
type ConnectionState int

const (
	// StatePreHandshake: connection created but handshake not started
	StatePreHandshake ConnectionState = iota
	// StateHandshaking: TLS handshake in progress
	StateHandshaking
	// StateEstablished: handshake complete, data can flow
	StateEstablished
	// StateDraining: closing, sending CONNECTION_CLOSE, waiting for peer
	StateDraining
	// StateClosed: fully closed, all resources released
	StateClosed
)

// String returns a human-readable state name.
func (s ConnectionState) String() string {
	switch s {
	case StatePreHandshake:
		return "PRE_HANDSHAKE"
	case StateHandshaking:
		return "HANDSHAKING"
	case StateEstablished:
		return "ESTABLISHED"
	case StateDraining:
		return "DRAINING"
	case StateClosed:
		return "CLOSED"
	default:
		return fmt.Sprintf("UNKNOWN(%d)", int(s))
	}
}

// PNSpace represents a QUIC packet number space (RFC 9000, Section 12.3).
type PNSpace int

const (
	PNSpaceInitial    PNSpace = 0
	PNSpaceHandshake  PNSpace = 1
	PNSpaceApplication PNSpace = 2
)

// String returns a human-readable PN space name.
func (s PNSpace) String() string {
	switch s {
	case PNSpaceInitial:
		return "INITIAL"
	case PNSpaceHandshake:
		return "HANDSHAKE"
	case PNSpaceApplication:
		return "APPLICATION"
	default:
		return fmt.Sprintf("UNKNOWN(%d)", int(s))
	}
}

// PathInfo tracks a network path for connection migration (RFC 9000, Section 9).
type PathInfo struct {
	LocalAddr  net.Addr
	RemoteAddr net.Addr
	// True if this path has been validated
	Validated bool
	// Bytes sent on this path since validation (for anti-amplification)
	BytesSent uint64
	// Bytes received on this path since validation
	BytesReceived uint64
}

// Connection represents a QUIC connection's state and lifecycle.
//
// This is the central coordinator that ties together:
//   - Connection ID management (§5.1)
//   - Packet routing (§5.2)
//   - Idle timeout (§10.1)
//   - Immediate close / draining (§10.2-10.3)
//   - Stateless reset detection (§10.3)
type Connection struct {
	mu sync.Mutex

	// Connection identity
	id           uint64
	connIDMgr    *ConnIDManager
	isServer     bool

	// State
	state    ConnectionState
	peerParams transport.Params
	localParams transport.Params

	// Packet number tracking per space
	// nextPN per space: the next packet number to send
	nextPN [3]uint64
	// largestAckedPN per space: the largest packet number acknowledged
	largestAckedPN [3]*uint64

	// Idle timeout (§10.1)
	idleTimeout      time.Duration
	lastActivity     time.Time
	idleTimer        *time.Timer

	// Draining (§10.2)
	drainingTimer    *time.Timer
	closeError       *errors.Error
	closeFrame       *frames.ConnectionClose

	// Paths (§9)
	paths      []*PathInfo
	activePath int

	// Stateless reset (§10.3)
	resetTokens map[[16]byte]bool

	// Callbacks for I/O
	onClose func()
}

// NewConnection creates a new QUIC connection.
func NewConnection(isServer bool, localParams transport.Params) *Connection {
	c := &Connection{
		id:           generateConnID(),
		connIDMgr:    NewConnIDManager(),
		isServer:     isServer,
		state:        StatePreHandshake,
		localParams:  localParams,
		idleTimeout:  time.Duration(localParams.MaxIdleTimeout) * time.Millisecond,
		lastActivity: time.Now(),
		resetTokens:  make(map[[16]byte]bool),
		activePath:   0,
	}

	// Initialize next PN for all spaces to 0
	// largestAckedPN starts as nil (no packets acked yet)

	return c
}

// ID returns the internal connection identifier.
func (c *Connection) ID() uint64 {
	c.mu.Lock()
	defer c.mu.Unlock()
	return c.id
}

// State returns the current connection state.
func (c *Connection) State() ConnectionState {
	c.mu.Lock()
	defer c.mu.Unlock()
	return c.state
}

// SetState transitions the connection to a new state.
func (c *Connection) SetState(s ConnectionState) {
	c.mu.Lock()
	defer c.mu.Unlock()
	c.state = s
}

// ConnIDManager returns the connection ID manager.
func (c *Connection) ConnIDManager() *ConnIDManager {
	return c.connIDMgr
}

// IsServer returns whether this connection is the server side.
func (c *Connection) IsServer() bool {
	return c.isServer
}

// === Packet Number Tracking (§12.3) ===

// NextPacketNumber returns and increments the next packet number for a space.
func (c *Connection) NextPacketNumber(space PNSpace) uint64 {
	c.mu.Lock()
	defer c.mu.Unlock()
	pn := c.nextPN[space]
	c.nextPN[space]++
	return pn
}

// LargestAckedPN returns the largest acknowledged PN for a space, or nil.
func (c *Connection) LargestAckedPN(space PNSpace) *uint64 {
	c.mu.Lock()
	defer c.mu.Unlock()
	return c.largestAckedPN[space]
}

// UpdateLargestAcked updates the largest acknowledged PN if the new value is larger.
func (c *Connection) UpdateLargestAcked(space PNSpace, pn uint64) {
	c.mu.Lock()
	defer c.mu.Unlock()
	if c.largestAckedPN[space] == nil || pn > *c.largestAckedPN[space] {
		v := pn
		c.largestAckedPN[space] = &v
	}
}

// === Packet Routing (§5.2) ===

// MatchPacket determines whether an incoming packet belongs to this connection
// by checking if its DCID matches any of our active connection IDs.
// Returns true if the packet should be processed by this connection.
func (c *Connection) MatchPacket(dcid []byte) bool {
	c.mu.Lock()
	defer c.mu.Unlock()

	// Check against active CIDs we've issued (as server) or the dest CID we use
	if c.connIDMgr != nil {
		active := c.connIDMgr.ActiveConnIDs()
		for _, entry := range active {
			if bytesEqual(entry.ConnectionID, dcid) {
				return true
			}
		}
		// Also check our own source CID
		if bytesEqual(c.connIDMgr.SrcConnID(), dcid) {
			return true
		}
	}
	return false
}

// === Idle Timeout (§10.1) ===

// StartIdleTimer starts (or restarts) the idle timeout timer.
func (c *Connection) StartIdleTimer() {
	c.mu.Lock()
	defer c.mu.Unlock()

	if c.idleTimeout == 0 {
		return // no idle timeout
	}

	c.lastActivity = time.Now()
	if c.idleTimer != nil {
		c.idleTimer.Reset(c.idleTimeout)
		return
	}

	c.idleTimer = time.AfterFunc(c.idleTimeout, func() {
		c.onIdleTimeout()
	})
}

// TouchActivity records that activity was seen, resetting the idle timer.
func (c *Connection) TouchActivity() {
	c.mu.Lock()
	defer c.mu.Unlock()

	c.lastActivity = time.Now()
	if c.idleTimer != nil {
		c.idleTimer.Reset(c.idleTimeout)
	}
}

// onIdleTimeout is called when the idle timer fires.
func (c *Connection) onIdleTimeout() {
	c.mu.Lock()
	if c.state == StateClosed || c.state == StateDraining {
		c.mu.Unlock()
		return
	}
	closeErr := errors.New(errors.NoError, "idle timeout")
	c.mu.Unlock()

	// Trigger immediate close
	c.Close(closeErr, false)
}

// SetIdleTimeout sets the connection idle timeout duration.
func (c *Connection) SetIdleTimeout(d time.Duration) {
	c.mu.Lock()
	defer c.mu.Unlock()
	c.idleTimeout = d
}

// === Immediate Close (§10.2) ===

// Close initiates an immediate close of the connection.
// If drain is true, enters the draining period before full closure.
func (c *Connection) Close(err *errors.Error, drain bool) {
	c.mu.Lock()
	if c.state == StateClosed || c.state == StateDraining {
		c.mu.Unlock()
		return
	}

	c.closeError = err
	c.state = StateDraining

	// Build CONNECTION_CLOSE frame
	closeFrame := &frames.ConnectionClose{
		ErrorCode:        uint64(err.Code),
		TriggerFrameType: 0,
		ReasonPhrase:     err.Message,
		ApplicationError: false,
	}
	c.closeFrame = closeFrame

	// Stop idle timer
	if c.idleTimer != nil {
		c.idleTimer.Stop()
		c.idleTimer = nil
	}

	c.mu.Unlock()

	if drain {
		// Enter draining period (3 * PTO or a fixed grace period)
		// Use a simplified draining period of 3 seconds
		c.mu.Lock()
		c.drainingTimer = time.AfterFunc(3*time.Second, func() {
			c.finalizeClose()
		})
		c.mu.Unlock()
	} else {
		c.finalizeClose()
	}
}

// finalizeClose transitions to fully closed state.
func (c *Connection) finalizeClose() {
	c.mu.Lock()
	if c.state == StateClosed {
		c.mu.Unlock()
		return
	}
	c.state = StateClosed
	if c.drainingTimer != nil {
		c.drainingTimer.Stop()
	}
	if c.idleTimer != nil {
		c.idleTimer.Stop()
	}
	onClose := c.onClose
	c.mu.Unlock()

	if onClose != nil {
		onClose()
	}
}

// CloseFrame returns the CONNECTION_CLOSE frame to send, if closing.
func (c *Connection) CloseFrame() *frames.ConnectionClose {
	c.mu.Lock()
	defer c.mu.Unlock()
	return c.closeFrame
}

// CloseError returns the error that caused the connection to close.
func (c *Connection) CloseError() *errors.Error {
	c.mu.Lock()
	defer c.mu.Unlock()
	return c.closeError
}

// === Stateless Reset Detection (§10.3) ===

// AddResetToken registers a stateless reset token to watch for.
func (c *Connection) AddResetToken(token [16]byte) {
	c.mu.Lock()
	defer c.mu.Unlock()
	c.resetTokens[token] = true
}

// RemoveResetToken removes a stateless reset token.
func (c *Connection) RemoveResetToken(token [16]byte) {
	c.mu.Lock()
	defer c.mu.Unlock()
	delete(c.resetTokens, token)
}

// IsStatelessReset checks if the given data looks like a stateless reset
// packet for this connection (RFC 9000, Section 10.3.1).
//
// A stateless reset is a short header packet that ends with
// a registered 16-byte stateless reset token.
func (c *Connection) IsStatelessReset(data []byte) bool {
	c.mu.Lock()
	defer c.mu.Unlock()

	// Minimum size: short header (1 byte) + DCID + 16-byte token
	// The token is the last 16 bytes
	if len(data) < 1+16 {
		return false
	}

	// Must look like a short header (first bit = 0)
	if data[0]&0x80 != 0 {
		return false
	}

	// Extract last 16 bytes as potential token
	var token [16]byte
	copy(token[:], data[len(data)-16:])

	return c.resetTokens[token]
}

// === Path Management (§9) ===

// AddPath adds a new network path to track.
func (c *Connection) AddPath(local, remote net.Addr) int {
	c.mu.Lock()
	defer c.mu.Unlock()

	path := &PathInfo{
		LocalAddr:   local,
		RemoteAddr:  remote,
		Validated:   false,
	}
	c.paths = append(c.paths, path)
	return len(c.paths) - 1
}

// ActivePath returns the currently active path.
func (c *Connection) ActivePath() *PathInfo {
	c.mu.Lock()
	defer c.mu.Unlock()
	if len(c.paths) == 0 || c.activePath >= len(c.paths) {
		return nil
	}
	return c.paths[c.activePath]
}

// SetActivePath switches the active path to the given index.
func (c *Connection) SetActivePath(idx int) {
	c.mu.Lock()
	defer c.mu.Unlock()
	if idx >= 0 && idx < len(c.paths) {
		c.activePath = idx
	}
}

// MarkPathValidated marks a path as validated (after PATH_CHALLENGE/RESPONSE).
func (c *Connection) MarkPathValidated(idx int) {
	c.mu.Lock()
	defer c.mu.Unlock()
	if idx >= 0 && idx < len(c.paths) {
		c.paths[idx].Validated = true
	}
}

// PathBytesSent tracks bytes sent on a path for anti-amplification (§8.1).
func (c *Connection) PathBytesSent(idx int, n uint64) {
	c.mu.Lock()
	defer c.mu.Unlock()
	if idx >= 0 && idx < len(c.paths) {
		c.paths[idx].BytesSent += n
	}
}

// PathBytesReceived tracks bytes received on a path (§8.1).
func (c *Connection) PathBytesReceived(idx int, n uint64) {
	c.mu.Lock()
	defer c.mu.Unlock()
	if idx >= 0 && idx < len(c.paths) {
		c.paths[idx].BytesReceived += n
	}
}

// CanSendOnPath checks the anti-amplification limit (§8.1):
// a server can send at most 3x the bytes it has received on an unvalidated path.
func (c *Connection) CanSendOnPath(idx int, pendingBytes int) bool {
	c.mu.Lock()
	defer c.mu.Unlock()
	if idx < 0 || idx >= len(c.paths) {
		return false
	}
	path := c.paths[idx]
	if path.Validated {
		return true // no limit on validated paths
	}
	// Anti-amplification: sent must not exceed 3 * received
	allowed := 3 * path.BytesReceived
	return path.BytesSent+uint64(pendingBytes) <= allowed
}

// === OnClose callback ===

// OnClose sets a callback to be invoked when the connection fully closes.
func (c *Connection) OnClose(fn func()) {
	c.mu.Lock()
	defer c.mu.Unlock()
	c.onClose = fn
}

// === Transport Parameters ===

// SetPeerParams stores the peer's transport parameters.
func (c *Connection) SetPeerParams(p transport.Params) {
	c.mu.Lock()
	defer c.mu.Unlock()
	c.peerParams = p
}

// PeerParams returns the peer's transport parameters.
func (c *Connection) PeerParams() transport.Params {
	c.mu.Lock()
	defer c.mu.Unlock()
	return c.peerParams
}

// LocalParams returns the local transport parameters.
func (c *Connection) LocalParams() transport.Params {
	c.mu.Lock()
	defer c.mu.Unlock()
	return c.localParams
}

// === Helpers ===

// generateConnID generates a random uint64 connection identifier.
func generateConnID() uint64 {
	b := make([]byte, 8)
	if _, err := readRandom(b); err != nil {
		return 0 // fallback
	}
	var id uint64
	for i := 0; i < 8; i++ {
		id = (id << 8) | uint64(b[i])
	}
	return id
}

// bytesEqual compares two byte slices.
func bytesEqual(a, b []byte) bool {
	if len(a) != len(b) {
		return false
	}
	for i := range a {
		if a[i] != b[i] {
			return false
		}
	}
	return true
}

// readRandom reads random bytes (separate function for testability).
func readRandom(b []byte) (int, error) {
	return randRead(b)
}

// randRead is a variable for testing; default uses crypto/rand
var randRead = func(b []byte) (int, error) {
	return defaultRandRead(b)
}
