// Package path implements QUIC path validation and connection migration
// (RFC 9000, Sections 8 and 9).
//
// Path validation ensures that a peer can receive packets at the address
// it claims to be sending from. Connection migration occurs when a peer
// changes its address and the connection continues on the new path.
package path

import (
	"crypto/rand"
	"fmt"
	"net"
	"sync"
	"time"
)

// ChallengeTimeout is the default timeout for path validation.
const ChallengeTimeout = 3 * time.Second

// PathState represents the validation state of a path.
type PathState int

const (
	PathStateUnknown    PathState = iota // not yet probed
	PathStateValidating                  // challenge sent, awaiting response
	PathStateValid                       // validated by PATH_RESPONSE
	PathStateFailed                      // validation timed out or failed
	PathStateOld                         // superseded by a newer path
)

// String returns a human-readable state name.
func (s PathState) String() string {
	switch s {
	case PathStateUnknown:
		return "UNKNOWN"
	case PathStateValidating:
		return "VALIDATING"
	case PathStateValid:
		return "VALID"
	case PathStateFailed:
		return "FAILED"
	case PathStateOld:
		return "OLD"
	default:
		return fmt.Sprintf("UNKNOWN_STATE(%d)", int(s))
	}
}

// Path represents a network path for a QUIC connection.
type Path struct {
	mu sync.Mutex

	// Network addresses
	LocalAddr  net.Addr
	RemoteAddr net.Addr

	// Path validation state
	state PathState

	// PATH_CHALLENGE data (8 bytes random)
	challengeData [8]byte

	// When the challenge was sent
	challengeSentAt time.Time

	// Whether we've received a PATH_RESPONSE matching the challenge
	challengeResponded bool

	// Anti-amplification tracking (RFC 9000 §8.1)
	// A server can send at most 3x the bytes it has received on an
	// unvalidated path
	bytesSent     uint64
	bytesReceived uint64

	// Whether this path is the active path
	isActive bool

	// When the path was first seen
	firstSeen time.Time
}

// NewPath creates a new Path with the given addresses.
func NewPath(local, remote net.Addr) *Path {
	return &Path{
		LocalAddr:  local,
		RemoteAddr: remote,
		state:      PathStateUnknown,
		firstSeen:  time.Now(),
	}
}

// State returns the current validation state.
func (p *Path) State() PathState {
	p.mu.Lock()
	defer p.mu.Unlock()
	return p.state
}

// IsActive returns whether this is the active path for the connection.
func (p *Path) IsActive() bool {
	p.mu.Lock()
	defer p.mu.Unlock()
	return p.isActive
}

// SetActive marks this path as the active path.
func (p *Path) SetActive(active bool) {
	p.mu.Lock()
	defer p.mu.Unlock()
	p.isActive = active
}

// StartChallenge generates a random PATH_CHALLENGE data value and
// transitions the path to the Validating state.
// Returns the 8-byte challenge data.
func (p *Path) StartChallenge() ([8]byte, error) {
	p.mu.Lock()
	defer p.mu.Unlock()

	var data [8]byte
	if _, err := rand.Read(data[:]); err != nil {
		return [8]byte{}, fmt.Errorf("path: generate challenge: %w", err)
	}

	p.challengeData = data
	p.challengeSentAt = time.Now()
	p.state = PathStateValidating
	p.challengeResponded = false
	return data, nil
}

// HandleResponse checks if a received PATH_RESPONSE matches the
// outstanding PATH_CHALLENGE. If it matches, the path is validated.
// Returns true if the response matched.
func (p *Path) HandleResponse(data [8]byte) bool {
	p.mu.Lock()
	defer p.mu.Unlock()

	if p.state != PathStateValidating {
		return false
	}
	if p.challengeData != data {
		return false
	}

	p.challengeResponded = true
	p.state = PathStateValid
	return true
}

// CheckTimeout returns true if the path validation has timed out.
func (p *Path) CheckTimeout() bool {
	p.mu.Lock()
	defer p.mu.Unlock()

	if p.state != PathStateValidating {
		return false
	}
	if time.Since(p.challengeSentAt) > ChallengeTimeout {
		p.state = PathStateFailed
		return true
	}
	return false
}

// ChallengeData returns the current challenge data (if any).
func (p *Path) ChallengeData() [8]byte {
	p.mu.Lock()
	defer p.mu.Unlock()
	return p.challengeData
}

// === Anti-amplification (§8.1) ===

// RecordSent tracks bytes sent on this path.
func (p *Path) RecordSent(n int) {
	p.mu.Lock()
	defer p.mu.Unlock()
	p.bytesSent += uint64(n)
}

// RecordReceived tracks bytes received on this path.
func (p *Path) RecordReceived(n int) {
	p.mu.Lock()
	defer p.mu.Unlock()
	p.bytesReceived += uint64(n)
}

// CanSend checks the anti-amplification limit (§8.1).
// On an unvalidated path, a server can send at most 3x the bytes received.
// Returns true if sending n bytes is allowed.
func (p *Path) CanSend(n int) bool {
	p.mu.Lock()
	defer p.mu.Unlock()

	if p.state == PathStateValid {
		return true // no limit on validated paths
	}

	allowed := 3 * p.bytesReceived
	return p.bytesSent+uint64(n) <= allowed
}

// BytesSent returns the total bytes sent on this path.
func (p *Path) BytesSent() uint64 {
	p.mu.Lock()
	defer p.mu.Unlock()
	return p.bytesSent
}

// BytesReceived returns the total bytes received on this path.
func (p *Path) BytesReceived() uint64 {
	p.mu.Lock()
	defer p.mu.Unlock()
	return p.bytesReceived
}

// String returns a human-readable representation.
func (p *Path) String() string {
	p.mu.Lock()
	defer p.mu.Unlock()
	return fmt.Sprintf("Path(local=%v, remote=%v, state=%s, sent=%d, recv=%d)",
		p.LocalAddr, p.RemoteAddr, p.state, p.bytesSent, p.bytesReceived)
}

// === Connection Migration (§9) ===

// Manager tracks all paths for a connection and handles migration.
type Manager struct {
	mu sync.Mutex

	paths      []*Path
	activeIdx  int

	// DisableActiveMigration: if true, the endpoint does not support
	// active connection migration (from transport params)
	disableMigration bool

	// Callback when a new path becomes active
	onMigration func(old, new_ net.Addr)
}

// NewManager creates a new path manager.
func NewManager() *Manager {
	return &Manager{
		activeIdx: -1,
	}
}

// SetDisableMigration sets whether active migration is disabled.
func (m *Manager) SetDisableMigration(disabled bool) {
	m.mu.Lock()
	defer m.mu.Unlock()
	m.disableMigration = disabled
}

// AddPath registers a new path. Returns its index.
func (m *Manager) AddPath(p *Path) int {
	m.mu.Lock()
	defer m.mu.Unlock()
	m.paths = append(m.paths, p)
	if m.activeIdx == -1 {
		m.activeIdx = 0
		p.SetActive(true)
	}
	return len(m.paths) - 1
}

// ActivePath returns the current active path.
func (m *Manager) ActivePath() *Path {
	m.mu.Lock()
	defer m.mu.Unlock()
	if m.activeIdx < 0 || m.activeIdx >= len(m.paths) {
		return nil
	}
	return m.paths[m.activeIdx]
}

// ActiveIndex returns the index of the active path.
func (m *Manager) ActiveIndex() int {
	m.mu.Lock()
	defer m.mu.Unlock()
	return m.activeIdx
}

// FindPath finds a path by remote address. Returns nil if not found.
func (m *Manager) FindPath(remote net.Addr) *Path {
	m.mu.Lock()
	defer m.mu.Unlock()
	for _, p := range m.paths {
		if addrsEqual(p.RemoteAddr, remote) {
			return p
		}
	}
	return nil
}

// addrsEqual compares two net.Addr by string representation.
func addrsEqual(a, b net.Addr) bool {
	return a.String() == b.String()
}

// HandleMigration is called when a packet arrives from a new remote address.
// It returns the new path (which may need validation) and whether migration occurred.
//
// RFC 9000 §9.3: When a peer changes address, the server must validate
// the new path before sending significant data on it.
func (m *Manager) HandleMigration(local, remote net.Addr) (*Path, bool) {
	m.mu.Lock()

	if m.disableMigration {
		m.mu.Unlock()
		return nil, false
	}

	// Check if we already have this path
	for i, p := range m.paths {
		if addrsEqual(p.RemoteAddr, remote) {
			// Existing path — check if it should become active
			if i != m.activeIdx {
				old := m.paths[m.activeIdx]
				old.SetActive(false)
				m.paths[i].SetActive(true)
				m.activeIdx = i
				cb := m.onMigration
				m.mu.Unlock()
				if cb != nil {
					cb(old.RemoteAddr, remote)
				}
				return m.paths[i], true
			}
			m.mu.Unlock()
			return p, false
		}
	}

	// New path — create and add
	m.mu.Unlock()
	newPath := NewPath(local, remote)
	idx := m.AddPath(newPath)

	m.mu.Lock()
	// Mark old path as old, new as active
	if m.activeIdx >= 0 && m.activeIdx < len(m.paths) {
		old := m.paths[m.activeIdx]
		old.SetActive(false)
	}
	m.activeIdx = idx
	newPath.SetActive(true)
	cb := m.onMigration
	m.mu.Unlock()

	if cb != nil {
		cb(nil, remote)
	}

	return newPath, true
}

// OnMigration sets a callback for connection migration events.
func (m *Manager) OnMigration(fn func(old, new_ net.Addr)) {
	m.mu.Lock()
	defer m.mu.Unlock()
	m.onMigration = fn
}

// Paths returns a copy of all paths.
func (m *Manager) Paths() []*Path {
	m.mu.Lock()
	defer m.mu.Unlock()
	result := make([]*Path, len(m.paths))
	copy(result, m.paths)
	return result
}

// RemoveFailedPaths removes paths that have failed validation.
func (m *Manager) RemoveFailedPaths() {
	m.mu.Lock()
	defer m.mu.Unlock()

	var active []*Path
	for _, p := range m.paths {
		if p.State() != PathStateFailed && p.State() != PathStateOld {
			active = append(active, p)
		}
	}
	m.paths = active
	// Find new active if needed
	if m.activeIdx >= len(m.paths) && len(m.paths) > 0 {
		m.activeIdx = 0
		m.paths[0].SetActive(true)
	} else if len(m.paths) == 0 {
		m.activeIdx = -1
	}
}
