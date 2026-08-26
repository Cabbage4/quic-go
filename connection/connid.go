// Package connection implements QUIC connection ID management (RFC 9000, Section 5.1).
//
// Connection IDs are used to allow endpoints to route packets to the correct
// connection and to allow peers to change the address they send to.
package connection

import (
	"crypto/rand"
	"crypto/sha256"
	"fmt"
	"sync"
)

// MaxConnIDLen is the maximum connection ID length (RFC 9000: 0..160 bits = 20 bytes).
const MaxConnIDLen = 20

// ConnIDEntry represents a connection ID issued by a peer.
type ConnIDEntry struct {
	SequenceNumber      uint64
	ConnectionID        []byte
	StatelessResetToken [16]byte
}

// ConnIDManager manages connection IDs for a QUIC connection.
type ConnIDManager struct {
	mu sync.Mutex

	// Connection IDs we've issued (as server)
	nextSeqNum   uint64
	activeIDs    []ConnIDEntry
	maxActiveIDs int

	// The destination connection ID we use to send to the peer
	destConnID []byte

	// The source connection ID we use
	srcConnID []byte

	// Retired sequence numbers
	retiredSeqNums map[uint64]bool
}

// NewConnIDManager creates a new connection ID manager.
func NewConnIDManager() *ConnIDManager {
	return &ConnIDManager{
		maxActiveIDs:   8,
		retiredSeqNums: make(map[uint64]bool),
	}
}

// GenerateConnID generates a random connection ID of the given length.
func GenerateConnID(length int) ([]byte, error) {
	if length < 0 || length > MaxConnIDLen {
		return nil, fmt.Errorf("connection: invalid CID length %d (must be 0-%d)", length, MaxConnIDLen)
	}
	cid := make([]byte, length)
	if length > 0 {
		if _, err := rand.Read(cid); err != nil {
			return nil, fmt.Errorf("connection: generate CID: %w", err)
		}
	}
	return cid, nil
}

// GenerateStatelessResetToken generates a 16-byte stateless reset token
// derived from the connection ID and a secret (RFC 9000, Section 10.3.2).
func GenerateStatelessResetToken(connID []byte, secret []byte) [16]byte {
	h := sha256.New()
	h.Write(secret)
	h.Write(connID)
	var token [16]byte
	copy(token[:], h.Sum(nil)[:16])
	return token
}

// InitDestination initializes the destination connection ID (client's initial DCID).
func (m *ConnIDManager) InitDestConnID(cid []byte) {
	m.mu.Lock()
	defer m.mu.Unlock()
	m.destConnID = make([]byte, len(cid))
	copy(m.destConnID, cid)
}

// InitSource initializes the source connection ID (our SCID).
func (m *ConnIDManager) InitSrcConnID(cid []byte) {
	m.mu.Lock()
	defer m.mu.Unlock()
	m.srcConnID = make([]byte, len(cid))
	copy(m.srcConnID, cid)
}

// DestConnID returns the current destination connection ID.
func (m *ConnIDManager) DestConnID() []byte {
	m.mu.Lock()
	defer m.mu.Unlock()
	cid := make([]byte, len(m.destConnID))
	copy(cid, m.destConnID)
	return cid
}

// SrcConnID returns the current source connection ID.
func (m *ConnIDManager) SrcConnID() []byte {
	m.mu.Lock()
	defer m.mu.Unlock()
	cid := make([]byte, len(m.srcConnID))
	copy(cid, m.srcConnID)
	return cid
}

// IssueNewConnID issues a new connection ID with the given secret for stateless reset tokens.
func (m *ConnIDManager) IssueNewConnID(secret []byte) (*ConnIDEntry, error) {
	m.mu.Lock()
	defer m.mu.Unlock()

	if len(m.activeIDs) >= m.maxActiveIDs {
		return nil, fmt.Errorf("connection: max active connection IDs (%d) reached", m.maxActiveIDs)
	}

	cid, err := GenerateConnID(8) // default 8-byte CID
	if err != nil {
		return nil, err
	}

	entry := ConnIDEntry{
		SequenceNumber:      m.nextSeqNum,
		ConnectionID:        cid,
		StatelessResetToken: GenerateStatelessResetToken(cid, secret),
	}
	m.nextSeqNum++
	m.activeIDs = append(m.activeIDs, entry)

	// Copy return value to avoid race
	ret := entry
	return &ret, nil
}

// RetireConnID retires a connection ID by sequence number.
func (m *ConnIDManager) RetireConnID(seqNum uint64) {
	m.mu.Lock()
	defer m.mu.Unlock()
	m.retiredSeqNums[seqNum] = true
	// Remove from active list
	for i, e := range m.activeIDs {
		if e.SequenceNumber == seqNum {
			m.activeIDs = append(m.activeIDs[:i], m.activeIDs[i+1:]...)
			break
		}
	}
}

// ActiveConnIDs returns a copy of the active connection IDs.
func (m *ConnIDManager) ActiveConnIDs() []ConnIDEntry {
	m.mu.Lock()
	defer m.mu.Unlock()
	result := make([]ConnIDEntry, len(m.activeIDs))
	copy(result, m.activeIDs)
	return result
}

// SetMaxActiveIDs sets the maximum number of active connection IDs.
func (m *ConnIDManager) SetMaxActiveIDs(n int) {
	m.mu.Lock()
	defer m.mu.Unlock()
	m.maxActiveIDs = n
}

// String returns a human-readable representation.
func (m *ConnIDManager) String() string {
	m.mu.Lock()
	defer m.mu.Unlock()
	return fmt.Sprintf("ConnIDManager(src=%x, dest=%x, active=%d, retired=%d)",
		m.srcConnID, m.destConnID, len(m.activeIDs), len(m.retiredSeqNums))
}
