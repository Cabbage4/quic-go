// Package pmtu implements Path Maximum Transmission Unit discovery
// for QUIC (RFC 9000, Section 14).
//
// QUIC endpoints need to determine the maximum UDP datagram size they
// can send on a path without fragmentation. This package implements
// a simplified version of DPLPMTUD (Datagram Packetization Layer PMTUD,
// RFC 8899).
package pmtu

import (
	"fmt"
	"sync"
	"time"
)

// DefaultMTU is the default MTU that works in most networks.
const DefaultMTU = 1252 // IPv4 minimum: 1280 - 20 (IP) - 8 (UDP) = 1252

// MinMTU is the minimum MTU per RFC 9000 §14.2.
const MinMTU = 1252

// MaxMTU is the maximum MTU we'll probe.
const MaxMTU = 1500 // typical Ethernet MTU

// IPv6Overhead is the extra overhead for IPv6 (40 vs 20 bytes header).
const IPv6Overhead = 20

// PMTUState represents the state of the PMTU discovery process.
type PMTUState int

const (
	StateDisabled  PMTUState = iota // PMTUD not started
	StateSearching                  // actively probing for larger MTU
	StateComplete                   // found max MTU, no more probing
	StateBase       = StateComplete // alias
)

// String returns a human-readable state name.
func (s PMTUState) String() string {
	switch s {
	case StateDisabled:
		return "DISABLED"
	case StateSearching:
		return "SEARCHING"
	case StateComplete:
		return "COMPLETE"
	default:
		return fmt.Sprintf("UNKNOWN(%d)", int(s))
	}
}

// Probe represents a single PMTU probe packet.
type Probe struct {
	// Size of the probe packet (including QUIC header + payload)
	Size int
	// When the probe was sent
	SentAt time.Time
	// Whether an ACK has been received
	Acked bool
}

// Discoverer manages PMTU discovery for a single path.
type Discoverer struct {
	mu sync.Mutex

	// Current discovered MTU (what we'll use for sending)
	currentMTU int
	// Whether we're using IPv6
	isIPv6 bool

	// Probing state
	state PMTUState
	// Current probe (nil if no probe in flight)
	currentProbe *Probe
	// Next probe size to try
	nextProbeSize int
	// Upper and lower bounds for binary search
	lowerBound int
	upperBound int

	// Probe timeout
	probeTimeout time.Duration

	// Number of failed probes (to stop probing after too many)
	consecutiveFailures int
	maxFailures         int
}

// NewDiscoverer creates a new PMTU discoverer.
// isIPv6 should be true if the path uses IPv6.
func NewDiscoverer(isIPv6 bool) *Discoverer {
	base := DefaultMTU
	if isIPv6 {
		base -= IPv6Overhead
	}
	return &Discoverer{
		currentMTU:   base,
		isIPv6:       isIPv6,
		state:        StateDisabled,
		lowerBound:   MinMTU,
		upperBound:   MaxMTU,
		probeTimeout: 3 * time.Second,
		maxFailures:  3,
	}
}

// CurrentMTU returns the current MTU that should be used for sending.
func (d *Discoverer) CurrentMTU() int {
	d.mu.Lock()
	defer d.mu.Unlock()
	return d.currentMTU
}

// State returns the current discovery state.
func (d *Discoverer) State() PMTUState {
	d.mu.Lock()
	defer d.mu.Unlock()
	return d.state
}

// StartProbing begins the PMTU discovery process.
func (d *Discoverer) StartProbing() {
	d.mu.Lock()
	defer d.mu.Unlock()
	if d.state == StateDisabled {
		d.state = StateSearching
		d.nextProbeSize = d.upperBound
		d.consecutiveFailures = 0
	}
}

// NextProbeSize returns the size of the next probe packet to send,
// or 0 if no probe is needed.
func (d *Discoverer) NextProbeSize() int {
	d.mu.Lock()
	defer d.mu.Unlock()

	if d.state != StateSearching {
		return 0
	}
	if d.currentProbe != nil {
		return 0 // probe already in flight
	}
	return d.nextProbeSize
}

// RecordProbeSent records that a probe of the given size was sent.
func (d *Discoverer) RecordProbeSent(size int) {
	d.mu.Lock()
	defer d.mu.Unlock()
	if d.state != StateSearching {
		return
	}
	d.currentProbe = &Probe{
		Size:   size,
		SentAt: time.Now(),
		Acked:  false,
	}
}

// RecordProbeAcked records that the current probe was acknowledged.
// This means the probe size is viable — try larger.
func (d *Discoverer) RecordProbeAcked() {
	d.mu.Lock()
	defer d.mu.Unlock()

	if d.currentProbe == nil {
		return
	}

	size := d.currentProbe.Size
	d.currentProbe.Acked = true

	// Update current MTU to the probe size
	d.currentMTU = size
	d.lowerBound = size

	// Try a larger size
	d.currentProbe = nil
	d.consecutiveFailures = 0

	// Binary search: next probe is midpoint between lower and upper
	next := (d.lowerBound + d.upperBound) / 2
	if next <= d.lowerBound {
		// No more room to grow — we're done
		d.state = StateComplete
		d.nextProbeSize = 0
	} else {
		d.nextProbeSize = next
	}
}

// RecordProbeLost records that the current probe was lost (timed out
// or explicitly marked as lost).
// This means the probe size is too large — try smaller.
func (d *Discoverer) RecordProbeLost() {
	d.mu.Lock()
	defer d.mu.Unlock()

	if d.currentProbe == nil {
		return
	}

	size := d.currentProbe.Size
	d.currentProbe = nil

	// Reduce upper bound
	d.upperBound = size - 1
	d.consecutiveFailures++

	// Check if we should stop probing
	if d.consecutiveFailures >= d.maxFailures || d.upperBound <= d.lowerBound {
		d.state = StateComplete
		d.nextProbeSize = 0
		return
	}

	// Try a smaller size
	next := (d.lowerBound + d.upperBound) / 2
	if next < MinMTU {
		next = MinMTU
	}
	d.nextProbeSize = next
}

// CheckProbeTimeout returns true if the current probe has timed out.
func (d *Discoverer) CheckProbeTimeout() bool {
	d.mu.Lock()
	defer d.mu.Unlock()

	if d.currentProbe == nil {
		return false
	}
	if time.Since(d.currentProbe.SentAt) > d.probeTimeout {
		return true
	}
	return false
}

// SetProbeTimeout sets the probe timeout duration.
func (d *Discoverer) SetProbeTimeout(dur time.Duration) {
	d.mu.Lock()
	defer d.mu.Unlock()
	d.probeTimeout = dur
}

// Reset resets the discoverer to initial state.
func (d *Discoverer) Reset() {
	d.mu.Lock()
	defer d.mu.Unlock()

	base := DefaultMTU
	if d.isIPv6 {
		base -= IPv6Overhead
	}
	d.currentMTU = base
	d.state = StateDisabled
	d.currentProbe = nil
	d.lowerBound = MinMTU
	d.upperBound = MaxMTU
	d.consecutiveFailures = 0
}

// CanSend returns true if a packet of the given size fits within
// the current MTU.
func (d *Discoverer) CanSend(size int) bool {
	d.mu.Lock()
	defer d.mu.Unlock()
	return size <= d.currentMTU
}

// IsIPv6 returns whether the path uses IPv6.
func (d *Discoverer) IsIPv6() bool {
	d.mu.Lock()
	defer d.mu.Unlock()
	return d.isIPv6
}

// SetIPv6 updates the IPv6 flag and adjusts the base MTU.
func (d *Discoverer) SetIPv6(isIPv6 bool) {
	d.mu.Lock()
	defer d.mu.Unlock()
	d.isIPv6 = isIPv6
}

// MaxPayloadSize returns the maximum QUIC payload size that fits
// in the current MTU, accounting for UDP and IP overhead.
func (d *Discoverer) MaxPayloadSize() int {
	d.mu.Lock()
	defer d.mu.Unlock()

	overhead := 28 // 20 (IPv4) + 8 (UDP)
	if d.isIPv6 {
		overhead = 48 // 40 (IPv6) + 8 (UDP)
	}
	return d.currentMTU - overhead
}

// String returns a human-readable representation.
func (d *Discoverer) String() string {
	d.mu.Lock()
	defer d.mu.Unlock()
	return fmt.Sprintf("PMTU(state=%s, mtu=%d, ipv6=%v, lower=%d, upper=%d)",
		d.state, d.currentMTU, d.isIPv6, d.lowerBound, d.upperBound)
}
