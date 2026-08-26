package pmtu

import (
	"testing"
	"time"
)

func TestNewDiscoverer(t *testing.T) {
	d := NewDiscoverer(false)
	if d.CurrentMTU() != DefaultMTU {
		t.Errorf("IPv4 MTU = %d, want %d", d.CurrentMTU(), DefaultMTU)
	}
	if d.IsIPv6() {
		t.Error("should not be IPv6 by default")
	}

	d6 := NewDiscoverer(true)
	if d6.CurrentMTU() != DefaultMTU-IPv6Overhead {
		t.Errorf("IPv6 MTU = %d, want %d", d6.CurrentMTU(), DefaultMTU-IPv6Overhead)
	}
}

func TestInitialState(t *testing.T) {
	d := NewDiscoverer(false)
	if d.State() != StateDisabled {
		t.Errorf("state = %s, want DISABLED", d.State())
	}
	if d.NextProbeSize() != 0 {
		t.Error("should not probe when disabled")
	}
}

func TestStartProbing(t *testing.T) {
	d := NewDiscoverer(false)
	d.StartProbing()

	if d.State() != StateSearching {
		t.Errorf("state = %s, want SEARCHING", d.State())
	}
	if d.NextProbeSize() == 0 {
		t.Error("should have a probe size after starting")
	}
}

func TestProbeAcked(t *testing.T) {
	d := NewDiscoverer(false)
	d.StartProbing()

	probeSize := d.NextProbeSize()
	if probeSize == 0 {
		t.Fatal("no probe size")
	}

	d.RecordProbeSent(probeSize)
	d.RecordProbeAcked()

	if d.CurrentMTU() != probeSize {
		t.Errorf("MTU = %d, want %d", d.CurrentMTU(), probeSize)
	}
}

func TestProbeLost(t *testing.T) {
	d := NewDiscoverer(false)
	d.StartProbing()

	probeSize := d.NextProbeSize()
	d.RecordProbeSent(probeSize)
	d.RecordProbeLost()

	// After loss, should try smaller
	if d.State() != StateSearching {
		t.Errorf("state = %s, want SEARCHING", d.State())
	}
	// Upper bound should have been reduced
	nextSize := d.NextProbeSize()
	if nextSize == 0 {
		t.Error("should have next probe size")
	}
}

func TestConvergeToMax(t *testing.T) {
	d := NewDiscoverer(false)
	d.SetProbeTimeout(50 * time.Millisecond)
	d.StartProbing()

	// Simulate successful probes converging
	for i := 0; i < 10; i++ {
		size := d.NextProbeSize()
		if size == 0 {
			break
		}
		d.RecordProbeSent(size)
		d.RecordProbeAcked()
	}

	// Should eventually reach COMPLETE state
	if d.State() != StateComplete {
		t.Errorf("state = %s, want COMPLETE", d.State())
	}
}

func TestProbeTimeout(t *testing.T) {
	d := NewDiscoverer(false)
	d.SetProbeTimeout(10 * time.Millisecond)
	d.StartProbing()

	size := d.NextProbeSize()
	d.RecordProbeSent(size)

	// Should not be timed out immediately
	if d.CheckProbeTimeout() {
		t.Error("should not timeout immediately")
	}

	time.Sleep(20 * time.Millisecond)

	if !d.CheckProbeTimeout() {
		t.Error("should timeout after 10ms")
	}
}

func TestMaxFailures(t *testing.T) {
	d := NewDiscoverer(false)
	d.StartProbing()

	// Fail probes until we hit maxFailures
	for i := 0; i < 10; i++ {
		size := d.NextProbeSize()
		if size == 0 {
			break
		}
		d.RecordProbeSent(size)
		d.RecordProbeLost()
	}

	if d.State() != StateComplete {
		t.Errorf("state = %s, want COMPLETE after max failures", d.State())
	}
}

func TestReset(t *testing.T) {
	d := NewDiscoverer(false)
	d.StartProbing()
	d.RecordProbeSent(d.NextProbeSize())

	d.Reset()

	if d.State() != StateDisabled {
		t.Errorf("state = %s, want DISABLED", d.State())
	}
	if d.CurrentMTU() != DefaultMTU {
		t.Errorf("MTU = %d, want %d", d.CurrentMTU(), DefaultMTU)
	}
}

func TestCanSend(t *testing.T) {
	d := NewDiscoverer(false)
	mtu := d.CurrentMTU()

	if !d.CanSend(mtu) {
		t.Error("should be able to send at MTU")
	}
	if d.CanSend(mtu + 1) {
		t.Error("should not be able to send above MTU")
	}
}

func TestMaxPayloadSize(t *testing.T) {
	d4 := NewDiscoverer(false)
	expected4 := DefaultMTU - 28 // 20 IP + 8 UDP
	if d4.MaxPayloadSize() != expected4 {
		t.Errorf("IPv4 payload = %d, want %d", d4.MaxPayloadSize(), expected4)
	}

	d6 := NewDiscoverer(true)
	expected6 := DefaultMTU - IPv6Overhead - 48 // 40 IPv6 + 8 UDP
	if d6.MaxPayloadSize() != expected6 {
		t.Errorf("IPv6 payload = %d, want %d", d6.MaxPayloadSize(), expected6)
	}
}

func TestSetIPv6(t *testing.T) {
	d := NewDiscoverer(false)
	d.SetIPv6(true)

	if !d.IsIPv6() {
		t.Error("should be IPv6 after SetIPv6(true)")
	}
}
