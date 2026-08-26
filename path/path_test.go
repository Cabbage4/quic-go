package path

import (
	"net"
	"testing"
	"time"
)

type testAddr struct{ s string }

func (a *testAddr) Network() string { return "test" }
func (a *testAddr) String() string   { return a.s }

func makeAddr(s string) net.Addr { return &testAddr{s: s} }

func TestPathValidation(t *testing.T) {
	p := NewPath(makeAddr("127.0.0.1:1234"), makeAddr("10.0.0.1:4321"))

	if p.State() != PathStateUnknown {
		t.Errorf("initial state = %s, want UNKNOWN", p.State())
	}

	// Start challenge
	data, err := p.StartChallenge()
	if err != nil {
		t.Fatalf("StartChallenge: %v", err)
	}
	if p.State() != PathStateValidating {
		t.Errorf("state after challenge = %s, want VALIDATING", p.State())
	}

	// Wrong response
	wrong := [8]byte{0, 1, 2, 3, 4, 5, 6, 7}
	if p.HandleResponse(wrong) {
		t.Error("should not match wrong response")
	}

	// Correct response
	if !p.HandleResponse(data) {
		t.Error("should match correct response")
	}
	if p.State() != PathStateValid {
		t.Errorf("state after response = %s, want VALID", p.State())
	}
}

func TestPathValidationTimeout(t *testing.T) {
	p := NewPath(makeAddr("127.0.0.1:1234"), makeAddr("10.0.0.1:4321"))

	_, _ = p.StartChallenge()

	// Haven't timed out yet
	if p.CheckTimeout() {
		t.Error("should not timeout immediately")
	}

	// Simulate elapsed time by adjusting the internal timestamp
	p.mu.Lock()
	p.challengeSentAt = time.Now().Add(-ChallengeTimeout - time.Second)
	p.mu.Unlock()

	if !p.CheckTimeout() {
		t.Error("should timeout after ChallengeTimeout")
	}
	if p.State() != PathStateFailed {
		t.Errorf("state = %s, want FAILED", p.State())
	}
}

func TestAntiAmplification(t *testing.T) {
	p := NewPath(makeAddr("127.0.0.1:1234"), makeAddr("10.0.0.1:4321"))

	// Unvalidated path: can send 3x received
	p.RecordReceived(100)

	if !p.CanSend(300) {
		t.Error("should allow 3x received")
	}
	if p.CanSend(301) {
		t.Error("should not allow more than 3x received")
	}

	// Record some sent bytes
	p.RecordSent(200)

	// Now only 100 bytes left
	if !p.CanSend(100) {
		t.Error("should allow remaining")
	}
	if p.CanSend(101) {
		t.Error("should not allow more than remaining")
	}

	// Validated path: no limit
	p.mu.Lock()
	p.state = PathStateValid
	p.mu.Unlock()

	p.RecordReceived(100) // total 200
	p.RecordSent(600)     // total 800

	// Validated: unlimited
	if !p.CanSend(1000000) {
		t.Error("validated path should have no limit")
	}
}

func TestConnectionMigration(t *testing.T) {
	mgr := NewManager()

	addr1 := makeAddr("10.0.0.1:4321")
	addr2 := makeAddr("10.0.0.2:5678")
	local := makeAddr("127.0.0.1:1234")

	p1 := NewPath(local, addr1)
	mgr.AddPath(p1)

	if mgr.ActiveIndex() != 0 {
		t.Errorf("active = %d, want 0", mgr.ActiveIndex())
	}

	// Migration to addr2
	newPath, migrated := mgr.HandleMigration(local, addr2)
	if !migrated {
		t.Error("should have migrated")
	}
	if newPath == nil {
		t.Fatal("newPath is nil")
	}
	if newPath.RemoteAddr.String() != "10.0.0.2:5678" {
		t.Errorf("new path remote = %v, want 10.0.0.2:5678", newPath.RemoteAddr)
	}

	// Active path should now be the new one
	active := mgr.ActivePath()
	if active == nil {
		t.Fatal("no active path")
	}
	if active.RemoteAddr.String() != "10.0.0.2:5678" {
		t.Errorf("active path remote = %v, want 10.0.0.2:5678", active.RemoteAddr)
	}
}

func TestDisableMigration(t *testing.T) {
	mgr := NewManager()
	mgr.SetDisableMigration(true)

	local := makeAddr("127.0.0.1:1234")
	remote1 := makeAddr("10.0.0.1:4321")
	remote2 := makeAddr("10.0.0.2:5678")

	p1 := NewPath(local, remote1)
	mgr.AddPath(p1)

	_, migrated := mgr.HandleMigration(local, remote2)
	if migrated {
		t.Error("should not migrate when disabled")
	}
}

func TestFindPath(t *testing.T) {
	mgr := NewManager()
	local := makeAddr("127.0.0.1:1234")
	remote1 := makeAddr("10.0.0.1:4321")
	remote2 := makeAddr("10.0.0.2:5678")

	p1 := NewPath(local, remote1)
	mgr.AddPath(p1)
	p2 := NewPath(local, remote2)
	mgr.AddPath(p2)

	found := mgr.FindPath(remote2)
	if found == nil {
		t.Fatal("should find path")
	}
	if found.RemoteAddr.String() != "10.0.0.2:5678" {
		t.Errorf("found wrong path: %v", found.RemoteAddr)
	}

	notFound := mgr.FindPath(makeAddr("10.0.0.3:9999"))
	if notFound != nil {
		t.Error("should not find non-existent path")
	}
}

func TestMigrationCallback(t *testing.T) {
	mgr := NewManager()

	var gotNewAddr net.Addr
	mgr.OnMigration(func(old, new_ net.Addr) {
		gotNewAddr = new_
	})

	local := makeAddr("127.0.0.1:1234")
	remote1 := makeAddr("10.0.0.1:4321")
	remote2 := makeAddr("10.0.0.2:5678")

	p1 := NewPath(local, remote1)
	mgr.AddPath(p1)

	mgr.HandleMigration(local, remote2)

	if gotNewAddr == nil {
		t.Fatal("callback not called")
	}
	if gotNewAddr.String() != "10.0.0.2:5678" {
		t.Errorf("new addr = %v, want 10.0.0.2:5678", gotNewAddr)
	}
}
