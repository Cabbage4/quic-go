package token

import (
	"net"
	"testing"
	"time"
)

func TestTokenGenerateAndValidate(t *testing.T) {
	secret := []byte("test-secret-key-32-bytes-long!!")
	mgr := NewManager(secret)

	ip := net.ParseIP("10.0.0.1")
	tokenBytes, err := mgr.Generate(ip, "retry")
	if err != nil {
		t.Fatalf("Generate: %v", err)
	}

	if len(tokenBytes) < 32 {
		t.Errorf("token too short: %d bytes", len(tokenBytes))
	}

	// Validate with correct IP
	parsed, err := mgr.Validate(tokenBytes, ip)
	if err != nil {
		t.Fatalf("Validate: %v", err)
	}
	if parsed.Type != "retry" {
		t.Errorf("type = %s, want retry", parsed.Type)
	}
	if !parsed.ClientIP.Equal(ip) {
		t.Errorf("IP = %v, want %v", parsed.ClientIP, ip)
	}
}

func TestTokenWrongIP(t *testing.T) {
	secret := []byte("test-secret-key-32-bytes-long!!")
	mgr := NewManager(secret)

	ip1 := net.ParseIP("10.0.0.1")
	ip2 := net.ParseIP("10.0.0.2")

	token, _ := mgr.Generate(ip1, "new")

	_, err := mgr.Validate(token, ip2)
	if err == nil {
		t.Error("should fail with wrong IP")
	}
}

func TestTokenTampered(t *testing.T) {
	secret := []byte("test-secret-key-32-bytes-long!!")
	mgr := NewManager(secret)

	ip := net.ParseIP("10.0.0.1")
	token, _ := mgr.Generate(ip, "retry")

	// Tamper with a byte in the signature
	token[len(token)-1] ^= 0x01

	_, err := mgr.Validate(token, ip)
	if err == nil {
		t.Error("should fail with tampered token")
	}
}

func TestTokenExpired(t *testing.T) {
	secret := []byte("test-secret-key-32-bytes-long!!")
	mgr := NewManager(secret)
	mgr.SetMaxAge(1 * time.Millisecond) // very short

	ip := net.ParseIP("10.0.0.1")
	token, _ := mgr.Generate(ip, "retry")

	// Wait for expiry
	time.Sleep(10 * time.Millisecond)

	_, err := mgr.Validate(token, ip)
	if err == nil {
		t.Error("should fail with expired token")
	}
}

func TestTokenNewType(t *testing.T) {
	secret := []byte("test-secret-key-32-bytes-long!!")
	mgr := NewManager(secret)

	ip := net.ParseIP("192.168.1.1")
	token, _ := mgr.Generate(ip, "new")

	parsed, err := mgr.Validate(token, ip)
	if err != nil {
		t.Fatalf("Validate: %v", err)
	}
	if parsed.Type != "new" {
		t.Errorf("type = %s, want new", parsed.Type)
	}
}

func TestTokenIPv6(t *testing.T) {
	secret := []byte("test-secret-key-32-bytes-long!!")
	mgr := NewManager(secret)

	ip := net.ParseIP("2001:db8::1")
	token, _ := mgr.Generate(ip, "retry")

	parsed, err := mgr.Validate(token, ip)
	if err != nil {
		t.Fatalf("Validate: %v", err)
	}
	if !parsed.ClientIP.Equal(ip) {
		t.Errorf("IP = %v, want %v", parsed.ClientIP, ip)
	}
}

func TestTokenDifferentSecrets(t *testing.T) {
	secret1 := []byte("secret-one-32-bytes-long!!!!!!!")
	secret2 := []byte("secret-two-32-bytes-long!!!!!!!")

	mgr1 := NewManager(secret1)
	mgr2 := NewManager(secret2)

	ip := net.ParseIP("10.0.0.1")
	token, _ := mgr1.Generate(ip, "retry")

	// Should fail with different secret
	_, err := mgr2.Validate(token, ip)
	if err == nil {
		t.Error("should fail with different secret")
	}
}

func TestRetryIntegrityTag(t *testing.T) {
	// Test that the tag computation produces a consistent 16-byte result
	dcid := []byte{0x01, 0x02, 0x03, 0x04, 0x05, 0x06, 0x07, 0x08}
	scid := []byte{0x0a, 0x0b, 0x0c, 0x0d}
	retryPacket := []byte{
		0xf0, 0x00, 0x00, 0x00, 0x01, // long header, retry type, version
		0x08, // DCID len
		0x01, 0x02, 0x03, 0x04, 0x05, 0x06, 0x07, 0x08,
		0x04, // SCID len
		0x0a, 0x0b, 0x0c, 0x0d,
		0x05, 0x06, 0x07, 0x08, // token
	}

	tag1 := ComputeRetryIntegrityTag(dcid, scid, retryPacket)
	tag2 := ComputeRetryIntegrityTag(dcid, scid, retryPacket)

	// Same input → same output
	if tag1 != tag2 {
		t.Error("Retry integrity tag should be deterministic")
	}

	// Different input → different output
	tag3 := ComputeRetryIntegrityTag(dcid, scid, []byte{0xff})
	if tag1 == tag3 {
		t.Error("different input should produce different tag")
	}
}
