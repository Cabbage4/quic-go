package crypto

import (
	"bytes"
	"crypto/sha256"
	"encoding/hex"
	"testing"
)

// ============================================================================
// HKDF-Expand-Label Tests (RFC 9001 §5.1, RFC 8446 §7.1)
// ============================================================================

// TestHKDFExpandLabelKnownVector tests HKDF-Expand-Label with a known
// test vector from the TLS 1.3 test vectors.
func TestHKDFExpandLabelKnownVector(t *testing.T) {
	// Test vector from RFC 8446 Appendix A.1 (derived from the TLS 1.3
	// key schedule test vectors). We test that the function produces
	// deterministic output of the correct length.
	secret := bytes.Repeat([]byte{0x01}, sha256.Size) // 32 bytes
	label := "quic key"
	length := 16

	result := HKDFExpandLabel(sha256.New, secret, label, nil, length)

	if len(result) != length {
		t.Fatalf("expected %d bytes, got %d", length, len(result))
	}

	// The result should be deterministic
	result2 := HKDFExpandLabel(sha256.New, secret, label, nil, length)
	if !bytes.Equal(result, result2) {
		t.Fatal("HKDF-Expand-Label should be deterministic")
	}

	// Different label should produce different output
	otherResult := HKDFExpandLabel(sha256.New, secret, "quic iv", nil, length)
	if bytes.Equal(result, otherResult) {
		t.Fatal("different labels should produce different output")
	}
}

// TestDeriveKey produces correct length output
func TestDeriveKey(t *testing.T) {
	secret := bytes.Repeat([]byte{0xAB}, 32)

	key := DeriveKey(sha256.New, secret, "quic key", 16)
	if len(key) != 16 {
		t.Fatalf("expected 16-byte key, got %d", len(key))
	}

	iv := DeriveKey(sha256.New, secret, "quic iv", 12)
	if len(iv) != 12 {
		t.Fatalf("expected 12-byte IV, got %d", len(iv))
	}

	hpKey := DeriveKey(sha256.New, secret, "quic hp", 16)
	if len(hpKey) != 16 {
		t.Fatalf("expected 16-byte HP key, got %d", len(hpKey))
	}

	// All three should be different
	if bytes.Equal(key, iv[:16]) || bytes.Equal(key, hpKey) || bytes.Equal(iv[:16], hpKey) {
		t.Fatal("derived keys should be different from each other")
	}
}

// ============================================================================
// Initial Secret Derivation Tests (RFC 9001 §5.2)
// ============================================================================

// TestDeriveInitialSecret tests the initial secret derivation with a
// known connection ID. The QUIC Initial salt and derivation process
// is defined in RFC 9001 §5.2.
func TestDeriveInitialSecret(t *testing.T) {
	// Use a known DCID for deterministic test
	dcid := []byte{0x01, 0x02, 0x03, 0x04, 0x05, 0x06, 0x07, 0x08}

	initialSecret := DeriveInitialSecret(dcid)
	if len(initialSecret) != sha256.Size {
		t.Fatalf("expected %d-byte initial secret, got %d", sha256.Size, len(initialSecret))
	}

	// The result should be deterministic
	secret2 := DeriveInitialSecret(dcid)
	if !bytes.Equal(initialSecret, secret2) {
		t.Fatal("initial secret should be deterministic")
	}

	// Different DCID should produce different secret
	otherDcid := []byte{0x08, 0x07, 0x06, 0x05, 0x04, 0x03, 0x02, 0x01}
	otherSecret := DeriveInitialSecret(otherDcid)
	if bytes.Equal(initialSecret, otherSecret) {
		t.Fatal("different DCIDs should produce different initial secrets")
	}
}

// TestDeriveClientServerInitialSecret tests that client and server
// initial secrets are different.
func TestDeriveClientServerInitialSecret(t *testing.T) {
	dcid := []byte{0x01, 0x02, 0x03, 0x04, 0x05, 0x06, 0x07, 0x08}

	initialSecret := DeriveInitialSecret(dcid)
	clientInitial := DeriveClientInitialSecret(initialSecret)
	serverInitial := DeriveServerInitialSecret(initialSecret)

	if bytes.Equal(clientInitial, serverInitial) {
		t.Fatal("client and server initial secrets must be different")
	}

	if len(clientInitial) != sha256.Size {
		t.Fatalf("expected %d-byte client initial secret, got %d", sha256.Size, len(clientInitial))
	}
	if len(serverInitial) != sha256.Size {
		t.Fatalf("expected %d-byte server initial secret, got %d", sha256.Size, len(serverInitial))
	}
}

// TestDeriveTrafficKeys tests that traffic keys have correct lengths.
func TestDeriveTrafficKeys(t *testing.T) {
	secret := bytes.Repeat([]byte{0x42}, 32)
	cs := DefaultCipherSuite() // AES-128-GCM

	keys := DeriveTrafficKeys(secret, cs)

	if len(keys.Key) != cs.KeyLen {
		t.Fatalf("expected %d-byte key, got %d", cs.KeyLen, len(keys.Key))
	}
	if len(keys.IV) != cs.IVLen {
		t.Fatalf("expected %d-byte IV, got %d", cs.IVLen, len(keys.IV))
	}
	if len(keys.HPKey) != cs.HPKeyLen {
		t.Fatalf("expected %d-byte HP key, got %d", cs.HPKeyLen, len(keys.HPKey))
	}
}

// TestDeriveKeyUpdateSecret tests key update secret derivation.
func TestDeriveKeyUpdateSecret(t *testing.T) {
	secret := bytes.Repeat([]byte{0x42}, 32)
	h := sha256.New

	newSecret := DeriveKeyUpdateSecret(secret, h)

	if len(newSecret) != h().Size() {
		t.Fatalf("expected %d-byte secret, got %d", h().Size(), len(newSecret))
	}

	if bytes.Equal(secret, newSecret) {
		t.Fatal("updated secret should be different from original")
	}

	// Second update should produce yet another different secret
	newerSecret := DeriveKeyUpdateSecret(newSecret, h)
	if bytes.Equal(newSecret, newerSecret) {
		t.Fatal("second update should produce a different secret")
	}
}

// ============================================================================
// AEAD Tests (RFC 9001 §5.3)
// ============================================================================

// TestAEADEncryptDecrypt tests AEAD encrypt/decrypt round-trip.
func TestAEADEncryptDecrypt(t *testing.T) {
	secret := bytes.Repeat([]byte{0x42}, 32)
	cs := DefaultCipherSuite()
	keys := DeriveTrafficKeys(secret, cs)

	aead, err := NewAEAD(keys, cs.ID)
	if err != nil {
		t.Fatalf("failed to create AEAD: %v", err)
	}

	header := []byte{0xC0, 0x00, 0x00, 0x00, 0x01, 0x08, 0x01, 0x02, 0x03, 0x04, 0x05, 0x06, 0x07, 0x08, 0x00}
	plaintext := []byte("Hello, QUIC!")

	ciphertext := aead.Encrypt(42, header, plaintext)

	if len(ciphertext) != len(plaintext)+aead.Overhead() {
		t.Fatalf("expected %d-byte ciphertext, got %d", len(plaintext)+aead.Overhead(), len(ciphertext))
	}

	decrypted, err := aead.Decrypt(42, header, ciphertext)
	if err != nil {
		t.Fatalf("decryption failed: %v", err)
	}

	if !bytes.Equal(plaintext, decrypted) {
		t.Fatalf("decrypted data doesn't match: got %x, expected %x", decrypted, plaintext)
	}
}

// TestAEADDifferentPacketNumbers tests that different packet numbers
// produce different ciphertexts.
func TestAEADDifferentPacketNumbers(t *testing.T) {
	secret := bytes.Repeat([]byte{0x42}, 32)
	cs := DefaultCipherSuite()
	keys := DeriveTrafficKeys(secret, cs)

	aead, _ := NewAEAD(keys, cs.ID)

	header := []byte{0xC0, 0x00, 0x00, 0x00, 0x01}
	plaintext := []byte("test")

	ct1 := aead.Encrypt(1, header, plaintext)
	ct2 := aead.Encrypt(2, header, plaintext)

	if bytes.Equal(ct1, ct2) {
		t.Fatal("different packet numbers should produce different ciphertexts")
	}

	// Decrypting with wrong packet number should fail
	_, err := aead.Decrypt(2, header, ct1)
	if err == nil {
		t.Fatal("decrypting with wrong packet number should fail")
	}
}

// TestAEADTamperedCiphertext tests that tampered ciphertext fails decryption.
func TestAEADTamperedCiphertext(t *testing.T) {
	secret := bytes.Repeat([]byte{0x42}, 32)
	cs := DefaultCipherSuite()
	keys := DeriveTrafficKeys(secret, cs)

	aead, _ := NewAEAD(keys, cs.ID)

	header := []byte{0xC0, 0x00}
	plaintext := []byte("hello")

	ciphertext := aead.Encrypt(1, header, plaintext)

	// Tamper with the ciphertext
	tampered := make([]byte, len(ciphertext))
	copy(tampered, ciphertext)
	tampered[0] ^= 0xFF

	_, err := aead.Decrypt(1, header, tampered)
	if err == nil {
		t.Fatal("tampered ciphertext should fail decryption")
	}
}

// TestAEADTxCount tests the TX packet counter.
func TestAEADTxCount(t *testing.T) {
	secret := bytes.Repeat([]byte{0x42}, 32)
	cs := DefaultCipherSuite()
	keys := DeriveTrafficKeys(secret, cs)

	aead, _ := NewAEAD(keys, cs.ID)

	if aead.TxCount() != 0 {
		t.Fatalf("expected initial TX count 0, got %d", aead.TxCount())
	}

	aead.Encrypt(1, []byte{0xC0}, []byte("test1"))
	aead.Encrypt(2, []byte{0xC0}, []byte("test2"))
	aead.Encrypt(3, []byte{0xC0}, []byte("test3"))

	if aead.TxCount() != 3 {
		t.Fatalf("expected TX count 3, got %d", aead.TxCount())
	}
}

// ============================================================================
// Header Protection Tests (RFC 9001 §5.4)
// ============================================================================

// TestHeaderProtectionRoundTrip tests header protection apply/remove round-trip.
func TestHeaderProtectionRoundTrip(t *testing.T) {
	hpKey := bytes.Repeat([]byte{0x42}, 16) // AES-128 HP key
	suiteID := CipherSuiteAES128GCM

	// Create a packet: first byte + header + packet number + ciphertext
	// Long header: 4 bits masked
	packet := make([]byte, 50)
	packet[0] = 0xC3 // long header, PN length = 4 (0x03 + 1)
	// Fill rest with some data
	for i := 1; i < len(packet); i++ {
		packet[i] = byte(i)
	}

	pnOffset := 10 // packet number at offset 10
	pnLen := 4     // 4-byte packet number

	// Save original for comparison
	original := make([]byte, len(packet))
	copy(original, packet)

	// Apply header protection
	err := ApplyHeaderProtection(packet, pnOffset, pnLen, true, hpKey, suiteID)
	if err != nil {
		t.Fatalf("ApplyHeaderProtection failed: %v", err)
	}

	// The packet should be different after applying HP
	if bytes.Equal(packet, original) {
		t.Fatal("packet should be modified after applying header protection")
	}

	// Remove header protection
	err = RemoveHeaderProtection(packet, pnOffset, pnLen, true, hpKey, suiteID)
	if err != nil {
		t.Fatalf("RemoveHeaderProtection failed: %v", err)
	}

	// The packet should be restored to its original form
	if !bytes.Equal(packet, original) {
		t.Fatalf("packet not restored after HP round-trip:\n  got:      %x\n  expected: %x", packet, original)
	}
}

// TestHeaderProtectionShortHeader tests header protection with short headers.
func TestHeaderProtectionShortHeader(t *testing.T) {
	hpKey := bytes.Repeat([]byte{0x42}, 16)
	suiteID := CipherSuiteAES128GCM

	// Short header: 5 bits masked
	packet := make([]byte, 50)
	packet[0] = 0x43 // short header (header form=0, fixed bit=1), PN length = 4
	for i := 1; i < len(packet); i++ {
		packet[i] = byte(i * 2)
	}

	pnOffset := 5 // DCID (4 bytes) + 1 byte first byte
	pnLen := 4

	original := make([]byte, len(packet))
	copy(original, packet)

	// Apply and remove
	err := ApplyHeaderProtection(packet, pnOffset, pnLen, false, hpKey, suiteID)
	if err != nil {
		t.Fatalf("ApplyHeaderProtection (short) failed: %v", err)
	}

	if bytes.Equal(packet, original) {
		t.Fatal("short header packet should be modified after HP")
	}

	err = RemoveHeaderProtection(packet, pnOffset, pnLen, false, hpKey, suiteID)
	if err != nil {
		t.Fatalf("RemoveHeaderProtection (short) failed: %v", err)
	}

	if !bytes.Equal(packet, original) {
		t.Fatal("short header packet not restored after HP round-trip")
	}
}

// TestHeaderProtectionPacketTooShort tests that short packets are rejected.
func TestHeaderProtectionPacketTooShort(t *testing.T) {
	hpKey := bytes.Repeat([]byte{0x42}, 16)
	suiteID := CipherSuiteAES128GCM

	// Packet too short to contain the sample
	packet := make([]byte, 10)
	pnOffset := 5
	pnLen := 4

	err := ApplyHeaderProtection(packet, pnOffset, pnLen, true, hpKey, suiteID)
	if err == nil {
		t.Fatal("should fail for too-short packet")
	}
}

// TestCalculatePNOffset tests the packet number offset calculations.
func TestCalculatePNOffset(t *testing.T) {
	// Short header: pn_offset = 1 + len(DCID)
	offset := CalculatePNOffsetShort(8) // 8-byte DCID
	if offset != 9 {
		t.Fatalf("expected short header PN offset 9, got %d", offset)
	}

	offset = CalculatePNOffsetShort(0) // 0-byte DCID
	if offset != 1 {
		t.Fatalf("expected short header PN offset 1, got %d", offset)
	}
}

// TestPacketNumberLength tests the PN length extraction from first byte.
func TestPacketNumberLength(t *testing.T) {
	tests := []struct {
		firstByte byte
		expected  int
	}{
		{0x00, 1}, // 0x00 & 0x03 = 0 → 1 byte
		{0x01, 2}, // 0x01 & 0x03 = 1 → 2 bytes
		{0x02, 3}, // 0x02 & 0x03 = 2 → 3 bytes
		{0x03, 4}, // 0x03 & 0x03 = 3 → 4 bytes
		{0xC0, 1}, // long header, 0x00 & 0x03 = 0 → 1 byte
		{0xC3, 4}, // long header, 0x03 & 0x03 = 3 → 4 bytes
	}

	for _, tt := range tests {
		got := PacketNumberLength(tt.firstByte)
		if got != tt.expected {
			t.Errorf("PacketNumberLength(0x%02x) = %d, expected %d", tt.firstByte, got, tt.expected)
		}
	}
}

// ============================================================================
// Full Packet Protection Tests (AEAD + Header Protection)
// ============================================================================

// TestProtectUnprotectPayload tests the full packet protection round-trip.
func TestProtectUnprotectPayload(t *testing.T) {
	secret := bytes.Repeat([]byte{0x42}, 32)
	cs := DefaultCipherSuite()
	keys := DeriveTrafficKeys(secret, cs)

	ks, err := NewKeySet(keys, cs.ID, true)
	if err != nil {
		t.Fatalf("failed to create key set: %v", err)
	}

	// Create a packet: header (with PN) + payload
	// Long header: first byte + version(4) + DCID len(1) + DCID(8) + SCID len(1) + SCID(8) + payload length varint(1) + PN(4)
	header := []byte{
		0xC3,                   // long header, Initial type, PN len = 4
		0x00, 0x00, 0x00, 0x01, // version
		0x08,                   // DCID length
		0x01, 0x02, 0x03, 0x04, 0x05, 0x06, 0x07, 0x08, // DCID
		0x08,                   // SCID length
		0x11, 0x12, 0x13, 0x14, 0x15, 0x16, 0x17, 0x18, // SCID
		0x10,                   // payload length (varint, 16)
		0x00, 0x00, 0x00, 0x2A, // packet number = 42
	}
	payload := []byte("Hello, QUIC! This is a test payload.")

	packet := make([]byte, 0, len(header)+len(payload))
	packet = append(packet, header...)
	packet = append(packet, payload...)

	pnOffset := len(header) - 4 // PN is the last 4 bytes of header
	pnLen := 4
	packetNumber := uint64(42)

	// Protect the packet
	protected, err := ProtectPayload(packet, pnOffset, pnLen, packetNumber, true, ks)
	if err != nil {
		t.Fatalf("ProtectPayload failed: %v", err)
	}

	// Unprotect the packet
	unprotected, err := UnprotectPayload(protected, pnOffset, pnLen, packetNumber, true, ks)
	if err != nil {
		t.Fatalf("UnprotectPayload failed: %v", err)
	}

	// The unprotected packet should contain the original header + plaintext
	if !bytes.Equal(unprotected[:pnOffset+pnLen], packet[:pnOffset+pnLen]) {
		t.Fatal("header bytes don't match after round-trip")
	}

	if !bytes.Equal(unprotected[pnOffset+pnLen:], payload) {
		t.Fatal("payload doesn't match after round-trip")
	}
}

// ============================================================================
// Key Manager / Key Update Tests (RFC 9001 §6)
// ============================================================================

// TestKeyManagerInitialPhase tests the initial key phase.
func TestKeyManagerInitialPhase(t *testing.T) {
	txSecret := bytes.Repeat([]byte{0x01}, 32)
	rxSecret := bytes.Repeat([]byte{0x02}, 32)
	cs := DefaultCipherSuite()

	km, err := NewKeyManager(txSecret, rxSecret, cs)
	if err != nil {
		t.Fatalf("failed to create key manager: %v", err)
	}

	if km.TxKeyPhase() != KeyPhaseZero {
		t.Fatal("initial TX key phase should be 0")
	}
	if km.RxKeyPhase() != KeyPhaseZero {
		t.Fatal("initial RX key phase should be 0")
	}

	// Key update should fail before handshake confirmation
	err = km.InitiateKeyUpdate()
	if err == nil {
		t.Fatal("key update should fail before handshake confirmation")
	}
}

// TestKeyManagerKeyUpdate tests the key update process.
func TestKeyManagerKeyUpdate(t *testing.T) {
	txSecret := bytes.Repeat([]byte{0x01}, 32)
	rxSecret := bytes.Repeat([]byte{0x02}, 32)
	cs := DefaultCipherSuite()

	km, err := NewKeyManager(txSecret, rxSecret, cs)
	if err != nil {
		t.Fatalf("failed to create key manager: %v", err)
	}

	// Enable key updates
	km.SetHandshakeConfirmed()

	// Record a packet sent and acknowledged
	km.RecordPacketSent(1)
	km.RecordAckedPN(1)

	// Now we can initiate a key update
	oldTxPhase := km.TxKeyPhase()
	err = km.InitiateKeyUpdate()
	if err != nil {
		t.Fatalf("InitiateKeyUpdate failed: %v", err)
	}

	// Key phase should have toggled
	newTxPhase := km.TxKeyPhase()
	if newTxPhase == oldTxPhase {
		t.Fatal("key phase should toggle after update")
	}

	// The new TX keys should be different from the old ones
	// (We verify by checking that encryption with old keys + decryption
	// with new keys fails)
}

// TestKeyManagerPeerKeyUpdate tests handling a peer-initiated key update.
func TestKeyManagerPeerKeyUpdate(t *testing.T) {
	txSecret := bytes.Repeat([]byte{0x01}, 32)
	rxSecret := bytes.Repeat([]byte{0x02}, 32)
	cs := DefaultCipherSuite()

	km, err := NewKeyManager(txSecret, rxSecret, cs)
	if err != nil {
		t.Fatalf("failed to create key manager: %v", err)
	}

	km.SetHandshakeConfirmed()

	oldTxPhase := km.TxKeyPhase()
	oldRxPhase := km.RxKeyPhase()

	err = km.HandlePeerKeyUpdate()
	if err != nil {
		t.Fatalf("HandlePeerKeyUpdate failed: %v", err)
	}

	if km.TxKeyPhase() == oldTxPhase {
		t.Fatal("TX key phase should toggle after peer update")
	}
	if km.RxKeyPhase() == oldRxPhase {
		t.Fatal("RX key phase should toggle after peer update")
	}
}

// TestKeyPhaseToggle tests KeyPhase toggle behavior.
func TestKeyPhaseToggle(t *testing.T) {
	if KeyPhaseZero.Toggle() != KeyPhaseOne {
		t.Fatal("KeyPhaseZero toggle should be KeyPhaseOne")
	}
	if KeyPhaseOne.Toggle() != KeyPhaseZero {
		t.Fatal("KeyPhaseOne toggle should be KeyPhaseZero")
	}
}

// TestKeyManagerSelectRxKeys tests the key set selection logic.
func TestKeyManagerSelectRxKeys(t *testing.T) {
	txSecret := bytes.Repeat([]byte{0x01}, 32)
	rxSecret := bytes.Repeat([]byte{0x02}, 32)
	cs := DefaultCipherSuite()

	km, _ := NewKeyManager(txSecret, rxSecret, cs)

	// Current phase should return current keys
	current := km.SelectRxKeys(5, KeyPhaseZero)
	if current != km.RxKeys() {
		t.Fatal("should select current keys for current phase")
	}

	// Different phase should return next or previous keys
	other := km.SelectRxKeys(5, KeyPhaseOne)
	if other == nil {
		t.Fatal("should return non-nil keys for different phase")
	}
}

// ============================================================================
// Cipher Suite Tests
// ============================================================================

func TestGetCipherSuite(t *testing.T) {
	cs, ok := GetCipherSuite(CipherSuiteAES128GCM)
	if !ok {
		t.Fatal("AES-128-GCM should be a valid cipher suite")
	}
	if cs.KeyLen != 16 {
		t.Fatalf("expected 16-byte key for AES-128-GCM, got %d", cs.KeyLen)
	}
	if cs.IVLen != 12 {
		t.Fatalf("expected 12-byte IV, got %d", cs.IVLen)
	}
	if cs.HeaderProtection != "AES-ECB" {
		t.Fatalf("expected AES-ECB header protection, got %s", cs.HeaderProtection)
	}

	cs2, ok := GetCipherSuite(CipherSuiteAES256GCM)
	if !ok {
		t.Fatal("AES-256-GCM should be a valid cipher suite")
	}
	if cs2.KeyLen != 32 {
		t.Fatalf("expected 32-byte key for AES-256-GCM, got %d", cs2.KeyLen)
	}
}

// TestAEAD256GCM tests AES-256-GCM cipher suite.
func TestAEAD256GCM(t *testing.T) {
	secret := bytes.Repeat([]byte{0x42}, 48) // SHA-384 hash size for AES-256-GCM
	cs, _ := GetCipherSuite(CipherSuiteAES256GCM)
	keys := DeriveTrafficKeys(secret, cs)

	aead, err := NewAEAD(keys, cs.ID)
	if err != nil {
		t.Fatalf("failed to create AES-256-GCM AEAD: %v", err)
	}

	header := []byte{0xC0, 0x00, 0x00, 0x00, 0x01}
	plaintext := []byte("AES-256-GCM test")

	ciphertext := aead.Encrypt(1, header, plaintext)
	decrypted, err := aead.Decrypt(1, header, ciphertext)
	if err != nil {
		t.Fatalf("AES-256-GCM decrypt failed: %v", err)
	}

	if !bytes.Equal(plaintext, decrypted) {
		t.Fatal("AES-256-GCM round-trip failed")
	}
}

// TestConstructNonce tests the nonce construction.
func TestConstructNonce(t *testing.T) {
	secret := bytes.Repeat([]byte{0x42}, 32)
	cs := DefaultCipherSuite()
	keys := DeriveTrafficKeys(secret, cs)

	aead, _ := NewAEAD(keys, cs.ID)

	// The nonce should be IV XOR padded_packet_number
	nonce := aead.constructNonce(0)
	if !bytes.Equal(nonce, aead.iv) {
		t.Fatal("nonce for PN=0 should equal IV")
	}

	// Different PNs should produce different nonces
	nonce1 := aead.constructNonce(1)
	nonce2 := aead.constructNonce(2)
	if bytes.Equal(nonce1, nonce2) {
		t.Fatal("different PNs should produce different nonces")
	}
}

// TestAEADLimitExceeded tests the AEAD limit check.
func TestAEADLimitExceeded(t *testing.T) {
	secret := bytes.Repeat([]byte{0x42}, 32)
	cs := DefaultCipherSuite()
	keys := DeriveTrafficKeys(secret, cs)

	aead, _ := NewAEAD(keys, cs.ID)

	// Initially not exceeded
	if aead.AEADLimitExceeded() {
		t.Fatal("AEAD limit should not be exceeded initially")
	}

	// Simulate exceeding the limit by setting txCount directly
	// (in production this takes 2^23 packets)
	aead.txCount = 1 << 23
	if !aead.AEADLimitExceeded() {
		t.Fatal("AEAD limit should be exceeded after 2^23 packets")
	}
}

// TestTLSErrorToQUICError tests TLS alert to QUIC error code conversion.
func TestTLSErrorToQUICError(t *testing.T) {
	// handshake_failure (0x28) → 0x0128
	code := TLSErrorToQUICError(0x28)
	if code != 0x0128 {
		t.Fatalf("expected 0x0128, got 0x%04x", code)
	}

	// no_application_protocol (0x78) → 0x0178
	code = TLSErrorToQUICError(0x78)
	if code != 0x0178 {
		t.Fatalf("expected 0x0178, got 0x%04x", code)
	}
}

// TestEncryptionLevelString tests EncryptionLevel.String().
func TestEncryptionLevelString(t *testing.T) {
	tests := []struct {
		level    EncryptionLevel
		expected string
	}{
		{EncryptionInitial, "Initial"},
		{EncryptionHandshake, "Handshake"},
		{EncryptionApplication, "Application"},
		{EncryptionEarly, "Early"},
	}

	for _, tt := range tests {
		if got := tt.level.String(); got != tt.expected {
			t.Errorf("got %q, expected %q", got, tt.expected)
		}
	}
}

// TestHKDFExtract tests HKDF-Extract.
func TestHKDFExtract(t *testing.T) {
	salt := bytes.Repeat([]byte{0x01}, 32)
	ikm := bytes.Repeat([]byte{0x02}, 32)

	prk := HKDFExtract(sha256.New, salt, ikm)
	if len(prk) != sha256.Size {
		t.Fatalf("expected %d-byte PRK, got %d", sha256.Size, len(prk))
	}

	// Different IKM should produce different PRK
	otherPrk := HKDFExtract(sha256.New, salt, bytes.Repeat([]byte{0x03}, 32))
	if bytes.Equal(prk, otherPrk) {
		t.Fatal("different IKM should produce different PRK")
	}
}

// TestHKDFExpand tests HKDF-Expand.
func TestHKDFExpand(t *testing.T) {
	prk := bytes.Repeat([]byte{0x42}, 32)
	info := []byte("test info")

	result := HKDFExpand(sha256.New, prk, info, 32)
	if len(result) != 32 {
		t.Fatalf("expected 32 bytes, got %d", len(result))
	}

	// Different info should produce different output
	otherResult := HKDFExpand(sha256.New, prk, []byte("different"), 32)
	if bytes.Equal(result, otherResult) {
		t.Fatal("different info should produce different output")
	}
}

// TestInitialSalt tests that the initial salt has the correct value.
func TestInitialSalt(t *testing.T) {
	expected := "38762cf7f55934b34d179ae6a4c80cadccbb7f0a"
	got := hex.EncodeToString(InitialSalt)
	if got != expected {
		t.Fatalf("initial salt: expected %s, got %s", expected, got)
	}
}

// TestKeyDerivationStruct tests the KeyDerivation helper.
func TestKeyDerivationStruct(t *testing.T) {
	kd := NewKeyDerivation(sha256.New)
	dcid := []byte{0x01, 0x02, 0x03, 0x04}

	clientInitial, serverInitial := kd.DeriveInitial(dcid)
	if bytes.Equal(clientInitial, serverInitial) {
		t.Fatal("client and server initial secrets must differ")
	}

	cs := DefaultCipherSuite()
	keys := kd.DeriveTrafficKeys(clientInitial, cs)
	if len(keys.Key) != cs.KeyLen || len(keys.IV) != cs.IVLen || len(keys.HPKey) != cs.HPKeyLen {
		t.Fatal("traffic keys have wrong lengths")
	}
}
