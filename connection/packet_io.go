// Package connection: unified packet send/receive pipeline with protection.
//
// This file implements the complete packet I/O pipeline:
//
//   Sending path:
//     1. Collect frames to send (control + data)
//     2. Encode frames into packet payload
//     3. Build packet header (long or short)
//     4. AEAD encrypt payload + apply header protection
//     5. Optionally coalesce multiple packets into one datagram
//     6. Send via UDP
//
//   Receiving path:
//     1. Split coalesced datagram into individual packets
//     2. Determine packet type and encryption level
//     3. Remove header protection + AEAD decrypt payload
//     4. Reconstruct full packet number
//     5. Decode frames from payload
//     6. Dispatch frames to FrameHandler
//     7. Record packet for ACK tracking
//     8. Update loss detection
//
// This is the final integration point that ties together:
//   - header: packet header encoding/decoding
//   - frames: frame encoding/decoding
//   - crypto: packet protection (AEAD + header protection)
//   - coalesce: packet coalescing/splitting
//   - recovery: loss detection + congestion control
//   - ack: ACK tracking
//   - stream: stream management
package connection

import (
	"fmt"
	"log"
	"net"
	"strings"
	"sync"

	"github.com/Cabbage4/quic-go/coalesce"
	"github.com/Cabbage4/quic-go/crypto"
	"github.com/Cabbage4/quic-go/frames"
	"github.com/Cabbage4/quic-go/header"
	"github.com/Cabbage4/quic-go/packet"
)

// maxBufferedPackets caps how many not-yet-decryptable datagrams PacketIO
// will retain while waiting for the corresponding receive keys to be installed
// (e.g. coalesced Initial+Handshake where Handshake keys arrive late, or a
// flood of packets just before the 1-RTT keys are ready). Without a cap an
// attacker (or just a very fast peer) can drive this slice to unbounded size
// and exhaust memory; each entry also pins the whole underlying datagram slice.
// 256 is plenty for legitimate handshake ordering on a single connection.
const maxBufferedPackets = 256

// PacketIO manages the complete packet send/receive pipeline.
type PacketIO struct {
	mu sync.Mutex

	conn        *Connection
	keyStore    *KeySetStore
	frameHandler *FrameHandler
	recovery    *RecoveryManager
	ackHandler  *AckHandler

	// UDP socket
	connUDP *net.UDPConn
	remoteAddr *net.UDPAddr

	// Spin bit manager
	spinBit *header.SpinBitManager

	// Connection IDs
	localConnID  []byte
	remoteConnID []byte

	// Packet number truncation: minimum 1 byte, default 4
	// In a real implementation, this adapts based on largest acked PN
	pnTruncationLen int

	// Whether we're in plaintext mode (no TLS/encryption)
	plaintextMode bool

	// Buffered packets that could not be decrypted because recv keys
	// were not yet installed (e.g. coalesced Initial + Handshake where
	// the Handshake packet arrives before keys are installed).
	// These are retried after driveHandshakeLoop installs new keys.
	bufferedPackets [][]byte

	// Stats
	packetsSent     uint64
	packetsReceived uint64
	bytesSent       uint64
	bytesReceived   uint64
}

// NewPacketIO creates a new packet I/O pipeline.
func NewPacketIO(
	conn *Connection,
	keyStore *KeySetStore,
	frameHandler *FrameHandler,
	recovery *RecoveryManager,
	ackHandler *AckHandler,
) *PacketIO {
	return &PacketIO{
		conn:           conn,
		keyStore:       keyStore,
		frameHandler:   frameHandler,
		recovery:       recovery,
		ackHandler:     ackHandler,
		spinBit:        header.NewSpinBitManager(),
		pnTruncationLen: 4,
	}
}

// SetUDPConn sets the UDP socket and remote address for sending.
// If remote is nil, the socket is assumed to be connected (created via
// net.DialUDP) and Write is used instead of WriteToUDP.
func (p *PacketIO) SetUDPConn(conn *net.UDPConn, remote *net.UDPAddr) {
	p.mu.Lock()
	defer p.mu.Unlock()
	p.connUDP = conn
	p.remoteAddr = remote
}

// writeUDP sends a packet via the UDP socket. Uses Write for connected
// sockets (created via net.DialUDP) and WriteToUDP for unconnected
// sockets (created via net.ListenUDP).
func (p *PacketIO) writeUDP(data []byte) (int, error) {
	if p.remoteAddr != nil {
		return p.connUDP.WriteToUDP(data, p.remoteAddr)
	}
	return p.connUDP.Write(data)
}

// SetConnIDs sets the local and remote connection IDs.
func (p *PacketIO) SetConnIDs(local, remote []byte) {
	p.mu.Lock()
	defer p.mu.Unlock()
	p.localConnID = local
	p.remoteConnID = remote
}

// SetPlaintextMode enables or disables plaintext (no encryption) mode.
// This is used for the simplified handshake without TLS.
func (p *PacketIO) SetPlaintextMode(plaintext bool) {
	p.mu.Lock()
	defer p.mu.Unlock()
	p.plaintextMode = plaintext
}

// === Sending ===

// SendPacket builds, protects, and sends a packet with the given frames
// at the specified encryption level.
//
// Parameters:
//   - level: encryption level (Initial, Handshake, Application)
//   - frames: list of frames to include in the payload
//
// Returns the packet number used, or an error.
func (p *PacketIO) SendPacket(level crypto.EncryptionLevel, frs []frames.Frame) (uint64, error) {
	p.mu.Lock()
	defer p.mu.Unlock()

	if p.connUDP == nil {
		return 0, fmt.Errorf("connection: no UDP socket configured")
	}

	pnSpace := EncryptionLevelToPNSpace(level)
	pn := p.conn.NextPacketNumber(pnSpace)

	// Encode all frames into payload
	payload := make([]byte, 0, 1024)
	ackEliciting := false
	for _, f := range frs {
		encoded, err := f.Encode()
		if err != nil {
			return pn, fmt.Errorf("connection: frame encode failed: %w", err)
		}
		payload = append(payload, encoded...)
		// Determine if this frame is ACK-eliciting
		if isAckElicitingFrame(f) {
			ackEliciting = true
		}
	}

	// Determine if we should send in plaintext mode
	if p.plaintextMode {
		// Build and send packet without encryption
		packet, err := p.buildUnprotectedPacket(level, pn, payload)
		if err != nil {
			return pn, err
		}
		_, err = p.writeUDP(packet)
		if err != nil {
			return pn, fmt.Errorf("connection: UDP write failed: %w", err)
		}

		// Record for recovery
		p.recovery.OnPacketSent(pn, pnSpace, len(packet), ackEliciting, true, now())

		// Record sent frames for ACK-driven stream state updates
		p.frameHandler.RecordSentFrames(pn, pnSpace, frs)

		p.packetsSent++
		p.bytesSent += uint64(len(packet))
		return pn, nil
	}

	// Protected mode: build header, encrypt payload, apply header protection
	packet, pnOffset, pnLen, err := p.buildProtectedPacket(level, pn, payload)
	if err != nil {
		return pn, err
	}

	// Protect the packet (AEAD + header protection)
	protected, err := p.keyStore.ProtectPacket(packet, pnOffset, pnLen, pn,
		level != crypto.EncryptionApplication, level)
	if err != nil {
		return pn, fmt.Errorf("connection: packet protection failed: %w", err)
	}

	// Send via UDP
	_, err = p.writeUDP(protected)
	if err != nil {
		return pn, fmt.Errorf("connection: UDP write failed: %w", err)
	}

	// Record for loss detection and congestion control
	p.recovery.OnPacketSent(pn, pnSpace, len(protected), ackEliciting, true, now())

	// Record sent frames for ACK-driven stream state updates
	p.frameHandler.RecordSentFrames(pn, pnSpace, frs)

	p.packetsSent++
	p.bytesSent += uint64(len(protected))

	return pn, nil
}

// buildProtectedPacket constructs the unprotected packet (header + plaintext payload)
// and returns it along with the PN offset and PN length for protection.
func (p *PacketIO) buildProtectedPacket(level crypto.EncryptionLevel, pn uint64, payload []byte) (packet []byte, pnOffset int, pnLen int, err error) {
	pnLen = p.pnTruncationLen
	if pnLen < 1 {
		pnLen = 1
	}
	if pnLen > 4 {
		pnLen = 4
	}

	if level == crypto.EncryptionApplication {
		// Short header (1-RTT)
	// KeyPhase: use key manager's phase if available
	keyPhase := false
	if km := p.keyStore.KeyManager(); km != nil {
		keyPhase = bool(km.TxKeyPhase())
	}
	sh := &header.ShortHeader{
		DestConnID:      p.remoteConnID,
		PacketNumber:    pn,
		PacketNumberLen: pnLen,
		Payload:         payload,
		SpinBit:         p.spinBit.OnPacketSent(),
		KeyPhase:        keyPhase,
	}
		encoded, err := sh.Encode()
		if err != nil {
			return nil, 0, 0, err
		}
		// PN offset = 1 (first byte) + DCID length
		pnOffset = 1 + len(p.remoteConnID)
		return encoded, pnOffset, pnLen, nil
	}

	// Long header (Initial or Handshake)
	// Length field must cover: PN + ciphertext (payload + AEAD tag)
	// AEAD tag is 16 bytes for AES-128-GCM and AES-256-GCM.
	const aeadTagLen = 16
	pktType := header.PacketTypeInitial
	token := []byte{}
	if level == crypto.EncryptionHandshake {
		pktType = header.PacketTypeHandshake
		token = nil
	}

	lh := &header.LongHeader{
		Type:            pktType,
		Version:         header.Version,
		DestConnID:      p.remoteConnID,
		SrcConnID:       p.localConnID,
		Token:           token,
		PacketNumber:    pn,
		PacketNumberLen: pnLen,
		Payload:         payload,
		Length:          uint64(pnLen + len(payload) + aeadTagLen),
	}
	encoded, err := lh.Encode()
	if err != nil {
		return nil, 0, 0, err
	}

	// Calculate PN offset for long header
	// 1 (flags) + 4 (version) + 1 (dcid len) + len(dcid) + 1 (scid len) + len(scid)
	// + [token len + token] (Initial only) + length varint
	pnOffset = 1 + 4 + 1 + len(p.remoteConnID) + 1 + len(p.localConnID)
	if pktType == header.PacketTypeInitial {
		// Token length varint + token bytes
		tl := varintLen(uint64(len(token)))
		pnOffset += tl + len(token)
	}
	// Length varint (use the corrected length with AEAD tag)
	lengthVal := uint64(pnLen + len(payload) + aeadTagLen)
	pnOffset += varintLen(lengthVal)

	return encoded, pnOffset, pnLen, nil
}

// buildUnprotectedPacket builds a packet without encryption (plaintext mode).
func (p *PacketIO) buildUnprotectedPacket(level crypto.EncryptionLevel, pn uint64, payload []byte) ([]byte, error) {
	pnLen := p.pnTruncationLen

	if level == crypto.EncryptionApplication {
		sh := &header.ShortHeader{
			DestConnID:      p.remoteConnID,
			PacketNumber:    pn,
			PacketNumberLen: pnLen,
			Payload:         payload,
			SpinBit:         p.spinBit.OnPacketSent(),
		}
		return sh.Encode()
	}

	pktType := header.PacketTypeInitial
	token := []byte{}
	if level == crypto.EncryptionHandshake {
		pktType = header.PacketTypeHandshake
		token = nil
	}

	lh := &header.LongHeader{
		Type:            pktType,
		Version:         header.Version,
		DestConnID:      p.remoteConnID,
		SrcConnID:       p.localConnID,
		Token:           token,
		PacketNumber:    pn,
		PacketNumberLen: pnLen,
		Payload:         payload,
	}
	return lh.Encode()
}

// SendDatagram coalesces and sends multiple packets in one UDP datagram.
func (p *PacketIO) SendDatagram(packets []coalesce.EncodedPacket) (int, error) {
	p.mu.Lock()
	defer p.mu.Unlock()

	if p.connUDP == nil {
		return 0, fmt.Errorf("connection: no UDP socket configured")
	}

	dat, count := coalesce.CoalescePackets(packets)
	if count == 0 {
		return 0, nil
	}

	_, err := p.writeUDP(dat)
	if err != nil {
		return 0, fmt.Errorf("connection: UDP write failed: %w", err)
	}

	p.packetsSent += uint64(count)
	p.bytesSent += uint64(len(dat))
	return count, nil
}

// === Receiving ===

// RecvDatagram processes a received UDP datagram.
// It splits coalesced packets, unprotects each, decodes frames,
// and dispatches them to the frame handler.
//
// For coalesced datagrams with Initial + Handshake packets, the
// Initial packet's CRYPTO data is queued for the TLS handshake loop.
// If the Handshake packet cannot be decrypted yet (no recv keys),
// it is buffered and retried by RetryBufferedPackets() after the
// driveHandshakeLoop installs the new keys.
func (p *PacketIO) RecvDatagram(datagram []byte) error {
	p.mu.Lock()
	defer p.mu.Unlock()

	p.bytesReceived += uint64(len(datagram))

	// Split coalesced datagram into individual packets
	packets, err := coalesce.SplitDatagram(datagram)
	if err != nil {
		return fmt.Errorf("connection: datagram split failed: %w", err)
	}

	for i, pkt := range packets {
		if derr := p.processPacket(pkt); derr != nil {
			// Log but continue processing remaining packets
			log.Printf("connection: processPacket error: %v", derr)
		}
		// Note: packets that fail decryption due to missing keys are
		// buffered in p.bufferedPackets. They are retried by
		// RetryBufferedPackets() after driveHandshakeLoop installs
		// new keys (e.g., after processing ServerHello CRYPTO data).
		_ = i
	}

	return nil
}

// bufferPacket appends a not-yet-decryptable datagram for later retry,
// enforcing the maxBufferedPackets cap. When the cap is reached we drop the
// oldest entry (the one least likely to still be useful) rather than growing
// without bound — protecting memory under a pre-keys packet flood. The slice
// is owned under p.mu, which the caller already holds.
func (p *PacketIO) bufferPacket(pkt []byte) {
	if len(p.bufferedPackets) >= maxBufferedPackets {
		// Drop oldest; keep the tail (most recent, most likely to matter).
		p.bufferedPackets[0] = nil
		p.bufferedPackets = p.bufferedPackets[1:]
	}
	p.bufferedPackets = append(p.bufferedPackets, pkt)
}

// RetryBufferedPackets re-attempts decryption of packets that were
// buffered because recv keys were not yet available. This is called
// by driveHandshakeLoop after flushing CRYPTO data and installing new
// keys (e.g., after processing ServerHello which installs Handshake keys).
func (p *PacketIO) RetryBufferedPackets() {
	p.mu.Lock()
	defer p.mu.Unlock()

	if len(p.bufferedPackets) == 0 {
		return
	}

	// Take a snapshot of buffered packets and clear the buffer.
	// If any still fail, they'll be re-buffered.
	pending := p.bufferedPackets
	p.bufferedPackets = nil

	for _, pkt := range pending {
		if err := p.processPacket(pkt); err != nil {
			// Log but continue — the packet may still fail if keys
			// for a different level are still missing.
			log.Printf("connection: buffered packet retry failed: %v", err)
		}
	}
}

// processPacket handles a single (de-coalesced) packet.
func (p *PacketIO) processPacket(pkt []byte) error {
	if len(pkt) < 1 {
		return fmt.Errorf("connection: empty packet")
	}

	// Determine if long or short header
	isLong := pkt[0]&0x80 != 0

	if isLong {
		return p.processLongHeaderPacket(pkt)
	}
	return p.processShortHeaderPacket(pkt)
}

// processLongHeaderPacket handles Initial and Handshake packets.
func (p *PacketIO) processLongHeaderPacket(pkt []byte) error {
	// For protected packets, we must use DecodeLongHeaderPartial which does
	// NOT read the masked bits (reserved bits + PN length in byte 0).
	// The full DecodeLongHeader would fail on protected packets because:
	//   1. Reserved bits validation fails (bits are masked)
	//   2. PN length is wrong (bits are masked) → wrong PN, wrong payload boundary
	isRetry := pkt[0]&0x80 != 0 && (pkt[0]>>4)&0x03 == byte(header.PacketTypeRetry)

	if isRetry {
		// Retry packets are not encrypted; use full decode
		lh, _, err := header.DecodeLongHeader(pkt)
		if err != nil {
			return fmt.Errorf("connection: retry header decode failed: %w", err)
		}
		return p.handleRetryPacket(lh)
	}

	// Use partial decode (skips masked bits)
	lh, _, err := header.DecodeLongHeaderPartial(pkt)
	if err != nil {
		return fmt.Errorf("connection: long header partial decode failed: %w", err)
	}

	// Determine encryption level from packet type
	var level crypto.EncryptionLevel
	switch lh.Type {
	case header.PacketTypeInitial:
		level = crypto.EncryptionInitial
	case header.PacketTypeHandshake:
		level = crypto.EncryptionHandshake
	case header.PacketType0RTT:
		level = crypto.EncryptionEarly
	default:
		return fmt.Errorf("connection: unexpected long header type %d", lh.Type)
	}

	// Version negotiation check
	if lh.Version != header.Version {
		return fmt.Errorf("connection: unsupported version 0x%08x", lh.Version)
	}

	pnOffset := lh.PNOffset
	var pn uint64
	var payload []byte

	if p.plaintextMode {
		// Plaintext mode: use full decode (no HP, no AEAD)
		fullHeader, _, derr := header.DecodeLongHeader(pkt)
		if derr != nil {
			return fmt.Errorf("connection: plaintext long header decode failed: %w", derr)
		}
		pn = fullHeader.PacketNumber
		payload = fullHeader.Payload
	} else {
	// Protected mode: two-phase unprotection
	// Phase 1: Remove header protection using pnLen=4 (max) for sample.
	// The HP sample is always at pnOffset+4 regardless of actual PN length.
	// Phase 2: Read real pnLen from unmasked byte 0, reconstruct PN, AEAD decrypt.
	unprotected, realPNLen, realTruncatedPN, decErr := p.unprotectLongHeader(pkt, pnOffset, level)
	if decErr != nil {
		// If keys are not yet available for this level, buffer the
		// packet for later retry. The driveHandshakeLoop will call
		// RetryBufferedPackets after installing new keys.
		if strings.Contains(decErr.Error(), "no recv keys") {
			p.bufferPacket(pkt)
			return nil
		}
		return fmt.Errorf("connection: packet unprotection failed: %w", decErr)
	}

		// Reconstruct full PN
		fullPN := p.reconstructPN(realTruncatedPN, realPNLen, EncryptionLevelToPNSpace(level))
		pn = fullPN

		// Extract payload from unprotected packet
		// The unprotected packet has the same header layout but with unmasked byte 0.
		// PN is at pnOffset, length realPNLen. Payload starts at pnOffset + realPNLen.
		payloadStart := pnOffset + realPNLen
		if payloadStart > len(unprotected) {
			return fmt.Errorf("connection: unprotected packet too short for payload")
		}
		payload = unprotected[payloadStart:]
	}

	// Process frames in the payload
	pnSpace := EncryptionLevelToPNSpace(level)
	ackEliciting, ferr := p.frameHandler.ProcessFrames(payload, pnSpace, pn)
	if ferr != nil {
		return ferr
	}

	// Record packet for ACK tracking
	p.ackHandler.OnPacketReceived(pn, pnSpace, ackEliciting)

	// Touch activity (idle timeout)
	p.conn.TouchActivity()
	p.packetsReceived++

	return nil
}

// processShortHeaderPacket handles 1-RTT (Application) packets.
func (p *PacketIO) processShortHeaderPacket(pkt []byte) error {
	dcidLen := len(p.localConnID)
	if dcidLen == 0 {
		return fmt.Errorf("connection: cannot decode short header without DCID length")
	}

	if p.plaintextMode {
		// Plaintext: use full decode
		sh, _, err := header.DecodeShortHeader(pkt, dcidLen)
		if err != nil {
			return fmt.Errorf("connection: short header decode failed: %w", err)
		}
		pn := sh.PacketNumber
		payload := sh.Payload
		pnSpace := PNSpaceApplication
		ackEliciting, ferr := p.frameHandler.ProcessFrames(payload, pnSpace, pn)
		if ferr != nil {
			return ferr
		}
		p.ackHandler.OnPacketReceived(pn, pnSpace, ackEliciting)
		p.spinBit.OnPacketReceived(sh.SpinBit)
		p.conn.TouchActivity()
		p.packetsReceived++
		return nil
	}

	// Protected mode: two-phase unprotection
	// Use partial decode (skips masked bits)
	sh, _, err := header.DecodeShortHeaderPartial(pkt, dcidLen)
	if err != nil {
		return fmt.Errorf("connection: short header partial decode failed: %w", err)
	}

	// PN offset for short header = 1 (first byte) + dcidLen
	pnOffset := 1 + dcidLen
	level := crypto.EncryptionApplication

	// Two-phase unprotection
	unprotected, realPNLen, realTruncatedPN, decErr := p.unprotectShortHeader(pkt, pnOffset, level)
	if decErr != nil {
		// Buffer if Application keys not yet available
		if strings.Contains(decErr.Error(), "no recv keys") {
			p.bufferPacket(pkt)
			return nil
		}
		return fmt.Errorf("connection: packet unprotection failed: %w", decErr)
	}

	// Reconstruct full PN
	fullPN := p.reconstructPN(realTruncatedPN, realPNLen, PNSpaceApplication)
	pn := fullPN

	// Extract payload
	payloadStart := pnOffset + realPNLen
	if payloadStart > len(unprotected) {
		return fmt.Errorf("connection: unprotected short packet too short for payload")
	}
	payload := unprotected[payloadStart:]

	// Update spin bit
	p.spinBit.OnPacketReceived(sh.SpinBit)

	// Process frames
	pnSpace := PNSpaceApplication
	ackEliciting, ferr := p.frameHandler.ProcessFrames(payload, pnSpace, pn)
	if ferr != nil {
		return ferr
	}

	// Record packet for ACK tracking
	p.ackHandler.OnPacketReceived(pn, pnSpace, ackEliciting)

	// Touch activity
	p.conn.TouchActivity()
	p.packetsReceived++

	return nil
}

// handleRetryPacket processes a Retry packet (RFC 9000 §17.2.5).
// The client must switch to using the Retry's Source Connection ID as the
// destination connection ID for all subsequent Initial packets it sends.
func (p *PacketIO) handleRetryPacket(lh *header.LongHeader) error {
	// Switch the remote connection ID to the Retry's Source Connection ID.
	// This is the core behavior: the server's Retry picks a new SCID, and
	// the client must use it as the DCID for subsequent Initial packets.
	if len(lh.SrcConnID) > 0 {
		p.remoteConnID = make([]byte, len(lh.SrcConnID))
		copy(p.remoteConnID, lh.SrcConnID)
	}

	// Reset the packet number for Initial space since we're restarting
	// the handshake with the new connection ID.
	p.conn.ResetPacketNumber(PNSpaceInitial)

	return nil
}

// reconstructPN reconstructs the full packet number from a truncated one.
// This uses the largest acknowledged PN as context (RFC 9000 §17.3.2 /
// Appendix A.3).
//
// We delegate to packet.DecodePacketNumber, which is the RFC-faithful
// implementation with correct unsigned-underflow guards. The previous inline
// version computed `expectedPN - (rangeBits>>1)` without guarding
// `expectedPN >= rangeBits/2`; for a 4-byte PN field with a small expectedPN
// that subtraction underflows to ~2^64, making the "candidate too low"
// condition always true and inflating every packet number by 2^32
// (observed as largestAcked ≈ 0x1_0000_5EE7, freezing the receive loop).
func (p *PacketIO) reconstructPN(truncatedPN uint64, pnLen int, space PNSpace) uint64 {
	largestReceived := p.ackHandler.LargestReceivedPN(space)
	if largestReceived == nil {
		// No packets received yet; the truncated PN is the full PN
		return truncatedPN
	}

	return packet.DecodePacketNumber(*largestReceived, truncatedPN, pnLen*8)
}

// unprotectLongHeader performs two-phase unprotection for long header packets
// (RFC 9001 §5.4).
//
// Phase 1: Remove header protection using pnLen=4 (maximum) for the sample.
//   The HP sample is always at pnOffset+4 regardless of actual PN length.
//   This unmasks byte 0 (reserved bits + PN length) and the PN field.
//
// Phase 2: Read the real pnLen from the unmasked byte 0 (bits 0-1).
//   Read the real truncated PN using the real pnLen.
//   AEAD decrypt using the real PN.
//
// Returns:
//   - unprotected packet (header + plaintext payload)
//   - real PN length (from unmasked byte 0)
//   - real truncated PN value
//   - error
func (p *PacketIO) unprotectLongHeader(pkt []byte, pnOffset int, level crypto.EncryptionLevel) ([]byte, int, uint64, error) {
	// Get receive keys for this level
	ks := p.keyStore.GetKeys(level, KeyDirectionRecv)
	if ks == nil {
		return nil, 0, 0, fmt.Errorf("connection: no recv keys for level %s", level)
	}

	pktCopy := make([]byte, len(pkt))
	copy(pktCopy, pkt)

	// Check minimum length for HP sample
	sampleEnd := pnOffset + 4 + 16 // pnOffset + 4 (sample offset) + 16 (sample length)
	if len(pktCopy) < sampleEnd {
		return nil, 0, 0, fmt.Errorf("crypto: packet too short for header protection (need %d, have %d)", sampleEnd, len(pktCopy))
	}

	// Two-phase unprotection (RFC 9001 §5.4):
	// Phase 1: Generate the mask and unmask byte 0 to discover the real PN length.
	// The sample is at pnOffset+4 (always 4 bytes, regardless of actual PN length).
	// The mask is 5 bytes: mask[0] for byte 0, mask[1..4] for up to 4 PN bytes.
	// We only unmask byte 0 and the actual PN bytes, NOT all 4 bytes,
	// to avoid corrupting ciphertext bytes when the real PN is shorter than 4.
	mask, err := crypto.GenerateHeaderProtectionMask(ks.HPKey, pktCopy, pnOffset, ks.AEAD.CipherSuiteID())
	if err != nil {
		return nil, 0, 0, fmt.Errorf("crypto: header protection mask generation failed: %w", err)
	}

	// Unmask byte 0's low 4 bits (long header: reserved bits + PN length)
	pktCopy[0] ^= mask[0] & 0x0f

	// Phase 2: Read real pnLen from unmasked byte 0
	realPNLen := int(pktCopy[0]&0x03) + 1

	// Unmask only the actual PN bytes (not all 4)
	for i := 0; i < realPNLen; i++ {
		pktCopy[pnOffset+i] ^= mask[1+i]
	}

	// Read real truncated PN
	realTruncatedPN := readTruncatedPN(pktCopy, pnOffset, realPNLen)

	// AEAD decrypt
	// Header = everything up to pnOffset + realPNLen
	// Ciphertext = everything after pnOffset + realPNLen
	headerEnd := pnOffset + realPNLen
	if headerEnd > len(pktCopy) {
		return nil, 0, 0, fmt.Errorf("crypto: packet too short for AEAD (header ends at %d, packet is %d)", headerEnd, len(pktCopy))
	}
	header := pktCopy[:headerEnd]
	ciphertext := pktCopy[headerEnd:]

	plaintext, err := ks.AEAD.Decrypt(realTruncatedPN, header, ciphertext)
	if err != nil {
		return nil, 0, 0, fmt.Errorf("crypto: AEAD decryption failed: %w", err)
	}

	// Construct unprotected packet = header + plaintext
	unprotected := make([]byte, headerEnd+len(plaintext))
	copy(unprotected, header)
	copy(unprotected[headerEnd:], plaintext)

	return unprotected, realPNLen, realTruncatedPN, nil
}

// unprotectShortHeader performs two-phase unprotection for short header packets
// (RFC 9001 §5.4). Same logic as unprotectLongHeader but for short headers.
func (p *PacketIO) unprotectShortHeader(pkt []byte, pnOffset int, level crypto.EncryptionLevel) ([]byte, int, uint64, error) {
	// Get receive keys
	var ks *crypto.KeySet
	if level == crypto.EncryptionApplication {
		ks = p.keyStore.GetKeys(level, KeyDirectionRecv)
		if ks == nil && p.keyStore.KeyManager() != nil {
			ks = p.keyStore.KeyManager().RxKeys()
		}
	} else {
		ks = p.keyStore.GetKeys(level, KeyDirectionRecv)
	}
	if ks == nil {
		return nil, 0, 0, fmt.Errorf("connection: no recv keys for level %s", level)
	}

	pktCopy := make([]byte, len(pkt))
	copy(pktCopy, pkt)

	// Check minimum length for HP sample
	sampleEnd := pnOffset + 4 + 16
	if len(pktCopy) < sampleEnd {
		return nil, 0, 0, fmt.Errorf("crypto: packet too short for header protection (need %d, have %d)", sampleEnd, len(pktCopy))
	}

	// Two-phase unprotection (RFC 9001 §5.4):
	// Phase 1: Generate the mask and unmask byte 0 to discover the real PN length.
	// For short headers, 5 bits of byte 0 are masked (reserved + key phase + PN length).
	mask, err := crypto.GenerateHeaderProtectionMask(ks.HPKey, pktCopy, pnOffset, ks.AEAD.CipherSuiteID())
	if err != nil {
		return nil, 0, 0, fmt.Errorf("crypto: header protection mask generation failed: %w", err)
	}

	// Unmask byte 0's low 5 bits (short header: reserved + key phase + PN length)
	pktCopy[0] ^= mask[0] & 0x1f

	// Phase 2: Read real pnLen from unmasked byte 0
	realPNLen := int(pktCopy[0]&0x03) + 1

	// Unmask only the actual PN bytes (not all 4)
	for i := 0; i < realPNLen; i++ {
		pktCopy[pnOffset+i] ^= mask[1+i]
	}

	// Read real truncated PN
	realTruncatedPN := readTruncatedPN(pktCopy, pnOffset, realPNLen)

	// AEAD decrypt
	headerEnd := pnOffset + realPNLen
	if headerEnd > len(pktCopy) {
		return nil, 0, 0, fmt.Errorf("crypto: packet too short for AEAD")
	}
	header := pktCopy[:headerEnd]
	ciphertext := pktCopy[headerEnd:]

	plaintext, err := ks.AEAD.Decrypt(realTruncatedPN, header, ciphertext)
	if err != nil {
		return nil, 0, 0, fmt.Errorf("crypto: AEAD decryption failed: %w", err)
	}

	// Construct unprotected packet
	unprotected := make([]byte, headerEnd+len(plaintext))
	copy(unprotected, header)
	copy(unprotected[headerEnd:], plaintext)

	return unprotected, realPNLen, realTruncatedPN, nil
}

// readTruncatedPN reads the truncated packet number from the given offset.
func readTruncatedPN(data []byte, pnOffset, pnLen int) uint64 {
	var pn uint64
	for i := 0; i < pnLen; i++ {
		pn = (pn << 8) | uint64(data[pnOffset+i])
	}
	return pn
}

// === Helpers ===

// varintLen returns the number of bytes needed to encode a varint value.
func varintLen(v uint64) int {
	switch {
	case v <= 63:
		return 1
	case v <= 16383:
		return 2
	case v <= 1073741823:
		return 4
	default:
		return 8
	}
}

// isAckElicitingFrame returns true if the frame type requires acknowledgment.
// Per RFC 9000 §13.2: PADDING, ACK, and CONNECTION_CLOSE are not ACK-eliciting.
func isAckElicitingFrame(f frames.Frame) bool {
	switch f.(type) {
	case *frames.Padding:
		return false
	case *frames.ACK:
		return false
	case *frames.ConnectionClose:
		return false
	case *frames.HandshakeDone:
		// HANDSHAKE_DONE is technically ACK-eliciting
		return true
	default:
		return true
	}
}

// === Stats ===

// PacketsSent returns the total number of packets sent.
func (p *PacketIO) PacketsSent() uint64 {
	p.mu.Lock()
	defer p.mu.Unlock()
	return p.packetsSent
}

// PacketsReceived returns the total number of packets received.
func (p *PacketIO) PacketsReceived() uint64 {
	p.mu.Lock()
	defer p.mu.Unlock()
	return p.packetsReceived
}

// BytesSent returns the total bytes sent.
func (p *PacketIO) BytesSent() uint64 {
	p.mu.Lock()
	defer p.mu.Unlock()
	return p.bytesSent
}

// BytesReceived returns the total bytes received.
func (p *PacketIO) BytesReceived() uint64 {
	p.mu.Lock()
	defer p.mu.Unlock()
	return p.bytesReceived
}

// FlushPendingControlFrames sends all pending control frames (ACKs, flow control, etc.)
// and CRYPTO data for each encryption level.
//
// Each level's CRYPTO data is sent as a separate UDP datagram (not coalesced)
// to avoid the timing problem where the receiver can't decrypt the Handshake
// packet before processing the Initial CRYPTO. If the receiver still can't
// decrypt a packet, it buffers it and retries after keys are installed.
func (p *PacketIO) FlushPendingControlFrames() error {
	// Generate and send control frames for each PN space that has pending data
	for _, space := range []PNSpace{PNSpaceInitial, PNSpaceHandshake, PNSpaceApplication} {
		ctrlFrames := p.frameHandler.GenerateControlFrames(space)
		if len(ctrlFrames) == 0 {
			continue
		}

		level := PNSpaceToEncryptionLevel(space)
		_, err := p.SendPacket(level, ctrlFrames)
		if err != nil {
			return fmt.Errorf("connection: failed to flush control frames for %s: %w", space, err)
		}
	}

	// Collect and send CRYPTO data from TLS for each level as separate packets.
	// We send Initial first, then Handshake, so the receiver processes Initial
	// CRYPTO (installing Handshake keys) before the Handshake CRYPTO arrives.
	// Even if the order isn't guaranteed over UDP, the receiver's packet
	// buffering mechanism handles out-of-order arrival.
	for _, level := range []crypto.EncryptionLevel{crypto.EncryptionInitial, crypto.EncryptionHandshake, crypto.EncryptionApplication} {
		data := p.keyStore.GetCryptoData(level)
		if len(data) == 0 {
			continue
		}

		_, err := p.SendPacket(level, []frames.Frame{
			&frames.Crypto{Offset: 0, Data: data},
		})
		if err != nil {
			return fmt.Errorf("connection: failed to send CRYPTO data for %s: %w", level, err)
		}
	}

	return nil
}

// Close stops the packet I/O.
func (p *PacketIO) Close() {
	p.mu.Lock()
	defer p.mu.Unlock()

	if p.connUDP != nil {
		p.connUDP.Close()
	}
}
