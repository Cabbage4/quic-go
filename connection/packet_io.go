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
	"net"
	"sync"
	"time"

	"github.com/Cabbage4/quic-go/coalesce"
	"github.com/Cabbage4/quic-go/crypto"
	"github.com/Cabbage4/quic-go/errors"
	"github.com/Cabbage4/quic-go/frames"
	"github.com/Cabbage4/quic-go/header"
	"github.com/Cabbage4/quic-go/varint"
)

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
func (p *PacketIO) SetUDPConn(conn *net.UDPConn, remote *net.UDPAddr) {
	p.mu.Lock()
	defer p.mu.Unlock()
	p.connUDP = conn
	p.remoteAddr = remote
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
		_, err = p.connUDP.WriteToUDP(packet, p.remoteAddr)
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
	_, err = p.connUDP.WriteToUDP(protected, p.remoteAddr)
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
	// Length varint
	lengthVal := uint64(pnLen + len(payload))
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

	_, err := p.connUDP.WriteToUDP(dat, p.remoteAddr)
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
func (p *PacketIO) RecvDatagram(datagram []byte) error {
	p.mu.Lock()
	defer p.mu.Unlock()

	p.bytesReceived += uint64(len(datagram))

	// Split coalesced datagram into individual packets
	packets, err := coalesce.SplitDatagram(datagram)
	if err != nil {
		return fmt.Errorf("connection: datagram split failed: %w", err)
	}

	for _, pkt := range packets {
		if derr := p.processPacket(pkt); derr != nil {
			// Log but continue processing remaining packets
			// In a real implementation, this would log the error
			_ = derr
		}
	}

	return nil
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
	lh, _, err := header.DecodeLongHeader(pkt)
	if err != nil {
		return fmt.Errorf("connection: long header decode failed: %w", err)
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
	case header.PacketTypeRetry:
		// Retry packets are not encrypted; handle specially
		return p.handleRetryPacket(lh)
	default:
		return fmt.Errorf("connection: unknown long header type %d", lh.Type)
	}

	// Version negotiation check
	if lh.Version != header.Version {
		// Handle version negotiation (simplified)
		return fmt.Errorf("connection: unsupported version 0x%08x", lh.Version)
	}

	// Reconstruct packet number and payload
	pn := lh.PacketNumber
	payload := lh.Payload

	if !p.plaintextMode {
		// Calculate PN offset for unprotection
		pnOffset, pnLen := p.calcLongHeaderPNOffset(lh, pkt)

		// Reconstruct full packet number from truncated value
		fullPN := p.reconstructPN(pn, pnLen, EncryptionLevelToPNSpace(level))
		pn = fullPN

		// Unprotect the packet
		unprotected, err := p.keyStore.UnprotectPacket(pkt, pnOffset, pnLen, fullPN, true, level)
		if err != nil {
			return fmt.Errorf("connection: packet unprotection failed: %w", err)
		}

		// Re-decode header to get the unprotected payload
		ulh, _, derr := header.DecodeLongHeader(unprotected)
		if derr != nil {
			return fmt.Errorf("connection: re-decode unprotected header: %w", derr)
		}
		payload = ulh.Payload
	}

	// Process frames in the payload
	pnSpace := EncryptionLevelToPNSpace(level)
	ackEliciting, ferr := p.frameHandler.ProcessFrames(payload, pnSpace, pn)
	if ferr != nil {
		return ferr
	}

	// Record packet for ACK tracking
	p.ackHandler.OnPacketReceived(pn, pnSpace, ackEliciting)

	// Update spin bit
	if lh.Type != header.PacketTypeRetry {
		// Spin bit is only in short headers, but we check for completeness
	}

	// Touch activity (idle timeout)
	p.conn.TouchActivity()
	p.packetsReceived++

	return nil
}

// processShortHeaderPacket handles 1-RTT (Application) packets.
func (p *PacketIO) processShortHeaderPacket(pkt []byte) error {
	dcidLen := len(p.localConnID)
	if dcidLen == 0 {
		// Try to infer DCID length from context
		// In a real implementation, this would use the connection's known DCID length
		return fmt.Errorf("connection: cannot decode short header without DCID length")
	}

	sh, _, err := header.DecodeShortHeader(pkt, dcidLen)
	if err != nil {
		return fmt.Errorf("connection: short header decode failed: %w", err)
	}

	level := crypto.EncryptionApplication
	pn := sh.PacketNumber
	payload := sh.Payload

	if !p.plaintextMode {
		pnOffset := 1 + dcidLen
		pnLen := sh.PacketNumberLen

		// Reconstruct full packet number
		fullPN := p.reconstructPN(pn, pnLen, PNSpaceApplication)
		pn = fullPN

		// Unprotect the packet
		unprotected, err := p.keyStore.UnprotectPacket(pkt, pnOffset, pnLen, fullPN, false, level)
		if err != nil {
			return fmt.Errorf("connection: packet unprotection failed: %w", err)
		}

		// Re-decode to get unprotected payload
		ush, _, derr := header.DecodeShortHeader(unprotected, dcidLen)
		if derr != nil {
			return fmt.Errorf("connection: re-decode unprotected short header: %w", derr)
		}
		payload = ush.Payload
	}

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
func (p *PacketIO) handleRetryPacket(lh *header.LongHeader) error {
	// Retry packets are used for address validation by the server.
	// The client should switch to using the Retry Source Connection ID.
	// For now, just record that we received a retry.
	return nil
}

// reconstructPN reconstructs the full packet number from a truncated one.
// This uses the largest acknowledged PN as context (RFC 9000 §17.3.2).
func (p *PacketIO) reconstructPN(truncatedPN uint64, pnLen int, space PNSpace) uint64 {
	largestAcked := p.conn.LargestAckedPN(space)
	if largestAcked == nil {
		// No packets acked yet; the truncated PN is the full PN
		return truncatedPN
	}

	// Packet number reconstruction algorithm (RFC 9000 §17.3.2)
	expectedPN := *largestAcked + 1
	rangeBits := uint64(1) << (uint(pnLen) * 8)
	candidatePN := (expectedPN & ^(rangeBits - 1)) | (truncatedPN & (rangeBits - 1))

	// If candidate is less than expected, it wrapped around
	if candidatePN < expectedPN-(rangeBits>>1) {
		candidatePN += rangeBits
	}

	return candidatePN
}

// calcLongHeaderPNOffset calculates the PN offset and length for a long header.
func (p *PacketIO) calcLongHeaderPNOffset(lh *header.LongHeader, pkt []byte) (pnOffset int, pnLen int) {
	pnLen = lh.PacketNumberLen
	if pnLen < 1 {
		pnLen = 1
	}

	// Calculate offset: 1 (flags) + 4 (version) + 1 (dcid len) + dcid + 1 (scid len) + scid
	pnOffset = 1 + 4 + 1 + len(lh.DestConnID) + 1 + len(lh.SrcConnID)

	// Initial packets have token length + token
	if lh.Type == header.PacketTypeInitial {
		tl := varintLen(uint64(len(lh.Token)))
		pnOffset += tl + len(lh.Token)
	}

	// Length varint
	lengthVal := uint64(pnLen + len(lh.Payload))
	pnOffset += varintLen(lengthVal)

	return pnOffset, pnLen
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

// === Receive loop ===

// StartReceiveLoop starts a background goroutine that reads from the UDP socket
// and processes incoming datagrams.
func (p *PacketIO) StartReceiveLoop() error {
	p.mu.Lock()
	conn := p.connUDP
	p.mu.Unlock()

	if conn == nil {
		return fmt.Errorf("connection: no UDP socket configured")
	}

	go func() {
		buf := make([]byte, 65535)
		for {
			n, _, err := conn.ReadFromUDP(buf)
			if err != nil {
				// Socket closed or error
				return
			}
			data := make([]byte, n)
			copy(data, buf[:n])
			_ = p.RecvDatagram(data)
		}
	}()

	return nil
}

// === Convenience send methods ===

// SendPing sends a PING frame at the Application level.
func (p *PacketIO) SendPing() error {
	_, err := p.SendPacket(crypto.EncryptionApplication, []frames.Frame{&frames.Ping{}})
	return err
}

// SendHandshakeDone sends a HANDSHAKE_DONE frame (server only).
func (p *PacketIO) SendHandshakeDone() error {
	_, err := p.SendPacket(crypto.EncryptionApplication, []frames.Frame{&frames.HandshakeDone{}})
	return err
}

// SendConnectionClose sends a CONNECTION_CLOSE frame.
func (p *PacketIO) SendConnectionClose(errCode errors.TransportErrorCode, reason string) error {
	cc := &frames.ConnectionClose{
		ErrorCode:    uint64(errCode),
		ReasonPhrase: reason,
	}
	if p.conn.State() == StateClosed {
		cc.ApplicationError = true
	}
	_, err := p.SendPacket(crypto.EncryptionApplication, []frames.Frame{cc})
	return err
}

// SendCryptoFrame sends a CRYPTO frame at the given encryption level.
func (p *PacketIO) SendCryptoFrame(level crypto.EncryptionLevel, offset uint64, data []byte) error {
	cf := &frames.Crypto{
		Offset: offset,
		Data:   data,
	}
	_, err := p.SendPacket(level, []frames.Frame{cf})
	return err
}

// FlushPendingControlFrames sends all pending control frames (ACKs, flow control, etc.)
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

	// Also check for pending CRYPTO data from TLS
	for _, level := range []crypto.EncryptionLevel{crypto.EncryptionInitial, crypto.EncryptionHandshake, crypto.EncryptionApplication} {
		data := p.keyStore.GetCryptoData(level)
		if len(data) > 0 {
			// Send as CRYPTO frame
			_, err := p.SendPacket(level, []frames.Frame{
				&frames.Crypto{Offset: 0, Data: data},
			})
			if err != nil {
				return fmt.Errorf("connection: failed to send CRYPTO data for %s: %w", level, err)
			}
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

// ensure varint import is used
var _ = varint.Decode
var _ = time.Now
