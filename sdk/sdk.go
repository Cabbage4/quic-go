package sdk

import (
	"crypto/rand"
	"fmt"
	"io"
	"log"
	"net"
	"time"

	"github.com/Cabbage4/quic-go/connection"
	"github.com/Cabbage4/quic-go/crypto"
	"github.com/Cabbage4/quic-go/frames"
	"github.com/Cabbage4/quic-go/header"
	"github.com/Cabbage4/quic-go/stream"
	"github.com/Cabbage4/quic-go/transport"
	"github.com/Cabbage4/quic-go/varint"
)

// === Listener ===

// Listen creates a QUIC listener on the given address.
// The network must be "udp" or "udp4" or "udp6".
func Listen(network, addr string, config *Config) (*Listener, error) {
	if config == nil {
		config = DefaultConfig()
	}

	udpAddr, err := net.ResolveUDPAddr(network, addr)
	if err != nil {
		return nil, fmt.Errorf("sdk: resolve address: %w", err)
	}

	udpConn, err := net.ListenUDP(network, udpAddr)
	if err != nil {
		return nil, fmt.Errorf("sdk: listen UDP: %w", err)
	}

	// Generate a random secret for stateless reset tokens and tokens
	secret := make([]byte, 32)
	if _, err := rand.Read(secret); err != nil {
		udpConn.Close()
		return nil, fmt.Errorf("sdk: generate secret: %w", err)
	}

	l := &Listener{
		udpConn:    udpConn,
		config:     config,
		connTable:  make(map[string]*Conn),
		connTableMu: newNetMutex(),
		secret:     secret,
		acceptCh:   make(chan *Conn, 64),
		done:       make(chan struct{}),
	}

	go l.recvLoop()

	return l, nil
}

// Addr returns the listener's address.
func (l *Listener) Addr() net.Addr {
	return l.udpConn.LocalAddr()
}

// Accept waits for and returns the next incoming connection.
// In TLS mode, this blocks until the TLS handshake completes.
func (l *Listener) Accept() (*Conn, error) {
	select {
	case c := <-l.acceptCh:
		// Wait for handshake to complete
		if c.config.TLSMode {
			select {
			case <-c.handshakeDone:
			case <-c.closeCh:
				return nil, fmt.Errorf("sdk: connection closed during handshake")
			case <-l.done:
				return nil, fmt.Errorf("sdk: listener closed")
			}
		}
		return c, nil
	case <-l.done:
		return nil, fmt.Errorf("sdk: listener closed")
	}
}

// Close stops the listener.
func (l *Listener) Close() error {
	if l.closed {
		return nil
	}
	l.closed = true
	close(l.done)
	return l.udpConn.Close()
}

// recvLoop reads UDP datagrams and dispatches them to connections.
func (l *Listener) recvLoop() {
	buf := make([]byte, 65535)
	for {
		select {
		case <-l.done:
			return
		default:
		}

		n, raddr, err := l.udpConn.ReadFromUDP(buf)
		if err != nil {
			if l.closed {
				return
			}
			continue
		}

		data := make([]byte, n)
		copy(data, buf[:n])

		l.handlePacket(data, raddr)
	}
}

// handlePacket routes a received packet to the right connection or creates a new one.
func (l *Listener) handlePacket(data []byte, raddr *net.UDPAddr) {
	if len(data) < 1 {
		return
	}

	// Check header form bit
	isLongHeader := data[0]&0x80 != 0

	var dcid []byte

	if isLongHeader {
		// Parse long header to get DCID — use partial decode because
		// protected packets have masked reserved bits that would cause
		// DecodeLongHeader to fail.
		hdr, _, err := header.DecodeLongHeaderPartial(data)
		if err != nil {
			return
		}
		dcid = hdr.DestConnID
	} else {
		// Short header: DCID has no length prefix. We need to find the connection
		// by matching known CIDs. Iterate through all connections and check if
		// the bytes after the first byte match any connection's SrcConnID.
		l.connTableMu.Lock()
		for _, c := range l.connTable {
			scid := c.connMgr.SrcConnID()
			if len(scid) > 0 && len(data) > 1+len(scid) {
				if matchBytes(data[1:1+len(scid)], scid) {
					dcid = scid
					break
				}
			}
		}
		l.connTableMu.Unlock()
	}

	// Look up connection by DCID
	dcidKey := string(dcid)
	l.connTableMu.Lock()
	c, ok := l.connTable[dcidKey]
	l.connTableMu.Unlock()

	if ok {
		// Route to existing connection
		c.handleIncoming(data, raddr, isLongHeader)
		return
	}

	// New connection from Initial packet
	if isLongHeader {
		// Use partial decode — protected packets have masked bits
		hdr, _, err := header.DecodeLongHeaderPartial(data)
		if err != nil {
			return
		}

		// Only handle Initial packets for new connections
		if hdr.Type == header.PacketTypeInitial {
			l.createNewConnection(hdr, data, raddr)
		}
	}
}

// createNewConnection handles an Initial packet from a new client.
func (l *Listener) createNewConnection(hdr *header.LongHeader, data []byte, raddr *net.UDPAddr) {
	// Create a new server-side connection
	params := l.config.toTransportParams()

	conn := connection.NewConnection(true, transport.Params{})

	// Generate server source CID
	srcCID, err := connection.GenerateConnID(l.config.ConnIDLength)
	if err != nil {
		return
	}

	conn.ConnIDManager().InitSrcConnID(srcCID)
	// Use client's SCID as our DCID
	conn.ConnIDManager().InitDestConnID(hdr.SrcConnID)

	// Set transport parameters
	tp := transport.Params(params)
	conn.SetPeerParams(tp)

	// Initialize connection-layer subsystems
	c := &Conn{
		conn:           conn,
		connMgr:        conn.ConnIDManager(),
		udpConn:        l.udpConn,
		remoteAddr:     raddr,
		listener:       l,
		config:         l.config,
		sendQueue:      make(chan []byte, 256),
		acceptStreamCh: make(chan *Stream, 64),
		closeCh:        make(chan struct{}),
		handshakeDone:  make(chan struct{}),
		isServer:       true,
		streams:        make(map[uint64]*Stream),
		streamsMu:      newNetMutex(),
		nextServerBidi: 1, // server bidi streams start at 1
		nextServerUni:  3, // server uni streams start at 3
	}

	// Initialize subsystems
	c.initSubsystems(true, tp, hdr.DestConnID)

	// In TLS mode, set certificates in the TLS config
	if l.config.TLSMode && c.keyStore != nil {
		c.applyTLSConfig()
	}

	// Add to connection table
	dcidKey := string(hdr.DestConnID)
	l.connTableMu.Lock()
	l.connTable[dcidKey] = c
	// Also register with our server CID
	scidKey := string(srcCID)
	l.connTable[scidKey] = c
	l.connTableMu.Unlock()

	// Set up close callback
	conn.OnClose(func() {
		l.connTableMu.Lock()
		delete(l.connTable, dcidKey)
		delete(l.connTable, scidKey)
		l.connTableMu.Unlock()
		close(c.closeCh)
	})

	// Start the connection's send loop
	go c.sendLoop()

	// Process the initial packet
	c.handleIncoming(data, raddr, true)

	// In TLS mode, drive the handshake (server side)
	if l.config.TLSMode {
		go c.driveHandshakeLoop()
	}

	// Send server response
	if l.config.TLSMode {
		// TLS mode: let PacketIO handle the encrypted Initial response
		// The driveHandshakeLoop will flush pending CRYPTO data
	} else {
		// Plaintext mode: send PING + HANDSHAKE_DONE directly
		c.sendServerInitial()
	}

	// Notify Accept()
	select {
	case l.acceptCh <- c:
	default:
		// Accept queue full, drop connection
	}
}

// sendServerInitial sends the server's Initial response packet.
func (c *Conn) sendServerInitial() {
	// Build payload: PING + HANDSHAKE_DONE
	payload := []byte{0x01, 0x1e} // PING + HANDSHAKE_DONE

	pn := c.conn.NextPacketNumber(connection.PNSpaceInitial)

	hdr := &header.LongHeader{
		Type:            header.PacketTypeInitial,
		Version:         header.Version,
		DestConnID:      c.connMgr.DestConnID(), // client's SCID
		SrcConnID:       c.connMgr.SrcConnID(),  // our server SCID
		Token:           nil,
		PacketNumber:    pn,
		PacketNumberLen: 4,
		Payload:         payload,
	}

	packet, err := hdr.Encode()
	if err == nil {
		c.udpConn.WriteToUDP(packet, c.remoteAddr)
	}
}

// initSubsystems creates and wires the connection-layer subsystems:
// KeySetStore, AckHandler, RecoveryManager, FrameHandler, stream.Manager,
// PacketIO, and Coordinator. In plaintext mode, encryption is skipped.
// In TLS mode, initial keys are derived and a TLS session is started.
func (c *Conn) initSubsystems(isServer bool, tp transport.Params, initialDCID []byte) {
	// Create key store
	c.keyStore = connection.NewKeySetStore()

	// Create ACK handler
	c.ackHandler = connection.NewAckHandler()

	// Create recovery manager
	maxAckDelay := time.Duration(tp.MaxAckDelay) * time.Millisecond
	c.recovery = connection.NewRecoveryManager(
		maxAckDelay,
		!isServer, // isClient
	)

	// Create stream manager
	c.streamMgr = stream.NewManager(
		isServer,
		tp.InitialMaxData,
		tp.InitialMaxStreamDataBidiLocal,
		tp.InitialMaxStreamDataBidiRemote,
		tp.InitialMaxStreamDataUni,
		tp.InitialMaxStreamsBidi,
		tp.InitialMaxStreamsUni,
	)

	// Create frame handler
	c.frameHandler = connection.NewFrameHandler(
		c.conn,
		c.streamMgr,
		c.ackHandler,
		c.recovery,
		c.keyStore,
	)

	// Create coordinator
	c.coordinator = connection.NewCoordinator(
		c.conn, c.keyStore, c.frameHandler, c.recovery, c.ackHandler,
	)

	// Create packet I/O pipeline
	c.packetIO = connection.NewPacketIO(
		c.conn,
		c.keyStore,
		c.frameHandler,
		c.recovery,
		c.ackHandler,
	)
	c.packetIO.SetUDPConn(c.udpConn, c.remoteAddr)
	c.packetIO.SetConnIDs(c.connMgr.SrcConnID(), c.connMgr.DestConnID())

	// For client (connected socket via net.DialUDP), use nil remoteAddr
	// so PacketIO uses Write() instead of WriteToUDP().
	if !c.isServer {
		c.packetIO.SetUDPConn(c.udpConn, nil)
	}

	// Set up key discard callback to discard PN space
	c.keyStore.SetDiscardCallback(func(level crypto.EncryptionLevel) {
		pnSpace := connection.EncryptionLevelToPNSpace(level)
		c.ackHandler.DiscardPNSpace(pnSpace)
		c.recovery.OnPacketNumberSpaceDiscarded(pnSpace)
		c.frameHandler.CleanUpSentFrames(pnSpace)
	})

	// Configure encryption mode
	if c.config.TLSMode {
		// TLS mode: derive initial keys and start TLS session
		c.coordinator.SetPlaintextMode(false)
		c.packetIO.SetPlaintextMode(false)

		// Derive initial keys from the initial DCID
		if err := c.keyStore.DeriveInitialKeys(initialDCID, isServer); err != nil {
			log.Printf("quic: failed to derive initial keys: %v", err)
		}

		// Encode transport parameters for TLS
		tpBytes, err := connection.TransportParamsToBytes(&tp)
		if err != nil {
			log.Printf("quic: failed to encode transport params: %v", err)
			tpBytes = nil
		}

	// Start TLS session — key callbacks auto-install keys into KeySetStore
	err = c.keyStore.StartTLS(
		!isServer, // isClient
		tpBytes,
		c.config.ALPNProtocols,
		c.config.ServerName,
		c.config.TLSCertificates,
		c.config.InsecureSkipVerify,
		func(peerParams []byte) {
			// Peer's transport parameters received via TLS
			// FrameHandler will apply them
		},
	)
		if err != nil {
			log.Printf("quic: failed to start TLS: %v", err)
		}
	} else {
		// Plaintext mode: no encryption
		c.coordinator.SetPlaintextMode(true)
		c.packetIO.SetPlaintextMode(true)
	}
}

// applyTLSConfig applies TLS certificates to the TLS session.
// For server-side: sets certificates for the server's TLS config.
// For client-side: sets InsecureSkipVerify and root CAs if configured.
func (c *Conn) applyTLSConfig() {
	session := c.keyStore.TLSSession()
	if session == nil {
		return
	}
	// The TLS config (certificates, ALPN, ServerName) is already set
	// via keyStore.StartTLS(). This method can be extended for
	// certificate rotation, client auth, etc.
}

// driveHandshakeLoop runs the TLS handshake to completion.
// It repeatedly calls coordinator.DriveHandshake() and flushes
// pending CRYPTO data via PacketIO until the handshake is complete.
// After the handshake, the connection transitions to StateEstablished.
func (c *Conn) driveHandshakeLoop() {
	// Drive TLS handshake — this produces ClientHello/ServerHello CRYPTO
	// data which PacketIO.FlushPendingControlFrames() will send.
	for {
		select {
		case <-c.closeCh:
			return
		default:
		}

		// Check if handshake is complete
		session := c.keyStore.TLSSession()
		if session != nil && session.HandshakeComplete() {
			// Signal that the handshake is done (for Accept() and Stream.Write)
			select {
			case <-c.handshakeDone:
			default:
				close(c.handshakeDone)
			}
			// Handshake complete — flush any remaining CRYPTO data.
			if err := c.packetIO.FlushPendingControlFrames(); err != nil {
				log.Printf("quic: flush after handshake: %v", err)
			}
			// Retry any buffered packets that may have been waiting for keys
			c.packetIO.RetryBufferedPackets()
			return
		}

		// Drive the TLS handshake forward (Start on first call, then processEvents)
		// This must happen BEFORE feeding CRYPTO data: the server's QUICConn
		// must be Start()-ed before HandleData can process the ClientHello.
		if err := c.coordinator.DriveHandshake(); err != nil {
			log.Printf("quic: handshake error: %v", err)
			return
		}

		// Feed any queued CRYPTO data from received packets to TLS.
		// This must happen in the same goroutine to avoid deadlock
		// with the TLS session mutex.
		if err := c.frameHandler.FlushPendingCryptoData(); err != nil {
			log.Printf("quic: flush crypto data: %v", err)
		}

		// Drive TLS again after feeding CRYPTO data to process events
		// (e.g., server produces ServerHello after receiving ClientHello)
		if err := c.coordinator.DriveHandshake(); err != nil {
			log.Printf("quic: handshake error after crypto feed: %v", err)
			return
		}

		// Flush pending CRYPTO data and control frames
		if err := c.packetIO.FlushPendingControlFrames(); err != nil {
			log.Printf("quic: flush control frames: %v", err)
		}

		// Retry buffered packets that may now have keys available
		// (e.g., after processing ServerHello which installed Handshake keys)
		c.packetIO.RetryBufferedPackets()

		// Small delay to avoid busy-looping before more CRYPTO data arrives
		time.Sleep(1 * time.Millisecond)
	}
}

// === Dialer (Client) ===

// Dial establishes a QUIC connection to the given address.
func Dial(network, addr string, config *Config) (*Conn, error) {
	if config == nil {
		config = DefaultConfig()
	}

	udpAddr, err := net.ResolveUDPAddr(network, addr)
	if err != nil {
		return nil, fmt.Errorf("sdk: resolve address: %w", err)
	}

	// Use a local ephemeral port
	localAddr := &net.UDPAddr{IP: net.IPv4zero, Port: 0}
	udpConn, err := net.DialUDP(network, localAddr, udpAddr)
	if err != nil {
		return nil, fmt.Errorf("sdk: dial UDP: %w", err)
	}

	// Generate client source CID
	srcCID, err := connection.GenerateConnID(config.ConnIDLength)
	if err != nil {
		udpConn.Close()
		return nil, fmt.Errorf("sdk: generate CID: %w", err)
	}

	// Generate initial destination CID (random, will be replaced by server's CID)
	initialDCID, err := connection.GenerateConnID(config.ConnIDLength)
	if err != nil {
		udpConn.Close()
		return nil, fmt.Errorf("sdk: generate initial DCID: %w", err)
	}

	conn := connection.NewConnection(false, config.toTransportParams())

	connMgr := conn.ConnIDManager()
	connMgr.InitSrcConnID(srcCID)
	connMgr.InitDestConnID(initialDCID)

	c := &Conn{
		conn:           conn,
		connMgr:        connMgr,
		udpConn:        udpConn,
		remoteAddr:     udpAddr,
		config:         config,
		sendQueue:      make(chan []byte, 256),
		acceptStreamCh: make(chan *Stream, 64),
		closeCh:        make(chan struct{}),
		handshakeDone:  make(chan struct{}),
		isServer:       false,
		streams:        make(map[uint64]*Stream),
		streamsMu:      newNetMutex(),
		nextClientBidi: 0, // client bidi streams start at 0
		nextClientUni:  2, // client uni streams start at 2
	}

	// Initialize subsystems
	c.initSubsystems(false, config.toTransportParams(), initialDCID)

	// In TLS mode, set certificates in the TLS config
	if config.TLSMode && c.keyStore != nil {
		c.applyTLSConfig()
	}

	// Send Initial packet
	if err := c.sendInitial(srcCID, initialDCID); err != nil {
		udpConn.Close()
		return nil, fmt.Errorf("sdk: send initial: %w", err)
	}

	// In TLS mode, drive the handshake
	if config.TLSMode {
		go c.driveHandshakeLoop()
	}

	// Start receiving
	go c.clientRecvLoop()

	// Start send loop
	go c.sendLoop()

	// Set up idle timeout
	if config.MaxIdleTimeout > 0 {
		conn.SetIdleTimeout(config.MaxIdleTimeout)
		conn.StartIdleTimer()
	}

	// In TLS mode, wait for the handshake to complete before returning
	if config.TLSMode {
		deadline := time.Now().Add(10 * time.Second)
		for {
			session := c.keyStore.TLSSession()
			if session != nil && session.HandshakeComplete() {
				// Signal handshakeDone for Stream.Write
				select {
				case <-c.handshakeDone:
				default:
					close(c.handshakeDone)
				}
				break
			}
			if time.Now().After(deadline) {
				udpConn.Close()
				return nil, fmt.Errorf("sdk: TLS handshake timed out")
			}
			time.Sleep(10 * time.Millisecond)
		}
	}

	return c, nil
}

// sendInitial builds and sends an Initial packet.
func (c *Conn) sendInitial(srcCID, destCID []byte) error {
	if c.config.TLSMode {
		// TLS mode: the driveHandshakeLoop will start TLS and send
		// the ClientHello as CRYPTO data via PacketIO. We just need
		// to send a minimal Initial PING to elicit a server response.
		// The actual CRYPTO data (ClientHello) will be sent by
		// FlushPendingControlFrames after DriveHandshake produces it.
		pingFrame := []byte{0x01} // PING
		pn := c.conn.NextPacketNumber(connection.PNSpaceInitial)
		_, err := c.packetIO.SendPacket(crypto.EncryptionInitial, nil)
		// Send PING via the protected path
		if err != nil {
			// Fallback: send unprotected if SendPacket fails
			hdr := &header.LongHeader{
				Type:            header.PacketTypeInitial,
				Version:         header.Version,
				DestConnID:      destCID,
				SrcConnID:       srcCID,
				Token:           nil,
				PacketNumber:    pn,
				PacketNumberLen: 4,
				Payload:         pingFrame,
			}
			packet, eerr := hdr.Encode()
			if eerr != nil {
				return eerr
			}
			_, err = c.udpConn.Write(packet)
			return err
		}
		return nil
	}

	// Plaintext mode: build a minimal Initial packet with a PING frame
	pingFrame := []byte{0x01} // PING frame type

	pn := c.conn.NextPacketNumber(connection.PNSpaceInitial)

	hdr := &header.LongHeader{
		Type:            header.PacketTypeInitial,
		Version:         header.Version,
		DestConnID:      destCID,
		SrcConnID:       srcCID,
		Token:           nil,
		PacketNumber:    pn,
		PacketNumberLen: 4,
		Payload:         pingFrame,
	}

	packet, err := hdr.Encode()
	if err != nil {
		return err
	}

	_, err = c.udpConn.Write(packet)
	return err
}

// clientRecvLoop reads packets from the UDP connection (client side).
func (c *Conn) clientRecvLoop() {
	buf := make([]byte, 65535)
	for {
		select {
		case <-c.closeCh:
			return
		default:
		}

		n, raddr, err := c.udpConn.ReadFromUDP(buf)
		if err != nil {
			select {
			case <-c.closeCh:
				return
			default:
			}
			continue
		}

		data := make([]byte, n)
		copy(data, buf[:n])

		c.remoteAddr = raddr
		isLong := len(data) > 0 && data[0]&0x80 != 0
		c.handleIncoming(data, raddr, isLong)
	}
}

// === Connection Methods ===

// sendLoop processes the send queue and writes packets to the network.
func (c *Conn) sendLoop() {
	for {
		select {
		case <-c.closeCh:
			return
		case data := <-c.sendQueue:
			if c.remoteAddr == nil {
				continue
			}
			if c.isServer {
				c.udpConn.WriteToUDP(data, c.remoteAddr)
			} else {
				c.udpConn.Write(data)
			}
		}
	}
}

// handleIncoming processes a received packet.
func (c *Conn) handleIncoming(data []byte, raddr *net.UDPAddr, isLongHeader bool) {
	c.conn.TouchActivity()

	// In TLS mode, route through PacketIO for decryption
	if c.config.TLSMode && c.packetIO != nil {
		// For long headers: extract SCID before decryption to update DCID
		if isLongHeader && !c.isServer {
			// Use partial decode — the full DecodeLongHeader would fail
			// on protected packets because reserved bits are masked.
			hdr, _, err := header.DecodeLongHeaderPartial(data)
			if err == nil && len(hdr.SrcConnID) > 0 {
				c.connMgr.InitDestConnID(hdr.SrcConnID)
				c.packetIO.SetConnIDs(c.connMgr.SrcConnID(), c.connMgr.DestConnID())
			}
		}
		// RecvDatagram handles: split, unprotect, decode, dispatch frames,
		// record for ACK, update recovery, touch activity.
		// It also flushes CRYPTO data between coalesced packets.
		if err := c.packetIO.RecvDatagram(data); err != nil {
			log.Printf("quic: packet receive error: %v", err)
		}
		// After the handshake is complete, driveHandshakeLoop has exited
		// and there is no risk of deadlock with the TLS session mutex.
		// Flush ACK and flow control frames in response to received data.
		session := c.keyStore.TLSSession()
		if session != nil && session.HandshakeComplete() {
			c.packetIO.FlushPendingControlFrames()
		}
		// Deliver any received stream data to SDK-level Stream wrappers
		c.deliverReceivedStreamData()
		return
	}

	if isLongHeader {
		hdr, _, err := header.DecodeLongHeader(data)
		if err != nil {
			return
		}

		// On client side: update our DCID to the server's SCID
		if !c.isServer && len(hdr.SrcConnID) > 0 {
			c.connMgr.InitDestConnID(hdr.SrcConnID)
			if c.packetIO != nil {
				c.packetIO.SetConnIDs(c.connMgr.SrcConnID(), c.connMgr.DestConnID())
			}
		}

		// Process payload frames via FrameHandler
		var pnSpace connection.PNSpace
		switch hdr.Type {
		case header.PacketTypeInitial:
			pnSpace = connection.PNSpaceInitial
		case header.PacketTypeHandshake:
			pnSpace = connection.PNSpaceHandshake
		default:
			pnSpace = connection.PNSpaceApplication
		}

		if len(hdr.Payload) > 0 {
			_, ferr := c.frameHandler.ProcessFrames(hdr.Payload, pnSpace, hdr.PacketNumber)
			if ferr != nil {
				log.Printf("quic: frame processing error (long header, pn=%d): %v", hdr.PacketNumber, ferr)
			}
			c.ackHandler.OnPacketReceived(hdr.PacketNumber, pnSpace, true)
		}

		// If we got a Handshake or HANDSHAKE_DONE, transition to established
		if hdr.Type == header.PacketTypeHandshake {
			c.conn.SetState(connection.StateEstablished)
		}

		// Flush pending ACKs
		c.flushPendingControlFrames()
	} else {
		// Short header (1-RTT data packet)
		dcidLen := len(c.connMgr.SrcConnID())
		if dcidLen == 0 {
			dcidLen = c.config.ConnIDLength
		}
		hdr, _, err := header.DecodeShortHeader(data, dcidLen)
		if err != nil {
			return
		}
		if len(hdr.Payload) > 0 {
			_, ferr := c.frameHandler.ProcessFrames(hdr.Payload, connection.PNSpaceApplication, hdr.PacketNumber)
			if ferr != nil {
				log.Printf("quic: frame processing error (short header, pn=%d): %v", hdr.PacketNumber, ferr)
			}
			c.ackHandler.OnPacketReceived(hdr.PacketNumber, connection.PNSpaceApplication, true)
		}

		// Flush pending ACKs
		c.flushPendingControlFrames()
	}

	// Deliver any received stream data to SDK-level Stream wrappers
	c.deliverReceivedStreamData()
}

// deliverReceivedStreamData pulls data from stream.Manager streams into
// the SDK-level Stream wrappers' read channels.
// This is called after packet processing to bridge the connection-layer
// stream.Manager data into the SDK's channel-based Stream API.
func (c *Conn) deliverReceivedStreamData() {
	if c.streamMgr == nil {
		return
	}

	c.streamsMu.Lock()
	defer c.streamsMu.Unlock()

	// Fully-done streams (read EOF delivered AND write side closed) are
	// collected and removed from c.streams / the stream.Manager below.
	// Without this, every closed stream stays in c.streams forever; this
	// loop runs on every received packet and ranges over c.streams, so the
	// per-packet cost grows with the total number of streams ever opened
	// on the connection — O(N^2) over the connection's lifetime, observed
	// as per-request latency rising linearly with the request count.
	var dead []uint64

	for id, sdkStream := range c.streams {
		// Get the underlying stream from the manager
		mgrStream, ok := c.streamMgr.Get(id)
		if !ok {
			// Manager already dropped it — drop our wrapper too.
			dead = append(dead, id)
			continue
		}

		// Read any available data from the manager's stream — but only if
		// readCh has room. deliverReceivedStreamData runs on the recvLoop
		// (holding streamsMu) for EVERY packet; a blocking readCh send here
		// would stall the entire receive path, and since the peer's ACKs
		// can't be processed either, the sender deadlocks too. This was the
		// bulk-transfer flaky stall (both sides idle/blocked). So we probe
		// readCh capacity first: if full, skip this stream for this packet
		// (the data stays buffered in the manager stream and is re-read on
		// the next packet's delivery pass).
		buf := make([]byte, 65536)
		n, err := mgrStream.Read(buf)
		if n > 0 {
			data := make([]byte, n)
			copy(data, buf[:n])
			select {
			case sdkStream.readCh <- data:
			case <-sdkStream.closeCh:
				continue
			default:
				// readCh full — app is slow to drain. Put the bytes back
				// into the manager stream's recv buffer so they're not lost
				// and get re-delivered on the next packet.
				mgrStream.PushBack(buf[:n])
				continue
			}
		}
		// If EOF, signal it — but only once. mgrStream.Read keeps
		// returning EOF for finished streams, and re-queuing a nil
		// on every packet would eventually fill readCh and block
		// this loop (which holds streamsMu), stalling delivery on
		// all streams.
		if err != nil && n == 0 && !sdkStream.eofSent {
			sdkStream.eofSent = true
			select {
			case sdkStream.readCh <- nil: // nil = EOF signal
			case <-sdkStream.closeCh:
			default:
				// readCh full — retry the EOF signal on the next packet.
				sdkStream.eofSent = false
			}
		}
		// A stream whose read side hit EOF and whose write side was
		// closed by the app is fully retired. The final EOF (nil) is
		// already queued on readCh, so the app's last Read still
		// completes; removing the wrapper only stops this per-packet
		// loop from polling it. Also retire it from the manager so
		// AllStreams()/PendingWindowUpdates stop ranging over it.
		if sdkStream.eofSent && sdkStream.writeClosed {
			dead = append(dead, id)
		}
	}

	for _, id := range dead {
		delete(c.streams, id)
		c.streamMgr.CloseStream(id)
	}

	// Also check for new peer-initiated streams that need to be
	// delivered to AcceptStream
	for _, mgrStream := range c.streamMgr.AllStreams() {
		id := mgrStream.ID
		if _, exists := c.streams[id]; !exists {
			// New peer-initiated stream — create SDK wrapper
			sdkStream := c.createPeerStreamLocked(id)
			if sdkStream != nil {
			// Read initial data. Non-blocking send (same reason as the main
			// loop above: this runs on recvLoop holding streamsMu; a blocking
			// send stalls the whole receive path).
			buf := make([]byte, 65536)
			n, _ := mgrStream.Read(buf)
			if n > 0 {
				data := make([]byte, n)
				copy(data, buf[:n])
				select {
				case sdkStream.readCh <- data:
				case <-sdkStream.closeCh:
				default:
					// readCh full — put data back; re-delivered next packet.
					mgrStream.PushBack(buf[:n])
				}
			}
				// Notify AcceptStream for bidirectional streams
				if sdkStream.bidi {
					select {
					case c.acceptStreamCh <- sdkStream:
					default:
					}
				} else {
					// For unidirectional streams, also notify AcceptStream
					select {
					case c.acceptStreamCh <- sdkStream:
					default:
					}
				}
			}
		}
	}
}

// createPeerStreamLocked creates an SDK Stream wrapper for a peer-initiated stream.
// Caller must hold c.streamsMu.
func (c *Conn) createPeerStreamLocked(id uint64) *Stream {
	if c.streams == nil {
		c.streams = make(map[uint64]*Stream)
	}
	if s, ok := c.streams[id]; ok {
		return s
	}

	bidi := (id & 0x02) == 0
	s := &Stream{
		id:      id,
		bidi:    bidi,
		conn:    c,
		readCh:  make(chan []byte, 64),
		closeCh: make(chan struct{}),
	}
	c.streams[id] = s
	return s
}

// flushPendingControlFrames sends pending ACK and flow control frames.
func (c *Conn) flushPendingControlFrames() {
	if c.packetIO == nil {
		return
	}
	c.packetIO.FlushPendingControlFrames()
}

// processFrames decodes and dispatches frames in a packet payload.
func (c *Conn) processFrames(payload []byte, space connection.PNSpace) {
	offset := 0
	for offset < len(payload) {
		// Read frame type
		ft, n, err := varint.Decode(payload[offset:])
		if err != nil {
			break
		}
		offset += n

		switch {
		case ft == 0x00: // PADDING
			// Just skip
			continue

		case ft == 0x01: // PING
			// Nothing to do, just an ack-eliciting frame
			continue

		case ft == 0x08 || (ft >= 0x08 && ft <= 0x0f): // STREAM
			// Parse STREAM frame
			s, consumed, err := parseStreamFrame(payload[offset-1:])
			if err != nil {
				break
			}
			offset += consumed - 1 // -1 because we already consumed the frame type

			// Deliver data to the stream
			c.deliverStreamData(s)

		case ft == 0x1e: // HANDSHAKE_DONE
			c.conn.SetState(connection.StateEstablished)

		case ft == 0x1c || ft == 0x1d: // CONNECTION_CLOSE
			// Peer is closing the connection
			c.conn.SetState(connection.StateDraining)
			select {
			case <-c.closeCh:
			default:
				close(c.closeCh)
			}

		default:
			// For unhandled frame types, try to skip
			// In a real implementation we'd parse each frame properly
			break
		}
	}
}

// parsedStreamData holds parsed STREAM frame data.
type parsedStreamData struct {
	StreamID uint64
	Offset   uint64
	Data     []byte
	FIN     bool
}

// parseStreamFrame parses a STREAM frame from the given data (including frame type byte).
// Returns the parsed data and the number of bytes consumed (including the type byte).
func parseStreamFrame(data []byte) (*parsedStreamData, int, error) {
	if len(data) < 1 {
		return nil, 0, fmt.Errorf("empty data")
	}

	// Frame type byte: 0b00001_FSO (F=FIN, S=offset, O=Len)
	ftByte := data[0]
	offset := 1

	hasFIN := ftByte&0x01 != 0
	hasOffset := ftByte&0x02 != 0
	hasLen := ftByte&0x04 != 0

	// Stream ID (varint)
	streamID, n, err := varint.Decode(data[offset:])
	if err != nil {
		return nil, 0, fmt.Errorf("stream ID: %w", err)
	}
	offset += n

	// Offset (varint, if present)
	var streamOffset uint64
	if hasOffset {
		streamOffset, n, err = varint.Decode(data[offset:])
		if err != nil {
			return nil, 0, fmt.Errorf("offset: %w", err)
		}
		offset += n
	}

	// Length (varint, if present)
	var dataLen uint64
	if hasLen {
		dataLen, n, err = varint.Decode(data[offset:])
		if err != nil {
			return nil, 0, fmt.Errorf("length: %w", err)
		}
		offset += n
	}

	// Data
	var streamData []byte
	if hasLen {
		if offset+int(dataLen) > len(data) {
			return nil, 0, fmt.Errorf("stream data too short")
		}
		streamData = make([]byte, dataLen)
		copy(streamData, data[offset:offset+int(dataLen)])
		offset += int(dataLen)
	} else {
		// No length: rest of the packet is data
		streamData = make([]byte, len(data)-offset)
		copy(streamData, data[offset:])
		offset = len(data)
	}

	return &parsedStreamData{
		StreamID: streamID,
		Offset:   streamOffset,
		Data:     streamData,
		FIN:      hasFIN,
	}, offset, nil
}

// deliverStreamData delivers received stream data to the appropriate stream.
func (c *Conn) deliverStreamData(s *parsedStreamData) {
	// Get or create the stream
	streamObj, exists := c.getStream(s.StreamID)
	if !exists {
		// Peer-initiated stream — create it
		streamObj = c.createPeerStream(s.StreamID)
		if streamObj == nil {
			return
		}
		// Notify AcceptStream for bidirectional streams
		if streamObj.bidi {
			select {
			case c.acceptStreamCh <- streamObj:
			default:
			}
		}
	}

	// Deliver data to the stream's read channel
	if len(s.Data) > 0 {
		select {
		case streamObj.readCh <- s.Data:
		case <-streamObj.closeCh:
		}
	}

	// Handle FIN (also latch: retransmitted FIN frames must not queue
	// a second EOF signal).
	if s.FIN && !streamObj.eofSent {
		streamObj.eofSent = true
		select {
		case streamObj.readCh <- nil: // nil = EOF signal
		case <-streamObj.closeCh:
		}
	}
}

// getStream retrieves a stream by ID.
func (c *Conn) getStream(id uint64) (*Stream, bool) {
	c.streamsMu.Lock()
	defer c.streamsMu.Unlock()

	if c.streams == nil {
		return nil, false
	}
	s, ok := c.streams[id]
	return s, ok
}

// createPeerStream creates a stream for a peer-initiated stream ID.
func (c *Conn) createPeerStream(id uint64) *Stream {
	c.streamsMu.Lock()
	defer c.streamsMu.Unlock()

	if c.streams == nil {
		c.streams = make(map[uint64]*Stream)
	}
	if s, ok := c.streams[id]; ok {
		return s
	}

	bidi := (id & 0x02) == 0
	s := &Stream{
		id:      id,
		bidi:    bidi,
		conn:    c,
		readCh:  make(chan []byte, 64),
		closeCh: make(chan struct{}),
	}
	c.streams[id] = s
	return s
}

// === Public Conn Methods ===

// OpenStream opens a new bidirectional stream.
func (c *Conn) OpenStream() (*Stream, error) {
	return c.openStream(true)
}

// OpenUniStream opens a new unidirectional stream (send-only).
func (c *Conn) OpenUniStream() (*Stream, error) {
	return c.openStream(false)
}

// openStream opens a new stream with the given direction.
func (c *Conn) openStream(bidi bool) (*Stream, error) {
	c.streamsMu.Lock()
	defer c.streamsMu.Unlock()

	if c.streams == nil {
		c.streams = make(map[uint64]*Stream)
	}

	// Allocate stream ID
	var id uint64
	if bidi {
		if c.isServer {
			id = c.nextServerBidi
			c.nextServerBidi += 4
		} else {
			id = c.nextClientBidi
			c.nextClientBidi += 4
		}
	} else {
		if c.isServer {
			id = c.nextServerUni
			c.nextServerUni += 4
		} else {
			id = c.nextClientUni
			c.nextClientUni += 4
		}
	}

	s := &Stream{
		id:      id,
		bidi:    bidi,
		conn:    c,
		readCh:  make(chan []byte, 64),
		closeCh: make(chan struct{}),
	}
	c.streams[id] = s

	// Also create the stream in the stream.Manager so that
	// received data for this stream can be properly tracked
	if c.streamMgr != nil {
		// Use Open to create a locally-initiated stream in the manager.
		// This must use the same ID allocation, so we create it directly
		// using New() and register it in the manager's map.
		initialMaxData := c.config.MaxStreamData
		s2 := stream.New(id, initialMaxData, c.config.MaxConnectionData)
		// Register in the manager's internal map
		// We access the manager's streams map via a helper
		c.streamMgr.RegisterLocalStream(id, s2)
	}

	return s, nil
}

// AcceptStream waits for and returns the next incoming stream.
func (c *Conn) AcceptStream() (*Stream, error) {
	select {
	case s := <-c.acceptStreamCh:
		return s, nil
	case <-c.closeCh:
		return nil, fmt.Errorf("connection closed")
	}
}

// Close closes the connection.
func (c *Conn) Close() error {
	select {
	case <-c.closeCh:
		return nil // already closed
	default:
	}
	close(c.closeCh)

	// Close all streams
	c.streamsMu.Lock()
	for _, s := range c.streams {
		s.closeLocal()
	}
	c.streamsMu.Unlock()

	// Send CONNECTION_CLOSE frame
	closeFrame := buildConnectionCloseFrame(0, "connection closed")
	pn := c.conn.NextPacketNumber(connection.PNSpaceApplication)

	hdr := &header.ShortHeader{
		DestConnID:      c.connMgr.DestConnID(),
		PacketNumber:    pn,
		PacketNumberLen: 4,
		Payload:         closeFrame,
	}

	packet, err := hdr.Encode()
	if err == nil {
		c.udpConn.WriteToUDP(packet, c.remoteAddr)
	}

	c.conn.SetState(connection.StateClosed)

	if c.listener == nil {
		c.udpConn.Close()
	}

	return nil
}

// IsClosed returns whether the connection is closed.
func (c *Conn) IsClosed() bool {
	select {
	case <-c.closeCh:
		return true
	default:
		return false
	}
}

// RemoteAddr returns the remote address.
func (c *Conn) RemoteAddr() net.Addr {
	if c.remoteAddr != nil {
		return c.remoteAddr
	}
	return nil
}

// LocalAddr returns the local address.
func (c *Conn) LocalAddr() net.Addr {
	return c.udpConn.LocalAddr()
}

// === Stream Methods ===

// Write writes data to the stream, sending it in STREAM frames.
// maxStreamPayloadPerPacket caps how much stream data is carried in a single
// QUIC packet. QUIC packets must fit in one UDP datagram and stay under the
// path MTU to avoid IP fragmentation; without this cap, Stream.Write would
// wrap an arbitrarily large buffer in a single STREAM frame / single packet,
// producing an oversized UDP datagram that the kernel drops on send (EMSGSIZE)
// or on receive — observed as bulk transfers silently making no progress.
//
// 1100 is a conservative safe QUIC initial PMTU (fits within a 1280-byte IPv6
// minimum MTU with headroom for the short header, STREAM frame header, and
// AEAD tag). A production deployment should negotiate PMTU (DPLPMTUD) and may
// raise this toward the discovered path MTU.
const maxStreamPayloadPerPacket = 1100

// mustVarint encodes v as a varint, panicking only if v exceeds the 62-bit
// varint range — which cannot happen for stream IDs / offsets / lengths in
// any realistic use. It keeps STREAM-frame construction terse.
func mustVarint(v uint64) []byte {
	b, err := varint.Encode(v)
	if err != nil {
		panic(fmt.Sprintf("sdk: varint encode %d: %v", v, err))
	}
	return b
}

func (s *Stream) Write(data []byte) (int, error) {
	if s.writeClosed {
		return 0, fmt.Errorf("stream closed for writing")
	}

	if len(data) == 0 {
		return 0, nil
	}

	// In TLS mode, application data must wait for handshake completion.
	if s.conn.config.TLSMode && s.conn.packetIO != nil {
		select {
		case <-s.conn.handshakeDone:
		case <-s.conn.closeCh:
			return 0, fmt.Errorf("sdk: connection closed")
		}
	}

	// Chunk the payload so each STREAM frame fits in one (sub-MTU) packet.
	// s.sendOneStreamFrame advances s.writeOffset by the bytes it actually
	// sends and returns the count, so we loop until all of `data` is sent.
	total := 0
	for total < len(data) {
		end := total + maxStreamPayloadPerPacket
		if end > len(data) {
			end = len(data)
		}
		n, err := s.sendOneStreamFrame(data[total:end])
		if err != nil {
			return total, err
		}
		if n == 0 {
			// Should not happen for a non-empty chunk, but guard against a
			// busy-loop if it ever does.
			return total, fmt.Errorf("sdk: stream write stalled at %d/%d", total, len(data))
		}
		total += n
	}
	return total, nil
}

// sendOneStreamFrame emits a single STREAM frame carrying `data` (which must be
// <= maxStreamPayloadPerPacket) at the current s.writeOffset, advances the
// offset, and returns the number of stream bytes sent. TLS mode routes
// through PacketIO.SendPacket (for AEAD protection); plaintext mode builds a
// short-header packet and queues it on the connection's send loop.
func (s *Stream) sendOneStreamFrame(data []byte) (int, error) {
	if len(data) == 0 {
		return 0, nil
	}

	// TLS mode: STREAM frame via the encrypted packet pipeline.
	if s.conn.config.TLSMode && s.conn.packetIO != nil {
		frame := &frames.Stream{
			StreamID: s.id,
			Offset:   s.writeOffset,
			Data:     data,
			Fin:      false,
		}
		if _, err := s.conn.packetIO.SendPacket(crypto.EncryptionApplication,
			[]frames.Frame{frame}); err != nil {
			return 0, err
		}
		s.writeOffset += uint64(len(data))
		return len(data), nil
	}

	// Plaintext mode: STREAM frame (OFF+LEN, no FIN) wrapped in a short header.
	frameType := byte(0x08 | 0x04 | 0x02)
	buf := []byte{frameType}
	buf = append(buf, mustVarint(s.id)...)
	buf = append(buf, mustVarint(s.writeOffset)...)
	buf = append(buf, mustVarint(uint64(len(data)))...)
	buf = append(buf, data...)

	pn := s.conn.conn.NextPacketNumber(connection.PNSpaceApplication)
	hdr := &header.ShortHeader{
		DestConnID:      s.conn.connMgr.DestConnID(),
		PacketNumber:    pn,
		PacketNumberLen: 4,
		Payload:         buf,
	}
	packet, err := hdr.Encode()
	if err != nil {
		return 0, err
	}
	s.conn.sendQueue <- packet
	s.writeOffset += uint64(len(data))
	return len(data), nil
}

// Close closes the stream (sends FIN).
func (s *Stream) Close() error {
	if s.writeClosed {
		return nil
	}
	s.writeClosed = true

	// In TLS mode, send STREAM+FIN via PacketIO for encryption
	if s.conn.config.TLSMode && s.conn.packetIO != nil {
		select {
		case <-s.conn.handshakeDone:
		case <-s.conn.closeCh:
			return fmt.Errorf("sdk: connection closed")
		}

		frame := &frames.Stream{
			StreamID: s.id,
			Offset:   s.writeOffset,
			Data:     nil,
			Fin:      true,
		}
		_, err := s.conn.packetIO.SendPacket(crypto.EncryptionApplication,
			[]frames.Frame{frame})
		return err
	}

	// Plaintext mode: build STREAM frame with FIN manually
	frameType := byte(0x08 | 0x04 | 0x02 | 0x01) // STREAM with FIN, OFF, LEN

	buf := []byte{frameType}
	sidBytes, _ := varint.Encode(s.id)
	buf = append(buf, sidBytes...)

	offBytes, _ := varint.Encode(s.writeOffset)
	buf = append(buf, offBytes...)

	lenBytes, _ := varint.Encode(0) // zero-length data
	buf = append(buf, lenBytes...)

	pn := s.conn.conn.NextPacketNumber(connection.PNSpaceApplication)

	hdr := &header.ShortHeader{
		DestConnID:      s.conn.connMgr.DestConnID(),
		PacketNumber:    pn,
		PacketNumberLen: 4,
		Payload:         buf,
	}

	packet, err := hdr.Encode()
	if err != nil {
		return err
	}

	s.conn.sendQueue <- packet
	return nil
}

// closeLocal closes the stream without sending anything (used during conn shutdown).
func (s *Stream) closeLocal() {
	if !s.closed {
		s.closed = true
		close(s.closeCh)
	}
}
// Read reads data from the stream. Returns io.EOF when the stream is finished.
func (s *Stream) Read(p []byte) (int, error) {
	// If we have buffered data, return it
	if len(s.readBuf) > 0 {
		n := copy(p, s.readBuf)
		s.readBuf = s.readBuf[n:]
		return n, nil
	}

	select {
	case data, ok := <-s.readCh:
		if !ok || data == nil {
			// EOF
			return 0, io.EOF
		}
		n := copy(p, data)
		if n < len(data) {
			// Save remaining
			s.readBuf = data[n:]
		}
		return n, nil
	case <-s.closeCh:
		return 0, io.EOF
	}
}

// ID returns the stream ID.
func (s *Stream) ID() uint64 {
	return s.id
}

// IsBidirectional returns whether the stream is bidirectional.
func (s *Stream) IsBidirectional() bool {
	return s.bidi
}

// === Helpers ===

// buildConnectionCloseFrame builds a CONNECTION_CLOSE frame.
func buildConnectionCloseFrame(errorCode uint64, reason string) []byte {
	// Frame type: 0x1c (transport error)
	buf := []byte{0x1c}

	// Error code (varint)
	ecBytes, _ := varint.Encode(errorCode)
	buf = append(buf, ecBytes...)

	// Frame type that triggered the error (varint) — 0 for no specific frame
	buf = append(buf, 0x00)

	// Reason phrase length (varint) + reason
	rpBytes, _ := varint.Encode(uint64(len(reason)))
	buf = append(buf, rpBytes...)
	buf = append(buf, []byte(reason)...)

	return buf
}

// matchBytes compares two byte slices.
func matchBytes(a, b []byte) bool {
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
