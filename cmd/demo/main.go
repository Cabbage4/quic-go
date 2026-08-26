// Package main is a demo application that showcases the QUIC implementation.
// It demonstrates varint encoding, packet construction, frame encoding,
// transport parameter negotiation, stream management, and a UDP echo server/client.
package main

import (
	"bytes"
	"crypto/rand"
	"encoding/hex"
	"fmt"
	"log"
	"net"
	"os"
	"time"

	"github.com/Cabbage4/quic-go/connection"
	"github.com/Cabbage4/quic-go/errors"
	"github.com/Cabbage4/quic-go/frames"
	"github.com/Cabbage4/quic-go/header"
	"github.com/Cabbage4/quic-go/packet"
	"github.com/Cabbage4/quic-go/stream"
	"github.com/Cabbage4/quic-go/transport"
	"github.com/Cabbage4/quic-go/varint"
)

func main() {
	fmt.Println("============================================")
	fmt.Println("    QUIC Protocol (RFC 9000) - Go Demo")
	fmt.Println("============================================")

	// 1. Variable-Length Integer Encoding (Section 16)
	demoVarint()

	// 2. Packet Number Encoding/Decoding (Section 17.1)
	demoPacketNumber()

	// 3. Frame Types (Section 19)
	demoFrames()

	// 4. Packet Headers (Section 17)
	demoPacketHeaders()

	// 5. Transport Parameters (Section 18)
	demoTransportParams()

	// 6. Connection ID Management (Section 5.1)
	demoConnectionID()

	// 7. Stream Management (Sections 2-4)
	demoStreams()

	// 8. Error Codes (Section 20)
	demoErrorCodes()

	// 9. UDP Demo: QUIC Packet Round-Trip
	fmt.Println("\n--- 9. UDP Demo: QUIC Packet Round-Trip ---")
	runUDPDemo()

	fmt.Println("\n============================================")
	fmt.Println("    Demo Complete! All systems working.")
	fmt.Println("============================================")
}

func demoVarint() {
	fmt.Println("\n--- 1. Variable-Length Integer Encoding (RFC 9000 §16) ---")
	fmt.Println()

	tests := []uint64{37, 15293, 494878333, 151288809941952652}
	expects := []string{"0x25", "0x7bbd", "0x9d7f3e7d", "0xc2197c5eff14e88c"}

	for i, v := range tests {
		encoded, err := varint.Encode(v)
		if err != nil {
			log.Fatalf("Encode(%d): %v", v, err)
		}
		decoded, n, err := varint.Decode(encoded)
		if err != nil {
			log.Fatalf("Decode: %v", err)
		}
		fmt.Printf("  Value: %-25d  Encoded: %-28s  Decoded: %-25d  Bytes: %d  Match: %v\n",
			v, hex.EncodeToString(encoded), decoded, n, expects[i] == hex.EncodeToString(encoded))
	}
}

func demoPacketNumber() {
	fmt.Println("\n--- 2. Packet Number Encoding/Decoding (RFC 9000 §17.1) ---")
	fmt.Println()

	// RFC 9000 Appendix A.2 example:
	// acked = 0xabe8b3, sending 0xac5c02 -> 16-bit encoding (2 bytes)
	acked := uint64(0xabe8b3)
	fullPN := uint64(0xac5c02)
	trunc, n := packet.EncodePacketNumber(fullPN, &acked)
	fmt.Printf("  Encoding: full_pn=0x%x, largest_acked=0x%x\n", fullPN, acked)
	fmt.Printf("  Result:   truncated=0x%x, num_bytes=%d\n", trunc, n)

	// RFC 9000 Appendix A.3 example:
	// largest = 0xa82f30ea, 16-bit value = 0x9b32 -> 0xa82f9b32
	largest := uint64(0xa82f30ea)
	truncated := uint64(0x9b32)
	decoded := packet.DecodePacketNumber(largest, truncated, 16)
	fmt.Printf("\n  Decoding: largest_pn=0x%x, truncated_pn=0x%x, pn_bits=16\n", largest, truncated)
	fmt.Printf("  Result:   full_pn=0x%x (expected 0xa82f9b32)\n", decoded)
}

func demoFrames() {
	fmt.Println("\n--- 3. Frame Types (RFC 9000 §19) ---")
	fmt.Println()

	framesList := []frames.Frame{
		&frames.Ping{},
		&frames.Padding{Length: 4},
		&frames.ACK{LargestAcked: 100, ACKDelay: 5, FirstACKRange: 10},
		&frames.ACK{LargestAcked: 200, ACKDelay: 3, FirstACKRange: 5,
			ACKRanges: []frames.ACKRange{{Gap: 2, ACKRangeLen: 8}}, HasECN: true, ECT0Count: 5},
		&frames.Crypto{Offset: 0, Data: []byte("TLS handshake data")},
		&frames.Stream{StreamID: 0, Offset: 0, Data: []byte("Hello QUIC!"), Fin: true},
		&frames.NewConnectionID{SequenceNumber: 1, RetirePriorTo: 0,
			ConnectionID: []byte{0x01, 0x02, 0x03, 0x04},
			StatelessResetToken: [16]byte{0, 1, 2, 3, 4, 5, 6, 7, 8, 9, 10, 11, 12, 13, 14, 15}},
		&frames.MaxData{MaximumData: 1048576},
		&frames.ConnectionClose{ErrorCode: 0x0a, TriggerFrameType: 0x06, ReasonPhrase: "protocol violation"},
		&frames.HandshakeDone{},
		&frames.PathChallenge{Data: [8]byte{0xDE, 0xAD, 0xBE, 0xEF, 0x01, 0x02, 0x03, 0x04}},
		&frames.PathResponse{Data: [8]byte{0xDE, 0xAD, 0xBE, 0xEF, 0x01, 0x02, 0x03, 0x04}},
	}

	for _, f := range framesList {
		encoded, err := f.Encode()
		if err != nil {
			fmt.Printf("  ERROR encoding %v: %v\n", f, err)
			continue
		}
		decoded, n, err := frames.Decode(encoded)
		if err != nil {
			fmt.Printf("  ERROR decoding: %v\n", err)
			continue
		}
		_ = n
		fmt.Printf("  %-45s -> %-30s -> %-45s\n",
			f.String(), hex.EncodeToString(encoded), decoded)
	}

	// Multi-frame packet
	fmt.Println("\n  Multiple frames in one packet:")
	ping, _ := (&frames.Ping{}).Encode()
	hd, _ := (&frames.HandshakeDone{}).Encode()
	streamFrame, _ := (&frames.Stream{StreamID: 0, Data: []byte("data"), Fin: true}).Encode()
	packet := append(append(ping, streamFrame...), hd...)
	fmt.Printf("  PING + STREAM(fin) + HANDSHAKE_DONE = %s (%d bytes)\n",
		hex.EncodeToString(packet), len(packet))
}

func demoPacketHeaders() {
	fmt.Println("\n--- 4. Packet Headers (RFC 9000 §17) ---")
	fmt.Println()

	// Long Header: Initial Packet
	dcid, _ := connection.GenerateConnID(8)
	scid, _ := connection.GenerateConnID(8)
	lh := &header.LongHeader{
		Type:            header.PacketTypeInitial,
		Version:         header.Version,
		DestConnID:      dcid,
		SrcConnID:       scid,
		PacketNumber:    1,
		PacketNumberLen: 1,
		Payload:         []byte{0xAA, 0xBB, 0xCC},
	}
	encoded, err := lh.Encode()
	if err != nil {
		log.Fatalf("LongHeader encode: %v", err)
	}
	fmt.Printf("  Initial Packet (Long Header):\n")
	fmt.Printf("    DCID: %s  SCID: %s\n", hex.EncodeToString(dcid), hex.EncodeToString(scid))
	fmt.Printf("    Raw:  %s\n", hex.EncodeToString(encoded))
	decoded, _, _ := header.DecodeLongHeader(encoded)
	fmt.Printf("    Decoded: type=%d ver=0x%x pn=%d payload_len=%d\n",
		decoded.Type, decoded.Version, decoded.PacketNumber, len(decoded.Payload))

	// Short Header: 1-RTT Packet
	fmt.Println()
	sh := &header.ShortHeader{
		SpinBit:         true,
		DestConnID:      dcid,
		PacketNumber:    42,
		PacketNumberLen: 2,
		Payload:         []byte{0x01, 0x02, 0x03},
	}
	encoded2, _ := sh.Encode()
	fmt.Printf("  1-RTT Packet (Short Header):\n")
	fmt.Printf("    Raw:  %s\n", hex.EncodeToString(encoded2))
	decoded2, _, _ := header.DecodeShortHeader(encoded2, len(dcid))
	fmt.Printf("    Decoded: spin=%v pn=%d payload_len=%d\n",
		decoded2.SpinBit, decoded2.PacketNumber, len(decoded2.Payload))

	// Version Negotiation
	fmt.Println()
	vn := &header.VersionNegotiation{
		DestConnID: dcid,
		SrcConnID:  scid,
		Versions:   []uint32{0x00000001, 0xff000020},
	}
	encoded3, _ := vn.Encode()
	fmt.Printf("  Version Negotiation Packet:\n")
	fmt.Printf("    Raw:  %s\n", hex.EncodeToString(encoded3))
	decoded3, _, _ := header.DecodeVersionNegotiation(encoded3)
	fmt.Printf("    Versions: %v\n", decoded3.Versions)
}

func demoTransportParams() {
	fmt.Println("\n--- 5. Transport Parameters (RFC 9000 §18) ---")
	fmt.Println()

	p := transport.Default()
	p.MaxIdleTimeout = 30000
	p.InitialMaxData = 1048576
	p.InitialMaxStreamDataBidiLocal = 256000
	p.InitialMaxStreamDataBidiRemote = 256000
	p.InitialMaxStreamDataUni = 128000
	p.InitialMaxStreamsBidi = 100
	p.InitialMaxStreamsUni = 50
	p.ActiveConnectionIDLimit = 8
	p.InitialSourceConnID = []byte{0x01, 0x02, 0x03, 0x04}
	p.DisableActiveMigration = false

	encoded, err := p.Encode()
	if err != nil {
		log.Fatalf("Transport params encode: %v", err)
	}
	fmt.Printf("  Encoded params (%d bytes): %s\n", len(encoded), hex.EncodeToString(encoded))

	decoded, err := transport.Decode(encoded)
	if err != nil {
		log.Fatalf("Transport params decode: %v", err)
	}
	fmt.Printf("  Decoded:\n")
	fmt.Printf("    MaxIdleTimeout:              %dms\n", decoded.MaxIdleTimeout)
	fmt.Printf("    InitialMaxData:              %d bytes\n", decoded.InitialMaxData)
	fmt.Printf("    InitialMaxStreamDataBidiLocal: %d\n", decoded.InitialMaxStreamDataBidiLocal)
	fmt.Printf("    InitialMaxStreamDataBidiRemote: %d\n", decoded.InitialMaxStreamDataBidiRemote)
	fmt.Printf("    InitialMaxStreamDataUni:     %d\n", decoded.InitialMaxStreamDataUni)
	fmt.Printf("    InitialMaxStreamsBidi:       %d\n", decoded.InitialMaxStreamsBidi)
	fmt.Printf("    InitialMaxStreamsUni:        %d\n", decoded.InitialMaxStreamsUni)
	fmt.Printf("    ActiveConnectionIDLimit:     %d\n", decoded.ActiveConnectionIDLimit)
	fmt.Printf("    InitialSourceConnID:         %s\n", hex.EncodeToString(decoded.InitialSourceConnID))
}

func demoConnectionID() {
	fmt.Println("\n--- 6. Connection ID Management (RFC 9000 §5.1) ---")
	fmt.Println()

	mgr := connection.NewConnIDManager()
	secret := []byte("server-secret-key")

	// Generate initial connection IDs
	destCID, _ := connection.GenerateConnID(8)
	srcCID, _ := connection.GenerateConnID(8)
	mgr.InitDestConnID(destCID)
	mgr.InitSrcConnID(srcCID)
	fmt.Printf("  Initial Dest CID:  %s\n", hex.EncodeToString(destCID))
	fmt.Printf("  Initial Src CID:    %s\n", hex.EncodeToString(srcCID))

	// Issue new connection IDs (as server)
	fmt.Println("\n  Issued Connection IDs:")
	for i := 0; i < 3; i++ {
		entry, err := mgr.IssueNewConnID(secret)
		if err != nil {
			log.Fatalf("IssueNewConnID: %v", err)
		}
		fmt.Printf("    SeqNum=%d  CID=%s  ResetToken=%s\n",
			entry.SequenceNumber,
			hex.EncodeToString(entry.ConnectionID),
			hex.EncodeToString(entry.StatelessResetToken[:]))
	}

	// Retire one
	mgr.RetireConnID(1)
	fmt.Printf("\n  After retiring seq 1: %s\n", mgr)
	fmt.Printf("  Active IDs: %d\n", len(mgr.ActiveConnIDs()))
}

func demoStreams() {
	fmt.Println("\n--- 7. Stream Management (RFC 9000 §2-4) ---")
	fmt.Println()

	// Create a stream manager (client side)
	mgr := stream.NewManager(false,
		1048576, // initialMaxData
		256000, 256000, // bidi local/remote
		128000, // uni
		100,    // maxStreamsBidi
		50,     // maxStreamsUni
	)

	// Client opens bidirectional stream 0
	s1, err := mgr.Open(true)
	if err != nil {
		log.Fatalf("Open bidi: %v", err)
	}
	fmt.Printf("  Opened bidi stream: ID=%d (type=0x%x)\n", s1.ID, s1.StreamType)

	// Client opens unidirectional stream 2
	s2, err := mgr.Open(false)
	if err != nil {
		log.Fatalf("Open uni: %v", err)
	}
	fmt.Printf("  Opened uni stream:  ID=%d (type=0x%x)\n", s2.ID, s2.StreamType)

	// Simulate server-initiated stream 1 received by client
	s3, err := mgr.GetOrCreate(1)
	if err != nil {
		log.Fatalf("GetOrCreate: %v", err)
	}
	fmt.Printf("  Received server stream: ID=%d\n", s3.ID)

	// Write data to stream 0
	data := []byte("Hello, QUIC stream!")
	n, err := s1.Write(data)
	if err != nil {
		log.Fatalf("Write: %v", err)
	}
	fmt.Printf("\n  Wrote %d bytes to stream %d: %q\n", n, s1.ID, data)

	// Close sending side (FIN)
	s1.CloseSending()
	fmt.Printf("  Closed sending side (FIN) on stream %d\n", s1.ID)

	// Receive data with FIN
	s1.ReceiveData(0, []byte("Response from server"), true)
	buf := make([]byte, 256)
	n, _ = s1.Read(buf)
	fmt.Printf("  Read %d bytes from stream %d: %q\n", n, s1.ID, string(buf[:n]))

	// List all streams
	fmt.Printf("\n  All streams:\n")
	for _, s := range mgr.AllStreams() {
		fmt.Printf("    %s\n", s)
	}

	// Flow control demo
	fmt.Println("\n  Flow control test:")
	small := stream.New(4, 10, 1000) // max 10 bytes
	n, _ = small.Write([]byte("0123456789"))
	fmt.Printf("    Wrote %d bytes (max=10)\n", n)
	_, err = small.Write([]byte("X"))
	fmt.Printf("    Write 1 more: %v (flow control blocked)\n", err)
	small.UpdateSendMaxData(20)
	n, _ = small.Write([]byte("X"))
	fmt.Printf("    After MAX_STREAM_DATA: wrote %d more bytes\n", n)
}

func demoErrorCodes() {
	fmt.Println("\n--- 8. Error Codes (RFC 9000 §20) ---")
	fmt.Println()

	codes := []errors.TransportErrorCode{
		errors.NoError,
		errors.InternalError,
		errors.FlowControlError,
		errors.StreamLimitError,
		errors.FrameEncodingError,
		errors.ProtocolViolation,
		errors.InvalidToken,
		errors.CryptoBufferExceeded,
	}
	for _, c := range codes {
		fmt.Printf("  0x%02x: %s\n", uint64(c), c)
	}

	e := errors.New(errors.FlowControlError, "stream data limit exceeded")
	fmt.Printf("\n  Error: %v\n", e)
}

// --- UDP Demo ---

func runUDPDemo() {
	// Start a simple UDP "server" that echoes QUIC-like packets
	addr := "127.0.0.1:4242"
	udpAddr, err := net.ResolveUDPAddr("udp", addr)
	if err != nil {
		log.Fatalf("ResolveUDPAddr: %v", err)
	}

	conn, err := net.ListenUDP("udp", udpAddr)
	if err != nil {
		fmt.Printf("  (UDP server unavailable on %s, skipping live demo)\n", addr)
		udpRoundTripDemo()
		return
	}
	defer conn.Close()

	fmt.Printf("  QUIC UDP server listening on %s\n", addr)

	// Start server goroutine
	go func() {
		buf := make([]byte, 1500)
		for {
			n, raddr, err := conn.ReadFromUDP(buf)
			if err != nil {
				return
			}

			// Parse as long header
			lh, _, err := header.DecodeLongHeader(buf[:n])
			if err != nil {
				continue
			}

			fmt.Printf("  [Server] Received Initial packet:\n")
			fmt.Printf("    DCID=%s  SCID=%s  PN=%d\n",
				hex.EncodeToString(lh.DestConnID),
				hex.EncodeToString(lh.SrcConnID),
				lh.PacketNumber)

			// Parse frames in payload
			offset := 0
			for offset < len(lh.Payload) {
				f, n, err := frames.Decode(lh.Payload[offset:])
				if err != nil {
					break
				}
				offset += n
				if cf, ok := f.(*frames.Crypto); ok {
					fmt.Printf("    CRYPTO frame: offset=%d, data=%q\n", cf.Offset, string(cf.Data))
				}
			}

			// Build response: a Handshake packet with a PING frame
			pingFrame, _ := (&frames.Ping{}).Encode()
			hdFrame, _ := (&frames.HandshakeDone{}).Encode()
			payload := append(pingFrame, hdFrame...)

			respLH := &header.LongHeader{
				Type:            header.PacketTypeHandshake,
				Version:         header.Version,
				DestConnID:      lh.SrcConnID,  // swap
				SrcConnID:       lh.DestConnID,  // swap
				PacketNumber:    1,
				PacketNumberLen: 1,
				Payload:         payload,
			}
			respBytes, _ := respLH.Encode()
			conn.WriteToUDP(respBytes, raddr)
		}
	}()

	// Give server time to start
	time.Sleep(100 * time.Millisecond)

	// Client: send a QUIC-like Initial packet
	clientConn, err := net.DialUDP("udp", nil, udpAddr)
	if err != nil {
		fmt.Printf("  (Client dial failed: %v)\n", err)
		udpRoundTripDemo()
		return
	}
	defer clientConn.Close()

	// Generate connection IDs
	clientDCID, _ := connection.GenerateConnID(8)
	clientSCID, _ := connection.GenerateConnID(8)

	// Create a CRYPTO frame with "ClientHello" data
	cryptoFrame := &frames.Crypto{
		Offset: 0,
		Data:   []byte("ClientHello"),
	}
	cryptoBytes, _ := cryptoFrame.Encode()

	// Build Initial packet
	initial := &header.LongHeader{
		Type:            header.PacketTypeInitial,
		Version:         header.Version,
		DestConnID:      clientDCID,
		SrcConnID:       clientSCID,
		PacketNumber:    0,
		PacketNumberLen: 1,
		Payload:         cryptoBytes,
	}
	initialBytes, _ := initial.Encode()

	fmt.Printf("  [Client] Sending Initial packet (%d bytes):\n", len(initialBytes))
	fmt.Printf("    DCID=%s  SCID=%s  PN=0\n",
		hex.EncodeToString(clientDCID), hex.EncodeToString(clientSCID))
	fmt.Printf("    Payload: CRYPTO frame (\"ClientHello\")\n")

	_, err = clientConn.Write(initialBytes)
	if err != nil {
		fmt.Printf("  (Write failed: %v)\n", err)
		return
	}

	// Wait for response
	clientConn.SetReadDeadline(time.Now().Add(2 * time.Second))
	respBuf := make([]byte, 1500)
	n, err := clientConn.Read(respBuf)
	if err != nil {
		fmt.Printf("  (No response: %v)\n", err)
		return
	}

	// Parse response
	respLH, _, err := header.DecodeLongHeader(respBuf[:n])
	if err != nil {
		fmt.Printf("  (Response parse error: %v)\n", err)
		return
	}
	fmt.Printf("  [Client] Received Handshake response (%d bytes):\n", n)
	fmt.Printf("    DCID=%s  SCID=%s  PN=%d\n",
		hex.EncodeToString(respLH.DestConnID),
		hex.EncodeToString(respLH.SrcConnID),
		respLH.PacketNumber)
	fmt.Printf("    Frames: ")
	offset := 0
	for offset < len(respLH.Payload) {
		f, n, err := frames.Decode(respLH.Payload[offset:])
		if err != nil {
			break
		}
		offset += n
		fmt.Printf("%s ", f)
	}
	fmt.Println()
}

// udpRoundTripDemo shows the packet round-trip without a live UDP socket.
func udpRoundTripDemo() {
	fmt.Println("\n  (Static demo of QUIC packet construction)")

	// Generate connection IDs
	dcid := make([]byte, 8)
	rand.Read(dcid)
	scid := make([]byte, 8)
	rand.Read(scid)

	// Create CRYPTO frame
	cryptoFrame := &frames.Crypto{
		Offset: 0,
		Data:   []byte("ClientHello"),
	}
	cryptoBytes, _ := cryptoFrame.Encode()

	// Build Initial packet
	initial := &header.LongHeader{
		Type:            header.PacketTypeInitial,
		Version:         header.Version,
		DestConnID:      dcid,
		SrcConnID:       scid,
		PacketNumber:    0,
		PacketNumberLen: 1,
		Payload:         cryptoBytes,
	}
	initialBytes, _ := initial.Encode()

	fmt.Printf("  Client Initial Packet (%d bytes): %s\n", len(initialBytes), hex.EncodeToString(initialBytes))

	// Simulate server response
	respPayload := bytes.Buffer{}
	ping, _ := (&frames.Ping{}).Encode()
	hd, _ := (&frames.HandshakeDone{}).Encode()
	respPayload.Write(ping)
	respPayload.Write(hd)

	resp := &header.LongHeader{
		Type:            header.PacketTypeHandshake,
		Version:         header.Version,
		DestConnID:      scid,
		SrcConnID:       dcid,
		PacketNumber:    1,
		PacketNumberLen: 1,
		Payload:         respPayload.Bytes(),
	}
	respBytes, _ := resp.Encode()
	fmt.Printf("  Server Handshake Response (%d bytes): %s\n", len(respBytes), hex.EncodeToString(respBytes))

	// Decode response
	decoded, _, _ := header.DecodeLongHeader(respBytes)
	fmt.Printf("  Decoded response: type=%d, DCID=%s, PN=%d\n",
		decoded.Type, hex.EncodeToString(decoded.DestConnID), decoded.PacketNumber)
	fmt.Printf("  Response frames: ")
	offset := 0
	for offset < len(decoded.Payload) {
		f, n, err := frames.Decode(decoded.Payload[offset:])
		if err != nil {
			break
		}
		offset += n
		fmt.Printf("%s ", f)
	}
	fmt.Println()

	_ = os.Stdout.Sync()
}
