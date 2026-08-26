# QUIC Transport Protocol - Go Implementation (RFC 9000)

A Go implementation of the core QUIC transport protocol components as specified in [RFC 9000](https://www.rfc-editor.org/rfc/rfc9000), including a high-level SDK for building servers and clients.

## Overview

This project implements the fundamental building blocks of the QUIC transport protocol, including:

- **Variable-Length Integer Encoding** (Section 16) — QUIC's custom varint format (6/14/30/62-bit)
- **Packet Number Encoding/Decoding** (Section 17.1) — Truncated packet number encoding with Appendix A pseudocode
- **Frame Types** (Section 19) — All 23 core frame types: PADDING, PING, ACK, RESET_STREAM, STOP_SENDING, CRYPTO, NEW_TOKEN, STREAM, MAX_DATA, MAX_STREAM_DATA, MAX_STREAMS, DATA_BLOCKED, STREAM_DATA_BLOCKED, STREAMS_BLOCKED, NEW_CONNECTION_ID, RETIRE_CONNECTION_ID, PATH_CHALLENGE, PATH_RESPONSE, CONNECTION_CLOSE, HANDSHAKE_DONE
- **Packet Headers** (Section 17) — Long headers (Initial, 0-RTT, Handshake, Retry), short headers (1-RTT), and Version Negotiation
- **Transport Parameters** (Section 18) — Full encoding/decoding of all 17 transport parameters
- **Connection ID Management** (Section 5.1) — CID generation, retirement, and stateless reset tokens
- **Stream Management** (Sections 2-4) — Bidirectional/unidirectional streams, stream state machines, flow control
- **Error Codes** (Section 20) — All transport error codes
- **Connection State Machine** (Sections 5, 10) — Lifecycle, packet routing, idle timeout, close/draining
- **ACK Tracking** (Section 13) — Received packet set tracking, ACK range generation
- **Path Validation & Migration** (Sections 8-9) — PATH_CHALLENGE/RESPONSE, anti-amplification
- **Token Management** (Section 8) — Address validation tokens, Retry integrity tag
- **Packet Coalescing** (Section 12.4) — Multi-packet UDP datagram merging/splitting
- **Version Negotiation** (Section 6) — VN packet generation and handling
- **PMTU Discovery** (Section 14) — DPLPMTUD binary search probing

## SDK Usage

The `sdk/` package provides a high-level API inspired by Go's `net` package:

### Server

```go
listener, err := sdk.Listen("udp", "127.0.0.1:4433", nil)
if err != nil {
    log.Fatal(err)
}
defer listener.Close()

for {
    conn, err := listener.Accept()
    if err != nil {
        log.Fatal(err)
    }
    go handleConn(conn)
}

func handleConn(conn *sdk.Conn) {
    defer conn.Close()
    for {
        stream, err := conn.AcceptStream()
        if err != nil {
            return
        }
        go handleStream(stream)
    }
}
```

### Client

```go
conn, err := sdk.Dial("udp", "127.0.0.1:4433", nil)
if err != nil {
    log.Fatal(err)
}
defer conn.Close()

stream, err := conn.OpenStream()
if err != nil {
    log.Fatal(err)
}
stream.Write([]byte("Hello QUIC!"))

buf := make([]byte, 1024)
n, _ := stream.Read(buf)
fmt.Println(string(buf[:n]))
```

### Config

```go
config := &sdk.Config{
    MaxIdleTimeout:     30 * time.Second,
    MaxStreamData:      1 << 20,  // 1 MiB per stream
    MaxConnectionData:  10 << 20, // 10 MiB per connection
    MaxStreamsBidi:     100,
    MaxStreamsUni:      100,
    ConnIDLength:       8,
}
```

## Project Structure

```
quic-go/
├── go.mod
├── varint/           # Variable-length integer encoding (Section 16)
├── packet/           # Packet number encoding/decoding (Section 17.1)
├── frames/           # Frame type encoding/decoding (Section 19)
├── header/           # Packet header formats (Section 17)
├── transport/        # Transport parameters (Section 18)
├── connection/       # Connection lifecycle & CID management (Sections 5, 10)
├── stream/           # Stream management & flow control (Sections 2-4)
├── errors/           # Error codes (Section 20)
├── ack/              # ACK tracking & generation (Section 13)
├── path/             # Path validation & migration (Sections 8-9)
├── token/            # Address validation tokens (Section 8)
├── coalesce/         # Packet coalescing (Section 12.4)
├── version/          # Version negotiation (Section 6)
├── pmtu/             # PMTU discovery (Section 14)
├── sdk/              # High-level SDK (server & client)
│   ├── config.go     # Config, Listener, Conn, Stream types
│   ├── sdk.go        # Implementation
│   └── sdk_test.go   # Tests
├── cmd/
│   ├── demo/         # Protocol-level interactive demo
│   └── echo/         # SDK echo server/client example
└── README.md
```

## Running

```bash
# Run all tests
cd quic-go && go test ./...

# Run the SDK echo demo (terminal 1 — server)
cd quic-go && go run ./cmd/echo -server -addr 127.0.0.1:4433

# Run the SDK echo demo (terminal 2 — client)
cd quic-go && go run ./cmd/echo -client -addr 127.0.0.1:4433 -msg "Hello QUIC!"

# Run the protocol demo
cd quic-go && go run ./cmd/demo
```

## Key Design Decisions

1. **Pure Go** — No external dependencies (standard library only)
2. **RFC 9000 Appendix A pseudocode** — The packet number encode/decode algorithms directly implement the pseudocode from Appendix A.2 and A.3
3. **Network byte order** — All multi-byte integers use big-endian encoding
4. **Test vectors** — Uses the RFC 9000 test vectors for validation (e.g., varint 0x25=37, 0x7bbd=15293)
5. **SDK operates in plaintext mode** — Since TLS 1.3 (RFC 9001) is not implemented, the SDK sends packets without encryption. Suitable for testing, learning, and reliable-network environments.

## What's NOT Implemented (Intentional)

- **TLS 1.3 integration** (RFC 9001) — Packet protection/encryption
- **Loss detection & congestion control** (RFC 9002) — Retransmission, RTT estimation, PTO

See `GAP_ANALYSIS.html` for a detailed RFC 9000 compliance audit.

For a production QUIC implementation in Go, see [quic-go](https://github.com/quic-go/quic-go).
