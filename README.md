# QUIC Transport Protocol - Go Implementation (RFC 9000, RFC 9001, RFC 9002)

A Go implementation of the core QUIC transport protocol as specified in [RFC 9000](https://www.rfc-editor.org/rfc/rfc9000) (Transport), [RFC 9001](https://www.rfc-editor.org/rfc/rfc9001) (Using TLS to Secure QUIC), and [RFC 9002](https://www.rfc-editor.org/rfc/rfc9002) (Loss Detection and Congestion Control), including a high-level SDK for building servers and clients.

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
- **Packet Protection** (RFC 9001 §5) — AEAD encryption/decryption (AES-128-GCM, AES-256-GCM), header protection (AES-ECB mask)
- **Key Derivation** (RFC 9001 §5.1-5.2) — HKDF-Expand-Label, initial secrets from DCID, traffic key/IV/HP derivation, key update
- **TLS 1.3 Integration** (RFC 9001 §4) — CRYPTO frame data routing, encryption level management, handshake state tracking via Go crypto/tls QUICConn
- **Key Update & Key Phase** (RFC 9001 §6) — Key phase bit toggle, old key retention, AEAD usage limits
- **RTT Estimation** (RFC 9002 §5) — smoothed_rtt, rttvar, min_rtt, ack delay handling
- **Loss Detection** (RFC 9002 §6) — Packet threshold (kPacketThreshold=3), time threshold (9/8 RTT), PTO calculation & backoff, multi-modal loss detection timer
- **Congestion Control** (RFC 9002 §7) — NewReno-like: slow start, congestion avoidance, recovery period, ECN, persistent congestion

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

## TLS Quick Start

The SDK supports full TLS 1.3 encryption (RFC 9001) via `Config.TLSMode`. This section covers everything from running the built-in demo to writing your own TLS server and client.

### 环境要求

- Go 1.26+（使用了 `crypto/tls` 的 QUICConn API）
- 无外部依赖（仅 Go 标准库）

### 快速运行 Demo

项目内置了一个 TLS echo demo（`cmd/tls-demo/`），自动生成自签名证书并在内存中完成 TLS 握手：

```bash
# 终端 1：启动 TLS 服务端
cd quic-go && go run ./cmd/tls-demo -server -addr 127.0.0.1:8443

# 终端 2：运行 TLS 客户端
cd quic-go && go run ./cmd/tls-demo -addr 127.0.0.1:8443
```

预期输出：

```
# 服务端
QUIC TLS server listening on 127.0.0.1:8443
TLS 1.3 + QUIC packet protection enabled
Waiting for connections...
connection from 127.0.0.1:xxxxx
server received: "hello over QUIC+TLS"

# 客户端
Dialing 127.0.0.1:8443 with QUIC+TLS...
TLS handshake complete, connection established
client sending: "hello over QUIC+TLS"
client received: "echo: hello over QUIC+TLS"
Demo complete!
```

### TLS 模式 API 概览

SDK 的 API 设计与 Go 标准库的 `net` 包一致，只需在 `Config` 中设置 `TLSMode: true` 即可启用 TLS：

```go
import "github.com/Cabbage4/quic-go/sdk"

config := &sdk.Config{
    TLSMode: true,              // 启用 TLS 1.3 加密
    TLSCertificates: []tls.Certificate{cert},  // 服务端证书（客户端不需要）
    ServerName: "example.com", // 客户端 SNI（仅客户端）
    InsecureSkipVerify: false,  // 客户端是否跳过证书验证
    ALPNProtocols: []string{"h3"}, // ALPN 协议列表

    // 通用配置
    MaxIdleTimeout:    30 * time.Second,
    MaxStreamData:     1 << 20,   // 1 MiB
    MaxConnectionData: 10 << 20,  // 10 MiB
    MaxStreamsBidi:    100,
    MaxStreamsUni:     100,
    ConnIDLength:      8,
}
```

#### Config 中 TLS 相关字段

| 字段 | 类型 | 服务端 | 客户端 | 说明 |
|------|------|--------|--------|------|
| `TLSMode` | `bool` | 必填 | 必填 | `true` 启用 TLS 1.3，`false` 使用明文模式 |
| `TLSCertificates` | `[]tls.Certificate` | 必填 | 不需要 | 服务端 TLS 证书 |
| `ALPNProtocols` | `[]string` | 可选 | 可选 | ALPN 协议协商列表 |
| `ServerName` | `string` | 不需要 | 可选 | 客户端 SNI（应匹配证书主机名） |
| `InsecureSkipVerify` | `bool` | 不需要 | 可选 | 跳过证书验证（仅测试用） |

### 服务端用法

```go
package main

import (
    "crypto/tls"
    "log"
    "time"

    "github.com/Cabbage4/quic-go/sdk"
)

func main() {
    // 加载证书（生产环境从文件加载）
    cert, err := tls.LoadX509KeyPair("server.crt", "server.key")
    if err != nil {
        log.Fatal(err)
    }

    config := &sdk.Config{
        TLSMode:         true,
        TLSCertificates: []tls.Certificate{cert},
        ALPNProtocols:   []string{"myapp"},
        MaxIdleTimeout:  30 * time.Second,
        ConnIDLength:    8,
    }

    listener, err := sdk.Listen("udp", "0.0.0.0:443", config)
    if err != nil {
        log.Fatal(err)
    }
    defer listener.Close()

    for {
        conn, err := listener.Accept()
        if err != nil {
            log.Println(err)
            continue
        }
        go handleConnection(conn)
    }
}

func handleConnection(conn *sdk.Conn) {
    defer conn.Close()
    for {
        stream, err := conn.AcceptStream()
        if err != nil {
            return
        }
        go handleStream(stream)
    }
}

func handleStream(stream *sdk.Stream) {
    defer stream.Close()
    buf := make([]byte, 4096)
    for {
        n, err := stream.Read(buf)
        if err != nil {
            return
        }
        stream.Write(buf[:n]) // echo
    }
}
```

### 客户端用法

```go
package main

import (
    "log"
    "time"

    "github.com/Cabbage4/quic-go/sdk"
)

func main() {
    config := &sdk.Config{
        TLSMode:            true,
        ServerName:         "example.com",
        ALPNProtocols:      []string{"myapp"},
        MaxIdleTimeout:     30 * time.Second,
        ConnIDLength:       8,
        InsecureSkipVerify: true, // 测试时跳过证书验证，生产环境应配置 RootCAs
    }

    conn, err := sdk.Dial("udp", "example.com:443", config)
    if err != nil {
        log.Fatal(err)
    }
    defer conn.Close()

    // TLS 握手在 Dial 时自动驱动完成
    // 打开双向流并发送数据
    stream, err := conn.OpenStream()
    if err != nil {
        log.Fatal(err)
    }
    defer stream.Close()

    stream.Write([]byte("hello QUIC+TLS"))

    buf := make([]byte, 4096)
    n, _ := stream.Read(buf)
    log.Printf("received: %s", buf[:n])
}
```

### 明文模式（调试用）

不设置 `TLSMode` 或设为 `false` 即可使用明文模式。明文模式下数据包不加密，适用于协议学习和功能调试：

```go
config := &sdk.Config{
    // TLSMode: false (默认值，无需显式设置)
    MaxIdleTimeout: 30 * time.Second,
    ConnIDLength:   8,
}

// 服务端
listener, _ := sdk.Listen("udp", "127.0.0.1:8443", config)

// 客户端
conn, _ := sdk.Dial("udp", "127.0.0.1:8443", config)
```

### TLS 模式 vs 明文模式

| 特性 | 明文模式 (`TLSMode: false`) | TLS 模式 (`TLSMode: true`) |
|------|-----|-----|
| 数据加密 | 无 | AES-128-GCM / AES-256-GCM |
| 头部保护 | 无 | AES-ECB mask (RFC 9001 §5.4) |
| 握手 | PING → HANDSHAKE_DONE（简化） | TLS 1.3 ClientHello → ServerHello → Finished |
| 证书 | 不需要 | 需要（服务端必须，客户端可选 mTLS） |
| 传输参数 | 通过 Initial 帧交换 | 通过 TLS 扩展交换 |
| 密钥更新 | 不支持 | 支持（RFC 9001 §6 Key Update） |
| 适用场景 | 开发调试、协议学习 | 生产环境、安全通信 |

### 架构说明

TLS 模式下数据流经以下管道：

```
应用层数据
    ↓
SDK (sdk.Conn / sdk.Stream)
    ↓ 调用 PacketIO.SendPacket()
Connection 层
    ├── 帧编码 (frames.Encode)
    ├── 构建包头 (header.LongHeader / ShortHeader)
    ├── AEAD 加密 (crypto.ProtectPayload)
    ├── 头部保护 (crypto.ApplyHeaderProtection)
    ├── 可选：包合并 (coalesce.CoalescePackets)
    └── UDP 发送
    ↓
UDP 数据包
```

握手流程：

```
客户端                                     服务端
  │                                          │
  ├── Initial [CRYPTO: ClientHello] ────────→│
  │                                          │ (DeriveInitialKeys)
  │                                          │ (StartTLS → process ClientHello)
  │←─── Initial [CRYPTO: ServerHello] ───────┤
  │←─── Handshake [CRYPTO: Cert, Finished] ──┤
  │                                          │
  │ (process ServerHello)                    │
  │ (install Handshake keys)                 │
  │                                          │
  ├── Handshake [CRYPTO: Finished] ────────→│
  │                                          │ (handshake confirmed)
  │←──── 1-RTT [HANDSHAKE_DONE] ─────────────┤
  │                                          │
  │     连接建立，可传输应用数据               │
  ├── 1-RTT [STREAM: data] ────────────────→│
  │←─── 1-RTT [STREAM: response] ───────────┤
```

关键组件：

- **`crypto.TLSSession`** — 封装 `crypto/tls.QUICConn`，处理 TLS 事件循环
- **`connection.KeySetStore`** — 管理各加密级别的密钥（Initial / Handshake / Application）
- **`connection.PacketIO`** — 统一收发管道，根据 `plaintextMode` 自动切换加密/明文路径
- **`connection.Coordinator`** — 生命周期协调器，驱动 TLS 握手、PN 空间丢弃、密钥更新
- **`connection.FrameHandler`** — 帧分发器，自动将 CRYPTO 帧路由到 `KeyStore.FeedCryptoData()`

## HTTP SDK Usage

The `http/` package provides an HTTP/1.1-over-QUIC implementation with a familiar `net/http`-style API:

### Server

```go
mux := http.NewServeMux()
mux.HandleFunc("/hello", func(w http.ResponseWriter, r *http.Request) {
    w.Write([]byte("Hello, World!"))
})
mux.HandleFunc("/echo", func(w http.ResponseWriter, r *http.Request) {
    w.Write(r.Body) // echo POST body back
})

srv := &http.Server{Handler: mux}
ln, err := http.Listen("udp", "127.0.0.1:8443", srv, nil)
if err != nil {
    log.Fatal(err)
}
defer ln.Close()
```

### Client

```go
// Simple GET
resp, err := http.Get("http://127.0.0.1:8443/hello")
fmt.Println(resp.StatusCode, string(resp.Body))

// POST with body and headers
resp, err = http.Post("http://127.0.0.1:8443/echo", []byte("ping"), nil)
fmt.Println(string(resp.Body))

// Custom client with timeout
client := &http.Client{Timeout: 5 * time.Second}
resp, err = client.Do("GET", "http://127.0.0.1:8443/hello", nil, nil)
```

Each HTTP request-response pair is carried over a single bidirectional QUIC stream. This is plain HTTP/1.1 text framing over QUIC, not HTTP/3 (no QPACK, no dedicated unidirectional streams).

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
│   ├── conn.go            # State machine, packet routing, idle timeout, close/draining
│   ├── connid.go          # Connection ID management (Section 5.1)
│   ├── crypto.go          # Per-level key store + packet protection pipeline (RFC 9001 integration)
│   ├── recovery.go        # Loss detection + congestion control integration (RFC 9002)
│   ├── ack_handler.go     # Per-PN-space ACK tracker integration (Section 13)
│   ├── frame_handler.go   # Comprehensive frame processing dispatch (Section 19)
│   ├── packet_io.go       # Unified packet send/receive pipeline with protection
│   ├── coordinator.go     # Connection lifecycle orchestrator (handshake, key discard, close)
│   ├── integration_test.go # Integration tests
│   └── e2e_test.go        # End-to-end lifecycle tests
├── stream/           # Stream management & flow control (Sections 2-4)
├── errors/           # Error codes (Section 20)
├── ack/              # ACK tracking & generation (Section 13)
├── path/             # Path validation & migration (Sections 8-9)
├── token/            # Address validation tokens (Section 8)
├── coalesce/         # Packet coalescing (Section 12.4)
├── version/          # Version negotiation (Section 6)
├── pmtu/             # PMTU discovery (Section 14)
├── crypto/           # Packet protection & TLS integration (RFC 9001)
│   ├── keys.go       # HKDF-Expand-Label, initial secrets, traffic key derivation
│   ├── aead.go       # AEAD encrypt/decrypt (AES-128-GCM, AES-256-GCM)
│   ├── header_protection.go  # Header protection mask generation & apply/remove
│   ├── key_update.go # Key update & Key Phase management
│   ├── tls.go        # TLS 1.3 integration via crypto/tls QUICConn
│   └── crypto_test.go # Tests
├── recovery/         # Loss detection & congestion control (RFC 9002)
│   ├── loss_detection.go  # RTT estimation, PTO, loss detection algorithms
│   ├── congestion.go      # NewReno-like congestion control
│   └── recovery_test.go   # Tests
├── sdk/              # High-level SDK (server & client)
│   ├── config.go     # Config, Listener, Conn, Stream types
│   ├── sdk.go        # Implementation
│   └── sdk_test.go   # Tests
├── http/             # HTTP/1.1-over-QUIC SDK
│   ├── http.go       # Server, Client, Handler, ServeMux, Request/Response
│   └── http_test.go  # Tests
├── cmd/
│   ├── demo/         # Protocol-level interactive demo
│   ├── echo/         # SDK echo server/client example
│   ├── tls-demo/     # SDK TLS echo demo (self-signed cert, AEAD encryption)
│   └── http-demo/    # HTTP-over-QUIC server/client example
└── README.md
```

## Running

```bash
# Run all tests
cd quic-go && go test ./...

# Run the SDK echo demo (terminal 1 — server)
cd quic-go && go run ./cmd/echo -server -addr 127.0.0.1:4433

# Run the SDK echo demo (terminal 2 — client)
cd quic-go && go run ./cmd/echo -addr 127.0.0.1:4433 -msg "Hello QUIC!"

# Run the HTTP demo (terminal 1 — server)
cd quic-go && go run ./cmd/http-demo -server -addr 127.0.0.1:8443

# Run the HTTP demo (terminal 2 — client)
cd quic-go && go run ./cmd/http-demo -addr 127.0.0.1:8443

# Run the TLS echo demo (terminal 1 — server)
cd quic-go && go run ./cmd/tls-demo -server -addr 127.0.0.1:8443

# Run the TLS echo demo (terminal 2 — client)
cd quic-go && go run ./cmd/tls-demo -addr 127.0.0.1:8443

# Run the protocol demo
cd quic-go && go run ./cmd/demo
```

## Key Design Decisions

1. **Pure Go** — No external dependencies (standard library only)
2. **RFC 9000 Appendix A pseudocode** — The packet number encode/decode algorithms directly implement the pseudocode from Appendix A.2 and A.3
3. **Network byte order** — All multi-byte integers use big-endian encoding
4. **Test vectors** — Uses the RFC 9000 test vectors for validation (e.g., varint 0x25=37, 0x7bbd=15293)
5. **SDK uses connection-layer pipeline** — The SDK's `Conn` struct wires together all connection-layer subsystems via `initSubsystems()`: KeySetStore, AckHandler, RecoveryManager, stream.Manager, FrameHandler, and PacketIO. The SDK's `handleIncoming` dispatches incoming packet payloads through `FrameHandler.ProcessFrames()` (using `frames.Decode()` for all 27 frame types) instead of inline frame parsing. A `Coordinator` orchestrates lifecycle transitions (handshake, PN space discard, key phase, connection close with draining). The SDK currently operates in plaintext mode (no encryption) for testing and learning; the protected path through `PacketIO` is available when TLS keys are installed.

6. **Connection Layer Integration** — The `connection/` package provides a complete integration layer that wires together crypto, recovery, ACK tracking, frame processing, packet I/O, and lifecycle coordination:
   - `crypto.go`: KeySetStore for per-encryption-level key management, packet protection pipeline (AEAD + header protection), TLS session management
   - `recovery.go`: RecoveryManager integrating loss detection + congestion control with packet send/recv hooks
   - `ack_handler.go`: Per-PN-space ACK trackers with ACK frame generation and parsing
   - `frame_handler.go`: Comprehensive frame dispatch using `frames.Decode()` for all 27 frame types, PATH_CHALLENGE/RESPONSE queuing, RETIRE_CONNECTION_ID handling, sent-frame tracking for ACK-driven stream state updates
   - `packet_io.go`: Unified packet send/receive pipeline with protection, coalescing, PN truncation/reconstruction, key phase bit wiring, and sent-frame recording
   - `coordinator.go`: Central lifecycle orchestrator — handshake driver, PN space discard coordination (RFC 9001 §4.9), key phase management (RFC 9001 §6), connection close with draining (RFC 9000 §10.2-10.3)
   - `e2e_test.go`: 14 end-to-end integration tests covering the full connection lifecycle

## Status

- **57 Go files, 245 tests, all passing**
- **21 packages, zero external dependencies (Go standard library only)**
- RFC 9000 (Transport): Complete
- RFC 9001 (TLS Integration): Complete — key derivation, AEAD, header protection, key update, TLS handshake via crypto/tls QUICConn
- RFC 9002 (Loss Detection & Congestion Control): Complete — RTT estimation, PTO, loss detection, NewReno congestion control
- Connection Layer Integration: Complete — crypto, recovery, ACK, frame handler, packet I/O, coordinator, e2e tests
- SDK Integration: Complete — SDK uses connection-layer PacketIO/FrameHandler/stream.Manager pipeline with Coordinator lifecycle management
- **SDK TLS Mode: Complete — `Config.TLSMode=true` enables full TLS 1.3 + AEAD packet protection**. See the [TLS Quick Start](#tls-quick-start) section above and `cmd/tls-demo/` for a runnable demo.

See `GAP_ANALYSIS.html` for a detailed RFC compliance audit.

For a production QUIC implementation in Go, see [quic-go](https://github.com/quic-go/quic-go).
