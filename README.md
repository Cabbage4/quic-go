# QUIC Transport Protocol - Go Implementation (RFC 9000, RFC 9001, RFC 9002)
# QUIC 传输协议 - Go 实现（RFC 9000、RFC 9001、RFC 9002）

A Go implementation of the core QUIC transport protocol as specified in [RFC 9000](https://www.rfc-editor.org/rfc/rfc9000) (Transport), [RFC 9001](https://www.rfc-editor.org/rfc/rfc9001) (Using TLS to Secure QUIC), and [RFC 9002](https://www.rfc-editor.org/rfc/rfc9002) (Loss Detection and Congestion Control), including a high-level SDK for building servers and clients.

本项目按 [RFC 9000](https://www.rfc-editor.org/rfc/rfc9000)（传输）、[RFC 9001](https://www.rfc-editor.org/rfc/rfc9001)（用 TLS 保护 QUIC）、[RFC 9002](https://www.rfc-editor.org/rfc/rfc9002)（丢包检测与拥塞控制）规范，用 Go 实现了 QUIC 传输协议的核心，并提供一套用于构建服务端与客户端的高层 SDK。

> **Bilingual / 双语**: this README is written in English followed by Chinese in each section. / 本 README 每节均为「英文 + 中文」双语。

## Overview / 概览

This project implements the fundamental building blocks of the QUIC transport protocol, including:

本项目实现了 QUIC 传输协议的基础构建模块，包括：

- **Variable-Length Integer Encoding** (Section 16) — QUIC's custom varint format (6/14/30/62-bit). / **变长整数编码**（§16）—— QUIC 自定义 varint 格式（6/14/30/62 位）。
- **Packet Number Encoding/Decoding** (Section 17.1) — Truncated packet number encoding with Appendix A pseudocode. / **包号编码/解码**（§17.1）—— 截断包号编码，遵循附录 A 伪代码。
- **Frame Types** (Section 19) — All 23 core frame types: PADDING, PING, ACK, RESET_STREAM, STOP_SENDING, CRYPTO, NEW_TOKEN, STREAM, MAX_DATA, MAX_STREAM_DATA, MAX_STREAMS, DATA_BLOCKED, STREAM_DATA_BLOCKED, STREAMS_BLOCKED, NEW_CONNECTION_ID, RETIRE_CONNECTION_ID, PATH_CHALLENGE, PATH_RESPONSE, CONNECTION_CLOSE, HANDSHAKE_DONE. / **帧类型**（§19）—— 全部 23 种核心帧类型。
- **Packet Headers** (Section 17) — Long headers (Initial, 0-RTT, Handshake, Retry), short headers (1-RTT), and Version Negotiation. / **包头**（§17）—— 长头（Initial/0-RTT/Handshake/Retry）、短头（1-RTT）及版本协商。
- **Transport Parameters** (Section 18) — Full encoding/decoding of all 17 transport parameters. / **传输参数**（§18）—— 全部 17 个传输参数的编解码。
- **Connection ID Management** (Section 5.1) — CID generation, retirement, and stateless reset tokens. / **连接 ID 管理**（§5.1）—— CID 生成、退役与无状态重置令牌。
- **Stream Management** (Sections 2-4) — Bidirectional/unidirectional streams, stream state machines, flow control. / **流管理**（§2-4）—— 双向/单向流、流状态机、流控。
- **Error Codes** (Section 20) — All transport error codes. / **错误码**（§20）—— 全部传输错误码。
- **Connection State Machine** (Sections 5, 10) — Lifecycle, packet routing, idle timeout, close/draining. / **连接状态机**（§5、§10）—— 生命周期、包路由、空闲超时、关闭/排空。
- **ACK Tracking** (Section 13) — Received packet set tracking, ACK range generation. / **ACK 跟踪**（§13）—— 已收包集合跟踪、ACK 区间生成。
- **Path Validation & Migration** (Sections 8-9) — PATH_CHALLENGE/RESPONSE, anti-amplification. / **路径校验与迁移**（§8-9）—— PATH_CHALLENGE/RESPONSE、放大攻击防护。
- **Token Management** (Section 8) — Address validation tokens, Retry integrity tag. / **令牌管理**（§8）—— 地址校验令牌、Retry 完整性标签。
- **Packet Coalescing** (Section 12.4) — Multi-packet UDP datagram merging/splitting. / **包合并**（§12.4）—— 单 UDP 数据报多包合并/拆分。
- **Version Negotiation** (Section 6) — VN packet generation and handling. / **版本协商**（§6）—— VN 包生成与处理。
- **PMTU Discovery** (Section 14) — DPLPMTUD binary search probing. / **PMTU 发现**（§14）—— DPLPMTUD 二分探测。
- **Packet Protection** (RFC 9001 §5) — AEAD encryption/decryption (AES-128-GCM, AES-256-GCM), header protection (AES-ECB mask). / **包保护**（RFC 9001 §5）—— AEAD 加解密（AES-128-GCM、AES-256-GCM）、头部保护（AES-ECB 掩码）。
- **Key Derivation** (RFC 9001 §5.1-5.2) — HKDF-Expand-Label, initial secrets from DCID, traffic key/IV/HP derivation, key update. / **密钥派生**（RFC 9001 §5.1-5.2）—— HKDF-Expand-Label、由 DCID 派生初始密钥、流量密钥/IV/HP 派生、密钥更新。
- **TLS 1.3 Integration** (RFC 9001 §4) — CRYPTO frame data routing, encryption level management, handshake state tracking via Go crypto/tls QUICConn. / **TLS 1.3 集成**（RFC 9001 §4）—— CRYPTO 帧数据路由、加密级别管理、通过 Go crypto/tls QUICConn 跟踪握手状态。
- **Key Update & Key Phase** (RFC 9001 §6) — Key phase bit toggle, old key retention, AEAD usage limits. / **密钥更新与 Key Phase**（RFC 9001 §6）—— Key Phase 位翻转、旧密钥保留、AEAD 用量上限。
- **RTT Estimation** (RFC 9002 §5) — smoothed_rtt, rttvar, min_rtt, ack delay handling. / **RTT 估计**（RFC 9002 §5）—— smoothed_rtt、rttvar、min_rtt、ACK 延迟处理。
- **Loss Detection** (RFC 9002 §6) — Packet threshold (kPacketThreshold=3), time threshold (9/8 RTT), PTO calculation & backoff, multi-modal loss detection timer. / **丢包检测**（RFC 9002 §6）—— 包阈值（kPacketThreshold=3）、时间阈值（9/8 RTT）、PTO 计算与退避、多模丢包检测定时器。
- **Congestion Control** (RFC 9002 §7) — NewReno-like: slow start, congestion avoidance, recovery period, ECN, persistent congestion. / **拥塞控制**（RFC 9002 §7）—— 类 NewReno：慢启动、拥塞避免、恢复期、ECN、持续拥塞。

## SDK Usage / SDK 用法

The `sdk/` package provides a high-level API inspired by Go's `net` package:

`sdk/` 包提供了一套仿照 Go 标准库 `net` 包设计的高层 API：

### Server / 服务端

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

### Client / 客户端

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

### Config / 配置

```go
config := &sdk.Config{
    MaxIdleTimeout:     30 * time.Second,
    MaxStreamData:      1 << 20,  // 1 MiB per stream / 每流 1 MiB
    MaxConnectionData:  10 << 20, // 10 MiB per connection / 每连接 10 MiB
    MaxStreamsBidi:     100,
    MaxStreamsUni:      100,
    ConnIDLength:       8,
}
```

## TLS Quick Start / TLS 快速上手

The SDK supports full TLS 1.3 encryption (RFC 9001) via `Config.TLSMode`. This section covers everything from running the built-in demo to writing your own TLS server and client.

SDK 通过 `Config.TLSMode` 支持完整的 TLS 1.3 加密（RFC 9001）。本节涵盖从运行内置 demo 到自写 TLS 服务端/客户端的全部内容。

### Requirements / 环境要求

- Go 1.26+ (uses the `crypto/tls` QUICConn API) / Go 1.26+（使用 `crypto/tls` 的 QUICConn API）
- No external dependencies (Go standard library only) / 无外部依赖（仅 Go 标准库）

### Run the Demo / 快速运行 Demo

The project ships a TLS echo demo (`cmd/tls-demo/`) that generates a self-signed certificate in memory and completes the TLS handshake:

项目内置了一个 TLS echo demo（`cmd/tls-demo/`），自动在内存中生成自签名证书并完成 TLS 握手：

```bash
# Terminal 1: start the TLS server / 终端 1：启动 TLS 服务端
cd quic-go && go run ./cmd/tls-demo -server -addr 127.0.0.1:8443

# Terminal 2: run the TLS client / 终端 2：运行 TLS 客户端
cd quic-go && go run ./cmd/tls-demo -addr 127.0.0.1:8443
```

Expected output / 预期输出：

```
# Server / 服务端
QUIC TLS server listening on 127.0.0.1:8443
TLS 1.3 + QUIC packet protection enabled
Waiting for connections...
connection from 127.0.0.1:xxxxx
server received: "hello over QUIC+TLS"

# Client / 客户端
Dialing 127.0.0.1:8443 with QUIC+TLS...
TLS handshake complete, connection established
client sending: "hello over QUIC+TLS"
client received: "echo: hello over QUIC+TLS"
Demo complete!
```

### TLS Mode API Overview / TLS 模式 API 概览

The SDK API mirrors Go's standard `net` package — set `TLSMode: true` in `Config` to enable TLS:

SDK 的 API 与 Go 标准 `net` 包一致，只需在 `Config` 中设置 `TLSMode: true` 即可启用 TLS：

```go
import "github.com/Cabbage4/quic-go/sdk"

config := &sdk.Config{
    TLSMode: true,              // Enable TLS 1.3 / 启用 TLS 1.3 加密
    TLSCertificates: []tls.Certificate{cert},  // Server cert (not needed on client) / 服务端证书（客户端不需要）
    ServerName: "example.com", // Client SNI (client only) / 客户端 SNI（仅客户端）
    InsecureSkipVerify: false,  // Skip cert verification on client / 客户端是否跳过证书验证
    ALPNProtocols: []string{"h3"}, // ALPN protocol list / ALPN 协议列表

    // Common config / 通用配置
    MaxIdleTimeout:    30 * time.Second,
    MaxStreamData:     1 << 20,   // 1 MiB
    MaxConnectionData: 10 << 20,  // 10 MiB
    MaxStreamsBidi:    100,
    MaxStreamsUni:     100,
    ConnIDLength:      8,
}
```

#### TLS-related Config fields / Config 中 TLS 相关字段

| Field / 字段 | Type / 类型 | Server / 服务端 | Client / 客户端 | Description / 说明 |
|------|------|--------|--------|------|
| `TLSMode` | `bool` | required / 必填 | required / 必填 | `true` enables TLS 1.3; `false` uses plaintext / `true` 启用 TLS 1.3，`false` 使用明文模式 |
| `TLSCertificates` | `[]tls.Certificate` | required / 必填 | not needed / 不需要 | Server TLS certificates / 服务端 TLS 证书 |
| `ALPNProtocols` | `[]string` | optional / 可选 | optional / 可选 | ALPN negotiation list / ALPN 协商列表 |
| `ServerName` | `string` | not needed / 不需要 | optional / 可选 | Client SNI (should match cert hostname) / 客户端 SNI（应匹配证书主机名） |
| `InsecureSkipVerify` | `bool` | not needed / 不需要 | optional / 可选 | Skip cert verification (test only) / 跳过证书验证（仅测试用） |

### Server Usage / 服务端用法

```go
package main

import (
    "crypto/tls"
    "log"
    "time"

    "github.com/Cabbage4/quic-go/sdk"
)

func main() {
    // Load certificate (in production, load from files) / 加载证书（生产环境从文件加载）
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
        stream.Write(buf[:n]) // echo / 回显
    }
}
```

### Client Usage / 客户端用法

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
        InsecureSkipVerify: true, // Skip cert verification in tests; configure RootCAs in production / 测试时跳过证书验证，生产环境应配置 RootCAs
    }

    conn, err := sdk.Dial("udp", "example.com:443", config)
    if err != nil {
        log.Fatal(err)
    }
    defer conn.Close()

    // The TLS handshake is driven automatically during Dial / TLS 握手在 Dial 时自动驱动完成
    // Open a bidirectional stream and send data / 打开双向流并发送数据
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

### Plaintext Mode (for Debugging) / 明文模式（调试用）

Set `TLSMode` to `false` (or leave it unset) to use plaintext mode, where packets are not encrypted — useful for protocol learning and debugging:

不设置 `TLSMode` 或设为 `false` 即可使用明文模式。明文模式下数据包不加密，适用于协议学习和功能调试：

```go
config := &sdk.Config{
    // TLSMode: false (default — no need to set explicitly) / 默认值，无需显式设置
    MaxIdleTimeout: 30 * time.Second,
    ConnIDLength:   8,
}

// Server / 服务端
listener, _ := sdk.Listen("udp", "127.0.0.1:8443", config)

// Client / 客户端
conn, _ := sdk.Dial("udp", "127.0.0.1:8443", config)
```

### TLS Mode vs Plaintext Mode / TLS 模式 vs 明文模式

| Feature / 特性 | Plaintext (`TLSMode: false`) | TLS (`TLSMode: true`) |
|------|-----|-----|
| Data encryption / 数据加密 | None / 无 | AES-128-GCM / AES-256-GCM |
| Header protection / 头部保护 | None / 无 | AES-ECB mask (RFC 9001 §5.4) |
| Handshake / 握手 | PING → HANDSHAKE_DONE (simplified) / 简化 | TLS 1.3 ClientHello → ServerHello → Finished |
| Certificates / 证书 | Not required / 不需要 | Required (server must; client optional for mTLS) / 需要（服务端必须，客户端可选 mTLS） |
| Transport params / 传输参数 | Exchanged via Initial frames / 通过 Initial 帧交换 | Exchanged via TLS extension / 通过 TLS 扩展交换 |
| Key update / 密钥更新 | Not supported / 不支持 | Supported (RFC 9001 §6 Key Update) / 支持 |
| Use case / 适用场景 | Dev/debug, protocol learning / 开发调试、协议学习 | Production, secure communication / 生产环境、安全通信 |

### Architecture / 架构说明

In TLS mode, data flows through this pipeline:

TLS 模式下数据流经以下管道：

```
Application data / 应用层数据
    ↓
SDK (sdk.Conn / sdk.Stream)
    ↓ calls / 调用 PacketIO.SendPacket()
Connection layer / Connection 层
    ├── Frame encoding / 帧编码 (frames.Encode)
    ├── Header build / 构建包头 (header.LongHeader / ShortHeader)
    ├── AEAD encrypt / AEAD 加密 (crypto.ProtectPayload)
    ├── Header protection / 头部保护 (crypto.ApplyHeaderProtection)
    ├── Optional: packet coalescing / 可选：包合并 (coalesce.CoalescePackets)
    └── UDP send / UDP 发送
    ↓
UDP datagrams / UDP 数据包
```

Handshake flow / 握手流程：

```
Client / 客户端                              Server / 服务端
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
  │                                          │ (handshake confirmed / 握手确认)
  │←──── 1-RTT [HANDSHAKE_DONE] ─────────────┤
  │                                          │
  │     Connection established, app data / 连接建立，可传应用数据
  ├── 1-RTT [STREAM: data] ────────────────→│
  │←─── 1-RTT [STREAM: response] ───────────┤
```

Key components / 关键组件：

- **`crypto.TLSSession`** — wraps `crypto/tls.QUICConn`, drives the TLS event loop. / 封装 `crypto/tls.QUICConn`，处理 TLS 事件循环。
- **`connection.KeySetStore`** — manages keys per encryption level (Initial / Handshake / Application). / 管理各加密级别的密钥（Initial / Handshake / Application）。
- **`connection.PacketIO`** — unified send/receive pipeline; switches between encrypted and plaintext paths via `plaintextMode`. / 统一收发管道，根据 `plaintextMode` 自动切换加密/明文路径。
- **`connection.Coordinator`** — lifecycle orchestrator: drives TLS handshake, PN-space discard, key update. / 生命周期协调器：驱动 TLS 握手、PN 空间丢弃、密钥更新。
- **`connection.FrameHandler`** — frame dispatcher; routes CRYPTO frames to `KeyStore.FeedCryptoData()`. / 帧分发器，自动将 CRYPTO 帧路由到 `KeyStore.FeedCryptoData()`。

## HTTP SDK Usage / HTTP SDK 用法

The `http/` package provides an HTTP/1.1-over-QUIC implementation with a familiar `net/http`-style API:

`http/` 包提供了一套 HTTP/1.1-over-QUIC 实现，API 风格与 `net/http` 一致：

### Server / 服务端

```go
mux := http.NewServeMux()
mux.HandleFunc("/hello", func(w http.ResponseWriter, r *http.Request) {
    w.Write([]byte("Hello, World!"))
})
mux.HandleFunc("/echo", func(w http.ResponseWriter, r *http.Request) {
    w.Write(r.Body) // echo POST body back / 回显 POST 请求体
})

srv := &http.Server{Handler: mux}
ln, err := http.Listen("udp", "127.0.0.1:8443", srv, nil)
if err != nil {
    log.Fatal(err)
}
defer ln.Close()
```

### Client / 客户端

```go
// Simple GET / 简单 GET
resp, err := http.Get("http://127.0.0.1:8443/hello")
fmt.Println(resp.StatusCode, string(resp.Body))

// POST with body and headers / 带 body 与 header 的 POST
resp, err = http.Post("http://127.0.0.1:8443/echo", []byte("ping"), nil)
fmt.Println(string(resp.Body))

// Custom client with timeout / 带超时的自定义 client
client := &http.Client{Timeout: 5 * time.Second}
resp, err = client.Do("GET", "http://127.0.0.1:8443/hello", nil, nil)
```

Each HTTP request-response pair is carried over a single bidirectional QUIC stream. This is plain HTTP/1.1 text framing over QUIC, not HTTP/3 (no QPACK, no dedicated unidirectional streams).

每个 HTTP 请求-响应对在一条双向 QUIC 流上传输。这是基于 QUIC 的纯 HTTP/1.1 文本成帧，**不是** HTTP/3（无 QPACK、无专用单向流）。

## Project Structure / 项目结构

```
quic-go/
├── go.mod
├── varint/           # Variable-length integer encoding (Section 16) / 变长整数编码（§16）
├── packet/           # Packet number encoding/decoding (Section 17.1) / 包号编解码（§17.1）
├── frames/           # Frame type encoding/decoding (Section 19) / 帧类型编解码（§19）
├── header/           # Packet header formats (Section 17) / 包头格式（§17）
├── transport/        # Transport parameters (Section 18) / 传输参数（§18）
├── connection/       # Connection lifecycle & CID management (Sections 5, 10) / 连接生命周期与 CID 管理（§5、§10）
│   ├── conn.go            # State machine, packet routing, idle timeout, close/draining / 状态机、包路由、空闲超时、关闭/排空
│   ├── connid.go          # Connection ID management (Section 5.1) / 连接 ID 管理（§5.1）
│   ├── crypto.go          # Per-level key store + packet protection pipeline (RFC 9001) / 各级别密钥库 + 包保护管道
│   ├── recovery.go        # Loss detection + congestion control integration (RFC 9002) / 丢包检测 + 拥塞控制集成
│   ├── ack_handler.go     # Per-PN-space ACK tracker integration (Section 13) / 各 PN 空间 ACK 跟踪集成（§13）
│   ├── frame_handler.go   # Comprehensive frame processing dispatch (Section 19) / 全帧处理分发（§19）
│   ├── packet_io.go       # Unified packet send/receive pipeline with protection / 带保护的统一收发管道
│   ├── coordinator.go     # Connection lifecycle orchestrator (handshake, key discard, close) / 生命周期协调器（握手、密钥丢弃、关闭）
│   ├── integration_test.go # Integration tests / 集成测试
│   └── e2e_test.go        # End-to-end lifecycle tests / 端到端生命周期测试
├── stream/           # Stream management & flow control (Sections 2-4) / 流管理与流控（§2-4）
├── errors/           # Error codes (Section 20) / 错误码（§20）
├── ack/              # ACK tracking & generation (Section 13) / ACK 跟踪与生成（§13）
├── path/             # Path validation & migration (Sections 8-9) / 路径校验与迁移（§8-9）
├── token/            # Address validation tokens (Section 8) / 地址校验令牌（§8）
├── coalesce/         # Packet coalescing (Section 12.4) / 包合并（§12.4）
├── version/          # Version negotiation (Section 6) / 版本协商（§6）
├── pmtu/             # PMTU discovery (Section 14) / PMTU 发现（§14）
├── crypto/           # Packet protection & TLS integration (RFC 9001) / 包保护与 TLS 集成
│   ├── keys.go       # HKDF-Expand-Label, initial secrets, traffic key derivation / HKDF-Expand-Label、初始密钥、流量密钥派生
│   ├── aead.go       # AEAD encrypt/decrypt (AES-128-GCM, AES-256-GCM) / AEAD 加解密
│   ├── header_protection.go  # Header protection mask generation & apply/remove / 头部保护掩码生成与应用
│   ├── key_update.go # Key update & Key Phase management / 密钥更新与 Key Phase 管理
│   ├── tls.go        # TLS 1.3 integration via crypto/tls QUICConn / 经 crypto/tls QUICConn 的 TLS 1.3 集成
│   └── crypto_test.go # Tests / 测试
├── recovery/         # Loss detection & congestion control (RFC 9002) / 丢包检测与拥塞控制
│   ├── loss_detection.go  # RTT estimation, PTO, loss detection algorithms / RTT 估计、PTO、丢包检测算法
│   ├── congestion.go      # NewReno-like congestion control / 类 NewReno 拥塞控制
│   └── recovery_test.go   # Tests / 测试
├── sdk/              # High-level SDK (server & client) / 高层 SDK（服务端与客户端）
│   ├── config.go     # Config, Listener, Conn, Stream types / Config、Listener、Conn、Stream 类型
│   ├── sdk.go        # Implementation / 实现
│   └── sdk_test.go   # Tests / 测试
├── http/             # HTTP/1.1-over-QUIC SDK / 基于 QUIC 的 HTTP/1.1 SDK
│   ├── http.go       # Server, Client, Handler, ServeMux, Request/Response / Server、Client、Handler、ServeMux、Request/Response
│   └── http_test.go  # Tests / 测试
├── cmd/
│   ├── demo/         # Protocol-level interactive demo / 协议级交互 demo
│   ├── echo/         # SDK echo server/client example / SDK echo 服务端/客户端示例
│   ├── tls-demo/     # SDK TLS echo demo (self-signed cert, AEAD encryption) / SDK TLS echo demo（自签名证书、AEAD 加密）
│   └── http-demo/    # HTTP-over-QUIC server/client example / HTTP-over-QUIC 服务端/客户端示例
└── README.md
```

## Running / 运行

```bash
# Run all tests / 运行全部测试
cd quic-go && go test ./...

# Run the SDK echo demo (terminal 1 — server) / SDK echo demo（终端 1 — 服务端）
cd quic-go && go run ./cmd/echo -server -addr 127.0.0.1:4433

# Run the SDK echo demo (terminal 2 — client) / SDK echo demo（终端 2 — 客户端）
cd quic-go && go run ./cmd/echo -addr 127.0.0.1:4433 -msg "Hello QUIC!"

# Run the HTTP demo (terminal 1 — server) / HTTP demo（终端 1 — 服务端）
cd quic-go && go run ./cmd/http-demo -server -addr 127.0.0.1:8443

# Run the HTTP demo (terminal 2 — client) / HTTP demo（终端 2 — 客户端）
cd quic-go && go run ./cmd/http-demo -addr 127.0.0.1:8443

# Run the TLS echo demo (terminal 1 — server) / TLS echo demo（终端 1 — 服务端）
cd quic-go && go run ./cmd/tls-demo -server -addr 127.0.0.1:8443

# Run the TLS echo demo (terminal 2 — client) / TLS echo demo（终端 2 — 客户端）
cd quic-go && go run ./cmd/tls-demo -addr 127.0.0.1:8443

# Run the protocol demo / 运行协议 demo
cd quic-go && go run ./cmd/demo
```

## Key Design Decisions / 关键设计决策

1. **Pure Go** — No external dependencies (standard library only). / **纯 Go** —— 无外部依赖（仅标准库）。
2. **RFC 9000 Appendix A pseudocode** — The packet number encode/decode algorithms directly implement the pseudocode from Appendix A.2 and A.3. / **RFC 9000 附录 A 伪代码** —— 包号编解码算法直接实现附录 A.2 与 A.3 的伪代码。
3. **Network byte order** — All multi-byte integers use big-endian encoding. / **网络字节序** —— 所有多字节整数使用大端编码。
4. **Test vectors** — Uses the RFC 9000 test vectors for validation (e.g., varint 0x25=37, 0x7bbd=15293). / **测试向量** —— 使用 RFC 9000 测试向量校验（如 varint 0x25=37、0x7bbd=15293）。
5. **SDK uses connection-layer pipeline** — The SDK's `Conn` struct wires together all connection-layer subsystems via `initSubsystems()`: KeySetStore, AckHandler, RecoveryManager, stream.Manager, FrameHandler, and PacketIO. The SDK's `handleIncoming` dispatches incoming packet payloads through `FrameHandler.ProcessFrames()` (using `frames.Decode()` for all 27 frame types) instead of inline frame parsing. A `Coordinator` orchestrates lifecycle transitions (handshake, PN space discard, key phase, connection close with draining). The SDK currently operates in plaintext mode (no encryption) for testing and learning; the protected path through `PacketIO` is available when TLS keys are installed. / **SDK 复用 connection 层管道** —— SDK 的 `Conn` 通过 `initSubsystems()` 把 connection 层各子系统串联起来：KeySetStore、AckHandler、RecoveryManager、stream.Manager、FrameHandler、PacketIO。SDK 的 `handleIncoming` 经 `FrameHandler.ProcessFrames()`（用 `frames.Decode()` 解析全部 27 种帧）分发入包载荷，而非内联解析。`Coordinator` 统一编排生命周期过渡（握手、PN 空间丢弃、Key Phase、带排空的连接关闭）。SDK 默认明文模式（无加密）便于测试与学习；安装 TLS 密钥后即可走 `PacketIO` 的加密路径。

6. **Connection Layer Integration** — The `connection/` package provides a complete integration layer that wires together crypto, recovery, ACK tracking, frame processing, packet I/O, and lifecycle coordination:
   - `crypto.go`: KeySetStore for per-encryption-level key management, packet protection pipeline (AEAD + header protection), TLS session management
   - `recovery.go`: RecoveryManager integrating loss detection + congestion control with packet send/recv hooks
   - `ack_handler.go`: Per-PN-space ACK trackers with ACK frame generation and parsing
   - `frame_handler.go`: Comprehensive frame dispatch using `frames.Decode()` for all 27 frame types, PATH_CHALLENGE/RESPONSE queuing, RETIRE_CONNECTION_ID handling, sent-frame tracking for ACK-driven stream state updates
   - `packet_io.go`: Unified packet send/receive pipeline with protection, coalescing, PN truncation/reconstruction, key phase bit wiring, and sent-frame recording
   - `coordinator.go`: Central lifecycle orchestrator — handshake driver, PN space discard coordination (RFC 9001 §4.9), key phase management (RFC 9001 §6), connection close with draining (RFC 9000 §10.2-10.3)
   - `e2e_test.go`: 14 end-to-end integration tests covering the full connection lifecycle

   / **Connection 层集成** —— `connection/` 包提供完整集成层，串联 crypto、recovery、ACK 跟踪、帧处理、包 I/O 与生命周期协调：
   - `crypto.go`：KeySetStore 管理各级别密钥、包保护管道（AEAD + 头部保护）、TLS 会话管理
   - `recovery.go`：RecoveryManager 集成丢包检测 + 拥塞控制，挂接收发钩子
   - `ack_handler.go`：各 PN 空间 ACK 跟踪器，含 ACK 帧生成与解析
   - `frame_handler.go`：用 `frames.Decode()` 全量分发 27 种帧，PATH_CHALLENGE/RESPONSE 排队、RETIRE_CONNECTION_ID 处理、已发帧跟踪（ACK 驱动流状态更新）
   - `packet_io.go`：带保护的统一收发管道，含合并、PN 截断/重建、Key Phase 位接线、已发帧记录
   - `coordinator.go`：中央生命周期协调器 —— 握手驱动、PN 空间丢弃协调（RFC 9001 §4.9）、Key Phase 管理（RFC 9001 §6）、带排空的连接关闭（RFC 9000 §10.2-10.3）
   - `e2e_test.go`：14 个覆盖完整连接生命周期的端到端集成测试

## Status / 状态

- **57 Go files, 245 tests, all passing** / **57 个 Go 文件、245 个测试，全部通过**
- **21 packages, zero external dependencies (Go standard library only)** / **21 个包，零外部依赖（仅 Go 标准库）**
- RFC 9000 (Transport): Complete / RFC 9000（传输）：完成
- RFC 9001 (TLS Integration): Complete — key derivation, AEAD, header protection, key update, TLS handshake via crypto/tls QUICConn / RFC 9001（TLS 集成）：完成 —— 密钥派生、AEAD、头部保护、密钥更新、经 crypto/tls QUICConn 的 TLS 握手
- RFC 9002 (Loss Detection & Congestion Control): Complete — RTT estimation, PTO, loss detection, NewReno congestion control / RFC 9002（丢包检测与拥塞控制）：完成 —— RTT 估计、PTO、丢包检测、NewReno 拥塞控制
- Connection Layer Integration: Complete — crypto, recovery, ACK, frame handler, packet I/O, coordinator, e2e tests / Connection 层集成：完成 —— crypto、recovery、ACK、frame handler、packet I/O、coordinator、e2e 测试
- SDK Integration: Complete — SDK uses connection-layer PacketIO/FrameHandler/stream.Manager pipeline with Coordinator lifecycle management / SDK 集成：完成 —— SDK 复用 connection 层 PacketIO/FrameHandler/stream.Manager 管道，由 Coordinator 管理生命周期
- **SDK TLS Mode: Complete — `Config.TLSMode=true` enables full TLS 1.3 + AEAD packet protection**. See the [TLS Quick Start](#tls-quick-start--tls-快速上手) section above and `cmd/tls-demo/` for a runnable demo. / **SDK TLS 模式：完成 —— `Config.TLSMode=true` 启用完整 TLS 1.3 + AEAD 包保护**。见上文 [TLS 快速上手](#tls-quick-start--tls-快速上手) 节及 `cmd/tls-demo/` 可运行示例。

See `GAP_ANALYSIS.html` for a detailed RFC compliance audit. / 详见 `GAP_ANALYSIS.html` 的 RFC 合规审计（注：该报告为较早生成快照，未含近期 ACK/包号/流控修复）。

For a production QUIC implementation in Go, see [quic-go](https://github.com/quic-go/quic-go). / 生产级 Go QUIC 实现可参考 [quic-go](https://github.com/quic-go/quic-go)。
