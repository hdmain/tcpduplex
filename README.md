# tcpduplex

**tcpduplex** is a small Go library for **encrypted full-duplex messaging over TCP**: X25519 ECDH, AES-256-GCM, length-prefixed records, and concurrent read/write loops. It is **not** TLS and does **not** replace certificate-based authentication for the public internet; it suits private networks, constrained environments, or protocols where you control both peers.

## Requirements

- Go **1.22+**

## Install

```bash
go get tcpduplex
```

Use the **module path** declared in [`go.mod`](go.mod). For a **local checkout**, point consumers at it with a `replace` directive (or a vanity import path) instead of `go get`.

When developing inside this repository, imports use the module name `tcpduplex`.

## Features

- **Duplex `Conn`**: `Send` / `Receive` (or context-aware variants), bounded queues, max message size.
- **Optional `OnMessage`**: callback delivery path; `Receive` is disabled when configured (see [`Config.OnMessage`](config.go)).
- **`context.Context`**: `DialContext`, `ServeConnContext`, `SendContext`, `ReceiveContext`, `Shutdown`, `Server.Serve`.
- **`Config`**: dial/handshake timeouts, protocol version, queue depths, PSK + peer fingerprint hooks.
- **`Server`**: `Listen` + `Serve` with per-connection `onConnect`.
- Subpackages [`tcpduplex/protocol`](protocol/) (framing, versioning) and [`tcpduplex/crypto`](crypto/) (handshake, AES-GCM session).

## Quick start

### Client

```go
conn, err := tcpduplex.Dial("127.0.0.1:9090")
if err != nil {
    log.Fatal(err)
}
defer conn.Close()

if err := conn.Send([]byte("hello")); err != nil {
    log.Fatal(err)
}
msg, err := conn.Receive()
if err != nil {
    log.Fatal(err)
}
log.Printf("got: %s", msg)
```

### Server (manual accept)

```go
ln, err := net.Listen("tcp", ":9090")
if err != nil {
    log.Fatal(err)
}
defer ln.Close()

nc, err := ln.Accept()
if err != nil {
    log.Fatal(err)
}
conn, err := tcpduplex.ServeConn(nc)
if err != nil {
    log.Fatal(err)
}
defer conn.Close()

msg, err := conn.Receive()
// ...
```

### Server helper (`Listen` + `Serve`)

```go
srv, err := tcpduplex.Listen("tcp", ":9090", nil)
if err != nil {
    log.Fatal(err)
}
defer srv.Close()

ctx, cancel := context.WithCancel(context.Background())
defer cancel()

go func() {
    _ = srv.Serve(ctx, func(peerCtx context.Context, c *tcpduplex.Conn) {
        defer c.Close()
        msg, err := c.ReceiveContext(peerCtx)
        if err != nil {
            return
        }
        _ = c.Send(msg)
    })
}()
```

Cancel `ctx` (or call `srv.Close()`) to unblock `Accept` and stop accepting new peers.

## Configuration

Pass a non-nil [`Config`](config.go) to `DialContext` / `ServeConnContext` / `Listen`:

| Field | Role |
|--------|------|
| `DialTimeout` | TCP dial budget (`DefaultConfig`: 30s). |
| `HandshakeTimeout` | Full ECDH exchange budget (default 15s). |
| `ProtocolVersion` | Client-advertised wire revision (must satisfy `protocol.SupportsVersion`). |
| `MaxMessageBytes` | Max decrypted application payload (default 512 KiB). |
| `SendQueueDepth` / `ReceiveQueueDepth` | Backpressure for send/receive channels. |
| `OnMessage` | Optional inbound handler; when set, `Receive` returns `ErrReceiveDisabled`. |
| `OnMessageBufferDepth` | Pending callback queue; full → drops counted via `Conn.CallbackDropped()` or disconnect if `DisconnectOnSlowCallbackConsumer`. |
| `Handshake.PreSharedKey` | Mixed into key derivation with ECDH output (both ends must match). |
| `Handshake.ExpectedPeerPubKeySHA256` | Optional `SHA256(raw X25519 pub key)` pin for the **peer** key observed on the wire. |

Use [`PeerPublicKeyFingerprint`](fingerprint.go) to compute the fingerprint from raw pubkey bytes.

Example with PSK:

```go
cfg := tcpduplex.DefaultConfig()
cfg.Handshake.PreSharedKey = []byte("rotate-this-secret")

cli, err := tcpduplex.DialContext(ctx, addr, cfg)
// server uses the same cfg (or matching Handshake) in ServeConnContext
```

## Graceful shutdown

- **`Conn.Close()`**: waits for the writer to flush (including a `MsgClose` record), stops delivery workers, closes TCP, waits for the reader to exit.
- **`Conn.Shutdown(ctx)`**: same pipeline but waits respect `ctx` (returns `ctx.Err()` if a deadline fires while waiting).

Calling `Close`/`Shutdown` more than once returns [`ErrClosed`](errors.go).

## Wire format (summary)

1. **Handshake (plaintext)**  
   Magic `TDX1`, `uint16` big-endian **protocol version**, 32-byte **X25519 public key**. Client sends first; server replies with the **same negotiated version** and its public key. Unsupported versions fail with [`protocol.ErrUnsupportedVersion`](protocol/protocol.go).

2. **Records**  
   `uint32` BE length (includes 1-byte type + sealed blob), type byte (`MsgText`, `MsgPing`, `MsgPong`, `MsgClose`), then **nonce ‖ ciphertext ‖ tag** from AES-GCM.

Details and constants live in package [`tcpduplex/protocol`](protocol/).

## Examples in this repo

| Path | Description |
|------|-------------|
| [`examples/simple`](examples/simple/main.go) | Minimal listen/dial round-trip. |
| [`cmd/server`](cmd/server/main.go) | Chat-style server using `Listen` + `Serve`. |
| [`cmd/client`](cmd/client/main.go) | Line-oriented client. |

```bash
go run ./examples/simple
go run ./cmd/server -listen :9090
go run ./cmd/client -addr 127.0.0.1:9090
```

## Documentation (godoc)

Package overviews for godoc:

- [`tcpduplex` package](doc.go) — `Conn`, dial/serve, server, config.
- [`tcpduplex/protocol`](protocol/doc.go) — framing and versioning.
- [`tcpduplex/crypto`](crypto/doc.go) — ECDH session and optional handshake auth.

Local viewing:

```bash
go doc -all .
go doc -all ./protocol
go doc -all ./crypto
```

Or run `pkgsite` / `godoc` against the module root.

## Security notes

- **Symmetric keys** derive from ECDH output; with **`PreSharedKey`**, material is mixed deterministically on both sides—peers must agree on the secret.
- **Fingerprint pinning** checks the peer’s **ephemeral** X25519 public key from the handshake (not a long-term identity certificate).
- For **authentication + integrity + PKI** on hostile networks, prefer **TLS** (or QUIC) and treat tcpduplex as a building block for controlled deployments.

## Testing

```bash
go test ./...
```
