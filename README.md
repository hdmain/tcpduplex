# tcpduplex

**Repository:** [https://github.com/hdmain/tcpduplex](https://github.com/hdmain/tcpduplex)

**tcpduplex** is a small Go library for **encrypted full-duplex messaging over TCP**: X25519 ECDH, AES-256-GCM, length-prefixed records, and concurrent read/write loops. It is **not** TLS and does **not** replace certificate-based authentication for the public internet; it suits private networks, constrained environments, or protocols where you control both peers.

## Requirements

- Go **1.22+**

## Install

```bash
go get github.com/hdmain/tcpduplex
```

Module path: [`github.com/hdmain/tcpduplex`](https://github.com/hdmain/tcpduplex) (see [`go.mod`](go.mod)). For a **local checkout**, point consumers at it with a `replace` directive if needed.

```go
import "github.com/hdmain/tcpduplex"
```

## Features

- **Duplex `Conn`**: `Send` / `Receive` (or context-aware variants), bounded queues, max message size.
- **Optional `OnMessage`**: callback delivery path; `Receive` is disabled when configured (see [`Config.OnMessage`](config.go)).
- **`context.Context`**: `DialContext`, `ServeConnContext`, `SendContext`, `ReceiveContext`, `Shutdown`, `Server.Serve`.
- **`Config`**: dial/handshake timeouts, protocol version, queue depths, PSK + peer fingerprint hooks.
- **`Server`**: `Listen` + `Serve` with per-connection `onConnect`.
- Subpackages [`github.com/hdmain/tcpduplex/protocol`](protocol/) (framing, versioning), [`github.com/hdmain/tcpduplex/crypto`](crypto/) (handshake, AES-GCM session), and [`github.com/hdmain/tcpduplex/transfer`](transfer/) (encrypted resumable file transfers).
- **Encrypted file transfer**: chunked, windowed sends over the existing AES-GCM session; automatic resume from the last acknowledged offset when `Options.Redial` reconnects after an interrupt.

## Quick start

### Client

```go
import "github.com/hdmain/tcpduplex"

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
import (
    "net"

    "github.com/hdmain/tcpduplex"
)

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
import (
    "context"

    "github.com/hdmain/tcpduplex"
)

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

## Encrypted file transfer

Package [`transfer`](transfer/) copies files or `io.ReaderAt` streams over a `Conn`. Data is encrypted by the session (no second cipher layer). Large chunks plus a sliding ACK window keep the pipe full.

```go
import (
    "context"

    "github.com/hdmain/tcpduplex"
    "github.com/hdmain/tcpduplex/transfer"
)

// sender
err := transfer.SendFile(ctx, conn, "/path/to/file", &transfer.Options{
    ChunkSize: 256 << 10, // fit under Config.MaxMessageBytes
    Window:    32,        // unacked chunks in flight
    Redial: func(ctx context.Context) (*tcpduplex.Conn, error) {
        return tcpduplex.DialContext(ctx, addr, cfg)
    },
})

// receiver (resumes if dest already has a prefix of the file)
meta, err := transfer.ReceiveFile(ctx, conn, "/path/to/dest", &transfer.Options{
    Redial: func(ctx context.Context) (*tcpduplex.Conn, error) {
        // accept/handshake a replacement Conn
        return nextConn, nil
    },
})
```

Each transfer has a stable 16-byte ID. After a drop, both sides redial, the sender re-offers the same ID, the receiver reports how many bytes it already has, and the sender continues from that offset—already written data is kept.

While a transfer is running, do not use the same `Conn` for other `Send`/`Receive` traffic (frames share `MsgText`).

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
import "github.com/hdmain/tcpduplex"

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

Details and constants live in package [`github.com/hdmain/tcpduplex/protocol`](protocol/).

## Examples in this repo

| Path | Description |
|------|-------------|
| [`examples/simple`](https://github.com/hdmain/tcpduplex/tree/main/examples/simple) | Minimal listen/dial round-trip. |
| [`examples/transfer`](https://github.com/hdmain/tcpduplex/tree/main/examples/transfer) | Encrypted file send/receive. |
| [`cmd/server`](https://github.com/hdmain/tcpduplex/tree/main/cmd/server) | Chat-style server using `Listen` + `Serve`. |
| [`cmd/client`](https://github.com/hdmain/tcpduplex/tree/main/cmd/client) | Line-oriented client. |

```bash
go run ./examples/simple
go run ./examples/transfer
go run ./cmd/server -listen :9090
go run ./cmd/client -addr 127.0.0.1:9090
```

## Documentation (godoc)

Package overviews for godoc ([pkg.go.dev/github.com/hdmain/tcpduplex](https://pkg.go.dev/github.com/hdmain/tcpduplex)):

- [`github.com/hdmain/tcpduplex`](doc.go) — `Conn`, dial/serve, server, config.
- [`github.com/hdmain/tcpduplex/protocol`](protocol/doc.go) — framing and versioning.
- [`github.com/hdmain/tcpduplex/crypto`](crypto/doc.go) — ECDH session and optional handshake auth.
- [`github.com/hdmain/tcpduplex/transfer`](transfer/doc.go) — encrypted resumable file transfers.

Local viewing:

```bash
go doc -all .
go doc -all ./protocol
go doc -all ./crypto
go doc -all ./transfer
```

Or run `pkgsite` / `godoc` against the module root ([github.com/hdmain/tcpduplex](https://github.com/hdmain/tcpduplex)).

## Security notes

- **Symmetric keys** derive from ECDH output; with **`PreSharedKey`**, material is mixed deterministically on both sides—peers must agree on the secret.
- **Fingerprint pinning** checks the peer’s **ephemeral** X25519 public key from the handshake (not a long-term identity certificate).
- For **authentication + integrity + PKI** on hostile networks, prefer **TLS** (or QUIC) and treat tcpduplex as a building block for controlled deployments.

## Testing

```bash
go test ./...
```
