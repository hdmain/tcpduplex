# tcpduplex documentation

**Repository:** [https://github.com/hdmain/tcpduplex](https://github.com/hdmain/tcpduplex)

- **[Project README](../README.md)** — installation, quick start, configuration table, wire-format summary, examples, security notes.
- **Godoc** — [pkg.go.dev/github.com/hdmain/tcpduplex](https://pkg.go.dev/github.com/hdmain/tcpduplex); package-level docs live next to the code:
  - [`github.com/hdmain/tcpduplex`](../doc.go) — `Conn`, dialing, server, shutdown.
  - [`github.com/hdmain/tcpduplex/protocol`](../protocol/doc.go) — handshake and record framing.
  - [`github.com/hdmain/tcpduplex/crypto`](../crypto/doc.go) — ECDH, optional PSK/fingerprint, `Session`.
  - [`github.com/hdmain/tcpduplex/transfer`](../transfer/doc.go) — encrypted resumable file/stream transfers.

From the repository root:

```bash
go doc -all .
go doc -all ./protocol
go doc -all ./crypto
go doc -all ./transfer
```

For a browser UI (optional):

```bash
go install golang.org/x/pkgsite/cmd/pkgsite@latest
pkgsite -http=:6060
```

Then open [`github.com/hdmain/tcpduplex`](https://github.com/hdmain/tcpduplex).
