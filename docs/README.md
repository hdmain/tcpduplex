# tcpduplex documentation

- **[Project README](../README.md)** — installation, quick start, configuration table, wire-format summary, examples, security notes.
- **Godoc** — package-level docs live next to the code:
  - [`tcpduplex/doc.go`](../doc.go) — `Conn`, dialing, server, shutdown.
  - [`protocol/doc.go`](../protocol/doc.go) — handshake and record framing.
  - [`crypto/doc.go`](../crypto/doc.go) — ECDH, optional PSK/fingerprint, `Session`.

From the repository root:

```bash
go doc -all .
go doc -all ./protocol
go doc -all ./crypto
```

For a browser UI (optional):

```bash
go install golang.org/x/pkgsite/cmd/pkgsite@latest
pkgsite -http=:6060
```

Then open the module path shown in `go.mod`.
