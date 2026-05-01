// Package tcpduplex provides encrypted full-duplex messaging over TCP using X25519 ECDH
// followed by AES-256-GCM record encryption.
//
// Entry points:
//   - Dial / DialContext — TCP client plus handshake; returns *Conn.
//   - ServeConn / ServeConnContext — server handshake on an accepted net.Conn; returns *Conn.
//   - Listen + (*Server).Serve — convenience accept loop with per-connection handlers.
//
// A Conn multiplexes a reader goroutine (decrypt, dispatch to Receive or OnMessage)
// and a writer goroutine (encrypt, flush, graceful MsgClose). Use SendContext and
// ReceiveContext for cancellation and deadlines; Close / Shutdown tear down the session.
//
// Optional authentication uses Config.Handshake: PreSharedKey mixing and/or
// ExpectedPeerPubKeySHA256 (SHA256 of raw peer X25519 public key bytes).
//
// Subpackages protocol (wire format, versioning) and crypto (handshake, Session) are
// layered deliberately so framing and cryptography stay testable in isolation.
package tcpduplex
