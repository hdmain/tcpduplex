// Package crypto implements the tcpduplex key exchange and symmetric session.
//
// ClientHandshake and ServerHandshake perform X25519 ECDH over the tcpduplex/protocol
// handshake framing. Optional HandshakeOpts can supply PreSharedKey material mixed into
// the AES-256-GCM key derivation, and ExpectedPeerPubKeySHA256 to pin the peer’s
// ephemeral public key (SHA256 over the raw 32-byte X25519 encoding).
//
// Session exposes Seal/Open for AES-GCM with random nonces; callers normally interact
// through tcpduplex.Conn, which serializes reads/writes with protocol.ReadRecord /
// protocol.WriteRecord.
package crypto
