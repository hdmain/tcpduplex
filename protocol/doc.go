// Package protocol defines the tcpduplex wire encoding: handshake preamble and
// length-prefixed encrypted records.
//
// Handshake records are plaintext: magic bytes "TDX1", a uint16 big-endian protocol
// revision (see CurrentProtocolVersion and SupportsVersion), and a 32-byte X25519
// public key. Unsupported revisions are rejected with ErrUnsupportedVersion.
//
// Application records are uint32 length (big-endian), a one-byte message type
// (MsgText, MsgPing, MsgPong, MsgClose), followed by the AEAD sealed payload
// (nonce || ciphertext || tag) as produced by tcpduplex/crypto.Session.
//
// MaxRecordPayload caps the length field to mitigate allocation abuse on hostile peers.
package protocol
