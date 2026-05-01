package tcpduplex

import (
	"crypto/sha256"
)

// PeerPublicKeyFingerprint returns SHA256(raw X25519 public key bytes) for use with HandshakeAuth.ExpectedPeerPubKeySHA256.
func PeerPublicKeyFingerprint(pubKey []byte) [sha256.Size]byte {
	return sha256.Sum256(pubKey)
}
