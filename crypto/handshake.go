package crypto

import (
	"bytes"
	"crypto/ecdh"
	"crypto/rand"
	"crypto/sha256"
	"errors"
	"fmt"
	"io"

	"github.com/hdmain/tcpduplex/protocol"
)

var (
	// ErrPeerFingerprintMismatch is returned when ExpectedPeerPubKeySHA256 does not match the peer handshake key.
	ErrPeerFingerprintMismatch = errors.New("crypto: peer public key fingerprint mismatch")

	// ErrHandshakeAuthenticationFailed wraps handshake-layer failures attributable to optional auth constraints.
	ErrHandshakeAuthenticationFailed = errors.New("crypto: handshake authentication failed")
)

func fingerprintSHA256(pubKey []byte) [sha256.Size]byte {
	return sha256.Sum256(pubKey)
}

func verifyPeerFingerprint(remotePub []byte, expected *[sha256.Size]byte) error {
	if expected == nil {
		return nil
	}
	sum := fingerprintSHA256(remotePub)
	if !bytes.Equal(sum[:], expected[:]) {
		return fmt.Errorf("%w", ErrPeerFingerprintMismatch)
	}
	return nil
}

// HandshakeOpts configures optional authenticated ECDH handshakes.
type HandshakeOpts struct {
	// PreSharedKey is mixed into the AEAD session key derivation alongside ECDH output when non-nil/non-empty.
	PreSharedKey []byte

	// ExpectedPeerPubKeySHA256, when non-nil, must equal SHA256(raw X25519 public key bytes received from the peer).
	ExpectedPeerPubKeySHA256 *[sha256.Size]byte
}

// CloneHandshakeOpts returns a shallow copy suitable for concurrent misuse avoidance when callers reuse structs.
func CloneHandshakeOpts(o *HandshakeOpts) *HandshakeOpts {
	if o == nil {
		return nil
	}
	cp := *o
	return &cp
}

// ClientHandshake completes the tcpduplex handshake from the initiator side.
func ClientHandshake(rw io.ReadWriter, negotiatedVersion uint16, opts *HandshakeOpts) (*Session, error) {
	priv, err := ecdh.X25519().GenerateKey(rand.Reader)
	if err != nil {
		return nil, err
	}
	if err := protocol.WriteHandshake(rw, negotiatedVersion, priv.PublicKey().Bytes()); err != nil {
		return nil, err
	}
	peerVer, peerPub, err := protocol.ReadHandshake(rw)
	if err != nil {
		return nil, err
	}
	if peerVer != negotiatedVersion {
		return nil, fmt.Errorf("%w: unexpected negotiated revision %d vs %d", ErrHandshakeAuthenticationFailed, peerVer, negotiatedVersion)
	}
	if opts != nil && opts.ExpectedPeerPubKeySHA256 != nil {
		if err := verifyPeerFingerprint(peerPub, opts.ExpectedPeerPubKeySHA256); err != nil {
			return nil, err
		}
	}
	remotePub, err := ecdh.X25519().NewPublicKey(peerPub)
	if err != nil {
		return nil, err
	}
	shared, err := priv.ECDH(remotePub)
	if err != nil {
		return nil, err
	}
	var psk []byte
	if opts != nil {
		psk = opts.PreSharedKey
	}
	return newSession(shared, psk)
}

// ServerHandshake completes the tcpduplex handshake from the listener side.
func ServerHandshake(rw io.ReadWriter, opts *HandshakeOpts) (*Session, uint16, error) {
	priv, err := ecdh.X25519().GenerateKey(rand.Reader)
	if err != nil {
		return nil, 0, err
	}
	peerVer, peerPub, err := protocol.ReadHandshake(rw)
	if err != nil {
		return nil, 0, err
	}
	if opts != nil && opts.ExpectedPeerPubKeySHA256 != nil {
		if err := verifyPeerFingerprint(peerPub, opts.ExpectedPeerPubKeySHA256); err != nil {
			return nil, 0, err
		}
	}
	remotePub, err := ecdh.X25519().NewPublicKey(peerPub)
	if err != nil {
		return nil, 0, err
	}
	shared, err := priv.ECDH(remotePub)
	if err != nil {
		return nil, 0, err
	}
	if err := protocol.WriteHandshake(rw, peerVer, priv.PublicKey().Bytes()); err != nil {
		return nil, 0, err
	}
	var psk []byte
	if opts != nil {
		psk = opts.PreSharedKey
	}
	sess, err := newSession(shared, psk)
	if err != nil {
		return nil, 0, err
	}
	return sess, peerVer, nil
}
