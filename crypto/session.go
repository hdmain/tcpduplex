package crypto

import (
	"crypto/aes"
	"crypto/cipher"
	"crypto/rand"
	"crypto/sha256"
	"encoding/binary"
	"io"

	"github.com/hdmain/tcpduplex/protocol"
)

// Session holds AES-GCM state derived from ECDH (optionally mixed with PSK material).
type Session struct {
	gcm cipher.AEAD
}

func deriveSessionKey(sharedSecret []byte, psk []byte) []byte {
	if len(psk) == 0 {
		sum := sha256.Sum256(sharedSecret)
		return sum[:]
	}
	h := sha256.New()
	_, _ = h.Write(sharedSecret)
	_, _ = h.Write([]byte{0})
	var lb [4]byte
	binary.BigEndian.PutUint32(lb[:], uint32(len(psk)))
	_, _ = h.Write(lb[:])
	_, _ = h.Write(psk)
	sum := h.Sum(nil)
	return sum[:]
}

func newSession(sharedSecret []byte, psk []byte) (*Session, error) {
	key := deriveSessionKey(sharedSecret, psk)
	block, err := aes.NewCipher(key)
	if err != nil {
		return nil, err
	}
	gcm, err := cipher.NewGCM(block)
	if err != nil {
		return nil, err
	}
	return &Session{gcm: gcm}, nil
}

// Seal encrypts plaintext and returns nonce || ciphertext || tag.
func (s *Session) Seal(plaintext []byte) ([]byte, error) {
	maxSeal := protocol.MaxRecordPayload - 1
	if s.gcm.NonceSize()+s.gcm.Overhead()+len(plaintext) > maxSeal {
		return nil, protocol.ErrBadFrame
	}
	nonce := make([]byte, s.gcm.NonceSize())
	if _, err := io.ReadFull(rand.Reader, nonce); err != nil {
		return nil, err
	}
	dst := make([]byte, 0, len(nonce)+len(plaintext)+s.gcm.Overhead())
	dst = append(dst, nonce...)
	return s.gcm.Seal(dst, nonce, plaintext, nil), nil
}

// Open decrypts a blob produced by Seal.
func (s *Session) Open(sealed []byte) ([]byte, error) {
	ns := s.gcm.NonceSize()
	if len(sealed) < ns+s.gcm.Overhead() {
		return nil, protocol.ErrBadFrame
	}
	nonce := sealed[:ns]
	return s.gcm.Open(nil, nonce, sealed[ns:], nil)
}
