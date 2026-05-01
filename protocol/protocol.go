package protocol

import (
	"bytes"
	"encoding/binary"
	"errors"
	"fmt"
	"io"
)

// Message types carried in the cleartext type byte (outside the ciphertext).
const (
	MsgText  uint8 = 1
	MsgPing  uint8 = 2
	MsgPong  uint8 = 3
	MsgClose uint8 = 4
)

const handshakeMagicLen = 4

var handshakeMagic = []byte{'T', 'D', 'X', '1'}

// CurrentProtocolVersion is the preferred protocol revision tcpduplex library implementations negotiate first.
const CurrentProtocolVersion uint16 = 1

// X25519PubKeyLen is the encoded length of an X25519 public key on the wire.
const X25519PubKeyLen = 32

// MaxRecordPayload is the maximum value of (1 + len(sealed)) on the wire.
const MaxRecordPayload = 1 << 20

var (
	ErrBadHandshake       = errors.New("protocol: invalid handshake")
	ErrBadFrame           = errors.New("protocol: invalid frame")
	ErrUnsupportedVersion = errors.New("protocol: unsupported protocol version")
)

// SupportsVersion reports whether v may be used as the negotiated wire revision for handshakes and framing.
func SupportsVersion(v uint16) bool {
	switch v {
	case 1:
		return true
	default:
		return false
	}
}

func validateVersion(v uint16) error {
	if SupportsVersion(v) {
		return nil
	}
	return fmt.Errorf("%w: %d", ErrUnsupportedVersion, v)
}

// WriteHandshake writes magic || negotiated protocol version || X25519 public key.
func WriteHandshake(w io.Writer, negotiatedVersion uint16, pubKey []byte) error {
	if err := validateVersion(negotiatedVersion); err != nil {
		return err
	}
	var hdr [2 + handshakeMagicLen]byte
	copy(hdr[:], handshakeMagic)
	binary.BigEndian.PutUint16(hdr[handshakeMagicLen:], negotiatedVersion)
	if _, err := w.Write(hdr[:]); err != nil {
		return err
	}
	if len(pubKey) != X25519PubKeyLen {
		return ErrBadHandshake
	}
	_, err := w.Write(pubKey)
	return err
}

// ReadHandshake reads and validates magic + declared peer protocol revision + public key.
func ReadHandshake(r io.Reader) (protocolVersion uint16, pubKey []byte, err error) {
	var magic [handshakeMagicLen]byte
	if err := readFull(r, magic[:]); err != nil {
		return 0, nil, err
	}
	if !bytes.Equal(magic[:], handshakeMagic) {
		return 0, nil, ErrBadHandshake
	}
	var ver [2]byte
	if err := readFull(r, ver[:]); err != nil {
		return 0, nil, err
	}
	protocolVersion = binary.BigEndian.Uint16(ver[:])
	if err := validateVersion(protocolVersion); err != nil {
		return 0, nil, err
	}
	pubKey = make([]byte, X25519PubKeyLen)
	if err := readFull(r, pubKey); err != nil {
		return 0, nil, err
	}
	return protocolVersion, pubKey, nil
}

func readFull(r io.Reader, buf []byte) error {
	_, err := io.ReadFull(r, buf)
	return err
}

// ReadRecord reads length || type || sealed (nonce||ciphertext||tag).
func ReadRecord(r io.Reader) (msgType uint8, sealed []byte, err error) {
	var lenBuf [4]byte
	if err := readFull(r, lenBuf[:]); err != nil {
		return 0, nil, err
	}
	n := binary.BigEndian.Uint32(lenBuf[:])
	if n == 0 || n > MaxRecordPayload {
		return 0, nil, ErrBadFrame
	}
	payload := make([]byte, n)
	if err := readFull(r, payload); err != nil {
		return 0, nil, err
	}
	msgType = payload[0]
	sealed = payload[1:]
	return msgType, sealed, nil
}

// WriteRecord writes length || type || sealed.
func WriteRecord(w io.Writer, msgType uint8, sealed []byte) error {
	if len(sealed) > MaxRecordPayload-1 {
		return ErrBadFrame
	}
	n := uint32(1 + len(sealed))
	var lenBuf [4]byte
	binary.BigEndian.PutUint32(lenBuf[:], n)
	if _, err := w.Write(lenBuf[:]); err != nil {
		return err
	}
	var hdr [1]byte
	hdr[0] = msgType
	if _, err := w.Write(hdr[:]); err != nil {
		return err
	}
	_, err := w.Write(sealed)
	return err
}
