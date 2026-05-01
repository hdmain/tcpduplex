package tcpduplex

import (
	"errors"
	"fmt"

	"github.com/hdmain/tcpduplex/crypto"
	"github.com/hdmain/tcpduplex/protocol"
)

// Sentinel errors returned by Conn and dial helpers.
var (
	ErrClosed          = errors.New("tcpduplex: connection closed")
	ErrReceiveDisabled = errors.New("tcpduplex: Receive unavailable while OnMessage is configured")

	// ErrMessageTooLarge is returned when a plaintext payload exceeds Config.MaxMessageBytes.
	ErrMessageTooLarge = errors.New("tcpduplex: message exceeds MaxMessageBytes")

	// ErrInboundDropped indicates inbound callback delivery could not accept more work (buffer full).
	ErrInboundDropped = errors.New("tcpduplex: inbound OnMessage buffer full")

	// ErrSlowConsumer is returned when DisconnectOnSlowCallbackConsumer is set and the inbound buffer fills.
	ErrSlowConsumer = errors.New("tcpduplex: disconnected due to slow OnMessage consumer")

	// ErrUnsupportedProtocol reports an incompatible peer revision during handshake validation.
	ErrUnsupportedProtocol = protocol.ErrUnsupportedVersion

	// ErrHandshakeAuthentication reports optional fingerprint / negotiation mismatch during handshake.
	ErrHandshakeAuthentication = crypto.ErrHandshakeAuthenticationFailed

	// ErrPeerFingerprintMismatch indicates ExpectedPeerPubKeySHA256 did not match the peer handshake key.
	ErrPeerFingerprintMismatch = crypto.ErrPeerFingerprintMismatch
)

// Error exposes stable helpers for classification without leaking internal packages everywhere.
type Error struct {
	Op  string
	Err error
}

func (e *Error) Error() string { return fmt.Sprintf("tcpduplex %s: %v", e.Op, e.Err) }
func (e *Error) Unwrap() error { return e.Err }

// Wrap wraps err as an OpError with operation context.
func Wrap(op string, err error) error {
	if err == nil {
		return nil
	}
	return &Error{Op: op, Err: err}
}
