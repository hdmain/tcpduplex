package tcpduplex

import (
	"crypto/sha256"
	"time"

	"github.com/hdmain/tcpduplex/crypto"
	"github.com/hdmain/tcpduplex/protocol"
)

const (
	defaultDialTimeout          = 30 * time.Second
	defaultHandshakeTimeout     = 15 * time.Second
	defaultMaxMessageBytes      = 512 << 10 // 512 KiB plaintext
	defaultSendQueueDepth       = 256
	defaultReceiveQueueDepth    = 256
	defaultOnMessageBufferDepth = 128
)

// HandshakeAuth configures optional authenticated ECDH (PSK mixing + optional peer fingerprint).
type HandshakeAuth struct {
	// PreSharedKey is mixed into the symmetric key derivation alongside ECDH output when non-empty.
	PreSharedKey []byte

	// ExpectedPeerPubKeySHA256, when non-nil, must equal SHA256(peer raw X25519 public key bytes).
	ExpectedPeerPubKeySHA256 *[sha256.Size]byte
}

// Config tunes transport timing, queue depths, protocol revision, and handshake authentication.
// A nil Config passed to DialContext/ServeConnContext is replaced by DefaultConfig().
type Config struct {
	// DialTimeout bounds net.Dialer.DialContext when establishing TCP (zero uses default).
	DialTimeout time.Duration

	// HandshakeTimeout bounds the ECDH handshake on the wire (zero uses default).
	HandshakeTimeout time.Duration

	// ProtocolVersion selects the wire revision advertised by the client. Must satisfy protocol.SupportsVersion.
	ProtocolVersion uint16

	// MaxMessageBytes caps decrypted plaintext application payloads (send + receive).
	MaxMessageBytes int

	// SendQueueDepth bounds the outbound channel (Send backpressure).
	SendQueueDepth int

	// ReceiveQueueDepth bounds Receive buffering when OnMessage is nil.
	ReceiveQueueDepth int

	// OnMessage, when non-nil, delivers inbound MsgText asynchronously without requiring Receive.
	// Receive and ReceiveContext return ErrReceiveDisabled in this mode.
	OnMessage func(payload []byte)

	// OnMessageBufferDepth bounds pending deliveries waiting for OnMessage (drop or disconnect when full).
	OnMessageBufferDepth int

	// DisconnectOnSlowCallbackConsumer tears down the session when OnMessageBufferDepth is exhausted.
	DisconnectOnSlowCallbackConsumer bool

	// Handshake configures optional pre-shared key mixing and fingerprint verification.
	Handshake HandshakeAuth
}

// DefaultConfig returns conservative production defaults.
func DefaultConfig() *Config {
	return &Config{
		DialTimeout:                      defaultDialTimeout,
		HandshakeTimeout:                 defaultHandshakeTimeout,
		ProtocolVersion:                  protocol.CurrentProtocolVersion,
		MaxMessageBytes:                  defaultMaxMessageBytes,
		SendQueueDepth:                   defaultSendQueueDepth,
		ReceiveQueueDepth:                defaultReceiveQueueDepth,
		OnMessageBufferDepth:             defaultOnMessageBufferDepth,
		DisconnectOnSlowCallbackConsumer: false,
	}
}

type frozenConfig struct {
	DialTimeout                      time.Duration
	HandshakeTimeout                 time.Duration
	ProtocolVersion                  uint16
	MaxMessageBytes                  int
	SendQueueDepth                   int
	ReceiveQueueDepth                int
	OnMessage                        func([]byte)
	OnMessageBufferDepth             int
	DisconnectOnSlowCallbackConsumer bool
	Handshake                        HandshakeAuth
}

func freezeConfig(cfg *Config) frozenConfig {
	var f frozenConfig
	if cfg == nil {
		d := DefaultConfig()
		cfg = d
	}
	f.DialTimeout = cfg.DialTimeout
	f.HandshakeTimeout = cfg.HandshakeTimeout
	f.ProtocolVersion = cfg.ProtocolVersion
	f.MaxMessageBytes = cfg.MaxMessageBytes
	f.SendQueueDepth = cfg.SendQueueDepth
	f.ReceiveQueueDepth = cfg.ReceiveQueueDepth
	f.OnMessage = cfg.OnMessage
	f.OnMessageBufferDepth = cfg.OnMessageBufferDepth
	f.DisconnectOnSlowCallbackConsumer = cfg.DisconnectOnSlowCallbackConsumer
	f.Handshake = cfg.Handshake

	if f.DialTimeout <= 0 {
		f.DialTimeout = defaultDialTimeout
	}
	if f.HandshakeTimeout <= 0 {
		f.HandshakeTimeout = defaultHandshakeTimeout
	}
	if f.ProtocolVersion == 0 {
		f.ProtocolVersion = protocol.CurrentProtocolVersion
	}
	if f.MaxMessageBytes <= 0 {
		f.MaxMessageBytes = defaultMaxMessageBytes
	}
	if f.SendQueueDepth <= 0 {
		f.SendQueueDepth = defaultSendQueueDepth
	}
	if f.ReceiveQueueDepth <= 0 {
		f.ReceiveQueueDepth = defaultReceiveQueueDepth
	}
	if f.OnMessage != nil && f.OnMessageBufferDepth <= 0 {
		f.OnMessageBufferDepth = defaultOnMessageBufferDepth
	}
	return f
}

func handshakeOpts(f frozenConfig) *crypto.HandshakeOpts {
	h := f.Handshake
	if len(h.PreSharedKey) == 0 && h.ExpectedPeerPubKeySHA256 == nil {
		return nil
	}
	return &crypto.HandshakeOpts{
		PreSharedKey:             append([]byte(nil), h.PreSharedKey...),
		ExpectedPeerPubKeySHA256: h.ExpectedPeerPubKeySHA256,
	}
}
