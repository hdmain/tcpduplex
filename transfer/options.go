package transfer

import (
	"context"

	"github.com/hdmain/tcpduplex"
)

const (
	defaultChunkSize = 256 << 10 // 256 KiB
	defaultWindow    = 32
	defaultAckEvery  = 8
	defaultAttempts  = 8
	chunkOverhead    = chunkFixedLen // magic+type+id+offset
)

// Options tunes throughput, resume, and reconnect behavior.
// A nil Options passed to Send/Receive is replaced by DefaultOptions().
type Options struct {
	// ChunkSize is the max plaintext data bytes per chunk frame (before the
	// transfer header). Zero selects a size that fits under Conn.MaxMessageBytes.
	ChunkSize int

	// Window is the maximum number of unacknowledged chunks in flight.
	// Larger windows hide latency; zero uses DefaultOptions.
	Window int

	// AckEvery is how many chunks the receiver processes before sending a
	// cumulative ACK (also ACKs on last chunk). Zero uses DefaultOptions.
	AckEvery int

	// Redial, when set, is called after a connection failure to obtain a fresh
	// Conn so the transfer can resume from the last acknowledged offset.
	Redial func(ctx context.Context) (*tcpduplex.Conn, error)

	// MaxAttempts bounds connection attempts including the first (0 → default).
	MaxAttempts int

	// OnProgress is invoked with (bytesConfirmedOrWritten, totalSize) as the
	// transfer advances. May be called from the Send/Receive goroutine.
	OnProgress func(transferred, total int64)

	// Accept, when set on the receiver, is called with the offer Meta before
	// Accept is sent. Returning a non-nil error rejects the offer.
	Accept func(meta Meta) error
}

// DefaultOptions returns throughput-oriented defaults suitable for LAN/WAN.
func DefaultOptions() *Options {
	return &Options{
		ChunkSize:   defaultChunkSize,
		Window:      defaultWindow,
		AckEvery:    defaultAckEvery,
		MaxAttempts: defaultAttempts,
	}
}

func normalizeOptions(opts *Options) *Options {
	d := DefaultOptions()
	if opts == nil {
		return d
	}
	out := *opts
	if out.ChunkSize <= 0 {
		out.ChunkSize = d.ChunkSize
	}
	if out.Window <= 0 {
		out.Window = d.Window
	}
	if out.AckEvery <= 0 {
		out.AckEvery = d.AckEvery
	}
	if out.MaxAttempts <= 0 {
		out.MaxAttempts = d.MaxAttempts
	}
	return &out
}

func effectiveChunkSize(conn *tcpduplex.Conn, want int) int {
	max := conn.MaxMessageBytes() - chunkOverhead
	if max < 1 {
		max = 1
	}
	if want <= 0 || want > max {
		return max
	}
	return want
}
