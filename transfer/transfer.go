package transfer

import (
	"context"
	"crypto/sha256"
	"errors"
	"fmt"
	"hash"
	"io"
	"os"

	"github.com/hdmain/tcpduplex"
)

// Send transfers size bytes from r (ReaderAt) to the peer over conn.
// Encryption is provided by the underlying tcpduplex session.
//
// If the connection fails mid-transfer and opts.Redial is set, Send dials a new
// Conn, re-offers the same transfer ID, and continues from the peer's resume
// offset so already-acked data is not retransmitted.
func Send(ctx context.Context, conn *tcpduplex.Conn, r io.ReaderAt, meta Meta, opts *Options) error {
	opts = normalizeOptions(opts)
	if meta.Size < 0 {
		return ErrSizeMismatch
	}
	if meta.ID == (ID{}) {
		id, err := NewID()
		if err != nil {
			return err
		}
		meta.ID = id
	}
	if isZeroHash(meta.Hash) {
		h, err := hashReaderAt(r, meta.Size)
		if err != nil {
			return err
		}
		meta.Hash = h
	}

	attempts := 0
	var lastErr error
	for {
		attempts++
		if attempts > opts.MaxAttempts {
			if lastErr != nil {
				return fmt.Errorf("%w: %v", ErrTooManyRetries, lastErr)
			}
			return ErrTooManyRetries
		}
		if err := ctx.Err(); err != nil {
			return err
		}

		err := sendOnce(ctx, conn, r, meta, opts)
		if err == nil {
			return nil
		}
		lastErr = err
		if opts.Redial == nil || !isRetriable(err) {
			return err
		}
		next, dialErr := opts.Redial(ctx)
		if dialErr != nil {
			return fmt.Errorf("transfer: redial: %w", dialErr)
		}
		conn = next
	}
}

// SendFile opens path and sends its contents (name = base name).
func SendFile(ctx context.Context, conn *tcpduplex.Conn, path string, opts *Options) error {
	f, err := os.Open(path)
	if err != nil {
		return err
	}
	defer f.Close()
	st, err := f.Stat()
	if err != nil {
		return err
	}
	meta := Meta{
		Name: pathBase(path),
		Size: st.Size(),
	}
	return Send(ctx, conn, f, meta, opts)
}

func sendOnce(ctx context.Context, conn *tcpduplex.Conn, r io.ReaderAt, meta Meta, opts *Options) error {
	chunkSize := effectiveChunkSize(conn, opts.ChunkSize)

	offer, err := encodeOffer(meta)
	if err != nil {
		return err
	}
	if err := conn.SendContext(ctx, offer); err != nil {
		return err
	}

	msg, err := conn.ReceiveContext(ctx)
	if err != nil {
		return mapConnErr(err)
	}
	dec, err := decodeFrame(msg)
	if err != nil {
		return err
	}
	switch dec.typ {
	case typeReject:
		if dec.id != meta.ID {
			return ErrBadFrame
		}
		if dec.reason != "" {
			return fmt.Errorf("%w: %s", ErrRejected, dec.reason)
		}
		return ErrRejected
	case typeAccept:
		if dec.id != meta.ID {
			return ErrBadFrame
		}
	default:
		return ErrBadFrame
	}

	offset := dec.offset
	if offset < 0 || offset > meta.Size {
		return ErrResumePastEnd
	}
	if opts.OnProgress != nil {
		opts.OnProgress(offset, meta.Size)
	}
	if offset == meta.Size {
		return finishSend(ctx, conn, meta)
	}

	acked := offset
	nextOff := offset
	buf := make([]byte, chunkSize)

	for acked < meta.Size {
		for countInFlight(acked, nextOff, chunkSize) < opts.Window && nextOff < meta.Size {
			n := int64(chunkSize)
			if nextOff+n > meta.Size {
				n = meta.Size - nextOff
			}
			if err := readFullAt(r, buf[:n], nextOff); err != nil {
				return err
			}
			frame := encodeChunk(meta.ID, nextOff, buf[:n])
			if err := conn.SendContext(ctx, frame); err != nil {
				return mapConnErr(err)
			}
			nextOff += n
		}

		msg, err := conn.ReceiveContext(ctx)
		if err != nil {
			return mapConnErr(err)
		}
		dec, err := decodeFrame(msg)
		if err != nil {
			return err
		}
		switch dec.typ {
		case typeAck:
			if dec.id != meta.ID {
				return ErrBadFrame
			}
			if dec.offset < acked || dec.offset > nextOff {
				return ErrBadFrame
			}
			acked = dec.offset
			if opts.OnProgress != nil {
				opts.OnProgress(acked, meta.Size)
			}
		case typeAbort:
			if dec.id != meta.ID {
				return ErrBadFrame
			}
			if dec.reason != "" {
				return fmt.Errorf("%w: %s", ErrAborted, dec.reason)
			}
			return ErrAborted
		default:
			return ErrBadFrame
		}
	}

	return finishSend(ctx, conn, meta)
}

func countInFlight(acked, nextOff int64, chunkSize int) int {
	if nextOff <= acked {
		return 0
	}
	remain := nextOff - acked
	cs := int64(chunkSize)
	return int((remain + cs - 1) / cs)
}

func finishSend(ctx context.Context, conn *tcpduplex.Conn, meta Meta) error {
	if err := conn.SendContext(ctx, encodeDone(meta.ID, true, meta.Hash)); err != nil {
		return mapConnErr(err)
	}
	msg, err := conn.ReceiveContext(ctx)
	if err != nil {
		return mapConnErr(err)
	}
	dec, err := decodeFrame(msg)
	if err != nil {
		return err
	}
	if dec.typ != typeDone || dec.id != meta.ID {
		return ErrBadFrame
	}
	if !dec.ok {
		return ErrHashMismatch
	}
	return nil
}

// Receive accepts one transfer from the peer and writes bytes into w at absolute
// offsets. resumeOffset is how many contiguous bytes from the start are already
// present (typically the size of a partial file); the sender will skip them.
//
// w should also implement io.ReaderAt when resumeOffset > 0 or content hashing
// is required (os.File satisfies this). Bytes already present are hashed from
// ReaderAt; new bytes are hashed as they arrive.
//
// With opts.Redial, if the connection drops, Receive redials, waits for the same
// offer ID again, and continues writing from the new resume offset.
func Receive(ctx context.Context, conn *tcpduplex.Conn, w io.WriterAt, resumeOffset int64, opts *Options) (Meta, error) {
	opts = normalizeOptions(opts)
	if resumeOffset < 0 {
		return Meta{}, ErrResumePastEnd
	}

	var meta Meta
	var haveMeta bool
	written := resumeOffset
	attempts := 0
	var lastErr error

	for {
		attempts++
		if attempts > opts.MaxAttempts {
			if lastErr != nil {
				return meta, fmt.Errorf("%w: %v", ErrTooManyRetries, lastErr)
			}
			return meta, ErrTooManyRetries
		}
		if err := ctx.Err(); err != nil {
			return meta, err
		}

		m, n, err := receiveOnce(ctx, conn, w, written, haveMeta, meta, opts)
		if err == nil {
			return m, nil
		}
		lastErr = err
		if m.ID != (ID{}) {
			meta = m
			haveMeta = true
		}
		if n > written {
			written = n
		}
		if opts.Redial == nil || !isRetriable(err) {
			return meta, err
		}
		next, dialErr := opts.Redial(ctx)
		if dialErr != nil {
			return meta, fmt.Errorf("transfer: redial: %w", dialErr)
		}
		conn = next
	}
}

func receiveOnce(
	ctx context.Context,
	conn *tcpduplex.Conn,
	w io.WriterAt,
	resumeOffset int64,
	expectMeta bool,
	want Meta,
	opts *Options,
) (Meta, int64, error) {
	msg, err := conn.ReceiveContext(ctx)
	if err != nil {
		return want, resumeOffset, mapConnErr(err)
	}
	dec, err := decodeFrame(msg)
	if err != nil {
		return want, resumeOffset, err
	}
	if dec.typ != typeOffer {
		return want, resumeOffset, ErrBadFrame
	}
	meta := dec.meta
	if expectMeta && meta.ID != want.ID {
		_ = conn.SendContext(ctx, encodeReject(meta.ID, "unexpected transfer id"))
		return want, resumeOffset, ErrBadFrame
	}
	if resumeOffset > meta.Size {
		_ = conn.SendContext(ctx, encodeReject(meta.ID, "resume past end"))
		return meta, resumeOffset, ErrResumePastEnd
	}
	if opts.Accept != nil {
		if err := opts.Accept(meta); err != nil {
			_ = conn.SendContext(ctx, encodeReject(meta.ID, err.Error()))
			return meta, resumeOffset, fmt.Errorf("%w: %v", ErrRejected, err)
		}
	}
	if err := conn.SendContext(ctx, encodeAccept(meta.ID, resumeOffset)); err != nil {
		return meta, resumeOffset, mapConnErr(err)
	}

	if opts.OnProgress != nil {
		opts.OnProgress(resumeOffset, meta.Size)
	}
	if resumeOffset == meta.Size {
		return finalizeReceive(ctx, conn, w, meta, resumeOffset, nil)
	}

	hw, err := newHashingWriter(w, resumeOffset)
	if err != nil {
		_ = conn.SendContext(ctx, encodeAbort(meta.ID, err.Error()))
		return meta, resumeOffset, err
	}

	written := resumeOffset
	chunksSinceAck := 0

	for written < meta.Size {
		msg, err := conn.ReceiveContext(ctx)
		if err != nil {
			return meta, written, mapConnErr(err)
		}
		dec, err := decodeFrame(msg)
		if err != nil {
			return meta, written, err
		}
		switch dec.typ {
		case typeChunk:
			if dec.id != meta.ID {
				return meta, written, ErrBadFrame
			}
			if dec.offset != written {
				return meta, written, ErrBadFrame
			}
			if dec.offset+int64(len(dec.data)) > meta.Size {
				return meta, written, ErrBadFrame
			}
			if _, err := hw.WriteAt(dec.data, dec.offset); err != nil {
				_ = conn.SendContext(ctx, encodeAbort(meta.ID, err.Error()))
				return meta, written, err
			}
			written = dec.offset + int64(len(dec.data))
			chunksSinceAck++
			if opts.OnProgress != nil {
				opts.OnProgress(written, meta.Size)
			}
			if chunksSinceAck >= opts.AckEvery || written == meta.Size {
				if err := conn.SendContext(ctx, encodeAck(meta.ID, written)); err != nil {
					return meta, written, mapConnErr(err)
				}
				chunksSinceAck = 0
			}
		case typeDone:
			if dec.id != meta.ID {
				return meta, written, ErrBadFrame
			}
			if written != meta.Size {
				return meta, written, ErrSizeMismatch
			}
			return verifyAndAckDone(ctx, conn, meta, written, dec, hw.sum())
		case typeAbort:
			if dec.id != meta.ID {
				return meta, written, ErrBadFrame
			}
			if dec.reason != "" {
				return meta, written, fmt.Errorf("%w: %s", ErrAborted, dec.reason)
			}
			return meta, written, ErrAborted
		default:
			return meta, written, ErrBadFrame
		}
	}

	msg, err = conn.ReceiveContext(ctx)
	if err != nil {
		return meta, written, mapConnErr(err)
	}
	dec, err = decodeFrame(msg)
	if err != nil {
		return meta, written, err
	}
	if dec.typ != typeDone || dec.id != meta.ID {
		return meta, written, ErrBadFrame
	}
	return verifyAndAckDone(ctx, conn, meta, written, dec, hw.sum())
}

func finalizeReceive(
	ctx context.Context,
	conn *tcpduplex.Conn,
	w io.WriterAt,
	meta Meta,
	written int64,
	_ *hashingWriter,
) (Meta, int64, error) {
	var sum [32]byte
	hw, err := newHashingWriter(w, written)
	if err != nil {
		// Nothing to write; try ReaderAt hash of full content.
		if h, herr := hashWriterAt(w, meta.Size); herr == nil {
			sum = h
		} else {
			return meta, written, herr
		}
	} else {
		sum = hw.sum()
	}
	msg, err := conn.ReceiveContext(ctx)
	if err != nil {
		return meta, written, mapConnErr(err)
	}
	dec, err := decodeFrame(msg)
	if err != nil {
		return meta, written, err
	}
	if dec.typ != typeDone || dec.id != meta.ID {
		return meta, written, ErrBadFrame
	}
	return verifyAndAckDone(ctx, conn, meta, written, dec, sum)
}

func verifyAndAckDone(
	ctx context.Context,
	conn *tcpduplex.Conn,
	meta Meta,
	written int64,
	dec decoded,
	local [32]byte,
) (Meta, int64, error) {
	ok := true
	expect := meta.Hash
	if isZeroHash(expect) {
		expect = dec.hash
	}
	if !isZeroHash(expect) && local != expect {
		ok = false
	}
	if !isZeroHash(dec.hash) && dec.hash != local {
		ok = false
	}
	if err := conn.SendContext(ctx, encodeDone(meta.ID, ok, local)); err != nil {
		return meta, written, mapConnErr(err)
	}
	if !ok {
		return meta, written, ErrHashMismatch
	}
	return meta, written, nil
}

// ReceiveFile receives one transfer into destPath. If destPath already exists
// with a smaller size than offered, the transfer resumes by appending from that
// length.
func ReceiveFile(ctx context.Context, conn *tcpduplex.Conn, destPath string, opts *Options) (Meta, error) {
	opts = normalizeOptions(opts)

	var resume int64
	if st, err := os.Stat(destPath); err == nil {
		resume = st.Size()
	} else if !os.IsNotExist(err) {
		return Meta{}, err
	}

	f, err := os.OpenFile(destPath, os.O_CREATE|os.O_RDWR, 0o644)
	if err != nil {
		return Meta{}, err
	}
	defer f.Close()

	meta, err := Receive(ctx, conn, f, resume, opts)
	if err != nil {
		return meta, err
	}
	if err := f.Truncate(meta.Size); err != nil {
		return meta, err
	}
	if err := f.Sync(); err != nil {
		return meta, err
	}
	return meta, nil
}

type hashingWriter struct {
	w      io.WriterAt
	h      hash.Hash
	offset int64
}

func newHashingWriter(w io.WriterAt, resumeOffset int64) (*hashingWriter, error) {
	h := sha256.New()
	if resumeOffset > 0 {
		ra, ok := w.(io.ReaderAt)
		if !ok {
			return nil, fmt.Errorf("transfer: WriterAt must implement ReaderAt to resume or verify")
		}
		if err := copyHash(h, ra, resumeOffset); err != nil {
			return nil, err
		}
	}
	return &hashingWriter{w: w, h: h, offset: resumeOffset}, nil
}

func (hw *hashingWriter) WriteAt(p []byte, off int64) (int, error) {
	if off != hw.offset {
		return 0, ErrBadFrame
	}
	n, err := hw.w.WriteAt(p, off)
	if n > 0 {
		_, _ = hw.h.Write(p[:n])
		hw.offset += int64(n)
	}
	return n, err
}

func (hw *hashingWriter) sum() [32]byte {
	var out [32]byte
	copy(out[:], hw.h.Sum(nil))
	return out
}

func readFullAt(r io.ReaderAt, buf []byte, off int64) error {
	var got int
	for got < len(buf) {
		n, err := r.ReadAt(buf[got:], off+int64(got))
		got += n
		if err != nil {
			if errors.Is(err, io.EOF) {
				if got == len(buf) {
					return nil
				}
				return io.ErrUnexpectedEOF
			}
			return err
		}
		if n == 0 {
			return io.ErrUnexpectedEOF
		}
	}
	return nil
}

func hashReaderAt(r io.ReaderAt, size int64) ([32]byte, error) {
	var out [32]byte
	h := sha256.New()
	if err := copyHash(h, r, size); err != nil {
		return out, err
	}
	copy(out[:], h.Sum(nil))
	return out, nil
}

func hashWriterAt(w io.WriterAt, size int64) ([32]byte, error) {
	var out [32]byte
	ra, ok := w.(io.ReaderAt)
	if !ok {
		return out, fmt.Errorf("transfer: WriterAt does not implement ReaderAt; cannot verify hash")
	}
	return hashReaderAt(ra, size)
}

func copyHash(h hash.Hash, r io.ReaderAt, size int64) error {
	const bufSize = 256 << 10
	buf := make([]byte, bufSize)
	var off int64
	for off < size {
		n := bufSize
		if int64(n) > size-off {
			n = int(size - off)
		}
		if err := readFullAt(r, buf[:n], off); err != nil {
			return err
		}
		_, _ = h.Write(buf[:n])
		off += int64(n)
	}
	return nil
}

func isZeroHash(h [32]byte) bool {
	var z [32]byte
	return h == z
}

func mapConnErr(err error) error {
	if err == nil {
		return nil
	}
	if errors.Is(err, tcpduplex.ErrClosed) || errors.Is(err, io.EOF) || errors.Is(err, io.ErrClosedPipe) {
		return fmt.Errorf("%w: %v", ErrClosed, err)
	}
	return err
}

func isRetriable(err error) bool {
	if err == nil {
		return false
	}
	if errors.Is(err, ErrRejected) || errors.Is(err, ErrHashMismatch) ||
		errors.Is(err, ErrSizeMismatch) || errors.Is(err, ErrResumePastEnd) ||
		errors.Is(err, ErrBadFrame) || errors.Is(err, context.Canceled) ||
		errors.Is(err, context.DeadlineExceeded) {
		return false
	}
	return true
}

func pathBase(path string) string {
	for i := len(path) - 1; i >= 0; i-- {
		if path[i] == '/' || path[i] == '\\' {
			return path[i+1:]
		}
	}
	return path
}
