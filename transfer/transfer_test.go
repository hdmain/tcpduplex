package transfer

import (
	"bytes"
	"context"
	"crypto/sha256"
	"errors"
	"io"
	"net"
	"os"
	"path/filepath"
	"sync"
	"sync/atomic"
	"testing"
	"time"

	"github.com/hdmain/tcpduplex"
)

func TestFrameRoundTrip(t *testing.T) {
	id, err := NewID()
	if err != nil {
		t.Fatal(err)
	}
	meta := Meta{ID: id, Name: "demo.bin", Size: 12345, Hash: sha256.Sum256([]byte("x"))}

	offer, err := encodeOffer(meta)
	if err != nil {
		t.Fatal(err)
	}
	d, err := decodeFrame(offer)
	if err != nil || d.typ != typeOffer || d.meta != meta {
		t.Fatalf("offer: %+v %v", d, err)
	}

	for _, frame := range [][]byte{
		encodeAccept(id, 99),
		encodeAck(id, 50),
		encodeChunk(id, 10, []byte("payload")),
		encodeDone(id, true, meta.Hash),
		encodeReject(id, "nope"),
		encodeAbort(id, "stop"),
	} {
		if _, err := decodeFrame(frame); err != nil {
			t.Fatalf("decode: %v", err)
		}
	}
}

func TestSendReceive(t *testing.T) {
	cli, srv := pairedConns(t)
	defer cli.Close()
	defer srv.Close()

	payload := bytes.Repeat([]byte("abcdefgh"), 8<<10) // 64 KiB
	meta := Meta{Name: "blob", Size: int64(len(payload))}

	errCh := make(chan error, 1)
	go func() {
		_, err := Receive(context.Background(), srv, &memFile{}, 0, &Options{
			ChunkSize: 16 << 10,
			Window:    4,
			AckEvery:  2,
		})
		errCh <- err
	}()

	if err := Send(context.Background(), cli, bytes.NewReader(payload), meta, &Options{
		ChunkSize: 16 << 10,
		Window:    4,
	}); err != nil {
		t.Fatal(err)
	}
	if err := <-errCh; err != nil {
		t.Fatal(err)
	}
}

func TestSendReceiveEmpty(t *testing.T) {
	cli, srv := pairedConns(t)
	defer cli.Close()
	defer srv.Close()

	dst := &memFile{}
	errCh := make(chan error, 1)
	go func() {
		_, err := Receive(context.Background(), srv, dst, 0, nil)
		errCh <- err
	}()

	if err := Send(context.Background(), cli, bytes.NewReader(nil), Meta{Name: "empty", Size: 0}, nil); err != nil {
		t.Fatal(err)
	}
	if err := <-errCh; err != nil {
		t.Fatal(err)
	}
	if dst.Len() != 0 {
		t.Fatalf("want empty, got %d", dst.Len())
	}
}

func TestSendFileReceiveFile(t *testing.T) {
	dir := t.TempDir()
	srcPath := filepath.Join(dir, "src.bin")
	dstPath := filepath.Join(dir, "dst.bin")
	data := bytes.Repeat([]byte{0x5a}, 200<<10)
	if err := os.WriteFile(srcPath, data, 0o644); err != nil {
		t.Fatal(err)
	}

	cli, srv := pairedConns(t)
	defer cli.Close()
	defer srv.Close()

	errCh := make(chan error, 1)
	go func() {
		_, err := ReceiveFile(context.Background(), srv, dstPath, &Options{ChunkSize: 32 << 10})
		errCh <- err
	}()

	if err := SendFile(context.Background(), cli, srcPath, &Options{ChunkSize: 32 << 10}); err != nil {
		t.Fatal(err)
	}
	if err := <-errCh; err != nil {
		t.Fatal(err)
	}
	got, err := os.ReadFile(dstPath)
	if err != nil {
		t.Fatal(err)
	}
	if !bytes.Equal(got, data) {
		t.Fatalf("content mismatch: len %d vs %d", len(got), len(data))
	}
}

func TestResumeAfterInterrupt(t *testing.T) {
	payload := bytes.Repeat([]byte("0123456789abcdef"), 4<<10) // 64 KiB
	meta := Meta{Name: "resume.bin", Size: int64(len(payload))}
	id, err := NewID()
	if err != nil {
		t.Fatal(err)
	}
	meta.ID = id

	ln, err := net.Listen("tcp", "127.0.0.1:0")
	if err != nil {
		t.Fatal(err)
	}
	defer ln.Close()

	dst := &memFile{}
	var written atomic.Int64
	var srvConn atomic.Pointer[tcpduplex.Conn]
	var dropOnce sync.Once
	acceptCh := make(chan *tcpduplex.Conn, 2)

	go func() {
		for {
			raw, err := ln.Accept()
			if err != nil {
				return
			}
			c, err := tcpduplex.ServeConn(raw)
			if err != nil {
				return
			}
			srvConn.Store(c)
			acceptCh <- c
		}
	}()

	dial := func(ctx context.Context) (*tcpduplex.Conn, error) {
		return tcpduplex.DialContext(ctx, ln.Addr().String(), nil)
	}

	recvDone := make(chan error, 1)
	go func() {
		c := <-acceptCh
		opts := &Options{
			ChunkSize: 4 << 10,
			Window:    2,
			AckEvery:  1,
			Redial: func(ctx context.Context) (*tcpduplex.Conn, error) {
				return <-acceptCh, nil
			},
			MaxAttempts: 4,
			OnProgress: func(n, _ int64) {
				written.Store(n)
				// Kill the first connection after some progress.
				if n >= 16<<10 {
					dropOnce.Do(func() {
						if sc := srvConn.Load(); sc != nil {
							_ = sc.Underlying().Close()
						}
					})
				}
			},
		}
		_, err := Receive(context.Background(), c, dst, 0, opts)
		recvDone <- err
	}()

	cli, err := dial(context.Background())
	if err != nil {
		t.Fatal(err)
	}

	sendOpts := &Options{
		ChunkSize: 4 << 10,
		Window:    2,
		AckEvery:  1,
		Redial: func(ctx context.Context) (*tcpduplex.Conn, error) {
			time.Sleep(20 * time.Millisecond)
			return dial(ctx)
		},
		MaxAttempts: 4,
	}
	if err := Send(context.Background(), cli, bytes.NewReader(payload), meta, sendOpts); err != nil {
		t.Fatalf("send: %v", err)
	}
	if err := <-recvDone; err != nil {
		t.Fatalf("recv: %v", err)
	}
	if !bytes.Equal(dst.Bytes(), payload) {
		t.Fatalf("resumed content mismatch (dst %d)", dst.Len())
	}
	if written.Load() < int64(len(payload)) {
		t.Fatalf("progress %d < %d", written.Load(), len(payload))
	}
}

func TestReject(t *testing.T) {
	cli, srv := pairedConns(t)
	defer cli.Close()
	defer srv.Close()

	errCh := make(chan error, 1)
	go func() {
		_, err := Receive(context.Background(), srv, &memFile{}, 0, &Options{
			Accept: func(Meta) error { return errors.New("denied") },
		})
		errCh <- err
	}()

	err := Send(context.Background(), cli, bytes.NewReader([]byte("hi")), Meta{Name: "x", Size: 2}, nil)
	if !errors.Is(err, ErrRejected) {
		t.Fatalf("want ErrRejected, got %v", err)
	}
	if err := <-errCh; !errors.Is(err, ErrRejected) {
		t.Fatalf("recv want ErrRejected, got %v", err)
	}
}

func pairedConns(t *testing.T) (cli, srv *tcpduplex.Conn) {
	t.Helper()
	ln, err := net.Listen("tcp", "127.0.0.1:0")
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { _ = ln.Close() })

	type result struct {
		c   *tcpduplex.Conn
		err error
	}
	ch := make(chan result, 1)
	go func() {
		raw, err := ln.Accept()
		if err != nil {
			ch <- result{err: err}
			return
		}
		c, err := tcpduplex.ServeConn(raw)
		ch <- result{c: c, err: err}
	}()

	cli, err = tcpduplex.Dial(ln.Addr().String())
	if err != nil {
		t.Fatal(err)
	}
	res := <-ch
	if res.err != nil {
		t.Fatal(res.err)
	}
	return cli, res.c
}

// memFile is an in-memory WriterAt/ReaderAt that grows as needed.
type memFile struct {
	mu sync.Mutex
	b  []byte
}

func (m *memFile) WriteAt(p []byte, off int64) (int, error) {
	m.mu.Lock()
	defer m.mu.Unlock()
	end := int(off) + len(p)
	if end > len(m.b) {
		nb := make([]byte, end)
		copy(nb, m.b)
		m.b = nb
	}
	copy(m.b[off:], p)
	return len(p), nil
}

func (m *memFile) ReadAt(p []byte, off int64) (int, error) {
	m.mu.Lock()
	defer m.mu.Unlock()
	if off >= int64(len(m.b)) {
		return 0, io.EOF
	}
	n := copy(p, m.b[off:])
	if n < len(p) {
		return n, io.EOF
	}
	return n, nil
}

func (m *memFile) Bytes() []byte {
	m.mu.Lock()
	defer m.mu.Unlock()
	return append([]byte(nil), m.b...)
}

func (m *memFile) Len() int {
	m.mu.Lock()
	defer m.mu.Unlock()
	return len(m.b)
}
