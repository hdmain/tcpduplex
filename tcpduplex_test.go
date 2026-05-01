package tcpduplex

import (
	"context"
	"errors"
	"net"
	"sync"
	"testing"
)

func TestConnSendReceive(t *testing.T) {
	ln, err := net.Listen("tcp", "127.0.0.1:0")
	if err != nil {
		t.Fatal(err)
	}
	defer ln.Close()

	type srvResult struct {
		conn *Conn
		err  error
	}
	srvCh := make(chan srvResult, 1)

	go func() {
		c, err := ln.Accept()
		if err != nil {
			srvCh <- srvResult{err: err}
			return
		}
		sc, err := ServeConn(c)
		srvCh <- srvResult{conn: sc, err: err}
	}()

	cli, err := Dial(ln.Addr().String())
	if err != nil {
		t.Fatal(err)
	}
	defer cli.Close()

	res := <-srvCh
	if res.err != nil {
		t.Fatalf("server: %v", res.err)
	}
	srvConn := res.conn
	defer func() { _ = srvConn.Close() }()

	msg := []byte("hello duplex")
	if err := cli.Send(msg); err != nil {
		t.Fatal(err)
	}
	got, err := srvConn.Receive()
	if err != nil {
		t.Fatal(err)
	}
	if string(got) != string(msg) {
		t.Fatalf("payload mismatch: %q", got)
	}

	reply := []byte("ack")
	if err := srvConn.Send(reply); err != nil {
		t.Fatal(err)
	}
	got2, err := cli.Receive()
	if err != nil {
		t.Fatal(err)
	}
	if string(got2) != string(reply) {
		t.Fatalf("reply mismatch: %q", got2)
	}

	if err := srvConn.Close(); err != nil {
		t.Fatal(err)
	}

	if _, err := cli.Receive(); err == nil {
		t.Fatal("expected error after peer close")
	}
}

func TestConnConcurrentSendReceive(t *testing.T) {
	ln, err := net.Listen("tcp", "127.0.0.1:0")
	if err != nil {
		t.Fatal(err)
	}
	defer ln.Close()

	errCh := make(chan error, 1)
	var wg sync.WaitGroup
	wg.Add(1)

	go func() {
		defer wg.Done()
		c, err := ln.Accept()
		if err != nil {
			errCh <- err
			return
		}
		srv, err := ServeConn(c)
		if err != nil {
			errCh <- err
			return
		}
		defer srv.Close()
		for i := 0; i < 50; i++ {
			b, err := srv.Receive()
			if err != nil {
				errCh <- err
				return
			}
			if err := srv.Send(b); err != nil {
				errCh <- err
				return
			}
		}
	}()

	cli, err := Dial(ln.Addr().String())
	if err != nil {
		t.Fatal(err)
	}
	defer cli.Close()

	for i := 0; i < 50; i++ {
		payload := []byte{byte(i)}
		if err := cli.Send(payload); err != nil {
			t.Fatal(err)
		}
		out, err := cli.Receive()
		if err != nil {
			t.Fatal(err)
		}
		if len(out) != 1 || out[0] != byte(i) {
			t.Fatalf("round-trip %d: got %v", i, out)
		}
	}

	wg.Wait()
	select {
	case err := <-errCh:
		if err != nil {
			t.Fatal(err)
		}
	default:
	}
}

func TestDialUnsupportedProtocolVersion(t *testing.T) {
	cfg := DefaultConfig()
	cfg.ProtocolVersion = 42
	_, err := DialContext(context.Background(), "127.0.0.1:1", cfg)
	if err == nil {
		t.Fatal("expected error")
	}
	if !errors.Is(err, ErrUnsupportedProtocol) {
		t.Fatalf("unexpected error: %v", err)
	}
}

func TestPSKHandshake(t *testing.T) {
	ln, err := net.Listen("tcp", "127.0.0.1:0")
	if err != nil {
		t.Fatal(err)
	}
	defer ln.Close()

	cfg := DefaultConfig()
	cfg.Handshake.PreSharedKey = []byte("unit-test-psk")

	go func() {
		c, err := ln.Accept()
		if err != nil {
			return
		}
		srv, err := ServeConnContext(context.Background(), c, cfg)
		if err != nil {
			t.Error(err)
			return
		}
		defer srv.Close()
		msg, err := srv.Receive()
		if err != nil || string(msg) != "ping" {
			t.Errorf("srv recv %v %q", err, msg)
			return
		}
		_ = srv.Send([]byte("pong"))
	}()

	cli, err := DialContext(context.Background(), ln.Addr().String(), cfg)
	if err != nil {
		t.Fatal(err)
	}
	defer cli.Close()

	if err := cli.Send([]byte("ping")); err != nil {
		t.Fatal(err)
	}
	out, err := cli.Receive()
	if err != nil || string(out) != "pong" {
		t.Fatalf("cli recv %v %q", err, out)
	}
}

func TestSendContextCanceled(t *testing.T) {
	ln, err := net.Listen("tcp", "127.0.0.1:0")
	if err != nil {
		t.Fatal(err)
	}
	defer ln.Close()

	var wg sync.WaitGroup
	wg.Add(1)
	go func() {
		defer wg.Done()
		c, err := ln.Accept()
		if err != nil {
			return
		}
		srv, err := ServeConn(c)
		if err != nil {
			return
		}
		defer srv.Close()
		if _, err := srv.Receive(); err != nil {
			return
		}
	}()

	cli, err := Dial(ln.Addr().String())
	if err != nil {
		t.Fatal(err)
	}

	ctx, cancel := context.WithCancel(context.Background())
	cancel()
	if err := cli.SendContext(ctx, []byte("x")); !errors.Is(err, context.Canceled) {
		t.Fatalf("expected canceled, got %v", err)
	}

	_ = cli.Send([]byte("flush"))
	_ = cli.Close()
	wg.Wait()
}

func TestReceiveAfterPeerClose(t *testing.T) {
	ln, err := net.Listen("tcp", "127.0.0.1:0")
	if err != nil {
		t.Fatal(err)
	}

	done := make(chan struct{})
	go func() {
		defer close(done)
		c, err := ln.Accept()
		if err != nil {
			return
		}
		sc, err := ServeConn(c)
		if err != nil {
			return
		}
		_ = sc.Close()
	}()

	cli, err := Dial(ln.Addr().String())
	if err != nil {
		t.Fatal(err)
	}
	defer cli.Close()

	<-done
	_ = ln.Close()

	if _, err := cli.Receive(); err == nil {
		t.Fatal("expected error after peer closed")
	}
}
