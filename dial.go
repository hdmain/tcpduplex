package tcpduplex

import (
	"context"
	"fmt"
	"net"
	"time"

	"github.com/hdmain/tcpduplex/crypto"
	"github.com/hdmain/tcpduplex/protocol"
)

// Dial is equivalent to DialContext(context.Background(), address, nil).
func Dial(address string) (*Conn, error) {
	return DialContext(context.Background(), address, nil)
}

// DialContext dials TCP, negotiates tcpduplex with ProtocolVersion from cfg, and returns a running Conn.
func DialContext(ctx context.Context, address string, cfg *Config) (*Conn, error) {
	fc := freezeConfig(cfg)
	if !protocol.SupportsVersion(fc.ProtocolVersion) {
		return nil, fmt.Errorf("%w: %d", ErrUnsupportedProtocol, fc.ProtocolVersion)
	}

	d := net.Dialer{Timeout: fc.DialTimeout}
	nc, err := d.DialContext(ctx, "tcp", address)
	if err != nil {
		return nil, Wrap("dial", err)
	}

	sess, err := clientHandshakeContext(ctx, nc, fc)
	if err != nil {
		_ = nc.Close()
		return nil, err
	}
	return newConn(nc, sess, fc), nil
}

// ServeConn is equivalent to ServeConnContext(context.Background(), nc, nil).
func ServeConn(nc net.Conn) (*Conn, error) {
	return ServeConnContext(context.Background(), nc, nil)
}

// ServeConnContext completes the listener handshake under ctx cancellation and optional deadlines from cfg.
func ServeConnContext(ctx context.Context, nc net.Conn, cfg *Config) (*Conn, error) {
	fc := freezeConfig(cfg)

	sess, err := serverHandshakeContext(ctx, nc, fc)
	if err != nil {
		_ = nc.Close()
		return nil, err
	}
	return newConn(nc, sess, fc), nil
}

func clientHandshakeContext(ctx context.Context, nc net.Conn, fc frozenConfig) (*crypto.Session, error) {
	type result struct {
		sess *crypto.Session
		err  error
	}
	ch := make(chan result, 1)
	go func() {
		var res result
		if fc.HandshakeTimeout > 0 {
			_ = nc.SetDeadline(time.Now().Add(fc.HandshakeTimeout))
		}
		res.sess, res.err = crypto.ClientHandshake(nc, fc.ProtocolVersion, handshakeOpts(fc))
		_ = nc.SetDeadline(time.Time{})
		ch <- res
	}()

	select {
	case <-ctx.Done():
		_ = nc.Close()
		<-ch
		return nil, ctx.Err()
	case r := <-ch:
		if r.err != nil {
			return nil, Wrap("handshake", r.err)
		}
		return r.sess, nil
	}
}

func serverHandshakeContext(ctx context.Context, nc net.Conn, fc frozenConfig) (*crypto.Session, error) {
	type result struct {
		sess *crypto.Session
		err  error
	}
	ch := make(chan result, 1)
	go func() {
		var res result
		if fc.HandshakeTimeout > 0 {
			_ = nc.SetDeadline(time.Now().Add(fc.HandshakeTimeout))
		}
		res.sess, _, res.err = crypto.ServerHandshake(nc, handshakeOpts(fc))
		_ = nc.SetDeadline(time.Time{})
		ch <- res
	}()

	select {
	case <-ctx.Done():
		_ = nc.Close()
		<-ch
		return nil, ctx.Err()
	case r := <-ch:
		if r.err != nil {
			return nil, Wrap("handshake", r.err)
		}
		return r.sess, nil
	}
}
