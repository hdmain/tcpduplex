package tcpduplex

import (
	"context"
	"errors"
	"net"
	"sync"
)

// Server wraps a net.Listener configured with shared tcpduplex defaults for accepted peers.
type Server struct {
	cfg *Config
	ln  net.Listener
}

// Listen opens a TCP listener. cfg may be nil (defaults applied per-connection via freezeConfig).
func Listen(network, addr string, cfg *Config) (*Server, error) {
	ln, err := net.Listen(network, addr)
	if err != nil {
		return nil, Wrap("listen", err)
	}
	return &Server{cfg: cfg, ln: ln}, nil
}

// Addr returns the listener's network address.
func (s *Server) Addr() net.Addr {
	return s.ln.Addr()
}

// Close shuts down the listener.
func (s *Server) Close() error {
	return s.ln.Close()
}

// Serve accepts connections until ctx is canceled or Accept fails. Each accepted socket is passed to onConnect after ServeConnContext.
func (s *Server) Serve(ctx context.Context, onConnect func(ctx context.Context, conn *Conn)) error {
	if onConnect == nil {
		return errors.New("tcpduplex: Serve requires onConnect")
	}

	go func() {
		<-ctx.Done()
		_ = s.ln.Close()
	}()

	var wg sync.WaitGroup
	for {
		nc, err := s.ln.Accept()
		if err != nil {
			wg.Wait()
			if ctx.Err() != nil {
				return ctx.Err()
			}
			return Wrap("accept", err)
		}

		wg.Add(1)
		go func(nc net.Conn) {
			defer wg.Done()
			peerCtx, cancel := context.WithCancel(ctx)
			defer cancel()

			conn, err := ServeConnContext(peerCtx, nc, s.cfg)
			if err != nil {
				return
			}
			onConnect(peerCtx, conn)
		}(nc)
	}
}
