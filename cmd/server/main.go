package main

import (
	"bufio"
	"context"
	"flag"
	"fmt"
	"log/slog"
	"os"
	"os/signal"
	"sync"

	"github.com/hdmain/tcpduplex"
)

func main() {
	addr := flag.String("listen", ":9090", "TCP listen address")
	flag.Parse()

	ctx, stop := signal.NotifyContext(context.Background(), os.Interrupt)
	defer stop()

	srv, err := tcpduplex.Listen("tcp", *addr, nil)
	if err != nil {
		slog.Error("listen", "err", err)
		os.Exit(1)
	}
	defer srv.Close()

	slog.Info("tcpduplex listening", "addr", srv.Addr())

	var mu sync.Mutex
	conns := make([]*tcpduplex.Conn, 0)

	broadcast := func(line string) {
		mu.Lock()
		defer mu.Unlock()
		payload := []byte(line)
		for _, c := range conns {
			if err := c.Send(payload); err != nil {
				slog.Debug("broadcast skip", "err", err)
			}
		}
	}

	go func() {
		sc := bufio.NewScanner(os.Stdin)
		for sc.Scan() {
			broadcast(sc.Text())
		}
		if err := sc.Err(); err != nil {
			slog.Error("stdin", "err", err)
		}
	}()

	errCh := make(chan error, 1)
	go func() {
		errCh <- srv.Serve(ctx, func(peerCtx context.Context, conn *tcpduplex.Conn) {
			mu.Lock()
			conns = append(conns, conn)
			mu.Unlock()

			defer func() {
				mu.Lock()
				defer mu.Unlock()
				for i, x := range conns {
					if x == conn {
						conns = append(conns[:i], conns[i+1:]...)
						break
					}
				}
				_ = conn.Close()
			}()

			slog.Info("peer joined", "remote", conn.Underlying().RemoteAddr())
			for {
				msg, err := conn.ReceiveContext(peerCtx)
				if err != nil {
					slog.Debug("peer done", "remote", conn.Underlying().RemoteAddr(), "err", err)
					return
				}
				fmt.Fprintf(os.Stderr, "[%s] %s\n", conn.Underlying().RemoteAddr(), msg)
				line := fmt.Sprintf("[%s] %s", conn.Underlying().RemoteAddr(), msg)
				broadcast(line)
			}
		})
	}()

	select {
	case <-ctx.Done():
		_ = srv.Close()
	case err := <-errCh:
		if err != nil && ctx.Err() == nil {
			slog.Error("serve", "err", err)
		}
	}
}
