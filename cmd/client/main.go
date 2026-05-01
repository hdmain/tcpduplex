package main

import (
	"bufio"
	"context"
	"flag"
	"fmt"
	"log/slog"
	"os"
	"os/signal"

	"github.com/hdmain/tcpduplex"
)

func main() {
	addr := flag.String("addr", "127.0.0.1:9090", "server host:port")
	flag.Parse()

	conn, err := tcpduplex.Dial(*addr)
	if err != nil {
		slog.Error("dial", "err", err)
		os.Exit(1)
	}

	ctx, stop := signal.NotifyContext(context.Background(), os.Interrupt)
	defer stop()

	go func() {
		<-ctx.Done()
		_ = conn.Close()
	}()

	go func() {
		for {
			msg, err := conn.Receive()
			if err != nil {
				return
			}
			fmt.Println(string(msg))
		}
	}()

	sc := bufio.NewScanner(os.Stdin)
	for sc.Scan() {
		line := sc.Text()
		if line == "/quit" {
			break
		}
		if err := conn.Send([]byte(line)); err != nil {
			fmt.Fprintf(os.Stderr, "send: %v\n", err)
		}
	}
	if err := sc.Err(); err != nil {
		slog.Error("stdin", "err", err)
	}

	_ = conn.Close()
}
