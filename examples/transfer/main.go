package main

import (
	"context"
	"fmt"
	"log"
	"net"
	"os"
	"path/filepath"

	"github.com/hdmain/tcpduplex"
	"github.com/hdmain/tcpduplex/transfer"
)

// Example: encrypted file transfer with automatic resume on reconnect.
func main() {
	dir, err := os.MkdirTemp("", "tcpduplex-transfer-*")
	if err != nil {
		log.Fatal(err)
	}
	defer os.RemoveAll(dir)

	src := filepath.Join(dir, "hello.txt")
	dst := filepath.Join(dir, "hello-copy.txt")
	content := []byte("encrypted resumable transfer over tcpduplex\n")
	if err := os.WriteFile(src, content, 0o644); err != nil {
		log.Fatal(err)
	}

	ln, err := net.Listen("tcp", "127.0.0.1:0")
	if err != nil {
		log.Fatal(err)
	}
	defer ln.Close()

	done := make(chan error, 1)
	go func() {
		raw, err := ln.Accept()
		if err != nil {
			done <- err
			return
		}
		srv, err := tcpduplex.ServeConn(raw)
		if err != nil {
			done <- err
			return
		}
		defer srv.Close()

		meta, err := transfer.ReceiveFile(context.Background(), srv, dst, nil)
		if err != nil {
			done <- err
			return
		}
		fmt.Printf("received %q (%d bytes, id=%s)\n", meta.Name, meta.Size, meta.ID)
		done <- nil
	}()

	cli, err := tcpduplex.Dial(ln.Addr().String())
	if err != nil {
		log.Fatal(err)
	}
	defer cli.Close()

	if err := transfer.SendFile(context.Background(), cli, src, &transfer.Options{
		OnProgress: func(n, total int64) {
			fmt.Printf("progress %d/%d\n", n, total)
		},
	}); err != nil {
		log.Fatal(err)
	}
	if err := <-done; err != nil {
		log.Fatal(err)
	}

	got, err := os.ReadFile(dst)
	if err != nil {
		log.Fatal(err)
	}
	fmt.Printf("verified: %s", got)
}
