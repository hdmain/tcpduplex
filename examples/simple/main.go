package main

import (
	"fmt"
	"log"
	"net"

	"github.com/hdmain/tcpduplex"
)

// Example: start a listener, accept one encrypted session, and exchange messages.
func main() {
	ln, err := net.Listen("tcp", "127.0.0.1:0")
	if err != nil {
		log.Fatal(err)
	}
	defer ln.Close()

	serverDone := make(chan struct{})
	go func() {
		defer close(serverDone)
		raw, err := ln.Accept()
		if err != nil {
			log.Printf("accept: %v", err)
			return
		}
		srv, err := tcpduplex.ServeConn(raw)
		if err != nil {
			log.Printf("handshake: %v", err)
			return
		}
		defer srv.Close()

		msg, err := srv.Receive()
		if err != nil {
			log.Printf("receive: %v", err)
			return
		}
		fmt.Printf("server received: %s\n", msg)

		if err := srv.Send([]byte("world")); err != nil {
			log.Printf("send: %v", err)
		}
	}()

	cli, err := tcpduplex.Dial(ln.Addr().String())
	if err != nil {
		log.Fatal(err)
	}
	defer cli.Close()

	if err := cli.Send([]byte("hello")); err != nil {
		log.Fatal(err)
	}
	out, err := cli.Receive()
	if err != nil {
		log.Fatal(err)
	}
	fmt.Printf("client received: %s\n", out)

	<-serverDone
}
