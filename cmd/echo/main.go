// Command echo demonstrates the QUIC SDK with a simple echo server and client.
//
// Run the server:
//
//	go run ./cmd/echo -server -addr 127.0.0.1:4433
//
// Run the client:
//
//	go run ./cmd/echo -client -addr 127.0.0.1:4433
package main

import (
	"flag"
	"fmt"
	"io"
	"log"
	"time"

	"github.com/Cabbage4/quic-go"
)

func main() {
	var (
		isServer bool
		addr     string
		message  string
	)
	flag.BoolVar(&isServer, "server", false, "run as server")
	flag.BoolVar(&isServer, "s", false, "run as server (shorthand)")
	flag.StringVar(&addr, "addr", "127.0.0.1:4433", "address to listen/dial")
	flag.StringVar(&message, "msg", "Hello QUIC!", "message to send (client only)")
	flag.Parse()

	if isServer {
		runServer(addr)
	} else {
		runClient(addr, message)
	}
}

func runServer(addr string) {
	config := quic.DefaultConfig()
	listener, err := quic.Listen("udp", addr, config)
	if err != nil {
		log.Fatalf("Listen failed: %v", err)
	}
	defer listener.Close()

	fmt.Printf("QUIC echo server listening on %s\n", listener.Addr())

	for {
		conn, err := listener.Accept()
		if err != nil {
			log.Printf("Accept error: %v", err)
			return
		}

		go handleConn(conn)
	}
}

func handleConn(conn *quic.Conn) {
	defer conn.Close()

	fmt.Printf("Connection from %s\n", conn.RemoteAddr())

	for {
		stream, err := conn.AcceptStream()
		if err != nil {
			return
		}

		go func(s *quic.Stream) {
			defer s.Close()
			buf := make([]byte, 4096)
			for {
				n, err := s.Read(buf)
				if err != nil {
					if err == io.EOF {
						return
					}
					return
				}
				msg := string(buf[:n])
				fmt.Printf("  recv on stream %d: %s\n", s.ID(), msg)

				// Echo back
				reply := []byte("echo: " + msg)
				if s.IsBidirectional() {
					s.Write(reply)
				}
			}
		}(stream)
	}
}

func runClient(addr, message string) {
	config := quic.DefaultConfig()

	fmt.Printf("Dialing %s...\n", addr)
	conn, err := quic.Dial("udp", addr, config)
	if err != nil {
		log.Fatalf("Dial failed: %v", err)
	}
	defer conn.Close()

	fmt.Printf("Connected to %s\n", conn.RemoteAddr())

	// Wait for the connection to be established
	time.Sleep(50 * time.Millisecond)

	// Open a bidirectional stream
	stream, err := conn.OpenStream()
	if err != nil {
		log.Fatalf("OpenStream failed: %v", err)
	}

	// Send a message
	data := []byte(message)
	n, err := stream.Write(data)
	if err != nil {
		log.Fatalf("Write failed: %v", err)
	}
	fmt.Printf("Sent %d bytes on stream %d: %s\n", n, stream.ID(), message)

	// Read the echo reply
	buf := make([]byte, 4096)
	n, err = stream.Read(buf)
	if err != nil {
		log.Fatalf("Read failed: %v", err)
	}
	fmt.Printf("Received %d bytes on stream %d: %s\n", n, stream.ID(), string(buf[:n]))

	stream.Close()
	fmt.Println("Done")
}
