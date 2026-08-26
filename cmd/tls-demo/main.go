// Command tls-demo demonstrates the QUIC SDK with TLS 1.3 encryption.
//
// Usage:
//
//	# Terminal 1: start the TLS server
//	go run ./cmd/tls-demo -server -addr 127.0.0.1:8443
//
//	# Terminal 2: run the TLS client
//	go run ./cmd/tls-demo -addr 127.0.0.1:8443
//
// The demo generates a self-signed certificate in-memory, starts a QUIC
// server with TLS, and the client connects with InsecureSkipVerify.
// After the TLS handshake completes, the client opens a bidirectional
// stream, sends "hello over QUIC+TLS", and the server echoes it back.
package main

import (
	"crypto/ecdsa"
	"crypto/elliptic"
	"crypto/rand"
	"crypto/tls"
	"crypto/x509"
	"crypto/x509/pkix"
	"flag"
	"fmt"
	"io"
	"log"
	"math/big"
	"net"
	"time"

	"github.com/Cabbage4/quic-go"
)

func main() {
	var (
		server = flag.Bool("server", false, "run as server")
		addr   = flag.String("addr", "127.0.0.1:8443", "listen/dial address")
	)
	flag.Parse()

	if *server {
		runServer(*addr)
	} else {
		runClient(*addr)
	}
}

// generateSelfSignedCert creates an in-memory self-signed TLS certificate.
func generateSelfSignedCert() (tls.Certificate, error) {
	priv, err := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	if err != nil {
		return tls.Certificate{}, fmt.Errorf("generate key: %w", err)
	}

	serial, err := rand.Int(rand.Reader, new(big.Int).Lsh(big.NewInt(1), 128))
	if err != nil {
		return tls.Certificate{}, fmt.Errorf("generate serial: %w", err)
	}

	tmpl := &x509.Certificate{
		SerialNumber: serial,
		Subject: pkix.Name{
			CommonName: "localhost",
		},
		NotBefore:             time.Now(),
		NotAfter:              time.Now().Add(24 * time.Hour),
		KeyUsage:              x509.KeyUsageDigitalSignature | x509.KeyUsageKeyEncipherment,
		ExtKeyUsage:           []x509.ExtKeyUsage{x509.ExtKeyUsageServerAuth},
		DNSNames:              []string{"localhost"},
		BasicConstraintsValid: true,
	}

	der, err := x509.CreateCertificate(rand.Reader, tmpl, tmpl, &priv.PublicKey, priv)
	if err != nil {
		return tls.Certificate{}, fmt.Errorf("create cert: %w", err)
	}

	return tls.Certificate{
		Certificate: [][]byte{der},
		PrivateKey:  priv,
	}, nil
}

func runServer(addr string) {
	cert, err := generateSelfSignedCert()
	if err != nil {
		log.Fatalf("generate cert: %v", err)
	}

	config := &quic.Config{
		TLSMode:         true,
		TLSCertificates: []tls.Certificate{cert},
		ALPNProtocols:   []string{"echo"},
		MaxIdleTimeout:  30 * time.Second,
		MaxStreamData:   1 << 20,
		MaxConnectionData: 10 << 20,
		ConnIDLength:    8,
	}

	listener, err := quic.Listen("udp", addr, config)
	if err != nil {
		log.Fatalf("listen: %v", err)
	}
	defer listener.Close()

	fmt.Printf("QUIC TLS server listening on %s\n", addr)
	fmt.Println("TLS 1.3 + QUIC packet protection enabled")
	fmt.Println("Waiting for connections...")

	for {
		conn, err := listener.Accept()
		if err != nil {
			log.Printf("accept: %v", err)
			continue
		}

		go handleConn(conn)
	}
}

func handleConn(conn *quic.Conn) {
	defer conn.Close()

	fmt.Printf("connection from %s\n", conn.RemoteAddr())

	for {
		stream, err := conn.AcceptStream()
		if err != nil {
			return
		}
		go handleStream(stream)
	}
}

func handleStream(stream *quic.Stream) {
	defer stream.Close()

	buf := make([]byte, 65536)
	for {
		n, err := stream.Read(buf)
		if err == io.EOF || n == 0 {
			return
		}
		if err != nil {
			log.Printf("read: %v", err)
			return
		}

		msg := string(buf[:n])
		fmt.Printf("server received: %q\n", msg)

		// Echo back
		resp := fmt.Sprintf("echo: %s", msg)
		if _, err := stream.Write([]byte(resp)); err != nil {
			log.Printf("write: %v", err)
			return
		}
	}
}

func runClient(addr string) {
	// Resolve the address to get the IP for SNI
	udpAddr, err := net.ResolveUDPAddr("udp", addr)
	if err != nil {
		log.Fatalf("resolve: %v", err)
	}

	config := &quic.Config{
		TLSMode:            true,
		ServerName:         "localhost",
		InsecureSkipVerify: true, // self-signed cert
		ALPNProtocols:      []string{"echo"},
		MaxIdleTimeout:     30 * time.Second,
		MaxStreamData:      1 << 20,
		MaxConnectionData:  10 << 20,
		ConnIDLength:       8,
	}

	fmt.Printf("Dialing %s with QUIC+TLS...\n", addr)
	conn, err := quic.Dial("udp", udpAddr.String(), config)
	if err != nil {
		log.Fatalf("dial: %v", err)
	}
	defer conn.Close()

	fmt.Println("TLS handshake complete, connection established")

	// Open a bidirectional stream
	stream, err := conn.OpenStream()
	if err != nil {
		log.Fatalf("open stream: %v", err)
	}
	defer stream.Close()

	// Send a message
	msg := "hello over QUIC+TLS"
	fmt.Printf("client sending: %q\n", msg)
	if _, err := stream.Write([]byte(msg)); err != nil {
		log.Fatalf("write: %v", err)
	}

	// Read the echo response
	buf := make([]byte, 65536)
	n, err := stream.Read(buf)
	if err != nil && err != io.EOF {
		log.Fatalf("read: %v", err)
	}

	fmt.Printf("client received: %q\n", string(buf[:n]))
	fmt.Println("Demo complete!")
}
