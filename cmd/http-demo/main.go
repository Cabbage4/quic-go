// Command http-demo demonstrates the HTTP-over-QUIC SDK.
//
// Run as server:
//
//	go run ./cmd/http-demo -server -addr 127.0.0.1:8443
//
// Run as client (in another terminal):
//
//	go run ./cmd/http-demo -addr 127.0.0.1:8443
package main

import (
	"flag"
	"fmt"
	"log"
	"time"

	http "github.com/Cabbage4/quic-go/http"
	sdk "github.com/Cabbage4/quic-go/sdk"
)

func main() {
	server := flag.Bool("server", false, "run as HTTP server")
	addr := flag.String("addr", "127.0.0.1:8443", "listen/dial address")
	flag.Parse()

	if *server {
		runServer(*addr)
	} else {
		runClient(*addr)
	}
}

func runServer(addr string) {
	mux := http.NewServeMux()

	mux.HandleFunc("/", func(w http.ResponseWriter, r *http.Request) {
		w.Write([]byte("Welcome to HTTP-over-QUIC!"))
	})

	mux.HandleFunc("/hello", func(w http.ResponseWriter, r *http.Request) {
		w.Write([]byte("Hello, World!"))
	})

	mux.HandleFunc("/echo", func(w http.ResponseWriter, r *http.Request) {
		w.Write(r.Body) // echo the request body
	})

	mux.HandleFunc("/time", func(w http.ResponseWriter, r *http.Request) {
		w.Write([]byte(time.Now().Format(time.RFC3339)))
	})

	mux.HandleFunc("/status", func(w http.ResponseWriter, r *http.Request) {
		w.WriteHeader(http.StatusOK)
		w.Write([]byte(`{"status":"ok","service":"http-over-quic"}`))
	})

	srv := &http.Server{Handler: mux}

	ln, err := http.Listen("udp", addr, srv, &sdk.Config{
		MaxIdleTimeout:    30 * time.Second,
		MaxStreamData:     1 << 16,
		MaxConnectionData: 1 << 20,
		MaxStreamsBidi:    100,
		MaxStreamsUni:     100,
		ConnIDLength:      8,
	})
	if err != nil {
		log.Fatalf("Listen failed: %v", err)
	}

	log.Printf("HTTP-over-QUIC server listening on %s", ln.Addr().String())
	log.Println("Endpoints:")
	log.Println("  GET  /        - Welcome message")
	log.Println("  GET  /hello   - Hello World")
	log.Println("  POST /echo    - Echo back request body")
	log.Println("  GET  /time    - Current server time")
	log.Println("  GET  /status  - JSON status")

	select {}
}

func runClient(addr string) {
	baseURL := fmt.Sprintf("http://%s", addr)
	cfg := &sdk.Config{
		MaxIdleTimeout:    5 * time.Second,
		MaxStreamData:     1 << 16,
		MaxConnectionData: 1 << 18,
		MaxStreamsBidi:    10,
		MaxStreamsUni:     10,
		ConnIDLength:      8,
	}
	client := &http.Client{Timeout: 3 * time.Second, QUICConfig: cfg}

	// GET /
	resp, err := client.Get(fmt.Sprintf("%s/", baseURL))
	if err != nil {
		log.Fatalf("GET / failed: %v", err)
	}
	fmt.Printf("GET / -> %d %s: %s\n", resp.StatusCode, resp.Status, string(resp.Body))

	// GET /hello
	resp, err = client.Get(fmt.Sprintf("%s/hello", baseURL))
	if err != nil {
		log.Fatalf("GET /hello failed: %v", err)
	}
	fmt.Printf("GET /hello -> %d %s: %s\n", resp.StatusCode, resp.Status, string(resp.Body))

	// POST /echo
	resp, err = client.Post(fmt.Sprintf("%s/echo", baseURL), []byte("ping over QUIC!"), nil)
	if err != nil {
		log.Fatalf("POST /echo failed: %v", err)
	}
	fmt.Printf("POST /echo -> %d %s: %s\n", resp.StatusCode, resp.Status, string(resp.Body))

	// GET /time
	resp, err = client.Get(fmt.Sprintf("%s/time", baseURL))
	if err != nil {
		log.Fatalf("GET /time failed: %v", err)
	}
	fmt.Printf("GET /time -> %d %s: %s\n", resp.StatusCode, resp.Status, string(resp.Body))

	// GET /status
	resp, err = client.Get(fmt.Sprintf("%s/status", baseURL))
	if err != nil {
		log.Fatalf("GET /status failed: %v", err)
	}
	fmt.Printf("GET /status -> %d %s: %s\n", resp.StatusCode, resp.Status, string(resp.Body))

	// GET /nonexistent (should get 404)
	resp, err = client.Get(fmt.Sprintf("%s/nonexistent", baseURL))
	if err != nil {
		log.Fatalf("GET /nonexistent failed: %v", err)
	}
	fmt.Printf("GET /nonexistent -> %d %s: %s\n", resp.StatusCode, resp.Status, string(resp.Body))

	fmt.Println("\nAll HTTP-over-QUIC requests completed successfully!")
}
