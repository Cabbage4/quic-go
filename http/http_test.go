package http

import (
	"fmt"
	"io"
	"net"
	"sync"
	"testing"
	"time"

	sdk "github.com/Cabbage4/quic-go/sdk"
)

// helper: start an HTTP server on a random port, return the listener and addr.
func startTestServer(t *testing.T, handler Handler) (*Listener, string) {
	t.Helper()
	ln, err := Listen("udp", "127.0.0.1:0", &Server{Handler: handler}, &sdk.Config{
		MaxIdleTimeout:    5 * time.Second,
		MaxStreamData:     1 << 16,
		MaxConnectionData: 1 << 18,
		MaxStreamsBidi:    10,
		MaxStreamsUni:     10,
		ConnIDLength:      8,
	})
	if err != nil {
		t.Fatalf("Listen failed: %v", err)
	}
	addr := ln.Addr().(*net.UDPAddr)
	return ln, fmt.Sprintf("127.0.0.1:%d", addr.Port)
}

// helper: default QUIC config for clients.
func testClientConfig() *sdk.Config {
	return &sdk.Config{
		MaxIdleTimeout:    5 * time.Second,
		MaxStreamData:     1 << 16,
		MaxConnectionData: 1 << 18,
		MaxStreamsBidi:    10,
		MaxStreamsUni:     10,
		ConnIDLength:      8,
	}
}

// === Unit tests for parsing/building ===

func TestStatusText(t *testing.T) {
	cases := []struct {
		code int
		want string
	}{
		{StatusOK, "OK"},
		{StatusNotFound, "Not Found"},
		{StatusInternalServerError, "Internal Server Error"},
		{999, ""},
	}
	for _, c := range cases {
		if got := StatusText(c.code); got != c.want {
			t.Errorf("StatusText(%d) = %q, want %q", c.code, got, c.want)
		}
	}
}

func TestParseURL(t *testing.T) {
	cases := []struct {
		url      string
		host     string
		port     int
		path     string
	}{
		{"http://127.0.0.1:8443/hello", "127.0.0.1", 8443, "/hello"},
		{"127.0.0.1:8443/api/users", "127.0.0.1", 8443, "/api/users"},
		{"127.0.0.1/path", "127.0.0.1", 443, "/path"},
		{"127.0.0.1:9000", "127.0.0.1", 9000, "/"},
		{"https://example.com/secure", "example.com", 443, "/secure"},
	}
	for _, c := range cases {
		host, port, path, err := parseURL(c.url)
		if err != nil {
			t.Errorf("parseURL(%q) error: %v", c.url, err)
			continue
		}
		if host != c.host || port != c.port || path != c.path {
			t.Errorf("parseURL(%q) = (%s, %d, %s), want (%s, %d, %s)",
				c.url, host, port, path, c.host, c.port, c.path)
		}
	}
}

func TestBuildRequest(t *testing.T) {
	body := []byte("hello world")
	req := buildRequest("POST", "/submit", "127.0.0.1", 8443, body, map[string]string{
		"X-Custom": "test",
	})
	// Verify structure
	if indexOf(req, "POST /submit HTTP/1.1\r\n") < 0 {
		t.Errorf("request line missing or wrong: %q", req)
	}
	if indexOf(req, "Host: 127.0.0.1:8443\r\n") < 0 {
		t.Errorf("Host header missing: %q", req)
	}
	if indexOf(req, "Content-Length: 11\r\n") < 0 {
		t.Errorf("Content-Length missing: %q", req)
	}
	if indexOf(req, "X-Custom: test\r\n") < 0 {
		t.Errorf("custom header missing: %q", req)
	}
	if indexOf(req, "hello world") < 0 {
		t.Errorf("body missing: %q", req)
	}
}

func TestBuildRequestNoBody(t *testing.T) {
	req := buildRequest("GET", "/", "127.0.0.1", 8443, nil, nil)
	if indexOf(req, "Content-Length") >= 0 {
		t.Errorf("GET request should not have Content-Length: %q", req)
	}
}

func TestParseRequest(t *testing.T) {
	raw := "GET /hello HTTP/1.1\r\nHost: 127.0.0.1:8443\r\nConnection: close\r\n\r\n"
	req, err := parseRequest([]byte(raw))
	if err != nil {
		t.Fatalf("parseRequest error: %v", err)
	}
	if req.Method != "GET" {
		t.Errorf("Method = %q, want GET", req.Method)
	}
	if req.URL != "/hello" {
		t.Errorf("URL = %q, want /hello", req.URL)
	}
	if req.Host != "127.0.0.1:8443" {
		t.Errorf("Host = %q, want 127.0.0.1:8443", req.Host)
	}
	if req.Header["Connection"] != "close" {
		t.Errorf("Connection header = %q, want close", req.Header["Connection"])
	}
}

func TestParseRequestWithBody(t *testing.T) {
	raw := "POST /submit HTTP/1.1\r\nHost: 127.0.0.1:8443\r\nContent-Length: 5\r\n\r\nhello"
	req, err := parseRequest([]byte(raw))
	if err != nil {
		t.Fatalf("parseRequest error: %v", err)
	}
	if req.Method != "POST" {
		t.Errorf("Method = %q, want POST", req.Method)
	}
	if string(req.Body) != "hello" {
		t.Errorf("Body = %q, want hello", string(req.Body))
	}
}

func TestParseResponse(t *testing.T) {
	raw := "HTTP/1.1 200 OK\r\nContent-Length: 5\r\nContent-Type: text/plain\r\n\r\nhello"
	resp, err := parseResponse([]byte(raw))
	if err != nil {
		t.Fatalf("parseResponse error: %v", err)
	}
	if resp.StatusCode != 200 {
		t.Errorf("StatusCode = %d, want 200", resp.StatusCode)
	}
	if resp.Status != "OK" {
		t.Errorf("Status = %q, want OK", resp.Status)
	}
	if string(resp.Body) != "hello" {
		t.Errorf("Body = %q, want hello", string(resp.Body))
	}
	if resp.Header["Content-Type"] != "text/plain" {
		t.Errorf("Content-Type = %q, want text/plain", resp.Header["Content-Type"])
	}
}

func TestParseResponseError(t *testing.T) {
	_, err := parseResponse([]byte("garbage"))
	if err == nil {
		t.Error("expected error for malformed response")
	}
}

func TestServeMuxExact(t *testing.T) {
	mux := NewServeMux()
	called := false
	mux.HandleFunc("/hello", func(w ResponseWriter, r *Request) {
		called = true
		w.Write([]byte("hi"))
	})

	rw := newResponseWriter()
	mux.ServeHTTP(rw, &Request{URL: "/hello", Header: map[string]string{}})

	if !called {
		t.Error("handler not called for exact match")
	}
}

func TestServeMuxPrefix(t *testing.T) {
	mux := NewServeMux()
	mux.HandleFunc("/api/", func(w ResponseWriter, r *Request) {
		w.Write([]byte("api"))
	})

	rw := newResponseWriter()
	mux.ServeHTTP(rw, &Request{URL: "/api/users", Header: map[string]string{}})

	if rw.statusCode != StatusOK {
		t.Errorf("expected 200 for prefix match, got %d", rw.statusCode)
	}
}

func TestServeMuxNotFound(t *testing.T) {
	mux := NewServeMux()
	mux.HandleFunc("/exists", func(w ResponseWriter, r *Request) {})

	rw := newResponseWriter()
	mux.ServeHTTP(rw, &Request{URL: "/nope", Header: map[string]string{}})

	if rw.statusCode != StatusNotFound {
		t.Errorf("expected 404, got %d", rw.statusCode)
	}
}

func TestHandlerFunc(t *testing.T) {
	called := false
	f := HandlerFunc(func(w ResponseWriter, r *Request) {
		called = true
	})
	f.ServeHTTP(newResponseWriter(), &Request{Header: map[string]string{}})
	if !called {
		t.Error("HandlerFunc not called")
	}
}

func TestResponseWriter(t *testing.T) {
	rw := newResponseWriter()
	rw.Header()["X-Test"] = "yes"
	rw.WriteHeader(StatusCreated)
	rw.Write([]byte("body"))

	if rw.statusCode != StatusCreated {
		t.Errorf("statusCode = %d, want 201", rw.statusCode)
	}
	if string(rw.body) != "body" {
		t.Errorf("body = %q, want body", string(rw.body))
	}
	if rw.header["X-Test"] != "yes" {
		t.Errorf("header not set")
	}
}

func TestResponseWriterWriteHeaderOnce(t *testing.T) {
	rw := newResponseWriter()
	rw.WriteHeader(StatusOK)
	rw.WriteHeader(StatusNotFound) // should be ignored
	if rw.statusCode != StatusOK {
		t.Errorf("WriteHeader called twice, should keep first: got %d", rw.statusCode)
	}
}

func TestStringHelpers(t *testing.T) {
	if indexOf("hello world", "world") != 6 {
		t.Error("indexOf failed")
	}
	if indexOf("hello", "xyz") != -1 {
		t.Error("indexOf should return -1 for not found")
	}
	if lastIndexOf("a-b-c", "-") != 3 {
		t.Error("lastIndexOf failed")
	}
	parts := splitSpace("GET /path HTTP/1.1")
	if len(parts) != 3 || parts[0] != "GET" || parts[1] != "/path" || parts[2] != "HTTP/1.1" {
		t.Errorf("splitSpace failed: %v", parts)
	}
	lines := splitLines("line1\r\nline2\r\nline3")
	if len(lines) != 3 || lines[0] != "line1" || lines[2] != "line3" {
		t.Errorf("splitLines failed: %v", lines)
	}
}

func TestReadUntilDoubleCRLF(t *testing.T) {
	// Use a simple reader
	data := []byte("HTTP/1.1 200 OK\r\nContent-Length: 5\r\n\r\nhello")
	r := &byteReader{data: data}
	result, err := readUntilDoubleCRLF(r)
	if err != nil {
		t.Fatalf("readUntilDoubleCRLF error: %v", err)
	}
	if indexOf(string(result), "\r\n\r\n") < 0 {
		t.Errorf("result should contain double CRLF: %q", string(result))
	}
}

// byteReader is a simple io.Reader for testing.
type byteReader struct {
	data []byte
	pos  int
}

func (r *byteReader) Read(p []byte) (int, error) {
	if r.pos >= len(r.data) {
		return 0, io.EOF
	}
	n := copy(p, r.data[r.pos:])
	r.pos += n
	return n, nil
}

// === Integration tests (server + client over QUIC) ===

func TestHTTPGetRoundTrip(t *testing.T) {
	ln, addr := startTestServer(t, HandlerFunc(func(w ResponseWriter, r *Request) {
		if r.Method != "GET" {
			t.Errorf("server: Method = %q, want GET", r.Method)
		}
		if r.URL != "/hello" {
			t.Errorf("server: URL = %q, want /hello", r.URL)
		}
		w.Write([]byte("Hello, World!"))
	}))
	defer ln.Close()

	client := &Client{Timeout: 3 * time.Second, QUICConfig: testClientConfig()}
	resp, err := client.Do("GET", fmt.Sprintf("%s/hello", addr), nil, nil)
	if err != nil {
		t.Fatalf("Do failed: %v", err)
	}
	if resp.StatusCode != StatusOK {
		t.Errorf("StatusCode = %d, want 200", resp.StatusCode)
	}
	if string(resp.Body) != "Hello, World!" {
		t.Errorf("Body = %q, want Hello, World!", string(resp.Body))
	}
}

func TestHTTPPostRoundTrip(t *testing.T) {
	ln, addr := startTestServer(t, HandlerFunc(func(w ResponseWriter, r *Request) {
		if r.Method != "POST" {
			t.Errorf("server: Method = %q, want POST", r.Method)
		}
		w.Write(r.Body) // echo the body back
	}))
	defer ln.Close()

	client := &Client{Timeout: 3 * time.Second, QUICConfig: testClientConfig()}
	resp, err := client.Do("POST", fmt.Sprintf("%s/echo", addr), []byte("ping"), nil)
	if err != nil {
		t.Fatalf("Do failed: %v", err)
	}
	if string(resp.Body) != "ping" {
		t.Errorf("Body = %q, want ping", string(resp.Body))
	}
}

func TestHTTPNotFound(t *testing.T) {
	mux := NewServeMux()
	mux.HandleFunc("/exists", func(w ResponseWriter, r *Request) {
		w.Write([]byte("ok"))
	})
	ln, addr := startTestServer(t, mux)
	defer ln.Close()

	client := &Client{Timeout: 3 * time.Second, QUICConfig: testClientConfig()}
	resp, err := client.Do("GET", fmt.Sprintf("%s/nope", addr), nil, nil)
	if err != nil {
		t.Fatalf("Do failed: %v", err)
	}
	if resp.StatusCode != StatusNotFound {
		t.Errorf("StatusCode = %d, want 404", resp.StatusCode)
	}
}

func TestHTTPStatusCode(t *testing.T) {
	ln, addr := startTestServer(t, HandlerFunc(func(w ResponseWriter, r *Request) {
		w.WriteHeader(StatusCreated)
		w.Write([]byte("created"))
	}))
	defer ln.Close()

	client := &Client{Timeout: 3 * time.Second, QUICConfig: testClientConfig()}
	resp, err := client.Do("GET", fmt.Sprintf("%s/create", addr), nil, nil)
	if err != nil {
		t.Fatalf("Do failed: %v", err)
	}
	if resp.StatusCode != StatusCreated {
		t.Errorf("StatusCode = %d, want 201", resp.StatusCode)
	}
}

func TestHTTPCustomHeaders(t *testing.T) {
	ln, addr := startTestServer(t, HandlerFunc(func(w ResponseWriter, r *Request) {
		w.Header()["X-Response"] = "yes"
		w.Write([]byte("ok"))
	}))
	defer ln.Close()

	client := &Client{Timeout: 3 * time.Second, QUICConfig: testClientConfig()}
	resp, err := client.Do("GET", fmt.Sprintf("%s/test", addr), nil, map[string]string{
		"X-Request": "sent",
	})
	if err != nil {
		t.Fatalf("Do failed: %v", err)
	}
	if resp.Header["X-Response"] != "yes" {
		t.Errorf("X-Response header = %q, want yes", resp.Header["X-Response"])
	}
}

func TestHTTPServeMuxConcurrent(t *testing.T) {
	mux := NewServeMux()
	var mu sync.Mutex
	count := 0
	mux.HandleFunc("/count", func(w ResponseWriter, r *Request) {
		mu.Lock()
		count++
		mu.Unlock()
		w.Write([]byte(fmt.Sprintf("%d", count)))
	})
	ln, addr := startTestServer(t, mux)
	defer ln.Close()

	var wg sync.WaitGroup
	for i := 0; i < 5; i++ {
		wg.Add(1)
		go func() {
			defer wg.Done()
			client := &Client{Timeout: 3 * time.Second, QUICConfig: testClientConfig()}
			_, err := client.Do("GET", fmt.Sprintf("%s/count", addr), nil, nil)
			if err != nil {
				t.Errorf("Do failed: %v", err)
			}
		}()
	}
	wg.Wait()
	if count != 5 {
		t.Errorf("count = %d, want 5", count)
	}
}

func TestHTTPLargeBody(t *testing.T) {
	ln, addr := startTestServer(t, HandlerFunc(func(w ResponseWriter, r *Request) {
		w.Write(r.Body)
	}))
	defer ln.Close()

	largeBody := make([]byte, 4096)
	for i := range largeBody {
		largeBody[i] = 'A'
	}

	client := &Client{Timeout: 3 * time.Second, QUICConfig: testClientConfig()}
	resp, err := client.Do("POST", fmt.Sprintf("%s/large", addr), largeBody, nil)
	if err != nil {
		t.Fatalf("Do failed: %v", err)
	}
	if len(resp.Body) != len(largeBody) {
		t.Errorf("Body length = %d, want %d", len(resp.Body), len(largeBody))
	}
}

func TestHTTPListenerAddr(t *testing.T) {
	ln, _ := startTestServer(t, NewServeMux())
	defer ln.Close()

	addr := ln.Addr()
	if addr == nil {
		t.Error("Addr() returned nil")
	}
	udpAddr, ok := addr.(*net.UDPAddr)
	if !ok {
		t.Fatalf("Addr() type = %T, want *net.UDPAddr", addr)
	}
	if udpAddr.Port == 0 {
		t.Error("port should not be 0")
	}
}

func TestHTTPListenNilServer(t *testing.T) {
	ln, err := Listen("udp", "127.0.0.1:0", nil, &sdk.Config{
		MaxIdleTimeout:    5 * time.Second,
		MaxStreamData:     1 << 16,
		MaxConnectionData: 1 << 18,
		MaxStreamsBidi:    10,
		MaxStreamsUni:     10,
		ConnIDLength:      8,
	})
	if err != nil {
		t.Fatalf("Listen with nil server failed: %v", err)
	}
	defer ln.Close()
}

func TestHTTPListenCloseTwice(t *testing.T) {
	ln, _ := startTestServer(t, NewServeMux())
	if err := ln.Close(); err != nil {
		t.Errorf("first Close failed: %v", err)
	}
	if err := ln.Close(); err != nil {
		t.Errorf("second Close failed: %v", err)
	}
}
