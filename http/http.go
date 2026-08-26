// Package http provides a simple HTTP/1.1 implementation over QUIC.
//
// Each HTTP request-response pair is carried over a single bidirectional
// QUIC stream. The client opens a stream, writes the HTTP/1.1 request,
// and reads the response. The server accepts streams, parses requests,
// invokes the handler, and writes responses.
//
// This is NOT HTTP/3 (which uses HTTP/3 framing, QPACK headers, and
// dedicated unidirectional streams). This is plain HTTP/1.1 text framing
// over QUIC streams — much simpler, but sufficient for many use cases.
//
// Server:
//
//	mux := http.NewServeMux()
//	mux.HandleFunc("/hello", func(w http.ResponseWriter, r *http.Request) {
//	    w.Write([]byte("Hello!"))
//	})
//	srv := &http.Server{Handler: mux}
//	ln, err := http.Listen("udp", "127.0.0.1:8443", srv, nil)
//	defer ln.Close()
//
// Client:
//
//	resp, err := http.Get("http://127.0.0.1:8443/hello")
//	body := resp.Body.ReadAll()
package http

import (
	"fmt"
	"io"
	"net"
	"sync"
	"time"

	sdk "github.com/Cabbage4/quic-go/sdk"
)

// === Status constants ===

// Standard HTTP status codes.
const (
	StatusContinue           = 100
	StatusOK                 = 200
	StatusCreated            = 201
	StatusAccepted           = 202
	StatusNoContent          = 204
	StatusMovedPermanently    = 301
	StatusFound              = 302
	StatusNotModified        = 304
	StatusBadRequest         = 400
	StatusUnauthorized       = 401
	StatusForbidden          = 403
	StatusNotFound           = 404
	StatusMethodNotAllowed   = 405
	StatusInternalServerError = 500
	StatusNotImplemented     = 501
	StatusBadGateway         = 502
	StatusServiceUnavailable = 503
)

var statusText = map[int]string{
	StatusContinue:           "Continue",
	StatusOK:                 "OK",
	StatusCreated:            "Created",
	StatusAccepted:           "Accepted",
	StatusNoContent:          "No Content",
	StatusMovedPermanently:    "Moved Permanently",
	StatusFound:              "Found",
	StatusNotModified:        "Not Modified",
	StatusBadRequest:         "Bad Request",
	StatusUnauthorized:       "Unauthorized",
	StatusForbidden:          "Forbidden",
	StatusNotFound:           "Not Found",
	StatusMethodNotAllowed:   "Method Not Allowed",
	StatusInternalServerError: "Internal Server Error",
	StatusNotImplemented:     "Not Implemented",
	StatusBadGateway:         "Bad Gateway",
	StatusServiceUnavailable: "Service Unavailable",
}

// StatusText returns the standard text for an HTTP status code.
func StatusText(code int) string {
	if s, ok := statusText[code]; ok {
		return s
	}
	return ""
}

// === Handler ===

// Handler is like net/http.Handler — handles an HTTP request.
type Handler interface {
	ServeHTTP(ResponseWriter, *Request)
}

// HandlerFunc adapts a function to the Handler interface.
type HandlerFunc func(ResponseWriter, *Request)

// ServeHTTP calls f(w, r).
func (f HandlerFunc) ServeHTTP(w ResponseWriter, r *Request) {
	f(w, r)
}

// === ServeMux ===

// ServeMux is a simple HTTP request multiplexer (like net/http.ServeMux).
type ServeMux struct {
	mu    sync.RWMutex
	routes map[string]Handler
}

// NewServeMux creates a new ServeMux.
func NewServeMux() *ServeMux {
	return &ServeMux{routes: make(map[string]Handler)}
}

// Handle registers a handler for the given pattern.
func (m *ServeMux) Handle(pattern string, handler Handler) {
	m.mu.Lock()
	defer m.mu.Unlock()
	m.routes[pattern] = handler
}

// HandleFunc registers a handler function for the given pattern.
func (m *ServeMux) HandleFunc(pattern string, handler func(ResponseWriter, *Request)) {
	m.Handle(pattern, HandlerFunc(handler))
}

// ServeHTTP dispatches the request to the matching handler.
func (m *ServeMux) ServeHTTP(w ResponseWriter, r *Request) {
	m.mu.RLock()
	defer m.mu.RUnlock()

	// Try exact match first
	if h, ok := m.routes[r.URL]; ok {
		h.ServeHTTP(w, r)
		return
	}

	// Try prefix match (longest match)
	var bestPattern string
	for pattern := range m.routes {
		if len(pattern) > len(bestPattern) && len(r.URL) >= len(pattern) && r.URL[:len(pattern)] == pattern {
			bestPattern = pattern
		}
	}
	if bestPattern != "" {
		m.routes[bestPattern].ServeHTTP(w, r)
		return
	}

	// No match
	w.WriteHeader(StatusNotFound)
	fmt.Fprintf(w, "404 Not Found: %s\n", r.URL)
}

// === Request ===

// Request represents an HTTP request.
type Request struct {
	Method string
	URL    string // path (e.g., "/api/users")
	Host   string
	Header map[string]string
	Body   []byte
	Remote string // remote address
}

// === ResponseWriter ===

// ResponseWriter is used by handlers to write HTTP responses.
type ResponseWriter interface {
	Header() map[string]string
	WriteHeader(statusCode int)
	Write([]byte) (int, error)
}

// responseWriter implements ResponseWriter.
type responseWriter struct {
	header     map[string]string
	statusCode int
	wroteHead  bool
	body       []byte
}

func newResponseWriter() *responseWriter {
	return &responseWriter{
		header:     map[string]string{},
		statusCode: StatusOK,
	}
}

func (w *responseWriter) Header() map[string]string {
	return w.header
}

func (w *responseWriter) WriteHeader(statusCode int) {
	if w.wroteHead {
		return
	}
	w.statusCode = statusCode
	w.wroteHead = true
}

func (w *responseWriter) Write(data []byte) (int, error) {
	w.body = append(w.body, data...)
	return len(data), nil
}

// === Response ===

// Response represents an HTTP response (client side).
type Response struct {
	StatusCode int
	Status     string
	Header     map[string]string
	Body       []byte
}

// === Body ===

// Body wraps response body bytes with a convenience ReadAll.
type Body struct {
	data []byte
}

// ReadAll returns all body bytes.
func (b *Body) ReadAll() []byte {
	return b.data
}

// String returns the body as a string.
func (b *Body) String() string {
	return string(b.data)
}

// === Server ===

// Server is an HTTP-over-QUIC server.
type Server struct {
	Handler Handler

	// ReadTimeout is the max duration for reading the request.
	// Default: 30s
	ReadTimeout time.Duration

	// WriteTimeout is the max duration for writing the response.
	// Default: 30s
	WriteTimeout time.Duration
}

// Listener wraps a QUIC listener for HTTP.
type Listener struct {
	udpListener *sdk.Listener
	server      *Server
	done        chan struct{}
}

// Listen creates an HTTP-over-QUIC listener.
func Listen(network, addr string, server *Server, config *sdk.Config) (*Listener, error) {
	if server == nil {
		server = &Server{Handler: NewServeMux()}
	}
	if server.Handler == nil {
		server.Handler = NewServeMux()
	}
	if server.ReadTimeout == 0 {
		server.ReadTimeout = 30 * time.Second
	}
	if server.WriteTimeout == 0 {
		server.WriteTimeout = 30 * time.Second
	}

	ln, err := sdk.Listen(network, addr, config)
	if err != nil {
		return nil, fmt.Errorf("http: listen: %w", err)
	}

	l := &Listener{
		udpListener: ln,
		server:      server,
		done:        make(chan struct{}),
	}

	go l.acceptLoop()

	return l, nil
}

// Addr returns the listener's address.
func (l *Listener) Addr() net.Addr {
	return l.udpListener.Addr()
}

// Close stops the listener.
func (l *Listener) Close() error {
	select {
	case <-l.done:
		return nil
	default:
	}
	close(l.done)
	return l.udpListener.Close()
}

// acceptLoop accepts QUIC connections and serves them.
func (l *Listener) acceptLoop() {
	for {
		select {
		case <-l.done:
			return
		default:
		}

		conn, err := l.udpListener.Accept()
		if err != nil {
			select {
			case <-l.done:
				return
			default:
			}
			continue
		}

		go l.serveConn(conn)
	}
}

// serveConn accepts streams on a connection and serves HTTP requests.
func (l *Listener) serveConn(conn *sdk.Conn) {
	defer conn.Close()

	for {
		stream, err := conn.AcceptStream()
		if err != nil {
			return
		}

		go l.serveStream(stream, conn)
	}
}

// serveStream reads an HTTP request from a stream and writes the response.
func (l *Listener) serveStream(stream *sdk.Stream, conn *sdk.Conn) {
	defer stream.Close()

	// Read the HTTP request headers (and any body bytes that came along)
	reqData, err := readUntilDoubleCRLF(stream)
	if err != nil {
		return
	}

	req, err := parseRequest(reqData)
	if err != nil {
		rw := newResponseWriter()
		rw.WriteHeader(StatusBadRequest)
		writeResponse(stream, rw)
		return
	}

	// If Content-Length is set and we haven't read the full body yet,
	// read the remaining bytes from the stream.
	if cl, ok := req.Header["Content-Length"]; ok {
		expected := 0
		fmt.Sscanf(cl, "%d", &expected)
		if len(req.Body) < expected {
			remaining := expected - len(req.Body)
			buf := make([]byte, remaining)
			n, _ := stream.Read(buf)
			req.Body = append(req.Body, buf[:n]...)
		}
	}

	req.Remote = ""

	// Serve the request
	rw := newResponseWriter()
	l.server.Handler.ServeHTTP(rw, req)

	// Write the response
	if err := writeResponse(stream, rw); err != nil {
		return
	}
}

// === Client ===

// Client is an HTTP-over-QUIC client.
type Client struct {
	// Timeout for requests. Default: 30s
	Timeout time.Duration

	// QUIC config for connections.
	// If nil, sdk.DefaultConfig() is used.
	QUICConfig *sdk.Config
}

// DefaultClient returns a default client.
func DefaultClient() *Client {
	return &Client{Timeout: 30 * time.Second}
}

// Get sends a GET request to the given URL.
func Get(url string) (*Response, error) {
	return DefaultClient().Get(url)
}

// Post sends a POST request with the given body and headers.
func Post(url string, body []byte, headers map[string]string) (*Response, error) {
	return DefaultClient().Post(url, body, headers)
}

// Get sends a GET request.
func (c *Client) Get(url string) (*Response, error) {
	return c.Do("GET", url, nil, nil)
}

// Post sends a POST request with the given body and headers.
func (c *Client) Post(url string, body []byte, headers map[string]string) (*Response, error) {
	return c.Do("POST", url, body, headers)
}

// Do sends an HTTP request and returns the response.
// The url should be in the form "host:port/path" or "host/path".
// If no port is specified, 443 is used.
func (c *Client) Do(method, url string, body []byte, headers map[string]string) (*Response, error) {
	if c.Timeout == 0 {
		c.Timeout = 30 * time.Second
	}

	host, port, path, err := parseURL(url)
	if err != nil {
		return nil, err
	}

	// Dial QUIC connection
	quicCfg := c.QUICConfig
	if quicCfg == nil {
		quicCfg = sdk.DefaultConfig()
	}
	quicCfg.MaxIdleTimeout = c.Timeout

	addr := fmt.Sprintf("%s:%d", host, port)
	conn, err := sdk.Dial("udp", addr, quicCfg)
	if err != nil {
		return nil, fmt.Errorf("http: dial: %w", err)
	}
	defer conn.Close()

	// Wait for connection to establish
	time.Sleep(50 * time.Millisecond)

	// Open a bidirectional stream
	stream, err := conn.OpenStream()
	if err != nil {
		return nil, fmt.Errorf("http: open stream: %w", err)
	}

	// Build the HTTP/1.1 request
	reqStr := buildRequest(method, path, host, port, body, headers)

	// Write the request
	_, err = stream.Write([]byte(reqStr))
	if err != nil {
		return nil, fmt.Errorf("http: write request: %w", err)
	}

	// Send FIN (close write side)
	stream.Close()

	// Read the response
	respData, err := readUntilDoubleCRLF(stream)
	if err != nil {
		return nil, fmt.Errorf("http: read response: %w", err)
	}

	// If we got headers but no body, read the rest based on Content-Length
	resp, err := parseResponse(respData)
	if err != nil {
		return nil, fmt.Errorf("http: parse response: %w", err)
	}

	// Read body if Content-Length says there's more
	if cl, ok := resp.Header["Content-Length"]; ok {
		expected := 0
		fmt.Sscanf(cl, "%d", &expected)
		if len(resp.Body) < expected {
			remaining := expected - len(resp.Body)
			buf := make([]byte, remaining)
			n, _ := stream.Read(buf)
			resp.Body = append(resp.Body, buf[:n]...)
		}
	}

	return resp, nil
}

// === HTTP/1.1 Parsing ===

// readUntilDoubleCRLF reads from a stream until \r\n\r\n is found,
// then returns all data read so far (headers + any body that was read).
func readUntilDoubleCRLF(r io.Reader) ([]byte, error) {
	buf := make([]byte, 0, 4096)
	tmp := make([]byte, 1)

	for {
		n, err := r.Read(tmp)
		if n > 0 {
			buf = append(buf, tmp[:n]...)
		}
		if err != nil {
			if len(buf) > 0 {
				return buf, nil // return what we have
			}
			return nil, err
		}

		// Check for \r\n\r\n
		if len(buf) >= 4 && buf[len(buf)-4] == '\r' && buf[len(buf)-3] == '\n' &&
			buf[len(buf)-2] == '\r' && buf[len(buf)-1] == '\n' {
			return buf, nil
		}
	}
}

// parseRequest parses an HTTP/1.1 request from raw bytes.
func parseRequest(data []byte) (*Request, error) {
	str := string(data)

	// Find the end of the status line
	idx := indexOf(str, "\r\n")
	if idx < 0 {
		return nil, fmt.Errorf("malformed request: no status line")
	}

	statusLine := str[:idx]
	rest := str[idx+2:]

	// Parse status line: METHOD PATH HTTP/1.1
	parts := splitSpace(statusLine)
	if len(parts) < 3 {
		return nil, fmt.Errorf("malformed status line: %s", statusLine)
	}

	req := &Request{
		Method: parts[0],
		URL:    parts[1],
		Header: map[string]string{},
	}

	// Parse headers and body
	headerEnd := indexOf(rest, "\r\n\r\n")
	var headerBlock, bodyStr string
	if headerEnd >= 0 {
		headerBlock = rest[:headerEnd]
		bodyStr = rest[headerEnd+4:]
	} else {
		headerBlock = rest
	}

	// Parse headers
	for _, line := range splitLines(headerBlock) {
		if line == "" {
			continue
		}
		colon := indexOf(line, ": ")
		if colon < 0 {
			continue
		}
		key := line[:colon]
		val := line[colon+2:]
		req.Header[key] = val
		if key == "Host" {
			req.Host = val
		}
	}

	req.Body = []byte(bodyStr)
	return req, nil
}

// parseResponse parses an HTTP/1.1 response from raw bytes.
func parseResponse(data []byte) (*Response, error) {
	str := string(data)

	// Find the end of the status line
	idx := indexOf(str, "\r\n")
	if idx < 0 {
		return nil, fmt.Errorf("malformed response: no status line")
	}

	statusLine := str[:idx]
	rest := str[idx+2:]

	// Parse status line: HTTP/1.1 200 OK
	parts := splitSpace(statusLine)
	if len(parts) < 2 {
		return nil, fmt.Errorf("malformed status line: %s", statusLine)
	}

	resp := &Response{
		Header: map[string]string{},
	}

	fmt.Sscanf(parts[1], "%d", &resp.StatusCode)

	if len(parts) >= 3 {
		resp.Status = parts[2]
	} else {
		resp.Status = StatusText(resp.StatusCode)
	}

	// Parse headers and body
	headerEnd := indexOf(rest, "\r\n\r\n")
	var headerBlock, bodyStr string
	if headerEnd >= 0 {
		headerBlock = rest[:headerEnd]
		bodyStr = rest[headerEnd+4:]
	} else {
		headerBlock = rest
	}

	// Parse headers
	for _, line := range splitLines(headerBlock) {
		if line == "" {
			continue
		}
		colon := indexOf(line, ": ")
		if colon < 0 {
			continue
		}
		key := line[:colon]
		val := line[colon+2:]
		resp.Header[key] = val
	}

	resp.Body = []byte(bodyStr)
	return resp, nil
}

// buildRequest builds an HTTP/1.1 request string.
func buildRequest(method, path, host string, port int, body []byte, headers map[string]string) string {
	req := fmt.Sprintf("%s %s HTTP/1.1\r\n", method, path)
	req += fmt.Sprintf("Host: %s:%d\r\n", host, port)

	// Default headers
	if body != nil {
		req += fmt.Sprintf("Content-Length: %d\r\n", len(body))
	}
	req += "Connection: close\r\n"

	// User-provided headers
	for k, v := range headers {
		req += fmt.Sprintf("%s: %s\r\n", k, v)
	}

	req += "\r\n"

	if body != nil {
		req += string(body)
	}

	return req
}

// writeResponse writes an HTTP/1.1 response to a stream.
func writeResponse(stream *sdk.Stream, rw *responseWriter) error {
	// Build the response
	statusText := StatusText(rw.statusCode)
	if statusText == "" {
		statusText = "Unknown"
	}

	resp := fmt.Sprintf("HTTP/1.1 %d %s\r\n", rw.statusCode, statusText)

	// Content-Length
	resp += fmt.Sprintf("Content-Length: %d\r\n", len(rw.body))

	// Content-Type if not set
	hasContentType := false
	for k := range rw.header {
		if k == "Content-Type" {
			hasContentType = true
			break
		}
	}
	if !hasContentType {
		resp += "Content-Type: text/plain; charset=utf-8\r\n"
	}

	// Other headers
	for k, v := range rw.header {
		resp += fmt.Sprintf("%s: %s\r\n", k, v)
	}

	resp += "Connection: close\r\n"
	resp += "\r\n"

	// Write headers
	_, err := stream.Write([]byte(resp))
	if err != nil {
		return err
	}

	// Write body
	if len(rw.body) > 0 {
		_, err = stream.Write(rw.body)
	}

	return err
}

// parseURL parses a URL like "host:port/path" or "host/path".
// Returns host, port (default 443), and path.
func parseURL(url string) (string, int, string, error) {
	// Remove protocol prefix if present
	for _, prefix := range []string{"http://", "https://"} {
		if len(url) > len(prefix) && url[:len(prefix)] == prefix {
			url = url[len(prefix):]
			break
		}
	}

	// Find the first slash to separate host:port from path
	slashIdx := indexOf(url, "/")
	var hostPort, path string
	if slashIdx < 0 {
		hostPort = url
		path = "/"
	} else {
		hostPort = url[:slashIdx]
		path = url[slashIdx:]
	}

	// Parse host:port
	host := hostPort
	port := 443 // default QUIC port
	colonIdx := lastIndexOf(hostPort, ":")
	if colonIdx >= 0 {
		host = hostPort[:colonIdx]
		fmt.Sscanf(hostPort[colonIdx+1:], "%d", &port)
	}

	return host, port, path, nil
}

// === String helpers ===

func indexOf(s, sub string) int {
	for i := 0; i <= len(s)-len(sub); i++ {
		if s[i:i+len(sub)] == sub {
			return i
		}
	}
	return -1
}

func lastIndexOf(s, sub string) int {
	for i := len(s) - len(sub); i >= 0; i-- {
		if s[i:i+len(sub)] == sub {
			return i
		}
	}
	return -1
}

func splitSpace(s string) []string {
	var parts []string
	current := ""
	for _, ch := range s {
		if ch == ' ' || ch == '\t' {
			if current != "" {
				parts = append(parts, current)
				current = ""
			}
		} else {
			current += string(ch)
		}
	}
	if current != "" {
		parts = append(parts, current)
	}
	return parts
}

func splitLines(s string) []string {
	var lines []string
	current := ""
	for i := 0; i < len(s); i++ {
		if s[i] == '\r' && i+1 < len(s) && s[i+1] == '\n' {
			lines = append(lines, current)
			current = ""
			i++
		} else {
			current += string(s[i])
		}
	}
	if current != "" {
		lines = append(lines, current)
	}
	return lines
}
