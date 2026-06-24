package server

import (
	"bufio"
	"fmt"
	"net"
	"net/http"
	"strings"
	"testing"
	"time"
)

// roundTripFake drives serveFakeWebsite over an in-memory pipe and returns the
// raw bytes the server wrote for a single request.
func roundTripFake(t *testing.T, cfg *Config, request string) string {
	t.Helper()
	client, server := net.Pipe()
	done := make(chan struct{})
	go func() {
		serveFakeWebsite(server, cfg, testLogger(t))
		server.Close()
		close(done)
	}()

	_ = client.SetDeadline(time.Now().Add(5 * time.Second))
	if _, err := client.Write([]byte(request)); err != nil {
		t.Fatalf("write request: %v", err)
	}

	var sb strings.Builder
	buf := make([]byte, 4096)
	for {
		n, err := client.Read(buf)
		sb.Write(buf[:n])
		if err != nil {
			break
		}
		if strings.Contains(sb.String(), "</html>") {
			break
		}
	}
	client.Close()
	<-done
	return sb.String()
}

func TestFakeWebsite_NginxHeaders(t *testing.T) {
	raw := roundTripFake(t, &Config{}, "GET / HTTP/1.1\r\nHost: example.com\r\nConnection: close\r\n\r\n")

	// CRLF line endings in the HEADER block (the body is an HTML file and
	// legitimately uses LF, same as a real nginx index.html).
	headersPart := raw
	if i := strings.Index(raw, "\r\n\r\n"); i >= 0 {
		headersPart = raw[:i]
	}
	if strings.Contains(strings.ReplaceAll(headersPart, "\r\n", ""), "\n") {
		t.Error("response headers contain bare LF - real nginx uses CRLF")
	}

	headerOrder := []string{
		"HTTP/1.1 200 OK",
		"Server: nginx",
		"Date: ",
		"Content-Type: text/html",
		"Content-Length: ",
		"Last-Modified: ",
		"Connection: ",
		"ETag: \"",
		"Accept-Ranges: bytes",
	}
	lastIdx := -1
	for _, h := range headerOrder {
		idx := strings.Index(raw, h)
		if idx < 0 {
			t.Errorf("missing header/line: %q", h)
			continue
		}
		if idx < lastIdx {
			t.Errorf("header %q out of nginx order", h)
		}
		lastIdx = idx
	}

	// Parse it back and check Content-Length matches the body exactly.
	resp, err := http.ReadResponse(bufio.NewReader(strings.NewReader(raw)), nil)
	if err != nil {
		t.Fatalf("response not parseable: %v", err)
	}
	if resp.ContentLength != int64(len(nginxIndexHTML)) {
		t.Errorf("Content-Length %d != body %d", resp.ContentLength, len(nginxIndexHTML))
	}
	if got := resp.Header.Get("ETag"); got != fmt.Sprintf("\"%x-%x\"", nginxIndexModTime.Unix(), len(nginxIndexHTML)) {
		t.Errorf("unexpected ETag %q", got)
	}
	if resp.Header.Get("Date") == "" {
		t.Error("missing Date header")
	}
}

func TestFakeWebsite_HeadHasNoBody(t *testing.T) {
	raw := roundTripFake(t, &Config{}, "HEAD / HTTP/1.1\r\nHost: x\r\nConnection: close\r\n\r\n")
	if strings.Contains(raw, "Welcome to nginx!") {
		t.Error("HEAD response must not include a body")
	}
	if !strings.Contains(raw, "Content-Length: ") {
		t.Error("HEAD must still advertise Content-Length")
	}
}

func TestFakeWebsite_UnknownPath404(t *testing.T) {
	raw := roundTripFake(t, &Config{}, "GET /nope.php HTTP/1.1\r\nHost: x\r\nConnection: close\r\n\r\n")
	if !strings.HasPrefix(raw, "HTTP/1.1 404 Not Found") {
		t.Errorf("expected 404 for unknown path, got: %.40q", raw)
	}
	if !strings.Contains(raw, "nginx/1.24.0") {
		t.Error("404 page should carry the nginx footer")
	}
}
