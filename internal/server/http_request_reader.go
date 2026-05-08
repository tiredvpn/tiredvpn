package server

import (
	"errors"
	"fmt"
	"io"
	"net"
	"strings"
)

// readHTTPRequestExact reads an HTTP/1.1 request line + headers from conn
// strictly up to and including the empty-line terminator (\r\n\r\n) and
// not one byte further. It reads ONE byte at a time and tracks a 4-byte
// sliding suffix; returns when the suffix matches \r\n\r\n.
//
// By construction no Read consumes more bytes than needed, so a subsequent
// conn.Read() (potentially after kTLS Enable) starts on the first byte
// past the terminator.
//
// Caps total bytes at maxHeaderBytes. Returns an error if the cap is hit
// before the terminator. Returns the raw request line and a map of
// canonicalised-key headers; the body (if any) stays in the conn.
func readHTTPRequestExact(conn net.Conn, maxHeaderBytes int) (string, map[string]string, error) {
	if maxHeaderBytes <= 0 {
		maxHeaderBytes = 8192
	}

	buf := make([]byte, 0, 1024)
	one := make([]byte, 1)

	for len(buf) < maxHeaderBytes {
		if _, err := io.ReadFull(conn, one); err != nil {
			return "", nil, fmt.Errorf("read header byte: %w", err)
		}
		buf = append(buf, one[0])

		// Detect \r\n\r\n at the tail.
		n := len(buf)
		if n >= 4 &&
			buf[n-4] == '\r' && buf[n-3] == '\n' &&
			buf[n-2] == '\r' && buf[n-1] == '\n' {
			return parseRequestHead(buf[:n-4])
		}
	}

	return "", nil, errors.New("http header too large")
}

// parseRequestHead splits the bytes before the empty-line terminator into
// the request line and a map of headers. Header keys are kept as-sent
// (no canonicalisation) — callers compare with the same casing the wire
// uses (e.g. "Sec-WebSocket-Key").
func parseRequestHead(b []byte) (string, map[string]string, error) {
	lines := strings.Split(string(b), "\r\n")
	if len(lines) == 0 || lines[0] == "" {
		return "", nil, errors.New("empty request")
	}
	requestLine := lines[0]
	headers := make(map[string]string, len(lines)-1)
	for _, line := range lines[1:] {
		if line == "" {
			continue
		}
		i := strings.IndexByte(line, ':')
		if i <= 0 {
			return "", nil, fmt.Errorf("malformed header: %q", line)
		}
		key := strings.TrimSpace(line[:i])
		val := strings.TrimSpace(line[i+1:])
		headers[key] = val
	}
	return requestLine, headers, nil
}
