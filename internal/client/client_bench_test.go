package client

import (
	"bytes"
	"io"
	"net"
	"testing"
	"time"
)

// BenchmarkBufferedConnRead benchmarks bufferedConn reading
func BenchmarkBufferedConnRead(b *testing.B) {
	data := bytes.Repeat([]byte("x"), 4096)

	b.ResetTimer()
	for i := 0; i < b.N; i++ {
		conn := &bufferedConn{
			Conn:   &mockConn{reader: bytes.NewReader(data)},
			buffer: []byte{0x05}, // SOCKS5 version byte
			offset: 0,
		}
		buf := make([]byte, 4096)
		_, _ = conn.Read(buf)
	}
}

// BenchmarkBufferedConnReadSmall benchmarks small reads from bufferedConn
func BenchmarkBufferedConnReadSmall(b *testing.B) {
	data := bytes.Repeat([]byte("x"), 256)

	b.ResetTimer()
	for i := 0; i < b.N; i++ {
		conn := &bufferedConn{
			Conn:   &mockConn{reader: bytes.NewReader(data)},
			buffer: []byte{0x05},
			offset: 0,
		}
		buf := make([]byte, 256)
		_, _ = conn.Read(buf)
	}
}

// BenchmarkSplitRoutes benchmarks route string splitting
func BenchmarkSplitRoutes(b *testing.B) {
	routes := "10.0.0.0/8, 172.16.0.0/12, 192.168.0.0/16, 0.0.0.0/0"

	b.ResetTimer()
	for i := 0; i < b.N; i++ {
		_ = splitRoutes(routes)
	}
}

// BenchmarkSplitRoutesMany benchmarks splitting many routes
func BenchmarkSplitRoutesMany(b *testing.B) {
	routes := "10.0.0.0/8, 172.16.0.0/12, 192.168.0.0/16, 8.8.8.0/24, 1.1.1.0/24, 9.9.9.0/24, 208.67.0.0/16, 10.8.0.0/24, 10.9.0.0/24, 10.10.0.0/24"

	b.ResetTimer()
	for i := 0; i < b.N; i++ {
		_ = splitRoutes(routes)
	}
}

// BenchmarkTruncate benchmarks string truncation
func BenchmarkTruncate(b *testing.B) {
	s := "This is a very long string that needs to be truncated for display purposes in the UI"

	b.ResetTimer()
	for i := 0; i < b.N; i++ {
		_ = truncate(s, 32)
	}
}

// BenchmarkTruncateShort benchmarks truncation of short strings
func BenchmarkTruncateShort(b *testing.B) {
	s := "Short"

	b.ResetTimer()
	for i := 0; i < b.N; i++ {
		_ = truncate(s, 32)
	}
}

// mockConn implements minimal net.Conn for benchmarking
type mockConn struct {
	reader io.Reader
}

func (m *mockConn) Read(b []byte) (n int, err error) {
	return m.reader.Read(b)
}

func (m *mockConn) Write(b []byte) (n int, err error) {
	return len(b), nil
}

func (m *mockConn) Close() error {
	return nil
}

func (m *mockConn) LocalAddr() net.Addr {
	return &net.TCPAddr{IP: net.IPv4(127, 0, 0, 1), Port: 1080}
}

func (m *mockConn) RemoteAddr() net.Addr {
	return &net.TCPAddr{IP: net.IPv4(127, 0, 0, 1), Port: 12345}
}

func (m *mockConn) SetDeadline(t time.Time) error {
	return nil
}

func (m *mockConn) SetReadDeadline(t time.Time) error {
	return nil
}

func (m *mockConn) SetWriteDeadline(t time.Time) error {
	return nil
}
