package strategy

import (
	"crypto/rand"
	"io"
	"net"
	"testing"
	"time"

	"github.com/tiredvpn/tiredvpn/internal/padding"
)

// pumpThroughput writes total bytes from writer to reader over the two wrapped
// conns and returns the elapsed time. It mimics the VPN data path: many
// MTU-sized writes (one per TUN packet) streamed back to back.
func pumpThroughput(tb testing.TB, writer, reader net.Conn, total, chunk int) time.Duration {
	tb.Helper()
	payload := make([]byte, chunk)
	if _, err := rand.Read(payload); err != nil {
		tb.Fatal(err)
	}

	done := make(chan struct{})
	var readErr error
	go func() {
		buf := make([]byte, 64*1024)
		got := 0
		for got < total {
			n, err := reader.Read(buf)
			if err != nil {
				readErr = err
				break
			}
			got += n
		}
		close(done)
	}()

	start := time.Now()
	written := 0
	for written < total {
		n := chunk
		if total-written < n {
			n = total - written
		}
		if _, err := writer.Write(payload[:n]); err != nil {
			tb.Fatalf("write: %v", err)
		}
		written += n
	}
	<-done
	elapsed := time.Since(start)
	if readErr != nil && readErr != io.EOF {
		tb.Fatalf("read: %v", readErr)
	}
	return elapsed
}

func reportThroughput(tb testing.TB, name string, total int, elapsed time.Duration) {
	mbps := float64(total) / elapsed.Seconds() / (1024 * 1024)
	tb.Logf("%s: %d bytes in %v = %.2f MB/s", name, total, elapsed, mbps)
}

// TestIMAPThroughput streams 10 MB through the IMAP camouflage conn (client ->
// server framing) and asserts the data path is not throttled to cover-traffic
// speed. With the per-write shaper delay removed it should be tens of MB/s.
func TestIMAPThroughput(t *testing.T) {
	cli, srv := net.Pipe()
	defer cli.Close()
	defer srv.Close()

	client := NewIMAPCamouflageConn(cli, nil, false)
	server := NewIMAPCamouflageConn(srv, nil, true)

	const total = 10 * 1024 * 1024
	const chunk = 1400
	elapsed := pumpThroughput(t, client, server, total, chunk)
	reportThroughput(t, "IMAP camouflage", total, elapsed)

	// Regression floor, not a perf target (see WebSocket variant): a shaped
	// data path would collapse to KB/s. Keep a low absolute floor so the check
	// stays meaningful without flaking on slow CI runners.
	mbps := float64(total) / elapsed.Seconds() / (1024 * 1024)
	if mbps < 0.5 {
		t.Fatalf("IMAP throughput too low: %.2f MB/s (data path is being shaped)", mbps)
	}
}

// TestWebSocketThroughput streams 10 MB through the Salamander/WebSocket conn.
func TestWebSocketThroughput(t *testing.T) {
	cli, srv := net.Pipe()
	defer cli.Close()
	defer srv.Close()

	secret := []byte("websocket-throughput-secret")
	clientConn := NewSalamanderConn(cli, padding.NewSalamanderPadder(secret, padding.Balanced), true)
	serverConn := NewSalamanderConn(srv, padding.NewSalamanderPadder(secret, padding.Balanced), false)

	const total = 10 * 1024 * 1024
	const chunk = 1400
	elapsed := pumpThroughput(t, clientConn, serverConn, total, chunk)
	reportThroughput(t, "WebSocket Salamander", total, elapsed)

	// Regression floor, not a perf target: if the data path were throttled to
	// cover-traffic speed it would be in the KB/s range. A low absolute floor
	// catches that regression without flaking on slow/loaded CI runners, where
	// an aggressive MB/s bound is runner-speed-dependent.
	mbps := float64(total) / elapsed.Seconds() / (1024 * 1024)
	if mbps < 0.5 {
		t.Fatalf("WebSocket throughput too low: %.2f MB/s (data path may be shaped)", mbps)
	}
}

func BenchmarkIMAPThroughput(b *testing.B) {
	cli, srv := net.Pipe()
	defer cli.Close()
	defer srv.Close()
	client := NewIMAPCamouflageConn(cli, nil, false)
	server := NewIMAPCamouflageConn(srv, nil, true)
	const chunk = 1400
	b.SetBytes(chunk)
	b.ResetTimer()
	pumpThroughput(b, client, server, b.N*chunk, chunk)
}

func BenchmarkWebSocketThroughput(b *testing.B) {
	cli, srv := net.Pipe()
	defer cli.Close()
	defer srv.Close()
	secret := []byte("bench-secret")
	clientConn := NewSalamanderConn(cli, padding.NewSalamanderPadder(secret, padding.Balanced), true)
	serverConn := NewSalamanderConn(srv, padding.NewSalamanderPadder(secret, padding.Balanced), false)
	const chunk = 1400
	b.SetBytes(chunk)
	b.ResetTimer()
	pumpThroughput(b, clientConn, serverConn, b.N*chunk, chunk)
}
