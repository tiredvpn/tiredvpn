package mux

import (
	"bytes"
	"io"
	"net"
	"sync"
	"testing"
	"time"
)

// TestNewClient tests client creation
func TestNewClient(t *testing.T) {
	// Create a pipe for testing
	clientConn, serverConn := net.Pipe()
	defer clientConn.Close()
	defer serverConn.Close()

	// Create server in background to accept client handshake
	go func() {
		_, _ = NewServer(serverConn, nil)
	}()

	// Test with default config
	client, err := NewClient(clientConn, nil)
	if err != nil {
		t.Fatalf("NewClient with nil config failed: %v", err)
	}
	defer client.Close()

	if client.IsClosed() {
		t.Error("New client should not be closed")
	}

	if client.NumStreams() != 0 {
		t.Errorf("New client should have 0 streams, got %d", client.NumStreams())
	}
}

// TestNewClientWithConfig tests client creation with custom config
func TestNewClientWithConfig(t *testing.T) {
	clientConn, serverConn := net.Pipe()
	defer clientConn.Close()
	defer serverConn.Close()

	go func() {
		_, _ = NewServer(serverConn, nil)
	}()

	config := &Config{
		KeepAliveInterval: 5 * time.Second,
		KeepAliveTimeout:  15 * time.Second,
		MaxFrameSize:      16384,
		MaxReceiveBuffer:  2097152,
		MaxStreams:        10,
	}

	client, err := NewClient(clientConn, config)
	if err != nil {
		t.Fatalf("NewClient with custom config failed: %v", err)
	}
	defer client.Close()

	if client.IsClosed() {
		t.Error("New client should not be closed")
	}
}

// TestNewClientInvalidConfig tests client creation with invalid config
func TestNewClientInvalidConfig(t *testing.T) {
	clientConn, serverConn := net.Pipe()
	defer clientConn.Close()
	defer serverConn.Close()

	// Invalid keepalive (timeout <= interval)
	invalidConfig := &Config{
		KeepAliveInterval: 30 * time.Second,
		KeepAliveTimeout:  15 * time.Second,
		MaxFrameSize:      16384,
		MaxReceiveBuffer:  2097152,
	}

	_, err := NewClient(clientConn, invalidConfig)
	if err == nil {
		t.Error("NewClient with invalid config should fail")
	}
}

// TestNewServer tests server creation
func TestNewServer(t *testing.T) {
	clientConn, serverConn := net.Pipe()
	defer clientConn.Close()
	defer serverConn.Close()

	// Create client in background
	go func() {
		_, _ = NewClient(clientConn, nil)
	}()

	server, err := NewServer(serverConn, nil)
	if err != nil {
		t.Fatalf("NewServer failed: %v", err)
	}
	defer server.Close()

	if server.IsClosed() {
		t.Error("New server should not be closed")
	}

	if server.NumStreams() != 0 {
		t.Errorf("New server should have 0 streams, got %d", server.NumStreams())
	}
}

// TestOpenStream tests opening a stream
func TestOpenStream(t *testing.T) {
	clientConn, serverConn := net.Pipe()
	defer clientConn.Close()
	defer serverConn.Close()

	var server *Server
	var serverErr error
	serverDone := make(chan struct{})

	go func() {
		defer close(serverDone)
		server, serverErr = NewServer(serverConn, nil)
	}()

	client, err := NewClient(clientConn, nil)
	if err != nil {
		t.Fatalf("NewClient failed: %v", err)
	}
	defer client.Close()

	<-serverDone
	if serverErr != nil {
		t.Fatalf("NewServer failed: %v", serverErr)
	}
	defer server.Close()

	// Open stream from client
	stream, err := client.OpenStream()
	if err != nil {
		t.Fatalf("OpenStream failed: %v", err)
	}
	defer stream.Close()

	if client.NumStreams() != 1 {
		t.Errorf("Client should have 1 stream, got %d", client.NumStreams())
	}
}

// TestDataTransfer tests bidirectional data transfer
func TestDataTransfer(t *testing.T) {
	clientConn, serverConn := net.Pipe()
	defer clientConn.Close()
	defer serverConn.Close()

	var server *Server
	serverReady := make(chan struct{})

	go func() {
		var err error
		server, err = NewServer(serverConn, nil)
		if err != nil {
			t.Errorf("NewServer failed: %v", err)
			close(serverReady)
			return
		}
		close(serverReady)
	}()

	client, err := NewClient(clientConn, nil)
	if err != nil {
		t.Fatalf("NewClient failed: %v", err)
	}
	defer client.Close()

	<-serverReady
	if server == nil {
		t.Fatal("Server creation failed")
	}
	defer server.Close()

	// Test data
	testData := []byte("Hello, Mux World! This is a test message for DPI evasion.")

	var wg sync.WaitGroup
	wg.Add(2)

	// Client sends data
	go func() {
		defer wg.Done()
		stream, err := client.OpenStream()
		if err != nil {
			t.Errorf("Client OpenStream failed: %v", err)
			return
		}
		defer stream.Close()

		n, err := stream.Write(testData)
		if err != nil {
			t.Errorf("Client Write failed: %v", err)
			return
		}
		if n != len(testData) {
			t.Errorf("Client wrote %d bytes, expected %d", n, len(testData))
		}
	}()

	// Server receives data
	go func() {
		defer wg.Done()
		stream, err := server.AcceptStream()
		if err != nil {
			t.Errorf("Server AcceptStream failed: %v", err)
			return
		}
		defer stream.Close()

		buf := make([]byte, len(testData))
		n, err := io.ReadFull(stream, buf)
		if err != nil {
			t.Errorf("Server Read failed: %v", err)
			return
		}
		if n != len(testData) {
			t.Errorf("Server read %d bytes, expected %d", n, len(testData))
		}
		if !bytes.Equal(buf, testData) {
			t.Errorf("Data mismatch: got %q, want %q", buf, testData)
		}
	}()

	wg.Wait()
}

// TestMultipleStreams tests opening multiple concurrent streams
func TestMultipleStreams(t *testing.T) {
	clientConn, serverConn := net.Pipe()
	defer clientConn.Close()
	defer serverConn.Close()

	var server *Server
	serverReady := make(chan struct{})

	go func() {
		var err error
		server, err = NewServer(serverConn, nil)
		if err != nil {
			t.Errorf("NewServer failed: %v", err)
		}
		close(serverReady)
	}()

	client, err := NewClient(clientConn, nil)
	if err != nil {
		t.Fatalf("NewClient failed: %v", err)
	}
	defer client.Close()

	<-serverReady
	if server == nil {
		t.Fatal("Server creation failed")
	}
	defer server.Close()

	numStreams := 10
	streams := make([]net.Conn, numStreams)

	// Open multiple streams
	for i := 0; i < numStreams; i++ {
		stream, err := client.OpenStream()
		if err != nil {
			t.Fatalf("OpenStream %d failed: %v", i, err)
		}
		streams[i] = stream
	}

	if client.NumStreams() != numStreams {
		t.Errorf("Expected %d streams, got %d", numStreams, client.NumStreams())
	}

	// Close all streams
	for i, stream := range streams {
		if err := stream.Close(); err != nil {
			t.Errorf("Close stream %d failed: %v", i, err)
		}
	}
}

// TestMaxStreamsLimit tests the max streams limit
func TestMaxStreamsLimit(t *testing.T) {
	clientConn, serverConn := net.Pipe()
	defer clientConn.Close()
	defer serverConn.Close()

	serverReady := make(chan struct{})

	go func() {
		_, err := NewServer(serverConn, nil)
		if err != nil {
			t.Errorf("NewServer failed: %v", err)
		}
		close(serverReady)
	}()

	config := &Config{
		KeepAliveInterval: 10 * time.Second,
		KeepAliveTimeout:  30 * time.Second,
		MaxFrameSize:      32768,
		MaxReceiveBuffer:  4194304,
		MaxStreams:        3, // Limit to 3 streams
	}

	client, err := NewClient(clientConn, config)
	if err != nil {
		t.Fatalf("NewClient failed: %v", err)
	}
	defer client.Close()

	<-serverReady

	// Open streams up to the limit
	streams := make([]net.Conn, 0)
	for i := 0; i < 3; i++ {
		stream, err := client.OpenStream()
		if err != nil {
			t.Fatalf("OpenStream %d failed: %v", i, err)
		}
		streams = append(streams, stream)
	}

	// Try to open one more - should fail
	_, err = client.OpenStream()
	if err != ErrMuxMaxStreamsReached {
		t.Errorf("Expected ErrMuxMaxStreamsReached, got %v", err)
	}

	// Close streams
	for _, stream := range streams {
		stream.Close()
	}
}

// TestClientClose tests closing a client
func TestClientClose(t *testing.T) {
	clientConn, serverConn := net.Pipe()
	defer clientConn.Close()
	defer serverConn.Close()

	go func() {
		_, _ = NewServer(serverConn, nil)
	}()

	client, err := NewClient(clientConn, nil)
	if err != nil {
		t.Fatalf("NewClient failed: %v", err)
	}

	// Open a stream
	stream, err := client.OpenStream()
	if err != nil {
		t.Fatalf("OpenStream failed: %v", err)
	}

	// Close client
	if err := client.Close(); err != nil {
		t.Errorf("Close failed: %v", err)
	}

	if !client.IsClosed() {
		t.Error("Client should be closed")
	}

	// Try to open another stream - should fail
	_, err = client.OpenStream()
	if err != ErrMuxClosed {
		t.Errorf("Expected ErrMuxClosed, got %v", err)
	}

	// Close stream after client is closed
	stream.Close()
}

// TestServerClose tests closing a server
func TestServerClose(t *testing.T) {
	clientConn, serverConn := net.Pipe()
	defer clientConn.Close()
	defer serverConn.Close()

	var server *Server
	serverReady := make(chan struct{})

	go func() {
		var err error
		server, err = NewServer(serverConn, nil)
		if err != nil {
			t.Errorf("NewServer failed: %v", err)
		}
		close(serverReady)
	}()

	_, err := NewClient(clientConn, nil)
	if err != nil {
		t.Fatalf("NewClient failed: %v", err)
	}

	<-serverReady
	if server == nil {
		t.Fatal("Server creation failed")
	}

	// Close server
	if err := server.Close(); err != nil {
		t.Errorf("Server Close failed: %v", err)
	}

	if !server.IsClosed() {
		t.Error("Server should be closed")
	}
}

// TestMetrics tests metrics tracking
func TestMetrics(t *testing.T) {
	// Reset global metrics before test
	globalMetrics.Reset()

	clientConn, serverConn := net.Pipe()
	defer clientConn.Close()
	defer serverConn.Close()

	var server *Server
	serverReady := make(chan struct{})

	go func() {
		var err error
		server, err = NewServer(serverConn, nil)
		if err != nil {
			t.Errorf("NewServer failed: %v", err)
		}
		close(serverReady)
	}()

	client, err := NewClient(clientConn, nil)
	if err != nil {
		t.Fatalf("NewClient failed: %v", err)
	}
	defer client.Close()

	<-serverReady
	defer server.Close()

	// Open and close a stream
	stream, err := client.OpenStream()
	if err != nil {
		t.Fatalf("OpenStream failed: %v", err)
	}

	// Write some data
	testData := []byte("Test metrics data")
	_, err = stream.Write(testData)
	if err != nil {
		t.Fatalf("Write failed: %v", err)
	}

	stream.Close()

	// Check metrics
	snapshot := client.GetMetrics()
	if snapshot.SessionsCreated < 1 {
		t.Errorf("Expected at least 1 session created, got %d", snapshot.SessionsCreated)
	}
	if snapshot.StreamsOpened < 1 {
		t.Errorf("Expected at least 1 stream opened, got %d", snapshot.StreamsOpened)
	}
	if snapshot.BytesSent < uint64(len(testData)) {
		t.Errorf("Expected at least %d bytes sent, got %d", len(testData), snapshot.BytesSent)
	}
}

// TestConcurrentStreams tests concurrent stream operations
func TestConcurrentStreams(t *testing.T) {
	clientConn, serverConn := net.Pipe()
	defer clientConn.Close()
	defer serverConn.Close()

	var server *Server
	serverReady := make(chan struct{})

	go func() {
		var err error
		server, err = NewServer(serverConn, nil)
		if err != nil {
			t.Errorf("NewServer failed: %v", err)
		}
		close(serverReady)
	}()

	client, err := NewClient(clientConn, nil)
	if err != nil {
		t.Fatalf("NewClient failed: %v", err)
	}
	defer client.Close()

	<-serverReady
	defer server.Close()

	// Launch multiple goroutines opening streams
	numGoroutines := 20
	var wg sync.WaitGroup
	wg.Add(numGoroutines)

	for i := 0; i < numGoroutines; i++ {
		go func(id int) {
			defer wg.Done()
			stream, err := client.OpenStream()
			if err != nil {
				t.Errorf("Goroutine %d: OpenStream failed: %v", id, err)
				return
			}
			defer stream.Close()

			// Small delay to simulate work
			time.Sleep(10 * time.Millisecond)

			// Write some data
			data := []byte("test data from goroutine")
			_, err = stream.Write(data)
			if err != nil {
				t.Errorf("Goroutine %d: Write failed: %v", id, err)
			}
		}(i)
	}

	wg.Wait()
}

// TestBidirectionalData tests bidirectional data transfer on same stream
func TestBidirectionalData(t *testing.T) {
	clientConn, serverConn := net.Pipe()
	defer clientConn.Close()
	defer serverConn.Close()

	var server *Server
	serverReady := make(chan struct{})

	go func() {
		var err error
		server, err = NewServer(serverConn, nil)
		if err != nil {
			t.Errorf("NewServer failed: %v", err)
		}
		close(serverReady)
	}()

	client, err := NewClient(clientConn, nil)
	if err != nil {
		t.Fatalf("NewClient failed: %v", err)
	}
	defer client.Close()

	<-serverReady
	defer server.Close()

	clientData := []byte("Hello from client!")
	serverData := []byte("Hello from server!")

	// Error channel for goroutines
	errCh := make(chan error, 2)

	// Client side
	go func() {
		stream, err := client.OpenStream()
		if err != nil {
			errCh <- err
			return
		}
		defer stream.Close()

		// Send data
		if _, err := stream.Write(clientData); err != nil {
			errCh <- err
			return
		}

		// Receive response
		buf := make([]byte, len(serverData))
		if _, err := io.ReadFull(stream, buf); err != nil {
			errCh <- err
			return
		}

		if !bytes.Equal(buf, serverData) {
			errCh <- io.ErrShortBuffer
			return
		}
		errCh <- nil
	}()

	// Server side
	go func() {
		stream, err := server.AcceptStream()
		if err != nil {
			errCh <- err
			return
		}
		defer stream.Close()

		// Receive data
		buf := make([]byte, len(clientData))
		if _, err := io.ReadFull(stream, buf); err != nil {
			errCh <- err
			return
		}

		if !bytes.Equal(buf, clientData) {
			errCh <- io.ErrShortBuffer
			return
		}

		// Send response
		if _, err := stream.Write(serverData); err != nil {
			errCh <- err
			return
		}
		errCh <- nil
	}()

	// Check for errors
	for i := 0; i < 2; i++ {
		if err := <-errCh; err != nil {
			t.Fatalf("Bidirectional test failed: %v", err)
		}
	}
}

// TestConfigValidation tests configuration validation
func TestConfigValidation(t *testing.T) {
	tests := []struct {
		name    string
		config  *Config
		wantErr bool
	}{
		{
			name:    "valid default config",
			config:  DefaultConfig(),
			wantErr: false,
		},
		{
			name:    "valid high throughput config",
			config:  HighThroughputConfig(),
			wantErr: false,
		},
		{
			name:    "valid low latency config",
			config:  LowLatencyConfig(),
			wantErr: false,
		},
		{
			name:    "valid mobile config",
			config:  MobileConfig(),
			wantErr: false,
		},
		{
			name: "invalid keepalive (timeout <= interval)",
			config: &Config{
				KeepAliveInterval: 30 * time.Second,
				KeepAliveTimeout:  30 * time.Second, // Should be > interval
				MaxFrameSize:      32768,
				MaxReceiveBuffer:  4194304,
			},
			wantErr: true,
		},
		{
			name: "invalid frame size (too small)",
			config: &Config{
				KeepAliveInterval: 10 * time.Second,
				KeepAliveTimeout:  30 * time.Second,
				MaxFrameSize:      100, // < 1024
				MaxReceiveBuffer:  4194304,
			},
			wantErr: true,
		},
		{
			name: "invalid frame size (too large)",
			config: &Config{
				KeepAliveInterval: 10 * time.Second,
				KeepAliveTimeout:  30 * time.Second,
				MaxFrameSize:      100000, // > 65535
				MaxReceiveBuffer:  4194304,
			},
			wantErr: true,
		},
		{
			name: "invalid buffer (receive < frame)",
			config: &Config{
				KeepAliveInterval: 10 * time.Second,
				KeepAliveTimeout:  30 * time.Second,
				MaxFrameSize:      32768,
				MaxReceiveBuffer:  1024, // < MaxFrameSize
			},
			wantErr: true,
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			err := tt.config.Validate()
			if (err != nil) != tt.wantErr {
				t.Errorf("Config.Validate() error = %v, wantErr %v", err, tt.wantErr)
			}
		})
	}
}

// TestConfigClone tests config cloning
func TestConfigClone(t *testing.T) {
	original := DefaultConfig()
	original.MaxStreams = 100

	cloned := original.Clone()

	// Modify original
	original.MaxStreams = 200

	// Clone should be unchanged
	if cloned.MaxStreams != 100 {
		t.Errorf("Clone was modified: MaxStreams = %d, want 100", cloned.MaxStreams)
	}
}

// BenchmarkOpenStream benchmarks stream opening performance
func BenchmarkOpenStream(b *testing.B) {
	clientConn, serverConn := net.Pipe()
	defer clientConn.Close()
	defer serverConn.Close()

	go func() {
		server, _ := NewServer(serverConn, nil)
		for {
			stream, err := server.AcceptStream()
			if err != nil {
				return
			}
			stream.Close()
		}
	}()

	client, err := NewClient(clientConn, nil)
	if err != nil {
		b.Fatalf("NewClient failed: %v", err)
	}
	defer client.Close()

	b.ResetTimer()
	for i := 0; i < b.N; i++ {
		stream, err := client.OpenStream()
		if err != nil {
			b.Fatalf("OpenStream failed: %v", err)
		}
		stream.Close()
	}
}

// BenchmarkDataTransfer benchmarks data transfer performance
func BenchmarkDataTransfer(b *testing.B) {
	clientConn, serverConn := net.Pipe()
	defer clientConn.Close()
	defer serverConn.Close()

	go func() {
		server, _ := NewServer(serverConn, nil)
		for {
			stream, err := server.AcceptStream()
			if err != nil {
				return
			}
			go func(s net.Conn) {
				io.Copy(io.Discard, s)
				s.Close()
			}(stream)
		}
	}()

	client, err := NewClient(clientConn, nil)
	if err != nil {
		b.Fatalf("NewClient failed: %v", err)
	}
	defer client.Close()

	data := make([]byte, 4096) // 4KB chunks
	for i := range data {
		data[i] = byte(i % 256)
	}

	b.ResetTimer()
	b.SetBytes(int64(len(data)))

	stream, err := client.OpenStream()
	if err != nil {
		b.Fatalf("OpenStream failed: %v", err)
	}
	defer stream.Close()

	for i := 0; i < b.N; i++ {
		if _, err := stream.Write(data); err != nil {
			b.Fatalf("Write failed: %v", err)
		}
	}
}
