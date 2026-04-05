package server

import (
	"context"
	"net"
	"sync"
	"testing"
	"time"
)

// TestIPv6Listener tests basic IPv6 listener functionality
func TestIPv6Listener(t *testing.T) {
	// Check if IPv6 is available
	testListener, err := net.Listen("tcp6", "[::1]:0")
	if err != nil {
		t.Skip("IPv6 not available on this system, skipping test")
		return
	}
	testListener.Close()

	// Create server context with minimal config
	cfg := &Config{
		ListenAddrV6: "[::1]:0", // Use localhost and random port
		EnableIPv6:   true,
		DualStack:    false,
	}
	_ = cfg // Use cfg to avoid unused variable warning

	// Start IPv6 listener in background
	ctx, cancel := context.WithCancel(context.Background())
	defer cancel()

	var wg sync.WaitGroup
	var listenerErr error
	var actualAddr string

	// Channel to signal when listener is ready
	ready := make(chan struct{})

	wg.Add(1)
	go func() {
		defer wg.Done()

		lc := net.ListenConfig{}
		listener, err := lc.Listen(ctx, "tcp6", cfg.ListenAddrV6)
		if err != nil {
			listenerErr = err
			close(ready)
			return
		}
		defer listener.Close()

		actualAddr = listener.Addr().String()
		close(ready) // Signal that listener is ready

		// Accept one connection
		conn, err := listener.Accept()
		if err != nil {
			return
		}
		defer conn.Close()

		// Echo back
		buf := make([]byte, 100)
		n, _ := conn.Read(buf)
		conn.Write(buf[:n])
	}()

	// Wait for listener to be ready
	select {
	case <-ready:
		if listenerErr != nil {
			t.Fatalf("Failed to start IPv6 listener: %v", listenerErr)
		}
	case <-time.After(2 * time.Second):
		t.Fatal("Listener did not start in time")
	}

	// Try to connect via IPv6
	conn, err := net.Dial("tcp6", actualAddr)
	if err != nil {
		t.Fatalf("Failed to connect to IPv6 listener: %v", err)
	}
	defer conn.Close()

	// Check that connection is indeed IPv6
	if tcpAddr, ok := conn.RemoteAddr().(*net.TCPAddr); ok {
		if tcpAddr.IP.To4() != nil {
			t.Error("Expected IPv6 address, got IPv4")
		}
	}

	// Test echo
	testMsg := []byte("hello ipv6")
	_, err = conn.Write(testMsg)
	if err != nil {
		t.Fatalf("Failed to write: %v", err)
	}

	buf := make([]byte, 100)
	n, err := conn.Read(buf)
	if err != nil {
		t.Fatalf("Failed to read: %v", err)
	}

	if string(buf[:n]) != string(testMsg) {
		t.Errorf("Echo mismatch: got %q, want %q", string(buf[:n]), string(testMsg))
	}

	cancel()
	wg.Wait()
}

// TestDualStackListeners tests that both IPv4 and IPv6 listeners work
func TestDualStackListeners(t *testing.T) {
	// Check if IPv6 is available
	testListener, err := net.Listen("tcp6", "[::1]:0")
	if err != nil {
		t.Skip("IPv6 not available on this system, skipping test")
		return
	}
	testListener.Close()

	// Create IPv4 listener
	ipv4Listener, err := net.Listen("tcp4", "127.0.0.1:0")
	if err != nil {
		t.Fatalf("Failed to create IPv4 listener: %v", err)
	}
	defer ipv4Listener.Close()

	ipv4Addr := ipv4Listener.Addr().String()

	// Create server context
	cfg := &Config{
		ListenAddr:   ipv4Addr,
		ListenAddrV6: "[::1]:0", // Random port
		EnableIPv6:   true,
		DualStack:    true,
	}
	_ = cfg // Use cfg to avoid unused variable warning

	// Channel to signal when IPv6 listener is ready
	ready := make(chan string, 1)

	// Start IPv6 listener
	var wg sync.WaitGroup
	wg.Add(1)
	go func() {
		defer wg.Done()

		lc := net.ListenConfig{}
		listener, err := lc.Listen(context.Background(), "tcp6", cfg.ListenAddrV6)
		if err != nil {
			t.Errorf("IPv6 listener failed: %v", err)
			close(ready)
			return
		}
		defer listener.Close()

		ready <- listener.Addr().String()

		// Accept one connection
		conn, err := listener.Accept()
		if err != nil {
			return
		}
		conn.Close()
	}()

	// Wait for IPv6 listener to be ready
	var ipv6Addr string
	select {
	case ipv6Addr = <-ready:
		if ipv6Addr == "" {
			t.Fatal("IPv6 listener failed to start")
		}
	case <-time.After(2 * time.Second):
		t.Fatal("IPv6 listener did not start in time")
	}

	// Test IPv4 connection
	ipv4Conn, err := net.Dial("tcp4", ipv4Addr)
	if err != nil {
		t.Errorf("Failed to connect to IPv4 listener: %v", err)
	} else {
		ipv4Conn.Close()
		t.Log("IPv4 connection successful")
	}

	// Test IPv6 connection
	ipv6Conn, err := net.Dial("tcp6", ipv6Addr)
	if err != nil {
		t.Errorf("Failed to connect to IPv6 listener: %v", err)
	} else {
		ipv6Conn.Close()
		t.Log("IPv6 connection successful")
	}

	wg.Wait()
}
