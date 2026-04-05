package porthopping_test

import (
	"context"
	"net"
	"sync"
	"testing"
	"time"

	"github.com/tiredvpn/tiredvpn/internal/porthopping"
	"github.com/tiredvpn/tiredvpn/internal/server"
)

// TestClientServerPortHopping simulates client-server port hopping scenario.
// Client periodically switches ports, server accepts on all configured ports.
func TestClientServerPortHopping(t *testing.T) {
	// Skip in short mode as this involves network operations
	if testing.Short() {
		t.Skip("Skipping integration test in short mode")
	}

	// Server: listen on port range 48000-48005
	ports := []int{48000, 48001, 48002, 48003, 48004, 48005}

	// Track which ports received connections
	portHits := make(map[int]int)
	var mu sync.Mutex

	// Start listeners on all ports
	listeners := make([]net.Listener, 0, len(ports))
	ctx, cancel := context.WithCancel(context.Background())
	defer cancel()

	for _, port := range ports {
		addr := "127.0.0.1:" + itoa(port)
		ln, err := net.Listen("tcp", addr)
		if err != nil {
			t.Fatalf("Failed to listen on %s: %v", addr, err)
		}
		listeners = append(listeners, ln)

		// Accept connections in background
		go func(ln net.Listener, port int) {
			for {
				conn, err := ln.Accept()
				if err != nil {
					select {
					case <-ctx.Done():
						return
					default:
						continue
					}
				}

				mu.Lock()
				portHits[port]++
				mu.Unlock()

				// Send OK and close
				conn.Write([]byte("OK"))
				conn.Close()
			}
		}(ln, port)
	}
	defer func() {
		for _, ln := range listeners {
			ln.Close()
		}
	}()

	// Client: configure port hopping with fast interval for testing
	hopCfg := &porthopping.Config{
		Enabled:        true,
		PortRangeStart: 48000,
		PortRangeEnd:   48005,
		HopInterval:    100 * time.Millisecond, // Fast hopping for test
		Strategy:       porthopping.StrategyRandom,
		Seed:           []byte("integration-test-seed"),
	}

	hopper, err := porthopping.NewPortHopper(hopCfg)
	if err != nil {
		t.Fatalf("Failed to create hopper: %v", err)
	}

	// Connect multiple times, hopping between connections
	for i := 0; i < 10; i++ {
		port := hopper.CurrentPort()
		addr := "127.0.0.1:" + itoa(port)

		conn, err := net.DialTimeout("tcp", addr, 1*time.Second)
		if err != nil {
			t.Errorf("Failed to connect to %s: %v", addr, err)
			continue
		}

		// Read response
		buf := make([]byte, 10)
		conn.SetReadDeadline(time.Now().Add(1 * time.Second))
		n, _ := conn.Read(buf)
		if string(buf[:n]) != "OK" {
			t.Errorf("Unexpected response: %s", string(buf[:n]))
		}
		conn.Close()

		// Wait and hop
		time.Sleep(50 * time.Millisecond)
		if hopper.ShouldHop() {
			hopper.NextPort()
		}
	}

	// Verify we hit multiple ports
	mu.Lock()
	defer mu.Unlock()

	t.Logf("Port hits: %v", portHits)

	if len(portHits) < 2 {
		t.Errorf("Expected connections on multiple ports, got %d", len(portHits))
	}

	totalHits := 0
	for _, count := range portHits {
		totalHits += count
	}
	t.Logf("Total connections: %d across %d ports", totalHits, len(portHits))
}

// TestMultiPortListenerIntegration tests the MultiPortListener with port hopping
func TestMultiPortListenerIntegration(t *testing.T) {
	if testing.Short() {
		t.Skip("Skipping integration test in short mode")
	}

	// Create multi-port listener
	ports := []int{49000, 49001, 49002}
	mpl, err := server.NewMultiPortListener("127.0.0.1", ports)
	if err != nil {
		t.Fatalf("Failed to create MultiPortListener: %v", err)
	}
	defer mpl.Close()

	// Accept in background
	connChan := make(chan net.Conn, 10)
	go func() {
		for {
			conn, err := mpl.Accept()
			if err != nil {
				return
			}
			connChan <- conn
		}
	}()

	// Create hopper targeting these ports
	hopCfg := &porthopping.Config{
		Enabled:        true,
		PortRangeStart: 49000,
		PortRangeEnd:   49002,
		HopInterval:    50 * time.Millisecond,
		Strategy:       porthopping.StrategySequential, // Sequential for predictable test
	}

	hopper, _ := porthopping.NewPortHopper(hopCfg)

	// Connect multiple times
	for i := 0; i < 5; i++ {
		port := hopper.CurrentPort()
		addr := "127.0.0.1:" + itoa(port)

		conn, err := net.DialTimeout("tcp", addr, 1*time.Second)
		if err != nil {
			t.Errorf("Connection %d to %s failed: %v", i, addr, err)
			continue
		}

		// Wait for server to accept
		select {
		case srvConn := <-connChan:
			srvConn.Close()
		case <-time.After(1 * time.Second):
			t.Errorf("Server didn't accept connection %d", i)
		}

		conn.Close()
		hopper.NextPort()
	}
}

// TestPortHoppingWithReconnect simulates connection drop and reconnect on new port
func TestPortHoppingWithReconnect(t *testing.T) {
	if testing.Short() {
		t.Skip("Skipping integration test in short mode")
	}

	// Server on single port that will "force" client to try another
	ln, err := net.Listen("tcp", "127.0.0.1:49100")
	if err != nil {
		t.Fatalf("Failed to listen: %v", err)
	}
	defer ln.Close()

	// Also listen on next port in range
	ln2, err := net.Listen("tcp", "127.0.0.1:49101")
	if err != nil {
		t.Fatalf("Failed to listen on second port: %v", err)
	}
	defer ln2.Close()

	// Create hopper
	hopCfg := &porthopping.Config{
		Enabled:        true,
		PortRangeStart: 49100,
		PortRangeEnd:   49105,
		HopInterval:    10 * time.Millisecond,
		Strategy:       porthopping.StrategySequential,
	}

	hopper, _ := porthopping.NewPortHopper(hopCfg)

	// Simulate: connect, disconnect, hop, reconnect
	reconnectCount := 0

	for reconnectCount < 3 {
		port := hopper.CurrentPort()
		addr := "127.0.0.1:" + itoa(port)

		conn, err := net.DialTimeout("tcp", addr, 100*time.Millisecond)
		if err != nil {
			// Connection failed, hop to next port
			t.Logf("Connection to %s failed, hopping...", addr)
			hopper.NextPort()
			continue
		}

		t.Logf("Connected to port %d", port)
		reconnectCount++
		conn.Close()

		// Simulate network interruption, hop to new port
		time.Sleep(15 * time.Millisecond)
		hopper.NextPort()
	}

	t.Logf("Successfully reconnected %d times with port hopping", reconnectCount)
}

func itoa(n int) string {
	if n < 0 {
		return "-" + itoa(-n)
	}
	if n < 10 {
		return string(byte('0' + n))
	}
	return itoa(n/10) + string(byte('0'+n%10))
}
