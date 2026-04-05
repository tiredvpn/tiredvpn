package server

import (
	"net"
	"sync"
	"testing"
	"time"
)

func TestNewMultiPortListener(t *testing.T) {
	// Find available ports
	ports := findAvailablePorts(t, 3)

	mpl, err := NewMultiPortListener("127.0.0.1", ports)
	if err != nil {
		t.Fatalf("Failed to create MultiPortListener: %v", err)
	}
	defer mpl.Close()

	// Verify number of ports
	if mpl.NumPorts() != 3 {
		t.Errorf("Expected 3 ports, got %d", mpl.NumPorts())
	}

	// Verify ports match
	actualPorts := mpl.Ports()
	for i, p := range ports {
		if actualPorts[i] != p {
			t.Errorf("Port mismatch at index %d: expected %d, got %d", i, p, actualPorts[i])
		}
	}

	// Verify not closed
	if mpl.IsClosed() {
		t.Error("Listener should not be closed")
	}
}

func TestMultiPortListenerAccept(t *testing.T) {
	ports := findAvailablePorts(t, 3)

	mpl, err := NewMultiPortListener("127.0.0.1", ports)
	if err != nil {
		t.Fatalf("Failed to create MultiPortListener: %v", err)
	}
	defer mpl.Close()

	// Connect to each port and verify acceptance
	var wg sync.WaitGroup
	connReceived := make(chan struct{}, len(ports))

	// Start accepting
	go func() {
		for i := 0; i < len(ports); i++ {
			conn, err := mpl.Accept()
			if err != nil {
				t.Errorf("Accept error: %v", err)
				return
			}
			conn.Close()
			connReceived <- struct{}{}
		}
	}()

	// Connect to each port
	for _, port := range ports {
		wg.Add(1)
		go func(p int) {
			defer wg.Done()
			addr := net.JoinHostPort("127.0.0.1", itoa(p))
			conn, err := net.DialTimeout("tcp", addr, time.Second)
			if err != nil {
				t.Errorf("Failed to connect to port %d: %v", p, err)
				return
			}
			conn.Close()
		}(port)
	}

	wg.Wait()

	// Wait for all connections to be received
	timeout := time.After(2 * time.Second)
	for i := 0; i < len(ports); i++ {
		select {
		case <-connReceived:
			// OK
		case <-timeout:
			t.Fatalf("Timeout waiting for connection %d", i+1)
		}
	}
}

func TestMultiPortListenerClose(t *testing.T) {
	ports := findAvailablePorts(t, 2)

	mpl, err := NewMultiPortListener("127.0.0.1", ports)
	if err != nil {
		t.Fatalf("Failed to create MultiPortListener: %v", err)
	}

	// Close listener
	if err := mpl.Close(); err != nil {
		t.Errorf("Close error: %v", err)
	}

	// Verify closed
	if !mpl.IsClosed() {
		t.Error("Listener should be closed")
	}

	// Accept should return error
	_, err = mpl.Accept()
	if err != ErrListenerClosed {
		t.Errorf("Expected ErrListenerClosed, got %v", err)
	}

	// Double close should be safe
	if err := mpl.Close(); err != nil {
		t.Errorf("Double close error: %v", err)
	}
}

func TestMultiPortListenerConcurrentAccept(t *testing.T) {
	ports := findAvailablePorts(t, 5)

	mpl, err := NewMultiPortListener("127.0.0.1", ports)
	if err != nil {
		t.Fatalf("Failed to create MultiPortListener: %v", err)
	}
	defer mpl.Close()

	numConnections := 20
	accepted := make(chan net.Conn, numConnections)

	// Start multiple accept goroutines
	var acceptWg sync.WaitGroup
	for i := 0; i < 3; i++ {
		acceptWg.Add(1)
		go func() {
			defer acceptWg.Done()
			for {
				conn, err := mpl.Accept()
				if err != nil {
					return
				}
				accepted <- conn
			}
		}()
	}

	// Make concurrent connections to random ports
	var connectWg sync.WaitGroup
	for i := 0; i < numConnections; i++ {
		connectWg.Add(1)
		go func(idx int) {
			defer connectWg.Done()
			port := ports[idx%len(ports)]
			addr := net.JoinHostPort("127.0.0.1", itoa(port))
			conn, err := net.DialTimeout("tcp", addr, time.Second)
			if err != nil {
				t.Errorf("Connection %d failed: %v", idx, err)
				return
			}
			time.Sleep(50 * time.Millisecond)
			conn.Close()
		}(i)
	}

	connectWg.Wait()

	// Wait for accepts with timeout
	timeout := time.After(3 * time.Second)
	count := 0
	for count < numConnections {
		select {
		case conn := <-accepted:
			conn.Close()
			count++
		case <-timeout:
			t.Fatalf("Timeout: only received %d of %d connections", count, numConnections)
		}
	}
}

func TestMultiPortListenerAddr(t *testing.T) {
	ports := findAvailablePorts(t, 3)

	mpl, err := NewMultiPortListener("127.0.0.1", ports)
	if err != nil {
		t.Fatalf("Failed to create MultiPortListener: %v", err)
	}
	defer mpl.Close()

	// Addr() should return first listener's address
	addr := mpl.Addr()
	if addr == nil {
		t.Fatal("Addr() returned nil")
	}

	// Verify it's the first port
	tcpAddr, ok := addr.(*net.TCPAddr)
	if !ok {
		t.Fatalf("Expected *net.TCPAddr, got %T", addr)
	}
	if tcpAddr.Port != ports[0] {
		t.Errorf("Expected port %d, got %d", ports[0], tcpAddr.Port)
	}

	// Addrs() should return all addresses
	addrs := mpl.Addrs()
	if len(addrs) != len(ports) {
		t.Errorf("Expected %d addresses, got %d", len(ports), len(addrs))
	}
}

func TestMultiPortListenerEmptyPorts(t *testing.T) {
	_, err := NewMultiPortListener("127.0.0.1", []int{})
	if err != ErrNoListeners {
		t.Errorf("Expected ErrNoListeners, got %v", err)
	}

	_, err = NewMultiPortListener("127.0.0.1", nil)
	if err != ErrNoListeners {
		t.Errorf("Expected ErrNoListeners for nil ports, got %v", err)
	}
}

func TestPortRange(t *testing.T) {
	tests := []struct {
		name     string
		start    int
		end      int
		count    int
		wantLen  int
		checkAll bool
	}{
		{
			name:     "full range",
			start:    47000,
			end:      47010,
			count:    0,
			wantLen:  11,
			checkAll: true,
		},
		{
			name:    "partial range",
			start:   47000,
			end:     47010,
			count:   5,
			wantLen: 5,
		},
		{
			name:     "count exceeds range",
			start:    47000,
			end:      47005,
			count:    100,
			wantLen:  6,
			checkAll: true,
		},
		{
			name:     "reversed range",
			start:    47010,
			end:      47000,
			count:    0,
			wantLen:  11,
			checkAll: true,
		},
		{
			name:    "single port",
			start:   47000,
			end:     47000,
			count:   0,
			wantLen: 1,
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			ports := PortRange(tt.start, tt.end, tt.count)
			if len(ports) != tt.wantLen {
				t.Errorf("PortRange() length = %d, want %d", len(ports), tt.wantLen)
			}

			// Check ports are within range
			minPort := tt.start
			maxPort := tt.end
			if minPort > maxPort {
				minPort, maxPort = maxPort, minPort
			}
			for _, p := range ports {
				if p < minPort || p > maxPort {
					t.Errorf("Port %d outside range [%d, %d]", p, minPort, maxPort)
				}
			}

			// Check uniqueness
			seen := make(map[int]bool)
			for _, p := range ports {
				if seen[p] {
					t.Errorf("Duplicate port %d", p)
				}
				seen[p] = true
			}

			// Check sorting
			for i := 1; i < len(ports); i++ {
				if ports[i] < ports[i-1] {
					t.Errorf("Ports not sorted: %d > %d", ports[i-1], ports[i])
				}
			}
		})
	}
}

func TestPortRangeSequential(t *testing.T) {
	ports := PortRangeSequential(47000, 10)
	if len(ports) != 10 {
		t.Errorf("Expected 10 ports, got %d", len(ports))
	}

	for i, p := range ports {
		expected := 47000 + i
		if p != expected {
			t.Errorf("Port at index %d: expected %d, got %d", i, expected, p)
		}
	}

	// Test boundary
	ports = PortRangeSequential(65530, 10)
	if len(ports) != 6 { // Only 65530-65535
		t.Errorf("Expected 6 ports at boundary, got %d", len(ports))
	}
}

func TestPortRangeWithStep(t *testing.T) {
	ports := PortRangeWithStep(47000, 47010, 2)
	expected := []int{47000, 47002, 47004, 47006, 47008, 47010}
	if len(ports) != len(expected) {
		t.Errorf("Expected %d ports, got %d", len(expected), len(ports))
	}
	for i, p := range ports {
		if p != expected[i] {
			t.Errorf("Port at index %d: expected %d, got %d", i, expected[i], p)
		}
	}

	// Test step of 0 (should use 1)
	ports = PortRangeWithStep(47000, 47002, 0)
	if len(ports) != 3 {
		t.Errorf("Expected 3 ports with step 0, got %d", len(ports))
	}
}

func TestMultiPortListenerImplementsNetListener(t *testing.T) {
	ports := findAvailablePorts(t, 1)
	mpl, err := NewMultiPortListener("127.0.0.1", ports)
	if err != nil {
		t.Fatalf("Failed to create MultiPortListener: %v", err)
	}
	defer mpl.Close()

	// Verify interface compliance
	var _ net.Listener = mpl
}

// Helper functions

func findAvailablePorts(t *testing.T, count int) []int {
	t.Helper()
	ports := make([]int, count)
	listeners := make([]net.Listener, count)

	for i := 0; i < count; i++ {
		l, err := net.Listen("tcp", "127.0.0.1:0")
		if err != nil {
			// Close already opened listeners
			for j := 0; j < i; j++ {
				listeners[j].Close()
			}
			t.Fatalf("Failed to find available port: %v", err)
		}
		listeners[i] = l
		ports[i] = l.Addr().(*net.TCPAddr).Port
	}

	// Close all listeners to free ports
	for _, l := range listeners {
		l.Close()
	}

	// Small delay to ensure ports are released
	time.Sleep(10 * time.Millisecond)

	return ports
}

func itoa(i int) string {
	if i == 0 {
		return "0"
	}
	var result []byte
	for i > 0 {
		result = append([]byte{byte('0' + i%10)}, result...)
		i /= 10
	}
	return string(result)
}
