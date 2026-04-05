package server

import (
	"errors"
	"fmt"
	"math/rand"
	"net"
	"strings"
	"sync"

	"github.com/tiredvpn/tiredvpn/internal/log"
)

// Error definitions
var (
	ErrListenerClosed = errors.New("listener closed")
	ErrNoListeners    = errors.New("no listeners available")
	ErrInvalidRange   = errors.New("invalid port range")
)

// MultiPortListener listens on multiple ports simultaneously
// Accepts connections from any of the configured ports and multiplexes them
// into a single channel for unified handling
type MultiPortListener struct {
	listeners []net.Listener
	ports     []int
	host      string
	conns     chan net.Conn
	errors    chan error
	closed    bool
	mu        sync.RWMutex
	wg        sync.WaitGroup
}

// NewMultiPortListener creates a new listener that listens on multiple ports
// host - the host to bind to (e.g., "0.0.0.0" or "127.0.0.1")
// ports - list of ports to listen on
func NewMultiPortListener(host string, ports []int) (*MultiPortListener, error) {
	if len(ports) == 0 {
		return nil, ErrNoListeners
	}

	mpl := &MultiPortListener{
		listeners: make([]net.Listener, 0, len(ports)),
		ports:     make([]int, 0, len(ports)),
		host:      host,
		conns:     make(chan net.Conn, 100),
		errors:    make(chan error, 10),
	}

	// Start listeners on all ports, skip any that fail (e.g., TIME_WAIT)
	skipped := 0
	for _, port := range ports {
		addr := fmt.Sprintf("%s:%d", host, port)
		l, err := net.Listen("tcp", addr)
		if err != nil {
			// Log warning and skip this port (likely TIME_WAIT or in use)
			log.Debug("Skipping port %d: %v", port, err)
			skipped++
			continue
		}

		mpl.listeners = append(mpl.listeners, l)
		mpl.ports = append(mpl.ports, port)
	}

	// Error only if ALL ports failed
	if len(mpl.listeners) == 0 {
		return nil, fmt.Errorf("failed to listen on any of %d ports", len(ports))
	}

	if skipped > 0 {
		log.Warn("Skipped %d/%d ports (likely TIME_WAIT or in use)", skipped, len(ports))
	}

	// Start accept loops for each listener
	for i, l := range mpl.listeners {
		mpl.wg.Add(1)
		go mpl.acceptLoop(l, mpl.ports[i])
	}

	log.Info("MultiPortListener started on %s with %d ports (range: %d-%d)",
		host, len(ports), ports[0], ports[len(ports)-1])

	return mpl, nil
}

// acceptLoop accepts connections on a single port and sends them to the channel
func (m *MultiPortListener) acceptLoop(l net.Listener, port int) {
	defer m.wg.Done()

	for {
		conn, err := l.Accept()
		if err != nil {
			m.mu.RLock()
			closed := m.closed
			m.mu.RUnlock()

			if closed {
				return
			}

			// Non-fatal error, log and continue
			log.Debug("Accept error on port %d: %v", port, err)
			continue
		}

		m.mu.RLock()
		closed := m.closed
		m.mu.RUnlock()

		if closed {
			conn.Close()
			return
		}

		log.Debug("Connection accepted on port %d from %s", port, conn.RemoteAddr())

		select {
		case m.conns <- conn:
			// Connection queued successfully
		default:
			// Channel full, close connection (backpressure)
			log.Warn("Connection channel full, dropping connection on port %d", port)
			conn.Close()
		}
	}
}

// Accept returns the next connection from any of the listening ports
// Implements net.Listener interface
func (m *MultiPortListener) Accept() (net.Conn, error) {
	conn, ok := <-m.conns
	if !ok {
		return nil, ErrListenerClosed
	}
	return conn, nil
}

// Close closes all listeners and the connection channel
// Implements net.Listener interface
func (m *MultiPortListener) Close() error {
	m.mu.Lock()
	if m.closed {
		m.mu.Unlock()
		return nil
	}
	m.closed = true
	m.mu.Unlock()

	// Close all listeners first to stop accept loops
	var firstErr error
	for i, l := range m.listeners {
		if err := l.Close(); err != nil {
			log.Debug("Error closing listener on port %d: %v", m.ports[i], err)
			if firstErr == nil {
				firstErr = err
			}
		}
	}

	// Wait for all accept loops to finish
	m.wg.Wait()

	// Now safe to close the channel
	close(m.conns)

	// Drain and close any remaining connections
	for conn := range m.conns {
		conn.Close()
	}

	log.Info("MultiPortListener closed")
	return firstErr
}

// Addr returns the address of the first listener (for net.Listener compatibility)
// Implements net.Listener interface
func (m *MultiPortListener) Addr() net.Addr {
	m.mu.RLock()
	defer m.mu.RUnlock()

	if len(m.listeners) == 0 || m.closed {
		return nil
	}
	return m.listeners[0].Addr()
}

// Addrs returns all addresses being listened on
func (m *MultiPortListener) Addrs() []net.Addr {
	m.mu.RLock()
	defer m.mu.RUnlock()

	addrs := make([]net.Addr, len(m.listeners))
	for i, l := range m.listeners {
		addrs[i] = l.Addr()
	}
	return addrs
}

// Ports returns the list of ports being listened on
func (m *MultiPortListener) Ports() []int {
	m.mu.RLock()
	defer m.mu.RUnlock()

	ports := make([]int, len(m.ports))
	copy(ports, m.ports)
	return ports
}

// NumPorts returns the number of ports being listened on
func (m *MultiPortListener) NumPorts() int {
	m.mu.RLock()
	defer m.mu.RUnlock()
	return len(m.ports)
}

// IsClosed returns true if the listener has been closed
func (m *MultiPortListener) IsClosed() bool {
	m.mu.RLock()
	defer m.mu.RUnlock()
	return m.closed
}

// PortRange generates a list of ports in the given range
// start - starting port (inclusive)
// end - ending port (inclusive)
// count - number of ports to generate (0 = all ports in range)
// Returns a list of ports, potentially randomized if count < total range
func PortRange(start, end, count int) []int {
	if start > end {
		start, end = end, start
	}

	// Enforce valid port range
	if start < 1 {
		start = 1
	}
	if end > 65535 {
		end = 65535
	}

	totalPorts := end - start + 1

	// If count is 0 or greater than range, return all ports
	if count <= 0 || count >= totalPorts {
		ports := make([]int, totalPorts)
		for i := 0; i < totalPorts; i++ {
			ports[i] = start + i
		}
		return ports
	}

	// Generate count random unique ports from the range
	// Use Fisher-Yates shuffle on indices
	indices := make([]int, totalPorts)
	for i := 0; i < totalPorts; i++ {
		indices[i] = i
	}

	// Shuffle first 'count' elements
	for i := 0; i < count; i++ {
		j := i + rand.Intn(totalPorts-i)
		indices[i], indices[j] = indices[j], indices[i]
	}

	// Take first 'count' and convert to ports
	ports := make([]int, count)
	for i := 0; i < count; i++ {
		ports[i] = start + indices[i]
	}

	// Sort ports for more predictable behavior
	sortInts(ports)

	return ports
}

// PortRangeSequential generates a sequential list of ports
// start - starting port (inclusive)
// count - number of ports to generate
func PortRangeSequential(start, count int) []int {
	if start < 1 {
		start = 1
	}
	if start+count-1 > 65535 {
		count = 65535 - start + 1
	}
	if count <= 0 {
		return nil
	}

	ports := make([]int, count)
	for i := 0; i < count; i++ {
		ports[i] = start + i
	}
	return ports
}

// PortRangeWithStep generates ports with a fixed step
// start - starting port
// end - ending port (inclusive)
// step - step between ports
func PortRangeWithStep(start, end, step int) []int {
	if step <= 0 {
		step = 1
	}
	if start > end {
		start, end = end, start
	}
	if start < 1 {
		start = 1
	}
	if end > 65535 {
		end = 65535
	}

	var ports []int
	for p := start; p <= end; p += step {
		ports = append(ports, p)
	}
	return ports
}

// sortInts sorts a slice of integers in ascending order (simple insertion sort)
func sortInts(a []int) {
	for i := 1; i < len(a); i++ {
		for j := i; j > 0 && a[j-1] > a[j]; j-- {
			a[j-1], a[j] = a[j], a[j-1]
		}
	}
}

// Verify MultiPortListener implements net.Listener
var _ net.Listener = (*MultiPortListener)(nil)

// ParsePortRange parses a port range string and returns a list of ports
// Supports formats: "995" (single port), "47000-47100" (range)
// maxPorts limits the number of ports returned (0 = no limit)
func ParsePortRange(portRange string, maxPorts int) ([]int, error) {
	if portRange == "" {
		return nil, ErrInvalidRange
	}

	// Check for range format
	if idx := strings.Index(portRange, "-"); idx > 0 {
		startStr := strings.TrimSpace(portRange[:idx])
		endStr := strings.TrimSpace(portRange[idx+1:])

		start, err := parsePort(startStr)
		if err != nil {
			return nil, fmt.Errorf("invalid start port: %w", err)
		}

		end, err := parsePort(endStr)
		if err != nil {
			return nil, fmt.Errorf("invalid end port: %w", err)
		}

		if start > end {
			start, end = end, start
		}

		// Generate port list
		return PortRange(start, end, maxPorts), nil
	}

	// Single port
	port, err := parsePort(portRange)
	if err != nil {
		return nil, fmt.Errorf("invalid port: %w", err)
	}

	return []int{port}, nil
}

// parsePort parses and validates a single port number
func parsePort(s string) (int, error) {
	s = strings.TrimSpace(s)
	var port int
	_, err := fmt.Sscanf(s, "%d", &port)
	if err != nil {
		return 0, err
	}

	if port < 1 || port > 65535 {
		return 0, fmt.Errorf("port %d out of range (1-65535)", port)
	}

	return port, nil
}

// NewMultiPortListenerFromRange creates a multi-port listener from a port range string
// Supports formats: "995" (single port), "47000-47100" (range)
// For single port, returns a regular net.Listener wrapped to implement MultiPortListener methods
func NewMultiPortListenerFromRange(host, portRange string, maxPorts int) (net.Listener, error) {
	ports, err := ParsePortRange(portRange, maxPorts)
	if err != nil {
		return nil, err
	}

	if len(ports) == 1 {
		// Single port - use regular listener
		addr := fmt.Sprintf("%s:%d", host, ports[0])
		return net.Listen("tcp", addr)
	}

	// Multiple ports - use MultiPortListener
	return NewMultiPortListener(host, ports)
}
