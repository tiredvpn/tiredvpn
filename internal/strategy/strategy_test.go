package strategy

import (
	"bytes"
	"context"
	"crypto/tls"
	"fmt"
	"io"
	"net"
	"sync"
	"testing"
	"time"
)

// Mock server for testing
type mockServer struct {
	listener net.Listener
	handler  func(net.Conn)
	wg       sync.WaitGroup
}

func newMockServer(t *testing.T, handler func(net.Conn)) *mockServer {
	l, err := net.Listen("tcp", "127.0.0.1:0")
	if err != nil {
		t.Fatalf("Failed to create listener: %v", err)
	}

	s := &mockServer{
		listener: l,
		handler:  handler,
	}

	s.wg.Add(1)
	go func() {
		defer s.wg.Done()
		for {
			conn, err := l.Accept()
			if err != nil {
				return
			}
			go s.handler(conn)
		}
	}()

	return s
}

func (s *mockServer) Addr() string {
	return s.listener.Addr().String()
}

func (s *mockServer) Close() {
	s.listener.Close()
	s.wg.Wait()
}

// TestManagerRegistration tests strategy registration
func TestManagerRegistration(t *testing.T) {
	m := NewManager()

	// Register mock strategies
	m.Register(&mockStrategy{id: "test1", priority: 10})
	m.Register(&mockStrategy{id: "test2", priority: 5})
	m.Register(&mockStrategy{id: "test3", priority: 15})

	strategies := m.GetOrderedStrategies()

	if len(strategies) != 3 {
		t.Errorf("Expected 3 strategies, got %d", len(strategies))
	}

	// Should be sorted by priority (lower first)
	if strategies[0].ID() != "test2" {
		t.Errorf("Expected test2 first (priority 5), got %s", strategies[0].ID())
	}
}

// TestManagerProbeAll tests parallel probing
func TestManagerProbeAll(t *testing.T) {
	m := NewManager()

	// ProbeAll filters out non-server strategies, so we need actual strategies
	// Just verify it doesn't crash with empty set
	ctx := context.Background()
	results := m.ProbeAll(ctx, "test:443")

	// With no registered strategies that require server, should return empty
	if results == nil {
		t.Error("Expected non-nil results")
	}
}

// TestManagerConnect tests connection with fallback
func TestManagerConnect(t *testing.T) {
	m := NewManager()

	// No strategies registered, should fail
	ctx := context.Background()
	_, _, err := m.Connect(ctx, "target:443")

	if err == nil {
		t.Error("Expected error with no strategies, got nil")
	}
}

// TestConfidenceUpdate tests adaptive ordering
func TestConfidenceUpdate(t *testing.T) {
	m := NewManager()
	m.Register(&mockStrategy{id: "test1", priority: 10})

	// Initial confidence should be 0.5
	stats := m.GetStats()
	if stats["test1"].Confidence != 0.5 {
		t.Errorf("Expected initial confidence 0.5, got %f", stats["test1"].Confidence)
	}

	// Simulate successful probe
	m.mu.Lock()
	m.updateConfidence("test1", true)
	m.mu.Unlock()

	stats = m.GetStats()
	if stats["test1"].Confidence <= 0.5 {
		t.Errorf("Expected increased confidence after success, got %f", stats["test1"].Confidence)
	}
}

// TestTrafficMorphProfile tests traffic morphing profiles
func TestTrafficMorphProfile(t *testing.T) {
	if YandexVideoProfile == nil {
		t.Fatal("YandexVideoProfile is nil")
	}

	if len(YandexVideoProfile.PacketSizes) == 0 {
		t.Error("YandexVideoProfile has no packet sizes")
	}

	if len(YandexVideoProfile.PacketSizeProbs) != len(YandexVideoProfile.PacketSizes) {
		t.Error("PacketSizes and PacketSizeProbs length mismatch")
	}

	// Verify probabilities sum to 1.0
	var sum float64
	for _, p := range YandexVideoProfile.PacketSizeProbs {
		sum += p
	}
	if sum < 0.99 || sum > 1.01 {
		t.Errorf("Probabilities should sum to 1.0, got %f", sum)
	}
}

// TestProtocolConfusionTypes tests all confusion types exist
func TestProtocolConfusionTypes(t *testing.T) {
	strategies := AllConfusionTypes(NewManager())

	if len(strategies) != 5 {
		t.Errorf("Expected 5 confusion types, got %d", len(strategies))
	}

	// Verify each has unique ID
	ids := make(map[string]bool)
	for _, s := range strategies {
		if ids[s.ID()] {
			t.Errorf("Duplicate ID: %s", s.ID())
		}
		ids[s.ID()] = true
	}
}

// TestConfusedConnWrite tests protocol confusion packet building
func TestConfusedConnWrite(t *testing.T) {
	// Create a pipe for testing
	client, server := net.Pipe()
	defer client.Close()
	defer server.Close()

	cc := NewConfusedConn(client, ConfusionDNSoverTLS)

	testData := []byte("hello world")

	// Write in goroutine
	writeErrCh := make(chan error, 1)
	go func() {
		_, err := cc.Write(testData)
		writeErrCh <- err
	}()

	// Read from server side
	buf := make([]byte, 1024)
	n, err := server.Read(buf)
	if err != nil {
		t.Fatalf("Read failed: %v", err)
	}

	if writeErr := <-writeErrCh; writeErr != nil {
		t.Fatalf("Write failed: %v", writeErr)
	}

	// Should contain DNS header and our data
	if n < len(testData)+12 {
		t.Errorf("Packet too short: %d bytes", n)
	}

	// Check for TIRED magic marker
	if !bytes.Contains(buf[:n], []byte("TIRED")) {
		t.Error("Missing TIRED magic marker")
	}
}

// TestMeshRelayNodeSelection tests relay node selection
func TestMeshRelayNodeSelection(t *testing.T) {
	mesh := NewMeshRelayStrategy("exit.example.com:443")

	mesh.AddRelay(&RelayNode{
		Address:   "10.0.0.1:443",
		Location:  "RU-Moscow",
		Available: true,
		Latency:   50 * time.Millisecond,
		Load:      0.3,
	})

	mesh.AddRelay(&RelayNode{
		Address:   "10.0.0.2:443",
		Location:  "RU-SPB",
		Available: true,
		Latency:   30 * time.Millisecond,
		Load:      0.1,
	})

	mesh.AddRelay(&RelayNode{
		Address:   "10.0.0.3:443",
		Location:  "RU-Kazan",
		Available: false, // Not available
		Latency:   20 * time.Millisecond,
		Load:      0.0,
	})

	relay, err := mesh.selectBestRelay()
	if err != nil {
		t.Fatalf("selectBestRelay failed: %v", err)
	}

	// Should select SPB (lowest latency + load among available)
	if relay.Location != "RU-SPB" {
		t.Errorf("Expected RU-SPB relay, got %s", relay.Location)
	}
}

// TestAntiProbeKnockSequence tests knock sequence generation
func TestAntiProbeKnockSequence(t *testing.T) {
	secret := []byte("test-secret")
	strat := NewAntiProbeStrategy(NewManager(), secret)

	seq := strat.generateKnockSequence()

	if len(seq.Delays) != 5 {
		t.Errorf("Expected 5 delays, got %d", len(seq.Delays))
	}

	if len(seq.Sizes) != 5 {
		t.Errorf("Expected 5 sizes, got %d", len(seq.Sizes))
	}

	// Verify delays are in expected range (50-200ms)
	for i, d := range seq.Delays {
		if d < 50*time.Millisecond || d > 200*time.Millisecond {
			t.Errorf("Delay %d out of range: %v", i, d)
		}
	}

	// Verify sizes are in expected range (10-100)
	for i, s := range seq.Sizes {
		if s < 10 || s > 100 {
			t.Errorf("Size %d out of range: %d", i, s)
		}
	}
}

// TestDefaultManagerConfig tests default manager creation
func TestDefaultManagerConfig(t *testing.T) {
	cfg := DefaultManagerConfig{
		ServerAddr: "server:443",
		Secret:     []byte("test-secret"),
		CoverHost:  "api.googleapis.com",
	}

	m := NewDefaultManager(cfg)

	strategies := m.GetOrderedStrategies()
	if len(strategies) == 0 {
		t.Error("No strategies registered")
	}

	// Should have at least Traffic Morph and Protocol Confusion
	hasTrafficMorph := false
	hasConfusion := false

	for _, s := range strategies {
		if s.ID() == "morph_Yandex Video" {
			hasTrafficMorph = true
		}
		if s.ID() == "confusion_0" {
			hasConfusion = true
		}
	}

	if !hasTrafficMorph {
		t.Error("Missing Traffic Morph strategy")
	}

	if !hasConfusion {
		t.Error("Missing Protocol Confusion strategy")
	}
}

// TestStrategyPrintSummary tests summary printing
func TestStrategyPrintSummary(t *testing.T) {
	m := NewManager()
	m.Register(&mockStrategy{id: "test1", name: "Test Strategy 1", priority: 10})

	summary := m.PrintStrategySummary()

	if !bytes.Contains([]byte(summary), []byte("Test Strategy 1")) {
		t.Error("Summary should contain strategy name")
	}

	if !bytes.Contains([]byte(summary), []byte("test1")) {
		t.Error("Summary should contain strategy ID")
	}
}

// Benchmark tests

func BenchmarkManagerConnect(b *testing.B) {
	server := &mockServer{
		handler: func(conn net.Conn) {
			defer conn.Close()
			io.Copy(conn, conn)
		},
	}

	l, _ := net.Listen("tcp", "127.0.0.1:0")
	server.listener = l
	go func() {
		for {
			conn, err := l.Accept()
			if err != nil {
				return
			}
			go server.handler(conn)
		}
	}()
	defer l.Close()

	m := NewManager()
	m.Register(&mockStrategy{id: "test", serverAddr: server.Addr()})

	ctx := context.Background()

	b.ResetTimer()
	for i := 0; i < b.N; i++ {
		conn, _, _ := m.Connect(ctx, "target:443")
		if conn != nil {
			conn.Close()
		}
	}
}

// Mock strategy for testing
type mockStrategy struct {
	id         string
	name       string
	priority   int
	probeErr   error
	probeDelay time.Duration
	connectErr error
	serverAddr string
}

func (m *mockStrategy) Name() string {
	if m.name != "" {
		return m.name
	}
	return m.id
}

func (m *mockStrategy) ID() string {
	return m.id
}

func (m *mockStrategy) Priority() int {
	return m.priority
}

func (m *mockStrategy) Description() string {
	return "Mock strategy for testing"
}

func (m *mockStrategy) RequiresServer() bool {
	return false
}

func (m *mockStrategy) Probe(ctx context.Context, target string) error {
	if m.probeDelay > 0 {
		time.Sleep(m.probeDelay)
	}
	return m.probeErr
}

func (m *mockStrategy) Connect(ctx context.Context, target string) (net.Conn, error) {
	if m.connectErr != nil {
		return nil, m.connectErr
	}

	if m.serverAddr != "" {
		return net.Dial("tcp", m.serverAddr)
	}

	return nil, fmt.Errorf("no server configured")
}

// TestHTTP2StegoAuth tests HTTP/2 steganography authentication
func TestHTTP2StegoAuth(t *testing.T) {
	secret := []byte("test-secret-key")

	// Generate auth token
	strat := NewHTTP2StegoStrategy(NewManager(), secret, "")

	// Just verify it doesn't panic and returns valid strategy
	if strat.ID() != "http2_stego" {
		t.Errorf("Wrong ID: %s", strat.ID())
	}

	if !strat.RequiresServer() {
		t.Error("HTTP/2 stego should require server")
	}
}

// Integration test with TLS mock server
func TestHTTP2StegoIntegration(t *testing.T) {
	if testing.Short() {
		t.Skip("Skipping integration test in short mode")
	}

	// This would require a full TLS mock server
	// Skipping for now as it requires certificate setup
	t.Skip("Requires TLS certificate setup")
}

// Test helper to create TLS config for testing
func testTLSConfig(t *testing.T) *tls.Config {
	// Would need to generate test certificates
	return &tls.Config{
		InsecureSkipVerify: true,
	}
}
