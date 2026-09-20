package strategy

import (
	"context"
	"crypto/hmac"
	"crypto/sha256"
	"crypto/tls"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"net"
	"sort"
	"sync"
	"time"

	customtls "github.com/tiredvpn/tiredvpn/internal/tls"
)

// MeshRelayStrategy routes traffic through intermediate relays inside Russia
// Internal RU traffic is not filtered as heavily by TSPU
type MeshRelayStrategy struct {
	relays      []*RelayNode
	exitNode    string // Final exit node outside RU
	mu          sync.RWMutex
	healthCheck time.Duration
}

// RelayNode represents a relay node in the mesh
type RelayNode struct {
	Address   string        `json:"address"`   // host:port
	Location  string        `json:"location"`  // e.g., "RU-Moscow", "RU-SPB"
	Type      RelayType     `json:"type"`      // home, vps, friend
	Latency   time.Duration `json:"latency"`   // measured latency
	Available bool          `json:"available"` // is node up
	LastCheck time.Time     `json:"last_check"`
	Load      float64       `json:"load"`   // current load 0-1
	Secret    string        `json:"secret"` // shared secret for auth
}

// RelayType defines the type of relay node
type RelayType string

const (
	RelayTypeHome   RelayType = "home"   // Home server/Raspberry Pi
	RelayTypeVPS    RelayType = "vps"    // VPS in Russia
	RelayTypeFriend RelayType = "friend" // Friend's computer
	RelayTypePublic RelayType = "public" // Public relay (less trusted)
)

// NewMeshRelayStrategy creates a new mesh relay strategy
func NewMeshRelayStrategy(exitNode string) *MeshRelayStrategy {
	return &MeshRelayStrategy{
		relays:      make([]*RelayNode, 0),
		exitNode:    exitNode,
		healthCheck: 30 * time.Second,
	}
}

// AddRelay adds a relay node to the mesh
func (s *MeshRelayStrategy) AddRelay(node *RelayNode) {
	s.mu.Lock()
	defer s.mu.Unlock()
	s.relays = append(s.relays, node)
}

// AddRelays adds multiple relays
func (s *MeshRelayStrategy) AddRelays(nodes []*RelayNode) {
	s.mu.Lock()
	defer s.mu.Unlock()
	s.relays = append(s.relays, nodes...)
}

func (s *MeshRelayStrategy) Name() string {
	return "Mesh Relay (RU internal)"
}

func (s *MeshRelayStrategy) ID() string {
	return "mesh_relay"
}

func (s *MeshRelayStrategy) Priority() int {
	return 15 // High priority - often works well
}

func (s *MeshRelayStrategy) Description() string {
	return "Routes through relay nodes inside Russia (internal traffic not heavily filtered)"
}

func (s *MeshRelayStrategy) RequiresServer() bool {
	return true // Needs relay nodes and exit node
}

func (s *MeshRelayStrategy) Probe(ctx context.Context, target string) error {
	// Check if we have any available relays
	s.mu.RLock()
	defer s.mu.RUnlock()

	if len(s.relays) == 0 {
		return errors.New("no relay nodes configured")
	}

	// Check at least one relay is available
	for _, relay := range s.relays {
		if relay.Available {
			return nil
		}
	}

	return errors.New("no available relay nodes")
}

func (s *MeshRelayStrategy) Connect(ctx context.Context, target string) (net.Conn, error) {
	// Bound the number of attempts by the relay count so a chain of failing
	// relays can't loop forever. selectBestRelay always picks the best of the
	// currently-available relays, and a failed relay is marked unavailable
	// below, so each iteration narrows the candidate set.
	maxAttempts := s.relayCount()
	if maxAttempts == 0 {
		return nil, errors.New("no available relays")
	}

	var lastErr error
	for attempt := 0; attempt < maxAttempts; attempt++ {
		// Select best relay
		relay, err := s.selectBestRelay()
		if err != nil {
			if lastErr != nil {
				return nil, lastErr
			}
			return nil, err
		}

		// Connect to relay
		relayConn, err := s.connectToRelay(ctx, relay)
		if err != nil {
			// Mark relay as unavailable and try next.
			// Mutate relay fields under s.mu: selectBestRelay/Probe read
			// Available under the same lock. s.mu is not held here (Connect
			// and connectToRelay don't hold it), so this is deadlock-free.
			s.markRelayUnavailable(relay)
			lastErr = err
			continue
		}

		// Ask relay to connect to exit node
		exitConn, err := s.connectThroughRelay(relayConn, s.exitNode)
		if err != nil {
			relayConn.Close()
			return nil, err
		}

		// Return wrapped connection
		return &MeshConn{
			Conn:     exitConn,
			relay:    relay,
			exitNode: s.exitNode,
		}, nil
	}

	if lastErr != nil {
		return nil, lastErr
	}
	return nil, errors.New("no available relays")
}

// relayCount returns the number of configured relays under the lock.
func (s *MeshRelayStrategy) relayCount() int {
	s.mu.RLock()
	defer s.mu.RUnlock()
	return len(s.relays)
}

// markRelayUnavailable flips a relay's Available flag under the write lock so
// it is safe against concurrent selectBestRelay/Probe readers.
func (s *MeshRelayStrategy) markRelayUnavailable(relay *RelayNode) {
	s.mu.Lock()
	defer s.mu.Unlock()
	relay.Available = false
}

// selectBestRelay chooses the best available relay
func (s *MeshRelayStrategy) selectBestRelay() (*RelayNode, error) {
	s.mu.RLock()
	defer s.mu.RUnlock()

	// Filter available relays
	available := make([]*RelayNode, 0)
	for _, r := range s.relays {
		if r.Available {
			available = append(available, r)
		}
	}

	if len(available) == 0 {
		return nil, errors.New("no available relays")
	}

	// Sort by score (latency + load)
	sort.Slice(available, func(i, j int) bool {
		scoreI := float64(available[i].Latency.Milliseconds()) + available[i].Load*100
		scoreJ := float64(available[j].Latency.Milliseconds()) + available[j].Load*100
		return scoreI < scoreJ
	})

	return available[0], nil
}

// connectToRelay establishes connection to relay node
func (s *MeshRelayStrategy) connectToRelay(ctx context.Context, relay *RelayNode) (net.Conn, error) {
	dialer := &net.Dialer{Timeout: 10 * time.Second}
	conn, err := dialer.DialContext(ctx, "tcp", relay.Address)
	if err != nil {
		return nil, err
	}

	// Upgrade to TLS
	tlsConn := tls.Client(conn, &tls.Config{
		InsecureSkipVerify: true, // Relay uses self-signed cert
		NextProtos:         []string{"mesh-v1"},
	})

	if err := tlsConn.HandshakeContext(ctx); err != nil {
		conn.Close()
		return nil, err
	}

	// Bind the relay auth to this TLS session: a proof lifted from one session
	// is worthless on another, which matters because the relay uses a
	// self-signed cert (InsecureSkipVerify), so the certificate proves nothing.
	state := tlsConn.ConnectionState()
	ekm, err := customtls.ExportBindingKey(&state)
	if err != nil {
		tlsConn.Close()
		return nil, fmt.Errorf("mesh relay: export keying material: %w", err)
	}

	// Authenticate with relay
	if err := s.authenticateRelay(tlsConn, relay, ekm); err != nil {
		tlsConn.Close()
		return nil, err
	}

	return tlsConn, nil
}

// Mesh relay challenge-response constants. The v1 auth put the shared secret in
// a JSON body on the wire, so anyone who could read one handshake (the relay
// operator, a compromised relay, a passive tap that broke the self-signed TLS)
// learned the secret verbatim and could reuse it forever. v2 keeps the secret
// off the wire: the relay sends a fresh challenge, the client answers with an
// HMAC over the challenge and the TLS-session exporter, and the relay recomputes
// and compares it.
const (
	meshChallengeLen = 32
	meshProofLen     = 32
	meshAuthLabel    = "tiredvpn-mesh-relay-auth"
)

// MeshRelayProof is the client's answer to a relay challenge: HMAC over the
// challenge and the TLS-session exporter, keyed by the shared secret. Exported
// so the relay server (out of this repo) and the tests recompute it the same
// way.
func MeshRelayProof(secret string, challenge, ekm []byte) [meshProofLen]byte {
	mac := hmac.New(sha256.New, []byte(secret))
	mac.Write([]byte(meshAuthLabel))
	mac.Write(challenge)
	mac.Write(ekm)
	var out [meshProofLen]byte
	copy(out[:], mac.Sum(nil))
	return out
}

// authenticateRelay proves knowledge of the relay secret without sending it.
func (s *MeshRelayStrategy) authenticateRelay(conn net.Conn, relay *RelayNode, ekm []byte) error {
	// A relay with no secret is a misconfiguration, not a default: refuse rather
	// than authenticate against "". This is the single choke point every relay
	// dial passes through, so it covers relays added by AddRelay, AddRelays and
	// LoadRelaysFromConfig alike.
	if relay.Secret == "" {
		return errors.New("mesh relay: empty secret, refusing to authenticate")
	}

	// The relay speaks first with a fresh challenge.
	challenge := make([]byte, meshChallengeLen)
	conn.SetReadDeadline(time.Now().Add(10 * time.Second))
	if _, err := io.ReadFull(conn, challenge); err != nil {
		return fmt.Errorf("mesh relay: read challenge: %w", err)
	}
	conn.SetReadDeadline(time.Time{})

	// Answer with the keyed proof; the secret itself never leaves this process.
	proof := MeshRelayProof(relay.Secret, challenge, ekm)
	if _, err := conn.Write(proof[:]); err != nil {
		return fmt.Errorf("mesh relay: write proof: %w", err)
	}

	resp := make([]byte, 1)
	if _, err := io.ReadFull(conn, resp); err != nil {
		return fmt.Errorf("mesh relay: read auth response: %w", err)
	}
	if resp[0] != 0x01 {
		return errors.New("mesh relay: authentication failed")
	}

	return nil
}

// connectThroughRelay asks relay to connect to target
func (s *MeshRelayStrategy) connectThroughRelay(relayConn net.Conn, target string) (net.Conn, error) {
	// Send CONNECT request
	req := MeshConnectRequest{
		Target: target,
	}

	data, _ := json.Marshal(req)
	header := make([]byte, 2)
	header[0] = 0x01 // CONNECT command
	header[1] = byte(len(data))

	_, err := relayConn.Write(append(header, data...))
	if err != nil {
		return nil, err
	}

	// Read response
	resp := make([]byte, 1)
	_, err = relayConn.Read(resp)
	if err != nil {
		return nil, err
	}

	if resp[0] != 0x00 {
		return nil, fmt.Errorf("relay connect failed: %d", resp[0])
	}

	// Connection is now proxied through relay to target
	return relayConn, nil
}

// StartHealthChecker starts background health checking
func (s *MeshRelayStrategy) StartHealthChecker(ctx context.Context) {
	go func() {
		ticker := time.NewTicker(s.healthCheck)
		defer ticker.Stop()

		for {
			select {
			case <-ctx.Done():
				return
			case <-ticker.C:
				s.checkRelayHealth()
			}
		}
	}()
}

// checkRelayHealth checks health of all relays
func (s *MeshRelayStrategy) checkRelayHealth() {
	s.mu.Lock()
	relays := make([]*RelayNode, len(s.relays))
	copy(relays, s.relays)
	s.mu.Unlock()

	var wg sync.WaitGroup
	for _, relay := range relays {
		wg.Add(1)
		go func(r *RelayNode) {
			defer wg.Done()

			start := time.Now()
			conn, err := net.DialTimeout("tcp", r.Address, 5*time.Second)
			if err != nil {
				// Mutate the relay's fields under the same lock selectBestRelay
				// and Probe read them with; without it these writes race the
				// selector (caught by -race in TestMeshHealthCheckNoRace).
				s.mu.Lock()
				r.Available = false
				s.mu.Unlock()
				return
			}
			conn.Close()

			latency := time.Since(start)
			now := time.Now()
			s.mu.Lock()
			r.Latency = latency
			r.Available = true
			r.LastCheck = now
			s.mu.Unlock()
		}(relay)
	}
	wg.Wait()
}

// MeshConn wraps a connection through the mesh
type MeshConn struct {
	net.Conn
	relay    *RelayNode
	exitNode string
}

// RelayInfo returns info about the relay being used
func (mc *MeshConn) RelayInfo() *RelayNode {
	return mc.relay
}

// MeshConnectRequest asks relay to connect to target
type MeshConnectRequest struct {
	Target string `json:"target"`
}

// GetRelays returns current relay list
func (s *MeshRelayStrategy) GetRelays() []*RelayNode {
	s.mu.RLock()
	defer s.mu.RUnlock()

	result := make([]*RelayNode, len(s.relays))
	copy(result, s.relays)
	return result
}

// LoadRelaysFromConfig loads relays from JSON config
func (s *MeshRelayStrategy) LoadRelaysFromConfig(data []byte) error {
	var relays []*RelayNode
	if err := json.Unmarshal(data, &relays); err != nil {
		return err
	}

	s.mu.Lock()
	s.relays = relays
	s.mu.Unlock()

	return nil
}

// ExampleRelayConfig returns example relay configuration. The Secret fields are
// left empty on purpose: there is no shipped default. A relay dialed with an
// empty secret is refused at authenticateRelay, so a config copied from this
// example fails loudly until the operator fills in a real per-relay secret,
// rather than silently authenticating against a well-known placeholder.
func ExampleRelayConfig() string {
	relays := []*RelayNode{
		{
			Address:   "192.168.1.100:8443",
			Location:  "RU-Moscow-Home",
			Type:      RelayTypeHome,
			Available: true,
			Secret:    "",
		},
		{
			Address:   "10.0.0.5:443",
			Location:  "RU-SPB-Friend",
			Type:      RelayTypeFriend,
			Available: true,
			Secret:    "",
		},
	}

	data, _ := json.MarshalIndent(relays, "", "  ")
	return string(data)
}

// Ensure interface compliance
var _ io.ReadWriteCloser = (*MeshConn)(nil)
