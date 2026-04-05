package strategy

import (
	"bufio"
	"bytes"
	"context"
	"crypto/tls"
	"encoding/hex"
	"fmt"
	"net"
	"strings"
	"time"

	"github.com/tiredvpn/tiredvpn/internal/geneva"
	"github.com/tiredvpn/tiredvpn/internal/log"
	"github.com/tiredvpn/tiredvpn/internal/padding"
)

// GenevaStrategy applies Geneva-style packet manipulation to evade DPI
// It works by fragmenting the TLS ClientHello during connection establishment
type GenevaStrategy struct {
	manager    *Manager          // Reference to Manager for IPv6/IPv4 support
	serverAddr string            // Deprecated: use manager.GetServerAddr() instead
	secret     []byte
	country    string            // "russia", "china", "iran", "turkey"
	strategies []*geneva.Strategy
	wsHost     string
	wsPath     string
}

// NewGenevaStrategy creates a new Geneva strategy for a specific country
// manager is required for IPv6/IPv4 transport layer support
func NewGenevaStrategy(manager *Manager, secret []byte, country string) *GenevaStrategy {
	return &GenevaStrategy{
		manager:    manager,
		serverAddr: "", // Deprecated: use manager.GetServerAddr() instead
		secret:     secret,
		country:    strings.ToLower(country),
		strategies: geneva.GetStrategiesByCountry(country),
		wsHost:     "cdn.jsdelivr.net", // Common CDN that's unlikely to be blocked
		wsPath:     "/npm/jquery@3.7.1/dist/jquery.min.js", // Looks like CDN request
	}
}

func (g *GenevaStrategy) ID() string {
	return fmt.Sprintf("geneva_%s", g.country)
}

func (g *GenevaStrategy) Name() string {
	countryName := map[string]string{
		"russia": "Russia TSPU",
		"ru":     "Russia TSPU",
		"china":  "China GFW",
		"cn":     "China GFW",
		"iran":   "Iran DPI",
		"ir":     "Iran DPI",
		"turkey": "Turkey DPI",
		"tr":     "Turkey DPI",
	}[g.country]

	if countryName == "" {
		countryName = "Generic"
	}

	return fmt.Sprintf("Geneva (%s)", countryName)
}

func (g *GenevaStrategy) Priority() int {
	return 12 // Between Traffic Morph (10) and Mesh (15)
}

func (g *GenevaStrategy) RequiresServer() bool {
	return true
}

func (g *GenevaStrategy) Description() string {
	count := len(g.strategies)
	rates := make([]string, 0, count)
	for _, s := range g.strategies {
		rates = append(rates, s.GetSuccessRate())
	}
	return fmt.Sprintf("Geneva packet manipulation for %s DPI evasion (%d strategies: %s)",
		g.country, count, strings.Join(rates, ", "))
}

// Connect establishes connection using Geneva-style TCP fragmentation
// The key insight: fragment the TLS ClientHello at TCP level BEFORE TLS negotiation
func (g *GenevaStrategy) Connect(ctx context.Context, target string) (net.Conn, error) {
	log.Debug("Geneva: Connecting to %s using %s strategies", target, g.country)

	// Step 1: Get server address (IPv6/IPv4 with automatic fallback)
	serverAddr := g.manager.GetServerAddr(ctx)
	log.Debug("Geneva: Using server address: %s", serverAddr)

	// Step 2: Establish TCP connection to server (context-aware, respects Android timeouts)
	dialer := &net.Dialer{}
	tcpConn, err := dialer.DialContext(ctx, "tcp", serverAddr)
	if err != nil {
		return nil, fmt.Errorf("geneva tcp dial: %w", err)
	}

	// Step 3: Wrap TCP connection with Geneva fragmentation
	// This will fragment the TLS ClientHello when TLS handshake happens
	genevaConn := NewGenevaConn(tcpConn, g.strategies, g.country)

	// Step 4: Do TLS handshake THROUGH Geneva connection
	// The Geneva wrapper will fragment the ClientHello automatically
	tlsConfig := &tls.Config{
		ServerName:         g.wsHost,
		InsecureSkipVerify: true, // Server uses self-signed cert
		MinVersion:         tls.VersionTLS12,
	}

	tlsConn := tls.Client(genevaConn, tlsConfig)
	if err := tlsConn.HandshakeContext(ctx); err != nil {
		genevaConn.Close()
		return nil, fmt.Errorf("geneva tls handshake: %w", err)
	}

	log.Debug("Geneva: TLS handshake complete, manipulation: %s", genevaConn.GetManipulation())

	// Step 5: Perform WebSocket upgrade (same format as WebSocket Salamander) with auth token
	wsKey := generateWebSocketKey()
	authToken := generateAuthToken(g.secret)
	upgradeReq := fmt.Sprintf(
		"GET %s HTTP/1.1\r\n"+
			"Host: %s\r\n"+
			"Upgrade: websocket\r\n"+
			"Connection: Upgrade\r\n"+
			"Sec-WebSocket-Key: %s\r\n"+
			"Sec-WebSocket-Version: 13\r\n"+
			"X-Salamander-Version: 1.0\r\n"+
			"X-Auth-Token: %s\r\n"+
			"User-Agent: Mozilla/5.0 (compatible; TiredVPN/2.0)\r\n"+
			"\r\n",
		g.wsPath, g.wsHost, wsKey, hex.EncodeToString(authToken))

	if _, err := tlsConn.Write([]byte(upgradeReq)); err != nil {
		tlsConn.Close()
		return nil, fmt.Errorf("geneva ws upgrade request failed: %w", err)
	}

	// Step 6: Read upgrade response
	reader := bufio.NewReader(tlsConn)
	if deadline, ok := ctx.Deadline(); ok {
		tlsConn.SetReadDeadline(deadline)
	} else {
		tlsConn.SetReadDeadline(time.Now().Add(30 * time.Second))
	}

	statusLine, err := reader.ReadString('\n')
	if err != nil {
		tlsConn.Close()
		return nil, fmt.Errorf("geneva ws upgrade: failed to read status: %w", err)
	}

	if !bytes.Contains([]byte(statusLine), []byte("101")) {
		tlsConn.Close()
		return nil, fmt.Errorf("geneva ws upgrade: failed: %s", strings.TrimSpace(statusLine))
	}

	// Read headers until empty line
	for {
		line, err := reader.ReadString('\n')
		if err != nil {
			tlsConn.Close()
			return nil, fmt.Errorf("geneva ws upgrade: failed to read headers: %w", err)
		}
		if line == "\r\n" || line == "\n" {
			break // End of headers
		}
	}

	tlsConn.SetReadDeadline(time.Time{})

	log.Info("Geneva: WebSocket upgrade successful")

	// Step 6: Wrap with SalamanderConn (handles padding)
	padder := padding.NewSalamanderPadder(g.secret, padding.Balanced)
	salamanderConn := NewSalamanderConn(tlsConn, padder, true) // true = client side

	log.Info("Geneva (%s): Connection established with %s manipulation", g.country, genevaConn.GetManipulation())

	return salamanderConn, nil
}

// Probe tests if the strategy works
func (g *GenevaStrategy) Probe(ctx context.Context, target string) error {
	conn, err := g.Connect(ctx, target)
	if err != nil {
		return err
	}
	conn.Close()
	return nil
}

// GenevaConn wraps a TCP connection with Geneva-style packet fragmentation
// It fragments the first write (TLS ClientHello) to evade DPI
type GenevaConn struct {
	net.Conn
	strategies   []*geneva.Strategy
	country      string
	isFirstWrite bool
	manipulation string
}

// NewGenevaConn creates a new Geneva-wrapped TCP connection
func NewGenevaConn(conn net.Conn, strategies []*geneva.Strategy, country string) *GenevaConn {
	return &GenevaConn{
		Conn:         conn,
		strategies:   strategies,
		country:      country,
		isFirstWrite: true,
	}
}

// Write applies Geneva manipulations to outgoing TCP data
func (g *GenevaConn) Write(p []byte) (int, error) {
	if !g.isFirstWrite || len(g.strategies) == 0 {
		return g.Conn.Write(p)
	}

	g.isFirstWrite = false

	// Check if this looks like TLS ClientHello (0x16 0x03 xx)
	if len(p) > 5 && p[0] == 0x16 && p[1] == 0x03 {
		return g.fragmentClientHello(p)
	}

	return g.Conn.Write(p)
}

// fragmentClientHello fragments TLS ClientHello to evade DPI
// Key technique: split at strategic points so DPI can't reassemble
func (g *GenevaConn) fragmentClientHello(p []byte) (int, error) {
	stratName := "default"
	if len(g.strategies) > 0 {
		stratName = g.strategies[0].GetName()
	}

	log.Debug("Geneva: Fragmenting ClientHello (%d bytes) using %s", len(p), stratName)

	// Different fragmentation strategies based on country
	var fragments [][]byte

	switch g.country {
	case "russia", "ru":
		// TSPU is defeated by fragmenting after TLS record header
		// Split: [5 bytes header] [rest in small chunks]
		fragments = g.fragmentForTSPU(p)
		g.manipulation = "TSPU-fragment"

	case "china", "cn":
		// GFW is defeated by very small initial fragment + delays
		// Split: [1 byte] [delay] [rest]
		fragments = g.fragmentForGFW(p)
		g.manipulation = "GFW-fragment"

	case "iran", "ir":
		// Iran DPI is defeated by fragmenting in the middle of SNI
		fragments = g.fragmentAtSNI(p)
		g.manipulation = "SNI-fragment"

	case "turkey", "tr":
		// Turkey uses similar techniques to Iran
		fragments = g.fragmentAtSNI(p)
		g.manipulation = "SNI-fragment"

	default:
		// Generic: small chunks with delays
		fragments = g.fragmentGeneric(p)
		g.manipulation = "generic-fragment"
	}

	// Send fragments without timing delay
	// Fragmentation works due to fragment SIZE, not timing
	// 1ms delay between fragments caused TLS handshake timeout on server (io.ReadFull blocks)
	totalWritten := 0
	for _, frag := range fragments {
		n, err := g.Conn.Write(frag)
		totalWritten += n
		if err != nil {
			return totalWritten, err
		}
	}

	log.Debug("Geneva: Sent %d fragments, total %d bytes", len(fragments), totalWritten)
	return totalWritten, nil
}

// fragmentForTSPU creates fragments optimized for Russian TSPU bypass
func (g *GenevaConn) fragmentForTSPU(p []byte) [][]byte {
	if len(p) < 10 {
		return [][]byte{p}
	}

	// TSPU key: split after TLS record header (5 bytes) + 1 byte
	// This breaks the DPI's ability to parse handshake type
	fragments := [][]byte{
		p[:6],  // TLS header + 1 byte of handshake
	}

	// Rest in 50-byte chunks
	remaining := p[6:]
	for len(remaining) > 0 {
		size := 50
		if size > len(remaining) {
			size = len(remaining)
		}
		fragments = append(fragments, remaining[:size])
		remaining = remaining[size:]
	}

	return fragments
}

// fragmentForGFW creates fragments optimized for China GFW bypass
func (g *GenevaConn) fragmentForGFW(p []byte) [][]byte {
	if len(p) < 10 {
		return [][]byte{p}
	}

	// GFW key: very small first fragment (1-3 bytes)
	// This causes GFW to timeout waiting for complete record
	fragments := [][]byte{
		p[:1],  // Just 1 byte
		p[1:5], // Rest of TLS header
	}

	// Rest in medium chunks
	remaining := p[5:]
	for len(remaining) > 0 {
		size := 100
		if size > len(remaining) {
			size = len(remaining)
		}
		fragments = append(fragments, remaining[:size])
		remaining = remaining[size:]
	}

	return fragments
}

// fragmentAtSNI fragments specifically to split the SNI extension
func (g *GenevaConn) fragmentAtSNI(p []byte) [][]byte {
	if len(p) < 50 {
		return [][]byte{p}
	}

	// Find SNI extension (type 0x00 0x00) in ClientHello
	// SNI is usually around offset 40-100
	sniOffset := -1
	for i := 40; i < len(p)-5 && i < 200; i++ {
		// Look for SNI extension type (0x00 0x00)
		if p[i] == 0x00 && p[i+1] == 0x00 {
			// Verify it looks like SNI (next bytes are length)
			if p[i+2] == 0x00 && p[i+4] == 0x00 {
				sniOffset = i + 5 // Point to start of hostname
				break
			}
		}
	}

	if sniOffset > 0 && sniOffset < len(p)-10 {
		// Split in the middle of the SNI hostname
		splitPoint := sniOffset + 5 // Few bytes into hostname
		return [][]byte{
			p[:splitPoint],
			p[splitPoint:],
		}
	}

	// Fallback: generic fragmentation
	return g.fragmentGeneric(p)
}

// fragmentGeneric creates generic small fragments
func (g *GenevaConn) fragmentGeneric(p []byte) [][]byte {
	var fragments [][]byte
	chunkSize := 30 // Small chunks

	for len(p) > 0 {
		size := chunkSize
		if size > len(p) {
			size = len(p)
		}
		fragments = append(fragments, p[:size])
		p = p[size:]
	}

	return fragments
}

// GetManipulation returns description of applied manipulation
func (g *GenevaConn) GetManipulation() string {
	if g.manipulation == "" {
		return "none"
	}
	return g.manipulation
}

// Ensure interface compliance
var _ net.Conn = (*GenevaConn)(nil)
