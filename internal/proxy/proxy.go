package proxy

import (
	"encoding/binary"
	"fmt"
	"io"
	"log"
	"net"
	"sync"
	"time"

	"github.com/tiredvpn/tiredvpn/internal/config"
	"github.com/tiredvpn/tiredvpn/internal/evasion"
	tlsutil "github.com/tiredvpn/tiredvpn/internal/tls"
	"github.com/tiredvpn/tiredvpn/internal/tunnel"
)

// Proxy is the main SOCKS5 proxy server with DPI evasion
type Proxy struct {
	config     *config.Config
	listener   net.Listener
	sniRotator *evasion.SNIRotator

	mu          sync.Mutex
	connections map[string]net.Conn
	closed      bool
}

// New creates a new proxy server
func New(cfg *config.Config) (*Proxy, error) {
	// Initialize SNI rotator
	var strategy evasion.RotationStrategy
	switch cfg.Mode {
	case config.ModeGRPC:
		strategy = evasion.StrategyWeighted // Prefer Google SNIs
	case config.ModeWebSocket:
		strategy = evasion.StrategyCooldown
	default:
		strategy = evasion.StrategyRandom
	}

	rotator := evasion.NewSNIRotator(strategy)

	// Override with custom pool if provided
	if len(cfg.SNIPool) > 0 {
		rotator = evasion.NewSNIRotatorWithPool(cfg.SNIPool, strategy)
	}

	return &Proxy{
		config:      cfg,
		sniRotator:  rotator,
		connections: make(map[string]net.Conn),
	}, nil
}

// ListenAndServe starts the SOCKS5 proxy server
func (p *Proxy) ListenAndServe() error {
	listener, err := net.Listen("tcp", p.config.ListenAddr)
	if err != nil {
		return fmt.Errorf("failed to listen on %s: %w", p.config.ListenAddr, err)
	}
	p.listener = listener

	log.Printf("SOCKS5 proxy listening on %s", p.config.ListenAddr)

	for {
		conn, err := listener.Accept()
		if err != nil {
			if p.closed {
				return nil
			}
			log.Printf("Accept error: %v", err)
			continue
		}

		go p.handleConnection(conn)
	}
}

// Close shuts down the proxy
func (p *Proxy) Close() error {
	p.mu.Lock()
	p.closed = true
	p.mu.Unlock()

	if p.listener != nil {
		p.listener.Close()
	}

	// Close all active connections
	p.mu.Lock()
	for _, conn := range p.connections {
		conn.Close()
	}
	p.mu.Unlock()

	return nil
}

// handleConnection handles a single SOCKS5 client connection
func (p *Proxy) handleConnection(clientConn net.Conn) {
	defer clientConn.Close()

	connID := clientConn.RemoteAddr().String()
	p.mu.Lock()
	p.connections[connID] = clientConn
	p.mu.Unlock()

	defer func() {
		p.mu.Lock()
		delete(p.connections, connID)
		p.mu.Unlock()
	}()

	// SOCKS5 handshake
	if err := p.socks5Handshake(clientConn); err != nil {
		if p.config.Verbose {
			log.Printf("[%s] SOCKS5 handshake failed: %v", connID, err)
		}
		return
	}

	// Get target address from SOCKS5 request
	targetAddr, err := p.socks5Request(clientConn)
	if err != nil {
		if p.config.Verbose {
			log.Printf("[%s] SOCKS5 request failed: %v", connID, err)
		}
		return
	}

	if p.config.Verbose {
		log.Printf("[%s] Connecting to %s via %s mode", connID, targetAddr, p.config.Mode)
	}

	// Establish tunnel to remote server
	tunnelConn, err := p.establishTunnel(targetAddr)
	if err != nil {
		log.Printf("[%s] Failed to establish tunnel: %v", connID, err)
		p.socks5Reply(clientConn, 0x04) // Host unreachable
		return
	}
	defer tunnelConn.Close()

	// Send success reply
	p.socks5Reply(clientConn, 0x00)

	// Proxy data bidirectionally
	p.relay(clientConn, tunnelConn)
}

// socks5Handshake performs SOCKS5 authentication handshake
func (p *Proxy) socks5Handshake(conn net.Conn) error {
	// Read version and auth methods
	buf := make([]byte, 258)
	n, err := conn.Read(buf)
	if err != nil || n < 2 {
		return fmt.Errorf("failed to read SOCKS5 greeting: %w", err)
	}

	if buf[0] != 0x05 {
		return fmt.Errorf("unsupported SOCKS version: %d", buf[0])
	}

	// We only support no authentication
	// Reply: version (0x05) + method (0x00 = no auth)
	_, err = conn.Write([]byte{0x05, 0x00})
	return err
}

// socks5Request reads and parses SOCKS5 connect request
func (p *Proxy) socks5Request(conn net.Conn) (string, error) {
	// Request format:
	// VER(1) + CMD(1) + RSV(1) + ATYP(1) + DST.ADDR(variable) + DST.PORT(2)
	buf := make([]byte, 4)
	if _, err := io.ReadFull(conn, buf); err != nil {
		return "", fmt.Errorf("failed to read SOCKS5 request: %w", err)
	}

	if buf[0] != 0x05 {
		return "", fmt.Errorf("unsupported SOCKS version: %d", buf[0])
	}

	if buf[1] != 0x01 {
		return "", fmt.Errorf("unsupported command: %d (only CONNECT supported)", buf[1])
	}

	var host string
	switch buf[3] { // ATYP
	case 0x01: // IPv4
		addr := make([]byte, 4)
		if _, err := io.ReadFull(conn, addr); err != nil {
			return "", err
		}
		host = net.IP(addr).String()

	case 0x03: // Domain name
		lenBuf := make([]byte, 1)
		if _, err := io.ReadFull(conn, lenBuf); err != nil {
			return "", err
		}
		domain := make([]byte, lenBuf[0])
		if _, err := io.ReadFull(conn, domain); err != nil {
			return "", err
		}
		host = string(domain)

	case 0x04: // IPv6
		addr := make([]byte, 16)
		if _, err := io.ReadFull(conn, addr); err != nil {
			return "", err
		}
		host = net.IP(addr).String()

	default:
		return "", fmt.Errorf("unsupported address type: %d", buf[3])
	}

	// Read port
	portBuf := make([]byte, 2)
	if _, err := io.ReadFull(conn, portBuf); err != nil {
		return "", err
	}
	port := binary.BigEndian.Uint16(portBuf)

	return fmt.Sprintf("%s:%d", host, port), nil
}

// socks5Reply sends SOCKS5 reply
func (p *Proxy) socks5Reply(conn net.Conn, status byte) {
	// Reply: VER(1) + REP(1) + RSV(1) + ATYP(1) + BND.ADDR(4) + BND.PORT(2)
	reply := []byte{
		0x05,                   // VER
		status,                 // REP
		0x00,                   // RSV
		0x01,                   // ATYP: IPv4
		0x00, 0x00, 0x00, 0x00, // BND.ADDR
		0x00, 0x00, // BND.PORT
	}
	conn.Write(reply)
}

// establishTunnel creates a tunnel to the remote server with DPI evasion
func (p *Proxy) establishTunnel(targetAddr string) (net.Conn, error) {
	// Get SNI for this connection
	coverSNI := p.config.CoverSNI
	if coverSNI == "" || coverSNI == "rotate" {
		coverSNI = p.sniRotator.Next()
	}

	// Establish TCP connection to remote tunnel server
	tcpConn, err := net.DialTimeout("tcp", p.config.RemoteAddr, p.config.ConnectTimeout)
	if err != nil {
		return nil, fmt.Errorf("failed to connect to %s: %w", p.config.RemoteAddr, err)
	}

	// Apply fragmentation if enabled
	conn := tcpConn
	if p.config.Fragment.Enabled {
		fragConfig := &evasion.FragmentationConfig{
			FragmentSize:       p.config.Fragment.Size,
			SplitPosition:      p.config.Fragment.SplitPosition,
			FragmentDelay:      p.config.Fragment.Delay,
			BufferFlood:        p.config.Fragment.BufferFlood,
			BufferFloodCount:   p.config.Fragment.BufferFloodSize,
			BufferFloodTTL:     2,
			BufferFloodTimeout: 6 * time.Second,
		}
		conn = evasion.NewFragmentedWriter(tcpConn, fragConfig)
	}

	// Inject fake packets if enabled
	if p.config.FakePacket.Enabled {
		if err := p.injectFakePackets(tcpConn, coverSNI); err != nil {
			// Log but continue - fake injection is best effort
			if p.config.Verbose {
				log.Printf("Fake packet injection warning: %v", err)
			}
		}
	}

	// Establish TLS with browser fingerprint
	tlsConfig := &tlsutil.Config{
		ServerName:  coverSNI,
		Fingerprint: p.config.TLSFingerprint,
		ALPN:        p.config.ALPN,
	}

	fp, ok := tlsutil.FingerprintMap[p.config.TLSFingerprint]
	if !ok {
		fp = tlsutil.FingerprintChrome124
	}

	tlsConn, err := tlsutil.ClientWithConn(conn, tlsConfig, fp)
	if err != nil {
		tcpConn.Close()
		return nil, fmt.Errorf("TLS handshake failed: %w", err)
	}

	// Wrap with tunnel protocol based on mode
	switch p.config.Mode {
	case config.ModeGRPC:
		grpcConfig := &tunnel.GRPCConfig{
			ServiceName:   p.config.GRPC.ServiceName,
			MethodName:    p.config.GRPC.MethodName,
			Authority:     coverSNI,
			UserAgent:     p.config.GRPC.Headers["user-agent"],
			ContentType:   p.config.GRPC.Headers["content-type"],
			GRPCEncoding:  p.config.GRPC.Headers["grpc-encoding"],
			EnablePadding: p.config.GRPC.Padding,
		}
		return tunnel.NewGRPCTunnel(tlsConn, grpcConfig)

	case config.ModeWebSocket:
		wsConfig := &tunnel.WebSocketConfig{
			Host:            coverSNI,
			Path:            p.config.WebSocket.Path,
			Origin:          fmt.Sprintf("https://%s", coverSNI),
			CustomHeaders:   p.config.WebSocket.Headers,
			UseBinaryFrames: p.config.WebSocket.BinaryFrames,
			PingInterval:    p.config.WebSocket.PingInterval,
		}
		return tunnel.NewWebSocketTunnel(tlsConn, wsConfig)

	case config.ModeFragment:
		// Already applied fragmentation, use raw TLS
		return tlsConn, nil

	case config.ModeFake:
		// Already injected fake packets, use raw TLS
		return tlsConn, nil

	case config.ModeCombo:
		// Combined mode: uses all techniques
		// Fragmentation + Fake already applied
		// Wrap in gRPC tunnel
		grpcConfig := tunnel.DefaultGRPCConfig(coverSNI)
		return tunnel.NewGRPCTunnel(tlsConn, grpcConfig)

	default:
		// Raw TLS tunnel
		return tlsConn, nil
	}
}

// injectFakePackets injects fake ClientHello packets to confuse DPI
func (p *Proxy) injectFakePackets(conn net.Conn, coverSNI string) error {
	rawSocket, err := evasion.NewRawSocket()
	if err != nil {
		return err // Requires root - best effort
	}
	defer rawSocket.Close()

	localAddr := conn.LocalAddr().(*net.TCPAddr)
	remoteAddr := conn.RemoteAddr().(*net.TCPAddr)

	injector := evasion.NewFakePacketInjector(evasion.FakePacketConfig{
		TTL:         p.config.FakePacket.TTL,
		BadChecksum: p.config.FakePacket.BadChecksum,
		BadSeq:      p.config.FakePacket.BadSeq,
		FakeSNI:     p.config.FakePacket.FakeSNI,
		Count:       p.config.FakePacket.Count,
	})

	// We need to get TCP sequence numbers - simplified version
	// In production, this would require packet sniffing or kernel integration
	seqNum := uint32(0) // Placeholder - real impl needs actual seq
	ackNum := uint32(0)

	return injector.InjectFakeClientHello(
		rawSocket,
		localAddr.IP, remoteAddr.IP,
		uint16(localAddr.Port), uint16(remoteAddr.Port),
		seqNum, ackNum,
	)
}

// relay proxies data between two connections
func (p *Proxy) relay(client, remote net.Conn) {
	done := make(chan struct{}, 2)

	// Client -> Remote
	go func() {
		io.Copy(remote, client)
		remote.SetReadDeadline(time.Now().Add(5 * time.Second))
		done <- struct{}{}
	}()

	// Remote -> Client
	go func() {
		io.Copy(client, remote)
		client.SetReadDeadline(time.Now().Add(5 * time.Second))
		done <- struct{}{}
	}()

	// Wait for one direction to finish
	<-done

	// Give the other direction a chance to finish
	select {
	case <-done:
	case <-time.After(5 * time.Second):
	}
}

// Stats returns current connection statistics
func (p *Proxy) Stats() (int, []string) {
	p.mu.Lock()
	defer p.mu.Unlock()

	addrs := make([]string, 0, len(p.connections))
	for addr := range p.connections {
		addrs = append(addrs, addr)
	}

	return len(p.connections), addrs
}
