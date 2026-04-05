package tls

import (
	"crypto/sha256"
	"encoding/hex"
	"fmt"
	"net"
	"strings"

	utls "github.com/refraction-networking/utls"
)

// BrowserFingerprint represents a browser's TLS fingerprint
type BrowserFingerprint struct {
	Name        string
	JA3         string
	ClientHello *utls.ClientHelloID
}

// Predefined browser fingerprints
// These match real browser signatures to evade JA3-based detection
var (
	// Chrome 120 on Windows - most common fingerprint globally
	FingerprintChrome120 = &BrowserFingerprint{
		Name:        "Chrome 120",
		ClientHello: &utls.HelloChrome_120,
	}

	// Chrome 124 - latest stable
	FingerprintChrome124 = &BrowserFingerprint{
		Name:        "Chrome 124",
		ClientHello: &utls.HelloChrome_Auto,
	}

	// Firefox 121
	FingerprintFirefox121 = &BrowserFingerprint{
		Name:        "Firefox 121",
		ClientHello: &utls.HelloFirefox_Auto,
	}

	// Safari 17.2
	FingerprintSafari17 = &BrowserFingerprint{
		Name:        "Safari 17",
		ClientHello: &utls.HelloSafari_Auto,
	}

	// Edge (Chromium-based)
	FingerprintEdge = &BrowserFingerprint{
		Name:        "Edge 120",
		ClientHello: &utls.HelloEdge_Auto,
	}

	// iOS Safari
	FingerprintiOS = &BrowserFingerprint{
		Name:        "iOS Safari",
		ClientHello: &utls.HelloIOS_Auto,
	}

	// Android Chrome
	FingerprintAndroid = &BrowserFingerprint{
		Name:        "Android Chrome",
		ClientHello: &utls.HelloAndroid_11_OkHttp,
	}

	// Randomized - changes per connection
	FingerprintRandomized = &BrowserFingerprint{
		Name:        "Randomized",
		ClientHello: &utls.HelloRandomized,
	}
)

// FingerprintMap maps names to fingerprints
var FingerprintMap = map[string]*BrowserFingerprint{
	"chrome":     FingerprintChrome124,
	"chrome120":  FingerprintChrome120,
	"chrome124":  FingerprintChrome124,
	"firefox":    FingerprintFirefox121,
	"safari":     FingerprintSafari17,
	"edge":       FingerprintEdge,
	"ios":        FingerprintiOS,
	"android":    FingerprintAndroid,
	"randomized": FingerprintRandomized,
}

// TLSConn wraps uTLS connection with fingerprint support
type TLSConn struct {
	*utls.UConn
	fingerprint *BrowserFingerprint
	sni         string
}

// Config for TLS connection
type Config struct {
	ServerName      string   // SNI
	Fingerprint     string   // Browser fingerprint name
	ALPN            []string // Application-Layer Protocol Negotiation
	InsecureSkipVerify bool  // Skip certificate verification (for testing)

	// Advanced options
	SessionTicket   []byte   // Session resumption ticket
	UseECH          bool     // Use Encrypted Client Hello (if available)
	PaddingLen      int      // Pad ClientHello to this length
}

// DefaultConfig returns default TLS config
func DefaultConfig(serverName string) *Config {
	return &Config{
		ServerName:  serverName,
		Fingerprint: "chrome",
		ALPN:        []string{"h2", "http/1.1"},
		InsecureSkipVerify: false,
	}
}

// Dial creates a new TLS connection with browser fingerprint
func Dial(network, addr string, config *Config) (*TLSConn, error) {
	// Get fingerprint
	fp, ok := FingerprintMap[strings.ToLower(config.Fingerprint)]
	if !ok {
		fp = FingerprintChrome124 // Default to Chrome
	}

	// Establish TCP connection
	tcpConn, err := net.Dial(network, addr)
	if err != nil {
		return nil, fmt.Errorf("tcp dial failed: %w", err)
	}

	return ClientWithConn(tcpConn, config, fp)
}

// ClientWithConn wraps existing connection with TLS
func ClientWithConn(conn net.Conn, config *Config, fp *BrowserFingerprint) (*TLSConn, error) {
	// Create uTLS config
	tlsConfig := &utls.Config{
		ServerName:         config.ServerName,
		InsecureSkipVerify: config.InsecureSkipVerify,
		NextProtos:         config.ALPN,
	}

	// Create uTLS connection
	uconn := utls.UClient(conn, tlsConfig, *fp.ClientHello)

	// Apply custom ClientHello modifications if needed
	if config.PaddingLen > 0 {
		if err := applyPadding(uconn, config.PaddingLen); err != nil {
			conn.Close()
			return nil, fmt.Errorf("padding failed: %w", err)
		}
	}

	// Perform handshake
	if err := uconn.Handshake(); err != nil {
		conn.Close()
		return nil, fmt.Errorf("tls handshake failed: %w", err)
	}

	return &TLSConn{
		UConn:       uconn,
		fingerprint: fp,
		sni:         config.ServerName,
	}, nil
}

// applyPadding adds padding to ClientHello
func applyPadding(conn *utls.UConn, targetLen int) error {
	// Get current ClientHello spec
	spec, err := utls.UTLSIdToSpec(conn.ClientHelloID)
	if err != nil {
		return err
	}

	// Add padding extension
	spec.Extensions = append(spec.Extensions, &utls.UtlsPaddingExtension{
		PaddingLen: targetLen,
		WillPad:    true,
	})

	return conn.ApplyPreset(&spec)
}

// GetNegotiatedProtocol returns the negotiated ALPN protocol
func (c *TLSConn) GetNegotiatedProtocol() string {
	state := c.ConnectionState()
	return state.NegotiatedProtocol
}

// GetFingerprint returns the used fingerprint
func (c *TLSConn) GetFingerprint() string {
	return c.fingerprint.Name
}

// GetSNI returns the SNI used
func (c *TLSConn) GetSNI() string {
	return c.sni
}

// CalculateJA3 calculates JA3 fingerprint of the connection
func (c *TLSConn) CalculateJA3() string {
	state := c.ConnectionState()

	// JA3 format: SSLVersion,Ciphers,Extensions,EllipticCurves,EllipticCurvePointFormats
	// Simplified version - real implementation needs ClientHello parsing
	ja3String := fmt.Sprintf("%d,%d", state.Version, state.CipherSuite)

	hash := sha256.Sum256([]byte(ja3String))
	return hex.EncodeToString(hash[:])
}

// BuildClientHelloBytes builds raw ClientHello bytes for custom sending
// This is useful for fragmentation and fake packet attacks
// If config.PaddingLen > 0, a padding extension is added to the ClientHello
func BuildClientHelloBytes(config *Config, fp *BrowserFingerprint) ([]byte, error) {
	// Create a dummy connection to extract ClientHello
	// We'll use a pipe for this
	client, server := net.Pipe()
	defer server.Close()

	tlsConfig := &utls.Config{
		ServerName:         config.ServerName,
		InsecureSkipVerify: true,
		NextProtos:         config.ALPN,
	}

	uconn := utls.UClient(client, tlsConfig, *fp.ClientHello)

	// Apply padding if requested
	if config.PaddingLen > 0 {
		if err := applyPadding(uconn, config.PaddingLen); err != nil {
			client.Close()
			return nil, fmt.Errorf("failed to apply padding: %w", err)
		}
	}

	// Get the ClientHello bytes without actually sending
	if err := uconn.BuildHandshakeState(); err != nil {
		client.Close()
		return nil, err
	}

	// Extract ClientHello from handshake state
	clientHello := uconn.HandshakeState.Hello.Raw

	// Build TLS record layer
	recordHeader := []byte{
		0x16,       // Content type: Handshake
		0x03, 0x01, // Version: TLS 1.0 (for compatibility)
		byte(len(clientHello) >> 8), byte(len(clientHello)), // Length
	}

	fullPacket := append(recordHeader, clientHello...)

	client.Close()
	return fullPacket, nil
}

// ModifyClientHelloSNI modifies SNI in raw ClientHello bytes
// Returns modified bytes with new SNI
func ModifyClientHelloSNI(clientHello []byte, newSNI string) ([]byte, error) {
	// SNI extension type is 0x0000
	// Format: [type:2][length:2][list_length:2][name_type:1][name_length:2][name]

	// Find SNI extension in ClientHello
	// This is a simplified parser - production code needs full TLS parsing

	result := make([]byte, len(clientHello))
	copy(result, clientHello)

	// Search for SNI pattern (0x00 0x00 followed by extension data)
	for i := 0; i < len(result)-10; i++ {
		// Check for extension type 0x0000 (SNI)
		if result[i] == 0x00 && result[i+1] == 0x00 {
			// Verify it looks like SNI structure
			// Skip extension type (2) + extension length (2) + list length (2) + name type (1)
			nameOffset := i + 7
			if nameOffset+2 < len(result) {
				nameLen := int(result[nameOffset])<<8 | int(result[nameOffset+1])
				nameStart := nameOffset + 2

				// Verify this looks like a hostname
				if nameStart+nameLen <= len(result) && nameLen > 0 && nameLen < 256 {
					// Check if current content looks like a domain
					oldSNI := string(result[nameStart : nameStart+nameLen])
					if looksLikeDomain(oldSNI) {
						// Replace SNI
						// Note: This only works if new SNI is same length
						// For different lengths, we'd need to rebuild the packet
						if len(newSNI) == nameLen {
							copy(result[nameStart:], []byte(newSNI))
							return result, nil
						}
						// TODO: Handle different length SNIs by rebuilding packet
						return nil, fmt.Errorf("SNI length mismatch: old=%d new=%d", nameLen, len(newSNI))
					}
				}
			}
		}
	}

	return nil, fmt.Errorf("SNI extension not found")
}

func looksLikeDomain(s string) bool {
	if len(s) < 3 {
		return false
	}
	// Simple check: contains dot and only valid chars
	hasDot := false
	for _, c := range s {
		if c == '.' {
			hasDot = true
		} else if (c < 'a' || c > 'z') && (c < 'A' || c > 'Z') &&
				(c < '0' || c > '9') && c != '-' {
			return false
		}
	}
	return hasDot
}
