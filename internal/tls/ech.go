package tls

import (
	"context"
	"crypto/tls"
	"encoding/base64"
	"errors"
	"fmt"
	"net"
	"strings"
	"time"

	"github.com/tiredvpn/tiredvpn/internal/log"
)

// ECHConfig holds Encrypted Client Hello configuration
type ECHConfig struct {
	// Enabled turns ECH on/off
	Enabled bool

	// ConfigList is the serialized ECHConfigList from server
	// Can be obtained via DNS HTTPS record or out-of-band
	ConfigList []byte

	// PublicName is the outer SNI (visible to network)
	// Inner SNI (real destination) is encrypted
	PublicName string

	// FallbackToPlain allows falling back to plain TLS if ECH fails
	FallbackToPlain bool

	// RetryOnRejection retries with new config if server rejects ECH
	RetryOnRejection bool
}

// ECHResult contains the result of an ECH connection
type ECHResult struct {
	// Accepted indicates if ECH was successfully negotiated
	Accepted bool

	// RetryConfigs contains new ECHConfigList if server rejected with retry
	RetryConfigs []byte

	// Error if ECH failed
	Error error
}

// DefaultECHConfig returns default ECH configuration
func DefaultECHConfig() *ECHConfig {
	return &ECHConfig{
		Enabled:          false,
		FallbackToPlain:  true,
		RetryOnRejection: true,
	}
}

// DialWithECH creates a TLS connection with ECH support
func DialWithECH(ctx context.Context, network, addr string, serverName string, echConfig *ECHConfig) (*tls.Conn, *ECHResult, error) {
	result := &ECHResult{}

	// Resolve address
	dialer := &net.Dialer{
		Timeout: 30 * time.Second,
	}

	tcpConn, err := dialer.DialContext(ctx, network, addr)
	if err != nil {
		return nil, result, fmt.Errorf("tcp dial failed: %w", err)
	}

	// Build TLS config with ECH
	tlsConfig := &tls.Config{
		ServerName:         serverName,
// InsecureSkipVerify is intentional: the VPN server presents a certificate for
		// the cover domain which it does not own (required for DPI evasion via ECH).
		// Server identity is authenticated at the VPN protocol layer via shared secret.
		// TODO: implement certificate pinning for the actual server certificate.
		InsecureSkipVerify: true, //nolint:gosec
		MinVersion:         tls.VersionTLS13, // ECH requires TLS 1.3
		NextProtos:         []string{"h2", "http/1.1"},
	}

	// Add ECH config if enabled and available
	if echConfig != nil && echConfig.Enabled && len(echConfig.ConfigList) > 0 {
		tlsConfig.EncryptedClientHelloConfigList = echConfig.ConfigList
		log.Debug("ECH enabled with config list (%d bytes), public_name=%s",
			len(echConfig.ConfigList), echConfig.PublicName)
	}

	// Perform TLS handshake
	tlsConn := tls.Client(tcpConn, tlsConfig)

	if err := tlsConn.HandshakeContext(ctx); err != nil {
		tcpConn.Close()

		// Check for ECH rejection error
		var echErr *tls.ECHRejectionError
		if errors.As(err, &echErr) {
			result.RetryConfigs = echErr.RetryConfigList
			result.Error = err

			log.Debug("ECH rejected by server, retry configs available: %d bytes",
				len(echErr.RetryConfigList))

			// Retry with new config if enabled
			if echConfig.RetryOnRejection && len(echErr.RetryConfigList) > 0 {
				log.Debug("Retrying with new ECH config...")
				newConfig := *echConfig
				newConfig.ConfigList = echErr.RetryConfigList
				return DialWithECH(ctx, network, addr, serverName, &newConfig)
			}

			// Fallback to plain TLS if enabled
			if echConfig.FallbackToPlain {
				log.Debug("Falling back to plain TLS...")
				return DialWithECH(ctx, network, addr, serverName, nil)
			}

			return nil, result, fmt.Errorf("ech rejected: %w", err)
		}

		return nil, result, fmt.Errorf("tls handshake failed: %w", err)
	}

	// Check ECH acceptance
	connState := tlsConn.ConnectionState()
	result.Accepted = connState.ECHAccepted

	if result.Accepted {
		log.Debug("ECH successfully negotiated")
	} else if echConfig != nil && echConfig.Enabled {
		log.Debug("ECH was enabled but not accepted by server")
	}

	return tlsConn, result, nil
}

// FetchECHConfig fetches ECH configuration from DNS HTTPS record
// Returns nil if no ECH config is available
func FetchECHConfig(ctx context.Context, domain string) ([]byte, error) {
	// DNS HTTPS record lookup
	// Format: dig HTTPS example.com
	// Response contains: ech="..." parameter with base64-encoded ECHConfigList

	resolver := &net.Resolver{
		PreferGo: true,
	}

	// Lookup HTTPS record type (TYPE65)
	// Go 1.24+ supports this via LookupHTTPS
	records, err := lookupHTTPSRecord(ctx, resolver, domain)
	if err != nil {
		return nil, fmt.Errorf("dns lookup failed: %w", err)
	}

	// Parse ECH config from records
	for _, record := range records {
		if echConfig := parseECHFromHTTPSRecord(record); echConfig != nil {
			log.Debug("Found ECH config in DNS for %s (%d bytes)", domain, len(echConfig))
			return echConfig, nil
		}
	}

	return nil, nil // No ECH config available
}

// lookupHTTPSRecord performs DNS HTTPS record lookup
func lookupHTTPSRecord(ctx context.Context, resolver *net.Resolver, domain string) ([]string, error) {
	// Use TXT as fallback since HTTPS record support varies
	// Real implementation would use DNS library for TYPE65

	// For now, return empty - ECH config should be provided out-of-band
	// or via server configuration
	return nil, nil
}

// parseECHFromHTTPSRecord extracts ECH config from DNS record
func parseECHFromHTTPSRecord(record string) []byte {
	// Parse "ech=BASE64DATA" from HTTPS record
	parts := strings.Split(record, " ")
	for _, part := range parts {
		if strings.HasPrefix(part, "ech=") {
			echB64 := strings.TrimPrefix(part, "ech=")
			echB64 = strings.Trim(echB64, "\"")

			decoded, err := base64.StdEncoding.DecodeString(echB64)
			if err != nil {
				log.Debug("Failed to decode ECH config: %v", err)
				continue
			}
			return decoded
		}
	}
	return nil
}

// GenerateECHConfigList generates a new ECH configuration for server
// Returns public config (for clients) and private keys (for server)
func GenerateECHConfigList(publicName string) (configList []byte, privateKey []byte, err error) {
	// ECH config generation requires:
	// 1. Generate X25519 keypair for HPKE
	// 2. Build ECHConfig structure (RFC 9001)
	// 3. Serialize to wire format

	// This is complex and typically done by server tooling
	// For now, return placeholder - real implementation needs HPKE library

	return nil, nil, errors.New("ech config generation not implemented - use external tool")
}

// ECHConn wraps a TLS connection with ECH status
type ECHConn struct {
	*tls.Conn
	echAccepted bool
	publicName  string
	innerName   string
}

// NewECHConn creates a new ECH-aware connection wrapper
func NewECHConn(conn *tls.Conn, accepted bool, publicName, innerName string) *ECHConn {
	return &ECHConn{
		Conn:        conn,
		echAccepted: accepted,
		publicName:  publicName,
		innerName:   innerName,
	}
}

// ECHAccepted returns whether ECH was successfully negotiated
func (c *ECHConn) ECHAccepted() bool {
	return c.echAccepted
}

// PublicName returns the outer SNI (visible to network)
func (c *ECHConn) PublicName() string {
	return c.publicName
}

// InnerName returns the real SNI (encrypted)
func (c *ECHConn) InnerName() string {
	return c.innerName
}

// WellKnownECHConfigs contains ECH configs for well-known services
// These can be used as fallback when DNS lookup fails
var WellKnownECHConfigs = map[string][]byte{
	// Cloudflare (example - real config would be fetched from DNS)
	// "cloudflare-ech.com": {...},
}

// GetWellKnownECHConfig returns ECH config for well-known domains
func GetWellKnownECHConfig(domain string) []byte {
	// Check exact match
	if config, ok := WellKnownECHConfigs[domain]; ok {
		return config
	}

	// Check wildcard
	parts := strings.Split(domain, ".")
	if len(parts) > 2 {
		wildcard := "*." + strings.Join(parts[1:], ".")
		if config, ok := WellKnownECHConfigs[wildcard]; ok {
			return config
		}
	}

	return nil
}

// DialTLSWithECH is a convenience function for strategies to dial with optional ECH
// It wraps the standard TLS dial with ECH support when configured
func DialTLSWithECH(ctx context.Context, addr string, tlsConfig *tls.Config, echConfig *ECHConfig) (*tls.Conn, error) {
	// If ECH not enabled, use standard TLS dial
	if echConfig == nil || !echConfig.Enabled || len(echConfig.ConfigList) == 0 {
		dialer := &net.Dialer{Timeout: 30 * time.Second}
		return tls.DialWithDialer(dialer, "tcp", addr, tlsConfig)
	}

	// Dial with ECH
	serverName := tlsConfig.ServerName
	if serverName == "" {
		host, _, _ := net.SplitHostPort(addr)
		serverName = host
	}

	// Merge configs
	mergedConfig := tlsConfig.Clone()
	mergedConfig.MinVersion = tls.VersionTLS13 // ECH requires TLS 1.3
	mergedConfig.EncryptedClientHelloConfigList = echConfig.ConfigList

	dialer := &net.Dialer{Timeout: 30 * time.Second}
	tcpConn, err := dialer.DialContext(ctx, "tcp", addr)
	if err != nil {
		return nil, fmt.Errorf("tcp dial failed: %w", err)
	}

	tlsConn := tls.Client(tcpConn, mergedConfig)
	if err := tlsConn.HandshakeContext(ctx); err != nil {
		tcpConn.Close()

		// Handle ECH rejection
		var echErr *tls.ECHRejectionError
		if errors.As(err, &echErr) {
			log.Debug("ECH rejected, retry configs: %d bytes", len(echErr.RetryConfigList))

			// Retry with new config
			if echConfig.RetryOnRejection && len(echErr.RetryConfigList) > 0 {
				newConfig := *echConfig
				newConfig.ConfigList = echErr.RetryConfigList
				return DialTLSWithECH(ctx, addr, tlsConfig, &newConfig)
			}

			// Fallback to plain TLS
			if echConfig.FallbackToPlain {
				log.Debug("ECH fallback to plain TLS")
				return DialTLSWithECH(ctx, addr, tlsConfig, nil)
			}
		}

		return nil, fmt.Errorf("tls handshake failed: %w", err)
	}

	state := tlsConn.ConnectionState()
	if state.ECHAccepted {
		log.Debug("ECH accepted for %s (outer SNI: %s)", serverName, echConfig.PublicName)
	}

	return tlsConn, nil
}
