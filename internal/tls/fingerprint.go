package tls

import (
	"crypto/sha256"
	"encoding/hex"
	"fmt"
	"net"
	"sort"
	"strings"

	utls "github.com/refraction-networking/utls"
)

// BrowserFingerprint represents a browser's TLS fingerprint
type BrowserFingerprint struct {
	Name        string
	JA3         string
	ClientHello *utls.ClientHelloID
}

// Predefined browser fingerprints.
//
// Names here state what uTLS actually parrots, not what we wish it parroted.
// The previous naming ("Chrome 124" pointing at HelloChrome_Auto) hid a growing
// gap between the label and the bytes on the wire, which is exactly the kind of
// thing that gets a transport fingerprinted.
//
// Version gap against what browsers ship as of 2026-08 (utls master):
//
//	HelloFirefox_Auto  = Firefox 148  — current, no gap
//	HelloSafari_Auto   = Safari 26.3  — current, no gap
//	HelloChrome_Auto   = Chrome 133   — Chrome stable is 152, 19 majors behind
//	HelloEdge_Auto     = Edge 85      — 2020
//	HelloIOS_Auto      = iOS 14       — 2020
//	HelloAndroid_11_OkHttp            — 2020
var (
	// Chrome 120 on Windows - pinned, kept only for reproducing old captures.
	FingerprintChrome120 = &BrowserFingerprint{
		Name:        "Chrome 120",
		ClientHello: &utls.HelloChrome_120,
	}

	// Newest Chrome uTLS can parrot. Currently Chrome 133 (see gap table above).
	FingerprintChromeAuto = &BrowserFingerprint{
		Name:        "Chrome (uTLS auto)",
		ClientHello: &utls.HelloChrome_Auto,
	}

	// Chrome 133 - pinned. Same bytes as FingerprintChromeAuto today, but it
	// stays on 133 when uTLS moves Auto forward.
	FingerprintChrome133 = &BrowserFingerprint{
		Name:        "Chrome 133",
		ClientHello: &utls.HelloChrome_133,
	}

	// Newest Firefox uTLS can parrot. Currently Firefox 148 — matches shipping
	// Firefox, which is why this is the default profile.
	FingerprintFirefoxAuto = &BrowserFingerprint{
		Name:        "Firefox (uTLS auto)",
		ClientHello: &utls.HelloFirefox_Auto,
	}

	// Firefox 120 - pinned, kept only for reproducing old captures.
	FingerprintFirefox120 = &BrowserFingerprint{
		Name:        "Firefox 120",
		ClientHello: &utls.HelloFirefox_120,
	}

	// Firefox 148 - pinned. Same bytes as FingerprintFirefoxAuto today; pick
	// this one when a capture has to stay reproducible across a uTLS bump.
	FingerprintFirefox148 = &BrowserFingerprint{
		Name:        "Firefox 148",
		ClientHello: &utls.HelloFirefox_148,
	}

	// Newest Safari uTLS can parrot. Currently Safari 26.3.
	FingerprintSafariAuto = &BrowserFingerprint{
		Name:        "Safari (uTLS auto)",
		ClientHello: &utls.HelloSafari_Auto,
	}

	// Edge (Chromium-based). HelloEdge_Auto is still Edge 85 upstream — six
	// years stale, do not use as a default.
	FingerprintEdge = &BrowserFingerprint{
		Name:        "Edge 85",
		ClientHello: &utls.HelloEdge_Auto,
	}

	// iOS Safari. HelloIOS_Auto is iOS 14 upstream — stale.
	FingerprintiOS = &BrowserFingerprint{
		Name:        "iOS 14 Safari",
		ClientHello: &utls.HelloIOS_Auto,
	}

	// Android OkHttp on Android 11 — stale, and OkHttp is not a browser.
	FingerprintAndroid = &BrowserFingerprint{
		Name:        "Android 11 OkHttp",
		ClientHello: &utls.HelloAndroid_11_OkHttp,
	}

	// Randomized - changes per connection. Matches no real client, so it stands
	// out against any census of observed ClientHellos. Diagnostics only.
	FingerprintRandomized = &BrowserFingerprint{
		Name:        "Randomized",
		ClientHello: &utls.HelloRandomized,
	}
)

// DefaultFingerprintName is the profile used when nothing is configured.
//
// Firefox for two independent reasons:
//
//  1. It is the only major-browser profile uTLS parrots at its current shipping
//     version (148). Chrome_Auto is 19 majors behind Chrome stable, which shows
//     up in the extension set and in the post-quantum key share — a mismatch a
//     censor gets for free by comparing our JA4 against live Chrome traffic.
//  2. Xray issue #6293 reports Chrome/Safari/iOS profiles landing in the
//     suspicious classes at Russian and Iranian censors, while Firefox, Android,
//     OkHttp and Edge pass. Of those four, Firefox is the only one uTLS parrots
//     at a current version — the Edge/iOS/Android parrots are all from 2020.
const DefaultFingerprintName = "firefox"

// FingerprintMap maps configuration names to fingerprints. These names are
// operator-facing config (-tls-fingerprint, tls.fingerprint), so the rule is
// strict and worth stating: a bare browser name tracks whatever uTLS parrots
// as newest and will change under you on a uTLS bump; a version-suffixed name
// is pinned to that exact parrot forever. A name must never mean a version
// other than the one it says — that is the whole bug this package had.
var FingerprintMap = map[string]*BrowserFingerprint{
	"chrome":     FingerprintChromeAuto,
	"chrome120":  FingerprintChrome120,
	"chrome133":  FingerprintChrome133,
	"firefox":    FingerprintFirefoxAuto,
	"firefox120": FingerprintFirefox120,
	"firefox148": FingerprintFirefox148,
	"safari":     FingerprintSafariAuto,
	"edge":       FingerprintEdge,
	"ios":        FingerprintiOS,
	"android":    FingerprintAndroid,
	"randomized": FingerprintRandomized,
}

// LookupFingerprint resolves a configured profile name, falling back to the
// default profile when the name is empty or unknown. The bool reports whether
// the name was recognised, so callers can warn on a typo instead of silently
// dialing with something the operator did not ask for.
func LookupFingerprint(name string) (*BrowserFingerprint, bool) {
	if name == "" {
		return FingerprintMap[DefaultFingerprintName], true
	}
	fp, ok := FingerprintMap[strings.ToLower(name)]
	if !ok {
		return FingerprintMap[DefaultFingerprintName], false
	}
	return fp, true
}

// FingerprintNames returns the configurable profile names, sorted, for use in
// help text and error messages.
func FingerprintNames() []string {
	names := make([]string, 0, len(FingerprintMap))
	for name := range FingerprintMap {
		names = append(names, name)
	}
	sort.Strings(names)
	return names
}

// TLSConn wraps uTLS connection with fingerprint support
type TLSConn struct {
	*utls.UConn
	fingerprint *BrowserFingerprint
	sni         string
}

// Config for TLS connection
type Config struct {
	ServerName         string   // SNI
	Fingerprint        string   // Browser fingerprint name
	ALPN               []string // Application-Layer Protocol Negotiation
	InsecureSkipVerify bool     // Skip certificate verification (for testing)

	// Advanced options
	SessionTicket []byte // Session resumption ticket
	UseECH        bool   // Use Encrypted Client Hello (if available)
	PaddingLen    int    // Pad ClientHello to this length
}

// DefaultConfig returns default TLS config
func DefaultConfig(serverName string) *Config {
	return &Config{
		ServerName:         serverName,
		Fingerprint:        DefaultFingerprintName,
		ALPN:               []string{"h2", "http/1.1"},
		InsecureSkipVerify: false,
	}
}

// Dial creates a new TLS connection with browser fingerprint
func Dial(network, addr string, config *Config) (*TLSConn, error) {
	// Get fingerprint
	fp, _ := LookupFingerprint(config.Fingerprint)

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

	uconn, err := newUConn(conn, tlsConfig, fp, config.PaddingLen)
	if err != nil {
		conn.Close()
		return nil, err
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

// newUConn builds a uTLS client for the given profile, optionally with a
// padding extension of paddingLen bytes appended to the profile's extension
// list.
//
// The padding has to go in through HelloCustom, not through the profile ID.
// uTLS resolves a profile ID lazily inside BuildHandshakeState: if
// uconn.clientHelloSpec is still nil at that point it re-derives the pristine
// spec from the ID and overwrites uconn.Extensions. ApplyPreset does not set
// clientHelloSpec, so calling UClient(id) and then ApplyPreset(modified spec)
// — which is what this package used to do — has the modification silently
// thrown away before the ClientHello is marshalled. Dialing with HelloCustom
// makes applyPresetByID a no-op and leaves our extensions in place.
//
// This matters because REALITY hides its credentials in that padding extension.
// With the padding lost, callers fell through to AddPaddingWithREALITY, which
// splices the extension into the marshalled bytes after the fact.
func newUConn(conn net.Conn, tlsConfig *utls.Config, fp *BrowserFingerprint, paddingLen int) (*utls.UConn, error) {
	if paddingLen <= 0 {
		return utls.UClient(conn, tlsConfig, *fp.ClientHello), nil
	}

	spec, err := utls.UTLSIdToSpec(*fp.ClientHello)
	if err != nil {
		// Randomized profiles are generated, not tabulated, so they have no
		// spec to fetch. Fall back to the plain profile; the caller's own
		// padding splice still runs.
		return utls.UClient(conn, tlsConfig, *fp.ClientHello), nil //nolint:nilerr // documented fallback
	}

	// Some profiles (Chrome 120, Edge 85, iOS 14) already carry a padding
	// extension sized by BoringPaddingStyle, which pads to 512 bytes and so
	// yields nothing at all for a modern post-quantum ClientHello. Replace it
	// rather than appending a second one — uTLS rejects two padding extensions
	// outright. Replacing instead of mutating keeps us clear of the shared
	// extension objects UTLSIdToSpec hands out.
	padding := &utls.UtlsPaddingExtension{PaddingLen: paddingLen, WillPad: true}
	replaced := false
	for i, ext := range spec.Extensions {
		if _, ok := ext.(*utls.UtlsPaddingExtension); ok {
			spec.Extensions[i] = padding
			replaced = true
			break
		}
	}
	if !replaced {
		spec.Extensions = append(spec.Extensions, padding)
	}

	uconn := utls.UClient(conn, tlsConfig, utls.HelloCustom)
	if err := uconn.ApplyPreset(&spec); err != nil {
		return nil, fmt.Errorf("apply %s spec: %w", fp.Name, err)
	}
	return uconn, nil
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

	uconn, err := newUConn(client, tlsConfig, fp, config.PaddingLen)
	if err != nil {
		client.Close()
		return nil, err
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
