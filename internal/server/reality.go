package server

import (
	"crypto/hmac"
	"crypto/rand"
	"crypto/sha256"
	"fmt"
	"io"
	"net"
	"time"

	"github.com/xtaci/smux"

	"github.com/tiredvpn/tiredvpn/internal/log"
	"github.com/tiredvpn/tiredvpn/internal/protocol"
	"github.com/tiredvpn/tiredvpn/internal/strategy"
	customtls "github.com/tiredvpn/tiredvpn/internal/tls"
)

// DetectREALITYExtension checks if the data contains a REALITY extension
// Properly parses TLS ClientHello structure to find padding extension (0x0015)
// with REALITY magic "REAL" inside
func DetectREALITYExtension(data []byte) bool {
	// Check for TLS handshake record (0x16)
	if len(data) < 5 || data[0] != 0x16 {
		log.Debug("DetectREALITY: not TLS handshake (len=%d)", len(data))
		return false
	}

	log.Debug("DetectREALITY: checking %d bytes of TLS data", len(data))

	// TLS Record: type(1) + version(2) + length(2) = 5 bytes
	// Handshake: type(1) + length(3) = 4 bytes
	// ClientHello: version(2) + random(32) = 34 bytes
	offset := 5 + 4 + 2 + 32 // = 43

	if offset >= len(data) {
		log.Debug("DetectREALITY: data too short for ClientHello header")
		return false
	}

	// Check handshake type is ClientHello (0x01)
	if data[5] != 0x01 {
		log.Debug("DetectREALITY: not ClientHello (type=%x)", data[5])
		return false
	}

	// Skip session ID
	sessionIDLen := int(data[offset])
	offset += 1 + sessionIDLen
	if offset+2 > len(data) {
		log.Debug("DetectREALITY: truncated after session ID")
		return false
	}

	// Skip cipher suites
	cipherLen := int(data[offset])<<8 | int(data[offset+1])
	offset += 2 + cipherLen
	if offset >= len(data) {
		log.Debug("DetectREALITY: truncated after cipher suites")
		return false
	}

	// Skip compression methods
	compLen := int(data[offset])
	offset += 1 + compLen
	if offset+2 > len(data) {
		log.Debug("DetectREALITY: truncated after compression")
		return false
	}

	// Extensions length
	extTotalLen := int(data[offset])<<8 | int(data[offset+1])
	offset += 2
	extEnd := offset + extTotalLen

	if extEnd > len(data) {
		extEnd = len(data)
	}

	log.Debug("DetectREALITY: extensions start at %d, total len=%d", offset, extTotalLen)

	// Walk extensions properly: each is type(2) + length(2) + data(length)
	for offset+4 <= extEnd {
		extType := int(data[offset])<<8 | int(data[offset+1])
		extLen := int(data[offset+2])<<8 | int(data[offset+3])
		extDataStart := offset + 4

		// Padding extension type: 0x0015 with enough data for PubKey+AuthToken.
		// Handle truncated extension body: DPI may drop the trailing random padding
		// while the REALITY auth bytes (first 64 bytes of extension body) are still present.
		if extType == customtls.PaddingExtensionType {
			availableBody := extEnd - extDataStart
			if availableBody > extLen {
				availableBody = extLen
			}
			log.Debug("DetectREALITY: found padding ext at offset %d, declared_len=%d, available=%d (need %d)", offset, extLen, availableBody, customtls.REALITYExtensionLength)
			if extLen >= customtls.REALITYExtensionLength && availableBody >= customtls.REALITYExtensionLength {
				log.Debug("DetectREALITY: candidate REALITY padding found (auth verified per-connection in handler)")
				return true
			}
		}

		if extDataStart+extLen > extEnd {
			log.Debug("DetectREALITY: extension 0x%04x at %d truncated (len=%d), stopping walk", extType, offset, extLen)
			break
		}

		offset = extDataStart + extLen
	}

	log.Debug("DetectREALITY: no padding extension with REALITY magic found")
	return false
}

// HandleREALITYConnection processes a REALITY protocol connection
func HandleREALITYConnection(conn net.Conn, srvCtx *serverContext, logger *log.Logger) {
	defer conn.Close()

	logger.Debug("REALITY: Processing connection from %s", conn.RemoteAddr())

	// Read ClientHello
	clientHello, err := ReadTLSRecord(conn)
	if err != nil {
		logger.Error("REALITY: Failed to read ClientHello: %v", err)
		return
	}

	// Extract REALITY extension
	realityExt, err := ExtractREALITYExtensionFromClientHello(clientHello)
	if err != nil {
		logger.Error("REALITY: Failed to extract extension: %v", err)
		return
	}

	logger.Debug("REALITY: Extension extracted, pubkey=%x", realityExt.PubKey[:8])

	// Verify auth token - try per-client secrets from Redis first, then global
	authenticated := false
	var authClientID string
	var usedSecret []byte

	// 1. Try per-client secrets from Redis (if registry exists)
	if srvCtx.registry != nil {
		clients := srvCtx.registry.ListClients()
		for _, client := range clients {
			secretBytes := []byte(client.Secret)
			if customtls.VerifyClientAuth(secretBytes, realityExt.PubKey, realityExt.AuthToken) {
				logger.Info("REALITY: Auth successful (client: %s, id: %s)", client.Name, client.ID)
				authenticated = true
				usedSecret = secretBytes
				authClientID = client.ID
				break
			}
		}
	}

	// 2. Fallback to global secret (if not found in registry and global secret exists)
	if !authenticated && len(srvCtx.cfg.Secret) > 0 {
		if customtls.VerifyClientAuth(srvCtx.cfg.Secret, realityExt.PubKey, realityExt.AuthToken) {
			logger.Info("REALITY: Auth successful (global secret)")
			authenticated = true
			usedSecret = srvCtx.cfg.Secret
			authClientID = "global"
		}
	}

	if !authenticated {
		logger.Info("REALITY: Auth failed")
		if srvCtx.cfg.REALITYCoverDomain != "" {
			handleREALITYUnauthorized(conn, clientHello, srvCtx.cfg.REALITYCoverDomain, logger)
		}
		// No cover domain configured: silently drop to avoid SSRF via client-controlled SNI.
		return
	}

	logger.Debug("REALITY: Using secret from %s", authClientID)
	realityAuthLegacyTotal.Add(1)

	// Data layer version. A v2 client appends [salt][MAC] to the padding block
	// after its 64-byte core; a v1 client leaves random bytes there, which fail
	// the MAC. Nothing on the wire changes size either way.
	clientSalt, dataV2 := customtls.ParseClientDataV2(usedSecret, realityExt.PubKey, realityExt.Extra)
	if !dataV2 {
		// Logged at Info, not Debug, so the rollout is observable without
		// turning on -debug on a production exit: once no client reports v1 for
		// a full day, -reality-require-data-v2 is safe to switch on. Silence
		// means everyone is on v2. The v2 case stays at Debug to keep a busy
		// exit's log quiet.
		if srvCtx.cfg.REALITYRequireDataV2 {
			logger.Info("REALITY: rejecting legacy v1 data layer from %s (client: %s)", conn.RemoteAddr(), authClientID)
			if srvCtx.cfg.REALITYCoverDomain != "" {
				handleREALITYUnauthorized(conn, clientHello, srvCtx.cfg.REALITYCoverDomain, logger)
			}
			return
		}
		logger.Info("REALITY: accepting legacy v1 data layer from %s (client: %s)", conn.RemoteAddr(), authClientID)
	}

	// Extract SNI to determine destination
	sni, err := ExtractSNI(clientHello)
	if err != nil {
		logger.Error("REALITY: Failed to extract SNI: %v", err)
		return
	}

	// Default to port 443 if not specified
	dest := sni
	if _, _, err := net.SplitHostPort(dest); err != nil {
		dest = net.JoinHostPort(sni, "443")
	}

	logger.Debug("REALITY: Connecting to destination %s", dest)

	// Connect to real destination
	destConn, err := net.DialTimeout("tcp", dest, 10*time.Second)
	if err != nil {
		logger.Error("REALITY: Failed to connect to %s: %v", dest, err)
		sendTLSAlert(conn, 0x50) // internal_error
		return
	}

	// Remove REALITY extension from ClientHello
	strippedClientHello, err := RemoveREALITYExtension(clientHello)
	if err != nil {
		logger.Error("REALITY: Failed to strip extension: %v", err)
		destConn.Close()
		return
	}

	logger.Debug("REALITY: Stripped ClientHello (%d bytes): %s", len(strippedClientHello), log.HexDump(strippedClientHello, 256))

	// Forward ClientHello to destination
	if _, err := destConn.Write(strippedClientHello); err != nil {
		logger.Error("REALITY: Failed to send ClientHello to dest: %v", err)
		destConn.Close()
		return
	}

	// Read ServerHello from destination
	serverHello, err := ReadTLSRecord(destConn)
	if err != nil {
		logger.Error("REALITY: Failed to read ServerHello from dest: %v", err)
		destConn.Close()
		return
	}

	logger.Debug("REALITY: Received ServerHello from dest (%d bytes): %s", len(serverHello), log.HexDump(serverHello, 32))

	// Generate server auth token. For a v2 client the key pair is ephemeral for
	// this connection, so the data keys survive a later leak of the password;
	// for v1 we keep using the process-wide key, which that client ignores anyway.
	var (
		serverExt  *customtls.REALITYExtension
		dataParams *strategy.RealityV2Params
	)
	if dataV2 {
		serverPriv, serverPub, kerr := customtls.GenerateX25519KeyPair()
		if kerr != nil {
			logger.Error("REALITY: Failed to generate ephemeral key: %v", kerr)
			destConn.Close()
			return
		}
		var serverSalt [32]byte
		if _, rerr := rand.Read(serverSalt[:]); rerr != nil {
			logger.Error("REALITY: Failed to generate salt: %v", rerr)
			destConn.Close()
			return
		}
		ecdh, eerr := strategy.RealityV2ECDH(serverPriv, realityExt.PubKey)
		if eerr != nil {
			logger.Error("REALITY: ECDH failed: %v", eerr)
			destConn.Close()
			return
		}
		serverExt, err = customtls.NewServerREALITYExtensionDataV2(
			usedSecret, serverPriv, realityExt.PubKey, clientSalt, serverSalt,
		)
		dataParams = &strategy.RealityV2Params{
			SharedSecret: usedSecret,
			ECDH:         ecdh,
			ClientPub:    realityExt.PubKey,
			ServerPub:    serverPub,
			ClientSalt:   clientSalt,
			ServerSalt:   serverSalt,
		}
	} else {
		privKey, _ := realityStaticKeys()
		serverExt, err = customtls.NewServerREALITYExtension(usedSecret, privKey, realityExt.PubKey)
	}
	if err != nil {
		logger.Error("REALITY: Failed to create server extension: %v", err)
		destConn.Close()
		return
	}

	// Inject REALITY extension into ServerHello
	modifiedServerHello, err := InjectREALITYExtension(serverHello, serverExt)
	if err != nil {
		logger.Error("REALITY: Failed to inject extension: %v", err)
		destConn.Close()
		return
	}

	logger.Debug("REALITY: Modified ServerHello (%d bytes, was %d)", len(modifiedServerHello), len(serverHello))

	// Send modified ServerHello to client
	if _, err := conn.Write(modifiedServerHello); err != nil {
		logger.Error("REALITY: Failed to send ServerHello to client: %v", err)
		destConn.Close()
		return
	}

	logger.Debug("REALITY: ServerHello sent to client")

	// Close connection to real destination (we only needed the certificate)
	destConn.Close()

	// Derive stable clientID from the shared secret — same user reconnects with the same secret,
	// so gets the same clientID and same IP from the pool.
	mac := hmac.New(sha256.New, usedSecret)
	mac.Write([]byte("tiredvpn-client-id-v1"))
	clientID := fmt.Sprintf("reality:%x", mac.Sum(nil)[:8])

	logger.Info("REALITY: Tunnel established for %s (client: %s)", conn.RemoteAddr(), clientID)

	// Read negotiation byte: TypeMux (0x08) → smux session, anything else → legacy raw tunnel.
	var negBuf [1]byte
	conn.SetReadDeadline(time.Now().Add(10 * time.Second))
	_, err = io.ReadFull(conn, negBuf[:])
	conn.SetReadDeadline(time.Time{})
	if err != nil {
		logger.Debug("REALITY: Failed to read negotiation byte: %v", err)
		return
	}

	if negBuf[0] == protocol.TypeMux {
		logger.Debug("REALITY: Client requested smux multiplexing (data layer v%d)", dataLayerVersion(dataV2))
		handleREALITYMuxSession(conn, srvCtx, logger, clientID, usedSecret, realityExt.PubKey, dataParams)
		return
	}

	// Legacy mode: prepend the peeked byte and handle as raw tunnel.
	handleRawTunnel(&realityPrependConn{Conn: conn, first: negBuf[0]}, srvCtx, logger, clientID)
}

// realityPrependConn is a net.Conn that prepends a single already-read byte to the first Read call.
type realityPrependConn struct {
	net.Conn
	first byte
	used  bool
}

func (c *realityPrependConn) Read(b []byte) (int, error) {
	if !c.used {
		c.used = true
		if len(b) == 0 {
			return 0, nil
		}
		b[0] = c.first
		return 1, nil
	}
	return c.Conn.Read(b)
}

// dataLayerVersion maps the negotiated flag to the version number used in logs.
func dataLayerVersion(v2 bool) int {
	if v2 {
		return 2
	}
	return 1
}

// handleREALITYMuxSession runs a smux server over the post-auth REALITY connection.
// Each stream is handled as an independent raw tunnel request.
//
// The connection is wrapped in the same TLS-record framing the client applies
// after its TypeMux write. params non-nil selects the v2 AEAD layer keyed by
// this connection's X25519 exchange; nil is a v1 client, still keyed by
// HKDF(secret, salt=clientPubKey).
func handleREALITYMuxSession(conn net.Conn, srvCtx *serverContext, logger *log.Logger, clientID string, usedSecret []byte, clientPubKey [32]byte, params *strategy.RealityV2Params) {
	// Mirror the client-side wrap: server is !isClient so write/read keys are reversed.
	var (
		dataConn net.Conn
		err      error
	)
	if params != nil {
		dataConn, err = strategy.NewRealityDataConnV2(conn, *params, false)
	} else {
		dataConn, err = strategy.NewRealityDataConn(conn, usedSecret, clientPubKey[:], false)
	}
	if err != nil {
		logger.Error("REALITY: data conn init failed: %v", err)
		return
	}

	sess, err := smux.Server(dataConn, smux.DefaultConfig())
	if err != nil {
		logger.Error("REALITY: smux server create failed: %v", err)
		return
	}
	defer sess.Close()

	logger.Debug("REALITY: smux session started")
	for {
		stream, err := sess.AcceptStream()
		if err != nil {
			logger.Debug("REALITY: smux session closed: %v", err)
			return
		}
		go handleRawTunnel(strategy.ReshapeServerStream(stream, burstReshapeConfig(srvCtx.cfg)), srvCtx, logger, clientID)
	}
}

// handleREALITYUnauthorized proxies unauthorized REALITY clients to the configured
// cover domain. coverDomain is admin-controlled (Config.REALITYCoverDomain), not
// client-provided SNI, so there is no SSRF via attacker-controlled hostname.
func handleREALITYUnauthorized(conn net.Conn, clientHello []byte, coverDomain string, logger *log.Logger) {
	dest := net.JoinHostPort(coverDomain, "443")

	logger.Info("REALITY-UNAUTH: Proxying to %s", dest)

	// Connect to real destination
	destConn, err := net.DialTimeout("tcp", dest, 10*time.Second)
	if err != nil {
		logger.Error("REALITY-UNAUTH: Failed to connect to %s: %v", dest, err)
		return
	}
	defer destConn.Close()

	// Remove REALITY extension from ClientHello
	strippedClientHello, err := RemoveREALITYExtension(clientHello)
	if err != nil {
		// If stripping fails, forward original (less safe but functional)
		logger.Warn("REALITY-UNAUTH: Failed to strip extension, forwarding original")
		strippedClientHello = clientHello
	}

	// Forward ClientHello to destination
	if _, err := destConn.Write(strippedClientHello); err != nil {
		logger.Error("REALITY-UNAUTH: Failed to send ClientHello: %v", err)
		return
	}

	// Bidirectional copy (transparent proxy)
	logger.Info("REALITY-UNAUTH: Starting transparent proxy for %s", conn.RemoteAddr())

	errChan := make(chan error, 2)

	go func() {
		_, err := io.Copy(conn, destConn)
		errChan <- err
	}()

	go func() {
		_, err := io.Copy(destConn, conn)
		errChan <- err
	}()

	// Wait for either direction to finish
	<-errChan

	logger.Debug("REALITY-UNAUTH: Proxy session ended for %s", conn.RemoteAddr())
}

// sendTLSAlert sends a TLS alert message
func sendTLSAlert(conn net.Conn, alertCode byte) {
	// TLS alert record: type(0x15) + version(0x0303) + length(0x0002) + level(0x02=fatal) + description
	alert := []byte{
		0x15,       // Alert
		0x03, 0x03, // TLS 1.2
		0x00, 0x02, // Length: 2
		0x02,      // Fatal
		alertCode, // Alert code
	}
	conn.Write(alert)
}
