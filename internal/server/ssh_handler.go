package server

import (
	"bufio"
	"bytes"
	"fmt"
	"net"
	"time"

	"github.com/tiredvpn/tiredvpn/internal/log"
	"github.com/tiredvpn/tiredvpn/internal/strategy"
)

// DetectSSHCamouflage reports whether the peeked bytes are the start of an SSH
// camouflage session. It matches the "SSH-2.0" identification prefix but rejects
// the legacy protocol-confusion SSH variant, which embeds the "TIRED" marker in
// its very first segment. The camouflage client sends only the banner line first
// (an interactive handshake), so a TIRED marker here means it is confusion, not us.
func DetectSSHCamouflage(peek []byte) bool {
	if !bytes.HasPrefix(peek, []byte("SSH-2.0")) {
		return false
	}
	if bytes.Contains(peek, []byte("TIRED")) {
		return false
	}
	return true
}

// handleSSHCamouflage drives the server side of the fake SSH handshake and then
// delegates the tunnel phase to handleRawTunnel over an SSH-framed connection.
func handleSSHCamouflage(conn net.Conn, srvCtx *serverContext, logger *log.Logger) {
	logger.Debug("Processing SSH camouflage connection")

	clientID, err := sshServerHandshake(conn, srvCtx, logger)
	if err != nil {
		logger.Debug("SSH camouflage handshake failed: %v", err)
		serveFakeWebsite(conn, srvCtx.cfg, logger)
		return
	}

	logger.Info("SSH camouflage authenticated (clientID=%s)", clientID)

	// The post-handshake stream is a clean byte channel once SSH packet framing
	// is stripped, so handleRawTunnel (which already supports both SOCKS proxy
	// and TUN mode) can run over it unchanged.
	sshConn := strategy.NewSSHCamouflageConn(conn)
	handleRawTunnel(sshConn, srvCtx, logger, clientID)
}

// sshServerHandshake performs banner exchange, KEXINIT negotiation and the ECDH
// round trip, verifying the client auth token. On success it returns the matched
// client ID (or "global" for the global secret).
func sshServerHandshake(conn net.Conn, srvCtx *serverContext, logger *log.Logger) (string, error) {
	conn.SetDeadline(time.Now().Add(15 * time.Second))
	defer conn.SetDeadline(time.Time{})

	br := bufio.NewReader(conn)

	// 1. Read the client banner line.
	line, err := br.ReadString('\n')
	if err != nil {
		return "", fmt.Errorf("reading client banner: %w", err)
	}
	if !bytes.HasPrefix([]byte(line), []byte("SSH-2.0")) {
		return "", fmt.Errorf("not an SSH-2.0 banner")
	}
	// 2. Send our banner.
	if _, err := conn.Write([]byte(strategy.SSHBanner)); err != nil {
		return "", err
	}
	// 3. Read the client KEXINIT (discard contents).
	if _, err := strategy.ReadSSHPacket(br); err != nil {
		return "", fmt.Errorf("reading client KEXINIT: %w", err)
	}
	// 4. Send our KEXINIT.
	if err := strategy.WriteSSHPacket(conn, strategy.BuildSSHKexInit()); err != nil {
		return "", err
	}
	// 5. Read the client ECDH init carrying the auth token.
	payload, err := strategy.ReadSSHPacket(br)
	if err != nil {
		return "", fmt.Errorf("reading client ECDH init: %w", err)
	}
	token, err := strategy.ParseSSHKexPubKey(payload, 30) // SSH_MSG_KEX_ECDH_INIT
	if err != nil {
		return "", err
	}

	clientID, secret, ok := verifySSHAuth(token, srvCtx)
	if !ok {
		return "", fmt.Errorf("auth token verification failed")
	}

	// 6. Send the ECDH reply carrying our token derived from the same secret so
	//    the client can confirm the server understands the protocol.
	serverToken := strategy.GenerateSSHAuthToken(secret)
	if err := strategy.WriteSSHPacket(conn, strategy.BuildSSHKexECDH(31, serverToken)); err != nil { // SSH_MSG_KEX_ECDH_REPLY
		return "", err
	}

	conn.SetDeadline(time.Time{})
	return clientID, nil
}

// verifySSHAuth checks the token against per-client secrets (registry) and then
// the global secret. Returns the matched client ID, the secret used, and whether
// authentication succeeded.
func verifySSHAuth(token []byte, srvCtx *serverContext) (string, []byte, bool) {
	if srvCtx.registry != nil {
		for _, client := range srvCtx.registry.ListClients() {
			secret := []byte(client.Secret)
			if strategy.VerifySSHAuthToken(token, secret) {
				return client.ID, secret, true
			}
		}
	}
	if len(srvCtx.cfg.Secret) > 0 && strategy.VerifySSHAuthToken(token, srvCtx.cfg.Secret) {
		return "global", srvCtx.cfg.Secret, true
	}
	return "", nil, false
}
