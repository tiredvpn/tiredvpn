package server

import (
	"bytes"
	"errors"
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

// handleSSHCamouflage drives the server side of the SSH transport and then
// delegates the tunnel phase to handleRawTunnel over the encrypted channel.
func handleSSHCamouflage(conn net.Conn, srvCtx *serverContext, logger *log.Logger) {
	logger.Debug("Processing SSH camouflage connection")

	transport, clientID, err := sshServerHandshake(conn, srvCtx, logger)
	if err != nil {
		logger.Debug("SSH camouflage handshake failed: %v", err)
		// A rejection that happened after NEWKEYS has already been answered in
		// SSH's own terms. Following it with an HTTP page would put a decoy
		// response in the middle of an encrypted SSH stream, which is a
		// stronger signal than the probe it is meant to deflect.
		if !errors.Is(err, strategy.SSHAuthRejectedError()) {
			serveFakeWebsite(conn, srvCtx.cfg, logger)
		}
		return
	}

	logger.Info("SSH camouflage authenticated (clientID=%s)", clientID)

	// The post-auth stream is a clean byte channel once SSH channel framing is
	// stripped, so handleRawTunnel (which already supports both SOCKS proxy and
	// TUN mode) can run over it unchanged.
	sshConn := strategy.NewSSHCamouflageConn(transport)
	handleRawTunnel(sshConn, srvCtx, logger, clientID)
}

// sshServerHandshake performs the SSH transport handshake and then verifies the
// client's auth token inside the encrypted channel. On success it returns the
// established transport and the matched client ID (or "global" for the global
// secret).
func sshServerHandshake(conn net.Conn, srvCtx *serverContext, logger *log.Logger) (*strategy.SSHTransport, clientIdentity, error) {
	conn.SetDeadline(time.Now().Add(15 * time.Second))

	hostKey := strategy.SSHHostKey(srvCtx.cfg.Secret)
	transport, err := strategy.SSHServerHandshake(conn, hostKey)
	if err != nil {
		conn.SetDeadline(time.Time{})
		return nil, clientIdentity{}, err
	}

	token, err := strategy.SSHServerReadAuth(transport)
	if err != nil {
		if errors.Is(err, strategy.SSHAuthRejectedError()) {
			strategy.SSHServerRejectAuth(transport)
		}
		conn.SetDeadline(time.Time{})
		return nil, clientIdentity{}, fmt.Errorf("reading SSH auth: %w", err)
	}

	clientID, secret, ok := verifySSHAuth(token, transport.SessionID(), srvCtx)
	if !ok {
		strategy.SSHServerRejectAuth(transport)
		conn.SetDeadline(time.Time{})
		return nil, clientIdentity{}, fmt.Errorf("%w: token does not match any secret", strategy.SSHAuthRejectedError())
	}

	// The answering token uses the server-to-client context, so a man in the
	// middle cannot reflect the client's own token back at it, and it is bound
	// to this session's exchange hash, so it cannot be replayed into another.
	if err := strategy.SSHServerAcceptAuth(transport, secret); err != nil {
		conn.SetDeadline(time.Time{})
		return nil, clientIdentity{}, err
	}

	conn.SetDeadline(time.Time{})
	return transport, clientID, nil
}

// verifySSHAuth checks the token against per-client secrets (registry) and then
// the global secret. Returns the matched client ID, the secret used, and whether
// authentication succeeded. sessionID is the exchange hash the token is bound to.
func verifySSHAuth(token, sessionID []byte, srvCtx *serverContext) (clientIdentity, []byte, bool) {
	if srvCtx.registry != nil {
		for _, client := range srvCtx.registry.ListClients() {
			secret := []byte(client.Secret)
			if strategy.VerifySSHAuthToken(token, secret, sessionID, strategy.SSHAuthClientToServer) {
				return registryIdentity(client.ID), secret, true
			}
		}
	}
	if len(srvCtx.cfg.Secret) > 0 &&
		strategy.VerifySSHAuthToken(token, srvCtx.cfg.Secret, sessionID, strategy.SSHAuthClientToServer) {
		return sharedIdentity(globalClientID), srvCtx.cfg.Secret, true
	}
	return clientIdentity{}, nil, false
}
