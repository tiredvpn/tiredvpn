package tls

import (
	stdtls "crypto/tls"
	"errors"
	"net"
)

// Carrying the connection's authKey from the session_id gate to GetCertificate.
//
// This exists because of a gap that is easy to hit and unpleasant to debug.
// cert-HMAC needs the connection's authKey at the moment the certificate is
// minted, and that moment is inside tls.Config.GetCertificate. But the callback
// receives only a *tls.ClientHelloInfo, which exposes the parsed SNI, cipher
// suites and extension IDs — not the raw ClientHello bytes and not the client's
// key share. There is no way to derive authKey from what the callback is given.
//
// The key has to come from earlier: the session_id gate already peeks the
// ClientHello, extracts the client's key share and derives authKey to open the
// session_id. AuthConn carries that value forward on the connection itself,
// which ClientHelloInfo.Conn hands back.
//
// The alternative — a map from net.Conn to authKey — works but has to be
// cleaned up on every exit path, and a leak there is a slow memory leak keyed by
// connection. Wrapping the connection ties the lifetime to the thing it
// describes.

// ErrNoConnAuthKey reports a connection that never went through the gate, so it
// carries no authKey. On the server this means the caller reached certificate
// minting without authenticating the client, which is a bug in the caller
// rather than something to paper over.
var ErrNoConnAuthKey = errors.New("reality cert: connection carries no auth key")

// AuthConn is a net.Conn carrying the authKey derived while authenticating the
// client's session_id.
type AuthConn struct {
	net.Conn
	authKey []byte
}

// NewAuthConn wraps c so its authKey travels with it.
func NewAuthConn(c net.Conn, authKey []byte) *AuthConn {
	return &AuthConn{Conn: c, authKey: authKey}
}

// AuthKey returns the carried key.
func (c *AuthConn) AuthKey() []byte { return c.authKey }

// Unwrap exposes the wrapped connection, so a conn wrapped further still
// resolves through AuthKeyFromConn.
func (c *AuthConn) Unwrap() net.Conn { return c.Conn }

// AuthKeyFromConn recovers the authKey from a connection, walking through any
// wrappers that expose Unwrap() net.Conn.
//
// The walk matters: by the time crypto/tls calls GetCertificate the connection
// has usually been wrapped again — for buffering the peeked ClientHello, for
// deadlines, for accounting. Requiring the AuthConn to be the outermost layer
// would make this break the first time someone adds a wrapper, and break as a
// certificate that fails to authenticate rather than as a compile error.
func AuthKeyFromConn(c net.Conn) ([]byte, error) {
	for range 16 { // bounded: a cycle in the wrapper chain must not hang the server
		if c == nil {
			break
		}
		if ac, ok := c.(*AuthConn); ok {
			return ac.authKey, nil
		}
		u, ok := c.(interface{ Unwrap() net.Conn })
		if !ok {
			break
		}
		c = u.Unwrap()
	}
	return nil, ErrNoConnAuthKey
}

// CertificateForHello mints the certificate for one connection, for use as the
// body of tls.Config.GetCertificate.
//
// It takes the SNI and the blank cache, and recovers the authKey from
// chi.Conn. Both fields of the returned certificate matter: the DER carries our
// MAC in its signature field, and the private key signs CertificateVerify,
// which the client does check against the certificate's public key.
//
// Certificate selection policy — which SNI to mint for when the client's is not
// one we serve — is deliberately not decided here. That is the server's call
// and it interacts with the donor fallback.
func CertificateForHello(cache *CertBlankCache, chi *stdtls.ClientHelloInfo, sni string) (*stdtls.Certificate, error) {
	authKey, err := AuthKeyFromConn(chi.Conn)
	if err != nil {
		return nil, err
	}
	return CertificateFor(cache, sni, authKey)
}

// CertificateFor assembles the per-connection certificate from a cached blank.
func CertificateFor(cache *CertBlankCache, sni string, authKey []byte) (*stdtls.Certificate, error) {
	blank, err := cache.Get(sni)
	if err != nil {
		return nil, err
	}
	der, err := blank.WithAuthHMAC(authKey)
	if err != nil {
		return nil, err
	}
	return &stdtls.Certificate{
		Certificate: [][]byte{der},
		PrivateKey:  blank.PrivateKey(),
	}, nil
}
