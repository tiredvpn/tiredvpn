package server

import (
	"crypto/rand"
	"crypto/x509/pkix"
	"encoding/pem"
	"math/big"
	"net"
	"testing"
	"time"

	"github.com/tiredvpn/tiredvpn/internal/protocol"
	"github.com/xtaci/smux"
	"gitverse.ru/uzer_007/gogost/v3/gost3410"
	"gitverse.ru/uzer_007/gogost/v3/gosttls"
	gostx509 "gitverse.ru/uzer_007/gogost/v3/gostx509"
)

func TestGOSTTLSIngressRoutesMuxOnSeparateHandler(t *testing.T) {
	priv, err := gost3410.GenPrivateKey(gost3410.CurveIdtc26gost341012256paramSetA(), rand.Reader)
	if err != nil {
		t.Fatal(err)
	}
	pub, err := priv.PublicKey()
	if err != nil {
		t.Fatal(err)
	}
	now := time.Now()
	tpl := &gostx509.Certificate{SerialNumber: big.NewInt(11), Subject: pkix.Name{CommonName: "test"}, DNSNames: []string{"test"}, NotBefore: now.Add(-time.Minute), NotAfter: now.Add(time.Hour), KeyUsage: gostx509.KeyUsageDigitalSignature | gostx509.KeyUsageCertSign, ExtKeyUsage: []gostx509.ExtKeyUsage{gostx509.ExtKeyUsageServerAuth, gostx509.ExtKeyUsageClientAuth}, BasicConstraintsValid: true, IsCA: true}
	der, err := gostx509.CreateCertificate(rand.Reader, tpl, tpl, pub, priv)
	if err != nil {
		t.Fatal(err)
	}
	keyDER, err := gostx509.MarshalPKCS8PrivateKey(priv)
	if err != nil {
		t.Fatal(err)
	}
	cert, err := gosttls.X509KeyPair(pem.EncodeToMemory(&pem.Block{Type: "CERTIFICATE", Bytes: der}), pem.EncodeToMemory(&pem.Block{Type: "PRIVATE KEY", Bytes: keyDER}))
	if err != nil {
		t.Fatal(err)
	}
	ctx := &serverContext{cfg: &Config{}, gostTLSConfig: gosttls.GOSTConfig(&gosttls.Config{Certificates: []gosttls.Certificate{cert}})}
	clientRaw, serverRaw := net.Pipe()
	done := make(chan struct{})
	go func() { handleGOSTTLSConnection(serverRaw, ctx, 77); close(done) }()
	_ = clientRaw.SetDeadline(time.Now().Add(10 * time.Second))
	clientTLS := gosttls.Client(clientRaw, gosttls.GOSTConfig(&gosttls.Config{ServerName: "test", InsecureSkipVerify: true}))
	if err := clientTLS.Handshake(); err != nil {
		t.Fatal(err)
	}
	if state := clientTLS.ConnectionState(); state.Version != gosttls.VersionTLS13 || !isGOSTSuiteServer(state.CipherSuite) {
		t.Fatalf("unexpected negotiated state: version=%x suite=%04x", state.Version, state.CipherSuite)
	}
	if err := protocol.WriteDispatch(clientTLS, protocol.TypeMux); err != nil {
		t.Fatal(err)
	}
	sess, err := smux.Client(clientTLS, smux.DefaultConfig())
	if err != nil {
		t.Fatal(err)
	}
	_ = sess.Close()
	_ = clientRaw.Close()
	select {
	case <-done:
	case <-time.After(2 * time.Second):
		t.Fatal("GOST server handler did not stop after mux close")
	}
}
