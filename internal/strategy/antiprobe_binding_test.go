package strategy

import (
	"context"
	"crypto/tls"
	"net"
	"testing"
	"time"

	"github.com/tiredvpn/tiredvpn/internal/protocol"
)

// antiProbeServerProof drives the production server side of an anti-probe
// handshake up to and including the knock ACK, then hands control to writeProof
// so a test can send a good proof, a bogus one, or none at all. Returns the
// session exporter the real server would key its proof with.
func antiProbeServeKnock(t *testing.T, ln net.Listener, cert tls.Certificate, secret []byte, writeProof func(conn net.Conn, ekm []byte)) {
	t.Helper()
	tlsLn := tls.NewListener(ln, &tls.Config{
		Certificates: []tls.Certificate{cert},
		MinVersion:   tls.VersionTLS12,
		NextProtos:   []string{"http/1.1"},
	})
	conn, err := tlsLn.Accept()
	if err != nil {
		return
	}
	defer conn.Close()

	conn.SetReadDeadline(time.Now().Add(5 * time.Second))
	protoType, err := protocol.ReadDispatch(conn)
	if err != nil || protoType != protocol.TypeAntiProbe {
		return
	}
	conn.SetReadDeadline(time.Time{})

	if !verifyServerKnock(conn, secret, t) {
		return
	}
	conn.Write([]byte{0x01})

	tc := conn.(interface {
		ConnectionState() tls.ConnectionState
	})
	state := tc.ConnectionState()
	ekm, err := exporterFor(&state)
	if err != nil {
		return
	}
	if writeProof != nil {
		writeProof(conn, ekm)
	}
}

// exporterFor is a thin wrapper so the test does not import internal/tls twice.
func exporterFor(state *tls.ConnectionState) ([]byte, error) {
	return state.ExportKeyingMaterial(customBindingLabel, nil, customBindingLen)
}

// The exporter label/length must match internal/tls.ExportBindingKey. They are
// duplicated here (not imported) only so this test can build a mismatching EKM
// on purpose; the production paths both go through ExportBindingKey.
const (
	customBindingLabel = "EXPORTER-tiredvpn-reality-bind"
	customBindingLen   = 32
)

// TestAntiProbeRejectsBogusServerProof predicts the broken code: revert
// verifyServerAuth to `return nil` and this goes green, because the client
// would accept a server that answered the ACK with 32 arbitrary bytes. With the
// proof check in place the client must reject it.
func TestAntiProbeRejectsBogusServerProof(t *testing.T) {
	cert, err := generateTestCert()
	if err != nil {
		t.Fatalf("generateTestCert: %v", err)
	}
	ln, err := net.Listen("tcp", "127.0.0.1:0")
	if err != nil {
		t.Fatalf("listen: %v", err)
	}
	defer ln.Close()

	secret := []byte("antiprobe-bogus-proof-secret")

	go antiProbeServeKnock(t, ln, cert, secret, func(conn net.Conn, ekm []byte) {
		// 32 bytes that are not the keyed proof: a peer that passed the knock
		// (knowing the secret) but cannot bind to this session, or simply the
		// old server that sent nothing meaningful.
		conn.Write(make([]byte, AntiProbeProofLen))
	})

	mgr := NewManager()
	setTestEndpoint(mgr, ln.Addr().String())
	strat := NewAntiProbeStrategy(mgr, secret)

	ctx, cancel := context.WithTimeout(context.Background(), 10*time.Second)
	defer cancel()

	conn, err := strat.Connect(ctx, ln.Addr().String())
	if err == nil {
		conn.Close()
		t.Fatal("Connect accepted a server that sent a bogus proof; verifyServerAuth is not checking the session binding")
	}
}

// TestAntiProbeAcceptsValidServerProof is the positive control for the test
// above (verification.md rule 2): the same harness with a correctly keyed proof
// must succeed, proving the rejection is about the proof and not the harness.
func TestAntiProbeAcceptsValidServerProof(t *testing.T) {
	cert, err := generateTestCert()
	if err != nil {
		t.Fatalf("generateTestCert: %v", err)
	}
	ln, err := net.Listen("tcp", "127.0.0.1:0")
	if err != nil {
		t.Fatalf("listen: %v", err)
	}
	defer ln.Close()

	secret := []byte("antiprobe-valid-proof-secret")

	go antiProbeServeKnock(t, ln, cert, secret, func(conn net.Conn, ekm []byte) {
		proof := AntiProbeServerProof(secret, ekm)
		conn.Write(proof[:])
	})

	mgr := NewManager()
	setTestEndpoint(mgr, ln.Addr().String())
	strat := NewAntiProbeStrategy(mgr, secret)

	ctx, cancel := context.WithTimeout(context.Background(), 10*time.Second)
	defer cancel()

	conn, err := strat.Connect(ctx, ln.Addr().String())
	if err != nil {
		t.Fatalf("Connect rejected a valid server proof: %v", err)
	}
	conn.Close()
}

// TestAntiProbeServerProofIsSessionBound checks the property directly: a proof
// computed over one session's exporter does not verify against another's, and a
// proof from the wrong secret never verifies. This is the "token from session A
// fails on session B" requirement at the primitive level.
func TestAntiProbeServerProofIsSessionBound(t *testing.T) {
	secret := []byte("session-bound-secret")
	ekmA := []byte("aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa") // 32 bytes, session A
	ekmB := []byte("bbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbb") // 32 bytes, session B

	proofA := AntiProbeServerProof(secret, ekmA)
	proofB := AntiProbeServerProof(secret, ekmB)
	if proofA == proofB {
		t.Fatal("proof did not change with the session exporter: it is not session-bound")
	}

	// Wrong secret over the same session must also differ.
	proofWrongSecret := AntiProbeServerProof([]byte("a-different-secret"), ekmA)
	if proofWrongSecret == proofA {
		t.Fatal("proof did not change with the secret")
	}
}
