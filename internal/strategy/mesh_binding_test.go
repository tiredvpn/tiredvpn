package strategy

import (
	"bytes"
	"context"
	"crypto/hmac"
	"crypto/rand"
	"crypto/tls"
	"io"
	"net"
	"sync"
	"testing"
	"time"

	customtls "github.com/tiredvpn/tiredvpn/internal/tls"
)

// meshTLSPipe returns a connected TLS client/server pair over an in-memory
// pipe, so the auth exchange runs over a real handshake with a real exporter.
func meshTLSPipe(t *testing.T) (client, server *tls.Conn) {
	t.Helper()
	cert, err := generateTestCert()
	if err != nil {
		t.Fatalf("generateTestCert: %v", err)
	}
	c1, c2 := net.Pipe()
	server = tls.Server(c2, &tls.Config{
		Certificates: []tls.Certificate{cert},
		MinVersion:   tls.VersionTLS12,
	})
	client = tls.Client(c1, &tls.Config{
		InsecureSkipVerify: true,
		MinVersion:         tls.VersionTLS12,
	})
	errc := make(chan error, 2)
	go func() { errc <- server.Handshake() }()
	go func() { errc <- client.Handshake() }()
	for i := 0; i < 2; i++ {
		if err := <-errc; err != nil {
			t.Fatalf("tls handshake: %v", err)
		}
	}
	deadline := time.Now().Add(3 * time.Second)
	client.SetDeadline(deadline)
	server.SetDeadline(deadline)
	return client, server
}

// TestMeshAuthNoSecretOnWire drives the real authenticateRelay against a mock
// relay that follows the v2 challenge-response, and asserts the relay never
// sees the secret bytes. Revert authenticateRelay to the v1 JSON body that put
// relay.Secret on the wire and this goes red: the short secret lands in the
// first bytes the relay reads.
func TestMeshAuthNoSecretOnWire(t *testing.T) {
	client, server := meshTLSPipe(t)
	defer client.Close()
	defer server.Close()

	const secret = "sekret" // short on purpose: fits inside the v1 JSON prefix

	ss := server.ConnectionState()
	serverEKM, err := customtls.ExportBindingKey(&ss)
	if err != nil {
		t.Fatalf("server exporter: %v", err)
	}
	cs := client.ConnectionState()
	clientEKM, err := customtls.ExportBindingKey(&cs)
	if err != nil {
		t.Fatalf("client exporter: %v", err)
	}

	var received bytes.Buffer
	var challenge [meshChallengeLen]byte
	relayDone := make(chan error, 1)
	go func() {
		if _, err := rand.Read(challenge[:]); err != nil {
			relayDone <- err
			return
		}
		if _, err := server.Write(challenge[:]); err != nil {
			relayDone <- err
			return
		}
		resp := make([]byte, meshProofLen)
		if _, err := io.ReadFull(server, resp); err != nil {
			relayDone <- err
			return
		}
		received.Write(resp)
		server.Write([]byte{0x01})
		relayDone <- nil
	}()

	mesh := NewMeshRelayStrategy("exit.example.com:443")
	relay := &RelayNode{Address: "relay:443", Secret: secret}
	if err := mesh.authenticateRelay(client, relay, clientEKM); err != nil {
		t.Fatalf("authenticateRelay: %v", err)
	}
	if err := <-relayDone; err != nil {
		t.Fatalf("mock relay: %v", err)
	}

	if bytes.Contains(received.Bytes(), []byte(secret)) {
		t.Fatal("the relay secret appeared in the bytes the client sent")
	}

	// Positive control (rule 2): the bytes the relay read are exactly the keyed
	// proof, so the check above is rejecting the secret, not any 32 bytes.
	want := MeshRelayProof(secret, challenge[:], serverEKM)
	if !hmac.Equal(received.Bytes(), want[:]) {
		t.Fatal("client did not send the expected challenge-response proof")
	}
}

// TestMeshAuthRejectsEmptySecret checks the choke point: a relay with no secret
// is refused, so a config copied from ExampleRelayConfig (empty secrets) fails
// loudly instead of authenticating against a default. The mock relay here
// accepts ANY proof, so if the empty-secret guard is removed the exchange would
// otherwise succeed and the test goes red — the guard is what it is testing.
func TestMeshAuthRejectsEmptySecret(t *testing.T) {
	client, server := meshTLSPipe(t)
	defer client.Close()
	defer server.Close()

	go func() {
		challenge := make([]byte, meshChallengeLen)
		if _, err := rand.Read(challenge); err != nil {
			return
		}
		if _, err := server.Write(challenge); err != nil {
			return
		}
		resp := make([]byte, meshProofLen)
		if _, err := io.ReadFull(server, resp); err != nil {
			return
		}
		server.Write([]byte{0x01}) // permissive: accept whatever the client sent
	}()

	mesh := NewMeshRelayStrategy("exit.example.com:443")
	relay := &RelayNode{Address: "relay:443", Secret: ""}
	if err := mesh.authenticateRelay(client, relay, make([]byte, 32)); err == nil {
		t.Fatal("authenticateRelay accepted an empty secret")
	}
}

// TestMeshRelayProofSessionBound is the "proof from session A fails on session
// B" property at the primitive level: the proof changes with the exporter, with
// the challenge, and with the secret.
func TestMeshRelayProofSessionBound(t *testing.T) {
	const secret = "mesh-binding-secret"
	challenge := []byte("cccccccccccccccccccccccccccccccc")
	ekmA := []byte("aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa")
	ekmB := []byte("bbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbb")

	base := MeshRelayProof(secret, challenge, ekmA)
	if base == MeshRelayProof(secret, challenge, ekmB) {
		t.Fatal("proof did not change with the TLS session exporter")
	}
	if base == MeshRelayProof(secret, []byte("dddddddddddddddddddddddddddddddd"), ekmA) {
		t.Fatal("proof did not change with the relay challenge")
	}
	if base == MeshRelayProof("other-secret", challenge, ekmA) {
		t.Fatal("proof did not change with the secret")
	}
}

// TestMeshHealthCheckNoRace runs checkRelayHealth concurrently with the locked
// readers (selectBestRelay/Probe/GetRelays). Before the fix the health
// goroutines wrote r.Available/r.Latency/r.LastCheck without the lock the
// selector reads them under; -race flags that. Relays point at a discard port so
// dials fail fast and take the r.Available=false branch too.
func TestMeshHealthCheckNoRace(t *testing.T) {
	mesh := NewMeshRelayStrategy("exit.example.com:443")
	mesh.AddRelays([]*RelayNode{
		{Address: "127.0.0.1:1", Location: "RU-Moscow", Available: true},
		{Address: "127.0.0.1:1", Location: "RU-SPB", Available: true},
		{Address: "127.0.0.1:1", Location: "RU-Kazan", Available: true},
	})

	var wg sync.WaitGroup
	wg.Add(1)
	go func() {
		defer wg.Done()
		for i := 0; i < 5; i++ {
			mesh.checkRelayHealth()
		}
	}()
	for i := 0; i < 4; i++ {
		wg.Add(1)
		go func() {
			defer wg.Done()
			for j := 0; j < 200; j++ {
				_ = mesh.Probe(context.Background(), "x")
				_, _ = mesh.selectBestRelay()
				_ = mesh.GetRelays()
			}
		}()
	}
	wg.Wait()
}
