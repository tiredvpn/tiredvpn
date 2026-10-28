package server

import (
	"bytes"
	"crypto/tls"
	"crypto/x509"
	"encoding/binary"
	"encoding/pem"
	"io"
	"net"
	"os"
	"os/exec"
	"path/filepath"
	"strings"
	"sync"
	"testing"
	"time"
)

// The relay's upstream keepalive is an empty stego DATA frame, and the
// exits it meets are older than it: 1.11.8 is what runs in the field. These
// run the new relay against the real 1.11.8 release binary (verification
// rule 9) on real clocks - its 60 s read deadline cannot be scaled - for 2.5
// of its deadlines, in the fix12-slow stand's shape: 28 B down every 5 s,
// nothing up. The exit's TUN needs CAP_NET_ADMIN, so they run in a network
// namespace of their own:
//
//	go test -c -o /tmp/server.test ./internal/server
//	unshare -rn sh -c 'ip link set lo up &&
//	  TIREDVPN_OLD_EXIT=/path/to/tiredvpn-1.11.8 /tmp/server.test \
//	  -test.run TestAnOldExit -test.v'
//
// Skipped without TIREDVPN_OLD_EXIT.

const oldExitSecret = "relay-leg-secret-0123456789abcdef"

// oldExit is a 1.11.8 exit running as a subprocess, with its TUN when
// withTUN (one per namespace: they all take tiredvpn0), a proxy exit only
// otherwise.
type oldExit struct {
	addr string
	log  *lockedLog
}

func startOldExit(t *testing.T, withTUN bool) *oldExit {
	t.Helper()
	bin := os.Getenv("TIREDVPN_OLD_EXIT")
	if bin == "" {
		t.Skip("TIREDVPN_OLD_EXIT not set: needs the 1.11.8 release binary and a network namespace")
	}
	dir := t.TempDir()
	cert := selfSignedCertForTest(t)
	certPEM := pem.EncodeToMemory(&pem.Block{Type: "CERTIFICATE", Bytes: cert.Certificate[0]})
	keyDER, err := x509.MarshalPKCS8PrivateKey(cert.PrivateKey)
	if err != nil {
		t.Fatal(err)
	}
	keyPEM := pem.EncodeToMemory(&pem.Block{Type: "PRIVATE KEY", Bytes: keyDER})
	certFile, keyFile := filepath.Join(dir, "server.crt"), filepath.Join(dir, "server.key")
	if err := os.WriteFile(certFile, certPEM, 0o600); err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(keyFile, keyPEM, 0o600); err != nil {
		t.Fatal(err)
	}
	ln, err := net.Listen("tcp", "127.0.0.1:0")
	if err != nil {
		t.Fatal(err)
	}
	addr := ln.Addr().String()
	ln.Close()
	out := &lockedLog{}
	args := []string{"server", "-listen", addr, "-secret", oldExitSecret, "-cert", certFile, "-key", keyFile, "-debug"}
	if withTUN {
		args = append(args, "-ip-pool", "10.8.9.0/24", "-tun-ip", "10.8.9.1")
	}
	cmd := exec.Command(bin, args...)
	cmd.Stdout, cmd.Stderr = out, out
	if err := cmd.Start(); err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() {
		_ = cmd.Process.Kill()
		_ = cmd.Wait()
		if t.Failed() {
			t.Logf("1.11.8 exit log:\n%s", out.String())
		}
	})
	for deadline := time.Now().Add(10 * time.Second); ; time.Sleep(50 * time.Millisecond) {
		if c, err := tls.Dial("tcp", addr, &tls.Config{InsecureSkipVerify: true}); err == nil {
			c.Close()
			break
		}
		if time.Now().After(deadline) {
			t.Fatalf("the 1.11.8 exit did not come up:\n%s", out.String())
		}
	}
	return &oldExit{addr: addr, log: out}
}

// udpPacket is an IPv4/UDP packet from src to dst:port with a valid header
// checksum, so the exit's kernel delivers it to a socket.
func udpPacket(src, dst net.IP, port int, payload []byte) []byte {
	p := make([]byte, 28+len(payload))
	p[0], p[8], p[9] = 0x45, 64, 17
	binary.BigEndian.PutUint16(p[2:], uint16(len(p)))
	copy(p[12:16], src.To4())
	copy(p[16:20], dst.To4())
	var sum uint32
	for i := 0; i < 20; i += 2 {
		sum += uint32(binary.BigEndian.Uint16(p[i:]))
	}
	for sum > 0xffff {
		sum = sum&0xffff + sum>>16
	}
	binary.BigEndian.PutUint16(p[10:], ^uint16(sum))
	binary.BigEndian.PutUint16(p[20:], 40000)
	binary.BigEndian.PutUint16(p[22:], uint16(port))
	binary.BigEndian.PutUint16(p[24:], uint16(8+len(payload)))
	copy(p[28:], payload)
	return p
}

// oldExitSpan is how long the tests hold the leg: 2.5 of the exit's 60 s
// read deadlines.
const oldExitSpan = 150 * time.Second

// TestAnOldExitKeepsABridgeLegOnASparseDownload: the TUN bridge into a
// 1.11.8 exit. The keepalive frames reach the exit's TUN path as an empty
// payload; the leg has to outlive the deadline, and a packet up at the end
// has to come out of the exit's TUN.
func TestAnOldExitKeepsABridgeLegOnASparseDownload(t *testing.T) {
	t.Parallel()
	exit := startOldExit(t, true)
	b := startRelayBridgeTo(t, exit.addr, []byte(oldExitSecret))
	up, err := net.ListenUDP("udp4", &net.UDPAddr{IP: net.IPv4(10, 8, 9, 1), Port: 5555})
	if err != nil {
		t.Fatalf("listen on the exit's TUN address: %v", err)
	}
	t.Cleanup(func() { up.Close() })
	down, err := net.DialUDP("udp4", nil, &net.UDPAddr{IP: b.clientIP, Port: 9})
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { down.Close() })

	tick := time.NewTicker(5 * time.Second)
	defer tick.Stop()
	var sent int64
	for range oldExitSpan / (5 * time.Second) {
		<-tick.C
		if _, err := down.Write(make([]byte, 28)); err == nil {
			sent++
		}
		select {
		case <-b.done:
			t.Fatalf("the relay closed the bridge after %d datagrams", sent)
		default:
		}
	}
	if got := b.down.Load(); got < sent*9/10 {
		t.Fatalf("%d of %d datagrams came down", got, sent)
	}
	if err := b.send(udpPacket(b.clientIP, net.IPv4(10, 8, 9, 1), 5555, []byte("hello"))); err != nil {
		t.Fatal(err)
	}
	_ = up.SetReadDeadline(time.Now().Add(5 * time.Second))
	buf := make([]byte, 64)
	n, _, err := up.ReadFromUDP(buf)
	if err != nil || string(buf[:n]) != "hello" {
		t.Fatalf("the packet up after %v came out of the exit as %q: %v", oldExitSpan, buf[:n], err)
	}
	if logs := exit.log.String(); strings.Contains(logs, "session ended") || strings.Contains(logs, "bad record MAC") {
		t.Fatalf("the 1.11.8 exit ended the leg:\n%s", logs)
	}
}

// TestAnOldExitDeliversNothingOfAKeepaliveToAProxyTarget: a proxy relay -
// handleRawTunnel over UpstreamDialer.Dial - into a 1.11.8 exit, whose
// proxy writes each payload it extracts to the target. The empty keepalive
// payloads must reach the target as nothing at all: at the end the target
// has the client's "hello" and not one byte more.
func TestAnOldExitDeliversNothingOfAKeepaliveToAProxyTarget(t *testing.T) {
	t.Parallel()
	exit := startOldExit(t, false)
	ln, err := net.Listen("tcp", "127.0.0.1:0")
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { ln.Close() })
	var mu sync.Mutex
	var got bytes.Buffer
	gotHello := make(chan struct{})
	stop := make(chan struct{})
	stopTarget := sync.OnceFunc(func() { close(stop) })
	t.Cleanup(stopTarget)
	go func() {
		c, err := ln.Accept()
		if err != nil {
			return
		}
		defer c.Close()
		go func() {
			buf := make([]byte, 256)
			for {
				n, err := c.Read(buf)
				mu.Lock()
				got.Write(buf[:n])
				done := strings.Contains(got.String(), "hello")
				mu.Unlock()
				if done {
					close(gotHello)
					return
				}
				if err != nil {
					return
				}
			}
		}()
		tick := time.NewTicker(5 * time.Second)
		defer tick.Stop()
		for {
			select {
			case <-stop:
				return
			case <-tick.C:
				if _, err := c.Write(make([]byte, 28)); err != nil {
					return
				}
			}
		}
	}()

	relayCtx := &serverContext{cfg: &Config{}, upstreamDialer: NewUpstreamDialer(exit.addr, []byte(oldExitSecret))}
	client, relaySide := tcpPair(t)
	t.Cleanup(func() { client.Close() })
	done := make(chan struct{})
	go func() {
		defer close(done)
		handleRawTunnel(relaySide, relayCtx, testLogger(t), clientIdentity{})
	}()
	addr := []byte(ln.Addr().String())
	if _, err := client.Write(append([]byte{byte(len(addr) >> 8), byte(len(addr))}, addr...)); err != nil {
		t.Fatal(err)
	}
	ack := make([]byte, 1)
	_ = client.SetReadDeadline(time.Now().Add(10 * time.Second))
	if _, err := io.ReadFull(client, ack); err != nil || ack[0] != 0 {
		t.Fatalf("relay ack %x: %v", ack, err)
	}
	_ = client.SetReadDeadline(time.Time{})
	go func() { _, _ = io.Copy(io.Discard, client) }()
	for end := time.Now().Add(oldExitSpan); time.Now().Before(end); time.Sleep(time.Second) {
		select {
		case <-done:
			t.Fatal("the relay closed the tunnel")
		default:
		}
	}
	if _, err := client.Write([]byte("hello")); err != nil {
		t.Fatal(err)
	}
	select {
	case <-gotHello:
	case <-time.After(10 * time.Second):
		t.Fatal("the hello after the quiet never reached the target")
	}
	mu.Lock()
	defer mu.Unlock()
	if got.String() != "hello" {
		t.Fatalf("the target got %q, want the client's hello and nothing else", got.String())
	}
}
