package server

import (
	"bytes"
	"context"
	"crypto/tls"
	"crypto/x509"
	"encoding/binary"
	"encoding/pem"
	"errors"
	"fmt"
	"io"
	"net"
	"os"
	"path/filepath"
	"slices"
	"strconv"
	"sync"
	"sync/atomic"
	"testing"
	"time"

	"github.com/tiredvpn/tiredvpn/internal/endpoint"
	"github.com/tiredvpn/tiredvpn/internal/strategy"
	"github.com/tiredvpn/tiredvpn/internal/tun"
	"golang.org/x/net/http2/hpack"
	"golang.org/x/sys/unix"
)

// Per-client byte accounting, driven through the functions each transport's
// traffic actually flows through. Up to 1.11.8 the three counters of a client
// were one shared int64, and no TUN transport counted a byte, so Redis showed
// the connection count as bytes_up and bytes_down.
//
// The data paths, enumerated (rule 7):
//
//	TUN, terminated here    native (handleRawTunnel: REALITY, REALITY-B1, WS,
//	                        IMAP, SSH, anti-probe; QUIC enters the same core),
//	                        morph, confusion, H2 stego, HTTP polling
//	TUN, relayed upstream   the same five
//	proxy                   raw tunnel, morph, confusion, H2 stego, HTTP polling,
//	                        QUIC (no harness: needs a live QUIC session; same
//	                        end-of-stream accounting as the raw tunnel)
//
// ICMP reaches handleRawTunnel with no identity (the master key is shared), so
// its bytes have no client to land on. MuxHandler has no caller.

const (
	trafficClient = "c1"
	trafficSecret = "traffic-test-client-c1-secret32!"
	quietClient   = "c2"
	quietSecret   = "traffic-test-client-c2-secret32!"
	upstreamKey   = "traffic-test-upstream-secret-32!"
)

func trafficRegistry(t *testing.T) *ClientRegistry {
	t.Helper()
	return newTestRegistryWithSecrets(t, map[string]string{
		trafficClient: trafficSecret,
		quietClient:   quietSecret,
	})
}

// socketTUN is a SharedTUN whose device is one end of a SEQPACKET socketpair,
// with the dispatcher running: what the test writes to far reaches clients the
// way kernel packets do, and what clients send can be read from far.
func socketTUN(t *testing.T, name string) (*SharedTUN, *os.File) {
	t.Helper()
	fds, err := unix.Socketpair(unix.AF_UNIX, unix.SOCK_SEQPACKET|unix.SOCK_CLOEXEC, 0)
	if err != nil {
		t.Fatalf("socketpair: %v", err)
	}
	dev, err := tun.CreateTUNFromFd(fds[0], name, 1500)
	if err != nil {
		t.Fatalf("tun from fd: %v", err)
	}
	far := os.NewFile(uintptr(fds[1]), name+"-far")
	_, network, _ := net.ParseCIDR("10.8.0.0/24")
	st := newSharedTUNOn(dev, net.IPv4(10, 8, 0, 1), network, 1500, 2)
	st.start()
	// Not st.Close: that would run the host teardown (MSS clamp rules, link
	// removal) for an interface name that exists only in this test.
	t.Cleanup(func() {
		atomic.StoreInt32(&st.running, 0)
		close(st.stopCh)
		far.Close() // the dispatcher's blocked read returns EOF
		st.wg.Wait()
	})
	return st, far
}

// exitContext is a terminating node: shared TUN on a socketpair, a pool, and
// the given registry (nil: global secret only).
func exitContext(t *testing.T, name string, registry *ClientRegistry) (*serverContext, *os.File) {
	t.Helper()
	srvCtx := newTestServerContext(t)
	srvCtx.cfg.TunIP = net.IPv4(10, 8, 0, 1)
	srvCtx.ipPool = newTestPool(t)
	srvCtx.registry = registry
	st, far := socketTUN(t, name)
	srvCtx.sharedTUN = st
	return srvCtx, far
}

// startExit runs a real exit that relays reach the way they do in production:
// TLS, then handleTLSConnection, keyed by upstreamKey.
func startExit(t *testing.T) (addr string, far *os.File) {
	t.Helper()
	exitCtx, far := exitContext(t, "fxexit0", nil)
	exitCtx.cfg.Secret = []byte(upstreamKey)

	ln, err := tls.Listen("tcp", "127.0.0.1:0", &tls.Config{
		Certificates: []tls.Certificate{selfSignedCertForTest(t)},
		NextProtos:   []string{"h2"},
	})
	if err != nil {
		t.Fatalf("exit listen: %v", err)
	}
	var wg sync.WaitGroup
	t.Cleanup(func() {
		ln.Close()
		wg.Wait()
	})
	wg.Go(func() {
		var id uint64
		for {
			c, err := ln.Accept()
			if err != nil {
				return
			}
			id++
			tc := c.(*tls.Conn)
			go func() {
				defer tc.Close()
				if tc.Handshake() != nil {
					return
				}
				handleTLSConnection(tc, exitCtx, id)
			}()
		}
	})
	return ln.Addr().String(), far
}

// relayContext is a relay node in front of a real exit.
func relayContext(t *testing.T, registry *ClientRegistry) (*serverContext, *os.File) {
	t.Helper()
	addr, far := startExit(t)
	srvCtx := newTestServerContext(t)
	srvCtx.registry = registry
	srvCtx.upstreamDialer = NewUpstreamDialer(addr, []byte(upstreamKey))
	t.Cleanup(func() { srvCtx.upstreamDialer.Close() })
	return srvCtx, far
}

// trafficPacket builds an IPv4/UDP packet of size bytes to dst.
func trafficPacket(dst net.IP, seq, size int) []byte {
	p := make([]byte, size)
	p[0] = 0x45
	binary.BigEndian.PutUint16(p[2:4], uint16(size))
	p[8] = 64
	p[9] = 17
	copy(p[12:16], net.IPv4(198, 51, 100, 7).To4())
	copy(p[16:20], dst.To4())
	for i := 20; i < size; i++ {
		p[i] = byte(seq + i)
	}
	return p
}

func lenFrame(pkt []byte) []byte {
	f := make([]byte, 4+len(pkt))
	binary.BigEndian.PutUint32(f, uint32(len(pkt)))
	copy(f[4:], pkt)
	return f
}

// readLenFrame reads one [len:4][pkt:N] frame, skipping keepalives.
func readLenFrame(r io.Reader) ([]byte, error) {
	var hdr [4]byte
	for {
		if _, err := io.ReadFull(r, hdr[:]); err != nil {
			return nil, err
		}
		if n := binary.BigEndian.Uint32(hdr[:]); n > 0 {
			pkt := make([]byte, n)
			_, err := io.ReadFull(r, pkt)
			return pkt, err
		}
	}
}

// v3Handshake is [localIP:4][mtu:2][version:1]: auto IP, MTU 1400, version 3.
func v3Handshake() []byte { return []byte{0, 0, 0, 0, 0x05, 0x78, 0x03} }

// waitTraffic waits for the client's counters to reach want and fails if they
// do not, or if they go past it. Counters are added after the write returns,
// so the far end can see a packet a moment before it is counted.
func waitTraffic(t *testing.T, r *ClientRegistry, id string, wantUp, wantDown int64) {
	t.Helper()
	deadline := time.Now().Add(5 * time.Second)
	for {
		s := r.GetStats(id)
		if s.BytesUp == wantUp && s.BytesDown == wantDown {
			return
		}
		if s.BytesUp > wantUp || s.BytesDown > wantDown || time.Now().After(deadline) {
			t.Fatalf("%s: bytes_up=%d bytes_down=%d, want %d/%d", id, s.BytesUp, s.BytesDown, wantUp, wantDown)
		}
		time.Sleep(10 * time.Millisecond)
	}
}

// tunClient is one connected TUN client, whatever carries it.
type tunClient struct {
	ip   net.IP
	send func(pkt []byte) error
	recv func() ([]byte, error)
}

type tunTransport struct {
	name string
	open func(t *testing.T, srvCtx *serverContext) tunClient
	// conns is the total_conns one session adds: the transports that track
	// their connection with the registry add one.
	conns int64
}

var tunTransports = []tunTransport{
	{"native", openNativeTUN, 1},
	{"morph", openMorphTUN, 1},
	{"confusion", openConfusionTUN, 0},
	{"h2", openH2TUN, 1},
	{"polling", openPollingTUN, 0},
}

// streamTUNClient frames packets as [len:4][pkt:N] over a byte stream.
func streamTUNClient(t *testing.T, conn net.Conn, w io.Writer, r io.Reader) tunClient {
	t.Helper()
	resp, next, err := tun.ReadTUNHandshakeResponse(conn, 0x03, time.Now().Add(10*time.Second))
	if err != nil {
		t.Fatalf("handshake response: %v", err)
	}
	if resp[0] != 0x00 {
		t.Fatalf("handshake status 0x%02x", resp[0])
	}
	if r == nil {
		r = next
	}
	return tunClient{
		ip:   net.IP(append([]byte(nil), resp[5:9]...)),
		send: func(pkt []byte) error { _, err := w.Write(lenFrame(pkt)); return err },
		recv: func() ([]byte, error) { return readLenFrame(r) },
	}
}

// openNativeTUN runs the native TUN under the identity REALITY's
// authentication gives a registry client - the path most sessions take.
func openNativeTUN(t *testing.T, srvCtx *serverContext) tunClient {
	id := realityIdentityFor(t, srvCtx, []byte(trafficSecret))
	client, server := tcpPair(t)
	go handleRawTunnel(server, srvCtx, testLogger(t), id)
	if _, err := client.Write(append([]byte{0x02}, v3Handshake()...)); err != nil {
		t.Fatalf("write handshake: %v", err)
	}
	return streamTUNClient(t, client, client, nil)
}

func morphFrame(data []byte) []byte {
	f := make([]byte, 6+len(data))
	binary.BigEndian.PutUint32(f, uint32(len(data)))
	copy(f[6:], data)
	return f
}

// readMorphFrame reads [dataLen:4][padLen:2][data][padding] and returns data.
func readMorphFrame(r io.Reader) ([]byte, error) {
	var hdr [6]byte
	for {
		if _, err := io.ReadFull(r, hdr[:]); err != nil {
			return nil, err
		}
		dataLen := binary.BigEndian.Uint32(hdr[:4])
		padLen := binary.BigEndian.Uint16(hdr[4:6])
		body := make([]byte, int(dataLen)+int(padLen))
		if _, err := io.ReadFull(r, body); err != nil {
			return nil, err
		}
		if dataLen > 0 {
			return body[:dataLen], nil
		}
	}
}

// openMorphTUN authenticates for real (TLS, MRPH token from the registry
// secret) and asks for TUN mode, the way the morph client does.
func openMorphTUN(t *testing.T, srvCtx *serverContext) tunClient {
	client, server := tlsLoopbackPair(t)
	go handleMorphConnection(server, srvCtx, testLogger(t))
	client.SetReadDeadline(time.Now().Add(10 * time.Second))
	client.Write(append([]byte("MRPH\x04test"), computeMorphAuthForTest(t, []byte(trafficSecret), clientExporter(t, client))...))
	ack := make([]byte, 1)
	if _, err := io.ReadFull(client, ack); err != nil || ack[0] != 0 {
		t.Fatalf("early ack %x, err %v", ack, err)
	}
	client.Write(morphFrame(append([]byte{0x02}, v3Handshake()...)))
	resp, err := readMorphFrame(client)
	if err != nil || len(resp) < 9 || resp[0] != 0x00 {
		t.Fatalf("morph handshake response %x, err %v", resp, err)
	}
	client.SetReadDeadline(time.Time{})
	return tunClient{
		ip:   net.IP(resp[5:9]),
		send: func(pkt []byte) error { _, err := client.Write(morphFrame(lenFrame(pkt))); return err },
		recv: func() ([]byte, error) {
			data, err := readMorphFrame(client)
			if err != nil {
				return nil, err
			}
			return readLenFrame(bytes.NewReader(data))
		},
	}
}

func openConfusionTUN(t *testing.T, srvCtx *serverContext) tunClient {
	client, server := tcpPair(t)
	go handleConnection(server, srvCtx, 21)
	cc, err := strategy.NewConfusedConn(client, strategy.ConfusionDNSoverTLS, []byte(trafficSecret))
	if err != nil {
		t.Fatalf("NewConfusedConn: %v", err)
	}
	if _, err := cc.Write(append([]byte{0x02}, v3Handshake()...)); err != nil {
		t.Fatalf("write handshake: %v", err)
	}
	client.SetReadDeadline(time.Now().Add(10 * time.Second))
	resp := make([]byte, 9)
	if _, err := io.ReadFull(cc, resp); err != nil || resp[0] != 0x00 {
		t.Fatalf("confusion handshake response %x, err %v", resp, err)
	}
	client.SetReadDeadline(time.Time{})
	return tunClient{
		ip:   net.IP(resp[5:9]),
		send: func(pkt []byte) error { _, err := cc.Write(lenFrame(pkt)); return err },
		recv: func() ([]byte, error) { return readLenFrame(cc) },
	}
}

// h2Stego connects the real stego client to the real server frame loop.
func h2Stego(t *testing.T, srvCtx *serverContext, tunMode bool) *strategy.HTTP2StegoConn {
	t.Helper()
	client, server := tcpPair(t)
	go func() {
		logger := testLogger(t)
		if readH2Preface(server, logger) != nil {
			return
		}
		framer, err := newH2Framer(server, logger)
		if err != nil {
			return
		}
		var (
			authenticated bool
			authClientID  clientIdentity
			authSecret    []byte
			tunnel        *h2TunnelState
			connTracked   bool
		)
		runH2FrameLoop(&server, &framer, hpack.NewDecoder(4096, nil), srvCtx, logger,
			&authenticated, &authClientID, &authSecret, &connTracked, &tunnel, nil, pipeTestEKM)
	}()
	mode := strategy.NaivePaddingStandard
	if tunMode {
		mode = strategy.NaivePaddingMinimal
	}
	sc := strategy.NewHTTP2StegoConn(client, []byte(trafficSecret), true, mode, pipeTestEKM)
	if err := sc.Handshake(); err != nil {
		t.Fatalf("stego handshake: %v", err)
	}
	return sc
}

func openH2TUN(t *testing.T, srvCtx *serverContext) tunClient {
	sc := h2Stego(t, srvCtx, true)
	if _, err := sc.Write(append([]byte{0x02}, v3Handshake()...)); err != nil {
		t.Fatalf("write handshake: %v", err)
	}
	return streamTUNClient(t, sc, sc, nil)
}

// pollingReader reads a polling session's downlink the way the client does:
// each poll acknowledges everything received so far.
type pollingReader struct {
	sess *HTTPPollingSession
	ack  int64
	buf  []byte
}

func (p *pollingReader) Read(b []byte) (int, error) {
	deadline := time.Now().Add(10 * time.Second)
	for len(p.buf) == 0 {
		if chunk := p.sess.ReadToClient(p.ack); len(chunk) > 0 {
			p.ack += int64(len(chunk))
			p.buf = append(p.buf, chunk...)
			break
		}
		if time.Now().After(deadline) {
			return 0, errors.New("polling downlink: nothing within 10s")
		}
		time.Sleep(5 * time.Millisecond)
	}
	n := copy(b, p.buf)
	p.buf = p.buf[n:]
	return n, nil
}

func pollingSession(t *testing.T, id string) *HTTPPollingSession {
	t.Helper()
	sess := newPollingSession(id)
	sess.ClientID = registryIdentity(trafficClient)
	t.Cleanup(sess.Close)
	return sess
}

func openPollingTUN(t *testing.T, srvCtx *serverContext) tunClient {
	sess := pollingSession(t, "traffic-polling-tun-"+t.Name())
	sess.WriteFromClient(append([]byte{0x02}, v3Handshake()...))
	go runPollingSessionRelay(sess, srvCtx, testLogger(t))

	down := &pollingReader{sess: sess}
	resp := make([]byte, 9)
	if _, err := io.ReadFull(down, resp); err != nil || resp[0] != 0x00 {
		t.Fatalf("polling handshake response %x, err %v", resp, err)
	}
	return tunClient{
		ip:   net.IP(resp[5:9]),
		send: func(pkt []byte) error { sess.WriteFromClient(lenFrame(pkt)); return nil },
		recv: func() ([]byte, error) { return readLenFrame(down) },
	}
}

// exchangeTUN moves packets of the given sizes each way through c and returns
// the IP bytes sent and received.
func exchangeTUN(t *testing.T, c tunClient, far *os.File, sizes []int) (up, down int64) {
	t.Helper()
	buf := make([]byte, 2048)
	for i, size := range sizes {
		pkt := trafficPacket(net.IPv4(203, 0, 113, 9), i, size)
		if err := c.send(pkt); err != nil {
			t.Fatalf("send packet %d: %v", i, err)
		}
		far.SetReadDeadline(time.Now().Add(10 * time.Second))
		n, err := far.Read(buf)
		if err != nil {
			t.Fatalf("packet %d never reached the TUN device: %v", i, err)
		}
		if !bytes.Equal(buf[:n], pkt) {
			t.Fatalf("packet %d arrived as %d bytes, sent %d", i, n, len(pkt))
		}
		up += int64(size)
	}
	for i, size := range sizes {
		pkt := trafficPacket(c.ip, 100+i, size+3)
		if _, err := far.Write(pkt); err != nil {
			t.Fatalf("inject packet %d: %v", i, err)
		}
		got, err := c.recv()
		if err != nil {
			t.Fatalf("packet %d never reached the client: %v", i, err)
		}
		if !bytes.Equal(got, pkt) {
			t.Fatalf("client got %d bytes for packet %d, want %d", len(got), i, len(pkt))
		}
		down += int64(len(pkt))
	}
	return up, down
}

var tunSizes = []int{20, 96, 577, 1400, 1300, 61}

// TestTUNTrafficCountsIPBytes: every byte of every IP packet, nothing of the
// framing, in both directions, for every TUN transport on an exit and on a
// relay, and nothing for another client.
func TestTUNTrafficCountsIPBytes(t *testing.T) {
	for _, tr := range tunTransports {
		for _, node := range []string{"exit", "relay"} {
			t.Run(tr.name+"/"+node, func(t *testing.T) {
				reg := trafficRegistry(t)
				var srvCtx *serverContext
				var far *os.File
				if node == "exit" {
					srvCtx, far = exitContext(t, "fx"+tr.name, reg)
				} else {
					srvCtx, far = relayContext(t, reg)
				}

				c := tr.open(t, srvCtx)
				up, down := exchangeTUN(t, c, far, tunSizes)
				waitTraffic(t, reg, trafficClient, up, down)
				waitTraffic(t, reg, quietClient, 0, 0)
				if got := reg.GetStats(trafficClient).TotalConns; got != tr.conns {
					t.Fatalf("total_conns = %d, want %d", got, tr.conns)
				}
			})
		}
	}
}

// proxyTarget accepts one connection, reads exactly upN bytes, answers with
// downN bytes and closes.
func proxyTarget(t *testing.T, upN, downN int) string {
	t.Helper()
	ln, err := net.Listen("tcp", "127.0.0.1:0")
	if err != nil {
		t.Fatalf("listen: %v", err)
	}
	t.Cleanup(func() { ln.Close() })
	go func() {
		c, err := ln.Accept()
		if err != nil {
			return
		}
		defer c.Close()
		if _, err := io.ReadFull(c, make([]byte, upN)); err != nil {
			return
		}
		c.Write(bytes.Repeat([]byte{0xd7}, downN))
	}()
	return ln.Addr().String()
}

// proxyRun is one proxied stream: it sends up, reads down bytes until EOF and
// closes its side, returning when the server-side handler has returned.
type proxyRun func(t *testing.T, srvCtx *serverContext, target string, up []byte, downN int)

func readDown(t *testing.T, r io.Reader, downN int) {
	t.Helper()
	got, err := io.ReadAll(io.LimitReader(r, int64(downN)))
	if err != nil || len(got) != downN {
		t.Fatalf("read %d of %d downlink bytes: %v", len(got), downN, err)
	}
}

func proxyRaw(t *testing.T, srvCtx *serverContext, target string, up []byte, downN int) {
	client, server := tcpPair(t)
	done := make(chan struct{})
	go func() {
		defer close(done)
		handleRawTunnel(server, srvCtx, testLogger(t), registryIdentity(trafficClient))
	}()
	client.Write(targetPacket(target))
	ack := make([]byte, 1)
	if _, err := io.ReadFull(client, ack); err != nil || ack[0] != 0 {
		t.Fatalf("ack %x, err %v", ack, err)
	}
	client.Write(up)
	readDown(t, client, downN)
	client.Close()
	waitHandler(t, done)
}

func proxyMorph(t *testing.T, srvCtx *serverContext, target string, up []byte, downN int) {
	client, server := tlsLoopbackPair(t)
	done := make(chan struct{})
	go func() {
		defer close(done)
		handleMorphConnection(server, srvCtx, testLogger(t))
	}()
	client.SetDeadline(time.Now().Add(15 * time.Second))
	hs := append([]byte("MRPH\x04test"), computeMorphAuthForTest(t, []byte(trafficSecret), clientExporter(t, client))...)
	client.Write(hs)
	ack := make([]byte, 1)
	if _, err := io.ReadFull(client, ack); err != nil || ack[0] != 0 {
		t.Fatalf("early ack %x, err %v", ack, err)
	}
	client.Write(morphFrame(targetPacket(target)))
	status, err := readMorphFrame(client)
	if err != nil || len(status) != 1 || status[0] != 0 {
		t.Fatalf("dial status %x, err %v", status, err)
	}
	for chunk := range slices.Chunk(up, 1000) {
		client.Write(morphFrame(chunk))
	}
	got := 0
	for got < downN {
		data, err := readMorphFrame(client)
		if err != nil {
			t.Fatalf("downlink after %d of %d bytes: %v", got, downN, err)
		}
		got += len(data)
	}
	client.Close()
	waitHandler(t, done)
}

func proxyConfusion(t *testing.T, srvCtx *serverContext, target string, up []byte, downN int) {
	client, server := tcpPair(t)
	done := make(chan struct{})
	go func() {
		defer close(done)
		handleConnection(server, srvCtx, 22)
	}()
	cc, err := strategy.NewConfusedConn(client, strategy.ConfusionDNSoverTLS, []byte(trafficSecret))
	if err != nil {
		t.Fatalf("NewConfusedConn: %v", err)
	}
	cc.Write(targetPacket(target))
	client.SetReadDeadline(time.Now().Add(10 * time.Second))
	ack := make([]byte, 1)
	if _, err := io.ReadFull(cc, ack); err != nil || ack[0] != 0 {
		t.Fatalf("ack %x, err %v", ack, err)
	}
	cc.Write(up)
	readDown(t, cc, downN)
	client.Close()
	waitHandler(t, done)
}

func proxyH2(t *testing.T, srvCtx *serverContext, target string, up []byte, downN int) {
	sc := h2Stego(t, srvCtx, false)
	sc.Write(targetPacket(target))
	ack := make([]byte, 1)
	if _, err := io.ReadFull(sc, ack); err != nil || ack[0] != 0 {
		t.Fatalf("ack %x, err %v", ack, err)
	}
	sc.Write(up)
	readDown(t, sc, downN)
	sc.Close()
	// The H2 proxy counts as it goes and has no end-of-stream step to wait for.
}

func proxyPolling(t *testing.T, srvCtx *serverContext, target string, up []byte, downN int) {
	sess := pollingSession(t, "traffic-polling-proxy")
	// The first body carries the target and the first payload bytes, which the
	// relay writes to the target before anything else.
	first := min(len(up), 300)
	sess.WriteFromClient(append(targetPacket(target), up[:first]...))
	done := make(chan struct{})
	go func() {
		defer close(done)
		runPollingSessionRelay(sess, srvCtx, testLogger(t))
	}()
	down := &pollingReader{sess: sess}
	status := make([]byte, 1)
	if _, err := io.ReadFull(down, status); err != nil || status[0] != 0 {
		t.Fatalf("status %x, err %v", status, err)
	}
	sess.WriteFromClient(up[first:])
	readDown(t, down, downN)
	sess.Close()
	waitHandler(t, done)
}

// TestProxyTrafficCountsPayloadBytes: the client's payload, not the framing or
// the target address, for every proxy transport.
func TestProxyTrafficCountsPayloadBytes(t *testing.T) {
	for _, tc := range []struct {
		name string
		run  proxyRun
	}{
		{"raw", proxyRaw},
		{"morph", proxyMorph},
		{"confusion", proxyConfusion},
		{"h2", proxyH2},
		{"polling", proxyPolling},
	} {
		t.Run(tc.name, func(t *testing.T) {
			const upN, downN = 70001, 123457
			reg := trafficRegistry(t)
			srvCtx := newTestServerContext(t)
			srvCtx.registry = reg
			up := bytes.Repeat([]byte{0x3c}, upN)

			tc.run(t, srvCtx, proxyTarget(t, upN, downN), up, downN)
			waitTraffic(t, reg, trafficClient, upN, downN)
			waitTraffic(t, reg, quietClient, 0, 0)
		})
	}
}

// TestConnectionDoesNotMoveByteCounters is the 1.11.8 bug at the registry: a
// connection is not a byte.
func TestConnectionDoesNotMoveByteCounters(t *testing.T) {
	reg := trafficRegistry(t)
	for range 3 {
		a, b := net.Pipe()
		if err := reg.AddConnection(trafficClient, a); err != nil {
			t.Fatalf("AddConnection: %v", err)
		}
		reg.RemoveConnection(trafficClient, a)
		a.Close()
		b.Close()
	}
	reg.AddBytes(trafficClient, 10, 20)
	s := reg.GetStats(trafficClient)
	if s.TotalConns != 3 || s.BytesUp != 10 || s.BytesDown != 20 {
		t.Fatalf("conns/up/down = %d/%d/%d, want 3/10/20", s.TotalConns, s.BytesUp, s.BytesDown)
	}
}

// TestSharedIdentityHasNoTraffic: an identity every global-secret client
// carries must not be accounted to a registry client, even one whose id
// happens to spell the same.
func TestSharedIdentityHasNoTraffic(t *testing.T) {
	srvCtx := newTestServerContext(t)
	srvCtx.registry = trafficRegistry(t)
	if srvCtx.trafficOf(registryIdentity(trafficClient)) == nil {
		t.Fatal("registry identity has no counters")
	}
	if srvCtx.trafficOf(sharedIdentity(trafficClient)) != nil {
		t.Fatal("shared identity was accounted to a registry client")
	}
	if srvCtx.trafficOf(registryIdentity("polling:"+trafficClient)) != nil {
		t.Fatal("a transport-prefixed id named a registry client")
	}
}

// TestTUNFrameMeterMatchesExit: the bridge meter counts what an exit
// terminating the stream would - packets only, split over any writes, no
// keepalives, no probe frames, and a length the exit skips is a bare header.
func TestTUNFrameMeterMatchesExit(t *testing.T) {
	probe := append([]byte{0x10, 'M', 'T', 0x01}, make([]byte, 60)...)
	if !tun.IsProbeFrame(probe) {
		t.Fatal("test probe frame is not one")
	}
	var stream []byte
	want := 0
	for _, size := range []int{20, 1400, 0, 33, 65535, 0, 0, 512} {
		stream = append(stream, lenFrame(make([]byte, size))...)
		want += size
	}
	stream = append(stream, lenFrame(probe)...)
	stream = binary.BigEndian.AppendUint32(stream, 7)     // too short: the exit skips the header
	stream = binary.BigEndian.AppendUint32(stream, 70000) // too long: same
	stream = append(stream, lenFrame(make([]byte, 99))...)
	want += 99

	for _, chunk := range []int{1, 3, 4, 5, 7, 1000, len(stream)} {
		t.Run(fmt.Sprint(chunk), func(t *testing.T) {
			var got int
			var sink bytes.Buffer
			m := newTUNFrameMeter(&sink, func(n int) { got += n })
			for part := range slices.Chunk(stream, chunk) {
				if _, err := m.Write(part); err != nil {
					t.Fatal(err)
				}
			}
			if got != want || !bytes.Equal(sink.Bytes(), stream) {
				t.Fatalf("counted %d, want %d (passed %d of %d bytes)", got, want, sink.Len(), len(stream))
			}
		})
	}
}

// TestSinksSkipProbeFrames: an auto-MTU probe frame is not the client's
// traffic on any path, whether the transport forwards it or answers it.
func TestSinksSkipProbeFrames(t *testing.T) {
	probe := append([]byte{0x10, 'M', 'T', 0x01}, make([]byte, 60)...)
	var n int
	countPacket(func(k int) { n += k }, probe)
	countPacket(func(k int) { n += k }, trafficPacket(net.IPv4(10, 8, 0, 2), 1, 40))
	if n != 40 {
		t.Fatalf("counted %d, want only the 40-byte IP packet", n)
	}
}

// TestPollingTUNShedFramesNotCounted: a packet the polling downlink sheds
// because it is full did not reach the client and is not counted, whether the
// dispatcher (exit) or the relay pump offered it.
func TestPollingTUNShedFramesNotCounted(t *testing.T) {
	for _, node := range []string{"exit", "relay"} {
		t.Run(node, func(t *testing.T) {
			reg := trafficRegistry(t)
			var srvCtx *serverContext
			var far *os.File
			if node == "exit" {
				srvCtx, far = exitContext(t, "fxshed", reg)
			} else {
				srvCtx, far = relayContext(t, reg)
			}
			sess := pollingSession(t, "traffic-polling-shed-"+node)
			sess.WriteFromClient(append([]byte{0x02}, v3Handshake()...))
			go runPollingSessionRelay(sess, srvCtx, testLogger(t))
			down := &pollingReader{sess: sess}
			resp := make([]byte, 9)
			if _, err := io.ReadFull(down, resp); err != nil {
				t.Fatal(err)
			}
			clientIP := net.IP(resp[5:9])

			// Nobody polls: the downlink fills and then sheds.
			const size = 1400
			sent := (pollingMaxToClientBuffered / (size + 4)) + 20
			for i := range sent {
				if _, err := far.Write(trafficPacket(clientIP, i, size)); err != nil {
					t.Fatal(err)
				}
			}
			deadline := time.Now().Add(10 * time.Second)
			for sess.toClientDropped.Load() < 10 && time.Now().Before(deadline) {
				time.Sleep(10 * time.Millisecond)
			}
			if sess.toClientDropped.Load() == 0 {
				t.Fatal("the downlink never shed a frame; the test proves nothing")
			}
			time.Sleep(300 * time.Millisecond)
			queued := int64(downlinkLen(sess)/(size+4)) * size
			if got := reg.GetStats(trafficClient).BytesDown; got != queued {
				t.Fatalf("bytes_down = %d, but only %d bytes were queued for the client (%d frames shed)",
					got, queued, sess.toClientDropped.Load())
			}
		})
	}
}

// TestRelayPumpDropsNotCounted: a frame the downstream transport refuses as
// dropped is neither counted nor treated as the end of the tunnel.
func TestRelayPumpDropsNotCounted(t *testing.T) {
	up, exit := net.Pipe()
	defer exit.Close()
	tr := newClientTraffic()
	sink := &relayTUNSink{up: up, logger: testLogger(t), traffic: tr, done: make(chan struct{})}
	delivered := 0
	go sink.pump(func(pkt []byte) error {
		delivered++
		if delivered%2 == 0 {
			return errFrameShed
		}
		return nil
	})
	for i := range 4 {
		exit.Write(lenFrame(trafficPacket(net.IPv4(10, 8, 0, 2), i, 100)))
	}
	exit.Close()
	<-sink.Done()
	if delivered != 4 {
		t.Fatalf("pump stopped after %d frames", delivered)
	}
	if got := tr.bytesDown.Load(); got != 200 {
		t.Fatalf("bytes_down = %d, want the 200 bytes delivered", got)
	}
}

// TestRelayCountedCountsWhileStreaming: a long proxied stream is counted as it
// goes, not when it ends - a download still running at SIGTERM used to be
// lost whole.
func TestRelayCountedCountsWhileStreaming(t *testing.T) {
	src, srcFar := tcpPair(t)
	dst, dstFar := tcpPair(t)
	var counted atomic.Int64
	done := make(chan struct{})
	go func() {
		defer close(done)
		relayCounted(dst, src, func(n int) { counted.Add(int64(n)) })
	}()
	go io.Copy(io.Discard, dstFar)

	chunk := make([]byte, relayCountChunk)
	for range 3 {
		if _, err := srcFar.Write(chunk); err != nil {
			t.Fatal(err)
		}
	}
	deadline := time.Now().Add(5 * time.Second)
	for counted.Load() < 2*relayCountChunk && time.Now().Before(deadline) {
		time.Sleep(10 * time.Millisecond)
	}
	if got := counted.Load(); got < 2*relayCountChunk {
		t.Fatalf("counted %d bytes of a stream still open after %d", got, 3*relayCountChunk)
	}
	srcFar.Write([]byte("tail"))
	srcFar.Close()
	<-done
	if got := counted.Load(); got != 3*relayCountChunk+4 {
		t.Fatalf("counted %d, want %d", got, 3*relayCountChunk+4)
	}
}

// writeCertFiles writes a self-signed certificate and key as PEM files.
func writeCertFiles(t *testing.T) (certFile, keyFile string) {
	t.Helper()
	cert := selfSignedCertForTest(t)
	dir := t.TempDir()
	certFile, keyFile = filepath.Join(dir, "srv.crt"), filepath.Join(dir, "srv.key")
	keyDER, err := x509.MarshalPKCS8PrivateKey(cert.PrivateKey)
	if err != nil {
		t.Fatal(err)
	}
	os.WriteFile(certFile, pem.EncodeToMemory(&pem.Block{Type: "CERTIFICATE", Bytes: cert.Certificate[0]}), 0o600)
	os.WriteFile(keyFile, pem.EncodeToMemory(&pem.Block{Type: "PRIVATE KEY", Bytes: keyDER}), 0o600)
	return certFile, keyFile
}

// TestQUICProxyTrafficCounted runs the QUIC listener the server starts and
// the Salamander QUIC client, authenticated with a registry secret, and
// proxies a stream through them.
func TestQUICProxyTrafficCounted(t *testing.T) {
	const upN, downN = 40001, 60002
	udp, err := net.ListenPacket("udp", "127.0.0.1:0")
	if err != nil {
		t.Fatal(err)
	}
	addr := udp.LocalAddr().String()
	udp.Close()

	reg := trafficRegistry(t)
	srvCtx := newTestServerContext(t)
	srvCtx.registry = reg
	srvCtx.cfg.QUICEnabled = true
	srvCtx.cfg.QUICListenAddr = addr
	srvCtx.cfg.CertFile, srvCtx.cfg.KeyFile = writeCertFiles(t)
	qs := startQUICServer(srvCtx.cfg, srvCtx)
	if qs == nil {
		t.Fatal("QUIC server did not start")
	}
	t.Cleanup(func() { qs.Stop() })

	mgr := strategy.NewManager()
	if err := mgr.SetEndpoints([]endpoint.Endpoint{{Name: "quic", V4: addr}}, endpoint.V4Only); err != nil {
		t.Fatal(err)
	}
	_, port, _ := net.SplitHostPort(addr)
	p, _ := strconv.Atoi(port)
	ctx, cancel := context.WithTimeout(t.Context(), 15*time.Second)
	defer cancel()
	conn, err := strategy.NewQUICSalamanderStrategy(mgr, []byte(trafficSecret), p).Connect(ctx, "unused:0")
	if err != nil {
		t.Fatalf("QUIC connect: %v", err)
	}
	defer conn.Close()

	conn.Write(targetPacket(proxyTarget(t, upN, downN)))
	status := make([]byte, 1)
	if _, err := io.ReadFull(conn, status); err != nil || status[0] != 0 {
		t.Fatalf("status %x, err %v", status, err)
	}
	conn.Write(bytes.Repeat([]byte{2}, upN))
	readDown(t, conn, downN)
	waitTraffic(t, reg, trafficClient, upN, downN)
}

// TestRelayCountedBufferedCountsEachWrite: where no splice is possible (a QUIC
// stream, TLS without kTLS) every write is counted at once, so a small stream
// that stays open is not invisible until it closes.
func TestRelayCountedBufferedCountsEachWrite(t *testing.T) {
	src, srcFar := net.Pipe()
	dst, dstFar := tcpPair(t)
	defer srcFar.Close()
	var counted atomic.Int64
	go relayCounted(dst, src, func(n int) { counted.Add(int64(n)) })
	go io.Copy(io.Discard, dstFar)

	srcFar.Write(make([]byte, 100))
	deadline := time.Now().Add(5 * time.Second)
	for counted.Load() != 100 && time.Now().Before(deadline) {
		time.Sleep(5 * time.Millisecond)
	}
	if got := counted.Load(); got != 100 {
		t.Fatalf("counted %d of 100 bytes written to a stream still open", got)
	}
}
