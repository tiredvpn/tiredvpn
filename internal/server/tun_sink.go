package server

import (
	"context"
	"encoding/binary"
	"errors"
	"fmt"
	"io"
	"net"
	"sync"
	"sync/atomic"
	"time"

	"github.com/tiredvpn/tiredvpn/internal/log"
	"github.com/tiredvpn/tiredvpn/internal/strategy"
	"github.com/tiredvpn/tiredvpn/internal/tun"
)

// tunPacketSink is where the IP packets a downstream TUN client sends go.
//
// On an exit that is the shared TUN device. On a relay (-upstream set) it is a
// TUN tunnel to the upstream exit: the relay must forward the client's packets
// instead of terminating them, otherwise the client leaves the internet from the
// relay rather than from the exit it asked for. Only the native TUN path used to
// do that, so a client that fell back to morph, confusion, H2 stego or HTTP
// polling silently ended up with the relay's own exit and address pool.
type tunPacketSink interface {
	// WritePacket forwards one IP packet coming up from the client.
	WritePacket(pkt []byte) error
	// Done is closed when the sink dies, so the transport's read loop can stop.
	Done() <-chan struct{}
	// UpdateActivity refreshes the idle timer, where the sink keeps one.
	UpdateActivity()
	// Close releases the sink. Safe to call more than once.
	Close()
}

// localTUNSink terminates the client on this node's shared TUN device.
type localTUNSink struct {
	shared   *SharedTUN
	writer   *ClientWriter
	clientIP net.IP
	once     sync.Once
}

func newLocalTUNSink(shared *SharedTUN, writer *ClientWriter, clientIP net.IP) *localTUNSink {
	return &localTUNSink{shared: shared, writer: writer, clientIP: clientIP}
}

func (s *localTUNSink) WritePacket(pkt []byte) error {
	_, err := s.shared.TUNDevice().Write(pkt)
	return err
}

func (s *localTUNSink) Done() <-chan struct{} { return s.writer.Done() }
func (s *localTUNSink) UpdateActivity()       { s.writer.UpdateActivity() }

func (s *localTUNSink) Close() {
	s.once.Do(func() {
		s.shared.UnregisterClient(s.clientIP, s.writer)
	})
}

// relayTUNSink forwards the client's packets to the upstream exit over the
// [len:4][pkt:N] stream a native TUN client would speak, and pumps the exit's
// packets back down through the transport's own framing.
type relayTUNSink struct {
	up     net.Conn
	logger *log.Logger

	// serverIP6/clientIP6 are the IPv6 tunnel addresses the exit assigned in
	// its handshake response, when it negotiated dual-stack (nil otherwise).
	// The relay answers its downstream client with these so the v6 addresses,
	// like the v4 ones, always come from the exit, never from the relay's pool.
	serverIP6 net.IP
	clientIP6 net.IP

	writeMu sync.Mutex
	done    chan struct{}
	once    sync.Once

	// lastUp and lastDown are the UnixNano of the last frame the relay sent
	// to the exit and read from it, keepalives and their echoes included;
	// lastActivity that of the downstream client's last sign of life
	// (UpdateActivity). quietFor is the silence the keepalive timer waits
	// for, drawn anew after each keepalive (relayKeepaliveAfter).
	lastUp       atomic.Int64
	lastDown     atomic.Int64
	lastActivity atomic.Int64
	quietFor     atomic.Int64
	keepalive    atomic.Pointer[time.Timer]
}

// dualAddrs returns the exit-assigned IPv6 tunnel addresses for the downstream
// handshake response, or nil when the exit did not negotiate dual-stack.
func (s *relayTUNSink) dualAddrs() *dualStackAddrs {
	if len(s.serverIP6) == 0 || len(s.clientIP6) == 0 {
		return nil
	}
	return &dualStackAddrs{ServerIP6: s.serverIP6, ClientIP6: s.clientIP6}
}

// relayTUNIdleTimeout bounds how long the relay waits for anything from the
// exit. The exit echoes the relay's keepalives (startKeepalive), so a leg
// with nothing on it for this long is dead rather than idle. Atomic so tests
// can shorten it.
var relayTUNIdleTimeoutNs = func() *atomic.Int64 {
	var v atomic.Int64
	v.Store(int64(3 * time.Minute))
	return &v
}()

func relayTUNIdleTimeout() time.Duration { return time.Duration(relayTUNIdleTimeoutNs.Load()) }

func (s *relayTUNSink) WritePacket(pkt []byte) error {
	if len(pkt) > 65535 {
		return fmt.Errorf("packet too large for relay frame: %d bytes", len(pkt))
	}
	frame := make([]byte, 4+len(pkt))
	binary.BigEndian.PutUint32(frame[:4], uint32(len(pkt)))
	copy(frame[4:], pkt)

	s.writeMu.Lock()
	defer s.writeMu.Unlock()
	s.up.SetWriteDeadline(time.Now().Add(30 * time.Second))
	_, err := s.up.Write(frame)
	s.lastUp.Store(time.Now().UnixNano())
	return err
}

func (s *relayTUNSink) Done() <-chan struct{} { return s.done }

// relayKeepaliveAfter draws how long either direction of the upstream leg
// may stay silent before the relay sends a keepalive up. The draw lives in
// relayKeepaliveDraw, atomic so tests can scale it.
//
// The exit reads the leg under h2FrameReadTimeout (60 s): a relay-to-exit
// gap longer than that closes it. The relay reads it under
// relayTUNIdleTimeout (3 min), fed by the exit's echo of the keepalive. The
// round-5 draw (60-150 s) started at the exit's deadline, and the keepalive
// rode the downstream client's 10 s keepalive grid on top of it: every idle
// leg through a relay died after exactly a minute (P1-A of the round-6
// review), and the gaps the leg showed were whole multiples of 10 s (P2-A).
//
// Now a timer of its own sends the keepalive, so nothing ties it to the
// client's grid, after a quiet period drawn as a hump between 20 and 45 s
// (HumpDelay: 20 s plus a gamma of shape 3, mean 30 s, redrawn above 45 s).
// The ceiling leaves 15 s of the exit's 60 s for the network. There is no
// measured reference distribution for an idle server-to-server TLS leg
// (verification rule 3); the shape is chosen to have no grid, no spike, and
// no flat plateau, and the hard floor at 20 s is the one regularity left.
var relayKeepaliveDraw atomic.Pointer[func() time.Duration]

func init() {
	draw := func() time.Duration { return strategy.HumpDelay(20*time.Second, 30*time.Second, 45*time.Second) }
	relayKeepaliveDraw.Store(&draw)
}

func relayKeepaliveAfter() time.Duration { return (*relayKeepaliveDraw.Load())() }

// relayClientActiveWindow is how long after its downstream client's last
// sign of life the relay keeps its upstream leg alive with keepalives. A
// downstream client sends something at least every 10 s (its keepalive, or a
// Polling poll); one silent for this long is gone, and its leg may go too.
const relayClientActiveWindow = time.Minute

// UpdateActivity records that the downstream client is alive, which keeps
// the keepalive timer sending (startKeepalive).
func (s *relayTUNSink) UpdateActivity() {
	s.lastActivity.Store(time.Now().UnixNano())
}

// startKeepalive arms the timer that keeps the upstream leg alive while the
// downstream client is: when either direction of the leg has been silent for
// the drawn quiet period, a keepalive goes up. The exit's read deadline sees
// the keepalive, and the relay's own sees the exit's echo - an upload-only
// leg died of the second, a download-only one of the first, while one
// keepalive per silence covered neither (P1-A of the round-6 review).
func (s *relayTUNSink) startKeepalive() {
	now := time.Now().UnixNano()
	s.lastUp.CompareAndSwap(0, now)
	s.lastDown.CompareAndSwap(0, now)
	s.lastActivity.CompareAndSwap(0, now)
	quiet := relayKeepaliveAfter()
	s.quietFor.Store(int64(quiet))
	t := time.AfterFunc(time.Hour, s.keepaliveTick)
	s.keepalive.Store(t)
	t.Reset(quiet)
}

func (s *relayTUNSink) keepaliveTick() {
	select {
	case <-s.done:
		return
	default:
	}
	now := time.Now()
	quiet := time.Duration(s.quietFor.Load())
	oldest := time.Unix(0, min(s.lastUp.Load(), s.lastDown.Load()))
	active := now.Sub(time.Unix(0, s.lastActivity.Load())) < relayClientActiveWindow
	if active && now.Sub(oldest) >= quiet {
		s.writeMu.Lock()
		s.up.SetWriteDeadline(now.Add(30 * time.Second))
		_, err := s.up.Write([]byte{0, 0, 0, 0})
		s.writeMu.Unlock()
		if err != nil {
			s.logger.Debug("Relay TUN: keepalive up failed: %v", err)
		}
		s.lastUp.Store(now.UnixNano())
		quiet = relayKeepaliveAfter()
		s.quietFor.Store(int64(quiet))
		oldest = time.Unix(0, min(s.lastUp.Load(), s.lastDown.Load()))
	}
	next := oldest.Add(quiet).Sub(now)
	if next < 100*time.Millisecond {
		next = quiet // the echo has not come back yet, or the client is gone
	}
	if t := s.keepalive.Load(); t != nil {
		t.Reset(next)
	}
}

func (s *relayTUNSink) Close() {
	s.once.Do(func() {
		if t := s.keepalive.Load(); t != nil {
			t.Stop()
		}
		// Closing writes too (HTTP/2 stego sends GOAWAY), so it takes the
		// write lock like WritePacket and the keepalive; a write stuck on a
		// dead leg is cut first.
		_ = s.up.SetWriteDeadline(time.Now())
		s.writeMu.Lock()
		s.up.Close()
		s.writeMu.Unlock()
		close(s.done)
	})
}

// pump reads [len:4][pkt:N] frames from the upstream exit and hands each packet
// to deliver, which re-frames it in the downstream transport's own format.
// Zero-length frames are the upstream's keepalive echo and are dropped: the
// downstream transport answers its client's keepalives itself.
func (s *relayTUNSink) pump(deliver func(pkt []byte) error) {
	defer s.Close()

	header := make([]byte, 4)
	for {
		s.up.SetReadDeadline(time.Now().Add(relayTUNIdleTimeout()))
		if _, err := io.ReadFull(s.up, header); err != nil {
			if !errors.Is(err, io.EOF) {
				s.logger.Debug("Relay TUN: upstream read ended: %v", err)
			}
			return
		}
		s.lastDown.Store(time.Now().UnixNano())
		n := binary.BigEndian.Uint32(header)
		if n == 0 {
			continue
		}
		if n > 65535 {
			// The stream is desynced; a length above the IP ceiling can never
			// resync by reading more, so drop the leg instead of buffering.
			s.logger.Warn("Relay TUN: invalid upstream frame length %d, closing", n)
			return
		}
		pkt := make([]byte, n)
		if _, err := io.ReadFull(s.up, pkt); err != nil {
			s.logger.Debug("Relay TUN: upstream payload read ended: %v", err)
			return
		}
		if err := deliver(pkt); err != nil {
			s.logger.Debug("Relay TUN: downstream delivery failed: %v", err)
			return
		}
	}
}

// dialRelayTUN opens a TUN tunnel to the upstream exit on behalf of a downstream
// client and starts pumping the exit's packets back down through deliver.
//
// handshake is the client's [localIP:4][mtu:2][version:1] payload, forwarded
// as-is so the exit sees the client's own request; origin identifies the client
// so the exit can tell two clients on one secret apart. Returns the sink plus
// the server/client IPs the exit assigned - the caller answers its client with
// those, so the address always comes from the exit, never from the relay's pool.
// When the exit negotiated dual-stack, its IPv6 tunnel addresses ride on the
// sink (see relayTUNSink.dualAddrs).
func dialRelayTUN(srvCtx *serverContext, logger *log.Logger, handshake []byte, origin string,
	deliver func(pkt []byte) error) (*relayTUNSink, net.IP, net.IP, error) {

	handshake, forwarded := splitTUNOrigin(handshake)
	if forwarded != "" {
		origin = forwarded
	}

	dialCtx, cancel := context.WithTimeout(context.Background(), 15*time.Second)
	upConn, resp, err := srvCtx.upstreamDialer.DialTUN(dialCtx, handshake, origin)
	cancel()
	if err != nil {
		return nil, nil, nil, err
	}
	if len(resp) < 9 {
		upConn.Close()
		return nil, nil, nil, fmt.Errorf("short upstream handshake response: %d bytes", len(resp))
	}

	sink := &relayTUNSink{up: upConn, logger: logger, done: make(chan struct{})}
	serverIP := append(net.IP(nil), resp[1:5]...)
	clientIP := append(net.IP(nil), resp[5:9]...)

	// Dual-stack: when the exit's response carries the v6 address block, carry
	// the addresses on the sink so the transport can forward them to its
	// downstream client. An exit that did not negotiate dual-stack leaves them
	// nil and the downstream response degrades to v4-only naturally.
	if caps, ok := tun.ParseTUNHandshakeCapabilities(resp); ok && caps.DualStackEnabled {
		sink.serverIP6 = caps.ServerIP6
		sink.clientIP6 = caps.ClientIP6
		logger.Info("Relay TUN: upstream assigned dual-stack (server6=%s, client6=%s)",
			caps.ServerIP6, caps.ClientIP6)
	}

	go sink.pump(deliver)
	sink.startKeepalive()

	logger.Info("Relay TUN bridge established (origin=%s, upstream-assigned=%s)", origin, clientIP)
	return sink, serverIP, clientIP, nil
}
