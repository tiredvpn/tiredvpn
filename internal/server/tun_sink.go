package server

import (
	"context"
	"encoding/binary"
	"errors"
	"fmt"
	"io"
	"net"
	"sync"
	"time"

	"github.com/tiredvpn/tiredvpn/internal/log"
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
}

// dualAddrs returns the exit-assigned IPv6 tunnel addresses for the downstream
// handshake response, or nil when the exit did not negotiate dual-stack.
func (s *relayTUNSink) dualAddrs() *dualStackAddrs {
	if len(s.serverIP6) == 0 || len(s.clientIP6) == 0 {
		return nil
	}
	return &dualStackAddrs{ServerIP6: s.serverIP6, ClientIP6: s.clientIP6}
}

// relayTUNIdleTimeout bounds a silent upstream leg. Clients keepalive every 30s
// and those frames are forwarded, so a leg with nothing on it for this long is
// dead rather than idle.
const relayTUNIdleTimeout = 3 * time.Minute

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
	return err
}

func (s *relayTUNSink) Done() <-chan struct{} { return s.done }

// UpdateActivity is a no-op: the upstream leg's liveness is the read deadline in
// pump, not a separate idle timer.
func (s *relayTUNSink) UpdateActivity() {}

func (s *relayTUNSink) Close() {
	s.once.Do(func() {
		s.up.Close()
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
		s.up.SetReadDeadline(time.Now().Add(relayTUNIdleTimeout))
		if _, err := io.ReadFull(s.up, header); err != nil {
			if !errors.Is(err, io.EOF) {
				s.logger.Debug("Relay TUN: upstream read ended: %v", err)
			}
			return
		}
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

	logger.Info("Relay TUN bridge established (origin=%s, upstream-assigned=%s)", origin, clientIP)
	return sink, serverIP, clientIP, nil
}
