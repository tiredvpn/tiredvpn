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

	writeMu sync.Mutex
	done    chan struct{}
	once    sync.Once
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

	go sink.pump(deliver)

	logger.Info("Relay TUN bridge established (origin=%s, upstream-assigned=%s)", origin, clientIP)
	return sink, serverIP, clientIP, nil
}
