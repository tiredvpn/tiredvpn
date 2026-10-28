package strategy

import (
	"context"
	"errors"
	"net"
	"sync/atomic"
	"syscall"
	"testing"
	"time"

	"github.com/tiredvpn/tiredvpn/internal/protect"
)

// slowHelloListener answers every connection with one byte after delay: a
// server whose handshake answer takes that long, as REALITY's does while the
// server reaches its cover domain.
func slowHelloListener(t *testing.T, delay time.Duration) string {
	t.Helper()
	ln, err := net.Listen("tcp", "127.0.0.1:0")
	if err != nil {
		t.Fatalf("listen: %v", err)
	}
	t.Cleanup(func() { ln.Close() })
	go func() {
		for {
			conn, err := ln.Accept()
			if err != nil {
				return
			}
			go func() {
				defer conn.Close()
				time.Sleep(delay)
				_, _ = conn.Write([]byte{'x'})
				_, _ = conn.Read(make([]byte, 1))
			}()
		}
	}()
	return ln.Addr().String()
}

// protectedGreeter is greetingStrategy dialling through protect.ProtectDialer,
// the way REALITY, Seqovl, Stego and Polling do, and declaring so. stall makes
// its dial hang instead: a SYN nobody answers. swallow makes it
// connect and then hear nothing: a handshake a censor drops.
type protectedGreeter struct {
	id       string
	priority int
	stall    bool
	swallow  bool
	// hello writes a byte as soon as the TCP connect is up, as a real
	// handshake's first flight does, so the server's TCP acknowledges it.
	// A swallowed attempt sends nothing: the censor dropped it.
	hello bool
	dials atomic.Int64
}

func (s *protectedGreeter) Name() string                        { return s.id }
func (s *protectedGreeter) ID() string                          { return s.id }
func (s *protectedGreeter) Priority() int                       { return s.priority }
func (s *protectedGreeter) RequiresServer() bool                { return true }
func (s *protectedGreeter) Description() string                 { return "greeting over a protected dial" }
func (s *protectedGreeter) Probe(context.Context, string) error { return nil }
func (*protectedGreeter) reportsTCPConnect()                    {}

func (s *protectedGreeter) Connect(ctx context.Context, target string) (net.Conn, error) {
	s.dials.Add(1)
	dialer := &protect.ProtectDialer{}
	if s.stall {
		// The dial goes out and its SYN is never answered.
		dialer.Dialer = &net.Dialer{Control: func(string, string, syscall.RawConn) error {
			<-ctx.Done()
			return ctx.Err()
		}}
	}
	conn, err := dialer.DialContext(ctx, "tcp", target)
	if err != nil {
		return nil, err
	}
	if s.swallow {
		<-ctx.Done()
		conn.Close()
		return nil, ctx.Err()
	}
	if s.hello {
		if _, err := conn.Write([]byte{0x16}); err != nil {
			conn.Close()
			return nil, err
		}
	}
	stop := context.AfterFunc(ctx, func() { conn.Close() })
	defer stop()
	if _, err := conn.Read(make([]byte, 1)); err != nil {
		conn.Close()
		return nil, err
	}
	return conn, nil
}

// TestSlowHandshakeOnTheFastPathIsNotCut is N6 of the second acceptance of PR
// #126. The fast path got half of what was left of a short cycle, all of it,
// handshake included; a REALITY handshake needing 7-9 s (the server reaching its
// cover domain) was cut at 6.6-7.5 s and the tunnel came up on HTTP Polling.
// Scaled: a 1 s cycle, a 2 s connect timeout, a handshake answered after 0.7 s.
func TestSlowHandshakeOnTheFastPathIsNotCut(t *testing.T) {
	addr := slowHelloListener(t, 700*time.Millisecond)
	m := newSilenceManager(t, 2*time.Second, addr)
	reality := &protectedGreeter{id: "reality", priority: 5}
	m.Register(reality)
	m.Register(&greetingStrategy{id: "polling", priority: 6})
	markConnected(m, reality)

	ctx, cancel := context.WithTimeout(context.Background(), time.Second)
	defer cancel()
	conn, s, err := m.Connect(ctx, "")
	if err != nil {
		t.Fatalf("connect: %v", err)
	}
	conn.Close()
	if s.ID() != "reality" {
		t.Fatalf("connected via %s: the fast path's handshake was cut while under way", s.ID())
	}
}

// TestSlowHandshakeInTheScanIsNotCut: the same in the scan, where every attempt
// but the last got half as well.
func TestSlowHandshakeInTheScanIsNotCut(t *testing.T) {
	addr := slowHelloListener(t, 700*time.Millisecond)
	m := newSilenceManager(t, 2*time.Second, addr)
	m.Register(&protectedGreeter{id: "reality", priority: 5})
	m.Register(&greetingStrategy{id: "polling", priority: 6})

	ctx, cancel := context.WithTimeout(context.Background(), time.Second)
	defer cancel()
	conn, s, err := m.Connect(ctx, "")
	if err != nil {
		t.Fatalf("connect: %v", err)
	}
	conn.Close()
	if s.ID() != "reality" {
		t.Fatalf("connected via %s: the scan cut a handshake under way", s.ID())
	}
}

// TestAStalledConnectStillLeavesRoomForTheNext: what stays cut at half is the
// wait for a TCP connect. A transport that never gets one leaves the rest of
// the cycle to the next, and its silence is counted as before.
func TestAStalledConnectStillLeavesRoomForTheNext(t *testing.T) {
	addr := slowHelloListener(t, 0)
	m := newSilenceManager(t, 2*time.Second, addr)
	reality := &protectedGreeter{id: "reality", priority: 5, stall: true}
	m.Register(reality)
	m.Register(&greetingStrategy{id: "polling", priority: 6})
	markConnected(m, reality)

	ctx, cancel := context.WithTimeout(context.Background(), time.Second)
	defer cancel()
	conn, s, err := m.Connect(ctx, "")
	if err != nil {
		t.Fatalf("a stalled connect took the whole cycle: %v", err)
	}
	conn.Close()
	if s.ID() != "polling" {
		t.Fatalf("connected via %s, want polling", s.ID())
	}
	if skip := m.swallowSkip(addr); len(skip) != 0 {
		t.Fatalf("a connect that never came up was booked as a swallowed handshake (%v)", skip)
	}
}

// TestAStalledConnectIsStillSilence: cut at the dial limit with no TCP connect
// is silence, as a dial timeout was before. With nothing else to try, that is
// the address's silence verdict.
func TestAStalledConnectIsStillSilence(t *testing.T) {
	addr := slowHelloListener(t, 0)
	m := newSilenceManager(t, 2*time.Second, addr)
	reality := &protectedGreeter{id: "reality", priority: 5, stall: true}
	m.Register(reality)
	markConnected(m, reality)

	ctx, cancel := context.WithTimeout(context.Background(), time.Second)
	defer cancel()
	_, _, err := m.Connect(ctx, "")
	if !errors.Is(err, errAddrSilent) {
		t.Fatalf("a stalled connect, the only transport, gave %v, want the silence verdict", err)
	}
}

// TestSwallowedHandshakeSitsOutTheNextCycle is the price of not cutting a
// handshake under way: one that is swallowed runs out the cycle. It must not
// park the server for it, and the next cycle starts with the other transports
// instead of spending itself the same way.
func TestSwallowedHandshakeSitsOutTheNextCycle(t *testing.T) {
	addr := slowHelloListener(t, 0)
	m := newSilenceManager(t, 2*time.Second, addr)
	reality := &protectedGreeter{id: "reality", priority: 5, swallow: true}
	m.Register(reality)
	m.Register(&greetingStrategy{id: "polling", priority: 6})
	markConnected(m, reality)

	ctx, cancel := context.WithTimeout(context.Background(), time.Second)
	_, _, err := m.Connect(ctx, "")
	cancel()
	if err == nil {
		t.Fatal("a swallowed handshake connected")
	}
	if errors.Is(err, errAddrSilent) {
		t.Fatalf("one swallowed handshake was read as the address's silence: %v", err)
	}
	if st := endpointState(t, m, addr); st.CooldownUntil.After(time.Now()) {
		t.Fatal("the server was parked for one swallowed handshake")
	}

	before := reality.dials.Load()
	ctx, cancel = context.WithTimeout(context.Background(), time.Second)
	defer cancel()
	conn, s, err := m.Connect(ctx, "")
	if n := reality.dials.Load() - before; n != 0 {
		t.Fatalf("the next cycle dialled the swallowed transport again (%d dials) before the others", n)
	}
	if err != nil {
		t.Fatalf("the cycle after a swallowed handshake: %v", err)
	}
	conn.Close()
	if s.ID() != "polling" {
		t.Fatalf("connected via %s, want polling", s.ID())
	}
}

// TestTheDialsThatReportAConnect pins the strategies whose handshake the scan
// lets run past the dial limit: each of them must dial the server only through
// protect.ProtectDialer.
func TestTheDialsThatReportAConnect(t *testing.T) {
	for _, s := range []Strategy{&REALITYStrategy{}, &SeqovlStrategy{}, &HTTP2StegoStrategy{}, &HTTPPollingStrategy{}} {
		if _, ok := s.(connectReporter); !ok {
			t.Errorf("%T no longer reports its connect", s)
		}
	}
	for _, s := range []Strategy{&WebSocketPaddedStrategy{}, &GenevaStrategy{}, &QUICStrategy{}, &greetingStrategy{}} {
		if _, ok := s.(connectReporter); ok {
			t.Errorf("%T reports a connect it cannot see", s)
		}
	}
}
