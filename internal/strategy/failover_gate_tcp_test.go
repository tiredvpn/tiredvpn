package strategy

import (
	"context"
	"net"
	"sync"
	"testing"
	"time"
)

// TestGateDialsOnlyTheTransportPorts is N5 of the PR #126 acceptance run and P2
// of its review. The pre-flight gate decides on TCP to the pool and nothing
// else, yet each run also dialled the server host's :443 and :80 (the "ICMP"
// leg) and sent a UDP datagram - extra ports and a second protocol after every
// silent disconnect, visible in the WAN-down capture. A client with no QUIC
// strategy has no use for the UDP verdict at all.
func TestGateDialsOnlyTheTransportPorts(t *testing.T) {
	live := newHelloListener(t)
	m := newSilenceManager(t, time.Second, live.addr)
	m.Register(&greetingStrategy{id: "reality", priority: 5})

	var mu sync.Mutex
	var tcp, udp []string
	checker := NewConnectivityChecker(live.addr, 500*time.Millisecond, false)
	checker.tcpDial = func(ctx context.Context, network, addr string) (net.Conn, error) {
		mu.Lock()
		tcp = append(tcp, addr)
		mu.Unlock()
		return (&net.Dialer{}).DialContext(ctx, network, addr)
	}
	checker.udpDial = func(ctx context.Context, network, addr string) (net.Conn, error) {
		mu.Lock()
		udp = append(udp, addr)
		mu.Unlock()
		return (&net.Dialer{}).DialContext(ctx, network, addr)
	}
	m.SetConnectivityChecker(checker)

	conn, _, err := m.Connect(context.Background(), "")
	if err != nil {
		t.Fatalf("Connect: %v", err)
	}
	conn.Close()
	time.Sleep(100 * time.Millisecond) // anything the gate left running in the background

	mu.Lock()
	defer mu.Unlock()
	if len(tcp) == 0 {
		t.Fatal("the gate did not run - the test proves nothing")
	}
	for _, a := range tcp {
		if a != live.addr {
			t.Errorf("the gate dialled %s, not a transport address", a)
		}
	}
	if len(udp) != 0 {
		t.Errorf("the gate sent UDP to %v for a client with no QUIC strategy", udp)
	}
}
