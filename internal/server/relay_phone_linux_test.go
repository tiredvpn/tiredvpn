package server

import (
	"context"
	"encoding/json"
	"net"
	"path/filepath"
	"strings"
	"sync/atomic"
	"testing"
	"time"

	"golang.org/x/sys/unix"

	"github.com/tiredvpn/tiredvpn/internal/endpoint"
	"github.com/tiredvpn/tiredvpn/internal/strategy"
	"github.com/tiredvpn/tiredvpn/internal/tun"
)

// phoneCore is an Android core on its control socket, as the app runs it,
// connected through a relay: "connect" dials the relay on mk's strategy,
// "set_fd" hands it a TUN made of a seqpacket pair. got counts the packets
// that came out of the TUN on the app's side.
type phoneCore struct {
	ip  net.IP
	got atomic.Int64
}

func startPhone(t *testing.T, relay string, mk func(*strategy.Manager) strategy.Strategy) *phoneCore {
	t.Helper()
	m := strategy.NewManager()
	if err := m.SetEndpoints([]endpoint.Endpoint{{Name: "relay", V4: relay}}, endpoint.V4Only); err != nil {
		t.Fatal(err)
	}
	t.Cleanup(endpoint.ResetSharedSelectors)
	m.Register(mk(m))
	path := filepath.Join(t.TempDir(), "ctl.sock")
	cs, err := tun.NewControlServer(path, &tun.ControlConfig{MTU: 1280,
		ConnectFn: func(ctx context.Context) (net.IP, net.IP, net.Conn, error) {
			conn, _, err := m.Connect(ctx, relay)
			return net.IPv4(10, 9, 0, 2), net.IPv4(10, 9, 0, 1), conn, err
		}})
	if err != nil {
		t.Fatal(err)
	}
	ctx, cancel := context.WithCancel(context.Background())
	go func() { _ = cs.Run(ctx) }()
	t.Cleanup(func() { cancel(); cs.Close() })

	ctl, err := net.DialUnix("unix", nil, &net.UnixAddr{Name: path, Net: "unix"})
	for deadline := time.Now().Add(3 * time.Second); err != nil && time.Now().Before(deadline); {
		time.Sleep(10 * time.Millisecond)
		ctl, err = net.DialUnix("unix", nil, &net.UnixAddr{Name: path, Net: "unix"})
	}
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { ctl.Close() })
	dec := json.NewDecoder(ctl)
	answer := func(cmd string, fd int) tun.ControlResponse {
		t.Helper()
		var oob []byte
		if fd >= 0 {
			oob = unix.UnixRights(fd)
		}
		if _, _, err := ctl.WriteMsgUnix([]byte(cmd+"\n"), oob, nil); err != nil {
			t.Fatal(err)
		}
		_ = ctl.SetReadDeadline(time.Now().Add(15 * time.Second))
		for {
			var raw map[string]any
			if err := dec.Decode(&raw); err != nil {
				t.Fatalf("%s: no answer: %v", cmd, err)
			}
			if _, ok := raw["status"]; !ok {
				continue // an event
			}
			b, _ := json.Marshal(raw)
			var resp tun.ControlResponse
			_ = json.Unmarshal(b, &resp)
			return resp
		}
	}
	resp := answer(`{"command":"connect"}`, -1)
	if resp.Status != "waiting_fd" {
		t.Fatalf("connect answered %+v", resp)
	}
	fds, err := unix.Socketpair(unix.AF_UNIX, unix.SOCK_SEQPACKET, 0)
	if err != nil {
		t.Fatal(err)
	}
	p := &phoneCore{ip: net.ParseIP(resp.IP).To4()}
	go func() {
		buf := make([]byte, 2048)
		for {
			if n, err := unix.Read(fds[1], buf); err != nil || n == 0 {
				return
			}
			p.got.Add(1)
		}
	}()
	t.Cleanup(func() { unix.Close(fds[1]) })
	if resp := answer(`{"command":"set_fd"}`, fds[0]); resp.Status != "connected" {
		t.Fatalf("set_fd answered %+v", resp)
	}
	unix.Close(fds[0]) // the core holds its own copy, as the app's does
	return p
}

// TestAPushOnlyPhoneKeepsItsRelayLeg is the phone case: push traffic down
// and no app traffic up. The Android core sends a keepalive every 10 s,
// whatever the traffic, and that alone kept the leg; but its timer does not
// run while the phone sleeps between two pushes, and then nothing went up
// for minutes. Here the core's keepalive never fires (a sleeping phone)
// while a push comes down every 5 s, scaled 1:25, through the relay's bridge
// (anti-probe) and its sink (Morph). The phone's TCP acknowledges each push.
func TestAPushOnlyPhoneKeepsItsRelayLeg(t *testing.T) {
	for _, tc := range []struct {
		name string
		make func(m *strategy.Manager, secret []byte) strategy.Strategy
	}{
		{"bridge", func(m *strategy.Manager, s []byte) strategy.Strategy { return strategy.NewAntiProbeStrategy(m, s) }},
		{"sink", func(m *strategy.Manager, s []byte) strategy.Strategy {
			return strategy.NewTrafficMorphStrategy(m, nil, nil, s)
		}},
	} {
		t.Run(tc.name, func(t *testing.T) {
			scaleLegClocks(t)
			old := tun.SetKeepaliveInterval(time.Hour)
			t.Cleanup(func() { tun.SetKeepaliveInterval(old) })
			secret := []byte("relay-leg-secret-0123456789abcdef")
			exit := newLegExit(t, secret)
			relay := legRelay(t, secret, exit)
			phone := startPhone(t, relay, func(m *strategy.Manager) strategy.Strategy { return tc.make(m, secret) })
			if phone.ip == nil || strings.HasPrefix(phone.ip.String(), "10.9.") {
				t.Fatalf("the phone got %v from the exit", phone.ip)
			}
			sent := sparseDownload(t, exit, phone.ip)
			deadline := time.Now().Add(5 * time.Second)
			for phone.got.Load() < sent*9/10 && time.Now().Before(deadline) {
				time.Sleep(10 * time.Millisecond)
			}
			if got := phone.got.Load(); got < sent*9/10 {
				t.Fatalf("%d of %d pushes reached the phone", got, sent)
			}
		})
	}
}
