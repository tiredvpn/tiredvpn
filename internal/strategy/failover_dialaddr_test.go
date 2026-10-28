package strategy

import (
	"context"
	"net"
	"testing"
	"time"

	"github.com/tiredvpn/tiredvpn/internal/endpoint"
)

// pinMovingStrategy moves the pin to another candidate in the middle of its
// dial, the way a concurrent Connect or the pre-flight gate can, and records
// which server and which key the dial then goes on with.
type pinMovingStrategy struct {
	m      *Manager
	moveTo endpoint.Candidate

	gotAddr   string
	gotSecret string
}

func (s *pinMovingStrategy) Name() string                        { return "mover" }
func (s *pinMovingStrategy) ID() string                          { return "mover" }
func (s *pinMovingStrategy) Priority() int                       { return 1 }
func (s *pinMovingStrategy) RequiresServer() bool                { return true }
func (s *pinMovingStrategy) Description() string                 { return "moves the pin mid-dial" }
func (s *pinMovingStrategy) Probe(context.Context, string) error { return nil }
func (s *pinMovingStrategy) Connect(ctx context.Context, _ string) (net.Conn, error) {
	s.m.selector().Pin(s.moveTo)
	s.gotAddr = s.m.GetServerAddr(ctx) // what REALITY and a dozen others dial
	s.gotSecret = string(dialSecret(ctx, nil))
	c, peer := net.Pipe()
	peer.Close()
	return c, nil
}

// TestDialKeepsItsAddressWhenThePinMoves is the latent D8 item of the
// 2026-10-21 stand report: REALITY (and most other strategies) dial
// GetServerAddr, the pin as of that moment, while the secret rides the
// dial's context. A pin that moved mid-dial would split them: one server's
// address, another server's key.
func TestDialKeepsItsAddressWhenThePinMoves(t *testing.T) {
	eps := []endpoint.Endpoint{
		{Name: "a", V4: "198.51.100.1:995", Secret: "key-a"},
		{Name: "b", V4: "198.51.100.2:995", Secret: "key-b", Order: 1},
	}
	sel, err := endpoint.NewSelector(endpoint.Config{Endpoints: eps, Family: endpoint.V4Only, ProbeTimeout: time.Millisecond})
	if err != nil {
		t.Fatalf("NewSelector: %v", err)
	}
	cands := sel.Candidates()
	// Both probed, so the family probe does not dial.
	sel.ReportProbe(cands[0], true, time.Millisecond)
	sel.ReportProbe(cands[1], true, time.Millisecond)

	m := NewManager()
	m.endpoints = sel
	s := &pinMovingStrategy{m: m, moveTo: cands[1]}
	m.Register(s)

	conn, _, err := m.Connect(context.Background(), "")
	if err != nil {
		t.Fatalf("Connect: %v", err)
	}
	conn.Close()
	if s.gotAddr != cands[0].Addr || s.gotSecret != "key-a" {
		t.Fatalf("the dial went on with address %s and key %q, want %s and key-a", s.gotAddr, s.gotSecret, cands[0].Addr)
	}
}
