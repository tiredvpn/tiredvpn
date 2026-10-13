package strategy

import "testing"

// TestQUICPlainForcedComesBack covers -strategy quic where auto mode
// registered only Salamander. A server started with -quic-sni-reassembly
// speaks unwrapped QUIC to any client, and main reached it this way, so an
// explicit request brings plain QUIC back on Salamander's port and secret
// instead of erroring or quietly matching quic_salamander by prefix. Without
// -quic the generic "no strategy matching" answer stays.
func TestQUICPlainForcedComesBack(t *testing.T) {
	m := NewDefaultManager(DefaultManagerConfig{
		ServerAddr:  "192.0.2.1:995",
		Secret:      []byte("0123456789abcdef0123456789abcdef"),
		QUICEnabled: true,
	})
	if err := m.ForceStrategy("quic"); err != nil {
		t.Fatalf("forcing plain quic with only Salamander registered: %v", err)
	}
	if len(m.strategies) != 1 || m.strategies[0].ID() != "quic" {
		t.Fatalf("forced list %v, want only plain quic", strategyIDs(m.strategies))
	}
	q := m.strategies[0].(*QUICStrategy)
	if q.useSalamander || q.sniFragmentEnabled || q.port != 995 {
		t.Fatalf("plain quic built as salamander=%v sniFrag=%v port=%d, want plain on 995",
			q.useSalamander, q.sniFragmentEnabled, q.port)
	}

	m = NewDefaultManager(DefaultManagerConfig{
		ServerAddr:  "192.0.2.1:995",
		Secret:      []byte("0123456789abcdef0123456789abcdef"),
		QUICEnabled: true,
	})
	if err := m.ForceStrategy("quic_salamander"); err != nil || len(m.strategies) != 1 || m.strategies[0].ID() != "quic_salamander" {
		t.Fatalf("forcing quic_salamander: %v %v", err, strategyIDs(m.strategies))
	}

	m = NewManager()
	m.Register(&mockStrategy{id: "confusion_0", priority: 10})
	if err := m.ForceStrategy("quic"); err == nil {
		t.Fatal("without any QUIC strategy forcing quic must fail")
	}
}

func strategyIDs(ss []Strategy) []string {
	out := make([]string, 0, len(ss))
	for _, s := range ss {
		out = append(out, s.ID())
	}
	return out
}
