package strategy

import (
	"bytes"
	"os"
	"strings"
	"testing"

	"github.com/tiredvpn/tiredvpn/internal/log"
)

// TestIsCamouflageOnly pins the classification. Every shipped transport id is
// listed with the verdict verified against its handshake code (see
// camouflage.go and docs/security.md). A transport that moves between buckets
// must move here too, deliberately.
func TestIsCamouflageOnly(t *testing.T) {
	camouflageOnly := []string{
		"morph",               // base id
		"morph_YouTube 1080p", // variant suffix must match the base
		"websocket_padded",    //
		"geneva_russia",       // variant suffix
		"geneva_china",        //
		"http_polling",        //
		"mesh_relay",          //
		"imap_camouflage",     //
		"http2_stego",         // server ack keyed but not session-bound -> replayable
	}
	serverAuthenticated := []string{
		"reality",          // ServerHello ack HMAC(secret, clientPubKey)
		"reality_b1",       //
		"seqovl",           // wraps REALITY
		"antiprobe",        // HMAC over TLS exporter
		"quic",             // server marker over fresh nonce
		"quic_salamander",  //
		"ssh_camouflage",   // server auth token over SSH session id
		"confusion_0",      // server marker over fresh nonce + AEAD
		"confusion_1",      //
		"state_exhaustion", // Confusion wrapper
		"icmp_tunnel",      // ChaCha20-Poly1305, keys from secret
	}

	for _, id := range camouflageOnly {
		if !IsCamouflageOnly(id) {
			t.Errorf("IsCamouflageOnly(%q) = false, want true", id)
		}
		if reason, ok := camouflageOnlyReason(id); !ok || reason == "" {
			t.Errorf("camouflageOnlyReason(%q) = (%q, %v), want a non-empty reason", id, reason, ok)
		}
	}
	for _, id := range serverAuthenticated {
		if IsCamouflageOnly(id) {
			t.Errorf("IsCamouflageOnly(%q) = true, want false (server-authenticated)", id)
		}
	}
}

// TestWarnCamouflageOnlyOncePerID checks the warning fires for a camouflage-only
// transport, carries the transport id, and does not repeat for the same id.
func TestWarnCamouflageOnlyOncePerID(t *testing.T) {
	var buf bytes.Buffer
	log.SetOutput(&buf)
	log.SetLevel(log.LevelWarn)
	log.SetDedupWindow(0) // the manager dedups; do not let the logger hide a repeat
	t.Cleanup(func() {
		log.SetOutput(os.Stderr)
		log.SetLevel(log.LevelInfo)
		log.SetDedupWindow(5_000_000_000)
	})

	m := NewManager()
	camo := &mockStrategy{id: "morph_YouTube 1080p"}

	m.warnCamouflageOnly(camo)
	first := buf.String()
	if !strings.Contains(first, "camouflage-only") || !strings.Contains(first, camo.ID()) {
		t.Fatalf("first warning missing text or id: %q", first)
	}
	if strings.Count(first, "camouflage-only") != 1 {
		t.Fatalf("expected exactly one warning, got: %q", first)
	}

	m.warnCamouflageOnly(camo)
	if got := strings.Count(buf.String(), "camouflage-only"); got != 1 {
		t.Fatalf("warning repeated for the same id: count=%d, log=%q", got, buf.String())
	}
}

// TestWarnCamouflageOnlySilentForServerAuth checks a server-authenticated
// transport produces no warning.
func TestWarnCamouflageOnlySilentForServerAuth(t *testing.T) {
	var buf bytes.Buffer
	log.SetOutput(&buf)
	log.SetLevel(log.LevelWarn)
	t.Cleanup(func() {
		log.SetOutput(os.Stderr)
		log.SetLevel(log.LevelInfo)
	})

	m := NewManager()
	m.warnCamouflageOnly(&mockStrategy{id: "reality"})
	m.warnCamouflageOnly(&mockStrategy{id: "antiprobe"})
	m.warnCamouflageOnly(nil)

	if got := buf.String(); strings.Contains(got, "camouflage-only") {
		t.Fatalf("server-authenticated transport warned: %q", got)
	}
}
