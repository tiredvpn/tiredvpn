package client

import (
	"bytes"
	"os"
	"strings"
	"sync"
	"testing"

	"github.com/tiredvpn/tiredvpn/internal/log"
)

type lockedBuffer struct {
	mu  sync.Mutex
	buf bytes.Buffer
}

func (b *lockedBuffer) Write(p []byte) (int, error) {
	b.mu.Lock()
	defer b.mu.Unlock()
	return b.buf.Write(p)
}

func (b *lockedBuffer) String() string {
	b.mu.Lock()
	defer b.mu.Unlock()
	return b.buf.String()
}

// TestEndpointPoolLineShowsTheConfiguredFamily: with family = "v4_only" in the
// config the "Endpoint pool" line said prefer_v6 - the family the legacy flags
// imply - while the selector actually ran v4_only (stand report D8). Both
// lines a reader compares have to name the family in force.
func TestEndpointPoolLineShowsTheConfiguredFamily(t *testing.T) {
	out := &lockedBuffer{}
	log.SetOutput(out)
	t.Cleanup(func() { log.SetOutput(os.Stderr) })

	cfg := &Config{
		PreferIPv6:   true,
		FallbackToV4: true,
		Servers: []ServerSpec{
			{Name: "a", Addr: "192.0.2.1:995", AddrV6: "[2001:db8::1]:995"},
			{Name: "b", Addr: "192.0.2.2:995", AddrV6: "[2001:db8::2]:995"},
		},
		Selection: SelectionSpec{Family: "v4_only"},
	}
	if _, err := buildManager(cfg, "secret"); err != nil {
		t.Fatalf("buildManager: %v", err)
	}

	var pool, selection string
	for l := range strings.Lines(out.String()) {
		switch {
		case strings.Contains(l, "Endpoint pool:"):
			pool = l
		case strings.Contains(l, "Endpoint selection:"):
			selection = l
		}
	}
	if !strings.Contains(selection, "family=v4_only") {
		t.Fatalf("selection line %q does not say v4_only - the test proves nothing", selection)
	}
	if !strings.Contains(pool, "family=v4_only") {
		t.Fatalf("pool line names another family than the one in force:\n%s", pool)
	}
}
