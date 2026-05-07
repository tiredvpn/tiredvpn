package server

import (
	"os"
	"strings"
	"testing"
)

// TestKTLSUnsafeMapRemoved asserts that the static kTLSUnsafe ALPN exclusion
// list — the workaround Phase 1 and Phase 2 set out to eliminate — is no
// longer present in server.go. Each "tired-*" handler now invokes
// ktls.TryEnable at its own auth-complete boundary, so the static map is
// dead code; if a future change reintroduces it, this test fails and
// points at the regression.
//
// Note: tired-polling was deferred in Phase 2 (Task 0 NO-GO — every poll
// opens a new TCP connection so kTLS has no relay phase to amortize). The
// polling handler simply does not call ktls.TryEnable; it does NOT need a
// kTLSUnsafe entry, because handleConnection no longer consults such a
// map. So the post-Phase-2 invariant is simply "the symbol is gone".
func TestKTLSUnsafeMapRemoved(t *testing.T) {
	src, err := os.ReadFile("server.go")
	if err != nil {
		t.Fatalf("read server.go: %v", err)
	}
	if strings.Contains(string(src), "kTLSUnsafe") {
		t.Fatalf("kTLSUnsafe symbol resurfaced in server.go — Phase 2 removed it; per-handler ktls.TryEnable is the new pattern")
	}
}
