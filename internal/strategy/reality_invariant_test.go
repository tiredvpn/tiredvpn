package strategy

import (
	"testing"
)

// testGlobalPool returns a deterministic global pool large enough that a
// 12-element derived subpool is a strict subset.
func testGlobalPool() []string {
	return []string{
		"yandex.ru", "ya.ru", "yandex.net", "vk.com", "vk.me",
		"mail.ru", "ok.ru", "sberbank.ru", "gosuslugi.ru", "mos.ru",
		"google.com", "google.ru", "googleapis.com", "gstatic.com",
		"microsoft.com", "office.com", "azure.com", "windows.net",
		"cloudflare.com", "akamai.net", "fastly.net",
		"tinkoff.ru", "alfabank.ru", "vtb.ru",
	}
}

// TestDerivePoolDeterministic verifies blast-radius-min T2: deriving a subpool
// from the same secret twice yields the identical result.
func TestDerivePoolDeterministic(t *testing.T) {
	global := testGlobalPool()
	secret := []byte("user-secret-deterministic")

	a := derivePool(global, secret, 12)
	b := derivePool(global, secret, 12)

	if len(a) != len(b) {
		t.Fatalf("subpool lengths differ across calls: %d vs %d", len(a), len(b))
	}
	for i := range a {
		if a[i] != b[i] {
			t.Errorf("subpool element %d differs: %q vs %q", i, a[i], b[i])
		}
	}
}

// TestDerivePoolDistinctSecrets verifies that different secrets yield different
// subpools (overlap strictly below 100%). This is the core blast-radius
// property: one user's donor set must not equal another's.
func TestDerivePoolDistinctSecrets(t *testing.T) {
	global := testGlobalPool()

	a := derivePool(global, []byte("secret-alice"), 12)
	b := derivePool(global, []byte("secret-bob"), 12)

	set := make(map[string]bool, len(a))
	for _, d := range a {
		set[d] = true
	}
	overlap := 0
	for _, d := range b {
		if set[d] {
			overlap++
		}
	}

	if overlap >= len(b) {
		t.Errorf("distinct secrets produced identical subpools (overlap=%d/%d, want < 100%%)", overlap, len(b))
	}
}

// TestDerivePoolSize verifies the subpool has exactly N elements when the global
// pool is larger than N, and is capped to globalPool size otherwise.
func TestDerivePoolSize(t *testing.T) {
	global := testGlobalPool()
	secret := []byte("size-secret")

	t.Run("N=12 with large global pool", func(t *testing.T) {
		sub := derivePool(global, secret, 12)
		if len(sub) != 12 {
			t.Errorf("subpool size = %d, want 12", len(sub))
		}
	})

	t.Run("N larger than global pool is capped", func(t *testing.T) {
		small := []string{"a.example", "b.example", "c.example"}
		sub := derivePool(small, secret, 12)
		if len(sub) != len(small) {
			t.Errorf("subpool size = %d, want %d (capped to global pool)", len(sub), len(small))
		}
	})

	t.Run("empty global pool yields nil", func(t *testing.T) {
		sub := derivePool([]string{}, secret, 12)
		if len(sub) != 0 {
			t.Errorf("expected empty subpool for empty global pool, got %d", len(sub))
		}
	})
}

// TestDerivePoolSubsetOfGlobal verifies every derived element is a real member
// of the global pool (no invented domains).
func TestDerivePoolSubsetOfGlobal(t *testing.T) {
	global := testGlobalPool()
	secret := []byte("subset-secret")

	globalSet := make(map[string]bool, len(global))
	for _, d := range global {
		globalSet[d] = true
	}

	sub := derivePool(global, secret, 12)
	if len(sub) == 0 {
		t.Fatal("derived subpool is empty")
	}

	// No duplicates and all members of global.
	seen := make(map[string]bool, len(sub))
	for _, d := range sub {
		if !globalSet[d] {
			t.Errorf("subpool contains domain not in global pool: %q", d)
		}
		if seen[d] {
			t.Errorf("subpool contains duplicate domain: %q", d)
		}
		seen[d] = true
	}
}
