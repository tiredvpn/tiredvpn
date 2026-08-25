package buildinfo

import (
	"fmt"
	"os"
	"path/filepath"
	"slices"
	"strings"
	"testing"

	"github.com/tiredvpn/tiredvpn/internal/client"
	"github.com/tiredvpn/tiredvpn/internal/server"
)

// The version number lives in five places, and the project's own notes listed
// four of them for a long time - deploy/helm/tiredvpn/Chart.yaml was missing
// from the list. An incomplete list is worse than none: people check against it
// and believe they are done.
//
// A sixth place, deploy/helm/tiredvpn/README.md, carries the version in prose.
// It is deliberately NOT checked here - the version sits in a sentence, and
// false failures would cost more than the drift they catch. It is also the
// proof that discipline alone does not hold: at the time this test was written
// that README was four releases behind.
const notCheckedHint = "deploy/helm/tiredvpn/README.md also carries a version, in prose; " +
	"this test does not check it, so fix it by hand when bumping"

// place is one location that must agree with the VERSION file.
type place struct {
	name    string
	version string
}

// mismatch is one disagreement, phrased so the failure names the file and both
// values rather than saying that something, somewhere, is wrong.
type mismatch struct {
	place string
	want  string
	got   string
}

func (m mismatch) String() string {
	return fmt.Sprintf("%s has %q, VERSION has %q", m.place, m.got, m.want)
}

// compare returns every place that disagrees with want, not just the first.
// Stopping at the first would let a second drifted file hide behind the one
// being fixed, which is the failure mode this whole test exists to prevent.
func compare(want string, places []place) []mismatch {
	var out []mismatch
	for _, p := range places {
		if p.version != want {
			out = append(out, mismatch{place: p.name, want: want, got: p.version})
		}
	}
	return out
}

// repoRoot walks up from the package directory until it finds the VERSION file,
// so the test does not depend on where `go test` was invoked from.
func repoRoot(t *testing.T) string {
	t.Helper()
	dir, err := os.Getwd()
	if err != nil {
		t.Fatalf("getwd: %v", err)
	}
	for {
		if _, err := os.Stat(filepath.Join(dir, "VERSION")); err == nil {
			return dir
		}
		parent := filepath.Dir(dir)
		if parent == dir {
			t.Fatal("VERSION not found in any parent directory")
		}
		dir = parent
	}
}

func readVersionFile(t *testing.T, root string) string {
	t.Helper()
	b, err := os.ReadFile(filepath.Join(root, "VERSION"))
	if err != nil {
		t.Fatalf("read VERSION: %v", err)
	}
	return strings.TrimSpace(string(b))
}

// readChartAppVersion pulls appVersion out of the Helm chart by reading lines
// rather than pulling in a YAML parser: the field is a scalar at the top level,
// and a dependency here would be more machinery than the job needs.
func readChartAppVersion(t *testing.T, root string) string {
	t.Helper()
	path := filepath.Join(root, "deploy", "helm", "tiredvpn", "Chart.yaml")
	b, err := os.ReadFile(path)
	if err != nil {
		t.Fatalf("read Chart.yaml: %v", err)
	}
	for line := range strings.SplitSeq(string(b), "\n") {
		rest, ok := strings.CutPrefix(strings.TrimSpace(line), "appVersion:")
		if !ok {
			continue
		}
		return strings.Trim(strings.TrimSpace(rest), `"'`)
	}
	t.Fatalf("appVersion not found in %s", path)
	return ""
}

// TestVersionsAgree is the check that runs in CI. A bump that misses a file
// cannot reach main once this is green, which is cheaper than remembering to
// check five places by hand.
func TestVersionsAgree(t *testing.T) {
	root := repoRoot(t)
	want := readVersionFile(t, root)

	places := []place{
		{name: "internal/client.Version", version: client.Version},
		{name: "internal/server.Version", version: server.Version},
		{name: "deploy/helm/tiredvpn/Chart.yaml appVersion", version: readChartAppVersion(t, root)},
	}

	if bad := compare(want, places); len(bad) > 0 {
		var lines []string
		for _, m := range bad {
			lines = append(lines, "  "+m.String())
		}
		t.Errorf("version drifted in %d of %d places:\n%s\n\nnote: %s",
			len(bad), len(places), strings.Join(lines, "\n"), notCheckedHint)
	}
}

// TestCompareDetectsEachPlaceIndependently is the guard on the guard.
//
// A test that only ever sees a consistent tree proves nothing: it would pass
// just as happily if compare always returned nil. Each place is broken on its
// own here, so a check that silently stops looking after the first file - or
// never looks at one of them at all - fails.
func TestCompareDetectsEachPlaceIndependently(t *testing.T) {
	const want = "1.4.0"
	good := []place{
		{name: "internal/client.Version", version: want},
		{name: "internal/server.Version", version: want},
		{name: "deploy/helm/tiredvpn/Chart.yaml appVersion", version: want},
	}

	if bad := compare(want, good); len(bad) != 0 {
		t.Fatalf("consistent input reported %d mismatches: %v", len(bad), bad)
	}

	for i, p := range good {
		t.Run(p.name, func(t *testing.T) {
			broken := slices.Clone(good)
			broken[i].version = "1.3.99"

			bad := compare(want, broken)
			if len(bad) != 1 {
				t.Fatalf("breaking %s alone produced %d mismatches, want 1: %v", p.name, len(bad), bad)
			}
			if bad[0].place != p.name {
				t.Errorf("reported %q, want %q", bad[0].place, p.name)
			}
			if !strings.Contains(bad[0].String(), "1.3.99") || !strings.Contains(bad[0].String(), want) {
				t.Errorf("message %q does not name both versions", bad[0].String())
			}
		})
	}
}

// TestCompareReportsEveryDriftedPlace covers the case the single-break subtests
// cannot: two files drifting at once, where reporting only one would send
// someone to fix half the problem and re-run into the same failure.
func TestCompareReportsEveryDriftedPlace(t *testing.T) {
	const want = "1.4.0"
	bad := compare(want, []place{
		{name: "a", version: "1.3.99"},
		{name: "b", version: want},
		{name: "c", version: "1.3.98"},
	})
	if len(bad) != 2 {
		t.Fatalf("got %d mismatches, want 2: %v", len(bad), bad)
	}
}
