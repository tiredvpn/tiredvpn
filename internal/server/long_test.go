package server

import "testing"

// longTest skips a test under -short. These run for several seconds up to
// minutes each - real clocks, legs held for tens of seconds, read deadlines
// waited out - and together they took the package past the 5 min -short
// budget of CI and of the release workflow: it went from about 1 min to
// about 8 under -race. scripts/ci-long-tests.sh runs them by name, without
// -short, in CI and before a release, and requires a PASS from each.
func longTest(t *testing.T) {
	t.Helper()
	if testing.Short() {
		t.Skip("long test: runs in scripts/ci-long-tests.sh")
	}
}
