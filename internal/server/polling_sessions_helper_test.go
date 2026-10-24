package server

import "testing"

// forgetNewPollingSessions removes, once the test is over, the polling
// sessions the test opened on the process-wide pollingManager: the client is
// gone, but its session would wait out its idle timeout and fill the
// ceiling the session-cap tests count on.
func forgetNewPollingSessions(t *testing.T) {
	t.Helper()
	pollingManager.mu.Lock()
	before := make(map[string]bool, len(pollingManager.sessions))
	for id := range pollingManager.sessions {
		before[id] = true
	}
	pollingManager.mu.Unlock()
	t.Cleanup(func() {
		pollingManager.mu.Lock()
		var ours []*HTTPPollingSession
		for id, sess := range pollingManager.sessions {
			if !before[id] {
				ours = append(ours, sess)
			}
		}
		pollingManager.mu.Unlock()
		for _, sess := range ours {
			pollingManager.removeSession(sess)
		}
	})
}
