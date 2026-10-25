package server

import (
	"bytes"
	"time"
)

// newPollingSession builds a session the way GetOrCreate does, without putting
// it in the global manager.
func newPollingSession(id string) *HTTPPollingSession {
	sess := &HTTPPollingSession{
		ID:         id,
		Created:    time.Now(),
		toClient:   bytes.NewBuffer(nil),
		fromClient: bytes.NewBuffer(nil),
	}
	sess.touch(time.Now())
	return sess
}
