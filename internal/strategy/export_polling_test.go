package strategy

import "testing"

// Hooks for the external-package polling tests, which drive the real
// internal/tun handshake reader (internal/tun imports this package, so those
// tests cannot live inside it).

func NewScriptedPollingConnForTest(t *testing.T, bodies [][]byte) *HTTPPollingConn {
	return newScriptedPollingConn(t, bodies)
}

func (c *HTTPPollingConn) PollForTest() bool {
	ok, _ := c.poll()
	return ok
}

func (c *HTTPPollingConn) FeedKeepaliveForTest() bool { return c.feedKeepalive() }

func (c *HTTPPollingConn) BufferedForTest() int {
	c.recvLock.Lock()
	defer c.recvLock.Unlock()
	return c.recvBuf.Len()
}
