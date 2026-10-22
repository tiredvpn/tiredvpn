package protect

import (
	"context"
	"strings"
)

type connectedHookKey struct{}

// WithConnectedHook returns a context that makes every ProtectDialer dialling
// on it call fn once a TCP connection is up. The strategy manager uses it to
// tell an attempt still waiting for its TCP connect from one whose handshake is
// under way: the first may be cut short, the second may not.
func WithConnectedHook(ctx context.Context, fn func()) context.Context {
	return context.WithValue(ctx, connectedHookKey{}, fn)
}

// tcpConnected runs the hook WithConnectedHook put on ctx, if any, for a TCP
// dial that succeeded. UDP "connects" without a packet leaving, so it says
// nothing about the server and does not count.
func tcpConnected(ctx context.Context, network string) {
	if !strings.HasPrefix(network, "tcp") {
		return
	}
	if fn, ok := ctx.Value(connectedHookKey{}).(func()); ok {
		fn()
	}
}
