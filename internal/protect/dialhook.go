package protect

import (
	"context"
	"net"
	"strings"
)

type dialHooksKey struct{}

// dialHooks are the callbacks WithDialHooks puts on a context.
type dialHooks struct {
	started   func()
	connected func(net.Conn)
}

// WithDialHooks returns a context that makes every ProtectDialer dialling on
// it call started when a TCP dial begins and connected once the connection is
// up. The strategy manager uses them to tell three moments of an attempt
// apart: still waiting locally (a handshake gate, key generation) before any
// SYN, waiting for the TCP connect, and a handshake under way. The first two
// may be cut short; only the second is the server's silence. connected gets
// the connection, to watch the handshake's progress on it. Either may be nil.
func WithDialHooks(ctx context.Context, started func(), connected func(net.Conn)) context.Context {
	return context.WithValue(ctx, dialHooksKey{}, dialHooks{started: started, connected: connected})
}

// tcpDialStarted runs the started hook for a TCP dial about to go out. UDP
// "connects" without a packet leaving, so it says nothing about the server and
// does not count, here or in tcpConnected.
func tcpDialStarted(ctx context.Context, network string) {
	if h, ok := ctx.Value(dialHooksKey{}).(dialHooks); ok && h.started != nil && strings.HasPrefix(network, "tcp") {
		h.started()
	}
}

// tcpConnected runs the connected hook for a TCP dial that succeeded.
func tcpConnected(ctx context.Context, network string, conn net.Conn) {
	if h, ok := ctx.Value(dialHooksKey{}).(dialHooks); ok && h.connected != nil && strings.HasPrefix(network, "tcp") {
		h.connected(conn)
	}
}
