//go:build !android && !linux

package protect

import (
	"context"
	"net"
)

// Protocol versions accepted by SetProtocol.
const (
	ProtoV1 = 1
	ProtoV2 = 2
)

func SetProtocol(_ int) {}

func Protocol() int { return ProtoV1 }

func InitAndroidProtector(_ string) error { return nil }

func ProtectSocket(_ int) error { return nil }

func ProtectRawFd(_ int) error { return nil }

func ProtectConn(_ net.Conn) error { return nil }

func IsProtectorActive() bool { return false }

func DialWithProtect(network, address string) (net.Conn, error) {
	return net.Dial(network, address)
}

type ProtectDialer struct {
	Dialer *net.Dialer
}

func (d *ProtectDialer) Dial(network, address string) (net.Conn, error) {
	if d.Dialer != nil {
		return d.Dialer.Dial(network, address)
	}
	return net.Dial(network, address)
}

func (d *ProtectDialer) DialContext(ctx context.Context, network, address string) (net.Conn, error) {
	if d.Dialer != nil {
		return d.Dialer.DialContext(ctx, network, address)
	}
	var dialer net.Dialer
	return dialer.DialContext(ctx, network, address)
}
