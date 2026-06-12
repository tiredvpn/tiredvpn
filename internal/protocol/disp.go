package protocol

import (
	"fmt"
	"io"
	"net"
	"time"
)

// Protocol type bytes sent as the first byte after TLS handshake.
// ALPN values in ClientHello are cleartext and visible to DPI; these bytes are encrypted.
const (
	TypeStego    = byte(0x01)
	TypeRaw      = byte(0x02)
	TypeMorph    = byte(0x03)
	TypeWS       = byte(0x04)
	TypePolling  = byte(0x05)
	TypeConfusion = byte(0x06)

	dispReadTimeout = 10 * time.Second
)

// WriteDispatch sends the 1-byte protocol discriminator after TLS handshake.
func WriteDispatch(conn net.Conn, protoType byte) error {
	conn.SetWriteDeadline(time.Now().Add(dispReadTimeout))
	defer conn.SetWriteDeadline(time.Time{})
	_, err := conn.Write([]byte{protoType})
	return err
}

// ReadDispatch reads the 1-byte protocol discriminator after TLS handshake.
func ReadDispatch(conn net.Conn) (byte, error) {
	conn.SetReadDeadline(time.Now().Add(dispReadTimeout))
	defer conn.SetReadDeadline(time.Time{})
	var buf [1]byte
	if _, err := io.ReadFull(conn, buf[:]); err != nil {
		return 0, fmt.Errorf("reading protocol discriminator: %w", err)
	}
	return buf[0], nil
}
