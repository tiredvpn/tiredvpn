//go:build !linux

package server

import "time"

// tcpSinceAckReceived: no TCP_INFO here; clientLiveness falls back to what
// it heard from the client.
func tcpSinceAckReceived(uintptr) (time.Duration, bool) { return 0, false }
