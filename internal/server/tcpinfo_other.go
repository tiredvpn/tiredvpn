//go:build !linux

package server

// tcpBytesAcked: no TCP_INFO here; clientLiveness falls back to what it
// heard from the client.
func tcpBytesAcked(uintptr) (uint64, bool) { return 0, false }
