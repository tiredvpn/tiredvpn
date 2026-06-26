package server

import (
	"sync"
)

// LargeBufSize is the relay buffer size (64KB for high throughput relay).
const LargeBufSize = 64 * 1024

// largeBufPool reduces allocations on the relay hot path.
var largeBufPool = sync.Pool{
	New: func() interface{} {
		buf := make([]byte, LargeBufSize)
		return &buf
	},
}

// GetRelayBuffer returns a buffer suitable for relay operations (64KB)
func GetRelayBuffer() []byte {
	buf := largeBufPool.Get().(*[]byte)
	return *buf
}

// PutRelayBuffer returns a relay buffer to the pool
func PutRelayBuffer(buf []byte) {
	if cap(buf) >= LargeBufSize {
		b := buf[:LargeBufSize]
		largeBufPool.Put(&b)
	}
}
