package server

import (
	"sync"
)

// Buffer sizes
const (
	SmallBufSize  = 4 * 1024  // 4KB for headers and small packets
	MediumBufSize = 16 * 1024 // 16KB for general relay
	LargeBufSize  = 64 * 1024 // 64KB for high throughput relay
)

// Buffer pools to reduce allocations in hot paths
var (
	smallBufPool = sync.Pool{
		New: func() interface{} {
			buf := make([]byte, SmallBufSize)
			return &buf
		},
	}

	mediumBufPool = sync.Pool{
		New: func() interface{} {
			buf := make([]byte, MediumBufSize)
			return &buf
		},
	}

	largeBufPool = sync.Pool{
		New: func() interface{} {
			buf := make([]byte, LargeBufSize)
			return &buf
		},
	}
)

// GetSmallBuffer returns a 4KB buffer from the pool
func GetSmallBuffer() *[]byte {
	return smallBufPool.Get().(*[]byte)
}

// PutSmallBuffer returns a 4KB buffer to the pool
func PutSmallBuffer(buf *[]byte) {
	if buf != nil && cap(*buf) >= SmallBufSize {
		smallBufPool.Put(buf)
	}
}

// GetMediumBuffer returns a 16KB buffer from the pool
func GetMediumBuffer() *[]byte {
	return mediumBufPool.Get().(*[]byte)
}

// PutMediumBuffer returns a 16KB buffer to the pool
func PutMediumBuffer(buf *[]byte) {
	if buf != nil && cap(*buf) >= MediumBufSize {
		mediumBufPool.Put(buf)
	}
}

// GetLargeBuffer returns a 64KB buffer from the pool
func GetLargeBuffer() *[]byte {
	return largeBufPool.Get().(*[]byte)
}

// PutLargeBuffer returns a 64KB buffer to the pool
func PutLargeBuffer(buf *[]byte) {
	if buf != nil && cap(*buf) >= LargeBufSize {
		largeBufPool.Put(buf)
	}
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
