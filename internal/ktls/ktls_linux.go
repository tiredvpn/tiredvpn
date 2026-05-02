//go:build linux

// Package ktls provides kernel TLS (kTLS) support for Go.
// It offloads TLS encryption to the Linux kernel after handshake completes.
package ktls

import (
	"bytes"
	"crypto/sha256"
	"crypto/sha512"
	"crypto/tls"
	"errors"
	"fmt"
	"hash"
	"io"
	"net"
	"os"
	"reflect"
	"sync/atomic"
	"syscall"
	"unsafe"

	"github.com/tiredvpn/tiredvpn/internal/log"
	"golang.org/x/crypto/hkdf"
)

// Linux kTLS constants
const (
	SOL_TLS = 282
	TLS_TX  = 1
	TLS_RX  = 2

	TLS_1_2_VERSION = 0x0303
	TLS_1_3_VERSION = 0x0304

	// Cipher types
	TLS_CIPHER_AES_GCM_128       = 51
	TLS_CIPHER_AES_GCM_256       = 52
	TLS_CIPHER_CHACHA20_POLY1305 = 54

	// Sizes
	TLS_CIPHER_AES_GCM_128_KEY_SIZE       = 16
	TLS_CIPHER_AES_GCM_256_KEY_SIZE       = 32
	TLS_CIPHER_AES_GCM_128_IV_SIZE        = 8
	TLS_CIPHER_AES_GCM_256_IV_SIZE        = 8
	TLS_CIPHER_AES_GCM_128_SALT_SIZE      = 4
	TLS_CIPHER_AES_GCM_256_SALT_SIZE      = 4
	TLS_CIPHER_AES_GCM_128_TAG_SIZE       = 16
	TLS_CIPHER_AES_GCM_256_TAG_SIZE       = 16
	TLS_CIPHER_AES_GCM_128_REC_SEQ_SIZE   = 8
	TLS_CIPHER_AES_GCM_256_REC_SEQ_SIZE   = 8
	TLS_CIPHER_CHACHA20_POLY1305_KEY_SIZE = 32
	TLS_CIPHER_CHACHA20_POLY1305_IV_SIZE  = 12
	TLS_CIPHER_CHACHA20_POLY1305_TAG_SIZE = 16
)

// TLS 1.3 cipher suites
const (
	TLS_AES_128_GCM_SHA256       = 0x1301
	TLS_AES_256_GCM_SHA384       = 0x1302
	TLS_CHACHA20_POLY1305_SHA256 = 0x1303
)

// tlsCryptoInfoAESGCM128 for TLS 1.3 AES-128-GCM
type tlsCryptoInfoAESGCM128 struct {
	Version    uint16
	CipherType uint16
	IV         [8]byte // implicit IV (last 8 bytes of 12-byte nonce)
	Key        [16]byte
	Salt       [4]byte // first 4 bytes of 12-byte IV
	RecSeq     [8]byte // record sequence number
}

// tlsCryptoInfoAESGCM256 for TLS 1.3 AES-256-GCM
type tlsCryptoInfoAESGCM256 struct {
	Version    uint16
	CipherType uint16
	IV         [8]byte
	Key        [32]byte
	Salt       [4]byte
	RecSeq     [8]byte
}

// tlsCryptoInfoChaCha20Poly1305 for TLS 1.3 ChaCha20-Poly1305
type tlsCryptoInfoChaCha20Poly1305 struct {
	Version    uint16
	CipherType uint16
	IV         [12]byte
	Key        [32]byte
	RecSeq     [8]byte
}

var (
	supported     atomic.Bool
	initialized   atomic.Bool
	enabledConns  atomic.Int64
	fallbackConns atomic.Int64
)

// checkSupport verifies kTLS availability in the kernel
func checkSupport() bool {
	if initialized.Load() {
		return supported.Load()
	}

	// Check environment variable to force disable
	if os.Getenv("TIREDVPN_NO_KTLS") == "1" {
		log.Info("kTLS: disabled via environment variable")
		initialized.Store(true)
		return false
	}

	// Check if TLS module is loaded by checking /proc/modules
	// This is safer than trying TCP_ULP on an unconnected socket
	data, err := os.ReadFile("/proc/modules")
	if err != nil {
		log.Warn("kTLS: cannot read /proc/modules: %v", err)
		initialized.Store(true)
		return false
	}

	// Look for "tls" module
	if bytes.Contains(data, []byte("tls ")) {
		supported.Store(true)
		initialized.Store(true)
		log.Info("kTLS: kernel TLS support detected, will offload encryption")
		return true
	}

	log.Warn("kTLS: TLS kernel module not loaded")
	initialized.Store(true)
	return false
}

// Supported returns true if kTLS is available
func Supported() bool {
	if !initialized.Load() {
		checkSupport()
	}
	return supported.Load()
}

// Stats returns kTLS usage statistics
func Stats() (enabled, fallback int64) {
	return enabledConns.Load(), fallbackConns.Load()
}

// tlsConnState extracts internal state from tls.Conn using reflection
type tlsConnState struct {
	Version          uint16
	CipherSuite      uint16
	InTrafficSecret  []byte
	OutTrafficSecret []byte
	InSeq            [8]byte
	OutSeq           [8]byte
}

// extractTLSState extracts TLS keys and IVs from tls.Conn using reflection
func extractTLSState(conn *tls.Conn) (*tlsConnState, error) {
	connValue := reflect.ValueOf(conn).Elem()

	// Get version
	versField := connValue.FieldByName("vers")
	if !versField.IsValid() {
		return nil, errors.New("cannot find vers field")
	}
	version := uint16(versField.Uint())

	// Only support TLS 1.3 for now (TLS 1.2 has different key structure)
	if version != tls.VersionTLS13 {
		return nil, fmt.Errorf("kTLS only supports TLS 1.3, got version 0x%04x", version)
	}

	// Get cipher suite
	cipherField := connValue.FieldByName("cipherSuite")
	if !cipherField.IsValid() {
		return nil, errors.New("cannot find cipherSuite field")
	}
	cipherSuite := uint16(cipherField.Uint())

	// Get in halfConn
	inField := connValue.FieldByName("in")
	if !inField.IsValid() {
		return nil, errors.New("cannot find in field")
	}

	// Get out halfConn
	outField := connValue.FieldByName("out")
	if !outField.IsValid() {
		return nil, errors.New("cannot find out field")
	}

	// Extract traffic secrets using unsafe pointer access
	// halfConn.trafficSecret is at a specific offset
	inTrafficSecret := extractTrafficSecret(inField)
	outTrafficSecret := extractTrafficSecret(outField)

	if inTrafficSecret == nil || outTrafficSecret == nil {
		return nil, errors.New("cannot extract traffic secrets")
	}

	// Extract sequence numbers
	inSeq := extractSeq(inField)
	outSeq := extractSeq(outField)

	return &tlsConnState{
		Version:          version,
		CipherSuite:      cipherSuite,
		InTrafficSecret:  inTrafficSecret,
		OutTrafficSecret: outTrafficSecret,
		InSeq:            inSeq,
		OutSeq:           outSeq,
	}, nil
}

// extractTrafficSecret extracts trafficSecret from halfConn using reflection
func extractTrafficSecret(halfConn reflect.Value) []byte {
	// trafficSecret is a []byte field in halfConn
	secretField := halfConn.FieldByName("trafficSecret")
	if !secretField.IsValid() || secretField.IsNil() {
		return nil
	}

	// Use unsafe to access unexported field
	secretPtr := unsafe.Pointer(secretField.UnsafeAddr())
	secretSlice := *(*[]byte)(secretPtr)

	// Make a copy to avoid issues with GC
	result := make([]byte, len(secretSlice))
	copy(result, secretSlice)
	return result
}

// extractSeq extracts sequence number from halfConn
func extractSeq(halfConn reflect.Value) [8]byte {
	seqField := halfConn.FieldByName("seq")
	if !seqField.IsValid() {
		return [8]byte{}
	}

	var seq [8]byte
	for i := 0; i < 8; i++ {
		seq[i] = byte(seqField.Index(i).Uint())
	}
	return seq
}

// deriveKeys derives key and IV from traffic secret using HKDF
func deriveKeys(trafficSecret []byte, cipherSuite uint16) (key, iv []byte, err error) {
	var h func() hash.Hash
	var keyLen int

	switch cipherSuite {
	case TLS_AES_128_GCM_SHA256:
		h = sha256.New
		keyLen = 16
	case TLS_AES_256_GCM_SHA384:
		h = sha512.New384
		keyLen = 32
	case TLS_CHACHA20_POLY1305_SHA256:
		h = sha256.New
		keyLen = 32
	default:
		return nil, nil, fmt.Errorf("unsupported cipher suite: 0x%04x", cipherSuite)
	}

	// TLS 1.3 key derivation using HKDF-Expand-Label
	key = hkdfExpandLabel(h, trafficSecret, "key", nil, keyLen)
	iv = hkdfExpandLabel(h, trafficSecret, "iv", nil, 12) // nonce is always 12 bytes

	return key, iv, nil
}

// hkdfExpandLabel implements TLS 1.3 HKDF-Expand-Label
func hkdfExpandLabel(h func() hash.Hash, secret []byte, label string, context []byte, length int) []byte {
	// Construct HkdfLabel structure
	// struct {
	//     uint16 length = Length;
	//     opaque label<7..255> = "tls13 " + Label;
	//     opaque context<0..255> = Context;
	// } HkdfLabel;

	fullLabel := "tls13 " + label
	hkdfLabel := make([]byte, 2+1+len(fullLabel)+1+len(context))
	hkdfLabel[0] = byte(length >> 8)
	hkdfLabel[1] = byte(length)
	hkdfLabel[2] = byte(len(fullLabel))
	copy(hkdfLabel[3:], fullLabel)
	hkdfLabel[3+len(fullLabel)] = byte(len(context))
	copy(hkdfLabel[4+len(fullLabel):], context)

	reader := hkdf.Expand(h, secret, hkdfLabel)
	result := make([]byte, length)
	io.ReadFull(reader, result)
	return result
}

// Enable attempts to enable kTLS for the given connection.
// Returns a wrapped connection that uses raw socket I/O if successful, nil otherwise.
// After calling this, the original tlsConn should NOT be used for I/O.
func Enable(tlsConn *tls.Conn) *Conn {
	if !Supported() {
		fallbackConns.Add(1)
		return nil
	}

	// Extract TLS state
	state, err := extractTLSState(tlsConn)
	if err != nil {
		log.Debug("kTLS: cannot extract state: %v", err)
		fallbackConns.Add(1)
		return nil
	}

	// Get underlying TCP connection
	netConn := tlsConn.NetConn()

	// Try to unwrap bufferedConn or other wrappers
	var tcpConn *net.TCPConn
	for {
		if tc, ok := netConn.(*net.TCPConn); ok {
			tcpConn = tc
			break
		}

		// Check if it's a wrapper with embedded net.Conn
		v := reflect.ValueOf(netConn)
		if v.Kind() == reflect.Pointer {
			v = v.Elem()
		}

		// Look for embedded net.Conn field
		connField := v.FieldByName("Conn")
		if connField.IsValid() && connField.Type().Implements(reflect.TypeOf((*net.Conn)(nil)).Elem()) {
			netConn = connField.Interface().(net.Conn)
			continue
		}

		log.Debug("kTLS: not a TCP connection (type=%T)", netConn)
		fallbackConns.Add(1)
		return nil
	}

	// Get raw file descriptor for setsockopt
	rawConn, err := tcpConn.SyscallConn()
	if err != nil {
		log.Debug("kTLS: cannot get syscall conn: %v", err)
		fallbackConns.Add(1)
		return nil
	}

	var enableErr error
	err = rawConn.Control(func(fd uintptr) {
		enableErr = enableKTLS(int(fd), state)
	})

	if err != nil || enableErr != nil {
		log.Debug("kTLS: enable failed: %v / %v", err, enableErr)
		fallbackConns.Add(1)
		return nil
	}

	enabledConns.Add(1)
	log.Debug("kTLS: enabled for connection (cipher: 0x%04x, inSeq: %d, outSeq: %d)",
		state.CipherSuite,
		uint64(state.InSeq[0])<<56|uint64(state.InSeq[1])<<48|uint64(state.InSeq[2])<<40|uint64(state.InSeq[3])<<32|
			uint64(state.InSeq[4])<<24|uint64(state.InSeq[5])<<16|uint64(state.InSeq[6])<<8|uint64(state.InSeq[7]),
		uint64(state.OutSeq[0])<<56|uint64(state.OutSeq[1])<<48|uint64(state.OutSeq[2])<<40|uint64(state.OutSeq[3])<<32|
			uint64(state.OutSeq[4])<<24|uint64(state.OutSeq[5])<<16|uint64(state.OutSeq[6])<<8|uint64(state.OutSeq[7]))

	// Create wrapped connection - uses tcpConn directly for I/O
	// After kTLS is enabled, the kernel handles encryption/decryption transparently
	ktlsConn := &Conn{
		tcpConn: tcpConn,
		tlsConn: tlsConn,
	}

	return ktlsConn
}

// enableKTLS sets up kernel TLS on the socket
func enableKTLS(fd int, state *tlsConnState) error {
	// First, enable TLS ULP
	err := syscall.SetsockoptString(fd, syscall.SOL_TCP, 31 /* TCP_ULP */, "tls")
	if err != nil {
		return fmt.Errorf("TCP_ULP failed: %w", err)
	}

	// Derive keys from traffic secrets
	txKey, txIV, err := deriveKeys(state.OutTrafficSecret, state.CipherSuite)
	if err != nil {
		return fmt.Errorf("derive TX keys failed: %w", err)
	}

	rxKey, rxIV, err := deriveKeys(state.InTrafficSecret, state.CipherSuite)
	if err != nil {
		return fmt.Errorf("derive RX keys failed: %w", err)
	}

	// Set TX (write) crypto info
	if err := setCryptoInfo(fd, TLS_TX, state.CipherSuite, txKey, txIV, state.OutSeq); err != nil {
		return fmt.Errorf("set TX crypto failed: %w", err)
	}

	// Set RX (read) crypto info
	if err := setCryptoInfo(fd, TLS_RX, state.CipherSuite, rxKey, rxIV, state.InSeq); err != nil {
		return fmt.Errorf("set RX crypto failed: %w", err)
	}

	return nil
}

// setCryptoInfo sets the crypto info for TX or RX direction
func setCryptoInfo(fd int, direction int, cipherSuite uint16, key, iv []byte, seq [8]byte) error {
	switch cipherSuite {
	case TLS_AES_128_GCM_SHA256:
		info := tlsCryptoInfoAESGCM128{
			Version:    TLS_1_3_VERSION,
			CipherType: TLS_CIPHER_AES_GCM_128,
		}
		copy(info.Salt[:], iv[:4])
		copy(info.IV[:], iv[4:])
		copy(info.Key[:], key)
		copy(info.RecSeq[:], seq[:])

		_, _, errno := syscall.Syscall6(
			syscall.SYS_SETSOCKOPT,
			uintptr(fd),
			SOL_TLS,
			uintptr(direction),
			uintptr(unsafe.Pointer(&info)),
			unsafe.Sizeof(info),
			0,
		)
		if errno != 0 {
			return errno
		}

	case TLS_AES_256_GCM_SHA384:
		info := tlsCryptoInfoAESGCM256{
			Version:    TLS_1_3_VERSION,
			CipherType: TLS_CIPHER_AES_GCM_256,
		}
		copy(info.Salt[:], iv[:4])
		copy(info.IV[:], iv[4:])
		copy(info.Key[:], key)
		copy(info.RecSeq[:], seq[:])

		_, _, errno := syscall.Syscall6(
			syscall.SYS_SETSOCKOPT,
			uintptr(fd),
			SOL_TLS,
			uintptr(direction),
			uintptr(unsafe.Pointer(&info)),
			unsafe.Sizeof(info),
			0,
		)
		if errno != 0 {
			return errno
		}

	case TLS_CHACHA20_POLY1305_SHA256:
		info := tlsCryptoInfoChaCha20Poly1305{
			Version:    TLS_1_3_VERSION,
			CipherType: TLS_CIPHER_CHACHA20_POLY1305,
		}
		copy(info.IV[:], iv)
		copy(info.Key[:], key)
		copy(info.RecSeq[:], seq[:])

		_, _, errno := syscall.Syscall6(
			syscall.SYS_SETSOCKOPT,
			uintptr(fd),
			SOL_TLS,
			uintptr(direction),
			uintptr(unsafe.Pointer(&info)),
			unsafe.Sizeof(info),
			0,
		)
		if errno != 0 {
			return errno
		}

	default:
		return fmt.Errorf("unsupported cipher suite: 0x%04x", cipherSuite)
	}

	return nil
}

func init() {
	// Check support on startup
	checkSupport()
}
