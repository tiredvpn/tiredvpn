package evasion

import (
	"bytes"
	"crypto/rand"
	"encoding/binary"
	"errors"
	"net"
	"sync"
	"time"

	"github.com/tiredvpn/tiredvpn/internal/log"
)

// QUICCryptoFragmenter fragments QUIC CRYPTO frames to bypass GFW SNI inspection
// GFW does NOT reassemble fragmented CRYPTO frames, allowing SNI to be hidden
type QUICCryptoFragmenter struct {
	config *QUICFragmentConfig
}

// QUICFragmentConfig configures QUIC CRYPTO frame fragmentation
type QUICFragmentConfig struct {
	// Enabled turns fragmentation on/off
	Enabled bool

	// FragmentSize is the maximum size of each CRYPTO frame fragment
	// Smaller = more fragments = harder to reassemble
	// Default: 50 bytes (splits SNI across 2-3 frames)
	FragmentSize int

	// DelayBetweenFragments adds delay between fragments
	// Can help bypass timing-based detection
	DelayBetweenFragments time.Duration

	// ShuffleFragments randomizes fragment order
	// GFW may struggle with out-of-order reassembly
	ShuffleFragments bool

	// AddPaddingFrames inserts PADDING frames between CRYPTO frames
	AddPaddingFrames bool

	// PaddingFrameCount is number of padding frames to add
	PaddingFrameCount int

	// SplitAtSNI specifically targets SNI field for splitting
	// Ensures the SNI hostname is split across frame boundaries
	SplitAtSNI bool
}

// DefaultQUICFragmentConfig returns sensible defaults for GFW bypass
func DefaultQUICFragmentConfig() *QUICFragmentConfig {
	return &QUICFragmentConfig{
		Enabled:               true,
		FragmentSize:          50, // Small fragments
		DelayBetweenFragments: 1 * time.Millisecond,
		ShuffleFragments:      false, // Can cause issues with some servers
		AddPaddingFrames:      true,
		PaddingFrameCount:     2,
		SplitAtSNI:            true,
	}
}

// NewQUICCryptoFragmenter creates a new fragmenter
func NewQUICCryptoFragmenter(config *QUICFragmentConfig) *QUICCryptoFragmenter {
	if config == nil {
		config = DefaultQUICFragmentConfig()
	}
	return &QUICCryptoFragmenter{config: config}
}

// CryptoFrame represents a QUIC CRYPTO frame
type CryptoFrame struct {
	Offset uint64
	Data   []byte
}

// FragmentCryptoFrame splits a CRYPTO frame into multiple smaller frames
func (f *QUICCryptoFragmenter) FragmentCryptoFrame(data []byte) []CryptoFrame {
	if !f.config.Enabled || len(data) <= f.config.FragmentSize {
		return []CryptoFrame{{Offset: 0, Data: data}}
	}

	fragments := []CryptoFrame{}
	offset := uint64(0)

	// If SplitAtSNI, find SNI offset and ensure split there
	var sniOffset int
	if f.config.SplitAtSNI {
		sniOffset = findSNIOffset(data)
		log.Debug("SNI offset in ClientHello: %d", sniOffset)
	}

	for len(data) > 0 {
		fragSize := f.config.FragmentSize
		if fragSize > len(data) {
			fragSize = len(data)
		}

		// If SplitAtSNI is enabled and we haven't passed SNI yet
		if f.config.SplitAtSNI && sniOffset > 0 && int(offset) < sniOffset && int(offset)+fragSize >= sniOffset {
			// Split exactly at SNI offset
			fragSize = sniOffset - int(offset)
			if fragSize <= 0 {
				fragSize = f.config.FragmentSize / 2 // Split in middle of SNI
			}
		}

		fragments = append(fragments, CryptoFrame{
			Offset: offset,
			Data:   data[:fragSize],
		})

		data = data[fragSize:]
		offset += uint64(fragSize)
	}

	log.Debug("Fragmented CRYPTO frame into %d fragments", len(fragments))
	return fragments
}

// findSNIOffset finds the offset of SNI extension in ClientHello
func findSNIOffset(data []byte) int {
	// ClientHello structure:
	// [0]: HandshakeType (1 byte)
	// [1-3]: Length (3 bytes)
	// [4-5]: Version (2 bytes)
	// [6-37]: Random (32 bytes)
	// [38]: Session ID Length (1 byte)
	// [...]: Session ID
	// [...]: Cipher Suites
	// [...]: Compression Methods
	// [...]: Extensions

	if len(data) < 44 {
		return -1
	}

	// Skip to Session ID
	offset := 38
	if offset >= len(data) {
		return -1
	}
	sessionIDLen := int(data[offset])
	offset += 1 + sessionIDLen

	// Skip Cipher Suites
	if offset+2 > len(data) {
		return -1
	}
	cipherLen := int(binary.BigEndian.Uint16(data[offset:]))
	offset += 2 + cipherLen

	// Skip Compression Methods
	if offset >= len(data) {
		return -1
	}
	compLen := int(data[offset])
	offset += 1 + compLen

	// Now at extensions
	if offset+2 > len(data) {
		return -1
	}
	extLen := int(binary.BigEndian.Uint16(data[offset:]))
	offset += 2

	// Search for SNI extension (type 0x0000)
	extEnd := offset + extLen
	for offset+4 <= extEnd && offset+4 <= len(data) {
		extType := binary.BigEndian.Uint16(data[offset:])
		extDataLen := int(binary.BigEndian.Uint16(data[offset+2:]))

		if extType == 0x0000 { // SNI extension
			// Found SNI, return offset to the hostname
			// SNI format: [list_len:2][name_type:1][name_len:2][name]
			sniDataOffset := offset + 4 + 2 + 1 + 2 // Skip to hostname
			return sniDataOffset
		}

		offset += 4 + extDataLen
	}

	return -1
}

// QUICFragmentPacketConn wraps net.PacketConn with UDP datagram fragmentation
// This splits large Initial packets into multiple UDP datagrams with a custom header
// to bypass GFW that doesn't reassemble UDP fragments
type QUICFragmentPacketConn struct {
	net.PacketConn
	config *QUICFragmentConfig

	mu sync.Mutex
}

// Fragment header format:
// [MAGIC:2][SEQ:2][TOTAL:2][FRAG_ID:4][DATA...]
// MAGIC = 0x54 0x46 ("TF" for TiredFragment)
// SEQ = fragment sequence number (0-based)
// TOTAL = total fragment count
// FRAG_ID = random ID to group fragments
const (
	fragMagic1     = 0x54
	fragMagic2     = 0x46
	fragHeaderSize = 10 // 2 magic + 2 seq + 2 total + 4 fragID
)

// NewQUICFragmentPacketConn creates a fragmenting PacketConn wrapper
func NewQUICFragmentPacketConn(conn net.PacketConn, config *QUICFragmentConfig) *QUICFragmentPacketConn {
	if config == nil {
		config = DefaultQUICFragmentConfig()
	}
	return &QUICFragmentPacketConn{
		PacketConn: conn,
		config:     config,
	}
}

// WriteTo sends packet with UDP fragmentation for Initial packets
func (c *QUICFragmentPacketConn) WriteTo(p []byte, addr net.Addr) (int, error) {
	c.mu.Lock()
	defer c.mu.Unlock()

	if !c.config.Enabled || len(p) < 10 {
		return c.PacketConn.WriteTo(p, addr)
	}

	// Only fragment QUIC Initial packets (contains ClientHello with SNI)
	if !isQUICInitialPacket(p) {
		return c.PacketConn.WriteTo(p, addr)
	}

	log.Debug("Fragmenting QUIC Initial packet, size=%d", len(p))

	// Generate random fragment ID
	fragID := make([]byte, 4)
	rand.Read(fragID)

	// Calculate fragment count
	dataSize := c.config.FragmentSize
	if dataSize < 50 {
		dataSize = 50
	}
	fragCount := (len(p) + dataSize - 1) / dataSize
	if fragCount > 255 {
		fragCount = 255
		dataSize = (len(p) + 254) / 255
	}

	log.Debug("Fragmenting QUIC Initial packet into %d fragments of ~%d bytes", fragCount, dataSize)

	// Send fragments
	offset := 0
	for i := 0; i < fragCount; i++ {
		end := offset + dataSize
		if end > len(p) {
			end = len(p)
		}

		// Build fragment: [HEADER][DATA]
		frag := make([]byte, fragHeaderSize+end-offset)
		frag[0] = fragMagic1
		frag[1] = fragMagic2
		frag[2] = byte(i >> 8)
		frag[3] = byte(i)
		frag[4] = byte(fragCount >> 8)
		frag[5] = byte(fragCount)
		copy(frag[6:10], fragID)
		copy(frag[fragHeaderSize:], p[offset:end])

		_, err := c.PacketConn.WriteTo(frag, addr)
		if err != nil {
			return offset, err
		}

		offset = end

		// Delay between fragments
		if c.config.DelayBetweenFragments > 0 && i < fragCount-1 {
			time.Sleep(c.config.DelayBetweenFragments)
		}
	}

	log.Debug("Sent %d fragments for QUIC Initial", fragCount)
	return len(p), nil
}

// isQUICInitialPacket checks if packet is a QUIC Initial packet
func isQUICInitialPacket(p []byte) bool {
	if len(p) < 5 {
		return false
	}
	// Long Header (bit 7 = 1) + Initial (bits 4-5 = 00)
	return p[0]&0x80 != 0 && p[0]&0x30 == 0x00
}

// parseQUICInitialForCrypto parses QUIC Initial packet and extracts CRYPTO frame
func parseQUICInitialForCrypto(p []byte) (cryptoOffset int, cryptoData []byte, header []byte, trailer []byte) {
	if len(p) < 10 {
		return 0, nil, nil, nil
	}

	// QUIC Initial packet format:
	// [0]: Header byte
	// [1-4]: Version
	// [5]: DCID Length
	// [6...]: DCID
	// [...]: SCID Length + SCID
	// [...]: Token Length (var int) + Token
	// [...]: Length (var int)
	// [...]: Packet Number (1-4 bytes based on header)
	// [...]: Payload (frames)

	offset := 5
	if offset >= len(p) {
		return 0, nil, nil, nil
	}

	// DCID
	dcidLen := int(p[offset])
	offset += 1 + dcidLen
	if offset >= len(p) {
		return 0, nil, nil, nil
	}

	// SCID
	scidLen := int(p[offset])
	offset += 1 + scidLen
	if offset >= len(p) {
		return 0, nil, nil, nil
	}

	// Token Length (variable length integer)
	tokenLen, tokenLenSize := readVarInt(p[offset:])
	offset += tokenLenSize + int(tokenLen)
	if offset >= len(p) {
		return 0, nil, nil, nil
	}

	// Length (variable length integer)
	payloadLen, lengthSize := readVarInt(p[offset:])
	offset += lengthSize
	if offset >= len(p) {
		return 0, nil, nil, nil
	}

	// Packet number (length from header byte, bits 0-1)
	pnLen := int(p[0]&0x03) + 1
	offset += pnLen

	// Now at payload (frames)
	// Note: Payload is encrypted in real QUIC, this only works for testing
	// or when we're building our own packets
	header = p[:offset]

	// Search for CRYPTO frame (type 0x06)
	for offset < len(p) && offset < int(offset)+int(payloadLen) {
		if p[offset] == 0x06 { // CRYPTO frame
			cryptoOffset = offset

			// Read CRYPTO frame header
			frameOffset, foSize := readVarInt(p[offset+1:])
			_ = frameOffset
			cryptoLen, clSize := readVarInt(p[offset+1+foSize:])

			dataStart := offset + 1 + foSize + clSize
			dataEnd := dataStart + int(cryptoLen)

			if dataEnd <= len(p) {
				cryptoData = p[dataStart:dataEnd]
				trailer = p[dataEnd:]
				return cryptoOffset, cryptoData, header, trailer
			}
		}
		offset++
	}

	return 0, nil, nil, nil
}

// readVarInt reads QUIC variable length integer
func readVarInt(b []byte) (uint64, int) {
	if len(b) == 0 {
		return 0, 0
	}

	prefix := b[0] >> 6
	switch prefix {
	case 0:
		return uint64(b[0] & 0x3f), 1
	case 1:
		if len(b) < 2 {
			return 0, 0
		}
		return uint64(b[0]&0x3f)<<8 | uint64(b[1]), 2
	case 2:
		if len(b) < 4 {
			return 0, 0
		}
		return uint64(b[0]&0x3f)<<24 | uint64(b[1])<<16 | uint64(b[2])<<8 | uint64(b[3]), 4
	case 3:
		if len(b) < 8 {
			return 0, 0
		}
		return uint64(b[0]&0x3f)<<56 | uint64(b[1])<<48 | uint64(b[2])<<40 | uint64(b[3])<<32 |
			uint64(b[4])<<24 | uint64(b[5])<<16 | uint64(b[6])<<8 | uint64(b[7]), 8
	}
	return 0, 0
}

// writeVarInt writes QUIC variable length integer
func writeVarInt(buf *bytes.Buffer, v uint64) {
	if v < 0x40 {
		buf.WriteByte(byte(v))
	} else if v < 0x4000 {
		buf.WriteByte(byte(v>>8) | 0x40)
		buf.WriteByte(byte(v))
	} else if v < 0x40000000 {
		buf.WriteByte(byte(v>>24) | 0x80)
		buf.WriteByte(byte(v >> 16))
		buf.WriteByte(byte(v >> 8))
		buf.WriteByte(byte(v))
	} else {
		buf.WriteByte(byte(v>>56) | 0xc0)
		buf.WriteByte(byte(v >> 48))
		buf.WriteByte(byte(v >> 40))
		buf.WriteByte(byte(v >> 32))
		buf.WriteByte(byte(v >> 24))
		buf.WriteByte(byte(v >> 16))
		buf.WriteByte(byte(v >> 8))
		buf.WriteByte(byte(v))
	}
}


// ChromeChaosProtection implements Chrome's Chaos Protection mechanism
// Disperses QUIC client Initial message into multiple QUIC frames shuffled across UDP datagrams
type ChromeChaosProtection struct {
	enabled       bool
	shuffleFrames bool
	maxFrameSize  int
}

// NewChromeChaosProtection creates a Chrome-style chaos protection
func NewChromeChaosProtection() *ChromeChaosProtection {
	return &ChromeChaosProtection{
		enabled:       true,
		shuffleFrames: true,
		maxFrameSize:  100,
	}
}

// ApplyChaos applies Chrome's chaos protection to QUIC Initial
func (c *ChromeChaosProtection) ApplyChaos(initialPacket []byte) ([][]byte, error) {
	if !c.enabled {
		return [][]byte{initialPacket}, nil
	}

	// Split into multiple UDP datagrams
	// Each datagram contains partial CRYPTO frame
	datagrams := [][]byte{}

	// For now, simple fragmentation
	// Real Chrome chaos is more complex with shuffling
	fragmenter := NewQUICCryptoFragmenter(&QUICFragmentConfig{
		Enabled:          true,
		FragmentSize:     c.maxFrameSize,
		ShuffleFragments: c.shuffleFrames,
	})

	_, cryptoData, header, trailer := parseQUICInitialForCrypto(initialPacket)
	if cryptoData == nil {
		return [][]byte{initialPacket}, nil
	}

	fragments := fragmenter.FragmentCryptoFrame(cryptoData)

	for _, frag := range fragments {
		var buf bytes.Buffer
		buf.Write(header)
		buf.WriteByte(0x06) // CRYPTO
		writeVarInt(&buf, frag.Offset)
		writeVarInt(&buf, uint64(len(frag.Data)))
		buf.Write(frag.Data)
		buf.Write(trailer)
		datagrams = append(datagrams, buf.Bytes())
	}

	return datagrams, nil
}

// Ensure interface compliance
var (
	_ net.PacketConn = (*QUICFragmentPacketConn)(nil)
)

// Error definitions
var (
	ErrNotQUICInitial   = errors.New("not a QUIC Initial packet")
	ErrNoCryptoFrame    = errors.New("no CRYPTO frame found")
	ErrFragmentTooSmall = errors.New("fragment size too small")
)
