package padding

import (
	"crypto/rand"
	"crypto/subtle"
	"encoding/binary"
	"errors"
	"fmt"

	"golang.org/x/crypto/blake2b"
)

// PaddingLevel defines the aggressiveness of padding obfuscation
type PaddingLevel int

const (
	// Conservative adds 5-10% padding overhead (minimal impact, good for stable connections)
	Conservative PaddingLevel = iota
	// Balanced adds 15-25% padding overhead (default, good balance)
	Balanced
	// Aggressive adds 30-50% padding overhead (maximum obfuscation, higher latency)
	Aggressive
)

// String returns the string representation of PaddingLevel
func (p PaddingLevel) String() string {
	switch p {
	case Conservative:
		return "Conservative"
	case Balanced:
		return "Balanced"
	case Aggressive:
		return "Aggressive"
	default:
		return "Unknown"
	}
}

// SalamanderPadder implements BLAKE2b-256 based cryptographic padding (Hysteria2-style)
// Each packet: [salt:8][XOR(data, BLAKE2b(salt || secret))][random padding]
type SalamanderPadder struct {
	secret  []byte
	level   PaddingLevel
	buckets []int // Packet size buckets for normalization

	// maxDatagram caps every datagram EncryptUDP puts on the wire; see
	// defaultMaxDatagram. dgramBuckets is the bucket ladder trimmed to that cap
	// and terminated by it, so the datagram path always has a rung to pad to.
	maxDatagram  int
	dgramBuckets []int
}

// NewSalamanderPadder creates a new Salamander padder with specified level
func NewSalamanderPadder(secret []byte, level PaddingLevel) *SalamanderPadder {
	sp := &SalamanderPadder{
		secret:      secret,
		level:       level,
		maxDatagram: defaultMaxDatagram,
	}

	// Initialize buckets based on level
	sp.buckets = getBucketsForLevel(level)
	sp.dgramBuckets = datagramLadder(sp.buckets, sp.maxDatagram)

	return sp
}

// SetMaxDatagram lowers the ceiling on datagram sizes, for callers that know a
// smaller path MTU than defaultMaxDatagram assumes. Payloads that no longer fit
// underneath it are split by EncryptUDPDatagrams rather than sent oversized.
func (sp *SalamanderPadder) SetMaxDatagram(max int) {
	if max < minMaxDatagram {
		max = minMaxDatagram
	}
	sp.maxDatagram = max
	sp.dgramBuckets = datagramLadder(sp.buckets, max)
}

// MaxDatagram returns the current datagram ceiling.
func (sp *SalamanderPadder) MaxDatagram() int { return sp.maxDatagram }

// Encrypt obfuscates plaintext data with Salamander padding
func (sp *SalamanderPadder) Encrypt(plaintext []byte) ([]byte, error) {
	if len(plaintext) == 0 {
		return nil, errors.New("salamander: empty plaintext")
	}
	if len(sp.secret) > 64 {
		return nil, errors.New("salamander: secret too long (max 64 bytes for BLAKE2b)")
	}

	// 1. Generate random salt (8 bytes) plus the entropy the size jitter draws
	//    from, in one CSPRNG read.
	seed := make([]byte, 8+4)
	if _, err := rand.Read(seed); err != nil {
		return nil, err
	}
	salt := seed[:8]

	// 2. Derive 32-byte hash from salt + secret using BLAKE2b-256
	h, err := blake2b.New256(sp.secret)
	if err != nil {
		return nil, err
	}
	h.Write(salt)
	hash := h.Sum(nil) // 32 bytes

	// 3. XOR plaintext with hash (cycling through hash bytes)
	encrypted := make([]byte, len(plaintext))
	for i, b := range plaintext {
		encrypted[i] = b ^ hash[i%32]
	}

	// 4. Determine target size: bucket floor plus jitter. The stream ladder
	//    repeats its top rung above the largest bucket, so a long record is
	//    still normalised instead of travelling at its exact length.
	targetSize := sp.streamTarget(len(plaintext), seed[8:])

	// 5. Calculate padding length (accounting for salt overhead)
	totalDataLen := 8 + len(encrypted) // salt + encrypted
	paddingLen := targetSize - totalDataLen

	if paddingLen < 0 {
		paddingLen = 0 // unreachable: streamTarget never returns below required
	}

	// 6. Generate random padding
	padding := make([]byte, paddingLen)
	if paddingLen > 0 {
		if _, err := rand.Read(padding); err != nil {
			return nil, fmt.Errorf("failed to generate padding: %w", err)
		}
	}

	// 7. Assemble final packet: [salt:8][encrypted][padding]
	result := make([]byte, 0, 8+len(encrypted)+paddingLen)
	result = append(result, salt...)
	result = append(result, encrypted...)
	result = append(result, padding...)

	return result, nil
}

// Decrypt recovers plaintext from Salamander-encrypted data
func (sp *SalamanderPadder) Decrypt(ciphertext []byte) ([]byte, error) {
	if len(ciphertext) < 8 {
		return nil, errors.New("salamander: ciphertext too short")
	}

	// 1. Extract salt (first 8 bytes)
	salt := ciphertext[:8]

	// 2. Derive same hash from salt + secret
	h, err := blake2b.New256(sp.secret)
	if err != nil {
		return nil, err
	}
	h.Write(salt)
	hash := h.Sum(nil)

	// 3. XOR encrypted data (rest of ciphertext, including padding)
	encrypted := ciphertext[8:]
	plaintext := make([]byte, len(encrypted))
	for i, b := range encrypted {
		plaintext[i] = b ^ hash[i%32]
	}

	// Note: We cannot know exact plaintext length here without additional framing
	// The caller must handle length detection (e.g., via WebSocket frame length or length prefix)
	// For now, return full decrypted data including padding

	return plaintext, nil
}

// udpTagLen is the width of the keyed authenticity tag carried by the UDP/QUIC
// framing. It sets the odds that a packet encrypted under a foreign secret
// survives the check: 2^-udpTagLen*8. The previous width of 2 bytes gave 2^-16,
// i.e. one bogus accept per ~65k trials - a server holding a few thousand
// per-client secrets trials each of them against every unmatched packet, so at
// that width false accepts are an operational event, not a theoretical one. At
// 8 bytes the same server needs on the order of 10^19 trials before the first
// one, which is out of reach of any traffic volume this code will ever see.
//
// The six extra bytes cost nothing on the wire in the common case: EncryptUDP
// pads to a fixed size bucket, so a wider tag only eats into the random padding
// and the datagram an observer measures is unchanged. The exceptions are
// payloads within six bytes below a bucket boundary, which move up one bucket,
// and payloads above the largest bucket, where no padding applies at all and
// the datagram grows by six. See TestSalamanderUDPWireSizeStable.
const udpTagLen = 8

// udpHeaderLen is the framing that precedes the payload inside the masked
// region: [tag:udpTagLen][lenHi][lenLo].
const udpHeaderLen = udpTagLen + 2

// keyTag derives a deterministic verification tag from the secret and salt. It
// is used by the UDP/QUIC framing to confirm that a packet was encrypted with
// the same secret before trusting the (XOR-only, unauthenticated) length
// prefix. A wrong secret yields a different keystream and therefore a different
// tag, so mismatches are rejected deterministically instead of being guessed at
// via header heuristics.
func (sp *SalamanderPadder) keyTag(salt []byte) ([udpTagLen]byte, error) {
	var tag [udpTagLen]byte
	h, err := blake2b.New256(sp.secret)
	if err != nil {
		return tag, err
	}
	// Domain-separate the tag from the XOR keystream so the tag never leaks
	// keystream bytes used to mask the payload.
	h.Write([]byte("tag"))
	h.Write(salt)
	copy(tag[:], h.Sum(nil))
	return tag, nil
}

// EncryptUDP frames a single UDP/QUIC payload for transmission. The inner
// plaintext layout is [tag:udpTagLen][lenHi][lenLo][payload], which is then
// masked with the keystream and padded to a bucket. The tag lets the receiver
// verify the secret deterministically.
//
// It fails when the payload cannot travel whole under the datagram ceiling.
// Callers that must handle such payloads use EncryptUDPDatagrams, which splits
// them; what neither of them does any more is send an oversized payload with no
// padding at all, which put its exact length on the wire.
func (sp *SalamanderPadder) EncryptUDP(payload []byte) ([]byte, error) {
	if len(payload) > maxUDPPayload {
		return nil, fmt.Errorf("salamander: payload too large (%d > %d)", len(payload), maxUDPPayload)
	}
	return sp.encryptUDPFrame(payload, nil)
}

// EncryptUDPDatagrams frames a payload as one or more datagrams, none of them
// larger than the datagram ceiling. A payload that fits comes back as a single
// datagram byte-identical in shape to EncryptUDP's; one that does not is split
// into near-equal chunks, each carrying the group id, its index and the group
// size inside the masked region, and each padded to a bucket of its own.
//
// Rule 8 (a fix breeds a new signature): this trades one leak for one. The old
// behaviour put the exact payload length on the wire; the split instead emits a
// burst of N datagrams that an observer can correlate by arrival time. No
// measurement backs either side of that trade - see paddingJitterWidth - but
// the split only engages above the ceiling, which QUIC's own path MTU discovery
// keeps it below in every configuration this code ships with.
func (sp *SalamanderPadder) EncryptUDPDatagrams(payload []byte) ([][]byte, error) {
	if len(payload) > maxUDPPayload {
		return nil, fmt.Errorf("salamander: payload too large (%d > %d)", len(payload), maxUDPPayload)
	}

	if sp.fitsOneDatagram(udpHeaderLen + len(payload)) {
		dgram, err := sp.encryptUDPFrame(payload, nil)
		if err != nil {
			return nil, err
		}
		return [][]byte{dgram}, nil
	}

	chunkMax := sp.maxDatagram - 8 - fragHeaderLen
	count := (len(payload) + chunkMax - 1) / chunkMax
	if count > maxFragmentsPerPayload {
		return nil, fmt.Errorf("salamander: payload of %d bytes needs %d fragments (max %d)",
			len(payload), count, maxFragmentsPerPayload)
	}

	var idBuf [4]byte
	if _, err := rand.Read(idBuf[:]); err != nil {
		return nil, err
	}
	id := binary.BigEndian.Uint32(idBuf[:])

	// Even chunks rather than "fill, fill, remainder": a short trailing chunk
	// would announce len(payload) mod chunkMax through its own bucket.
	chunk := (len(payload) + count - 1) / count

	out := make([][]byte, 0, count)
	for i := 0; i < count; i++ {
		lo := i * chunk
		hi := lo + chunk
		if hi > len(payload) {
			hi = len(payload)
		}
		dgram, err := sp.encryptUDPFrame(payload[lo:hi], &fragMeta{id: id, index: i, count: count})
		if err != nil {
			return nil, err
		}
		out = append(out, dgram)
	}
	return out, nil
}

// fitsOneDatagram reports whether an inner frame of innerLen bytes has a rung
// to pad to under the datagram ceiling.
func (sp *SalamanderPadder) fitsOneDatagram(innerLen int) bool {
	_, _, ok := floorAndCeil(sp.dgramBuckets, innerLen+8)
	return ok
}

// encryptUDPFrame builds one datagram. With frag nil the inner layout is
// [tag][lenHi][lenLo][payload]; otherwise lenHi carries fragFlag and six bytes
// of group id, index and count sit between the length and the chunk. The
// fragment header lives inside the masked region, so nothing about the split is
// visible to an observer - unlike a cleartext fragment magic.
func (sp *SalamanderPadder) encryptUDPFrame(chunk []byte, frag *fragMeta) ([]byte, error) {
	if len(chunk) > maxFrameChunk {
		return nil, fmt.Errorf("salamander: frame chunk too large (%d > %d)", len(chunk), maxFrameChunk)
	}

	hdrLen := udpHeaderLen
	if frag != nil {
		hdrLen = fragHeaderLen
	}

	inner := make([]byte, hdrLen+len(chunk))
	// tag is filled after we know the salt, so encrypt manually below.
	lenHi := byte(len(chunk) >> 8)
	if frag != nil {
		lenHi |= fragFlag
	}
	inner[udpTagLen] = lenHi
	inner[udpTagLen+1] = byte(len(chunk))
	if frag != nil {
		binary.BigEndian.PutUint32(inner[udpHeaderLen:udpHeaderLen+4], frag.id)
		inner[udpHeaderLen+4] = byte(frag.index)
		inner[udpHeaderLen+5] = byte(frag.count)
	}
	copy(inner[hdrLen:], chunk)

	// Generate salt + jitter entropy in one read, then the keystream exactly
	// like Encrypt, but inject the tag.
	seed := make([]byte, 8+4)
	if _, err := rand.Read(seed); err != nil {
		return nil, err
	}
	salt := seed[:8]
	tag, err := sp.keyTag(salt)
	if err != nil {
		return nil, err
	}
	copy(inner[:udpTagLen], tag[:])

	h, err := blake2b.New256(sp.secret)
	if err != nil {
		return nil, err
	}
	h.Write(salt)
	hash := h.Sum(nil)

	encrypted := make([]byte, len(inner))
	for i, b := range inner {
		encrypted[i] = b ^ hash[i%32]
	}

	targetSize, ok := sp.datagramTarget(len(inner), seed[8:])
	if !ok {
		return nil, fmt.Errorf("salamander: frame of %d bytes exceeds the %d-byte datagram ceiling",
			8+len(inner), sp.maxDatagram)
	}
	paddingLen := targetSize - 8 - len(encrypted)
	if paddingLen < 0 {
		paddingLen = 0 // unreachable: datagramTarget never returns below required
	}
	padding := make([]byte, paddingLen)
	if paddingLen > 0 {
		if _, err := rand.Read(padding); err != nil {
			return nil, fmt.Errorf("failed to generate padding: %w", err)
		}
	}

	result := make([]byte, 0, 8+len(encrypted)+paddingLen)
	result = append(result, salt...)
	result = append(result, encrypted...)
	result = append(result, padding...)
	return result, nil
}

// DecryptUDP reverses EncryptUDP. It returns the original payload only if the
// embedded tag matches the secret; otherwise ok is false. This is the
// authoritative secret-match check for the UDP/QUIC transport.
//
// A datagram that is one fragment of a split payload is rejected here: it
// carries a chunk, not a payload. Callers that must handle split payloads use
// decryptUDPFrame together with a fragReassembler.
func (sp *SalamanderPadder) DecryptUDP(ciphertext []byte) (payload []byte, ok bool) {
	frame, ok := sp.decryptUDPFrame(ciphertext)
	if !ok || frame.frag {
		return nil, false
	}
	return frame.data, true
}

// decryptUDPFrame verifies the tag and unmasks one datagram, reporting whether
// it carries a whole payload or one chunk of a split one.
func (sp *SalamanderPadder) decryptUDPFrame(ciphertext []byte) (udpFrame, bool) {
	var frame udpFrame

	if len(ciphertext) < 8+udpHeaderLen {
		return frame, false
	}
	salt := ciphertext[:8]

	wantTag, err := sp.keyTag(salt)
	if err != nil {
		return frame, false
	}

	h, err := blake2b.New256(sp.secret)
	if err != nil {
		return frame, false
	}
	h.Write(salt)
	hash := h.Sum(nil)

	enc := ciphertext[8:]
	// Decrypt just the header first (tag + length) to validate cheaply.
	var hdr [fragHeaderLen]byte
	for i := 0; i < udpHeaderLen; i++ {
		hdr[i] = enc[i] ^ hash[i%32]
	}
	// Constant-time so the number of leading tag bytes an attacker got right is
	// not readable from how long the reject took. MultiSecret trials this per
	// registered secret, which would otherwise be a convenient amplifier.
	if subtle.ConstantTimeCompare(hdr[:udpTagLen], wantTag[:]) != 1 {
		return frame, false
	}

	lenHi := hdr[udpTagLen]
	dataLen := int(lenHi&fragLenMask)<<8 | int(hdr[udpTagLen+1])

	hdrLen := udpHeaderLen
	if lenHi&fragFlag != 0 {
		hdrLen = fragHeaderLen
		if len(enc) < fragHeaderLen {
			return frame, false
		}
		for i := udpHeaderLen; i < fragHeaderLen; i++ {
			hdr[i] = enc[i] ^ hash[i%32]
		}
		frame.frag = true
		frame.id = binary.BigEndian.Uint32(hdr[udpHeaderLen : udpHeaderLen+4])
		frame.index = int(hdr[udpHeaderLen+4])
		frame.count = int(hdr[udpHeaderLen+5])
		if frame.count == 0 || frame.count > maxFragmentsPerPayload || frame.index >= frame.count {
			return frame, false
		}
	}

	if hdrLen+dataLen > len(enc) {
		return frame, false
	}

	frame.data = make([]byte, dataLen)
	for i := 0; i < dataLen; i++ {
		frame.data[i] = enc[hdrLen+i] ^ hash[(hdrLen+i)%32]
	}
	return frame, true
}

// DecryptWithLength decrypts data and returns only the specified plaintext length
func (sp *SalamanderPadder) DecryptWithLength(ciphertext []byte, plaintextLen int) ([]byte, error) {
	decrypted, err := sp.Decrypt(ciphertext)
	if err != nil {
		return nil, err
	}

	if len(decrypted) < plaintextLen {
		return nil, errors.New("salamander: decrypted data shorter than expected length")
	}

	return decrypted[:plaintextLen], nil
}

// defaultMaxDatagram is the largest datagram the UDP/QUIC framing will put on
// the wire. 1452 = 1500 (Ethernet MTU) - 40 (IPv6 header) - 8 (UDP header);
// it is the same number the Conservative ladder already carried as its top
// bucket, not a fresh guess at a path MTU. Exceeding it would hand the datagram
// to IP fragmentation, which costs throughput and is conspicuous on its own.
// Callers that have measured a smaller path MTU call SetMaxDatagram.
const defaultMaxDatagram = 1452

// minMaxDatagram is the floor SetMaxDatagram clamps to: below this a single
// fragment header plus salt leaves no room for payload.
const minMaxDatagram = 8 + fragHeaderLen + 64

// paddingJitterWidth is how far above its bucket floor a padded record may
// land.
//
// Why jitter at all: quantising onto the bucket value exactly makes the size
// histogram of a flow a comb of four delta spikes (Balanced: 400/800/1200/1400).
// "This peer only ever emits datagrams of four distinct sizes" is a one-line
// classifier, and it survives any amount of encryption underneath. Smearing
// each spike over a band destroys that rule.
//
// Rule 3 of .claude/rules/verification.md requires naming the MEASURED
// distribution this is checked against. There is none: this repository holds no
// capture of donor-traffic datagram sizes, and none was taken for this change.
// Recording that explicitly, as the rule allows: there is nothing to check it
// against. The band is uniform because uniform is the only shape that can be
// stated honestly here, NOT because it was observed anywhere - and a flat band
// 96 bytes wide is itself an unnatural shape that a measurement should replace.
// What the change does buy, without needing a measurement, is the removal of
// the exact-value comb, which is strictly the worse of the two.
const paddingJitterWidth = 96

// datagramLadder trims the level's buckets to maxDatagram and terminates the
// result with maxDatagram itself, so every payload that can travel in one
// datagram has a rung to pad up to.
func datagramLadder(buckets []int, maxDatagram int) []int {
	ladder := make([]int, 0, len(buckets)+1)
	for _, b := range buckets {
		if b < maxDatagram {
			ladder = append(ladder, b)
		}
	}
	return append(ladder, maxDatagram)
}

// floorAndCeil returns the smallest rung of ladder that fits requiredSize and
// the rung above it. ceil is 0 when floor is the last rung; ok is false when
// requiredSize is above the whole ladder.
func floorAndCeil(ladder []int, requiredSize int) (floor, ceil int, ok bool) {
	for i, rung := range ladder {
		if rung >= requiredSize {
			if i+1 < len(ladder) {
				return rung, ladder[i+1], true
			}
			return rung, 0, true
		}
	}
	return 0, 0, false
}

// jitterOffset picks a uniform offset in [0, min(paddingJitterWidth, ceil-floor)]
// from four CSPRNG bytes. ceil is a hard limit and callers must pass a real
// one: floorAndCeil reports 0 for "no rung above", and treating that as "no
// limit" here is how an earlier draft pushed datagrams past the MTU ceiling.
//
// The modulo is biased by at most (room+1)/2^32, i.e. below 2.3e-8 for the
// widest band this uses. That bias is orders of magnitude under what an
// observer could separate from sampling noise, and avoiding a rejection loop
// keeps the draw constant-time per packet.
func jitterOffset(entropy []byte, floor, ceil int) int {
	room := ceil - floor
	if room > paddingJitterWidth {
		room = paddingJitterWidth
	}
	if room <= 0 {
		return 0
	}
	return int(binary.BigEndian.Uint32(entropy) % uint32(room+1))
}

// streamTarget sizes a record for the byte-stream path (Encrypt). There is no
// MTU here - the record travels inside a WebSocket frame over TCP - so above
// the top bucket the ladder simply repeats that bucket instead of giving up and
// letting the exact plaintext length reach the wire.
func (sp *SalamanderPadder) streamTarget(dataLen int, entropy []byte) int {
	required := dataLen + 8
	floor, ceil, ok := floorAndCeil(sp.buckets, required)
	if !ok {
		top := sp.buckets[len(sp.buckets)-1]
		rungs := (required + top - 1) / top
		floor, ceil = rungs*top, (rungs+1)*top
	} else if ceil == 0 {
		// Top bucket, nothing above it, and no MTU to respect on a stream.
		ceil = floor + paddingJitterWidth
	}
	return floor + jitterOffset(entropy, floor, ceil)
}

// datagramTarget sizes a single datagram. ok is false when the payload cannot
// travel whole under maxDatagram; the caller must then split it rather than
// send it unpadded.
func (sp *SalamanderPadder) datagramTarget(dataLen int, entropy []byte) (int, bool) {
	floor, ceil, ok := floorAndCeil(sp.dgramBuckets, dataLen+8)
	if !ok {
		return 0, false
	}
	// The ladder ends at maxDatagram, so the top rung has no jitter room: the
	// ceiling is a hard MTU limit, not another bucket.
	if ceil == 0 || ceil > sp.maxDatagram {
		ceil = sp.maxDatagram
	}
	return floor + jitterOffset(entropy, floor, ceil), true
}

// normalizeToucket reports the bucket floor a payload of dataLen lands on,
// ignoring jitter. It backs EstimatePaddedSize and is the value tests pin; the
// bytes actually emitted are this floor plus a jitter offset below
// paddingJitterWidth.
func (sp *SalamanderPadder) normalizeToucket(dataLen int) int {
	requiredSize := dataLen + 8

	for _, bucket := range sp.buckets {
		if bucket >= requiredSize {
			return bucket
		}
	}

	top := sp.buckets[len(sp.buckets)-1]
	return ((requiredSize + top - 1) / top) * top
}

// getBucketsForLevel returns bucket sizes for a given padding level
func getBucketsForLevel(level PaddingLevel) []int {
	switch level {
	case Conservative:
		// MTU-aligned buckets (minimal overhead)
		return []int{512, 1024, 1452} // 1452 = 1500 MTU - 48 bytes (IP+TCP headers)

	case Balanced:
		// More buckets for better distribution
		return []int{400, 800, 1200, 1400}

	case Aggressive:
		// Many small buckets for maximum obfuscation
		return []int{300, 600, 900, 1200, 1400}

	default:
		return []int{512, 1024, 1452}
	}
}

// GetOverheadPercentage returns the approximate overhead percentage for this level
func (sp *SalamanderPadder) GetOverheadPercentage() (min, max int) {
	switch sp.level {
	case Conservative:
		return 5, 10
	case Balanced:
		return 15, 25
	case Aggressive:
		return 30, 50
	default:
		return 10, 20
	}
}

// GetBuckets returns the current bucket configuration
func (sp *SalamanderPadder) GetBuckets() []int {
	return sp.buckets
}

// GetLevel returns the current padding level
func (sp *SalamanderPadder) GetLevel() PaddingLevel {
	return sp.level
}

// SetLevel updates the padding level and bucket configuration
func (sp *SalamanderPadder) SetLevel(level PaddingLevel) {
	sp.level = level
	sp.buckets = getBucketsForLevel(level)
}

// EstimatePaddedSize estimates the padded size for a given plaintext length
func (sp *SalamanderPadder) EstimatePaddedSize(plaintextLen int) int {
	return sp.normalizeToucket(plaintextLen)
}

// Obfuscate is an alias for Encrypt for clarity in some contexts
func (sp *SalamanderPadder) Obfuscate(data []byte) ([]byte, error) {
	return sp.Encrypt(data)
}

// Deobfuscate is an alias for Decrypt for clarity in some contexts
func (sp *SalamanderPadder) Deobfuscate(data []byte) ([]byte, error) {
	return sp.Decrypt(data)
}

// LevelFromString parses a padding level from string
func LevelFromString(s string) PaddingLevel {
	switch s {
	case "conservative", "low", "1":
		return Conservative
	case "balanced", "medium", "2":
		return Balanced
	case "aggressive", "high", "3":
		return Aggressive
	default:
		return Balanced // Default to balanced
	}
}

// LevelToString converts padding level to string
func LevelToString(level PaddingLevel) string {
	switch level {
	case Conservative:
		return "conservative"
	case Balanced:
		return "balanced"
	case Aggressive:
		return "aggressive"
	default:
		return "balanced"
	}
}
