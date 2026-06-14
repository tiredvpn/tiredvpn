package tls

import (
	"crypto/hmac"
	"crypto/rand"
	"crypto/sha256"
	"encoding/binary"
	"errors"
	"fmt"
	"time"

	"github.com/tiredvpn/tiredvpn/internal/log"
	"golang.org/x/crypto/curve25519"
)

// debugLog writes debug info for tracing padding issues
func debugLog(format string, args ...interface{}) {
	msg := fmt.Sprintf(format, args...)
	log.Debug("[TLS-PAD] %s", msg)
}

const (
	// Padding extension type (RFC 7685) - used to hide REALITY data
	PaddingExtensionType = 0x0015

	// REALITYMagic is used only by the postquantum V2 path.
	// V1 format contains no magic markers - just PubKey+AuthToken at a fixed offset.
	REALITYMagic = "REAL"

	REALITYExtensionLength = 32 + 32 // pubkey + auth token (no magic, no version)
	MinPaddingSize         = 256     // minimum padding size for REALITY data + random

	// authTokenGraceBuckets is the number of adjacent 5-minute buckets accepted
	// on each side of the current one in VerifyClientAuth, to tolerate clock skew.
	authTokenGraceBuckets = 1
)

// REALITYExtension carries client credentials hidden inside TLS padding extension.
// Wire format: [PubKey:32][AuthToken:32] — looks like random bytes to an observer.
type REALITYExtension struct {
	PubKey    [32]byte
	AuthToken [32]byte
}

// NewClientREALITYExtension creates a client-side REALITY extension with auth token.
// AuthToken is bound to the ephemeral clientPubKey, making it unique per connection.
func NewClientREALITYExtension(secret []byte, clientPrivKey [32]byte) (*REALITYExtension, error) {
	var clientPubKey [32]byte
	curve25519.ScalarBaseMult(&clientPubKey, &clientPrivKey)

	// Bind token to per-connection pubkey to prevent replay across connections
	authToken := generateAuthToken(secret, clientPubKey)

	log.Debug("REALITY-AUTH-CLIENT: auth token generated")

	return &REALITYExtension{
		PubKey:    clientPubKey,
		AuthToken: authToken,
	}, nil
}

// NewServerREALITYExtension creates a server-side REALITY extension response
func NewServerREALITYExtension(secret []byte, serverPrivKey, clientPubKey [32]byte) (*REALITYExtension, error) {
	var serverPubKey [32]byte
	curve25519.ScalarBaseMult(&serverPubKey, &serverPrivKey)

	h := hmac.New(sha256.New, secret)
	h.Write(clientPubKey[:])
	h.Write([]byte("reality-server-ack"))
	authSum := h.Sum(nil)

	var authToken [32]byte
	copy(authToken[:], authSum)

	return &REALITYExtension{
		PubKey:    serverPubKey,
		AuthToken: authToken,
	}, nil
}

// Marshal serializes the extension to bytes: [PubKey:32][AuthToken:32].
// No magic or version bytes — indistinguishable from random padding to an observer.
func (e *REALITYExtension) Marshal() []byte {
	buf := make([]byte, REALITYExtensionLength)
	copy(buf[0:32], e.PubKey[:])
	copy(buf[32:64], e.AuthToken[:])
	return buf
}

// Unmarshal parses [PubKey:32][AuthToken:32] from the start of data.
func (e *REALITYExtension) Unmarshal(data []byte) error {
	if len(data) < REALITYExtensionLength {
		return errors.New("reality extension too short")
	}
	copy(e.PubKey[:], data[0:32])
	copy(e.AuthToken[:], data[32:64])
	return nil
}

// VerifyClientAuth validates a client's auth token bound to its ephemeral pubKey.
// Accepts tokens from the current 5-minute bucket and the adjacent ones to
// tolerate clock skew between client and server.
func VerifyClientAuth(secret []byte, clientPubKey [32]byte, authToken [32]byte) bool {
	// Check the current bucket first, then the grace buckets on either side.
	offsets := []int64{0}
	for g := int64(1); g <= authTokenGraceBuckets; g++ {
		offsets = append(offsets, -g, g)
	}
	for _, offset := range offsets {
		expected := generateAuthTokenAtBucket(secret, clientPubKey, offset)
		if hmac.Equal(authToken[:], expected[:]) {
			return true
		}
	}
	log.Debug("REALITY-AUTH: token mismatch (grace +-%d buckets)", authTokenGraceBuckets)
	return false
}

// generateAuthTokenAtBucket computes HMAC-SHA256(secret, pubKey || timestamp_bucket)
// for the bucket offset by bucketOffset from the current 5-minute bucket.
func generateAuthTokenAtBucket(secret []byte, clientPubKey [32]byte, bucketOffset int64) [32]byte {
	bucket := (time.Now().Unix() / 300) + bucketOffset
	h := hmac.New(sha256.New, secret)
	h.Write(clientPubKey[:])
	var tsBuf [8]byte
	binary.BigEndian.PutUint64(tsBuf[:], uint64(bucket))
	h.Write(tsBuf[:])
	h.Write([]byte("reality-auth"))
	var token [32]byte
	copy(token[:], h.Sum(nil))
	return token
}

// VerifyServerAuth validates a server's auth token
func VerifyServerAuth(secret, clientPubKey []byte, authToken [32]byte) bool {
	h := hmac.New(sha256.New, secret)
	h.Write(clientPubKey)
	h.Write([]byte("reality-server-ack"))
	expected := h.Sum(nil)

	return hmac.Equal(expected, authToken[:])
}

// generateAuthToken creates HMAC-SHA256(secret, pubKey || timestamp_bucket) for
// the current 5-minute bucket. Binding to pubKey makes the token unique per
// connection. It is a thin wrapper over generateAuthTokenAtBucket with offset 0.
func generateAuthToken(secret []byte, clientPubKey [32]byte) [32]byte {
	return generateAuthTokenAtBucket(secret, clientPubKey, 0)
}

// GenerateX25519KeyPair generates a new X25519 key pair
func GenerateX25519KeyPair() (privKey, pubKey [32]byte, err error) {
	if _, err := rand.Read(privKey[:]); err != nil {
		return privKey, pubKey, err
	}

	curve25519.ScalarBaseMult(&pubKey, &privKey)
	return privKey, pubKey, nil
}

// InjectREALITYIntoPadding finds padding extension in ClientHello and injects REALITY data
// The padding extension content is replaced with: [REALITY data (69 bytes)][random padding]
func InjectREALITYIntoPadding(clientHello []byte, ext *REALITYExtension) ([]byte, error) {
	if len(clientHello) < 50 {
		return nil, errors.New("clientHello too short")
	}

	// Find padding extension (0x00 0x15)
	paddingOffset := -1
	for i := 0; i < len(clientHello)-4; i++ {
		if clientHello[i] == 0x00 && clientHello[i+1] == 0x15 {
			// Check extension length
			extLen := int(clientHello[i+2])<<8 | int(clientHello[i+3])
			if extLen >= REALITYExtensionLength && i+4+extLen <= len(clientHello) {
				paddingOffset = i
				break
			}
		}
	}

	if paddingOffset < 0 {
		return nil, errors.New("padding extension not found in clientHello")
	}

	// Get padding extension bounds
	extLen := int(clientHello[paddingOffset+2])<<8 | int(clientHello[paddingOffset+3])
	dataStart := paddingOffset + 4

	// Make a copy
	result := make([]byte, len(clientHello))
	copy(result, clientHello)

	// Write REALITY data at the start of padding
	realityData := ext.Marshal()
	copy(result[dataStart:dataStart+REALITYExtensionLength], realityData)

	// Fill rest with random data (not zeros, to avoid detection)
	remaining := extLen - REALITYExtensionLength
	if remaining > 0 {
		randomPadding := make([]byte, remaining)
		if _, err := rand.Read(randomPadding); err != nil {
			return nil, fmt.Errorf("failed to generate random padding: %w", err)
		}
		copy(result[dataStart+REALITYExtensionLength:dataStart+extLen], randomPadding)
	}

	return result, nil
}

// ExtractREALITYFromPadding extracts REALITY extension from the start of padding data.
// No magic check — caller must verify AuthToken to confirm this is a real REALITY client.
func ExtractREALITYFromPadding(paddingData []byte) (*REALITYExtension, error) {
	if len(paddingData) < REALITYExtensionLength {
		return nil, errors.New("padding too short for REALITY data")
	}

	ext := &REALITYExtension{}
	if err := ext.Unmarshal(paddingData[:REALITYExtensionLength]); err != nil {
		return nil, err
	}

	return ext, nil
}

// AddPaddingWithREALITY adds or replaces padding extension with REALITY data in ClientHello
// If an existing padding extension exists (any size), it will be REPLACED, not added as a duplicate
func AddPaddingWithREALITY(clientHello []byte, ext *REALITYExtension, totalPaddingLen int) ([]byte, error) {
	if totalPaddingLen < MinPaddingSize {
		totalPaddingLen = MinPaddingSize
	}

	// Find extensions section
	if len(clientHello) < 50 {
		return nil, errors.New("clientHello too short")
	}

	// Log original record length for debugging
	origRecordLen := int(clientHello[3])<<8 | int(clientHello[4])
	debugLog("AddPaddingWithREALITY: input len=%d, record_len=%d (0x%02x%02x)", len(clientHello), origRecordLen, clientHello[3], clientHello[4])

	// First, check if there's an existing padding extension (any size)
	// If found, we need to REPLACE it, not add a duplicate
	existingPaddingOffset := -1
	existingPaddingLen := 0
	for i := 0; i < len(clientHello)-4; i++ {
		if clientHello[i] == 0x00 && clientHello[i+1] == 0x15 {
			existingPaddingLen = int(clientHello[i+2])<<8 | int(clientHello[i+3])
			if i+4+existingPaddingLen <= len(clientHello) {
				existingPaddingOffset = i
				debugLog("AddPaddingWithREALITY: found existing padding at offset=%d, len=%d", i, existingPaddingLen)
				break
			}
		}
	}

	// If existing padding found, replace it instead of adding duplicate
	if existingPaddingOffset >= 0 {
		return replacePaddingExtension(clientHello, existingPaddingOffset, existingPaddingLen, ext, totalPaddingLen)
	}

	// Parse to find extensions offset
	// TLS Record: type(1) + version(2) + length(2) = 5
	// Handshake: type(1) + length(3) = 4
	// ClientHello: version(2) + random(32) + sessionID(1+len) + ciphers(2+len) + compression(1+len) + extensions(2+len)

	offset := 5 + 4 + 2 + 32 // Skip record header, handshake header, version, random

	// Skip session ID
	if offset >= len(clientHello) {
		return nil, errors.New("invalid clientHello: missing session ID")
	}
	sessionIDLen := int(clientHello[offset])
	offset += 1 + sessionIDLen
	debugLog("AddPaddingWithREALITY: after sessionID (len=%d), offset=%d", sessionIDLen, offset)

	// Skip cipher suites
	if offset+2 > len(clientHello) {
		return nil, errors.New("invalid clientHello: missing cipher suites")
	}
	cipherLen := int(clientHello[offset])<<8 | int(clientHello[offset+1])
	offset += 2 + cipherLen
	debugLog("AddPaddingWithREALITY: after ciphers (len=%d), offset=%d", cipherLen, offset)

	// Skip compression methods
	if offset >= len(clientHello) {
		return nil, errors.New("invalid clientHello: missing compression")
	}
	compLen := int(clientHello[offset])
	offset += 1 + compLen
	debugLog("AddPaddingWithREALITY: after compression (len=%d), offset=%d", compLen, offset)

	// Extensions section
	if offset+2 > len(clientHello) {
		return nil, errors.New("invalid clientHello: missing extensions")
	}
	extLenOffset := offset
	oldExtLen := int(clientHello[offset])<<8 | int(clientHello[offset+1])
	offset += 2
	debugLog("AddPaddingWithREALITY: extensions at offset=%d, oldExtLen=%d, endOfExt=%d, totalInput=%d", extLenOffset, oldExtLen, offset+oldExtLen, len(clientHello))

	// Build padding extension with REALITY
	paddingExt := make([]byte, 4+totalPaddingLen)
	paddingExt[0] = 0x00 // Extension type high byte
	paddingExt[1] = 0x15 // Extension type low byte (padding)
	paddingExt[2] = byte(totalPaddingLen >> 8)
	paddingExt[3] = byte(totalPaddingLen)

	// Write REALITY data
	realityData := ext.Marshal()
	copy(paddingExt[4:4+REALITYExtensionLength], realityData)

	// Fill rest with random
	remaining := totalPaddingLen - REALITYExtensionLength
	if remaining > 0 {
		randomPadding := make([]byte, remaining)
		rand.Read(randomPadding)
		copy(paddingExt[4+REALITYExtensionLength:], randomPadding)
	}

	// Build new ClientHello
	// Original data up to end of extensions
	endOfExtensions := offset + oldExtLen

	result := make([]byte, 0, len(clientHello)+len(paddingExt))
	result = append(result, clientHello[:endOfExtensions]...)
	result = append(result, paddingExt...)

	// Update extensions length
	newExtLen := oldExtLen + len(paddingExt)
	result[extLenOffset] = byte(newExtLen >> 8)
	result[extLenOffset+1] = byte(newExtLen)

	// Update handshake length (offset 6-8, 3 bytes)
	newHandshakeLen := len(result) - 9 // Minus record header (5) and handshake type+length (4)
	result[6] = byte(newHandshakeLen >> 16)
	result[7] = byte(newHandshakeLen >> 8)
	result[8] = byte(newHandshakeLen)

	// Update record length (offset 3-4, 2 bytes)
	newRecordLen := len(result) - 5 // Minus record header
	result[3] = byte(newRecordLen >> 8)
	result[4] = byte(newRecordLen)

	// Verify the result
	finalRecordLen := int(result[3])<<8 | int(result[4])
	debugLog("AddPaddingWithREALITY: OUTPUT len=%d, record_len=%d (0x%02x%02x), paddingExt added=%d bytes",
		len(result), finalRecordLen, result[3], result[4], len(paddingExt))
	debugLog("AddPaddingWithREALITY: first 16 bytes: %02x", result[:16])

	return result, nil
}

// replacePaddingExtension replaces an existing padding extension with a new one containing REALITY data
// This is used when uTLS already added a padding extension (possibly with wrong size)
func replacePaddingExtension(clientHello []byte, paddingOffset, oldPaddingLen int, ext *REALITYExtension, totalPaddingLen int) ([]byte, error) {
	debugLog("replacePaddingExtension: offset=%d, oldLen=%d, newLen=%d", paddingOffset, oldPaddingLen, totalPaddingLen)

	// Build new padding extension
	newPaddingExt := make([]byte, 4+totalPaddingLen)
	newPaddingExt[0] = 0x00 // Extension type high byte
	newPaddingExt[1] = 0x15 // Extension type low byte (padding)
	newPaddingExt[2] = byte(totalPaddingLen >> 8)
	newPaddingExt[3] = byte(totalPaddingLen)

	// Write REALITY data
	realityData := ext.Marshal()
	copy(newPaddingExt[4:4+REALITYExtensionLength], realityData)

	// Fill rest with random
	remaining := totalPaddingLen - REALITYExtensionLength
	if remaining > 0 {
		randomPadding := make([]byte, remaining)
		rand.Read(randomPadding)
		copy(newPaddingExt[4+REALITYExtensionLength:], randomPadding)
	}

	// Calculate size difference
	oldExtTotalLen := 4 + oldPaddingLen // type(2) + len(2) + data
	newExtTotalLen := len(newPaddingExt)
	sizeDiff := newExtTotalLen - oldExtTotalLen

	debugLog("replacePaddingExtension: oldExtTotal=%d, newExtTotal=%d, sizeDiff=%d", oldExtTotalLen, newExtTotalLen, sizeDiff)

	// Build result: [before padding ext] + [new padding ext] + [after old padding ext]
	result := make([]byte, 0, len(clientHello)+sizeDiff)
	result = append(result, clientHello[:paddingOffset]...)
	result = append(result, newPaddingExt...)
	result = append(result, clientHello[paddingOffset+oldExtTotalLen:]...)

	// Now update lengths in result

	// Find extensions length offset by parsing from start
	// TLS Record: type(1) + version(2) + length(2) = 5
	// Handshake: type(1) + length(3) = 4
	// ClientHello: version(2) + random(32) + sessionID(1+len) + ciphers(2+len) + compression(1+len) + extensions(2+len)

	offset := 5 + 4 + 2 + 32 // Skip record header, handshake header, version, random

	// Skip session ID
	sessionIDLen := int(result[offset])
	offset += 1 + sessionIDLen

	// Skip cipher suites
	cipherLen := int(result[offset])<<8 | int(result[offset+1])
	offset += 2 + cipherLen

	// Skip compression methods
	compLen := int(result[offset])
	offset += 1 + compLen

	// Extensions length is at offset
	extLenOffset := offset
	oldExtLen := int(result[extLenOffset])<<8 | int(result[extLenOffset+1])
	newExtLen := oldExtLen + sizeDiff

	debugLog("replacePaddingExtension: extLenOffset=%d, oldExtLen=%d, newExtLen=%d", extLenOffset, oldExtLen, newExtLen)

	// Update extensions length
	result[extLenOffset] = byte(newExtLen >> 8)
	result[extLenOffset+1] = byte(newExtLen)

	// Update handshake length (offset 6-8, 3 bytes)
	newHandshakeLen := len(result) - 9 // Minus record header (5) and handshake type+length (4)
	result[6] = byte(newHandshakeLen >> 16)
	result[7] = byte(newHandshakeLen >> 8)
	result[8] = byte(newHandshakeLen)

	// Update record length (offset 3-4, 2 bytes)
	newRecordLen := len(result) - 5 // Minus record header
	result[3] = byte(newRecordLen >> 8)
	result[4] = byte(newRecordLen)

	// Verify the result
	finalRecordLen := int(result[3])<<8 | int(result[4])
	debugLog("replacePaddingExtension: OUTPUT len=%d, record_len=%d, REALITY at padding offset", len(result), finalRecordLen)

	return result, nil
}
