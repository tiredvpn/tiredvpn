package server

import (
	"bytes"
	"encoding/binary"
	"errors"
	"io"

	customtls "github.com/tiredvpn/tiredvpn/internal/tls"
)

// TLS record and handshake type constants
const (
	recordTypeHandshake      = 0x16
	handshakeTypeClientHello = 0x01
	handshakeTypeServerHello = 0x02
)

// TLSRecord represents a TLS record layer frame
type TLSRecord struct {
	Type    uint8
	Version uint16
	Length  uint16
	Payload []byte
}

// HandshakeMessage represents a TLS handshake message
type HandshakeMessage struct {
	Type    uint8
	Length  uint32 // 24-bit length
	Payload []byte
}

// ParseTLSRecord extracts a TLS record from raw bytes
func ParseTLSRecord(data []byte) (*TLSRecord, error) {
	if len(data) < 5 {
		return nil, errors.New("record too short")
	}

	record := &TLSRecord{
		Type:    data[0],
		Version: binary.BigEndian.Uint16(data[1:3]),
		Length:  binary.BigEndian.Uint16(data[3:5]),
	}

	if len(data) < 5+int(record.Length) {
		return nil, errors.New("incomplete record")
	}

	record.Payload = data[5 : 5+record.Length]
	return record, nil
}

// ParseHandshakeMessage extracts a handshake message
func ParseHandshakeMessage(data []byte) (*HandshakeMessage, error) {
	if len(data) < 4 {
		return nil, errors.New("handshake message too short")
	}

	msg := &HandshakeMessage{
		Type:   data[0],
		Length: uint32(data[1])<<16 | uint32(data[2])<<8 | uint32(data[3]),
	}

	if len(data) < 4+int(msg.Length) {
		return nil, errors.New("incomplete handshake message")
	}

	msg.Payload = data[4 : 4+msg.Length]
	return msg, nil
}

// ExtractREALITYExtensionFromClientHello searches for REALITY extension in ClientHello
func ExtractREALITYExtensionFromClientHello(data []byte) (*customtls.REALITYExtension, error) {
	// Parse TLS record
	record, err := ParseTLSRecord(data)
	if err != nil {
		return nil, err
	}

	if record.Type != recordTypeHandshake {
		return nil, errors.New("not a handshake record")
	}

	// Parse handshake message
	msg, err := ParseHandshakeMessage(record.Payload)
	if err != nil {
		return nil, err
	}

	if msg.Type != handshakeTypeClientHello {
		return nil, errors.New("not a ClientHello")
	}

	// Search for extensions section
	// ClientHello structure:
	// - Version (2)
	// - Random (32)
	// - Session ID length (1) + Session ID (variable)
	// - Cipher suites length (2) + Cipher suites (variable)
	// - Compression methods length (1) + Compression methods (variable)
	// - Extensions length (2) + Extensions (variable)

	offset := 0
	payload := msg.Payload

	// Skip version and random
	if len(payload) < 34 {
		return nil, errors.New("clienthello too short")
	}
	offset += 34

	// Skip session ID
	if offset >= len(payload) {
		return nil, errors.New("invalid clienthello: no session id length")
	}
	sessionIDLen := int(payload[offset])
	offset += 1 + sessionIDLen

	// Skip cipher suites
	if offset+2 > len(payload) {
		return nil, errors.New("invalid clienthello: no cipher suites")
	}
	cipherSuitesLen := int(binary.BigEndian.Uint16(payload[offset:]))
	offset += 2 + cipherSuitesLen

	// Skip compression methods
	if offset >= len(payload) {
		return nil, errors.New("invalid clienthello: no compression methods")
	}
	compressionMethodsLen := int(payload[offset])
	offset += 1 + compressionMethodsLen

	// Parse extensions
	if offset+2 > len(payload) {
		return nil, errors.New("no extensions")
	}
	extensionsLen := int(binary.BigEndian.Uint16(payload[offset:]))
	offset += 2

	if offset+extensionsLen > len(payload) {
		return nil, errors.New("invalid extensions length")
	}

	extensions := payload[offset : offset+extensionsLen]

	// Search for REALITY extension (0xFF01)
	return findREALITYExtension(extensions)
}

// findREALITYExtension searches extension list for REALITY extension inside padding (0x0015)
func findREALITYExtension(extensions []byte) (*customtls.REALITYExtension, error) {
	offset := 0

	for offset+4 <= len(extensions) {
		extType := binary.BigEndian.Uint16(extensions[offset:])
		extLen := int(binary.BigEndian.Uint16(extensions[offset+2:]))
		offset += 4

		if offset+extLen > len(extensions) {
			return nil, errors.New("invalid extension length")
		}

		// Search for REALITY in padding extension (0x0015)
		if extType == customtls.PaddingExtensionType && extLen >= customtls.REALITYExtensionLength {
			extData := extensions[offset : offset+extLen]

			// Check for REALITY magic at start of padding
			if len(extData) >= 4 &&
				extData[0] == 'R' && extData[1] == 'E' &&
				extData[2] == 'A' && extData[3] == 'L' {

				// Extract REALITY extension from padding
				ext, err := customtls.ExtractREALITYFromPadding(extData)
				if err != nil {
					return nil, err
				}
				return ext, nil
			}
		}

		offset += extLen
	}

	return nil, errors.New("reality extension not found in padding")
}

// RemoveREALITYExtension strips the REALITY data from ClientHello by removing padding extension
// This is used before forwarding ClientHello to the real destination server
func RemoveREALITYExtension(clientHello []byte) ([]byte, error) {
	// Parse original record and handshake
	record, err := ParseTLSRecord(clientHello)
	if err != nil {
		return nil, err
	}

	msg, err := ParseHandshakeMessage(record.Payload)
	if err != nil {
		return nil, err
	}

	// Navigate to extensions
	offset := 34 // version + random

	payload := msg.Payload
	sessionIDLen := int(payload[offset])
	offset += 1 + sessionIDLen

	cipherSuitesLen := int(binary.BigEndian.Uint16(payload[offset:]))
	offset += 2 + cipherSuitesLen

	compressionMethodsLen := int(payload[offset])
	offset += 1 + compressionMethodsLen

	extensionsLenOffset := offset
	extensionsLen := int(binary.BigEndian.Uint16(payload[offset:]))
	offset += 2

	extensions := payload[offset : offset+extensionsLen]

	// Remove padding extension (which contains REALITY data)
	newExtensions := removeExtensionByType(extensions, customtls.PaddingExtensionType)

	// Rebuild payload
	newPayload := make([]byte, len(payload))
	copy(newPayload, payload[:extensionsLenOffset])

	// Update extensions length
	newExtensionsLen := len(newExtensions)
	binary.BigEndian.PutUint16(newPayload[extensionsLenOffset:], uint16(newExtensionsLen))

	// Copy new extensions
	copy(newPayload[extensionsLenOffset+2:], newExtensions)

	// Truncate payload to new size
	newPayloadLen := extensionsLenOffset + 2 + newExtensionsLen
	newPayload = newPayload[:newPayloadLen]

	// Rebuild handshake message
	newMsg := &HandshakeMessage{
		Type:    msg.Type,
		Length:  uint32(len(newPayload)),
		Payload: newPayload,
	}

	newMsgBytes := marshalHandshakeMessage(newMsg)

	// Rebuild TLS record
	newRecord := &TLSRecord{
		Type:    record.Type,
		Version: record.Version,
		Length:  uint16(len(newMsgBytes)),
		Payload: newMsgBytes,
	}

	return marshalTLSRecord(newRecord), nil
}

// removeExtensionByType filters out a specific extension type
func removeExtensionByType(extensions []byte, targetType uint16) []byte {
	var result bytes.Buffer
	offset := 0

	for offset+4 <= len(extensions) {
		extType := binary.BigEndian.Uint16(extensions[offset:])
		extLen := int(binary.BigEndian.Uint16(extensions[offset+2:]))

		if extType != targetType {
			// Keep this extension
			result.Write(extensions[offset : offset+4+extLen])
		}

		offset += 4 + extLen
	}

	return result.Bytes()
}

// InjectREALITYExtension adds REALITY extension to ServerHello inside a padding extension
func InjectREALITYExtension(serverHello []byte, realityExt *customtls.REALITYExtension) ([]byte, error) {
	// Parse original record and handshake
	record, err := ParseTLSRecord(serverHello)
	if err != nil {
		return nil, err
	}

	msg, err := ParseHandshakeMessage(record.Payload)
	if err != nil {
		return nil, err
	}

	if msg.Type != handshakeTypeServerHello {
		return nil, errors.New("not a ServerHello")
	}

	// Find extensions offset
	// ServerHello structure: Version (2) + Random (32) + Session ID len (1) + Session ID (var) + Cipher (2) + Compression (1) + Extensions len (2)
	offset := 34 // version + random

	payload := msg.Payload
	if offset >= len(payload) {
		return nil, errors.New("serverhello too short")
	}

	sessionIDLen := int(payload[offset])
	offset += 1 + sessionIDLen + 2 + 1 // session ID + cipher suite + compression

	if offset+2 > len(payload) {
		return nil, errors.New("no extensions in serverhello")
	}

	extensionsLenOffset := offset
	extensionsLen := int(binary.BigEndian.Uint16(payload[offset:]))
	offset += 2

	// Build padding extension with REALITY data inside
	// Format: type(2) + len(2) + [REALITY data (69 bytes)] + [random padding]
	extData := realityExt.Marshal()
	paddingLen := customtls.MinPaddingSize // 256 bytes total padding
	if paddingLen < len(extData) {
		paddingLen = len(extData)
	}

	paddingExtension := make([]byte, 4+paddingLen)
	binary.BigEndian.PutUint16(paddingExtension[0:], customtls.PaddingExtensionType) // 0x0015
	binary.BigEndian.PutUint16(paddingExtension[2:], uint16(paddingLen))

	// Write REALITY data at start of padding
	copy(paddingExtension[4:], extData)

	// Fill rest with random bytes
	if paddingLen > len(extData) {
		randomPadding := make([]byte, paddingLen-len(extData))
		for i := range randomPadding {
			randomPadding[i] = byte(i * 7 % 256) // Pseudo-random but deterministic for debugging
		}
		copy(paddingExtension[4+len(extData):], randomPadding)
	}

	// Rebuild payload with injected extension
	newPayload := make([]byte, 0, len(payload)+len(paddingExtension))
	newPayload = append(newPayload, payload[:offset]...)                     // Before extensions
	newPayload = append(newPayload, payload[offset:offset+extensionsLen]...) // Original extensions
	newPayload = append(newPayload, paddingExtension...)                     // Padding with REALITY

	// Update extensions length
	newExtensionsLen := extensionsLen + len(paddingExtension)
	binary.BigEndian.PutUint16(newPayload[extensionsLenOffset:], uint16(newExtensionsLen))

	// Rebuild handshake message
	newMsg := &HandshakeMessage{
		Type:    msg.Type,
		Length:  uint32(len(newPayload)),
		Payload: newPayload,
	}

	newMsgBytes := marshalHandshakeMessage(newMsg)

	// Rebuild TLS record
	newRecord := &TLSRecord{
		Type:    record.Type,
		Version: record.Version,
		Length:  uint16(len(newMsgBytes)),
		Payload: newMsgBytes,
	}

	return marshalTLSRecord(newRecord), nil
}

// marshalHandshakeMessage serializes a handshake message
func marshalHandshakeMessage(msg *HandshakeMessage) []byte {
	buf := make([]byte, 4+len(msg.Payload))
	buf[0] = msg.Type
	buf[1] = byte(msg.Length >> 16)
	buf[2] = byte(msg.Length >> 8)
	buf[3] = byte(msg.Length)
	copy(buf[4:], msg.Payload)
	return buf
}

// marshalTLSRecord serializes a TLS record
func marshalTLSRecord(record *TLSRecord) []byte {
	buf := make([]byte, 5+len(record.Payload))
	buf[0] = record.Type
	binary.BigEndian.PutUint16(buf[1:], record.Version)
	binary.BigEndian.PutUint16(buf[3:], record.Length)
	copy(buf[5:], record.Payload)
	return buf
}

// ReadTLSRecord reads a full TLS record from a connection
func ReadTLSRecord(conn io.Reader) ([]byte, error) {
	// Read 5-byte header
	header := make([]byte, 5)
	if _, err := io.ReadFull(conn, header); err != nil {
		return nil, err
	}

	recordLen := binary.BigEndian.Uint16(header[3:5])

	// Read payload
	payload := make([]byte, recordLen)
	if _, err := io.ReadFull(conn, payload); err != nil {
		return nil, err
	}

	// Return complete record
	result := make([]byte, 5+recordLen)
	copy(result, header)
	copy(result[5:], payload)

	return result, nil
}

// ExtractSNI extracts the Server Name Indication from ClientHello
func ExtractSNI(clientHello []byte) (string, error) {
	record, err := ParseTLSRecord(clientHello)
	if err != nil {
		return "", err
	}

	msg, err := ParseHandshakeMessage(record.Payload)
	if err != nil {
		return "", err
	}

	// Navigate to extensions (same as ExtractREALITYExtensionFromClientHello)
	offset := 34
	payload := msg.Payload

	sessionIDLen := int(payload[offset])
	offset += 1 + sessionIDLen

	cipherSuitesLen := int(binary.BigEndian.Uint16(payload[offset:]))
	offset += 2 + cipherSuitesLen

	compressionMethodsLen := int(payload[offset])
	offset += 1 + compressionMethodsLen

	extensionsLen := int(binary.BigEndian.Uint16(payload[offset:]))
	offset += 2

	extensions := payload[offset : offset+extensionsLen]

	// Search for SNI extension (type 0x0000)
	return findSNIExtension(extensions)
}

// findSNIExtension extracts SNI from extensions
func findSNIExtension(extensions []byte) (string, error) {
	offset := 0

	for offset+4 <= len(extensions) {
		extType := binary.BigEndian.Uint16(extensions[offset:])
		extLen := int(binary.BigEndian.Uint16(extensions[offset+2:]))
		offset += 4

		if offset+extLen > len(extensions) {
			return "", errors.New("invalid extension length")
		}

		if extType == 0x0000 { // SNI extension
			extData := extensions[offset : offset+extLen]

			// SNI extension format:
			// - Server Name List Length (2)
			// - Name Type (1, 0x00 for hostname)
			// - Name Length (2)
			// - Name (variable)

			if len(extData) < 5 {
				return "", errors.New("invalid sni extension")
			}

			nameType := extData[2]
			if nameType != 0x00 {
				return "", errors.New("non-hostname sni")
			}

			nameLen := int(binary.BigEndian.Uint16(extData[3:5]))
			if len(extData) < 5+nameLen {
				return "", errors.New("invalid sni name length")
			}

			return string(extData[5 : 5+nameLen]), nil
		}

		offset += extLen
	}

	return "", errors.New("sni extension not found")
}
