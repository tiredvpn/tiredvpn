package strategy

// walkSNIHostname locates the SNI hostname inside a TLS ClientHello by walking
// the extension list by extension-type rather than scanning for raw 0x00 0x00
// bytes. The raw-byte approach produces false positives inside semi-random
// fields (ClientHello.Random, session ID, and especially post-quantum key_share
// values such as kyber768, ~1152 bytes that can contain any short hostname as a
// substring).
//
// clientHello must include the 5-byte TLS record header. On success it returns
// the absolute offset where the hostname bytes begin, the hostname length, and
// true. If the SNI extension cannot be located it returns 0, 0, false.
func walkSNIHostname(clientHello []byte) (nameStart, nameLen int, ok bool) {
	if len(clientHello) < 47 {
		return 0, 0, false
	}

	// TLS Record header (5) + Handshake header (4) + CH version (2) + CH random (32) = 43
	offset := 43
	if offset >= len(clientHello) {
		return 0, 0, false
	}

	// Skip session ID
	sessionIDLen := int(clientHello[offset])
	offset += 1 + sessionIDLen
	if offset+2 > len(clientHello) {
		return 0, 0, false
	}

	// Skip cipher suites
	cipherLen := int(clientHello[offset])<<8 | int(clientHello[offset+1])
	offset += 2 + cipherLen
	if offset+1 > len(clientHello) {
		return 0, 0, false
	}

	// Skip compression methods
	compLen := int(clientHello[offset])
	offset += 1 + compLen
	if offset+2 > len(clientHello) {
		return 0, 0, false
	}

	// Extensions: 2-byte total length, then each ext is type(2)+len(2)+data(len)
	extTotalLen := int(clientHello[offset])<<8 | int(clientHello[offset+1])
	offset += 2
	extEnd := offset + extTotalLen
	if extEnd > len(clientHello) {
		extEnd = len(clientHello)
	}

	for offset+4 <= extEnd {
		extType := int(clientHello[offset])<<8 | int(clientHello[offset+1])
		extLen := int(clientHello[offset+2])<<8 | int(clientHello[offset+3])
		extDataStart := offset + 4

		if extType == 0x0000 { // SNI extension
			// SNI body: server_name_list_len(2) + name_type(1) + name_len(2) + name(name_len)
			if extDataStart+5 > extEnd {
				return 0, 0, false
			}
			nameType := clientHello[extDataStart+2]
			if nameType != 0x00 { // not host_name
				return 0, 0, false
			}
			nLen := int(clientHello[extDataStart+3])<<8 | int(clientHello[extDataStart+4])
			nStart := extDataStart + 5
			if nStart+nLen > extEnd {
				return 0, 0, false
			}
			return nStart, nLen, true
		}

		if extDataStart+extLen > extEnd {
			break
		}
		offset = extDataStart + extLen
	}

	return 0, 0, false
}
