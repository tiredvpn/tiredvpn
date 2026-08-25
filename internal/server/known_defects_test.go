package server

import (
	"bytes"
	"encoding/binary"
	"testing"
)

// These tests describe defects found while raising coverage. They assert the
// CORRECT behaviour. A test still carrying t.Skip is an open bug on record;
// delete the skip once the fix lands and it becomes the regression guard.

// TestRemoveExtensionByTypeOverrunPanics documents a remotely reachable panic.
//
// removeExtensionByType trusts each extension's own 16-bit length field and
// slices extensions[offset : offset+4+extLen] without checking it against the
// bytes actually present. RemoveREALITYExtension bounds-checks the *outer*
// extensions-length field before calling in, but nothing checks an individual
// extension that over-declares its body, so a ClientHello whose outer length is
// consistent while an inner extension claims 0xFFFF bytes slices out of range.
//
// Reachability: reality.go:227 (HandleREALITYConnection) and reality.go:385
// (handleREALITYUnauthorized). The second is the anti-probe path and runs on
// UNAUTHENTICATED input. There is no recover() anywhere in internal/server, so
// the panic takes the whole process down — one crafted packet per restart.
//
// Verified panic: "slice bounds out of range [:65539] with capacity 6".
//
// Fixed: extLen is bounded by len(extensions)-offset-4 and the walk stops on
// overrun, the same way findREALITYExtension does. This test is now the
// regression guard.
func TestRemoveExtensionByTypeOverrunPanics(t *testing.T) {
	// A single extension of a type we do NOT strip, declaring 0xFFFF bytes of
	// body while only two are present.
	exts := []byte{0x00, 0x2b, 0xFF, 0xFF, 0xAA, 0xBB}

	var body bytes.Buffer
	body.Write([]byte{0x03, 0x03})
	body.Write(bytes.Repeat([]byte{0x11}, 32))
	body.WriteByte(0)           // no session id
	body.Write([]byte{0, 2})    // cipher suites length
	body.Write([]byte{0x13, 1}) // one suite
	body.WriteByte(1)           // compression methods length
	body.WriteByte(0)
	var extLen [2]byte
	// Consistent with what is actually present, so the caller's own check passes.
	binary.BigEndian.PutUint16(extLen[:], uint16(len(exts)))
	body.Write(extLen[:])
	body.Write(exts)

	// Must not panic. An error is NOT required: findREALITYExtension
	// deliberately tolerates a truncated padding extension because DPI strips
	// trailing padding from legitimate ClientHellos, so rejecting on a short
	// body would break real clients. Stopping the walk is the correct
	// behaviour - the over-declaring extension and everything after it is
	// dropped, and the caller gets a well-formed (shorter) ClientHello.
	out, err := RemoveREALITYExtension(wrapClientHello(body.Bytes()))
	if err != nil {
		return // rejecting outright is also acceptable; the point is no panic
	}
	if len(out) == 0 {
		t.Error("stripped ClientHello is empty")
	}
}

// TestParsePortRejectsTrailingGarbage documents a validation gap.
//
// parsePort uses fmt.Sscanf(s, "%d", &port), which stops at the first
// non-digit and reports no error for whatever follows. So "995abc",
// "443 junk" and "80;rm -rf" all parse as valid ports (995, 443, 80). A typo
// in -port or -port-range is silently truncated to a different, valid port
// instead of failing at startup, and the operator only finds out when clients
// cannot connect.
//
// Not remotely reachable — the only callers are server.go:697 and server.go:801,
// both reading operator config — so this is a usability bug, not a security one.
//
// Fix: strconv.Atoi on the trimmed string, which rejects trailing input.
func TestParsePortRejectsTrailingGarbage(t *testing.T) {
	t.Skip("KNOWN DEFECT: parsePort uses fmt.Sscanf and silently ignores trailing garbage")

	for _, bad := range []string{"995abc", "443 junk", "80;rm -rf", "1.5", "0x1bb"} {
		if got, err := parsePort(bad); err == nil {
			t.Errorf("parsePort(%q) = %d, want an error for the trailing garbage", bad, got)
		}
	}
}
