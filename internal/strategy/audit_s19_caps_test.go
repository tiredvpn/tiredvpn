package strategy

import (
	"bufio"
	"encoding/binary"
	"strings"
	"testing"

	"github.com/tiredvpn/tiredvpn/internal/shaper"
)

// The S19 caps guard four peer-supplied lengths that were used to size a make()
// with no upper bound: a huge value OOMs the client and, once it wraps a 32/64
// bit int negative, panics make(). Each test feeds an over-cap length and
// asserts the reader rejects it with the cap error *before* allocating - not an
// EOF from a short body (uncapped code) and not a panic (negative wrap).

// mkWSFrameHeader builds a masked=0 binary WebSocket frame header announcing a
// 64-bit extended payload length, with no payload bytes following.
func mkWSFrameHeader(l uint64) []byte {
	b := []byte{0x82, 0x7F} // FIN|binary, len indicator 127 (8-byte extended)
	var ext [8]byte
	binary.BigEndian.PutUint64(ext[:], l)
	return append(b, ext[:]...)
}

func TestReadWebSocketFrameCapsPeerLength(t *testing.T) {
	t.Parallel()

	// Just over the cap: uncapped code would make() ~1 MiB then block on an
	// empty body and return EOF; the cap must reject first with its own error.
	sc := &SalamanderConn{conn: readOnlyConn{Reader: strings.NewReader(string(mkWSFrameHeader(maxWSFrameLen + 1)))}}
	_, err := sc.readWebSocketFrame()
	if err == nil {
		t.Fatal("oversize websocket frame was accepted")
	}
	if !strings.Contains(err.Error(), "cap") {
		t.Fatalf("want cap error, got %v", err)
	}

	// All-ones length turns into a negative int; uncapped make() panics. The
	// guard must turn it into an error instead.
	sc2 := &SalamanderConn{conn: readOnlyConn{Reader: strings.NewReader(string(mkWSFrameHeader(^uint64(0))))}}
	_, err = sc2.readWebSocketFrame()
	if err == nil {
		t.Fatal("negative-wrap websocket length was accepted")
	}
}

func TestMorphReadCapsPeerDataLen(t *testing.T) {
	t.Parallel()

	var hdr [morphHeaderLen]byte
	writeFrameHeader(hdr[:], 70000, 0) // dataLen 70000 > the 65535 server cap
	mc := &MorphedConn{
		Conn:   readOnlyConn{Reader: strings.NewReader(string(hdr[:]))},
		shaper: shaper.NoopShaper{},
	}
	buf := make([]byte, 1500)
	_, err := mc.Read(buf)
	if err == nil {
		t.Fatal("oversize morph data length was accepted")
	}
	if !strings.Contains(err.Error(), "out of range") {
		t.Fatalf("want out-of-range cap error, got %v", err)
	}
}

func TestReadPollResponseCapsContentLength(t *testing.T) {
	t.Parallel()

	resp := "HTTP/1.1 200 OK\r\nContent-Length: 2097152\r\n\r\n" // 2 MiB > maxPollBody (1 MiB)
	_, err := readPollResponse(bufio.NewReader(strings.NewReader(resp)))
	if err == nil {
		t.Fatal("oversize Content-Length was accepted")
	}
	if !strings.Contains(err.Error(), "cap") {
		t.Fatalf("want cap error, got %v", err)
	}

	// Under the cap the same reader path still returns the body, so the cap does
	// not reject legitimate responses.
	ok := "HTTP/1.1 200 OK\r\nContent-Length: 3\r\n\r\nabc"
	body, err := readPollResponse(bufio.NewReader(strings.NewReader(ok)))
	if err != nil || string(body) != "abc" {
		t.Fatalf("under-cap body: got %q err %v", body, err)
	}
}

// The fourth site, imap_camouflage.go, already caps the announced literal at
// maxIMAPLiteralLen (added in S3); this pins that the cap still exists so a
// later change cannot silently drop it.
func TestIMAPLiteralCapStillPresent(t *testing.T) {
	t.Parallel()
	if maxIMAPLiteralLen <= 0 || maxIMAPLiteralLen > 1<<24 {
		t.Fatalf("maxIMAPLiteralLen looks wrong: %d", maxIMAPLiteralLen)
	}
}
