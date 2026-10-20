package strategy

import (
	"bytes"
	"errors"
	"io"
	"net"
	"os"
	"testing"
	"time"
)

// TestConfusionReadResumesAfterDeadline pins that a read deadline firing in
// the middle of a record costs nothing: the timed-out read returns a timeout,
// and once the rest of the record arrives the next read opens it. Before the
// fix the bytes of the record read so far were dropped, the next read took
// body bytes for a header and the stream failed authentication for good
// (issue #98). The cut points cover each place a record read can stop: inside
// the header, between header and body, and inside the body.
func TestConfusionReadResumesAfterDeadline(t *testing.T) {
	secret := []byte(wireTestSecret)
	nonce, _ := NewConfusionNonce()

	for _, tc := range []struct {
		name string
		cut  int
	}{
		{"inside header", 1},
		{"between header and body", 2},
		{"inside body", 2 + 5},
	} {
		for _, mode := range []string{"Read", "ReadFrame"} {
			t.Run(tc.name+"/"+mode, func(t *testing.T) {
				rawCli, rawSrv := wireTCPPair(t)
				sealer, err := NewConfusionConn(rawCli, secret, nonce[:], confusionVariantHTTP, true)
				if err != nil {
					t.Fatalf("writer: %v", err)
				}
				reader, err := NewConfusionConn(rawSrv, secret, nonce[:], confusionVariantHTTP, false)
				if err != nil {
					t.Fatalf("reader: %v", err)
				}

				first := []byte("the record a deadline cut in two")
				second := []byte("and the one behind it")
				frame := sealer.SealFrames(first)
				next := sealer.SealFrames(second)

				if _, err := rawCli.Write(frame[:tc.cut]); err != nil {
					t.Fatal(err)
				}
				read := func() ([]byte, error) {
					if mode == "ReadFrame" {
						return reader.ReadFrame()
					}
					buf := make([]byte, 256)
					n, err := reader.Read(buf)
					return buf[:n], err
				}

				_ = reader.SetReadDeadline(time.Now().Add(100 * time.Millisecond))
				if got, err := read(); !errors.Is(err, os.ErrDeadlineExceeded) {
					t.Fatalf("read on a partial record = %q, %v; want a deadline error", got, err)
				}
				_ = reader.SetReadDeadline(time.Now().Add(5 * time.Second))

				if _, err := rawCli.Write(append(frame[tc.cut:], next...)); err != nil {
					t.Fatal(err)
				}
				for _, want := range [][]byte{first, second} {
					got, err := read()
					if err != nil {
						t.Fatalf("read after the deadline: %v", err)
					}
					if !bytes.Equal(got, want) {
						t.Fatalf("read after the deadline = %q, want %q", got, want)
					}
				}
			})
		}
	}
}

// TestConfusionEOFInsideRecord pins that a peer closing inside a record is
// reported as io.ErrUnexpectedEOF wherever the record was cut, and a close on
// a record boundary as io.EOF.
func TestConfusionEOFInsideRecord(t *testing.T) {
	secret := []byte(wireTestSecret)
	nonce, _ := NewConfusionNonce()

	for _, tc := range []struct {
		name string
		cut  int // bytes of the record sent before the close; -1 sends none
		want error
	}{
		{"on a boundary", -1, io.EOF},
		{"inside header", 1, io.ErrUnexpectedEOF},
		{"between header and body", 2, io.ErrUnexpectedEOF},
		{"inside body", 2 + 5, io.ErrUnexpectedEOF},
	} {
		t.Run(tc.name, func(t *testing.T) {
			a, b := net.Pipe()
			defer b.Close()
			sealer, _ := NewConfusionConn(a, secret, nonce[:], confusionVariantHTTP, true)
			reader, _ := NewConfusionConn(b, secret, nonce[:], confusionVariantHTTP, false)
			frame := sealer.SealFrames([]byte("cut short"))
			go func() {
				if tc.cut > 0 {
					a.Write(frame[:tc.cut])
				}
				a.Close()
			}()
			if _, err := reader.ReadFrame(); !errors.Is(err, tc.want) {
				t.Fatalf("err = %v, want %v", err, tc.want)
			}
		})
	}
}
