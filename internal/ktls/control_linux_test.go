//go:build linux

package ktls

import (
	"bytes"
	"crypto/tls"
	"errors"
	"io"
	"strings"
	"testing"
)

// These run without kernel TLS: they pin the logic the handover tests exercise
// only where the tls module is loaded.

func hsMsg(typ byte, body []byte) []byte {
	n := len(body)
	return append([]byte{typ, byte(n >> 16), byte(n >> 8), byte(n)}, body...)
}

func TestConsumeControl(t *testing.T) {
	ticket := hsMsg(msgTypeNewSessionTicket, bytes.Repeat([]byte{0xab}, 300))
	keyUpdate := hsMsg(msgTypeKeyUpdate, []byte{0})
	finished := hsMsg(20, make([]byte, 32))

	cases := []struct {
		name    string
		typ     byte
		records [][]byte // bytes of one non-data message stream, as successive reads
		wantErr string   // "" = no error; "EOF" = io.EOF
		left    int      // bytes still held after the last record
	}{
		{"ticket in one record", recordTypeHandshake, [][]byte{ticket}, "", 0},
		{"ticket split over three reads", recordTypeHandshake, [][]byte{ticket[:2], ticket[2:100], ticket[100:]}, "", 0},
		{"ticket header only so far", recordTypeHandshake, [][]byte{ticket[:4]}, "", 4},
		{"two tickets in one record", recordTypeHandshake, [][]byte{append(append([]byte{}, ticket...), ticket...)}, "", 0},
		{"key update", recordTypeHandshake, [][]byte{keyUpdate}, "KeyUpdate", 0},
		{"ticket then key update", recordTypeHandshake, [][]byte{append(append([]byte{}, ticket...), keyUpdate...)}, "KeyUpdate", 0},
		{"unexpected handshake message", recordTypeHandshake, [][]byte{finished}, "post-handshake message type 20", 0},
		{"close_notify", recordTypeAlert, [][]byte{{1, 0}}, "EOF", 0},
		{"close_notify split", recordTypeAlert, [][]byte{{1}, {0}}, "EOF", 0},
		{"fatal alert", recordTypeAlert, [][]byte{{2, 40}}, "remote alert 40", 0},
		{"change_cipher_spec", 20, [][]byte{{1}}, "record type 20", 0},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			c := &Conn{}
			c.rx.ctrlTyp = tc.typ
			var err error
			for i, rec := range tc.records {
				c.rx.ctrl = append(c.rx.ctrl, rec...)
				err = c.consumeControl()
				if err != nil && i != len(tc.records)-1 {
					t.Fatalf("error before the last read: %v", err)
				}
			}
			switch tc.wantErr {
			case "":
				if err != nil {
					t.Fatalf("unexpected error: %v", err)
				}
			case "EOF":
				if !errors.Is(err, io.EOF) {
					t.Fatalf("want io.EOF, got %v", err)
				}
			default:
				if err == nil || !strings.Contains(err.Error(), tc.wantErr) {
					t.Fatalf("want error containing %q, got %v", tc.wantErr, err)
				}
			}
			if err == nil && len(c.rx.ctrl) != tc.left {
				t.Fatalf("%d bytes left held, want %d", len(c.rx.ctrl), tc.left)
			}
		})
	}
}

// TestTLSReceiveBuffers pins the reflection into crypto/tls: the fields must be
// found on this toolchain, and they must be the live buffers, not copies.
func TestTLSReceiveBuffers(t *testing.T) {
	client, server := tls13Pair(t, tls.VersionTLS13)
	bufs, err := tlsReceiveBuffers(client)
	if err != nil {
		t.Fatalf("crypto/tls internals moved on this Go version: %v", err)
	}

	go server.Write([]byte("0123456789"))
	one := make([]byte, 1)
	if _, err := io.ReadFull(client, one); err != nil {
		t.Fatal(err)
	}
	if bufs.input.Len() != 9 {
		t.Fatalf("input shows %d bytes after reading 1 of 10, want 9: not the live buffer", bufs.input.Len())
	}

	// restore must feed data back so the next Read returns it first.
	rest := make([]byte, 9)
	if _, err := io.ReadFull(client, rest); err != nil {
		t.Fatal(err)
	}
	bufs.restore([]byte("back"))
	got := make([]byte, 4)
	if _, err := io.ReadFull(client, got); err != nil || string(got) != "back" {
		t.Fatalf("after restore Read gave %q, %v", got, err)
	}
}
