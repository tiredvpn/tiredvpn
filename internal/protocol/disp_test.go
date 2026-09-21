package protocol

import (
	"errors"
	"io"
	"net"
	"testing"
	"time"
)

var allTypes = []byte{
	TypeStego, TypeRaw, TypeMorph, TypeWS,
	TypePolling, TypeConfusion, TypeAntiProbe, TypeMux,
}

// TestTypeConstantsDistinct guards against an accidental duplicate
// discriminator, which would route one protocol's connections to another.
func TestTypeConstantsDistinct(t *testing.T) {
	seen := map[byte]bool{}
	for _, b := range allTypes {
		if seen[b] {
			t.Errorf("duplicate protocol type byte 0x%02x", b)
		}
		seen[b] = true
	}
	if len(seen) != len(allTypes) {
		t.Fatalf("expected %d distinct types, got %d", len(allTypes), len(seen))
	}
}

func TestWriteReadDispatchRoundTrip(t *testing.T) {
	for _, pt := range allTypes {
		c1, c2 := net.Pipe()
		errCh := make(chan error, 1)
		go func() {
			errCh <- WriteDispatch(c1, pt)
		}()

		got, err := ReadDispatch(c2)
		if err != nil {
			t.Fatalf("ReadDispatch(0x%02x) error: %v", pt, err)
		}
		if got != pt {
			t.Errorf("ReadDispatch = 0x%02x, want 0x%02x", got, pt)
		}
		if werr := <-errCh; werr != nil {
			t.Errorf("WriteDispatch(0x%02x) error: %v", pt, werr)
		}
		_ = c1.Close()
		_ = c2.Close()
	}
}

// TestReadDispatchEOF: peer closes without sending a byte. io.ReadFull must
// surface an error (EOF), wrapped with the discriminator context.
func TestReadDispatchEOF(t *testing.T) {
	c1, c2 := net.Pipe()
	_ = c1.Close() // no byte written, reader sees EOF

	_, err := ReadDispatch(c2)
	if err == nil {
		t.Fatal("ReadDispatch on closed peer returned nil error")
	}
	if !errors.Is(err, io.EOF) {
		t.Errorf("expected wrapped io.EOF, got %v", err)
	}
	_ = c2.Close()
}

// TestReadDispatchDelayedWrite: a write that lands after a short delay (well
// inside the 10s read deadline) must still be read correctly. Positive control
// that the deadline does not prematurely abort a live-but-slow peer.
func TestReadDispatchDelayedWrite(t *testing.T) {
	c1, c2 := net.Pipe()
	go func() {
		time.Sleep(50 * time.Millisecond)
		_ = WriteDispatch(c1, TypeMux)
	}()
	got, err := ReadDispatch(c2)
	if err != nil {
		t.Fatalf("delayed ReadDispatch error: %v", err)
	}
	if got != TypeMux {
		t.Errorf("got 0x%02x, want 0x%02x", got, TypeMux)
	}
	_ = c1.Close()
	_ = c2.Close()
}

func TestWriteDispatchClosedConn(t *testing.T) {
	c1, c2 := net.Pipe()
	_ = c1.Close()
	_ = c2.Close()
	if err := WriteDispatch(c1, TypeStego); err == nil {
		t.Error("WriteDispatch on closed conn returned nil error")
	}
}
