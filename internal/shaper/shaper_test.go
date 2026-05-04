package shaper

import (
	"bytes"
	"testing"
	"time"
)

func TestNoopShaper_ImplementsInterface(t *testing.T) {
	var _ Shaper = NoopShaper{}
	var _ Shaper = NewNoopShaper()
}

func TestNoopShaper_NextPacketSize_Deterministic(t *testing.T) {
	s := NewNoopShaper()
	for _, d := range []Direction{DirectionUp, DirectionDown} {
		for range 5 {
			if got := s.NextPacketSize(d); got != 0 {
				t.Fatalf("NextPacketSize(%v) = %d, want 0", d, got)
			}
		}
	}
}

func TestNoopShaper_NextDelay_Zero(t *testing.T) {
	s := NewNoopShaper()
	for _, d := range []Direction{DirectionUp, DirectionDown} {
		for range 5 {
			if got := s.NextDelay(d); got != time.Duration(0) {
				t.Fatalf("NextDelay(%v) = %v, want 0", d, got)
			}
		}
	}
}

func TestNoopShaper_WrapUnwrap_Roundtrip(t *testing.T) {
	s := NewNoopShaper()
	cases := [][]byte{
		nil,
		{},
		[]byte("hello"),
		bytes.Repeat([]byte{0xAB}, 4096),
	}
	for _, in := range cases {
		frames := s.Wrap(in)
		out := s.Unwrap(frames)
		if len(in) == 0 && len(out) == 0 {
			continue
		}
		if !bytes.Equal(in, out) {
			t.Fatalf("roundtrip mismatch: in=%d bytes out=%d bytes", len(in), len(out))
		}
	}
}

func TestNoopShaper_Wrap_SingleFrame(t *testing.T) {
	s := NewNoopShaper()
	payload := []byte("packet")
	frames := s.Wrap(payload)
	if len(frames) != 1 {
		t.Fatalf("Wrap returned %d frames, want 1", len(frames))
	}
	if !bytes.Equal(frames[0], payload) {
		t.Fatalf("Wrap altered payload: got %q want %q", frames[0], payload)
	}
}

func TestNoopShaper_Unwrap_ConcatenatesInOrder(t *testing.T) {
	s := NewNoopShaper()
	frames := [][]byte{[]byte("foo"), []byte("bar"), []byte("baz")}
	got := s.Unwrap(frames)
	want := []byte("foobarbaz")
	if !bytes.Equal(got, want) {
		t.Fatalf("Unwrap = %q, want %q", got, want)
	}
}

func TestNoopShaper_Release_NoPanic(t *testing.T) {
	s := NewNoopShaper()
	// Nil, empty, single, multi — all must be no-ops without panicking.
	s.Release(nil)
	s.Release([][]byte{})
	s.Release([][]byte{[]byte("a")})
	s.Release([][]byte{[]byte("a"), []byte("bc")})
}

func TestNoopShaper_Unwrap_EmptyInput(t *testing.T) {
	s := NewNoopShaper()
	if got := s.Unwrap(nil); got != nil {
		t.Fatalf("Unwrap(nil) = %v, want nil", got)
	}
	if got := s.Unwrap([][]byte{}); got != nil {
		t.Fatalf("Unwrap([]) = %v, want nil", got)
	}
}
