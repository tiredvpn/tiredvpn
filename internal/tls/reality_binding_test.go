package tls

import (
	"bytes"
	"crypto/hmac"
	"crypto/rand"
	"crypto/sha256"
	stdtls "crypto/tls"
	"encoding/binary"
	"errors"
	"io"
	"net"
	"sync"
	"testing"
	"time"

	utls "github.com/refraction-networking/utls"
)

// Both TLS stacks must satisfy Exporter, or the client (uTLS) and the server
// (crypto/tls) could not share this code. A compile-time check is the whole
// point — if this stops compiling, B1 has lost its shared layer.
// Note the pointer receivers: ExportKeyingMaterial is declared on
// *ConnectionState in both stacks, so callers must hold the state by pointer.
var (
	_ Exporter = (*stdtls.ConnectionState)(nil)
	_ Exporter = (*utls.ConnectionState)(nil)
)

func testEKM(t *testing.T) []byte {
	t.Helper()
	ekm := make([]byte, BindingExporterLen)
	if _, err := rand.Read(ekm); err != nil {
		t.Fatalf("rand: %v", err)
	}
	return ekm
}

// pipeRoundTrip runs write on one end of a net.Pipe and read on the other.
// net.Pipe is unbuffered and synchronous, so the write has to run concurrently.
func pipeRoundTrip(t *testing.T, write func(io.Writer) error, read func(io.Reader) error) {
	t.Helper()
	client, server := net.Pipe()
	defer client.Close()
	defer server.Close()

	deadline := time.Now().Add(5 * time.Second)
	if err := client.SetDeadline(deadline); err != nil {
		t.Fatalf("SetDeadline: %v", err)
	}
	if err := server.SetDeadline(deadline); err != nil {
		t.Fatalf("SetDeadline: %v", err)
	}

	writeErr := make(chan error, 1)
	go func() { writeErr <- write(client) }()

	readErr := read(server)
	if err := <-writeErr; err != nil {
		t.Fatalf("write side: %v", err)
	}
	if readErr != nil {
		t.Fatalf("read side: %v", readErr)
	}
}

func TestClientBindingRoundTrip(t *testing.T) {
	secret := []byte("shared-secret")
	ekm := testEKM(t)
	const wantDispatch = byte(0x08)

	var got byte
	pipeRoundTrip(t,
		func(w io.Writer) error { return WriteClientBinding(w, secret, ekm, wantDispatch) },
		func(r io.Reader) error {
			d, err := ReadClientBinding(r, secret, ekm)
			got = d
			return err
		})

	if got != wantDispatch {
		t.Fatalf("dispatch = %#x, want %#x", got, wantDispatch)
	}
}

// TestBindingRejectsDivergentInputs is the property the whole exchange exists
// for: a peer that did not complete the same handshake, or does not hold the
// same secret, cannot produce the proof.
func TestBindingRejectsDivergentInputs(t *testing.T) {
	secret := []byte("shared-secret")
	ekm := testEKM(t)

	otherEKM := testEKM(t)
	otherSecret := []byte("a-different-secret")

	// A single flipped bit in the exporter must be enough.
	nearEKM := bytes.Clone(ekm)
	nearEKM[len(nearEKM)-1] ^= 0x01

	for _, tc := range []struct {
		name                string
		readSecret, readEKM []byte
	}{
		{"different exporter", secret, otherEKM},
		{"one-bit exporter change", secret, nearEKM},
		{"different secret", otherSecret, ekm},
		{"both different", otherSecret, otherEKM},
	} {
		t.Run(tc.name, func(t *testing.T) {
			var readErr error
			pipeRoundTrip(t,
				func(w io.Writer) error { return WriteClientBinding(w, secret, ekm, 0x08) },
				func(r io.Reader) error {
					_, readErr = ReadClientBinding(r, tc.readSecret, tc.readEKM)
					return nil
				})
			if !errors.Is(readErr, ErrBindingMismatch) {
				t.Fatalf("err = %v, want ErrBindingMismatch", readErr)
			}
		})
	}
}

// TestServerTimeRoundTrip covers the one-way clock hint. It carries no proof:
// authentication of the server is cert-HMAC's job, during the handshake.
func TestServerTimeRoundTrip(t *testing.T) {
	want := time.Now().Truncate(time.Second)

	var got time.Time
	pipeRoundTrip(t,
		func(w io.Writer) error { return WriteServerTime(w, want) },
		func(r io.Reader) error {
			ts, err := ReadServerTime(r)
			got = ts
			return err
		})

	if !got.Equal(want) {
		t.Fatalf("server time = %v, want %v", got, want)
	}
}

// TestServerTimeIsPadded checks the record varies in size like the client's,
// and lands in a single write.
func TestServerTimeIsPadded(t *testing.T) {
	sizes := make(map[int]bool)
	for range 32 {
		w := &countingWriter{}
		if err := WriteServerTime(w, time.Now()); err != nil {
			t.Fatalf("WriteServerTime: %v", err)
		}
		if w.writes != 1 {
			t.Fatalf("frame took %d writes, want 1", w.writes)
		}
		pad := w.buf.Len() - 8 - 2
		if pad < minBindingPad || pad > maxBindingPad {
			t.Fatalf("padding %d outside [%d, %d]", pad, minBindingPad, maxBindingPad)
		}
		sizes[w.buf.Len()] = true
	}
	if len(sizes) < 8 {
		t.Fatalf("only %d distinct sizes over 32 writes; padding is not varying", len(sizes))
	}
}

// TestClientProofIsDomainSeparated checks that the direction tag actually
// participates in the HMAC. It is the only proof left now that the server side
// moved to cert-HMAC, so nothing else would catch the tag being dropped — and a
// bare HMAC over the exporter would collide with any other use of the same
// secret and exporter pair.
func TestClientProofIsDomainSeparated(t *testing.T) {
	secret := []byte("shared-secret")
	ekm := testEKM(t)

	bare := hmac.New(sha256.New, secret)
	bare.Write(ekm)

	got := ClientProof(secret, ekm)
	if bytes.Equal(got[:], bare.Sum(nil)) {
		t.Fatal("ClientProof is a bare HMAC over the exporter; the direction tag is not mixed in")
	}

	// And the tag must be prefixed, not appended: prefixing is what makes the
	// tag unambiguous when the exporter length is fixed by the protocol.
	tagged := hmac.New(sha256.New, secret)
	tagged.Write([]byte(dirClientToServer))
	tagged.Write(ekm)
	if !bytes.Equal(got[:], tagged.Sum(nil)) {
		t.Fatal("ClientProof does not match HMAC(secret, \"c2s\" || ekm)")
	}
}

// TestBindingRejectsOversizedPadding covers the resource-exhaustion path: a
// peer claiming a huge padLen must get an error, not an allocation.
func TestBindingRejectsOversizedPadding(t *testing.T) {
	secret := []byte("shared-secret")
	ekm := testEKM(t)

	t.Run("client record", func(t *testing.T) {
		proof := ClientProof(secret, ekm)
		frame := append(bytes.Clone(proof[:]), 0x08)
		frame = binary.BigEndian.AppendUint16(frame, maxBindingPad+1)

		_, err := ReadClientBinding(bytes.NewReader(frame), secret, ekm)
		if !errors.Is(err, ErrBindingPadTooLarge) {
			t.Fatalf("err = %v, want ErrBindingPadTooLarge", err)
		}
	})

	t.Run("server time record", func(t *testing.T) {
		frame := binary.BigEndian.AppendUint64(nil, uint64(time.Now().Unix()))
		frame = binary.BigEndian.AppendUint16(frame, 0xFFFF)

		_, err := ReadServerTime(bytes.NewReader(frame))
		if !errors.Is(err, ErrBindingPadTooLarge) {
			t.Fatalf("err = %v, want ErrBindingPadTooLarge", err)
		}
	})

	t.Run("checked before the proof", func(t *testing.T) {
		// An oversized padLen from a peer with the wrong proof must still be
		// refused on the size, so the read never allocates on that path.
		frame := make([]byte, proofLen+1)
		frame = binary.BigEndian.AppendUint16(frame, 0xFFFF)
		_, err := ReadClientBinding(bytes.NewReader(frame), secret, ekm)
		if !errors.Is(err, ErrBindingPadTooLarge) {
			t.Fatalf("err = %v, want ErrBindingPadTooLarge", err)
		}
	})
}

func TestBindingRejectsTruncatedRecords(t *testing.T) {
	secret := []byte("shared-secret")
	ekm := testEKM(t)

	t.Run("short header", func(t *testing.T) {
		_, err := ReadClientBinding(bytes.NewReader(make([]byte, 10)), secret, ekm)
		if err == nil || errors.Is(err, ErrBindingMismatch) {
			t.Fatalf("err = %v, want an I/O error distinct from ErrBindingMismatch", err)
		}
	})

	t.Run("padding shorter than declared", func(t *testing.T) {
		proof := ClientProof(secret, ekm)
		frame := append(bytes.Clone(proof[:]), 0x08)
		frame = binary.BigEndian.AppendUint16(frame, 100)
		frame = append(frame, make([]byte, 20)...) // 80 bytes short

		_, err := ReadClientBinding(bytes.NewReader(frame), secret, ekm)
		if err == nil || errors.Is(err, ErrBindingMismatch) {
			t.Fatalf("err = %v, want an I/O error distinct from ErrBindingMismatch", err)
		}
	})
}

// TestBindingIsOneWriteAndOneRecordSized checks three things the wire shape
// depends on: the frame goes out in a single Write (so it becomes one TLS
// record), its size varies between connections, and it never lands small
// enough to stand out on its own.
func TestBindingIsOneWriteAndOneRecordSized(t *testing.T) {
	secret := []byte("shared-secret")
	ekm := testEKM(t)

	sizes := make(map[int]bool)
	for range 32 {
		w := &countingWriter{}
		if err := WriteClientBinding(w, secret, ekm, 0x08); err != nil {
			t.Fatalf("WriteClientBinding: %v", err)
		}
		if w.writes != 1 {
			t.Fatalf("frame took %d writes, want 1 (it must land in one TLS record)", w.writes)
		}
		total := w.buf.Len()
		payload := total - proofLen - 1 - 2
		if payload < minBindingPad || payload > maxBindingPad {
			t.Fatalf("padding %d outside [%d, %d]", payload, minBindingPad, maxBindingPad)
		}
		// The floor exists because the first application record's size is a
		// signal in itself: measured on a real capture it is the only thing in
		// that position, every connection, so a 99-byte version of it is a
		// distinctive small record right after the handshake.
		if total < 200 {
			t.Fatalf("frame is %d bytes; the floor on padding is meant to keep it clear of that", total)
		}
		sizes[total] = true
	}
	if len(sizes) < 8 {
		t.Fatalf("only %d distinct frame sizes over 32 writes; padding is not varying", len(sizes))
	}
}

type countingWriter struct {
	buf    bytes.Buffer
	writes int
}

func (w *countingWriter) Write(p []byte) (int, error) {
	w.writes++
	return w.buf.Write(p)
}

func TestClockOffset(t *testing.T) {
	t.Run("zero value is plain wall clock", func(t *testing.T) {
		var c ClockOffset
		if delta := time.Since(c.Now()).Abs(); delta > time.Second {
			t.Fatalf("unobserved offset shifted the clock by %v", delta)
		}
		if c.Offset() != 0 {
			t.Fatalf("unobserved offset = %v, want 0", c.Offset())
		}
	})

	t.Run("applies an observed forward skew", func(t *testing.T) {
		var c ClockOffset
		want := time.Now().Add(400 * time.Second)
		c.Observe(want)
		if delta := c.Now().Sub(want).Abs(); delta > time.Second {
			t.Fatalf("corrected clock is %v off the server time", delta)
		}
	})

	t.Run("applies an observed backward skew", func(t *testing.T) {
		var c ClockOffset
		want := time.Now().Add(-1234 * time.Second)
		c.Observe(want)
		if delta := c.Now().Sub(want).Abs(); delta > time.Second {
			t.Fatalf("corrected clock is %v off the server time", delta)
		}
		if c.Offset() > 0 {
			t.Fatalf("backward skew stored as a positive offset: %v", c.Offset())
		}
	})

	t.Run("last observation wins", func(t *testing.T) {
		var c ClockOffset
		c.Observe(time.Now().Add(400 * time.Second))
		want := time.Now().Add(10 * time.Second)
		c.Observe(want)
		if delta := c.Now().Sub(want).Abs(); delta > time.Second {
			t.Fatalf("second observation did not replace the first: off by %v", delta)
		}
	})

	t.Run("concurrent use", func(t *testing.T) {
		// The client observes from whichever connection finishes its binding
		// exchange while other goroutines are stamping new session_ids, so the
		// race detector needs to see that pattern.
		var c ClockOffset
		var wg sync.WaitGroup
		wg.Go(func() {
			for i := range 1000 {
				c.Observe(time.Now().Add(time.Duration(i%600) * time.Second))
			}
		})
		wg.Go(func() {
			for range 1000 {
				_ = c.Now()
				_ = c.Offset()
			}
		})
		wg.Wait()
	})
}

// TestBindingProofUsesFullExporter is a guard against a subtle weakening: if
// the proof only covered a prefix of the exporter, a MITM with partial control
// would have room to work.
func TestBindingProofUsesFullExporter(t *testing.T) {
	secret := []byte("shared-secret")
	base := testEKM(t)

	first := ClientProof(secret, base)
	for i := range base {
		mutated := bytes.Clone(base)
		mutated[i] ^= 0x80
		if ClientProof(secret, mutated) == first {
			t.Fatalf("exporter byte %d does not affect the proof", i)
		}
	}
}
