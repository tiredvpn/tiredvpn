package server

import (
	"bytes"
	"testing"
	"time"
)

// TestPollingNeverSkipsBytesAfterALostResponse is N4 of the PR #126
// acceptance run: "bad frame: length 916517968" after "poll error: i/o
// timeout". A poll whose response was lost comes back with the old ack, and
// the client's retry arrives within ~0.2 s - inside the server's 500 ms resend
// grace. The server then skipped the resend and handed out the NEXT chunk, and
// the client appended it where the lost bytes belonged: every frame boundary
// after that point was off.
//
// Whatever the server answers a client that is behind, it must be the bytes
// the client asks for or nothing - never bytes from further on.
func TestPollingNeverSkipsBytesAfterALostResponse(t *testing.T) {
	s := &HTTPPollingSession{toClient: &bytes.Buffer{}}
	a := bytes.Repeat([]byte{'A'}, 100)
	b := bytes.Repeat([]byte{'B'}, 100)

	s.WriteToClient(a)
	if got := s.ReadToClient(0); !bytes.Equal(got, a) {
		t.Fatalf("first poll got %q", got)
	}
	// The response carrying A is lost. More data arrives for the client.
	s.WriteToClient(b)

	// The retry, still acking 0, right away.
	got := s.ReadToClient(0)
	if len(got) > 0 && got[0] != 'A' {
		t.Fatalf("client behind at 0 was sent %q... - bytes past the ones it lost", got[:1])
	}

	// After the grace it gets A again, and only then B.
	time.Sleep(600 * time.Millisecond)
	if got := s.ReadToClient(0); !bytes.HasPrefix(got, a) {
		t.Fatalf("resend after the grace got %q, want A first", got)
	}
}
