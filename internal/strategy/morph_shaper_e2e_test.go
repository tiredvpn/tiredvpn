package strategy

import (
	"bytes"
	"crypto/rand"
	"encoding/binary"
	"io"
	"net"
	"sync"
	"testing"

	"github.com/tiredvpn/tiredvpn/internal/shaper"
	"github.com/tiredvpn/tiredvpn/internal/shaper/presets"
)

// TestMorphShaper_E2E_Upstream_1MB drives a client MorphedConn configured with
// the youtube_streaming shaper and reconstructs the payload on the other end
// using the same server-side framing the morph relay applies (read morph
// header -> Unwrap shaper frame). It confirms that 1 MB pushed through the
// shaped Write path arrives byte-identical after the server unwraps it.
//
// This mirrors handleMorphConnection's client->target loop: the wire carries
// [dataLen:4][paddingLen:2][shaperFrame] and the server feeds shaperFrame to
// shaper.Unwrap to recover the original bytes.
func TestMorphShaper_E2E_Upstream_1MB(t *testing.T) {
	clientShaper, err := presets.ByName(presets.PresetYouTubeStreaming, 42)
	if err != nil {
		t.Fatalf("build client shaper: %v", err)
	}
	// Server uses a different seed on purpose: Unwrap is seed-independent, so
	// the reconstruction must succeed regardless. ByID(0 seed) is what the
	// real server does.
	serverShaper, err := presets.ShaperByID(presets.ShaperIDYouTube, 0)
	if err != nil {
		t.Fatalf("build server shaper: %v", err)
	}

	cli, srv := net.Pipe()
	defer cli.Close()
	defer srv.Close()

	mc := &MorphedConn{Conn: cli, profile: YandexVideoProfile, shaper: clientShaper}

	const total = 1 << 20 // 1 MB
	payload := make([]byte, total)
	if _, err := rand.Read(payload); err != nil {
		t.Fatalf("rand: %v", err)
	}

	var got bytes.Buffer
	var serverErr error
	done := make(chan struct{})
	go func() {
		defer close(done)
		hdr := make([]byte, morphHeaderLen)
		for got.Len() < total {
			if _, err := io.ReadFull(srv, hdr); err != nil {
				serverErr = err
				return
			}
			dataLen, padLen := readFrameHeader(hdr)
			if dataLen == 0 {
				if padLen > 0 {
					if _, err := io.ReadFull(srv, make([]byte, padLen)); err != nil {
						serverErr = err
						return
					}
				}
				continue
			}
			frame := make([]byte, dataLen)
			if _, err := io.ReadFull(srv, frame); err != nil {
				serverErr = err
				return
			}
			if padLen > 0 {
				if _, err := io.ReadFull(srv, make([]byte, padLen)); err != nil {
					serverErr = err
					return
				}
			}
			got.Write(serverShaper.Unwrap([][]byte{frame}))
		}
	}()

	// Producer: chunked writes through the shaped Write path. net.Pipe is
	// synchronous so the pacer drains as the server reads.
	const chunk = 16 << 10
	for off := 0; off < total; off += chunk {
		end := off + chunk
		if end > total {
			end = total
		}
		if _, err := mc.Write(payload[off:end]); err != nil {
			t.Fatalf("write at %d: %v", off, err)
		}
	}

	<-done
	if serverErr != nil {
		t.Fatalf("server read: %v", serverErr)
	}
	if got.Len() != total {
		t.Fatalf("length mismatch: got %d want %d", got.Len(), total)
	}
	if !bytes.Equal(got.Bytes(), payload) {
		t.Fatal("payload mismatch after shaped upstream roundtrip")
	}
}

// TestMorphShaper_E2E_Downstream_1MB is the reverse direction: a simulated
// server Wraps + morph-frames 1 MB (mirroring writeMorphShapedFrames) and the
// client MorphedConn.Read reconstructs the original bytes via readShaped.
func TestMorphShaper_E2E_Downstream_1MB(t *testing.T) {
	clientShaper, err := presets.ByName(presets.PresetYouTubeStreaming, 7)
	if err != nil {
		t.Fatalf("build client shaper: %v", err)
	}
	serverShaper, err := presets.ShaperByID(presets.ShaperIDYouTube, 99)
	if err != nil {
		t.Fatalf("build server shaper: %v", err)
	}

	cli, srv := net.Pipe()
	defer cli.Close()
	defer srv.Close()

	mc := &MorphedConn{Conn: cli, profile: YandexVideoProfile, shaper: clientShaper}

	const total = 1 << 20
	payload := make([]byte, total)
	if _, err := rand.Read(payload); err != nil {
		t.Fatalf("rand: %v", err)
	}

	var wg sync.WaitGroup
	wg.Add(1)
	var serverErr error
	go func() {
		defer wg.Done()
		defer srv.Close()
		const chunk = 1400
		for off := 0; off < total; off += chunk {
			end := off + chunk
			if end > total {
				end = total
			}
			frames := serverShaper.Wrap(payload[off:end])
			for _, frame := range frames {
				out := make([]byte, morphHeaderLen+len(frame))
				binary.BigEndian.PutUint32(out[0:4], uint32(len(frame)))
				// paddingLen stays 0: shaper frame carries its own padding.
				copy(out[morphHeaderLen:], frame)
				if _, err := srv.Write(out); err != nil {
					serverErr = err
					serverShaper.Release(frames)
					return
				}
			}
			serverShaper.Release(frames)
		}
	}()

	got := make([]byte, 0, total)
	buf := make([]byte, 32<<10)
	for len(got) < total {
		n, err := mc.Read(buf)
		if n > 0 {
			got = append(got, buf[:n]...)
		}
		if err != nil {
			if err == io.EOF && len(got) == total {
				break
			}
			t.Fatalf("client read at %d: %v", len(got), err)
		}
	}
	wg.Wait()
	if serverErr != nil {
		t.Fatalf("server write: %v", serverErr)
	}
	if len(got) != total {
		t.Fatalf("length mismatch: got %d want %d", len(got), total)
	}
	if !bytes.Equal(got, payload) {
		t.Fatal("payload mismatch after shaped downstream roundtrip")
	}
}

// TestMorphShaper_NoopBackwardCompat asserts that a noop shaper (shaper ID 0,
// old client) keeps the legacy wire format: one Write produces exactly one
// [header:6][data][padding] frame whose data is the verbatim payload, so a
// pre-shaper server unwrapping nothing still recovers the bytes.
func TestMorphShaper_NoopBackwardCompat(t *testing.T) {
	cli, srv := net.Pipe()
	defer cli.Close()
	defer srv.Close()

	mc := &MorphedConn{Conn: cli, profile: YandexVideoProfile, shaper: shaper.NoopShaper{}}

	payload := []byte("hello legacy morph wire format")

	got := make(chan []byte, 1)
	go func() {
		hdr := make([]byte, morphHeaderLen)
		if _, err := io.ReadFull(srv, hdr); err != nil {
			got <- nil
			return
		}
		dataLen, padLen := readFrameHeader(hdr)
		data := make([]byte, dataLen)
		io.ReadFull(srv, data)
		if padLen > 0 {
			io.ReadFull(srv, make([]byte, padLen))
		}
		got <- data
	}()

	if _, err := mc.Write(payload); err != nil {
		t.Fatalf("write: %v", err)
	}
	recv := <-got
	if !bytes.Equal(recv, payload) {
		t.Fatalf("legacy frame data mismatch: got %q want %q", recv, payload)
	}
}
