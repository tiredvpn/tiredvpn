package tun

import (
	"net"
	"os"
	"sync/atomic"
	"testing"
	"time"

	"github.com/tiredvpn/tiredvpn/internal/log"
	"github.com/tiredvpn/tiredvpn/internal/strategy"
	"github.com/xtaci/smux"
)

// smuxStreamPair returns the client end of a real smux stream whose server end
// accepts it and then says nothing - the REALITY tunnel conn when the server
// has gone quiet.
func smuxStreamPair(t *testing.T) net.Conn {
	t.Helper()
	cliRaw, srvRaw := net.Pipe()
	cfg := smux.DefaultConfig()
	srv, err := smux.Server(srvRaw, cfg)
	if err != nil {
		t.Fatalf("smux.Server: %v", err)
	}
	cli, err := smux.Client(cliRaw, cfg)
	if err != nil {
		t.Fatalf("smux.Client: %v", err)
	}
	t.Cleanup(func() { cli.Close(); srv.Close() })
	go func() {
		s, err := srv.AcceptStream()
		if err == nil {
			t.Cleanup(func() { s.Close() })
		}
	}()
	stream, err := cli.OpenStream()
	if err != nil {
		t.Fatalf("OpenStream: %v", err)
	}
	return stream
}

// TestSilentSmuxStreamCountsAsSilence is N1 of the PR #126 acceptance run. The
// REALITY tunnel conn is a smux stream, and smux v2 reports its read deadline
// as errors.WithStack(errors.New("timeout")) - neither os.ErrDeadlineExceeded
// nor a net.Error. Every REALITY silence on the stand went past the error check,
// so D1 never armed the gate and D6 never charged an endpoint. The tests that
// passed fed handleDisconnect a net.OpError, which no REALITY session produces.
//
// Here the read loop runs on a real smux stream and the client's own deadline
// fires.
func TestSilentSmuxStreamCountsAsSilence(t *testing.T) {
	old := readTimeout
	readTimeout = 200 * time.Millisecond
	t.Cleanup(func() { readTimeout = old })

	m := strategy.NewManager()
	m.SetConnectivityChecker(strategy.NewConnectivityChecker("127.0.0.1:1", time.Second, true))
	v := &VPNClient{
		running:     1,
		stopCh:      make(chan struct{}),
		manager:     m,
		conn:        smuxStreamPair(t),
		connectedAt: time.Now().Add(-5 * time.Minute),
		lastRx:      time.Now(),
	}
	out := &stopOnDisconnectLog{v: v}
	log.SetOutput(out)
	t.Cleanup(func() { log.SetOutput(os.Stderr) })

	done := make(chan struct{})
	go func() {
		v.readFromServer()
		close(done)
	}()
	select {
	case <-done:
	case <-time.After(5 * time.Second):
		atomic.StoreInt32(&v.running, 0)
		t.Fatalf("read loop did not return; log:\n%s", out)
	}
	if !m.PreflightArmed() {
		t.Fatalf("a real smux read deadline was not taken for silence; log:\n%s", out)
	}
}
