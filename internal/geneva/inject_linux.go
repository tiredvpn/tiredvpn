//go:build linux

package geneva

import (
	"context"
	"fmt"
	"net"
	"syscall"
	"time"

	nfqueue "github.com/florianl/go-nfqueue"
	"github.com/tiredvpn/tiredvpn/internal/log"
)

// InjectorPacketMark is set via SO_MARK on the raw socket used to inject
// additional packets (fragments/duplicates). Exclude it from the NFQUEUE rule
// so injected packets don't re-enter the queue and loop:
//
//	iptables -I OUTPUT -p tcp -d <server-ip> -m mark ! --mark 0x54495245 -j NFQUEUE --queue-num <N>
const InjectorPacketMark = 0x54495245 // "TIRE"

// Injector intercepts outgoing TCP packets via Linux NFQUEUE and applies
// Geneva strategies before releasing them to the kernel.
//
// Prerequisites:
//   - CAP_NET_ADMIN
//   - iptables rule with mark exclusion (see InjectorPacketMark):
//     iptables -I OUTPUT -p tcp -d <server-ip> -m mark ! --mark 0x54495245 -j NFQUEUE --queue-num <N>
type Injector struct {
	strategies []*Strategy
	queueNum   uint16
	nfq        *nfqueue.Nfqueue
	rawFd      int
	cancel     context.CancelFunc
}

// NewInjector creates an Injector for the given NFQUEUE number and strategies.
func NewInjector(queueNum uint16, strategies []*Strategy) *Injector {
	return &Injector{
		queueNum:   queueNum,
		strategies: strategies,
		rawFd:      -1,
	}
}

// Start opens the NFQUEUE and begins processing packets.
// Returns an error immediately if CAP_NET_ADMIN is unavailable.
func (inj *Injector) Start(ctx context.Context) error {
	// Raw socket is needed to inject additional packets (fragments, duplicates)
	// when a strategy produces more than one output packet.
	fd, err := syscall.Socket(syscall.AF_INET, syscall.SOCK_RAW, syscall.IPPROTO_RAW)
	if err != nil {
		return fmt.Errorf("geneva injector: raw socket failed (need CAP_NET_ADMIN): %w", err)
	}
	if err := syscall.SetsockoptInt(fd, syscall.IPPROTO_IP, syscall.IP_HDRINCL, 1); err != nil {
		syscall.Close(fd)
		return fmt.Errorf("geneva injector: IP_HDRINCL: %w", err)
	}
	// Mark injected packets so the iptables NFQUEUE rule (which must use
	// ! --mark InjectorPacketMark) does not re-queue them, preventing an
	// infinite re-injection loop.
	if err := syscall.SetsockoptInt(fd, syscall.SOL_SOCKET, syscall.SO_MARK, InjectorPacketMark); err != nil {
		syscall.Close(fd)
		return fmt.Errorf("geneva injector: SO_MARK: %w", err)
	}
	inj.rawFd = fd

	cfg := &nfqueue.Config{
		NfQueue:      inj.queueNum,
		MaxPacketLen: 65535,
		MaxQueueLen:  128,
		Copymode:     nfqueue.NfQnlCopyPacket,
		WriteTimeout: 15 * time.Millisecond,
	}
	nfq, err := nfqueue.Open(cfg)
	if err != nil {
		syscall.Close(inj.rawFd)
		inj.rawFd = -1
		return fmt.Errorf("geneva injector: nfqueue open failed: %w", err)
	}
	inj.nfq = nfq

	innerCtx, cancel := context.WithCancel(ctx)
	inj.cancel = cancel

	hook := func(a nfqueue.Attribute) int {
		if a.PacketID == nil || a.Payload == nil {
			if a.PacketID != nil {
				inj.nfq.SetVerdict(*a.PacketID, nfqueue.NfAccept)
			}
			return 0
		}
		inj.processPacket(*a.PacketID, *a.Payload)
		return 0
	}

	errFn := func(e error) int {
		select {
		case <-innerCtx.Done():
			return 1
		default:
			log.Debug("Geneva injector: nfqueue error: %v", e)
			return 0
		}
	}

	if err := inj.nfq.RegisterWithErrorFunc(innerCtx, hook, errFn); err != nil {
		inj.nfq.Close()
		syscall.Close(inj.rawFd)
		inj.rawFd = -1
		return fmt.Errorf("geneva injector: register failed: %w", err)
	}

	log.Info("Geneva injector: active on queue %d (%d strategies)", inj.queueNum, len(inj.strategies))
	return nil
}

func (inj *Injector) processPacket(id uint32, packet []byte) {
	results := [][]byte{packet}
	for _, strat := range inj.strategies {
		var next [][]byte
		for _, pkt := range results {
			modified, err := strat.Apply(pkt, true)
			if err != nil {
				log.Debug("Geneva injector: strategy %q error: %v", strat.Trigger.Protocol, err)
				next = append(next, pkt)
				continue
			}
			if len(modified) == 0 {
				// Strategy dropped this packet - skip it
				continue
			}
			next = append(next, modified...)
		}
		results = next
	}

	if len(results) == 0 {
		inj.nfq.SetVerdict(id, nfqueue.NfDrop)
		return
	}

	// First result goes back via NFQUEUE (possibly modified);
	// remaining results (fragments, duplicates) go via raw socket.
	if err := inj.nfq.SetVerdictModPacket(id, nfqueue.NfAccept, results[0]); err != nil {
		log.Debug("Geneva injector: SetVerdictModPacket error: %v", err)
	}

	for _, extra := range results[1:] {
		if err := inj.injectRaw(extra); err != nil {
			log.Debug("Geneva injector: inject extra packet failed: %v", err)
		}
	}
}

func (inj *Injector) injectRaw(packet []byte) error {
	if len(packet) < 20 {
		return fmt.Errorf("packet too short (%d bytes)", len(packet))
	}
	dstIP := net.IP(packet[16:20])
	addr := &syscall.SockaddrInet4{}
	copy(addr.Addr[:], dstIP.To4())
	return syscall.Sendto(inj.rawFd, packet, 0, addr)
}

// Stop cancels the packet-processing goroutine and releases resources.
func (inj *Injector) Stop() {
	if inj.cancel != nil {
		inj.cancel()
		inj.cancel = nil
	}
	if inj.nfq != nil {
		inj.nfq.Close()
		inj.nfq = nil
	}
	if inj.rawFd >= 0 {
		syscall.Close(inj.rawFd)
		inj.rawFd = -1
	}
	log.Info("Geneva injector: stopped")
}
