package strategy

import (
	"io"

	"github.com/tiredvpn/tiredvpn/internal/config/toml"
	"github.com/tiredvpn/tiredvpn/internal/shaper"
	"github.com/tiredvpn/tiredvpn/internal/shaper/presets"
)

// isNoopShaper reports whether sh is the passthrough shaper. The legacy Write
// path stays bit-identical to pre-shaper builds when this is true, so existing
// servers keep wire compatibility regardless of how a connection is built.
func isNoopShaper(sh shaper.Shaper) bool {
	if sh == nil {
		return true
	}
	switch sh.(type) {
	case shaper.NoopShaper, *shaper.NoopShaper:
		return true
	}
	return false
}

// ensurePacer lazily starts the async write pacer for this connection.
// Idempotent and safe to call from any goroutine.
func (mc *MorphedConn) ensurePacer() {
	mc.pacerOnce.Do(func() {
		mc.pacer = newWritePacer(mc.Conn, mc.shaper)
	})
}

// writeShaped emits one or more frames per Write according to the shaper's
// Wrap/NextPacketSize decisions. Inter-frame spacing and Conn.Write are
// delegated to a per-connection pacer goroutine so the producer never
// blocks on time.Sleep at sub-tick granularity (see adr-shaper-perf.md).
func (mc *MorphedConn) writeShaped(p []byte) (int, error) {
	mc.ensurePacer()

	frames := mc.shaper.Wrap(p)
	if len(frames) == 0 {
		mc.shaper.Release(frames)
		return len(p), nil
	}

	for _, frame := range frames {
		target := mc.shaper.NextPacketSize(shaper.DirectionUp)
		padLen := target - len(frame) - morphHeaderLen
		if padLen < 0 {
			padLen = 0
		}
		packet, bucket, _ := buildFrame(frame, padLen)

		if mc.rateLimiter != nil {
			mc.rateLimiter.Wait(len(packet))
		}
		if err := mc.pacer.enqueue(pacedFrame{packet: packet, bucket: bucket}); err != nil {
			if mc.rateLimiter != nil {
				mc.rateLimiter.RecordFailure()
			}
			mc.shaper.Release(frames)
			return 0, err
		}
		if mc.rateLimiter != nil {
			mc.rateLimiter.RecordSuccess()
		}
		mc.packetsSent++
		mc.bytesSent += int64(len(packet))
	}
	mc.shaper.Release(frames)
	return len(p), nil
}

// readShaped pulls a single Morph frame off the wire, strips padding and
// hands the framed payload to shaper.Unwrap. Calling Unwrap with a single
// frame matches the documented streaming contract: NoopShaper is identity,
// distribution-driven shapers strip per-frame padding/markers as needed.
func (mc *MorphedConn) readShaped(p []byte) (int, error) {
	header := make([]byte, morphHeaderLen)
	if _, err := io.ReadFull(mc.Conn, header); err != nil {
		return 0, err
	}
	dataLen, paddingLen := readFrameHeader(header)

	// Dummy frames carry no payload (keepalive). Match the legacy contract:
	// signal the TUN layer with the 4-zero-byte sentinel.
	if dataLen == 0 {
		if paddingLen > 0 {
			discard := make([]byte, paddingLen)
			if _, err := io.ReadFull(mc.Conn, discard); err != nil {
				return 0, err
			}
		}
		if len(p) >= 4 {
			p[0], p[1], p[2], p[3] = 0, 0, 0, 0
			return 4, nil
		}
		return mc.readShaped(p)
	}

	totalPayload := dataLen + paddingLen
	payload := make([]byte, totalPayload)
	n, err := io.ReadFull(mc.Conn, payload)
	if err != nil {
		return 0, err
	}
	frame := payload[:dataLen]
	data := mc.shaper.Unwrap([][]byte{frame})

	mc.packetsRecv++
	mc.bytesRecv += int64(n)

	copied := copy(p, data)
	if copied < len(data) {
		mc.readBuf = append(mc.readBuf, data[copied:]...)
	}
	if mc.rateLimiter != nil {
		mc.rateLimiter.Wait(copied)
	}
	return copied, nil
}

// ShaperFromConfig builds a Shaper for MorphedConn from the parsed TOML
// [shaper] section. A nil cfg or one with neither preset nor custom returns
// NoopShaper so callers can always safely pass through; otherwise the
// construction is delegated to internal/shaper/presets.FromConfig.
func ShaperFromConfig(cfg *toml.ShaperConfig) (shaper.Shaper, error) {
	if cfg == nil {
		return shaper.NoopShaper{}, nil
	}
	if cfg.Preset == "" && cfg.Custom == nil {
		return shaper.NoopShaper{}, nil
	}
	return presets.FromConfig(*cfg)
}
