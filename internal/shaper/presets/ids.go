package presets

import (
	"fmt"

	"github.com/tiredvpn/tiredvpn/internal/shaper"
)

// ShaperID is the 1-byte identifier negotiated in the Morph handshake so the
// server can reconstruct the framing the client applied. ID 0 means "no
// shaper" (NoopShaper) and keeps the wire format byte-identical to pre-shaper
// builds — old clients that send no ID byte are treated as ID 0.
//
// IDs are a stable wire contract: never renumber an existing entry. Append new
// presets with the next free value. All non-zero IDs must map to presets whose
// Wrap output uses the distShaper frame layout, since the server reconstructs
// the payload via the matching shaper's Unwrap.
type ShaperID byte

const (
	// ShaperIDNoop is the passthrough shaper (legacy wire format).
	ShaperIDNoop ShaperID = 0
	// ShaperIDYouTube is youtube_streaming.
	ShaperIDYouTube ShaperID = 1
	// ShaperIDChrome is chrome_browsing.
	ShaperIDChrome ShaperID = 2
	// ShaperIDIMAP is imap_sync.
	ShaperIDIMAP ShaperID = 3
	// ShaperIDRandom is random_per_session.
	ShaperIDRandom ShaperID = 4
)

// idToName maps a negotiated ShaperID to its registry preset name. ID 0
// (noop) is intentionally absent — it is handled before this table is
// consulted.
var idToName = map[ShaperID]string{
	ShaperIDYouTube: PresetYouTubeStreaming,
	ShaperIDChrome:  PresetChromeBrowsing,
	ShaperIDIMAP:    PresetIMAPSync,
	ShaperIDRandom:  PresetRandomPerSession,
}

// nameToID is the inverse of idToName, built once at init.
var nameToID = func() map[string]ShaperID {
	m := make(map[string]ShaperID, len(idToName))
	for id, name := range idToName {
		m[name] = id
	}
	return m
}()

// IDForName returns the negotiation ID for a preset name. Unknown names map to
// ShaperIDNoop so a misconfigured client degrades to the legacy wire format
// rather than negotiating an ID the server cannot honour.
func IDForName(name string) ShaperID {
	if id, ok := nameToID[name]; ok {
		return id
	}
	return ShaperIDNoop
}

// ShaperByID builds the shaper that matches a negotiated ID. ID 0 returns a
// NoopShaper. Unknown non-zero IDs return an error so the server can fall back
// to noop rather than silently mis-framing the stream. The frame layout that
// drives Unwrap is identical across distShaper presets and independent of
// seed, so the server need not learn the client's seed to reconstruct the
// payload; seed only affects this side's outbound sizing decisions.
//
// Uses ByNameAllowAny because some presets (imap_sync) carry the
// not-data-plane-safe flag for cover-traffic gating, yet are valid framings
// once a peer has already negotiated them on the data plane.
func ShaperByID(id ShaperID, seed int64) (shaper.Shaper, error) {
	if id == ShaperIDNoop {
		return shaper.NoopShaper{}, nil
	}
	name, ok := idToName[id]
	if !ok {
		return nil, fmt.Errorf("presets: unknown shaper id %d", id)
	}
	return ByNameAllowAny(name, seed)
}
