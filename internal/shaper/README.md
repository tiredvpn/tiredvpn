# shaper

Behavioral traffic-shaping primitives that decouple the TLS transport from the
anti-DPI shape. Strategies (`reality`, `morph_*`, …) decide what the handshake
looks like; the shaper decides the size and spacing of what flows afterwards.

Layout:

| Path | Contents |
|---|---|
| `internal/shaper` | the `Shaper` interface and `NoopShaper` |
| `internal/shaper/dist` | distribution engines: Histogram, LogNormal, Pareto, MarkovBurst |
| `internal/shaper/presets` | ready-made profiles, the registry, and the negotiation IDs |
| `internal/strategy.ShaperFromConfig` | the wiring point for `MorphedConn` |

A `Shaper` answers four questions per frame — `NextPacketSize`, `NextDelay`,
`Wrap`, `Unwrap` — plus `Release` to hand pooled buffers back. `NoopShaper`
answers 0/0/passthrough and keeps the wire format byte-identical to pre-shaper
builds.

## Presets

| Preset | ID | DataPlaneSafe | Selectable via `-shaper` / TOML | Intended use |
|---|---:|---|---|---|
| *(none)* | 0 | — | omit the flag | legacy passthrough |
| `youtube_streaming` | 1 | yes | yes | data plane (HD video shape) |
| `chrome_browsing` | 2 | yes | yes | data plane (HTTPS browsing shape) |
| `imap_sync` | 3 | no | **no** | mail-sync shape; see below |
| `random_per_session` | 4 | yes | yes | data plane (rotates basis per session) |
| `bittorrent_idle` | — | no | **no** | cover traffic only (~7 s median gaps) |

The `DataPlaneSafe` flag gates the data-plane entry points. `presets.FromConfig`
(used by the `[shaper]` TOML section) and `presets.ByName` (used by the
`-shaper` flag) refuse anything not marked safe and return
`ErrPresetNotDataPlaneSafe`. `bittorrent_idle` earns the refusal honestly: its
inter-arrival distribution is built around multi-second gaps that are realistic
for a stalled BT swarm participant and catastrophic for user payload.

`imap_sync` is currently unreachable from configuration. It is registered as
not-data-plane-safe, so both `-shaper imap_sync` and `preset = "imap_sync"` fail
at startup:

```
Error: shaper "imap_sync": presets: preset is not safe for data plane: "imap_sync"
```

`ShaperByID` deliberately uses `ByNameAllowAny`, so the *server* can rebuild
`imap_sync` framing from a negotiated ID — but no client can negotiate ID 3,
because building the shaper is what produces the ID. Today it is reachable only
from `cmd/shaper-dump` and from library callers doing cover traffic. Either the
gate or the flag needs to move before it is a usable data-plane option.

Cover-traffic emitters that intentionally need long idle gaps call
`presets.ByNameAllowAny` and take responsibility for the schedule. Custom TOML
shapers (`shaper.custom = …`) are not gated at all — operators own the
parameters they author.

## Negotiation IDs

`ShaperID` is the 1-byte value the client advertises in the MRPH handshake so
the server reconstructs the matching framing. The mapping lives in
`presets/ids.go` and is a **stable wire contract**: never renumber an existing
entry, append new presets at the next free value.

Two properties make this cheap. The frame layout that drives `Unwrap` is
identical across all `distShaper` presets and independent of the seed, so the
server never learns the client's seed — the seed only affects the sender's own
sizing decisions. And ID 0 short-circuits before the table is consulted, so a
client that sends no ID byte is treated as noop and gets the legacy wire format.

`IDForName` maps an unknown name to `ShaperIDNoop` rather than erroring: a
misconfigured client degrades to legacy framing instead of negotiating an ID the
server cannot honour. A custom (non-preset) shaper has no ID for the same
reason — the server cannot reconstruct an arbitrary distribution, so it stays
noop on the wire while the client still shapes its own sends.

## Verification & testing

Four layers. Rerun any of them after touching a preset, a distribution, or the
morph framing path.

### Unit tests

```sh
go test ./internal/shaper/... ./internal/strategy/...
```

Covers the `Shaper` interface contract, the four `dist` engines, preset
registration and determinism, and the `MorphedConn` Wrap/Unwrap roundtrip.

### Statistical signature (χ² goodness-of-fit)

```sh
go test ./internal/shaper/presets -run TestPreset_ -v
```

Each histogram-backed preset is sampled 100k times and the empirical bin counts
are compared against the spec weights with Pearson's χ². The Wilson–Hilferty
cube-root transform yields the upper-tail p-value; tests pass when p > 0.05,
i.e. we cannot reject the null hypothesis that samples come from the specified
distribution. `random_per_session` instead runs a pairwise two-sample χ² across
10 seeds and requires ≥ 60% of pairs to be distinguishable at p < 0.01 — the
point of that preset is that two sessions do *not* look alike.

### End-to-end roundtrip

```sh
go test ./internal/integration -v
```

Two `MorphedConn` endpoints over `net.Pipe` exchange 1 MiB of random data with a
preset shaper on each side. A second case mixes presets to document that the
on-wire shape is per-side independent and the embedded length prefix carries the
application bytes regardless. A third pushes 4 MiB through a queue far smaller
than the payload to pin the pacer's graceful-overflow contract.

### Throughput overhead benchmark

```sh
go test ./internal/strategy -run=^$ -bench=BenchmarkMorphedConn -benchmem
```

Compares NoopShaper vs. `chrome_browsing` vs. `youtube_streaming` for a 64 KiB
payload. Saved baseline: `internal/strategy/testdata/shaper_overhead.txt`.

### Visual / Jupyter inspection

```sh
go run ./cmd/shaper-dump --preset chrome_browsing --samples 10000 --seed 42 --out /tmp/chrome.csv
```

Emits `idx,direction,size,delay_ms` and prints a per-direction mean/median/p95
summary on stderr. `shaper-dump` uses `ByNameAllowAny`, so it is the one place
`imap_sync` and `bittorrent_idle` can be inspected. CSVs are not committed.

## Performance characteristics

Numbers below are a **saved baseline from 2026-05-04**, not a guarantee. Source:
`internal/strategy/testdata/shaper_overhead_receiver.txt`
(`BenchmarkRealistic_*`, loopback TCP, 16 MiB payload, `-benchtime=3s`, 13th Gen
Core i7-1370P, linux/amd64). They reflect the async pacer plus writev
coalescing, the bucketed packet pool and pooled Wrap/Unwrap buffers. Re-measure
on your own hardware before quoting them.

| Preset | Throughput | bytes/op | allocs/op | Notes |
|---|---|---:|---:|---|
| Noop (baseline) | ~1023 MB/s | ~50 MB | 4 | direct passthrough, no shaping |
| `chrome_browsing` | ~191 MB/s | 5.8 MB | 127 k | recommended for HTTPS-mimicry data plane |
| `youtube_streaming` | sleep-bound | — | — | Pareto tail dominates wallclock |
| `random_per_session` | sleep-bound | — | — | same family as its basis preset |

That is ~81% throughput overhead against unshaped Noop, and it is the number to
plan around. The alloc cleanup that got `chrome_browsing` here cut heap traffic
by roughly 8× against the immediately preceding build; the earlier synchronous
shaper was slower still (1.75 MB/s on a differently-configured bench in
`shaper_perf_summary.md` — the two runs are not directly comparable, so do not
read a single speedup ratio across them). The original ≤30% overhead acceptance
bar from issue #18 was never met and the write-up recommends re-baselining it;
see `internal/strategy/testdata/shaper_perf_summary.md`.

Remaining headroom sits in the pacer goroutine handoff and channel ops, not in
allocation. Pursue it when a real workload needs it.

Sleep-bound presets (`youtube_streaming`, `random_per_session`) spend most of
their wallclock honoring inter-arrival distributions clamped to a 50 ms cap
(`pacerMaxDelay` in `internal/strategy/morph_pacer.go`); on bulk transfer that
caps throughput in single-digit MB/s. They are for workloads where the shape
matters more than the bandwidth — interactive, chat-like, browsing-like. For
bulk transfer prefer `chrome_browsing`.

Operators who need raw bandwidth run with no shaper (omit `[shaper]` in TOML and
`-shaper` on the command line); the rest of the anti-DPI stack — REALITY,
port hopping, RTT masking — stays effective on its own.
