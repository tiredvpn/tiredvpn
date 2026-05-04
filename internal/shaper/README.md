# shaper

Behavioral traffic-shaping primitives used to decouple TLS transport from
anti-DPI shape. The package defines the `Shaper` interface and a no-op
implementation; concrete distribution-driven shapers live in
`internal/shaper/dist`, ready-made profiles in `internal/shaper/presets`,
and the wiring point for `MorphedConn` is `internal/strategy.ShaperFromConfig`.

## Data-plane vs cover-traffic presets

Each preset carries a `DataPlaneSafe` metadata flag that splits profiles
into two categories:

| Preset               | DataPlaneSafe | Median delay | Intended use                  |
|----------------------|---------------|--------------|-------------------------------|
| `chrome_browsing`    | yes           | ~0.9 ms      | data plane (HTTPS browsing)   |
| `youtube_streaming`  | yes           | sub-second   | data plane (HD video)         |
| `random_per_session` | yes           | sub-second   | data plane (rotates basis)    |
| `bittorrent_idle`    | no            | ~7 s         | cover traffic only            |

The data-plane entry points — `presets.FromConfig` (used by TOML config) and
`presets.ByName` — refuse non-safe presets and return
`ErrPresetNotDataPlaneSafe`. Putting `bittorrent_idle` into a tunnel would
collapse throughput, since its inter-arrival distribution is built around
multi-second gaps that are realistic for a stalled BT swarm participant but
catastrophic for user payload.

Cover-traffic emitters that intentionally need long idle gaps must call
`presets.ByNameAllowAny` and assume responsibility for the schedule. Custom
TOML shapers (`shaper.custom = ...`) are not gated — operators take
responsibility for parameters they author.

## Verification & Testing

The shaping pipeline is verified at four layers; rerun any of them locally
when changing a preset, distribution, or the morph framing path.

### Unit tests

```sh
go test ./internal/shaper/... ./internal/strategy/...
```

Covers the `Shaper` interface contract, the four `dist` engines (Histogram,
LogNormal, Pareto, MarkovBurst), preset registration / determinism, and the
`MorphedConn` Wrap/Unwrap roundtrip.

### Statistical signature (χ² goodness-of-fit)

```sh
go test ./internal/shaper/presets -run TestPreset_ -v
```

Each histogram-backed preset (`chrome_browsing`, `youtube_streaming`,
`bittorrent_idle`) is sampled 100k times and the empirical bin counts are
compared against the spec weights with Pearson's χ². The Wilson–Hilferty
cube-root transform yields the upper-tail p-value; tests pass when p > 0.05
(i.e. we cannot reject the null hypothesis that samples come from the
specified distribution). `random_per_session` runs a pairwise two-sample χ²
across 10 seeds and requires ≥ 60% of pairs to be distinguishable at p < 0.01.

### End-to-end roundtrip

```sh
go test ./internal/integration -v
```

Two `MorphedConn` endpoints over `net.Pipe` exchange 1 MiB of random data
with a preset shaper on each side. A second case mixes presets to document
that the on-wire shape is per-side independent and the embedded length
prefix carries the application bytes regardless.

### Throughput overhead benchmark

```sh
go test ./internal/strategy -run=^$ -bench=BenchmarkMorphedConn -benchmem
```

Compares NoopShaper vs. `chrome_browsing` vs. `youtube_streaming` for a 64
KiB payload. Saved baseline: `internal/strategy/testdata/shaper_overhead.txt`.

### Visual / Jupyter inspection

```sh
go run ./cmd/shaper-dump --preset chrome_browsing --samples 10000 --seed 42 --out /tmp/chrome.csv
```

Emits `idx,direction,size,delay_ms` and prints a per-direction mean/median/p95
summary on stderr. CSVs are not committed.
