# Shaper performance fix verification

Verification run for issue #18 after PR #19 (DataPlaneSafe gating) and
PR #20 (async pacer goroutine + adaptive throttle + 50 ms delay cap +
1 s overflow timeout) merged into main.

Hardware: 13th Gen Intel Core i7-1370P, Linux amd64, kernel default
TCP buffers, kTLS available but not on this hop (loopback, no TLS).

## Results

| Preset            | Before fix (MB/s) | After fix - net.Pipe (MB/s) | After fix - real TCP (MB/s) | Overhead vs Noop (real TCP) | χ² test | Acceptance (≤30%) |
|-------------------|------------------:|----------------------------:|----------------------------:|----------------------------:|---------|-------------------|
| Noop              |             907.5 |                       907.5 |                       535.9 |                          0% | —       | reference         |
| chrome_browsing   |              1.75 |                        74.0 |                        54.1 |                       89.9% | pass    | NOT MET           |
| youtube_streaming |              0.23 |                         9.9 |                        12.9 |                       97.6% | pass    | NOT MET           |
| random_per_session|                 — |                           — |                        13.4 |                       97.5% | pass    | NOT MET           |

Sources: `shaper_overhead.txt` (pre-fix), `shaper_overhead_async.txt`
(post-PR-20 net.Pipe), `shaper_overhead_realistic.txt` (this run, real TCP).

## χ² regression

All four `TestPreset_*_StatisticalSignature` and the
`TestPreset_RandomPerSession_VariesAcrossSeeds` tests pass without any
relaxation. The 50 ms delay cap introduced in PR #20 affects inter-frame
delays only; the χ² tests in `internal/shaper/presets/stats_test.go` measure
`NextPacketSize` distributions, which are untouched.

## Did we hit the goal?

**No.** The async pacer fix delivered a 31× improvement on chrome
(1.75 → 54 MB/s on the deployment-realistic loopback-TCP benchmark) and
similar magnitude wins on youtube/random_per_session, but throughput
overhead vs Noop remains at ~90 % across the board — far above the 30 %
acceptance bar from the issue.

The remaining cost is **structural framing overhead**, not the producer
sleep stall PR #20 fixed. With chrome_browsing's mean ~600 B frame size, a
16 MiB payload generates ~28 000 frames × (allocation in `buildFrame`,
length-prefix write, `Wrap` slice creation, individual `Conn.Write` syscall,
shaper `NextPacketSize` + `NextDelay` RNG calls). The bench shows ~250 k
allocs and 70 MB allocated for chrome on a 16 MiB transfer — that's the
ceiling. youtube_streaming's ~120 B avg frame multiplies it by 5×.

Concretely, the issue as filed ("shaper time.Sleep dominates write path")
is fixed: the producer no longer blocks on sub-tick sleeps, and the cure
demonstrably moves the needle by 30×+. But the original 30 % overhead bar
turns out to be unreachable from this layer alone; getting there requires
follow-up work on the framing layer (per-frame alloc reduction, batching
multiple shaped frames into one Conn.Write, or a pool-aware Wrap path) and
perhaps a re-baselined target that accounts for "shaper produces small
packets — that is the design".

## Recommendation

- **Do not close #18 in this PR.** The acceptance criterion was not met.
- Open a follow-up issue scoped to "reduce per-frame allocation in
  morph framing layer" (target candidates: `buildFrame` second alloc,
  pre-sized Wrap output, scatter/gather writev in pacer). A reasonable
  target is half the current overhead (45 %) at chrome_browsing, with
  the understanding that small-packet presets like youtube_streaming
  inherently cap above 50 % overhead due to per-syscall and per-allocation
  fixed cost regardless of what we do above the framing layer.
- This PR delivers the verification harness, regression smoke tests for the
  pacer's saturation/overflow contracts, and end-to-end large-payload +
  graceful-overflow assertions, all running green under `-race`.
