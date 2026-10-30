# CC adaptive benchmark report

Date: 2026-07-24

Environment: Apple M4, macOS 26.4.1 (25E253), Go 1.24.3 darwin/arm64. The
OpenResty smoke used the pinned arm64 image
`openresty/openresty@sha256:b141c051015a17c8bbf59f19a7d412659b274797c1f62a89ced10bedaee19eb8`
(OpenResty 1.27.1.2).

## Decision results

| Limiter | Correct labels | Accuracy | False boundary burst |
| --- | ---: | ---: | ---: |
| Fixed-window test reference | 2,100 / 2,200 | 95.45% | 100 |
| Token-bucket test reference | 2,200 / 2,200 | 100% | 0 |
| Production integer GCRA | 2,200 / 2,200 | 100% | 0 |

The labels and limitations are defined in `workload.md`. This demonstrates the
specific fixed-window boundary behavior; it is not a general claim that GCRA is
always more accurate for every traffic distribution.

The final deterministic metric run used five latency trials with 20,000
operations per trial and produced these observed percentiles:

| Limiter | p50 | p95 | p99 |
| --- | ---: | ---: | ---: |
| Fixed-window test reference | 2 ns | 4 ns | 5 ns |
| Token-bucket test reference | 2 ns | 6 ns | 7 ns |
| Production rational-debt GCRA | 62 ns | 155 ns | 272 ns |

The final `go test -benchmem -benchtime=1s -count=5` run gave these five-trial
ranges:

| Limiter | ns/op range | B/op | allocs/op |
| --- | ---: | ---: | ---: |
| Fixed-window test reference | 1.257-1.634 | 0 | 0 |
| Token-bucket test reference | 3.080-3.714 | 0 | 0 |
| Production rational-debt GCRA | 67.19-97.54 | 0 | 0 |

The reference implementations omit production policy lookup and logging, so
their absolute latency is not a production comparison. GCRA's result includes
the real key lookup, per-key lock, rational debt update, monotonic guard, TTL,
and decision fact path. A 100,000-key heap capacity sample measured
approximately 194 bytes per active GCRA key,
including map/key/state overhead; the two isolated reference structs are 32
bytes before map overhead. This is a one-run capacity estimate, not an RSS
guarantee.

Shared-host load can widen these latency distributions. An isolated-node
capacity gate remains required before production sizing.

The high-rate regression configured 999,999 requests/second with burst 100 and
submitted one request at every integer microsecond in the first second. The
production limiter allowed 1,000,000 requests, a +1 request/second difference
covered by the initial burst; the former rounded-interval implementation would
have allowed only about 500,000 under this timestamp pattern.

The capacity boundary regressions also passed with capacity one: a higher policy
revision admitted its first adaptive group without counting the prior revision,
and both Go state stores reclaimed an older saturated-expiry entry at
`2^53-1` without deleting a new entry touched on that same tick. The shared
Go/Lua parity fixture accepts `2^53-1` and saturates next-eligible time there.
Separate Go compiler and Lua policy-load checks reject `2^53` through the
policy/input bounds.

## Adaptive results

| Profile | Usable suggestions | Final rate (requests/s) | Maximum suggestion step (requests/s) | Recovery |
| --- | ---: | ---: | ---: | ---: |
| Normal | 16 | 50 | 0 | N/A |
| Periodic | 8 | 100 | 58 | N/A |
| Spike | 25 | 52 | 50 | 11 buckets to return to <=55 requests/s |
| Attack training | 8 | 100 | 0 | N/A |
| Low sample | 0 | baseline 100 | 0 | insufficient samples |

Every usable result remained `adaptive_shadow_only` with `apply=false`; the
test does not manufacture a false-positive count for a non-enforcing mode.
Attack samples were capped
at the administrator's static 100 requests/second limit; low samples returned
`adaptive_insufficient_samples`. The periodic sequence shows substantial
suggestion movement, which is why shadow observation and approval remain
mandatory rather than enabling automatic enforcement by default.

## Reproduce

From `agents/edge-agent`:

```sh
GOWORK=off go test -count=1 -run 'TestLimiterComparisonMetrics|TestAdaptiveScenarioMetrics|TestStateMemoryMetrics' -v ./internal/ccadaptive
GOWORK=off go test -run '^$' -bench '^BenchmarkLimiters$' -benchmem -benchtime=1s -count=5 ./internal/ccadaptive
```

From the repository root:

```sh
edge/openresty/ccadaptive/smoke.sh
```

The smoke runs two OpenResty workers and the production Lua module. It covers
the shared Go/Lua parity fixture, exact identifier grammar, revision and
colon-safe keys, rational 999,999 requests/second debt, deny-clock parity, burst
and steady traffic, maximum-timestamp saturation, multiple keys, clock
regression, upstream 503 and timeout, shadow profiles, manual freeze, monotonic
approved-auto clamps, state/model exhaustion, cross-worker model admission,
failed insertion/delete/TTL recovery,
the 9,007,199,252 exact adaptive ceiling case, rejected-policy LKG, and a fresh
process state reset.
