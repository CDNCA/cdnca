# CC adaptive benchmark workload

This workload is deterministic and is implemented by
`agents/edge-agent/internal/ccadaptive/benchmark_test.go`.

## Limiter comparison

- Configuration: 100 requests/second and an immediate burst of 100.
- Window boundary: 100 requests at 999,999 microseconds followed by 100 at
  1,000,000 microseconds. The second group is labeled denied because no token or
  GCRA interval has elapsed.
- Steady: 1,000 requests separated by 10,000 microseconds. Every request is
  labeled allowed.
- Instant attack: 1,000 requests at the same timestamp. The first 100 are
  labeled allowed and the remaining 900 denied.
- Accuracy is the number of decisions matching those 2,200 labels. False burst
  is the number of second-group window-boundary requests incorrectly allowed.

The fixed-window and token-bucket implementations are test-only references.
The repository's existing CC baseline executes in Lua and has no reusable Go
decision API. The GCRA benchmark uses the production `ccadaptive.Store` path.

## Adaptive profiles

- Normal: twenty 50 requests/second buckets.
- Periodic: alternating 30 and 70 requests/second buckets.
- Spike: eight 50 buckets, one 500 bucket, then twenty 50 buckets.
- Attack training: twelve 10,000 requests/second buckets.
- Low sample: two 50 requests/second buckets, below the five-bucket warmup.

All buckets are one second and contain no IP, header, token, URL, or other raw
request identity. Rates and suggestion deltas are reported in requests/second.
The static hard limit is 100 requests/second with burst 20. The measured
adaptive mode is shadow, so the test asserts that every suggestion has
`apply=false`; it does not infer an enforcement false-positive count from a
mode that performs no enforcement.

The metric tests assert the exact correct-label, false-boundary-burst, usable
suggestion, final-rate, jitter, and spike-recovery results recorded in the
report. Latency remains observational because shared-host scheduling is not a
stable functional assertion.

## State-capacity boundaries

The functional capacity gates use `max_groups=1` or `max_keys=1`. They verify
that a higher policy revision starts with fresh adaptive capacity, lower-revision
samples arriving concurrently cannot repopulate it, and a state whose expiry is
saturated at `2^53-1` remains live on the preceding tick, releases capacity at
the boundary, and does not cause a new same-tick state to be removed.
