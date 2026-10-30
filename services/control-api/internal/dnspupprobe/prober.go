package dnspupprobe

import (
	"context"
	"crypto/sha256"
	"encoding/hex"
	"errors"
	"strconv"
	"sync"
	"time"
)

const (
	// PollInterval is dnspup's documented poll pace (Retry-After 2).
	PollInterval = 2 * time.Second
	// MaxWait bounds one job (dnspup http jobs end within 20 s + 30 s; a
	// pending job is read again from the cache in the same round).
	MaxWait = 25 * time.Second
	// MaxJobsPerRound bounds the jobs (each one is a charged request) one
	// consumer creates per round.
	MaxJobsPerRound = 50
)

// Degrade reasons: the source pauses until the given time and the platform is
// alerted once.
const (
	DegradeQuota        = "quota_exceeded"
	DegradeRateLimited  = "rate_limited"
	DegradeUnauthorized = "unauthorized"
	DegradeUnavailable  = "unavailable"
)

// DegradeHook records that the source cannot be used until until (reason one
// of the Degrade* codes, code the dnspup error code).
type DegradeHook func(reason, code string, until time.Time)

// Prober runs dnspup async probes: create (idempotent per key) → poll every
// PollInterval honouring Retry-After → results. Finished results are cached
// per idempotency key for the round; older rounds are dropped.
type Prober struct {
	client  *Client
	degrade DegradeHook
	now     func() time.Time
	sleep   func(context.Context, time.Duration) error

	mu      sync.Mutex
	round   map[string]int64 // consumer → current round
	created map[string]int   // consumer → jobs created this round
	cache   map[string]cached
}

type cached struct {
	round     int64
	requestID string
	done      bool // results handed out (once per round)
	refused   bool // target_restricted / invalid: no votes this round
}

func NewProber(client *Client, degrade DegradeHook) *Prober {
	return &Prober{client: client, degrade: degrade, now: time.Now, sleep: sleepContext,
		round: map[string]int64{}, created: map[string]int{}, cache: map[string]cached{}}
}

func sleepContext(ctx context.Context, wait time.Duration) error {
	timer := time.NewTimer(wait)
	defer timer.Stop()
	select {
	case <-ctx.Done():
		return ctx.Err()
	case <-timer.C:
		return nil
	}
}

// IdempotencyKey is the dnspup Idempotency-Key of (consumer, site, target,
// round): a retry or a second look in the same round reuses the job and is
// not charged again.
func IdempotencyKey(consumer, site, target string, round int64) string {
	sum := sha256.Sum256([]byte(consumer + "\x00" + site + "\x00" + target + "\x00" + strconv.FormatInt(round, 10)))
	return "cdnca-" + hex.EncodeToString(sum[:20])
}

// ErrRoundBudget: the consumer created MaxJobsPerRound jobs this round.
var ErrRoundBudget = errors.New("dnspup: round job budget used")

// ErrRefused: dnspup refused this target (target_restricted, invalid
// request); no votes, the source stays usable.
var ErrRefused = errors.New("dnspup: target refused")

// ErrPending: the job did not finish within MaxWait.
var ErrPending = errors.New("dnspup: job still pending")

// Round is the dnspup round of now: one charged job per (site, target) and
// interval.
func Round(now time.Time, interval time.Duration) int64 {
	return now.Unix() / int64(max(interval/time.Second, 1))
}

// ErrDelivered: this round's results were already handed out; a consumer
// probing more often than the dnspup interval must not count them again.
var ErrDelivered = errors.New("dnspup: round results already used")

// Run returns the checkpoints' results of request for (consumer, site,
// target, round), once per round (later calls: ErrDelivered). A source-level
// failure calls the degrade hook and returns the error; callers then fall
// back to their next source.
func (prober *Prober) Run(ctx context.Context, consumer, site, target string, round int64, request ProbeRequest) ([]Result, error) {
	key := IdempotencyKey(consumer, site, target, round)
	prober.mu.Lock()
	if prober.round[consumer] != round {
		prober.round[consumer], prober.created[consumer] = round, 0
		for name, entry := range prober.cache {
			if entry.round < round-1 {
				delete(prober.cache, name)
			}
		}
	}
	entry, found := prober.cache[key]
	if found && entry.done {
		prober.mu.Unlock()
		return nil, ErrDelivered
	}
	if found && entry.refused {
		prober.mu.Unlock()
		return nil, ErrRefused
	}
	if !found && prober.created[consumer] >= MaxJobsPerRound {
		prober.mu.Unlock()
		return nil, ErrRoundBudget
	}
	if !found {
		prober.created[consumer]++
	}
	prober.mu.Unlock()

	ctx, cancel := context.WithTimeout(ctx, MaxWait)
	defer cancel()
	var job Job
	var err error
	if entry.requestID != "" {
		job, err = prober.client.GetProbe(ctx, entry.requestID)
	} else {
		// The same key and body returns the existing job (200), never a new charge.
		job, err = prober.client.CreateProbe(ctx, key, request)
	}
	for err == nil && job.Pending() {
		prober.remember(key, cached{round: round, requestID: job.RequestID})
		wait := max(job.RetryAfter, PollInterval)
		if err = prober.sleep(ctx, wait); err != nil {
			return nil, ErrPending
		}
		job, err = prober.client.GetProbe(ctx, job.RequestID)
	}
	if err != nil {
		if ctx.Err() != nil {
			return nil, ErrPending
		}
		return nil, prober.fail(key, round, err)
	}
	results := job.Results()
	prober.remember(key, cached{round: round, requestID: job.RequestID, done: true})
	return results, nil
}

func (prober *Prober) remember(key string, entry cached) {
	prober.mu.Lock()
	prober.cache[key] = entry
	prober.mu.Unlock()
}

// fail classifies err: target-level refusals are cached for the round;
// account-level ones pause the source (quota until dnspup's next check,
// rate limits for Retry-After).
func (prober *Prober) fail(key string, round int64, err error) error {
	var apiErr *APIError
	if !errors.As(err, &apiErr) {
		return err // transport: try again next time, no pause
	}
	now := prober.now()
	switch apiErr.Code {
	case "target_restricted", "invalid_request", "invalid_nodes", "trusted_dns_resolution_failed", "idempotency_conflict":
		prober.remember(key, cached{round: round, refused: true})
		return ErrRefused
	case "quota_exceeded":
		prober.report(DegradeQuota, apiErr.Code, now.Add(time.Hour))
	case "rate_limited", "capacity_limited":
		prober.report(DegradeRateLimited, apiErr.Code, now.Add(max(apiErr.RetryAfter, time.Minute)))
	case "unauthorized", "source_forbidden", "signature_required", "malformed_signature", "stale_signature",
		"bad_signature", "tool_not_allowed":
		prober.report(DegradeUnauthorized, apiErr.Code, now.Add(time.Hour))
	case "task_not_found", "result_expired":
		prober.remember(key, cached{round: round, refused: true})
		return ErrRefused
	default:
		if apiErr.Status >= 500 || apiErr.Code == "async_unavailable" {
			prober.report(DegradeUnavailable, apiErr.Code, now.Add(5*time.Minute))
		}
	}
	return err
}

func (prober *Prober) report(reason, code string, until time.Time) {
	if prober.degrade != nil {
		prober.degrade(reason, code, until)
	}
}
