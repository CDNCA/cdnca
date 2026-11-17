package dnspupprobe

import (
	"context"
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"
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
// PollInterval honouring Retry-After → results. A job is keyed by (consumer,
// request body, round), so subjects (sites, nodes) asking dnspup the very same
// request in a round share one charged job: concurrent askers wait for the one
// fetching it, later ones read its cached results. Each subject gets them once
// per round; a consumer's older rounds are dropped when it moves on.
type Prober struct {
	client  *Client
	degrade DegradeHook
	now     func() time.Time
	sleep   func(context.Context, time.Duration) error

	// onCreated is told about every new (charged, 202) job's consumer.
	onCreated func(consumer string)
	// onResults is told once per finished job (not per subject sharing it).
	onResults func(consumer string, request ProbeRequest, results []Result)

	mu      sync.Mutex
	round   map[string]int64 // consumer → current round
	created map[string]int   // consumer → jobs created this round
	cache   map[string]*cached
}

type cached struct {
	consumer  string
	round     int64
	requestID string
	done      bool // results fetched
	refused   bool // target_restricted / invalid: no votes this round
	results   []Result
	delivered map[string]bool // subjects (site + target) handed the results
	flight    *flight         // the Run fetching the job now; nil: none
}

// flight is one Run fetching a job; askers of the same key wait for done.
type flight struct {
	done chan struct{}
	err  error
}

func NewProber(client *Client, degrade DegradeHook) *Prober {
	return &Prober{client: client, degrade: degrade, now: time.Now, sleep: sleepContext,
		round: map[string]int64{}, created: map[string]int{}, cache: map[string]*cached{}}
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

// IdempotencyKey is the dnspup Idempotency-Key of (consumer, request body,
// round): a retry, a second look or another subject with the same request in
// the same round reuses the job and is not charged again.
func IdempotencyKey(consumer string, request ProbeRequest, round int64) string {
	body, _ := json.Marshal(request) // the body CreateProbe sends
	sum := sha256.Sum256([]byte(consumer + "\x00" + string(body) + "\x00" + strconv.FormatInt(round, 10)))
	return "cdnca-" + hex.EncodeToString(sum[:20])
}

// ErrRoundBudget: the consumer created MaxJobsPerRound jobs this round.
var ErrRoundBudget = errors.New("dnspup: round job budget used")

// ErrRefused: dnspup refused this target (target_restricted, invalid
// request); no votes, the source stays usable.
var ErrRefused = errors.New("dnspup: target refused")

// ErrPending: the job did not finish within MaxWait.
var ErrPending = errors.New("dnspup: job still pending")

// Round is the dnspup round of now: one charged job per request and
// interval.
func Round(now time.Time, interval time.Duration) int64 {
	return now.Unix() / int64(max(interval/time.Second, 1))
}

// ErrDelivered: this round's results were already handed to the subject; a
// consumer probing more often than the dnspup interval must not count them
// again.
var ErrDelivered = errors.New("dnspup: round results already used")

// Run returns the checkpoints' results of request for subject (site, target)
// in round, once per subject and round (later calls: ErrDelivered). Subjects
// with the same request share the round's job and its outcome. A source-level
// failure calls the degrade hook and returns the error; callers then fall
// back to their next source.
func (prober *Prober) Run(ctx context.Context, consumer, site, target string, round int64, request ProbeRequest) ([]Result, error) {
	key := IdempotencyKey(consumer, request, round)
	subject := site + "\x00" + target
	prober.mu.Lock()
	if prober.round[consumer] != round {
		prober.round[consumer], prober.created[consumer] = round, 0
		for name, entry := range prober.cache {
			if entry.consumer == consumer && entry.round < round-1 {
				delete(prober.cache, name)
			}
		}
	}
	entry, found := prober.cache[key]
	switch {
	case found && entry.flight != nil:
		running := entry.flight
		prober.mu.Unlock()
		select {
		case <-running.done:
		case <-ctx.Done():
			return nil, ErrPending
		}
		if running.err != nil {
			return nil, running.err
		}
		prober.mu.Lock()
		defer prober.mu.Unlock()
		return entry.deliver(subject)
	case found && entry.done:
		defer prober.mu.Unlock()
		return entry.deliver(subject)
	case found && entry.refused:
		prober.mu.Unlock()
		return nil, ErrRefused
	case !found && prober.created[consumer] >= MaxJobsPerRound:
		prober.mu.Unlock()
		return nil, ErrRoundBudget
	case !found:
		prober.created[consumer]++
		entry = &cached{consumer: consumer, round: round, delivered: map[string]bool{}}
		prober.cache[key] = entry
	}
	running := &flight{done: make(chan struct{})}
	entry.flight = running
	requestID := entry.requestID
	prober.mu.Unlock()

	results, err := prober.fetch(ctx, consumer, key, entry, requestID, request)
	prober.mu.Lock()
	entry.flight, running.err = nil, err
	if err == nil {
		entry.done, entry.results = true, results
		entry.delivered[subject] = true
	} else if entry.requestID == "" && !entry.refused && prober.cache[key] == entry {
		delete(prober.cache, key) // no job to read again: the next look creates (as before)
	}
	close(running.done)
	prober.mu.Unlock()
	if err == nil && prober.onResults != nil {
		prober.onResults(consumer, request, results)
	}
	return results, err
}

// deliver hands the job's results to subject once (prober.mu held).
func (entry *cached) deliver(subject string) ([]Result, error) {
	if entry.delivered[subject] {
		return nil, ErrDelivered
	}
	entry.delivered[subject] = true
	return entry.results, nil
}

// fetch creates (requestID empty) or reads the job until it ends or MaxWait.
func (prober *Prober) fetch(ctx context.Context, consumer, key string, entry *cached, requestID string,
	request ProbeRequest) ([]Result, error) {
	ctx, cancel := context.WithTimeout(ctx, MaxWait)
	defer cancel()
	var job Job
	var err error
	if requestID != "" {
		job, err = prober.client.GetProbe(ctx, requestID)
	} else {
		// The same key and body returns the existing job (200), never a new charge.
		job, err = prober.client.CreateProbe(ctx, key, request)
		if err == nil && job.Created && prober.onCreated != nil {
			prober.onCreated(consumer)
		}
	}
	for err == nil && job.Pending() {
		prober.remember(entry, job.RequestID)
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
		return nil, prober.fail(entry, err)
	}
	prober.remember(entry, job.RequestID)
	return job.Results(), nil
}

func (prober *Prober) remember(entry *cached, requestID string) {
	prober.mu.Lock()
	entry.requestID = requestID
	prober.mu.Unlock()
}

// fail classifies err (entry: the round's cache entry, nil for plugin
// requests): target-level refusals are cached for the round;
// account-level ones pause the source (quota until dnspup's next check,
// rate limits for Retry-After).
func (prober *Prober) fail(entry *cached, err error) error {
	var apiErr *APIError
	if !errors.As(err, &apiErr) {
		return err // transport: try again next time, no pause
	}
	now := prober.now()
	switch apiErr.Code {
	case "target_restricted", "invalid_request", "invalid_nodes", "trusted_dns_resolution_failed", "idempotency_conflict":
		prober.refuse(entry)
		return ErrRefused
	case "quota_exceeded":
		prober.report(DegradeQuota, apiErr.Code, now.Add(time.Hour))
	case "rate_limited", "capacity_limited":
		prober.report(DegradeRateLimited, apiErr.Code, now.Add(max(apiErr.RetryAfter, time.Minute)))
	case "unauthorized", "source_forbidden", "signature_required", "malformed_signature", "stale_signature",
		"bad_signature", "tool_not_allowed":
		prober.report(DegradeUnauthorized, apiErr.Code, now.Add(time.Hour))
	case "task_not_found", "result_expired":
		prober.refuse(entry)
		return ErrRefused
	default:
		if apiErr.Status >= 500 || apiErr.Code == "async_unavailable" {
			prober.report(DegradeUnavailable, apiErr.Code, now.Add(5*time.Minute))
		}
	}
	return err
}

// refuse marks entry refused for its round (nil: a plugin request, not cached).
func (prober *Prober) refuse(entry *cached) {
	if entry == nil {
		return
	}
	prober.mu.Lock()
	entry.refused = true
	prober.mu.Unlock()
}

func (prober *Prober) report(reason, code string, until time.Time) {
	if prober.degrade != nil {
		prober.degrade(reason, code, until)
	}
}
