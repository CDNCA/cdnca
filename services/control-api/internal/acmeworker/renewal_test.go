package acmeworker

import (
	"context"
	"errors"
	"sync"
	"sync/atomic"
	"testing"
	"time"
)

type memoryClaims struct {
	mu     sync.Mutex
	states map[string]ClaimState
}

func (s *memoryClaims) Claim(_ context.Context, request RenewalClaimRequest) (RenewalClaim, error) {
	s.mu.Lock()
	defer s.mu.Unlock()
	state := s.states[request.Key]
	if state == ClaimCompleted {
		return RenewalClaim{State: ClaimCompleted}, nil
	}
	if state == ClaimAcquired {
		return RenewalClaim{State: ClaimBusy}, nil
	}
	s.states[request.Key] = ClaimAcquired
	return RenewalClaim{State: ClaimAcquired, Token: "lease-token"}, nil
}

func (s *memoryClaims) Complete(_ context.Context, key, token, _ string) error {
	s.mu.Lock()
	defer s.mu.Unlock()
	if token != "lease-token" || s.states[key] != ClaimAcquired {
		return context.Canceled
	}
	s.states[key] = ClaimCompleted
	return nil
}

func (s *memoryClaims) Release(_ context.Context, key, token string, _ ErrorCode) error {
	s.mu.Lock()
	defer s.mu.Unlock()
	if token == "lease-token" {
		delete(s.states, key)
	}
	return nil
}

type countingIssuer struct {
	calls    atomic.Int32
	current  atomic.Int32
	maximum  atomic.Int32
	block    chan struct{}
	mu       sync.Mutex
	requests []IssueRequest
}

type cancellationAwareClaims struct {
	*memoryClaims
	completeMu          sync.Mutex
	completeContextErr  error
	completeHasDeadline bool
}

func (s *cancellationAwareClaims) Complete(ctx context.Context, key, token, fingerprint string) error {
	_, hasDeadline := ctx.Deadline()
	s.completeMu.Lock()
	s.completeContextErr = ctx.Err()
	s.completeHasDeadline = hasDeadline
	s.completeMu.Unlock()
	if err := ctx.Err(); err != nil {
		return err
	}
	return s.memoryClaims.Complete(ctx, key, token, fingerprint)
}

type cancelAfterSuccessfulIssue struct {
	cancel context.CancelFunc
	calls  atomic.Int32
}

func (i *cancelAfterSuccessfulIssue) Issue(_ context.Context, request IssueRequest) (IssueResult, error) {
	i.calls.Add(1)
	i.cancel()
	return IssueResult{Certificate: IssuedCertificate{LeafFingerprint: "sha256:" + request.OperationID}}, nil
}

func (i *countingIssuer) Issue(ctx context.Context, request IssueRequest) (IssueResult, error) {
	i.calls.Add(1)
	i.mu.Lock()
	i.requests = append(i.requests, request)
	i.mu.Unlock()
	current := i.current.Add(1)
	defer i.current.Add(-1)
	for {
		maximum := i.maximum.Load()
		if current <= maximum || i.maximum.CompareAndSwap(maximum, current) {
			break
		}
	}
	if i.block != nil {
		select {
		case <-i.block:
		case <-ctx.Done():
			return IssueResult{}, ctx.Err()
		}
	}
	return IssueResult{Certificate: IssuedCertificate{LeafFingerprint: "sha256:" + request.OperationID}}, nil
}

func TestRenewalUsesFixedClockAndDeterministicCompletedClaim(t *testing.T) {
	now := time.Date(2026, 7, 22, 10, 0, 0, 0, time.UTC)
	claims := &memoryClaims{states: make(map[string]ClaimState)}
	issuer := &countingIssuer{}
	config := DefaultRenewalConfig()
	config.Clock = func() time.Time { return now }
	worker, err := NewRenewalWorker(config, claims, issuer)
	if err != nil {
		t.Fatal(err)
	}
	candidate := RenewalCandidate{
		CertificateID: "certificate-1",
		CurrentExpiry: now.Add(20 * 24 * time.Hour),
		AutoRenew:     true,
		IssueRequest:  validIssueRequest(ChallengeDNS01, "example.test"),
	}

	first := worker.Renew(context.Background(), candidate)
	second := worker.Renew(context.Background(), candidate)
	wantKey := RenewalClaimKey(candidate.CertificateID, candidate.CurrentExpiry)
	if first.Error != nil || first.State != ClaimCompleted || first.ClaimKey != wantKey ||
		second.Error != nil || second.State != ClaimCompleted || second.ClaimKey != wantKey || issuer.calls.Load() != 1 {
		t.Fatalf("first=%+v second=%+v issuer calls=%d", first, second, issuer.calls.Load())
	}
	issuer.mu.Lock()
	issuedRequest := issuer.requests[0]
	issuer.mu.Unlock()
	if issuedRequest.OperationID != candidate.IssueRequest.CertificateOrderID.String() ||
		issuedRequest.OperationID == wantKey {
		t.Fatalf("renewal operation ID = %q, claim key = %q", issuedRequest.OperationID, wantKey)
	}

	notDue := candidate
	notDue.CertificateID = "certificate-2"
	notDue.CurrentExpiry = now.Add(31 * 24 * time.Hour)
	result := worker.Renew(context.Background(), notDue)
	if result.ClaimKey != "" || issuer.calls.Load() != 1 {
		t.Fatalf("not-due result=%+v issuer calls=%d", result, issuer.calls.Load())
	}
}

func TestRenewalFinalizesSuccessfulIssueAfterCallerCancellation(t *testing.T) {
	now := time.Date(2026, 7, 22, 10, 0, 0, 0, time.UTC)
	ctx, cancel := context.WithCancel(context.Background())
	defer cancel()
	claims := &cancellationAwareClaims{memoryClaims: &memoryClaims{states: make(map[string]ClaimState)}}
	issuer := &cancelAfterSuccessfulIssue{cancel: cancel}
	config := DefaultRenewalConfig()
	config.Clock = func() time.Time { return now }
	worker, err := NewRenewalWorker(config, claims, issuer)
	if err != nil {
		t.Fatal(err)
	}
	candidate := RenewalCandidate{
		CertificateID: "certificate-cancelled-after-issue",
		CurrentExpiry: now.Add(20 * 24 * time.Hour),
		AutoRenew:     true,
		IssueRequest:  validIssueRequest(ChallengeDNS01, "cancelled.example.test"),
	}

	first := worker.Renew(ctx, candidate)
	if first.Error != nil || first.State != ClaimCompleted || ctx.Err() == nil {
		t.Fatalf("first renewal = %+v, caller error = %v", first, ctx.Err())
	}
	claims.completeMu.Lock()
	completeContextErr := claims.completeContextErr
	completeHasDeadline := claims.completeHasDeadline
	claims.completeMu.Unlock()
	if completeContextErr != nil || !completeHasDeadline {
		t.Fatalf("completion context error=%v has-deadline=%t", completeContextErr, completeHasDeadline)
	}

	replay := worker.Renew(context.Background(), candidate)
	if replay.Error != nil || replay.State != ClaimCompleted || issuer.calls.Load() != 1 {
		t.Fatalf("replay = %+v, issuer calls = %d", replay, issuer.calls.Load())
	}
}

func TestRenewalBatchHasBoundedConcurrency(t *testing.T) {
	now := time.Date(2026, 7, 22, 10, 0, 0, 0, time.UTC)
	claims := &memoryClaims{states: make(map[string]ClaimState)}
	issuer := &countingIssuer{block: make(chan struct{})}
	config := DefaultRenewalConfig()
	config.Clock = func() time.Time { return now }
	config.MaxConcurrent = 2
	worker, err := NewRenewalWorker(config, claims, issuer)
	if err != nil {
		t.Fatal(err)
	}
	candidates := make([]RenewalCandidate, 5)
	for index := range candidates {
		candidates[index] = RenewalCandidate{
			CertificateID: string(rune('a' + index)),
			CurrentExpiry: now.Add(time.Hour),
			AutoRenew:     true,
			IssueRequest:  validIssueRequest(ChallengeDNS01, "example.test"),
		}
	}
	done := make(chan []RenewalResult, 1)
	go func() { done <- worker.RenewBatch(context.Background(), candidates) }()
	deadline := time.After(time.Second)
	for issuer.current.Load() < 2 {
		select {
		case <-deadline:
			t.Fatal("renewal batch did not start two workers")
		default:
			time.Sleep(time.Millisecond)
		}
	}
	if maximum := issuer.maximum.Load(); maximum != 2 {
		t.Fatalf("maximum concurrency = %d, want 2", maximum)
	}
	close(issuer.block)
	results := <-done
	if len(results) != len(candidates) || issuer.maximum.Load() > 2 {
		t.Fatalf("results=%d maximum=%d", len(results), issuer.maximum.Load())
	}
}

type scriptedRenewalScheduleStore struct {
	mu       sync.Mutex
	results  []bool
	errors   []error
	calls    int
	renewFor time.Duration
	lease    time.Duration
}

type detailedRenewalScheduleStore struct {
	mu       sync.Mutex
	outcomes []RenewalScheduleOutcome
	errors   []error
	calls    int
}

func (store *detailedRenewalScheduleStore) ScheduleDueRenewal(
	context.Context, time.Duration, time.Duration,
) (bool, error) {
	store.mu.Lock()
	defer store.mu.Unlock()
	return false, errors.New("legacy scheduler path must not be used")
}

func (store *detailedRenewalScheduleStore) ScheduleDueRenewalDetailed(
	context.Context, time.Duration, time.Duration, time.Duration,
) (RenewalScheduleOutcome, error) {
	store.mu.Lock()
	defer store.mu.Unlock()
	index := store.calls
	store.calls++
	if index < len(store.errors) && store.errors[index] != nil {
		return RenewalScheduleOutcome{}, store.errors[index]
	}
	if index < len(store.outcomes) {
		return store.outcomes[index], nil
	}
	return RenewalScheduleOutcome{}, nil
}

func (store *scriptedRenewalScheduleStore) ScheduleDueRenewal(
	_ context.Context,
	renewBefore time.Duration,
	leaseDuration time.Duration,
) (bool, error) {
	store.mu.Lock()
	defer store.mu.Unlock()
	index := store.calls
	store.calls++
	store.renewFor = renewBefore
	store.lease = leaseDuration
	if index < len(store.errors) && store.errors[index] != nil {
		return false, store.errors[index]
	}
	if index < len(store.results) {
		return store.results[index], nil
	}
	return false, nil
}

func TestRenewalSchedulerDrainsBacksOffReadiesAndCancels(t *testing.T) {
	store := &scriptedRenewalScheduleStore{
		results: []bool{false, true, false},
		errors:  []error{errors.New("temporary database error")},
	}
	config := DefaultRenewalSchedulerConfig()
	config.PollInterval = 20 * time.Millisecond
	config.ErrorBackoffMin = 5 * time.Millisecond
	config.ErrorBackoffMax = 10 * time.Millisecond
	ctx, cancel := context.WithCancel(context.Background())
	var waits []time.Duration
	waiting := make(chan struct{})
	release := make(chan struct{})
	scheduler, err := newRenewalScheduler(store, config, func(_ context.Context, duration time.Duration) error {
		waits = append(waits, duration)
		if len(waits) == 1 {
			close(waiting)
			<-release
			return nil
		}
		if len(waits) == 2 {
			cancel()
			return context.Canceled
		}
		return nil
	})
	if err != nil {
		t.Fatal(err)
	}
	done := make(chan error, 1)
	go func() { done <- scheduler.Run(ctx) }()
	select {
	case <-waiting:
	case <-time.After(time.Second):
		t.Fatal("renewal scheduler did not reach its first backoff")
	}
	if err := scheduler.Ready(); err != nil {
		t.Fatalf("running renewal scheduler readiness error = %v", err)
	}
	close(release)
	if err := <-done; !errors.Is(err, context.Canceled) {
		t.Fatalf("scheduler cancellation error = %v", err)
	}
	store.mu.Lock()
	calls, renewBefore, leaseDuration := store.calls, store.renewFor, store.lease
	store.mu.Unlock()
	if calls != 3 || renewBefore != 30*24*time.Hour || leaseDuration != 10*time.Minute ||
		len(waits) != 2 || waits[0] != config.ErrorBackoffMin || waits[1] != config.PollInterval {
		t.Fatalf("calls=%d renew-before=%s lease=%s waits=%v",
			calls, renewBefore, leaseDuration, waits)
	}
	if scheduler.Ready() == nil {
		t.Fatal("stopped renewal scheduler remained ready")
	}
	stats := scheduler.Stats()
	if stats.Polls != 3 || stats.Failures != 1 || stats.Scheduled != 1 || stats.Reopened != 0 {
		t.Fatalf("legacy scheduler stats = %+v", stats)
	}
}

func TestRenewalSchedulerTracksDetailedReopenTelemetry(t *testing.T) {
	store := &detailedRenewalScheduleStore{
		outcomes: []RenewalScheduleOutcome{
			{}, {Scheduled: true}, {Scheduled: true, Reopened: true},
		},
		errors: []error{errors.New("temporary database error")},
	}
	config := DefaultRenewalSchedulerConfig()
	config.ErrorBackoffMin = time.Millisecond
	config.ErrorBackoffMax = 2 * time.Millisecond
	ctx, cancel := context.WithCancel(context.Background())
	defer cancel()
	waits := 0
	scheduler, err := newRenewalScheduler(store, config, func(waitCtx context.Context, _ time.Duration) error {
		waits++
		if waits == 2 {
			cancel()
			return waitCtx.Err()
		}
		return nil
	})
	if err != nil {
		t.Fatal(err)
	}
	if err := scheduler.Run(ctx); !errors.Is(err, context.Canceled) {
		t.Fatalf("detailed scheduler error = %v", err)
	}
	if stats := scheduler.Stats(); stats.Polls != 4 || stats.Failures != 1 ||
		stats.Scheduled != 2 || stats.Reopened != 1 {
		t.Fatalf("detailed scheduler stats = %+v", stats)
	}
}

func TestRenewalSchedulerRejectsInvalidConfiguration(t *testing.T) {
	store := &scriptedRenewalScheduleStore{}
	config := DefaultRenewalSchedulerConfig()
	config.RenewBefore = 0
	if _, err := NewRenewalScheduler(store, config); err == nil {
		t.Fatal("zero renew-before was accepted")
	}
}
