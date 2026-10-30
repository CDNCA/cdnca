package acmeworker

import (
	"context"
	"errors"
	"github.com/cdnca/cdnca/services/control-api/internal/installationlock"
	"log/slog"
	"strings"
	"sync"
	"sync/atomic"
	"time"
)

type RenewalScheduleStore interface {
	ScheduleDueRenewal(context.Context, time.Duration, time.Duration) (bool, error)
}

type RenewalScheduleOutcome struct {
	Scheduled bool
	Reopened  bool
}

type DetailedRenewalScheduleStore interface {
	ScheduleDueRenewalDetailed(context.Context, time.Duration, time.Duration, time.Duration) (RenewalScheduleOutcome, error)
}

type FixedClockRenewalScheduleStore interface {
	ScheduleDueRenewalAt(context.Context, time.Time, time.Duration, time.Duration) (bool, error)
}

type FixedClockDetailedRenewalScheduleStore interface {
	ScheduleDueRenewalDetailedAt(context.Context, time.Time, time.Duration, time.Duration, time.Duration) (RenewalScheduleOutcome, error)
}

type RenewalSchedulerConfig struct {
	Clock           Clock
	RenewBefore     time.Duration
	LeaseDuration   time.Duration
	RetryMaximum    time.Duration
	PollInterval    time.Duration
	ErrorBackoffMin time.Duration
	ErrorBackoffMax time.Duration
	Logger          *slog.Logger
}

func DefaultRenewalSchedulerConfig() RenewalSchedulerConfig {
	renewal := DefaultRenewalConfig()
	return RenewalSchedulerConfig{
		RenewBefore: renewal.RenewBefore, LeaseDuration: renewal.LeaseDuration,
		RetryMaximum: time.Hour,
		PollInterval: time.Second, ErrorBackoffMin: time.Second, ErrorBackoffMax: 30 * time.Second,
	}
}

type RenewalSchedulerStats struct {
	Polls     uint64
	Failures  uint64
	Scheduled uint64
	Reopened  uint64
}

type RenewalScheduler struct {
	store     RenewalScheduleStore
	config    RenewalSchedulerConfig
	wait      func(context.Context, time.Duration) error
	logger    *slog.Logger
	polls     atomic.Uint64
	failures  atomic.Uint64
	scheduled atomic.Uint64
	reopened  atomic.Uint64
	running   atomic.Bool
}

func NewRenewalScheduler(store RenewalScheduleStore, config RenewalSchedulerConfig) (*RenewalScheduler, error) {
	return newRenewalScheduler(store, config, waitForRenewalContext)
}

func newRenewalScheduler(
	store RenewalScheduleStore,
	config RenewalSchedulerConfig,
	wait func(context.Context, time.Duration) error,
) (*RenewalScheduler, error) {
	if store == nil || wait == nil || config.RenewBefore <= 0 || config.RenewBefore > 365*24*time.Hour ||
		config.LeaseDuration <= 0 || config.LeaseDuration > 24*time.Hour || config.RetryMaximum <= 0 ||
		config.RetryMaximum > 24*time.Hour || config.PollInterval <= 0 ||
		config.PollInterval > time.Hour || config.ErrorBackoffMin <= 0 ||
		config.ErrorBackoffMax < config.ErrorBackoffMin || config.ErrorBackoffMax > time.Hour {
		return nil, failure(CodeInvalidInput, nil)
	}
	if config.Logger == nil {
		config.Logger = slog.Default()
	}
	return &RenewalScheduler{store: store, config: config, wait: wait, logger: config.Logger}, nil
}

func (scheduler *RenewalScheduler) Run(ctx context.Context) error {
	if scheduler == nil || ctx == nil {
		return failure(CodeInvalidInput, nil)
	}
	if !scheduler.running.CompareAndSwap(false, true) {
		return errors.New("ACME renewal scheduler is already running")
	}
	defer scheduler.running.Store(false)

	errorBackoff := scheduler.config.ErrorBackoffMin
	for {
		if installationlock.Skip("acme_renewal") {
			if err := scheduler.wait(ctx, scheduler.config.PollInterval); err != nil {
				return err
			}
			continue
		}
		scheduler.polls.Add(1)
		var outcome RenewalScheduleOutcome
		var err error
		if fixedDetailed, ok := scheduler.store.(FixedClockDetailedRenewalScheduleStore); scheduler.config.Clock != nil && ok {
			outcome, err = fixedDetailed.ScheduleDueRenewalDetailedAt(
				ctx, scheduler.config.Clock().UTC(), scheduler.config.RenewBefore,
				scheduler.config.LeaseDuration, scheduler.config.RetryMaximum,
			)
		} else if fixed, ok := scheduler.store.(FixedClockRenewalScheduleStore); scheduler.config.Clock != nil && ok {
			outcome.Scheduled, err = fixed.ScheduleDueRenewalAt(
				ctx, scheduler.config.Clock().UTC(), scheduler.config.RenewBefore, scheduler.config.LeaseDuration,
			)
		} else if scheduler.config.Clock != nil {
			err = failure(CodeInvalidInput, nil)
		} else if detailed, ok := scheduler.store.(DetailedRenewalScheduleStore); ok {
			outcome, err = detailed.ScheduleDueRenewalDetailed(
				ctx, scheduler.config.RenewBefore, scheduler.config.LeaseDuration, scheduler.config.RetryMaximum,
			)
		} else {
			outcome.Scheduled, err = scheduler.store.ScheduleDueRenewal(
				ctx, scheduler.config.RenewBefore, scheduler.config.LeaseDuration,
			)
		}
		if ctx.Err() != nil {
			return ctx.Err()
		}
		if err != nil {
			scheduler.failures.Add(1)
			scheduler.logger.Warn("ACME renewal scheduler poll failed", "error", err)
			if waitErr := scheduler.wait(ctx, errorBackoff); waitErr != nil {
				return waitErr
			}
			errorBackoff = nextRenewalBackoff(errorBackoff, scheduler.config.ErrorBackoffMax)
			continue
		}
		errorBackoff = scheduler.config.ErrorBackoffMin
		if outcome.Scheduled {
			scheduler.scheduled.Add(1)
			if outcome.Reopened {
				scheduler.reopened.Add(1)
				scheduler.logger.Info("ACME renewal scheduler reopened failed child",
					"reason", "failed_renewal_retry")
			}
			continue
		}
		if err := scheduler.wait(ctx, scheduler.config.PollInterval); err != nil {
			return err
		}
	}
}

func (scheduler *RenewalScheduler) Stats() RenewalSchedulerStats {
	if scheduler == nil {
		return RenewalSchedulerStats{}
	}
	return RenewalSchedulerStats{
		Polls: scheduler.polls.Load(), Failures: scheduler.failures.Load(),
		Scheduled: scheduler.scheduled.Load(), Reopened: scheduler.reopened.Load(),
	}
}

func (scheduler *RenewalScheduler) Ready() error {
	if scheduler == nil || !scheduler.running.Load() {
		return errors.New("ACME renewal scheduler is unavailable")
	}
	return nil
}

func nextRenewalBackoff(current, maximum time.Duration) time.Duration {
	if current >= maximum || current > maximum/2 {
		return maximum
	}
	return current * 2
}

func waitForRenewalContext(ctx context.Context, duration time.Duration) error {
	timer := time.NewTimer(duration)
	defer timer.Stop()
	select {
	case <-ctx.Done():
		return ctx.Err()
	case <-timer.C:
		return nil
	}
}

type RenewalWorker struct {
	config RenewalConfig
	claims RenewalClaimStore
	issuer CertificateIssuer
}

func NewRenewalWorker(config RenewalConfig, claims RenewalClaimStore, issuer CertificateIssuer) (*RenewalWorker, error) {
	if config.Clock == nil || config.RenewBefore <= 0 || config.LeaseDuration <= 0 ||
		config.MaxConcurrent < 1 || config.MaxConcurrent > 100 || claims == nil || issuer == nil {
		return nil, failure(CodeInvalidInput, nil)
	}
	return &RenewalWorker{config: config, claims: claims, issuer: issuer}, nil
}

func (w *RenewalWorker) Renew(ctx context.Context, candidate RenewalCandidate) RenewalResult {
	now := w.config.Clock().UTC()
	if strings.TrimSpace(candidate.CertificateID) == "" || candidate.CurrentExpiry.IsZero() {
		return RenewalResult{Error: failure(CodeInvalidInput, nil)}
	}
	if !candidate.AutoRenew || now.Before(candidate.CurrentExpiry.Add(-w.config.RenewBefore)) {
		return RenewalResult{}
	}
	key := RenewalClaimKey(candidate.CertificateID, candidate.CurrentExpiry)
	result := RenewalResult{ClaimKey: key}
	claim, err := w.claims.Claim(ctx, RenewalClaimRequest{
		Key:           key,
		CertificateID: candidate.CertificateID,
		CurrentExpiry: candidate.CurrentExpiry.UTC(),
		ClaimedAt:     now,
		LeaseUntil:    now.Add(w.config.LeaseDuration),
	})
	if err != nil {
		result.Error = phaseFailure(CodeRenewalClaimFailed, err)
		return result
	}
	result.State = claim.State
	if claim.State == ClaimBusy || claim.State == ClaimCompleted {
		return result
	}
	if claim.State != ClaimAcquired || claim.Token == "" {
		result.Error = failure(CodeRenewalClaimFailed, nil)
		return result
	}

	candidate.IssueRequest.OperationID = candidate.IssueRequest.CertificateOrderID.String()
	issued, issueErr := w.issuer.Issue(ctx, candidate.IssueRequest)
	result.Issue = issued
	if issueErr != nil {
		result.Error = issueErr
		releaseCtx, cancel := context.WithTimeout(context.WithoutCancel(ctx), min(w.config.LeaseDuration, 30*time.Second))
		_ = w.claims.Release(releaseCtx, key, claim.Token, ErrorCodeOf(issueErr))
		cancel()
		return result
	}
	completeCtx, cancel := context.WithTimeout(context.WithoutCancel(ctx), min(w.config.LeaseDuration, 30*time.Second))
	err = w.claims.Complete(completeCtx, key, claim.Token, issued.Certificate.LeafFingerprint)
	cancel()
	if err != nil {
		result.Error = phaseFailure(CodeRenewalClaimFailed, err)
		return result
	}
	result.State = ClaimCompleted
	return result
}

func (w *RenewalWorker) RenewBatch(ctx context.Context, candidates []RenewalCandidate) []RenewalResult {
	results := make([]RenewalResult, len(candidates))
	sem := make(chan struct{}, w.config.MaxConcurrent)
	var wait sync.WaitGroup
	for index := range candidates {
		index := index
		wait.Add(1)
		go func() {
			defer wait.Done()
			select {
			case sem <- struct{}{}:
				defer func() { <-sem }()
				results[index] = w.Renew(ctx, candidates[index])
			case <-ctx.Done():
				results[index].Error = contextFailure(ctx.Err())
			}
		}()
	}
	wait.Wait()
	return results
}
