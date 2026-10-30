package cnameallocation

import (
	"context"
	"errors"
	"log/slog"
	"net/netip"
	"sort"
	"time"

	"github.com/cdnca/cdnca/services/control-api/internal/dnscheck"
	"github.com/cdnca/cdnca/services/control-api/internal/dnsreconcile"
	"github.com/cdnca/cdnca/services/control-api/internal/jobstate"
	"github.com/google/uuid"
)

type WorkerConfig struct {
	WorkerID      string
	LeaseDuration time.Duration
	PollInterval  time.Duration
	// RetargetInterval paces DNS retargets (zero: every poll).
	RetargetInterval time.Duration
	Now              func() time.Time
}

type WorkerDependencies struct {
	Tenants TenantSource
	Intents IntentStore
	// StreamIntents is optional; when set, 四层转发自有 CNAME intents
	// (dns.cname.stream_intent, migration 505) are executed.
	StreamIntents StreamIntentStore
	Claims        ClaimStore
	Targets       TargetStore
	Reconcile     ReconcileRuntime
	// Retargets is optional; when set, serving-set changes are republished.
	Retargets RetargetStore
	// Snapshots is optional; when set, publications see the owner's current
	// provider records and remove stale values.
	Snapshots ProviderSnapshotSource
	// Retirements and RetiredOwners are optional; when both are set, retired
	// owners (migration 476) are deleted from the provider.
	Retirements   RetirementStore
	RetiredOwners RetiredOwnerCleaner
	// EndedJobs is optional; when set, sites still pending on a CNAME job
	// jobstate already ended are failed (Store.SweepEndedJobs).
	EndedJobs EndedJobSweeper
}

// EndedJobSweeper fails sites of ended CNAME jobs (Store).
type EndedJobSweeper interface {
	SweepEndedJobs(ctx context.Context) (int, error)
}

// endedSweepInterval paces SweepEndedJobs; the first run is at start-up.
const endedSweepInterval = time.Minute

// RetirementStore leases and settles retired CNAME owners (Store).
type RetirementStore interface {
	DueRetirements(ctx context.Context, limit int) ([]RetiredOwner, error)
	FinishRetirement(ctx context.Context, owner RetiredOwner, deleted, kept int, code string) error
}

type Worker struct {
	config       WorkerConfig
	dependencies WorkerDependencies
	lastRetarget time.Time
	lastRetire   time.Time
	lastSweep    time.Time
}

const maxJobsPerTenantRound = 8

func NewWorker(config WorkerConfig, dependencies WorkerDependencies) (*Worker, error) {
	if config.WorkerID == "" || config.LeaseDuration <= 0 || dependencies.Claims == nil ||
		dependencies.Targets == nil || dependencies.Reconcile == nil {
		return nil, ErrInvalidInput
	}
	if config.PollInterval <= 0 {
		config.PollInterval = time.Second
	}
	if config.Now == nil {
		config.Now = time.Now
	}
	return &Worker{config: config, dependencies: dependencies}, nil
}

func canonicalTargetValues(raw []string) (TargetValues, error) {
	// Empty, never nil: the target columns are NOT NULL text[].
	result := TargetValues{A: []string{}, AAAA: []string{}}
	seen := map[netip.Addr]struct{}{}
	for _, value := range raw {
		address, err := netip.ParseAddr(value)
		if err != nil || address.Is4In6() {
			return TargetValues{}, ErrInvalidInput
		}
		address = address.Unmap()
		if _, exists := seen[address]; exists {
			continue
		}
		seen[address] = struct{}{}
		if address.Is4() {
			result.A = append(result.A, address.String())
		} else {
			result.AAAA = append(result.AAAA, address.String())
		}
	}
	if len(result.A)+len(result.AAAA) == 0 {
		return TargetValues{}, ErrInvalidInput
	}
	sort.Strings(result.A)
	sort.Strings(result.AAAA)
	return result, nil
}

func (worker *Worker) Run(ctx context.Context) error {
	if ctx == nil || worker.dependencies.Tenants == nil {
		return ErrInvalidInput
	}
	ticker := time.NewTicker(worker.config.PollInterval)
	defer ticker.Stop()
	for {
		select {
		case <-ctx.Done():
			return ctx.Err()
		default:
		}
		tenants, err := worker.dependencies.Tenants.PendingTenants(ctx, 128)
		if err != nil {
			return err
		}
		if err := worker.runTenants(ctx, tenants); err != nil {
			return err
		}
		if err := worker.RunRetargets(ctx); err != nil && ctx.Err() != nil {
			return ctx.Err()
		}
		if err := worker.runRetirementsPaced(ctx); err != nil {
			if ctx.Err() != nil {
				return ctx.Err()
			}
			slog.Warn("retired CNAME owners unavailable", "error", err)
		}
		if err := worker.RunEndedSweep(ctx); err != nil {
			if ctx.Err() != nil {
				return ctx.Err()
			}
			slog.Warn("CNAME ended job sweep unavailable", "error", err)
		}
		select {
		case <-ctx.Done():
			return ctx.Err()
		case <-ticker.C:
		}
	}
}

// RunRetargets advances DNS retargets at most once per RetargetInterval. A
// database error is returned but does not stop allocation processing.
func (worker *Worker) RunRetargets(ctx context.Context) error {
	if worker.dependencies.Retargets == nil {
		return nil
	}
	now := worker.config.Now()
	if !worker.lastRetarget.IsZero() && now.Sub(worker.lastRetarget) < worker.config.RetargetInterval {
		return nil
	}
	worker.lastRetarget = now
	return worker.runRetargets(ctx)
}

// runRetirementsPaced cleans retired owners at most once per
// RetargetInterval (at least ten seconds).
func (worker *Worker) runRetirementsPaced(ctx context.Context) error {
	now := worker.config.Now()
	if !worker.lastRetire.IsZero() && now.Sub(worker.lastRetire) < max(worker.config.RetargetInterval, 10*time.Second) {
		return nil
	}
	worker.lastRetire = now
	return worker.RunRetirements(ctx)
}

// RunEndedSweep runs SweepEndedJobs at start-up and then at most once per
// endedSweepInterval.
func (worker *Worker) RunEndedSweep(ctx context.Context) error {
	if worker.dependencies.EndedJobs == nil {
		return nil
	}
	now := worker.config.Now()
	if !worker.lastSweep.IsZero() && now.Sub(worker.lastSweep) < endedSweepInterval {
		return nil
	}
	worker.lastSweep = now
	failed, err := worker.dependencies.EndedJobs.SweepEndedJobs(ctx)
	if failed > 0 {
		slog.Info("failed sites of ended CNAME jobs", "sites", failed)
	}
	return err
}

func (worker *Worker) runTenants(ctx context.Context, tenants []uuid.UUID) error {
	for _, tenantID := range tenants {
		for processed := 0; processed < maxJobsPerTenantRound; processed++ {
			didWork, err := worker.RunOnce(ctx, tenantID)
			if err != nil {
				if errors.Is(err, ErrUnavailable) || errors.Is(err, ErrConflict) || errors.Is(err, ErrClaimLost) ||
					errors.Is(err, ErrRetryable) {
					// N20: a conflict ended this tenant's round silently;
					// the job waited for its lease with nothing logged.
					slog.Warn("CNAME job round stopped", "tenant_id", tenantID, "error", err)
					break
				}
				return err
			}
			if !didWork {
				break
			}
		}
	}
	return nil
}

func (worker *Worker) RunOnce(ctx context.Context, tenantID uuid.UUID) (bool, error) {
	if ctx == nil || tenantID == uuid.Nil {
		return false, ErrInvalidInput
	}
	if worker.dependencies.Intents != nil {
		intents, err := worker.dependencies.Claims.Claim(ctx, jobstate.ClaimInput{TenantID: tenantID,
			Kind: "dns.cname.intent", WorkerID: worker.config.WorkerID, Limit: 1, LeaseDuration: worker.config.LeaseDuration})
		if err != nil {
			return false, err
		}
		if len(intents) > 0 {
			return true, worker.retrySoon(ctx, intents[0], worker.dependencies.Intents.PrepareIntent(ctx, intents[0]))
		}
	}
	if worker.dependencies.StreamIntents != nil {
		intents, err := worker.dependencies.Claims.Claim(ctx, jobstate.ClaimInput{TenantID: tenantID,
			Kind: StreamIntentJobKind, WorkerID: worker.config.WorkerID, Limit: 1, LeaseDuration: worker.config.LeaseDuration})
		if err != nil {
			return false, err
		}
		if len(intents) > 0 {
			return true, worker.retrySoon(ctx, intents[0], worker.dependencies.StreamIntents.PrepareStreamIntent(ctx, intents[0]))
		}
	}
	claims, err := worker.dependencies.Claims.Claim(ctx, jobstate.ClaimInput{
		TenantID: tenantID, Kind: databaseJobKind, WorkerID: worker.config.WorkerID,
		Limit: 1, LeaseDuration: worker.config.LeaseDuration,
	})
	if err != nil {
		return false, err
	}
	if len(claims) == 0 {
		return false, nil
	}
	didWork, err := worker.runAllocation(ctx, claims[0])
	return didWork, worker.retrySoon(ctx, claims[0], err)
}

func (worker *Worker) runAllocation(ctx context.Context, claim jobstate.Claim) (bool, error) {
	target, err := worker.dependencies.Targets.LoadTarget(ctx, claim)
	if err != nil {
		return true, err
	}
	if target.ChildTaskID == uuid.Nil {
		check, key, snapshotErr := worker.withProviderSnapshot(ctx, target.checkRequest(), "cname-"+target.Digest,
			target.TenantID, target.SiteID, target.ZoneID)
		if snapshotErr != nil {
			// A provider answer a retry cannot change fails the job with its
			// code, so the CNAME page shows why (N1: DNSPod code 13 left the
			// job running silently until each lease expired).
			var permanent interface{ FailureCode() string }
			if errors.As(snapshotErr, &permanent) && errorCodePattern.MatchString(permanent.FailureCode()) {
				slog.Warn("CNAME provider snapshot failed", "tenant_id", target.TenantID, "site_id", target.SiteID,
					"zone_id", target.ZoneID, "code", permanent.FailureCode())
				return true, worker.fail(ctx, claim, target, permanent.FailureCode())
			}
			slog.Warn("CNAME provider snapshot unavailable, retrying after lease", "tenant_id", target.TenantID,
				"site_id", target.SiteID, "zone_id", target.ZoneID, "error", snapshotErr)
			return true, ErrUnavailable
		}
		task, applyErr := worker.dependencies.Reconcile.Apply(ctx, dnsreconcile.ApplyRequest{
			TenantID: target.TenantID, SiteID: target.SiteID, ActorUserID: target.ActorUserID,
			IdempotencyKey: key, RequestID: target.RequestID,
			Traceparent: target.traceparent(), ExpectedRevision: target.ZoneRevision,
			RequiredConsecutive: 3, Check: check,
		})
		if applyErr != nil {
			if errors.Is(applyErr, dnsreconcile.ErrUnavailable) ||
				errors.Is(applyErr, dnsreconcile.ErrOperationInFlight) {
				return true, ErrUnavailable
			}
			code := ApplyFailureCode(applyErr)
			slog.Warn("CNAME DNS reconcile apply refused", "tenant_id", target.TenantID, "site_id", target.SiteID,
				"zone_id", target.ZoneID, "actor_user_id", target.ActorUserID, "request_id", target.RequestID,
				"code", code, "error", applyErr)
			return true, worker.fail(ctx, claim, target, code)
		}
		if err := worker.dependencies.Targets.AttachChild(ctx, claim, target, task); err != nil {
			return true, err
		}
		return true, worker.yield(ctx, claim)
	}
	task, err := worker.dependencies.Reconcile.Get(ctx, target.TenantID, target.ChildTaskID)
	if err != nil {
		return true, err
	}
	if task.Result.Status == dnscheck.TaskReadyToCommit {
		task, err = worker.dependencies.Reconcile.Commit(ctx, dnsreconcile.CommitRequest{
			TenantID: target.TenantID, SiteID: target.SiteID, TaskID: task.ID,
			ActorUserID: target.ActorUserID, IdempotencyKey: "cname-commit-" + target.Digest,
			RequestID: target.RequestID, Traceparent: target.traceparent(), ExpectedRevision: task.Revision,
		})
		if err != nil {
			return true, err
		}
	}
	switch {
	case task.Result.Status == dnscheck.TaskCommitted:
		_, err = worker.dependencies.Targets.Complete(ctx, target.resultRequest(claim, ""))
	case childSettledUnsuccessfully(task):
		err = worker.fail(ctx, claim, target, childFailureCode(task))
	default:
		err = worker.yield(ctx, claim)
	}
	return true, err
}

// childSettledUnsuccessfully: the child reconcile task will not commit. Its
// result says so (failed, commit_failed, cancelled, timed_out), or its job
// ended without it (N14: jobstate finalized the job retries_exhausted while
// the last result was still propagating, and the allocation polled it forever
// as "in flight", the site's CNAME pending).
func childSettledUnsuccessfully(task dnsreconcile.Task) bool {
	switch task.Result.Status {
	case dnscheck.TaskFailed, dnscheck.TaskCommitFailed, dnscheck.TaskCancelled, dnscheck.TaskTimedOut:
		return true
	}
	switch task.Job.State {
	case jobstate.StateFailed, jobstate.StatePartialFailed, jobstate.StateCancelled:
		return true
	}
	return false
}

// childFailureCode tells a provider write failure from records written but
// never confirmed visible (the propagation check gave up): the site shows the
// reason and offers "regenerate" either way.
// ApplyFailureCode names a definitive Apply refusal by its cause;
// only an error of no known kind stays dns_reconcile_unavailable.
func ApplyFailureCode(err error) string {
	for _, known := range []struct {
		err  error
		code string
	}{
		{dnsreconcile.ErrPermissionDenied, FailureDNSPermissionDenied},
		{dnsreconcile.ErrEntitlementDenied, "dns_reconcile_entitlement_denied"},
		{dnsreconcile.ErrNotFound, "dns_reconcile_not_found"},
		{dnsreconcile.ErrInvalidInput, "dns_reconcile_invalid_request"},
		{dnsreconcile.ErrIdempotencyConflict, "dns_reconcile_idempotency_conflict"},
		{dnsreconcile.ErrRevisionConflict, "dns_reconcile_revision_conflict"},
	} {
		if errors.Is(err, known.err) {
			return known.code
		}
	}
	return "dns_reconcile_unavailable"
}

func childFailureCode(task dnsreconcile.Task) string {
	if task.Result.ErrorCode == FailureDNSPermissionDenied {
		return FailureDNSPermissionDenied
	}
	written := len(task.Result.Operations) > 0
	for _, operation := range task.Result.Operations {
		written = written && operation.Status == dnscheck.OperationSucceeded
	}
	if written && task.Result.Status != dnscheck.TaskCommitFailed && task.Result.Status != dnscheck.TaskCancelled {
		return "dns_propagation_unconfirmed"
	}
	return "dns_reconcile_failed"
}

const (
	// childPollInitial is the poll of the first childPollFastAttempts
	// attempts: a child that converges (write about 1 s, then 3 consecutive
	// healthy checks 1 s apart) is committed within one poll of it, so the
	// site lists its CNAME about 10 s after the write; later polls double.
	childPollInitial      = 2 * time.Second
	childPollFastAttempts = 5
	childPollMaximum      = 5 * time.Minute
	// yieldReservedAttempts keeps the last attempts for lease-expiry retries
	// so yields never exhaust max_attempts on their own.
	yieldReservedAttempts = 2
)

// retryDelay is how soon a job aborted by a deadlock or serialization
// failure is claimable again (N20: it waited for its 16-minute lease).
const retryDelay = time.Second

// retrySoon gives the lease of a job whose transaction the database aborted
// (ErrRetryable) back for retryDelay and logs it; other results pass through.
// A job that hit ErrConflict, typically an intent whose shared allocation is
// still pending for another site (fix-cnamewait: it waited for its 16-minute
// lease), is given back on the child poll back-off (childPollDelay): that
// allocation polls its own child on the same schedule, so the intent's
// attempts outlast it. The yield spends one attempt, so it keeps the reserved
// attempts as yield.
func (worker *Worker) retrySoon(ctx context.Context, claim jobstate.Claim, err error) error {
	delay := retryDelay
	switch {
	case errors.Is(err, ErrRetryable):
	case errors.Is(err, ErrConflict):
		delay = childPollDelay(claim.Job.Attempt)
	default:
		return err
	}
	slog.Warn("CNAME job conflicted, retrying soon", "job_id", claim.Job.ID,
		"kind", claim.Job.Kind, "attempt", claim.Job.Attempt, "retry_in", delay, "error", err)
	maxAttempts := claim.Job.MaxAttempts
	if maxAttempts == 0 {
		maxAttempts = maximumJobAttempts
	}
	if claim.Job.Attempt == 0 || claim.Job.Attempt+yieldReservedAttempts > maxAttempts {
		return err
	}
	if yieldErr := worker.dependencies.Targets.Yield(ctx, claim, delay); yieldErr != nil && !errors.Is(yieldErr, ErrClaimLost) {
		return yieldErr
	}
	return err
}

// yield gives the lease back while the child reconcile task is in flight so
// the job is re-checked after a back-off (2s for the first 5 attempts, then
// doubling per attempt, capped at 5m) instead of when the lease expires. Each reclaim spends one attempt.
// Near max_attempts, or when the claim was lost meanwhile, the lease is kept.
func (worker *Worker) yield(ctx context.Context, claim jobstate.Claim) error {
	maxAttempts := claim.Job.MaxAttempts
	if maxAttempts == 0 {
		maxAttempts = maximumJobAttempts
	}
	if claim.Job.Attempt == 0 || claim.Job.Attempt+yieldReservedAttempts > maxAttempts {
		return nil
	}
	if err := worker.dependencies.Targets.Yield(ctx, claim, childPollDelay(claim.Job.Attempt)); err != nil && !errors.Is(err, ErrClaimLost) {
		return err
	}
	return nil
}

// childPollDelay: 2s for the first childPollFastAttempts attempts, then
// doubling per attempt, capped at childPollMaximum.
func childPollDelay(attempt uint32) time.Duration {
	delay := childPollInitial
	for step := uint32(childPollFastAttempts); step < attempt && delay < childPollMaximum; step++ {
		delay *= 2
	}
	return min(delay, childPollMaximum)
}

func (worker *Worker) fail(ctx context.Context, claim jobstate.Claim, target Target, code string) error {
	_, err := worker.dependencies.Targets.Fail(ctx, target.resultRequest(claim, code))
	return err
}

func (target Target) resultRequest(claim jobstate.Claim, failure string) ResultRequest {
	return ResultRequest{TargetScopeID: target.ScopeID, SiteID: target.SiteID, AllocationID: target.AllocationID,
		JobID: target.JobID, ExpectedRevision: target.AllocationRevision, WorkerID: claim.WorkerID,
		Attempt: claim.Job.Attempt, LeaseID: claim.LeaseID, Sequence: 1, FailureCode: failure}
}

func (target Target) checkRequest() dnscheck.CheckRequest {
	publish := target.Publish
	if publish.TTL == 0 {
		publish.TTL = target.TTL
	}
	return PublishCheckRequest(target.TenantID, target.SiteID, target.ZoneID, target.ZoneRevision, target.OwnerName,
		target.Values, publish)
}

func (target Target) traceparent() string {
	if len(target.Traceparent) == 55 && target.Traceparent[:3] == "00-" {
		return target.Traceparent
	}
	digest := target.Digest
	if len(digest) >= 48 {
		return "00-" + digest[:32] + "-" + digest[32:48] + "-01"
	}
	return "00-00000000000000000000000000000001-0000000000000001-01"
}
