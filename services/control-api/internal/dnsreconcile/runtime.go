package dnsreconcile

import (
	"context"
	"crypto/sha256"
	"encoding/binary"
	"errors"
	"log/slog"
	"net/netip"
	"reflect"
	"strings"
	"time"

	"github.com/cdnca/cdnca/services/control-api/internal/dnscheck"
	"github.com/cdnca/cdnca/services/control-api/internal/dnspropagation"
	"github.com/google/uuid"
	"github.com/jackc/pgx/v5/pgconn"
)

const maximumRetryAfterDeferral = time.Hour

type retryAfterCheckpointStore interface {
	checkpointApplyAfter(context.Context, ApplyLease, dnscheck.ReconcileResult, time.Duration) (Task, error)
}

type RuntimeConfig struct {
	ProviderAttempts    int
	ProviderTimeout     time.Duration
	PollAttempts        int
	RequiredConsecutive int
	InitialBackoff      time.Duration
	MaximumBackoff      time.Duration
	OverallTimeout      time.Duration
	JitterFraction      float64
	ApplyLeaseDuration  time.Duration
	CommitLeaseDuration time.Duration
	Now                 func() time.Time
	Sleep               func(context.Context, time.Duration) error
	Random              func() float64
	PropagationEnabled  bool
}

type PropagationDependencies struct {
	Engine          PropagationEngine
	RetryStates     PropagationRetryStore
	ContextResolver PropagationContextResolver
	Policy          dnspropagation.ProviderRetryPolicy
}

type RuntimeDependencies struct {
	Store            Store
	CheckerResolver  CheckerResolver
	ProviderResolver ProviderResolver
	Entitlement      EntitlementGate
	Propagation      PropagationDependencies
}

type Runtime struct {
	config      RuntimeConfig
	store       Store
	checkers    CheckerResolver
	providers   ProviderResolver
	entitlement EntitlementGate
	propagation PropagationDependencies
}

func NewRuntime(config RuntimeConfig, dependencies RuntimeDependencies) (*Runtime, error) {
	if nilPort(dependencies.Store) || nilPort(dependencies.ProviderResolver) || nilPort(dependencies.Entitlement) ||
		!validRuntimeConfig(config) ||
		config.ApplyLeaseDuration < time.Second || config.ApplyLeaseDuration > time.Hour ||
		config.CommitLeaseDuration < time.Second || config.CommitLeaseDuration > time.Hour ||
		config.ApplyLeaseDuration <= config.OverallTimeout ||
		config.CommitLeaseDuration <= config.OverallTimeout {
		return nil, ErrUnavailable
	}
	if config.PropagationEnabled {
		if nilPort(dependencies.Propagation.Engine) || nilPort(dependencies.Propagation.RetryStates) ||
			nilPort(dependencies.Propagation.ContextResolver) || !validPropagationPolicy(dependencies.Propagation.Policy) {
			return nil, ErrUnavailable
		}
	} else if nilPort(dependencies.CheckerResolver) {
		return nil, ErrUnavailable
	}
	if config.Now == nil {
		config.Now = time.Now
	}
	return &Runtime{
		config: config, store: dependencies.Store, checkers: dependencies.CheckerResolver,
		providers: dependencies.ProviderResolver, entitlement: dependencies.Entitlement,
		propagation: dependencies.Propagation,
	}, nil
}

func validRuntimeConfig(config RuntimeConfig) bool {
	return config.ProviderAttempts >= 1 && config.ProviderAttempts <= 3 &&
		config.ProviderTimeout > 0 && config.ProviderTimeout <= 30*time.Second &&
		config.PollAttempts >= 1 && config.PollAttempts <= 20 &&
		config.RequiredConsecutive >= 1 && config.RequiredConsecutive <= 5 &&
		config.RequiredConsecutive <= config.PollAttempts && config.InitialBackoff > 0 &&
		config.MaximumBackoff >= config.InitialBackoff && config.MaximumBackoff <= 30*time.Second &&
		config.OverallTimeout >= config.ProviderTimeout && config.OverallTimeout <= 15*time.Minute &&
		config.JitterFraction >= 0 && config.JitterFraction <= 0.5
}

func (runtime *Runtime) Configured() bool {
	if runtime == nil || nilPort(runtime.store) || nilPort(runtime.providers) || nilPort(runtime.entitlement) {
		return false
	}
	if !runtime.config.PropagationEnabled {
		return !nilPort(runtime.checkers)
	}
	return !nilPort(runtime.propagation.Engine) && !nilPort(runtime.propagation.RetryStates) &&
		!nilPort(runtime.propagation.ContextResolver) && validPropagationPolicy(runtime.propagation.Policy)
}

func (runtime *Runtime) DryRun(ctx context.Context, request DryRunRequest) (dnscheck.ReconcileResult, error) {
	if !runtime.Configured() || request.ActorUserID == uuid.Nil || request.RequestID == "" ||
		!validCheckScope(request.TenantID, request.SiteID, request.Check) {
		return dnscheck.ReconcileResult{}, ErrInvalidInput
	}
	if err := runtime.authorize(ctx, EntitlementRequest{TenantID: request.TenantID, SiteID: request.SiteID,
		ActorUserID: request.ActorUserID, RequestID: request.RequestID, Action: ActionDryRun}); err != nil {
		return dnscheck.ReconcileResult{}, err
	}
	prepared, err := dnscheck.PrepareReconcile(dnscheck.ReconcileRequest{
		IdempotencyKey: "dry-run", Check: request.Check,
	}, runtime.config.Now)
	if err != nil {
		return dnscheck.ReconcileResult{}, mapDNSError(err)
	}
	prepared.Result.Operations = clearClientRequestIDs(prepared.Result.Operations)
	return prepared.Result, nil
}

func (runtime *Runtime) Apply(ctx context.Context, request ApplyRequest) (Task, error) {
	if !runtime.Configured() || !validApplyRequest(request) {
		return Task{}, ErrInvalidInput
	}
	if err := runtime.authorize(ctx, EntitlementRequest{TenantID: request.TenantID, SiteID: request.SiteID,
		ActorUserID: request.ActorUserID, RequestID: request.RequestID, Action: ActionApply}); err != nil {
		return Task{}, err
	}
	prepared, err := dnscheck.PrepareReconcile(dnscheck.ReconcileRequest{
		IdempotencyKey: request.IdempotencyKey, Check: request.Check,
	}, runtime.config.Now)
	if err != nil {
		return Task{}, mapDNSError(err)
	}
	request.RequiredConsecutive = runtime.config.RequiredConsecutive
	task, replayed, err := runtime.store.Create(ctx, request, prepared)
	if err != nil {
		return Task{}, err
	}
	task.Replayed = replayed
	return task, nil
}

func (runtime *Runtime) Get(ctx context.Context, tenantID, taskID uuid.UUID) (Task, error) {
	if !runtime.Configured() || ctx == nil || tenantID == uuid.Nil || taskID == uuid.Nil {
		return Task{}, ErrInvalidInput
	}
	return runtime.store.Get(ctx, tenantID, taskID)
}

func (runtime *Runtime) RunOnce(
	ctx context.Context,
	tenantID uuid.UUID,
	workerID string,
	limit int,
) ([]Task, error) {
	if !runtime.Configured() || ctx == nil || tenantID == uuid.Nil || workerID == "" || limit < 1 || limit > 100 {
		return nil, ErrInvalidInput
	}
	if err := ctx.Err(); err != nil {
		return nil, err
	}
	completed := make([]Task, 0, limit)
	for len(completed) < limit {
		if err := ctx.Err(); err != nil {
			return completed, err
		}
		claims, err := runtime.store.Claim(ctx, ClaimRequest{
			TenantID: tenantID, WorkerID: workerID, Limit: 1, LeaseDuration: runtime.config.ApplyLeaseDuration,
		})
		if ctxErr := ctx.Err(); ctxErr != nil {
			return completed, ctxErr
		}
		if err != nil {
			return completed, err
		}
		if len(claims) == 0 {
			return completed, nil
		}
		if len(claims) > 1 {
			return completed, ErrUnavailable
		}
		executionContext, cancel := context.WithTimeout(ctx, runtime.config.OverallTimeout)
		task, err := runtime.runApplyClaim(executionContext, claims[0])
		if err != nil && ctx.Err() == nil && unrecoverableApplyError(err) {
			task, err = runtime.failRejectedApply(executionContext, claims[0], err)
		}
		cancel()
		if ctxErr := ctx.Err(); ctxErr != nil {
			if task.ID != uuid.Nil {
				completed = append(completed, task)
			}
			return completed, ctxErr
		}
		if err != nil {
			return completed, err
		}
		completed = append(completed, task)
		if task.Result.Status == dnscheck.TaskPropagating {
			return completed, nil
		}
	}
	return completed, nil
}

func (runtime *Runtime) Commit(ctx context.Context, request CommitRequest) (Task, error) {
	if !runtime.Configured() || !validCommitRequest(request) {
		return Task{}, ErrInvalidInput
	}
	if err := runtime.authorize(ctx, EntitlementRequest{TenantID: request.TenantID, SiteID: request.SiteID,
		ActorUserID: request.ActorUserID, RequestID: request.RequestID, Action: ActionCommit}); err != nil {
		return Task{}, err
	}
	lease, replayed, err := runtime.store.AcquireCommit(
		ctx, request, commitWorkerID(request), runtime.config.CommitLeaseDuration,
	)
	if err != nil {
		return Task{}, err
	}
	if replayed {
		lease.Task.Replayed = true
		return lease.Task, nil
	}
	latest := lease.Task
	prepared := lease.Task.Prepared
	executionContext, cancel := context.WithTimeout(ctx, runtime.config.OverallTimeout)
	defer cancel()
	var reconciler *dnscheck.Reconciler
	if runtime.config.PropagationEnabled {
		lease, err = runtime.store.HeartbeatCommit(executionContext, lease, runtime.config.CommitLeaseDuration)
		if err != nil {
			return Task{}, err
		}
		// The deferred deletes run once the new records are confirmed at
		// the provider (apply); they no longer wait for propagation.
		checker, checkerErr := newPropagationBridgeChecker(prepared.Request, runtime.config.Now, false)
		if checkerErr != nil {
			return Task{}, ErrUnavailable
		}
		reconciler, err = runtime.providerReconciler(executionContext, lease.Task, checker)
	} else {
		reconciler, err = runtime.reconciler(executionContext, lease.Task)
	}
	if err != nil {
		return Task{}, err
	}
	result, runErr := reconciler.ResumeCommit(executionContext, prepared, lease.Task.Result,
		func(checkpointContext context.Context, result dnscheck.ReconcileResult) error {
			lease, err = runtime.store.HeartbeatCommit(checkpointContext, lease, runtime.config.CommitLeaseDuration)
			if err != nil {
				return err
			}
			latest, err = runtime.store.CheckpointCommit(checkpointContext, lease, result)
			return err
		})
	if runErr != nil {
		if errors.Is(runErr, dnscheck.ErrCommitNotReady) {
			return latest, ErrCommitNotReady
		}
		if ctx.Err() == nil && (unrecoverableApplyError(runErr) || errors.Is(runErr, dnscheck.ErrInvalidInput)) {
			return runtime.failRejectedCommit(ctx, lease, runErr)
		}
		return latest, runErr
	}
	latest.Result = result
	return latest, nil
}

// failRejectedCommit ends a commit whose checkpoint the store rejected (N25:
// the claim then held its 16-minute lease with nothing logged, and every retry
// was rejected the same way). The commit is recorded commit_failed with
// checkpointRejectedCode, which releases the lease; the caller sees the failed
// task and the reason. The original error is returned when even that fails.
func (runtime *Runtime) failRejectedCommit(ctx context.Context, lease CommitLease, cause error) (Task, error) {
	slog.Error("DNS reconcile commit checkpoint rejected; failing the commit",
		"tenant_id", lease.Task.TenantID, "task_id", lease.Task.ID, "attempt", lease.Attempt,
		"command_key", lease.Command.IdempotencyKey, "error", cause)
	current, err := runtime.store.Get(ctx, lease.Task.TenantID, lease.Task.ID)
	if err != nil || (current.Result.Status != dnscheck.TaskReadyToCommit && current.Result.Status != dnscheck.TaskCommitFailed) {
		return Task{}, cause
	}
	result := current.Result
	result.Status = dnscheck.TaskCommitFailed
	result.ErrorClass = dnscheck.ProviderErrorPermanent
	result.ErrorCode = checkpointRejectedCode
	result.UpdatedAt = runtime.config.Now().UTC()
	lease.Task = current
	failed, err := runtime.store.CheckpointCommit(ctx, lease, result)
	if err != nil {
		slog.Error("DNS reconcile rejected commit could not be failed",
			"tenant_id", lease.Task.TenantID, "task_id", lease.Task.ID, "error", err)
		return Task{}, cause
	}
	return failed, nil
}

func commitWorkerID(request CommitRequest) string {
	identity := request.TenantID.String() + "/" + request.TaskID.String() + "/" + request.IdempotencyKey
	return "dns-commit-" + uuid.NewSHA1(uuid.NameSpaceOID, []byte(identity)).String()
}

func (runtime *Runtime) Cancel(ctx context.Context, request CancelRequest) (Task, error) {
	if !runtime.Configured() || !validCancelRequest(request) {
		return Task{}, ErrInvalidInput
	}
	if err := runtime.authorize(ctx, EntitlementRequest{TenantID: request.TenantID, SiteID: request.SiteID,
		ActorUserID: request.ActorUserID, RequestID: request.RequestID, Action: ActionCancel}); err != nil {
		return Task{}, err
	}
	task, replayed, err := runtime.store.Cancel(ctx, request)
	if err != nil {
		return Task{}, err
	}
	task.Replayed = replayed
	return task, nil
}

func (runtime *Runtime) RecordProviderReport(ctx context.Context, request ProviderReportRequest) (ReportResult, error) {
	if !runtime.Configured() || ctx == nil || ctx.Err() != nil || !validProviderReportRequest(request) {
		return ReportResult{}, ErrInvalidInput
	}
	return runtime.store.RecordProviderReport(ctx, request)
}

func (runtime *Runtime) runApplyClaim(ctx context.Context, lease ApplyLease) (Task, error) {
	var err error
	lease, err = runtime.store.HeartbeatApply(ctx, lease, runtime.config.ApplyLeaseDuration)
	if err != nil {
		return Task{}, err
	}
	if terminalApplyStatus(lease.Task.Result.Status) {
		return runtime.store.FinishApply(ctx, lease, lease.Task.Result)
	}
	if activeRetryAfter(lease.Task.Result) > 0 {
		return runtime.checkpointApply(ctx, lease, lease.Task.Result)
	}
	if err := runtime.authorize(ctx, EntitlementRequest{TenantID: lease.Task.TenantID, SiteID: lease.Task.SiteID,
		ActorUserID: lease.Task.ActorUserID, RequestID: lease.Task.RequestID, Action: ActionApply}); err != nil {
		result := lease.Task.Result
		result.Status = dnscheck.TaskFailed
		result.ErrorClass = dnscheck.ProviderErrorPermanent
		result.ErrorCode = "entitlement_denied"
		if errors.Is(err, ErrPermissionDenied) {
			result.ErrorCode = "dns_permission_denied"
		}
		slog.Warn("DNS reconcile apply refused at execution", "tenant_id", lease.Task.TenantID,
			"site_id", lease.Task.SiteID, "actor_user_id", lease.Task.ActorUserID, "code", result.ErrorCode, "error", err)
		result.UpdatedAt = runtime.config.Now().UTC()
		return runtime.store.FinishApply(ctx, lease, result)
	}
	if lease.Task.RequiredConsecutive < 1 || lease.Task.RequiredConsecutive > 5 ||
		lease.Task.RequiredConsecutive > runtime.config.PollAttempts {
		return Task{}, ErrUnavailable
	}
	if runtime.config.PropagationEnabled {
		return runtime.runPropagationApply(ctx, lease)
	}
	reconciler, err := runtime.reconciler(ctx, lease.Task)
	if err != nil {
		if errors.Is(err, ErrUnavailable) && ctx.Err() == nil {
			result := lease.Task.Result
			result.Status = dnscheck.TaskPropagating
			result.ErrorClass = dnscheck.ProviderErrorTransient
			result.ErrorCode = "dependency_unavailable"
			result.CompensationPlan = nil
			result.UpdatedAt = runtime.config.Now().UTC()
			store, ok := runtime.store.(retryAfterCheckpointStore)
			if !ok {
				return Task{}, ErrUnavailable
			}
			return store.checkpointApplyAfter(ctx, lease, result, dependencyUnavailableDelay(runtime.config, lease))
		}
		return Task{}, err
	}
	latest := lease.Task
	result, err := reconciler.ResumeApply(ctx, lease.Task.Prepared, lease.Task.Result,
		func(checkpointContext context.Context, result dnscheck.ReconcileResult) error {
			lease, err = runtime.store.HeartbeatApply(checkpointContext, lease, runtime.config.ApplyLeaseDuration)
			if err != nil {
				return err
			}
			latest, err = runtime.checkpointApply(checkpointContext, lease, result)
			return err
		})
	if err != nil {
		return latest, err
	}
	if result.Status == dnscheck.TaskPropagating {
		// The callback already checkpointed this propagating result. Keep the
		// lease-backed task running so a later worker can resume its LKG check.
		return latest, nil
	}
	return runtime.store.FinishApply(ctx, lease, result)
}

// checkpointRejectedCode names a task failed because the store refused its
// checkpoint (N22).
const checkpointRejectedCode = "dns_reconcile_checkpoint_rejected"

// unrecoverableApplyError reports a claim error that a retry with the same
// result cannot clear: the store rejected the checkpoint as invalid, or the
// database rejected its facts (integrity constraint, SQLSTATE class 23).
func unrecoverableApplyError(err error) bool {
	if errors.Is(err, ErrInvalidInput) {
		return true
	}
	var postgresError *pgconn.PgError
	return errors.As(err, &postgresError) && strings.HasPrefix(postgresError.Code, "23")
}

// failRejectedApply ends a claim whose checkpoint the store rejected. Before
// N22 such a claim kept its lease until it expired (16 minutes) and was then
// retried into the same rejection; the site showed "生成中" all along. The
// task now fails with checkpointRejectedCode, so the CNAME allocation records
// the failure and the site shows the reason and "重新生成".
func (runtime *Runtime) failRejectedApply(ctx context.Context, lease ApplyLease, cause error) (Task, error) {
	slog.Error("DNS reconcile checkpoint rejected; failing the task",
		"tenant_id", lease.Task.TenantID, "task_id", lease.Task.ID, "attempt", lease.Attempt,
		"status", lease.Task.Result.Status, "error_code", lease.Task.Result.ErrorCode, "error", cause)
	current, err := runtime.store.Get(ctx, lease.Task.TenantID, lease.Task.ID)
	if err != nil {
		return Task{}, cause
	}
	if terminalApplyStatus(current.Result.Status) {
		return Task{}, cause
	}
	result := current.Result
	result.Status = dnscheck.TaskFailed
	result.ErrorClass = dnscheck.ProviderErrorPermanent
	result.ErrorCode = checkpointRejectedCode
	result.CompensationPlan = dnscheck.CompensationForApplied(result.Operations)
	result.UpdatedAt = runtime.config.Now().UTC()
	lease.Task = current
	failed, err := runtime.store.FinishApply(ctx, lease, result)
	if err != nil {
		slog.Error("DNS reconcile rejected task could not be failed",
			"tenant_id", lease.Task.TenantID, "task_id", lease.Task.ID, "error", err)
		return Task{}, cause
	}
	return failed, nil
}

func (runtime *Runtime) runPropagationApply(ctx context.Context, lease ApplyLease) (Task, error) {
	latest := lease.Task
	result := lease.Task.Result
	if !providerOperationsComplete(result) {
		checker, err := newPropagationBridgeChecker(lease.Task.Prepared.Request, runtime.config.Now, true)
		if err != nil {
			return Task{}, ErrUnavailable
		}
		reconciler, err := runtime.providerReconciler(ctx, lease.Task, checker)
		if err != nil {
			return runtime.checkpointPropagationUnavailable(ctx, lease, result)
		}
		basePropagation := len(result.Propagation)
		result, err = reconciler.ResumeApply(ctx, lease.Task.Prepared, result,
			func(checkpointContext context.Context, checkpoint dnscheck.ReconcileResult) error {
				if len(checkpoint.Propagation) > basePropagation &&
					checkpoint.Propagation[len(checkpoint.Propagation)-1].DependencyUnavailable {
					return nil
				}
				lease, err = runtime.store.HeartbeatApply(checkpointContext, lease, runtime.config.ApplyLeaseDuration)
				if err != nil {
					return err
				}
				latest, err = runtime.checkpointApply(checkpointContext, lease, checkpoint)
				return err
			})
		if err != nil {
			return latest, err
		}
		result.Propagation = result.Propagation[:basePropagation]
		result.ErrorClass = dnscheck.ProviderErrorNone
		result.ErrorCode = ""
		result.CompensationPlan = nil
	}
	if !providerOperationsComplete(result) {
		return runtime.store.FinishApply(ctx, lease, result)
	}
	// A write the provider accepted and its API lookup
	// then found (same name, type and value; ReconcileAdapter reports an
	// operation succeeded only after that lookup) completes the task. When
	// every resolver sees it is the provider's business: propagation is not
	// checked here, so it can neither hold the task nor fail it.
	now := runtime.config.Now().UTC()
	result.ReadyAt = &now
	result.ErrorClass = dnscheck.ProviderErrorNone
	result.ErrorCode = ""
	result.CompensationPlan = nil
	result.UpdatedAt = now
	if len(result.DeferredDeletes) == 0 {
		result.Status = dnscheck.TaskCommitted
	} else {
		result.Status = dnscheck.TaskReadyToCommit
	}
	return runtime.store.FinishApply(ctx, lease, result)
}

func (runtime *Runtime) checkpointPropagationUnavailable(
	ctx context.Context,
	lease ApplyLease,
	result dnscheck.ReconcileResult,
) (Task, error) {
	result.Status = dnscheck.TaskPropagating
	result.ErrorClass = dnscheck.ProviderErrorTransient
	result.ErrorCode = "dependency_unavailable"
	result.CompensationPlan = nil
	result.UpdatedAt = runtime.config.Now().UTC()
	store, ok := runtime.store.(retryAfterCheckpointStore)
	if !ok {
		return Task{}, ErrUnavailable
	}
	return store.checkpointApplyAfter(ctx, lease, result, dependencyUnavailableDelay(runtime.config, lease))
}

func providerOperationsComplete(result dnscheck.ReconcileResult) bool {
	for _, operation := range result.Operations {
		if operation.Status != dnscheck.OperationSucceeded {
			return false
		}
	}
	return result.Status == dnscheck.TaskPropagating || len(result.Operations) == 0
}

func (runtime *Runtime) checkpointApply(
	ctx context.Context,
	lease ApplyLease,
	result dnscheck.ReconcileResult,
) (Task, error) {
	hint := activeRetryAfter(result)
	if hint == 0 {
		return runtime.store.CheckpointApply(ctx, lease, result)
	}
	store, ok := runtime.store.(retryAfterCheckpointStore)
	if !ok {
		return Task{}, ErrUnavailable
	}
	return store.checkpointApplyAfter(ctx, lease, result, retryAfterDelay(lease, hint))
}

func activeRetryAfter(result dnscheck.ReconcileResult) time.Duration {
	if result.Status != dnscheck.TaskApplying && result.Status != dnscheck.TaskPropagating ||
		result.ErrorCode == "dependency_unavailable" {
		return 0
	}
	var hint time.Duration
	for _, operation := range result.Operations {
		active := operation.Status == dnscheck.OperationRunning || operation.Status == dnscheck.OperationTransientFailed
		if active && operation.ErrorCode != "dependency_unavailable" && operation.RetryAfter > hint &&
			(operation.ErrorClass == dnscheck.ProviderErrorTransient || operation.ErrorClass == dnscheck.ProviderErrorTimeout) {
			hint = operation.RetryAfter
		}
	}
	return hint
}

func retryAfterDelay(lease ApplyLease, hint time.Duration) time.Duration {
	if hint <= 0 {
		return 0
	}
	if hint >= maximumRetryAfterDeferral {
		return maximumRetryAfterDeferral
	}
	jitterLimit := hint / 10
	if remaining := maximumRetryAfterDeferral - hint; jitterLimit > remaining {
		jitterLimit = remaining
	}
	if jitterLimit <= 0 {
		return hint
	}
	hash := sha256.New()
	hash.Write([]byte("cdnca:dns-reconcile:retry-after-yield:v1\x00"))
	hash.Write(lease.Task.TenantID[:])
	hash.Write(lease.Task.ID[:])
	var encoded [8]byte
	binary.BigEndian.PutUint64(encoded[:], uint64(lease.Attempt))
	hash.Write(encoded[:])
	hash.Write(lease.LeaseID[:])
	binary.BigEndian.PutUint64(encoded[:], uint64(len(lease.WorkerID)))
	hash.Write(encoded[:])
	hash.Write([]byte(lease.WorkerID))
	binary.BigEndian.PutUint64(encoded[:], uint64(hint))
	hash.Write(encoded[:])
	digest := hash.Sum(nil)
	jitter := time.Duration(binary.BigEndian.Uint64(digest[:8]) % (uint64(jitterLimit) + 1))
	return hint + jitter
}

func dependencyUnavailableDelay(config RuntimeConfig, lease ApplyLease) time.Duration {
	delay := config.InitialBackoff
	for attempt := uint32(1); attempt < lease.Attempt && delay < config.MaximumBackoff; attempt++ {
		if delay >= config.MaximumBackoff-delay {
			delay = config.MaximumBackoff
		} else {
			delay += delay
		}
	}
	if jittered := retryAfterDelay(lease, delay); jittered < config.MaximumBackoff {
		return jittered
	}
	return config.MaximumBackoff
}

func (runtime *Runtime) reconciler(ctx context.Context, task Task) (*dnscheck.Reconciler, error) {
	if task.RequiredConsecutive < 1 || task.RequiredConsecutive > 5 {
		return nil, ErrUnavailable
	}
	checker, err := runtime.checkers.ResolveChecker(ctx, task.TenantID, task.SiteID)
	if err != nil || checker == nil {
		return nil, ErrUnavailable
	}
	return runtime.providerReconciler(ctx, task, checker)
}

func (runtime *Runtime) providerReconciler(
	ctx context.Context,
	task Task,
	checker *dnscheck.Checker,
) (*dnscheck.Reconciler, error) {
	if checker == nil || task.RequiredConsecutive < 1 || task.RequiredConsecutive > 5 {
		return nil, ErrUnavailable
	}
	provider, err := runtime.providers.ResolveProvider(ctx, task.TenantID, task.SiteID, task.Result.ZoneID)
	if err != nil || nilPort(provider) {
		return nil, ErrUnavailable
	}
	result, err := dnscheck.NewReconciler(dnscheck.ReconcilerConfig{
		Checker: checker, Provider: provider, ProviderAttempts: runtime.config.ProviderAttempts,
		ProviderTimeout: runtime.config.ProviderTimeout, PollAttempts: runtime.config.PollAttempts,
		RequiredConsecutive: task.RequiredConsecutive, InitialBackoff: runtime.config.InitialBackoff,
		MaximumBackoff: runtime.config.MaximumBackoff, OverallTimeout: runtime.config.OverallTimeout,
		JitterFraction: runtime.config.JitterFraction, Now: runtime.config.Now,
		Sleep: runtime.config.Sleep, Random: runtime.config.Random,
	})
	if err != nil {
		return nil, ErrUnavailable
	}
	return result, nil
}

type propagationBridgeResolver struct {
	expected    map[dnscheck.RecordType][]string
	ttl         uint32
	unavailable bool
}

func (resolver propagationBridgeResolver) Resolve(
	ctx context.Context,
	_ dnscheck.ResolverEndpoint,
	query dnscheck.DNSQuery,
) (dnscheck.DNSResponse, error) {
	if err := ctx.Err(); err != nil {
		return dnscheck.DNSResponse{}, err
	}
	if resolver.unavailable {
		return dnscheck.DNSResponse{}, dnscheck.ErrDependencyUnavailable
	}
	values := resolver.expected[query.Type]
	answers := make([]dnscheck.DNSRecord, len(values))
	for index, value := range values {
		answers[index] = dnscheck.DNSRecord{Name: query.Name, Type: query.Type, TTL: resolver.ttl, Value: value}
	}
	return dnscheck.DNSResponse{Authoritative: true, Answers: answers}, nil
}

func newPropagationBridgeChecker(
	request dnscheck.CheckRequest,
	now func() time.Time,
	unavailable bool,
) (*dnscheck.Checker, error) {
	authorityNames := append([]string(nil), request.AuthoritativeNS...)
	if len(authorityNames) == 0 {
		authorityNames = []string{"propagation-authority.invalid"}
	}
	if len(authorityNames) > 200 {
		return nil, ErrUnavailable
	}
	endpoints := make([]dnscheck.ResolverEndpoint, 0, len(authorityNames)+1)
	authorities := make([]dnscheck.NamedResolver, len(authorityNames))
	for index, name := range authorityNames {
		endpoint, err := dnscheck.NewResolverEndpoint(
			"udp", netip.AddrFrom4([4]byte{192, 0, 2, byte(index + 1)}).String(), 53,
		)
		if err != nil {
			return nil, ErrUnavailable
		}
		endpoints = append(endpoints, endpoint)
		authorities[index] = dnscheck.NamedResolver{Name: name, Endpoint: endpoint}
	}
	publicEndpoint, err := dnscheck.NewResolverEndpoint("udp", "198.51.100.1", 53)
	if err != nil {
		return nil, ErrUnavailable
	}
	endpoints = append(endpoints, publicEndpoint)
	policy, err := dnscheck.NewEndpointPolicy(endpoints...)
	if err != nil {
		return nil, ErrUnavailable
	}
	expected := make(map[dnscheck.RecordType][]string, len(request.Expected))
	for _, record := range request.Expected {
		expected[record.Type] = append([]string(nil), record.Values...)
	}
	checker, err := dnscheck.NewChecker(dnscheck.Config{
		Resolver:       propagationBridgeResolver{expected: expected, ttl: request.TTL, unavailable: unavailable},
		EndpointPolicy: policy, AuthoritativeResolvers: authorities,
		PublicResolvers: []dnscheck.NamedResolver{{Name: "propagation-public", Endpoint: publicEndpoint}},
		QueryTimeout:    time.Second, Attempts: 1, MaxCNAMEDepth: 16, Now: now,
	})
	if err != nil {
		return nil, ErrUnavailable
	}
	return checker, nil
}

func validPropagationPolicy(policy dnspropagation.ProviderRetryPolicy) bool {
	return policy.BaseDelay > 0 && policy.MaxDelay >= policy.BaseDelay && policy.MaxDelay <= time.Hour &&
		policy.BudgetWindow > 0 && policy.CircuitOpen > 0 && policy.AttemptsPerZone > 0 &&
		policy.TransientFailuresToOpen > 0
}

func (runtime *Runtime) authorize(ctx context.Context, request EntitlementRequest) error {
	if ctx == nil || ctx.Err() != nil || request.TenantID == uuid.Nil || request.SiteID == uuid.Nil ||
		request.ActorUserID == uuid.Nil || request.RequestID == "" {
		return ErrInvalidInput
	}
	err := runtime.entitlement.AuthorizeDNSReconcile(ctx, request)
	if err == nil {
		return nil
	}
	// The gate's own verdicts keep their meaning (fix-regen2: an actor who is
	// not the tenant's was reported as an entitlement denial, the CNAME page
	// as "DNS 服务商调用失败").
	for _, sentinel := range []error{ErrPermissionDenied, ErrNotFound, ErrUnavailable} {
		if errors.Is(err, sentinel) {
			return sentinel
		}
	}
	return ErrEntitlementDenied
}

func validCheckScope(tenantID, siteID uuid.UUID, check dnscheck.CheckRequest) bool {
	return tenantID != uuid.Nil && siteID != uuid.Nil && check.TenantID == tenantID &&
		check.SiteID == siteID && check.Provider.TenantID == tenantID && check.Provider.SiteID == siteID
}

func validApplyRequest(request ApplyRequest) bool {
	return validCheckScope(request.TenantID, request.SiteID, request.Check) && request.ActorUserID != uuid.Nil && request.ExpectedRevision > 0 &&
		request.ExpectedRevision == request.Check.Provider.Revision && request.IdempotencyKey != "" &&
		request.RequestID != "" && request.Traceparent != ""
}

func validCommitRequest(request CommitRequest) bool {
	return request.TenantID != uuid.Nil && request.SiteID != uuid.Nil && request.TaskID != uuid.Nil &&
		request.ActorUserID != uuid.Nil &&
		request.IdempotencyKey != "" && request.RequestID != "" && request.Traceparent != "" && request.ExpectedRevision > 0
}

func validCancelRequest(request CancelRequest) bool {
	return request.TenantID != uuid.Nil && request.SiteID != uuid.Nil && request.TaskID != uuid.Nil &&
		request.ActorUserID != uuid.Nil &&
		request.IdempotencyKey != "" && request.RequestID != "" && request.Traceparent != "" && request.ExpectedRevision > 0
}

func validProviderReportRequest(request ProviderReportRequest) bool {
	return request.TenantID != uuid.Nil && request.SiteID != uuid.Nil && request.TaskID != uuid.Nil &&
		validWorker(request.WorkloadID) && request.JobAttempt > 0 && request.LeaseID != uuid.Nil &&
		request.IdempotencyKey != "" && request.RequestID != "" && request.Traceparent != "" &&
		request.ExpectedRevision > 0 && request.Report.ClientRequestID != "" && request.Report.Sequence > 0
}

func terminalApplyStatus(status dnscheck.TaskStatus) bool {
	switch status {
	case dnscheck.TaskReadyToCommit, dnscheck.TaskCommitted, dnscheck.TaskFailed,
		dnscheck.TaskCancelled, dnscheck.TaskTimedOut:
		return true
	default:
		return false
	}
}

func clearClientRequestIDs(results []dnscheck.OperationResult) []dnscheck.OperationResult {
	cloned := append([]dnscheck.OperationResult(nil), results...)
	for index := range cloned {
		cloned[index].ClientRequestID = ""
	}
	return cloned
}

func mapDNSError(err error) error {
	if errors.Is(err, dnscheck.ErrInvalidInput) {
		return ErrInvalidInput
	}
	return err
}

func nilPort(value any) bool {
	if value == nil {
		return true
	}
	reflected := reflect.ValueOf(value)
	return reflected.Kind() == reflect.Pointer && reflected.IsNil()
}
