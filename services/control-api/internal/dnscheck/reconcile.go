package dnscheck

import (
	"context"
	"crypto/rand"
	"crypto/sha256"
	"encoding/binary"
	"encoding/hex"
	"encoding/json"
	"errors"
	"regexp"
	"sort"
	"strconv"
	"strings"
	"sync"
	"time"

	"github.com/google/uuid"
)

const (
	maximumProviderAttempts = 3
	maximumPollAttempts     = 20
	maximumConsecutive      = 5
	maximumBackoff          = 30 * time.Second
	maximumOverallTimeout   = 15 * time.Minute
	maximumJitterFraction   = 0.5
)

var providerCodePattern = regexp.MustCompile(`^[a-z][a-z0-9_]{0,63}$`)

type Reconciler struct {
	checker             *Checker
	provider            ProviderAdapter
	providerAttempts    int
	providerTimeout     time.Duration
	pollAttempts        int
	requiredConsecutive int
	initialBackoff      time.Duration
	maximumBackoff      time.Duration
	overallTimeout      time.Duration
	jitterFraction      float64
	now                 func() time.Time
	sleep               func(context.Context, time.Duration) error
	random              func() float64

	mu    sync.Mutex
	tasks map[string]*reconcileTask
}

type reconcileTask struct {
	digest     string
	key        string
	request    CheckRequest
	applying   bool
	applyDone  chan struct{}
	committing bool
	commitDone chan struct{}
	result     ReconcileResult
}

type preparedReconcile struct {
	request CheckRequest
	result  ReconcileResult
}

func NewReconciler(config ReconcilerConfig) (*Reconciler, error) {
	if config.Checker == nil || config.Provider == nil || config.ProviderAttempts < 1 || config.ProviderAttempts > maximumProviderAttempts ||
		config.ProviderTimeout <= 0 || config.ProviderTimeout > maximumQueryTimeout || config.PollAttempts < 1 || config.PollAttempts > maximumPollAttempts ||
		config.RequiredConsecutive < 1 || config.RequiredConsecutive > maximumConsecutive || config.RequiredConsecutive > config.PollAttempts ||
		config.InitialBackoff <= 0 || config.MaximumBackoff < config.InitialBackoff || config.MaximumBackoff > maximumBackoff ||
		config.OverallTimeout < config.ProviderTimeout || config.OverallTimeout > maximumOverallTimeout ||
		config.JitterFraction < 0 || config.JitterFraction > maximumJitterFraction {
		return nil, ErrInvalidInput
	}
	if config.Now == nil {
		config.Now = time.Now
	}
	if config.Sleep == nil {
		config.Sleep = sleepContext
	}
	if config.Random == nil {
		config.Random = secureRandomFloat64
	}
	return &Reconciler{
		checker: config.Checker, provider: config.Provider, providerAttempts: config.ProviderAttempts,
		providerTimeout: config.ProviderTimeout, pollAttempts: config.PollAttempts, requiredConsecutive: config.RequiredConsecutive,
		initialBackoff: config.InitialBackoff, maximumBackoff: config.MaximumBackoff, overallTimeout: config.OverallTimeout,
		jitterFraction: config.JitterFraction, now: config.Now, sleep: config.Sleep, random: config.Random,
		tasks: make(map[string]*reconcileTask),
	}, nil
}

func (r *Reconciler) DryRun(request ReconcileRequest) (ReconcileResult, error) {
	prepared, err := r.prepare(request, false)
	if err != nil {
		return ReconcileResult{}, err
	}
	return cloneReconcileResult(prepared.result), nil
}

func (r *Reconciler) Apply(ctx context.Context, request ReconcileRequest) (ReconcileResult, error) {
	if err := ctx.Err(); err != nil {
		return ReconcileResult{}, err
	}
	prepared, err := r.prepare(request, true)
	if err != nil {
		return ReconcileResult{}, err
	}
	taskKey := scopedTaskKey(prepared.request.TenantID, request.IdempotencyKey)
	r.mu.Lock()
	if existing := r.tasks[taskKey]; existing != nil {
		if existing.digest != prepared.result.PayloadDigest || existing.request.SiteID != prepared.request.SiteID {
			r.mu.Unlock()
			return ReconcileResult{}, ErrIdempotencyConflict
		}
		if existing.applying {
			done := existing.applyDone
			r.mu.Unlock()
			select {
			case <-ctx.Done():
				return ReconcileResult{}, ctx.Err()
			case <-done:
			}
			r.mu.Lock()
		}
		result := cloneReconcileResult(existing.result)
		result.Replayed = true
		r.mu.Unlock()
		return result, nil
	}
	entry := &reconcileTask{
		digest: prepared.result.PayloadDigest, key: request.IdempotencyKey, request: prepared.request,
		applying: true, applyDone: make(chan struct{}), result: cloneReconcileResult(prepared.result),
	}
	r.tasks[taskKey] = entry
	r.mu.Unlock()

	executionContext, cancel := context.WithTimeout(ctx, r.overallTimeout)
	result := r.executeApply(executionContext, request.IdempotencyKey, prepared)
	cancel()
	r.mu.Lock()
	entry.result = cloneReconcileResult(result)
	entry.applying = false
	close(entry.applyDone)
	r.mu.Unlock()
	return cloneReconcileResult(result), nil
}

func (r *Reconciler) Commit(ctx context.Context, request CommitRequest) (ReconcileResult, error) {
	if err := ctx.Err(); err != nil {
		return ReconcileResult{}, err
	}
	if request.TenantID == uuid.Nil || request.SiteID == uuid.Nil || !validIdempotencyKey(request.IdempotencyKey) || !validDigest(request.PayloadDigest) {
		return ReconcileResult{}, ErrInvalidInput
	}
	taskKey := scopedTaskKey(request.TenantID, request.IdempotencyKey)
	r.mu.Lock()
	entry := r.tasks[taskKey]
	if entry == nil {
		r.mu.Unlock()
		return ReconcileResult{}, ErrTaskNotFound
	}
	if entry.digest != request.PayloadDigest || entry.request.SiteID != request.SiteID {
		r.mu.Unlock()
		return ReconcileResult{}, ErrIdempotencyConflict
	}
	if entry.applying {
		done := entry.applyDone
		r.mu.Unlock()
		select {
		case <-ctx.Done():
			return ReconcileResult{}, ctx.Err()
		case <-done:
		}
		r.mu.Lock()
	}
	if entry.result.Status == TaskCommitted {
		result := cloneReconcileResult(entry.result)
		result.Replayed = true
		r.mu.Unlock()
		return result, nil
	}
	if entry.result.Status != TaskReadyToCommit {
		r.mu.Unlock()
		return ReconcileResult{}, ErrCommitNotReady
	}
	if entry.committing {
		done := entry.commitDone
		r.mu.Unlock()
		select {
		case <-ctx.Done():
			return ReconcileResult{}, ctx.Err()
		case <-done:
		}
		r.mu.Lock()
		result := cloneReconcileResult(entry.result)
		result.Replayed = result.Status == TaskCommitted
		r.mu.Unlock()
		return result, nil
	}
	entry.committing = true
	entry.commitDone = make(chan struct{})
	base := cloneReconcileResult(entry.result)
	checkRequest := entry.request
	key := entry.key
	r.mu.Unlock()

	executionContext, cancel := context.WithTimeout(ctx, r.overallTimeout)
	result, commitErr := r.executeCommit(executionContext, key, checkRequest, base)
	cancel()
	r.mu.Lock()
	entry.result = cloneReconcileResult(result)
	entry.committing = false
	close(entry.commitDone)
	r.mu.Unlock()
	return cloneReconcileResult(result), commitErr
}

func (r *Reconciler) RecordProviderReport(request ProviderReportRequest) (ReconcileResult, error) {
	if request.TenantID == uuid.Nil || request.SiteID == uuid.Nil || !validIdempotencyKey(request.IdempotencyKey) || !validDigest(request.PayloadDigest) {
		return ReconcileResult{}, ErrInvalidInput
	}
	r.mu.Lock()
	defer r.mu.Unlock()
	entry := r.tasks[scopedTaskKey(request.TenantID, request.IdempotencyKey)]
	if entry == nil {
		return ReconcileResult{}, ErrTaskNotFound
	}
	if entry.digest != request.PayloadDigest || entry.request.SiteID != request.SiteID {
		return ReconcileResult{}, ErrIdempotencyConflict
	}
	found := false
	for index := range entry.result.Operations {
		if entry.result.Operations[index].ClientRequestID == request.Report.ClientRequestID {
			entry.result.Operations[index], _ = MergeProviderReport(entry.result.Operations[index], request.Report)
			found = true
			break
		}
	}
	if !found {
		for index := range entry.result.DeferredDeletes {
			if entry.result.DeferredDeletes[index].ClientRequestID == request.Report.ClientRequestID && request.Report.ClientRequestID != "" {
				entry.result.DeferredDeletes[index], _ = MergeProviderReport(entry.result.DeferredDeletes[index], request.Report)
				found = true
				break
			}
		}
	}
	if !found {
		return ReconcileResult{}, ErrInvalidInput
	}
	entry.result.UpdatedAt = r.now().UTC()
	return cloneReconcileResult(entry.result), nil
}

func MergeProviderReport(current OperationResult, report ProviderReport) (OperationResult, bool) {
	if report.ClientRequestID == "" || report.ClientRequestID != current.ClientRequestID || report.Sequence <= current.ReportSequence ||
		current.ProviderRequestID != "" && report.ProviderRequestID != "" && report.ProviderRequestID != current.ProviderRequestID ||
		current.ProviderRecordID != "" && report.ProviderRecordID != "" && report.ProviderRecordID != current.ProviderRecordID ||
		report.RetryAfter < 0 || report.RetryAfter > 0 && (report.Status != OperationTransientFailed ||
		report.ErrorClass != ProviderErrorTransient && report.ErrorClass != ProviderErrorTimeout) ||
		!validReportedStatus(report.Status) || isTerminalOperation(current.Status) && current.Status != OperationTransientFailed ||
		operationStatusRank(report.Status) < operationStatusRank(current.Status) {
		return current, false
	}
	if report.ProviderRevision > 0 && current.ProviderRevision > report.ProviderRevision {
		return current, false
	}
	if report.ProviderRequestID != "" {
		current.ProviderRequestID = report.ProviderRequestID
	}
	if report.ProviderRecordID != "" {
		current.ProviderRecordID = report.ProviderRecordID
	}
	if report.ProviderRevision > 0 {
		current.ProviderRevision = report.ProviderRevision
	}
	current.Status = report.Status
	current.ErrorClass = report.ErrorClass
	current.ErrorCode = normalizeProviderCode(report.ErrorCode)
	current.ReportSequence = report.Sequence
	if report.Status == OperationSucceeded {
		current.RetryAfter = 0
	} else if report.RetryAfter > 0 {
		current.RetryAfter = normalizeProviderRetryAfter(report.RetryAfter)
	}
	return current, true
}

func (r *Reconciler) prepare(request ReconcileRequest, requireKey bool) (preparedReconcile, error) {
	if (requireKey && !validIdempotencyKey(request.IdempotencyKey)) ||
		(!requireKey && request.IdempotencyKey != "" && !validIdempotencyKey(request.IdempotencyKey)) {
		return preparedReconcile{}, ErrInvalidInput
	}
	now := r.now().UTC()
	normalized, err := normalizeRequest(request.Check, now)
	if err != nil {
		return preparedReconcile{}, err
	}
	plan, err := buildRepairPlan(normalized)
	if err != nil {
		return preparedReconcile{}, err
	}
	digest, err := reconcilePayloadDigest(normalized, plan)
	if err != nil {
		return preparedReconcile{}, err
	}
	operations, deferred := safeOperationStages(plan)
	if request.IdempotencyKey != "" {
		for index := range operations {
			operations[index].ClientRequestID = operationRequestID(normalized.TenantID, request.IdempotencyKey, digest, "apply", operations[index].SourceSequence)
		}
	}
	return preparedReconcile{
		request: normalized,
		result: ReconcileResult{
			TenantID: normalized.TenantID, SiteID: normalized.SiteID, ZoneID: normalized.Provider.ZoneID,
			PayloadDigest: digest, Plan: plan, Status: TaskDryRun, StartedAt: now, UpdatedAt: now,
			InitialRevision: normalized.Provider.Revision, ProviderRevision: normalized.Provider.Revision,
			Operations: operations, DeferredDeletes: deferred,
		},
	}, nil
}

func safeOperationStages(plan RepairPlan) ([]OperationResult, []OperationResult) {
	operations := make([]OperationResult, 0, len(plan.Operations))
	deferred := make([]OperationResult, 0, len(plan.Operations))
	for _, operation := range plan.Operations {
		switch {
		case operation.Action == ProviderDelete:
			deferred = append(deferred, OperationResult{SourceSequence: operation.Sequence, Operation: operation, Status: OperationDeferred})
		case operation.Action == ProviderUpdate && operation.PreviousValue != "" && operation.PreviousValue != operation.Value:
			create := operation
			create.Action = ProviderCreate
			create.RecordID = ""
			create.PreviousValue = ""
			create.PreviousTTL = 0
			create.PreviousLine = ""
			create.PreviousWeight = 0
			create.Reason = "safe_replace_create"
			operations = append(operations, OperationResult{SourceSequence: operation.Sequence, Operation: create, Status: OperationPlanned})
			old := ProviderOperation{
				Sequence: operation.Sequence, Action: ProviderDelete, RecordID: operation.RecordID, Name: operation.Name,
				Type: operation.Type, Value: operation.PreviousValue, TTL: operation.PreviousTTL,
				Line: operation.PreviousLine, Weight: operation.PreviousWeight, Reason: "safe_replace_delete",
			}
			deferred = append(deferred, OperationResult{SourceSequence: operation.Sequence, Operation: old, Status: OperationDeferred})
		default:
			operations = append(operations, OperationResult{SourceSequence: operation.Sequence, Operation: operation, Status: OperationPlanned})
		}
	}
	sort.SliceStable(operations, func(i, j int) bool { return operations[i].SourceSequence < operations[j].SourceSequence })
	sort.SliceStable(deferred, func(i, j int) bool { return deferred[i].SourceSequence < deferred[j].SourceSequence })
	return operations, deferred
}

func reconcilePayloadDigest(request CheckRequest, plan RepairPlan) (string, error) {
	encoded, err := json.Marshal(struct {
		Request CheckRequest
		Plan    RepairPlan
	}{Request: request, Plan: plan})
	if err != nil {
		return "", err
	}
	digest := sha256.Sum256(encoded)
	return hex.EncodeToString(digest[:]), nil
}

func operationRequestID(tenantID uuid.UUID, key, digest, phase string, sequence int) string {
	input := tenantID.String() + "\x00" + key + "\x00" + digest + "\x00" + phase + "\x00" + strconv.Itoa(sequence)
	sum := sha256.Sum256([]byte(input))
	return "dns-" + hex.EncodeToString(sum[:16])
}

func scopedTaskKey(tenantID uuid.UUID, key string) string {
	return tenantID.String() + "\x00" + key
}

func validIdempotencyKey(value string) bool {
	if len(value) < 1 || len(value) > 128 || value != strings.TrimSpace(value) {
		return false
	}
	for index := 0; index < len(value); index++ {
		character := value[index]
		if character >= 'a' && character <= 'z' || character >= 'A' && character <= 'Z' || character >= '0' && character <= '9' || strings.ContainsRune("._:-", rune(character)) {
			continue
		}
		return false
	}
	return true
}

func validDigest(value string) bool {
	if len(value) != 64 {
		return false
	}
	_, err := hex.DecodeString(value)
	return err == nil
}

func validReportedStatus(status OperationStatus) bool {
	return status == OperationRunning || status == OperationSucceeded || status == OperationTransientFailed ||
		status == OperationPermanentFailed || status == OperationRevisionConflict || status == OperationCancelled
}

func isTerminalOperation(status OperationStatus) bool {
	return status == OperationSucceeded || status == OperationTransientFailed || status == OperationPermanentFailed ||
		status == OperationRevisionConflict || status == OperationCancelled || status == OperationSkipped
}

func operationStatusRank(status OperationStatus) int {
	switch status {
	case OperationPlanned, OperationDeferred:
		return 0
	case OperationRunning:
		return 1
	default:
		return 2
	}
}

func normalizeProviderCode(code string) string {
	code = strings.ToLower(strings.TrimSpace(code))
	if !providerCodePattern.MatchString(code) {
		return "provider_error"
	}
	return code
}

func classifyProviderFailure(err error) (ProviderErrorClass, string, time.Duration, string) {
	if errors.Is(err, context.Canceled) {
		return ProviderErrorCancelled, "cancelled", 0, ""
	}
	if errors.Is(err, context.DeadlineExceeded) {
		return ProviderErrorTimeout, "timeout", 0, ""
	}
	if errors.Is(err, ErrProviderRevisionConflict) {
		return ProviderErrorRevisionConflict, "revision_conflict", 0, ""
	}
	var providerError *ProviderError
	if errors.As(err, &providerError) {
		class := providerError.Class
		if class != ProviderErrorTransient && class != ProviderErrorPermanent && class != ProviderErrorRevisionConflict {
			class = ProviderErrorPermanent
		}
		providerRequestID := providerError.ProviderRequestID
		if !validProviderIdentifier(providerRequestID) {
			providerRequestID = ""
		}
		return class, normalizeProviderCode(providerError.Code), providerError.RetryAfter, providerRequestID
	}
	return ProviderErrorPermanent, "provider_error", 0, ""
}

func sleepContext(ctx context.Context, delay time.Duration) error {
	timer := time.NewTimer(delay)
	defer timer.Stop()
	select {
	case <-ctx.Done():
		return ctx.Err()
	case <-timer.C:
		return nil
	}
}

func secureRandomFloat64() float64 {
	var value [8]byte
	if _, err := rand.Read(value[:]); err != nil {
		return 0.5
	}
	return float64(binary.BigEndian.Uint64(value[:])>>11) / (1 << 53)
}
