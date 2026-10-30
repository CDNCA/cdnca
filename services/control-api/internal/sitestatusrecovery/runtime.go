package sitestatusrecovery

import (
	"context"
	"errors"
	"math"
	"reflect"
	"strings"
	"sync"
	"time"
	"unicode"
	"unicode/utf8"

	"github.com/cdnca/cdnca/services/control-api/internal/jobstate"
	"github.com/cdnca/cdnca/services/control-api/internal/site"
	"github.com/google/uuid"
)

const (
	JobKind                  = "site.status_recovery"
	CodeInvalidClaim         = "site_status_recovery_invalid_claim"
	CodeRevisionConflict     = "site_status_recovery_revision_conflict"
	CodeInvalidRecoveryState = "site_status_recovery_invalid_state"
)

var (
	ErrInvalidRuntime        = errors.New("invalid site status recovery runtime")
	ErrRuntimeAlreadyRunning = errors.New("site status recovery runtime already running")
	ErrRuntimeNotReady       = errors.New("site status recovery runtime not ready")
	ErrRuntimeClosed         = errors.New("site status recovery runtime closed")
	ErrJobStateUnavailable   = errors.New("site status recovery job state unavailable")
	ErrRecoveryUnavailable   = errors.New("site status recovery store unavailable")
	ErrClaimMismatch         = errors.New("site status recovery claim mismatch")
)

type JobState interface {
	Claim(context.Context, jobstate.ClaimInput) ([]jobstate.Claim, error)
	Report(context.Context, jobstate.ReportInput) (jobstate.ReportResult, error)
}

type RecoveryStore interface {
	StartStatusRecovery(context.Context, site.StatusRecoveryStartRequest) (jobstate.Claim, error)
	ReportStatusRecovery(context.Context, site.StatusRecoveryReportRequest) (jobstate.ReportResult, error)
}

type RuntimeDependencies struct {
	JobState JobState
	Recovery RecoveryStore
}

type RuntimeConfig struct {
	TenantID         uuid.UUID
	WorkerID         string
	BatchSize        int
	LeaseDuration    time.Duration
	PollInterval     time.Duration
	OperationTimeout time.Duration
	ReportTimeout    time.Duration
}

type Runtime struct {
	config   RuntimeConfig
	jobs     JobState
	recovery RecoveryStore
	active   map[uuid.UUID]jobstate.Claim

	mu      sync.Mutex
	running bool
	closing bool
	closed  bool
	ready   bool
	failure error
	cancel  context.CancelFunc
	done    chan struct{}
	closeMu sync.Mutex
}

func NewRuntime(config RuntimeConfig, dependencies RuntimeDependencies) (*Runtime, error) {
	if !validRuntimeConfig(config) || nilDependency(dependencies.JobState) || nilDependency(dependencies.Recovery) {
		return nil, ErrInvalidRuntime
	}
	return &Runtime{
		config: config, jobs: dependencies.JobState, recovery: dependencies.Recovery,
		active: make(map[uuid.UUID]jobstate.Claim),
	}, nil
}

func (runtime *Runtime) Run(ctx context.Context) error {
	if runtime == nil || ctx == nil {
		return ErrInvalidRuntime
	}
	runCtx, cancel := context.WithCancel(ctx)
	done := make(chan struct{})
	runtime.mu.Lock()
	if runtime.closing || runtime.closed {
		runtime.mu.Unlock()
		cancel()
		return ErrRuntimeClosed
	}
	if runtime.running {
		runtime.mu.Unlock()
		cancel()
		return ErrRuntimeAlreadyRunning
	}
	runtime.running = true
	runtime.ready = false
	runtime.cancel = cancel
	runtime.done = done
	runtime.mu.Unlock()
	defer func() {
		cancel()
		runtime.mu.Lock()
		runtime.running = false
		runtime.ready = false
		runtime.cancel = nil
		if runtime.closing {
			runtime.closed = true
		}
		close(done)
		runtime.mu.Unlock()
	}()

	for {
		if runCtx.Err() != nil {
			return nil
		}
		err := runtime.poll(runCtx)
		if runCtx.Err() != nil {
			return nil
		}
		runtime.recordResult(err)
		if !wait(runCtx, runtime.config.PollInterval) {
			return nil
		}
	}
}

func (runtime *Runtime) poll(ctx context.Context) error {
	claims, err := runtime.jobs.Claim(ctx, jobstate.ClaimInput{
		TenantID: runtime.config.TenantID, Kind: JobKind, WorkerID: runtime.config.WorkerID,
		Limit: runtime.config.BatchSize, LeaseDuration: runtime.config.LeaseDuration,
	})
	if err != nil {
		return ErrJobStateUnavailable
	}
	for _, claim := range claims {
		if existing, found := runtime.active[claim.Job.ID]; found && !sameClaimAuthority(existing, claim) {
			return ErrClaimMismatch
		}
		runtime.active[claim.Job.ID] = claim
	}
	for taskID, claim := range runtime.active {
		terminal, err := runtime.processClaim(ctx, claim)
		if terminal || errors.Is(err, jobstate.ErrClaimLost) {
			delete(runtime.active, taskID)
		}
		if err != nil {
			return err
		}
	}
	return nil
}

func (runtime *Runtime) processClaim(ctx context.Context, claim jobstate.Claim) (bool, error) {
	siteID, valid := validateClaim(runtime.config.TenantID, claim)
	if !valid {
		return true, runtime.reportInvalidClaim(ctx, claim)
	}
	operationCtx, cancelOperation := context.WithTimeout(ctx, runtime.config.OperationTimeout)
	started, err := runtime.recovery.StartStatusRecovery(operationCtx, site.StatusRecoveryStartRequest{
		TenantID: runtime.config.TenantID, TaskID: claim.Job.ID, WorkerID: runtime.config.WorkerID,
		LeaseDuration: runtime.config.LeaseDuration,
	})
	cancelOperation()
	if err != nil {
		return false, err
	}
	if !sameClaimAuthority(claim, started) {
		return false, ErrClaimMismatch
	}
	item := claim.Job.Items[0]
	reportCtx, cancelReport := context.WithTimeout(ctx, runtime.config.ReportTimeout)
	result, err := runtime.recovery.ReportStatusRecovery(reportCtx, site.StatusRecoveryReportRequest{
		TenantID: runtime.config.TenantID, TaskID: claim.Job.ID, WorkerID: runtime.config.WorkerID,
		LeaseID: claim.LeaseID, State: jobstate.ItemSucceeded,
		Attempt: claim.Job.Attempt, Sequence: item.Sequence + 1,
	})
	cancelReport()
	if errors.Is(err, site.ErrRecoveryUnhealthy) || errors.Is(err, site.ErrRecoveryVersionMismatch) {
		return false, nil
	}
	if errors.Is(err, site.ErrRevisionConflict) {
		return true, runtime.reportClaimFailure(ctx, claim, CodeRevisionConflict)
	}
	if errors.Is(err, site.ErrInvalidInput) || errors.Is(err, site.ErrNotFound) ||
		errors.Is(err, site.ErrLockStateConflict) {
		return true, runtime.reportClaimFailure(ctx, claim, CodeInvalidRecoveryState)
	}
	if err != nil {
		return false, ErrRecoveryUnavailable
	}
	if !result.Applied {
		return false, ErrRecoveryUnavailable
	}
	_ = siteID
	return true, nil
}

func (runtime *Runtime) reportInvalidClaim(ctx context.Context, claim jobstate.Claim) error {
	return runtime.reportClaimFailure(ctx, claim, CodeInvalidClaim)
}

func (runtime *Runtime) reportClaimFailure(ctx context.Context, claim jobstate.Claim, code string) error {
	if claim.Job.ID == uuid.Nil || claim.Job.Attempt == 0 || claim.LeaseID == uuid.Nil ||
		len(claim.Job.Items) != 1 || claim.Job.Items[0].Sequence >= math.MaxInt64 || code == "" {
		return ErrClaimMismatch
	}
	reportCtx, cancel := context.WithTimeout(ctx, runtime.config.ReportTimeout)
	defer cancel()
	result, err := runtime.jobs.Report(reportCtx, jobstate.ReportInput{
		TenantID: runtime.config.TenantID, JobID: claim.Job.ID, WorkerID: runtime.config.WorkerID,
		LeaseID: claim.LeaseID, Report: jobstate.Report{
			ItemID: claim.Job.Items[0].ItemID, State: jobstate.ItemFailed, Code: code,
			Attempt: claim.Job.Attempt, Sequence: claim.Job.Items[0].Sequence + 1,
		},
	})
	if err != nil || !result.Applied {
		return ErrJobStateUnavailable
	}
	return nil
}

func validateClaim(tenantID uuid.UUID, claim jobstate.Claim) (uuid.UUID, bool) {
	if claim.Job.ID == uuid.Nil || claim.Job.TenantID != tenantID || claim.Job.Kind != JobKind ||
		claim.Job.State != jobstate.StateRunning || claim.Job.Attempt == 0 || claim.LeaseID == uuid.Nil ||
		claim.WorkerID == "" || len(claim.Job.Items) != 1 || claim.Job.Items[0].State != jobstate.ItemPending ||
		claim.Job.Items[0].Sequence >= math.MaxInt64 {
		return uuid.Nil, false
	}
	parts := strings.Split(claim.Job.Subject, "/")
	if len(parts) != 6 || parts[0] != "site" || parts[1] != "status-recovery" ||
		(parts[3] != "renewal" && parts[3] != "traffic_top_up" && parts[3] != "unlock") {
		return uuid.Nil, false
	}
	siteID, err := uuid.Parse(parts[2])
	if err != nil || siteID == uuid.Nil || siteID.String() != parts[2] || claim.Job.Items[0].ItemID != siteID.String() {
		return uuid.Nil, false
	}
	for _, revision := range parts[4:] {
		value, err := strconvParsePositive(revision)
		if err != nil || value < 1 {
			return uuid.Nil, false
		}
	}
	return siteID, true
}

func strconvParsePositive(value string) (int64, error) {
	var parsed int64
	if value == "" || value[0] == '0' {
		return 0, ErrClaimMismatch
	}
	for _, character := range value {
		if character < '0' || character > '9' || parsed > (math.MaxInt64-int64(character-'0'))/10 {
			return 0, ErrClaimMismatch
		}
		parsed = parsed*10 + int64(character-'0')
	}
	return parsed, nil
}

func sameClaimAuthority(left, right jobstate.Claim) bool {
	return left.Job.ID == right.Job.ID && left.Job.TenantID == right.Job.TenantID &&
		left.Job.Kind == right.Job.Kind && left.Job.Attempt == right.Job.Attempt &&
		left.LeaseID == right.LeaseID && left.WorkerID == right.WorkerID
}

func (runtime *Runtime) Ready() error {
	if runtime == nil {
		return ErrInvalidRuntime
	}
	runtime.mu.Lock()
	defer runtime.mu.Unlock()
	if runtime.closing || runtime.closed {
		return ErrRuntimeClosed
	}
	if runtime.failure != nil {
		return runtime.failure
	}
	if !runtime.running || !runtime.ready {
		return ErrRuntimeNotReady
	}
	return nil
}

func (runtime *Runtime) Close(ctx context.Context) error {
	if runtime == nil || ctx == nil {
		return ErrInvalidRuntime
	}
	runtime.closeMu.Lock()
	defer runtime.closeMu.Unlock()
	runtime.mu.Lock()
	if runtime.closed {
		runtime.mu.Unlock()
		return nil
	}
	runtime.closing = true
	runtime.ready = false
	runtime.failure = nil
	cancel, done, running := runtime.cancel, runtime.done, runtime.running
	if !running {
		runtime.closed = true
	}
	runtime.mu.Unlock()
	if cancel != nil {
		cancel()
	}
	if !running {
		return nil
	}
	select {
	case <-done:
		return nil
	case <-ctx.Done():
		return ctx.Err()
	}
}

func (runtime *Runtime) recordResult(err error) {
	runtime.mu.Lock()
	defer runtime.mu.Unlock()
	if runtime.closing || runtime.closed {
		return
	}
	runtime.failure = err
	runtime.ready = err == nil
}

func validRuntimeConfig(config RuntimeConfig) bool {
	return config.TenantID != uuid.Nil && validWorkerID(config.WorkerID) &&
		config.BatchSize > 0 && config.BatchSize <= 100 &&
		config.LeaseDuration >= time.Second && config.LeaseDuration <= time.Hour &&
		config.PollInterval > 0 && config.PollInterval < config.LeaseDuration &&
		config.OperationTimeout > 0 && config.OperationTimeout < config.LeaseDuration &&
		config.ReportTimeout > 0 && config.ReportTimeout <= config.OperationTimeout
}

func validWorkerID(value string) bool {
	if value == "" || strings.TrimSpace(value) != value || !utf8.ValidString(value) || utf8.RuneCountInString(value) > 128 {
		return false
	}
	for _, character := range value {
		if unicode.IsControl(character) || character == '\u2028' || character == '\u2029' {
			return false
		}
	}
	return true
}

func nilDependency(value any) bool {
	if value == nil {
		return true
	}
	typed := reflect.ValueOf(value)
	return typed.Kind() == reflect.Pointer && typed.IsNil()
}

func wait(ctx context.Context, duration time.Duration) bool {
	timer := time.NewTimer(duration)
	defer timer.Stop()
	select {
	case <-timer.C:
		return true
	case <-ctx.Done():
		return false
	}
}
