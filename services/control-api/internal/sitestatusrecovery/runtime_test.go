package sitestatusrecovery

import (
	"context"
	"errors"
	"sync"
	"testing"
	"time"

	"github.com/cdnca/cdnca/services/control-api/internal/jobstate"
	"github.com/cdnca/cdnca/services/control-api/internal/site"
	"github.com/google/uuid"
)

type runtimeJobState struct {
	mu      sync.Mutex
	claims  []jobstate.Claim
	reports []jobstate.ReportInput
}

func (state *runtimeJobState) Claim(context.Context, jobstate.ClaimInput) ([]jobstate.Claim, error) {
	state.mu.Lock()
	defer state.mu.Unlock()
	claims := state.claims
	state.claims = nil
	return claims, nil
}

func (state *runtimeJobState) Report(_ context.Context, input jobstate.ReportInput) (jobstate.ReportResult, error) {
	state.mu.Lock()
	defer state.mu.Unlock()
	state.reports = append(state.reports, input)
	return jobstate.ReportResult{Applied: true}, nil
}

type runtimeRecoveryStore struct {
	startCalls  []site.StatusRecoveryStartRequest
	reportCalls []site.StatusRecoveryReportRequest
	reportErrs  []error
	claim       jobstate.Claim
}

func (store *runtimeRecoveryStore) StartStatusRecovery(
	_ context.Context,
	request site.StatusRecoveryStartRequest,
) (jobstate.Claim, error) {
	store.startCalls = append(store.startCalls, request)
	return store.claim, nil
}

func (store *runtimeRecoveryStore) ReportStatusRecovery(
	_ context.Context,
	request site.StatusRecoveryReportRequest,
) (jobstate.ReportResult, error) {
	store.reportCalls = append(store.reportCalls, request)
	if len(store.reportErrs) != 0 {
		err := store.reportErrs[0]
		store.reportErrs = store.reportErrs[1:]
		return jobstate.ReportResult{}, err
	}
	return jobstate.ReportResult{Applied: true}, nil
}

func TestSITE14RuntimeKeepsClaimUntilHealthyActivation(t *testing.T) {
	tenantID := uuid.MustParse("018f47a2-5b9c-7d31-8a60-104c9c0b7301")
	siteID := uuid.MustParse("018f47a2-5b9c-7d31-8a60-104c9c0b7302")
	claim := statusRecoveryClaim(tenantID, siteID, "renewal", "package_expired", 4, 0)
	jobs := &runtimeJobState{claims: []jobstate.Claim{claim}}
	recovery := &runtimeRecoveryStore{claim: claim, reportErrs: []error{site.ErrRecoveryUnhealthy}}
	runtime, err := NewRuntime(runtimeTestConfig(tenantID), RuntimeDependencies{JobState: jobs, Recovery: recovery})
	if err != nil {
		t.Fatal(err)
	}
	if err := runtime.poll(t.Context()); err != nil {
		t.Fatalf("first poll: %v", err)
	}
	if len(runtime.active) != 1 || len(recovery.reportCalls) != 1 {
		t.Fatalf("first poll active/reports=%d/%d", len(runtime.active), len(recovery.reportCalls))
	}
	if err := runtime.poll(t.Context()); err != nil {
		t.Fatalf("second poll: %v", err)
	}
	if len(runtime.active) != 0 || len(recovery.startCalls) != 2 || len(recovery.reportCalls) != 2 {
		t.Fatalf("second poll active/starts/reports=%d/%d/%d", len(runtime.active), len(recovery.startCalls), len(recovery.reportCalls))
	}
	report := recovery.reportCalls[1]
	if report.TenantID != tenantID || report.TaskID != claim.Job.ID || report.LeaseID != claim.LeaseID ||
		report.State != jobstate.ItemSucceeded || report.Attempt != claim.Job.Attempt || report.Sequence != 1 {
		t.Fatalf("success report=%+v", report)
	}
}

func TestSITE14RuntimeRejectsWrongItemWithoutStartingRecovery(t *testing.T) {
	tenantID := uuid.MustParse("018f47a2-5b9c-7d31-8a60-104c9c0b7311")
	siteID := uuid.MustParse("018f47a2-5b9c-7d31-8a60-104c9c0b7312")
	claim := statusRecoveryClaim(tenantID, siteID, "traffic_top_up", "traffic_exceeded", 2, 7)
	claim.Job.Items[0].ItemID = uuid.NewString()
	jobs := &runtimeJobState{claims: []jobstate.Claim{claim}}
	recovery := &runtimeRecoveryStore{claim: claim}
	runtime, err := NewRuntime(runtimeTestConfig(tenantID), RuntimeDependencies{JobState: jobs, Recovery: recovery})
	if err != nil {
		t.Fatal(err)
	}
	if err := runtime.poll(t.Context()); err != nil {
		t.Fatalf("poll: %v", err)
	}
	if len(recovery.startCalls) != 0 || len(recovery.reportCalls) != 0 || len(jobs.reports) != 1 {
		t.Fatalf("starts/recovery reports/job reports=%d/%d/%d", len(recovery.startCalls), len(recovery.reportCalls), len(jobs.reports))
	}
	report := jobs.reports[0]
	if report.Report.State != jobstate.ItemFailed || report.Report.Code != CodeInvalidClaim ||
		report.Report.Attempt != claim.Job.Attempt || report.Report.Sequence != 8 {
		t.Fatalf("invalid claim report=%+v", report)
	}
}

func TestSITE14RuntimeReportsTerminalRevisionConflictOnce(t *testing.T) {
	tenantID := uuid.MustParse("018f47a2-5b9c-7d31-8a60-104c9c0b7315")
	siteID := uuid.MustParse("018f47a2-5b9c-7d31-8a60-104c9c0b7316")
	claim := statusRecoveryClaim(tenantID, siteID, "renewal", "package_expired", 3, 2)
	jobs := &runtimeJobState{claims: []jobstate.Claim{claim}}
	recovery := &runtimeRecoveryStore{claim: claim, reportErrs: []error{site.ErrRevisionConflict}}
	runtime, err := NewRuntime(runtimeTestConfig(tenantID), RuntimeDependencies{JobState: jobs, Recovery: recovery})
	if err != nil {
		t.Fatal(err)
	}
	if err := runtime.poll(t.Context()); err != nil {
		t.Fatalf("poll: %v", err)
	}
	if len(runtime.active) != 0 || len(jobs.reports) != 1 {
		t.Fatalf("active/job reports=%d/%d", len(runtime.active), len(jobs.reports))
	}
	if report := jobs.reports[0].Report; report.State != jobstate.ItemFailed ||
		report.Code != CodeRevisionConflict || report.Attempt != 3 || report.Sequence != 3 {
		t.Fatalf("terminal report=%+v", report)
	}
}

func TestSITE14RuntimeLifecycleReadinessCancellationAndIdempotentClose(t *testing.T) {
	tenantID := uuid.MustParse("018f47a2-5b9c-7d31-8a60-104c9c0b7321")
	jobs := &runtimeJobState{}
	recovery := &runtimeRecoveryStore{}
	config := runtimeTestConfig(tenantID)
	config.PollInterval = time.Millisecond
	runtime, err := NewRuntime(config, RuntimeDependencies{JobState: jobs, Recovery: recovery})
	if err != nil {
		t.Fatal(err)
	}
	if !errors.Is(runtime.Ready(), ErrRuntimeNotReady) {
		t.Fatalf("initial Ready()=%v", runtime.Ready())
	}
	runDone := make(chan error, 1)
	go func() { runDone <- runtime.Run(context.Background()) }()
	deadline := time.Now().Add(time.Second)
	for runtime.Ready() != nil && time.Now().Before(deadline) {
		time.Sleep(time.Millisecond)
	}
	if err := runtime.Ready(); err != nil {
		t.Fatalf("Ready()=%v", err)
	}
	closeCtx, cancel := context.WithTimeout(t.Context(), time.Second)
	defer cancel()
	if err := runtime.Close(closeCtx); err != nil {
		t.Fatal(err)
	}
	if err := runtime.Close(closeCtx); err != nil {
		t.Fatalf("second Close()=%v", err)
	}
	if err := <-runDone; err != nil {
		t.Fatalf("Run()=%v", err)
	}
	if !errors.Is(runtime.Ready(), ErrRuntimeClosed) {
		t.Fatalf("closed Ready()=%v", runtime.Ready())
	}
}

func statusRecoveryClaim(
	tenantID, siteID uuid.UUID,
	trigger, _ string,
	attempt uint32,
	sequence uint64,
) jobstate.Claim {
	jobID := uuid.New()
	leaseID := uuid.New()
	return jobstate.Claim{
		Job: jobstate.StoredJob{
			ID: jobID, TenantID: tenantID, Kind: JobKind,
			Subject: "site/status-recovery/" + siteID.String() + "/" + trigger + "/17/41",
			State:   jobstate.StateRunning, Attempt: attempt,
			Items: []jobstate.StoredItem{{ItemID: siteID.String(), State: jobstate.ItemPending, Sequence: sequence}},
		},
		LeaseID: leaseID, WorkerID: "site-status-recovery-test", LeaseExpiresAt: time.Now().Add(time.Minute),
	}
}

func runtimeTestConfig(tenantID uuid.UUID) RuntimeConfig {
	return RuntimeConfig{
		TenantID: tenantID, WorkerID: "site-status-recovery-test", BatchSize: 8,
		LeaseDuration: time.Minute, PollInterval: time.Second,
		OperationTimeout: 2 * time.Second, ReportTimeout: time.Second,
	}
}
