package dnsmaintenance

import (
	"context"
	"crypto/sha256"
	"encoding/hex"
	"errors"
	"time"

	"github.com/cdnca/cdnca/services/control-api/internal/cnameallocation"
	"github.com/cdnca/cdnca/services/control-api/internal/dnscheck"
	"github.com/cdnca/cdnca/services/control-api/internal/dnsproviderremote"
	"github.com/cdnca/cdnca/services/control-api/internal/jobstate"
	"github.com/google/uuid"
)

// Jobs is the jobstate.Store subset the worker uses.
type Jobs interface {
	Claim(context.Context, jobstate.ClaimInput) ([]jobstate.Claim, error)
	Heartbeat(context.Context, jobstate.HeartbeatInput) (time.Time, error)
	Report(context.Context, jobstate.ReportInput) (jobstate.ReportResult, error)
}

// Targets is the Store subset the worker uses (faked in tests).
type Targets interface {
	PendingTenants(context.Context) ([]uuid.UUID, error)
	TenantScope(context.Context, uuid.UUID) (uuid.UUID, error)
	RepairTarget(context.Context, uuid.UUID, uuid.UUID, string) (RepairTarget, error)
	ServingValues(context.Context, RepairTarget) (cnameallocation.TargetValues, error)
	PublishSettings(context.Context, RepairTarget) (cnameallocation.PublishSettings, error)
	ClaimedHostnames(context.Context, []uuid.UUID) (map[string]bool, error)
	// ZoneApex returns the target zone's hosted domain, looked up once and
	// written back for zones saved before migration 473.
	ZoneApex(ctx context.Context, target RepairTarget, providerType string, credentials map[string]string) (string, error)
}

// Remote lists and deletes provider records.
type Remote interface {
	dnsproviderremote.ZoneRecordLister
	Mutate(context.Context, dnsproviderremote.ProviderConfig, dnscheck.ProviderOperation) (string, error)
}

type WorkerConfig struct {
	WorkerID      string
	PollInterval  time.Duration
	LeaseDuration time.Duration
	// ItemTimeout bounds the wait for one repair's reconcile task.
	ItemTimeout time.Duration
	TaskPoll    time.Duration
}

type Worker struct {
	config    WorkerConfig
	jobs      Jobs
	targets   Targets
	platform  Platform
	remote    Remote
	reconcile cnameallocation.ReconcileRuntime
}

func NewWorker(config WorkerConfig, jobs Jobs, targets Targets, platform Platform, remote Remote,
	reconcile cnameallocation.ReconcileRuntime) (*Worker, error) {
	if config.WorkerID == "" || config.PollInterval <= 0 || config.LeaseDuration <= 0 || config.ItemTimeout <= 0 ||
		config.TaskPoll <= 0 || jobs == nil || targets == nil || platform == nil || remote == nil || reconcile == nil {
		return nil, ErrInvalidInput
	}
	return &Worker{config: config, jobs: jobs, targets: targets, platform: platform, remote: remote, reconcile: reconcile}, nil
}

func (worker *Worker) Run(ctx context.Context) error {
	ticker := time.NewTicker(worker.config.PollInterval)
	defer ticker.Stop()
	for {
		if err := worker.RunOnce(ctx); err != nil && !errors.Is(err, context.Canceled) {
			return err
		}
		select {
		case <-ctx.Done():
			return ctx.Err()
		case <-ticker.C:
		}
	}
}

// RunOnce claims and runs every claimable 记录修复 / 清除CDN无关解析 job.
func (worker *Worker) RunOnce(ctx context.Context) error {
	tenants, err := worker.targets.PendingTenants(ctx)
	if err != nil {
		return err
	}
	for _, tenantID := range tenants {
		for _, kind := range []string{RepairJobKind, CleanupJobKind} {
			claims, err := worker.jobs.Claim(ctx, jobstate.ClaimInput{TenantID: tenantID, Kind: kind,
				WorkerID: worker.config.WorkerID, Limit: 1, LeaseDuration: worker.config.LeaseDuration})
			if err != nil {
				return err
			}
			for _, claim := range claims {
				if err := worker.process(ctx, claim); err != nil {
					return err
				}
			}
		}
	}
	return nil
}

func (worker *Worker) process(ctx context.Context, claim jobstate.Claim) error {
	scopeID, err := worker.targets.TenantScope(ctx, claim.Job.TenantID)
	if err != nil {
		return err
	}
	for _, item := range claim.Job.Items {
		if item.State != jobstate.ItemPending {
			continue
		}
		if err := worker.heartbeat(ctx, claim); err != nil {
			return err
		}
		var code string
		if claim.Job.Kind == RepairJobKind {
			code = worker.repair(ctx, claim, scopeID, item.ItemID)
		} else {
			code = worker.cleanup(ctx, claim, scopeID, item.ItemID)
		}
		state := jobstate.ItemSucceeded
		if code != "" {
			state = jobstate.ItemFailed
		}
		if _, err := worker.jobs.Report(ctx, jobstate.ReportInput{TenantID: claim.Job.TenantID, JobID: claim.Job.ID,
			WorkerID: claim.WorkerID, LeaseID: claim.LeaseID, Report: jobstate.Report{ItemID: item.ItemID, State: state,
				Code: code, Attempt: claim.Job.Attempt, Sequence: 1}}); err != nil {
			return err
		}
	}
	return nil
}

func (worker *Worker) heartbeat(ctx context.Context, claim jobstate.Claim) error {
	_, err := worker.jobs.Heartbeat(ctx, jobstate.HeartbeatInput{TenantID: claim.Job.TenantID, JobID: claim.Job.ID,
		WorkerID: claim.WorkerID, Attempt: claim.Job.Attempt, LeaseID: claim.LeaseID, LeaseDuration: worker.config.LeaseDuration})
	return err
}

func digest(parts ...string) string {
	hash := sha256.New()
	for _, part := range parts {
		hash.Write([]byte(part))
		hash.Write([]byte{0})
	}
	return hex.EncodeToString(hash.Sum(nil))
}
