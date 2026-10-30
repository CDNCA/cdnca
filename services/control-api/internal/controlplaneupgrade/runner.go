package controlplaneupgrade

import (
	"context"
	"encoding/base64"
	"encoding/hex"
	"errors"
	"fmt"
	"time"

	"github.com/cdnca/cdnca/libs/entitlement"
	"github.com/cdnca/cdnca/services/control-api/internal/entitlementguard"
)

type Config struct {
	InstallationID string
	Component      string
	Target         Target
}

type Executor interface {
	Target() Target
	Facts(context.Context) (Facts, error)
	Expand(context.Context, Plan) error
	Preflight(context.Context, Plan) error
	Drain(context.Context, Plan) error
	Activate(context.Context, Plan) error
	Health(context.Context, Plan, Artifact) error
	Contract(context.Context, Plan) error
	Rollback(context.Context, Plan) error
	Resume(context.Context, Plan) error
}

type Runner struct {
	config   Config
	trust    *entitlementguard.TrustStore
	store    *FileStore
	executor Executor
	now      func() time.Time
	// runLog is the operator-readable step log; nil disables it.
	runLog *runLogWriter
}

// programLogCollector is implemented by executors that can attach a bounded,
// redacted tail of the affected services' logs to the run log.
type programLogCollector interface {
	collectProgramLogs(ctx context.Context, trigger string)
}

func New(config Config, trust *entitlementguard.TrustStore, store *FileStore, executor Executor,
	now func() time.Time) (*Runner, error) {
	if config.InstallationID == "" || config.Component != "control-api" ||
		(config.Target != TargetKubernetes && config.Target != TargetSystemd && config.Target != TargetNativeStandalone) || trust == nil || store == nil ||
		executor == nil || executor.Target() != config.Target || now == nil {
		return nil, ErrInvalidConfig
	}
	return &Runner{config: config, trust: trust, store: store, executor: executor, now: now}, nil
}

func (runner *Runner) verify(encoded []byte, facts Facts) (Plan, error) {
	plan, err := runner.verifyBundle(encoded)
	if err != nil {
		return Plan{}, err
	}
	if err := runner.matchFacts(plan, facts, PhaseVerified); err != nil {
		return Plan{}, err
	}
	return plan, nil
}

func (runner *Runner) verifyBundle(encoded []byte) (Plan, error) {
	if len(encoded) == 0 || len(encoded) > 1<<20 {
		return Plan{}, ErrInvalidPlan
	}
	signed, err := entitlement.DecodeUpgradePlanArtifactBundle(encoded)
	if err != nil {
		return Plan{}, err
	}
	bundle, err := runner.trust.VerifyUpgradePlanArtifactBundle(encoded, entitlement.UpgradePlanArtifactBundleVerifyOptions{
		Now: runner.now(), ExpectedAudience: entitlement.UpgradePlanArtifactBundleAudience,
		ExpectedInstallationID: runner.config.InstallationID, ExpectedPlanID: signed.Bundle.PlanID,
		ExpectedInitialPlanRevision: 1,
	})
	if err != nil {
		return Plan{}, err
	}
	if bundle.Component != runner.config.Component {
		return Plan{}, ErrTargetMismatch
	}
	toArtifact := func(value entitlement.UpgradePlanArtifact) (Artifact, error) {
		digest, err := base64.RawURLEncoding.DecodeString(value.Manifest.SHA256Digest)
		if err != nil || len(digest) != 32 {
			return Artifact{}, ErrInvalidPlan
		}
		return Artifact{ID: value.Manifest.ArtifactID, Version: value.Manifest.Version,
			Digest: hex.EncodeToString(digest), URL: value.Manifest.DownloadURL,
			Size: value.Manifest.ArtifactSizeBytes, Sequence: value.Manifest.ReleaseSequence}, nil
	}
	target, err := toArtifact(bundle.Forward)
	if err != nil {
		return Plan{}, err
	}
	rollback, err := toArtifact(bundle.Rollback)
	if err != nil {
		return Plan{}, err
	}
	if target.Sequence <= rollback.Sequence {
		return Plan{}, ErrTargetMismatch
	}
	return Plan{ID: bundle.PlanID, BundleID: bundle.BundleID, BundleSHA256: digestBytes(encoded),
		InstallationID: bundle.InstallationID, Component: bundle.Component, CurrentVersion: bundle.CurrentVersion,
		TargetVersion: bundle.Version, ProtocolVersion: bundle.ProtocolVersion, Sequence: target.Sequence,
		Target: target, Rollback: rollback}, nil
}

func (runner *Runner) matchFacts(plan Plan, facts Facts, phase Phase) error {
	if facts.InstallationID != runner.config.InstallationID || facts.ProtocolVersion != plan.ProtocolVersion ||
		!digestPattern.MatchString(facts.CurrentDigest) {
		return ErrTargetMismatch
	}
	if phase == PhaseVerified || phase == PhaseExpanded || phase == PhasePreflighted {
		if facts.CurrentVersion != plan.CurrentVersion || facts.CurrentDigest != plan.Rollback.Digest {
			return ErrTargetMismatch
		}
		return nil
	}
	if (facts.CurrentVersion == plan.CurrentVersion && facts.CurrentDigest == plan.Rollback.Digest) ||
		(facts.CurrentVersion == plan.TargetVersion && facts.CurrentDigest == plan.Target.Digest) {
		return nil
	}
	return ErrTargetMismatch
}

func (runner *Runner) Run(ctx context.Context, encoded []byte) (Receipt, error) {
	plan, err := runner.verifyBundle(encoded)
	if err != nil {
		return Receipt{}, err
	}
	state, err := runner.store.Load()
	if err == nil && state.PlanID == plan.ID && state.BundleSHA256 == plan.BundleSHA256 && state.Receipt != nil &&
		(state.Phase == PhaseCompleted || state.Phase == PhaseRolledBack || state.Phase == PhaseFailed) {
		receipt := *state.Receipt
		receipt.Replayed = true
		return receipt, nil
	}
	if err == nil && state.PlanID == plan.ID && state.BundleSHA256 != plan.BundleSHA256 {
		return Receipt{}, ErrPlanConflict
	}
	// A checkpoint that already failed before Drain changed nothing live, so a
	// different plan for the same or a newer sequence may replace it.
	superseded := err == nil && state.PlanID != plan.ID && state.Supersedable()
	if err == nil && state.PlanID != plan.ID && (state.Sequence > plan.Sequence || (state.Sequence == plan.Sequence && !superseded)) {
		return Receipt{}, ErrStalePlan
	}
	if err == nil && state.PlanID != plan.ID && !superseded && state.Phase != PhaseCompleted && state.Phase != PhaseRolledBack && state.Phase != PhaseFailed {
		return Receipt{}, ErrPlanInProgress
	}
	facts, factsErr := runner.executor.Facts(ctx)
	if factsErr != nil {
		return Receipt{}, factsErr
	}
	matchPhase := PhaseVerified
	if err == nil && state.PlanID == plan.ID {
		matchPhase = state.Phase
	}
	if err := runner.matchFacts(plan, facts, matchPhase); err != nil {
		return Receipt{}, err
	}
	switch {
	case errors.Is(err, ErrStateNotFound):
		state = State{Schema: StateSchema, PlanID: plan.ID, BundleSHA256: plan.BundleSHA256,
			Sequence: plan.Sequence, Phase: PhaseVerified, PreviousDigest: facts.CurrentDigest,
			TargetDigest: plan.Target.Digest}
		if err := runner.save(state); err != nil {
			return Receipt{}, err
		}
	case err != nil:
		return Receipt{}, err
	case state.PlanID == plan.ID && state.BundleSHA256 == plan.BundleSHA256:
	default:
		state = State{Schema: StateSchema, PlanID: plan.ID, BundleSHA256: plan.BundleSHA256,
			Sequence: plan.Sequence, Phase: PhaseVerified, PreviousDigest: facts.CurrentDigest,
			TargetDigest: plan.Target.Digest}
		if err := runner.save(state); err != nil {
			return Receipt{}, err
		}
	}
	return runner.resume(ctx, plan, state)
}

// migrationExecutor is implemented by executors that apply append-only
// database migrations between Drain and Activate. The runner owns the durable
// MigrationRecord; each method is idempotent so a restarted runner can redo it.
type migrationExecutor interface {
	// PendingMigrations returns the appended migration identifiers, or nil.
	PendingMigrations(context.Context, Plan) ([]string, error)
	StopControl(context.Context, Plan) error
	BackupDatabase(context.Context, Plan, *MigrationRecord) error
	MigrateDatabase(context.Context, Plan, *MigrationRecord) error
	RestoreDatabase(context.Context, Plan, *MigrationRecord) error
}

func (runner *Runner) resume(ctx context.Context, plan Plan, state State) (Receipt, error) {
	ctx = withRunLog(ctx, runner.runLog)
	if attempt := runner.runLog.begin(plan.ID, plan.Sequence); attempt == 1 {
		logRun(ctx, RunLogEntry{Level: "info", Event: "run_started", Version: plan.TargetVersion, Attempt: attempt})
	} else if attempt > 1 {
		logRun(ctx, RunLogEntry{Level: "info", Event: "run_resumed", Step: string(state.Phase), Attempt: attempt})
	}
	migrator, _ := runner.executor.(migrationExecutor)
	migrating := func() bool { return migrator != nil && state.Migration != nil }
	steps := []struct {
		from Phase
		to   Phase
		name string
		code string
		run  func(context.Context, Plan) error
		skip func() bool
	}{
		{PhaseVerified, PhaseExpanded, "expand", "expand_failed", runner.executor.Expand, nil},
		{PhaseExpanded, PhasePreflighted, "preflight", "compatibility_preflight_failed", runner.executor.Preflight, nil},
		{PhasePreflighted, PhaseDrained, "drain", "drain_failed", func(ctx context.Context, plan Plan) error {
			// The migration decision is fixed before anything live changes, so a
			// restarted runner follows the same path from the checkpoint.
			state.Migration = nil
			if migrator != nil {
				pending, err := migrator.PendingMigrations(ctx, plan)
				if err != nil {
					return err
				}
				if len(pending) > 0 {
					state.Migration = &MigrationRecord{Applied: pending}
					logRun(ctx, RunLogEntry{Level: "info", Event: "migrations_pending", Count: len(pending), Migrations: pending})
				}
			}
			return runner.executor.Drain(ctx, plan)
		}, nil},
		{PhaseDrained, PhaseControlStopped, "control_stop", "control_stop_failed", func(ctx context.Context, plan Plan) error {
			return migrator.StopControl(ctx, plan)
		}, func() bool { return !migrating() }},
		{PhaseControlStopped, PhaseDatabaseBackedUp, "database_backup", "database_backup_failed", func(ctx context.Context, plan Plan) error {
			if err := migrator.BackupDatabase(ctx, plan, state.Migration); err != nil {
				return err
			}
			logRun(ctx, RunLogEntry{Level: "info", Event: "database_backed_up", Bytes: state.Migration.BackupBytes,
				DurationMS: state.Migration.BackupMillis})
			return nil
		}, func() bool { return !migrating() }},
		{PhaseDatabaseBackedUp, PhaseDatabaseMigrated, "database_migrate", "database_migration_failed", func(ctx context.Context, plan Plan) error {
			if err := migrator.MigrateDatabase(ctx, plan, state.Migration); err != nil {
				return err
			}
			logRun(ctx, RunLogEntry{Level: "info", Event: "database_migrated", Count: len(state.Migration.Applied),
				Migrations: state.Migration.Applied, DurationMS: state.Migration.MigrateMillis})
			return nil
		}, func() bool { return !migrating() }},
		{PhaseDrained, PhaseActivated, "activate", "activation_failed", func(ctx context.Context, plan Plan) error {
			if migrator != nil {
				// Never start a candidate whose schema was not applied.
				if pending, err := migrator.PendingMigrations(ctx, plan); err != nil || len(pending) > 0 {
					return errors.Join(ErrTargetMismatch, err)
				}
			}
			return runner.executor.Activate(ctx, plan)
		}, migrating},
		{PhaseDatabaseMigrated, PhaseActivated, "activate", "activation_failed", runner.executor.Activate, func() bool { return !migrating() }},
		{PhaseActivated, PhaseHealthy, "health", "target_health_failed", func(ctx context.Context, plan Plan) error {
			return runner.executor.Health(ctx, plan, plan.Target)
		}, nil},
		{PhaseHealthy, PhaseContracted, "contract", "contract_failed", runner.executor.Contract, nil},
	}
	for _, step := range steps {
		if state.Phase != step.from || (step.skip != nil && step.skip()) {
			continue
		}
		started := runner.now()
		logRun(ctx, RunLogEntry{Level: "info", Event: "step_started", Step: step.name})
		if err := step.run(ctx, plan); err != nil {
			code := stepCode(err, step.code)
			logRun(ctx, RunLogEntry{Level: "error", Event: "step_failed", Step: step.name, ErrorCode: code,
				Reason: runFailureReason(err), DurationMS: runner.since(started)})
			if supersedablePhase(step.from) && errors.Is(err, ErrCandidateRejected) {
				return runner.fail(ctx, state, plan, code, err)
			}
			if supersedablePhase(step.from) {
				state.ErrorCode = code
				if saveErr := runner.save(state); saveErr != nil {
					return Receipt{}, saveErr
				}
				logRun(ctx, RunLogEntry{Level: "warning", Event: "retry_scheduled", Step: step.name, ErrorCode: code})
				return Receipt{}, err
			}
			return runner.rollback(ctx, state, plan, code, err)
		}
		logRun(ctx, RunLogEntry{Level: "info", Event: "step_succeeded", Step: step.name, DurationMS: runner.since(started)})
		state.Phase, state.ErrorCode = step.to, ""
		if err := runner.save(state); err != nil {
			return Receipt{}, err
		}
	}
	if state.Phase == PhaseRollingBack {
		return runner.rollback(ctx, state, plan, state.ErrorCode, errors.New(state.ErrorCode))
	}
	if state.Phase != PhaseContracted {
		return Receipt{}, ErrCorruptState
	}
	started := runner.now()
	logRun(ctx, RunLogEntry{Level: "info", Event: "step_started", Step: "resume"})
	if err := runner.executor.Resume(ctx, plan); err != nil {
		logRun(ctx, RunLogEntry{Level: "error", Event: "step_failed", Step: "resume", ErrorCode: "resume_failed",
			Reason: runFailureReason(err), DurationMS: runner.since(started)})
		return runner.rollback(ctx, state, plan, "resume_failed", err)
	}
	logRun(ctx, RunLogEntry{Level: "info", Event: "step_succeeded", Step: "resume", DurationMS: runner.since(started)})
	receipt := runner.receipt(plan, ResultApplied, "", state.Migration)
	state.Phase, state.Receipt = PhaseCompleted, &receipt
	if err := runner.save(state); err != nil {
		return Receipt{}, err
	}
	runner.finish(ctx, "completed", "info", "")
	return receipt, nil
}

// finish closes the run log with the terminal result and the services' logs.
func (runner *Runner) finish(ctx context.Context, result, level, code string) {
	if runner.runLog == nil {
		return
	}
	runner.collectPrograms(ctx, "run_"+result)
	logRun(ctx, RunLogEntry{Level: level, Event: "run_" + result, ErrorCode: code})
}

func (runner *Runner) collectPrograms(ctx context.Context, trigger string) {
	if collector, ok := runner.executor.(programLogCollector); ok && runner.runLog != nil {
		collector.collectProgramLogs(ctx, trigger)
	}
}

func (runner *Runner) since(started time.Time) int64 {
	elapsed := runner.now().Sub(started).Milliseconds()
	if elapsed < 0 {
		return 0
	}
	return elapsed
}

// runFailureReason maps a step error to a stable code the console explains.
// It never includes error text, which may carry a signed URL.
func runFailureReason(err error) string {
	switch {
	case errors.Is(err, ErrArtifactUnavailable):
		return "artifact_unavailable"
	case errors.Is(err, ErrCandidateRejected):
		return "candidate_rejected"
	case errors.Is(err, context.DeadlineExceeded):
		return "timeout"
	case errors.Is(err, context.Canceled):
		return "cancelled"
	case errors.Is(err, ErrPlanConflict):
		return "plan_conflict"
	case errors.Is(err, ErrInvalidPlan):
		return "artifact_invalid"
	case errors.Is(err, ErrTargetMismatch):
		return "target_mismatch"
	default:
		return "unexpected"
	}
}

func (runner *Runner) rollback(ctx context.Context, state State, plan Plan, code string, cause error) (Receipt, error) {
	state.Phase, state.ErrorCode = PhaseRollingBack, code
	if err := runner.save(state); err != nil {
		return Receipt{}, err
	}
	// Keep the failed version's service logs: rollback restarts replace them.
	runner.collectPrograms(ctx, "rollback_started")
	logRun(ctx, RunLogEntry{Level: "warning", Event: "rollback_started", ErrorCode: code, Version: plan.CurrentVersion})
	started := runner.now()
	// A completed backup means the database may hold the candidate schema:
	// restore it before the old release starts. Restored is persisted so a
	// restarted runner never restores again over the old release's writes.
	if migrator, ok := runner.executor.(migrationExecutor); ok && state.Migration != nil &&
		state.Migration.BackupPath != "" && !state.Migration.Restored {
		restoreStarted := runner.now()
		logRun(ctx, RunLogEntry{Level: "warning", Event: "database_restore_started", Bytes: state.Migration.BackupBytes})
		restoreFailed := func(err error) (Receipt, error) {
			logRun(ctx, RunLogEntry{Level: "error", Event: "step_failed", Step: "database_restore", ErrorCode: "database_restore_failed",
				Reason: runFailureReason(err), DurationMS: runner.since(restoreStarted)})
			return runner.fail(ctx, state, plan, "database_restore_failed", fmt.Errorf("%v: %w", cause, err))
		}
		if err := migrator.StopControl(ctx, plan); err != nil {
			return restoreFailed(err)
		}
		if err := migrator.RestoreDatabase(ctx, plan, state.Migration); err != nil {
			return restoreFailed(err)
		}
		state.Migration.Restored = true
		if err := runner.save(state); err != nil {
			return Receipt{}, err
		}
		logRun(ctx, RunLogEntry{Level: "info", Event: "database_restored", Bytes: state.Migration.BackupBytes,
			DurationMS: state.Migration.RestoreMillis})
	}
	if err := runner.executor.Rollback(ctx, plan); err != nil {
		logRun(ctx, RunLogEntry{Level: "error", Event: "step_failed", Step: "rollback", ErrorCode: "rollback_failed",
			Reason: runFailureReason(err), DurationMS: runner.since(started)})
		return runner.fail(ctx, state, plan, "rollback_failed", fmt.Errorf("%v: %w", cause, err))
	}
	if err := runner.executor.Health(ctx, plan, plan.Rollback); err != nil {
		logRun(ctx, RunLogEntry{Level: "error", Event: "step_failed", Step: "rollback_health", ErrorCode: "rollback_health_failed",
			Reason: runFailureReason(err), DurationMS: runner.since(started)})
		return runner.fail(ctx, state, plan, "rollback_health_failed", fmt.Errorf("%v: %w", cause, err))
	}
	if err := runner.executor.Resume(ctx, plan); err != nil {
		logRun(ctx, RunLogEntry{Level: "error", Event: "step_failed", Step: "resume", ErrorCode: "rollback_resume_failed",
			Reason: runFailureReason(err), DurationMS: runner.since(started)})
		return runner.fail(ctx, state, plan, "rollback_resume_failed", fmt.Errorf("%v: %w", cause, err))
	}
	logRun(ctx, RunLogEntry{Level: "info", Event: "rollback_succeeded", Version: plan.CurrentVersion, DurationMS: runner.since(started)})
	receipt := runner.receipt(plan, ResultRolledBack, code, state.Migration)
	state.Phase, state.Receipt = PhaseRolledBack, &receipt
	if err := runner.save(state); err != nil {
		return Receipt{}, err
	}
	runner.finish(ctx, "rolled_back", "warning", code)
	return receipt, fmt.Errorf("%w: %v", ErrRolledBack, cause)
}

func (runner *Runner) fail(ctx context.Context, state State, plan Plan, code string, cause error) (Receipt, error) {
	receipt := runner.receipt(plan, ResultFailed, code, state.Migration)
	state.Phase, state.ErrorCode, state.Receipt = PhaseFailed, code, &receipt
	if err := runner.save(state); err != nil {
		return Receipt{}, err
	}
	runner.finish(ctx, "failed", "error", code)
	return receipt, cause
}

// save persists the recovery checkpoint, then journals it for the upgrade
// log. The journal is evidence only and can never fail an upgrade step.
func supersedablePhase(phase Phase) bool {
	return phase == PhaseVerified || phase == PhaseExpanded || phase == PhasePreflighted
}

// Supersedable reports a retry checkpoint whose last attempt failed before
// Drain: the live release and maintenance gate were never touched.
func (state State) Supersedable() bool {
	return supersedablePhase(state.Phase) && state.ErrorCode != "" && state.Receipt == nil
}

func (runner *Runner) save(state State) error {
	if err := runner.store.Save(state); err != nil {
		return err
	}
	_ = runner.store.appendHistory(state, runner.now())
	return nil
}

func (runner *Runner) receipt(plan Plan, result Result, code string, migration *MigrationRecord) Receipt {
	return Receipt{ID: fmt.Sprintf("%s:%d", plan.ID, plan.Sequence), PlanID: plan.ID,
		BundleSHA256: plan.BundleSHA256, Sequence: plan.Sequence, Target: runner.config.Target,
		CurrentVersion: plan.CurrentVersion, TargetVersion: plan.TargetVersion, Result: result,
		ErrorCode: code, CompletedAt: runner.now().UTC().Unix(), Migration: migration.clone()}
}
