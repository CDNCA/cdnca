package controlupgrade

import (
	"context"
	"crypto/sha256"
	"encoding/json"
	"errors"
	"fmt"
	"log/slog"
	"sort"
	"strings"
	"time"

	"github.com/cdnca/cdnca/services/control-api/internal/approvalcenter"
	"github.com/google/uuid"
	"github.com/jackc/pgx/v5"
)

// A create preparation (migration 700) is the background half of CreateRollout:
// the request records it with its intent and returns; PrepareRolloutsOnce
// claims it, issues the License artifacts, caches both artifacts, finalizes
// the plan and, for a create with start_when_ready, starts it as the console's
// create-then-start did.
type PreparationState string

const (
	PreparationPreparing PreparationState = "preparing"
	PreparationFailed    PreparationState = "failed"
	PreparationReady     PreparationState = "ready"
)

type PreparationPhase string

const (
	PreparationQueued      PreparationPhase = "queued"
	PreparationIssuing     PreparationPhase = "issuing"
	PreparationDownloading PreparationPhase = "downloading"
	PreparationFinalizing  PreparationPhase = "finalizing"
	PreparationStarting    PreparationPhase = "starting"
	PreparationDone        PreparationPhase = "done"
)

// Stable failure codes of a failed preparation (the 710 CHECK lists the same set).
const (
	PreparationFailureLicenseUnavailable    = "license_unavailable"
	PreparationFailureLicenseOutcomeUnknown = "license_outcome_unknown"
	PreparationFailureLicenseRejected       = "license_rejected"
	PreparationFailureGrantInvalid          = "grant_invalid"
	PreparationFailureDownloadFailed        = "artifact_download_failed"
	PreparationFailureArtifactInvalid       = "artifact_invalid"
	PreparationFailureCohortIncompatible    = "cohort_incompatible"
	PreparationFailurePermissionDenied      = "permission_denied"
	PreparationFailureResourceUnavailable   = "resource_unavailable"
	PreparationFailureInternal              = "internal_error"
	// Start failure codes only (start_failure_code): the approval center holds
	// rollout starts, or the plan no longer takes a start.
	PreparationStartApprovalRequired = "approval_required"
	PreparationStartRefused          = "start_refused"
)

const (
	// The claim is renewed while the preparation runs, so a stopped process
	// releases it within one lease.
	createPreparationLease       = 2 * time.Minute
	createPreparationRenewal     = 30 * time.Second
	createPreparationRetryDelay  = 15 * time.Second
	createPreparationMaxAttempts = 5
	// Open (preparing or failed) preparations listed with the rollouts.
	createPreparationListLimit = 20
)

// ErrRolloutPreparing: the plan of this ID is still being prepared and cannot
// take an action yet.
var ErrRolloutPreparing = errors.New("control upgrade rollout is still being prepared")

var errCreatePreparationClaimLost = errors.New("control upgrade create preparation claim is no longer owned")

// errStartApprovalRequired: the approval center holds POST .../start, so the
// plan is left queued for the console's start to go through approval.
var errStartApprovalRequired = errors.New("control upgrade rollout start needs an approval")

type RolloutPreparation struct {
	ID          string           `json:"id"`
	PlanID      string           `json:"plan_id"`
	State       PreparationState `json:"state"`
	Phase       PreparationPhase `json:"phase"`
	FailureCode string           `json:"failure_code,omitempty"`
	// FailureReason is License's refusal code (or http_<status> for a codeless
	// refusal) when FailureCode or StartFailureCode is license_rejected.
	FailureReason  string `json:"failure_reason,omitempty"`
	StartWhenReady bool   `json:"start_when_ready"`
	// StartFailureCode: a ready plan asked to start was left queued, and why.
	StartFailureCode string    `json:"start_failure_code,omitempty"`
	NodeIDs          []string  `json:"node_ids"`
	CreatedAt        time.Time `json:"created_at"`
	UpdatedAt        time.Time `json:"updated_at"`
}

type CreateRolloutResult struct {
	Preparation RolloutPreparation
	Replayed    bool
}

type createPreparationClaim struct {
	IntentID string
	Token    string
	Attempt  int
	Actor    Actor
	Request  CreateRolloutRequest
}

// EnqueueCreateRollout reserves the create intent and its preparation in one
// transaction. A new intent is reserved only for a cohort that loads now, so an
// offline or incompatible node is refused at once; the same idempotency key
// returns the existing preparation (or the ready one of a finished create).
func (s *Store) EnqueueCreateRollout(ctx context.Context, actor Actor, identity RolloutIdentity,
	request CreateRolloutRequest, digest [sha256.Size]byte) (CreateRolloutResult, error) {
	if s == nil || s.pool == nil || !validRolloutActor(actor) || !validRolloutIdentity(identity) ||
		identity.ActorScopeID != actor.ScopeID.String() || identity.ActorUserID != actor.UserID.String() ||
		validateCreateRolloutRequest(request) != nil {
		return CreateRolloutResult{}, ErrInvalidInput
	}
	body, err := json.Marshal(request.CreateRolloutBody)
	if err != nil {
		return CreateRolloutResult{}, ErrInvalidInput
	}
	var result CreateRolloutResult
	var denied bool
	err = pgx.BeginFunc(ctx, s.pool, func(tx pgx.Tx) error {
		intent, replay, deniedTx, reserved, err := s.prepareCreateRolloutTx(ctx, tx, actor, identity, request, digest,
			func(tx pgx.Tx) error {
				_, err := loadRolloutTargetCohortTx(ctx, tx, actor.ScopeID, request.NodeIDs, false)
				return err
			})
		if err != nil {
			return err
		}
		if deniedTx {
			denied = true
			return nil
		}
		result.Replayed = !reserved
		if replay.Replayed {
			result.Preparation, err = readReadyPreparationTx(ctx, tx, actor.ScopeID, replay.Detail.ID)
			return err
		}
		// A new intent, or one a pre-710 console left unfinished, gets its preparation here.
		if _, err := tx.Exec(ctx, `INSERT INTO control_upgrade_create_preparations(
			intent_id,plan_id,actor_scope_id,actor_user_id,node_ids,request_bytes,start_when_ready,state,phase,
			attempt_count,available_at,created_at,updated_at)
			SELECT $1,$2,$3,$4,$5::uuid[],$6,$7,'preparing','queued',0,clock.at,clock.at,clock.at
			FROM (SELECT date_trunc('microseconds',clock_timestamp()) AS at) clock
			ON CONFLICT (intent_id) DO NOTHING`, intent.ID, intent.PlanID, actor.ScopeID, actor.UserID,
			request.NodeIDs, body, request.StartWhenReady); err != nil {
			return err
		}
		result.Preparation, err = readPreparationTx(ctx, tx, "intent_id=$1 AND actor_scope_id=$2", intent.ID, actor.ScopeID)
		return err
	})
	if err != nil {
		return CreateRolloutResult{}, fmt.Errorf("enqueue control upgrade rollout create: %w", err)
	}
	if denied {
		return CreateRolloutResult{}, ErrPermissionDenied
	}
	return result, nil
}

// readReadyPreparationTx is the preparation of a finished create; a plan created
// before migration 700 has none and is described from its intent.
func readReadyPreparationTx(ctx context.Context, tx pgx.Tx, scopeID uuid.UUID, planID string) (RolloutPreparation, error) {
	preparation, err := readPreparationTx(ctx, tx, "plan_id=$1 AND actor_scope_id=$2", planID, scopeID)
	if !errors.Is(err, pgx.ErrNoRows) {
		return preparation, err
	}
	preparation = RolloutPreparation{PlanID: planID, State: PreparationReady, Phase: PreparationDone}
	var snapshot []byte
	err = tx.QueryRow(ctx, `SELECT intent.id::text,intent.created_at,intent.updated_at,plan.canonical_snapshot_bytes
		FROM control_upgrade_grant_intents_096 intent
		JOIN control_upgrade_rollout_plans plan ON plan.id=intent.plan_id
		WHERE intent.plan_id=$1 AND intent.actor_scope_id=$2`, planID, scopeID).Scan(&preparation.ID,
		&preparation.CreatedAt, &preparation.UpdatedAt, &snapshot)
	if err != nil {
		return RolloutPreparation{}, err
	}
	var plan struct{ Targets map[string]json.RawMessage }
	if json.Unmarshal(snapshot, &plan) != nil || len(plan.Targets) == 0 {
		return RolloutPreparation{}, ErrInvalidPlan
	}
	for nodeID := range plan.Targets {
		preparation.NodeIDs = append(preparation.NodeIDs, nodeID)
	}
	sort.Strings(preparation.NodeIDs)
	return preparation, nil
}

func readPreparationTx(ctx context.Context, tx pgx.Tx, condition string, arguments ...any) (RolloutPreparation, error) {
	var preparation RolloutPreparation
	err := tx.QueryRow(ctx, `SELECT intent_id::text,plan_id::text,state,phase,COALESCE(failure_code,''),
		COALESCE(failure_reason,''),start_when_ready,COALESCE(start_failure_code,''),node_ids::text[],created_at,updated_at
		FROM control_upgrade_create_preparations WHERE `+condition, arguments...).Scan(&preparation.ID,
		&preparation.PlanID, &preparation.State, &preparation.Phase, &preparation.FailureCode,
		&preparation.FailureReason, &preparation.StartWhenReady, &preparation.StartFailureCode, &preparation.NodeIDs,
		&preparation.CreatedAt, &preparation.UpdatedAt)
	return preparation, err
}

// listOpenPreparationsTx lists the newest preparing or failed preparations of a
// scope, and ready ones whose plan was not started as asked, optionally only
// those naming nodeID.
func listOpenPreparationsTx(ctx context.Context, tx pgx.Tx, scopeID uuid.UUID, nodeID string) ([]RolloutPreparation, error) {
	rows, err := tx.Query(ctx, `SELECT intent_id::text,plan_id::text,state,phase,COALESCE(failure_code,''),
		COALESCE(failure_reason,''),start_when_ready,COALESCE(start_failure_code,''),node_ids::text[],created_at,updated_at
		FROM control_upgrade_create_preparations
		WHERE actor_scope_id=$1 AND (state<>'ready' OR start_failure_code IS NOT NULL)
		  AND ($2::uuid IS NULL OR $2::uuid=ANY(node_ids))
		ORDER BY created_at DESC,intent_id DESC LIMIT $3`, scopeID, nullableUUID(nodeID), createPreparationListLimit)
	if err != nil {
		return nil, err
	}
	defer rows.Close()
	preparations := []RolloutPreparation{}
	for rows.Next() {
		var preparation RolloutPreparation
		if err := rows.Scan(&preparation.ID, &preparation.PlanID, &preparation.State, &preparation.Phase,
			&preparation.FailureCode, &preparation.FailureReason, &preparation.StartWhenReady,
			&preparation.StartFailureCode, &preparation.NodeIDs, &preparation.CreatedAt, &preparation.UpdatedAt); err != nil {
			return nil, err
		}
		preparations = append(preparations, preparation)
	}
	return preparations, rows.Err()
}

func nullableUUID(value string) any {
	if value == "" {
		return nil
	}
	return value
}

// createPreparationPendingTx reports whether planID names a plan that is still
// being prepared (or whose preparation failed) in the scope.
func createPreparationPendingTx(ctx context.Context, tx pgx.Tx, scopeID uuid.UUID, planID string) (bool, error) {
	var pending bool
	err := tx.QueryRow(ctx, `SELECT EXISTS(SELECT 1 FROM control_upgrade_create_preparations
		WHERE plan_id=$1 AND actor_scope_id=$2 AND state<>'ready')`, planID, scopeID).Scan(&pending)
	return pending, err
}

// claimCreatePreparation claims the oldest due preparation that is unclaimed or
// whose claim expired (its process stopped), for one lease.
func (s *Store) claimCreatePreparation(ctx context.Context, workerID string) (createPreparationClaim, bool, error) {
	var claim createPreparationClaim
	var scopeID, userID uuid.UUID
	var body []byte
	err := s.pool.QueryRow(ctx, `WITH candidate AS (
			SELECT intent_id FROM control_upgrade_create_preparations
			WHERE state='preparing' AND available_at<=clock_timestamp()
			  AND (claim_token IS NULL OR claim_expires_at<=clock_timestamp())
			ORDER BY available_at,created_at,intent_id LIMIT 1 FOR UPDATE SKIP LOCKED)
		UPDATE control_upgrade_create_preparations preparation
		SET claimed_by=$1,claim_token=gen_random_uuid(),
			claim_expires_at=clock_timestamp()+$2*interval '1 millisecond',
			attempt_count=preparation.attempt_count+1,updated_at=GREATEST(preparation.updated_at,clock_timestamp())
		FROM candidate, control_upgrade_grant_intents_096 intent
		WHERE preparation.intent_id=candidate.intent_id AND intent.id=preparation.intent_id
		RETURNING preparation.intent_id::text,preparation.claim_token::text,preparation.attempt_count,
			preparation.actor_scope_id,preparation.actor_user_id,preparation.request_bytes,
			intent.idempotency_key,intent.request_id`, workerID, createPreparationLease.Milliseconds()).Scan(
		&claim.IntentID, &claim.Token, &claim.Attempt, &scopeID, &userID, &body,
		&claim.Request.IdempotencyKey, &claim.Request.RequestID)
	if errors.Is(err, pgx.ErrNoRows) {
		return createPreparationClaim{}, false, nil
	}
	if err != nil {
		return createPreparationClaim{}, false, fmt.Errorf("claim control upgrade create preparation: %w", err)
	}
	claim.Actor = Actor{UserID: userID, ScopeID: scopeID, ScopeKind: "platform"}
	// A body that no longer decodes fails the preparation through validation.
	_ = json.Unmarshal(body, &claim.Request.CreateRolloutBody)
	return claim, true, nil
}

// updateClaimedPreparation runs one claimed-row update; no row means the claim was lost.
func (s *Store) updateClaimedPreparation(ctx context.Context, claim createPreparationClaim, set string,
	arguments ...any) error {
	result, err := s.pool.Exec(ctx, `UPDATE control_upgrade_create_preparations SET `+set+`,
		updated_at=GREATEST(updated_at,clock_timestamp())
		WHERE intent_id=$1 AND claim_token=$2 AND state='preparing'`,
		append([]any{claim.IntentID, claim.Token}, arguments...)...)
	if err != nil {
		return err
	}
	if result.RowsAffected() != 1 {
		return errCreatePreparationClaimLost
	}
	return nil
}

func (s *Store) renewCreatePreparation(ctx context.Context, claim createPreparationClaim) error {
	return s.updateClaimedPreparation(ctx, claim,
		`claim_expires_at=clock_timestamp()+$3*interval '1 millisecond'`, createPreparationLease.Milliseconds())
}

func (s *Store) setCreatePreparationPhase(ctx context.Context, claim createPreparationClaim, phase PreparationPhase) error {
	return s.updateClaimedPreparation(ctx, claim, `phase=$3`, string(phase))
}

const releasePreparationClaim = `claimed_by=NULL,claim_token=NULL,claim_expires_at=NULL`

// completeCreatePreparation marks the plan made; startCode (with startReason)
// says why a plan asked to start was left queued.
func (s *Store) completeCreatePreparation(ctx context.Context, claim createPreparationClaim,
	startCode, startReason string) error {
	return s.updateClaimedPreparation(ctx, claim, `state='ready',phase='done',start_failure_code=NULLIF($3,''),
		failure_reason=NULLIF($4,''),`+releasePreparationClaim, startCode, startReason)
}

// controlUpgradeApprovalRequired: the approval center holds rollout starts
// (internal/approvalcenter, rule control.upgrade).
func (s *Store) controlUpgradeApprovalRequired(ctx context.Context) (bool, error) {
	var held bool
	err := s.pool.QueryRow(ctx, `SELECT COALESCE((SELECT enabled AND $1=ANY(rules)
		FROM approval_center_settings WHERE singleton),false)`, approvalcenter.RuleControlUpgrade).Scan(&held)
	return held, err
}

func (s *Store) failCreatePreparation(ctx context.Context, claim createPreparationClaim, code, reason string) error {
	return s.updateClaimedPreparation(ctx, claim, `state='failed',failure_code=$3,failure_reason=NULLIF($4,''),`+
		releasePreparationClaim, code, reason)
}

// requeueCreatePreparation releases the claim; the preparation runs again after delay.
func (s *Store) requeueCreatePreparation(ctx context.Context, claim createPreparationClaim, delay time.Duration) error {
	return s.updateClaimedPreparation(ctx, claim,
		`available_at=clock_timestamp()+$3*interval '1 millisecond',`+releasePreparationClaim, delay.Milliseconds())
}

// PrepareRolloutsOnce claims one due create preparation and runs it to a ready
// plan (started when the create asked for it), a stable failure, or a requeue
// (a transient conflict, or the process is stopping). It reports whether a
// preparation was claimed; the error is only a claim or settlement failure, a
// failed preparation is recorded instead.
func (s *Service) PrepareRolloutsOnce(ctx context.Context, workerID string) (bool, error) {
	if s == nil || s.store == nil || s.rollout == nil || ctx == nil || !rolloutSafeIDPattern.MatchString(workerID) {
		return false, ErrRuntimeUnavailable
	}
	claim, found, err := s.store.claimCreatePreparation(ctx, workerID)
	if err != nil || !found {
		return false, err
	}
	runCtx, cancel := context.WithTimeout(ctx, rolloutWriteTimeout)
	renewed := make(chan struct{})
	go func() {
		defer close(renewed)
		ticker := time.NewTicker(createPreparationRenewal)
		defer ticker.Stop()
		for {
			select {
			case <-runCtx.Done():
				return
			case <-ticker.C:
				if errors.Is(s.store.renewCreatePreparation(runCtx, claim), errCreatePreparationClaimLost) {
					cancel()
					return
				}
			}
		}
	}()
	progress := func(phase PreparationPhase) {
		if errors.Is(s.store.setCreatePreparationPhase(runCtx, claim, phase), errCreatePreparationClaimLost) {
			cancel()
		}
	}
	created, runErr := s.completeCreateRollout(runCtx, claim.Actor, claim.Request, progress)
	planned := runErr == nil
	code, reason, retryable := createPreparationFailure(runErr)
	if planned && claim.Request.StartWhenReady {
		progress(PreparationStarting)
		if startErr := s.startPreparedRollout(runCtx, claim, created.Detail); startErr != nil {
			runErr = startErr
			code, reason, retryable = createPreparationStartFailure(startErr)
		}
	}
	interrupted := runErr != nil && runCtx.Err() != nil && !errors.Is(runCtx.Err(), context.DeadlineExceeded)
	cancel()
	<-renewed
	// Settle even while the process stops, so the next one does not wait out the lease.
	settleCtx, settleCancel := context.WithTimeout(context.WithoutCancel(ctx), 10*time.Second)
	defer settleCancel()
	switch {
	case runErr == nil:
		err = s.store.completeCreatePreparation(settleCtx, claim, "", "")
	case interrupted:
		err = s.store.requeueCreatePreparation(settleCtx, claim, 0)
	case retryable && claim.Attempt < createPreparationMaxAttempts:
		err = s.store.requeueCreatePreparation(settleCtx, claim, createPreparationRetryDelay)
	case planned:
		// The plan exists and stays queued; the console offers its start with the reason.
		slog.Warn("control upgrade rollout was not started after its preparation", "intent_id", claim.IntentID,
			"start_failure_code", code, "error", runErr)
		err = s.store.completeCreatePreparation(settleCtx, claim, code, reason)
	default:
		slog.Warn("control upgrade create preparation failed", "intent_id", claim.IntentID,
			"failure_code", code, "error", runErr)
		err = s.store.failCreatePreparation(settleCtx, claim, code, reason)
	}
	if errors.Is(err, errCreatePreparationClaimLost) {
		// Another worker took it over after this claim expired; its result stands.
		err = nil
	}
	if err != nil {
		return true, fmt.Errorf("settle control upgrade create preparation: %w", err)
	}
	if planned && !interrupted {
		s.pruneArtifactCache(settleCtx)
	}
	return true, nil
}

// startPreparedRollout starts the plan the preparation just made, as the
// console's start after its create did: the creator's start with the plan's
// first revision, under a key fixed by the intent so a resumed preparation
// replays it. A held start (approval center) is left to the console.
func (s *Service) startPreparedRollout(ctx context.Context, claim createPreparationClaim, plan RolloutDetail) error {
	held, err := s.store.controlUpgradeApprovalRequired(ctx)
	if err != nil {
		return fmt.Errorf("%w: read approval center settings: %v", ErrResourceUnavailable, err)
	}
	if held {
		return errStartApprovalRequired
	}
	key := "control-upgrade-auto-start-" + strings.ReplaceAll(claim.IntentID, "-", "")
	_, err = s.ApplyRolloutAction(ctx, claim.Actor, RolloutActionRequest{
		RolloutActionBody: RolloutActionBody{ExpectedRevision: plan.Revision, Reason: "operator_upgrade"},
		PlanID:            plan.ID, Operation: string(PlanStart), IdempotencyKey: key, RequestID: key})
	return err
}

// createPreparationStartFailure maps an auto-start error to its start failure
// code. A retryable one is what the console offered "retry the same request"
// for (unknown or unavailable License, a transient conflict).
func createPreparationStartFailure(err error) (code, reason string, retryable bool) {
	switch {
	case errors.Is(err, errStartApprovalRequired):
		return PreparationStartApprovalRequired, "", false
	case errors.Is(err, ErrStalePlanRevision), errors.Is(err, ErrInvalidPlanTransition), errors.Is(err, ErrPlanBlocked):
		return PreparationStartRefused, "", false
	}
	code, reason, _ = createPreparationFailure(err)
	retryable = errors.Is(err, ErrResourceUnavailable) || errors.Is(err, ErrLicenseOutcomeUnknown) ||
		errors.Is(err, ErrLicenseUnavailable) || errors.Is(err, ErrArtifactUnavailable)
	return code, reason, retryable
}

// pruneArtifactCache: best effort, a new plan is when older versions stop being
// needed. Failure only leaves extra files; it never affects the plan.
func (s *Service) pruneArtifactCache(ctx context.Context) {
	if removed, err := s.rollout.config.Artifacts.PruneUnreferenced(ctx, s.store.pool); err != nil {
		slog.Warn("control upgrade artifact cache prune failed", "error", err)
	} else if removed > 0 {
		slog.Info("control upgrade artifact cache pruned", "removed", removed)
	}
}

// createPreparationFailure maps a preparation error to its stable failure code;
// retryable marks a transient conflict (a node identity changing, License 409).
func createPreparationFailure(err error) (code, reason string, retryable bool) {
	var blocked *UpgradeTargetBlockedError
	var refusal *LicenseRefusalError
	var statusRefusal *LicenseStatusRefusalError
	switch {
	case err == nil:
		return "", "", false
	case errors.As(err, &blocked):
		return PreparationFailureLicenseRejected, blocked.Reason, false
	case errors.As(err, &refusal):
		return PreparationFailureLicenseRejected, refusal.Code, false
	case errors.As(err, &statusRefusal):
		return PreparationFailureLicenseRejected, fmt.Sprintf("http_%d", statusRefusal.Status), false
	case errors.Is(err, ErrPermissionDenied):
		return PreparationFailurePermissionDenied, "", false
	case errors.Is(err, ErrNodeNotFound), errors.Is(err, ErrCohortIncompatible), errors.Is(err, ErrPlanNodeNotActive):
		return PreparationFailureCohortIncompatible, "", false
	case errors.Is(err, ErrArtifactInvalid):
		return PreparationFailureArtifactInvalid, "", false
	case errors.Is(err, ErrArtifactUnavailable):
		return PreparationFailureDownloadFailed, "", false
	case errors.Is(err, ErrGrantInvalid):
		return PreparationFailureGrantInvalid, "", false
	case errors.Is(err, ErrLicenseOutcomeUnknown):
		return PreparationFailureLicenseOutcomeUnknown, "", false
	case errors.Is(err, ErrLicenseUnavailable):
		return PreparationFailureLicenseUnavailable, "", false
	case errors.Is(err, ErrResourceUnavailable):
		return PreparationFailureResourceUnavailable, "", true
	default:
		return PreparationFailureInternal, "", false
	}
}
