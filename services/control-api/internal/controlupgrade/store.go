package controlupgrade

import (
	"bytes"
	"context"
	"crypto/sha256"
	"encoding/base64"
	"encoding/hex"
	"encoding/json"
	"errors"
	"fmt"
	"reflect"
	"regexp"
	"strings"
	"time"

	"github.com/cdnca/cdnca/libs/entitlement"
	"github.com/cdnca/cdnca/services/control-api/internal/audit"
	"github.com/cdnca/cdnca/services/control-api/internal/entitlementguard"
	"github.com/cdnca/cdnca/services/control-api/internal/platformpolicy"
	"github.com/google/uuid"
	"github.com/jackc/pgx/v5"
	"github.com/jackc/pgx/v5/pgconn"
	"github.com/jackc/pgx/v5/pgxpool"
)

const (
	checkOperation                 = "control.upgrade.check"
	rolloutOutboxRetryBaseDelay    = time.Second
	rolloutOutboxRetryMaximumDelay = time.Minute
	rolloutStatusFutureSkew        = 30 * time.Second
)

var rolloutSafeIDPattern = regexp.MustCompile(`^[A-Za-z0-9][A-Za-z0-9._-]{0,127}$`)

type Store struct {
	pool    *pgxpool.Pool
	guard   *entitlementguard.Guard
	policy  *platformpolicy.State
	auditor *audit.Log
	now     func() time.Time
}

type RolloutCausation struct {
	ID     string
	SHA256 string
}

type RolloutIdentity struct {
	ActorScopeID   string
	ActorUserID    string
	InstallationID string
}

type PlanGrantBinding struct {
	ParentGrantBytes      []byte
	ParentGrantSHA256     string
	ArtifactBundleBytes   []byte
	ArtifactBundleSHA256  string
	ForwardProfileBytes   []byte
	ForwardProfileSHA256  string
	RollbackProfileBytes  []byte
	RollbackProfileSHA256 string
}

type LockedRolloutPlan struct {
	Identity                RolloutIdentity
	Plan                    RolloutPlan
	CanonicalSnapshotBytes  []byte
	CanonicalSnapshotSHA256 string
}

type RolloutEventMutation struct {
	Causation      RolloutCausation
	CausationBytes []byte
	Event          PlanEvent
	EventBytes     []byte
	EventSHA256    string
}

type RolloutNodeCommand struct {
	ID                    string
	PlanID                string
	PlanRevision          uint64
	BatchID               string
	NodeID                string
	InstallationID        string
	Action                string
	CommandSchema         string
	ExecutionSequence     uint64
	ReleaseSequence       uint64
	Component             string
	CommandGrantBytes     []byte
	CommandGrantSHA256    string
	CommandGrantExpiresAt time.Time
	SignedExecutionBytes  []byte
	SignedExecutionSHA256 string
}

type RolloutOutboxMessage struct {
	ID            string
	PlanID        string
	PlanRevision  uint64
	Topic         string
	MessageKey    string
	PayloadBytes  []byte
	PayloadSHA256 string
	AvailableAt   time.Time
}

type RolloutAtomicMutation struct {
	ExpectedRevision        uint64
	Plan                    RolloutPlan
	CanonicalSnapshotBytes  []byte
	CanonicalSnapshotSHA256 string
	Events                  []RolloutEventMutation
	NodeCommands            []RolloutNodeCommand
	Outbox                  []RolloutOutboxMessage
}

type RolloutCommit struct {
	Plan         RolloutPlan
	Events       []PlanEvent
	NodeCommands []RolloutNodeCommand
	Outbox       []RolloutOutboxMessage
	Replayed     bool
}

type RolloutStatusReceipt struct {
	Schema           string
	StatusID         string
	StatusRevision   uint64
	CommandID        string
	PlanID           string
	PlanRevision     uint64
	BatchID          string
	InstallationID   string
	NodeID           string
	Action           string
	CommandSHA256    string
	StatusBytes      []byte
	StatusSHA256     string
	State            string
	ObservedAt       time.Time
	DeliveryStream   string
	DeliveryConsumer string
	DeliverySequence uint64
	ActiveEvidence   *ActiveProbeEvidence
	// Read-side projection of the stored status for operator logs.
	ErrorCode       string
	CurrentVersion  string
	PreviousVersion string
}

type rolloutStatusContext struct {
	Plan                 actionPlanRecord
	Command              RolloutNodeCommand
	CommandState         string
	CommandPublishedAt   *time.Time
	CommandPayloadDigest []byte
	Payload              rolloutStatusPayload
	PreviousState        string
	PreviousPayload      rolloutStatusPayload
	RollbackTriggerError string
	HasPrevious          bool
	TransactionNow       time.Time
}

type RolloutOutboxClaim struct {
	Message      RolloutOutboxMessage
	ClaimToken   string
	ClaimedBy    string
	ClaimedAt    time.Time
	ClaimExpires time.Time
	AttemptCount uint32
}

type RolloutOutboxDisposition string

const (
	RolloutOutboxPublished      RolloutOutboxDisposition = "published"
	RolloutOutboxRetryable      RolloutOutboxDisposition = "retryable_failure"
	RolloutOutboxUnknownOutcome RolloutOutboxDisposition = "unknown_outcome"
	RolloutOutboxRejected       RolloutOutboxDisposition = "rejected"
)

type RolloutOutboxSettlement struct {
	OutboxID          string
	ClaimToken        string
	PayloadSHA256     string
	Disposition       RolloutOutboxDisposition
	Stream            string
	MessageID         string
	PublishedStream   string
	PublishedSequence uint64
	ErrorCode         string
	SettledAt         time.Time
}

type RolloutPersistence interface {
	TransactLocked(context.Context, RolloutIdentity, string, RolloutCausation,
		func(LockedRolloutPlan) (RolloutAtomicMutation, error)) (RolloutCommit, error)
	ClaimOutbox(context.Context, string, time.Time, time.Duration, int) ([]RolloutOutboxClaim, error)
	SettleOutbox(context.Context, RolloutOutboxSettlement) error
	ReconcileOutbox(context.Context, string, string, time.Time) (RolloutOutboxMessage, bool, error)
	RecordStatus(context.Context, RolloutIdentity, RolloutStatusReceipt) (bool, error)
}

func NewStore(pool *pgxpool.Pool, guard *entitlementguard.Guard, policy *platformpolicy.State, now func() time.Time) *Store {
	if now == nil {
		now = time.Now
	}
	return &Store{pool: pool, guard: guard, policy: policy, auditor: audit.New(pool), now: now}
}

func validPlanGrantBinding(identity RolloutIdentity, plan RolloutPlan, binding PlanGrantBinding) bool {
	forward, forwardErr := json.Marshal(plan.ForwardProfile)
	rollback, rollbackErr := json.Marshal(plan.RollbackProfile)
	signedBundle, bundleErr := entitlement.DecodeUpgradePlanArtifactBundle(binding.ArtifactBundleBytes)
	bundle := signedBundle.Bundle
	return forwardErr == nil && rollbackErr == nil && len(binding.ParentGrantBytes) > 0 &&
		validPlanDigest(binding.ParentGrantSHA256) && rolloutDigestMatches(binding.ParentGrantBytes, binding.ParentGrantSHA256) &&
		bytes.Equal(forward, binding.ForwardProfileBytes) && validPlanDigest(binding.ForwardProfileSHA256) &&
		rolloutDigestMatches(binding.ForwardProfileBytes, binding.ForwardProfileSHA256) &&
		bytes.Equal(rollback, binding.RollbackProfileBytes) && validPlanDigest(binding.RollbackProfileSHA256) &&
		rolloutDigestMatches(binding.RollbackProfileBytes, binding.RollbackProfileSHA256) &&
		binding.ParentGrantSHA256 == plan.GrantDigest && bundleErr == nil &&
		validPlanDigest(binding.ArtifactBundleSHA256) &&
		rolloutDigestMatches(binding.ArtifactBundleBytes, binding.ArtifactBundleSHA256) &&
		binding.ArtifactBundleSHA256 == plan.ArtifactBundleSHA256 &&
		bundle.BundleID == plan.ArtifactBundleID && bundle.PlanID == plan.ID &&
		bundle.InitialPlanRevision == 1 && bundle.ParentGrantID == plan.ParentGrantID &&
		bundle.ParentGrantSHA256 == plan.GrantDigest && bundle.ParentGrantExpiresAt == plan.ParentGrantExpiresAt &&
		bundle.InstallationID == identity.InstallationID && bundle.Component == plan.Component &&
		bundle.CurrentVersion == plan.CurrentVersion && bundle.Version == plan.TargetVersion &&
		bundle.Forward.Manifest.ArtifactID == plan.ArtifactID &&
		bundle.Forward.Manifest.SHA256Digest == plan.SHA256Digest &&
		bundle.Forward.Manifest.ArtifactSizeBytes == plan.ArtifactSizeBytes &&
		bundle.Rollback.Manifest.ArtifactID == plan.RollbackArtifactID &&
		bundle.Rollback.Manifest.SHA256Digest == plan.RollbackSHA256Digest &&
		bundle.Rollback.Manifest.ArtifactSizeBytes == plan.RollbackArtifactSizeBytes &&
		bundle.CommandIssuanceNotAfter == plan.CommandIssuanceNotAfter
}

func sameStoredPlanGrantBinding(binding PlanGrantBinding, parent, parentDigest, bundle, bundleDigest, forward, forwardDigest,
	rollback, rollbackDigest []byte) bool {
	return bytes.Equal(parent, binding.ParentGrantBytes) &&
		bytes.Equal(parentDigest, mustDecodePlanDigest(binding.ParentGrantSHA256)) &&
		bytes.Equal(bundle, binding.ArtifactBundleBytes) &&
		bytes.Equal(bundleDigest, mustDecodePlanDigest(binding.ArtifactBundleSHA256)) &&
		bytes.Equal(forward, binding.ForwardProfileBytes) &&
		bytes.Equal(forwardDigest, mustDecodePlanDigest(binding.ForwardProfileSHA256)) &&
		bytes.Equal(rollback, binding.RollbackProfileBytes) &&
		bytes.Equal(rollbackDigest, mustDecodePlanDigest(binding.RollbackProfileSHA256))
}

func mustDecodePlanDigest(value string) []byte {
	decoded, _ := base64.RawURLEncoding.DecodeString(value)
	return decoded
}

func (s *Store) Check(ctx context.Context, actor Actor, request CheckRequest, digest [32]byte) (CheckResponse, error) {
	var response CheckResponse
	err := pgx.BeginFunc(ctx, s.pool, func(tx pgx.Tx) error {
		replayed, err := s.replayOrClaim(ctx, tx, actor, request.IdempotencyKey, digest)
		if err != nil {
			return err
		}
		if replayed != nil {
			if err := json.Unmarshal(replayed, &response); err != nil {
				return fmt.Errorf("decode stored control upgrade response: %w", err)
			}
			response.Replayed = true
			return nil
		}
		response, err = s.evaluate(ctx, tx, request)
		if err != nil {
			return err
		}
		result := "denied"
		if response.Eligible {
			result = "success"
		}
		payload := map[string]any{
			"component": request.Component, "current_version": request.CurrentVersion,
			"channel": request.Channel, "eligible": response.Eligible, "reason": response.Reason,
			"policy_source": response.Policy.Source, "policy_target_revision_id": response.Policy.TargetRevisionID,
			"policy_stale": response.Policy.Stale,
		}
		if response.Entitlement != nil {
			payload["lease_serial"] = response.Entitlement.Serial
			payload["entitlement_channel"] = response.Entitlement.Channel
			payload["entitlement_min_version"] = response.Entitlement.MinVersion
			payload["entitlement_max_version"] = response.Entitlement.MaxVersion
		}
		if err := s.auditor.Append(ctx, tx, audit.Event{
			ScopeID: actor.ScopeID, ActorUserID: &actor.UserID, Action: checkOperation,
			ResourceType: "control_upgrade", ResourceID: request.Component, RequestID: request.RequestID,
			Result: result, Payload: payload,
		}); err != nil {
			return err
		}
		return s.complete(ctx, tx, actor, request.IdempotencyKey, response)
	})
	if err != nil {
		return CheckResponse{}, fmt.Errorf("check control upgrade eligibility: %w", err)
	}
	return response, nil
}

func (s *Store) evaluate(ctx context.Context, tx pgx.Tx, request CheckRequest) (CheckResponse, error) {
	response := CheckResponse{
		Component: request.Component, CurrentVersion: request.CurrentVersion, Channel: request.Channel,
	}
	grant, err := s.guard.ReadValidVersion(ctx, tx)
	if grant.Serial != 0 {
		response.Entitlement = &EntitlementDecision{
			Serial: grant.Serial, Channel: grant.Channel, MinVersion: grant.MinVersion, MaxVersion: grant.MaxVersion,
		}
	}
	switch {
	case errors.Is(err, entitlementguard.ErrUnavailable):
		response.Reason = ReasonEntitlementUnavailable
	case errors.Is(err, entitlementguard.ErrInvalid):
		response.Reason = ReasonEntitlementInvalid
	case errors.Is(err, entitlementguard.ErrStateDenied):
		response.Reason = ReasonEntitlementStateDenied
	case err != nil:
		return CheckResponse{}, err
	case request.Channel != grant.Channel:
		response.Reason = ReasonEntitlementChannelMismatch
	case !grant.AllowsVersion(request.Channel, request.CurrentVersion):
		response.Reason = ReasonEntitlementVersionDenied
	default:
		decision, snapshot, stale := s.releaseDecision(request.Channel)
		response.Policy = PolicyDecision{
			Source: snapshot.Source, TargetRevisionID: snapshot.TargetRevisionID, Stale: stale,
		}
		if decision.Allowed {
			response.Eligible = true
			response.Reason = ReasonEligible
		} else {
			response.Reason = decision.Reason
		}
		return response, nil
	}
	snapshot, stale := s.policy.Snapshot()
	response.Policy = PolicyDecision{Source: snapshot.Source, TargetRevisionID: snapshot.TargetRevisionID, Stale: stale}
	return response, nil
}

func (s *Store) releaseDecision(channel string) (platformpolicy.Decision, platformpolicy.Snapshot, bool) {
	for range 3 {
		before, _ := s.policy.Snapshot()
		decision := s.policy.ReleaseChannel(channel, true)
		after, stale := s.policy.Snapshot()
		if sameSnapshot(before, after) && decision.Source == after.Source && decision.Stale == stale {
			return decision, after, stale
		}
	}
	snapshot, _ := s.policy.Snapshot()
	return platformpolicy.Decision{
		Allowed: false, Reason: platformpolicy.DecisionPolicyStale, Source: snapshot.Source, Stale: true,
	}, snapshot, true
}

func sameSnapshot(left, right platformpolicy.Snapshot) bool {
	return left.Source == right.Source && left.TargetRevisionID == right.TargetRevisionID &&
		left.ExpiresAt.Equal(right.ExpiresAt) && left.Defaulted == right.Defaulted
}

func (s *Store) replayOrClaim(ctx context.Context, tx pgx.Tx, actor Actor, key string, digest [32]byte) ([]byte, error) {
	stored, found, err := readStoredCheck(ctx, tx, actor.UserID, key, digest)
	if err != nil || found {
		return stored, err
	}
	id, err := uuid.NewV7()
	if err != nil {
		return nil, err
	}
	command, err := tx.Exec(ctx, `
		INSERT INTO control_upgrade_check_requests (
			id, actor_user_id, actor_scope_id, operation, idempotency_key, request_digest, created_at
		) VALUES ($1, $2, $3, $4, $5, $6, $7)
		ON CONFLICT (actor_user_id, operation, idempotency_key) DO NOTHING`,
		id, actor.UserID, actor.ScopeID, checkOperation, key, digest[:], s.now().UTC().Truncate(time.Microsecond))
	if err != nil {
		return nil, err
	}
	if command.RowsAffected() == 1 {
		return nil, nil
	}
	stored, found, err = readStoredCheck(ctx, tx, actor.UserID, key, digest)
	if err != nil {
		return nil, err
	}
	if !found {
		return nil, fmt.Errorf("control upgrade check claim disappeared")
	}
	return stored, nil
}

func readStoredCheck(ctx context.Context, tx pgx.Tx, actorID uuid.UUID, key string, digest [32]byte) ([]byte, bool, error) {
	var storedDigest []byte
	var response *string
	err := tx.QueryRow(ctx, `
		SELECT request_digest, response_body::text
		FROM control_upgrade_check_requests
		WHERE actor_user_id = $1 AND operation = $2 AND idempotency_key = $3
		FOR UPDATE`, actorID, checkOperation, key).Scan(&storedDigest, &response)
	if errors.Is(err, pgx.ErrNoRows) {
		return nil, false, nil
	}
	if err != nil {
		return nil, false, err
	}
	if !bytes.Equal(storedDigest, digest[:]) {
		return nil, true, ErrIdempotencyConflict
	}
	if response == nil {
		return nil, true, fmt.Errorf("control upgrade check is incomplete")
	}
	return []byte(*response), true, nil
}

func (s *Store) complete(ctx context.Context, tx pgx.Tx, actor Actor, key string, response CheckResponse) error {
	payload, err := json.Marshal(response)
	if err != nil {
		return err
	}
	command, err := tx.Exec(ctx, `
		UPDATE control_upgrade_check_requests
		SET response_status = 200, response_body = $4, completed_at = $5
		WHERE actor_user_id = $1 AND operation = $2 AND idempotency_key = $3 AND completed_at IS NULL`,
		actor.UserID, checkOperation, key, payload, s.now().UTC().Truncate(time.Microsecond))
	if err != nil {
		return err
	}
	if command.RowsAffected() != 1 {
		return fmt.Errorf("control upgrade check completion lost ownership")
	}
	return nil
}

func (s *Store) TransactLocked(
	ctx context.Context,
	identity RolloutIdentity,
	planID string,
	causation RolloutCausation,
	build func(LockedRolloutPlan) (RolloutAtomicMutation, error),
) (RolloutCommit, error) {
	if !validRolloutIdentity(identity) || !validCanonicalPlanUUID(planID) ||
		!validCanonicalPlanUUID(causation.ID) || !validPlanDigest(causation.SHA256) || build == nil {
		return RolloutCommit{}, ErrInvalidPlan
	}
	var commit RolloutCommit
	err := pgx.BeginFunc(ctx, s.pool, func(tx pgx.Tx) error {
		var err error
		commit, err = s.transactLockedTx(ctx, tx, identity, planID, causation, build)
		return err
	})
	if err != nil {
		return RolloutCommit{}, fmt.Errorf("transact control upgrade rollout: %w", err)
	}
	return commit, nil
}

func (s *Store) transactLockedTx(
	ctx context.Context,
	tx pgx.Tx,
	identity RolloutIdentity,
	planID string,
	causation RolloutCausation,
	build func(LockedRolloutPlan) (RolloutAtomicMutation, error),
) (RolloutCommit, error) {
	locked, err := readLockedRolloutPlan(ctx, tx, identity, planID)
	if err != nil {
		return RolloutCommit{}, err
	}
	replayed, found, err := readRolloutReplay(ctx, tx, locked, causation)
	if err != nil || found {
		return replayed, err
	}
	mutation, err := build(locked)
	if err != nil {
		return RolloutCommit{}, err
	}
	if mutation.ExpectedRevision != locked.Plan.Revision {
		return RolloutCommit{}, ErrStalePlanRevision
	}
	if err := validateRolloutMutation(locked, causation, mutation); err != nil {
		return RolloutCommit{}, err
	}
	var now time.Time
	if err := tx.QueryRow(ctx, `SELECT clock_timestamp()`).Scan(&now); err != nil {
		return RolloutCommit{}, err
	}
	now = now.UTC().Truncate(time.Microsecond)
	snapshotDigest, _ := decodeRolloutDigest(mutation.CanonicalSnapshotSHA256)
	for _, item := range mutation.Events {
		causeDigest, _ := decodeRolloutDigest(item.Causation.SHA256)
		eventDigest, _ := decodeRolloutDigest(item.EventSHA256)
		if _, err := tx.Exec(ctx, `
			INSERT INTO control_upgrade_rollout_events(
				plan_id,revision,event_id,actor_scope_id,actor_user_id,installation_id,
				causation_id,causation_bytes,causation_sha256,event_bytes,event_sha256,
				result_snapshot_bytes,result_snapshot_sha256,created_at)
			VALUES($1,$2,$3,$4,$5,$6,$7,$8,$9,$10,$11,$12,$13,$14)`,
			mutation.Plan.ID, item.Event.Revision, item.Event.ID,
			identity.ActorScopeID, identity.ActorUserID, identity.InstallationID,
			item.Causation.ID, item.CausationBytes, causeDigest, item.EventBytes, eventDigest,
			mutation.CanonicalSnapshotBytes, snapshotDigest, now); err != nil {
			return RolloutCommit{}, fmt.Errorf("insert control upgrade rollout event: %w", err)
		}
	}
	for _, command := range mutation.NodeCommands {
		digest, _ := decodeRolloutWireDigest(command.SignedExecutionSHA256)
		grantDigest, _ := decodeRolloutDigest(command.CommandGrantSHA256)
		if _, err := tx.Exec(ctx, `
			INSERT INTO control_upgrade_node_commands(
				command_id,plan_id,plan_revision,batch_id,actor_scope_id,actor_user_id,
				installation_id,node_id,action,signed_execution_bytes,signed_execution_sha256,
				state,created_at,command_grant_bytes,command_grant_sha256,command_grant_expires_at,
				command_schema,execution_sequence,release_sequence,component)
			VALUES($1,$2,$3,$4,$5,$6,$7,$8,$9,$10,$11,'pending',$12,$13,$14,$15,
				NULLIF($16::text,''),NULLIF($17::bigint,0),NULLIF($18::bigint,0),NULLIF($19::text,''))`,
			command.ID, command.PlanID, command.PlanRevision, command.BatchID,
			identity.ActorScopeID, identity.ActorUserID, command.InstallationID,
			command.NodeID, command.Action, command.SignedExecutionBytes, digest, now,
			command.CommandGrantBytes, grantDigest,
			command.CommandGrantExpiresAt.UTC().Truncate(time.Microsecond), command.CommandSchema,
			command.ExecutionSequence, command.ReleaseSequence, command.Component); err != nil {
			return RolloutCommit{}, fmt.Errorf("insert control upgrade node command: %w", err)
		}
	}
	for _, message := range mutation.Outbox {
		digest, _ := decodeRolloutWireDigest(message.PayloadSHA256)
		command := rolloutCommandByID(mutation.NodeCommands, message.ID)
		if _, err := tx.Exec(ctx, `
			INSERT INTO control_upgrade_outbox(
				id,command_id,plan_id,plan_revision,batch_id,actor_scope_id,actor_user_id,
				installation_id,node_id,action,topic,message_key,payload_bytes,payload_sha256,
				state,available_at,attempt_count,created_at)
			VALUES($1,$1,$2,$3,$4,$5,$6,$7,$8,$9,$10,$11,$12,$13,'pending',$14,0,$15)`,
			message.ID, message.PlanID, message.PlanRevision, command.BatchID,
			identity.ActorScopeID, identity.ActorUserID, command.InstallationID,
			command.NodeID, command.Action, message.Topic, message.MessageKey,
			message.PayloadBytes, digest, message.AvailableAt.UTC().Truncate(time.Microsecond), now); err != nil {
			return RolloutCommit{}, fmt.Errorf("insert control upgrade outbox: %w", err)
		}
	}
	result, err := tx.Exec(ctx, `
		UPDATE control_upgrade_rollout_plans
		SET revision=$6,state=$7,resume_state=$8,completion=$9,active_batch=$10,
			canonical_snapshot_bytes=$11,canonical_snapshot_sha256=$12,updated_at=$13
		WHERE id=$1 AND actor_scope_id=$2 AND actor_user_id=$3 AND installation_id=$4 AND revision=$5`,
		mutation.Plan.ID, identity.ActorScopeID, identity.ActorUserID, identity.InstallationID,
		mutation.ExpectedRevision, mutation.Plan.Revision, mutation.Plan.State,
		mutation.Plan.ResumeState, mutation.Plan.Completion, mutation.Plan.ActiveBatch,
		mutation.CanonicalSnapshotBytes, snapshotDigest, now)
	if err != nil {
		return RolloutCommit{}, fmt.Errorf("update control upgrade rollout plan: %w", err)
	}
	if result.RowsAffected() != 1 {
		return RolloutCommit{}, ErrStalePlanRevision
	}
	receiptObservedAt := now.UTC().Truncate(time.Second)
	if err := insertTerminalParentGrantReceiptTx(ctx, tx, locked.Plan, mutation.Plan,
		identity, receiptObservedAt); err != nil {
		return RolloutCommit{}, err
	}
	return RolloutCommit{Plan: cloneRolloutPlan(mutation.Plan), Events: rolloutMutationEvents(mutation.Events),
		NodeCommands: cloneRolloutCommands(mutation.NodeCommands), Outbox: cloneRolloutOutbox(mutation.Outbox)}, nil
}

func readLockedRolloutPlan(
	ctx context.Context,
	tx pgx.Tx,
	identity RolloutIdentity,
	planID string,
) (LockedRolloutPlan, error) {
	var snapshot, digest []byte
	err := tx.QueryRow(ctx, `
		SELECT canonical_snapshot_bytes,canonical_snapshot_sha256
		FROM control_upgrade_rollout_plans
		WHERE id=$1 AND actor_scope_id=$2 AND actor_user_id=$3 AND installation_id=$4
		FOR UPDATE`, planID, identity.ActorScopeID, identity.ActorUserID, identity.InstallationID).
		Scan(&snapshot, &digest)
	if errors.Is(err, pgx.ErrNoRows) {
		return LockedRolloutPlan{}, ErrInvalidPlan
	}
	if err != nil {
		return LockedRolloutPlan{}, fmt.Errorf("lock control upgrade rollout plan: %w", err)
	}
	plan, encodedDigest, err := decodeRolloutPlan(snapshot, digest)
	if err != nil || plan.ID != planID {
		return LockedRolloutPlan{}, ErrInvalidPlan
	}
	return LockedRolloutPlan{
		Identity: identity, Plan: plan, CanonicalSnapshotBytes: bytes.Clone(snapshot),
		CanonicalSnapshotSHA256: encodedDigest,
	}, nil
}

func readRolloutReplay(
	ctx context.Context,
	tx pgx.Tx,
	locked LockedRolloutPlan,
	causation RolloutCausation,
) (RolloutCommit, bool, error) {
	var revision uint64
	var storedCauseBytes, storedCauseDigest, snapshot, snapshotDigest []byte
	err := tx.QueryRow(ctx, `
		SELECT revision,causation_bytes,causation_sha256,result_snapshot_bytes,result_snapshot_sha256
		FROM control_upgrade_rollout_events WHERE plan_id=$1 AND causation_id=$2`,
		locked.Plan.ID, causation.ID).Scan(&revision, &storedCauseBytes, &storedCauseDigest, &snapshot, &snapshotDigest)
	if errors.Is(err, pgx.ErrNoRows) {
		return RolloutCommit{}, false, nil
	}
	if err != nil {
		return RolloutCommit{}, false, fmt.Errorf("read control upgrade rollout replay: %w", err)
	}
	wantDigest, _ := decodeRolloutDigest(causation.SHA256)
	if !bytes.Equal(storedCauseDigest, wantDigest) {
		return RolloutCommit{}, true, ErrPlanIdempotencyConflict
	}
	plan, _, err := decodeRolloutPlan(snapshot, snapshotDigest)
	if err != nil || plan.ID != locked.Plan.ID || plan.Revision < revision {
		return RolloutCommit{}, true, ErrInvalidPlan
	}
	causeValue, found := rolloutPlanCausationAt(plan, revision)
	if !found || rolloutCausationID(causeValue) != causation.ID ||
		!validRolloutValue(causeValue, storedCauseBytes, causation.SHA256) {
		return RolloutCommit{}, true, ErrInvalidPlanEvent
	}
	commit := RolloutCommit{Plan: plan, Replayed: true}
	rows, err := tx.Query(ctx, `
		SELECT event_bytes,event_sha256 FROM control_upgrade_rollout_events
		WHERE plan_id=$1 AND revision BETWEEN $2 AND $3 ORDER BY revision`,
		plan.ID, revision, plan.Revision)
	if err != nil {
		return RolloutCommit{}, true, err
	}
	for rows.Next() {
		var encoded, digest []byte
		if err := rows.Scan(&encoded, &digest); err != nil {
			rows.Close()
			return RolloutCommit{}, true, err
		}
		var event PlanEvent
		if !validRolloutEncodedJSON(encoded, digest, &event) {
			rows.Close()
			return RolloutCommit{}, true, ErrInvalidPlanEvent
		}
		commit.Events = append(commit.Events, event)
	}
	if err := rows.Err(); err != nil {
		rows.Close()
		return RolloutCommit{}, true, err
	}
	rows.Close()
	commands, err := readRolloutCommands(ctx, tx, plan.ID, revision, plan.Revision)
	if err != nil {
		return RolloutCommit{}, true, err
	}
	outbox, err := readRolloutOutbox(ctx, tx, plan.ID, revision, plan.Revision)
	if err != nil {
		return RolloutCommit{}, true, err
	}
	commit.NodeCommands, commit.Outbox = commands, outbox
	return commit, true, nil
}

func validateRolloutMutation(
	locked LockedRolloutPlan,
	causation RolloutCausation,
	mutation RolloutAtomicMutation,
) error {
	if mutation.Plan.ID != locked.Plan.ID || !sameRolloutStaticPlan(locked.Plan, mutation.Plan) ||
		!validRolloutPlan(mutation.Plan) ||
		mutation.Plan.Revision != locked.Plan.Revision+uint64(len(mutation.Events)) || len(mutation.Events) == 0 ||
		mutation.Events[0].Causation != causation ||
		!validRolloutSnapshot(mutation.Plan, mutation.CanonicalSnapshotBytes, mutation.CanonicalSnapshotSHA256) {
		return ErrInvalidPlan
	}
	for index, item := range mutation.Events {
		storedEvent, found := rolloutPlanEventAt(mutation.Plan, item.Event.Revision)
		causeValue, causeFound := rolloutPlanCausationAt(mutation.Plan, item.Event.Revision)
		if !found || storedEvent != item.Event || item.Event.Revision != locked.Plan.Revision+uint64(index)+1 ||
			!validCanonicalPlanUUID(item.Event.ID) || !validCanonicalPlanUUID(item.Causation.ID) ||
			!validPlanDigest(item.Causation.SHA256) || !causeFound ||
			rolloutCausationID(causeValue) != item.Causation.ID ||
			!validRolloutValue(causeValue, item.CausationBytes, item.Causation.SHA256) ||
			!validRolloutValue(item.Event, item.EventBytes, item.EventSHA256) {
			return ErrInvalidPlanEvent
		}
	}
	expectedCommands := expectedRolloutDispatches(locked.Plan, mutation.Plan)
	if len(mutation.NodeCommands) != len(mutation.Outbox) ||
		len(mutation.NodeCommands) != len(expectedCommands) {
		return ErrInvalidPlanCommand
	}
	seenCommands := make(map[string]bool, len(mutation.NodeCommands))
	for _, command := range mutation.NodeCommands {
		dispatchKey := rolloutDispatchKey{
			nodeID: command.NodeID, revision: command.PlanRevision, action: command.Action,
		}
		expected, found := expectedCommands[dispatchKey]
		if seenCommands[command.ID] || !found || command.BatchID != expected.batchID ||
			!validRolloutCommand(locked.Identity, mutation.Plan, command) {
			return ErrInvalidPlanCommand
		}
		seenCommands[command.ID] = true
		delete(expectedCommands, dispatchKey)
	}
	if len(expectedCommands) != 0 {
		return ErrInvalidPlanCommand
	}
	for _, message := range mutation.Outbox {
		command := rolloutCommandByID(mutation.NodeCommands, message.ID)
		if command.ID == "" || !validRolloutOutbox(mutation.Plan, command, message) {
			return ErrInvalidPlanCommand
		}
	}
	return nil
}

func sameRolloutStaticPlan(left, right RolloutPlan) bool {
	clearMutable := func(plan RolloutPlan) RolloutPlan {
		plan.State = ""
		plan.ResumeState = ""
		plan.Completion = ""
		plan.Revision = 0
		plan.ActiveBatch = 0
		plan.RollbackBatches = nil
		plan.NodeStates = nil
		plan.NodeDispatchRevisions = nil
		plan.CommandReceipts = nil
		plan.HealthReceipts = nil
		return plan
	}
	return reflect.DeepEqual(clearMutable(left), clearMutable(right))
}

type rolloutDispatchKey struct {
	nodeID   string
	revision uint64
	action   string
}

type rolloutDispatch struct {
	batchID string
}

func expectedRolloutDispatches(before, after RolloutPlan) map[rolloutDispatchKey]rolloutDispatch {
	expected := make(map[rolloutDispatchKey]rolloutDispatch)
	for nodeID, state := range after.NodeStates {
		if state != NodeDispatched ||
			before.NodeStates[nodeID] == NodeDispatched &&
				before.NodeDispatchRevisions[nodeID] == after.NodeDispatchRevisions[nodeID] {
			continue
		}
		action := "upgrade"
		batches := after.Batches
		if after.State == PlanRollingBack {
			action = "rollback"
			batches = after.RollbackBatches
		}
		for _, batch := range batches {
			if containsNode(batch.NodeIDs, nodeID) {
				expected[rolloutDispatchKey{
					nodeID: nodeID, revision: after.NodeDispatchRevisions[nodeID], action: action,
				}] = rolloutDispatch{batchID: batch.ID}
				break
			}
		}
	}
	return expected
}

func (s *Store) ClaimOutbox(
	ctx context.Context,
	worker string,
	now time.Time,
	lease time.Duration,
	limit int,
) ([]RolloutOutboxClaim, error) {
	worker = strings.TrimSpace(worker)
	if worker == "" || len(worker) > 128 || lease <= 0 || limit <= 0 || limit > 1000 || now.IsZero() {
		return nil, ErrInvalidPlanCommand
	}
	tx, err := s.pool.Begin(ctx)
	if err != nil {
		return nil, err
	}
	defer func() { _ = tx.Rollback(context.Background()) }()
	rows, err := tx.Query(ctx, `
		SELECT id,plan_id,plan_revision,topic,message_key,payload_bytes,payload_sha256,
			available_at,attempt_count
		FROM control_upgrade_outbox
		WHERE (state='pending' AND available_at <= $1) OR
			(state='claimed' AND claim_expires_at <= $1) OR
			(state='unknown' AND available_at <= $1 AND NOT EXISTS (
				SELECT 1 FROM control_upgrade_outbox_rejections_096 rejection
				WHERE rejection.outbox_id=control_upgrade_outbox.id))
		ORDER BY available_at,id
		FOR UPDATE SKIP LOCKED
		LIMIT $2`, now.UTC().Truncate(time.Microsecond), limit)
	if err != nil {
		return nil, fmt.Errorf("select control upgrade outbox: %w", err)
	}
	type candidate struct {
		message  RolloutOutboxMessage
		attempts uint32
	}
	candidates := make([]candidate, 0, limit)
	for rows.Next() {
		var item candidate
		var digest []byte
		if err := rows.Scan(&item.message.ID, &item.message.PlanID, &item.message.PlanRevision,
			&item.message.Topic, &item.message.MessageKey, &item.message.PayloadBytes, &digest,
			&item.message.AvailableAt, &item.attempts); err != nil {
			rows.Close()
			return nil, err
		}
		item.message.PayloadSHA256 = hex.EncodeToString(digest)
		candidates = append(candidates, item)
	}
	if err := rows.Err(); err != nil {
		rows.Close()
		return nil, err
	}
	rows.Close()
	claims := make([]RolloutOutboxClaim, 0, len(candidates))
	claimedAt := now.UTC().Truncate(time.Microsecond)
	for _, candidate := range candidates {
		token, err := uuid.NewV7()
		if err != nil {
			return nil, err
		}
		expires := claimedAt.Add(lease).Truncate(time.Microsecond)
		result, err := tx.Exec(ctx, `
			UPDATE control_upgrade_outbox
			SET state='claimed',claimed_by=$2,claim_token=$3,claimed_at=$4,claim_expires_at=$5,
				attempt_count=attempt_count+1,last_error_code=NULL
			WHERE id=$1`, candidate.message.ID, worker, token, claimedAt, expires)
		if err != nil {
			return nil, fmt.Errorf("claim control upgrade outbox: %w", err)
		}
		if result.RowsAffected() != 1 {
			return nil, ErrStalePlanRevision
		}
		claims = append(claims, RolloutOutboxClaim{
			Message: candidate.message, ClaimToken: token.String(), ClaimedBy: worker,
			ClaimedAt: claimedAt, ClaimExpires: expires, AttemptCount: candidate.attempts + 1,
		})
	}
	if err := tx.Commit(ctx); err != nil {
		return nil, fmt.Errorf("commit control upgrade outbox claims: %w", err)
	}
	return claims, nil
}

func (s *Store) SettleOutbox(ctx context.Context, settlement RolloutOutboxSettlement) error {
	if !validCanonicalPlanUUID(settlement.OutboxID) || !validCanonicalPlanUUID(settlement.ClaimToken) ||
		!validRolloutWireDigest(settlement.PayloadSHA256) ||
		(settlement.Disposition != RolloutOutboxPublished &&
			settlement.Disposition != RolloutOutboxRetryable &&
			settlement.Disposition != RolloutOutboxUnknownOutcome &&
			settlement.Disposition != RolloutOutboxRejected) ||
		settlement.Disposition == RolloutOutboxPublished &&
			(settlement.PublishedStream != upgradeCommandStream || settlement.PublishedSequence == 0) ||
		settlement.Disposition == RolloutOutboxRejected &&
			(settlement.Stream != upgradeCommandStream || settlement.MessageID == "") {
		return ErrInvalidPlanCommand
	}
	return pgx.BeginFunc(ctx, s.pool, func(tx pgx.Tx) error {
		var commandID, commandState string
		var commandPublishedAt *time.Time
		err := tx.QueryRow(ctx, `SELECT command_id,state,published_at FROM control_upgrade_node_commands
			WHERE command_id=$1 FOR UPDATE`, settlement.OutboxID).
			Scan(&commandID, &commandState, &commandPublishedAt)
		if errors.Is(err, pgx.ErrNoRows) {
			return ErrInvalidPlanCommand
		}
		if err != nil {
			return err
		}
		var state, topic string
		var token *string
		var digest, payload []byte
		var publishedStream *string
		var publishedSequence *uint64
		var publishedAt *time.Time
		var attemptCount int
		err = tx.QueryRow(ctx, `
			SELECT state,claim_token::text,payload_sha256,topic,payload_bytes,
				published_stream,published_sequence,published_at,attempt_count FROM control_upgrade_outbox
			WHERE id=$1 FOR UPDATE`, settlement.OutboxID).
			Scan(&state, &token, &digest, &topic, &payload, &publishedStream, &publishedSequence,
				&publishedAt, &attemptCount)
		if errors.Is(err, pgx.ErrNoRows) {
			return ErrInvalidPlanCommand
		}
		if err != nil {
			return err
		}
		wantDigest, _ := decodeRolloutWireDigest(settlement.PayloadSHA256)
		if !bytes.Equal(digest, wantDigest) {
			return ErrPlanIdempotencyConflict
		}
		if state == "published" && settlement.Disposition == RolloutOutboxPublished {
			if publishedStream == nil || publishedSequence == nil || *publishedStream != settlement.PublishedStream ||
				*publishedSequence != settlement.PublishedSequence || publishedAt == nil ||
				(commandState != "published" && commandState != "acknowledged") || commandPublishedAt == nil ||
				!publishedAt.Equal(*commandPublishedAt) {
				return ErrPlanIdempotencyConflict
			}
			return nil
		}
		if state == "unknown" && settlement.Disposition == RolloutOutboxRejected {
			var storedStream, storedSubject, storedMessageID, storedError string
			var storedDigest []byte
			err := tx.QueryRow(ctx, `SELECT stream,subject,message_id,payload_sha256,error_code
				FROM control_upgrade_outbox_rejections_096 WHERE outbox_id=$1`, settlement.OutboxID).
				Scan(&storedStream, &storedSubject, &storedMessageID, &storedDigest, &storedError)
			if err != nil {
				return ErrStalePlanRevision
			}
			if storedStream != settlement.Stream || storedSubject != topic ||
				storedMessageID != settlement.MessageID || storedError != settlement.ErrorCode ||
				!bytes.Equal(storedDigest, digest) {
				return ErrPlanIdempotencyConflict
			}
			return nil
		}
		if state != "claimed" || token == nil || *token != settlement.ClaimToken {
			return ErrStalePlanRevision
		}
		if commandState != "pending" || commandPublishedAt != nil {
			return ErrStalePlanRevision
		}
		var settledAt time.Time
		if err := tx.QueryRow(ctx, `SELECT transaction_timestamp()`).Scan(&settledAt); err != nil {
			return err
		}
		settledAt = settledAt.UTC().Truncate(time.Microsecond)
		switch settlement.Disposition {
		case RolloutOutboxPublished:
			outboxResult, err := tx.Exec(ctx, `
				UPDATE control_upgrade_outbox
				SET state='published',claimed_by=NULL,claim_token=NULL,claimed_at=NULL,
					claim_expires_at=NULL,published_at=$2,published_stream=$3,published_sequence=$4,
					last_error_code=NULL WHERE id=$1 AND state='claimed' AND claim_token=$5`,
				settlement.OutboxID, settledAt, settlement.PublishedStream,
				settlement.PublishedSequence, settlement.ClaimToken)
			if err != nil {
				return err
			}
			if outboxResult.RowsAffected() != 1 {
				return ErrStalePlanRevision
			}
			commandResult, err := tx.Exec(ctx, `
				UPDATE control_upgrade_node_commands
				SET state='published',published_at=$2
				WHERE command_id=$1 AND state='pending' AND published_at IS NULL`,
				settlement.OutboxID, settledAt)
			if err != nil {
				return err
			}
			if commandResult.RowsAffected() != 1 {
				return ErrStalePlanRevision
			}
		case RolloutOutboxRetryable:
			if !planReasonPattern.MatchString(settlement.ErrorCode) {
				return ErrInvalidPlanCommand
			}
			if _, err := tx.Exec(ctx, `
				UPDATE control_upgrade_outbox
				SET state='pending',available_at=$2,claimed_by=NULL,claim_token=NULL,claimed_at=NULL,
					claim_expires_at=NULL,last_error_code=$3 WHERE id=$1`,
				settlement.OutboxID, settledAt, settlement.ErrorCode); err != nil {
				return err
			}
		case RolloutOutboxUnknownOutcome:
			if !planReasonPattern.MatchString(settlement.ErrorCode) {
				return ErrInvalidPlanCommand
			}
			if _, err := tx.Exec(ctx, `
				UPDATE control_upgrade_outbox
				SET state='unknown',available_at=$2,claimed_by=NULL,claim_token=NULL,claimed_at=NULL,
					claim_expires_at=NULL,last_error_code=$3 WHERE id=$1`,
				settlement.OutboxID, settledAt.Add(rolloutOutboxRetryDelay(attemptCount)),
				settlement.ErrorCode); err != nil {
				return err
			}
		case RolloutOutboxRejected:
			if !planReasonPattern.MatchString(settlement.ErrorCode) ||
				settlement.MessageID != commandMessageID(payload) || topic == "" {
				return ErrInvalidPlanCommand
			}
			if _, err := tx.Exec(ctx, `INSERT INTO control_upgrade_outbox_rejections_096(
				command_id,outbox_id,plan_id,plan_revision,installation_id,node_id,stream,subject,
				message_id,payload_sha256,error_code,rejected_at)
				SELECT command_id,id,plan_id,plan_revision,installation_id,node_id,$2,topic,$3,
					payload_sha256,$4,$5 FROM control_upgrade_outbox WHERE id=$1`,
				settlement.OutboxID, settlement.Stream, settlement.MessageID,
				settlement.ErrorCode, settledAt); err != nil {
				return err
			}
			if _, err := tx.Exec(ctx, `UPDATE control_upgrade_outbox
				SET state='unknown',claimed_by=NULL,claim_token=NULL,claimed_at=NULL,
					claim_expires_at=NULL,last_error_code=$2 WHERE id=$1`,
				settlement.OutboxID, settlement.ErrorCode); err != nil {
				return err
			}
		}
		return nil
	})
}

func (s *Store) ReconcileOutbox(
	ctx context.Context,
	outboxID string,
	payloadSHA256 string,
	now time.Time,
) (RolloutOutboxMessage, bool, error) {
	if !validCanonicalPlanUUID(outboxID) || !validRolloutWireDigest(payloadSHA256) || now.IsZero() {
		return RolloutOutboxMessage{}, false, ErrInvalidPlanCommand
	}
	var message RolloutOutboxMessage
	var pending bool
	err := pgx.BeginFunc(ctx, s.pool, func(tx pgx.Tx) error {
		var state string
		var claimExpiresAt *time.Time
		var digest []byte
		err := tx.QueryRow(ctx, `
			SELECT id,plan_id,plan_revision,topic,message_key,payload_bytes,payload_sha256,
				available_at,state,claim_expires_at
			FROM control_upgrade_outbox WHERE id=$1 FOR UPDATE`, outboxID).
			Scan(&message.ID, &message.PlanID, &message.PlanRevision, &message.Topic,
				&message.MessageKey, &message.PayloadBytes, &digest, &message.AvailableAt, &state,
				&claimExpiresAt)
		if errors.Is(err, pgx.ErrNoRows) {
			return ErrInvalidPlanCommand
		}
		if err != nil {
			return err
		}
		wantDigest, _ := decodeRolloutWireDigest(payloadSHA256)
		if !bytes.Equal(digest, wantDigest) {
			return ErrPlanIdempotencyConflict
		}
		message.PayloadSHA256 = hex.EncodeToString(digest)
		if state == "published" || state == "claimed" &&
			(claimExpiresAt == nil || claimExpiresAt.After(now)) {
			return nil
		}
		if state == "unknown" {
			var rejected bool
			if err := tx.QueryRow(ctx, `SELECT EXISTS(SELECT 1 FROM control_upgrade_outbox_rejections_096
				WHERE outbox_id=$1)`, outboxID).Scan(&rejected); err != nil {
				return err
			}
			if rejected {
				return nil
			}
			if message.AvailableAt.After(now) {
				return nil
			}
		}
		if state != "unknown" && state != "pending" && state != "claimed" {
			return ErrInvalidPlanCommand
		}
		message.AvailableAt = now.UTC().Truncate(time.Microsecond)
		if _, err := tx.Exec(ctx, `
			UPDATE control_upgrade_outbox
			SET state='pending',available_at=$2,claimed_by=NULL,claim_token=NULL,claimed_at=NULL,
				claim_expires_at=NULL,last_error_code='reconciled_unknown_outcome'
			WHERE id=$1`, outboxID, message.AvailableAt); err != nil {
			return err
		}
		pending = true
		return nil
	})
	if err != nil {
		return RolloutOutboxMessage{}, false, fmt.Errorf("reconcile control upgrade outbox: %w", err)
	}
	return message, pending, nil
}

func rolloutOutboxRetryDelay(attemptCount int) time.Duration {
	if attemptCount <= 1 {
		return rolloutOutboxRetryBaseDelay
	}
	if attemptCount >= 7 {
		return rolloutOutboxRetryMaximumDelay
	}
	return rolloutOutboxRetryBaseDelay << (attemptCount - 1)
}

func (s *Store) ResolveStatusIdentity(ctx context.Context, commandID string) (RolloutIdentity, error) {
	if !validCanonicalPlanUUID(commandID) {
		return RolloutIdentity{}, ErrInvalidPlanCommand
	}
	var identity RolloutIdentity
	err := s.pool.QueryRow(ctx, `SELECT actor_scope_id,actor_user_id,installation_id
		FROM control_upgrade_node_commands WHERE command_id=$1`, commandID).
		Scan(&identity.ActorScopeID, &identity.ActorUserID, &identity.InstallationID)
	if errors.Is(err, pgx.ErrNoRows) {
		return RolloutIdentity{}, ErrInvalidPlanCommand
	}
	if err != nil {
		return RolloutIdentity{}, fmt.Errorf("resolve control upgrade status identity: %w", err)
	}
	if !validRolloutIdentity(identity) {
		return RolloutIdentity{}, ErrInvalidPlanCommand
	}
	return identity, nil
}

func (s *Store) RejectStatus(ctx context.Context, rejection RolloutStatusRejection) error {
	if !validCanonicalPlanUUID(rejection.ID) || rejection.Stream != upgradeStatusStream ||
		len(rejection.Subject) == 0 || len(rejection.Subject) > 512 ||
		!validRolloutWireDigest(rejection.PayloadSHA256) ||
		!validRolloutWireDigest(rejection.HeaderSHA256) || !planReasonPattern.MatchString(rejection.Reason) {
		return ErrInvalidPlanEvent
	}
	payloadDigest, _ := decodeRolloutWireDigest(rejection.PayloadSHA256)
	headerDigest, _ := decodeRolloutWireDigest(rejection.HeaderSHA256)
	return pgx.BeginFunc(ctx, s.pool, func(tx pgx.Tx) error {
		result, err := tx.Exec(ctx, `INSERT INTO control_upgrade_status_rejections_096(
			id,stream,subject,payload_sha256,header_sha256,reason,rejected_at)
			VALUES($1,$2,$3,$4,$5,$6,transaction_timestamp()) ON CONFLICT(id) DO NOTHING`,
			rejection.ID, rejection.Stream, rejection.Subject, payloadDigest, headerDigest, rejection.Reason)
		if err != nil {
			return err
		}
		if result.RowsAffected() == 1 {
			return nil
		}
		var stream, subject, reason string
		var storedPayload, storedHeader []byte
		if err := tx.QueryRow(ctx, `SELECT stream,subject,payload_sha256,header_sha256,reason
			FROM control_upgrade_status_rejections_096 WHERE id=$1 FOR SHARE`, rejection.ID).
			Scan(&stream, &subject, &storedPayload, &storedHeader, &reason); err != nil {
			return err
		}
		if stream != rejection.Stream || subject != rejection.Subject || reason != rejection.Reason ||
			!bytes.Equal(storedPayload, payloadDigest) || !bytes.Equal(storedHeader, headerDigest) {
			return ErrPlanIdempotencyConflict
		}
		return nil
	})
}

func (s *Store) RecordStatus(
	ctx context.Context,
	identity RolloutIdentity,
	receipt RolloutStatusReceipt,
) (bool, error) {
	receipt.ObservedAt = receipt.ObservedAt.UTC().Truncate(time.Microsecond)
	if !validRolloutIdentity(identity) || !validRolloutStatus(identity, receipt) {
		return false, ErrInvalidPlanEvent
	}
	if terminalRolloutStatus(receipt.State) {
		_, replayed, err := s.PrepareRolloutStatus(ctx, identity, receipt)
		if err != nil || replayed {
			return replayed, err
		}
		return false, ErrResourceUnavailable
	}
	var replayed bool
	err := pgx.BeginFunc(ctx, s.pool, func(tx pgx.Tx) error {
		status, found, err := s.readRolloutStatusContext(ctx, tx, identity, &receipt, true)
		if err != nil {
			return err
		}
		if found {
			replayed = true
			return nil
		}
		return insertRolloutStatusTx(ctx, tx, identity, receipt, status)
	})
	if err != nil {
		return false, fmt.Errorf("record control upgrade status: %w", err)
	}
	return replayed, nil
}

func (s *Store) readRolloutStatusContext(ctx context.Context, tx pgx.Tx, identity RolloutIdentity,
	receipt *RolloutStatusReceipt, lock bool) (rolloutStatusContext, bool, error) {
	var status rolloutStatusContext
	if err := json.Unmarshal(receipt.StatusBytes, &status.Payload); err != nil {
		return rolloutStatusContext{}, false, ErrInvalidPlanEvent
	}
	receipt.Schema = status.Payload.Schema
	receipt.ActiveEvidence = cloneControlActiveProbeEvidence(status.Payload.ActiveEvidence)
	if err := tx.QueryRow(ctx, `SELECT transaction_timestamp()`).Scan(&status.TransactionNow); err != nil {
		return rolloutStatusContext{}, false, err
	}
	status.TransactionNow = status.TransactionNow.UTC().Truncate(time.Microsecond)
	scopeID, err := uuid.Parse(identity.ActorScopeID)
	if err != nil {
		return rolloutStatusContext{}, false, ErrInvalidPlanEvent
	}
	status.Plan, err = readActionPlanTx(ctx, tx, scopeID, receipt.PlanID, lock)
	if err != nil {
		if errors.Is(err, ErrRolloutNotFound) {
			return rolloutStatusContext{}, false, ErrInvalidPlanEvent
		}
		return rolloutStatusContext{}, false, err
	}
	if status.Plan.Identity != identity {
		return rolloutStatusContext{}, false, ErrInvalidPlanEvent
	}
	lockClause := " FOR SHARE"
	if lock {
		lockClause = " FOR UPDATE"
	}
	err = tx.QueryRow(ctx, `SELECT command_id,plan_id,plan_revision,batch_id,node_id,installation_id,
		action,state,published_at FROM control_upgrade_node_commands
		WHERE command_id=$1 AND actor_scope_id=$2 AND actor_user_id=$3 AND installation_id=$4`+lockClause,
		receipt.CommandID, identity.ActorScopeID, identity.ActorUserID, identity.InstallationID).
		Scan(&status.Command.ID, &status.Command.PlanID, &status.Command.PlanRevision,
			&status.Command.BatchID, &status.Command.NodeID, &status.Command.InstallationID,
			&status.Command.Action, &status.CommandState, &status.CommandPublishedAt)
	if errors.Is(err, pgx.ErrNoRows) {
		return rolloutStatusContext{}, false, ErrInvalidPlanCommand
	}
	if err != nil {
		return rolloutStatusContext{}, false, err
	}
	var outboxState string
	err = tx.QueryRow(ctx, `SELECT payload_sha256,state FROM control_upgrade_outbox
		WHERE command_id=$1`+lockClause, receipt.CommandID).
		Scan(&status.CommandPayloadDigest, &outboxState)
	if errors.Is(err, pgx.ErrNoRows) {
		return rolloutStatusContext{}, false, ErrInvalidPlanCommand
	}
	if err != nil {
		return rolloutStatusContext{}, false, err
	}
	if status.CommandState == "pending" || outboxState != "published" {
		return rolloutStatusContext{}, false, ErrResourceUnavailable
	}
	if receipt.PlanID != status.Command.PlanID || receipt.PlanRevision != status.Command.PlanRevision ||
		receipt.NodeID != status.Command.NodeID || receipt.InstallationID != status.Command.InstallationID ||
		receipt.CommandSHA256 != hex.EncodeToString(status.CommandPayloadDigest) ||
		(status.CommandState != "published" && status.CommandState != "acknowledged") ||
		status.CommandPublishedAt == nil || receipt.ObservedAt.Before(*status.CommandPublishedAt) ||
		receipt.ObservedAt.After(status.TransactionNow.Add(rolloutStatusFutureSkew)) {
		return rolloutStatusContext{}, false, ErrInvalidPlanEvent
	}
	receipt.BatchID = status.Command.BatchID
	receipt.Action = status.Command.Action
	stored, found, err := readRolloutStatusByID(ctx, tx, receipt.StatusID)
	if err != nil {
		return rolloutStatusContext{}, false, err
	}
	if found {
		if !sameRolloutStatus(stored, *receipt) {
			return rolloutStatusContext{}, false, ErrPlanIdempotencyConflict
		}
		return status, true, nil
	}
	var deliveryStatusID string
	err = tx.QueryRow(ctx, `SELECT status_id FROM control_upgrade_status_receipts
		WHERE delivery_stream=$1 AND delivery_sequence=$2 FOR SHARE`,
		receipt.DeliveryStream, receipt.DeliverySequence).Scan(&deliveryStatusID)
	if err == nil && deliveryStatusID != receipt.StatusID {
		return rolloutStatusContext{}, false, ErrPlanIdempotencyConflict
	}
	if !errors.Is(err, pgx.ErrNoRows) && err != nil {
		return rolloutStatusContext{}, false, err
	}
	var previousRevision uint64
	var previousObservedAt time.Time
	var previousStatusBytes []byte
	err = tx.QueryRow(ctx, `SELECT status_revision,state,observed_at,status_bytes
		FROM control_upgrade_status_receipts WHERE command_id=$1
		ORDER BY status_revision DESC LIMIT 1`, receipt.CommandID).
		Scan(&previousRevision, &status.PreviousState, &previousObservedAt, &previousStatusBytes)
	if !errors.Is(err, pgx.ErrNoRows) && err != nil {
		return rolloutStatusContext{}, false, err
	}
	status.HasPrevious = !errors.Is(err, pgx.ErrNoRows)
	if !status.HasPrevious {
		if receipt.StatusRevision != 1 || receipt.State != "accepted" && receipt.State != "claimed" {
			return rolloutStatusContext{}, false, ErrInvalidPlanTransition
		}
	} else if receipt.StatusRevision != previousRevision+1 || receipt.ObservedAt.Before(previousObservedAt) ||
		!validRolloutStatusTransition(receipt.Action, status.PreviousState, receipt.State) {
		return rolloutStatusContext{}, false, ErrInvalidPlanTransition
	} else if status.PreviousState == "installing" || status.PreviousState == "rolling_back" ||
		status.PreviousState == "uncertain" {
		if err := json.Unmarshal(previousStatusBytes, &status.PreviousPayload); err != nil {
			return rolloutStatusContext{}, false, ErrInvalidPlanTransition
		}
	}
	if status.Command.Action == "upgrade" && status.Payload.State == "rolled_back" {
		var triggerBytes []byte
		err := tx.QueryRow(ctx, `SELECT status_bytes FROM control_upgrade_status_receipts
			WHERE command_id=$1 AND state='rolling_back' AND status_revision<$2
			ORDER BY status_revision DESC LIMIT 1`, receipt.CommandID, receipt.StatusRevision).Scan(&triggerBytes)
		if !errors.Is(err, pgx.ErrNoRows) && err != nil {
			return rolloutStatusContext{}, false, err
		}
		if err == nil {
			var trigger rolloutStatusPayload
			if json.Unmarshal(triggerBytes, &trigger) != nil || trigger.ErrorCode == "" {
				return rolloutStatusContext{}, false, ErrInvalidPlanTransition
			}
			status.RollbackTriggerError = trigger.ErrorCode
		}
	}
	if !validRolloutStatusSemantics(status.Plan.Plan, status.Command, status.Payload,
		status.PreviousState, status.PreviousPayload, status.RollbackTriggerError) {
		return rolloutStatusContext{}, false, ErrInvalidPlanEvent
	}
	return status, false, nil
}

func insertRolloutStatusTx(ctx context.Context, tx pgx.Tx, identity RolloutIdentity,
	receipt RolloutStatusReceipt, status rolloutStatusContext) error {
	digest, _ := decodeRolloutWireDigest(receipt.StatusSHA256)
	if _, err := tx.Exec(ctx, `INSERT INTO control_upgrade_status_receipts(
		command_id,status_revision,status_id,plan_id,plan_revision,batch_id,
		actor_scope_id,actor_user_id,installation_id,node_id,action,status_bytes,
		status_sha256,command_sha256,state,observed_at,created_at,
		delivery_stream,delivery_consumer,delivery_sequence)
		VALUES($1,$2,$3,$4,$5,$6,$7,$8,$9,$10,$11,$12,$13,$14,$15,$16,$17,$18,$19,$20)`,
		receipt.CommandID, receipt.StatusRevision, receipt.StatusID, receipt.PlanID,
		receipt.PlanRevision, status.Command.BatchID, identity.ActorScopeID, identity.ActorUserID,
		receipt.InstallationID, receipt.NodeID, status.Command.Action, receipt.StatusBytes,
		digest, status.CommandPayloadDigest, receipt.State, receipt.ObservedAt, status.TransactionNow,
		receipt.DeliveryStream, receipt.DeliveryConsumer, receipt.DeliverySequence); err != nil {
		var pgError *pgconn.PgError
		if errors.As(err, &pgError) && pgError.Code == "23505" &&
			pgError.ConstraintName == "control_upgrade_status_receipts_delivery_102_uk" {
			return ErrPlanIdempotencyConflict
		}
		return err
	}
	if status.CommandState != "published" {
		return nil
	}
	result, err := tx.Exec(ctx, `UPDATE control_upgrade_node_commands
		SET state='acknowledged',acknowledged_at=$2
		WHERE command_id=$1 AND state='published'`, receipt.CommandID, status.TransactionNow)
	if err != nil {
		return err
	}
	if result.RowsAffected() != 1 {
		return ErrStalePlanRevision
	}
	return nil
}

func readRolloutStatusByID(ctx context.Context, tx pgx.Tx, statusID string) (RolloutStatusReceipt, bool, error) {
	var receipt RolloutStatusReceipt
	var commandDigest, digest []byte
	err := tx.QueryRow(ctx, `
		SELECT status_id,status_revision,command_id,plan_id,plan_revision,batch_id,installation_id,
			node_id,action,command_sha256,status_bytes,status_sha256,state,observed_at,
			COALESCE(delivery_stream,''),COALESCE(delivery_consumer,''),COALESCE(delivery_sequence,0)
		FROM control_upgrade_status_receipts WHERE status_id=$1`, statusID).
		Scan(&receipt.StatusID, &receipt.StatusRevision, &receipt.CommandID, &receipt.PlanID,
			&receipt.PlanRevision, &receipt.BatchID, &receipt.InstallationID, &receipt.NodeID,
			&receipt.Action, &commandDigest, &receipt.StatusBytes, &digest, &receipt.State,
			&receipt.ObservedAt, &receipt.DeliveryStream, &receipt.DeliveryConsumer, &receipt.DeliverySequence)
	if errors.Is(err, pgx.ErrNoRows) {
		return RolloutStatusReceipt{}, false, nil
	}
	if err != nil {
		return RolloutStatusReceipt{}, false, err
	}
	receipt.StatusSHA256 = hex.EncodeToString(digest)
	receipt.CommandSHA256 = hex.EncodeToString(commandDigest)
	if !hydrateRolloutStatusReceipt(&receipt) {
		return RolloutStatusReceipt{}, false, ErrInvalidPlanEvent
	}
	return receipt, true, nil
}

func hydrateRolloutStatusReceipt(receipt *RolloutStatusReceipt) bool {
	if receipt == nil {
		return false
	}
	var payload rolloutStatusPayload
	if json.Unmarshal(receipt.StatusBytes, &payload) != nil {
		return false
	}
	receipt.Schema = payload.Schema
	receipt.ActiveEvidence = cloneControlActiveProbeEvidence(payload.ActiveEvidence)
	// Stored statuses were validated on receipt; re-check before projecting.
	if payload.ErrorCode == "" || rolloutSafeIDPattern.MatchString(payload.ErrorCode) {
		receipt.ErrorCode = payload.ErrorCode
	}
	if payload.CurrentVersion == "" || validCanonicalVersion(payload.CurrentVersion) {
		receipt.CurrentVersion = payload.CurrentVersion
	}
	if payload.PreviousVersion == "" || validCanonicalVersion(payload.PreviousVersion) {
		receipt.PreviousVersion = payload.PreviousVersion
	}
	return true
}

func readRolloutCommands(
	ctx context.Context,
	tx pgx.Tx,
	planID string,
	firstRevision, lastRevision uint64,
) ([]RolloutNodeCommand, error) {
	rows, err := tx.Query(ctx, `
		SELECT command_id,plan_id,plan_revision,batch_id,node_id,installation_id,action,
			command_grant_bytes,command_grant_sha256,command_grant_expires_at,
			signed_execution_bytes,signed_execution_sha256,
			command_schema,execution_sequence,release_sequence,component
		FROM control_upgrade_node_commands
		WHERE plan_id=$1 AND plan_revision BETWEEN $2 AND $3 ORDER BY plan_revision,command_id`,
		planID, firstRevision, lastRevision)
	if err != nil {
		return nil, err
	}
	defer rows.Close()
	var commands []RolloutNodeCommand
	for rows.Next() {
		var command RolloutNodeCommand
		var grantDigest, digest []byte
		var commandSchema, component *string
		var executionSequence, releaseSequence *int64
		if err := rows.Scan(&command.ID, &command.PlanID, &command.PlanRevision, &command.BatchID,
			&command.NodeID, &command.InstallationID, &command.Action,
			&command.CommandGrantBytes, &grantDigest, &command.CommandGrantExpiresAt,
			&command.SignedExecutionBytes, &digest, &commandSchema, &executionSequence,
			&releaseSequence, &component); err != nil {
			return nil, err
		}
		if commandSchema != nil {
			command.CommandSchema = *commandSchema
		}
		if executionSequence != nil {
			command.ExecutionSequence = uint64(*executionSequence)
		}
		if releaseSequence != nil {
			command.ReleaseSequence = uint64(*releaseSequence)
		}
		if component != nil {
			command.Component = *component
		}
		command.CommandGrantSHA256 = base64.RawURLEncoding.EncodeToString(grantDigest)
		command.SignedExecutionSHA256 = hex.EncodeToString(digest)
		commands = append(commands, command)
	}
	return commands, rows.Err()
}

func readRolloutOutbox(
	ctx context.Context,
	tx pgx.Tx,
	planID string,
	firstRevision, lastRevision uint64,
) ([]RolloutOutboxMessage, error) {
	rows, err := tx.Query(ctx, `
		SELECT id,plan_id,plan_revision,topic,message_key,payload_bytes,payload_sha256,available_at
		FROM control_upgrade_outbox
		WHERE plan_id=$1 AND plan_revision BETWEEN $2 AND $3 ORDER BY plan_revision,id`,
		planID, firstRevision, lastRevision)
	if err != nil {
		return nil, err
	}
	defer rows.Close()
	var messages []RolloutOutboxMessage
	for rows.Next() {
		var message RolloutOutboxMessage
		var digest []byte
		if err := rows.Scan(&message.ID, &message.PlanID, &message.PlanRevision, &message.Topic,
			&message.MessageKey, &message.PayloadBytes, &digest, &message.AvailableAt); err != nil {
			return nil, err
		}
		message.PayloadSHA256 = hex.EncodeToString(digest)
		messages = append(messages, message)
	}
	return messages, rows.Err()
}

func validRolloutIdentity(identity RolloutIdentity) bool {
	return validCanonicalPlanUUID(identity.ActorScopeID) && validCanonicalPlanUUID(identity.ActorUserID) &&
		validCanonicalPlanUUID(identity.InstallationID)
}

func validRolloutSnapshot(plan RolloutPlan, encoded []byte, digest string) bool {
	return validRolloutValue(plan, encoded, digest)
}

func validRolloutValue(value any, encoded []byte, digest string) bool {
	canonical, err := json.Marshal(value)
	return err == nil && bytes.Equal(canonical, encoded) && rolloutDigestMatches(encoded, digest)
}

func validRolloutEncodedJSON(encoded, digest []byte, value any) bool {
	if !bytes.Equal(rolloutSHA256(encoded), digest) || json.Unmarshal(encoded, value) != nil {
		return false
	}
	canonical, err := json.Marshal(value)
	return err == nil && bytes.Equal(canonical, encoded)
}

func decodeRolloutPlan(snapshot, digest []byte) (RolloutPlan, string, error) {
	var plan RolloutPlan
	if !validRolloutEncodedJSON(snapshot, digest, &plan) || !validRolloutPlan(plan) {
		return RolloutPlan{}, "", ErrInvalidPlan
	}
	return plan, base64.RawURLEncoding.EncodeToString(digest), nil
}

func rolloutDigestMatches(value []byte, encoded string) bool {
	digest, ok := decodeRolloutDigest(encoded)
	return ok && bytes.Equal(rolloutSHA256(value), digest)
}

func rolloutSHA256(value []byte) []byte {
	digest := sha256.Sum256(value)
	return digest[:]
}

func decodeRolloutDigest(value string) ([]byte, bool) {
	decoded, err := base64.RawURLEncoding.DecodeString(value)
	return decoded, err == nil && len(decoded) == sha256.Size &&
		base64.RawURLEncoding.EncodeToString(decoded) == value
}

func validRolloutWireDigest(value string) bool {
	_, ok := decodeRolloutWireDigest(value)
	return ok
}

func rolloutWireDigestMatches(value []byte, encoded string) bool {
	digest, ok := decodeRolloutWireDigest(encoded)
	return ok && bytes.Equal(rolloutSHA256(value), digest)
}

func decodeRolloutWireDigest(value string) ([]byte, bool) {
	decoded, err := hex.DecodeString(value)
	return decoded, err == nil && len(decoded) == sha256.Size && hex.EncodeToString(decoded) == value
}

func validRolloutCommand(identity RolloutIdentity, plan RolloutPlan, command RolloutNodeCommand) bool {
	if !validCanonicalPlanUUID(command.ID) || command.PlanID != plan.ID ||
		command.PlanRevision < 2 || command.PlanRevision > maxRolloutRevision ||
		command.PlanRevision > plan.Revision ||
		!validCanonicalPlanUUID(command.BatchID) || !validCanonicalPlanUUID(command.NodeID) ||
		command.InstallationID != identity.InstallationID ||
		(command.Action != "upgrade" && command.Action != "rollback") ||
		len(command.CommandGrantBytes) == 0 || !validPlanDigest(command.CommandGrantSHA256) ||
		!rolloutDigestMatches(command.CommandGrantBytes, command.CommandGrantSHA256) ||
		command.CommandGrantExpiresAt.IsZero() || command.CommandGrantExpiresAt.Unix() > plan.CommandIssuanceNotAfter ||
		len(command.SignedExecutionBytes) == 0 ||
		!rolloutWireDigestMatches(command.SignedExecutionBytes, command.SignedExecutionSHA256) {
		return false
	}
	signedGrant, grantErr := entitlement.DecodeUpgradeCommandGrant(command.CommandGrantBytes)
	signed, err := entitlement.DecodeUpgradeExecution(command.SignedExecutionBytes)
	expectedOperation := entitlement.UpgradeOperation
	expectedReleaseSequence := plan.ReleaseSequence
	expectedCurrentVersion := plan.CurrentVersion
	expectedTargetVersion := plan.TargetVersion
	expectedArtifactID := plan.ArtifactID
	expectedSHA256Digest := plan.SHA256Digest
	if command.Action == entitlement.RollbackOperation {
		expectedOperation = entitlement.RollbackOperation
		expectedReleaseSequence = plan.RollbackReleaseSequence
		expectedCurrentVersion = plan.TargetVersion
		expectedTargetVersion = plan.CurrentVersion
		expectedArtifactID = plan.RollbackArtifactID
		expectedSHA256Digest = plan.RollbackSHA256Digest
	}
	grant := signedGrant.Grant
	v2 := plan.SchemaVersion == RolloutPlanSchemaVersionV2 &&
		grant.Schema == entitlement.UpgradeCommandGrantV2Schema &&
		signed.Execution.Schema == entitlement.UpgradeExecutionV2Schema &&
		command.CommandSchema == "" && command.ExecutionSequence == 0 &&
		command.ReleaseSequence == 0 && command.Component == "" &&
		grant.ExecutionSequence == 0 && grant.ReleaseSequence == 0 && signed.Execution.ExecutionSequence == 0
	v3 := plan.SchemaVersion == RolloutPlanSchemaVersion &&
		grant.Schema == entitlement.UpgradeCommandGrantV3Schema &&
		signed.Execution.Schema == entitlement.UpgradeExecutionV3Schema &&
		command.CommandSchema == entitlement.UpgradeCommandGrantV3Schema &&
		command.ExecutionSequence == grant.ExecutionSequence &&
		command.ExecutionSequence == signed.Execution.ExecutionSequence && command.ExecutionSequence > 0 &&
		command.ReleaseSequence == grant.ReleaseSequence &&
		command.ReleaseSequence == signed.Execution.ReleaseSequence &&
		command.ReleaseSequence == expectedReleaseSequence && command.Component == plan.Component
	if grantErr != nil || err != nil || !v2 && !v3 ||
		grant.CommandID != command.ID || grant.InstallationID != command.InstallationID ||
		grant.NodeID != command.NodeID || grant.ParentGrantID != plan.ParentGrantID ||
		grant.ParentGrantSHA256 != plan.GrantDigest || grant.ExpiresAt != command.CommandGrantExpiresAt.Unix() ||
		grant.PlanID != plan.ID || grant.PlanRevision != command.PlanRevision || grant.BatchID != command.BatchID ||
		grant.ArtifactBundleID != plan.ArtifactBundleID || grant.ArtifactBundleSHA256 != plan.ArtifactBundleSHA256 ||
		grant.CommandIssuanceNotAfter != plan.CommandIssuanceNotAfter ||
		grant.Operation != expectedOperation || v2 && grant.ChannelRevision != expectedReleaseSequence ||
		grant.Component != plan.Component || grant.CurrentVersion != expectedCurrentVersion ||
		grant.Version != expectedTargetVersion || grant.ArtifactID != expectedArtifactID ||
		grant.SHA256Digest != expectedSHA256Digest ||
		signed.Execution.PlanID != plan.ID || signed.Execution.PlanRevision != command.PlanRevision ||
		signed.Execution.BatchID != command.BatchID ||
		signed.Execution.ArtifactBundleID != plan.ArtifactBundleID ||
		signed.Execution.ArtifactBundleSHA256 != plan.ArtifactBundleSHA256 ||
		signed.Execution.CommandIssuanceNotAfter != plan.CommandIssuanceNotAfter ||
		signed.Execution.CommandID != command.ID ||
		signed.Execution.InstallationID != command.InstallationID ||
		signed.Execution.NodeID != command.NodeID || signed.Execution.GrantDigest != command.CommandGrantSHA256 ||
		signed.Execution.ReleaseSequence != expectedReleaseSequence || signed.Execution.Component != plan.Component ||
		signed.Execution.Operation != expectedOperation || signed.Execution.Operation != command.Action ||
		signed.Execution.CurrentVersion != expectedCurrentVersion ||
		signed.Execution.TargetVersion != expectedTargetVersion || signed.Execution.ArtifactID != expectedArtifactID ||
		signed.Execution.SHA256Digest != expectedSHA256Digest || !signed.Execution.Rollback.Automatic {
		return false
	}
	batches := plan.Batches
	if command.Action == "rollback" {
		batches = plan.RollbackBatches
	}
	if plan.NodeDispatchRevisions[command.NodeID] != command.PlanRevision {
		return false
	}
	for _, batch := range batches {
		if batch.ID == command.BatchID && containsNode(batch.NodeIDs, command.NodeID) {
			return true
		}
	}
	return false
}

func rolloutPlanEventAt(plan RolloutPlan, revision uint64) (PlanEvent, bool) {
	for _, receipt := range plan.CommandReceipts {
		if receipt.Event.Revision == revision {
			return receipt.Event, true
		}
	}
	for _, receipt := range plan.HealthReceipts {
		if receipt.Event.Revision == revision {
			return receipt.Event, true
		}
	}
	return PlanEvent{}, false
}

func rolloutPlanCausationAt(plan RolloutPlan, revision uint64) (any, bool) {
	for _, receipt := range plan.CommandReceipts {
		if receipt.Event.Revision == revision {
			return receipt.Command, true
		}
	}
	for _, receipt := range plan.HealthReceipts {
		if receipt.Event.Revision == revision {
			return receipt.Health, true
		}
	}
	return nil, false
}

func rolloutCausationID(value any) string {
	switch cause := value.(type) {
	case PlanCommand:
		return cause.ID
	case PlanHealthEvent:
		return cause.ID
	default:
		return ""
	}
}

type rolloutCommandPayload struct {
	Schema                string `json:"schema"`
	CommandID             string `json:"command_id"`
	PlanID                string `json:"plan_id"`
	PlanRevision          uint64 `json:"plan_revision"`
	BatchID               string `json:"batch_id"`
	InstallationID        string `json:"installation_id"`
	NodeID                string `json:"node_id"`
	Action                string `json:"action"`
	SignedExecution       []byte `json:"signed_execution"`
	SignedExecutionSHA256 string `json:"signed_execution_sha256"`
}

func validRolloutOutbox(plan RolloutPlan, command RolloutNodeCommand, message RolloutOutboxMessage) bool {
	if message.ID != command.ID || message.PlanID != command.PlanID ||
		message.PlanRevision != command.PlanRevision ||
		message.Topic != upgradeCommandSubjectPrefix+"."+command.NodeID ||
		strings.TrimSpace(message.MessageKey) == "" || len(message.MessageKey) > 256 ||
		len(message.PayloadBytes) == 0 || !rolloutWireDigestMatches(message.PayloadBytes, message.PayloadSHA256) ||
		message.AvailableAt.IsZero() {
		return false
	}
	var payload rolloutCommandPayload
	if json.Unmarshal(message.PayloadBytes, &payload) != nil {
		return false
	}
	canonical, err := json.Marshal(payload)
	if err != nil || !bytes.Equal(canonical, message.PayloadBytes) {
		return false
	}
	return payload.Schema == "cdnca.edge.upgrade.command/v1" && payload.CommandID == command.ID &&
		payload.PlanID == plan.ID && payload.PlanRevision == command.PlanRevision &&
		payload.BatchID == command.BatchID && payload.InstallationID == command.InstallationID &&
		payload.NodeID == command.NodeID && payload.Action == command.Action &&
		bytes.Equal(payload.SignedExecution, command.SignedExecutionBytes) &&
		payload.SignedExecutionSHA256 == command.SignedExecutionSHA256
}

func rolloutCommandByID(commands []RolloutNodeCommand, id string) RolloutNodeCommand {
	for _, command := range commands {
		if command.ID == id {
			return command
		}
	}
	return RolloutNodeCommand{}
}

func rolloutMutationEvents(items []RolloutEventMutation) []PlanEvent {
	events := make([]PlanEvent, len(items))
	for index := range items {
		events[index] = items[index].Event
	}
	return events
}

func cloneRolloutCommands(commands []RolloutNodeCommand) []RolloutNodeCommand {
	cloned := append([]RolloutNodeCommand(nil), commands...)
	for index := range cloned {
		cloned[index].CommandGrantBytes = bytes.Clone(cloned[index].CommandGrantBytes)
		cloned[index].SignedExecutionBytes = bytes.Clone(cloned[index].SignedExecutionBytes)
	}
	return cloned
}

func cloneRolloutOutbox(messages []RolloutOutboxMessage) []RolloutOutboxMessage {
	cloned := append([]RolloutOutboxMessage(nil), messages...)
	for index := range cloned {
		cloned[index].PayloadBytes = bytes.Clone(cloned[index].PayloadBytes)
	}
	return cloned
}

func validRolloutStatus(identity RolloutIdentity, receipt RolloutStatusReceipt) bool {
	return validRolloutIdentity(identity) && receipt.InstallationID == identity.InstallationID &&
		validRolloutStatusPayload(receipt) && validRolloutStatusDelivery(receipt)
}

func validRolloutStatusDelivery(receipt RolloutStatusReceipt) bool {
	return receipt.DeliveryStream == upgradeStatusStream &&
		upgradeNATSNamePattern.MatchString(receipt.DeliveryConsumer) && receipt.DeliverySequence > 0
}

func validRolloutStatusPayload(receipt RolloutStatusReceipt) bool {
	if !validCanonicalPlanUUID(receipt.StatusID) || receipt.StatusRevision == 0 ||
		receipt.StatusRevision > maxRolloutRevision ||
		!validCanonicalPlanUUID(receipt.CommandID) || !validCanonicalPlanUUID(receipt.PlanID) ||
		receipt.PlanRevision == 0 || receipt.PlanRevision > maxRolloutRevision ||
		!validCanonicalPlanUUID(receipt.InstallationID) || !validCanonicalPlanUUID(receipt.NodeID) ||
		!validRolloutWireDigest(receipt.CommandSHA256) || len(receipt.StatusBytes) == 0 ||
		!rolloutWireDigestMatches(receipt.StatusBytes, receipt.StatusSHA256) ||
		receipt.ObservedAt.IsZero() {
		return false
	}
	if !validRolloutStatusState(receipt.State) {
		return false
	}
	var payload rolloutStatusPayload
	if json.Unmarshal(receipt.StatusBytes, &payload) != nil {
		return false
	}
	canonical, err := json.Marshal(payload)
	if err != nil || !bytes.Equal(canonical, receipt.StatusBytes) {
		return false
	}
	if payload.CurrentVersion != "" && !validCanonicalVersion(payload.CurrentVersion) ||
		payload.PreviousVersion != "" && !validCanonicalVersion(payload.PreviousVersion) ||
		payload.InstallerTransactionID != "" && !rolloutSafeIDPattern.MatchString(payload.InstallerTransactionID) ||
		payload.ErrorCode != "" && !rolloutSafeIDPattern.MatchString(payload.ErrorCode) {
		return false
	}
	if payload.Schema != EdgeUpgradeStatusSchemaV1 && payload.Schema != EdgeUpgradeStatusSchemaV2 ||
		receipt.Schema != "" && receipt.Schema != payload.Schema ||
		payload.StatusID != receipt.StatusID {
		return false
	}
	if payload.StatusRevision != receipt.StatusRevision || payload.CommandID != receipt.CommandID ||
		payload.PlanID != receipt.PlanID || payload.PlanRevision != receipt.PlanRevision ||
		payload.InstallationID != receipt.InstallationID || payload.NodeID != receipt.NodeID ||
		payload.CommandSHA256 != receipt.CommandSHA256 || payload.State != receipt.State ||
		!payload.ObservedAt.Equal(receipt.ObservedAt) {
		return false
	}
	if payload.Schema == EdgeUpgradeStatusSchemaV1 {
		return payload.ActiveEvidence == nil
	}
	if payload.State == "healthy" || payload.State == "rolled_back" {
		return validActiveProbeEvidence(payload.InstallerTransactionID, payload.ActiveEvidence) &&
			!payload.ActiveEvidence.ProbeObservedAt.After(payload.ObservedAt)
	}
	return payload.ActiveEvidence == nil
}

type rolloutStatusPayload struct {
	Schema                 string               `json:"schema"`
	StatusID               string               `json:"status_id"`
	StatusRevision         uint64               `json:"status_revision"`
	CommandID              string               `json:"command_id"`
	PlanID                 string               `json:"plan_id"`
	PlanRevision           uint64               `json:"plan_revision"`
	InstallationID         string               `json:"installation_id"`
	NodeID                 string               `json:"node_id"`
	CommandSHA256          string               `json:"command_sha256"`
	State                  string               `json:"state"`
	CurrentVersion         string               `json:"current_version"`
	PreviousVersion        string               `json:"previous_version"`
	InstallerTransactionID string               `json:"installer_transaction_id"`
	ErrorCode              string               `json:"error_code"`
	AlertRequired          bool                 `json:"alert_required"`
	ObservedAt             time.Time            `json:"observed_at"`
	ActiveEvidence         *ActiveProbeEvidence `json:"active_evidence,omitempty"`
}

type rolloutStatusWireV1 struct {
	Schema                 string    `json:"schema"`
	StatusID               string    `json:"status_id"`
	StatusRevision         uint64    `json:"status_revision"`
	CommandID              string    `json:"command_id"`
	PlanID                 string    `json:"plan_id"`
	PlanRevision           uint64    `json:"plan_revision"`
	InstallationID         string    `json:"installation_id"`
	NodeID                 string    `json:"node_id"`
	CommandSHA256          string    `json:"command_sha256"`
	State                  string    `json:"state"`
	CurrentVersion         string    `json:"current_version"`
	PreviousVersion        string    `json:"previous_version"`
	InstallerTransactionID string    `json:"installer_transaction_id"`
	ErrorCode              string    `json:"error_code"`
	AlertRequired          bool      `json:"alert_required"`
	ObservedAt             time.Time `json:"observed_at"`
}

type rolloutStatusWireV2 struct {
	rolloutStatusWireV1
	ActiveEvidence *ActiveProbeEvidence `json:"active_evidence"`
}

func (payload rolloutStatusPayload) MarshalJSON() ([]byte, error) {
	wire := rolloutStatusWireV1{Schema: payload.Schema, StatusID: payload.StatusID,
		StatusRevision: payload.StatusRevision, CommandID: payload.CommandID, PlanID: payload.PlanID,
		PlanRevision: payload.PlanRevision, InstallationID: payload.InstallationID, NodeID: payload.NodeID,
		CommandSHA256: payload.CommandSHA256, State: payload.State, CurrentVersion: payload.CurrentVersion,
		PreviousVersion: payload.PreviousVersion, InstallerTransactionID: payload.InstallerTransactionID,
		ErrorCode: payload.ErrorCode, AlertRequired: payload.AlertRequired, ObservedAt: payload.ObservedAt}
	if payload.Schema == EdgeUpgradeStatusSchemaV2 {
		return json.Marshal(rolloutStatusWireV2{rolloutStatusWireV1: wire,
			ActiveEvidence: payload.ActiveEvidence})
	}
	return json.Marshal(wire)
}

func validRolloutStatusTransition(action, from, to string) bool {
	switch from {
	case "accepted":
		return to == "claimed"
	case "claimed":
		return to == "installing"
	case "installing":
		if action == "upgrade" {
			return to == "healthy" || to == "failed" || to == "rolling_back" || to == "uncertain"
		}
		return action == "rollback" && (to == "failed" || to == "rolled_back" || to == "uncertain")
	case "rolling_back":
		return action == "upgrade" && (to == "rolled_back" || to == "uncertain")
	case "uncertain":
		if action == "upgrade" {
			return to == "uncertain" || to == "healthy" || to == "failed" || to == "rolled_back"
		}
		return action == "rollback" && (to == "uncertain" || to == "failed" || to == "rolled_back")
	default:
		return false
	}
}

func terminalRolloutStatus(state string) bool {
	return state == "healthy" || state == "failed" || state == "rolled_back" || state == "uncertain"
}

func validRolloutStatusSemantics(plan RolloutPlan, command RolloutNodeCommand,
	payload rolloutStatusPayload, previousState string, previousPayload rolloutStatusPayload,
	rollbackTriggerError string) bool {
	if previousState == "installing" || previousState == "rolling_back" || previousState == "uncertain" {
		if previousPayload.InstallerTransactionID == "" ||
			payload.InstallerTransactionID != previousPayload.InstallerTransactionID {
			return false
		}
	}
	noFailure := payload.ErrorCode == "" && !payload.AlertRequired
	switch payload.State {
	case "accepted", "claimed":
		return payload.CurrentVersion == "" && payload.PreviousVersion == "" &&
			payload.InstallerTransactionID == "" && noFailure
	case "installing":
		return (command.Action == "upgrade" || command.Action == "rollback") &&
			payload.CurrentVersion == "" && payload.PreviousVersion == "" &&
			payload.InstallerTransactionID != "" && noFailure
	case "rolling_back":
		return command.Action == "upgrade" && previousState == "installing" &&
			payload.CurrentVersion == plan.CurrentVersion && payload.PreviousVersion == plan.TargetVersion &&
			payload.InstallerTransactionID != "" && payload.ErrorCode != "" && !payload.AlertRequired
	case "healthy":
		return command.Action == "upgrade" && payload.CurrentVersion == plan.TargetVersion &&
			payload.PreviousVersion == plan.CurrentVersion && payload.InstallerTransactionID != "" && noFailure
	case "rolled_back":
		if command.Action == "rollback" {
			return (previousState == "installing" || previousState == "uncertain") &&
				payload.CurrentVersion == plan.TargetVersion && payload.PreviousVersion == plan.CurrentVersion &&
				payload.InstallerTransactionID != "" && noFailure
		}
		return command.Action == "upgrade" && (previousState == "rolling_back" || previousState == "uncertain") &&
			payload.CurrentVersion == plan.CurrentVersion && payload.PreviousVersion == plan.TargetVersion &&
			payload.InstallerTransactionID != "" && payload.ErrorCode != "" && !payload.AlertRequired &&
			(rollbackTriggerError == "" || payload.ErrorCode == rollbackTriggerError)
	case "failed":
		validVersions := payload.CurrentVersion == plan.CurrentVersion &&
			(command.Action == "upgrade" && payload.PreviousVersion == "" ||
				command.Action == "rollback" &&
					(payload.PreviousVersion == "" || payload.PreviousVersion == plan.TargetVersion))
		return validVersions && payload.InstallerTransactionID != "" &&
			payload.ErrorCode != "" && payload.ErrorCode != "ROLLBACK_FAILED" && payload.AlertRequired &&
			(command.Action == "upgrade" || command.Action == "rollback")
	case "uncertain":
		if payload.InstallerTransactionID == "" || payload.ErrorCode == "" || !payload.AlertRequired {
			return false
		}
		unproven := payload.CurrentVersion == "" && payload.PreviousVersion == ""
		candidateActive := payload.CurrentVersion == plan.TargetVersion && payload.PreviousVersion == plan.CurrentVersion
		return (command.Action == "upgrade" || command.Action == "rollback") && (unproven || candidateActive)
	default:
		return false
	}
}

func validRolloutStatusState(state string) bool {
	return state == "accepted" || state == "claimed" || state == "installing" || state == "healthy" ||
		state == "failed" || state == "rolling_back" || state == "rolled_back" || state == "uncertain"
}

func sameRolloutStatus(left, right RolloutStatusReceipt) bool {
	return left.Schema == right.Schema && left.StatusID == right.StatusID && left.StatusRevision == right.StatusRevision &&
		left.CommandID == right.CommandID && left.PlanID == right.PlanID &&
		left.PlanRevision == right.PlanRevision && left.BatchID == right.BatchID &&
		left.InstallationID == right.InstallationID && left.NodeID == right.NodeID &&
		left.Action == right.Action && left.CommandSHA256 == right.CommandSHA256 &&
		bytes.Equal(left.StatusBytes, right.StatusBytes) &&
		left.StatusSHA256 == right.StatusSHA256 && left.State == right.State &&
		left.ObservedAt.Equal(right.ObservedAt) && left.DeliveryStream == right.DeliveryStream &&
		left.DeliveryConsumer == right.DeliveryConsumer && left.DeliverySequence == right.DeliverySequence &&
		(left.ActiveEvidence == nil && right.ActiveEvidence == nil ||
			left.ActiveEvidence != nil && right.ActiveEvidence != nil && *left.ActiveEvidence == *right.ActiveEvidence)
}
