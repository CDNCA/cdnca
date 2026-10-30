package edgedeployment

import (
	"context"
	"crypto/sha256"
	"errors"
	"fmt"
	"time"

	agentv1 "github.com/cdnca/cdnca/proto/gen/go/agent/v1"
	"github.com/cdnca/cdnca/services/control-api/internal/audit"
	"github.com/google/uuid"
	"github.com/jackc/pgx/v5"
)

// systemSecretSessionID stands in for the session of a system rollout in the
// request digest; no session is authorized or recorded.
var systemSecretSessionID = uuid.MustParse("00000000-0000-7000-8000-00000000c0de")

// SystemSecretRolloutRequest is a secret rollout the control plane starts by
// itself (a JS challenge policy redelivered to a
// node that joined or recovered). AccountableUserID is the user whose
// publication is redelivered; the rollout is audited as the system.
type SystemSecretRolloutRequest struct {
	ConfigurationScopeID uuid.UUID
	AccountableUserID    uuid.UUID
	NodeIDs              []uuid.UUID
	CanonicalSnapshot    []byte
	GeneratorName        string
	GeneratorVersion     string
	PayloadDigest        [sha256.Size]byte
	RequiredCapabilities []*agentv1.Capability
	HealthCheck          HealthCheckPolicy
	Deadline             time.Time
	IdempotencyKey       string
	RequestID            string
	CorrelationID        string
	// Reason names the system writer in the audit payload.
	Reason string
}

// CreateSystemSecretRolloutTx persists a system secret rollout in the
// caller's transaction. Its caller decides what may be redelivered from
// durable publication facts; no session is authorized. The node boundary is
// the same as for any secret rollout: only active nodes that carry the scope
// and hold an active artifact recipient key.
func (s *Store) CreateSystemSecretRolloutTx(
	ctx context.Context,
	tx pgx.Tx,
	request SystemSecretRolloutRequest,
	builder SecretArtifactBuilder,
) (CreateRolloutResult, error) {
	if s == nil || !configuredPool(s.pool) || s.now == nil || s.auditor == nil || nilInterface(s.auditor) {
		return CreateRolloutResult{}, ErrUnavailable
	}
	if ctx == nil || tx == nil || builder == nil || request.AccountableUserID == uuid.Nil ||
		request.ConfigurationScopeID == uuid.Nil || !validLabel(request.Reason) {
		return CreateRolloutResult{}, ErrInvalidInput
	}
	var scopeKind string
	err := tx.QueryRow(ctx, `SELECT kind FROM access_scopes WHERE id=$1`, request.ConfigurationScopeID).Scan(&scopeKind)
	if errors.Is(err, pgx.ErrNoRows) {
		return CreateRolloutResult{}, ErrInvalidInput
	}
	if err != nil {
		return CreateRolloutResult{}, fmt.Errorf("read system secret rollout scope: %w", err)
	}
	now := s.now().UTC().Truncate(time.Microsecond)
	normalized, err := normalizeSecretRolloutRequest(SecretRolloutRequest{
		Actor: Actor{UserID: request.AccountableUserID, ScopeID: request.ConfigurationScopeID, ScopeKind: scopeKind,
			SessionID: systemSecretSessionID},
		ConfigurationScopeID: request.ConfigurationScopeID, NodeIDs: request.NodeIDs,
		CanonicalSnapshot: request.CanonicalSnapshot, GeneratorName: request.GeneratorName,
		GeneratorVersion: request.GeneratorVersion, PayloadDigest: request.PayloadDigest,
		RequiredCapabilities: request.RequiredCapabilities, HealthCheck: request.HealthCheck,
		Deadline: request.Deadline, IdempotencyKey: request.IdempotencyKey, RequestID: request.RequestID,
		CorrelationID: request.CorrelationID,
	}, now)
	if err != nil {
		return CreateRolloutResult{}, err
	}
	defer clearBytes(normalized.CanonicalSnapshot)
	if err := lockSecretRolloutIdempotency(ctx, tx, normalized.ConfigurationScopeID, normalized.IdempotencyKey); err != nil {
		return CreateRolloutResult{}, err
	}
	if replay, found, err := loadSecretRolloutReplay(ctx, tx, normalized); err != nil {
		return CreateRolloutResult{}, err
	} else if found {
		return CreateRolloutResult{Rollout: replay, Replayed: true}, nil
	}
	return s.persistSecretRolloutAs(ctx, tx, normalized, secretRolloutAuditActor{scopeID: normalized.ConfigurationScopeID,
		system: request.Reason}, builder, now)
}

// CancelSystemSecretRolloutTx withdraws a system secret rollout in the
// caller's transaction (fix-dnscert4: a user's binding change supersedes an
// in-flight certificate renewal delivery). Node commands not yet sent are
// cancelled; ones a node already took run to their end (the node refuses or
// later replaces them by binding revision). A rollout already cancelled is
// left as it is. Audited as the system (reason names the writer).
func (s *Store) CancelSystemSecretRolloutTx(ctx context.Context, tx pgx.Tx, scopeID, rolloutID uuid.UUID,
	requestID, reason string) error {
	if s == nil || s.now == nil || s.auditor == nil || nilInterface(s.auditor) {
		return ErrUnavailable
	}
	if ctx == nil || tx == nil || scopeID == uuid.Nil || rolloutID == uuid.Nil || !validLabel(reason) ||
		requestID == "" || len(requestID) > 128 {
		return ErrInvalidInput
	}
	now := s.now().UTC().Truncate(time.Microsecond)
	var status string
	var contractVersion int16
	err := tx.QueryRow(ctx, `SELECT status,contract_version FROM rollouts
		WHERE configuration_scope_id=$1 AND id=$2 FOR UPDATE`, scopeID, rolloutID).Scan(&status, &contractVersion)
	if errors.Is(err, pgx.ErrNoRows) {
		return ErrNotFound
	}
	if err != nil {
		return fmt.Errorf("lock system secret rollout: %w", err)
	}
	if status == "cancelled" {
		return nil
	}
	if contractVersion != 0 || status != "queued" {
		return ErrInvalidTransition // only secret rollouts (contract 0) are created by the system
	}
	if _, err := tx.Exec(ctx, `UPDATE edge_command_outbox outbox SET status='cancelled',updated_at=$2
		FROM node_deployments deployment WHERE deployment.rollout_id=$1 AND deployment.state='queued'
		  AND outbox.deployment_id=deployment.id AND outbox.deployment_attempt=deployment.attempt
		  AND outbox.status IN ('pending','failed')`, rolloutID, now); err != nil {
		return fmt.Errorf("cancel system secret rollout outbox: %w", err)
	}
	cancelled, err := tx.Exec(ctx, `UPDATE node_deployments deployment SET state='cancelled',updated_at=$2
		WHERE deployment.rollout_id=$1 AND deployment.state='queued' AND NOT EXISTS (
		  SELECT 1 FROM edge_command_outbox outbox WHERE outbox.deployment_id=deployment.id
		    AND outbox.deployment_attempt=deployment.attempt AND outbox.status<>'cancelled')`, rolloutID, now)
	if err != nil {
		return fmt.Errorf("cancel system secret rollout deployments: %w", err)
	}
	if _, err := tx.Exec(ctx, `UPDATE rollouts SET status='cancelled',revision=revision+1,updated_at=$3
		WHERE configuration_scope_id=$1 AND id=$2 AND status='queued'`, scopeID, rolloutID, now); err != nil {
		return fmt.Errorf("cancel system secret rollout: %w", err)
	}
	if err := projectSiteIPv6RolloutTerminalTx(ctx, tx, rolloutID, true, now); err != nil {
		return err
	}
	return s.auditor.Append(ctx, tx, audit.Event{
		ScopeID: scopeID, ActorKind: "system", ActorRef: "job:" + reason, Action: rolloutOperationCancel,
		ResourceType: "edge_rollout", ResourceID: rolloutID.String(), RequestID: requestID, Result: "success",
		Payload: map[string]any{
			"configuration_scope_id": scopeID.String(), "reason": reason, "actor_kind": "system",
			"cancelled_deployments": cancelled.RowsAffected(), "state": RolloutStateCancelled,
			"changes": map[string]any{"status": map[string]any{"before": status, "after": "cancelled"}},
		},
	})
}

// SystemSecretRolloutReceiptTx reads a system secret rollout's node receipts
// (pending until every node reported, then succeeded or failed). Its caller
// created the rollout; no session is authorized.
func (s *Store) SystemSecretRolloutReceiptTx(ctx context.Context, tx pgx.Tx, scopeID, rolloutID uuid.UUID,
) (CertificatePublicationReceipt, error) {
	if s == nil || s.now == nil {
		return CertificatePublicationReceipt{}, ErrUnavailable
	}
	if ctx == nil || tx == nil || scopeID == uuid.Nil || rolloutID == uuid.Nil {
		return CertificatePublicationReceipt{}, ErrInvalidInput
	}
	snapshot, err := loadRolloutSnapshot(ctx, tx, scopeID, rolloutID, s.now().UTC().Truncate(time.Microsecond))
	if err != nil {
		return CertificatePublicationReceipt{}, err
	}
	return certificatePublicationReceiptFromSnapshot(snapshot)
}
