package certificateasset

import (
	"context"
	cryptorand "crypto/rand"
	"errors"
	"fmt"
	"math/big"
	"strings"
	"time"
	"unicode"

	"github.com/cdnca/cdnca/services/control-api/internal/audit"
	"github.com/google/uuid"
	"github.com/jackc/pgx/v5"
	"github.com/jackc/pgx/v5/pgxpool"
)

// AuditPublicationComplete is a publication intent's terminal outcome: the
// certificate reached the site's nodes (success) or never will (failure).
// The worker settles it: system actor, the requester in the payload.
const AuditPublicationComplete = "certificate.publication.complete"

var ErrPublicationIntentLeaseLost = errors.New("certificate publication intent lease lost")

type PublicationIntentStoreConfig struct {
	LeaseDuration time.Duration
	RetryBase     time.Duration
	RetryMaximum  time.Duration
	MaxAttempts   int
	Jitter        func(time.Duration) time.Duration
}

func DefaultPublicationIntentStoreConfig() PublicationIntentStoreConfig {
	return PublicationIntentStoreConfig{
		LeaseDuration: time.Minute, RetryBase: time.Second,
		RetryMaximum: 5 * time.Minute, MaxAttempts: 10,
		Jitter: securePublicationIntentJitter,
	}
}

type PublicationIntentStore struct {
	pool   *pgxpool.Pool
	config PublicationIntentStoreConfig
}

type PublicationIntentLease struct {
	TenantScopeID        uuid.UUID
	SiteID               uuid.UUID
	BindingRevision      int64
	Operation            string
	AssetID              uuid.UUID
	VersionID            uuid.UUID
	Default              bool
	RequestID            string
	ActorScopeID         uuid.UUID
	ActorUserID          uuid.UUID
	ActorSessionID       uuid.UUID
	ActorScopeKind       string
	ActorUserRevision    int64
	TargetTenantID       uuid.UUID
	TargetTenantRevision int64
	Deadline             time.Time
	IdempotencyKey       string
	StateSequence        int64
	Attempt              int
	WorkerID             string
	Token                uuid.UUID
	ExpiresAt            time.Time
	CreatedAt            time.Time
}

func NewPublicationIntentStore(
	pool *pgxpool.Pool,
	config PublicationIntentStoreConfig,
) (*PublicationIntentStore, error) {
	if pool == nil || config.LeaseDuration <= 0 || config.LeaseDuration > time.Hour ||
		config.RetryBase <= 0 || config.RetryMaximum < config.RetryBase ||
		config.RetryMaximum > time.Hour || config.MaxAttempts < 1 || config.MaxAttempts > 1000 ||
		config.Jitter == nil {
		return nil, ErrInvalidInput
	}
	return &PublicationIntentStore{pool: pool, config: config}, nil
}

func (store *PublicationIntentStore) ClaimPublicationIntent(
	ctx context.Context,
	workerID string,
) (PublicationIntentLease, bool, error) {
	if store == nil || store.pool == nil || ctx == nil || !validPublicationWorkerID(workerID) {
		return PublicationIntentLease{}, false, ErrInvalidInput
	}
	token, err := uuid.NewV7()
	if err != nil {
		return PublicationIntentLease{}, false, fmt.Errorf("generate certificate publication lease: %w", err)
	}
	var lease PublicationIntentLease
	err = pgx.BeginFunc(ctx, store.pool, func(tx pgx.Tx) error {
		var databaseNow time.Time
		err := tx.QueryRow(ctx, `SELECT intent.tenant_scope_id,intent.site_id,
			intent.binding_revision,intent.operation,intent.asset_id,intent.version_id,
			intent.is_default,intent.request_id,intent.actor_scope_id,intent.actor_user_id,
			intent.actor_session_id,intent.actor_scope_kind,intent.actor_user_revision,
			intent.target_tenant_id,intent.target_tenant_revision,intent.deadline_at,
			intent.created_at,latest.sequence,latest.attempt,transaction_timestamp()
		FROM certificate_publication_intents intent
		JOIN LATERAL (
			SELECT sequence,state,attempt,next_attempt_at,lease_expires_at
			FROM certificate_publication_intent_state_facts state
			WHERE state.tenant_scope_id=intent.tenant_scope_id AND state.site_id=intent.site_id
			  AND state.binding_revision=intent.binding_revision
			ORDER BY sequence DESC LIMIT 1
		) latest ON true
		WHERE ((latest.state IN ('pending','retry_wait') AND latest.attempt<$1
		         AND latest.next_attempt_at<=transaction_timestamp())
		    OR (latest.state='leased' AND latest.lease_expires_at<=transaction_timestamp()))
		  AND NOT EXISTS (
			SELECT 1 FROM certificate_publication_intents previous_intent
			JOIN LATERAL (
				SELECT state FROM certificate_publication_intent_state_facts previous_state
				WHERE previous_state.tenant_scope_id=previous_intent.tenant_scope_id
				  AND previous_state.site_id=previous_intent.site_id
				  AND previous_state.binding_revision=previous_intent.binding_revision
				ORDER BY sequence DESC LIMIT 1
			) previous_latest ON true
			WHERE previous_intent.tenant_scope_id=intent.tenant_scope_id
			  AND previous_intent.site_id=intent.site_id
			  AND previous_intent.binding_revision<intent.binding_revision
				AND previous_latest.state NOT IN ('succeeded','permanent_failed')
		  )
		ORDER BY intent.tenant_scope_id,intent.site_id,intent.binding_revision
		FOR UPDATE OF intent SKIP LOCKED LIMIT 1`, store.config.MaxAttempts).Scan(
			&lease.TenantScopeID, &lease.SiteID, &lease.BindingRevision, &lease.Operation,
			&lease.AssetID, &lease.VersionID, &lease.Default, &lease.RequestID,
			&lease.ActorScopeID, &lease.ActorUserID, &lease.ActorSessionID, &lease.ActorScopeKind,
			&lease.ActorUserRevision, &lease.TargetTenantID, &lease.TargetTenantRevision, &lease.Deadline, &lease.CreatedAt,
			&lease.StateSequence, &lease.Attempt, &databaseNow,
		)
		if errors.Is(err, pgx.ErrNoRows) {
			return nil
		}
		if err != nil {
			return err
		}
		lease.StateSequence++
		lease.Attempt++
		lease.WorkerID = workerID
		lease.Token = token
		lease.ExpiresAt = databaseNow.Add(store.config.LeaseDuration)
		lease.IdempotencyKey = publicationIntentIdempotencyKey(
			lease.TenantScopeID, lease.SiteID, lease.BindingRevision,
		)
		if !validPublicationIntentLease(lease) {
			return ErrInvalidStore
		}
		_, err = tx.Exec(ctx, `INSERT INTO certificate_publication_intent_state_facts(
			tenant_scope_id,site_id,binding_revision,sequence,state,attempt,idempotency_key,
			lease_owner,lease_token,lease_expires_at,occurred_at
		) VALUES($1,$2,$3,$4,'leased',$5,$6,$7,$8,$9,$10)`,
			lease.TenantScopeID, lease.SiteID, lease.BindingRevision, lease.StateSequence,
			lease.Attempt, lease.IdempotencyKey, lease.WorkerID, lease.Token,
			lease.ExpiresAt, databaseNow,
		)
		return err
	})
	if err != nil {
		return PublicationIntentLease{}, false, fmt.Errorf("claim certificate publication intent: %w", err)
	}
	if lease.Token == uuid.Nil {
		return PublicationIntentLease{}, false, nil
	}
	return lease, true, nil
}

func (store *PublicationIntentStore) CompletePublicationIntent(
	ctx context.Context,
	lease PublicationIntentLease,
	result PublicationResult,
) error {
	if !validPublicationResult(result) || result.Outcome != PublicationAck {
		return ErrInvalidInput
	}
	return store.settlePublicationIntent(ctx, lease, "succeeded", "", 0, result)
}

func (store *PublicationIntentStore) FailPublicationIntent(
	ctx context.Context,
	lease PublicationIntentLease,
	failureCode string,
) error {
	if store == nil || !validPublicationFailureCode(failureCode) {
		return ErrInvalidInput
	}
	state := "retry_wait"
	delay, err := publicationIntentRetryDelay(store.config, lease.Attempt, store.config.Jitter)
	if err != nil {
		return err
	}
	if lease.Attempt >= store.config.MaxAttempts {
		state = "permanent_failed"
		delay = 0
	}
	return store.settlePublicationIntent(ctx, lease, state, failureCode, delay, PublicationResult{})
}

func (store *PublicationIntentStore) PermanentlyFailPublicationIntent(
	ctx context.Context,
	lease PublicationIntentLease,
	failureCode string,
) error {
	if store == nil || !validPublicationFailureCode(failureCode) {
		return ErrInvalidInput
	}
	return store.settlePublicationIntent(ctx, lease, "permanent_failed", failureCode, 0, PublicationResult{})
}

func (store *PublicationIntentStore) settlePublicationIntent(
	ctx context.Context,
	lease PublicationIntentLease,
	state, failureCode string,
	retryDelay time.Duration,
	result PublicationResult,
) error {
	if store == nil || store.pool == nil || ctx == nil || !validPublicationIntentLease(lease) ||
		(state != "succeeded" && state != "retry_wait" && state != "permanent_failed") ||
		(state == "succeeded") != (result.Outcome == PublicationAck) {
		return ErrInvalidInput
	}
	return pgx.BeginFunc(ctx, store.pool, func(tx pgx.Tx) error {
		var stored PublicationIntentLease
		var storedState string
		var databaseNow time.Time
		err := tx.QueryRow(ctx, `SELECT intent.tenant_scope_id,intent.site_id,
			intent.binding_revision,intent.operation,intent.asset_id,intent.version_id,
			intent.is_default,intent.request_id,intent.actor_scope_id,intent.actor_user_id,
			intent.actor_session_id,intent.actor_scope_kind,intent.actor_user_revision,
			intent.target_tenant_id,intent.target_tenant_revision,intent.deadline_at,
			intent.created_at,latest.sequence,latest.attempt,latest.idempotency_key,
			latest.lease_owner,latest.lease_token,latest.lease_expires_at,latest.state,
			transaction_timestamp()
		FROM certificate_publication_intents intent
		JOIN LATERAL (
			SELECT sequence,state,attempt,idempotency_key,lease_owner,lease_token,lease_expires_at
			FROM certificate_publication_intent_state_facts state
			WHERE state.tenant_scope_id=intent.tenant_scope_id AND state.site_id=intent.site_id
			  AND state.binding_revision=intent.binding_revision
			ORDER BY sequence DESC LIMIT 1
		) latest ON true
		WHERE intent.tenant_scope_id=$1 AND latest.lease_token=$2 AND latest.attempt=$3
		  AND intent.site_id=$4 AND intent.binding_revision=$5 AND latest.state='leased'
		  AND latest.lease_expires_at>transaction_timestamp()
		FOR UPDATE OF intent`, lease.TenantScopeID, lease.Token, lease.Attempt,
			lease.SiteID, lease.BindingRevision).Scan(
			&stored.TenantScopeID, &stored.SiteID, &stored.BindingRevision, &stored.Operation,
			&stored.AssetID, &stored.VersionID, &stored.Default, &stored.RequestID,
			&stored.ActorScopeID, &stored.ActorUserID, &stored.ActorSessionID, &stored.ActorScopeKind,
			&stored.ActorUserRevision, &stored.TargetTenantID, &stored.TargetTenantRevision, &stored.Deadline, &stored.CreatedAt,
			&stored.StateSequence, &stored.Attempt, &stored.IdempotencyKey,
			&stored.WorkerID, &stored.Token, &stored.ExpiresAt, &storedState, &databaseNow,
		)
		if errors.Is(err, pgx.ErrNoRows) {
			return ErrPublicationIntentLeaseLost
		}
		if err != nil {
			return err
		}
		if storedState != "leased" || !samePublicationIntentLease(stored, lease) {
			return ErrPublicationIntentLeaseLost
		}
		var nextAttemptAt *time.Time
		if state == "retry_wait" {
			next := databaseNow.Add(retryDelay)
			nextAttemptAt = &next
		}
		_, err = tx.Exec(ctx, `INSERT INTO certificate_publication_intent_state_facts(
			tenant_scope_id,site_id,binding_revision,sequence,state,attempt,idempotency_key,
			lease_owner,lease_token,lease_expires_at,next_attempt_at,failure_code,occurred_at,
			publication_id,publication_revision,config_version_id,rollout_id,rollout_revision
		) VALUES($1,$2,$3,$4,$5,$6,$7,$8,$9,$10,$11,$12,$13,$14,$15,$16,$17,$18)`,
			lease.TenantScopeID, lease.SiteID, lease.BindingRevision, stored.StateSequence+1,
			state, lease.Attempt, lease.IdempotencyKey, lease.WorkerID, lease.Token,
			lease.ExpiresAt, nextAttemptAt, nullablePublicationFailureCode(failureCode), databaseNow,
			nullablePublicationUUID(result.PublicationID), nullablePublicationRevision(result.PublicationRevision),
			nullablePublicationUUID(result.ConfigVersionID), nullablePublicationUUID(result.RolloutID),
			nullablePublicationRevision(result.RolloutRevision),
		)
		if err != nil || state == "retry_wait" {
			return err
		}
		if state == "succeeded" && stored.Operation == "publish" {
			// CERT-RENEW-LIFECYCLE-01 A: the ACME order that issued the
			// published version is now deployed (deploying -> active).
			var orderID uuid.UUID
			err := tx.QueryRow(ctx, `UPDATE certificate_orders SET status='active',revision=revision+1,
				updated_at=GREATEST(updated_at,statement_timestamp())
				WHERE scope_id=$1 AND issued_asset_id=$2 AND issued_asset_version_id=$3 AND status='deploying'
				RETURNING id`, stored.TenantScopeID, stored.AssetID, stored.VersionID).Scan(&orderID)
			if err != nil && !errors.Is(err, pgx.ErrNoRows) {
				return fmt.Errorf("advance deployed ACME order: %w", err)
			}
			if err == nil {
				if err := audit.New(nil).Append(ctx, tx, audit.Event{
					ScopeID: stored.TenantScopeID, Action: "certificate.order.transition",
					ResourceType: "certificate_order", ResourceID: orderID.String(), RequestID: stored.RequestID,
					Result: "success", Payload: map[string]any{
						"from_status": "deploying", "to_status": "active", "state": "active",
						"reason": "certificate_publication_succeeded", "site_id": stored.SiteID.String(),
						"changes": map[string]any{"status": map[string]any{"before": "deploying", "after": "active"}},
					},
				}); err != nil {
					return err
				}
			}
		}
		return appendPublicationCompleteAudit(ctx, tx, stored, lease, state, failureCode, result)
	})
}

func appendPublicationCompleteAudit(
	ctx context.Context,
	tx pgx.Tx,
	stored, lease PublicationIntentLease,
	state, failureCode string,
	result PublicationResult,
) error {
	payload := map[string]any{
		"operation": stored.Operation, "worker_id": lease.WorkerID, "attempt": lease.Attempt,
		"requested_by_user_id": stored.ActorUserID.String(), "requested_by_scope_id": stored.ActorScopeID.String(),
		"asset_id": stored.AssetID.String(), "version_id": stored.VersionID.String(),
		"binding_revision": stored.BindingRevision, "state": state,
	}
	outcome := "success"
	if state == "permanent_failed" {
		outcome = "failure"
		payload["reason_code"] = failureCode
	} else {
		payload["rollout_id"] = result.RolloutID.String()
		payload["rollout_revision"] = result.RolloutRevision
	}
	return audit.New(nil).Append(ctx, tx, audit.Event{
		ScopeID: stored.TenantScopeID, Action: AuditPublicationComplete,
		ResourceType: "site", ResourceID: stored.SiteID.String(), RequestID: stored.RequestID,
		Result: outcome, Payload: payload,
	})
}

func publicationIntentIdempotencyKey(tenantID, siteID uuid.UUID, revision int64) string {
	if tenantID == uuid.Nil || siteID == uuid.Nil || revision < 1 {
		return ""
	}
	return fmt.Sprintf("certificate.publication/%s/%s/%d", tenantID, siteID, revision)
}

func publicationIntentRetryDelay(
	config PublicationIntentStoreConfig,
	attempt int,
	jitter func(time.Duration) time.Duration,
) (time.Duration, error) {
	if attempt < 1 || config.RetryBase <= 0 || config.RetryMaximum < config.RetryBase || jitter == nil {
		return 0, ErrInvalidInput
	}
	delay := config.RetryBase
	for current := 1; current < attempt && delay < config.RetryMaximum; current++ {
		if delay > config.RetryMaximum/2 {
			delay = config.RetryMaximum
		} else {
			delay *= 2
		}
	}
	if delay > config.RetryMaximum {
		delay = config.RetryMaximum
	}
	spread := min(delay/2, config.RetryMaximum-delay)
	offset := jitter(spread)
	if offset < 0 || offset > spread {
		return 0, ErrInvalidInput
	}
	return delay + offset, nil
}

func securePublicationIntentJitter(maximum time.Duration) time.Duration {
	if maximum <= 0 {
		return 0
	}
	value, err := cryptorand.Int(cryptorand.Reader, big.NewInt(int64(maximum)+1))
	if err != nil {
		return 0
	}
	return time.Duration(value.Int64())
}

func validPublicationIntentLease(lease PublicationIntentLease) bool {
	return lease.TenantScopeID != uuid.Nil && lease.SiteID != uuid.Nil && lease.AssetID != uuid.Nil &&
		lease.VersionID != uuid.Nil && lease.ActorScopeID != uuid.Nil && lease.ActorUserID != uuid.Nil &&
		lease.ActorSessionID != uuid.Nil && (lease.ActorScopeKind == ScopeTenant || lease.ActorScopeKind == ScopePlatform) &&
		lease.ActorUserRevision > 0 && lease.TargetTenantID != uuid.Nil && lease.TargetTenantRevision > 0 &&
		lease.BindingRevision > 0 && lease.StateSequence > 1 && lease.Attempt > 0 &&
		(lease.Operation == "publish" || lease.Operation == "unpublish") &&
		lease.RequestID != "" && lease.RequestID == strings.TrimSpace(lease.RequestID) &&
		!lease.Deadline.IsZero() && lease.Deadline.After(lease.CreatedAt) &&
		validPublicationWorkerID(lease.WorkerID) && lease.Token != uuid.Nil &&
		!lease.ExpiresAt.IsZero() && !lease.CreatedAt.IsZero() &&
		lease.IdempotencyKey == publicationIntentIdempotencyKey(
			lease.TenantScopeID, lease.SiteID, lease.BindingRevision,
		)
}

func samePublicationIntentLease(stored, lease PublicationIntentLease) bool {
	return stored.TenantScopeID == lease.TenantScopeID && stored.SiteID == lease.SiteID &&
		stored.BindingRevision == lease.BindingRevision && stored.Operation == lease.Operation &&
		stored.AssetID == lease.AssetID && stored.VersionID == lease.VersionID &&
		stored.Default == lease.Default && stored.RequestID == lease.RequestID &&
		stored.ActorScopeID == lease.ActorScopeID && stored.ActorUserID == lease.ActorUserID &&
		stored.ActorSessionID == lease.ActorSessionID && stored.ActorScopeKind == lease.ActorScopeKind &&
		stored.ActorUserRevision == lease.ActorUserRevision && stored.TargetTenantID == lease.TargetTenantID &&
		stored.TargetTenantRevision == lease.TargetTenantRevision &&
		stored.Deadline.Equal(lease.Deadline) &&
		stored.CreatedAt.Equal(lease.CreatedAt) && stored.StateSequence == lease.StateSequence &&
		stored.Attempt == lease.Attempt && stored.IdempotencyKey == lease.IdempotencyKey &&
		stored.WorkerID == lease.WorkerID && stored.Token == lease.Token &&
		stored.ExpiresAt.Equal(lease.ExpiresAt)
}

func validPublicationWorkerID(value string) bool {
	if value == "" || value != strings.TrimSpace(value) || len(value) > 128 {
		return false
	}
	for _, character := range value {
		if unicode.IsControl(character) || character == '\u2028' || character == '\u2029' {
			return false
		}
	}
	return true
}

func validPublicationFailureCode(value string) bool {
	if len(value) < 1 || len(value) > 128 || value[0] < 'a' || value[0] > 'z' {
		return false
	}
	for _, character := range value[1:] {
		if (character < 'a' || character > 'z') && (character < '0' || character > '9') &&
			character != '.' && character != '_' && character != '-' {
			return false
		}
	}
	return true
}

func nullablePublicationFailureCode(value string) *string {
	if value == "" {
		return nil
	}
	return &value
}

func nullablePublicationUUID(value uuid.UUID) *uuid.UUID {
	if value == uuid.Nil {
		return nil
	}
	return &value
}

func nullablePublicationRevision(value int64) *int64 {
	if value == 0 {
		return nil
	}
	return &value
}
