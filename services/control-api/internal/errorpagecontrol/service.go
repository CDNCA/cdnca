package errorpagecontrol

import (
	"bytes"
	"context"
	"encoding/hex"
	"encoding/json"
	"errors"
	"fmt"
	"sync"
	"time"

	"github.com/cdnca/cdnca/services/control-api/internal/audit"
	"github.com/google/uuid"
	"github.com/jackc/pgx/v5"
	"github.com/jackc/pgx/v5/pgxpool"
)

type Service struct {
	pool       *pgxpool.Pool
	content    ContentStore
	scanner    Scanner
	limits     LimitProvider
	authorizer TxAuthorizer
	auditor    AuditAppender
	now        Clock
	// slotRepublisher queues node republication for a slot change
	// (errpage-content); nil stores the slot without queueing.
	slotRepublisher SlotRepublisher

	reconcileMu      sync.Mutex
	reconcileCursor  reconcileCursor
	reconcileCeiling reconcileCursor
}

func NewService(pool *pgxpool.Pool, content ContentStore, scanner Scanner, limits LimitProvider, authorizers ...TxAuthorizer) (*Service, error) {
	return NewServiceWithDependencies(pool, content, scanner, limits, audit.New(pool), time.Now, authorizers...)
}

func NewServiceWithDependencies(
	pool *pgxpool.Pool,
	content ContentStore,
	scanner Scanner,
	limits LimitProvider,
	auditor AuditAppender,
	now Clock,
	authorizers ...TxAuthorizer,
) (*Service, error) {
	if pool == nil || isNilDependency(content) || !content.Capabilities().runtimeReady() ||
		isNilDependency(scanner) || isNilDependency(limits) || isNilDependency(auditor) || now == nil ||
		!writeMetadataPattern.MatchString(scanner.Name()) || len(authorizers) > 1 {
		return nil, ErrInvalidStore
	}
	authorizer := TxAuthorizer(denyTxAuthorizer{})
	if len(authorizers) == 1 {
		if isNilDependency(authorizers[0]) {
			return nil, ErrInvalidStore
		}
		authorizer = authorizers[0]
	}
	return &Service{
		pool: pool, content: content, scanner: scanner, limits: limits,
		authorizer: authorizer, auditor: auditor, now: now,
	}, nil
}

// SlotRepublisher queues the republication of every tenant scope a platform
// error page slot change reaches (edgepublish.SlotErrorPageRepublisher),
// returning how many it queued. It runs before the publication lock.
type SlotRepublisher interface {
	QueueSlotRepublicationTx(context.Context, pgx.Tx) (int, error)
}

// WithSlotRepublisher wires the slot change republication.
func (s *Service) WithSlotRepublisher(republisher SlotRepublisher) error {
	if s == nil || isNilDependency(republisher) {
		return ErrInvalidStore
	}
	s.slotRepublisher = republisher
	return nil
}

type scopeRecord struct {
	ID       uuid.UUID
	Kind     string
	TenantID *uuid.UUID
}

type denyTxAuthorizer struct{}

func (denyTxAuthorizer) Authorize(context.Context, pgx.Tx, Actor, string) error {
	return ErrPermissionDenied
}

func (s *Service) authorizeActor(
	ctx context.Context,
	tx pgx.Tx,
	actor Actor,
	targetScopeID uuid.UUID,
	permission string,
) error {
	if err := validateActor(actor); err != nil {
		return err
	}
	if targetScopeID == uuid.Nil {
		return ErrPermissionDenied
	}
	if scoped, ok := s.authorizer.(scopedTxAuthorizer); ok {
		return scoped.AuthorizeTarget(ctx, tx, actor, targetScopeID, permission)
	}
	return s.authorizer.Authorize(ctx, tx, actor, permission)
}

func authorizationTarget(actor Actor, requested uuid.UUID) uuid.UUID {
	if requested == uuid.Nil {
		return actor.ScopeID
	}
	return requested
}

func (s *Service) checkEntitlement(
	ctx context.Context,
	tx pgx.Tx,
	actor Actor,
	check EntitlementCheck,
) (EntitlementLimits, error) {
	check.ActorUserID = actor.UserID
	check.PrincipalKind = entitlementPrincipalUser
	check.PrincipalID = actor.UserID.String()
	return s.entitlementLimits(ctx, tx, check)
}

func (s *Service) entitlementLimits(
	ctx context.Context,
	tx pgx.Tx,
	check EntitlementCheck,
) (EntitlementLimits, error) {
	limits, err := s.limits.Limits(ctx, tx, check)
	if err != nil {
		if errors.Is(err, ErrEntitlementDenied) || errors.Is(err, ErrQuotaExceeded) {
			return EntitlementLimits{}, err
		}
		return EntitlementLimits{}, ErrUnavailable
	}
	if !limits.FeatureEnabled {
		return EntitlementLimits{}, ErrEntitlementDenied
	}
	if limits.AssetQuota.MaxAssetBytes < 1 || limits.AssetQuota.MaxAssets < 1 ||
		limits.AssetQuota.MaxTotalBytes < 1 || limits.MaxRulesPerScope < 1 ||
		limits.MaxPublicationSites < 1 || limits.MaxPublicationBytes < 1 {
		return EntitlementLimits{}, ErrUnavailable
	}
	if limits.AssetQuota.MaxAssetBytes > MaxEdgeResourceBytes {
		limits.AssetQuota.MaxAssetBytes = MaxEdgeResourceBytes
	}
	if limits.MaxRulesPerScope > MaxEdgeRulesPerScope {
		limits.MaxRulesPerScope = MaxEdgeRulesPerScope
	}
	if limits.MaxPublicationSites > MaxPublicationSites {
		limits.MaxPublicationSites = MaxPublicationSites
	}
	if limits.MaxPublicationBytes > MaxEdgePolicyBytes {
		limits.MaxPublicationBytes = MaxEdgePolicyBytes
	}
	return limits, nil
}

func baselineEntitlementLimits() EntitlementLimits {
	return EntitlementLimits{
		FeatureEnabled: true,
		AssetQuota: AssetQuota{
			MaxAssetBytes: MaxEdgeResourceBytes, MaxAssets: 1, MaxTotalBytes: MaxEdgeResourceBytes,
		},
		MaxRulesPerScope: MaxEdgeRulesPerScope, MaxPublicationSites: MaxPublicationSites,
		MaxPublicationBytes: MaxEdgePolicyBytes,
	}
}

func resolveTargetScope(ctx context.Context, tx pgx.Tx, actor Actor, requested uuid.UUID) (scopeRecord, error) {
	if actor.ScopeKind == "tenant" {
		if requested != uuid.Nil && requested != actor.ScopeID {
			return scopeRecord{}, ErrPermissionDenied
		}
		requested = actor.ScopeID
	} else if requested == uuid.Nil {
		requested = actor.ScopeID
	}
	var target scopeRecord
	target.ID = requested
	err := tx.QueryRow(ctx, `SELECT kind,tenant_id FROM access_scopes WHERE id=$1`, requested).
		Scan(&target.Kind, &target.TenantID)
	if errors.Is(err, pgx.ErrNoRows) {
		return scopeRecord{}, ErrNotFound
	}
	if err != nil {
		return scopeRecord{}, err
	}
	if actor.ScopeKind == "tenant" && target.Kind != "tenant" {
		return scopeRecord{}, ErrPermissionDenied
	}
	return target, nil
}

type storedWrite struct {
	ResourceID uuid.UUID
	Status     int
	Response   []byte
	Completed  bool
}

func (s *Service) claimWrite(
	ctx context.Context,
	tx pgx.Tx,
	actor Actor,
	targetScopeID uuid.UUID,
	operation string,
	metadata WriteMetadata,
	digest [32]byte,
) (storedWrite, bool, error) {
	id, err := uuid.NewV7()
	if err != nil {
		return storedWrite{}, false, err
	}
	command, err := tx.Exec(ctx, `
		INSERT INTO error_page_write_requests (
			id,actor_user_id,actor_scope_id,target_scope_id,operation,idempotency_key,
			request_digest,request_id,trace_id,created_at
		) VALUES($1,$2,$3,$4,$5,$6,$7,$8,$9,$10)
		ON CONFLICT(actor_scope_id,actor_user_id,operation,idempotency_key) DO NOTHING`,
		id, actor.UserID, actor.ScopeID, targetScopeID, operation, metadata.IdempotencyKey,
		digest[:], metadata.RequestID, metadata.TraceID, storeTime(s.now()))
	if err != nil {
		return storedWrite{}, false, err
	}
	if command.RowsAffected() == 1 {
		return storedWrite{}, false, nil
	}
	var storedDigest []byte
	var storedRequestID string
	var resourceID *uuid.UUID
	var status *int
	var response []byte
	var completed *time.Time
	err = tx.QueryRow(ctx, `
		SELECT request_digest,request_id,resource_id,response_status,response_body,completed_at
		FROM error_page_write_requests
		WHERE actor_scope_id=$1 AND actor_user_id=$2 AND operation=$3 AND idempotency_key=$4`,
		actor.ScopeID, actor.UserID, operation, metadata.IdempotencyKey).
		Scan(&storedDigest, &storedRequestID, &resourceID, &status, &response, &completed)
	if err != nil {
		return storedWrite{}, false, err
	}
	if !bytes.Equal(storedDigest, digest[:]) || storedRequestID != metadata.RequestID {
		return storedWrite{}, false, ErrIdempotencyConflict
	}
	stored := storedWrite{Completed: completed != nil}
	if resourceID != nil {
		stored.ResourceID = *resourceID
	}
	if status != nil {
		stored.Status = *status
	}
	stored.Response = response
	return stored, true, nil
}

func (s *Service) completeWrite(
	ctx context.Context,
	tx pgx.Tx,
	actor Actor,
	operation string,
	metadata WriteMetadata,
	resourceID uuid.UUID,
	status int,
	response any,
) error {
	encoded, err := json.Marshal(response)
	if err != nil {
		return err
	}
	command, err := tx.Exec(ctx, `
		UPDATE error_page_write_requests
		SET resource_id=$5,response_status=$6,response_body=$7,completed_at=$8
		WHERE actor_scope_id=$1 AND actor_user_id=$2 AND operation=$3 AND idempotency_key=$4
		  AND completed_at IS NULL`, actor.ScopeID, actor.UserID, operation, metadata.IdempotencyKey,
		resourceID, status, encoded, storeTime(s.now()))
	if err != nil {
		return err
	}
	if command.RowsAffected() != 1 {
		return ErrIdempotencyConflict
	}
	return nil
}

func decodeReplay[T any](stored storedWrite) (WriteResult[T], error) {
	var value T
	if !stored.Completed || len(stored.Response) == 0 {
		return WriteResult[T]{}, ErrIdempotencyConflict
	}
	if err := json.Unmarshal(stored.Response, &value); err != nil {
		return WriteResult[T]{}, err
	}
	return WriteResult[T]{Value: value, Replayed: true}, nil
}

func (s *Service) appendAudit(
	ctx context.Context,
	tx pgx.Tx,
	actor *Actor,
	scopeID uuid.UUID,
	action, resourceType, resourceID string,
	metadata WriteMetadata,
	result string,
	payload map[string]any,
) error {
	var actorID *uuid.UUID
	if actor != nil {
		actorID = &actor.UserID
	}
	if payload == nil {
		payload = make(map[string]any)
	}
	payload["trace_id"] = metadata.TraceID
	if actor != nil {
		payload["credential_kind"] = actor.Credential.Kind
		payload["credential_id"] = actor.Credential.ID.String()
	}
	return s.auditor.Append(ctx, tx, audit.Event{
		ScopeID: scopeID, ActorUserID: actorID, Action: action, ResourceType: resourceType,
		ResourceID: resourceID, RequestID: metadata.RequestID, Result: result, Payload: payload,
	})
}

func decodeSHA256(value string) []byte {
	decoded, _ := hex.DecodeString(value)
	return decoded
}

func storeTime(value time.Time) time.Time {
	return value.UTC().Truncate(time.Microsecond)
}

func wrapUnavailable(operation string, err error) error {
	if err == nil {
		return nil
	}
	if errors.Is(err, context.Canceled) || errors.Is(err, context.DeadlineExceeded) {
		return fmt.Errorf("%s: %w", operation, ErrUnavailable)
	}
	return fmt.Errorf("%s: %w", operation, ErrUnavailable)
}
