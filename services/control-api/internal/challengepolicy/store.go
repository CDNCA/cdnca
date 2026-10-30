package challengepolicy

import (
	"bytes"
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"strings"
	"time"

	"github.com/cdnca/cdnca/services/control-api/internal/audit"
	"github.com/cdnca/cdnca/services/control-api/internal/entitlementguard"
	"github.com/cdnca/cdnca/services/control-api/internal/sitelock"
	"github.com/google/uuid"
	"github.com/jackc/pgx/v5"
	"github.com/jackc/pgx/v5/pgconn"
	"github.com/jackc/pgx/v5/pgxpool"
)

const documentSchema = "cdnca.control.challenge-policy/v1"

type Store struct {
	pool       *pgxpool.Pool
	auditor    *audit.Log
	gate       entitlementGate
	authorizer TxAuthorizer
	now        func() time.Time
	cursor     *CursorCodec
}

type entitlementGuardAdapter struct {
	guard *entitlementguard.Guard
}

func (adapter entitlementGuardAdapter) Check(ctx context.Context, tx pgx.Tx, check entitlementCheck) error {
	return adapter.guard.CheckSiteChange(ctx, tx, entitlementguard.SiteCheck{
		AuditScopeID: check.AuditScopeID,
		ActorUserID:  check.ActorUserID,
		ResourceID:   check.ResourceID,
		RequestID:    check.RequestID,
		Operation:    check.Operation,
		Delta:        0,
	})
}

type storedWrite struct {
	Found        bool
	Outcome      string
	ResponseBody []byte
}

type pageCursor struct {
	CreatedAt time.Time `json:"created_at"`
	ID        uuid.UUID `json:"id"`
}

type revisionDocument struct {
	SchemaVersion        string                     `json:"schema_version"`
	PolicyID             uuid.UUID                  `json:"policy_id"`
	TenantScopeID        uuid.UUID                  `json:"tenant_scope_id"`
	SiteID               uuid.UUID                  `json:"site_id"`
	Host                 string                     `json:"host"`
	Revision             int64                      `json:"revision"`
	Priority             int                        `json:"priority"`
	Mode                 string                     `json:"mode"`
	MinDelaySeconds      int                        `json:"min_delay_seconds"`
	ChallengeTTLSeconds  int                        `json:"challenge_ttl_seconds"`
	PassTTLSeconds       int                        `json:"pass_ttl_seconds"`
	ClockSkewSeconds     int                        `json:"clock_skew_seconds"`
	AttemptsPerNonce     int                        `json:"attempts_per_nonce"`
	FailureWindowSeconds int                        `json:"failure_window_seconds"`
	MaxFailuresPerWindow int                        `json:"max_failures_per_window"`
	IPBinding            string                     `json:"ip_binding"`
	BindUserAgent        bool                       `json:"bind_user_agent"`
	BypassRoutes         []BypassRoute              `json:"bypass_routes"`
	KeyReference         string                     `json:"key_reference"`
	ExternalProvider     *ExternalProviderReference `json:"external_provider"`
	Enabled              bool                       `json:"enabled"`
	Deleted              bool                       `json:"deleted"`
}

func NewStore(pool *pgxpool.Pool, cursor *CursorCodec) (*Store, error) {
	return NewStoreWithClock(pool, time.Now, nil, cursor)
}

func NewStoreWithClock(
	pool *pgxpool.Pool,
	now func() time.Time,
	trust *entitlementguard.TrustStore,
	cursor *CursorCodec,
) (*Store, error) {
	return newStoreWithGate(pool, now, entitlementGuardAdapter{
		guard: entitlementguard.NewGuard(pool, now, trust),
	}, cursor, denyTxAuthorizer{})
}

func NewStoreWithDependencies(
	pool *pgxpool.Pool,
	now func() time.Time,
	trust *entitlementguard.TrustStore,
	cursor *CursorCodec,
	authorizer TxAuthorizer,
) (*Store, error) {
	return newStoreWithGate(pool, now, entitlementGuardAdapter{
		guard: entitlementguard.NewGuard(pool, now, trust),
	}, cursor, authorizer)
}

func newStoreWithGate(
	pool *pgxpool.Pool,
	now func() time.Time,
	gate entitlementGate,
	cursor *CursorCodec,
	authorizer TxAuthorizer,
) (*Store, error) {
	if isNilDependency(pool) || isNilDependency(now) || isNilDependency(gate) ||
		isNilDependency(cursor) || isNilDependency(authorizer) {
		return nil, ErrInvalidStoreConfig
	}
	return &Store{
		pool: pool, auditor: audit.New(pool), gate: gate, authorizer: authorizer, now: now, cursor: cursor,
	}, nil
}

func (store *Store) Create(ctx context.Context, actor Actor, request CreateRequest, digest [32]byte) (WriteResult, error) {
	policyID, err := uuid.NewV7()
	if err != nil {
		return WriteResult{}, ErrUnavailable
	}
	var result WriteResult
	var denial error
	err = pgx.BeginFunc(ctx, store.pool, func(tx pgx.Tx) error {
		tenantID, err := store.authorize(ctx, tx, actor, request.TargetScopeID, PermissionManage)
		if err != nil {
			return err
		}
		write, err := store.claimWrite(ctx, tx, actor, request.TargetScopeID, "challenge_policy.create", request.WriteMetadata, digest)
		if err != nil {
			return err
		}
		if write.Found {
			return replayWrite(write, &result)
		}
		if err := authorizeSiteHost(ctx, tx, request.TargetScopeID, request.SiteID, request.Host); err != nil {
			return err
		}
		if err := requireSiteUnlocked(ctx, tx, actor, request.SiteID); err != nil {
			return err
		}
		if denial = store.checkEntitlement(ctx, tx, actor, request.TargetScopeID, policyID, request.WriteMetadata, "challenge_policy.create"); denial != nil {
			return store.completeDenial(ctx, tx, actor, request.TargetScopeID, policyID, "challenge_policy.create", request.WriteMetadata, denial)
		}
		now := store.now().UTC().Truncate(time.Microsecond)
		item := storedPolicy{
			Policy: Policy{
				ID: policyID, TenantScopeID: request.TargetScopeID, SiteID: request.SiteID, Host: request.Host,
				Enabled: request.Enabled, Revision: 1, CreatedAt: now, UpdatedAt: now,
			},
			TenantID: tenantID, CreatedByUserID: actor.UserID,
		}
		applyConfig(&item, request.Config)
		if err := store.appendAudit(ctx, tx, actor, item, request.WriteMetadata, "create", "success"); err != nil {
			return err
		}
		if err := insertRevision(ctx, tx, actor, item, request.WriteMetadata, "create"); err != nil {
			return err
		}
		result.Policy = item.public()
		return store.completeWrite(ctx, tx, actor, "challenge_policy.create", request.WriteMetadata.IdempotencyKey, "success", item.ID, 201, result.Policy)
	})
	if err != nil {
		return WriteResult{}, normalizeStoreError(err)
	}
	if denial != nil {
		return WriteResult{}, denial
	}
	return result, nil
}

func (store *Store) Update(ctx context.Context, actor Actor, request UpdateRequest, digest [32]byte) (WriteResult, error) {
	return store.change(ctx, actor, request.TargetScopeID, request.ID, request.ExpectedRevision,
		request.WriteMetadata, digest, "update", true, func(item *storedPolicy) error {
			applyConfig(item, request.Config)
			return nil
		})
}

func (store *Store) SetEnabled(ctx context.Context, actor Actor, request StateRequest, digest [32]byte) (WriteResult, error) {
	action := "disable"
	requireEntitlement := false
	if request.Enabled {
		action = "enable"
		requireEntitlement = true
	}
	return store.change(ctx, actor, request.TargetScopeID, request.ID, request.ExpectedRevision,
		request.WriteMetadata, digest, action, requireEntitlement, func(item *storedPolicy) error {
			if item.Enabled == request.Enabled {
				return ErrConflict
			}
			item.Enabled = request.Enabled
			return nil
		})
}

func (store *Store) Delete(ctx context.Context, actor Actor, request DeleteRequest, digest [32]byte) (WriteResult, error) {
	return store.change(ctx, actor, request.TargetScopeID, request.ID, request.ExpectedRevision,
		request.WriteMetadata, digest, "delete", false, func(item *storedPolicy) error {
			item.Enabled = false
			item.Deleted = true
			return nil
		})
}

func (store *Store) change(
	ctx context.Context,
	actor Actor,
	targetScopeID, policyID uuid.UUID,
	expectedRevision int64,
	metadata WriteMetadata,
	digest [32]byte,
	action string,
	requireEntitlement bool,
	mutate func(*storedPolicy) error,
) (WriteResult, error) {
	operation := "challenge_policy." + action
	var result WriteResult
	var denial error
	err := pgx.BeginFunc(ctx, store.pool, func(tx pgx.Tx) error {
		if _, err := store.authorize(ctx, tx, actor, targetScopeID, PermissionManage); err != nil {
			return err
		}
		write, err := store.claimWrite(ctx, tx, actor, targetScopeID, operation, metadata, digest)
		if err != nil {
			return err
		}
		if write.Found {
			return replayWrite(write, &result)
		}
		item, err := lockPolicy(ctx, tx, targetScopeID, policyID)
		if err != nil {
			return err
		}
		if err := requireSiteUnlocked(ctx, tx, actor, item.SiteID); err != nil {
			return err
		}
		if item.Revision != expectedRevision {
			return ErrRevisionConflict
		}
		if requireEntitlement {
			denial = store.checkEntitlement(ctx, tx, actor, targetScopeID, policyID, metadata, operation)
			if denial != nil {
				return store.completeDenial(ctx, tx, actor, targetScopeID, policyID, operation, metadata, denial)
			}
		}
		if err := mutate(&item); err != nil {
			return err
		}
		item.Revision++
		item.UpdatedAt = store.now().UTC().Truncate(time.Microsecond)
		if err := store.appendAudit(ctx, tx, actor, item, metadata, action, "success"); err != nil {
			return err
		}
		if err := insertRevision(ctx, tx, actor, item, metadata, action); err != nil {
			return err
		}
		result.Policy = item.public()
		status := 200
		return store.completeWrite(ctx, tx, actor, operation, metadata.IdempotencyKey, "success", item.ID, status, result.Policy)
	})
	if err != nil {
		return WriteResult{}, normalizeStoreError(err)
	}
	if denial != nil {
		return WriteResult{}, denial
	}
	return result, nil
}

func (store *Store) authorize(
	ctx context.Context,
	tx pgx.Tx,
	actor Actor,
	targetScopeID uuid.UUID,
	permission string,
) (uuid.UUID, error) {
	if !validCredentialReference(actor.Credential) {
		return uuid.Nil, ErrPermissionDenied
	}
	tenantID, err := store.authorizer.Authorize(ctx, tx, actor, targetScopeID, permission)
	if err != nil {
		return uuid.Nil, err
	}
	if tenantID == uuid.Nil {
		return uuid.Nil, ErrPermissionDenied
	}
	return tenantID, nil
}

func validCredentialReference(reference CredentialReference) bool {
	return reference.ID != uuid.Nil &&
		(reference.Kind == CredentialKindSession || reference.Kind == CredentialKindAPIKey)
}

func (store *Store) Get(ctx context.Context, actor Actor, targetScopeID, id uuid.UUID) (Policy, error) {
	var result Policy
	err := pgx.BeginFunc(ctx, store.pool, func(tx pgx.Tx) error {
		if _, err := store.authorize(ctx, tx, actor, targetScopeID, PermissionRead); err != nil {
			return err
		}
		item, err := selectPolicy(ctx, tx, targetScopeID, id, false)
		if err != nil {
			return err
		}
		result = item.public()
		return nil
	})
	if err != nil {
		return Policy{}, normalizeStoreError(err)
	}
	return result, nil
}

func (store *Store) List(ctx context.Context, actor Actor, filter ListFilter) (ListResult, error) {
	cursor, err := store.cursor.decode(filter.Cursor, actor, filter)
	if err != nil {
		return ListResult{}, ErrInvalidInput
	}
	conditions := []string{"policy.tenant_scope_id = $1", "policy.deleted_at IS NULL"}
	args := []any{filter.TargetScopeID}
	add := func(condition string, value any) {
		args = append(args, value)
		conditions = append(conditions, fmt.Sprintf(condition, len(args)))
	}
	if filter.SiteID != uuid.Nil {
		add("policy.site_id = $%d", filter.SiteID)
	}
	if filter.Host != "" {
		add("policy.host = $%d", filter.Host)
	}
	if filter.Enabled != nil {
		add("policy.current_enabled = $%d", *filter.Enabled)
	}
	if cursor != nil {
		args = append(args, cursor.CreatedAt, cursor.ID)
		conditions = append(conditions, fmt.Sprintf("(policy.created_at, policy.id) < ($%d, $%d)", len(args)-1, len(args)))
	}
	args = append(args, filter.Limit+1)
	var result ListResult
	err = pgx.BeginFunc(ctx, store.pool, func(tx pgx.Tx) error {
		if _, err := store.authorize(ctx, tx, actor, filter.TargetScopeID, PermissionRead); err != nil {
			return err
		}
		rows, err := tx.Query(ctx, selectPolicySQL+`
			WHERE `+strings.Join(conditions, " AND ")+`
			ORDER BY policy.created_at DESC, policy.id DESC
			LIMIT $`+fmt.Sprint(len(args)), args...)
		if err != nil {
			return err
		}
		defer rows.Close()
		items := make([]storedPolicy, 0, filter.Limit+1)
		for rows.Next() {
			item, err := scanStoredPolicy(rows)
			if err != nil {
				return err
			}
			items = append(items, item)
		}
		if err := rows.Err(); err != nil {
			return err
		}
		result = ListResult{Items: make([]Policy, 0, min(len(items), filter.Limit))}
		available := min(len(items), filter.Limit)
		for index := 0; index < available; index++ {
			candidate := ListResult{Items: append(result.Items, items[index].public())}
			if index+1 < len(items) {
				candidate.NextCursor, err = store.cursor.encode(actor, filter, pageCursor{
					CreatedAt: items[index].CreatedAt,
					ID:        items[index].ID,
				})
				if err != nil {
					return ErrUnavailable
				}
			}
			encoded, err := json.Marshal(candidate)
			if err != nil {
				return ErrUnavailable
			}
			if len(encoded)+1 > maxResponseBytes {
				break
			}
			result = candidate
		}
		if available > 0 && len(result.Items) == 0 {
			return ErrUnavailable
		}
		return nil
	})
	if err != nil {
		return ListResult{}, normalizeStoreError(err)
	}
	return result, nil
}

type queryRower interface {
	QueryRow(context.Context, string, ...any) pgx.Row
}

func requireSiteUnlocked(ctx context.Context, tx pgx.Tx, actor Actor, siteID uuid.UUID) error {
	err := sitelock.RequireUnlocked(ctx, tx, actor.ScopeID, siteID)
	if errors.Is(err, sitelock.ErrLocked) {
		return ErrSiteLocked
	}
	return err
}

func authorizeSiteHost(ctx context.Context, tx pgx.Tx, targetScopeID, siteID uuid.UUID, host string) error {
	var domain string
	err := tx.QueryRow(ctx, `
		SELECT domain FROM sites
		WHERE id = $1 AND scope_id = $2 AND deleted_at IS NULL`, siteID, targetScopeID).Scan(&domain)
	if errors.Is(err, pgx.ErrNoRows) {
		return ErrNotFound
	}
	if err != nil {
		return err
	}
	if strings.HasPrefix(domain, "*.") {
		suffix := strings.TrimPrefix(domain, "*.")
		if host == suffix || !strings.HasSuffix(host, "."+suffix) {
			return ErrValidation
		}
		return nil
	}
	if host != domain {
		return ErrValidation
	}
	return nil
}

func (store *Store) checkEntitlement(
	ctx context.Context,
	tx pgx.Tx,
	actor Actor,
	targetScopeID, resourceID uuid.UUID,
	metadata WriteMetadata,
	operation string,
) error {
	if store.gate == nil {
		return ErrEntitlementUnavailable
	}
	err := store.gate.Check(ctx, tx, entitlementCheck{
		AuditScopeID: targetScopeID, ActorUserID: actor.UserID, ResourceID: resourceID,
		RequestID: metadata.RequestID, Operation: operation,
	})
	switch {
	case err == nil:
		return nil
	case errors.Is(err, entitlementguard.ErrUnavailable), errors.Is(err, entitlementguard.ErrInvalid):
		return ErrEntitlementUnavailable
	case entitlementguard.IsDenial(err):
		return ErrEntitlementDenied
	default:
		return err
	}
}

func (store *Store) completeDenial(
	ctx context.Context,
	tx pgx.Tx,
	actor Actor,
	targetScopeID, resourceID uuid.UUID,
	operation string,
	metadata WriteMetadata,
	denial error,
) error {
	outcome := "entitlement_denied"
	status := 403
	if errors.Is(denial, ErrEntitlementUnavailable) {
		outcome = "entitlement_unavailable"
		status = 503
	} else if !errors.Is(denial, ErrEntitlementDenied) {
		return denial
	}
	if err := store.auditor.Append(ctx, tx, audit.Event{
		ScopeID: targetScopeID, ActorUserID: &actor.UserID, Action: operation,
		ResourceType: "challenge_policy", ResourceID: resourceID.String(), RequestID: metadata.RequestID,
		Result: "denied", Payload: map[string]any{"trace_id": metadata.TraceID, "reason": outcome},
	}); err != nil {
		return err
	}
	body := map[string]any{"error": map[string]string{"code": outcome}}
	return store.completeWrite(ctx, tx, actor, operation, metadata.IdempotencyKey, outcome, resourceID, status, body)
}

func (store *Store) appendAudit(
	ctx context.Context,
	tx pgx.Tx,
	actor Actor,
	item storedPolicy,
	metadata WriteMetadata,
	action, result string,
) error {
	return store.auditor.Append(ctx, tx, audit.Event{
		ScopeID: item.TenantScopeID, ActorUserID: &actor.UserID,
		Action: "challenge_policy." + action, ResourceType: "challenge_policy", ResourceID: item.ID.String(),
		RequestID: metadata.RequestID, Result: result,
		Payload: map[string]any{
			"trace_id": metadata.TraceID, "revision": item.Revision, "site_id": item.SiteID.String(),
			"host": item.Host, "mode": item.Mode, "enabled": item.Enabled,
		},
	})
}

func insertRevision(ctx context.Context, tx pgx.Tx, actor Actor, item storedPolicy, metadata WriteMetadata, action string) error {
	document := revisionDocument{
		SchemaVersion: documentSchema, PolicyID: item.ID, TenantScopeID: item.TenantScopeID,
		SiteID: item.SiteID, Host: item.Host, Revision: item.Revision,
		Priority: item.Priority, Mode: item.Mode, MinDelaySeconds: item.MinDelaySeconds,
		ChallengeTTLSeconds: item.ChallengeTTLSeconds, PassTTLSeconds: item.PassTTLSeconds,
		ClockSkewSeconds: item.ClockSkewSeconds, AttemptsPerNonce: item.AttemptsPerNonce,
		FailureWindowSeconds: item.FailureWindowSeconds, MaxFailuresPerWindow: item.MaxFailuresPerWindow,
		IPBinding: item.IPBinding, BindUserAgent: item.BindUserAgent, BypassRoutes: item.BypassRoutes,
		KeyReference: item.KeyReference, ExternalProvider: item.External,
		Enabled: item.Enabled, Deleted: item.Deleted,
	}
	encodedRoutes, err := json.Marshal(item.BypassRoutes)
	if err != nil {
		return err
	}
	encodedDocument, err := json.Marshal(document)
	if err != nil {
		return err
	}
	var provider, appReference any
	if item.External != nil {
		provider = item.External.Provider
		appReference = item.External.AppReference
	}
	_, err = tx.Exec(ctx, `
		INSERT INTO challenge_policy_revisions (
			policy_id, tenant_scope_id, tenant_id, site_id, host, revision, action,
			priority, mode, min_delay_seconds, challenge_ttl_seconds, pass_ttl_seconds,
			clock_skew_seconds, attempts_per_nonce, failure_window_seconds, max_failures_per_window,
			ip_binding, bind_user_agent, bypass_routes, key_reference, external_provider,
			external_app_reference, enabled, deleted, document, created_by_scope_id,
			created_by_user_id, request_id, trace_id, created_at
		) VALUES (
			$1,$2,$3,$4,$5,$6,$7,$8,$9,$10,$11,$12,$13,$14,$15,$16,$17,$18,$19,$20,
			$21,$22,$23,$24,$25,$26,$27,$28,$29,$30
		)`,
		item.ID, item.TenantScopeID, item.TenantID, item.SiteID, item.Host, item.Revision, action,
		item.Priority, item.Mode, item.MinDelaySeconds, item.ChallengeTTLSeconds, item.PassTTLSeconds,
		item.ClockSkewSeconds, item.AttemptsPerNonce, item.FailureWindowSeconds, item.MaxFailuresPerWindow,
		item.IPBinding, item.BindUserAgent, encodedRoutes, item.KeyReference, provider, appReference,
		item.Enabled, item.Deleted, encodedDocument, actor.ScopeID, actor.UserID,
		metadata.RequestID, metadata.TraceID, item.UpdatedAt,
	)
	return err
}

const selectPolicySQL = `
	SELECT policy.id, policy.tenant_scope_id, policy.tenant_id, policy.site_id, policy.host,
	       revision.priority, revision.mode, revision.min_delay_seconds,
	       revision.challenge_ttl_seconds, revision.pass_ttl_seconds, revision.clock_skew_seconds,
	       revision.attempts_per_nonce, revision.failure_window_seconds,
	       revision.max_failures_per_window, revision.ip_binding, revision.bind_user_agent,
	       revision.bypass_routes, revision.key_reference, revision.external_provider,
	       revision.external_app_reference, policy.current_enabled, policy.current_deleted,
	       policy.current_revision, policy.created_by_user_id, policy.created_at, policy.updated_at
	FROM challenge_policies policy
	JOIN challenge_policy_revisions revision
	  ON revision.policy_id = policy.id AND revision.revision = policy.current_revision`

func selectPolicy(ctx context.Context, database queryRower, targetScopeID, id uuid.UUID, includeDeleted bool) (storedPolicy, error) {
	query := selectPolicySQL + " WHERE policy.tenant_scope_id = $1 AND policy.id = $2"
	if !includeDeleted {
		query += " AND policy.deleted_at IS NULL"
	}
	item, err := scanStoredPolicy(database.QueryRow(ctx, query, targetScopeID, id))
	if errors.Is(err, pgx.ErrNoRows) {
		return storedPolicy{}, ErrNotFound
	}
	return item, err
}

func lockPolicy(ctx context.Context, tx pgx.Tx, targetScopeID, id uuid.UUID) (storedPolicy, error) {
	var lockedID uuid.UUID
	err := tx.QueryRow(ctx, `
		SELECT id FROM challenge_policies
		WHERE tenant_scope_id = $1 AND id = $2 AND deleted_at IS NULL
		FOR UPDATE`, targetScopeID, id).Scan(&lockedID)
	if errors.Is(err, pgx.ErrNoRows) {
		return storedPolicy{}, ErrNotFound
	}
	if err != nil {
		return storedPolicy{}, err
	}
	return selectPolicy(ctx, tx, targetScopeID, lockedID, false)
}

type rowScanner interface {
	Scan(...any) error
}

func scanStoredPolicy(row rowScanner) (storedPolicy, error) {
	var item storedPolicy
	var routes []byte
	var provider, appReference *string
	err := row.Scan(
		&item.ID, &item.TenantScopeID, &item.TenantID, &item.SiteID, &item.Host,
		&item.Priority, &item.Mode, &item.MinDelaySeconds, &item.ChallengeTTLSeconds,
		&item.PassTTLSeconds, &item.ClockSkewSeconds, &item.AttemptsPerNonce,
		&item.FailureWindowSeconds, &item.MaxFailuresPerWindow, &item.IPBinding,
		&item.BindUserAgent, &routes, &item.KeyReference, &provider, &appReference,
		&item.Enabled, &item.Deleted, &item.Revision, &item.CreatedByUserID,
		&item.CreatedAt, &item.UpdatedAt,
	)
	if err != nil {
		return storedPolicy{}, err
	}
	if err := json.Unmarshal(routes, &item.BypassRoutes); err != nil {
		return storedPolicy{}, err
	}
	if provider != nil || appReference != nil {
		if provider == nil || appReference == nil {
			return storedPolicy{}, ErrUnavailable
		}
		item.External = &ExternalProviderReference{Provider: *provider, AppReference: *appReference}
	}
	return item, nil
}

func applyConfig(item *storedPolicy, config Config) {
	item.Priority = config.Priority
	item.Mode = config.Mode
	item.MinDelaySeconds = config.MinDelaySeconds
	item.ChallengeTTLSeconds = config.ChallengeTTLSeconds
	item.PassTTLSeconds = config.PassTTLSeconds
	item.ClockSkewSeconds = config.ClockSkewSeconds
	item.AttemptsPerNonce = config.AttemptsPerNonce
	item.FailureWindowSeconds = config.FailureWindowSeconds
	item.MaxFailuresPerWindow = config.MaxFailuresPerWindow
	item.IPBinding = config.IPBinding
	item.BindUserAgent = config.BindUserAgent
	item.BypassRoutes = append([]BypassRoute(nil), config.BypassRoutes...)
	item.KeyReference = config.KeyReference
	if config.ExternalProvider == nil {
		item.External = nil
	} else {
		value := *config.ExternalProvider
		item.External = &value
	}
}

func (item storedPolicy) public() Policy {
	result := item.Policy
	result.BypassRoutes = append([]BypassRoute(nil), item.BypassRoutes...)
	result.KeyReferenceConfigured = item.KeyReference != ""
	result.ExternalProviderConfigured = item.External != nil
	return result
}

func replayWrite(write storedWrite, result *WriteResult) error {
	switch write.Outcome {
	case "success":
		if err := json.Unmarshal(write.ResponseBody, &result.Policy); err != nil {
			return err
		}
		result.Replayed = true
		return nil
	case "entitlement_denied":
		return ErrEntitlementDenied
	case "entitlement_unavailable":
		return ErrEntitlementUnavailable
	default:
		return ErrIdempotencyConflict
	}
}

func (store *Store) claimWrite(
	ctx context.Context,
	tx pgx.Tx,
	actor Actor,
	targetScopeID uuid.UUID,
	operation string,
	metadata WriteMetadata,
	digest [32]byte,
) (storedWrite, error) {
	id, err := uuid.NewV7()
	if err != nil {
		return storedWrite{}, err
	}
	command, err := tx.Exec(ctx, `
		INSERT INTO challenge_policy_write_requests (
			id, actor_scope_id, actor_user_id, target_scope_id, operation,
			idempotency_key, request_digest, request_id, trace_id, created_at
		) VALUES ($1,$2,$3,$4,$5,$6,$7,$8,$9,$10)
		ON CONFLICT (actor_scope_id, actor_user_id, operation, idempotency_key) DO NOTHING`,
		id, actor.ScopeID, actor.UserID, targetScopeID, operation, metadata.IdempotencyKey,
		digest[:], metadata.RequestID, metadata.TraceID, store.now().UTC().Truncate(time.Microsecond))
	if err != nil {
		return storedWrite{}, err
	}
	if command.RowsAffected() == 1 {
		return storedWrite{}, nil
	}
	var existingDigest []byte
	var existingTarget uuid.UUID
	var outcome *string
	var body []byte
	var completedAt *time.Time
	err = tx.QueryRow(ctx, `
		SELECT target_scope_id, request_digest, outcome, response_body, completed_at
		FROM challenge_policy_write_requests
		WHERE actor_scope_id = $1 AND actor_user_id = $2 AND operation = $3 AND idempotency_key = $4
		FOR UPDATE`, actor.ScopeID, actor.UserID, operation, metadata.IdempotencyKey).Scan(
		&existingTarget, &existingDigest, &outcome, &body, &completedAt)
	if err != nil {
		return storedWrite{}, err
	}
	if existingTarget != targetScopeID || !bytes.Equal(existingDigest, digest[:]) || outcome == nil || completedAt == nil {
		return storedWrite{}, ErrIdempotencyConflict
	}
	return storedWrite{Found: true, Outcome: *outcome, ResponseBody: body}, nil
}

func (store *Store) completeWrite(
	ctx context.Context,
	tx pgx.Tx,
	actor Actor,
	operation, key, outcome string,
	resourceID uuid.UUID,
	status int,
	body any,
) error {
	encoded, err := json.Marshal(body)
	if err != nil {
		return err
	}
	command, err := tx.Exec(ctx, `
		UPDATE challenge_policy_write_requests
		SET outcome = $5, resource_id = $6, response_status = $7,
		    response_body = $8, completed_at = $9
		WHERE actor_scope_id = $1 AND actor_user_id = $2 AND operation = $3
		  AND idempotency_key = $4 AND completed_at IS NULL`,
		actor.ScopeID, actor.UserID, operation, key, outcome, resourceID, status,
		string(encoded), store.now().UTC().Truncate(time.Microsecond))
	if err != nil {
		return err
	}
	if command.RowsAffected() != 1 {
		return ErrIdempotencyConflict
	}
	return nil
}

func normalizeStoreError(err error) error {
	if err == nil {
		return nil
	}
	for _, known := range []error{
		ErrUnauthenticated, ErrInvalidInput, ErrValidation, ErrPermissionDenied, ErrNotFound, ErrConflict, ErrSiteLocked,
		ErrRevisionConflict, ErrIdempotencyConflict, ErrEntitlementDenied, ErrEntitlementUnavailable,
		context.Canceled, context.DeadlineExceeded,
	} {
		if errors.Is(err, known) {
			return known
		}
	}
	var postgresError *pgconn.PgError
	if errors.As(err, &postgresError) && postgresError.Code == "23505" {
		return ErrConflict
	}
	return ErrUnavailable
}
