package originauthcontrol

import (
	"context"
	"encoding/json"
	"errors"
	"time"

	"github.com/cdnca/cdnca/services/control-api/internal/sitelock"
	"github.com/google/uuid"
	"github.com/jackc/pgx/v5"
)

func (service *Service) CreateRule(
	ctx context.Context,
	actor Actor,
	request CreateRuleRequest,
) (RuleWriteResult, error) {
	if err := validateTarget(actor, request.TargetScopeID); err != nil {
		return RuleWriteResult{}, err
	}
	if request.SiteID == uuid.Nil || request.SourcePosition < 1 || request.SourcePosition > 32 ||
		!validWriteMetadata(request.WriteMetadata) {
		return RuleWriteResult{}, ErrInvalidInput
	}
	if err := validateRuleConfig(&request.Config, service.egressPolicies); err != nil {
		return RuleWriteResult{}, err
	}
	if request.Config.PreviousCredential != nil || request.Config.ActivateCurrentAt != nil {
		return RuleWriteResult{}, ErrValidation
	}
	digest, err := digestRequest(struct {
		TargetScopeID  uuid.UUID  `json:"target_scope_id"`
		SiteID         uuid.UUID  `json:"site_id"`
		SourcePosition int        `json:"source_position"`
		Config         RuleConfig `json:"config"`
		Enabled        bool       `json:"enabled"`
	}{request.TargetScopeID, request.SiteID, request.SourcePosition, request.Config, request.Enabled})
	if err != nil {
		return RuleWriteResult{}, ErrUnavailable
	}
	ruleID := uuid.Must(uuid.NewV7())
	var result RuleWriteResult
	err = pgx.BeginFunc(ctx, service.pool, func(tx pgx.Tx) error {
		tenantID, err := service.authorizeTarget(ctx, tx, actor, request.TargetScopeID, PermissionManage)
		if err != nil {
			return err
		}
		write, err := service.claimWrite(ctx, tx, actor, request.TargetScopeID,
			"origin_auth.rule.create", request.WriteMetadata, digest)
		if err != nil {
			return err
		}
		if write.found {
			if err := json.Unmarshal(write.responseBody, &result.Rule); err != nil {
				return ErrUnavailable
			}
			result.Replayed = true
			return nil
		}
		if err := authorizeSiteSource(ctx, tx, request.TargetScopeID, request.SiteID, request.SourcePosition); err != nil {
			return err
		}
		if err := requireSiteUnlocked(ctx, tx, actor, request.SiteID); err != nil {
			return err
		}
		if err := validateSourceEndpoint(ctx, tx, request.SiteID, request.SourcePosition, request.Config.Endpoint); err != nil {
			return err
		}
		now := storeTime(service.now())
		currentRef, previousRef, err := validateRuleCredentials(ctx, tx, request.TargetScopeID,
			request.Config, request.Enabled, now)
		if err != nil {
			return err
		}
		if err := service.checkEntitlement(ctx, tx, actor, request.TargetScopeID, ruleID,
			request.WriteMetadata, "origin_auth.rule.create"); err != nil {
			return err
		}
		result.Rule = Rule{
			ID: ruleID, TenantScopeID: request.TargetScopeID, SiteID: request.SiteID,
			SourcePosition: request.SourcePosition, RuleConfig: request.Config,
			Enabled: request.Enabled, Revision: 1, CreatedAt: now, UpdatedAt: now,
		}
		if err := service.appendAudit(ctx, tx, actor, request.TargetScopeID, ruleID,
			request.WriteMetadata, "origin_auth.rule.create", "origin_auth_rule", ruleAuditPayload(result.Rule)); err != nil {
			return err
		}
		if _, err := tx.Exec(ctx, `INSERT INTO origin_auth_rules(
			id,tenant_scope_id,tenant_id,site_id,source_position,created_by_scope_id,created_by_user_id,
			request_id,trace_id,created_at)
			VALUES($1,$2,$3,$4,$5,$6,$7,$8,$9,$10)`, ruleID, request.TargetScopeID, tenantID,
			request.SiteID, request.SourcePosition, actor.ScopeID, actor.UserID, request.RequestID,
			request.TraceID, now); err != nil {
			return err
		}
		if err := insertRuleRevision(ctx, tx, actor, result.Rule, "create", currentRef, previousRef,
			request.WriteMetadata); err != nil {
			return err
		}
		return service.completeWrite(ctx, tx, actor, "origin_auth.rule.create",
			request.IdempotencyKey, ruleID, 201, result.Rule)
	})
	if err != nil {
		return RuleWriteResult{}, normalizeServiceError(err)
	}
	return result, nil
}

func (service *Service) UpdateRule(
	ctx context.Context,
	actor Actor,
	request UpdateRuleRequest,
) (RuleWriteResult, error) {
	if err := validateRuleConfig(&request.Config, service.egressPolicies); err != nil {
		return RuleWriteResult{}, err
	}
	digest, err := digestRequest(struct {
		TargetScopeID    uuid.UUID  `json:"target_scope_id"`
		RuleID           uuid.UUID  `json:"rule_id"`
		ExpectedRevision int64      `json:"expected_revision"`
		Config           RuleConfig `json:"config"`
	}{request.TargetScopeID, request.RuleID, request.ExpectedRevision, request.Config})
	if err != nil {
		return RuleWriteResult{}, ErrUnavailable
	}
	return service.changeRule(ctx, actor, request.TargetScopeID, request.RuleID, request.ExpectedRevision,
		request.WriteMetadata, digest, "update", func(rule *Rule) error {
			if request.Config.CurrentCredential != rule.CurrentCredential ||
				!sameCredentialReference(request.Config.PreviousCredential, rule.PreviousCredential) ||
				!sameTime(request.Config.ActivateCurrentAt, rule.ActivateCurrentAt) {
				return ErrValidation
			}
			rule.RuleConfig = request.Config
			return nil
		})
}

func (service *Service) EnableRule(ctx context.Context, actor Actor, request RuleMutationRequest) (RuleWriteResult, error) {
	return service.stateRule(ctx, actor, request, true)
}

func (service *Service) DisableRule(ctx context.Context, actor Actor, request RuleMutationRequest) (RuleWriteResult, error) {
	return service.stateRule(ctx, actor, request, false)
}

func (service *Service) stateRule(
	ctx context.Context,
	actor Actor,
	request RuleMutationRequest,
	enabled bool,
) (RuleWriteResult, error) {
	operation := "disable"
	if enabled {
		operation = "enable"
	}
	digest, err := digestRequest(struct {
		TargetScopeID    uuid.UUID `json:"target_scope_id"`
		RuleID           uuid.UUID `json:"rule_id"`
		ExpectedRevision int64     `json:"expected_revision"`
		Enabled          bool      `json:"enabled"`
	}{request.TargetScopeID, request.RuleID, request.ExpectedRevision, enabled})
	if err != nil {
		return RuleWriteResult{}, ErrUnavailable
	}
	return service.changeRule(ctx, actor, request.TargetScopeID, request.RuleID, request.ExpectedRevision,
		request.WriteMetadata, digest, operation, func(rule *Rule) error {
			if rule.Enabled == enabled || rule.Deleted {
				return ErrConflict
			}
			rule.Enabled = enabled
			return nil
		})
}

func (service *Service) RotateRule(
	ctx context.Context,
	actor Actor,
	request RotateRuleRequest,
) (RuleWriteResult, error) {
	request.ActivateCurrentAt = storeTime(request.ActivateCurrentAt)
	if request.CurrentCredential.CredentialID == uuid.Nil || request.CurrentCredential.Revision < 1 ||
		request.ActivateCurrentAt.IsZero() {
		return RuleWriteResult{}, ErrInvalidInput
	}
	digest, err := digestRequest(struct {
		TargetScopeID    uuid.UUID           `json:"target_scope_id"`
		RuleID           uuid.UUID           `json:"rule_id"`
		ExpectedRevision int64               `json:"expected_revision"`
		Current          CredentialReference `json:"current"`
		ActivateAt       time.Time           `json:"activate_at"`
	}{request.TargetScopeID, request.RuleID, request.ExpectedRevision,
		request.CurrentCredential, request.ActivateCurrentAt})
	if err != nil {
		return RuleWriteResult{}, ErrUnavailable
	}
	return service.changeRule(ctx, actor, request.TargetScopeID, request.RuleID, request.ExpectedRevision,
		request.WriteMetadata, digest, "rotate", func(rule *Rule) error {
			now := storeTime(service.now())
			if request.CurrentCredential == rule.CurrentCredential || !request.ActivateCurrentAt.After(now) ||
				request.ActivateCurrentAt.After(now.Add(30*24*time.Hour)) ||
				rule.ActivateCurrentAt != nil && rule.ActivateCurrentAt.After(now) {
				return ErrValidation
			}
			previous := rule.CurrentCredential
			rule.CurrentCredential = request.CurrentCredential
			rule.PreviousCredential = &previous
			rule.ActivateCurrentAt = &request.ActivateCurrentAt
			return nil
		})
}

func (service *Service) DeleteRule(
	ctx context.Context,
	actor Actor,
	request RuleMutationRequest,
) (RuleWriteResult, error) {
	digest, err := digestRequest(struct {
		TargetScopeID    uuid.UUID `json:"target_scope_id"`
		RuleID           uuid.UUID `json:"rule_id"`
		ExpectedRevision int64     `json:"expected_revision"`
	}{request.TargetScopeID, request.RuleID, request.ExpectedRevision})
	if err != nil {
		return RuleWriteResult{}, ErrUnavailable
	}
	return service.changeRule(ctx, actor, request.TargetScopeID, request.RuleID, request.ExpectedRevision,
		request.WriteMetadata, digest, "delete", func(rule *Rule) error {
			if rule.Deleted {
				return ErrConflict
			}
			rule.Enabled, rule.Deleted = false, true
			return nil
		})
}

func (service *Service) changeRule(
	ctx context.Context,
	actor Actor,
	targetScopeID, ruleID uuid.UUID,
	expectedRevision int64,
	metadata WriteMetadata,
	digest [32]byte,
	operation string,
	mutate func(*Rule) error,
) (RuleWriteResult, error) {
	if err := validateTarget(actor, targetScopeID); err != nil {
		return RuleWriteResult{}, err
	}
	if ruleID == uuid.Nil || expectedRevision < 1 || expectedRevision > maxSafeRevision ||
		!validWriteMetadata(metadata) || mutate == nil {
		return RuleWriteResult{}, ErrInvalidInput
	}
	apiOperation := "origin_auth.rule." + operation
	var result RuleWriteResult
	err := pgx.BeginFunc(ctx, service.pool, func(tx pgx.Tx) error {
		if _, err := service.authorizeTarget(ctx, tx, actor, targetScopeID, PermissionManage); err != nil {
			return err
		}
		write, err := service.claimWrite(ctx, tx, actor, targetScopeID, apiOperation, metadata, digest)
		if err != nil {
			return err
		}
		if write.found {
			if err := json.Unmarshal(write.responseBody, &result.Rule); err != nil {
				return ErrUnavailable
			}
			result.Replayed = true
			return nil
		}
		stored, err := loadRule(ctx, tx, targetScopeID, ruleID, true)
		if err != nil {
			return err
		}
		if err := requireSiteUnlocked(ctx, tx, actor, stored.SiteID); err != nil {
			return err
		}
		if stored.Revision != expectedRevision {
			return ErrRevisionConflict
		}
		result.Rule = stored
		if err := mutate(&result.Rule); err != nil {
			return err
		}
		if err := validateRuleConfig(&result.Rule.RuleConfig, service.egressPolicies); err != nil {
			return err
		}
		if err := validateSourceEndpoint(ctx, tx, result.Rule.SiteID, result.Rule.SourcePosition,
			result.Rule.Endpoint); err != nil {
			return err
		}
		now := storeTime(service.now())
		currentRef, previousRef, err := validateRuleCredentials(ctx, tx, targetScopeID,
			result.Rule.RuleConfig, result.Rule.Enabled && !result.Rule.Deleted, now)
		if err != nil {
			return err
		}
		if operation != "disable" && operation != "delete" {
			if err := service.checkEntitlement(ctx, tx, actor, targetScopeID, ruleID, metadata, apiOperation); err != nil {
				return err
			}
		}
		result.Rule.Revision++
		result.Rule.UpdatedAt = now
		if err := service.appendAudit(ctx, tx, actor, targetScopeID, ruleID, metadata,
			apiOperation, "origin_auth_rule", ruleAuditPayload(result.Rule)); err != nil {
			return err
		}
		if err := insertRuleRevision(ctx, tx, actor, result.Rule, operation, currentRef, previousRef, metadata); err != nil {
			return err
		}
		return service.completeWrite(ctx, tx, actor, apiOperation, metadata.IdempotencyKey,
			ruleID, 200, result.Rule)
	})
	if err != nil {
		return RuleWriteResult{}, normalizeServiceError(err)
	}
	return result, nil
}

func (service *Service) GetRule(ctx context.Context, actor Actor, targetScopeID, ruleID uuid.UUID) (Rule, error) {
	if err := validateTarget(actor, targetScopeID); err != nil {
		return Rule{}, err
	}
	if ruleID == uuid.Nil {
		return Rule{}, ErrInvalidInput
	}
	var rule Rule
	err := service.authorizedRead(ctx, actor, targetScopeID, PermissionRead, func(tx pgx.Tx) error {
		var err error
		rule, err = loadRule(ctx, tx, targetScopeID, ruleID, false)
		return err
	})
	if err != nil {
		return Rule{}, normalizeServiceError(err)
	}
	return rule, nil
}

func (service *Service) ListRules(ctx context.Context, actor Actor, filter RuleListFilter) (RuleList, error) {
	if err := validateTarget(actor, filter.TargetScopeID); err != nil {
		return RuleList{}, err
	}
	if filter.Limit < 1 || filter.Limit > 100 || len(filter.Cursor) > maxCursorBytes {
		return RuleList{}, ErrInvalidInput
	}
	cursor, err := decodeCursor(filter.Cursor)
	if err != nil {
		return RuleList{}, err
	}
	items := make([]Rule, 0, filter.Limit+1)
	err = service.authorizedRead(ctx, actor, filter.TargetScopeID, PermissionRead, func(tx pgx.Tx) error {
		rows, err := tx.Query(ctx, ruleSelect+`
			WHERE identity.tenant_scope_id=$1 AND ($2::uuid IS NULL OR identity.site_id=$2)
			  AND ($3::boolean IS NULL OR revision.enabled=$3)
			  AND ($4::timestamptz IS NULL OR (identity.created_at,identity.id) < ($4,$5))
			ORDER BY identity.created_at DESC,identity.id DESC LIMIT $6`, filter.TargetScopeID,
			nullableUUID(filter.SiteID), filter.Enabled, nullableCursorTime(cursor), nullableCursorID(cursor), filter.Limit+1)
		if err != nil {
			return err
		}
		defer rows.Close()
		for rows.Next() {
			item, err := scanRule(rows)
			if err != nil {
				return err
			}
			items = append(items, item)
		}
		return rows.Err()
	})
	if err != nil {
		return RuleList{}, normalizeServiceError(err)
	}
	result := RuleList{Items: items}
	if len(items) > filter.Limit {
		last := items[filter.Limit-1]
		result.Items = items[:filter.Limit]
		result.NextCursor, err = encodeCursor(pageCursor{CreatedAt: last.CreatedAt, ID: last.ID})
		if err != nil {
			return RuleList{}, ErrUnavailable
		}
	}
	return result, nil
}

type exactCredential struct {
	provider    string
	status      string
	revisionRef uuid.UUID
	notBefore   time.Time
	expiresAt   time.Time
}

func validateRuleCredentials(
	ctx context.Context,
	tx pgx.Tx,
	targetScopeID uuid.UUID,
	config RuleConfig,
	requireVerified bool,
	now time.Time,
) (uuid.UUID, *uuid.UUID, error) {
	current, err := loadExactCredential(ctx, tx, targetScopeID, config.CurrentCredential)
	if err != nil {
		return uuid.Nil, nil, err
	}
	if current.provider != config.Provider {
		return uuid.Nil, nil, ErrValidation
	}
	effectiveAt := now
	if config.ActivateCurrentAt != nil {
		effectiveAt = storeTime(*config.ActivateCurrentAt)
		if !effectiveAt.After(now) || effectiveAt.After(now.Add(30*24*time.Hour)) {
			return uuid.Nil, nil, ErrValidation
		}
	}
	if requireVerified && (current.status != StatusVerified || current.notBefore.After(effectiveAt) ||
		!current.expiresAt.After(effectiveAt.Add(time.Duration(config.SignatureTTLSeconds)*time.Second))) {
		return uuid.Nil, nil, ErrCredentialUnverified
	}
	var previousRef *uuid.UUID
	if config.PreviousCredential != nil {
		previous, err := loadExactCredential(ctx, tx, targetScopeID, *config.PreviousCredential)
		if err != nil {
			return uuid.Nil, nil, err
		}
		if previous.provider != config.Provider {
			return uuid.Nil, nil, ErrValidation
		}
		if requireVerified && (previous.status != StatusVerified || previous.notBefore.After(now) ||
			!previous.expiresAt.After(effectiveAt.Add(time.Duration(config.SignatureTTLSeconds)*time.Second))) {
			return uuid.Nil, nil, ErrCredentialUnverified
		}
		previousRef = &previous.revisionRef
	}
	return current.revisionRef, previousRef, nil
}

func loadExactCredential(
	ctx context.Context,
	tx pgx.Tx,
	targetScopeID uuid.UUID,
	reference CredentialReference,
) (exactCredential, error) {
	var result exactCredential
	err := tx.QueryRow(ctx, `SELECT identity.provider,revision.status,revision.revision_ref,
		revision.not_before,revision.expires_at
		FROM origin_auth_credentials identity
		JOIN origin_auth_credential_revisions revision ON revision.credential_id=identity.id
		WHERE identity.tenant_scope_id=$1 AND identity.id=$2 AND revision.revision=$3`,
		targetScopeID, reference.CredentialID, reference.Revision).Scan(
		&result.provider, &result.status, &result.revisionRef, &result.notBefore, &result.expiresAt)
	if errors.Is(err, pgx.ErrNoRows) {
		return exactCredential{}, ErrNotFound
	}
	return result, err
}

// FX31: rules of a site locked by a platform administrator are read-only for
// tenant actors.
func requireSiteUnlocked(ctx context.Context, tx pgx.Tx, actor Actor, siteID uuid.UUID) error {
	err := sitelock.RequireUnlocked(ctx, tx, actor.ScopeID, siteID)
	if errors.Is(err, sitelock.ErrLocked) {
		return ErrSiteLocked
	}
	return err
}

func authorizeSiteSource(ctx context.Context, tx pgx.Tx, targetScopeID, siteID uuid.UUID, sourcePosition int) error {
	var valid bool
	err := tx.QueryRow(ctx, `SELECT EXISTS(
		SELECT 1 FROM sites site JOIN site_origins source ON source.site_id=site.id
		WHERE site.scope_id=$1 AND site.id=$2 AND site.deleted_at IS NULL AND source.position=$3)`,
		targetScopeID, siteID, sourcePosition).Scan(&valid)
	if err != nil {
		return err
	}
	if !valid {
		return ErrNotFound
	}
	return nil
}

func validateSourceEndpoint(ctx context.Context, tx pgx.Tx, siteID uuid.UUID, sourcePosition int, endpoint string) error {
	var host, scheme string
	var port int
	err := tx.QueryRow(ctx, `SELECT origin.host,origin.port,pool.origin_scheme FROM site_origins origin
		JOIN site_origin_pools pool ON pool.site_id=origin.site_id
		WHERE origin.site_id=$1 AND origin.position=$2`,
		siteID, sourcePosition).Scan(&host, &port, &scheme)
	if errors.Is(err, pgx.ErrNoRows) {
		return ErrNotFound
	}
	if err != nil {
		return err
	}
	// The signature is computed for https://<host>: the edge must connect to
	// that bucket over HTTPS (a plain HTTP connection to 443 fails, to 80
	// sends the signed request in clear text).
	if port != 443 || scheme != "https" || endpoint != "https://"+host {
		return ErrValidation
	}
	return nil
}

const ruleSelect = `SELECT identity.id,identity.tenant_scope_id,identity.site_id,identity.source_position,
	revision.provider,revision.algorithm,revision.endpoint,revision.bucket,revision.path_prefix,
	revision.region,revision.service,revision.signature_ttl_seconds,COALESCE(revision.egress_policy_reference,''),
	revision.current_credential_id,revision.current_credential_revision,
	revision.previous_credential_id,revision.previous_credential_revision,revision.activate_current_at,
	revision.enabled,revision.deleted,revision.revision,identity.created_at,revision.created_at
	FROM origin_auth_rules identity
	JOIN LATERAL (SELECT * FROM origin_auth_rule_revisions current_revision
		WHERE current_revision.rule_id=identity.id ORDER BY current_revision.revision DESC LIMIT 1) revision ON true `

type rowScanner interface {
	Scan(...any) error
}

func scanRule(row rowScanner) (Rule, error) {
	var rule Rule
	var previousID *uuid.UUID
	var previousRevision *int64
	err := row.Scan(&rule.ID, &rule.TenantScopeID, &rule.SiteID, &rule.SourcePosition,
		&rule.Provider, &rule.Algorithm, &rule.Endpoint, &rule.Bucket, &rule.PathPrefix,
		&rule.Region, &rule.Service, &rule.SignatureTTLSeconds, &rule.EgressPolicyReference,
		&rule.CurrentCredential.CredentialID, &rule.CurrentCredential.Revision,
		&previousID, &previousRevision, &rule.ActivateCurrentAt, &rule.Enabled, &rule.Deleted,
		&rule.Revision, &rule.CreatedAt, &rule.UpdatedAt)
	if err != nil {
		return Rule{}, err
	}
	if previousID != nil && previousRevision != nil {
		rule.PreviousCredential = &CredentialReference{CredentialID: *previousID, Revision: *previousRevision}
	}
	return rule, nil
}

type ruleQueryer interface {
	QueryRow(context.Context, string, ...any) pgx.Row
}

func loadRule(ctx context.Context, database ruleQueryer, targetScopeID, ruleID uuid.UUID, lock bool) (Rule, error) {
	locking := ""
	if lock {
		locking = " FOR UPDATE OF identity"
	}
	rule, err := scanRule(database.QueryRow(ctx, ruleSelect+`
		WHERE identity.tenant_scope_id=$1 AND identity.id=$2`+locking, targetScopeID, ruleID))
	if errors.Is(err, pgx.ErrNoRows) {
		return Rule{}, ErrNotFound
	}
	return rule, err
}

func insertRuleRevision(
	ctx context.Context,
	tx pgx.Tx,
	actor Actor,
	rule Rule,
	operation string,
	currentRef uuid.UUID,
	previousRef *uuid.UUID,
	metadata WriteMetadata,
) error {
	var previousID any
	var previousRevision any
	if rule.PreviousCredential != nil {
		previousID, previousRevision = rule.PreviousCredential.CredentialID, rule.PreviousCredential.Revision
	}
	_, err := tx.Exec(ctx, `INSERT INTO origin_auth_rule_revisions(
		rule_id,revision,operation,provider,algorithm,endpoint,bucket,path_prefix,region,service,
		signature_ttl_seconds,egress_policy_reference,current_credential_id,current_credential_revision,
		current_credential_revision_ref,previous_credential_id,previous_credential_revision,
		previous_credential_revision_ref,activate_current_at,enabled,deleted,created_by_scope_id,
		created_by_user_id,request_id,trace_id,created_at)
		VALUES($1,$2,$3,$4,$5,$6,$7,$8,$9,$10,$11,$12,$13,$14,$15,$16,$17,$18,$19,$20,$21,$22,$23,$24,$25,$26)`,
		rule.ID, rule.Revision, operation, rule.Provider, rule.Algorithm, rule.Endpoint, rule.Bucket,
		rule.PathPrefix, rule.Region, rule.Service, rule.SignatureTTLSeconds,
		nullableText(rule.EgressPolicyReference), rule.CurrentCredential.CredentialID,
		rule.CurrentCredential.Revision, currentRef, previousID, previousRevision, previousRef,
		rule.ActivateCurrentAt, rule.Enabled, rule.Deleted, actor.ScopeID, actor.UserID,
		metadata.RequestID, metadata.TraceID, rule.UpdatedAt)
	return err
}

func ruleAuditPayload(rule Rule) map[string]any {
	return map[string]any{
		"revision": rule.Revision, "site_id": rule.SiteID.String(), "source_position": rule.SourcePosition,
		"provider": rule.Provider, "enabled": rule.Enabled, "deleted": rule.Deleted,
	}
}

func sameCredentialReference(left, right *CredentialReference) bool {
	if left == nil || right == nil {
		return left == nil && right == nil
	}
	return *left == *right
}

func sameTime(left, right *time.Time) bool {
	if left == nil || right == nil {
		return left == nil && right == nil
	}
	return left.Equal(*right)
}

func nullableText(value string) any {
	if value == "" {
		return nil
	}
	return value
}

func nullableUUID(value uuid.UUID) any {
	if value == uuid.Nil {
		return nil
	}
	return value
}
