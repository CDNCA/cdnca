package impersonation

import (
	"bytes"
	"context"
	"crypto/sha256"
	"crypto/subtle"
	"encoding/json"
	"errors"
	"fmt"
	"regexp"
	"sort"
	"strings"
	"time"

	"github.com/cdnca/cdnca/services/control-api/internal/audit"
	"github.com/cdnca/cdnca/services/control-api/internal/iamlock/protocol"
	"github.com/cdnca/cdnca/services/control-api/internal/iamstage2b"
	"github.com/google/uuid"
	"github.com/jackc/pgx/v5"
	"github.com/jackc/pgx/v5/pgxpool"
)

const (
	actionCreate   = "identity.impersonation.create"
	actionExchange = "identity.impersonation.exchange"
	actionUse      = "identity.impersonation.use"
	actionRevoke   = "identity.impersonation.revoke"
	actionExpire   = "identity.impersonation.expire"
)

var idempotencyPattern = regexp.MustCompile(`^[A-Za-z0-9][A-Za-z0-9._-]{0,127}$`)

type Service struct {
	pool    *pgxpool.Pool
	auditor AuditAppender
	now     Clock
	codeKey []byte
}

func NewService(pool *pgxpool.Pool, codeKey []byte) (*Service, error) {
	return NewServiceWithDependencies(pool, codeKey, audit.New(pool), time.Now)
}

func NewServiceWithDependencies(
	pool *pgxpool.Pool,
	codeKey []byte,
	auditor AuditAppender,
	now Clock,
) (*Service, error) {
	if pool == nil || auditor == nil || now == nil || validateCodeKey(codeKey) != nil {
		return nil, ErrInvalidStore
	}
	return &Service{
		pool: pool, auditor: auditor, now: now,
		codeKey: append([]byte(nil), codeKey...),
	}, nil
}

func (s *Service) Create(ctx context.Context, actor Actor, request CreateRequest) (CreateResult, error) {
	if !validIDs(request.TenantID, request.TenantScopeID, request.SubjectUserID) ||
		!validMetadata(request.Context) || !validIdempotencyKey(request.IdempotencyKey) {
		return CreateResult{}, ErrInvalidInput
	}
	now := storeTime(s.now())
	digest := createPayloadDigest(actor, request)

	var result CreateResult
	var outcome error
	err := pgx.BeginTxFunc(ctx, s.pool, pgx.TxOptions{IsoLevel: pgx.ReadCommitted}, func(tx pgx.Tx) error {
		if err := validatePrimaryActor(actor); err != nil {
			outcome = err
			return s.appendAudit(ctx, tx, request.TenantScopeID, actor.UserID, request.SubjectUserID,
				uuid.Nil, request.Context, actionCreate, "denied", errorCode(err), "")
		}
		if request.SubjectUserID == actor.UserID {
			outcome = ErrPermissionDenied
			return s.appendAudit(ctx, tx, request.TenantScopeID, actor.UserID, request.SubjectUserID,
				uuid.Nil, request.Context, actionCreate, "denied", errorCode(outcome), "")
		}
		if _, err := iamstage2b.BeginAuthorityMutation(ctx, tx,
			iamstage2b.OperationImpersonationCreate,
			[]uuid.UUID{actor.ScopeID, request.TenantScopeID}); err != nil {
			return err
		}
		actorState, err := loadActor(ctx, tx, actor.ScopeID, actor.UserID)
		if err != nil && !errors.Is(err, pgx.ErrNoRows) {
			return err
		}
		if errors.Is(err, pgx.ErrNoRows) || !actorState.canImpersonate() {
			outcome = ErrPermissionDenied
			return s.appendAudit(ctx, tx, request.TenantScopeID, actor.UserID, request.SubjectUserID,
				uuid.Nil, request.Context, actionCreate, "denied", errorCode(outcome), "")
		}
		if active, err := primaryAuthSessionActive(ctx, tx, actor, now); err != nil {
			return err
		} else if !active {
			outcome = ErrPermissionDenied
			return s.appendAudit(ctx, tx, request.TenantScopeID, actor.UserID, request.SubjectUserID,
				uuid.Nil, request.Context, actionCreate, "denied", errorCode(outcome), "")
		}
		target, err := loadTarget(ctx, tx, request.TenantID, request.TenantScopeID, request.SubjectUserID)
		if err != nil && !errors.Is(err, pgx.ErrNoRows) {
			return err
		}
		if errors.Is(err, pgx.ErrNoRows) || !target.active() || !safeTargetPermissions(target.permissions) {
			outcome = ErrPrincipalChanged
			return s.appendAudit(ctx, tx, request.TenantScopeID, actor.UserID, request.SubjectUserID,
				uuid.Nil, request.Context, actionCreate, "denied", errorCode(outcome), "")
		}
		if !actorState.mayTarget(target) {
			// RS-07: a reseller switches only to its own customers. The denial
			// is audited in the reseller's scope too, since the target is not
			// one of its own.
			outcome = ErrPermissionDenied
			if err := s.appendAudit(ctx, tx, actor.ScopeID, actor.UserID, request.SubjectUserID,
				uuid.Nil, request.Context, actionCreate, "denied", errorCode(outcome), ""); err != nil {
				return err
			}
			return s.appendAudit(ctx, tx, request.TenantScopeID, actor.UserID, request.SubjectUserID,
				uuid.Nil, request.Context, actionCreate, "denied", errorCode(outcome), "")
		}

		if err := lockIdempotency(ctx, tx, actionCreate, actor.ScopeID, actor.UserID, request.IdempotencyKey); err != nil {
			return err
		}
		existing, found, err := loadGrantByIdempotency(ctx, tx, actor, request.IdempotencyKey)
		if err != nil {
			return err
		}
		if found {
			if !bytes.Equal(existing.requestDigest, digest[:]) {
				outcome = ErrIdempotencyConflict
				return s.appendAudit(ctx, tx, request.TenantScopeID, actor.UserID, request.SubjectUserID,
					existing.ID, request.Context, actionCreate, "denied", errorCode(outcome), "")
			}
			if revoked, err := grantRevoked(ctx, tx, existing.ID); err != nil {
				return err
			} else if revoked {
				outcome = ErrGrantRevoked
				return s.appendAudit(ctx, tx, existing.TenantScopeID, actor.UserID, existing.SubjectUserID,
					existing.ID, request.Context, actionCreate, "denied", errorCode(outcome), "")
			}
			if !now.Before(existing.ExpiresAt) {
				outcome = ErrGrantExpired
				return s.appendAudit(ctx, tx, existing.TenantScopeID, actor.UserID, existing.SubjectUserID,
					existing.ID, request.Context, actionExpire, "denied", errorCode(outcome), "grant")
			}
			if consumed, err := grantConsumed(ctx, tx, existing.ID); err != nil {
				return err
			} else if consumed {
				outcome = ErrCodeReplay
				return s.appendAudit(ctx, tx, existing.TenantScopeID, actor.UserID, existing.SubjectUserID,
					existing.ID, request.Context, actionCreate, "denied", errorCode(outcome), "")
			}
			result = CreateResult{
				Grant:             existing.Grant,
				AuthorizationCode: authorizationCode(existing.ID, s.codeKey),
				Replayed:          true,
			}
			return nil
		}

		grantID, err := uuid.NewV7()
		if err != nil {
			return fmt.Errorf("generate impersonation grant ID: %w", err)
		}
		code := authorizationCode(grantID, s.codeKey)
		storedCodeDigest := codeDigest(code)
		targetDigest := permissionsDigest(target.permissions)
		grant := Grant{
			ID: grantID, TenantID: request.TenantID, TenantScopeID: request.TenantScopeID,
			ActorUserID: actor.UserID, ActorScopeID: actor.ScopeID, SubjectUserID: request.SubjectUserID,
			CreatedAt: now, ExpiresAt: now.Add(CodeTTL),
		}
		_, err = tx.Exec(ctx, `INSERT INTO admin_impersonation_grants (
			id,tenant_id,tenant_scope_id,actor_user_id,actor_scope_id,subject_user_id,
			primary_auth_session_id,code_digest,subject_permissions_digest,reason,idempotency_key,
			request_digest,request_id,trace_id,created_at,expires_at
		) VALUES($1,$2,$3,$4,$5,$6,$7,$8,$9,$10,$11,$12,$13,$14,$15,$16)`,
			grant.ID, grant.TenantID, grant.TenantScopeID, grant.ActorUserID, grant.ActorScopeID,
			grant.SubjectUserID, actor.PrimaryAuthSessionID, storedCodeDigest[:], targetDigest[:],
			SwitchReason, request.IdempotencyKey, digest[:], request.Context.RequestID, request.Context.TraceID,
			grant.CreatedAt, grant.ExpiresAt)
		if err != nil {
			return err
		}
		if err := s.appendAudit(ctx, tx, grant.TenantScopeID, grant.ActorUserID, grant.SubjectUserID,
			grant.ID, request.Context, actionCreate, "success", "", ""); err != nil {
			return err
		}
		if actorState.scopeKind == "tenant" {
			// ADR 0018 §7: a reseller's switch is recorded in its own scope as well.
			if err := s.appendAudit(ctx, tx, actor.ScopeID, grant.ActorUserID, grant.SubjectUserID,
				grant.ID, request.Context, actionCreate, "success", "", ""); err != nil {
				return err
			}
		}
		result = CreateResult{Grant: grant, AuthorizationCode: code}
		return nil
	})
	if err != nil {
		return CreateResult{}, fmt.Errorf("create impersonation grant: %w", err)
	}
	if outcome != nil {
		return CreateResult{}, outcome
	}
	return result, nil
}

func (s *Service) Exchange(ctx context.Context, request ExchangeRequest) (Session, error) {
	if !validIDs(request.TenantID, request.TenantScopeID) || !validMetadata(request.Context) ||
		!validIdempotencyKey(request.IdempotencyKey) || len(request.AuthorizationCode) > 256 {
		return Session{}, ErrInvalidInput
	}
	grantID, parseErr := parseAuthorizationCode(request.AuthorizationCode, s.codeKey)
	requestCodeDigest := codeDigest(request.AuthorizationCode)
	digest := digestValue(struct {
		TenantID      uuid.UUID `json:"tenant_id"`
		TenantScopeID uuid.UUID `json:"tenant_scope_id"`
		GrantID       uuid.UUID `json:"grant_id"`
		CodeDigest    [32]byte  `json:"code_digest"`
	}{request.TenantID, request.TenantScopeID, grantID, requestCodeDigest})
	now := storeTime(s.now())

	var result Session
	var outcome error
	err := pgx.BeginTxFunc(ctx, s.pool, pgx.TxOptions{IsoLevel: pgx.ReadCommitted}, func(tx pgx.Tx) error {
		if parseErr != nil {
			outcome = ErrInvalidCode
			return s.appendAudit(ctx, tx, request.TenantScopeID, uuid.Nil, uuid.Nil, uuid.Nil,
				request.Context, actionExchange, "denied", errorCode(outcome), "")
		}
		grant, err := loadGrant(ctx, tx, request.TenantID, request.TenantScopeID, grantID)
		if err != nil && !errors.Is(err, pgx.ErrNoRows) {
			return err
		}
		if errors.Is(err, pgx.ErrNoRows) || subtleDigestMismatch(grant.codeDigest, requestCodeDigest[:]) {
			outcome = ErrInvalidCode
			return s.appendAudit(ctx, tx, request.TenantScopeID, uuid.Nil, uuid.Nil, grantID,
				request.Context, actionExchange, "denied", errorCode(outcome), "")
		}
		if _, err := iamstage2b.BeginAuthorityMutation(ctx, tx,
			iamstage2b.OperationImpersonationExchange,
			[]uuid.UUID{grant.ActorScopeID, grant.TenantScopeID}); err != nil {
			return err
		}
		origin := Actor{UserID: grant.ActorUserID, ScopeID: grant.ActorScopeID,
			PrimaryAuthSessionID: grant.primaryAuthSessionID}
		if active, err := primaryAuthSessionActive(ctx, tx, origin, now); err != nil {
			return err
		} else if !active {
			outcome = ErrPrincipalChanged
			return s.appendAudit(ctx, tx, grant.TenantScopeID, grant.ActorUserID, grant.SubjectUserID,
				grant.ID, request.Context, actionExchange, "denied", errorCode(outcome), "")
		}
		grant, err = lockGrant(ctx, tx, request.TenantID, request.TenantScopeID, grantID)
		if err != nil {
			return err
		}
		if subtleDigestMismatch(grant.codeDigest, requestCodeDigest[:]) {
			outcome = ErrInvalidCode
			return s.appendAudit(ctx, tx, request.TenantScopeID, uuid.Nil, uuid.Nil, grantID,
				request.Context, actionExchange, "denied", errorCode(outcome), "")
		}

		if err := lockIdempotency(ctx, tx, actionExchange, request.TenantScopeID, uuid.Nil, request.IdempotencyKey); err != nil {
			return err
		}
		existing, found, err := loadSessionByIdempotency(ctx, tx, request.TenantScopeID, request.IdempotencyKey)
		if err != nil {
			return err
		}
		if found {
			if existing.GrantID != grant.ID || !bytes.Equal(existing.requestDigest, digest[:]) {
				outcome = ErrIdempotencyConflict
				return s.appendAudit(ctx, tx, grant.TenantScopeID, grant.ActorUserID, grant.SubjectUserID,
					grant.ID, request.Context, actionExchange, "denied", errorCode(outcome), "")
			}
		}
		if revoked, err := grantRevoked(ctx, tx, grant.ID); err != nil {
			return err
		} else if revoked {
			outcome = ErrGrantRevoked
			return s.appendAudit(ctx, tx, grant.TenantScopeID, grant.ActorUserID, grant.SubjectUserID,
				grant.ID, request.Context, actionExchange, "denied", errorCode(outcome), "")
		}
		if !now.Before(grant.ExpiresAt) {
			outcome = ErrGrantExpired
			return s.appendAudit(ctx, tx, grant.TenantScopeID, grant.ActorUserID, grant.SubjectUserID,
				grant.ID, request.Context, actionExpire, "denied", errorCode(outcome), "grant")
		}
		if consumed, err := grantConsumed(ctx, tx, grant.ID); err != nil {
			return err
		} else if consumed && !found {
			outcome = ErrCodeReplay
			return s.appendAudit(ctx, tx, grant.TenantScopeID, grant.ActorUserID, grant.SubjectUserID,
				grant.ID, request.Context, actionExchange, "denied", errorCode(outcome), "")
		}
		actorState, actorErr := loadActor(ctx, tx, grant.ActorScopeID, grant.ActorUserID)
		target, targetErr := loadTarget(ctx, tx, grant.TenantID, grant.TenantScopeID, grant.SubjectUserID)
		if actorErr != nil && !errors.Is(actorErr, pgx.ErrNoRows) {
			return actorErr
		}
		if targetErr != nil && !errors.Is(targetErr, pgx.ErrNoRows) {
			return targetErr
		}
		currentTargetDigest := permissionsDigest(target.permissions)
		if actorErr != nil || !actorState.canImpersonate() || targetErr != nil || !target.active() ||
			!safeTargetPermissions(target.permissions) || !actorState.mayTarget(target) ||
			!bytes.Equal(grant.subjectPermissionsDigest, currentTargetDigest[:]) {
			outcome = ErrPrincipalChanged
			return s.appendAudit(ctx, tx, grant.TenantScopeID, grant.ActorUserID, grant.SubjectUserID,
				grant.ID, request.Context, actionExchange, "denied", errorCode(outcome), "")
		}
		if found {
			if !now.Before(existing.ExpiresAt) {
				outcome = ErrSessionExpired
				return s.appendAudit(ctx, tx, grant.TenantScopeID, grant.ActorUserID, grant.SubjectUserID,
					grant.ID, request.Context, actionExpire, "denied", errorCode(outcome), "session")
			}
			result, err = s.sessionWithBanner(ctx, tx, existing.Session)
			if err != nil {
				return err
			}
			result.Replayed = true
			return nil
		}

		sessionID, err := uuid.NewV7()
		if err != nil {
			return fmt.Errorf("generate impersonation session ID: %w", err)
		}
		result = Session{
			ID: sessionID, GrantID: grant.ID, ActorUserID: grant.ActorUserID,
			ActorScopeID: grant.ActorScopeID, SubjectUserID: grant.SubjectUserID,
			TenantID: grant.TenantID, TenantScopeID: grant.TenantScopeID,
			CreatedAt: now, ExpiresAt: now.Add(SessionTTL), Refreshable: false,
		}
		_, err = tx.Exec(ctx, `INSERT INTO admin_impersonation_sessions (
			id,grant_id,tenant_id,tenant_scope_id,actor_user_id,actor_scope_id,subject_user_id,
			subject_permissions_digest,exchange_idempotency_key,exchange_request_digest,
			request_id,trace_id,created_at,expires_at
		) VALUES($1,$2,$3,$4,$5,$6,$7,$8,$9,$10,$11,$12,$13,$14)`, result.ID,
			result.GrantID, result.TenantID, result.TenantScopeID, result.ActorUserID,
			result.ActorScopeID, result.SubjectUserID, currentTargetDigest[:], request.IdempotencyKey,
			digest[:], request.Context.RequestID, request.Context.TraceID, result.CreatedAt, result.ExpiresAt)
		if err != nil {
			return err
		}
		result.Banner = BannerClaims{
			GrantID: grant.ID, ActorUserID: grant.ActorUserID, ActorDisplayName: actorState.displayName,
			SubjectUserID: grant.SubjectUserID, SubjectDisplayName: target.displayName,
			TenantID: grant.TenantID, ExpiresAt: result.ExpiresAt,
		}
		result.Principal = target.principal(result.SubjectUserID, result.TenantID, result.TenantScopeID)
		return s.appendAudit(ctx, tx, grant.TenantScopeID, grant.ActorUserID, grant.SubjectUserID,
			grant.ID, request.Context, actionExchange, "success", "", "")
	})
	if err != nil {
		return Session{}, fmt.Errorf("exchange impersonation authorization code: %w", err)
	}
	if outcome != nil {
		return Session{}, outcome
	}
	return result, nil
}

func (s *Service) Authorize(ctx context.Context, request UseRequest) (EffectiveIdentity, error) {
	if !validIDs(request.Session.ID, request.Session.GrantID, request.Session.ActorUserID,
		request.Session.ActorScopeID, request.Session.SubjectUserID, request.Session.TenantID,
		request.Session.TenantScopeID) ||
		!validMetadata(request.Context) || !validAction(request.Action) {
		return EffectiveIdentity{}, ErrInvalidInput
	}
	now := storeTime(s.now())
	var result EffectiveIdentity
	var outcome error
	err := pgx.BeginTxFunc(ctx, s.pool, pgx.TxOptions{IsoLevel: pgx.ReadCommitted}, func(tx pgx.Tx) error {
		grant, err := loadGrant(ctx, tx, request.Session.TenantID, request.Session.TenantScopeID,
			request.Session.GrantID)
		if err != nil && !errors.Is(err, pgx.ErrNoRows) {
			return err
		}
		if errors.Is(err, pgx.ErrNoRows) {
			outcome = ErrPrincipalChanged
			return s.appendAudit(ctx, tx, request.Session.TenantScopeID, request.Session.ActorUserID,
				request.Session.SubjectUserID, request.Session.GrantID, request.Context,
				actionUse, "denied", errorCode(outcome), request.Action)
		}
		if err := protocol.AcquireShared(ctx, tx); err != nil {
			return err
		}
		if _, err := protocol.AcquireScopes(ctx, tx,
			[]uuid.UUID{grant.ActorScopeID, grant.TenantScopeID}); err != nil {
			return err
		}
		origin := Actor{UserID: grant.ActorUserID, ScopeID: grant.ActorScopeID,
			PrimaryAuthSessionID: grant.primaryAuthSessionID}
		if active, err := primaryAuthSessionActive(ctx, tx, origin, now); err != nil {
			return err
		} else if !active {
			outcome = ErrPrincipalChanged
			return s.appendAudit(ctx, tx, grant.TenantScopeID, grant.ActorUserID, grant.SubjectUserID,
				grant.ID, request.Context, actionUse, "denied", errorCode(outcome), request.Action)
		}
		stored, storedDigest, err := lockSession(ctx, tx, request.Session.ID, request.Session.GrantID)
		if err != nil && !errors.Is(err, pgx.ErrNoRows) {
			return err
		}
		if errors.Is(err, pgx.ErrNoRows) || !sameSessionIdentity(stored, request.Session) {
			outcome = ErrPrincipalChanged
			return s.appendAudit(ctx, tx, request.Session.TenantScopeID, request.Session.ActorUserID,
				request.Session.SubjectUserID, request.Session.GrantID, request.Context,
				actionUse, "denied", errorCode(outcome), request.Action)
		}
		if revoked, err := grantRevoked(ctx, tx, stored.GrantID); err != nil {
			return err
		} else if revoked {
			outcome = ErrSessionRevoked
			return s.appendAudit(ctx, tx, stored.TenantScopeID, stored.ActorUserID, stored.SubjectUserID,
				stored.GrantID, request.Context, actionUse, "denied", errorCode(outcome), request.Action)
		}
		if !now.Before(stored.ExpiresAt) {
			outcome = ErrSessionExpired
			return s.appendAudit(ctx, tx, stored.TenantScopeID, stored.ActorUserID, stored.SubjectUserID,
				stored.GrantID, request.Context, actionExpire, "denied", errorCode(outcome), "session")
		}
		actorState, actorErr := loadActor(ctx, tx, stored.ActorScopeID, stored.ActorUserID)
		target, targetErr := loadTarget(ctx, tx, stored.TenantID, stored.TenantScopeID, stored.SubjectUserID)
		if actorErr != nil && !errors.Is(actorErr, pgx.ErrNoRows) {
			return actorErr
		}
		if targetErr != nil && !errors.Is(targetErr, pgx.ErrNoRows) {
			return targetErr
		}
		currentDigest := permissionsDigest(target.permissions)
		if actorErr != nil || !actorState.canImpersonate() || targetErr != nil || !target.active() ||
			!safeTargetPermissions(target.permissions) || !actorState.mayTarget(target) ||
			!bytes.Equal(storedDigest, currentDigest[:]) {
			outcome = ErrPrincipalChanged
			return s.appendAudit(ctx, tx, stored.TenantScopeID, stored.ActorUserID, stored.SubjectUserID,
				stored.GrantID, request.Context, actionUse, "denied", errorCode(outcome), request.Action)
		}
		if SensitiveAction(request.Action) {
			outcome = ErrSensitiveAction
			return s.appendAudit(ctx, tx, stored.TenantScopeID, stored.ActorUserID, stored.SubjectUserID,
				stored.GrantID, request.Context, actionUse, "denied", errorCode(outcome), request.Action)
		}
		stored.Banner = BannerClaims{
			GrantID: stored.GrantID, ActorUserID: stored.ActorUserID, ActorDisplayName: actorState.displayName,
			SubjectUserID: stored.SubjectUserID, SubjectDisplayName: target.displayName,
			TenantID: stored.TenantID, ExpiresAt: stored.ExpiresAt,
		}
		stored.Principal = target.principal(stored.SubjectUserID, stored.TenantID, stored.TenantScopeID)
		result = EffectiveIdentity{Session: stored, Permissions: append([]string(nil), target.permissions...)}
		return s.appendAudit(ctx, tx, stored.TenantScopeID, stored.ActorUserID, stored.SubjectUserID,
			stored.GrantID, request.Context, actionUse, "success", "", request.Action)
	})
	if err != nil {
		return EffectiveIdentity{}, fmt.Errorf("authorize impersonation session: %w", err)
	}
	if outcome != nil {
		return EffectiveIdentity{}, outcome
	}
	return result, nil
}

func (s *Service) Revoke(ctx context.Context, actor Actor, request RevokeRequest) (Revocation, error) {
	if !validIDs(request.GrantID, request.TenantID, request.TenantScopeID) ||
		!validMetadata(request.Context) || !validIdempotencyKey(request.IdempotencyKey) ||
		!validText(request.Reason, 1, 512) {
		return Revocation{}, ErrInvalidInput
	}
	digest := digestValue(struct {
		GrantID       uuid.UUID `json:"grant_id"`
		TenantID      uuid.UUID `json:"tenant_id"`
		TenantScopeID uuid.UUID `json:"tenant_scope_id"`
		Reason        string    `json:"reason"`
	}{request.GrantID, request.TenantID, request.TenantScopeID, request.Reason})
	now := storeTime(s.now())
	var result Revocation
	var outcome error
	err := pgx.BeginTxFunc(ctx, s.pool, pgx.TxOptions{IsoLevel: pgx.ReadCommitted}, func(tx pgx.Tx) error {
		if err := validatePrimaryActor(actor); err != nil {
			outcome = err
			return s.appendAudit(ctx, tx, request.TenantScopeID, actor.UserID, uuid.Nil, request.GrantID,
				request.Context, actionRevoke, "denied", errorCode(outcome), "")
		}
		if _, err := iamstage2b.BeginAuthorityMutation(ctx, tx,
			iamstage2b.OperationImpersonationRevoke,
			[]uuid.UUID{actor.ScopeID, request.TenantScopeID}); err != nil {
			return err
		}
		actorState, err := loadActor(ctx, tx, actor.ScopeID, actor.UserID)
		if err != nil && !errors.Is(err, pgx.ErrNoRows) {
			return err
		}
		if errors.Is(err, pgx.ErrNoRows) || !actorState.canImpersonate() {
			outcome = ErrPermissionDenied
			return s.appendAudit(ctx, tx, request.TenantScopeID, actor.UserID, uuid.Nil, request.GrantID,
				request.Context, actionRevoke, "denied", errorCode(outcome), "")
		}
		if active, err := primaryAuthSessionActive(ctx, tx, actor, now); err != nil {
			return err
		} else if !active {
			outcome = ErrPermissionDenied
			return s.appendAudit(ctx, tx, request.TenantScopeID, actor.UserID, uuid.Nil, request.GrantID,
				request.Context, actionRevoke, "denied", errorCode(outcome), "")
		}
		grant, err := lockGrant(ctx, tx, request.TenantID, request.TenantScopeID, request.GrantID)
		if err != nil && !errors.Is(err, pgx.ErrNoRows) {
			return err
		}
		if errors.Is(err, pgx.ErrNoRows) {
			outcome = ErrInvalidInput
			return s.appendAudit(ctx, tx, request.TenantScopeID, actor.UserID, uuid.Nil, request.GrantID,
				request.Context, actionRevoke, "denied", errorCode(outcome), "")
		}
		if actorState.scopeKind != "platform" && grant.ActorScopeID != actor.ScopeID {
			// A reseller ends only the switches it started (migration 482).
			outcome = ErrPermissionDenied
			return s.appendAudit(ctx, tx, request.TenantScopeID, actor.UserID, uuid.Nil, request.GrantID,
				request.Context, actionRevoke, "denied", errorCode(outcome), "")
		}
		if err := lockIdempotency(ctx, tx, actionRevoke, actor.ScopeID, actor.UserID, request.IdempotencyKey); err != nil {
			return err
		}
		existing, found, err := loadRevocationByIdempotency(ctx, tx, actor, request.IdempotencyKey)
		if err != nil {
			return err
		}
		if found {
			if existing.GrantID != grant.ID || !bytes.Equal(existing.requestDigest, digest[:]) {
				outcome = ErrIdempotencyConflict
				return s.appendAudit(ctx, tx, grant.TenantScopeID, actor.UserID, grant.SubjectUserID,
					grant.ID, request.Context, actionRevoke, "denied", errorCode(outcome), "")
			}
			result = existing.Revocation
			result.Replayed = true
			return revokeDelegateSessions(ctx, tx, grant.ID, now)
		}
		if existing, found, err := loadRevocationByGrant(ctx, tx, grant.ID); err != nil {
			return err
		} else if found {
			result = existing.Revocation
			result.Replayed = true
			return revokeDelegateSessions(ctx, tx, grant.ID, now)
		}
		revocationID, err := uuid.NewV7()
		if err != nil {
			return fmt.Errorf("generate impersonation revocation ID: %w", err)
		}
		result = Revocation{ID: revocationID, GrantID: grant.ID, RevokedBy: actor.UserID,
			Reason: request.Reason, RevokedAt: now}
		_, err = tx.Exec(ctx, `INSERT INTO admin_impersonation_revocations (
			id,grant_id,tenant_id,tenant_scope_id,original_actor_user_id,original_actor_scope_id,
			subject_user_id,revoked_by_user_id,revoked_by_scope_id,reason,idempotency_key,
			request_digest,request_id,trace_id,revoked_at
		) VALUES($1,$2,$3,$4,$5,$6,$7,$8,$9,$10,$11,$12,$13,$14,$15)`,
			result.ID, grant.ID, grant.TenantID, grant.TenantScopeID, grant.ActorUserID,
			grant.ActorScopeID, grant.SubjectUserID, actor.UserID, actor.ScopeID, request.Reason,
			request.IdempotencyKey, digest[:], request.Context.RequestID, request.Context.TraceID, now)
		if err != nil {
			return err
		}
		if err := revokeDelegateSessions(ctx, tx, grant.ID, now); err != nil {
			return err
		}
		return s.appendAudit(ctx, tx, grant.TenantScopeID, actor.UserID, grant.SubjectUserID,
			grant.ID, request.Context, actionRevoke, "success", "", "")
	})
	if err != nil {
		return Revocation{}, fmt.Errorf("revoke impersonation grant: %w", err)
	}
	if outcome != nil {
		return Revocation{}, outcome
	}
	return result, nil
}

// EndSession ends the impersonation carried by a verified session credential
// when the browser signs out while still impersonating (fix-pre1035, user
// 10-27: leaving must end it at once, not after SessionTTL). The revocation is
// recorded as made by the original actor. A session that can no longer be used
// (expired, or the actor lost the right to impersonate) gets no revocation
// row, but its delegate session row is revoked all the same. Idempotent.
func (s *Service) EndSession(ctx context.Context, request EndSessionRequest) error {
	session := request.Session
	if !validIDs(session.ID, session.GrantID, session.ActorUserID, session.ActorScopeID,
		session.SubjectUserID, session.TenantID, session.TenantScopeID) ||
		!validMetadata(request.Context) || !validText(request.Reason, 1, 512) {
		return ErrInvalidInput
	}
	now := storeTime(s.now())
	var outcome error
	err := pgx.BeginTxFunc(ctx, s.pool, pgx.TxOptions{IsoLevel: pgx.ReadCommitted}, func(tx pgx.Tx) error {
		if _, err := iamstage2b.BeginAuthorityMutation(ctx, tx, iamstage2b.OperationImpersonationRevoke,
			[]uuid.UUID{session.ActorScopeID, session.TenantScopeID}); err != nil {
			return err
		}
		stored, _, err := lockSession(ctx, tx, session.ID, session.GrantID)
		if err != nil && !errors.Is(err, pgx.ErrNoRows) {
			return err
		}
		if errors.Is(err, pgx.ErrNoRows) || !sameSessionIdentity(stored, session) {
			outcome = ErrPrincipalChanged
			return nil
		}
		if err := revokeDelegateSessions(ctx, tx, stored.GrantID, now); err != nil {
			return err
		}
		if revoked, err := grantRevoked(ctx, tx, stored.GrantID); err != nil || revoked {
			return err
		}
		actorState, err := loadActor(ctx, tx, stored.ActorScopeID, stored.ActorUserID)
		if err != nil && !errors.Is(err, pgx.ErrNoRows) {
			return err
		}
		if err != nil || !actorState.canImpersonate() || !now.Before(stored.ExpiresAt) {
			return nil
		}
		revocationID, err := uuid.NewV7()
		if err != nil {
			return fmt.Errorf("generate impersonation revocation ID: %w", err)
		}
		digest := digestValue(struct {
			SessionID uuid.UUID `json:"session_id"`
			Reason    string    `json:"reason"`
		}{stored.ID, request.Reason})
		if _, err := tx.Exec(ctx, `INSERT INTO admin_impersonation_revocations (
			id,grant_id,tenant_id,tenant_scope_id,original_actor_user_id,original_actor_scope_id,
			subject_user_id,revoked_by_user_id,revoked_by_scope_id,reason,idempotency_key,
			request_digest,request_id,trace_id,revoked_at
		) VALUES($1,$2,$3,$4,$5,$6,$7,$5,$6,$8,$9,$10,$11,$12,$13)`,
			revocationID, stored.GrantID, stored.TenantID, stored.TenantScopeID, stored.ActorUserID,
			stored.ActorScopeID, stored.SubjectUserID, request.Reason, "session-end-"+stored.ID.String(),
			digest[:], request.Context.RequestID, request.Context.TraceID, now); err != nil {
			return err
		}
		return s.appendAudit(ctx, tx, stored.TenantScopeID, stored.ActorUserID, stored.SubjectUserID,
			stored.GrantID, request.Context, actionRevoke, "success", "", "")
	})
	if err != nil {
		return fmt.Errorf("end impersonation session: %w", err)
	}
	return outcome
}

// revokeDelegateSessions revokes the target user's delegate auth_sessions rows
// of a grant (identity.ImpersonationAccessToken), so a revoked impersonation
// does not stay listed as an active session of the target.
func revokeDelegateSessions(ctx context.Context, tx pgx.Tx, grantID uuid.UUID, now time.Time) error {
	if _, err := tx.Exec(ctx, `UPDATE auth_sessions
		SET revoked_at=COALESCE(revoked_at,$2),
		    revocation_reason=COALESCE(revocation_reason,'impersonation_revoked')
		WHERE revoked_at IS NULL AND id IN (
			SELECT id FROM admin_impersonation_sessions WHERE grant_id=$1)`, grantID, now); err != nil {
		return fmt.Errorf("revoke impersonation delegate sessions: %w", err)
	}
	return nil
}

func SensitiveAction(action string) bool {
	action = strings.ToLower(strings.TrimSpace(action))
	if action == actionCreate || action == "identity.password.change" || action == "audit.delete" ||
		action == "billing.recharge" || action == "billing.refund" || action == "billing.adjustment.create" ||
		action == "traffic_package.refund" {
		return true
	}
	for _, prefix := range []string{
		"identity.mfa.", "identity.roles.", "identity.permissions.", "identity.user.roles.",
		"api_key.self.create", "api_key.self.update", "api_key.self.activate", "api_key.self.rotate",
		"api_key.admin.create",
		"api_key.secret.", "api_keys.secret.", "billing.recharge.", "billing.refund.",
		"audit.delete.", "audit.event.delete", "audit.events.delete",
	} {
		if strings.HasPrefix(action, prefix) {
			return true
		}
	}
	return false
}

func createPayloadDigest(actor Actor, request CreateRequest) [sha256.Size]byte {
	return digestValue(struct {
		ActorUserID          uuid.UUID `json:"actor_user_id"`
		ActorScopeID         uuid.UUID `json:"actor_scope_id"`
		PrimaryAuthSessionID uuid.UUID `json:"primary_auth_session_id"`
		TenantID             uuid.UUID `json:"tenant_id"`
		TenantScopeID        uuid.UUID `json:"tenant_scope_id"`
		SubjectUserID        uuid.UUID `json:"subject_user_id"`
	}{actor.UserID, actor.ScopeID, actor.PrimaryAuthSessionID, request.TenantID,
		request.TenantScopeID, request.SubjectUserID})
}

// validatePrimaryActor admits a platform session or a tenant session (a
// reseller, RS-07); whether the tenant is an active reseller holding
// ResellerPermission is checked against the database in the transaction.
func validatePrimaryActor(actor Actor) error {
	if actor.UserID == uuid.Nil || actor.ScopeID == uuid.Nil || actor.PrimaryAuthSessionID == uuid.Nil ||
		actor.ScopeKind != "platform" && actor.ScopeKind != "tenant" {
		return ErrPermissionDenied
	}
	if actor.SessionKind != SessionKindPrimary || actor.ImpersonationGrantID != nil {
		return ErrNested
	}
	return nil
}

func validMetadata(value RequestContext) bool {
	return validText(value.RequestID, 1, 128) && validText(value.TraceID, 1, 128)
}

func validIdempotencyKey(value string) bool { return idempotencyPattern.MatchString(value) }

func validIDs(values ...uuid.UUID) bool {
	for _, value := range values {
		if value == uuid.Nil {
			return false
		}
	}
	return true
}

func validText(value string, minimum, maximum int) bool {
	if value != strings.TrimSpace(value) || len(value) < minimum || len(value) > maximum {
		return false
	}
	for _, character := range value {
		if character < 0x20 || character == 0x7f || character == '\u2028' || character == '\u2029' {
			return false
		}
	}
	return true
}

func safeTargetPermissions(permissions []string) bool {
	for _, permission := range permissions {
		if permission == "platform.admin" || permission == ManagePermission {
			return false
		}
	}
	return true
}

func validAction(value string) bool {
	return validText(value, 1, 128) && value == strings.ToLower(value)
}

func digestValue(value any) [sha256.Size]byte {
	encoded, err := json.Marshal(value)
	if err != nil {
		panic(err)
	}
	return sha256.Sum256(encoded)
}

func permissionsDigest(permissions []string) [sha256.Size]byte {
	values := append([]string(nil), permissions...)
	sort.Strings(values)
	unique := values[:0]
	for _, value := range values {
		if len(unique) == 0 || unique[len(unique)-1] != value {
			unique = append(unique, value)
		}
	}
	return sha256.Sum256([]byte(strings.Join(unique, "\x00")))
}

func storeTime(value time.Time) time.Time { return value.UTC().Truncate(time.Microsecond) }

func errorCode(err error) string {
	switch {
	case errors.Is(err, ErrPermissionDenied):
		return "permission_denied"
	case errors.Is(err, ErrNested):
		return "nested_impersonation"
	case errors.Is(err, ErrIdempotencyConflict):
		return "idempotency_conflict"
	case errors.Is(err, ErrInvalidCode):
		return "invalid_code"
	case errors.Is(err, ErrGrantExpired):
		return "grant_expired"
	case errors.Is(err, ErrGrantRevoked), errors.Is(err, ErrSessionRevoked):
		return "revoked"
	case errors.Is(err, ErrCodeReplay):
		return "code_replay"
	case errors.Is(err, ErrSessionExpired):
		return "session_expired"
	case errors.Is(err, ErrPrincipalChanged):
		return "principal_changed"
	case errors.Is(err, ErrSensitiveAction):
		return "sensitive_action"
	default:
		return "invalid_input"
	}
}

func subtleDigestMismatch(stored, supplied []byte) bool {
	return len(stored) != sha256.Size || len(supplied) != sha256.Size ||
		subtle.ConstantTimeCompare(stored, supplied) != 1
}
