package accountrecovery

import (
	"bytes"
	"context"
	"crypto/hmac"
	"crypto/rand"
	"crypto/sha256"
	"encoding/base64"
	"encoding/binary"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"net"
	"regexp"
	"strings"
	"time"

	"github.com/cdnca/cdnca/libs/passwordpolicy"
	"github.com/cdnca/cdnca/services/control-api/internal/audit"
	"github.com/cdnca/cdnca/services/control-api/internal/iamstage2b"
	"github.com/cdnca/cdnca/services/control-api/internal/identity"
	"github.com/cdnca/cdnca/services/control-api/internal/notification"
	"github.com/google/uuid"
	"github.com/jackc/pgx/v5"
	"github.com/jackc/pgx/v5/pgxpool"
)

const (
	tokenDigestDomain       = "cdnca/account-recovery/token/v1"
	subjectDigestDomain     = "cdnca/account-recovery/subject/v1"
	sourceDigestDomain      = "cdnca/account-recovery/source/v1"
	passwordDigestDomain    = "cdnca/account-recovery/password/v1"
	requestDigestDomain     = "cdnca/account-recovery/request/v1"
	idempotencyDigestDomain = "cdnca/account-recovery/idempotency/v1"
	tokenBytes              = 32
)

var idempotencyPattern = regexp.MustCompile(`^[A-Za-z0-9][A-Za-z0-9._:-]{0,127}$`)
var dispatchTemplatePattern = regexp.MustCompile(`^[a-z][a-z0-9._-]{0,95}$`)

type Service struct {
	pool             *pgxpool.Pool
	auditor          AuditAppender
	now              func() time.Time
	entropy          io.Reader
	digestKey        []byte
	tokenTTL         time.Duration
	rateWindow       time.Duration
	subjectLimit     int
	sourceLimit      int
	dispatchKeys     *DispatchKeyring
	dispatcher       DispatchEnqueuer
	templates        map[notification.Channel]notification.TemplateRef
	templateResolver DispatchTemplateResolver
	hashPassword     func(string) (string, error)
}

type writeRecord struct {
	ID            uuid.UUID
	RequestDigest []byte
	ResponseCode  *string
	ResourceID    *uuid.UUID
	CreatedAt     time.Time
	CompletedAt   *time.Time
}

type challengeRecord struct {
	ID               uuid.UUID
	UserID           uuid.UUID
	PasswordRevision int64
	ExpiresAt        time.Time
	ConsumedAt       *time.Time
	RevokedAt        *time.Time
}

func NewService(pool *pgxpool.Pool, config Config) (*Service, error) {
	return NewServiceWithDependencies(pool, config, audit.New(pool))
}

func NewServiceWithDependencies(pool *pgxpool.Pool, config Config, auditor AuditAppender) (*Service, error) {
	if pool == nil || auditor == nil || len(config.DigestKey) < 32 ||
		!validDispatchKeyring(config.DispatchKeyring) || config.DispatchEnqueuer == nil ||
		!validDispatchTemplates(config.DispatchTemplates) {
		return nil, ErrInvalidInput
	}
	if config.Clock == nil {
		config.Clock = time.Now
	}
	if config.Entropy == nil {
		config.Entropy = rand.Reader
	}
	if config.TokenTTL == 0 {
		config.TokenTTL = 15 * time.Minute
	}
	if config.RateWindow == 0 {
		config.RateWindow = 15 * time.Minute
	}
	if config.SubjectLimit == 0 {
		config.SubjectLimit = 5
	}
	if config.SourceLimit == 0 {
		config.SourceLimit = 20
	}
	if config.TokenTTL <= 0 || config.TokenTTL > time.Hour ||
		config.RateWindow <= 0 || config.RateWindow > 24*time.Hour ||
		config.SubjectLimit < 1 || config.SourceLimit < 1 {
		return nil, ErrInvalidInput
	}
	return &Service{
		pool: pool, auditor: auditor, now: config.Clock, entropy: config.Entropy,
		digestKey: append([]byte(nil), config.DigestKey...), tokenTTL: config.TokenTTL,
		rateWindow: config.RateWindow, subjectLimit: config.SubjectLimit,
		sourceLimit: config.SourceLimit, dispatchKeys: config.DispatchKeyring,
		dispatcher: config.DispatchEnqueuer, templates: cloneDispatchTemplates(config.DispatchTemplates),
		templateResolver: config.TemplateResolver,
		hashPassword:     identity.HashPassword,
	}, nil
}

func (s *Service) Request(ctx context.Context, input RequestInput) (RequestResult, error) {
	now := storeTime(s.now())
	response := RequestResult{AcceptedAt: now}
	username, sourceIP, err := validateRequestEnvelope(input)
	if err != nil {
		return RequestResult{}, err
	}
	templates, err := s.resolveDispatchTemplates(ctx, input.ScopeID)
	if err != nil {
		return RequestResult{}, ErrDispatchUnavailable
	}
	subjectDigest := keyedDigest(s.digestKey, subjectDigestDomain, username)
	sourceDigest := keyedDigest(s.digestKey, sourceDigestDomain, sourceIP)
	requestDigest := digestJSON(s.digestKey, struct {
		TenantID      uuid.UUID `json:"tenant_id"`
		ScopeID       uuid.UUID `json:"scope_id"`
		SubjectDigest [32]byte  `json:"subject_digest"`
	}{input.TenantID, input.ScopeID, subjectDigest})
	token, tokenDigest, err := s.generateToken()
	if err != nil {
		return RequestResult{}, err
	}

	var outcome error
	err = pgx.BeginFunc(ctx, s.pool, func(tx pgx.Tx) error {
		if _, err := beginAccountRecoveryAuthorityMutation(ctx, tx,
			iamstage2b.OperationAccountRecoveryRequest, []uuid.UUID{input.ScopeID}); err != nil {
			return err
		}
		if err := validateScope(ctx, tx, input.TenantID, input.ScopeID); err != nil {
			return err
		}
		write, replayed, err := s.claimWrite(ctx, tx, input.TenantID, input.ScopeID, "request",
			input.IdempotencyKey, requestDigest, input.Context, now)
		if err != nil {
			return err
		}
		if replayed {
			response.AcceptedAt = *write.CompletedAt
			if *write.ResponseCode == "rate_limited" {
				outcome = ErrRateLimited
			}
			return nil
		}

		subjectCount, err := incrementRateWindow(ctx, tx, input.TenantID, input.ScopeID,
			"subject", subjectDigest[:], rateWindowStart(now, s.rateWindow), now)
		if err != nil {
			return err
		}
		sourceCount, err := incrementRateWindow(ctx, tx, input.TenantID, input.ScopeID,
			"source", sourceDigest[:], rateWindowStart(now, s.rateWindow), now)
		if err != nil {
			return err
		}
		if subjectCount > s.subjectLimit || sourceCount > s.sourceLimit {
			if err := s.appendAudit(ctx, tx, input.ScopeID, write.ID, input.Context,
				"identity.account_recovery.request", "account_recovery_request", "denied", "rate_limited", uuid.Nil); err != nil {
				return err
			}
			if err := completeWrite(ctx, tx, write.ID, "rate_limited", nil, now); err != nil {
				return err
			}
			outcome = ErrRateLimited
			return nil
		}

		dispatchReference := uuid.New()
		var userID uuid.UUID
		var revision int64
		var email, phone *string
		findErr := tx.QueryRow(ctx, `SELECT user_row.id,user_row.revision,user_row.email,user_row.phone
			FROM users user_row
			JOIN memberships membership ON membership.user_id=user_row.id
			JOIN access_scopes scope ON scope.id=membership.scope_id
			WHERE user_row.username=$1 AND membership.scope_id=$2
			  AND ((scope.kind='tenant' AND scope.tenant_id=$3) OR
			       (scope.kind='platform' AND scope.tenant_id IS NULL AND $3::uuid IS NULL))
			  AND user_row.status='active' AND membership.status='active'
			FOR UPDATE OF user_row,membership`, username, input.ScopeID, databaseTenantID(input.TenantID)).
			Scan(&userID, &revision, &email, &phone)
		if findErr != nil && !errors.Is(findErr, pgx.ErrNoRows) {
			return findErr
		}
		var challengeID *uuid.UUID
		var expiresAt time.Time
		if findErr == nil {
			id, err := uuid.NewV7()
			if err != nil {
				return fmt.Errorf("generate account recovery challenge ID: %w", err)
			}
			expiresAt = now.Add(s.tokenTTL)
			if _, err := tx.Exec(ctx, `INSERT INTO account_recovery_challenges(
				id,tenant_id,scope_id,user_id,token_digest,subject_digest,password_revision,
				issued_by_write_id,issued_at,expires_at
			) VALUES($1,$2,$3,$4,$5,$6,$7,$8,$9,$10)`, id, databaseTenantID(input.TenantID), input.ScopeID,
				userID, tokenDigest[:], subjectDigest[:], revision, write.ID, now, expiresAt); err != nil {
				return err
			}
			if _, err := tx.Exec(ctx, `UPDATE account_recovery_challenges
				SET revoked_at=$3,terminal_reason='superseded'
				WHERE scope_id=$1 AND user_id=$2 AND id<>$4
				  AND consumed_at IS NULL AND revoked_at IS NULL`, input.ScopeID, userID, now, id); err != nil {
				return err
			}
			challengeID = &id
		}
		enqueued, err := s.dispatcher.EnqueueDispatchTx(ctx, tx, notification.DispatchEnqueueRequest{
			ScopeID: input.ScopeID, SourceEventID: dispatchReference.String(),
			AnonymousDispatchReference: dispatchReference, Templates: templates,
			AuditRequestID: input.Context.RequestID,
		})
		if err != nil || len(enqueued.Deliveries) == 0 {
			return ErrDispatchUnavailable
		}
		if challengeID != nil {
			claim := dispatchClaim{
				Reference: dispatchReference, TenantID: input.TenantID, ScopeID: input.ScopeID,
				UserID: userID, ChallengeID: *challengeID, IssuedAt: now, ExpiresAt: expiresAt,
			}
			if email != nil {
				digest := keyedDigest(s.digestKey, contactDigestDomain(notification.ChannelEmail), *email)
				claim.EmailDigest = digest[:]
			}
			if phone != nil {
				digest := keyedDigest(s.digestKey, contactDigestDomain(notification.ChannelSMS), *phone)
				claim.PhoneDigest = digest[:]
			}
			if err := insertDispatchClaim(ctx, tx, s.dispatchKeys, claim, token); err != nil {
				return err
			}
		}
		if err := s.appendAudit(ctx, tx, input.ScopeID, write.ID, input.Context,
			"identity.account_recovery.request", "account_recovery_request", "success", "", uuid.Nil); err != nil {
			return err
		}
		return completeWrite(ctx, tx, write.ID, "accepted", challengeID, now)
	})
	if err != nil {
		return RequestResult{}, fmt.Errorf("request account recovery: %w", stableAccountRecoveryError(err))
	}
	if outcome != nil {
		return RequestResult{}, outcome
	}
	return response, nil
}

func (s *Service) resolveDispatchTemplates(
	ctx context.Context,
	scopeID uuid.UUID,
) (map[notification.Channel]notification.TemplateRef, error) {
	templates := cloneDispatchTemplates(s.templates)
	if s.templateResolver == nil {
		return templates, nil
	}
	for channel := range templates {
		ref, found, err := s.templateResolver.GetAccountRecoveryTemplate(ctx, scopeID, channel)
		if err != nil {
			continue
		}
		if found {
			if ref.ID == "" || ref.Version == 0 || ref.Channel != channel {
				return nil, ErrDispatchUnavailable
			}
			templates[channel] = ref
		}
	}
	return templates, nil
}

func (s *Service) Reset(ctx context.Context, input ResetInput) (ResetResult, error) {
	now := storeTime(s.now())
	token, _, err := validateResetEnvelope(input)
	if err != nil {
		return ResetResult{}, err
	}
	tokenDigest := keyedDigest(s.digestKey, tokenDigestDomain, token)
	passwordDigest := keyedDigest(s.digestKey, passwordDigestDomain, input.NewPassword)
	requestDigest := digestJSON(s.digestKey, struct {
		TenantID       uuid.UUID `json:"tenant_id"`
		ScopeID        uuid.UUID `json:"scope_id"`
		TokenDigest    [32]byte  `json:"token_digest"`
		PasswordDigest [32]byte  `json:"password_digest"`
	}{input.TenantID, input.ScopeID, tokenDigest, passwordDigest})
	result := ResetResult{CompletedAt: now}
	var outcome error
	challengeHint, hintErr := findChallengeIdentity(ctx, s.pool, input.TenantID, input.ScopeID, tokenDigest[:])
	if hintErr != nil && !errors.Is(hintErr, pgx.ErrNoRows) {
		return ResetResult{}, fmt.Errorf("reset account password: %w", stableAccountRecoveryError(hintErr))
	}
	authorityScopes := []uuid.UUID{input.ScopeID}
	if hintErr == nil {
		authorityScopes, err = accountRecoveryAuthorityScopes(
			ctx, s.pool, challengeHint.UserID, input.ScopeID)
		if err != nil {
			return ResetResult{}, fmt.Errorf("reset account password: %w", stableAccountRecoveryError(err))
		}
	}
	err = pgx.BeginFunc(ctx, s.pool, func(tx pgx.Tx) error {
		if _, err := beginAccountRecoveryAuthorityMutation(ctx, tx,
			iamstage2b.OperationAccountRecoveryReset, authorityScopes); err != nil {
			return err
		}

		challengeIdentity, identityErr := findChallengeIdentity(
			ctx, tx, input.TenantID, input.ScopeID, tokenDigest[:])
		if !sameChallengeHint(challengeHint, hintErr, challengeIdentity, identityErr) {
			return ErrUnavailable
		}
		confirmedScopes := []uuid.UUID{input.ScopeID}
		if identityErr == nil {
			confirmedScopes, err = accountRecoveryAuthorityScopes(
				ctx, tx, challengeIdentity.UserID, input.ScopeID)
			if err != nil {
				return err
			}
		}
		if err := assertAccountRecoveryAuthorityMutation(ctx, tx,
			iamstage2b.OperationAccountRecoveryReset, confirmedScopes); err != nil {
			return err
		}
		if err := validateScope(ctx, tx, input.TenantID, input.ScopeID); err != nil {
			return err
		}
		write, replayed, err := s.claimWrite(ctx, tx, input.TenantID, input.ScopeID, "reset",
			input.IdempotencyKey, requestDigest, input.Context, now)
		if err != nil {
			return err
		}
		if replayed {
			result.CompletedAt = *write.CompletedAt
			result.Replayed = true
			outcome = responseError(*write.ResponseCode)
			return nil
		}

		if errors.Is(identityErr, pgx.ErrNoRows) {
			return s.finishDeniedReset(ctx, tx, input.ScopeID, write, input.Context, now, "invalid_token", nil, &outcome)
		}

		var currentHash, userStatus, membershipStatus string
		var revision int64
		err = tx.QueryRow(ctx, `SELECT user_row.password_hash,user_row.status,user_row.revision,membership.status
			FROM users user_row
			JOIN memberships membership ON membership.user_id=user_row.id AND membership.scope_id=$2
			JOIN access_scopes scope ON scope.id=membership.scope_id
			WHERE user_row.id=$1 AND ((scope.kind='tenant' AND scope.tenant_id=$3) OR
			      (scope.kind='platform' AND scope.tenant_id IS NULL AND $3::uuid IS NULL))
			FOR UPDATE OF user_row,membership`, challengeIdentity.UserID, input.ScopeID, databaseTenantID(input.TenantID)).
			Scan(&currentHash, &userStatus, &revision, &membershipStatus)
		if err != nil && !errors.Is(err, pgx.ErrNoRows) {
			return err
		}
		challenge, challengeErr := lockChallenge(ctx, tx, input.TenantID, input.ScopeID, tokenDigest[:])
		if challengeErr != nil {
			return challengeErr
		}
		if challenge.ConsumedAt != nil || challenge.RevokedAt != nil || !now.Before(challenge.ExpiresAt) {
			return s.finishDeniedReset(ctx, tx, input.ScopeID, write, input.Context, now, "invalid_token", &challenge.ID, &outcome)
		}
		if errors.Is(err, pgx.ErrNoRows) || userStatus != "active" || membershipStatus != "active" || revision != challenge.PasswordRevision {
			if err := s.appendAudit(ctx, tx, input.ScopeID, challenge.ID, input.Context,
				"identity.account_recovery.reset", "account_recovery_challenge", "denied", "principal_changed", challenge.UserID); err != nil {
				return err
			}
			if _, updateErr := tx.Exec(ctx, `UPDATE account_recovery_challenges
				SET revoked_at=$2,terminal_reason='principal_changed' WHERE id=$1`, challenge.ID, now); updateErr != nil {
				return updateErr
			}
			if err := completeWrite(ctx, tx, write.ID, "principal_changed", &challenge.ID, now); err != nil {
				return err
			}
			outcome = ErrPrincipalChanged
			return nil
		}
		if identity.VerifyPassword(currentHash, input.NewPassword) {
			return s.finishDeniedReset(ctx, tx, input.ScopeID, write, input.Context, now, "password_reused", &challenge.ID, &outcome)
		}
		newPasswordHash, err := s.hashPassword(input.NewPassword)
		if err != nil {
			return ErrPasswordPolicy
		}

		command, err := tx.Exec(ctx, `UPDATE users
			SET password_hash=$3,password_change_required=false,revision=revision+1,updated_at=$4
			WHERE id=$1 AND revision=$2`, challenge.UserID, challenge.PasswordRevision, newPasswordHash, now)
		if err != nil {
			return err
		}
		if command.RowsAffected() != 1 {
			return ErrPrincipalChanged
		}
		if _, err := tx.Exec(ctx, `UPDATE auth_sessions
			SET revoked_at=$2,revocation_reason='password_reset'
			WHERE user_id=$1 AND revoked_at IS NULL`, challenge.UserID, now); err != nil {
			return err
		}
		if err := s.appendAudit(ctx, tx, input.ScopeID, challenge.ID, input.Context,
			"identity.account_recovery.reset", "account_recovery_challenge", "success", "", challenge.UserID); err != nil {
			return err
		}
		if _, err := tx.Exec(ctx, `UPDATE account_recovery_challenges
			SET consumed_at=$2,terminal_reason='consumed',completion_write_id=$3
			WHERE id=$1`, challenge.ID, now, write.ID); err != nil {
			return err
		}
		return completeWrite(ctx, tx, write.ID, "completed", &challenge.ID, now)
	})
	if err != nil {
		return ResetResult{}, fmt.Errorf("reset account password: %w", stableAccountRecoveryError(err))
	}
	if outcome != nil {
		return ResetResult{}, outcome
	}
	return result, nil
}

func (s *Service) finishDeniedReset(ctx context.Context, tx pgx.Tx, scopeID uuid.UUID, write writeRecord,
	request RequestContext, now time.Time, code string, resourceID *uuid.UUID, outcome *error) error {
	auditResource := write.ID
	resourceType := "account_recovery_request"
	if resourceID != nil {
		auditResource = *resourceID
		resourceType = "account_recovery_challenge"
	}
	if err := s.appendAudit(ctx, tx, scopeID, auditResource, request, "identity.account_recovery.reset",
		resourceType, "denied", code, uuid.Nil); err != nil {
		return err
	}
	if err := completeWrite(ctx, tx, write.ID, code, resourceID, now); err != nil {
		return err
	}
	*outcome = responseError(code)
	return nil
}

func (s *Service) generateToken() (string, [32]byte, error) {
	raw := make([]byte, tokenBytes)
	if _, err := io.ReadFull(s.entropy, raw); err != nil {
		return "", [32]byte{}, fmt.Errorf("generate account recovery token: %w", err)
	}
	token := base64.RawURLEncoding.EncodeToString(raw)
	return token, keyedDigest(s.digestKey, tokenDigestDomain, token), nil
}

func (s *Service) claimWrite(ctx context.Context, tx pgx.Tx, tenantID, scopeID uuid.UUID,
	operation, key string, requestDigest [32]byte, request RequestContext, now time.Time) (writeRecord, bool, error) {
	lockDigest := keyedDigest(s.digestKey, idempotencyDigestDomain, scopeID.String()+"\x00"+operation+"\x00"+key)
	if _, err := tx.Exec(ctx, `SELECT pg_advisory_xact_lock($1)`, int64(binary.BigEndian.Uint64(lockDigest[:8]))); err != nil {
		return writeRecord{}, false, err
	}
	var existing writeRecord
	err := tx.QueryRow(ctx, `SELECT id,request_digest,response_code,resource_id,created_at,completed_at
		FROM account_recovery_write_requests
		WHERE scope_id=$1 AND operation=$2 AND idempotency_key=$3`, scopeID, operation, key).
		Scan(&existing.ID, &existing.RequestDigest, &existing.ResponseCode, &existing.ResourceID,
			&existing.CreatedAt, &existing.CompletedAt)
	if err == nil {
		if !bytes.Equal(existing.RequestDigest, requestDigest[:]) {
			return writeRecord{}, false, ErrIdempotencyConflict
		}
		if existing.CompletedAt == nil || existing.ResponseCode == nil {
			return writeRecord{}, false, errors.New("incomplete account recovery write request")
		}
		return existing, true, nil
	}
	if !errors.Is(err, pgx.ErrNoRows) {
		return writeRecord{}, false, err
	}
	id, err := uuid.NewV7()
	if err != nil {
		return writeRecord{}, false, err
	}
	if _, err := tx.Exec(ctx, `INSERT INTO account_recovery_write_requests(
		id,tenant_id,scope_id,operation,idempotency_key,request_digest,request_id,trace_id,created_at
	) VALUES($1,$2,$3,$4,$5,$6,$7,$8,$9)`, id, databaseTenantID(tenantID), scopeID, operation, key,
		requestDigest[:], request.RequestID, request.TraceID, now); err != nil {
		return writeRecord{}, false, err
	}
	return writeRecord{ID: id, RequestDigest: requestDigest[:], CreatedAt: now}, false, nil
}

func (s *Service) appendAudit(ctx context.Context, tx pgx.Tx, scopeID uuid.UUID, resourceID uuid.UUID,
	request RequestContext, action, resourceType, result, reason string, userID uuid.UUID) error {
	payload := map[string]any{"trace_id": request.TraceID}
	if reason != "" {
		payload["reason_code"] = reason
	}
	if userID != uuid.Nil {
		payload["user_id"] = userID.String()
	}
	return s.auditor.Append(ctx, tx, audit.Event{ScopeID: scopeID, Action: action,
		ResourceType: resourceType, ResourceID: resourceID.String(), RequestID: request.RequestID,
		Result: result, Payload: payload})
}

func validateRequestEnvelope(input RequestInput) (string, string, error) {
	if input.ScopeID == uuid.Nil || !validMetadata(input.Context) ||
		!idempotencyPattern.MatchString(input.IdempotencyKey) || len(input.Username) > 1024 {
		return "", "", ErrInvalidInput
	}
	source := net.ParseIP(strings.TrimSpace(input.Context.SourceIP))
	if source == nil {
		return "", "", ErrInvalidInput
	}
	return strings.ToLower(strings.TrimSpace(input.Username)), source.String(), nil
}

func validateResetEnvelope(input ResetInput) (string, string, error) {
	if input.ScopeID == uuid.Nil || !validMetadata(input.Context) ||
		!idempotencyPattern.MatchString(input.IdempotencyKey) || input.NewPassword != input.ConfirmPassword {
		return "", "", ErrInvalidInput
	}
	if err := passwordpolicy.Check(input.NewPassword); err != nil {
		return "", "", fmt.Errorf("%w: %w", ErrPasswordPolicy, err)
	}
	raw, err := base64.RawURLEncoding.DecodeString(input.Token)
	if err != nil || len(raw) != tokenBytes || base64.RawURLEncoding.EncodeToString(raw) != input.Token {
		return "", "", ErrInvalidToken
	}
	source := net.ParseIP(strings.TrimSpace(input.Context.SourceIP))
	if source == nil {
		return "", "", ErrInvalidInput
	}
	return input.Token, source.String(), nil
}

func validMetadata(input RequestContext) bool {
	return len(input.RequestID) >= 1 && len(input.RequestID) <= 128 &&
		len(input.TraceID) >= 1 && len(input.TraceID) <= 128
}

func validateScope(ctx context.Context, tx pgx.Tx, tenantID, scopeID uuid.UUID) error {
	var valid bool
	if err := tx.QueryRow(ctx, `SELECT EXISTS(SELECT 1 FROM access_scopes scope
		LEFT JOIN tenants tenant ON tenant.id=scope.tenant_id
		WHERE scope.id=$1 AND (
			(scope.kind='tenant' AND scope.tenant_id=$2 AND tenant.id IS NOT NULL) OR
			(scope.kind='platform' AND scope.tenant_id IS NULL AND $2::uuid IS NULL)
		))`, scopeID, databaseTenantID(tenantID)).Scan(&valid); err != nil {
		return err
	}
	if !valid {
		return ErrScopeMismatch
	}
	return nil
}

func incrementRateWindow(ctx context.Context, tx pgx.Tx, tenantID, scopeID uuid.UUID,
	kind string, digest []byte, startedAt, now time.Time) (int, error) {
	var count int
	err := tx.QueryRow(ctx, `INSERT INTO account_recovery_rate_windows(
		tenant_id,scope_id,identifier_kind,identifier_digest,window_started_at,
		request_count,created_at,updated_at
	) VALUES($1,$2,$3,$4,$5,1,$6,$6)
	ON CONFLICT(scope_id,identifier_kind,identifier_digest,window_started_at)
	DO UPDATE SET request_count=account_recovery_rate_windows.request_count+1,updated_at=EXCLUDED.updated_at
	RETURNING request_count`, databaseTenantID(tenantID), scopeID, kind, digest, startedAt, now).Scan(&count)
	return count, err
}

func lockChallenge(ctx context.Context, tx pgx.Tx, tenantID, scopeID uuid.UUID, digest []byte) (challengeRecord, error) {
	var challenge challengeRecord
	err := tx.QueryRow(ctx, `SELECT id,user_id,password_revision,expires_at,consumed_at,revoked_at
		FROM account_recovery_challenges
		WHERE tenant_id IS NOT DISTINCT FROM $1::uuid AND scope_id=$2 AND token_digest=$3
		FOR UPDATE`, databaseTenantID(tenantID), scopeID, digest).Scan(&challenge.ID, &challenge.UserID,
		&challenge.PasswordRevision, &challenge.ExpiresAt, &challenge.ConsumedAt, &challenge.RevokedAt)
	return challenge, err
}

func findChallengeIdentity(ctx context.Context, query accountRecoveryRowQuerier, tenantID, scopeID uuid.UUID, digest []byte) (challengeRecord, error) {
	var challenge challengeRecord
	err := query.QueryRow(ctx, `SELECT id,user_id FROM account_recovery_challenges
		WHERE tenant_id IS NOT DISTINCT FROM $1::uuid AND scope_id=$2 AND token_digest=$3`,
		databaseTenantID(tenantID), scopeID, digest).
		Scan(&challenge.ID, &challenge.UserID)
	return challenge, err
}

func databaseTenantID(tenantID uuid.UUID) any {
	if tenantID == uuid.Nil {
		return nil
	}
	return tenantID
}

func completeWrite(ctx context.Context, tx pgx.Tx, id uuid.UUID, code string, resourceID *uuid.UUID, now time.Time) error {
	command, err := tx.Exec(ctx, `UPDATE account_recovery_write_requests
		SET response_code=$2,resource_id=$3,completed_at=$4
		WHERE id=$1 AND completed_at IS NULL`, id, code, resourceID, now)
	if err != nil {
		return err
	}
	if command.RowsAffected() != 1 {
		return errors.New("account recovery write completion lost CAS")
	}
	return nil
}

func responseError(code string) error {
	switch code {
	case "accepted", "completed":
		return nil
	case "rate_limited":
		return ErrRateLimited
	case "password_reused":
		return ErrPasswordReused
	case "principal_changed":
		return ErrPrincipalChanged
	default:
		return ErrInvalidToken
	}
}

func rateWindowStart(now time.Time, window time.Duration) time.Time {
	return now.UTC().Truncate(window)
}

func storeTime(now time.Time) time.Time {
	return now.UTC().Truncate(time.Microsecond)
}

func keyedDigest(key []byte, domain, value string) [32]byte {
	return keyedDigestBytes(key, domain, []byte(value))
}

func keyedDigestBytes(key []byte, domain string, value []byte) [32]byte {
	mac := hmac.New(sha256.New, key)
	_, _ = mac.Write([]byte(domain))
	_, _ = mac.Write([]byte{0})
	_, _ = mac.Write(value)
	var result [32]byte
	copy(result[:], mac.Sum(nil))
	return result
}

func digestJSON(key []byte, value any) [32]byte {
	encoded, err := json.Marshal(value)
	if err != nil {
		panic(fmt.Sprintf("account recovery request digest: %v", err))
	}
	return keyedDigestBytes(key, requestDigestDomain, encoded)
}

func validDispatchTemplates(templates map[notification.Channel]notification.TemplateRef) bool {
	if len(templates) == 0 || len(templates) > 2 {
		return false
	}
	for channel, ref := range templates {
		if (channel != notification.ChannelEmail && channel != notification.ChannelSMS) ||
			ref.Channel != channel || ref.Version == 0 || !dispatchTemplatePattern.MatchString(ref.ID) {
			return false
		}
	}
	return true
}

func cloneDispatchTemplates(source map[notification.Channel]notification.TemplateRef) map[notification.Channel]notification.TemplateRef {
	result := make(map[notification.Channel]notification.TemplateRef, len(source))
	for channel, ref := range source {
		result[channel] = ref
	}
	return result
}
