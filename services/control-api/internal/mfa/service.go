package mfa

import (
	"context"
	"crypto/rand"
	"crypto/sha256"
	"crypto/subtle"
	"encoding/base32"
	"encoding/base64"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"net/url"
	"regexp"
	"sort"
	"strings"
	"time"
	"unicode"

	"github.com/cdnca/cdnca/services/control-api/internal/audit"
	"github.com/cdnca/cdnca/services/control-api/internal/iamlock"
	"github.com/cdnca/cdnca/services/control-api/internal/iamstage2b"
	"github.com/google/uuid"
	"github.com/jackc/pgx/v5"
	"github.com/jackc/pgx/v5/pgxpool"
)

var idempotencyPattern = regexp.MustCompile(`^[A-Za-z0-9][A-Za-z0-9._-]{0,127}$`)

const defaultIssuer = "CDNCA"

type Service struct {
	pool          *pgxpool.Pool
	cipher        EnvelopeCipher
	auditor       AuditAppender
	now           func() time.Time
	random        io.Reader
	issuer        string
	enrollmentTTL time.Duration
}

type principalState struct {
	scopeKind   string
	tenantID    *uuid.UUID
	permissions []string
}

type storedCredential struct {
	id               uuid.UUID
	userID           uuid.UUID
	scopeID          uuid.UUID
	accountLabel     string
	keyID            string
	ciphertext       []byte
	ciphertextDigest []byte
	requestDigest    []byte
	challengeExpires time.Time
}

type storedProof struct {
	id                uuid.UUID
	actorUserID       uuid.UUID
	actorScopeID      uuid.UUID
	sessionID         uuid.UUID
	tenantID          uuid.UUID
	credentialID      uuid.UUID
	method            string
	permissionsDigest []byte
	audience          string
	action            string
	maxUses           int
	requestDigest     []byte
	issuedAt          time.Time
	expiresAt         time.Time
}

func NewService(pool *pgxpool.Pool, cipher EnvelopeCipher) (*Service, error) {
	return NewServiceWithDependencies(pool, cipher, audit.New(pool), Config{})
}

func NewServiceWithDependencies(
	pool *pgxpool.Pool,
	cipher EnvelopeCipher,
	auditor AuditAppender,
	config Config,
) (*Service, error) {
	if pool == nil || cipher == nil || auditor == nil {
		return nil, ErrEncryptionUnavailable
	}
	if config.Clock == nil {
		config.Clock = time.Now
	}
	if config.Random == nil {
		config.Random = rand.Reader
	}
	config.Issuer = strings.TrimSpace(config.Issuer)
	if config.Issuer == "" {
		config.Issuer = defaultIssuer
	}
	if !validText(config.Issuer, 1, 128) {
		return nil, ErrInvalidInput
	}
	if config.EnrollmentTTL == 0 {
		config.EnrollmentTTL = defaultEnrollmentTTL
	}
	if config.EnrollmentTTL <= 0 || config.EnrollmentTTL > 15*time.Minute {
		return nil, ErrInvalidInput
	}
	return &Service{pool: pool, cipher: cipher, auditor: auditor, now: config.Clock,
		random: config.Random, issuer: config.Issuer, enrollmentTTL: config.EnrollmentTTL}, nil
}

func (s *Service) Status(ctx context.Context, actor Actor) (StatusResult, error) {
	if !validActor(actor) {
		return StatusResult{}, ErrInvalidInput
	}
	now := storeTime(s.now())
	result := StatusResult{Status: StatusInactive}
	err := pgx.BeginFunc(ctx, s.pool, func(tx pgx.Tx) error {
		if err := iamlock.AcquireShared(ctx, tx); err != nil {
			return ErrUnavailable
		}
		locked, err := iamlock.AcquireScopes(ctx, tx, []uuid.UUID{actor.ScopeID})
		if err != nil || len(locked) != 1 || locked[0] != actor.ScopeID {
			return ErrUnavailable
		}
		if _, err := s.lockPrincipal(ctx, tx, actor, now); err != nil {
			return err
		}
		if err := lockPrincipalMFA(ctx, tx, actor); err != nil {
			return err
		}

		var credentialID uuid.UUID
		var method string
		var expiresAt time.Time
		var activated, terminal bool
		err = tx.QueryRow(ctx, `SELECT credential.id,credential.method,
			credential.challenge_expires_at,
			EXISTS(SELECT 1 FROM mfa_credential_events event
			       WHERE event.credential_id=credential.id AND event.event_type='activated'),
			EXISTS(SELECT 1 FROM mfa_credential_events event
			       WHERE event.credential_id=credential.id AND event.event_type IN ('disabled','reset'))
			FROM mfa_credentials credential
			WHERE credential.user_id=$1 AND credential.scope_id=$2
			ORDER BY credential.created_at DESC,credential.id DESC LIMIT 1
			FOR SHARE OF credential`, actor.UserID, actor.ScopeID).Scan(
			&credentialID, &method, &expiresAt, &activated, &terminal)
		if errors.Is(err, pgx.ErrNoRows) {
			return nil
		}
		if err != nil {
			return err
		}
		switch {
		case activated && !terminal:
			result = StatusResult{Status: StatusActive, CredentialID: credentialID, Method: method}
		case !activated && !terminal && now.Before(expiresAt):
			expiresAt = expiresAt.UTC()
			result = StatusResult{Status: StatusPending, CredentialID: credentialID,
				Method: method, EnrollmentExpiresAt: &expiresAt}
		}
		return nil
	})
	if err != nil {
		return StatusResult{}, stableMFAError(err)
	}
	return result, nil
}

func (s *Service) BeginEnrollment(
	ctx context.Context,
	actor Actor,
	request EnrollmentRequest,
) (EnrollmentResult, error) {
	request.AccountLabel = strings.TrimSpace(request.AccountLabel)
	if !validActor(actor) || !validText(request.AccountLabel, 1, 254) ||
		!validMutation(request.IdempotencyKey, request.Context) {
		return EnrollmentResult{}, ErrInvalidInput
	}
	digest := requestDigest(struct {
		AccountLabel string `json:"account_label"`
	}{request.AccountLabel})
	now := storeTime(s.now())
	var result EnrollmentResult
	err := pgx.BeginFunc(ctx, s.pool, func(tx pgx.Tx) error {
		if _, err := beginMFAMutation(ctx, tx, iamstage2b.OperationMFABeginEnrollment,
			[]uuid.UUID{actor.ScopeID}); err != nil {
			return err
		}
		if _, err := s.lockPrincipal(ctx, tx, actor, now); err != nil {
			return err
		}
		if err := lockPrincipalMFA(ctx, tx, actor); err != nil {
			return err
		}
		existing, found, _, err := loadCredentialByIdempotency(ctx, tx, actor, request.IdempotencyKey)
		if err != nil {
			return err
		}
		if found {
			if !equalDigest(existing.requestDigest, digest[:]) {
				return ErrIdempotencyConflict
			}
			result = EnrollmentResult{CredentialID: existing.id,
				ExpiresAt: existing.challengeExpires, Replayed: true}
			return nil
		}
		active, err := hasActiveCredential(ctx, tx, actor)
		if err != nil {
			return err
		}
		if active {
			return ErrAlreadyEnabled
		}
		pending, err := hasPendingCredential(ctx, tx, actor, now)
		if err != nil {
			return err
		}
		if pending {
			return ErrEnrollmentPending
		}

		encoded, secret, err := generateTOTPSecret(s.random)
		if err != nil {
			return err
		}
		keyID, ciphertext, err := s.cipher.Encrypt(secret)
		clear(secret)
		if err != nil || !validKeyID(keyID) || len(ciphertext) < 17 || len(ciphertext) > 4096 {
			return ErrEncryptionUnavailable
		}
		credentialID, err := uuid.NewV7()
		if err != nil {
			return fmt.Errorf("generate MFA credential ID: %w", err)
		}
		ciphertextDigest := sha256.Sum256(ciphertext)
		expiresAt := now.Add(s.enrollmentTTL)
		_, err = tx.Exec(ctx, `INSERT INTO mfa_credentials(
			id,user_id,scope_id,method,account_label,secret_key_id,envelope_algorithm,
			secret_ciphertext,secret_ciphertext_sha256,totp_algorithm,totp_digits,
			totp_period_seconds,idempotency_key,request_digest,request_id,trace_id,
			encrypted_at,created_at,challenge_expires_at
		) VALUES($1,$2,$3,'totp',$4,$5,'external-envelope-v1',$6,$7,'sha1',$8,$9,
			$10,$11,$12,$13,$14,$14,$15)`, credentialID, actor.UserID, actor.ScopeID,
			request.AccountLabel, keyID, ciphertext, ciphertextDigest[:], TOTPDigits,
			int(TOTPPeriod/time.Second), request.IdempotencyKey, digest[:],
			request.Context.RequestID, request.Context.TraceID, now, expiresAt)
		if err != nil {
			return err
		}
		if err := s.appendAudit(ctx, tx, actor, credentialID, request.Context,
			"mfa.enrollment.begin", "success", "", map[string]any{"method": MethodTOTP}); err != nil {
			return err
		}
		result = EnrollmentResult{CredentialID: credentialID, Secret: encoded,
			ProvisioningURI: s.provisioningURI(request.AccountLabel, encoded), ExpiresAt: expiresAt}
		return nil
	})
	if err != nil {
		return EnrollmentResult{}, stableMFAError(err)
	}
	return result, nil
}

func (s *Service) Activate(
	ctx context.Context,
	actor Actor,
	request ActivationRequest,
) (ActivationResult, error) {
	if !validActor(actor) || request.CredentialID == uuid.Nil || !validCode(MethodTOTP, request.Code) ||
		!validMutation(request.IdempotencyKey, request.Context) {
		return ActivationResult{}, ErrInvalidInput
	}
	codeDigest := sha256.Sum256([]byte(request.Code))
	digest := requestDigest(struct {
		CredentialID uuid.UUID `json:"credential_id"`
		CodeDigest   [32]byte  `json:"code_digest"`
	}{request.CredentialID, codeDigest})
	now := storeTime(s.now())
	var result ActivationResult
	var outcome error
	err := pgx.BeginFunc(ctx, s.pool, func(tx pgx.Tx) error {
		if _, err := beginMFAMutation(ctx, tx, iamstage2b.OperationMFAActivateEnrollment,
			[]uuid.UUID{actor.ScopeID}); err != nil {
			return err
		}
		if _, err := s.lockPrincipal(ctx, tx, actor, now); err != nil {
			return err
		}
		credential, err := lockCredential(ctx, tx, actor, request.CredentialID)
		if err != nil {
			if errors.Is(err, pgx.ErrNoRows) {
				return ErrNotActive
			}
			return err
		}
		existingDigest, activatedAt, found, err := loadCredentialEventIdempotency(
			ctx, tx, credential.id, "activated", request.IdempotencyKey)
		if err != nil {
			return err
		}
		if found {
			if !equalDigest(existingDigest, digest[:]) {
				return ErrIdempotencyConflict
			}
			result = ActivationResult{CredentialID: credential.id, ActivatedAt: activatedAt, Replayed: true}
			return nil
		}
		if active, err := credentialActivated(ctx, tx, credential.id); err != nil {
			return err
		} else if active {
			return ErrAlreadyActive
		}
		if !now.Before(credential.challengeExpires) {
			outcome = ErrEnrollmentExpired
			return s.appendAudit(ctx, tx, actor, credential.id, request.Context,
				"mfa.enrollment.activate", "denied", errorCode(outcome), nil)
		}
		secret, err := s.decryptSecret(credential)
		if err != nil {
			return err
		}
		counter, matched := matchTOTP(secret, request.Code, now, TOTPPeriod, TOTPWindow, TOTPDigits)
		clear(secret)
		if !matched {
			outcome = ErrInvalidCode
			return s.appendAudit(ctx, tx, actor, credential.id, request.Context,
				"mfa.enrollment.activate", "denied", errorCode(outcome), nil)
		}
		eventID, err := insertCredentialEvent(ctx, tx, credential, "activated", &counter, nil,
			request.IdempotencyKey, digest, request.Context, now)
		if err != nil {
			return err
		}
		_ = eventID
		codes, err := s.insertRecoveryCodes(ctx, tx, credential, now)
		if err != nil {
			return err
		}
		if err := s.appendAudit(ctx, tx, actor, credential.id, request.Context,
			"mfa.enrollment.activate", "success", "", map[string]any{"recovery_code_count": len(codes)}); err != nil {
			return err
		}
		result = ActivationResult{CredentialID: credential.id, RecoveryCodes: codes, ActivatedAt: now}
		return nil
	})
	if err != nil {
		return ActivationResult{}, stableMFAError(err)
	}
	if outcome != nil {
		return ActivationResult{}, outcome
	}
	return result, nil
}

func (s *Service) CreateStepUp(
	ctx context.Context,
	actor Actor,
	request StepUpRequest,
) (StepUpResult, error) {
	request.Audience = strings.TrimSpace(request.Audience)
	request.Action = strings.TrimSpace(request.Action)
	if !validActor(actor) || !validProofScope(request.PlatformScope, request.TenantID) ||
		!validText(request.Audience, 1, 128) ||
		!validText(request.Action, 1, 128) || !validAuthentication(request.Authentication) ||
		request.TTL <= 0 || request.TTL > MaxStepUpTTL || request.MaxUses < 1 ||
		request.MaxUses > MaxProofUses || !validMutation(request.IdempotencyKey, request.Context) {
		return StepUpResult{}, ErrInvalidInput
	}
	codeDigest := sha256.Sum256([]byte(normalizeAuthenticationCode(request.Authentication)))
	digest := requestDigest(struct {
		TenantID      uuid.UUID `json:"tenant_id"`
		Audience      string    `json:"audience"`
		Action        string    `json:"action"`
		Method        string    `json:"method"`
		CodeDigest    [32]byte  `json:"code_digest"`
		TTLNanosecond int64     `json:"ttl_nanosecond"`
		MaxUses       int       `json:"max_uses"`
	}{request.TenantID, request.Audience, request.Action, request.Authentication.Method,
		codeDigest, int64(request.TTL), request.MaxUses})
	now := storeTime(s.now())
	var result StepUpResult
	var outcome error
	requestedScopes, tenantScopeID, err := proofAuthorityScopes(ctx, s.pool, actor, request.PlatformScope, request.TenantID)
	if err != nil {
		return StepUpResult{}, stableMFAError(err)
	}
	err = pgx.BeginFunc(ctx, s.pool, func(tx pgx.Tx) error {
		lockedScopes, err := beginMFAMutation(ctx, tx, iamstage2b.OperationMFAIssueStepUp, requestedScopes)
		if err != nil {
			return err
		}
		if request.PlatformScope {
			if !containsMFAScope(lockedScopes, actor.ScopeID) {
				return ErrUnavailable
			}
			if err := assertMFAMutation(ctx, tx, iamstage2b.OperationMFAIssueStepUp, lockedScopes); err != nil {
				return err
			}
		} else if err := assertMFATenantAuthorityMutation(ctx, tx, iamstage2b.OperationMFAIssueStepUp,
			lockedScopes, actor.ScopeID, request.TenantID, tenantScopeID); err != nil {
			return err
		}
		principal, err := s.lockPrincipal(ctx, tx, actor, now)
		if err != nil {
			return err
		}
		if err := validateProofScopeBinding(ctx, tx, principal, request.PlatformScope, request.TenantID); err != nil {
			return err
		}
		existing, found, err := loadProofByIdempotency(ctx, tx, actor, request.IdempotencyKey)
		if err != nil {
			return err
		}
		if found {
			if !equalDigest(existing.requestDigest, digest[:]) {
				return ErrIdempotencyConflict
			}
			result = proofResult(existing, true)
			return nil
		}
		credential, err := lockActiveCredential(ctx, tx, actor)
		if err != nil {
			if errors.Is(err, pgx.ErrNoRows) {
				outcome = ErrNotActive
				return s.appendAudit(ctx, tx, actor, actor.UserID, request.Context,
					"mfa.step_up.issue", "denied", errorCode(outcome), map[string]any{
						"method": request.Authentication.Method, "audience": request.Audience,
						"requested_action": request.Action,
					})
			}
			return err
		}
		authEventID, authErr := s.authenticate(ctx, tx, credential, request.Authentication,
			internalEventKey("proof", actor.SessionID, request.IdempotencyKey), digest, request.Context, now)
		if authErr != nil {
			outcome = authErr
			return s.appendAudit(ctx, tx, actor, credential.id, request.Context,
				"mfa.step_up.issue", "denied", errorCode(outcome), map[string]any{
					"method": request.Authentication.Method, "audience": request.Audience,
					"requested_action": request.Action,
				})
		}
		token, tokenDigest, err := generateProofToken(s.random)
		if err != nil {
			return err
		}
		proofID, err := uuid.NewV7()
		if err != nil {
			return fmt.Errorf("generate step-up proof ID: %w", err)
		}
		permissionsDigest := digestPermissions(principal.permissions)
		expiresAt := now.Add(request.TTL)
		_, err = tx.Exec(ctx, `INSERT INTO mfa_step_up_proofs(
			id,token_digest,actor_user_id,actor_scope_id,auth_session_id,tenant_id,
			credential_id,authentication_event_id,authentication_method,permissions_digest,
			audience,action,max_uses,idempotency_key,request_digest,request_id,trace_id,
			issued_at,expires_at
		) VALUES($1,$2,$3,$4,$5,$6,$7,$8,$9,$10,$11,$12,$13,$14,$15,$16,$17,$18,$19)`,
			proofID, tokenDigest[:], actor.UserID, actor.ScopeID, actor.SessionID, nullableTenant(request.TenantID),
			credential.id, authEventID, request.Authentication.Method, permissionsDigest[:],
			request.Audience, request.Action, request.MaxUses, request.IdempotencyKey, digest[:],
			request.Context.RequestID, request.Context.TraceID, now, expiresAt)
		if err != nil {
			return err
		}
		if err := s.appendAudit(ctx, tx, actor, proofID, request.Context,
			"mfa.step_up.issue", "success", "", map[string]any{
				"method": request.Authentication.Method, "audience": request.Audience,
				"requested_action": request.Action, "max_uses": request.MaxUses,
			}); err != nil {
			return err
		}
		result = StepUpResult{ProofID: proofID, Token: token, Method: request.Authentication.Method,
			IssuedAt: now, ExpiresAt: expiresAt, MaxUses: request.MaxUses}
		return nil
	})
	if err != nil {
		return StepUpResult{}, stableMFAError(err)
	}
	if outcome != nil {
		return StepUpResult{}, outcome
	}
	return result, nil
}

func (s *Service) ConsumeStepUp(
	ctx context.Context,
	actor Actor,
	request ConsumeStepUpRequest,
) (Evidence, error) {
	request.Audience = strings.TrimSpace(request.Audience)
	request.Action = strings.TrimSpace(request.Action)
	if err := validateConsumeStepUp(actor, request); err != nil {
		return Evidence{}, err
	}
	var result Evidence
	var outcome error
	requestedScopes, _, err := proofAuthorityScopes(ctx, s.pool, actor, request.PlatformScope, request.TenantID)
	if err != nil {
		return Evidence{}, stableMFAError(err)
	}
	err = pgx.BeginFunc(ctx, s.pool, func(tx pgx.Tx) error {
		lockedScopes, err := beginMFAMutation(ctx, tx, iamstage2b.OperationMFAConsumeStepUp, requestedScopes)
		if err != nil {
			return err
		}
		result, outcome, err = s.consumeStepUpTxWithScopes(ctx, tx, actor, lockedScopes, request,
			iamstage2b.OperationMFAConsumeStepUp)
		return err
	})
	if err != nil {
		return Evidence{}, stableMFAError(err)
	}
	if outcome != nil {
		return Evidence{}, outcome
	}
	return result, nil
}

// ConsumeStepUpTx fails closed because the legacy contract cannot prove the
// caller's complete Stage2B authority scope set.
func (s *Service) ConsumeStepUpTx(
	context.Context,
	pgx.Tx,
	Actor,
	ConsumeStepUpRequest,
) (Evidence, error) {
	return Evidence{}, ErrUnavailable
}

// ConsumeStepUpTxWithScopes validates the caller's complete canonical authority
// scope set before consuming a proof in the caller-owned transaction.
func (s *Service) ConsumeStepUpTxWithScopes(
	ctx context.Context,
	tx pgx.Tx,
	actor Actor,
	authorityScopes []uuid.UUID,
	request ConsumeStepUpRequest,
) (Evidence, error) {
	result, outcome, err := s.consumeStepUpTxWithScopes(ctx, tx, actor, authorityScopes, request,
		iamstage2b.OperationMFAConsumeStepUp)
	if err != nil {
		return Evidence{}, stableMFAError(err)
	}
	if outcome != nil {
		return Evidence{}, outcome
	}
	return result, nil
}

func (s *Service) consumeStepUpTxWithScopes(
	ctx context.Context,
	tx pgx.Tx,
	actor Actor,
	authorityScopes []uuid.UUID,
	request ConsumeStepUpRequest,
	operation iamstage2b.Operation,
) (Evidence, error, error) {
	request.Audience = strings.TrimSpace(request.Audience)
	request.Action = strings.TrimSpace(request.Action)
	if err := validateConsumeStepUp(actor, request); err != nil || tx == nil {
		return Evidence{}, nil, ErrInvalidInput
	}
	if !validCanonicalMFAScopes(authorityScopes) {
		return Evidence{}, nil, ErrUnavailable
	}
	if err := assertMFAMutation(ctx, tx, operation, authorityScopes); err != nil {
		return Evidence{}, nil, err
	}
	if !containsMFAScope(authorityScopes, actor.ScopeID) {
		return Evidence{}, nil, ErrUnavailable
	}
	if !request.PlatformScope {
		tenantScopeID, err := mfaTenantAuthorityScope(ctx, tx, request.TenantID)
		if err != nil || !containsMFAScope(authorityScopes, tenantScopeID) {
			return Evidence{}, nil, ErrUnavailable
		}
	}
	return s.consumeStepUpTx(ctx, tx, actor, request)
}

func (s *Service) consumeStepUpTx(
	ctx context.Context,
	tx pgx.Tx,
	actor Actor,
	request ConsumeStepUpRequest,
) (Evidence, error, error) {
	request.Audience = strings.TrimSpace(request.Audience)
	request.Action = strings.TrimSpace(request.Action)
	if tx == nil || validateConsumeStepUp(actor, request) != nil {
		return Evidence{}, nil, ErrInvalidInput
	}
	tokenDigest := sha256.Sum256([]byte(request.Token))
	now := storeTime(s.now())
	var result Evidence
	var outcome error
	proof, err := lockProofByToken(ctx, tx, tokenDigest[:])
	if errors.Is(err, pgx.ErrNoRows) {
		outcome = ErrInvalidProof
		return Evidence{}, outcome, s.appendAudit(ctx, tx, actor, actor.UserID, request.Context,
			"mfa.step_up.consume", "denied", errorCode(outcome), nil)
	}
	if err != nil {
		return Evidence{}, nil, err
	}
	if proof.actorUserID != actor.UserID || proof.actorScopeID != actor.ScopeID ||
		proof.sessionID != actor.SessionID || proof.tenantID != request.TenantID ||
		proof.audience != request.Audience || proof.action != request.Action {
		outcome = ErrProofBinding
		return Evidence{}, outcome, s.appendAudit(ctx, tx, actor, proof.id, request.Context,
			"mfa.step_up.consume", "denied", errorCode(outcome), nil)
	}
	if !now.Before(proof.expiresAt) {
		outcome = ErrProofExpired
		return Evidence{}, outcome, s.appendAudit(ctx, tx, actor, proof.id, request.Context,
			"mfa.step_up.consume", "denied", errorCode(outcome), nil)
	}
	if err := lockProofCredentialActive(ctx, tx, proof.credentialID); err != nil {
		if errors.Is(err, pgx.ErrNoRows) {
			outcome = ErrPrincipalChanged
			return Evidence{}, outcome, s.appendAudit(ctx, tx, actor, proof.id, request.Context,
				"mfa.step_up.consume", "denied", errorCode(outcome), nil)
		}
		return Evidence{}, nil, err
	}
	principal, err := s.lockPrincipal(ctx, tx, actor, now)
	if err != nil {
		return Evidence{}, nil, err
	}
	if err := validateProofScopeBinding(ctx, tx, principal, request.PlatformScope, request.TenantID); err != nil {
		return Evidence{}, nil, err
	}
	currentPermissions := digestPermissions(principal.permissions)
	if !equalDigest(proof.permissionsDigest, currentPermissions[:]) {
		outcome = ErrPrincipalChanged
		return Evidence{}, outcome, s.appendAudit(ctx, tx, actor, proof.id, request.Context,
			"mfa.step_up.consume", "denied", errorCode(outcome), nil)
	}
	ordinal, storedBinding, storedTraceID, found, err := loadProofUseByRequest(
		ctx, tx, proof.id, request.Context.RequestID)
	if err != nil {
		return Evidence{}, nil, err
	}
	if found {
		if storedTraceID != request.Context.TraceID ||
			!sameOptionalDigest(storedBinding, request.ResourceBindingDigest) {
			outcome = ErrProofBinding
			return Evidence{}, outcome, s.appendAudit(ctx, tx, actor, proof.id, request.Context,
				"mfa.step_up.consume", "denied", errorCode(outcome), nil)
		}
		return evidenceForProof(proof, ordinal, storedBinding), nil, nil
	}
	uses, err := countProofUses(ctx, tx, proof.id)
	if err != nil {
		return Evidence{}, nil, err
	}
	if uses >= proof.maxUses {
		outcome = ErrProofConsumed
		return Evidence{}, outcome, s.appendAudit(ctx, tx, actor, proof.id, request.Context,
			"mfa.step_up.consume", "denied", errorCode(outcome), nil)
	}
	useID, err := uuid.NewV7()
	if err != nil {
		return Evidence{}, nil, fmt.Errorf("generate step-up use ID: %w", err)
	}
	ordinal = uses + 1
	_, err = tx.Exec(ctx, `INSERT INTO mfa_step_up_uses(
		id,proof_id,actor_user_id,actor_scope_id,auth_session_id,tenant_id,
		use_ordinal,request_id,trace_id,resource_binding_sha256,used_at
	) VALUES($1,$2,$3,$4,$5,$6,$7,$8,$9,$10,$11)`, useID, proof.id, actor.UserID,
		actor.ScopeID, actor.SessionID, nullableTenant(request.TenantID), ordinal,
		request.Context.RequestID, request.Context.TraceID, nullableDigest(request.ResourceBindingDigest), now)
	if err != nil {
		return Evidence{}, nil, err
	}
	if err := s.appendAudit(ctx, tx, actor, proof.id, request.Context,
		"mfa.step_up.consume", "success", "", map[string]any{
			"audience": request.Audience, "requested_action": request.Action,
			"use_ordinal": ordinal, "resource_bound": len(request.ResourceBindingDigest) != 0,
		}); err != nil {
		return Evidence{}, nil, err
	}
	result = evidenceForProof(proof, ordinal, request.ResourceBindingDigest)
	return result, nil, nil
}

func (s *Service) Disable(ctx context.Context, actor Actor, request DeactivateRequest) error {
	return s.deactivate(ctx, actor, request, "disabled", "mfa.disable")
}

func (s *Service) Reset(ctx context.Context, actor Actor, request DeactivateRequest) error {
	return s.deactivate(ctx, actor, request, "reset", "mfa.reset")
}

func (s *Service) deactivate(
	ctx context.Context,
	actor Actor,
	request DeactivateRequest,
	eventType string,
	action string,
) error {
	request.Reason = strings.TrimSpace(request.Reason)
	if !validActor(actor) || !validAuthentication(request.Authentication) ||
		!validText(request.Reason, 1, 512) || !validMutation(request.IdempotencyKey, request.Context) {
		return ErrInvalidInput
	}
	codeDigest := sha256.Sum256([]byte(normalizeAuthenticationCode(request.Authentication)))
	digest := requestDigest(struct {
		Method     string   `json:"method"`
		CodeDigest [32]byte `json:"code_digest"`
		Reason     string   `json:"reason"`
	}{request.Authentication.Method, codeDigest, request.Reason})
	now := storeTime(s.now())
	var outcome error
	err := pgx.BeginFunc(ctx, s.pool, func(tx pgx.Tx) error {
		operation := iamstage2b.OperationMFADisable
		if action == "mfa.reset" {
			operation = iamstage2b.OperationMFAReset
		}
		if _, err := beginMFAMutation(ctx, tx, operation, []uuid.UUID{actor.ScopeID}); err != nil {
			return err
		}
		if _, err := s.lockPrincipal(ctx, tx, actor, now); err != nil {
			return err
		}
		existingDigest, found, err := loadTerminalEventIdempotency(ctx, tx, actor, eventType,
			request.IdempotencyKey)
		if err != nil {
			return err
		}
		if found {
			if !equalDigest(existingDigest, digest[:]) {
				return ErrIdempotencyConflict
			}
			return nil
		}
		credential, err := lockActiveCredential(ctx, tx, actor)
		if errors.Is(err, pgx.ErrNoRows) {
			return ErrNotActive
		}
		if err != nil {
			return err
		}
		_, authErr := s.authenticate(ctx, tx, credential, request.Authentication,
			internalEventKey(eventType, actor.SessionID, request.IdempotencyKey), digest, request.Context, now)
		if authErr != nil {
			outcome = authErr
			return s.appendAudit(ctx, tx, actor, credential.id, request.Context,
				action, "denied", errorCode(outcome), map[string]any{"method": request.Authentication.Method})
		}
		if _, err := insertCredentialEvent(ctx, tx, credential, eventType, nil, nil,
			request.IdempotencyKey, digest, request.Context, now); err != nil {
			return err
		}
		return s.appendAudit(ctx, tx, actor, credential.id, request.Context,
			action, "success", "", map[string]any{"method": request.Authentication.Method})
	})
	if err != nil {
		return stableMFAError(err)
	}
	return outcome
}

func (s *Service) authenticate(
	ctx context.Context,
	tx pgx.Tx,
	credential storedCredential,
	authentication Authentication,
	idempotencyKey string,
	digest [32]byte,
	request RequestContext,
	now time.Time,
) (uuid.UUID, error) {
	switch authentication.Method {
	case MethodTOTP:
		secret, err := s.decryptSecret(credential)
		if err != nil {
			return uuid.Nil, err
		}
		counter, matched := matchTOTP(secret, authentication.Code, now, TOTPPeriod, TOTPWindow, TOTPDigits)
		clear(secret)
		if !matched {
			return uuid.Nil, ErrInvalidCode
		}
		var used bool
		if err := tx.QueryRow(ctx, `SELECT EXISTS(SELECT 1 FROM mfa_credential_events
			WHERE credential_id=$1 AND totp_counter=$2)`, credential.id, int64(counter)).Scan(&used); err != nil {
			return uuid.Nil, err
		}
		if used {
			return uuid.Nil, ErrCodeReplayed
		}
		return insertCredentialEvent(ctx, tx, credential, "totp_verified", &counter, nil,
			idempotencyKey, digest, request, now)
	case MethodRecoveryCode:
		normalized := normalizeRecoveryCode(authentication.Code)
		codeDigest := sha256.Sum256([]byte(normalized))
		var codeID uuid.UUID
		err := tx.QueryRow(ctx, `SELECT id FROM mfa_recovery_codes
			WHERE credential_id=$1 AND code_digest=$2 FOR UPDATE`, credential.id, codeDigest[:]).Scan(&codeID)
		if errors.Is(err, pgx.ErrNoRows) {
			return uuid.Nil, ErrInvalidCode
		}
		if err != nil {
			return uuid.Nil, err
		}
		var used bool
		if err := tx.QueryRow(ctx, `SELECT EXISTS(SELECT 1 FROM mfa_recovery_code_consumptions
			WHERE recovery_code_id=$1)`, codeID).Scan(&used); err != nil {
			return uuid.Nil, err
		}
		if used {
			return uuid.Nil, ErrRecoveryCodeUsed
		}
		consumptionID, err := uuid.NewV7()
		if err != nil {
			return uuid.Nil, fmt.Errorf("generate recovery consumption ID: %w", err)
		}
		_, err = tx.Exec(ctx, `INSERT INTO mfa_recovery_code_consumptions(
			id,recovery_code_id,credential_id,user_id,scope_id,request_id,trace_id,consumed_at
		) VALUES($1,$2,$3,$4,$5,$6,$7,$8)`, consumptionID, codeID, credential.id,
			credential.userID, credential.scopeID, request.RequestID, request.TraceID, now)
		if err != nil {
			return uuid.Nil, err
		}
		return insertCredentialEvent(ctx, tx, credential, "recovery_verified", nil, &codeID,
			idempotencyKey, digest, request, now)
	default:
		return uuid.Nil, ErrInvalidInput
	}
}

func (s *Service) lockPrincipal(
	ctx context.Context,
	tx pgx.Tx,
	actor Actor,
	now time.Time,
) (principalState, error) {
	var state principalState
	var userStatus, membershipStatus string
	var revokedAt *time.Time
	var expiresAt time.Time
	// Row locks follow the session credential check (sessioncredential.VerifyTx):
	// users, then memberships, then auth_sessions, one statement each. A single
	// FOR UPDATE OF session,users,membership locked the session row first and
	// deadlocked with a concurrent request on the same session (fix-e1 #4).
	err := tx.QueryRow(ctx, `SELECT status FROM users WHERE id=$1 FOR UPDATE`, actor.UserID).Scan(&userStatus)
	if err == nil {
		err = tx.QueryRow(ctx, `SELECT status FROM memberships WHERE scope_id=$1 AND user_id=$2 FOR UPDATE`,
			actor.ScopeID, actor.UserID).Scan(&membershipStatus)
	}
	if err == nil {
		err = tx.QueryRow(ctx, `SELECT scope.kind,scope.tenant_id,session.revoked_at,session.expires_at
			FROM auth_sessions session
			JOIN access_scopes scope ON scope.id=session.scope_id
			WHERE session.id=$1 AND session.user_id=$2 AND session.scope_id=$3
			FOR UPDATE OF session`, actor.SessionID, actor.UserID, actor.ScopeID).Scan(
			&state.scopeKind, &state.tenantID, &revokedAt, &expiresAt)
	}
	if errors.Is(err, pgx.ErrNoRows) || revokedAt != nil || (err == nil && !now.Before(expiresAt)) {
		return principalState{}, ErrInvalidSession
	}
	if err != nil {
		return principalState{}, err
	}
	if userStatus != "active" || membershipStatus != "active" {
		return principalState{}, ErrPrincipalChanged
	}
	rows, err := tx.Query(ctx, `SELECT DISTINCT permission.permission_name
		FROM role_assignments assignment
		JOIN role_permissions permission ON permission.role_id=assignment.role_id
		WHERE assignment.scope_id=$1 AND assignment.user_id=$2
		ORDER BY permission.permission_name`, actor.ScopeID, actor.UserID)
	if err != nil {
		return principalState{}, err
	}
	defer rows.Close()
	for rows.Next() {
		var permission string
		if err := rows.Scan(&permission); err != nil {
			return principalState{}, err
		}
		state.permissions = append(state.permissions, permission)
	}
	if err := rows.Err(); err != nil {
		return principalState{}, err
	}
	return state, nil
}

// validProofScope: a platform-scoped proof carries no tenant, a tenant proof
// carries exactly one.
func validProofScope(platform bool, tenantID uuid.UUID) bool {
	return platform == (tenantID == uuid.Nil)
}

// proofAuthorityScopes returns the Stage2B scopes to lock: the actor scope,
// plus the tenant scope for tenant-bound proofs.
func proofAuthorityScopes(
	ctx context.Context, query mfaRowQuerier, actor Actor, platform bool, tenantID uuid.UUID,
) ([]uuid.UUID, uuid.UUID, error) {
	if platform {
		return []uuid.UUID{actor.ScopeID}, uuid.Nil, nil
	}
	tenantScopeID, err := mfaTenantAuthorityScope(ctx, query, tenantID)
	if err != nil {
		return nil, uuid.Nil, err
	}
	return []uuid.UUID{actor.ScopeID, tenantScopeID}, tenantScopeID, nil
}

// validateProofScopeBinding: only a platform session may hold or use a
// platform-scoped proof; tenant proofs keep the tenant binding rules.
func validateProofScopeBinding(
	ctx context.Context, tx pgx.Tx, principal principalState, platform bool, tenantID uuid.UUID,
) error {
	if platform {
		if principal.scopeKind != "platform" {
			return ErrProofBinding
		}
		return nil
	}
	return validateTenantBinding(ctx, tx, principal, tenantID)
}

func nullableTenant(tenantID uuid.UUID) any {
	if tenantID == uuid.Nil {
		return nil
	}
	return tenantID
}

func validateTenantBinding(ctx context.Context, tx pgx.Tx, principal principalState, tenantID uuid.UUID) error {
	var active bool
	if err := tx.QueryRow(ctx, `SELECT status='active' FROM tenants WHERE id=$1`, tenantID).Scan(&active); err != nil {
		if errors.Is(err, pgx.ErrNoRows) {
			return ErrTenantUnavailable
		}
		return err
	}
	if !active {
		return ErrTenantUnavailable
	}
	if principal.scopeKind == "tenant" && (principal.tenantID == nil || *principal.tenantID != tenantID) {
		return ErrProofBinding
	}
	if principal.scopeKind != "platform" && principal.scopeKind != "tenant" {
		return ErrPrincipalChanged
	}
	return nil
}

func (s *Service) decryptSecret(credential storedCredential) ([]byte, error) {
	digest := sha256.Sum256(credential.ciphertext)
	if !equalDigest(credential.ciphertextDigest, digest[:]) {
		return nil, ErrEncryptionUnavailable
	}
	plaintext, err := s.cipher.Decrypt(credential.keyID, credential.ciphertext)
	if err != nil || len(plaintext) != totpSecretBytes {
		clear(plaintext)
		return nil, ErrEncryptionUnavailable
	}
	return plaintext, nil
}

func (s *Service) insertRecoveryCodes(
	ctx context.Context,
	tx pgx.Tx,
	credential storedCredential,
	now time.Time,
) ([]string, error) {
	codes := make([]string, 0, RecoveryCodeCount)
	for ordinal := 1; ordinal <= RecoveryCodeCount; ordinal++ {
		raw := make([]byte, 20)
		if _, err := io.ReadFull(s.random, raw); err != nil {
			return nil, fmt.Errorf("generate recovery code: %w", err)
		}
		compact := base32.StdEncoding.WithPadding(base32.NoPadding).EncodeToString(raw)
		clear(raw)
		code := groupRecoveryCode(compact)
		digest := sha256.Sum256([]byte(compact))
		codeID, err := uuid.NewV7()
		if err != nil {
			return nil, fmt.Errorf("generate recovery code ID: %w", err)
		}
		_, err = tx.Exec(ctx, `INSERT INTO mfa_recovery_codes(
			id,credential_id,user_id,scope_id,ordinal,code_digest,created_at
		) VALUES($1,$2,$3,$4,$5,$6,$7)`, codeID, credential.id, credential.userID,
			credential.scopeID, ordinal, digest[:], now)
		if err != nil {
			return nil, err
		}
		codes = append(codes, code)
	}
	return codes, nil
}

func insertCredentialEvent(
	ctx context.Context,
	tx pgx.Tx,
	credential storedCredential,
	eventType string,
	counter *uint64,
	recoveryCodeID *uuid.UUID,
	idempotencyKey string,
	digest [32]byte,
	request RequestContext,
	now time.Time,
) (uuid.UUID, error) {
	eventID, err := uuid.NewV7()
	if err != nil {
		return uuid.Nil, fmt.Errorf("generate MFA event ID: %w", err)
	}
	var databaseCounter *int64
	if counter != nil {
		value := int64(*counter)
		databaseCounter = &value
	}
	_, err = tx.Exec(ctx, `INSERT INTO mfa_credential_events(
		id,credential_id,user_id,scope_id,event_type,totp_counter,recovery_code_id,
		idempotency_key,request_digest,request_id,trace_id,occurred_at
	) VALUES($1,$2,$3,$4,$5,$6,$7,$8,$9,$10,$11,$12)`, eventID, credential.id,
		credential.userID, credential.scopeID, eventType, databaseCounter, recoveryCodeID,
		idempotencyKey, digest[:], request.RequestID, request.TraceID, now)
	return eventID, err
}

func (s *Service) appendAudit(
	ctx context.Context,
	tx pgx.Tx,
	actor Actor,
	resourceID uuid.UUID,
	request RequestContext,
	action string,
	result string,
	reasonCode string,
	extra map[string]any,
) error {
	payload := map[string]any{"trace_id": request.TraceID, "session_id": actor.SessionID.String()}
	for key, value := range extra {
		payload[key] = value
	}
	if reasonCode != "" {
		payload["reason_code"] = reasonCode
	}
	return s.auditor.Append(ctx, tx, audit.Event{
		ScopeID: actor.ScopeID, ActorUserID: &actor.UserID, Action: action,
		ResourceType: "mfa", ResourceID: resourceID.String(), RequestID: request.RequestID,
		Result: result, Payload: payload,
	})
}

func loadCredentialByIdempotency(
	ctx context.Context,
	tx pgx.Tx,
	actor Actor,
	key string,
) (storedCredential, bool, bool, error) {
	var credential storedCredential
	var activated bool
	err := tx.QueryRow(ctx, `SELECT credential.id,credential.user_id,credential.scope_id,
		credential.account_label,credential.secret_key_id,credential.secret_ciphertext,
		credential.secret_ciphertext_sha256,credential.request_digest,credential.challenge_expires_at,
		EXISTS(SELECT 1 FROM mfa_credential_events event
		       WHERE event.credential_id=credential.id AND event.event_type='activated')
		FROM mfa_credentials credential
		WHERE credential.user_id=$1 AND credential.scope_id=$2 AND credential.idempotency_key=$3
		FOR UPDATE OF credential`, actor.UserID, actor.ScopeID, key).Scan(&credential.id,
		&credential.userID, &credential.scopeID, &credential.accountLabel, &credential.keyID,
		&credential.ciphertext, &credential.ciphertextDigest, &credential.requestDigest,
		&credential.challengeExpires, &activated)
	if errors.Is(err, pgx.ErrNoRows) {
		return storedCredential{}, false, false, nil
	}
	return credential, err == nil, activated, err
}

func lockCredential(ctx context.Context, tx pgx.Tx, actor Actor, credentialID uuid.UUID) (storedCredential, error) {
	var credential storedCredential
	err := tx.QueryRow(ctx, `SELECT id,user_id,scope_id,account_label,secret_key_id,
		secret_ciphertext,secret_ciphertext_sha256,request_digest,challenge_expires_at
		FROM mfa_credentials WHERE id=$1 AND user_id=$2 AND scope_id=$3 FOR UPDATE`,
		credentialID, actor.UserID, actor.ScopeID).Scan(&credential.id, &credential.userID,
		&credential.scopeID, &credential.accountLabel, &credential.keyID, &credential.ciphertext,
		&credential.ciphertextDigest, &credential.requestDigest, &credential.challengeExpires)
	return credential, err
}

func lockActiveCredential(ctx context.Context, tx pgx.Tx, actor Actor) (storedCredential, error) {
	var credential storedCredential
	err := tx.QueryRow(ctx, `SELECT credential.id,credential.user_id,credential.scope_id,
		credential.account_label,credential.secret_key_id,credential.secret_ciphertext,
		credential.secret_ciphertext_sha256,credential.request_digest,credential.challenge_expires_at
		FROM mfa_credentials credential
		WHERE credential.user_id=$1 AND credential.scope_id=$2
		  AND EXISTS(SELECT 1 FROM mfa_credential_events event
		             WHERE event.credential_id=credential.id AND event.event_type='activated')
		  AND NOT EXISTS(SELECT 1 FROM mfa_credential_events event
		                 WHERE event.credential_id=credential.id AND event.event_type IN ('disabled','reset'))
		ORDER BY credential.created_at DESC,credential.id DESC LIMIT 1
		FOR UPDATE OF credential`, actor.UserID, actor.ScopeID).Scan(&credential.id,
		&credential.userID, &credential.scopeID, &credential.accountLabel, &credential.keyID,
		&credential.ciphertext, &credential.ciphertextDigest, &credential.requestDigest,
		&credential.challengeExpires)
	return credential, err
}

func lockPrincipalMFA(ctx context.Context, tx pgx.Tx, actor Actor) error {
	_, err := tx.Exec(ctx, `SELECT pg_advisory_xact_lock(hashtextextended($1,0))`,
		"mfa:"+actor.UserID.String()+":"+actor.ScopeID.String())
	return err
}

func hasActiveCredential(ctx context.Context, tx pgx.Tx, actor Actor) (bool, error) {
	var exists bool
	err := tx.QueryRow(ctx, `SELECT EXISTS(SELECT 1 FROM mfa_credentials credential
		WHERE credential.user_id=$1 AND credential.scope_id=$2
		AND EXISTS(SELECT 1 FROM mfa_credential_events event
		           WHERE event.credential_id=credential.id AND event.event_type='activated')
		AND NOT EXISTS(SELECT 1 FROM mfa_credential_events event
		               WHERE event.credential_id=credential.id AND event.event_type IN ('disabled','reset')))`,
		actor.UserID, actor.ScopeID).Scan(&exists)
	return exists, err
}

func hasPendingCredential(ctx context.Context, tx pgx.Tx, actor Actor, now time.Time) (bool, error) {
	var exists bool
	err := tx.QueryRow(ctx, `SELECT EXISTS(SELECT 1 FROM mfa_credentials credential
		WHERE credential.user_id=$1 AND credential.scope_id=$2 AND credential.challenge_expires_at>$3
		AND NOT EXISTS(SELECT 1 FROM mfa_credential_events event WHERE event.credential_id=credential.id))`,
		actor.UserID, actor.ScopeID, now).Scan(&exists)
	return exists, err
}

func credentialActivated(ctx context.Context, tx pgx.Tx, credentialID uuid.UUID) (bool, error) {
	var exists bool
	err := tx.QueryRow(ctx, `SELECT EXISTS(SELECT 1 FROM mfa_credential_events
		WHERE credential_id=$1 AND event_type='activated')`, credentialID).Scan(&exists)
	return exists, err
}

func loadCredentialEventIdempotency(
	ctx context.Context,
	tx pgx.Tx,
	credentialID uuid.UUID,
	eventType string,
	key string,
) ([]byte, time.Time, bool, error) {
	var digest []byte
	var occurredAt time.Time
	err := tx.QueryRow(ctx, `SELECT request_digest,occurred_at FROM mfa_credential_events
		WHERE credential_id=$1 AND event_type=$2 AND idempotency_key=$3`, credentialID,
		eventType, key).Scan(&digest, &occurredAt)
	if errors.Is(err, pgx.ErrNoRows) {
		return nil, time.Time{}, false, nil
	}
	return digest, occurredAt, err == nil, err
}

func loadTerminalEventIdempotency(
	ctx context.Context,
	tx pgx.Tx,
	actor Actor,
	eventType string,
	key string,
) ([]byte, bool, error) {
	var digest []byte
	err := tx.QueryRow(ctx, `SELECT event.request_digest FROM mfa_credential_events event
		JOIN mfa_credentials credential ON credential.id=event.credential_id
		WHERE credential.user_id=$1 AND credential.scope_id=$2 AND event.event_type=$3
		  AND event.idempotency_key=$4`, actor.UserID, actor.ScopeID, eventType, key).Scan(&digest)
	if errors.Is(err, pgx.ErrNoRows) {
		return nil, false, nil
	}
	return digest, err == nil, err
}

func loadProofByIdempotency(
	ctx context.Context,
	tx pgx.Tx,
	actor Actor,
	key string,
) (storedProof, bool, error) {
	var proof storedProof
	err := scanProof(tx.QueryRow(ctx, `SELECT id,actor_user_id,actor_scope_id,auth_session_id,
		tenant_id,credential_id,authentication_method,permissions_digest,audience,action,max_uses,
		request_digest,issued_at,expires_at FROM mfa_step_up_proofs
		WHERE actor_user_id=$1 AND actor_scope_id=$2 AND auth_session_id=$3 AND idempotency_key=$4
		FOR UPDATE`, actor.UserID, actor.ScopeID, actor.SessionID, key), &proof)
	if errors.Is(err, pgx.ErrNoRows) {
		return storedProof{}, false, nil
	}
	return proof, err == nil, err
}

func lockProofByToken(ctx context.Context, tx pgx.Tx, digest []byte) (storedProof, error) {
	var proof storedProof
	err := scanProof(tx.QueryRow(ctx, `SELECT id,actor_user_id,actor_scope_id,auth_session_id,
		tenant_id,credential_id,authentication_method,permissions_digest,audience,action,max_uses,
		request_digest,issued_at,expires_at FROM mfa_step_up_proofs
		WHERE token_digest=$1 FOR UPDATE`, digest), &proof)
	return proof, err
}

func lockProofCredentialActive(ctx context.Context, tx pgx.Tx, credentialID uuid.UUID) error {
	var lockedID uuid.UUID
	return tx.QueryRow(ctx, `SELECT credential.id FROM mfa_credentials credential
		WHERE credential.id=$1
		  AND EXISTS(SELECT 1 FROM mfa_credential_events event
		             WHERE event.credential_id=credential.id AND event.event_type='activated')
		  AND NOT EXISTS(SELECT 1 FROM mfa_credential_events event
		                 WHERE event.credential_id=credential.id AND event.event_type IN ('disabled','reset'))
		FOR UPDATE OF credential`, credentialID).Scan(&lockedID)
}

type rowScanner interface{ Scan(...any) error }

func scanProof(row rowScanner, proof *storedProof) error {
	var tenantID *uuid.UUID
	err := row.Scan(&proof.id, &proof.actorUserID, &proof.actorScopeID, &proof.sessionID,
		&tenantID, &proof.credentialID, &proof.method, &proof.permissionsDigest,
		&proof.audience, &proof.action, &proof.maxUses, &proof.requestDigest,
		&proof.issuedAt, &proof.expiresAt)
	// A platform-scoped proof has no tenant (uuid.Nil here).
	proof.tenantID = uuid.Nil
	if tenantID != nil {
		proof.tenantID = *tenantID
	}
	return err
}

func loadProofUseByRequest(
	ctx context.Context,
	tx pgx.Tx,
	proofID uuid.UUID,
	requestID string,
) (int, []byte, string, bool, error) {
	var ordinal int
	var binding []byte
	var traceID string
	err := tx.QueryRow(ctx, `SELECT use_ordinal,resource_binding_sha256,trace_id
		FROM mfa_step_up_uses WHERE proof_id=$1 AND request_id=$2`, proofID, requestID).
		Scan(&ordinal, &binding, &traceID)
	if errors.Is(err, pgx.ErrNoRows) {
		return 0, nil, "", false, nil
	}
	return ordinal, binding, traceID, err == nil, err
}

func countProofUses(ctx context.Context, tx pgx.Tx, proofID uuid.UUID) (int, error) {
	var count int
	err := tx.QueryRow(ctx, `SELECT count(*) FROM mfa_step_up_uses WHERE proof_id=$1`, proofID).Scan(&count)
	return count, err
}

func proofResult(proof storedProof, replayed bool) StepUpResult {
	return StepUpResult{ProofID: proof.id, Method: proof.method, IssuedAt: proof.issuedAt,
		ExpiresAt: proof.expiresAt, MaxUses: proof.maxUses, Replayed: replayed}
}

func evidenceForProof(proof storedProof, ordinal int, binding []byte) Evidence {
	return Evidence{ProofID: proof.id, ActorUserID: proof.actorUserID, ActorScopeID: proof.actorScopeID,
		SessionID: proof.sessionID,
		TenantID:  proof.tenantID, PlatformScope: proof.tenantID == uuid.Nil, Method: proof.method, Audience: proof.audience, Action: proof.action,
		VerifiedAt: proof.issuedAt, ExpiresAt: proof.expiresAt, UseOrdinal: ordinal,
		ResourceBindingDigest: append([]byte(nil), binding...)}
}

func generateProofToken(random io.Reader) (string, [32]byte, error) {
	raw := make([]byte, 32)
	if _, err := io.ReadFull(random, raw); err != nil {
		return "", [32]byte{}, fmt.Errorf("generate step-up token: %w", err)
	}
	token := base64.RawURLEncoding.EncodeToString(raw)
	clear(raw)
	return token, sha256.Sum256([]byte(token)), nil
}

func digestPermissions(permissions []string) [32]byte {
	values := append([]string(nil), permissions...)
	sort.Strings(values)
	hash := sha256.New()
	_, _ = hash.Write([]byte("cdnca-mfa-permissions/v1\x00"))
	for _, permission := range values {
		_, _ = hash.Write([]byte(permission))
		_, _ = hash.Write([]byte{0})
	}
	var result [32]byte
	copy(result[:], hash.Sum(nil))
	return result
}

func requestDigest(value any) [32]byte {
	encoded, _ := json.Marshal(value)
	return sha256.Sum256(encoded)
}

func internalEventKey(operation string, sessionID uuid.UUID, externalKey string) string {
	digest := sha256.Sum256([]byte(operation + "\x00" + sessionID.String() + "\x00" + externalKey))
	return "evt." + base64.RawURLEncoding.EncodeToString(digest[:])
}

func groupRecoveryCode(compact string) string {
	parts := make([]string, 0, 4)
	for len(compact) > 8 {
		parts = append(parts, compact[:8])
		compact = compact[8:]
	}
	parts = append(parts, compact)
	return strings.Join(parts, "-")
}

func normalizeRecoveryCode(code string) string {
	return strings.ToUpper(strings.ReplaceAll(strings.TrimSpace(code), "-", ""))
}

func normalizeAuthenticationCode(authentication Authentication) string {
	if authentication.Method == MethodRecoveryCode {
		return normalizeRecoveryCode(authentication.Code)
	}
	return authentication.Code
}

func validAuthentication(authentication Authentication) bool {
	return validCode(authentication.Method, authentication.Code)
}

func validCode(method, code string) bool {
	switch method {
	case MethodTOTP:
		return len(code) == TOTPDigits && strings.IndexFunc(code, func(r rune) bool {
			return r < '0' || r > '9'
		}) == -1
	case MethodRecoveryCode:
		normalized := normalizeRecoveryCode(code)
		return len(normalized) == 32 && strings.IndexFunc(normalized, func(r rune) bool {
			return (r < 'A' || r > 'Z') && (r < '2' || r > '7')
		}) == -1
	default:
		return false
	}
}

func validActor(actor Actor) bool {
	return actor.UserID != uuid.Nil && actor.ScopeID != uuid.Nil && actor.SessionID != uuid.Nil
}

func validMutation(key string, request RequestContext) bool {
	return idempotencyPattern.MatchString(key) && validRequestContext(request)
}

func validRequestContext(request RequestContext) bool {
	return validText(request.RequestID, 1, 128) && validText(request.TraceID, 1, 128) &&
		request.RequestID == strings.TrimSpace(request.RequestID) &&
		request.TraceID == strings.TrimSpace(request.TraceID)
}

func validateConsumeStepUp(actor Actor, request ConsumeStepUpRequest) error {
	if !validActor(actor) || !validProofScope(request.PlatformScope, request.TenantID) || !validProofToken(request.Token) ||
		!validText(request.Audience, 1, 128) || !validText(request.Action, 1, 128) ||
		!validRequestContext(request.Context) ||
		(len(request.ResourceBindingDigest) != 0 && len(request.ResourceBindingDigest) != sha256.Size) {
		return ErrInvalidInput
	}
	return nil
}

func validText(value string, minimum, maximum int) bool {
	if len(value) < minimum || len(value) > maximum || value != strings.TrimSpace(value) {
		return false
	}
	return strings.IndexFunc(value, func(r rune) bool {
		return unicode.IsControl(r) || r == '\u2028' || r == '\u2029'
	}) == -1
}

func validKeyID(value string) bool {
	if len(value) < 1 || len(value) > 128 {
		return false
	}
	for index, r := range value {
		if (r >= 'A' && r <= 'Z') || (r >= 'a' && r <= 'z') || (r >= '0' && r <= '9') ||
			r == '.' || r == '_' || r == ':' || r == '/' || r == '-' {
			continue
		}
		if index == 0 {
			return false
		}
		return false
	}
	first := value[0]
	return (first >= 'A' && first <= 'Z') || (first >= 'a' && first <= 'z') ||
		(first >= '0' && first <= '9')
}

func validProofToken(value string) bool {
	if len(value) != 43 {
		return false
	}
	decoded, err := base64.RawURLEncoding.DecodeString(value)
	return err == nil && len(decoded) == 32
}

func equalDigest(left, right []byte) bool {
	return len(left) == sha256.Size && len(right) == sha256.Size &&
		subtle.ConstantTimeCompare(left, right) == 1
}

func sameOptionalDigest(left, right []byte) bool {
	return len(left) == 0 && len(right) == 0 || equalDigest(left, right)
}

func nullableDigest(value []byte) any {
	if len(value) == 0 {
		return nil
	}
	return value
}

func storeTime(value time.Time) time.Time { return value.UTC().Truncate(time.Microsecond) }

func (s *Service) provisioningURI(accountLabel, secret string) string {
	value := &url.URL{Scheme: "otpauth", Host: "totp", Path: "/" + s.issuer + ":" + accountLabel}
	query := value.Query()
	query.Set("secret", secret)
	query.Set("issuer", s.issuer)
	query.Set("algorithm", "SHA1")
	query.Set("digits", fmt.Sprint(TOTPDigits))
	query.Set("period", fmt.Sprint(int(TOTPPeriod/time.Second)))
	value.RawQuery = query.Encode()
	return value.String()
}

func errorCode(err error) string {
	switch {
	case errors.Is(err, ErrInvalidCode):
		return "invalid_code"
	case errors.Is(err, ErrCodeReplayed):
		return "counter_replay"
	case errors.Is(err, ErrRecoveryCodeUsed):
		return "recovery_code_used"
	case errors.Is(err, ErrEnrollmentExpired):
		return "enrollment_expired"
	case errors.Is(err, ErrNotActive):
		return "mfa_not_active"
	case errors.Is(err, ErrInvalidProof):
		return "invalid_proof"
	case errors.Is(err, ErrProofBinding):
		return "proof_binding"
	case errors.Is(err, ErrProofExpired):
		return "proof_expired"
	case errors.Is(err, ErrProofConsumed):
		return "proof_consumed"
	case errors.Is(err, ErrPrincipalChanged):
		return "principal_changed"
	default:
		return "denied"
	}
}
