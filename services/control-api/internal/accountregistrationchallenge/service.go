package accountregistrationchallenge

import (
	"bytes"
	"context"
	"crypto/hmac"
	"crypto/rand"
	"crypto/sha256"
	"crypto/subtle"
	"encoding/base64"
	"encoding/binary"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"math/big"
	"net/mail"
	"net/netip"
	"regexp"
	"strings"
	"time"
	"unicode"

	"github.com/cdnca/cdnca/services/control-api/internal/accountregistration"
	"github.com/cdnca/cdnca/services/control-api/internal/accountregistrationproof"
	"github.com/cdnca/cdnca/services/control-api/internal/notification"
	"github.com/cdnca/cdnca/services/control-api/internal/phonenumber"
	"github.com/cdnca/cdnca/services/control-api/internal/systemusersettings"
	"github.com/google/uuid"
	"github.com/jackc/pgx/v5"
	"github.com/jackc/pgx/v5/pgconn"
	"github.com/jackc/pgx/v5/pgxpool"
)

const (
	defaultChallengeTTL = 10 * time.Minute
	maximumChallengeTTL = 30 * time.Minute
	defaultRateWindow   = 15 * time.Minute
	maximumRateWindow   = 24 * time.Hour
	defaultSourceLimit  = 10
	defaultSubjectLimit = 5
	defaultMaxAttempts  = 5
)

var (
	usernamePattern = regexp.MustCompile(`^[a-z0-9][a-z0-9._-]{2,127}$`)
	metadataPattern = regexp.MustCompile(`^[A-Za-z0-9][A-Za-z0-9._-]{0,127}$`)
	otpPattern      = regexp.MustCompile(`^[0-9]{6}$`)

	humanTokenDigestDomain  = []byte("account-registration-challenge:v1:human-token\x00")
	destinationDigestDomain = []byte("account-registration-challenge:v1:destination\x00")
	sourceDigestDomain      = []byte("account-registration-challenge:v1:source\x00")
	otpDigestDomain         = []byte("account-registration-challenge:v1:otp\x00")
	createDigestDomain      = []byte("account-registration-challenge:v1:create-request\x00")
	verifyDigestDomain      = []byte("account-registration-challenge:v1:verify-request\x00")
)

type Service struct {
	pool         *pgxpool.Pool
	human        HumanVerifier
	contacts     ContactSender
	proofs       ProofIssuer
	proofKeys    *EnvelopeKeyring
	policy       systemusersettingsReader
	templates    registrationVerificationTemplateReader
	digestKey    []byte
	now          func() time.Time
	entropy      io.Reader
	challengeTTL time.Duration
	maxAttempts  int
	rateWindow   time.Duration
	sourceLimit  int
	subjectLimit int
}

type normalizedCreate struct {
	CreateInput
	Destination       string
	SubjectDigest     [32]byte
	DestinationDigest [32]byte
	SourceDigest      [32]byte
	HumanTokenDigest  [32]byte
}

type normalizedVerify struct {
	VerifyInput
	Destination       string
	SubjectDigest     [32]byte
	DestinationDigest [32]byte
	SourceDigest      [32]byte
}

type storedChallenge struct {
	id                   uuid.UUID
	scopeID              uuid.UUID
	writeIdempotencyKey  string
	channel              string
	subjectDigest        []byte
	destinationDigest    []byte
	sourceDigest         []byte
	otpDigest            []byte
	attemptRevision      int64
	failedAttempts       int
	maxAttempts          int
	humanVerifiedAt      time.Time
	expiresAt            time.Time
	state                string
	proofEvidenceID      *uuid.UUID
	proofKeyID           *string
	proofNonce           []byte
	sealedProofReference []byte
	proofExpiresAt       *time.Time
}

func NewService(
	pool *pgxpool.Pool,
	human HumanVerifier,
	contacts ContactSender,
	proofs ProofIssuer,
	proofKeys *EnvelopeKeyring,
	config Config,
) (*Service, error) {
	if pool == nil || human == nil || contacts == nil || proofs == nil || !validEnvelopeKeyring(proofKeys) ||
		len(config.DigestKey) < 32 {
		return nil, ErrInvalidConfig
	}
	if config.Clock == nil {
		config.Clock = time.Now
	}
	if config.Entropy == nil {
		config.Entropy = rand.Reader
	}
	if config.ChallengeTTL == 0 {
		config.ChallengeTTL = defaultChallengeTTL
	}
	if config.MaxAttempts == 0 {
		config.MaxAttempts = defaultMaxAttempts
	}
	if config.RateWindow == 0 {
		config.RateWindow = defaultRateWindow
	}
	if config.SourceLimit == 0 {
		config.SourceLimit = defaultSourceLimit
	}
	if config.SubjectLimit == 0 {
		config.SubjectLimit = defaultSubjectLimit
	}
	if config.ChallengeTTL <= 0 || config.ChallengeTTL > maximumChallengeTTL ||
		config.MaxAttempts < 1 || config.MaxAttempts > 10 ||
		config.RateWindow <= 0 || config.RateWindow > maximumRateWindow ||
		config.SourceLimit < 1 || config.SourceLimit > 1000 || config.SubjectLimit < 1 || config.SubjectLimit > 1000 {
		return nil, ErrInvalidConfig
	}
	return &Service{
		pool: pool, human: human, contacts: contacts, proofs: proofs, proofKeys: proofKeys,
		policy: config.PublicSettings, templates: config.TemplateSettings,
		digestKey: append([]byte(nil), config.DigestKey...), now: config.Clock, entropy: config.Entropy,
		challengeTTL: config.ChallengeTTL, maxAttempts: config.MaxAttempts, rateWindow: config.RateWindow,
		sourceLimit: config.SourceLimit, subjectLimit: config.SubjectLimit,
	}, nil
}

func (service *Service) Create(ctx context.Context, input CreateInput) (CreateResult, error) {
	if service == nil || service.pool == nil || service.human == nil || service.contacts == nil ||
		service.proofs == nil || len(service.digestKey) < 32 {
		return CreateResult{}, ErrChallengeUnavailable
	}
	phoneCode, err := service.phoneCountryCode(ctx, input.ScopeID, input.Phone)
	if err != nil {
		return CreateResult{}, err
	}
	normalized, err := normalizeCreateInput(input, service.digestKey, phoneCode)
	if err != nil {
		return CreateResult{}, err
	}
	if err := service.checkPolicy(ctx, normalized.ScopeID, normalized.Email, normalized.Phone); err != nil {
		return CreateResult{}, err
	}
	requestDigest := createRequestDigest(service.digestKey, normalized)
	state := ""
	newWrite := false
	var replay CreateResult
	var outcomeErr error
	err = pgx.BeginTxFunc(ctx, service.pool, pgx.TxOptions{IsoLevel: pgx.Serializable}, func(tx pgx.Tx) error {
		var storedDigest []byte
		err := tx.QueryRow(ctx, `SELECT request_digest,state
			FROM account_registration_challenge_writes_163
			WHERE scope_id=$1 AND idempotency_key=$2 FOR UPDATE`,
			normalized.ScopeID, normalized.IdempotencyKey).Scan(&storedDigest, &state)
		if err == nil {
			if !hmac.Equal(storedDigest, requestDigest[:]) {
				outcomeErr = ErrIdempotencyConflict
				return nil
			}
			if state == "queued" {
				replay, err = loadChallengeByWrite(ctx, tx, normalized.ScopeID, normalized.IdempotencyKey)
				replay.Replayed = true
			}
			return err
		}
		if !errors.Is(err, pgx.ErrNoRows) {
			return err
		}
		now := storeTime(service.now())
		var sourceCount, subjectCount int
		if err := tx.QueryRow(ctx, `SELECT
			count(*) FILTER (WHERE source_digest=$1),
			count(*) FILTER (WHERE subject_digest=$2)
			FROM account_registration_challenge_writes_163 WHERE created_at>=$3`,
			normalized.SourceDigest[:], normalized.SubjectDigest[:], now.Add(-service.rateWindow)).
			Scan(&sourceCount, &subjectCount); err != nil {
			return err
		}
		if sourceCount >= service.sourceLimit || subjectCount >= service.subjectLimit {
			outcomeErr = ErrRateLimited
			return nil
		}
		_, err = tx.Exec(ctx, `INSERT INTO account_registration_challenge_writes_163 (
			scope_id,idempotency_key,request_digest,human_token_digest,subject_digest,source_digest,
			state,created_at,updated_at
		) VALUES($1,$2,$3,$4,$5,$6,'human_verifying',$7,$7)`, normalized.ScopeID,
			normalized.IdempotencyKey, requestDigest[:], normalized.HumanTokenDigest[:],
			normalized.SubjectDigest[:], normalized.SourceDigest[:], now)
		if err == nil {
			newWrite = true
			state = "human_verifying"
		}
		return err
	})
	if err != nil {
		var pgErr *pgconn.PgError
		if errors.As(err, &pgErr) && pgErr.Code == "23505" {
			return CreateResult{}, ErrHumanInvalid
		}
		return CreateResult{}, ErrChallengeUnavailable
	}
	if outcomeErr != nil {
		return CreateResult{}, outcomeErr
	}
	if replay.ChallengeID != uuid.Nil {
		return replay, nil
	}
	if newWrite {
		humanErr := service.human.Verify(ctx, HumanVerification{
			Token: normalized.HumanToken, Source: normalized.Source, IdempotencyKey: normalized.IdempotencyKey,
		})
		nextState := "human_verified"
		switch {
		case errors.Is(humanErr, ErrHumanInvalid):
			nextState = "human_rejected"
		case humanErr != nil:
			nextState = "human_unknown"
		}
		now := storeTime(service.now())
		command, updateErr := service.pool.Exec(ctx, `UPDATE account_registration_challenge_writes_163
			SET state=$3,human_verified_at=CASE WHEN $3='human_verified' THEN $4 ELSE NULL END,updated_at=$4
			WHERE scope_id=$1 AND idempotency_key=$2 AND state='human_verifying'`,
			normalized.ScopeID, normalized.IdempotencyKey, nextState, now)
		if updateErr != nil || command.RowsAffected() != 1 {
			return CreateResult{}, ErrChallengeUnavailable
		}
		state = nextState
	}
	switch state {
	case "human_verified":
		return service.finalizeCreate(ctx, normalized, requestDigest)
	case "human_rejected":
		return CreateResult{}, ErrHumanInvalid
	case "human_unknown", "human_verifying":
		return CreateResult{}, ErrHumanUnavailable
	default:
		return CreateResult{}, ErrChallengeUnavailable
	}
}

func (service *Service) finalizeCreate(
	ctx context.Context,
	input normalizedCreate,
	requestDigest [32]byte,
) (CreateResult, error) {
	var template notification.TemplateRef
	if service.templates != nil {
		resolved, found, err := service.templates.GetRegistrationVerificationTemplate(
			ctx, input.ScopeID, notification.Channel(input.Channel),
		)
		if err == nil && found {
			template = resolved
		}
	}
	var result CreateResult
	err := pgx.BeginTxFunc(ctx, service.pool, pgx.TxOptions{IsoLevel: pgx.Serializable}, func(tx pgx.Tx) error {
		var storedDigest []byte
		var state string
		var humanVerifiedAt *time.Time
		if err := tx.QueryRow(ctx, `SELECT request_digest,state,human_verified_at
			FROM account_registration_challenge_writes_163
			WHERE scope_id=$1 AND idempotency_key=$2 FOR UPDATE`, input.ScopeID, input.IdempotencyKey).
			Scan(&storedDigest, &state, &humanVerifiedAt); err != nil {
			return err
		}
		if !hmac.Equal(storedDigest, requestDigest[:]) {
			return ErrIdempotencyConflict
		}
		if state == "queued" {
			var err error
			result, err = loadChallengeByWrite(ctx, tx, input.ScopeID, input.IdempotencyKey)
			result.Replayed = true
			return err
		}
		if state != "human_verified" || humanVerifiedAt == nil {
			return ErrHumanUnavailable
		}
		now := storeTime(service.now())
		if _, err := tx.Exec(ctx, `SELECT pg_advisory_xact_lock(hashtextextended(
			'account-registration-challenge:v1:'||$1::text||':'||$2||':'||encode($3,'hex')||':'||
			encode($4,'hex')||':'||encode($5,'hex'),0))`, input.ScopeID, input.Channel,
			input.SubjectDigest[:], input.DestinationDigest[:], input.SourceDigest[:]); err != nil {
			return err
		}
		var active bool
		if err := tx.QueryRow(ctx, `SELECT EXISTS(
			SELECT 1 FROM account_registration_challenges_163
			WHERE scope_id=$1 AND channel=$2 AND subject_digest=$3 AND destination_digest=$4
			  AND source_digest=$5 AND expires_at>$6
		)`, input.ScopeID, input.Channel, input.SubjectDigest[:], input.DestinationDigest[:],
			input.SourceDigest[:], now).Scan(&active); err != nil {
			return err
		}
		if active {
			return ErrRateLimited
		}
		challengeID, err := uuid.NewV7()
		if err != nil {
			return err
		}
		otp, err := randomOTP(service.entropy)
		if err != nil {
			return err
		}
		expiresAt := now.Add(service.challengeTTL)
		otpDigest := keyedDigest(service.digestKey, otpDigestDomain, []byte(otp))
		_, err = tx.Exec(ctx, `INSERT INTO account_registration_challenges_163 (
			id,scope_id,write_idempotency_key,channel,subject_digest,destination_digest,source_digest,
			otp_digest,attempt_revision,failed_attempts,max_attempts,human_verified_at,issued_at,expires_at,state
		) VALUES($1,$2,$3,$4,$5,$6,$7,$8,1,0,$9,$10,$11,$12,'queued')`, challengeID,
			input.ScopeID, input.IdempotencyKey, input.Channel, input.SubjectDigest[:], input.DestinationDigest[:],
			input.SourceDigest[:], otpDigest[:], service.maxAttempts, storeTime(*humanVerifiedAt), now, expiresAt)
		if err != nil {
			return err
		}
		channel := notification.Channel(input.Channel)
		if _, err := service.contacts.Enqueue(ctx, tx, ContactRequest{
			ScopeID: input.ScopeID, ChallengeID: challengeID, Channel: channel, Template: template,
			Destination:       input.Destination,
			DestinationDigest: input.DestinationDigest, OTP: otp, ExpiresAt: expiresAt, RequestID: input.RequestID,
		}); err != nil {
			return ErrContactUnavailable
		}
		command, err := tx.Exec(ctx, `UPDATE account_registration_challenge_writes_163
			SET state='queued',updated_at=$3 WHERE scope_id=$1 AND idempotency_key=$2 AND state='human_verified'`,
			input.ScopeID, input.IdempotencyKey, now)
		if err != nil || command.RowsAffected() != 1 {
			return ErrChallengeUnavailable
		}
		result = CreateResult{ChallengeID: challengeID, ExpiresAt: expiresAt}
		return nil
	})
	if err != nil {
		if errors.Is(err, ErrIdempotencyConflict) || errors.Is(err, ErrHumanUnavailable) ||
			errors.Is(err, ErrContactUnavailable) || errors.Is(err, ErrRateLimited) {
			return CreateResult{}, err
		}
		return CreateResult{}, ErrChallengeUnavailable
	}
	return result, nil
}

func (service *Service) Verify(ctx context.Context, input VerifyInput) (VerifyResult, error) {
	if service == nil || service.pool == nil || service.proofs == nil || !validEnvelopeKeyring(service.proofKeys) {
		return VerifyResult{}, ErrChallengeUnavailable
	}
	phoneCode, err := service.phoneCountryCode(ctx, input.ScopeID, input.Phone)
	if err != nil {
		return VerifyResult{}, err
	}
	normalized, err := normalizeVerifyInput(input, service.digestKey, phoneCode)
	if err != nil {
		return VerifyResult{}, err
	}
	if err := service.checkPolicy(ctx, normalized.ScopeID, normalized.Email, normalized.Phone); err != nil {
		return VerifyResult{}, err
	}
	requestDigest := verifyRequestDigest(service.digestKey, normalized)
	var result VerifyResult
	var outcomeErr error
	err = pgx.BeginTxFunc(ctx, service.pool, pgx.TxOptions{IsoLevel: pgx.Serializable}, func(tx pgx.Tx) error {
		challenge, err := loadChallenge(ctx, tx, normalized.ChallengeID)
		if err != nil {
			if errors.Is(err, pgx.ErrNoRows) {
				outcomeErr = ErrOTPInvalid
				return nil
			}
			return err
		}
		if !validChallengeBinding(challenge, normalized) {
			outcomeErr = ErrOTPInvalid
			return nil
		}
		var storedDigest []byte
		var storedOutcome string
		receiptErr := tx.QueryRow(ctx, `SELECT request_digest,outcome
			FROM account_registration_challenge_verify_receipts_163
			WHERE challenge_id=$1 AND idempotency_key=$2 FOR UPDATE`, challenge.id, normalized.IdempotencyKey).
			Scan(&storedDigest, &storedOutcome)
		if receiptErr == nil {
			if !hmac.Equal(storedDigest, requestDigest[:]) {
				outcomeErr = ErrIdempotencyConflict
				return nil
			}
			switch storedOutcome {
			case "verified":
				result, err = service.replayProof(challenge)
				result.Replayed = true
				return err
			case "rate_limited":
				outcomeErr = ErrRateLimited
			case "invalid":
				outcomeErr = ErrOTPInvalid
			default:
				outcomeErr = ErrChallengeUnavailable
			}
			return nil
		}
		if !errors.Is(receiptErr, pgx.ErrNoRows) {
			return receiptErr
		}
		if challenge.state == "verified" {
			outcomeErr = ErrOTPInvalid
			return nil
		}
		now := storeTime(service.now())
		if challenge.state != "queued" || !now.Before(challenge.expiresAt) || challenge.failedAttempts >= challenge.maxAttempts {
			if err := insertVerifyReceipt(ctx, tx, challenge.id, normalized.IdempotencyKey,
				requestDigest, "rate_limited", now); err != nil {
				return err
			}
			outcomeErr = ErrRateLimited
			return nil
		}
		otpDigest := keyedDigest(service.digestKey, otpDigestDomain, []byte(normalized.OTP))
		if subtle.ConstantTimeCompare(challenge.otpDigest, otpDigest[:]) != 1 {
			command, err := tx.Exec(ctx, `UPDATE account_registration_challenges_163
				SET failed_attempts=failed_attempts+1
				WHERE id=$1 AND state='queued' AND failed_attempts=$2`, challenge.id, challenge.failedAttempts)
			if err != nil || command.RowsAffected() != 1 {
				return ErrChallengeUnavailable
			}
			outcome := "invalid"
			outcomeErr = ErrOTPInvalid
			if challenge.failedAttempts+1 >= challenge.maxAttempts {
				outcome = "rate_limited"
				outcomeErr = ErrRateLimited
			}
			return insertVerifyReceipt(ctx, tx, challenge.id, normalized.IdempotencyKey, requestDigest, outcome, now)
		}
		proofExpiresAt := challenge.expiresAt
		if limit := now.Add(5 * time.Minute); proofExpiresAt.After(limit) {
			proofExpiresAt = limit
		}
		issued, err := service.proofs.Issue(ctx, accountregistrationproof.IssueRequest{
			Channel: normalized.Channel, Destination: normalized.Destination, Source: normalized.Source,
			SubjectDigest: normalized.SubjectDigest, HumanVerifiedAt: challenge.humanVerifiedAt,
			ContactVerifiedAt: now, ExpiresAt: proofExpiresAt, AttemptRevision: challenge.attemptRevision,
			RiskContext: accountregistrationproof.RiskContextNormal,
		})
		if err != nil || issued.Reference == "" || issued.Proof.EvidenceID == uuid.Nil ||
			issued.Proof.Channel != normalized.Channel || issued.Proof.Destination != normalized.Destination {
			return ErrChallengeUnavailable
		}
		aad := proofReferenceAAD(challenge.id, issued.Proof.EvidenceID, normalized.SubjectDigest, normalized.SourceDigest)
		sealed, err := service.proofKeys.Seal([]byte(issued.Reference), aad)
		if err != nil {
			return err
		}
		command, err := tx.Exec(ctx, `UPDATE account_registration_challenges_163 SET
			state='verified',contact_verified_at=$2,proof_evidence_id=$3,proof_key_id=$4,
			proof_nonce=$5,sealed_proof_reference=$6,proof_expires_at=$7
			WHERE id=$1 AND state='queued'`, challenge.id, now, issued.Proof.EvidenceID,
			sealed.KeyID, sealed.Nonce, sealed.Ciphertext, issued.Proof.ExpiresAt)
		if err != nil || command.RowsAffected() != 1 {
			return ErrChallengeUnavailable
		}
		if err := insertVerifyReceipt(ctx, tx, challenge.id, normalized.IdempotencyKey,
			requestDigest, "verified", now); err != nil {
			return err
		}
		result = VerifyResult{Reference: issued.Reference, ExpiresAt: issued.Proof.ExpiresAt}
		return nil
	})
	if err != nil {
		if errors.Is(err, ErrChallengeUnavailable) {
			return VerifyResult{}, ErrChallengeUnavailable
		}
		return VerifyResult{}, ErrChallengeUnavailable
	}
	if outcomeErr != nil {
		return VerifyResult{}, outcomeErr
	}
	return result, nil
}

func (service *Service) checkPolicy(ctx context.Context, scopeID uuid.UUID, email, phone string) error {
	if service == nil || service.policy == nil {
		return nil
	}
	if scopeID == uuid.Nil {
		return ErrPolicyUnavailable
	}
	policy, err := service.policy.GetPublic(ctx, scopeID)
	if err != nil {
		return ErrPolicyUnavailable
	}
	if !policy.RegistrationEnabled {
		return ErrRegistrationDisabled
	}
	if policy.EmailRequired && email == "" || policy.PhoneRequired && phone == "" ||
		policy.EmailVerificationRequired && email == "" || policy.PhoneVerificationRequired && phone == "" {
		return ErrInvalidInput
	}
	return nil
}

func loadChallengeByWrite(ctx context.Context, tx pgx.Tx, scopeID uuid.UUID, key string) (CreateResult, error) {
	var result CreateResult
	err := tx.QueryRow(ctx, `SELECT id,expires_at FROM account_registration_challenges_163
		WHERE scope_id=$1 AND write_idempotency_key=$2`, scopeID, key).Scan(&result.ChallengeID, &result.ExpiresAt)
	return result, err
}

func loadChallenge(ctx context.Context, tx pgx.Tx, id uuid.UUID) (storedChallenge, error) {
	var challenge storedChallenge
	err := tx.QueryRow(ctx, `SELECT id,scope_id,write_idempotency_key,channel,subject_digest,destination_digest,
		source_digest,otp_digest,attempt_revision,failed_attempts,max_attempts,human_verified_at,expires_at,state,
		proof_evidence_id,proof_key_id,proof_nonce,sealed_proof_reference,proof_expires_at
		FROM account_registration_challenges_163 WHERE id=$1 FOR UPDATE`, id).Scan(
		&challenge.id, &challenge.scopeID, &challenge.writeIdempotencyKey, &challenge.channel,
		&challenge.subjectDigest, &challenge.destinationDigest, &challenge.sourceDigest, &challenge.otpDigest,
		&challenge.attemptRevision, &challenge.failedAttempts, &challenge.maxAttempts, &challenge.humanVerifiedAt,
		&challenge.expiresAt, &challenge.state, &challenge.proofEvidenceID, &challenge.proofKeyID,
		&challenge.proofNonce, &challenge.sealedProofReference, &challenge.proofExpiresAt,
	)
	return challenge, err
}

func (service *Service) replayProof(challenge storedChallenge) (VerifyResult, error) {
	if challenge.state != "verified" || challenge.proofEvidenceID == nil || challenge.proofKeyID == nil ||
		challenge.proofExpiresAt == nil || len(challenge.proofNonce) == 0 || len(challenge.sealedProofReference) == 0 ||
		!service.now().Before(*challenge.proofExpiresAt) {
		return VerifyResult{}, ErrOTPInvalid
	}
	var subjectDigest, sourceDigest [32]byte
	if len(challenge.subjectDigest) != 32 || len(challenge.sourceDigest) != 32 {
		return VerifyResult{}, ErrChallengeUnavailable
	}
	copy(subjectDigest[:], challenge.subjectDigest)
	copy(sourceDigest[:], challenge.sourceDigest)
	aad := proofReferenceAAD(challenge.id, *challenge.proofEvidenceID, subjectDigest, sourceDigest)
	reference, err := service.proofKeys.Open(SealedEnvelope{
		KeyID: *challenge.proofKeyID, Nonce: challenge.proofNonce, Ciphertext: challenge.sealedProofReference,
	}, aad)
	if err != nil {
		return VerifyResult{}, ErrChallengeUnavailable
	}
	return VerifyResult{Reference: string(reference), ExpiresAt: *challenge.proofExpiresAt}, nil
}

func insertVerifyReceipt(
	ctx context.Context,
	tx pgx.Tx,
	challengeID uuid.UUID,
	idempotencyKey string,
	requestDigest [32]byte,
	outcome string,
	now time.Time,
) error {
	_, err := tx.Exec(ctx, `INSERT INTO account_registration_challenge_verify_receipts_163 (
		challenge_id,idempotency_key,request_digest,outcome,created_at
	) VALUES($1,$2,$3,$4,$5)`, challengeID, idempotencyKey, requestDigest[:], outcome, now)
	return err
}

func validChallengeBinding(challenge storedChallenge, input normalizedVerify) bool {
	return challenge.id == input.ChallengeID && challenge.scopeID == input.ScopeID && challenge.channel == input.Channel &&
		hmac.Equal(challenge.subjectDigest, input.SubjectDigest[:]) &&
		hmac.Equal(challenge.destinationDigest, input.DestinationDigest[:]) &&
		hmac.Equal(challenge.sourceDigest, input.SourceDigest[:])
}

// phoneCountryCode reads the platform default calling code for a bare phone
// number (FX38); unavailable settings fail closed like the policy check.
func (service *Service) phoneCountryCode(ctx context.Context, scopeID uuid.UUID, phone string) (string, error) {
	if service.policy == nil || strings.TrimSpace(phone) == "" {
		return "", nil
	}
	if scopeID == uuid.Nil {
		return "", ErrPolicyUnavailable
	}
	code, err := systemusersettings.PhoneCountryCode(ctx, service.policy, scopeID, phone)
	if err != nil {
		return "", ErrPolicyUnavailable
	}
	return code, nil
}

func normalizeCreateInput(input CreateInput, key []byte, phoneCode string) (normalizedCreate, error) {
	username, email, phone, destination, source, err := normalizeSubject(
		input.Username, input.Email, input.Phone, input.Channel, input.Source, phoneCode,
	)
	if err != nil || input.ScopeID == uuid.Nil || len(key) < 32 || len(input.HumanToken) < 22 ||
		len(input.HumanToken) > 4096 || strings.TrimSpace(input.HumanToken) != input.HumanToken ||
		strings.IndexFunc(input.HumanToken, unicode.IsSpace) >= 0 ||
		!metadataPattern.MatchString(input.IdempotencyKey) || !metadataPattern.MatchString(input.RequestID) {
		return normalizedCreate{}, ErrInvalidInput
	}
	subjectDigest, err := registrationSubjectDigest(key, username, email, phone)
	if err != nil {
		return normalizedCreate{}, ErrInvalidInput
	}
	input.Username, input.Email, input.Phone, input.Source = username, email, phone, source
	return normalizedCreate{
		CreateInput: input, Destination: destination, SubjectDigest: subjectDigest,
		DestinationDigest: keyedDigest(key, destinationDigestDomain, []byte(destination)),
		SourceDigest:      keyedDigest(key, sourceDigestDomain, []byte(source)),
		HumanTokenDigest:  keyedDigest(key, humanTokenDigestDomain, []byte(input.HumanToken)),
	}, nil
}

func normalizeVerifyInput(input VerifyInput, key []byte, phoneCode string) (normalizedVerify, error) {
	username, email, phone, destination, source, err := normalizeSubject(
		input.Username, input.Email, input.Phone, input.Channel, input.Source, phoneCode,
	)
	if err != nil || input.ScopeID == uuid.Nil || input.ChallengeID == uuid.Nil || len(key) < 32 ||
		!otpPattern.MatchString(input.OTP) || !metadataPattern.MatchString(input.IdempotencyKey) ||
		!metadataPattern.MatchString(input.RequestID) {
		return normalizedVerify{}, ErrInvalidInput
	}
	subjectDigest, err := registrationSubjectDigest(key, username, email, phone)
	if err != nil {
		return normalizedVerify{}, ErrInvalidInput
	}
	input.Username, input.Email, input.Phone, input.Source = username, email, phone, source
	return normalizedVerify{
		VerifyInput: input, Destination: destination, SubjectDigest: subjectDigest,
		DestinationDigest: keyedDigest(key, destinationDigestDomain, []byte(destination)),
		SourceDigest:      keyedDigest(key, sourceDigestDomain, []byte(source)),
	}, nil
}

func normalizeSubject(username, email, phone, channel, source, phoneCode string) (string, string, string, string, string, error) {
	username = strings.ToLower(strings.TrimSpace(username))
	email = strings.ToLower(strings.TrimSpace(email))
	phone, err := phonenumber.Normalize(phone, phoneCode)
	if err != nil || !usernamePattern.MatchString(username) || len(email) > 254 {
		return "", "", "", "", "", ErrInvalidInput
	}
	address, err := mail.ParseAddress(email)
	if err != nil || address.Address != email {
		return "", "", "", "", "", ErrInvalidInput
	}
	destination := email
	if channel == accountregistration.VerificationSMS {
		destination = phone
	} else if channel != accountregistration.VerificationEmail {
		return "", "", "", "", "", ErrInvalidInput
	}
	ip, err := netip.ParseAddr(source)
	if err != nil || !ip.IsValid() || ip.Zone() != "" || ip.IsUnspecified() || ip.IsMulticast() ||
		ip.Unmap().String() != source {
		return "", "", "", "", "", ErrInvalidInput
	}
	return username, email, phone, destination, source, nil
}

func registrationSubjectDigest(key []byte, username, email, phone string) ([32]byte, error) {
	value, err := json.Marshal(struct {
		Username string `json:"username"`
		Email    string `json:"email"`
		Phone    string `json:"phone"`
	}{username, email, phone})
	if err != nil {
		return [32]byte{}, err
	}
	digest := hmac.New(sha256.New, key)
	_, _ = digest.Write(value)
	var result [32]byte
	copy(result[:], digest.Sum(nil))
	return result, nil
}

func createRequestDigest(key []byte, input normalizedCreate) [32]byte {
	value := bytes.NewBuffer(nil)
	writeDigestValue(value, input.ScopeID.String())
	writeDigestValue(value, input.Username)
	writeDigestValue(value, input.Email)
	writeDigestValue(value, input.Phone)
	writeDigestValue(value, input.Channel)
	writeDigestValue(value, input.Source)
	writeDigestValue(value, base64.RawURLEncoding.EncodeToString(input.HumanTokenDigest[:]))
	return keyedDigest(key, createDigestDomain, value.Bytes())
}

func verifyRequestDigest(key []byte, input normalizedVerify) [32]byte {
	value := bytes.NewBuffer(nil)
	for _, item := range []string{
		input.ScopeID.String(), input.ChallengeID.String(), input.Username, input.Email, input.Phone,
		input.Channel, input.Source, input.OTP,
	} {
		writeDigestValue(value, item)
	}
	return keyedDigest(key, verifyDigestDomain, value.Bytes())
}

func keyedDigest(key, domain, value []byte) [32]byte {
	digest := hmac.New(sha256.New, key)
	_, _ = digest.Write(domain)
	_, _ = digest.Write(value)
	var result [32]byte
	copy(result[:], digest.Sum(nil))
	return result
}

func writeDigestValue(buffer *bytes.Buffer, value string) {
	_ = binary.Write(buffer, binary.BigEndian, uint32(len(value)))
	_, _ = buffer.WriteString(value)
}

func randomOTP(entropy io.Reader) (string, error) {
	value, err := rand.Int(entropy, big.NewInt(1_000_000))
	if err != nil {
		return "", ErrChallengeUnavailable
	}
	return fmt.Sprintf("%06d", value.Int64()), nil
}

func proofReferenceAAD(challengeID, evidenceID uuid.UUID, subjectDigest, sourceDigest [32]byte) []byte {
	value := bytes.NewBuffer(nil)
	for _, item := range [][]byte{
		[]byte("account-registration-challenge:v1:proof-reference"), []byte(challengeID.String()),
		[]byte(evidenceID.String()), subjectDigest[:], sourceDigest[:],
	} {
		_ = binary.Write(value, binary.BigEndian, uint32(len(item)))
		_, _ = value.Write(item)
	}
	return value.Bytes()
}

func storeTime(value time.Time) time.Time {
	return value.UTC().Truncate(time.Microsecond)
}
