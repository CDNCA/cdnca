package accountloginchallenge

import (
	"bytes"
	"context"
	"crypto/hmac"
	"crypto/rand"
	"crypto/sha256"
	"encoding/binary"
	"errors"
	"fmt"
	"io"
	"math/big"
	"net/mail"
	"net/netip"
	"regexp"
	"strings"
	"time"

	"github.com/cdnca/cdnca/services/control-api/internal/identity"
	"github.com/cdnca/cdnca/services/control-api/internal/notification"
	"github.com/cdnca/cdnca/services/control-api/internal/phonenumber"
	"github.com/cdnca/cdnca/services/control-api/internal/systemusersettings"
	"github.com/google/uuid"
	"github.com/jackc/pgx/v5"
	"github.com/jackc/pgx/v5/pgconn"
	"github.com/jackc/pgx/v5/pgxpool"
)

const (
	defaultChallengeTTL = 5 * time.Minute
	defaultRateWindow   = 15 * time.Minute
	defaultSourceLimit  = 10
	defaultSubjectLimit = 5
	defaultMaxAttempts  = 5
)

var (
	otpPattern      = regexp.MustCompile(`^[0-9]{6}$`)
	metadataPattern = regexp.MustCompile(`^[A-Za-z0-9][A-Za-z0-9._-]{0,127}$`)

	identifierDigestDomain = []byte("account-login-challenge:v1:identifier\x00")
	sourceDigestDomain     = []byte("account-login-challenge:v1:source\x00")
	otpDigestDomain        = []byte("account-login-challenge:v1:otp\x00")
	createDigestDomain     = []byte("account-login-challenge:v1:create\x00")
	verifyDigestDomain     = []byte("account-login-challenge:v1:verify\x00")
)

type Service struct {
	pool                *pgxpool.Pool
	policy              PolicyReader
	templates           TemplateReader
	human               HumanVerifier
	issuer              SessionIssuer
	contacts            ContactSender
	digestKey           []byte
	now                 func() time.Time
	entropy             io.Reader
	challengeTTL        time.Duration
	rateWindow          time.Duration
	sourceLimit         int
	subjectLimit        int
	maxAttempts         int
	availableChannels   []notification.Channel
	registrationMounted bool
}

type normalizedCreate struct {
	CreateInput
	IdentifierDigest [32]byte
	SourceDigest     [32]byte
}

type normalizedVerify struct {
	VerifyInput
	IdentifierDigest [32]byte
	SourceDigest     [32]byte
}

func NewService(pool *pgxpool.Pool, config Config) (*Service, error) {
	if pool == nil || len(config.DigestKey) < 32 || config.Policy == nil || config.Issuer == nil || config.Contacts == nil {
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
	if config.RateWindow == 0 {
		config.RateWindow = defaultRateWindow
	}
	if config.SourceLimit == 0 {
		config.SourceLimit = defaultSourceLimit
	}
	if config.SubjectLimit == 0 {
		config.SubjectLimit = defaultSubjectLimit
	}
	if config.MaxAttempts == 0 {
		config.MaxAttempts = defaultMaxAttempts
	}
	if config.ChallengeTTL < time.Minute || config.ChallengeTTL > 30*time.Minute ||
		config.RateWindow < time.Minute || config.RateWindow > 24*time.Hour ||
		config.SourceLimit < 1 || config.SourceLimit > 1000 || config.SubjectLimit < 1 || config.SubjectLimit > 1000 ||
		config.MaxAttempts < 1 || config.MaxAttempts > 10 {
		return nil, ErrInvalidConfig
	}
	return &Service{
		pool: pool, policy: config.Policy, templates: config.Templates, human: config.Human,
		issuer: config.Issuer, contacts: config.Contacts, digestKey: append([]byte(nil), config.DigestKey...),
		now: config.Clock, entropy: config.Entropy, challengeTTL: config.ChallengeTTL,
		rateWindow: config.RateWindow, sourceLimit: config.SourceLimit,
		subjectLimit: config.SubjectLimit, maxAttempts: config.MaxAttempts, availableChannels: append([]notification.Channel(nil), config.AvailableChannels...),
		registrationMounted: config.RegistrationMounted,
	}, nil
}

func (service *Service) Methods(ctx context.Context, scopeID uuid.UUID) (Methods, error) {
	if service == nil || service.policy == nil || scopeID == uuid.Nil {
		return Methods{}, ErrUnavailable
	}
	policy, err := service.policy.GetPublic(ctx, scopeID)
	if err != nil {
		return Methods{}, ErrUnavailable
	}
	methods := publicMethods(policy)
	methods.RegistrationEnabled = methods.RegistrationEnabled && service.registrationMounted
	return methods, nil
}

func publicMethods(policy systemusersettings.PublicSettings) Methods {
	methods := Methods{
		RegistrationEnabled: policy.RegistrationEnabled,
		EmailEnabled:        policy.EmailCodeLoginEnabled, SMSEnabled: policy.SMSCodeLoginEnabled,
		EmailAntiAbuseMode: policy.EmailAntiAbuseMode, SMSAntiAbuseMode: policy.SMSAntiAbuseMode,
	}
	if externalHumanMode(policy.EmailAntiAbuseMode) || externalHumanMode(policy.SMSAntiAbuseMode) {
		methods.CaptchaProvider, methods.CaptchaAppID = policy.CaptchaProvider, policy.CaptchaAppID
	}
	return methods
}

func (service *Service) Create(ctx context.Context, input CreateInput) (CreateResult, error) {
	if service == nil || service.pool == nil || service.policy == nil || service.contacts == nil {
		return CreateResult{}, ErrUnavailable
	}
	phoneCode, err := service.phoneCountryCode(ctx, input.ScopeID, input.Channel, input.Identifier)
	if err != nil {
		return CreateResult{}, err
	}
	normalized, err := normalizeCreate(input, service.digestKey, phoneCode)
	if err != nil {
		return CreateResult{}, err
	}
	policy, err := service.policy.GetPublic(ctx, normalized.ScopeID)
	if err != nil {
		return CreateResult{}, ErrUnavailable
	}
	mode, enabled := loginMethodPolicy(policy, normalized.Channel)
	if !enabled {
		return CreateResult{}, ErrMethodDisabled
	}
	var captchaReplay *[32]byte
	if externalHumanMode(mode) {
		if service.human == nil || normalized.HumanToken == "" {
			return CreateResult{}, ErrHumanRequired
		}
		digest, ok := captchaReplayDigest(service.digestKey, mode, normalized.HumanToken)
		if !ok {
			return CreateResult{}, ErrHumanInvalid
		}
		if err := service.human.Verify(ctx, mode, normalized.HumanToken, normalized.Source); err != nil {
			return CreateResult{}, ErrHumanInvalid
		}
		captchaReplay = &digest
	}
	requestDigest := digestParts(service.digestKey, createDigestDomain,
		[]byte(normalized.ScopeID.String()), []byte(normalized.Channel), []byte(normalized.Identifier),
		[]byte(normalized.Source), []byte(normalized.HumanToken))
	if normalized.passwordSubject != nil {
		subject := normalized.passwordSubject
		requestDigest = digestParts(service.digestKey, []byte("account-login-challenge:v1:password-create\x00"), requestDigest[:], []byte(subject.UserID.String()), []byte(fmt.Sprint(subject.PolicyRevision)))
	}
	var template notification.TemplateRef
	if service.templates != nil {
		resolved, found, templateErr := service.templates.GetRegistrationVerificationTemplate(ctx, normalized.ScopeID, normalized.Channel)
		if templateErr != nil {
			return CreateResult{}, ErrUnavailable
		}
		if found {
			template = resolved
		}
	}
	var result CreateResult
	var outcomeErr error
	err = pgx.BeginTxFunc(ctx, service.pool, pgx.TxOptions{IsoLevel: pgx.Serializable}, func(tx pgx.Tx) error {
		var storedDigest []byte
		err := tx.QueryRow(ctx, `SELECT request_digest FROM account_login_challenge_writes_197
			WHERE scope_id=$1 AND idempotency_key=$2 FOR UPDATE`, normalized.ScopeID, normalized.IdempotencyKey).Scan(&storedDigest)
		if err == nil {
			if !hmac.Equal(storedDigest, requestDigest[:]) {
				outcomeErr = ErrIdempotencyConflict
				return nil
			}
			if err := tx.QueryRow(ctx, `SELECT id,expires_at FROM account_login_challenges_197
				WHERE scope_id=$1 AND write_idempotency_key=$2`, normalized.ScopeID, normalized.IdempotencyKey).
				Scan(&result.ChallengeID, &result.ExpiresAt); err != nil {
				return err
			}
			result.Replayed = true
			return nil
		}
		if !errors.Is(err, pgx.ErrNoRows) {
			return err
		}
		now := service.now().UTC().Truncate(time.Microsecond)
		var sourceCount, subjectCount int
		if err := tx.QueryRow(ctx, `SELECT
			count(*) FILTER (WHERE source_digest=$1),count(*) FILTER (WHERE subject_digest=$2)
			FROM account_login_challenge_writes_197 WHERE created_at>=$3`, normalized.SourceDigest[:],
			normalized.IdentifierDigest[:], now.Add(-service.rateWindow)).Scan(&sourceCount, &subjectCount); err != nil {
			return err
		}
		if sourceCount >= service.sourceLimit || subjectCount >= service.subjectLimit {
			outcomeErr = ErrRateLimited
			return nil
		}
		var userID *uuid.UUID
		var candidate uuid.UUID
		var userStatus, membershipStatus string
		err = tx.QueryRow(ctx, `SELECT u.id,u.status,m.status FROM users u
			JOIN memberships m ON m.user_id=u.id
			WHERE m.scope_id=$1 AND (($2='email' AND u.email=$3) OR ($2='sms' AND u.phone=$3))
			ORDER BY u.id LIMIT 1`, normalized.ScopeID, normalized.Channel, normalized.Identifier).
			Scan(&candidate, &userStatus, &membershipStatus)
		if err == nil && userStatus == "active" && membershipStatus == "active" {
			userID = &candidate
		} else if err != nil && !errors.Is(err, pgx.ErrNoRows) {
			return err
		}
		policyRevision := int64(0)
		if userID != nil {
			policy, err := identity.ReadLoginSecurityTx(ctx, tx, *userID, normalized.ScopeID)
			if err != nil {
				return err
			}
			policyRevision = policy.Revision
			if subject := normalized.passwordSubject; subject != nil {
				if subject.UserID != *userID || subject.ScopeID != normalized.ScopeID || subject.PolicyRevision != policy.Revision || policy.LoginVerification != string(normalized.Channel) {
					outcomeErr = ErrOTPInvalid
					return nil
				}
			}
		} else if normalized.passwordSubject != nil {
			outcomeErr = ErrOTPInvalid
			return nil
		}
		challengeID, err := uuid.NewV7()
		if err != nil {
			return err
		}
		otp, err := randomOTP(service.entropy)
		if err != nil {
			return err
		}
		// 外部验证码票据只能成功换一次挑战；同一幂等键的重试在上面已按重放返回，不会走到这里。
		if captchaReplay != nil {
			claimed, err := claimCaptchaReplay(ctx, tx, *captchaReplay, mode, now)
			if err != nil {
				return err
			}
			if !claimed {
				outcomeErr = ErrHumanInvalid
				return nil
			}
		}
		expiresAt := now.Add(service.challengeTTL)
		otpDigest := keyedDigest(service.digestKey, otpDigestDomain, []byte(otp))
		if _, err := tx.Exec(ctx, `INSERT INTO account_login_challenge_writes_197(
			scope_id,idempotency_key,request_digest,subject_digest,source_digest,created_at,updated_at
		) VALUES($1,$2,$3,$4,$5,$6,$6)`, normalized.ScopeID, normalized.IdempotencyKey,
			requestDigest[:], normalized.IdentifierDigest[:], normalized.SourceDigest[:], now); err != nil {
			return err
		}
		if _, err := tx.Exec(ctx, `INSERT INTO account_login_challenges_197(
			id,scope_id,write_idempotency_key,user_id,channel,destination_digest,source_digest,otp_digest,
			failed_attempts,max_attempts,issued_at,expires_at,state,login_security_revision
		) VALUES($1,$2,$3,$4,$5,$6,$7,$8,0,$9,$10,$11,'queued',$12)`, challengeID, normalized.ScopeID,
			normalized.IdempotencyKey, userID, normalized.Channel, normalized.IdentifierDigest[:],
			normalized.SourceDigest[:], otpDigest[:], service.maxAttempts, now, expiresAt, policyRevision); err != nil {
			return err
		}
		if userID != nil {
			if err := service.contacts.Enqueue(ctx, tx, ContactRequest{
				ScopeID: normalized.ScopeID, ChallengeID: challengeID, Channel: normalized.Channel,
				Template: template, Destination: normalized.Identifier, DestinationDigest: normalized.IdentifierDigest,
				OTP: otp, ExpiresAt: expiresAt, RequestID: normalized.RequestID,
			}); err != nil {
				return err
			}
		}
		result = CreateResult{ChallengeID: challengeID, ExpiresAt: expiresAt}
		return nil
	})
	if err != nil {
		var pgErr *pgconn.PgError
		if errors.As(err, &pgErr) && pgErr.Code == "40001" {
			return CreateResult{}, ErrRateLimited
		}
		return CreateResult{}, ErrUnavailable
	}
	if captchaReplay != nil {
		_, _ = cleanupCaptchaReplay(ctx, service.pool, service.now().UTC())
	}
	if outcomeErr != nil {
		return CreateResult{}, outcomeErr
	}
	return result, nil
}

func (service *Service) Verify(ctx context.Context, input VerifyInput) (VerifyResult, error) {
	if service == nil || service.pool == nil || service.policy == nil || service.issuer == nil {
		return VerifyResult{}, ErrUnavailable
	}
	phoneCode, err := service.phoneCountryCode(ctx, input.ScopeID, input.Channel, input.Identifier)
	if err != nil {
		return VerifyResult{}, err
	}
	normalized, err := normalizeVerify(input, service.digestKey, phoneCode)
	if err != nil {
		return VerifyResult{}, err
	}
	policy, err := service.policy.GetPublic(ctx, normalized.ScopeID)
	if err != nil {
		return VerifyResult{}, ErrUnavailable
	}
	if _, enabled := loginMethodPolicy(policy, normalized.Channel); !enabled {
		return VerifyResult{}, ErrMethodDisabled
	}
	var userID *uuid.UUID
	err = service.pool.QueryRow(ctx, `SELECT user_id FROM account_login_challenges_197 WHERE id=$1`, normalized.ChallengeID).Scan(&userID)
	if errors.Is(err, pgx.ErrNoRows) {
		return VerifyResult{}, ErrOTPInvalid
	}
	if err != nil {
		return VerifyResult{}, ErrUnavailable
	}
	proof := identity.LoginChallengeProof{ChallengeID: normalized.ChallengeID, Identifier: normalized.Identifier, Channel: string(normalized.Channel), OTP: normalized.OTP, IdempotencyKey: normalized.IdempotencyKey}
	if userID == nil {
		var denial error
		err := pgx.BeginFunc(ctx, service.pool, func(tx pgx.Tx) error {
			var err error
			denial, err = service.ConsumeLoginChallengeTx(ctx, tx, identity.LoginChallengeConsumeInput{ScopeID: normalized.ScopeID, Contact: normalized.Identifier, SourceIP: normalized.Source, RequestID: normalized.RequestID, Proof: proof})
			return err
		})
		if err != nil {
			return VerifyResult{}, ErrUnavailable
		}
		return VerifyResult{}, fromIdentityChallengeError(denial)
	}
	auth, err := service.issuer.LoginVerified(ctx, identity.VerifiedLoginInput{UserID: *userID, ScopeID: normalized.ScopeID, Method: string(normalized.Channel) + "_code", Challenge: &proof}, identity.RequestInfo{RequestID: normalized.RequestID, SourceIP: normalized.Source, UserAgent: normalized.UserAgent})
	if err != nil {
		return VerifyResult{}, fromIdentityChallengeError(err)
	}
	return VerifyResult{Auth: auth}, nil
}

// phoneCountryCode reads the platform default calling code that completes a
// bare SMS login identifier (FX38).
func (service *Service) phoneCountryCode(ctx context.Context, scopeID uuid.UUID, channel notification.Channel, identifier string) (string, error) {
	if channel != notification.ChannelSMS || scopeID == uuid.Nil {
		return "", nil
	}
	code, err := systemusersettings.PhoneCountryCode(ctx, service.policy, scopeID, identifier)
	if err != nil {
		return "", ErrUnavailable
	}
	return code, nil
}

func normalizeCreate(input CreateInput, key []byte, phoneCode string) (normalizedCreate, error) {
	identifier, source, err := normalizeCommon(input.ScopeID, input.Identifier, input.Channel, input.Source,
		input.IdempotencyKey, input.RequestID, phoneCode)
	if err != nil || len(input.HumanToken) > 4096 {
		return normalizedCreate{}, ErrInvalidInput
	}
	input.Identifier = identifier
	input.Source = source
	return normalizedCreate{CreateInput: input,
		IdentifierDigest: keyedDigest(key, identifierDigestDomain, []byte(identifier)),
		SourceDigest:     keyedDigest(key, sourceDigestDomain, []byte(source)),
	}, nil
}

func normalizeVerify(input VerifyInput, key []byte, phoneCode string) (normalizedVerify, error) {
	identifier, source, err := normalizeCommon(input.ScopeID, input.Identifier, input.Channel, input.Source,
		input.IdempotencyKey, input.RequestID, phoneCode)
	if err != nil || input.ChallengeID == uuid.Nil || !otpPattern.MatchString(input.OTP) || len(input.UserAgent) > 2048 {
		return normalizedVerify{}, ErrInvalidInput
	}
	input.Identifier = identifier
	input.Source = source
	return normalizedVerify{VerifyInput: input,
		IdentifierDigest: keyedDigest(key, identifierDigestDomain, []byte(identifier)),
		SourceDigest:     keyedDigest(key, sourceDigestDomain, []byte(source)),
	}, nil
}

func normalizeCommon(
	scopeID uuid.UUID,
	identifier string,
	channel notification.Channel,
	source, idempotencyKey, requestID, phoneCode string,
) (string, string, error) {
	identifier = strings.TrimSpace(identifier)
	if channel == notification.ChannelEmail {
		identifier = strings.ToLower(identifier)
		address, err := mail.ParseAddress(identifier)
		if err != nil || address.Address != identifier || len(identifier) > 254 {
			return "", "", ErrInvalidInput
		}
	} else if channel == notification.ChannelSMS {
		phone, err := phonenumber.Normalize(identifier, phoneCode)
		if err != nil {
			return "", "", ErrInvalidInput
		}
		identifier = phone
	} else {
		return "", "", ErrInvalidInput
	}
	address, err := netip.ParseAddr(source)
	if err != nil || address.Zone() != "" || address != address.Unmap() || scopeID == uuid.Nil ||
		!metadataPattern.MatchString(idempotencyKey) || !metadataPattern.MatchString(requestID) {
		return "", "", ErrInvalidInput
	}
	return identifier, address.String(), nil
}

func loginMethodPolicy(policy systemusersettings.PublicSettings, channel notification.Channel) (string, bool) {
	if channel == notification.ChannelEmail {
		return policy.EmailAntiAbuseMode, policy.EmailCodeLoginEnabled
	}
	return policy.SMSAntiAbuseMode, policy.SMSCodeLoginEnabled
}

func externalHumanMode(mode string) bool {
	return mode == "tencent" || mode == "geetest_v4"
}

func keyedDigest(key, domain, value []byte) [32]byte {
	mac := hmac.New(sha256.New, key)
	_, _ = mac.Write(domain)
	_, _ = mac.Write(value)
	var result [32]byte
	copy(result[:], mac.Sum(nil))
	return result
}

func digestParts(key, domain []byte, parts ...[]byte) [32]byte {
	buffer := bytes.NewBuffer(nil)
	for _, part := range parts {
		_ = binary.Write(buffer, binary.BigEndian, uint32(len(part)))
		_, _ = buffer.Write(part)
	}
	return keyedDigest(key, domain, buffer.Bytes())
}

func randomOTP(entropy io.Reader) (string, error) {
	limit := big.NewInt(1_000_000)
	value, err := rand.Int(entropy, limit)
	if err != nil {
		return "", fmt.Errorf("generate account login OTP: %w", err)
	}
	return fmt.Sprintf("%06d", value.Int64()), nil
}
