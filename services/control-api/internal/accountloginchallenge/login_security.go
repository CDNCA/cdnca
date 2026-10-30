package accountloginchallenge

import (
	"context"
	"crypto/hmac"
	"errors"
	"strings"
	"time"

	"github.com/cdnca/cdnca/services/control-api/internal/identity"
	"github.com/cdnca/cdnca/services/control-api/internal/notification"
	"github.com/cdnca/cdnca/services/control-api/internal/systemusersettings"
	"github.com/google/uuid"
	"github.com/jackc/pgx/v5"
)

type PasswordCreateInput struct {
	Login          identity.LoginInput
	Request        identity.RequestInfo
	Source         string
	HumanToken     string
	IdempotencyKey string
	RequestID      string
}

func (service *Service) LoginChannelAvailable(channel string) bool {
	if service == nil || service.contacts == nil || (channel != "email" && channel != "sms") {
		return false
	}
	if len(service.availableChannels) == 0 {
		return true
	}
	for _, available := range service.availableChannels {
		if string(available) == channel {
			return true
		}
	}
	return false
}

func (service *Service) CreatePassword(ctx context.Context, input PasswordCreateInput) (CreateResult, error) {
	if service == nil {
		return CreateResult{}, ErrUnavailable
	}
	verifier, ok := service.issuer.(interface {
		PreparePasswordLoginChallenge(context.Context, identity.LoginInput, identity.RequestInfo) (identity.PasswordLoginChallengeSubject, error)
	})
	if !ok {
		return CreateResult{}, ErrUnavailable
	}
	input.Request.SourceIP, input.Request.RequestID = input.Source, input.RequestID
	subject, err := verifier.PreparePasswordLoginChallenge(ctx, input.Login, input.Request)
	if err != nil {
		return CreateResult{}, err
	}
	return service.Create(ctx, CreateInput{ScopeID: subject.ScopeID, Identifier: subject.Destination, Channel: notification.Channel(subject.Channel), Source: input.Source, HumanToken: input.HumanToken, IdempotencyKey: input.IdempotencyKey, RequestID: input.RequestID, passwordSubject: &subject})
}

// publicSettingsTx is replaceable in unit tests.
var publicSettingsTx = systemusersettings.GetPublicTx

// consumePhoneCountryCode reads, inside the login transaction, the platform
// default calling code that Create used to complete a bare SMS identifier, so
// both sides compute the same destination digest (FX38).
func consumePhoneCountryCode(ctx context.Context, tx pgx.Tx, scopeID uuid.UUID, channel notification.Channel, identifier string) (string, error) {
	if channel != notification.ChannelSMS || scopeID == uuid.Nil || strings.TrimSpace(identifier) == "" {
		return "", nil
	}
	settings, err := publicSettingsTx(ctx, tx, scopeID)
	if err != nil {
		return "", err
	}
	return settings.DefaultPhoneCountryCode, nil
}

func (service *Service) ConsumeLoginChallengeTx(ctx context.Context, tx pgx.Tx, input identity.LoginChallengeConsumeInput) (error, error) {
	if service == nil || tx == nil {
		return nil, identity.ErrLoginSecurityUnavailable
	}
	phoneCode, err := consumePhoneCountryCode(ctx, tx, input.ScopeID, notification.Channel(input.Proof.Channel), input.Proof.Identifier)
	if err != nil {
		return nil, identity.ErrLoginSecurityUnavailable
	}
	normalized, err := normalizeVerify(VerifyInput{ScopeID: input.ScopeID, ChallengeID: input.Proof.ChallengeID, Identifier: input.Proof.Identifier, Channel: notification.Channel(input.Proof.Channel), Source: input.SourceIP, OTP: input.Proof.OTP, IdempotencyKey: input.Proof.IdempotencyKey, RequestID: input.RequestID}, service.digestKey, phoneCode)
	if err != nil {
		return identity.ErrLoginChallengeInvalid, nil
	}
	contactDigest := keyedDigest(service.digestKey, identifierDigestDomain, []byte(input.Contact))
	requestDigest := digestParts(service.digestKey, verifyDigestDomain, []byte(normalized.ScopeID.String()), []byte(normalized.ChallengeID.String()), []byte(normalized.Channel), []byte(normalized.Identifier), []byte(normalized.Source), []byte(normalized.OTP))
	var outcomeErr error
	err = func() error {
		var storedDigest []byte
		var storedOutcome string
		err := tx.QueryRow(ctx, `SELECT request_digest,outcome FROM account_login_challenge_verify_receipts_197
			WHERE challenge_id=$1 AND idempotency_key=$2`, normalized.ChallengeID, normalized.IdempotencyKey).
			Scan(&storedDigest, &storedOutcome)
		if err == nil {
			if !hmac.Equal(storedDigest, requestDigest[:]) {
				outcomeErr = ErrIdempotencyConflict
			} else if storedOutcome == "consumed" {
				outcomeErr = ErrChallengeUsed
			} else {
				outcomeErr = ErrOTPInvalid
			}
			return nil
		}
		if !errors.Is(err, pgx.ErrNoRows) {
			return err
		}
		var storedScope uuid.UUID
		var storedPolicyRevision int64
		var storedUserID *uuid.UUID
		var channel notification.Channel
		var destinationDigest, sourceDigest, otpDigest []byte
		var failedAttempts, maxAttempts int
		var expiresAt time.Time
		var state string
		if err := tx.QueryRow(ctx, `SELECT scope_id,user_id,channel,destination_digest,source_digest,otp_digest,
			failed_attempts,max_attempts,expires_at,state,login_security_revision FROM account_login_challenges_197 WHERE id=$1 FOR UPDATE`,
			normalized.ChallengeID).Scan(&storedScope, &storedUserID, &channel, &destinationDigest, &sourceDigest,
			&otpDigest, &failedAttempts, &maxAttempts, &expiresAt, &state, &storedPolicyRevision); err != nil {
			if errors.Is(err, pgx.ErrNoRows) {
				outcomeErr = ErrOTPInvalid
				return nil
			}
			return err
		}
		now := service.now().UTC().Truncate(time.Microsecond)
		providedOTP := keyedDigest(service.digestKey, otpDigestDomain, []byte(normalized.OTP))
		valid := storedScope == normalized.ScopeID && channel == normalized.Channel &&
			hmac.Equal(destinationDigest, normalized.IdentifierDigest[:]) && hmac.Equal(sourceDigest, normalized.SourceDigest[:]) &&
			hmac.Equal(otpDigest, providedOTP[:]) && state == "queued" && now.Before(expiresAt) && storedUserID != nil && *storedUserID == input.UserID && storedPolicyRevision == input.PolicyRevision &&
			hmac.Equal(destinationDigest, contactDigest[:])
		outcome := "invalid"
		if valid {
			command, err := tx.Exec(ctx, `UPDATE account_login_challenges_197 SET state='consumed',consumed_at=$2
				WHERE id=$1 AND state='queued'`, normalized.ChallengeID, now)
			if err != nil || command.RowsAffected() != 1 {
				return ErrUnavailable
			}
			outcome = "consumed"
		} else {
			if state == "consumed" {
				outcomeErr = ErrChallengeUsed
				return nil
			}
			nextAttempts := failedAttempts + 1
			if nextAttempts > maxAttempts {
				nextAttempts = maxAttempts
			}
			nextState := state
			if state == "queued" && nextAttempts >= maxAttempts {
				nextState = "locked"
			}
			if _, err := tx.Exec(ctx, `UPDATE account_login_challenges_197 SET failed_attempts=$2,state=$3
				WHERE id=$1`, normalized.ChallengeID, nextAttempts, nextState); err != nil {
				return err
			}
			outcomeErr = ErrOTPInvalid
		}
		if _, err := tx.Exec(ctx, `INSERT INTO account_login_challenge_verify_receipts_197(
			challenge_id,idempotency_key,request_digest,outcome,created_at
		) VALUES($1,$2,$3,$4,$5)`, normalized.ChallengeID, normalized.IdempotencyKey,
			requestDigest[:], outcome, now); err != nil {
			return err
		}
		return nil
	}()
	if err != nil {
		return nil, identity.ErrLoginSecurityUnavailable
	}
	switch {
	case errors.Is(outcomeErr, ErrIdempotencyConflict):
		return identity.ErrLoginChallengeIdempotencyConflict, nil
	case errors.Is(outcomeErr, ErrChallengeUsed):
		return identity.ErrLoginChallengeUsed, nil
	case outcomeErr != nil:
		return identity.ErrLoginChallengeInvalid, nil
	default:
		return nil, nil
	}
}

func fromIdentityChallengeError(err error) error {
	switch {
	case errors.Is(err, identity.ErrLoginChallengeUsed):
		return ErrChallengeUsed
	case errors.Is(err, identity.ErrLoginChallengeIdempotencyConflict):
		return ErrIdempotencyConflict
	case errors.Is(err, identity.ErrLoginMethodDisabled):
		return ErrMethodDisabled
	case errors.Is(err, identity.ErrAccountDisabled), errors.Is(err, identity.ErrMembershipDisabled), errors.Is(err, identity.ErrInvalidCredentials), errors.Is(err, identity.ErrLoginChallengeInvalid), errors.Is(err, identity.ErrLoginSourceDenied), errors.Is(err, identity.ErrLoginSecurityContactRequired):
		return ErrOTPInvalid
	default:
		return ErrUnavailable
	}
}

var _ identity.LoginChallengeConsumer = (*Service)(nil)
