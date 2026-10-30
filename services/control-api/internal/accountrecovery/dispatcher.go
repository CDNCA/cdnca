package accountrecovery

import (
	"bytes"
	"context"
	"crypto/hmac"
	"crypto/sha256"
	"encoding/base64"
	"encoding/binary"
	"errors"
	"net/url"
	"strings"
	"time"

	"github.com/cdnca/cdnca/services/control-api/internal/notification"
	"github.com/google/uuid"
	"github.com/jackc/pgx/v5"
	"github.com/jackc/pgx/v5/pgxpool"
)

const dispatchClaimAADDomain = "cdnca/account-recovery/dispatch-claim/v1"

type dispatchClaim struct {
	Reference   uuid.UUID
	TenantID    uuid.UUID
	ScopeID     uuid.UUID
	UserID      uuid.UUID
	ChallengeID uuid.UUID
	KeyID       string
	WrappedKey  []byte
	SealedToken []byte
	AADHash     []byte
	EmailDigest []byte
	PhoneDigest []byte
	IssuedAt    time.Time
	ExpiresAt   time.Time
}

type Dispatcher struct {
	pool        *pgxpool.Pool
	now         func() time.Time
	digestKey   []byte
	keyring     *DispatchKeyring
	recoveryURL url.URL
	sender      RecoverySender
}

func NewDispatcher(pool *pgxpool.Pool, config DispatcherConfig) (*Dispatcher, error) {
	if pool == nil || len(config.DigestKey) < 32 || !validDispatchKeyring(config.Keyring) || config.Sender == nil {
		return nil, ErrInvalidInput
	}
	if config.Clock == nil {
		config.Clock = time.Now
	}
	parsed, err := url.Parse(config.RecoveryURL)
	if err != nil || parsed.Scheme != "https" || parsed.Host == "" || parsed.User != nil ||
		parsed.RawQuery != "" || parsed.Fragment != "" {
		return nil, ErrInvalidInput
	}
	return &Dispatcher{
		pool: pool, now: config.Clock, digestKey: append([]byte(nil), config.DigestKey...),
		keyring: config.Keyring, recoveryURL: *parsed, sender: config.Sender,
	}, nil
}

func (d *Dispatcher) Dispatch(
	ctx context.Context,
	attempt notification.AnonymousDeliveryAttempt,
) notification.AnonymousDispatchResult {
	if d == nil || d.pool == nil || ctx == nil || attempt.OutboxID == uuid.Nil ||
		attempt.ScopeID == uuid.Nil || attempt.AnonymousDispatchReference == uuid.Nil ||
		attempt.EventID == uuid.Nil || attempt.LeaseToken == uuid.Nil || attempt.LeaseExpiresAt.IsZero() ||
		attempt.EventType != notification.EventTypeAccountRecovery ||
		attempt.SourceEventID != attempt.AnonymousDispatchReference.String() ||
		(attempt.Channel != notification.ChannelEmail && attempt.Channel != notification.ChannelSMS) ||
		attempt.DedupKey == "" || attempt.AttemptNumber < 1 {
		return permanentDispatchFailure("account_recovery_dispatch_invalid")
	}

	result := notification.AnonymousDispatchResult{Disposition: notification.AnonymousDispatchNoopACK}
	err := pgx.BeginFunc(ctx, d.pool, func(tx pgx.Tx) error {
		valid, err := validateDispatchAttemptFact(ctx, tx, attempt, storeTime(d.now()))
		if err != nil {
			return err
		}
		if !valid {
			result = permanentDispatchFailure("account_recovery_dispatch_invalid")
			return nil
		}
		claim, err := readDispatchClaim(ctx, tx, attempt.AnonymousDispatchReference, attempt.ScopeID)
		if errors.Is(err, pgx.ErrNoRows) {
			return nil
		}
		if err != nil {
			return err
		}

		var username, userStatus, membershipStatus string
		var revision int64
		var email, phone *string
		err = tx.QueryRow(ctx, `SELECT user_row.username,user_row.status,user_row.revision,user_row.email,user_row.phone,membership.status
			FROM users user_row
			JOIN memberships membership ON membership.user_id=user_row.id AND membership.scope_id=$2
			WHERE user_row.id=$1
			FOR SHARE OF user_row,membership`, claim.UserID, claim.ScopeID).
			Scan(&username, &userStatus, &revision, &email, &phone, &membershipStatus)
		if errors.Is(err, pgx.ErrNoRows) {
			return nil
		}
		if err != nil {
			return err
		}

		var challengeUserID uuid.UUID
		var tokenDigest []byte
		var passwordRevision int64
		var issuedAt, expiresAt time.Time
		var consumedAt, revokedAt *time.Time
		err = tx.QueryRow(ctx, `SELECT user_id,token_digest,password_revision,issued_at,expires_at,consumed_at,revoked_at
			FROM account_recovery_challenges WHERE id=$1
			FOR SHARE`, claim.ChallengeID).Scan(&challengeUserID, &tokenDigest, &passwordRevision,
			&issuedAt, &expiresAt, &consumedAt, &revokedAt)
		if errors.Is(err, pgx.ErrNoRows) {
			return nil
		}
		if err != nil {
			return err
		}
		now := storeTime(d.now())
		if challengeUserID != claim.UserID || userStatus != "active" || membershipStatus != "active" ||
			revision != passwordRevision || consumedAt != nil || revokedAt != nil ||
			!now.Before(expiresAt) || !issuedAt.Equal(claim.IssuedAt) || !expiresAt.Equal(claim.ExpiresAt) {
			return nil
		}

		contact, storedDigest, ok := dispatchContact(attempt.Channel, email, phone, claim.EmailDigest, claim.PhoneDigest)
		if !ok {
			return nil
		}
		currentDigest := keyedDigest(d.digestKey, contactDigestDomain(attempt.Channel), contact)
		if !hmac.Equal(currentDigest[:], storedDigest) {
			return nil
		}

		aad := dispatchClaimAAD(claim)
		aadHash := sha256.Sum256(aad)
		if !hmac.Equal(aadHash[:], claim.AADHash) {
			result = permanentDispatchFailure("account_recovery_claim_invalid")
			return nil
		}
		if _, exists := d.keyring.keys[claim.KeyID]; !exists {
			result = temporaryDispatchFailure("account_recovery_key_unavailable")
			return nil
		}
		plaintext, err := d.keyring.open(claim.KeyID, claim.WrappedKey, claim.SealedToken, aad)
		if err != nil {
			result = permanentDispatchFailure("account_recovery_claim_invalid")
			return nil
		}
		defer clear(plaintext)
		rawToken, err := base64.RawURLEncoding.DecodeString(string(plaintext))
		if err != nil || len(rawToken) != tokenBytes ||
			base64.RawURLEncoding.EncodeToString(rawToken) != string(plaintext) {
			result = permanentDispatchFailure("account_recovery_claim_invalid")
			return nil
		}
		expectedDigest := keyedDigest(d.digestKey, tokenDigestDomain, string(plaintext))
		if !hmac.Equal(expectedDigest[:], tokenDigest) {
			result = permanentDispatchFailure("account_recovery_claim_invalid")
			return nil
		}

		recoveryURL := d.recoveryURL
		query := recoveryURL.Query()
		query.Set("token", string(plaintext))
		recoveryContext, err := issueRecoveryContext(d.digestKey, claim, string(plaintext))
		if err != nil {
			result = permanentDispatchFailure("account_recovery_claim_invalid")
			return nil
		}
		query.Set("recovery_context", recoveryContext)
		recoveryURL.Fragment = query.Encode()
		subject, body := renderAccountRecoveryTemplate(attempt.Subject, attempt.Body, username)
		send := d.sender.SendRecovery(ctx, RecoveryDelivery{
			OutboxID: attempt.OutboxID, Channel: attempt.Channel, Contact: contact,
			Subject: subject, Body: body, RecoveryURL: recoveryURL.String(),
			IdempotencyKey: attempt.DedupKey, AttemptNumber: attempt.AttemptNumber,
			TemplateID: attempt.Template.ID,
			Params:     map[string]string{"username": username, "action_url": recoveryURL.String()},
		})
		if send.Failure != nil {
			result = notification.AnonymousDispatchResult{Failure: send.Failure, Observation: send.Observation}
			return nil
		}
		switch send.Disposition {
		case "", notification.SendDelivered:
			result = notification.AnonymousDispatchResult{Disposition: notification.AnonymousDispatchDelivered, Observation: send.Observation}
		case notification.SendAccepted:
			result = notification.AnonymousDispatchResult{
				Disposition: notification.AnonymousDispatchAccepted, Provider: send.Provider,
				ProviderDeliveryID: send.ProviderDeliveryID, Observation: send.Observation,
			}
		case notification.SendUnknown:
			result = notification.AnonymousDispatchResult{
				Disposition: notification.AnonymousDispatchUnknown, Provider: send.Provider, Observation: send.Observation,
			}
		default:
			result = permanentDispatchFailure("account_recovery_sender_contract_invalid")
		}
		return nil
	})
	if err != nil {
		return temporaryDispatchFailure("account_recovery_dispatch_unavailable")
	}
	return result
}

func renderAccountRecoveryTemplate(subject, body, username string) (string, string) {
	const placeholder = "{{.username}}"
	return strings.ReplaceAll(subject, placeholder, username), strings.ReplaceAll(body, placeholder, username)
}

func validateDispatchAttemptFact(
	ctx context.Context,
	tx pgx.Tx,
	attempt notification.AnonymousDeliveryAttempt,
	now time.Time,
) (bool, error) {
	var eventID uuid.UUID
	var reference *uuid.UUID
	var scopeID uuid.UUID
	var recipientKind, eventType, sourceEventID, deliveryPolicy string
	var channel notification.Channel
	var template notification.TemplateRef
	var subject, body, dedupKey, outboxStatus, attemptOutcome string
	var attemptCount int
	var leaseToken, recordedAttemptToken *uuid.UUID
	var leaseExpiresAt, recordedAttemptExpiry *time.Time
	err := tx.QueryRow(ctx, `SELECT event.id,event.scope_id,event.recipient_kind,
		event.anonymous_dispatch_reference,event.event_type,event.source_event_id,event.delivery_policy,
		outbox.channel,outbox.template_id,outbox.template_version,outbox.subject,outbox.body,
		outbox.dedup_key,outbox.status,outbox.attempt_count,outbox.lease_token,outbox.lease_expires_at,
		attempt.outcome,attempt.lease_token,attempt.lease_expires_at
		FROM notification_outbox outbox
		JOIN notification_events event ON event.scope_id=outbox.scope_id AND event.id=outbox.event_id
		JOIN notification_attempts attempt ON attempt.scope_id=outbox.scope_id
		  AND attempt.outbox_id=outbox.id AND attempt.attempt_number=$2
		WHERE outbox.id=$1
		FOR SHARE OF event,outbox,attempt`, attempt.OutboxID, attempt.AttemptNumber).Scan(
		&eventID, &scopeID, &recipientKind, &reference, &eventType, &sourceEventID, &deliveryPolicy,
		&channel, &template.ID, &template.Version, &subject, &body, &dedupKey, &outboxStatus,
		&attemptCount, &leaseToken, &leaseExpiresAt, &attemptOutcome, &recordedAttemptToken,
		&recordedAttemptExpiry,
	)
	if errors.Is(err, pgx.ErrNoRows) {
		return false, nil
	}
	if err != nil {
		return false, err
	}
	template.Channel = channel
	return eventID == attempt.EventID && scopeID == attempt.ScopeID && recipientKind == "anonymous" &&
		reference != nil && *reference == attempt.AnonymousDispatchReference && eventType == attempt.EventType &&
		sourceEventID == attempt.SourceEventID && deliveryPolicy == string(notification.DeliverySystemRequired) &&
		channel == attempt.Channel && template == attempt.Template && subject == attempt.Subject &&
		body == attempt.Body && dedupKey == attempt.DedupKey && outboxStatus == notification.OutboxLeased &&
		attemptCount == attempt.AttemptNumber && leaseToken != nil && *leaseToken == attempt.LeaseToken &&
		leaseExpiresAt != nil && leaseExpiresAt.Equal(attempt.LeaseExpiresAt) && attemptOutcome == "leased" &&
		recordedAttemptToken != nil && *recordedAttemptToken == attempt.LeaseToken &&
		recordedAttemptExpiry != nil && recordedAttemptExpiry.Equal(attempt.LeaseExpiresAt) &&
		now.Before(*leaseExpiresAt), nil
}

func readDispatchClaim(ctx context.Context, tx pgx.Tx, reference, scopeID uuid.UUID) (dispatchClaim, error) {
	claim := dispatchClaim{Reference: reference}
	err := tx.QueryRow(ctx, `SELECT COALESCE(tenant_id,'00000000-0000-0000-0000-000000000000'::uuid),
		scope_id,user_id,challenge_id,kek_key_id,
		wrapped_data_key,sealed_token,aad_sha256,email_digest,phone_digest,issued_at,expires_at
		FROM account_recovery_dispatch_claims
		WHERE reference=$1 AND scope_id=$2`, reference, scopeID).Scan(
		&claim.TenantID, &claim.ScopeID, &claim.UserID, &claim.ChallengeID, &claim.KeyID,
		&claim.WrappedKey, &claim.SealedToken, &claim.AADHash, &claim.EmailDigest,
		&claim.PhoneDigest, &claim.IssuedAt, &claim.ExpiresAt,
	)
	return claim, err
}

func insertDispatchClaim(ctx context.Context, tx pgx.Tx, keyring *DispatchKeyring, claim dispatchClaim, token string) error {
	claim.KeyID = keyring.activeID
	aad := dispatchClaimAAD(claim)
	keyID, wrappedKey, sealedToken, aadHash, err := keyring.seal([]byte(token), aad)
	if err != nil || keyID != claim.KeyID {
		return ErrDispatchUnavailable
	}
	_, err = tx.Exec(ctx, `INSERT INTO account_recovery_dispatch_claims(
		reference,tenant_id,scope_id,user_id,challenge_id,kek_key_id,wrapped_data_key,
		sealed_token,aad_sha256,email_digest,phone_digest,issued_at,expires_at
	) VALUES($1,$2,$3,$4,$5,$6,$7,$8,$9,$10,$11,$12,$13)`,
		claim.Reference, databaseTenantID(claim.TenantID), claim.ScopeID, claim.UserID, claim.ChallengeID,
		keyID, wrappedKey, sealedToken, aadHash[:], nullableDigest(claim.EmailDigest),
		nullableDigest(claim.PhoneDigest), claim.IssuedAt, claim.ExpiresAt)
	if err != nil {
		return ErrDispatchUnavailable
	}
	return nil
}

func dispatchClaimAAD(claim dispatchClaim) []byte {
	var buffer bytes.Buffer
	for _, value := range [][]byte{
		[]byte(dispatchClaimAADDomain), []byte(claim.Reference.String()), []byte(claim.TenantID.String()),
		[]byte(claim.ScopeID.String()), []byte(claim.UserID.String()), []byte(claim.ChallengeID.String()),
		[]byte(claim.KeyID), []byte(claim.IssuedAt.UTC().Format(time.RFC3339Nano)),
		[]byte(claim.ExpiresAt.UTC().Format(time.RFC3339Nano)), claim.EmailDigest, claim.PhoneDigest,
	} {
		_ = binary.Write(&buffer, binary.BigEndian, uint32(len(value)))
		_, _ = buffer.Write(value)
	}
	return buffer.Bytes()
}

func dispatchContact(
	channel notification.Channel,
	email, phone *string,
	emailDigest, phoneDigest []byte,
) (string, []byte, bool) {
	switch channel {
	case notification.ChannelEmail:
		if email == nil || *email == "" || len(emailDigest) != sha256.Size {
			return "", nil, false
		}
		return *email, emailDigest, true
	case notification.ChannelSMS:
		if phone == nil || *phone == "" || len(phoneDigest) != sha256.Size {
			return "", nil, false
		}
		return *phone, phoneDigest, true
	default:
		return "", nil, false
	}
}

func contactDigestDomain(channel notification.Channel) string {
	if channel == notification.ChannelSMS {
		return "cdnca/account-recovery/contact-phone/v1"
	}
	return "cdnca/account-recovery/contact-email/v1"
}

func nullableDigest(value []byte) any {
	if len(value) == 0 {
		return nil
	}
	return value
}

func temporaryDispatchFailure(code string) notification.AnonymousDispatchResult {
	return notification.AnonymousDispatchResult{Failure: &notification.Failure{
		Class: notification.FailureTemporary, Code: code,
	}}
}

func permanentDispatchFailure(code string) notification.AnonymousDispatchResult {
	return notification.AnonymousDispatchResult{Failure: &notification.Failure{
		Class: notification.FailurePermanent, Code: code,
	}}
}

var _ notification.AnonymousDispatcher = (*Dispatcher)(nil)
