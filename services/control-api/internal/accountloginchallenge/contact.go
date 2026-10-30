package accountloginchallenge

import (
	"bytes"
	"context"
	"crypto/hmac"
	"crypto/sha256"
	"encoding/binary"
	"encoding/json"
	"errors"
	"io"
	"time"

	"github.com/cdnca/cdnca/services/control-api/internal/accountregistrationchallenge"
	"github.com/cdnca/cdnca/services/control-api/internal/notification"
	"github.com/google/uuid"
	"github.com/jackc/pgx/v5"
	"github.com/jackc/pgx/v5/pgxpool"
)

type NotificationContactSender struct {
	outbox    DispatchEnqueuer
	keyring   *accountregistrationchallenge.EnvelopeKeyring
	templates map[notification.Channel]notification.TemplateRef
}

type dispatchPayload struct {
	Destination string `json:"destination"`
	OTP         string `json:"otp"`
}

func NewNotificationContactSender(
	outbox DispatchEnqueuer,
	keyring *accountregistrationchallenge.EnvelopeKeyring,
	templates map[notification.Channel]notification.TemplateRef,
) (*NotificationContactSender, error) {
	if outbox == nil || keyring == nil || len(templates) == 0 {
		return nil, ErrInvalidConfig
	}
	cloned := make(map[notification.Channel]notification.TemplateRef, len(templates))
	for channel, ref := range templates {
		if (channel != notification.ChannelEmail && channel != notification.ChannelSMS) || ref.Channel != channel || ref.ID == "" || ref.Version == 0 {
			return nil, ErrInvalidConfig
		}
		cloned[channel] = ref
	}
	return &NotificationContactSender{outbox: outbox, keyring: keyring, templates: cloned}, nil
}

func (sender *NotificationContactSender) Enqueue(ctx context.Context, tx pgx.Tx, request ContactRequest) error {
	if sender == nil || sender.outbox == nil || sender.keyring == nil || tx == nil || request.ScopeID == uuid.Nil ||
		request.ChallengeID == uuid.Nil || request.Destination == "" || !otpPattern.MatchString(request.OTP) ||
		(request.Channel != notification.ChannelEmail && request.Channel != notification.ChannelSMS) ||
		request.ExpiresAt.IsZero() || !metadataPattern.MatchString(request.RequestID) {
		return ErrUnavailable
	}
	template := request.Template
	fallback, available := sender.templates[request.Channel]
	if !available {
		return ErrUnavailable
	}
	if template == (notification.TemplateRef{}) {
		template = fallback
	}
	if template.Channel != request.Channel || template.ID == "" || template.Version == 0 {
		return ErrUnavailable
	}
	reference, err := uuid.NewV7()
	if err != nil {
		return ErrUnavailable
	}
	enqueued, err := sender.outbox.EnqueueDispatchTx(ctx, tx, notification.DispatchEnqueueRequest{
		ScopeID: request.ScopeID, SourceEventID: request.ChallengeID.String(),
		AnonymousDispatchReference: reference, EventType: notification.EventTypeAccountLoginVerification,
		SelectedChannel: request.Channel, Templates: map[notification.Channel]notification.TemplateRef{request.Channel: template},
		AuditRequestID: request.RequestID,
	})
	if err != nil || len(enqueued.Deliveries) != 1 || enqueued.Deliveries[0].Channel != request.Channel {
		return ErrUnavailable
	}
	payload, err := json.Marshal(dispatchPayload{Destination: request.Destination, OTP: request.OTP})
	if err != nil {
		return ErrUnavailable
	}
	outboxID := enqueued.Deliveries[0].OutboxID
	aad := claimAAD(reference, request.ScopeID, request.ChallengeID, outboxID, request.Channel, request.DestinationDigest, request.ExpiresAt)
	sealed, err := sender.keyring.Seal(payload, aad)
	if err != nil {
		return ErrUnavailable
	}
	_, err = tx.Exec(ctx, `INSERT INTO account_login_challenge_dispatch_claims_197(
		anonymous_dispatch_reference,scope_id,challenge_id,outbox_id,channel,destination_digest,
		key_id,nonce,sealed_payload,aad_sha256,expires_at,created_at
	) VALUES($1,$2,$3,$4,$5,$6,$7,$8,$9,$10,$11,clock_timestamp())`, reference, request.ScopeID,
		request.ChallengeID, outboxID, request.Channel, request.DestinationDigest[:], sealed.KeyID,
		sealed.Nonce, sealed.Ciphertext, sha256Bytes(aad), request.ExpiresAt)
	if err != nil {
		return ErrUnavailable
	}
	return nil
}

type Dispatcher struct {
	pool      *pgxpool.Pool
	keyring   *accountregistrationchallenge.EnvelopeKeyring
	provider  ContactProvider
	digestKey []byte
}

func NewDispatcher(
	pool *pgxpool.Pool,
	keyring *accountregistrationchallenge.EnvelopeKeyring,
	provider ContactProvider,
	digestKey []byte,
) (*Dispatcher, error) {
	if pool == nil || keyring == nil || provider == nil || len(digestKey) < 32 {
		return nil, ErrInvalidConfig
	}
	return &Dispatcher{pool: pool, keyring: keyring, provider: provider, digestKey: append([]byte(nil), digestKey...)}, nil
}

func (dispatcher *Dispatcher) Dispatch(ctx context.Context, attempt notification.AnonymousDeliveryAttempt) notification.AnonymousDispatchResult {
	if dispatcher == nil || dispatcher.pool == nil || dispatcher.keyring == nil || dispatcher.provider == nil ||
		attempt.EventType != notification.EventTypeAccountLoginVerification || attempt.OutboxID == uuid.Nil ||
		attempt.ScopeID == uuid.Nil || attempt.EventID == uuid.Nil || attempt.AnonymousDispatchReference == uuid.Nil ||
		attempt.LeaseToken == uuid.Nil || attempt.AttemptNumber < 1 || attempt.LeaseExpiresAt.IsZero() || attempt.DedupKey == "" ||
		(attempt.Channel != notification.ChannelEmail && attempt.Channel != notification.ChannelSMS) {
		return permanentFailure("account_login_dispatch_invalid")
	}
	var delivery ContactDelivery
	noop := false
	err := pgx.BeginFunc(ctx, dispatcher.pool, func(tx pgx.Tx) error {
		var validAttempt bool
		if err := tx.QueryRow(ctx, `SELECT EXISTS(
			SELECT 1 FROM notification_outbox outbox
			JOIN notification_events event ON event.id=outbox.event_id AND event.scope_id=outbox.scope_id
			JOIN notification_attempts delivery_attempt ON delivery_attempt.outbox_id=outbox.id
			WHERE outbox.id=$1 AND outbox.scope_id=$2 AND outbox.status='leased' AND outbox.lease_token=$3
			  AND outbox.lease_expires_at=$4 AND outbox.attempt_count=$5 AND event.id=$6 AND event.event_type=$7
			  AND event.source_event_id=$8 AND event.recipient_kind='anonymous' AND event.anonymous_dispatch_reference=$9
			  AND delivery_attempt.attempt_number=$5 AND delivery_attempt.lease_token=$3
			  AND delivery_attempt.lease_expires_at=$4 AND delivery_attempt.outcome='leased'
		)`, attempt.OutboxID, attempt.ScopeID, attempt.LeaseToken, attempt.LeaseExpiresAt, attempt.AttemptNumber,
			attempt.EventID, notification.EventTypeAccountLoginVerification, attempt.SourceEventID,
			attempt.AnonymousDispatchReference).Scan(&validAttempt); err != nil {
			return err
		}
		if !validAttempt {
			return ErrOTPInvalid
		}
		var challengeID, outboxID uuid.UUID
		var channel notification.Channel
		var destinationDigest, otpDigest, nonce, sealedPayload, storedAAD []byte
		var keyID, state string
		var expiresAt, databaseNow time.Time
		err := tx.QueryRow(ctx, `SELECT claim.challenge_id,claim.outbox_id,claim.channel,claim.destination_digest,
			claim.key_id,claim.nonce,claim.sealed_payload,claim.aad_sha256,claim.expires_at,
			challenge.otp_digest,challenge.state,clock_timestamp()
			FROM account_login_challenge_dispatch_claims_197 claim
			JOIN account_login_challenges_197 challenge ON challenge.id=claim.challenge_id AND challenge.scope_id=claim.scope_id
			WHERE claim.anonymous_dispatch_reference=$1 AND claim.scope_id=$2`, attempt.AnonymousDispatchReference,
			attempt.ScopeID).Scan(&challengeID, &outboxID, &channel, &destinationDigest, &keyID, &nonce,
			&sealedPayload, &storedAAD, &expiresAt, &otpDigest, &state, &databaseNow)
		if errors.Is(err, pgx.ErrNoRows) {
			noop = true
			return nil
		}
		if err != nil {
			return err
		}
		if outboxID != attempt.OutboxID || channel != attempt.Channel || attempt.SourceEventID != challengeID.String() ||
			len(destinationDigest) != sha256.Size || len(otpDigest) != sha256.Size || state != "queued" || !databaseNow.Before(expiresAt) {
			noop = true
			return nil
		}
		var destination [32]byte
		copy(destination[:], destinationDigest)
		aad := claimAAD(attempt.AnonymousDispatchReference, attempt.ScopeID, challengeID, outboxID, channel, destination, expiresAt)
		if !hmac.Equal(storedAAD, sha256Bytes(aad)) {
			return ErrOTPInvalid
		}
		plaintext, err := dispatcher.keyring.Open(accountregistrationchallenge.SealedEnvelope{
			KeyID: keyID, Nonce: nonce, Ciphertext: sealedPayload,
		}, aad)
		if err != nil {
			return ErrOTPInvalid
		}
		var payload dispatchPayload
		decoder := json.NewDecoder(bytes.NewReader(plaintext))
		decoder.DisallowUnknownFields()
		if err := decoder.Decode(&payload); err != nil || decoder.Decode(&struct{}{}) != io.EOF {
			return ErrOTPInvalid
		}
		currentDestination := keyedDigest(dispatcher.digestKey, identifierDigestDomain, []byte(payload.Destination))
		currentOTP := keyedDigest(dispatcher.digestKey, otpDigestDomain, []byte(payload.OTP))
		if !hmac.Equal(currentDestination[:], destinationDigest) || !hmac.Equal(currentOTP[:], otpDigest) {
			return ErrOTPInvalid
		}
		delivery = ContactDelivery{
			OutboxID: outboxID, Channel: channel, Template: attempt.Template, Destination: payload.Destination,
			OTP: payload.OTP, Subject: attempt.Subject, Body: attempt.Body, IdempotencyKey: attempt.DedupKey,
			AttemptNumber: attempt.AttemptNumber,
		}
		return nil
	})
	if err != nil {
		if errors.Is(err, ErrOTPInvalid) {
			return permanentFailure("account_login_dispatch_invalid")
		}
		return temporaryFailure("account_login_dispatch_unavailable")
	}
	if noop {
		return notification.AnonymousDispatchResult{Disposition: notification.AnonymousDispatchNoopACK}
	}
	return mapSendResult(dispatcher.provider.SendLoginVerification(ctx, delivery))
}

func claimAAD(
	reference, scopeID, challengeID, outboxID uuid.UUID,
	channel notification.Channel,
	destinationDigest [32]byte,
	expiresAt time.Time,
) []byte {
	buffer := bytes.NewBuffer(nil)
	for _, value := range [][]byte{
		[]byte("account-login-challenge:v1:dispatch-claim"), []byte(reference.String()), []byte(scopeID.String()),
		[]byte(challengeID.String()), []byte(outboxID.String()), []byte(channel), destinationDigest[:],
		[]byte(expiresAt.UTC().Truncate(time.Microsecond).Format(time.RFC3339Nano)),
	} {
		_ = binary.Write(buffer, binary.BigEndian, uint32(len(value)))
		_, _ = buffer.Write(value)
	}
	return buffer.Bytes()
}

func sha256Bytes(value []byte) []byte {
	digest := sha256.Sum256(value)
	return digest[:]
}

func mapSendResult(result notification.SendResult) notification.AnonymousDispatchResult {
	if result.Failure != nil {
		return notification.AnonymousDispatchResult{Failure: result.Failure, Observation: result.Observation}
	}
	mapped := notification.AnonymousDispatchResult{Provider: result.Provider, ProviderDeliveryID: result.ProviderDeliveryID, Observation: result.Observation}
	switch result.Disposition {
	case notification.SendDelivered:
		mapped.Disposition = notification.AnonymousDispatchDelivered
	case notification.SendAccepted:
		mapped.Disposition = notification.AnonymousDispatchAccepted
	case notification.SendUnknown:
		mapped.Disposition = notification.AnonymousDispatchUnknown
	default:
		return permanentFailure("account_login_dispatch_contract_invalid")
	}
	return mapped
}

func temporaryFailure(code string) notification.AnonymousDispatchResult {
	return notification.AnonymousDispatchResult{Failure: &notification.Failure{Class: notification.FailureTemporary, Code: code}}
}

func permanentFailure(code string) notification.AnonymousDispatchResult {
	return notification.AnonymousDispatchResult{Failure: &notification.Failure{Class: notification.FailurePermanent, Code: code}}
}
