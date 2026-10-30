package pluginwebhookruntime

import (
	"bytes"
	"context"
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"
	"errors"
	"fmt"
	"net/http"
	"regexp"
	"strconv"
	"strings"
	"time"

	"github.com/cdnca/cdnca/services/control-api/internal/pluginwebhook"
	"github.com/google/uuid"
	"github.com/jackc/pgx/v5"
	"github.com/nats-io/nats.go"
)

var stableCodePattern = regexp.MustCompile(`^[a-z][a-z0-9_]{0,127}$`)

type deliveryRow struct {
	tenantScope    uuid.UUID
	tenantID       uuid.UUID
	subscription   uuid.UUID
	delivery       uuid.UUID
	event          uuid.UUID
	actorScope     uuid.UUID
	actorUser      uuid.UUID
	secretVersion  uuid.UUID
	status         string
	attempts       uint64
	revision       uint64
	lifecycle      uint64
	nextAttemptAt  *time.Time
	idempotencyKey string
	targetURL      string
	body           []byte
	digest         []byte
	messageID      string
	streamEpoch    int64
	streamSequence uint64
	brokerIdentity bool
}

type outboxLease struct {
	tenantScope    uuid.UUID
	subscription   uuid.UUID
	delivery       uuid.UUID
	leaseToken     uuid.UUID
	body           []byte
	messageID      string
	status         string
	publishAttempt uint64
}

const (
	deadLetterScanBatch            = 32
	deliveryRecoveryEpochHeader    = "X-CDNCA-Webhook-Recovery-Stream-Created-Unix-Nano"
	deliveryRecoverySequenceHeader = "X-CDNCA-Webhook-Recovery-Stream-Sequence"
)

func deliveryMessage(config JetStreamConfig, tenantScope, subscription, delivery uuid.UUID, body []byte,
	messageID string) *nats.Msg {
	message := nats.NewMsg(deliverySubject(config.DeliverySubjectPrefix, tenantScope, subscription, delivery))
	message.Data = append([]byte(nil), body...)
	message.Header.Set(nats.MsgIdHdr, messageID)
	message.Header.Set("X-CDNCA-Webhook-Id", delivery.String())
	digest := sha256.Sum256(body)
	message.Header.Set("X-CDNCA-Webhook-Queue-Sha256", hex.EncodeToString(digest[:]))
	message.Header.Set(nats.ExpectedStreamHdr, config.DeliveryStream)
	message.Header.Set(nats.ExpectedLastSubjSeqHdr, "0")
	return message
}

func recoveryDeliveryMessage(config JetStreamConfig, item deliveryRow) *nats.Msg {
	message := deliveryMessage(config, item.tenantScope, item.subscription, item.delivery, item.body, item.messageID)
	message.Header.Set(deliveryRecoveryEpochHeader, strconv.FormatInt(item.streamEpoch, 10))
	message.Header.Set(deliveryRecoverySequenceHeader, strconv.FormatUint(item.streamSequence, 10))
	return message
}

func (runtime *Runtime) publishOutbox(ctx context.Context) error {
	lease, err := runtime.leaseOutbox(ctx)
	if errors.Is(err, errNoOutbox) {
		return nil
	}
	if err != nil {
		return err
	}
	message := deliveryMessage(runtime.config.JetStream, lease.tenantScope, lease.subscription,
		lease.delivery, lease.body, lease.messageID)
	if lease.publishAttempt > 1 {
		epoch, sequence, reconcileErr := runtime.reconcilePublishedOutbox(ctx, message)
		if reconcileErr != nil {
			return reconcileErr
		}
		if sequence > 0 {
			return runtime.markOutboxPublished(ctx, lease, epoch, sequence)
		}
	}
	epoch, err := runtime.deliveryStreamEpoch(ctx)
	if err != nil {
		return err
	}
	operationCtx, cancel := context.WithTimeout(ctx, runtime.config.OperationTimeout)
	ack, publishErr := runtime.jetstream.PublishMsg(message, nats.Context(operationCtx),
		nats.ExpectStream(runtime.config.JetStream.DeliveryStream), nats.ExpectLastSequencePerSubject(0))
	cancel()
	if publishErr != nil || ack == nil || ack.Stream != runtime.config.JetStream.DeliveryStream {
		if publishErr != nil {
			return publishErr
		}
		return fmt.Errorf("plugin webhook runtime NATS publish acknowledgement is invalid")
	}
	if err := runtime.verifyPublishedWire(ctx, runtime.config.JetStream.DeliveryStream, message, ack.Sequence); err != nil {
		return err
	}
	currentEpoch, err := runtime.deliveryStreamEpoch(ctx)
	if err != nil {
		return err
	}
	if currentEpoch != epoch {
		return fmt.Errorf("plugin webhook delivery stream changed during publication")
	}
	return runtime.markOutboxPublished(ctx, lease, epoch, ack.Sequence)
}

func (runtime *Runtime) recoverDeliveryStream(ctx context.Context) error {
	operationCtx, cancel := context.WithTimeout(ctx, runtime.config.OperationTimeout)
	info, err := runtime.jetstream.StreamInfo(runtime.config.JetStream.DeliveryStream, nats.Context(operationCtx))
	cancel()
	if err != nil {
		return fmt.Errorf("inspect plugin webhook delivery stream for recovery: %w", err)
	}
	epoch := info.Created.UTC().UnixNano()
	if epoch <= 0 {
		return fmt.Errorf("plugin webhook delivery stream recovery identity is invalid")
	}
	firstSequence := info.State.FirstSeq
	if firstSequence == 0 {
		firstSequence = 1
	}
	item, err := runtime.loadStaleDeliveryStreamCandidate(ctx, epoch, firstSequence)
	if errors.Is(err, errNoStaleDelivery) {
		return nil
	}
	if err != nil {
		return err
	}
	message := recoveryDeliveryMessage(runtime.config.JetStream, item)
	operationCtx, cancel = context.WithTimeout(ctx, runtime.config.OperationTimeout)
	ack, publishErr := runtime.jetstream.PublishMsg(message, nats.Context(operationCtx),
		nats.ExpectStream(runtime.config.JetStream.DeliveryStream), nats.ExpectLastSequencePerSubject(0))
	cancel()
	if publishErr != nil || ack == nil || ack.Stream != runtime.config.JetStream.DeliveryStream {
		reconciledEpoch, sequence, reconcileErr := runtime.reconcilePublishedOutbox(ctx, message)
		if reconcileErr == nil && reconciledEpoch == epoch && sequence > 0 {
			return nil
		}
		if publishErr != nil {
			return publishErr
		}
		if reconcileErr != nil {
			return reconcileErr
		}
		return fmt.Errorf("plugin webhook recovery NATS publish acknowledgement is invalid")
	}
	if err := runtime.verifyPublishedWire(ctx, runtime.config.JetStream.DeliveryStream, message, ack.Sequence); err != nil {
		return err
	}
	currentEpoch, err := runtime.deliveryStreamEpoch(ctx)
	if err != nil {
		return err
	}
	if currentEpoch != epoch {
		return fmt.Errorf("plugin webhook delivery stream changed during recovery publication")
	}
	return nil
}

func (runtime *Runtime) loadStaleDeliveryStreamCandidate(ctx context.Context, epoch int64, firstSequence uint64) (deliveryRow, error) {
	if epoch <= 0 || firstSequence == 0 {
		return deliveryRow{}, errAttemptState
	}
	var tenantScope, subscription, delivery uuid.UUID
	err := runtime.pool.QueryRow(ctx, `SELECT delivery.tenant_scope_id,delivery.subscription_id,delivery.id
		FROM plugin_webhook_deliveries delivery
		JOIN plugin_webhook_outbox outbox
		  ON outbox.tenant_scope_id=delivery.tenant_scope_id
		 AND outbox.subscription_id=delivery.subscription_id AND outbox.delivery_id=delivery.id
		JOIN plugin_webhook_subscriptions subscription
		  ON subscription.tenant_scope_id=delivery.tenant_scope_id AND subscription.id=delivery.subscription_id
		WHERE subscription.status='active' AND delivery.status IN ('queued','retry_scheduled')
		  AND outbox.status='published' AND (
		      delivery.nats_stream_created_unix_nano <> $1::numeric OR
		      (delivery.nats_stream_created_unix_nano = $1::numeric AND delivery.nats_stream_sequence < $2::numeric)
		  )
		ORDER BY delivery.queued_at,delivery.id LIMIT 1`, epoch, firstSequence).Scan(&tenantScope, &subscription, &delivery)
	if errors.Is(err, pgx.ErrNoRows) {
		return deliveryRow{}, errNoStaleDelivery
	}
	if err != nil {
		return deliveryRow{}, err
	}
	item, err := runtime.loadDeliveryScoped(ctx, tenantScope, subscription, delivery)
	if err != nil {
		return deliveryRow{}, err
	}
	if item.status != "queued" && item.status != "retry_scheduled" ||
		(item.streamEpoch == epoch && item.streamSequence >= firstSequence) {
		return deliveryRow{}, errNoStaleDelivery
	}
	return item, nil
}

func (runtime *Runtime) reconcilePublishedOutbox(ctx context.Context, message *nats.Msg) (int64, uint64, error) {
	epoch, err := runtime.deliveryStreamEpoch(ctx)
	if err != nil {
		return 0, 0, err
	}
	operationCtx, cancel := context.WithTimeout(ctx, runtime.config.OperationTimeout)
	stored, err := runtime.jetstream.GetLastMsg(runtime.config.JetStream.DeliveryStream, message.Subject,
		nats.Context(operationCtx))
	cancel()
	if errors.Is(err, nats.ErrMsgNotFound) {
		return 0, 0, nil
	}
	if err != nil {
		return 0, 0, fmt.Errorf("reconcile plugin webhook runtime NATS publication: %w", err)
	}
	if !storedDeliveryMessageMatches(stored, message) {
		return 0, 0, fmt.Errorf("plugin webhook runtime stored publication identity does not match")
	}
	currentEpoch, err := runtime.deliveryStreamEpoch(ctx)
	if err != nil {
		return 0, 0, err
	}
	if currentEpoch != epoch {
		return 0, 0, fmt.Errorf("plugin webhook delivery stream changed during publication reconciliation")
	}
	return epoch, stored.Sequence, nil
}

func (runtime *Runtime) deliveryStreamEpoch(ctx context.Context) (int64, error) {
	operationCtx, cancel := context.WithTimeout(ctx, runtime.config.OperationTimeout)
	info, err := runtime.jetstream.StreamInfo(runtime.config.JetStream.DeliveryStream, nats.Context(operationCtx))
	cancel()
	if err != nil {
		return 0, fmt.Errorf("inspect plugin webhook delivery stream: %w", err)
	}
	epoch := info.Created.UTC().UnixNano()
	if epoch <= 0 {
		return 0, fmt.Errorf("plugin webhook delivery stream epoch is invalid")
	}
	return epoch, nil
}

func storedDeliveryMessageMatches(stored *nats.RawStreamMsg, expected *nats.Msg) bool {
	if stored == nil || expected == nil || stored.Sequence == 0 || stored.Subject != expected.Subject ||
		!bytes.Equal(stored.Data, expected.Data) || len(stored.Header) != len(expected.Header) {
		return false
	}
	for name, values := range expected.Header {
		if !sameStrings(stored.Header.Values(name), values) {
			return false
		}
	}
	return true
}

func (runtime *Runtime) verifyPublishedWire(ctx context.Context, stream string, expected *nats.Msg, sequence uint64) error {
	if sequence == 0 {
		return fmt.Errorf("plugin webhook runtime NATS publish acknowledgement is invalid")
	}
	operationCtx, cancel := context.WithTimeout(ctx, runtime.config.OperationTimeout)
	stored, err := runtime.jetstream.GetMsg(stream, sequence, nats.Context(operationCtx))
	cancel()
	if err != nil {
		return fmt.Errorf("read plugin webhook runtime acknowledged publication: %w", err)
	}
	if !storedDeliveryMessageMatches(stored, expected) {
		return fmt.Errorf("plugin webhook runtime acknowledged publication wire does not match")
	}
	return nil
}

func (runtime *Runtime) leaseOutbox(ctx context.Context) (outboxLease, error) {
	tx, err := runtime.pool.Begin(ctx)
	if err != nil {
		return outboxLease{}, err
	}
	defer tx.Rollback(ctx)
	var lease outboxLease
	var body []byte
	var publishAttempt string
	var candidateStatus string
	row := tx.QueryRow(ctx, `
		SELECT outbox.tenant_scope_id,outbox.subscription_id,outbox.delivery_id,
		       outbox.queue_body,outbox.message_id,outbox.status,outbox.publish_attempt::text
		FROM plugin_webhook_outbox outbox
		JOIN plugin_webhook_deliveries delivery
		  ON delivery.tenant_scope_id=outbox.tenant_scope_id
		 AND delivery.subscription_id=outbox.subscription_id AND delivery.id=outbox.delivery_id
		JOIN plugin_webhook_subscriptions subscription
		  ON subscription.tenant_scope_id=outbox.tenant_scope_id AND subscription.id=outbox.subscription_id
		WHERE subscription.status='active' AND (
			(outbox.status='pending' AND outbox.available_at <= clock_timestamp()) OR
			(outbox.status='leased' AND outbox.lease_expires_at <= clock_timestamp())
		)
		ORDER BY outbox.available_at,outbox.id LIMIT 1`)
	if err := row.Scan(&lease.tenantScope, &lease.subscription, &lease.delivery, &body,
		&lease.messageID, &candidateStatus, &publishAttempt); err != nil {
		if errors.Is(err, pgx.ErrNoRows) {
			return outboxLease{}, errNoOutbox
		}
		return outboxLease{}, err
	}
	subscriptionFence, err := lockSubscription(ctx, tx, lease.tenantScope, lease.subscription)
	if err != nil {
		return outboxLease{}, err
	}
	if subscriptionFence.status != "active" {
		return outboxLease{}, errNoOutbox
	}
	deliveryStatus, _, _, err := lockDelivery(ctx, tx, lease.tenantScope, lease.subscription, lease.delivery)
	if err != nil {
		return outboxLease{}, err
	}
	if deliveryStatus != "pending" {
		return outboxLease{}, errNoOutbox
	}
	var availableAt, leaseExpiresAt *time.Time
	var serverNow time.Time
	if err := tx.QueryRow(ctx, `SELECT queue_body,message_id,status,publish_attempt::text,available_at,lease_expires_at,
		clock_timestamp()
		FROM plugin_webhook_outbox
		WHERE tenant_scope_id=$1 AND subscription_id=$2 AND delivery_id=$3 FOR UPDATE`,
		lease.tenantScope, lease.subscription, lease.delivery).Scan(
		&body, &lease.messageID, &lease.status, &publishAttempt, &availableAt, &leaseExpiresAt, &serverNow); err != nil {
		return outboxLease{}, err
	}
	if lease.status != candidateStatus || lease.status == "pending" && (availableAt == nil || availableAt.After(serverNow)) ||
		lease.status == "leased" && (leaseExpiresAt == nil || leaseExpiresAt.After(serverNow)) {
		return outboxLease{}, errNoOutbox
	}
	lease.body = body
	lease.leaseToken = uuid.New()
	lease.publishAttempt, err = strconv.ParseUint(publishAttempt, 10, 64)
	if err != nil {
		return outboxLease{}, fmt.Errorf("parse plugin webhook publish attempt: %w", err)
	}
	if lease.status == "leased" {
		if _, err := tx.Exec(ctx, `UPDATE plugin_webhook_outbox
			SET status='pending',lease_token=NULL,lease_expires_at=NULL,leased_at=NULL
			WHERE tenant_scope_id=$1 AND subscription_id=$2 AND delivery_id=$3 AND status='leased'`,
			lease.tenantScope, lease.subscription, lease.delivery); err != nil {
			return outboxLease{}, err
		}
	}
	tag, err := tx.Exec(ctx, `UPDATE plugin_webhook_outbox
		SET status='leased',lease_token=$4,lease_expires_at=$5::timestamptz+$6::interval,
		    leased_at=$5::timestamptz,publish_attempt=publish_attempt+1
		WHERE tenant_scope_id=$1 AND subscription_id=$2 AND delivery_id=$3 AND status='pending'`,
		lease.tenantScope, lease.subscription, lease.delivery, lease.leaseToken, serverNow,
		leaseInterval(runtime.config.LeaseDuration))
	if err != nil {
		return outboxLease{}, err
	}
	if tag.RowsAffected() != 1 {
		return outboxLease{}, errNoOutbox
	}
	lease.publishAttempt++
	if err := tx.Commit(ctx); err != nil {
		return outboxLease{}, err
	}
	return lease, nil
}

func (runtime *Runtime) markOutboxPublished(ctx context.Context, lease outboxLease, epoch int64, sequence uint64) error {
	if epoch <= 0 || sequence == 0 {
		return errAttemptState
	}
	if err := runtime.prepareAttestation(ctx); err != nil {
		return err
	}
	tx, err := runtime.pool.Begin(ctx)
	if err != nil {
		return err
	}
	defer tx.Rollback(ctx)
	head, err := runtime.lockAttestationHead(ctx, tx)
	if err != nil {
		return err
	}
	subscriptionFence, err := lockSubscription(ctx, tx, lease.tenantScope, lease.subscription)
	if err != nil {
		return err
	}
	if subscriptionFence.status != "active" {
		return errNotClaimable
	}
	var facts outboxPublication
	var eventID uuid.UUID
	var deliveryStatus string
	if err := tx.QueryRow(ctx, `SELECT event_id,status FROM plugin_webhook_deliveries
			WHERE tenant_scope_id=$1 AND subscription_id=$2 AND id=$3 FOR UPDATE`,
		lease.tenantScope, lease.subscription, lease.delivery).Scan(&eventID, &deliveryStatus); err != nil {
		return err
	}
	var outboxStatus, currentMessageID, publishAttempt string
	var currentLeaseToken *uuid.UUID
	var currentBody []byte
	if err := tx.QueryRow(ctx, `SELECT id,status,lease_token,message_id,queue_body,queue_body_sha256,
			publish_attempt::text FROM plugin_webhook_outbox
			WHERE tenant_scope_id=$1 AND subscription_id=$2 AND delivery_id=$3 FOR UPDATE`,
		lease.tenantScope, lease.subscription, lease.delivery).Scan(&facts.outboxID,
		&outboxStatus, &currentLeaseToken, &currentMessageID, &currentBody, &facts.queueDigest, &publishAttempt); err != nil {
		return err
	}
	if facts.publishAttempt, err = parseUint(publishAttempt); err != nil {
		return err
	}
	facts.eventID = eventID
	if deliveryStatus != "pending" || outboxStatus != "leased" || currentLeaseToken == nil ||
		*currentLeaseToken != lease.leaseToken || currentMessageID != lease.messageID ||
		!bytes.Equal(currentBody, lease.body) || facts.publishAttempt != lease.publishAttempt {
		return errAttemptState
	}
	// 084 moves the delivery to queued and the outbox to published itself,
	// after verifying the broker identity and this runtime's signature.
	subject := deliverySubject(runtime.config.JetStream.DeliverySubjectPrefix, lease.tenantScope,
		lease.subscription, lease.delivery)
	signature := runtime.outboxAttestation(head, lease, facts, epoch, subject, sequence)
	if _, err := tx.Exec(ctx, `SELECT publish_plugin_webhook_outbox_084(
			$1,$2,$3,$4,$5,$6,$7::numeric,$8,$9::numeric,$10,$11,0,$12::numeric,$13,$14)`,
		lease.tenantScope, lease.subscription, lease.delivery, lease.leaseToken, head.natsDomain,
		runtime.config.JetStream.DeliveryStream, strconv.FormatInt(epoch, 10), subject,
		strconv.FormatUint(sequence, 10), lease.messageID, facts.queueDigest,
		strconv.FormatUint(head.generation, 10), head.keyID, signature); err != nil {
		return err
	}
	return tx.Commit(ctx)
}

func (runtime *Runtime) loadDelivery(ctx context.Context, deliveryID uuid.UUID) (deliveryRow, error) {
	return runtime.loadDeliveryScoped(ctx, uuid.Nil, uuid.Nil, deliveryID)
}

func (runtime *Runtime) loadDeliveryScoped(ctx context.Context, tenantScope, subscription, deliveryID uuid.UUID) (deliveryRow, error) {
	return runtime.loadDeliveryWithBrokerIdentity(ctx, tenantScope, subscription, deliveryID, 0, 0)
}

func (runtime *Runtime) loadDeliveryWithBrokerIdentity(ctx context.Context, tenantScope, subscription, deliveryID uuid.UUID,
	brokerEpoch int64, brokerSequence uint64) (deliveryRow, error) {
	var item deliveryRow
	var attempts, revision, lifecycle, streamEpoch, streamSequence string
	err := runtime.pool.QueryRow(ctx, `
		SELECT delivery.tenant_scope_id,scope.tenant_id,delivery.subscription_id,delivery.id,delivery.event_id,
		       delivery.actor_scope_id,delivery.actor_user_id,subscription.active_secret_version_id,
		       delivery.status,delivery.attempt_count::text,subscription.revision::text,
		       subscription.lifecycle_sequence::text,delivery.next_attempt_at,
		       delivery.delivery_idempotency_key,delivery.target_url,event.canonical_body,event.body_sha256,
			       outbox.message_id,COALESCE(delivery.nats_stream_created_unix_nano::text,''),
			       COALESCE(delivery.nats_stream_sequence::text,'')
		FROM plugin_webhook_deliveries delivery
		JOIN plugin_webhook_events event
		  ON event.tenant_scope_id=delivery.tenant_scope_id
		 AND event.subscription_id=delivery.subscription_id AND event.id=delivery.event_id
		JOIN plugin_webhook_subscriptions subscription
		  ON subscription.tenant_scope_id=delivery.tenant_scope_id AND subscription.id=delivery.subscription_id
		JOIN access_scopes scope ON scope.id=delivery.tenant_scope_id AND scope.kind='tenant'
		JOIN plugin_webhook_outbox outbox
		  ON outbox.tenant_scope_id=delivery.tenant_scope_id AND outbox.subscription_id=delivery.subscription_id
		 AND outbox.delivery_id=delivery.id AND (outbox.status='published' OR
			(outbox.status='revoked' AND delivery.status='revoked'))
		WHERE delivery.tenant_scope_id=COALESCE(NULLIF($1::uuid,'00000000-0000-0000-0000-000000000000'),delivery.tenant_scope_id)
		  AND delivery.subscription_id=COALESCE(NULLIF($2::uuid,'00000000-0000-0000-0000-000000000000'),delivery.subscription_id)
		  AND delivery.id=$3`, tenantScope, subscription, deliveryID).Scan(
		&item.tenantScope, &item.tenantID, &item.subscription, &item.delivery, &item.event, &item.actorScope, &item.actorUser,
		&item.secretVersion, &item.status, &attempts, &revision, &lifecycle, &item.nextAttemptAt,
		&item.idempotencyKey, &item.targetURL, &item.body, &item.digest, &item.messageID, &streamEpoch, &streamSequence)
	if err != nil {
		return deliveryRow{}, err
	}
	var parseErr error
	item.attempts, parseErr = strconv.ParseUint(attempts, 10, 64)
	if parseErr != nil {
		return deliveryRow{}, parseErr
	}
	item.revision, parseErr = strconv.ParseUint(revision, 10, 64)
	if parseErr != nil {
		return deliveryRow{}, parseErr
	}
	item.lifecycle, parseErr = strconv.ParseUint(lifecycle, 10, 64)
	if parseErr != nil {
		return deliveryRow{}, parseErr
	}
	if streamEpoch != "" && streamSequence != "" {
		item.streamEpoch, parseErr = strconv.ParseInt(streamEpoch, 10, 64)
		if parseErr == nil {
			item.streamSequence, parseErr = strconv.ParseUint(streamSequence, 10, 64)
		}
	} else if streamEpoch == "" && streamSequence == "" && item.status == "revoked" && brokerEpoch > 0 && brokerSequence > 0 {
		item.streamEpoch, item.streamSequence, item.brokerIdentity = brokerEpoch, brokerSequence, true
	} else if streamEpoch != "" || streamSequence != "" {
		parseErr = errAttemptState
	}
	if parseErr != nil {
		return deliveryRow{}, fmt.Errorf("parse plugin webhook stream sequence: %w", parseErr)
	}
	if item.streamEpoch <= 0 || item.streamSequence == 0 {
		return deliveryRow{}, fmt.Errorf("plugin webhook delivery is missing positive stream identity")
	}
	if brokerEpoch != 0 || brokerSequence != 0 {
		if brokerEpoch <= 0 || brokerSequence == 0 || item.streamEpoch != brokerEpoch || item.streamSequence != brokerSequence {
			return deliveryRow{}, fmt.Errorf("plugin webhook delivery broker identity does not match")
		}
	}
	digest := sha256.Sum256(item.body)
	if len(item.digest) != sha256.Size || !bytes.Equal(item.digest, digest[:]) {
		return deliveryRow{}, fmt.Errorf("plugin webhook canonical event digest mismatch")
	}
	return item, nil
}

func (runtime *Runtime) processOne(ctx context.Context) error {
	message, err := runtime.consumer.next(ctx)
	if err != nil {
		return err
	}
	tenantScope, subscription, err := message.Scope(runtime.config.JetStream.DeliverySubjectPrefix)
	if err != nil {
		return message.nak(ctx, time.Second)
	}
	deliveryID, err := message.DeliveryID()
	if err != nil {
		return message.nak(ctx, time.Second)
	}
	if message.streamSequence == 0 {
		return message.nak(ctx, time.Second)
	}
	streamEpoch, err := runtime.deliveryStreamEpoch(ctx)
	if err != nil {
		return message.nak(ctx, time.Second)
	}
	item, err := runtime.loadDeliveryWithBrokerIdentity(ctx, tenantScope, subscription, deliveryID, streamEpoch, message.streamSequence)
	if err != nil {
		candidate, recoveryErr := runtime.loadDeliveryScoped(ctx, tenantScope, subscription, deliveryID)
		if recoveryErr == nil && natsMessagesEqual(message.message, recoveryDeliveryMessage(runtime.config.JetStream, candidate)) {
			originalMissing := candidate.streamEpoch != streamEpoch
			if !originalMissing {
				operationCtx, cancel := context.WithTimeout(ctx, runtime.config.OperationTimeout)
				_, originalErr := runtime.jetstream.GetMsg(runtime.config.JetStream.DeliveryStream,
					candidate.streamSequence, nats.Context(operationCtx))
				cancel()
				originalMissing = errors.Is(originalErr, nats.ErrMsgNotFound)
			}
			if originalMissing {
				candidate.brokerIdentity = true
				item, err = candidate, nil
			}
		}
	}
	if errors.Is(err, pgx.ErrNoRows) {
		return message.nak(ctx, time.Second)
	}
	if err != nil {
		return message.nak(ctx, time.Second)
	}
	if !bytes.Equal(message.message.Data, item.body) {
		return message.nak(ctx, time.Second)
	}
	if message.message.Header.Get(nats.MsgIdHdr) != item.messageID ||
		(!item.brokerIdentity && message.streamSequence != item.streamSequence) {
		return message.nak(ctx, time.Second)
	}
	operationCtx, cancel := context.WithTimeout(ctx, runtime.config.OperationTimeout)
	stored, storedErr := runtime.jetstream.GetMsg(runtime.config.JetStream.DeliveryStream,
		message.streamSequence, nats.Context(operationCtx))
	cancel()
	if storedErr != nil || !storedDeliveryMessageMatches(stored, message.message) {
		return message.nak(ctx, time.Second)
	}
	currentEpoch, epochErr := runtime.deliveryStreamEpoch(ctx)
	if epochErr != nil || currentEpoch != streamEpoch {
		return message.nak(ctx, time.Second)
	}
	if item.status == "delivered" || item.status == "dead_lettered" || item.status == "revoked" {
		return message.ack(ctx)
	}
	if item.status == "dead_letter_pending" {
		if err := runtime.publishPendingDeadLetter(ctx, tenantScope, subscription, deliveryID, true); err != nil {
			return message.nak(ctx, time.Second)
		}
		return message.ack(ctx)
	}
	claim, err := runtime.claim(ctx, item)
	if err != nil {
		if errors.Is(err, errNotClaimable) {
			return message.nak(ctx, time.Second)
		}
		if errors.Is(err, errNotDue) {
			delay, delayErr := runtime.retryDelay(ctx, item.tenantScope, item.subscription, item.delivery)
			if delayErr != nil || delay <= 0 {
				return message.nak(ctx, time.Second)
			}
			return message.nak(ctx, delay)
		}
		return message.nak(ctx, time.Second)
	}
	secret, err := runtime.start(ctx, &claim, item.digest)
	if err != nil {
		return message.nak(ctx, time.Second)
	}
	defer clearSecret(secret)
	queueItem, err := pluginwebhook.NewV2QueueItem(item.body, pluginwebhook.V2QueueIdentity{
		TargetScopeID: item.tenantScope, TenantID: item.tenantID, SubscriptionID: item.subscription,
		SecretVersionID: claim.secretVersion, EventID: item.event, DeliveryID: item.delivery,
	}, item.idempotencyKey, item.targetURL)
	if err != nil {
		if finishErr := runtime.finish(ctx, claim, pluginwebhook.SendResult{Code: "invalid_delivery"}); finishErr != nil {
			return message.nak(ctx, time.Second)
		}
		if deadLetterErr := runtime.publishPendingDeadLetter(ctx, claim.tenantScope, claim.subscription, claim.delivery, false); deadLetterErr != nil {
			return message.nak(ctx, time.Second)
		}
		return message.ack(ctx)
	}
	result := pluginwebhook.SendResult{}
	deliverer, ok := runtime.deliverer.(preparedV2Deliverer)
	if !ok {
		return message.nak(ctx, time.Second)
	}
	result = deliverer.DeliverV2(ctx, queueItem, claim.attempt, secret)
	if !validResult(result) {
		if !validOptionalSHA256(result.ResponseSHA256) {
			return message.nak(ctx, time.Second)
		}
		result = pluginwebhook.SendResult{Code: "sender_contract_invalid"}
	}
	finishErr := runtime.finish(ctx, claim, result)
	if finishErr != nil {
		return message.nak(ctx, time.Second)
	}
	if !result.Success && (!result.Retryable || claim.attempt == 5) {
		if err := runtime.publishPendingDeadLetter(ctx, claim.tenantScope, claim.subscription, claim.delivery, false); err != nil {
			return message.nak(ctx, time.Second)
		}
	}
	var currentStatus string
	if err := runtime.pool.QueryRow(ctx, `SELECT status FROM plugin_webhook_deliveries
		WHERE tenant_scope_id=$1 AND subscription_id=$2 AND id=$3`,
		claim.tenantScope, claim.subscription, claim.delivery).Scan(&currentStatus); err != nil {
		return message.nak(ctx, time.Second)
	}
	if currentStatus == "revoked" || currentStatus == "delivered" || currentStatus == "dead_lettered" {
		return message.ack(ctx)
	}
	if result.Retryable && claim.attempt < 5 {
		delay, delayErr := runtime.retryDelay(ctx, item.tenantScope, item.subscription, item.delivery)
		if delayErr != nil || delay <= 0 {
			return message.nak(ctx, time.Second)
		}
		return message.nak(ctx, delay)
	}
	return message.ack(ctx)
}

func natsMessagesEqual(actual, expected *nats.Msg) bool {
	if actual == nil || expected == nil || actual.Subject != expected.Subject || !bytes.Equal(actual.Data, expected.Data) ||
		len(actual.Header) != len(expected.Header) {
		return false
	}
	for name, values := range expected.Header {
		if !sameStrings(actual.Header.Values(name), values) {
			return false
		}
	}
	return true
}

type claimRow struct {
	tenantScope, subscription, delivery, token, secretVersion uuid.UUID
	attempt, claimSequence, claimedRevision                   uint64
}

type subscriptionFence struct {
	status       string
	revision     uint64
	lifecycle    uint64
	activeSecret uuid.UUID
	revokeSeq    uint64
	revokedAt    *time.Time
}

type attemptFence struct {
	status          string
	attempt         uint64
	claimSequence   uint64
	claimedRevision uint64
	secretVersion   uuid.UUID
	claimedAt       *time.Time
	startedAt       *time.Time
	recordedAt      *time.Time
	requestDigest   []byte
	httpStatus      *int
	failureCode     *string
	responseDigest  []byte
	responseBytes   *int
}

func lockSubscription(ctx context.Context, tx pgx.Tx, tenantScope, subscription uuid.UUID) (subscriptionFence, error) {
	var fence subscriptionFence
	var revision, lifecycle, revokeSequence string
	if err := tx.QueryRow(ctx, `SELECT status,revision::text,lifecycle_sequence::text,
		active_secret_version_id,COALESCE(revoke_sequence::text,''),revoked_at
		FROM plugin_webhook_subscriptions
		WHERE tenant_scope_id=$1 AND id=$2 FOR UPDATE`, tenantScope, subscription).Scan(
		&fence.status, &revision, &lifecycle, &fence.activeSecret, &revokeSequence, &fence.revokedAt); err != nil {
		return subscriptionFence{}, err
	}
	var err error
	fence.revision, err = parseUint(revision)
	if err != nil {
		return subscriptionFence{}, err
	}
	fence.lifecycle, err = parseUint(lifecycle)
	if err != nil {
		return subscriptionFence{}, err
	}
	if revokeSequence != "" {
		fence.revokeSeq, err = parseUint(revokeSequence)
		if err != nil {
			return subscriptionFence{}, err
		}
	}
	return fence, nil
}

func lockDelivery(ctx context.Context, tx pgx.Tx, tenantScope, subscription, delivery uuid.UUID) (string, uint64, *time.Time, error) {
	var status, attempts string
	var nextAttempt *time.Time
	if err := tx.QueryRow(ctx, `SELECT status,attempt_count::text,next_attempt_at
		FROM plugin_webhook_deliveries
		WHERE tenant_scope_id=$1 AND subscription_id=$2 AND id=$3 FOR UPDATE`,
		tenantScope, subscription, delivery).Scan(&status, &attempts, &nextAttempt); err != nil {
		return "", 0, nil, err
	}
	parsed, err := parseUint(attempts)
	if err != nil {
		return "", 0, nil, err
	}
	return status, parsed, nextAttempt, nil
}

func lockAttempt(ctx context.Context, tx pgx.Tx, claim claimRow) (attemptFence, error) {
	var fence attemptFence
	var attempt, claimSequence, claimedRevision string
	if err := tx.QueryRow(ctx, `SELECT status,attempt_number::text,claim_sequence::text,
		claimed_subscription_revision::text,secret_version_id,claimed_at,started_at,plugin_webhook_recorded_at,
		request_sha256,http_status,failure_code,response_sha256,response_bytes
		FROM plugin_webhook_delivery_attempts
		WHERE tenant_scope_id=$1 AND subscription_id=$2 AND delivery_id=$3 AND claim_token=$4
		FOR UPDATE`, claim.tenantScope, claim.subscription, claim.delivery, claim.token).Scan(
		&fence.status, &attempt, &claimSequence, &claimedRevision, &fence.secretVersion,
		&fence.claimedAt, &fence.startedAt, &fence.recordedAt, &fence.requestDigest,
		&fence.httpStatus, &fence.failureCode, &fence.responseDigest, &fence.responseBytes); err != nil {
		return attemptFence{}, err
	}
	var err error
	fence.attempt, err = parseUint(attempt)
	if err != nil {
		return attemptFence{}, err
	}
	fence.claimSequence, err = parseUint(claimSequence)
	if err != nil {
		return attemptFence{}, err
	}
	fence.claimedRevision, err = parseUint(claimedRevision)
	if err != nil {
		return attemptFence{}, err
	}
	return fence, nil
}

func claimStartAllowed(ctx context.Context, tx pgx.Tx, claim *claimRow, subscriptionFence subscriptionFence) (bool, error) {
	if subscriptionFence.status != "active" {
		return false, nil
	}
	if subscriptionFence.revision == claim.claimedRevision && subscriptionFence.activeSecret == claim.secretVersion {
		return true, nil
	}
	if subscriptionFence.revision <= claim.claimedRevision {
		return false, nil
	}
	nextSequence := subscriptionFence.lifecycle + 1
	tag, err := tx.Exec(ctx, `UPDATE plugin_webhook_delivery_attempts
		SET claim_sequence=$1,claimed_subscription_revision=$2,secret_version_id=$3
		WHERE tenant_scope_id=$4 AND subscription_id=$5 AND delivery_id=$6 AND claim_token=$7
		  AND attempt_number=$8 AND claim_sequence=$9 AND claimed_subscription_revision=$10
		  AND secret_version_id=$11 AND status='claimed'`,
		nextSequence, subscriptionFence.revision, subscriptionFence.activeSecret,
		claim.tenantScope, claim.subscription, claim.delivery, claim.token, claim.attempt,
		claim.claimSequence, claim.claimedRevision, claim.secretVersion)
	if err != nil {
		return false, err
	}
	if tag.RowsAffected() != 1 {
		return false, errAttemptState
	}
	claim.claimSequence = nextSequence
	claim.claimedRevision = subscriptionFence.revision
	claim.secretVersion = subscriptionFence.activeSecret
	return true, nil
}

func parseUint(value string) (uint64, error) {
	parsed, err := strconv.ParseUint(value, 10, 64)
	if err != nil {
		return 0, fmt.Errorf("parse plugin webhook numeric fence: %w", err)
	}
	return parsed, nil
}

func (runtime *Runtime) claim(ctx context.Context, item deliveryRow) (claimRow, error) {
	if item.status != "queued" && item.status != "retry_scheduled" {
		return claimRow{}, errNotClaimable
	}
	if item.status == "retry_scheduled" && item.nextAttemptAt == nil {
		return claimRow{}, errNotDue
	}
	if item.attempts >= 5 {
		return claimRow{}, errNotClaimable
	}
	token := uuid.New()
	claim := claimRow{tenantScope: item.tenantScope, subscription: item.subscription, delivery: item.delivery, token: token, attempt: item.attempts + 1}
	tx, err := runtime.pool.Begin(ctx)
	if err != nil {
		return claimRow{}, err
	}
	defer tx.Rollback(ctx)
	subscriptionFence, err := lockSubscription(ctx, tx, item.tenantScope, item.subscription)
	if err != nil {
		return claimRow{}, err
	}
	if subscriptionFence.status != "active" {
		return claimRow{}, errNotClaimable
	}
	deliveryStatus, deliveryAttempts, nextAttempt, err := lockDelivery(ctx, tx, item.tenantScope, item.subscription, item.delivery)
	if err != nil {
		return claimRow{}, err
	}
	if deliveryStatus == "claimed" && deliveryAttempts == item.attempts+1 {
		var recovered claimRow
		var attemptText, claimSequenceText, revisionText string
		var status string
		err = tx.QueryRow(ctx, `SELECT claim_token,attempt_number::text,claim_sequence::text,
			claimed_subscription_revision::text,secret_version_id,status
			FROM plugin_webhook_delivery_attempts
			WHERE tenant_scope_id=$1 AND subscription_id=$2 AND delivery_id=$3 AND attempt_number=$4
			FOR UPDATE`, item.tenantScope, item.subscription, item.delivery, deliveryAttempts).Scan(
			&recovered.token, &attemptText, &claimSequenceText, &revisionText, &recovered.secretVersion, &status)
		if err != nil {
			return claimRow{}, err
		}
		if status != "claimed" && status != "started" {
			return claimRow{}, errNotClaimable
		}
		recovered.tenantScope, recovered.subscription, recovered.delivery = item.tenantScope, item.subscription, item.delivery
		recovered.attempt, err = parseUint(attemptText)
		if err != nil {
			return claimRow{}, err
		}
		recovered.claimSequence, err = parseUint(claimSequenceText)
		if err != nil {
			return claimRow{}, err
		}
		recovered.claimedRevision, err = parseUint(revisionText)
		if err != nil {
			return claimRow{}, err
		}
		if err = tx.Commit(ctx); err != nil {
			return claimRow{}, err
		}
		return recovered, nil
	}
	if subscriptionFence.revision != item.revision || subscriptionFence.activeSecret != item.secretVersion {
		return claimRow{}, errNotClaimable
	}
	var databaseNow time.Time
	if err := tx.QueryRow(ctx, `SELECT clock_timestamp()`).Scan(&databaseNow); err != nil {
		return claimRow{}, err
	}
	if deliveryStatus != item.status || deliveryAttempts != item.attempts ||
		(deliveryStatus == "retry_scheduled" && (nextAttempt == nil || databaseNow.Before(*nextAttempt))) {
		if deliveryStatus == "retry_scheduled" && nextAttempt != nil && databaseNow.Before(*nextAttempt) {
			return claimRow{}, errNotDue
		}
		return claimRow{}, errNotClaimable
	}
	if _, err := tx.Exec(ctx, `SELECT 1 FROM plugin_webhook_outbox
		WHERE tenant_scope_id=$1 AND subscription_id=$2 AND delivery_id=$3 FOR UPDATE`,
		item.tenantScope, item.subscription, item.delivery); err != nil {
		return claimRow{}, err
	}
	_, err = tx.Exec(ctx, `INSERT INTO plugin_webhook_delivery_attempts(
		 tenant_scope_id,subscription_id,delivery_id,actor_scope_id,actor_user_id,
		 attempt_number,claim_token,claim_sequence,claimed_subscription_revision,
		 secret_version_id,status,claimed_at
	 ) VALUES($1,$2,$3,$4,$5,$6,$7,$8,$9,$10,'claimed',clock_timestamp())`,
		item.tenantScope, item.subscription, item.delivery, item.actorScope, item.actorUser,
		claim.attempt, token, item.lifecycle+1, item.revision, item.secretVersion)
	if err != nil {
		return claimRow{}, err
	}
	if err := tx.Commit(ctx); err != nil {
		return claimRow{}, err
	}
	claim.claimSequence = subscriptionFence.lifecycle + 1
	claim.claimedRevision = subscriptionFence.revision
	claim.secretVersion = subscriptionFence.activeSecret
	return claim, nil
}

func (runtime *Runtime) start(ctx context.Context, claim *claimRow, digest []byte) ([]byte, error) {
	if claim == nil {
		return nil, errAttemptState
	}
	startClaim := *claim
	tx, err := runtime.pool.Begin(ctx)
	if err != nil {
		return nil, err
	}
	defer tx.Rollback(ctx)
	subscriptionFence, err := lockSubscription(ctx, tx, startClaim.tenantScope, startClaim.subscription)
	if err != nil {
		return nil, err
	}
	deliveryStatus, deliveryAttempts, _, err := lockDelivery(ctx, tx, startClaim.tenantScope, startClaim.subscription, startClaim.delivery)
	if err != nil {
		return nil, err
	}
	if deliveryStatus != "claimed" || deliveryAttempts != startClaim.attempt {
		return nil, errAttemptState
	}
	attempt, err := lockAttempt(ctx, tx, startClaim)
	if err != nil {
		return nil, err
	}
	if attempt.attempt != startClaim.attempt ||
		attempt.claimSequence != startClaim.claimSequence || attempt.claimedRevision != startClaim.claimedRevision ||
		attempt.secretVersion != startClaim.secretVersion {
		return nil, errAttemptState
	}
	if attempt.status == "started" {
		if !bytes.Equal(attempt.requestDigest, digest) {
			return nil, errAttemptState
		}
		secret, secretErr := runtime.secrets.SecretTx(ctx, tx, startClaim.tenantScope, startClaim.subscription, startClaim.secretVersion)
		if secretErr != nil {
			clearSecret(secret)
			return nil, secretErr
		}
		if commitErr := tx.Commit(ctx); commitErr != nil {
			clearSecret(secret)
			return nil, commitErr
		}
		*claim = startClaim
		return secret, nil
	}
	if attempt.status != "claimed" {
		return nil, errAttemptState
	}
	allowed, err := claimStartAllowed(ctx, tx, &startClaim, subscriptionFence)
	if err != nil {
		return nil, err
	}
	if !allowed {
		return nil, errAttemptState
	}
	secret, err := runtime.secrets.SecretTx(ctx, tx, startClaim.tenantScope, startClaim.subscription, startClaim.secretVersion)
	if err != nil {
		clearSecret(secret)
		return nil, err
	}
	committed := false
	defer func() {
		if !committed {
			clearSecret(secret)
		}
	}()
	tag, err := tx.Exec(ctx, `UPDATE plugin_webhook_delivery_attempts
		SET status='started',request_sha256=$1
		WHERE tenant_scope_id=$2 AND subscription_id=$3 AND delivery_id=$4 AND claim_token=$5
		  AND attempt_number=$6 AND claim_sequence=$7 AND claimed_subscription_revision=$8
		  AND secret_version_id=$9 AND status='claimed'`,
		digest, startClaim.tenantScope, startClaim.subscription, startClaim.delivery, startClaim.token,
		startClaim.attempt, startClaim.claimSequence, startClaim.claimedRevision, startClaim.secretVersion)
	if err != nil {
		return nil, err
	}
	if tag.RowsAffected() != 1 {
		return nil, errAttemptState
	}
	if err := tx.Commit(ctx); err != nil {
		return nil, err
	}
	committed = true
	*claim = startClaim
	return secret, nil
}

func (runtime *Runtime) finish(ctx context.Context, claim claimRow, result pluginwebhook.SendResult) error {
	status := "permanent_failure"
	if result.Success {
		status = "succeeded"
	} else if result.Retryable {
		status = "temporary_failure"
	}
	if result.Success && (result.StatusCode < 200 || result.StatusCode > 299) {
		status = "permanent_failure"
		result.Code = "sender_contract_invalid"
	}
	code := result.Code
	if !stableCodePattern.MatchString(code) {
		code = "sender_contract_invalid"
	}
	responseDigest := []byte(nil)
	if result.ResponseSHA256 != "" {
		var digestErr error
		responseDigest, digestErr = hex.DecodeString(result.ResponseSHA256)
		if digestErr != nil || len(responseDigest) != sha256.Size {
			return fmt.Errorf("invalid plugin webhook response sha256")
		}
	}
	if result.ResponseBytes < 0 {
		result.ResponseBytes = 0
	}
	if result.ResponseBytes > 65536 {
		result.ResponseBytes = 65536
	}
	preview := []byte(result.ResponsePreview)
	if len(preview) > 2048 {
		preview = preview[:2048]
	}
	if preview == nil {
		preview = []byte{}
	}
	headerJSON, err := json.Marshal(result.ResponseHeaders)
	if err != nil || string(headerJSON) == "null" {
		headerJSON = []byte(`{}`)
	}
	var retryAfter any
	if status == "temporary_failure" && result.RetryAfter > 0 {
		seconds := int(result.RetryAfter / time.Second)
		if seconds > 300 {
			seconds = 300
		}
		retryAfter = seconds
	}
	tx, err := runtime.pool.Begin(ctx)
	if err != nil {
		return err
	}
	defer tx.Rollback(ctx)
	subscriptionFence, err := lockSubscription(ctx, tx, claim.tenantScope, claim.subscription)
	if err != nil {
		return err
	}
	if _, _, _, err := lockDelivery(ctx, tx, claim.tenantScope, claim.subscription, claim.delivery); err != nil {
		return err
	}
	attempt, err := lockAttempt(ctx, tx, claim)
	if err != nil {
		return err
	}
	if attempt.attempt != claim.attempt ||
		attempt.claimSequence != claim.claimSequence || attempt.claimedRevision != claim.claimedRevision ||
		attempt.secretVersion != claim.secretVersion {
		return errAttemptState
	}
	if attempt.status != "started" {
		if !completedAttemptMatches(attempt, status, result.StatusCode, code, responseDigest, result.ResponseBytes) {
			return errAttemptState
		}
		return tx.Commit(ctx)
	}
	if attempt.startedAt == nil {
		return errAttemptState
	}
	var recordedAt *time.Time
	if err := tx.QueryRow(ctx, `UPDATE plugin_webhook_delivery_attempts
		SET status=$2,http_status=NULLIF($3,0),failure_code=CASE WHEN $2 IN ('temporary_failure','permanent_failure') THEN $4 ELSE NULL END,
		    retry_after_seconds=$5,response_sha256=$6,response_bytes=$7,response_preview=$8,sanitized_headers=$9::jsonb
		WHERE tenant_scope_id=$10 AND subscription_id=$11 AND delivery_id=$12 AND claim_token=$1
		  AND attempt_number=$13 AND claim_sequence=$14 AND claimed_subscription_revision=$15
		  AND secret_version_id=$16 AND status='started'
		RETURNING plugin_webhook_recorded_at`,
		claim.token, status, result.StatusCode, code, retryAfter, responseDigest, result.ResponseBytes, preview,
		headerJSON, claim.tenantScope, claim.subscription, claim.delivery, claim.attempt,
		claim.claimSequence, claim.claimedRevision, claim.secretVersion).Scan(&recordedAt); err != nil {
		if errors.Is(err, pgx.ErrNoRows) {
			return errAttemptState
		}
		return err
	}
	if recordedAt == nil || recordedAt.Before(*attempt.startedAt) {
		return errAttemptState
	}
	var deliveryStatus string
	if err := tx.QueryRow(ctx, `SELECT status FROM plugin_webhook_deliveries
		WHERE tenant_scope_id=$1 AND subscription_id=$2 AND id=$3`,
		claim.tenantScope, claim.subscription, claim.delivery).Scan(&deliveryStatus); err != nil {
		return err
	}
	if (status == "permanent_failure" || (status == "temporary_failure" && claim.attempt == 5)) &&
		subscriptionFence.status != "revoked" && deliveryStatus == "dead_letter_pending" {
		deadLetterID := uuid.NewSHA1(uuid.NameSpaceOID, []byte(
			claim.tenantScope.String()+":"+claim.subscription.String()+":"+claim.delivery.String()+":"+strconv.FormatUint(claim.attempt, 10)))
		if _, err := tx.Exec(ctx, `INSERT INTO plugin_webhook_dead_letters(
			id,tenant_scope_id,subscription_id,delivery_id,event_id,final_attempt_number,
			actor_scope_id,actor_user_id,nats_stream,nats_subject,nats_message_id,payload_sha256,
			publish_state,reason_code,http_status,request_sha256,response_sha256,response_bytes,failed_at
		) SELECT $3,attempt.tenant_scope_id,attempt.subscription_id,attempt.delivery_id,
			delivery.event_id,attempt.attempt_number,delivery.actor_scope_id,delivery.actor_user_id,
			'PLUGIN_WEBHOOK_DLQ',$1,'plugin-webhook-dlq-v1-' || encode(sha256(convert_to(
			 attempt.delivery_id::text || ':' || attempt.attempt_number::text,'UTF8')),'hex'),
			plugin_webhook_dead_letter_payload_sha256_084(attempt.tenant_scope_id,attempt.subscription_id,
			 attempt.delivery_id,delivery.event_id,attempt.attempt_number,attempt.failure_code,attempt.http_status,
			 attempt.request_sha256,attempt.response_sha256,attempt.response_bytes),'pending',attempt.failure_code,
			 attempt.http_status,attempt.request_sha256,attempt.response_sha256,attempt.response_bytes,attempt.completed_at
		 FROM plugin_webhook_delivery_attempts attempt JOIN plugin_webhook_deliveries delivery
		 ON delivery.tenant_scope_id=attempt.tenant_scope_id AND delivery.subscription_id=attempt.subscription_id
		 AND delivery.id=attempt.delivery_id WHERE attempt.tenant_scope_id=$4
		   AND attempt.subscription_id=$5 AND attempt.delivery_id=$6 AND attempt.claim_token=$2
		   AND attempt.attempt_number=$7 AND delivery.status='dead_letter_pending'
		 ON CONFLICT (tenant_scope_id,subscription_id,delivery_id) DO NOTHING`,
			runtime.config.JetStream.DeadLetterSubject, claim.token, deadLetterID,
			claim.tenantScope, claim.subscription, claim.delivery, claim.attempt); err != nil {
			return err
		}
	}
	return tx.Commit(ctx)
}

func completedAttemptMatches(attempt attemptFence, status string, statusCode int, code string,
	responseDigest []byte, responseBytes int) bool {
	if attempt.status != status || attempt.responseBytes == nil || *attempt.responseBytes != responseBytes ||
		!bytes.Equal(attempt.responseDigest, responseDigest) {
		return false
	}
	if statusCode == 0 {
		if attempt.httpStatus != nil {
			return false
		}
	} else if attempt.httpStatus == nil || *attempt.httpStatus != statusCode {
		return false
	}
	if status == "succeeded" {
		return attempt.failureCode == nil
	}
	return attempt.failureCode != nil && *attempt.failureCode == code
}

func (runtime *Runtime) retryDelay(ctx context.Context, tenantScope, subscription, delivery uuid.UUID) (time.Duration, error) {
	var next *time.Time
	var databaseNow time.Time
	if err := runtime.pool.QueryRow(ctx, `SELECT next_attempt_at,clock_timestamp() FROM plugin_webhook_deliveries
		WHERE tenant_scope_id=$1 AND subscription_id=$2 AND id=$3`, tenantScope, subscription, delivery).Scan(&next, &databaseNow); err != nil {
		return 0, err
	}
	return retryDelayFromDatabaseClock(next, databaseNow)
}

func retryDelayFromDatabaseClock(next *time.Time, databaseNow time.Time) (time.Duration, error) {
	if next == nil {
		return 0, errNotDue
	}
	delay := next.UTC().Sub(databaseNow.UTC())
	if delay <= 0 {
		return time.Millisecond, nil
	}
	return delay, nil
}

func (runtime *Runtime) reconcile(ctx context.Context) error {
	if err := runtime.reconcileClaims(ctx); err != nil {
		return err
	}
	if err := runtime.recoverDeliveryStream(ctx); err != nil {
		return err
	}
	return runtime.reconcileDeadLetters(ctx)
}

func (runtime *Runtime) reconcileClaims(ctx context.Context) error {
	rows, err := runtime.pool.Query(ctx, `SELECT tenant_scope_id,subscription_id,delivery_id,claim_token,
		attempt_number::text,claim_sequence::text,claimed_subscription_revision::text,secret_version_id
		FROM plugin_webhook_delivery_attempts
		WHERE status IN ('claimed','started') AND claimed_at < clock_timestamp()-$1::interval
		ORDER BY claimed_at LIMIT 32`, claimInterval(runtime.config.ClaimTimeout))
	if err != nil {
		return err
	}
	defer rows.Close()
	for rows.Next() {
		var tenantScope, subscription, delivery, token, secretVersion uuid.UUID
		var attemptText, claimSequenceText, claimedRevisionText string
		if err := rows.Scan(&tenantScope, &subscription, &delivery, &token, &attemptText,
			&claimSequenceText, &claimedRevisionText, &secretVersion); err != nil {
			return err
		}
		attempt, err := parseUint(attemptText)
		if err != nil {
			return err
		}
		claimSequence, err := parseUint(claimSequenceText)
		if err != nil {
			return err
		}
		claimedRevision, err := parseUint(claimedRevisionText)
		if err != nil {
			return err
		}
		if err := runtime.recoverClaim(ctx, claimRow{tenantScope: tenantScope, subscription: subscription,
			delivery: delivery, token: token, secretVersion: secretVersion, attempt: attempt,
			claimSequence: claimSequence, claimedRevision: claimedRevision}); err != nil {
			runtime.config.Logger.Warn("plugin webhook stale claim recovery failed", "delivery_id", delivery, "error", err)
		}
	}
	return rows.Err()
}

func (runtime *Runtime) recoverClaim(ctx context.Context, claim claimRow) error {
	var digest []byte
	var status string
	if err := runtime.pool.QueryRow(ctx, `SELECT attempt.status,event.body_sha256 FROM plugin_webhook_delivery_attempts attempt
		JOIN plugin_webhook_events event ON event.tenant_scope_id=attempt.tenant_scope_id
		 AND event.subscription_id=attempt.subscription_id
		JOIN plugin_webhook_deliveries delivery ON delivery.tenant_scope_id=attempt.tenant_scope_id
		 AND delivery.subscription_id=attempt.subscription_id AND delivery.id=attempt.delivery_id
		 AND delivery.event_id=event.id
		WHERE attempt.tenant_scope_id=$1 AND attempt.subscription_id=$2 AND attempt.delivery_id=$3 AND attempt.claim_token=$4`,
		claim.tenantScope, claim.subscription, claim.delivery, claim.token).Scan(&status, &digest); err != nil {
		return err
	}
	if status == "claimed" {
		secret, err := runtime.start(ctx, &claim, digest)
		if err != nil {
			return err
		}
		clearSecret(secret)
	} else if status != "started" {
		return nil
	}
	if err := runtime.finish(ctx, claim, pluginwebhook.SendResult{Retryable: true, Code: "worker_crash_recovered", StatusCode: http.StatusServiceUnavailable}); err != nil {
		return err
	}
	return nil
}

type deadLetterRow struct {
	tenantScope, subscription, delivery          uuid.UUID
	id, generation                               uuid.UUID
	messageID, reasonCode, subject, stream       string
	payloadDigest, requestDigest, responseDigest []byte
	eventID                                      uuid.UUID
	attempt                                      uint64
	statusCode                                   *int
	responseBytes                                int
	publishState, phase                          string
	epoch, terminalEpoch                         *int64
	high, boundary, cursor, sequence             *uint64
	ackID                                        *string
}

const deadLetterSelect = `SELECT tenant_scope_id,subscription_id,delivery_id,event_id,
	final_attempt_number::text,nats_message_id,nats_subject,payload_sha256,reason_code,http_status,
	request_sha256,response_sha256,response_bytes,nats_stream,publish_state,reconcile_phase,
	reconcile_stream_created_unix_nano::text,reconcile_high_watermark::text,reconcile_scan_boundary::text,
	reconcile_cursor::text,nats_dlq_stream_created_unix_nano::text,nats_dlq_sequence::text,nats_ack_id,
	id,reconcile_generation
	FROM plugin_webhook_dead_letters`

type rowScanner interface {
	Scan(...any) error
}

func scanDeadLetter(scanner rowScanner) (deadLetterRow, error) {
	var row deadLetterRow
	var attempt string
	var epoch, high, boundary, cursor, terminalEpoch, sequence *string
	if err := scanner.Scan(&row.tenantScope, &row.subscription, &row.delivery, &row.eventID, &attempt,
		&row.messageID, &row.subject, &row.payloadDigest, &row.reasonCode, &row.statusCode,
		&row.requestDigest, &row.responseDigest, &row.responseBytes, &row.stream, &row.publishState, &row.phase,
		&epoch, &high, &boundary, &cursor, &terminalEpoch, &sequence, &row.ackID, &row.id, &row.generation); err != nil {
		return deadLetterRow{}, err
	}
	parsedAttempt, err := parseUint(attempt)
	if err != nil {
		return deadLetterRow{}, err
	}
	row.attempt = parsedAttempt
	if epoch != nil {
		value, parseErr := strconv.ParseInt(*epoch, 10, 64)
		if parseErr != nil || value <= 0 {
			return deadLetterRow{}, errDeadLetterState
		}
		row.epoch = &value
	}
	parseOptional := func(raw *string) (*uint64, error) {
		if raw == nil {
			return nil, nil
		}
		value, parseErr := strconv.ParseUint(*raw, 10, 64)
		if parseErr != nil {
			return nil, parseErr
		}
		return &value, nil
	}
	if row.high, err = parseOptional(high); err != nil {
		return deadLetterRow{}, err
	}
	if row.boundary, err = parseOptional(boundary); err != nil {
		return deadLetterRow{}, err
	}
	if row.cursor, err = parseOptional(cursor); err != nil {
		return deadLetterRow{}, err
	}
	if terminalEpoch != nil {
		value, parseErr := strconv.ParseInt(*terminalEpoch, 10, 64)
		if parseErr != nil || value <= 0 {
			return deadLetterRow{}, errDeadLetterState
		}
		row.terminalEpoch = &value
	}
	if row.sequence, err = parseOptional(sequence); err != nil {
		return deadLetterRow{}, err
	}
	return row, nil
}

func (runtime *Runtime) reconcileDeadLetters(ctx context.Context) error {
	rows, err := runtime.pool.Query(ctx, `SELECT tenant_scope_id,subscription_id,delivery_id FROM plugin_webhook_dead_letters
		WHERE publish_state='pending' ORDER BY failed_at LIMIT 32`)
	if err != nil {
		return err
	}
	defer rows.Close()
	type identity struct{ tenantScope, subscription, delivery uuid.UUID }
	pending := make([]identity, 0, 32)
	for rows.Next() {
		var row identity
		if err := rows.Scan(&row.tenantScope, &row.subscription, &row.delivery); err != nil {
			return err
		}
		pending = append(pending, row)
	}
	if err := rows.Err(); err != nil {
		return err
	}
	rows.Close()
	var firstRecoveryErr error
	for _, identity := range pending {
		row, loadErr := runtime.loadDeadLetter(ctx, identity.tenantScope, identity.subscription, identity.delivery)
		if loadErr != nil {
			runtime.config.Logger.Warn("plugin webhook DLQ load failed", "delivery_id", identity.delivery, "error", loadErr)
			if firstRecoveryErr == nil {
				firstRecoveryErr = loadErr
			}
			continue
		}
		if err := runtime.recoverDeadLetter(ctx, row); err != nil && !errors.Is(err, errDeadLetterScanPending) {
			runtime.config.Logger.Warn("plugin webhook DLQ publish failed", "delivery_id", identity.delivery, "error", err)
			if firstRecoveryErr == nil {
				firstRecoveryErr = err
			}
		}
	}
	return firstRecoveryErr
}

func (runtime *Runtime) publishPendingDeadLetter(ctx context.Context, tenantScope, subscription, delivery uuid.UUID, recover bool) error {
	row, err := runtime.loadDeadLetter(ctx, tenantScope, subscription, delivery)
	if errors.Is(err, pgx.ErrNoRows) {
		var status string
		if statusErr := runtime.pool.QueryRow(ctx, `SELECT status FROM plugin_webhook_deliveries
			WHERE tenant_scope_id=$1 AND subscription_id=$2 AND id=$3`, tenantScope, subscription, delivery).
			Scan(&status); statusErr == nil && (status == "revoked" || status == "dead_lettered" || status == "delivered") {
			return nil
		}
		return errDeadLetterState
	}
	if err != nil {
		return err
	}
	if row.publishState == "acknowledged" {
		return nil
	}
	if recover {
		return runtime.recoverDeadLetter(ctx, row)
	}
	return runtime.publishDeadLetter(ctx, row)
}

func (runtime *Runtime) loadDeadLetter(ctx context.Context, tenantScope, subscription, delivery uuid.UUID) (deadLetterRow, error) {
	return scanDeadLetter(runtime.pool.QueryRow(ctx, deadLetterSelect+`
		WHERE tenant_scope_id=$1 AND subscription_id=$2 AND delivery_id=$3`, tenantScope, subscription, delivery))
}

type deadLetterPayload struct {
	Schema         string `json:"schema"`
	DeliveryID     string `json:"delivery_id"`
	EventID        string `json:"event_id"`
	Attempt        uint64 `json:"attempt"`
	ReasonCode     string `json:"reason_code"`
	StatusCode     *int   `json:"status_code"`
	RequestSHA256  string `json:"request_sha256"`
	ResponseSHA256 string `json:"response_sha256"`
	ResponseBytes  int    `json:"response_bytes"`
}

func (runtime *Runtime) publishDeadLetter(ctx context.Context, row deadLetterRow) error {
	return runtime.reconcileDeadLetter(ctx, row)
}

func (runtime *Runtime) recoverDeadLetter(ctx context.Context, row deadLetterRow) error {
	return runtime.reconcileDeadLetter(ctx, row)
}

func deadLetterMessage(row deadLetterRow, stream string) (*nats.Msg, error) {
	payload := deadLetterPayload{Schema: "cdnca.plugin-webhook.dead-letter/v1", DeliveryID: row.delivery.String(),
		EventID: row.eventID.String(), Attempt: row.attempt, ReasonCode: row.reasonCode,
		StatusCode: row.statusCode, RequestSHA256: hex.EncodeToString(row.requestDigest),
		ResponseSHA256: hex.EncodeToString(row.responseDigest), ResponseBytes: row.responseBytes}
	body, err := json.Marshal(payload)
	if err != nil {
		return nil, err
	}
	message := nats.NewMsg(row.subject)
	message.Data = body
	message.Header.Set(nats.MsgIdHdr, row.messageID)
	wireDigest := sha256.Sum256(body)
	message.Header.Set("X-CDNCA-Webhook-DLQ-Payload-Sha256", hex.EncodeToString(wireDigest[:]))
	message.Header.Set(nats.ExpectedStreamHdr, stream)
	return message, nil
}

type deadLetterStreamState struct {
	epoch                 int64
	messages, first, last uint64
}

func (runtime *Runtime) deadLetterStreamSnapshot(ctx context.Context) (deadLetterStreamState, error) {
	operationCtx, cancel := context.WithTimeout(ctx, runtime.config.OperationTimeout)
	info, err := runtime.jetstream.StreamInfo(runtime.config.JetStream.DeadLetterStream, nats.Context(operationCtx))
	cancel()
	if err != nil {
		return deadLetterStreamState{}, fmt.Errorf("inspect plugin webhook DLQ stream: %w", err)
	}
	epoch := info.Created.UTC().UnixNano()
	if epoch <= 0 {
		return deadLetterStreamState{}, fmt.Errorf("plugin webhook DLQ stream epoch is invalid")
	}
	return deadLetterStreamState{epoch: epoch, messages: info.State.Msgs, first: info.State.FirstSeq,
		last: info.State.LastSeq}, nil
}

func storedDeadLetterMessageMatches(stored *nats.RawStreamMsg, expected *nats.Msg) bool {
	if stored == nil || expected == nil || stored.Sequence == 0 || stored.Subject != expected.Subject ||
		!bytes.Equal(stored.Data, expected.Data) || expected.Header.Get(nats.ExpectedLastSeqHdr) != "" ||
		len(expected.Header) != 3 || len(stored.Header) != 4 {
		return false
	}
	for _, name := range []string{nats.MsgIdHdr, nats.ExpectedStreamHdr, "X-CDNCA-Webhook-DLQ-Payload-Sha256"} {
		if !sameStrings(stored.Header.Values(name), expected.Header.Values(name)) || len(stored.Header.Values(name)) != 1 {
			return false
		}
	}
	digest := stored.Header.Get("X-CDNCA-Webhook-DLQ-Payload-Sha256")
	decodedDigest, digestErr := hex.DecodeString(digest)
	if digestErr != nil || len(decodedDigest) != sha256.Size || digest != strings.ToLower(digest) {
		return false
	}
	values := stored.Header.Values(nats.ExpectedLastSeqHdr)
	if len(values) != 1 {
		return false
	}
	previous, err := strconv.ParseUint(values[0], 10, 64)
	return err == nil && previous < ^uint64(0) && stored.Sequence == previous+1
}

func (runtime *Runtime) reconcileDeadLetter(ctx context.Context, expected deadLetterRow) error {
	for transition := 0; transition < 4; transition++ {
		row, err := runtime.loadDeadLetter(ctx, expected.tenantScope, expected.subscription, expected.delivery)
		if err != nil {
			return err
		}
		if !sameDeadLetterIdentity(row, expected) || row.stream != runtime.config.JetStream.DeadLetterStream {
			return errDeadLetterState
		}
		if row.publishState == "acknowledged" {
			if row.phase != "complete" || row.epoch != nil || row.high != nil || row.boundary != nil ||
				row.cursor != nil || row.terminalEpoch == nil || row.sequence == nil || row.ackID == nil {
				return errDeadLetterState
			}
			return nil
		}
		message, err := deadLetterMessage(row, runtime.config.JetStream.DeadLetterStream)
		if err != nil {
			return err
		}
		stream, err := runtime.deadLetterStreamSnapshot(ctx)
		if err != nil {
			return err
		}
		if row.epoch == nil || *row.epoch != stream.epoch {
			if err := runtime.resetDeadLetterProgress(ctx, row, stream); err != nil {
				return err
			}
			continue
		}
		switch row.phase {
		case "reverse_scan", "forward_scan":
			done, continueNow, scanErr := runtime.scanDeadLetterStream(ctx, row, message, stream)
			if scanErr != nil {
				return scanErr
			}
			if done {
				return nil
			}
			if continueNow {
				continue
			}
			return errDeadLetterScanPending
		case "publish_ready":
			publishErr := runtime.publishDeadLetterAtHighWatermark(ctx, row, message)
			if errors.Is(publishErr, errDeadLetterScanPending) {
				continue
			}
			return publishErr
		default:
			return errDeadLetterState
		}
	}
	return errDeadLetterScanPending
}

func (runtime *Runtime) resetDeadLetterProgress(ctx context.Context, row deadLetterRow, stream deadLetterStreamState) error {
	phase := "publish_ready"
	high := stream.last
	var boundary, cursor *uint64
	if stream.messages == 0 {
		initiallyEmpty := stream.first == 0 && stream.last == 0
		retainedEmpty := stream.last > 0 && stream.last < ^uint64(0) && stream.first == stream.last+1
		if !initiallyEmpty && !retainedEmpty {
			return errDeadLetterState
		}
		if stream.last > 0 {
			phase = "reverse_scan"
			boundaryValue, cursorValue := stream.last, stream.last
			boundary, cursor = &boundaryValue, &cursorValue
		}
	} else {
		if stream.first == 0 || stream.first > stream.last {
			return errDeadLetterState
		}
		phase, high = "reverse_scan", stream.last
		boundaryValue, cursorValue := stream.first, stream.last
		boundary, cursor = &boundaryValue, &cursorValue
	}
	err := runtime.updateDeadLetterProgress(ctx, row, phase, stream.epoch, high, boundary, cursor)
	if errors.Is(err, errDeadLetterComplete) {
		return nil
	}
	return err
}

func (runtime *Runtime) scanDeadLetterStream(ctx context.Context, row deadLetterRow, expected *nats.Msg,
	stream deadLetterStreamState) (bool, bool, error) {
	if row.epoch == nil || row.high == nil || row.boundary == nil || row.cursor == nil || *row.epoch != stream.epoch ||
		*row.boundary > *row.cursor || *row.cursor > *row.high ||
		(row.phase != "reverse_scan" && row.phase != "forward_scan") {
		return false, false, errDeadLetterState
	}
	operationCtx, cancel := context.WithTimeout(ctx, runtime.config.OperationTimeout)
	defer cancel()
	sequence := *row.cursor
	if row.phase == "reverse_scan" {
		for inspected := 0; inspected < deadLetterScanBatch; inspected++ {
			stored, err := runtime.jetstream.GetMsg(runtime.config.JetStream.DeadLetterStream, sequence,
				nats.Context(operationCtx))
			if err != nil && !errors.Is(err, nats.ErrMsgNotFound) {
				return false, false, fmt.Errorf("inspect plugin webhook DLQ reverse message: %w", err)
			}
			if err == nil && stored.Header.Get(nats.MsgIdHdr) == expected.Header.Get(nats.MsgIdHdr) {
				if !storedDeadLetterMessageMatches(stored, expected) {
					return false, false, fmt.Errorf("plugin webhook stored DLQ identity does not match")
				}
				if sequence != *row.cursor {
					value := sequence
					if err := runtime.updateDeadLetterProgress(ctx, row, row.phase, *row.epoch, *row.high,
						row.boundary, &value); err != nil {
						if errors.Is(err, errDeadLetterComplete) {
							return true, false, nil
						}
						return false, false, err
					}
					row.cursor = &value
				}
				currentStream, snapshotErr := runtime.deadLetterStreamSnapshot(ctx)
				if snapshotErr != nil || currentStream.epoch != *row.epoch {
					if snapshotErr != nil {
						return false, false, snapshotErr
					}
					return false, false, errDeadLetterScanPending
				}
				if err := runtime.acknowledgeDeadLetter(ctx, row, currentStream.epoch, sequence); err != nil {
					return false, false, err
				}
				return true, false, nil
			}
			if sequence == *row.boundary {
				if sequence != *row.cursor {
					value := sequence
					if err := runtime.updateDeadLetterProgress(ctx, row, row.phase, *row.epoch, *row.high,
						row.boundary, &value); err != nil {
						return errors.Is(err, errDeadLetterComplete), false, normalizeDeadLetterProgressError(err)
					}
					row.cursor = &value
				}
				err := runtime.updateDeadLetterProgress(ctx, row, "publish_ready", *row.epoch, *row.high, nil, nil)
				return errors.Is(err, errDeadLetterComplete), err == nil, normalizeDeadLetterProgressError(err)
			}
			sequence--
		}
		value := sequence
		err := runtime.updateDeadLetterProgress(ctx, row, row.phase, *row.epoch, *row.high, row.boundary, &value)
		if errors.Is(err, errDeadLetterComplete) {
			return true, false, nil
		}
		return false, false, err
	}

	for inspected := 0; inspected < deadLetterScanBatch; inspected++ {
		stored, err := runtime.jetstream.GetMsg(runtime.config.JetStream.DeadLetterStream, sequence,
			nats.Context(operationCtx))
		if err != nil && !errors.Is(err, nats.ErrMsgNotFound) {
			return false, false, fmt.Errorf("inspect plugin webhook DLQ forward message: %w", err)
		}
		if err == nil && stored.Header.Get(nats.MsgIdHdr) == expected.Header.Get(nats.MsgIdHdr) {
			if !storedDeadLetterMessageMatches(stored, expected) {
				return false, false, fmt.Errorf("plugin webhook stored DLQ identity does not match")
			}
			if sequence != *row.cursor {
				value := sequence
				if err := runtime.updateDeadLetterProgress(ctx, row, row.phase, *row.epoch, *row.high,
					row.boundary, &value); err != nil {
					if errors.Is(err, errDeadLetterComplete) {
						return true, false, nil
					}
					return false, false, err
				}
				row.cursor = &value
			}
			currentStream, snapshotErr := runtime.deadLetterStreamSnapshot(ctx)
			if snapshotErr != nil || currentStream.epoch != *row.epoch {
				if snapshotErr != nil {
					return false, false, snapshotErr
				}
				return false, false, errDeadLetterScanPending
			}
			if err := runtime.acknowledgeDeadLetter(ctx, row, currentStream.epoch, sequence); err != nil {
				return false, false, err
			}
			return true, false, nil
		}
		if sequence == *row.high {
			if sequence != *row.cursor {
				value := sequence
				if err := runtime.updateDeadLetterProgress(ctx, row, row.phase, *row.epoch, *row.high,
					row.boundary, &value); err != nil {
					return errors.Is(err, errDeadLetterComplete), false, normalizeDeadLetterProgressError(err)
				}
				row.cursor = &value
			}
			err := runtime.updateDeadLetterProgress(ctx, row, "publish_ready", *row.epoch, *row.high, nil, nil)
			return errors.Is(err, errDeadLetterComplete), err == nil, normalizeDeadLetterProgressError(err)
		}
		sequence++
	}
	value := sequence
	err := runtime.updateDeadLetterProgress(ctx, row, row.phase, *row.epoch, *row.high, row.boundary, &value)
	if errors.Is(err, errDeadLetterComplete) {
		return true, false, nil
	}
	return false, false, err
}

func normalizeDeadLetterProgressError(err error) error {
	if errors.Is(err, errDeadLetterComplete) {
		return nil
	}
	return err
}

func (runtime *Runtime) publishDeadLetterAtHighWatermark(ctx context.Context, row deadLetterRow, expected *nats.Msg) error {
	if row.epoch == nil || row.high == nil || row.phase != "publish_ready" || *row.high == ^uint64(0) {
		return errDeadLetterState
	}
	wire := &nats.Msg{Subject: expected.Subject, Data: append([]byte(nil), expected.Data...), Header: make(nats.Header, len(expected.Header)+1)}
	for name, values := range expected.Header {
		wire.Header[name] = append([]string(nil), values...)
	}
	wire.Header.Set(nats.ExpectedLastSeqHdr, strconv.FormatUint(*row.high, 10))
	operationCtx, cancel := context.WithTimeout(ctx, runtime.config.OperationTimeout)
	ack, publishErr := runtime.jetstream.PublishMsg(wire, nats.Context(operationCtx),
		nats.ExpectStream(runtime.config.JetStream.DeadLetterStream), nats.ExpectLastSequence(*row.high))
	cancel()
	if publishErr == nil {
		if ack == nil || ack.Stream != runtime.config.JetStream.DeadLetterStream || ack.Sequence != *row.high+1 {
			return fmt.Errorf("plugin webhook DLQ publish acknowledgement is invalid")
		}
		operationCtx, cancel = context.WithTimeout(ctx, runtime.config.OperationTimeout)
		stored, err := runtime.jetstream.GetMsg(runtime.config.JetStream.DeadLetterStream, ack.Sequence,
			nats.Context(operationCtx))
		cancel()
		if err != nil {
			return fmt.Errorf("read plugin webhook acknowledged DLQ publication: %w", err)
		}
		if !storedDeadLetterMessageMatches(stored, expected) {
			return fmt.Errorf("plugin webhook acknowledged DLQ publication wire does not match")
		}
		currentStream, err := runtime.deadLetterStreamSnapshot(ctx)
		if err != nil {
			return err
		}
		if currentStream.epoch != *row.epoch {
			return errDeadLetterScanPending
		}
		return runtime.acknowledgeDeadLetter(ctx, row, currentStream.epoch, ack.Sequence)
	}
	stream, inspectErr := runtime.deadLetterStreamSnapshot(ctx)
	if inspectErr != nil {
		return publishErr
	}
	if stream.epoch != *row.epoch {
		if err := runtime.resetDeadLetterProgress(ctx, row, stream); err != nil {
			return err
		}
		return errDeadLetterScanPending
	}
	if stream.last <= *row.high {
		return publishErr
	}
	cursor := *row.high + 1
	boundary := cursor
	if err := runtime.updateDeadLetterProgress(ctx, row, "forward_scan", *row.epoch, stream.last, &boundary, &cursor); err != nil {
		if errors.Is(err, errDeadLetterComplete) {
			return nil
		}
		return err
	}
	return errDeadLetterScanPending
}

func (runtime *Runtime) updateDeadLetterProgress(ctx context.Context, expected deadLetterRow, phase string,
	epoch int64, high uint64, boundary, cursor *uint64) error {
	tx, err := runtime.pool.Begin(ctx)
	if err != nil {
		return err
	}
	defer tx.Rollback(ctx)
	// Same lock order as transition_plugin_webhook_dead_letter_reconcile_084.
	if _, err := tx.Exec(ctx, `SELECT 1 FROM plugin_webhook_deliveries
			WHERE tenant_scope_id=$1 AND subscription_id=$2 AND id=$3 FOR SHARE`,
		expected.tenantScope, expected.subscription, expected.delivery); err != nil {
		return err
	}
	actual, err := scanDeadLetter(tx.QueryRow(ctx, deadLetterSelect+`
		WHERE tenant_scope_id=$1 AND subscription_id=$2 AND delivery_id=$3 FOR UPDATE`,
		expected.tenantScope, expected.subscription, expected.delivery))
	if err != nil {
		return err
	}
	if !sameDeadLetterIdentity(actual, expected) || actual.stream != runtime.config.JetStream.DeadLetterStream {
		return errDeadLetterState
	}
	if actual.publishState == "acknowledged" {
		return errDeadLetterComplete
	}
	if !sameDeadLetterProgress(actual, expected) {
		return errDeadLetterScanPending
	}
	optional := func(value *uint64) any {
		if value == nil {
			return nil
		}
		return strconv.FormatUint(*value, 10)
	}
	var currentEpoch any
	if actual.epoch != nil {
		currentEpoch = strconv.FormatInt(*actual.epoch, 10)
	}
	// 084 rotates the reconcile generation exactly when the stream epoch
	// changes and keeps it otherwise.
	generation := actual.generation
	if actual.epoch == nil || *actual.epoch != epoch {
		generation = uuid.New()
	}
	if _, err := tx.Exec(ctx, `SELECT transition_plugin_webhook_dead_letter_reconcile_084(
			$1,$2,$3,$4,$5,$6::numeric,$7::numeric,$8::numeric,$9::numeric,
			$10,$11,$12::numeric,$13::numeric,$14::numeric,$15::numeric)`,
		expected.tenantScope, expected.subscription, expected.delivery, actual.generation, actual.phase,
		currentEpoch, optional(actual.high), optional(actual.boundary), optional(actual.cursor),
		generation, phase, strconv.FormatInt(epoch, 10), strconv.FormatUint(high, 10),
		optional(boundary), optional(cursor)); err != nil {
		return err
	}
	return tx.Commit(ctx)
}

func sameDeadLetterProgress(left, right deadLetterRow) bool {
	return left.publishState == right.publishState && left.phase == right.phase &&
		sameInt64Pointer(left.epoch, right.epoch) && sameUint64Pointer(left.high, right.high) &&
		sameUint64Pointer(left.boundary, right.boundary) && sameUint64Pointer(left.cursor, right.cursor) &&
		sameInt64Pointer(left.terminalEpoch, right.terminalEpoch) && sameUint64Pointer(left.sequence, right.sequence) &&
		sameStringPointer(left.ackID, right.ackID)
}

func sameInt64Pointer(left, right *int64) bool {
	return left == nil && right == nil || left != nil && right != nil && *left == *right
}

func sameUint64Pointer(left, right *uint64) bool {
	return left == nil && right == nil || left != nil && right != nil && *left == *right
}

func sameStringPointer(left, right *string) bool {
	return left == nil && right == nil || left != nil && right != nil && *left == *right
}

func (runtime *Runtime) acknowledgeDeadLetter(ctx context.Context, expected deadLetterRow, epoch int64, sequence uint64) error {
	if epoch <= 0 || sequence == 0 {
		return errDeadLetterState
	}
	if err := runtime.prepareAttestation(ctx); err != nil {
		return err
	}
	tx, err := runtime.pool.Begin(ctx)
	if err != nil {
		return err
	}
	defer tx.Rollback(ctx)
	head, err := runtime.lockAttestationHead(ctx, tx)
	if err != nil {
		return err
	}
	// Same lock order as acknowledge_plugin_webhook_dead_letter_084.
	if _, err := tx.Exec(ctx, `SELECT 1 FROM plugin_webhook_subscriptions WHERE tenant_scope_id=$1 AND id=$2 FOR SHARE`,
		expected.tenantScope, expected.subscription); err != nil {
		return err
	}
	if _, err := tx.Exec(ctx, `SELECT 1 FROM plugin_webhook_deliveries
			WHERE tenant_scope_id=$1 AND subscription_id=$2 AND id=$3 FOR UPDATE`,
		expected.tenantScope, expected.subscription, expected.delivery); err != nil {
		return err
	}
	actual, err := scanDeadLetter(tx.QueryRow(ctx, deadLetterSelect+`
		WHERE tenant_scope_id=$1 AND subscription_id=$2 AND delivery_id=$3 FOR UPDATE`,
		expected.tenantScope, expected.subscription, expected.delivery))
	if err != nil {
		return err
	}
	if actual.stream != runtime.config.JetStream.DeadLetterStream || !sameDeadLetterIdentity(actual, expected) {
		return errDeadLetterState
	}
	expectedAckID := actual.stream + ":" + strconv.FormatUint(sequence, 10)
	if actual.publishState == "acknowledged" {
		if actual.terminalEpoch == nil || *actual.terminalEpoch != epoch || actual.sequence == nil || actual.ackID == nil ||
			*actual.ackID != expectedAckID || *actual.sequence != sequence {
			return errDeadLetterState
		}
		return tx.Commit(ctx)
	}
	if actual.publishState != "pending" || actual.terminalEpoch != nil || actual.sequence != nil || actual.ackID != nil ||
		actual.epoch == nil || *actual.epoch != epoch || actual.high == nil || !sameDeadLetterProgress(actual, expected) {
		return errDeadLetterState
	}
	if actual.phase == "publish_ready" && (sequence <= *actual.high || *actual.high == ^uint64(0)) {
		return errDeadLetterState
	}
	if (actual.phase == "reverse_scan" || actual.phase == "forward_scan") &&
		(actual.cursor == nil || sequence != *actual.cursor) {
		return errDeadLetterState
	}
	message, err := deadLetterMessage(actual, actual.stream)
	if err != nil {
		return err
	}
	wireDigest := sha256.Sum256(message.Data)
	signature := runtime.deadLetterAttestation(head, actual, epoch, sequence, wireDigest[:])
	optional := func(value *uint64) any {
		if value == nil {
			return nil
		}
		return strconv.FormatUint(*value, 10)
	}
	// 084 records the acknowledgement (and projects the delivery to
	// dead_lettered) only after verifying the exact wire hit and signature.
	if _, err := tx.Exec(ctx, `SELECT acknowledge_plugin_webhook_dead_letter_084(
			$1,$2,$3,$4,$5,$6::numeric,$7::numeric,$8::numeric,$9::numeric,
			$10,$11,$6::numeric,$12,$13::numeric,$14,$15,$16,$17::numeric,$18::numeric,$19,$20)`,
		actual.tenantScope, actual.subscription, actual.delivery, actual.generation, actual.phase,
		strconv.FormatInt(epoch, 10), optional(actual.high), optional(actual.boundary), optional(actual.cursor),
		head.natsDomain, actual.stream, actual.subject, strconv.FormatUint(sequence, 10), actual.messageID,
		actual.payloadDigest, wireDigest[:], strconv.FormatUint(sequence-1, 10),
		strconv.FormatUint(head.generation, 10), head.keyID, signature); err != nil {
		return err
	}
	return tx.Commit(ctx)
}

func sameDeadLetterIdentity(left, right deadLetterRow) bool {
	return left.tenantScope == right.tenantScope && left.subscription == right.subscription &&
		left.delivery == right.delivery && left.eventID == right.eventID && left.attempt == right.attempt &&
		left.messageID == right.messageID && left.subject == right.subject && left.stream == right.stream &&
		left.reasonCode == right.reasonCode &&
		bytes.Equal(left.payloadDigest, right.payloadDigest) && bytes.Equal(left.requestDigest, right.requestDigest) &&
		bytes.Equal(left.responseDigest, right.responseDigest) && left.responseBytes == right.responseBytes &&
		((left.statusCode == nil && right.statusCode == nil) ||
			(left.statusCode != nil && right.statusCode != nil && *left.statusCode == *right.statusCode))
}

func validResult(result pluginwebhook.SendResult) bool {
	return stableCodePattern.MatchString(result.Code) && result.StatusCode >= 0 && result.StatusCode <= 599 &&
		result.RequestBytes >= 0 && result.ResponseBytes >= 0 && result.ResponseBytes <= 65536 &&
		len(result.ResponsePreview) <= 2048 && result.RetryAfter >= 0 && validOptionalSHA256(result.ResponseSHA256) &&
		((result.Success && !result.Retryable && result.StatusCode >= 200 && result.StatusCode <= 299) ||
			(!result.Success && (result.StatusCode == 0 || result.StatusCode < 200 || result.StatusCode > 299)))
}

func validOptionalSHA256(value string) bool {
	if value == "" {
		return true
	}
	decoded, err := hex.DecodeString(value)
	return err == nil && len(decoded) == sha256.Size
}

func claimInterval(duration time.Duration) string { return duration.String() }
func leaseInterval(duration time.Duration) string { return duration.String() }

func clearSecret(secret []byte) {
	for index := range secret {
		secret[index] = 0
	}
}

var (
	errNoOutbox              = errors.New("no plugin webhook outbox row available")
	errNoStaleDelivery       = errors.New("no stale plugin webhook delivery stream row available")
	errNotClaimable          = errors.New("plugin webhook delivery is not claimable")
	errNotDue                = errors.New("plugin webhook retry is not due")
	errAttemptState          = errors.New("plugin webhook attempt state changed")
	errDeadLetterState       = errors.New("plugin webhook dead letter state changed")
	errDeadLetterScanPending = errors.New("plugin webhook dead letter scan has more messages")
	errDeadLetterComplete    = errors.New("plugin webhook dead letter already acknowledged")
)
