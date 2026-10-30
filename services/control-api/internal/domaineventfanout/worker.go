// Package domaineventfanout turns immutable domain event source facts
// (migration 368 outbox) into durable, per-subscription webhook receipts. It
// owns only the source lease and receipt state; delivery publication remains
// pluginwebhook's concern.
package domaineventfanout

import (
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"strconv"
	"strings"
	"time"

	"github.com/cdnca/cdnca/services/control-api/internal/domaineventsource"
	"github.com/cdnca/cdnca/services/control-api/internal/pluginwebhook"
	"github.com/google/uuid"
	"github.com/jackc/pgx/v5"
	"github.com/jackc/pgx/v5/pgxpool"
)

var (
	ErrInvalidConfig     = errors.New("invalid domain event fanout configuration")
	ErrFanoutUnavailable = errors.New("domain event fanout database unavailable")
	errNoSource          = errors.New("no domain event source ready")
)

const (
	defaultLeaseDuration = 2 * time.Minute
	defaultRetryDelay    = time.Minute
	maxReceiptError      = 2048
)

// Runner is intentionally small so pluginwebhookruntime can mount the worker
// optionally without importing or constructing it in existing test paths.
type Runner interface {
	RunOnce(context.Context) error
}

type Config struct {
	Pool          *pgxpool.Pool
	Producer      *pluginwebhook.DomainEventProducer
	WorkerID      string
	LeaseDuration time.Duration
	RetryDelay    time.Duration
}

type Worker struct {
	pool          *pgxpool.Pool
	producer      *pluginwebhook.DomainEventProducer
	workerID      string
	leaseDuration time.Duration
	retryDelay    time.Duration
}

type sourceEvent struct {
	id         uuid.UUID
	tenant     uuid.UUID
	eventType  string
	subject    string
	sequence   uint64
	priorState string
	occurred   time.Time
	payload    []byte
	lease      uuid.UUID
}

type receipt struct {
	subscription uuid.UUID
	status       string
}

func New(config Config) (*Worker, error) {
	if config.Pool == nil || config.Producer == nil {
		return nil, ErrInvalidConfig
	}
	if config.WorkerID == "" {
		config.WorkerID = "domain-event-fanout"
	}
	if config.LeaseDuration == 0 {
		config.LeaseDuration = defaultLeaseDuration
	}
	if config.RetryDelay == 0 {
		config.RetryDelay = defaultRetryDelay
	}
	if config.LeaseDuration <= 0 || config.LeaseDuration > 10*time.Minute ||
		config.RetryDelay <= 0 || config.RetryDelay > 24*time.Hour {
		return nil, ErrInvalidConfig
	}
	return &Worker{pool: config.Pool, producer: config.Producer, workerID: config.WorkerID,
		leaseDuration: config.LeaseDuration, retryDelay: config.RetryDelay}, nil
}

// RunOnce claims at most one source fact. A crash between producer commit and
// receipt settlement is safe: the receipt remains pending and producer replay
// resolves the stable source-event request identity on the next claim.
func (worker *Worker) RunOnce(ctx context.Context) error {
	if worker == nil || worker.pool == nil || worker.producer == nil || ctx == nil {
		return ErrInvalidConfig
	}
	source, err := worker.claim(ctx)
	if errors.Is(err, errNoSource) {
		return nil
	}
	if err != nil {
		return fmt.Errorf("%w: claim source event: %v", ErrFanoutUnavailable, err)
	}
	if err := worker.fanout(ctx, &source); err != nil {
		return err
	}
	return worker.settle(ctx, source)
}

func (worker *Worker) claim(ctx context.Context) (sourceEvent, error) {
	tx, err := worker.pool.Begin(ctx)
	if err != nil {
		return sourceEvent{}, err
	}
	defer tx.Rollback(ctx)

	// A fact is claimable only when no earlier fact of the same subject is
	// still unpublished, so every subscription receives one subject in
	// subject_sequence order even across lease expiry and retries.
	var source sourceEvent
	if err := tx.QueryRow(ctx, `
		SELECT outbox.id,outbox.tenant_scope_id,outbox.event_type,outbox.subject,outbox.subject_sequence,
		       outbox.delivery_state,outbox.occurred_at,outbox.payload::text::bytea
		FROM domain_event_outbox_368 outbox
		WHERE ((outbox.delivery_state IN ('pending','failed') AND outbox.available_at <= clock_timestamp()) OR
		       (outbox.delivery_state='leased' AND outbox.lease_expires_at <= clock_timestamp()))
		  AND NOT EXISTS (
		      SELECT 1 FROM domain_event_outbox_368 earlier
		      WHERE earlier.tenant_scope_id=outbox.tenant_scope_id AND earlier.event_type=outbox.event_type
		        AND earlier.subject=outbox.subject AND earlier.subject_sequence < outbox.subject_sequence
		        AND earlier.delivery_state <> 'published')
		ORDER BY outbox.available_at,outbox.id
		LIMIT 1 FOR UPDATE OF outbox SKIP LOCKED`).Scan(&source.id, &source.tenant, &source.eventType,
		&source.subject, &source.sequence, &source.priorState, &source.occurred, &source.payload); err != nil {
		if errors.Is(err, pgx.ErrNoRows) {
			return sourceEvent{}, errNoSource
		}
		return sourceEvent{}, err
	}
	leaseToken := uuid.New()
	if source.priorState == "leased" {
		if _, err := tx.Exec(ctx, `UPDATE domain_event_outbox_368
			SET delivery_state='failed',lease_token=NULL,lease_expires_at=NULL,last_error='lease_expired'
			WHERE id=$1 AND delivery_state='leased' AND lease_expires_at <= clock_timestamp()`, source.id); err != nil {
			return sourceEvent{}, err
		}
	}
	if _, err := tx.Exec(ctx, `
		UPDATE domain_event_outbox_368
		SET delivery_state='leased',lease_token=$2,lease_expires_at=clock_timestamp()+$3::interval,
		    publish_attempts=publish_attempts+1,last_error=NULL
		WHERE id=$1 AND delivery_state IN ('pending','failed','leased')`,
		source.id, leaseToken, intervalString(worker.leaseDuration)); err != nil {
		return sourceEvent{}, err
	}
	// The INSERT is the transaction snapshot of eligible bindings: an active
	// subscription to the type, created before the fact occurred (no
	// pre-consent history), whose site filter (migration 370) selects the
	// fact's site, and whose installation is enabled and holds the event's
	// permission. It is idempotent so an expired lease never duplicates work.
	if _, err := tx.Exec(ctx, `
		INSERT INTO domain_event_fanout_receipts_368(
			source_id,tenant_scope_id,subscription_id,installation_authorization_id,
			installation_id,plugin_id,created_at)
		SELECT $1,subscription.tenant_scope_id,subscription.id,
		       subscription.installation_authorization_id,subscription.installation_id,
		       subscription.plugin_id,clock_timestamp()
		FROM plugin_webhook_subscriptions subscription
		JOIN plugin_installation_heads installation
		  ON installation.tenant_scope_id=subscription.tenant_scope_id
		 AND installation.authorization_id=subscription.installation_authorization_id
		 AND installation.installation_id=subscription.installation_id
		 AND installation.plugin_id=subscription.plugin_id
		JOIN domain_event_types_368 contract ON contract.event_type=$3
		WHERE subscription.tenant_scope_id=$2 AND subscription.status='active'
		  AND $3 = ANY(subscription.event_types)
		  AND subscription.created_at <= $4
		  AND (subscription.site_ids IS NULL OR
		       (SELECT site_id FROM domain_event_outbox_368 WHERE id=$1) = ANY(subscription.site_ids))
		  AND installation.status='enabled'
		  AND contract.required_permission = ANY(installation.approved_scopes)
		ON CONFLICT (source_id,subscription_id) DO NOTHING`, source.id, source.tenant,
		source.eventType, source.occurred); err != nil {
		return sourceEvent{}, err
	}
	if err := tx.Commit(ctx); err != nil {
		return sourceEvent{}, err
	}
	source.lease = leaseToken
	return source, nil
}

func (worker *Worker) fanout(ctx context.Context, source *sourceEvent) error {
	rows, err := worker.pool.Query(ctx, `
		SELECT subscription_id,status
		FROM domain_event_fanout_receipts_368
		WHERE source_id=$1 ORDER BY subscription_id`, source.id)
	if err != nil {
		return fmt.Errorf("%w: load fanout receipts: %v", ErrFanoutUnavailable, err)
	}
	defer rows.Close()
	var receipts []receipt
	for rows.Next() {
		var item receipt
		if err := rows.Scan(&item.subscription, &item.status); err != nil {
			return fmt.Errorf("%w: scan fanout receipt: %v", ErrFanoutUnavailable, err)
		}
		receipts = append(receipts, item)
	}
	if err := rows.Err(); err != nil {
		return fmt.Errorf("%w: read fanout receipts: %v", ErrFanoutUnavailable, err)
	}
	for _, item := range receipts {
		if item.status != "pending" {
			continue
		}
		if _, err := worker.pool.Exec(ctx, `UPDATE domain_event_fanout_receipts_368
			SET attempts=attempts+1 WHERE source_id=$1 AND subscription_id=$2 AND status='pending'`,
			source.id, item.subscription); err != nil {
			return fmt.Errorf("%w: claim fanout receipt: %v", ErrFanoutUnavailable, err)
		}
		data, err := webhookData(source.payload, item.subscription, source.sequence)
		if err != nil {
			if markErr := worker.markFailed(ctx, *source, item.subscription, err); markErr != nil {
				return markErr
			}
			continue
		}
		result, publishErr := worker.producer.PublishDomainEvent(ctx, pluginwebhook.DomainEventRequest{
			SubscriptionID: item.subscription,
			EventType:      source.eventType,
			Subject:        source.subject,
			RequestID:      source.id.String(),
			OccurredAt:     source.occurred.UTC().Truncate(time.Microsecond),
			Data:           data,
		})
		if publishErr != nil {
			if markErr := worker.markFailed(ctx, *source, item.subscription, publishErr); markErr != nil {
				return markErr
			}
			continue
		}
		if _, err := worker.pool.Exec(ctx, `UPDATE domain_event_fanout_receipts_368
			SET status='published',event_id=$3,delivery_id=$4,completed_at=clock_timestamp(),error=NULL
			WHERE source_id=$1 AND subscription_id=$2 AND status='pending'`,
			source.id, item.subscription, result.EventID, result.DeliveryID); err != nil {
			return fmt.Errorf("%w: settle published fanout receipt: %v", ErrFanoutUnavailable, err)
		}
	}
	return nil
}

func (worker *Worker) markFailed(ctx context.Context, source sourceEvent, subscription uuid.UUID, cause error) error {
	message := sanitizeError(cause)
	if _, err := worker.pool.Exec(ctx, `UPDATE domain_event_fanout_receipts_368
		SET status='failed',error=$3,completed_at=clock_timestamp()
		WHERE source_id=$1 AND subscription_id=$2 AND status='pending'`, source.id, subscription, message); err != nil {
		return fmt.Errorf("%w: settle failed fanout receipt: %v", ErrFanoutUnavailable, err)
	}
	return nil
}

func (worker *Worker) settle(ctx context.Context, source sourceEvent) error {
	var pending int
	if err := worker.pool.QueryRow(ctx, `SELECT count(*) FILTER (WHERE status='pending')
		FROM domain_event_fanout_receipts_368 WHERE source_id=$1`, source.id).Scan(&pending); err != nil {
		return fmt.Errorf("%w: inspect fanout receipt state: %v", ErrFanoutUnavailable, err)
	}
	if pending > 0 {
		return nil
	}
	// Receipt failures are terminal facts. Migration 367 forbids a non-null
	// source last_error on publication, so the receipt error remains the
	// durable per-subscription diagnostic while the source can settle once.
	if _, err := worker.pool.Exec(ctx, `UPDATE domain_event_outbox_368
		SET delivery_state='published',lease_token=NULL,lease_expires_at=NULL,
		    published_at=clock_timestamp(),last_error=NULL
		WHERE id=$1 AND delivery_state='leased' AND lease_token=$2`, source.id, source.lease); err != nil {
		return fmt.Errorf("%w: publish source event: %v", ErrFanoutUnavailable, err)
	}
	return nil
}

// webhookData adds the per-delivery webhook fields to the stored contract
// payload. The payload was validated on append; it is re-checked here so a
// fact never leaves the outbox with fields outside its contract.
func webhookData(payload []byte, subscriptionID uuid.UUID, subjectSequence uint64) ([]byte, error) {
	if subscriptionID == uuid.Nil || subjectSequence == 0 || len(payload) == 0 || !json.Valid(payload) {
		return nil, pluginwebhook.ErrInvalidInput
	}
	var data map[string]json.RawMessage
	if err := json.Unmarshal(payload, &data); err != nil || data == nil {
		return nil, pluginwebhook.ErrInvalidInput
	}
	if _, taken := data[domaineventsource.FieldSubscriptionID]; taken {
		return nil, pluginwebhook.ErrInvalidInput
	}
	if _, taken := data[domaineventsource.FieldSubjectSequence]; taken {
		return nil, pluginwebhook.ErrInvalidInput
	}
	subscription, _ := json.Marshal(subscriptionID.String())
	data[domaineventsource.FieldSubscriptionID] = subscription
	data[domaineventsource.FieldSubjectSequence] = json.RawMessage(strconv.FormatUint(subjectSequence, 10))
	return json.Marshal(data)
}

func sanitizeError(err error) string {
	value := "fanout_failed"
	if err != nil && strings.TrimSpace(err.Error()) != "" {
		value = strings.TrimSpace(err.Error())
	}
	if len(value) > maxReceiptError {
		value = value[:maxReceiptError]
	}
	return value
}

func intervalString(value time.Duration) string {
	return fmt.Sprintf("%d microseconds", value.Microseconds())
}
