package nodeserving

import (
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"log/slog"
	"time"

	"github.com/cdnca/cdnca/services/control-api/internal/notification"
	"github.com/google/uuid"
	"github.com/jackc/pgx/v5"
)

// Node alert intents: an offline/recovered,
// bandwidth exceeded/recovered or backup IP activated/restored transition
// writes the alert it owes into node_alert_intents in the state transaction.
// Enqueueing still runs under a savepoint so a notification failure never
// blocks the protection; a failed enqueue leaves the intent pending and
// AlertIntentEvaluator enqueues it once on a later tick, with the original
// event time marked as a delayed notice.
const (
	alertIntentPending  = "pending"
	alertIntentEnqueued = "enqueued"
	alertIntentExpired  = "expired"

	// alertIntentRetryWindow: an older transition is not announced late.
	alertIntentRetryWindow = 6 * time.Hour
	alertIntentRetryBatch  = 100
	// alertIntentDelayedSuffix marks the original event time of a notice sent
	// after the notification channel recovered.
	alertIntentDelayedSuffix = "（延后通知）"
)

// alertIntent is one owed alert: the event, its stable source event ID and
// the template values captured at transition time.
type alertIntent struct {
	scopeID       uuid.UUID
	eventType     string
	sourceEventID string
	params        map[string]string
	occurredAt    time.Time
}

// values are the template values: a retry keeps the original event time and
// marks it as a delayed notice.
func (intent alertIntent) values(delayed bool) map[string]string {
	values := make(map[string]string, len(intent.params))
	for name, value := range intent.params {
		if delayed && name == "occurred_at" {
			value += alertIntentDelayedSuffix
		}
		values[name] = value
	}
	return values
}

func (intent alertIntent) context(delayed bool) notification.TemplateContext {
	values := make(notification.TemplateContext, len(intent.params))
	for name, value := range intent.values(delayed) {
		values[name] = notification.PublicValue(value)
	}
	return values
}

// raiseAlert runs in the state transaction. build reads what the alert needs
// and reports whether the subject is alerted at all (platform scope only);
// the intent is then written in the same transaction and enqueued under a
// savepoint. Nothing here fails the state transaction: protection is never
// delayed by notification, and an enqueue failure leaves the intent pending
// for AlertIntentEvaluator.
func (store *Store) raiseAlert(ctx context.Context, tx pgx.Tx, build func(pgx.Tx) (alertIntent, bool, error)) {
	if store.alerts == nil {
		return
	}
	var intent alertIntent
	var id uuid.UUID
	recorded, err := func() (bool, error) {
		savepoint, err := tx.Begin(ctx)
		if err != nil {
			return false, err
		}
		defer func() { _ = savepoint.Rollback(context.Background()) }()
		var alerted bool
		if intent, alerted, err = build(savepoint); err != nil || !alerted {
			return false, err
		}
		encoded, err := json.Marshal(intent.params)
		if err != nil {
			return false, fmt.Errorf("encode node alert intent: %w", err)
		}
		if id, err = uuid.NewV7(); err != nil {
			return false, fmt.Errorf("generate node alert intent ID: %w", err)
		}
		tag, err := savepoint.Exec(ctx, `INSERT INTO node_alert_intents(id,scope_id,event_type,source_event_id,params,occurred_at,status)
			VALUES($1,$2,$3,$4,$5::jsonb,$6,'pending') ON CONFLICT (scope_id,event_type,source_event_id) DO NOTHING`,
			id, intent.scopeID, intent.eventType, intent.sourceEventID, string(encoded), intent.occurredAt)
		if err != nil {
			return false, fmt.Errorf("record node alert intent: %w", err)
		}
		// Zero rows: the same transition is already recorded.
		return tag.RowsAffected() == 1, savepoint.Commit(ctx)
	}()
	if err != nil {
		slog.Warn("node alert intent not recorded", "event_type", intent.eventType, "error", err)
		return
	}
	if !recorded {
		return
	}
	if err := store.enqueueIntent(ctx, tx, id, intent, false); err != nil {
		slog.Warn("node alert not enqueued; kept for retry", "event_type", intent.eventType,
			"source_event_id", intent.sourceEventID, "error", err)
	}
}

// enqueueIntent enqueues the alert for the scope's current nodes.manage
// holders under a savepoint and records the attempt on the intent row.
func (store *Store) enqueueIntent(ctx context.Context, tx pgx.Tx, id uuid.UUID, intent alertIntent, delayed bool) error {
	enqueueErr := func() error {
		savepoint, err := tx.Begin(ctx)
		if err != nil {
			return err
		}
		defer func() { _ = savepoint.Rollback(context.Background()) }()
		recipients, err := readNodeAlertRecipients(ctx, savepoint, intent.scopeID)
		if err != nil {
			return err
		}
		if err := enqueueNodeAlert(ctx, store.alerts, savepoint, intent.scopeID, recipients, intent.eventType,
			intent.sourceEventID, intent.context(delayed)); err != nil {
			return err
		}
		return savepoint.Commit(ctx)
	}()
	status := alertIntentPending
	if enqueueErr == nil {
		status = alertIntentEnqueued
	}
	if _, err := tx.Exec(ctx, `UPDATE node_alert_intents SET attempts=attempts+1,status=$2,
		resolved_at=CASE WHEN $2='pending' THEN NULL ELSE clock_timestamp() END WHERE id=$1`, id, status); err != nil {
		return fmt.Errorf("record node alert attempt: %w", err)
	}
	return enqueueErr
}

// alertIntentGuards say whether the transition an intent announces is still
// the subject's current one; a superseded transition is not announced late
// (the later transition carries its own alert).
var alertIntentGuards = map[string]notification.ReplayGuard{
	EventTypeNodeOffline:            AvailabilityAlertReplayGuard,
	EventTypeNodeRecovered:          AvailabilityAlertReplayGuard,
	EventTypeNodeBandwidthExceeded:  BandwidthAlertReplayGuard,
	EventTypeNodeBandwidthRecovered: BandwidthAlertReplayGuard,
	EventTypeLineBackupActivated:    LineBackupReplayGuard,
	EventTypeLineBackupRestored:     LineBackupReplayGuard,
}

// AlertIntentEvaluator enqueues the alerts whose first enqueue failed. It
// runs last in the node serving worker; each intent is retried in its own
// transaction under a row lock, so two replicas never send it twice.
type AlertIntentEvaluator struct {
	store *Store
}

func NewAlertIntentEvaluator(store *Store) *AlertIntentEvaluator {
	return &AlertIntentEvaluator{store: store}
}

func (evaluator *AlertIntentEvaluator) Evaluate(ctx context.Context) error {
	store := evaluator.store
	if store.alerts == nil {
		return nil
	}
	if _, err := store.pool.Exec(ctx, `UPDATE node_alert_intents SET status='expired',resolved_at=clock_timestamp()
		WHERE status='pending' AND occurred_at<clock_timestamp()-$1::interval`,
		fmt.Sprintf("%d seconds", int64(alertIntentRetryWindow/time.Second))); err != nil {
		return fmt.Errorf("expire node alert intents: %w", err)
	}
	rows, err := store.pool.Query(ctx, `SELECT id FROM node_alert_intents WHERE status='pending'
		ORDER BY occurred_at,id LIMIT $1`, alertIntentRetryBatch)
	if err != nil {
		return fmt.Errorf("read pending node alert intents: %w", err)
	}
	ids, err := pgx.CollectRows(rows, pgx.RowTo[uuid.UUID])
	if err != nil {
		return fmt.Errorf("read pending node alert intents: %w", err)
	}
	var first error
	for _, id := range ids {
		if err := store.retryIntent(ctx, id); err != nil && first == nil {
			first = err
		}
	}
	return first
}

func (store *Store) retryIntent(ctx context.Context, id uuid.UUID) error {
	return pgx.BeginTxFunc(ctx, store.pool, pgx.TxOptions{}, func(tx pgx.Tx) error {
		var intent alertIntent
		var encoded []byte
		err := tx.QueryRow(ctx, `SELECT scope_id,event_type,source_event_id,params,occurred_at FROM node_alert_intents
			WHERE id=$1 AND status='pending' FOR UPDATE SKIP LOCKED`, id).Scan(
			&intent.scopeID, &intent.eventType, &intent.sourceEventID, &encoded, &intent.occurredAt)
		if errors.Is(err, pgx.ErrNoRows) {
			return nil // resolved or locked by another replica
		}
		if err != nil {
			return fmt.Errorf("read node alert intent: %w", err)
		}
		if err := json.Unmarshal(encoded, &intent.params); err != nil {
			return fmt.Errorf("decode node alert intent: %w", err)
		}
		guard := alertIntentGuards[intent.eventType]
		current := false
		if guard != nil {
			if current, err = guard(ctx, tx, notification.ReplayCandidate{
				ScopeID: intent.scopeID, EventType: intent.eventType, SourceEventID: intent.sourceEventID,
			}); err != nil {
				return err
			}
		}
		if !current {
			_, err := tx.Exec(ctx, `UPDATE node_alert_intents SET status='expired',resolved_at=clock_timestamp() WHERE id=$1`, id)
			return err
		}
		if err := store.enqueueIntent(ctx, tx, id, intent, true); err != nil {
			slog.Warn("node alert retry not enqueued", "event_type", intent.eventType,
				"source_event_id", intent.sourceEventID, "error", err)
		} else {
			slog.Info("node alert enqueued on retry", "event_type", intent.eventType, "source_event_id", intent.sourceEventID)
		}
		return nil
	})
}
