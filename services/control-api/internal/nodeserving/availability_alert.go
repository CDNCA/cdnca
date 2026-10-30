package nodeserving

import (
	"context"
	"errors"
	"fmt"
	"log/slog"
	"strconv"
	"strings"
	"time"

	"github.com/cdnca/cdnca/services/control-api/internal/notification"
	"github.com/google/uuid"
	"github.com/jackc/pgx/v5"
)

// Node availability alerts (FX33): a node going offline/recovering is
// announced to the platform members who manage nodes, whatever the monitor
// failure action (pause or none). Detection reuses DecideMonitor's thresholds;
// state lives in node_availability_alert_states, not in the serving hold.
// Delivery switches, repeat count and interval come from notification_event_policies.
const (
	EventTypeNodeOffline   = notification.EventTypeNodeOffline
	EventTypeNodeRecovered = notification.EventTypeNodeRecovered

	alertRecipientPermission = "nodes.manage"
	alertTemplateVersion     = 1
)

// AlertEnqueuer is notification.Store.
type AlertEnqueuer interface {
	EnqueueTx(context.Context, pgx.Tx, notification.EnqueueRequest) (notification.EnqueueResult, error)
}

// EnableAvailabilityAlerts makes ApplyAlert enqueue node offline/recovered
// alerts in the transition transaction. Call before the worker starts.
func (store *Store) EnableAvailabilityAlerts(enqueuer AlertEnqueuer) {
	store.alerts = enqueuer
}

// DecideAlert decides the offline alert as if the failure action were pause,
// so detection and recovery thresholds match the serving hold exactly.
func DecideAlert(input MonitorInput, alert AlertState) Decision {
	input.Held, input.Reason, input.RecentHealthy = alert.Offline, alert.Reason, alert.RecentHealthy
	input.Effective.MonitorAction = "pause"
	// Offline alerts stay on the local probe; dnspup has its own alert
	// (node.dnspup.unreachable).
	input.DNSPup = nil
	return DecideMonitor(input)
}

// ApplyAlert records one alert transition with revision CAS and, for a real
// offline or probe recovery, enqueues the alert in the same transaction.
// Releases for other reasons (monitor disabled, node inactive) only reset the
// state: the node did not come back, someone stopped watching it.
func (store *Store) ApplyAlert(ctx context.Context, nodeID, scopeID uuid.UUID, expectedRevision int64, decision Decision) (bool, error) {
	if store == nil || ctx == nil || nodeID == uuid.Nil || scopeID == uuid.Nil || decision.Reason == "" {
		return false, ErrInvalidInput
	}
	changed := false
	err := pgx.BeginTxFunc(ctx, store.pool, pgx.TxOptions{}, func(tx pgx.Tx) error {
		var now time.Time
		if err := tx.QueryRow(ctx, `SELECT clock_timestamp()`).Scan(&now); err != nil {
			return err
		}
		var offline bool
		var revision int64
		err := tx.QueryRow(ctx, `SELECT offline,revision FROM node_availability_alert_states
			WHERE node_id=$1 FOR UPDATE`, nodeID).Scan(&offline, &revision)
		found := err == nil
		if err != nil && !errors.Is(err, pgx.ErrNoRows) {
			return err
		}
		if revision != expectedRevision || offline == decision.Held {
			return nil
		}
		var since any
		if decision.Held {
			since = now
		}
		next := revision + 1
		if found {
			_, err = tx.Exec(ctx, `UPDATE node_availability_alert_states SET offline=$2,reason_code=$3,revision=$4,
				offline_since=$5,changed_at=$6 WHERE node_id=$1`, nodeID, decision.Held, decision.Reason, next, since, now)
		} else {
			_, err = tx.Exec(ctx, `INSERT INTO node_availability_alert_states(node_id,offline,reason_code,revision,offline_since,changed_at)
				VALUES($1,$2,$3,1,$4,$5)`, nodeID, decision.Held, decision.Reason, since, now)
		}
		if err != nil {
			return err
		}
		changed = true
		if decision.Held || decision.Reason == ReasonProbeRecovered {
			if err := store.enqueueAvailabilityAlert(ctx, tx, nodeID, scopeID, decision.Held, decision.Reason, next, now); err != nil {
				slog.Warn("node availability alert not enqueued", "node_id", nodeID, "error", err)
			}
		}
		return nil
	})
	return changed, err
}

// enqueueAvailabilityAlert runs inside ApplyAlert's transaction under a
// savepoint: a notification failure is logged but never blocks the state.
func (store *Store) enqueueAvailabilityAlert(ctx context.Context, tx pgx.Tx, nodeID, scopeID uuid.UUID,
	held bool, reason string, revision int64, now time.Time) error {
	if store.alerts == nil {
		return nil
	}
	savepoint, err := tx.Begin(ctx)
	if err != nil {
		return err
	}
	defer func() { _ = savepoint.Rollback(context.Background()) }()
	if err := store.enqueueAvailabilityAlertTx(ctx, savepoint, nodeID, scopeID, held, reason, revision, now); err != nil {
		return err
	}
	return savepoint.Commit(ctx)
}

func (store *Store) enqueueAvailabilityAlertTx(ctx context.Context, tx pgx.Tx, nodeID, scopeID uuid.UUID,
	held bool, reason string, revision int64, now time.Time) error {
	eventType := EventTypeNodeRecovered
	if held {
		eventType = EventTypeNodeOffline
	}
	name, address, platform, err := readAlertedNode(ctx, tx, nodeID, scopeID)
	if err != nil || !platform {
		// Tenant-owned (marketplace seller) nodes are not alerted yet.
		return err
	}
	recipients, err := readNodeAlertRecipients(ctx, tx, scopeID)
	if err != nil {
		return err
	}
	sourceEventID := "node-availability/" + nodeID.String() + "/" + strconv.FormatInt(revision, 10)
	values := notification.TemplateContext{
		"node_name":   notification.PublicValue(name),
		"node_ip":     notification.PublicValue(address),
		"reason":      notification.PublicValue(reason),
		"occurred_at": notification.PublicValue(now.UTC().Format(time.RFC3339)),
	}
	return enqueueNodeAlert(ctx, store.alerts, tx, scopeID, recipients, eventType, sourceEventID, values)
}

// AvailabilityAlertReplayGuard keeps a scheduled repeat of a node alert only
// while the alert revision that produced it is still the node's current one.
func AvailabilityAlertReplayGuard(ctx context.Context, tx pgx.Tx, candidate notification.ReplayCandidate) (bool, error) {
	rest, found := strings.CutPrefix(candidate.SourceEventID, "node-availability/")
	nodeText, revisionText, split := strings.Cut(rest, "/")
	if !found || !split {
		return false, nil
	}
	nodeID, err := uuid.Parse(nodeText)
	if err != nil {
		return false, nil
	}
	revision, err := strconv.ParseInt(revisionText, 10, 64)
	if err != nil {
		return false, nil
	}
	var current int64
	err = tx.QueryRow(ctx, `SELECT revision FROM node_availability_alert_states WHERE node_id=$1`, nodeID).Scan(&current)
	if errors.Is(err, pgx.ErrNoRows) {
		return false, nil
	}
	if err != nil {
		return false, fmt.Errorf("read node availability alert: %w", err)
	}
	return current == revision, nil
}

// RegisterAvailabilityAlertReplayGuards installs the guards for the node
// offline/recovered and bandwidth exceeded/recovered events.
func RegisterAvailabilityAlertReplayGuards(store *notification.Store) error {
	for eventType, guard := range map[string]notification.ReplayGuard{
		EventTypeNodeOffline: AvailabilityAlertReplayGuard, EventTypeNodeRecovered: AvailabilityAlertReplayGuard,
		EventTypeNodeBandwidthExceeded: BandwidthAlertReplayGuard, EventTypeNodeBandwidthRecovered: BandwidthAlertReplayGuard,
	} {
		if err := store.RegisterReplayGuard(eventType, guard); err != nil {
			return fmt.Errorf("register node alert replay guard %s: %w", eventType, err)
		}
	}
	return nil
}
