// Package ccautoswitch turns node-reported CC auto switch engagements (FX65)
// into site owner notifications. Every node serving a site reports its own
// engagement; the site is notified once per Window.
package ccautoswitch

import (
	"context"
	"errors"
	"fmt"
	"log/slog"
	"strconv"
	"sync/atomic"
	"time"

	"github.com/cdnca/cdnca/services/control-api/internal/nodemetrics"
	"github.com/cdnca/cdnca/services/control-api/internal/notification"
	"github.com/google/uuid"
	"github.com/jackc/pgx/v5"
	"github.com/jackc/pgx/v5/pgxpool"
)

const (
	EventType  = "package.monitor.cc_rule_auto_switch"
	TemplateID = EventType + ".zh-cn"
	// Window is the per-site deduplication window: engagements of the same
	// site (any node) within Window of the window's first one are one notice.
	Window = 5 * time.Minute
	// MaxAge drops engagements delivered long after they happened (a node
	// that was cut off from the gateway): the attack is over by then.
	MaxAge = time.Hour
	// MaxSkew tolerates node clocks slightly ahead of the database.
	MaxSkew = time.Minute
)

// Enqueuer is notification.Store.
type Enqueuer interface {
	EnqueueTx(context.Context, pgx.Tx, notification.EnqueueRequest) (notification.EnqueueResult, error)
}

// Stats counts outcomes since start. Rejected are engagements whose site is
// not in the reported tenant scope or whose node does not carry that scope.
type Stats struct {
	Notified, Deduplicated, Rejected, Stale, Undeliverable uint64
}

type Recorder struct {
	pool     *pgxpool.Pool
	enqueuer Enqueuer

	notified, deduplicated, rejected, stale, undeliverable atomic.Uint64
}

func NewRecorder(pool *pgxpool.Pool, enqueuer Enqueuer) (*Recorder, error) {
	if pool == nil || enqueuer == nil {
		return nil, nodemetrics.ErrInvalidConfiguration
	}
	return &Recorder{pool: pool, enqueuer: enqueuer}, nil
}

func (recorder *Recorder) Stats() Stats {
	return Stats{Notified: recorder.notified.Load(), Deduplicated: recorder.deduplicated.Load(),
		Rejected: recorder.rejected.Load(), Stale: recorder.stale.Load(), Undeliverable: recorder.undeliverable.Load()}
}

type outcome uint8

const (
	outcomeNotified outcome = iota + 1
	outcomeDeduplicated
	outcomeRejected
	outcomeStale
	outcomeUndeliverable
)

// RecordCCAutoSwitch checks ownership, deduplicates and enqueues in one
// transaction. Dropped engagements are acknowledged (nil error) and counted;
// only database failures are returned, and the delivery is retried.
func (recorder *Recorder) RecordCCAutoSwitch(ctx context.Context, sample nodemetrics.Sample) error {
	event := sample.CCAutoSwitch
	if recorder == nil || ctx == nil || sample.Kind != nodemetrics.RecordCCAutoSwitch || event == nil ||
		event.NodeID != sample.NodeID || !canonical(event.NodeID) || !canonical(event.TenantScopeID) ||
		!canonical(event.SiteID) || !canonical(sample.EventID) || event.EngagedAt.IsZero() {
		return nodemetrics.ErrInvalidSample
	}
	var result outcome
	err := pgx.BeginFunc(ctx, recorder.pool, func(tx pgx.Tx) error {
		var err error
		result, err = recorder.record(ctx, tx, sample.EventID, *event)
		return err
	})
	if err != nil {
		return fmt.Errorf("record CC auto switch: %w", err)
	}
	switch result {
	case outcomeNotified:
		recorder.notified.Add(1)
	case outcomeDeduplicated:
		recorder.deduplicated.Add(1)
	case outcomeRejected:
		recorder.rejected.Add(1)
		slog.Warn("CC auto switch engagement rejected: site not in reported scope or node not serving it",
			"node_id", event.NodeID, "tenant_scope_id", event.TenantScopeID, "site_id", event.SiteID)
	case outcomeStale:
		recorder.stale.Add(1)
	case outcomeUndeliverable:
		recorder.undeliverable.Add(1)
	}
	return nil
}

func (recorder *Recorder) record(ctx context.Context, tx pgx.Tx, eventID string, event nodemetrics.CCAutoSwitchEvent) (outcome, error) {
	var now time.Time
	if err := tx.QueryRow(ctx, `SELECT clock_timestamp()`).Scan(&now); err != nil {
		return 0, err
	}
	if event.EngagedAt.Before(now.Add(-MaxAge)) || event.EngagedAt.After(now.Add(MaxSkew)) {
		return outcomeStale, nil
	}
	var owner uuid.UUID
	var domain string
	err := tx.QueryRow(ctx, `SELECT site.owner_user_id, site.domain FROM sites site
		WHERE site.id=$1 AND site.scope_id=$2 AND site.deleted_at IS NULL AND EXISTS (
			SELECT 1 FROM node_config_state state WHERE state.node_id=$3 AND state.configuration_scope_id=$2)`,
		event.SiteID, event.TenantScopeID, event.NodeID).Scan(&owner, &domain)
	if errors.Is(err, pgx.ErrNoRows) {
		return outcomeRejected, nil
	}
	if err != nil {
		return 0, err
	}
	// The first engagement of a site opens its window; a racing first one
	// waits on the row lock and falls through to the window check below.
	inserted, err := tx.Exec(ctx, `INSERT INTO cc_auto_switch_notification_windows(
			site_id, sequence, window_started_at, last_engaged_at, first_event_id, first_node_id, updated_at)
		VALUES ($1, 1, $2, $2, $3, $4, $5) ON CONFLICT (site_id) DO NOTHING`,
		event.SiteID, event.EngagedAt, eventID, event.NodeID, now)
	if err != nil {
		return 0, err
	}
	sequence := int64(1)
	if inserted.RowsAffected() == 0 {
		var started time.Time
		if err := tx.QueryRow(ctx, `SELECT sequence, window_started_at
			FROM cc_auto_switch_notification_windows WHERE site_id=$1 FOR UPDATE`, event.SiteID).
			Scan(&sequence, &started); err != nil {
			return 0, err
		}
		if event.EngagedAt.Before(started.Add(Window)) {
			// Another node's engagement within the window, a redelivered
			// one (including the one that opened it), or a late one.
			if !event.EngagedAt.Before(started) {
				_, err = tx.Exec(ctx, `UPDATE cc_auto_switch_notification_windows
					SET last_engaged_at=GREATEST(last_engaged_at, $2), updated_at=$3 WHERE site_id=$1`,
					event.SiteID, event.EngagedAt, now)
			}
			return outcomeDeduplicated, err
		}
		sequence++
		if _, err := tx.Exec(ctx, `UPDATE cc_auto_switch_notification_windows
			SET sequence=$2, window_started_at=$3, last_engaged_at=$3, first_event_id=$4, first_node_id=$5,
				updated_at=$6 WHERE site_id=$1`,
			event.SiteID, sequence, event.EngagedAt, eventID, event.NodeID, now); err != nil {
			return 0, err
		}
	}
	return recorder.notify(ctx, tx, event, owner, domain, sequence)
}

// notify enqueues under a savepoint: a notice that cannot be built (no
// template, owner no longer a member) is logged and counted but still
// consumes the window, so a redelivery does not retry it forever.
func (recorder *Recorder) notify(ctx context.Context, tx pgx.Tx, event nodemetrics.CCAutoSwitchEvent,
	owner uuid.UUID, domain string, sequence int64) (outcome, error) {
	savepoint, err := tx.Begin(ctx)
	if err != nil {
		return 0, err
	}
	defer func() { _ = savepoint.Rollback(context.WithoutCancel(ctx)) }()
	sourceEventID := "cc-auto-switch/" + event.SiteID + "/" + strconv.FormatInt(sequence, 10)
	err = recorder.enqueue(ctx, savepoint, event, owner, domain, sourceEventID)
	if err == nil {
		err = savepoint.Commit(ctx)
	}
	if err != nil {
		slog.Warn("CC auto switch notification not enqueued", "site_id", event.SiteID, "error", err)
		return outcomeUndeliverable, nil
	}
	return outcomeNotified, nil
}

func (recorder *Recorder) enqueue(ctx context.Context, tx pgx.Tx, event nodemetrics.CCAutoSwitchEvent,
	owner uuid.UUID, domain, sourceEventID string) error {
	values := map[string]string{
		"domain":          domain,
		"engaged_at":      shanghai(event.EngagedAt),
		"trigger_qps":     strconv.FormatUint(event.TriggerQPS, 10),
		"trigger_5xx":     strconv.FormatUint(event.Trigger5xx, 10),
		"qps_total":       threshold(event.QPSTotal),
		"qps_5xx":         threshold(event.QPS5xx),
		"recover_minutes": strconv.FormatUint((event.RecoverSeconds+59)/60, 10),
	}
	// The newest version of each channel's template, filled with exactly
	// the variables it declares, so an edited template keeps enqueueing.
	rows, err := tx.Query(ctx, `SELECT DISTINCT ON (channel) channel, version, variables FROM notification_templates
		WHERE template_id=$1 ORDER BY channel, version DESC`, TemplateID)
	if err != nil {
		return err
	}
	templates := map[notification.Channel]notification.TemplateRef{}
	contexts := map[notification.Channel]notification.TemplateContext{}
	for rows.Next() {
		var channel string
		var version int64
		var variables []string
		if err := rows.Scan(&channel, &version, &variables); err != nil {
			rows.Close()
			return err
		}
		ref := notification.TemplateRef{ID: TemplateID, Version: uint64(version), Channel: notification.Channel(channel)}
		context := notification.TemplateContext{}
		for _, name := range variables {
			context[name] = notification.PublicValue(values[name])
		}
		templates[ref.Channel], contexts[ref.Channel] = ref, context
	}
	rows.Close()
	if err := rows.Err(); err != nil {
		return err
	}
	if len(templates) == 0 {
		return errors.New("CC auto switch template is missing")
	}
	siteID := uuid.MustParse(event.SiteID) // canonical() checked on ingest
	_, err = recorder.enqueuer.EnqueueTx(ctx, tx, notification.EnqueueRequest{
		ScopeID: uuid.MustParse(event.TenantScopeID), RecipientID: owner, SourceEventID: sourceEventID,
		EventType: EventType, Policy: notification.DeliveryTenantSubscribed, Templates: templates,
		Contexts: contexts, AuditRequestID: sourceEventID, SubjectSiteID: &siteID,
	})
	return err
}

func threshold(value uint64) string {
	if value == 0 {
		return "-"
	}
	return strconv.FormatUint(value, 10)
}

func shanghai(value time.Time) string {
	location, err := time.LoadLocation("Asia/Shanghai")
	if err != nil {
		location = time.FixedZone("CST", 8*3600)
	}
	return value.In(location).Format("2006-01-02 15:04:05")
}

func canonical(value string) bool {
	parsed, err := uuid.Parse(value)
	return err == nil && parsed != uuid.Nil && parsed.String() == value
}
