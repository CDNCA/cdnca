package poolmon

import (
	"context"
	"errors"
	"strconv"
	"strings"
	"time"

	"github.com/cdnca/cdnca/services/control-api/internal/notification"
	"github.com/google/uuid"
	"github.com/jackc/pgx/v5"
)

// Notification events and templates (migration 633).
const (
	EventTypeSaturated = notification.EventTypeControlDBPoolSaturated
	EventTypeRecovered = notification.EventTypeControlDBPoolRecovered
	saturatedTemplate  = "control.db_pool.saturated.zh-cn"
	recoveredTemplate  = "control.db_pool.recovered.zh-cn"
	// sourcePrefix + instance + "/" + since (Unix ms) identifies one alert;
	// the saturation and its recovery share it (different event types).
	sourcePrefix     = "control-db-pool/v1/"
	maxInstanceBytes = 128
	// staleLimit bounds the alerts one restart closes.
	staleLimit = 100
	// lockClass serialises check-then-enqueue of one alert across replicas.
	lockClass = 633
)

// Permissions whose platform holders get the notifications: those who can
// read the maintenance page showing the pool (GET /v1/admin/system-db-pool).
var recipientPermissions = []string{"control.upgrades.read", "platform.admin"}

// Enqueuer is notification.Store's transactional enqueue (it only uses tx).
type Enqueuer interface {
	EnqueueTx(context.Context, pgx.Tx, notification.EnqueueRequest) (notification.EnqueueResult, error)
}

// PGNotifier writes on a connection of its own, dialled per call: when the
// pool is saturated (the very thing being reported) a pool connection would
// wait in the same queue. Writes are rare (alert transitions).
type PGNotifier struct {
	config   *pgx.ConnConfig
	enqueuer Enqueuer
}

// NewPGNotifier dials with config (the pool's ConnConfig: same database,
// role, search_path and session settings).
func NewPGNotifier(config *pgx.ConnConfig, enqueuer Enqueuer) *PGNotifier {
	return &PGNotifier{config: config, enqueuer: enqueuer}
}

// SourceEventID is the merge key of the alert of instance that started at since.
func SourceEventID(instance string, since time.Time) string {
	return sourcePrefix + clipInstance(instance) + "/" + strconv.FormatInt(since.UTC().UnixMilli(), 10)
}

func clipInstance(instance string) string {
	if len(instance) > maxInstanceBytes {
		instance = instance[:maxInstanceBytes]
	}
	return strings.ReplaceAll(instance, "/", "_")
}

func (p *PGNotifier) tx(ctx context.Context, fn func(pgx.Tx) error) error {
	conn, err := pgx.ConnectConfig(ctx, p.config.Copy())
	if err != nil {
		return err
	}
	defer func() {
		closing, cancel := context.WithTimeout(context.WithoutCancel(ctx), time.Second)
		defer cancel()
		_ = conn.Close(closing)
	}()
	return pgx.BeginFunc(ctx, conn, fn)
}

func (p *PGNotifier) Saturated(ctx context.Context, instance string, since time.Time, s Sample) error {
	values := notification.TemplateContext{
		"instance":         notification.PublicValue(clipInstance(instance)),
		"in_use":           notification.PublicValue(strconv.Itoa(int(s.InUse))),
		"max_conns":        notification.PublicValue(strconv.Itoa(int(s.MaxConns))),
		"resident_conns":   notification.PublicValue(strconv.Itoa(int(s.ResidentConns))),
		"request_capacity": notification.PublicValue(strconv.Itoa(int(s.RequestCapacity))),
		"queued":           notification.PublicValue(strconv.FormatInt(s.Queued, 10)),
		"avg_wait_ms":      notification.PublicValue(formatWait(s.AvgWaitMS)),
		"reasons":          notification.PublicValue(strings.Join(s.Reasons, ",")),
		"occurred_at":      notification.PublicValue(s.At.UTC().Format(time.RFC3339)),
	}
	return p.tx(ctx, func(tx pgx.Tx) error {
		return p.enqueue(ctx, tx, EventTypeSaturated, saturatedTemplate, SourceEventID(instance, since), values)
	})
}

func (p *PGNotifier) Recovered(ctx context.Context, instance string, since time.Time, cause string, at time.Time) error {
	return p.tx(ctx, func(tx pgx.Tx) error {
		return p.enqueue(ctx, tx, EventTypeRecovered, recoveredTemplate, SourceEventID(instance, since), recoveredValues(instance, since, cause, at))
	})
}

func recoveredValues(instance string, since time.Time, cause string, at time.Time) notification.TemplateContext {
	return notification.TemplateContext{
		"instance":    notification.PublicValue(clipInstance(instance)),
		"since":       notification.PublicValue(since.UTC().Format(time.RFC3339)),
		"cause":       notification.PublicValue(cause),
		"occurred_at": notification.PublicValue(at.UTC().Format(time.RFC3339)),
	}
}

// CloseStale recovers the alerts of instance whose saturation was sent
// without a recovery: the process that sent them is gone, and the new one
// raises its own alert if the pool is still saturated.
func (p *PGNotifier) CloseStale(ctx context.Context, instance string, at time.Time) error {
	return p.tx(ctx, func(tx pgx.Tx) error {
		platform, err := platformScope(ctx, tx)
		if err != nil || platform == uuid.Nil {
			return err
		}
		rows, err := tx.Query(ctx, `SELECT DISTINCT fired.source_event_id FROM notification_events fired
			WHERE fired.scope_id=$1 AND fired.event_type=$2 AND starts_with(fired.source_event_id, $4)
			  AND NOT EXISTS (SELECT 1 FROM notification_events done WHERE done.scope_id=fired.scope_id
			      AND done.event_type=$3 AND done.source_event_id=fired.source_event_id)
			ORDER BY 1 LIMIT $5`, platform, EventTypeSaturated, EventTypeRecovered, sourcePrefix+clipInstance(instance)+"/", staleLimit)
		if err != nil {
			return err
		}
		sources, err := pgx.CollectRows(rows, pgx.RowTo[string])
		if err != nil {
			return err
		}
		for _, source := range sources {
			ms, err := strconv.ParseInt(source[strings.LastIndexByte(source, '/')+1:], 10, 64)
			if err != nil {
				continue
			}
			values := recoveredValues(instance, time.UnixMilli(ms), CauseInstanceRestarted, at)
			if err := p.enqueue(ctx, tx, EventTypeRecovered, recoveredTemplate, source, values); err != nil {
				return err
			}
		}
		return nil
	})
}

func platformScope(ctx context.Context, tx pgx.Tx) (uuid.UUID, error) {
	var platform uuid.UUID
	err := tx.QueryRow(ctx, `SELECT id FROM access_scopes WHERE kind='platform' AND tenant_id IS NULL ORDER BY id LIMIT 1`).Scan(&platform)
	if errors.Is(err, pgx.ErrNoRows) {
		return uuid.Nil, nil // not bootstrapped: nobody to notify
	}
	return platform, err
}

// enqueue sends eventType once per source to every active platform member
// holding a recipient permission (the SMS template uses part of values).
func (p *PGNotifier) enqueue(ctx context.Context, tx pgx.Tx, eventType, template, source string, values notification.TemplateContext) error {
	platform, err := platformScope(ctx, tx)
	if err != nil || platform == uuid.Nil {
		return err
	}
	if _, err := tx.Exec(ctx, `SELECT pg_advisory_xact_lock(hashtextextended($1, $2))`, eventType+"|"+source, lockClass); err != nil {
		return err
	}
	var sent bool
	if err := tx.QueryRow(ctx, `SELECT EXISTS(SELECT 1 FROM notification_events WHERE scope_id=$1 AND source_event_id=$2 AND event_type=$3)`,
		platform, source, eventType).Scan(&sent); err != nil || sent {
		return err
	}
	rows, err := tx.Query(ctx, `SELECT DISTINCT membership.user_id FROM memberships membership
		JOIN users member ON member.id=membership.user_id AND member.status='active'
		JOIN role_assignments assignment ON assignment.scope_id=membership.scope_id AND assignment.user_id=membership.user_id
		JOIN role_permissions grant_row ON grant_row.role_id=assignment.role_id AND grant_row.permission_name=ANY($2::text[])
		WHERE membership.scope_id=$1 AND membership.status='active' ORDER BY membership.user_id`, platform, recipientPermissions)
	if err != nil {
		return err
	}
	recipients, err := pgx.CollectRows(rows, pgx.RowTo[uuid.UUID])
	if err != nil {
		return err
	}
	templates := map[notification.Channel]notification.TemplateRef{
		notification.ChannelSMS:   {ID: template, Version: 1, Channel: notification.ChannelSMS},
		notification.ChannelEmail: {ID: template, Version: 1, Channel: notification.ChannelEmail},
	}
	contexts := map[notification.Channel]notification.TemplateContext{notification.ChannelSMS: values, notification.ChannelEmail: values}
	for _, recipient := range recipients {
		if _, err := p.enqueuer.EnqueueTx(ctx, tx, notification.EnqueueRequest{ScopeID: platform, RecipientID: recipient,
			SourceEventID: source, EventType: eventType, Policy: notification.DeliverySystemRequired,
			Templates: templates, AuditRequestID: source, Contexts: contexts}); err != nil {
			return err
		}
	}
	return nil
}
