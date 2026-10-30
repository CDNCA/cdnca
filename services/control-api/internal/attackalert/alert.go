// Package attackalert tells site owners their site is under attack (ge-waf
// S7, the WAF notify action): enforced WAF /
// CC decisions (block, challenge, temporary ban) are aggregated per site over
// aligned windows in ClickHouse, and a site at or over Threshold in one
// window gets one notice; the next one for the site waits at least Cooldown,
// so an attack does not flood the owner with one notice per matching request.
package attackalert

import (
	"context"
	"errors"
	"fmt"
	"log/slog"
	"slices"
	"strconv"
	"time"

	"github.com/cdnca/cdnca/services/control-api/internal/analyticslog"
	"github.com/cdnca/cdnca/services/control-api/internal/notification"
	"github.com/cdnca/cdnca/services/control-api/internal/securityanalytics"
	"github.com/google/uuid"
	"github.com/jackc/pgx/v5"
	"github.com/jackc/pgx/v5/pgxpool"
)

const (
	EventType  = "security.attack.detected"
	TemplateID = EventType + ".zh-cn"

	// Window is the aggregation window; windows are aligned to it.
	Window = 5 * time.Minute
	// Threshold is the decisions per window that make an attack.
	Threshold = 1000
	// Cooldown is the least time between two notices for one site.
	Cooldown = time.Hour
	// Settle is how long a window waits for late telemetry before it is
	// evaluated (agents batch and retry their spool).
	Settle = 2 * time.Minute
	// MaxCatchUp bounds how far back a restarted worker evaluates: older
	// attacks are over and not worth a notice.
	MaxCatchUp = time.Hour
)

// Summaries is analyticslog.Client.
type Summaries interface {
	ListAttackSummaries(ctx context.Context, from, to time.Time, minimum uint64, limit uint16) ([]analyticslog.AttackSiteSummary, error)
}

// MarketSummaries is securityanalytics.ClickHouse: attacks leaves relayed for
// this controller's market-supplied sites (ADR 0012 §19.1, ML-21), by
// received time.
type MarketSummaries interface {
	MarketAttackSummaries(ctx context.Context, from, to time.Time, limit int) ([]securityanalytics.MarketAttackSummary, error)
}

// Enqueuer is notification.Store.
type Enqueuer interface {
	EnqueueTx(context.Context, pgx.Tx, notification.EnqueueRequest) (notification.EnqueueResult, error)
}

type Worker struct {
	pool      *pgxpool.Pool
	summaries Summaries
	market    MarketSummaries
	enqueuer  Enqueuer
	now       func() time.Time
}

// WithMarket also counts relayed market attacks of each site in the window
// (same threshold, same cooldown as the site's local attacks).
func (worker *Worker) WithMarket(market MarketSummaries) *Worker {
	worker.market = market
	return worker
}

var ErrInvalidConfiguration = errors.New("attack alert worker configuration is invalid")

func NewWorker(pool *pgxpool.Pool, summaries Summaries, enqueuer Enqueuer, now func() time.Time) (*Worker, error) {
	if pool == nil || summaries == nil || enqueuer == nil || now == nil {
		return nil, ErrInvalidConfiguration
	}
	return &Worker{pool: pool, summaries: summaries, enqueuer: enqueuer, now: now}, nil
}

// Result counts one RunOnce.
type Result struct {
	Windows, Notified, Cooling, Rejected, Undeliverable int
}

// RunOnce evaluates every settled window after the cursor (at most
// MaxCatchUp back) and advances the cursor window by window, so a failure
// retries from the first unevaluated window. Disabled delivery (the event's
// notification policy) still advances the cursor: attacks are not queued up
// for when it is switched on.
func (worker *Worker) RunOnce(ctx context.Context) (Result, error) {
	var result Result
	now := worker.now().UTC()
	latestEnd := now.Add(-Settle).Truncate(Window)
	var cursor time.Time
	err := worker.pool.QueryRow(ctx, `SELECT evaluated_through FROM attack_alert_cursor WHERE singleton`).Scan(&cursor)
	if errors.Is(err, pgx.ErrNoRows) {
		cursor = latestEnd.Add(-Window)
	} else if err != nil {
		return result, fmt.Errorf("read attack alert cursor: %w", err)
	}
	if floor := latestEnd.Add(-MaxCatchUp); cursor.Before(floor) {
		cursor = floor
	}
	for start := cursor.UTC().Truncate(Window); start.Add(Window).Compare(latestEnd) <= 0; start = start.Add(Window) {
		if err := ctx.Err(); err != nil {
			return result, err
		}
		end := start.Add(Window)
		enabled, err := worker.enabled(ctx)
		if err != nil {
			return result, err
		}
		var sites []analyticslog.AttackSiteSummary
		if enabled {
			sites, err = worker.sites(ctx, start, end)
			if err != nil {
				return result, fmt.Errorf("aggregate attacks %s: %w", start.Format(time.RFC3339), err)
			}
		}
		err = pgx.BeginFunc(ctx, worker.pool, func(tx pgx.Tx) error {
			for _, site := range sites {
				outcome, err := worker.site(ctx, tx, site, start, end)
				if err != nil {
					return err
				}
				switch outcome {
				case outcomeNotified:
					result.Notified++
				case outcomeCooling:
					result.Cooling++
				case outcomeRejected:
					result.Rejected++
				case outcomeUndeliverable:
					result.Undeliverable++
				}
			}
			_, err := tx.Exec(ctx, `INSERT INTO attack_alert_cursor(singleton, evaluated_through, updated_at)
				VALUES (true, $1, $2) ON CONFLICT (singleton) DO UPDATE
				SET evaluated_through=GREATEST(attack_alert_cursor.evaluated_through, EXCLUDED.evaluated_through), updated_at=EXCLUDED.updated_at`,
				end, now)
			return err
		})
		if err != nil {
			return result, fmt.Errorf("record attack alerts %s: %w", start.Format(time.RFC3339), err)
		}
		result.Windows++
	}
	return result, nil
}

// sites returns the window's sites at or over Threshold. Without market
// summaries the aggregation filters in ClickHouse; with them, local sites
// below the threshold are read too (minimum 1) so a site attacked both
// locally and through a market supply adds up.
func (worker *Worker) sites(ctx context.Context, start, end time.Time) ([]analyticslog.AttackSiteSummary, error) {
	if worker.market == nil {
		return worker.summaries.ListAttackSummaries(ctx, start, end, Threshold, analyticslog.MaxAttackSummarySites)
	}
	local, err := worker.summaries.ListAttackSummaries(ctx, start, end, 1, analyticslog.MaxAttackSummarySites)
	if err != nil {
		return nil, err
	}
	relayed, err := worker.market.MarketAttackSummaries(ctx, start, end, analyticslog.MaxAttackSummarySites)
	if err != nil {
		return nil, err
	}
	return mergeMarket(local, relayed), nil
}

// mergeMarket adds relayed summaries to the local one of the same site and
// keeps the sites at or over Threshold. The top detector and client are
// those of the larger part.
func mergeMarket(local []analyticslog.AttackSiteSummary, relayed []securityanalytics.MarketAttackSummary) []analyticslog.AttackSiteSummary {
	type key struct{ tenant, site string }
	index := map[key]int{}
	out := slices.Clone(local)
	for i, s := range out {
		index[key{s.TenantID, s.SiteID}] = i
	}
	for _, m := range relayed {
		k := key{m.TenantID, m.SiteID}
		i, ok := index[k]
		if !ok {
			out = append(out, analyticslog.AttackSiteSummary{TenantID: m.TenantID, SiteID: m.SiteID,
				FirstEventAt: m.FirstEventAt, LastEventAt: m.LastEventAt})
			i = len(out) - 1
			index[k] = i
		}
		s := &out[i]
		if m.Events > s.Events {
			s.TopDetector, s.TopClientIP = m.TopDetector, m.TopClientIP
		}
		s.Events, s.Blocked, s.Challenged, s.Banned = s.Events+m.Events, s.Blocked+m.Blocked, s.Challenged+m.Challenged, s.Banned+m.Banned
		s.Clients += m.Clients
		if m.FirstEventAt.Before(s.FirstEventAt) {
			s.FirstEventAt = m.FirstEventAt
		}
		if m.LastEventAt.After(s.LastEventAt) {
			s.LastEventAt = m.LastEventAt
		}
	}
	return slices.DeleteFunc(out, func(s analyticslog.AttackSiteSummary) bool { return s.Events < Threshold })
}

func (worker *Worker) enabled(ctx context.Context) (bool, error) {
	var enabled bool
	err := worker.pool.QueryRow(ctx, `SELECT enabled AND supported FROM notification_event_policies WHERE event_type=$1`,
		EventType).Scan(&enabled)
	if errors.Is(err, pgx.ErrNoRows) {
		return false, nil
	}
	if err != nil {
		return false, fmt.Errorf("read attack alert policy: %w", err)
	}
	return enabled, nil
}

type outcome uint8

const (
	outcomeNotified outcome = iota + 1
	outcomeCooling
	outcomeRejected
	outcomeUndeliverable
)

// site checks the reported tenant owns the site, applies the cooldown and
// enqueues under a savepoint (a notice that cannot be built is logged and
// still consumes the cooldown, so it is not retried every window).
func (worker *Worker) site(ctx context.Context, tx pgx.Tx, summary analyticslog.AttackSiteSummary, start, end time.Time) (outcome, error) {
	siteID, err := uuid.Parse(summary.SiteID)
	if err != nil {
		return outcomeRejected, nil
	}
	var scopeID, owner uuid.UUID
	var domain string
	err = tx.QueryRow(ctx, `SELECT site.scope_id, site.owner_user_id, site.domain FROM sites site
		JOIN access_scopes scope ON scope.id=site.scope_id AND scope.kind='tenant'
		WHERE site.id=$1 AND scope.tenant_id::text=$2 AND site.deleted_at IS NULL`, siteID, summary.TenantID).
		Scan(&scopeID, &owner, &domain)
	if errors.Is(err, pgx.ErrNoRows) {
		slog.Warn("attack alert dropped: site not in the reported tenant", "site_id", summary.SiteID, "tenant_id", summary.TenantID)
		return outcomeRejected, nil
	}
	if err != nil {
		return 0, err
	}
	sequence := int64(1)
	var lastNotified time.Time
	err = tx.QueryRow(ctx, `SELECT sequence, last_notified_at FROM attack_alert_site_states WHERE site_id=$1 FOR UPDATE`,
		siteID).Scan(&sequence, &lastNotified)
	switch {
	case errors.Is(err, pgx.ErrNoRows):
		_, err = tx.Exec(ctx, `INSERT INTO attack_alert_site_states(site_id, sequence, last_notified_at, last_window_end,
			last_events, updated_at) VALUES ($1, 1, $2, $3, $4, $2)`, siteID, worker.now().UTC(), end, int64(summary.Events))
		if err != nil {
			return 0, err
		}
	case err != nil:
		return 0, err
	default:
		if end.Before(lastNotified.Add(Cooldown)) {
			return outcomeCooling, nil
		}
		sequence++
		if _, err := tx.Exec(ctx, `UPDATE attack_alert_site_states SET sequence=$2, last_notified_at=$3, last_window_end=$4,
			last_events=$5, updated_at=$3 WHERE site_id=$1`, siteID, sequence, worker.now().UTC(), end, int64(summary.Events)); err != nil {
			return 0, err
		}
	}
	savepoint, err := tx.Begin(ctx)
	if err != nil {
		return 0, err
	}
	defer func() { _ = savepoint.Rollback(context.WithoutCancel(ctx)) }()
	sourceEventID := "attack-alert/" + siteID.String() + "/" + strconv.FormatInt(sequence, 10)
	err = worker.enqueue(ctx, savepoint, scopeID, owner, domain, summary, start, end, sourceEventID)
	if err == nil {
		err = savepoint.Commit(ctx)
	}
	if err != nil {
		slog.Warn("attack alert not enqueued", "site_id", summary.SiteID, "error", err)
		return outcomeUndeliverable, nil
	}
	return outcomeNotified, nil
}

func (worker *Worker) enqueue(ctx context.Context, tx pgx.Tx, scopeID, owner uuid.UUID, domain string,
	summary analyticslog.AttackSiteSummary, start, end time.Time, sourceEventID string) error {
	detector, client := summary.TopDetector, summary.TopClientIP
	if detector == "" {
		detector = "-"
	}
	if client == "" {
		client = "-"
	}
	values := map[string]string{
		"domain": domain, "window_start": shanghai(start), "window_end": shanghai(end),
		"window_minutes": strconv.Itoa(int(Window / time.Minute)), "events": strconv.FormatUint(summary.Events, 10),
		"blocked": strconv.FormatUint(summary.Blocked, 10), "challenged": strconv.FormatUint(summary.Challenged, 10),
		"banned": strconv.FormatUint(summary.Banned, 10), "clients": strconv.FormatUint(summary.Clients, 10),
		"top_client_ip": client, "top_detector": detector, "cooldown_minutes": strconv.Itoa(int(Cooldown / time.Minute)),
	}
	// The newest version of each channel's template, filled with exactly the
	// variables it declares, so an edited template keeps enqueueing.
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
		return errors.New("attack alert template is missing")
	}
	request := notification.EnqueueRequest{
		ScopeID: scopeID, RecipientID: owner, SourceEventID: sourceEventID, EventType: EventType,
		Policy: notification.DeliveryTenantSubscribed, Templates: templates, Contexts: contexts, AuditRequestID: sourceEventID,
	}
	if siteID, err := uuid.Parse(summary.SiteID); err == nil && siteID != uuid.Nil {
		request.SubjectSiteID = &siteID
	}
	_, err = worker.enqueuer.EnqueueTx(ctx, tx, request)
	return err
}

func shanghai(value time.Time) string {
	location, err := time.LoadLocation("Asia/Shanghai")
	if err != nil {
		location = time.FixedZone("CST", 8*3600)
	}
	return value.In(location).Format("2006-01-02 15:04")
}

// Run evaluates every Window until ctx ends; failures are logged and retried
// at the next tick (the cursor keeps the unevaluated windows).
func (worker *Worker) Run(ctx context.Context) {
	timer := time.NewTimer(0)
	defer timer.Stop()
	for {
		select {
		case <-ctx.Done():
			return
		case <-timer.C:
		}
		result, err := worker.RunOnce(ctx)
		if err != nil && ctx.Err() == nil {
			slog.Warn("attack alert evaluation failed", "error", err)
		} else if result.Notified > 0 || result.Rejected > 0 || result.Undeliverable > 0 {
			slog.Info("attack alerts evaluated", "windows", result.Windows, "notified", result.Notified,
				"cooling", result.Cooling, "rejected", result.Rejected, "undeliverable", result.Undeliverable)
		}
		timer.Reset(time.Minute)
	}
}
