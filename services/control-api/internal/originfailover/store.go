package originfailover

import (
	"context"
	"errors"
	"fmt"
	"log/slog"
	"strconv"
	"time"

	"github.com/cdnca/cdnca/services/control-api/internal/audit"
	"github.com/cdnca/cdnca/services/control-api/internal/edgeautopublish"
	"github.com/cdnca/cdnca/services/control-api/internal/edgepublish"
	"github.com/cdnca/cdnca/services/control-api/internal/notification"
	"github.com/google/uuid"
	"github.com/jackc/pgx/v5"
	"github.com/jackc/pgx/v5/pgxpool"
)

// Audit actions (audit/catalog_site.go) and notification events (418).
const (
	AuditFailover        = "site.origin.failover"
	AuditFailback        = "site.origin.failback"
	EventFailover        = "site.origin.failover"
	EventRecovered       = "site.origin.recovered"
	templateFailover     = "site.origin.failover.zh-cn"
	templateRecovered    = "site.origin.recovered.zh-cn"
	ReasonAllDown        = "all_down"
	ReasonManualFailback = "manual_failback"
)

// Enqueuer is notification.Store.
type Enqueuer interface {
	EnqueueTx(context.Context, pgx.Tx, notification.EnqueueRequest) (notification.EnqueueResult, error)
}

type Store struct {
	pool     *pgxpool.Pool
	auditor  *audit.Log
	enqueuer Enqueuer
	now      func() time.Time
}

func NewStore(pool *pgxpool.Pool, enqueuer Enqueuer, now func() time.Time) *Store {
	if now == nil {
		now = time.Now
	}
	return &Store{pool: pool, auditor: audit.New(pool), enqueuer: enqueuer, now: now}
}

// Origin is one origin of a probed pool.
type Origin struct {
	Position int
	Host     string
	Port     int
	Level    int
	Enabled  bool
}

// Pool is what one probe round needs of a site.
type Pool struct {
	SiteID, ScopeID uuid.UUID
	Domain          string
	HealthCheckPath string
	Scheme          string // http | https | follow
	RequestHostMode string // visitor | origin | custom
	RequestHost     string
	SNI             string
	Trust           string // system | custom
	CAPEM           string
	Origins         []Origin
}

// HostHeader is the Host the edge sends to origin (request_host).
func (pool Pool) HostHeader(origin Origin) string {
	switch pool.RequestHostMode {
	case "origin":
		return origin.Host
	case "custom":
		if pool.RequestHost != "" {
			return pool.RequestHost
		}
	}
	return pool.Domain
}

// Outcome is one origin's probe result; Voted=false: not probed.
type Outcome struct {
	OK, Voted bool
	Reason    string
}

// DuePools are up to limit enabled sites, least recently probed first.
func (s *Store) DuePools(ctx context.Context, limit int) ([]Pool, error) {
	rows, err := s.pool.Query(ctx, `WITH due AS (
			SELECT site.id FROM sites site
			LEFT JOIN site_origin_failover_states state ON state.site_id=site.id
			WHERE site.deleted_at IS NULL AND site.enabled
			ORDER BY state.checked_at NULLS FIRST, site.id LIMIT $1)
		SELECT site.id, site.scope_id, site.domain, pool.health_check_path, pool.origin_scheme,
		       pool.request_host_mode, COALESCE(pool.request_host,''), COALESCE(pool.tls_sni,''), pool.tls_trust,
		       COALESCE(pool.tls_ca_pem,''), origin.position, origin.host, origin.port, origin.level, origin.enabled
		FROM due JOIN sites site ON site.id=due.id
		JOIN site_origin_pools pool ON pool.site_id=site.id
		JOIN site_origins origin ON origin.site_id=site.id
		ORDER BY site.id, origin.position`, limit)
	if err != nil {
		return nil, err
	}
	defer rows.Close()
	var pools []Pool
	for rows.Next() {
		var item Pool
		var origin Origin
		if err := rows.Scan(&item.SiteID, &item.ScopeID, &item.Domain, &item.HealthCheckPath, &item.Scheme,
			&item.RequestHostMode, &item.RequestHost, &item.SNI, &item.Trust, &item.CAPEM,
			&origin.Position, &origin.Host, &origin.Port, &origin.Level, &origin.Enabled); err != nil {
			return nil, err
		}
		if len(pools) == 0 || pools[len(pools)-1].SiteID != item.SiteID {
			pools = append(pools, item)
		}
		last := &pools[len(pools)-1]
		last.Origins = append(last.Origins, origin)
	}
	return pools, rows.Err()
}

type evaluation struct {
	siteID         uuid.UUID
	scopeID, owner uuid.UUID
	domain, mode   string
	state          failoverState
	levels         []LevelStatus
	decision       Decision
}

type failoverState struct {
	active   int
	ready    bool
	sequence int64
}

// Record folds one round's outcomes into the probe states and applies the
// failover decision. A level change (or a manual switch back) is made under
// the publication lock order: configuration scope, site, failover row.
func (s *Store) Record(ctx context.Context, pool Pool, outcomes map[string]Outcome) error {
	now := s.now().UTC().Truncate(time.Microsecond)
	var switching bool
	err := pgx.BeginFunc(ctx, s.pool, func(tx pgx.Tx) error {
		for _, origin := range pool.Origins {
			outcome, probed := outcomes[endpointKey(origin.Host, origin.Port)]
			if !origin.Enabled || !probed {
				continue
			}
			if err := observeTx(ctx, tx, pool.SiteID, origin, outcome, now); err != nil {
				return err
			}
		}
		value, err := evaluateTx(ctx, tx, pool.SiteID, false)
		if err != nil {
			return err
		}
		if value.decision.Target != value.state.active {
			switching = true
			return writeState(ctx, tx, pool.SiteID, value.state, value.state.ready, false, now)
		}
		if err := writeState(ctx, tx, pool.SiteID, value.state, value.decision.FailbackReady, false, now); err != nil {
			return err
		}
		return s.alertTx(ctx, tx, pool.SiteID, value, now)
	})
	if err != nil || !switching {
		return err
	}
	return pgx.BeginFunc(ctx, s.pool, func(tx pgx.Tx) error {
		value, err := lockedEvaluateTx(ctx, tx, pool.SiteID)
		if err != nil || value.decision.Target == value.state.active {
			return err
		}
		return s.switchTx(ctx, tx, pool.SiteID, value, value.decision.Target, value.decision.Reason, nil, "", now)
	})
}

func observeTx(ctx context.Context, tx pgx.Tx, siteID uuid.UUID, origin Origin, outcome Outcome, now time.Time) error {
	var state ProbeState
	var reason string
	err := tx.QueryRow(ctx, `SELECT status,consecutive_failures,consecutive_successes,reason FROM site_origin_probe_states
		WHERE site_id=$1 AND host=$2 AND port=$3 FOR UPDATE`, siteID, origin.Host, origin.Port).
		Scan(&state.Status, &state.Failures, &state.Successes, &reason)
	if err != nil && !errors.Is(err, pgx.ErrNoRows) {
		return err
	}
	state = Observe(state, outcome.OK, outcome.Voted)
	if outcome.Voted || outcome.Reason != "" {
		reason = outcome.Reason
	}
	_, err = tx.Exec(ctx, `INSERT INTO site_origin_probe_states(site_id,host,port,status,consecutive_failures,
			consecutive_successes,reason,checked_at) VALUES($1,$2,$3,$4,$5,$6,$7,$8)
		ON CONFLICT (site_id,host,port) DO UPDATE SET status=EXCLUDED.status,
			consecutive_failures=EXCLUDED.consecutive_failures, consecutive_successes=EXCLUDED.consecutive_successes,
			reason=EXCLUDED.reason, checked_at=EXCLUDED.checked_at`,
		siteID, origin.Host, origin.Port, state.Status, state.Failures, state.Successes, reason, now)
	return err
}

// lockedEvaluateTx locks scope, site and failover row in publication order.
func lockedEvaluateTx(ctx context.Context, tx pgx.Tx, siteID uuid.UUID) (evaluation, error) {
	var scopeID uuid.UUID
	if err := tx.QueryRow(ctx, `SELECT scope_id FROM sites WHERE id=$1 AND deleted_at IS NULL`, siteID).Scan(&scopeID); err != nil {
		if errors.Is(err, pgx.ErrNoRows) {
			return evaluation{}, ErrNotFound
		}
		return evaluation{}, err
	}
	if _, err := tx.Exec(ctx, `INSERT INTO edge_configuration_scopes(scope_id,source_revision,updated_at)
		VALUES($1,1,clock_timestamp()) ON CONFLICT(scope_id) DO NOTHING`, scopeID); err != nil {
		return evaluation{}, err
	}
	if _, err := tx.Exec(ctx, `SELECT 1 FROM edge_configuration_scopes WHERE scope_id=$1 FOR UPDATE`, scopeID); err != nil {
		return evaluation{}, err
	}
	return evaluateTx(ctx, tx, siteID, true)
}

// evaluateTx reads the pool's origins, their probe states and the failover
// state, and decides.
func evaluateTx(ctx context.Context, tx pgx.Tx, siteID uuid.UUID, lock bool) (evaluation, error) {
	value := evaluation{siteID: siteID}
	query := `SELECT site.scope_id, site.owner_user_id, site.domain, pool.failback_mode
		FROM sites site JOIN site_origin_pools pool ON pool.site_id=site.id WHERE site.id=$1 AND site.deleted_at IS NULL`
	if lock {
		query += ` FOR UPDATE OF site`
	}
	if err := tx.QueryRow(ctx, query, siteID).Scan(&value.scopeID, &value.owner, &value.domain, &value.mode); err != nil {
		if errors.Is(err, pgx.ErrNoRows) {
			return evaluation{}, ErrNotFound
		}
		return evaluation{}, err
	}
	if _, err := tx.Exec(ctx, `INSERT INTO site_origin_failover_states(site_id,active_level,updated_at)
		VALUES($1,0,clock_timestamp()) ON CONFLICT (site_id) DO NOTHING`, siteID); err != nil {
		return evaluation{}, err
	}
	if err := tx.QueryRow(ctx, `SELECT active_level,failback_ready,sequence FROM site_origin_failover_states
		WHERE site_id=$1 FOR UPDATE`, siteID).Scan(&value.state.active, &value.state.ready, &value.state.sequence); err != nil {
		return evaluation{}, err
	}
	rows, err := tx.Query(ctx, `SELECT origin.level, COALESCE(probe.status,'unknown')
		FROM site_origins origin LEFT JOIN site_origin_probe_states probe
		  ON probe.site_id=origin.site_id AND probe.host=origin.host AND probe.port=origin.port
		WHERE origin.site_id=$1 AND origin.enabled`, siteID)
	if err != nil {
		return evaluation{}, err
	}
	origins, err := pgx.CollectRows(rows, func(row pgx.CollectableRow) (LevelOrigin, error) {
		var origin LevelOrigin
		return origin, row.Scan(&origin.Level, &origin.Status)
	})
	if err != nil {
		return evaluation{}, err
	}
	value.levels = LevelStatuses(origins)
	value.decision = Decide(value.levels, value.state.active, value.mode == "manual")
	return value, nil
}

func writeState(ctx context.Context, tx pgx.Tx, siteID uuid.UUID, state failoverState, ready, switched bool, now time.Time) error {
	_, err := tx.Exec(ctx, `UPDATE site_origin_failover_states SET active_level=$2, failback_ready=$3, sequence=$4,
		switched_at=CASE WHEN $5 THEN $6 ELSE switched_at END, checked_at=$6, updated_at=$6 WHERE site_id=$1`,
		siteID, state.active, ready, state.sequence, switched, now)
	return err
}

// switchTx moves the active level: site revision (the scope's source
// revision follows), republication, audit, notification.
func (s *Store) switchTx(ctx context.Context, tx pgx.Tx, siteID uuid.UUID, value evaluation, target int, reason string,
	actor *uuid.UUID, requestKey string, now time.Time,
) error {
	var fromRevision int64
	if err := tx.QueryRow(ctx, `SELECT source_revision FROM edge_configuration_scopes WHERE scope_id=$1`, value.scopeID).
		Scan(&fromRevision); err != nil {
		return err
	}
	from := value.state.active
	value.state.active, value.state.sequence = target, value.state.sequence+1
	ready := value.mode == "manual" && FailbackTarget(value.levels, target) >= 0
	if err := writeState(ctx, tx, siteID, value.state, ready, true, now); err != nil {
		return err
	}
	if requestKey != "" {
		if _, err := tx.Exec(ctx, `UPDATE site_origin_failover_states SET failback_request_key=$2 WHERE site_id=$1`,
			siteID, requestKey); err != nil {
			return err
		}
	}
	// The release reads active_level; advance the site so the scope's
	// source revision moves.
	if _, err := tx.Exec(ctx, `UPDATE sites SET revision=revision+1, updated_at=$2 WHERE id=$1 AND deleted_at IS NULL`,
		siteID, now); err != nil {
		return err
	}
	requestID := "origin-failover:" + siteID.String() + ":" + strconv.FormatInt(value.state.sequence, 10)
	mode, err := edgeautopublish.RequestRepublicationTx(ctx, tx, edgeautopublish.RepublishRequest{
		ScopeID: value.scopeID, Trigger: edgepublish.SystemTriggerOriginFailover,
		SourceResourceID: siteID, SourceRequestID: requestID, FromRevision: fromRevision,
	})
	if err != nil {
		return fmt.Errorf("republish origin failover: %w", err)
	}
	action := AuditFailover
	if actor != nil {
		action = AuditFailback
	}
	if err := s.auditor.Append(ctx, tx, audit.Event{
		ScopeID: value.scopeID, ActorUserID: actor, Action: action, ResourceType: "site", ResourceID: siteID.String(),
		RequestID: requestID, Result: "success",
		Payload: map[string]any{
			"site_id": siteID.String(), "site_domain": value.domain, "reason": reason, "failback_mode": value.mode,
			"changes":          map[string]any{"active_level": map[string]any{"from": from, "to": target}},
			"publication_mode": mode.Mode,
		},
	}); err != nil {
		return err
	}
	if actor != nil {
		return nil
	}
	return s.notify(ctx, tx, value, EventFailover, templateFailover, "origin-failover/"+siteID.String()+"/"+
		strconv.FormatInt(value.state.sequence, 10), map[string]string{
		"domain": value.domain, "switched_at": shanghai(now), "from_level": LevelName(from), "to_level": LevelName(target),
		"reason": reasonText(reason), "failback_mode": modeText(value.mode), "action": actionText(value.mode),
	})
}

// alertTx: a manual pool whose higher level recovered (once per sequence),
// and a pool with every level down (once per sequence).
func (s *Store) alertTx(ctx context.Context, tx pgx.Tx, siteID uuid.UUID, value evaluation, now time.Time) error {
	sequence := strconv.FormatInt(value.state.sequence, 10)
	if value.decision.FailbackReady && !value.state.ready {
		target := FailbackTarget(value.levels, value.state.active)
		return s.notify(ctx, tx, value, EventRecovered, templateRecovered, "origin-recovered/"+siteID.String()+"/"+sequence,
			map[string]string{"domain": value.domain, "recovered_at": shanghai(now), "level": LevelName(target),
				"active_level": LevelName(value.state.active)})
	}
	if value.decision.AllDown {
		return s.notify(ctx, tx, value, EventFailover, templateFailover, "origin-all-down/"+siteID.String()+"/"+sequence,
			map[string]string{"domain": value.domain, "switched_at": shanghai(now), "from_level": LevelName(value.state.active),
				"to_level": LevelName(value.state.active), "reason": reasonText(ReasonAllDown),
				"failback_mode": modeText(value.mode), "action": actionText(value.mode)})
	}
	return nil
}

// notify enqueues under a savepoint: a notice that cannot be built (no
// template, owner no longer a member) is logged and does not undo the
// switch. The same source event is enqueued once.
func (s *Store) notify(ctx context.Context, tx pgx.Tx, value evaluation, eventType, templateID, sourceEventID string,
	values map[string]string,
) error {
	if s.enqueuer == nil {
		return nil
	}
	savepoint, err := tx.Begin(ctx)
	if err != nil {
		return err
	}
	defer func() { _ = savepoint.Rollback(context.WithoutCancel(ctx)) }()
	err = s.enqueue(ctx, savepoint, value, eventType, templateID, sourceEventID, values)
	if err == nil {
		err = savepoint.Commit(ctx)
	}
	if err != nil {
		slog.Warn("origin failover notification not enqueued", "event", eventType, "source", sourceEventID, "error", err)
	}
	return nil
}

func (s *Store) enqueue(ctx context.Context, tx pgx.Tx, value evaluation, eventType, templateID, sourceEventID string,
	values map[string]string,
) error {
	rows, err := tx.Query(ctx, `SELECT DISTINCT ON (channel) channel, version, variables FROM notification_templates
		WHERE template_id=$1 ORDER BY channel, version DESC`, templateID)
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
		ref := notification.TemplateRef{ID: templateID, Version: uint64(version), Channel: notification.Channel(channel)}
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
		return errors.New("origin failover template is missing")
	}
	_, err = s.enqueuer.EnqueueTx(ctx, tx, notification.EnqueueRequest{
		ScopeID: value.scopeID, RecipientID: value.owner, SourceEventID: sourceEventID, EventType: eventType,
		Policy: notification.DeliveryTenantSubscribed, Templates: templates, Contexts: contexts, AuditRequestID: sourceEventID,
		SubjectSiteID: &value.siteID,
	})
	return err
}

// Failback is the user's switch back (POST origin-failback): the active
// level moves to the best healthy level above it. The same request key
// replays the result.
func (s *Store) Failback(ctx context.Context, actor uuid.UUID, siteID uuid.UUID, requestKey string) error {
	now := s.now().UTC().Truncate(time.Microsecond)
	return pgx.BeginFunc(ctx, s.pool, func(tx pgx.Tx) error {
		value, err := lockedEvaluateTx(ctx, tx, siteID)
		if err != nil {
			return err
		}
		var previous *string
		if err := tx.QueryRow(ctx, `SELECT failback_request_key FROM site_origin_failover_states WHERE site_id=$1`,
			siteID).Scan(&previous); err != nil {
			return err
		}
		if previous != nil && *previous == requestKey {
			return nil
		}
		target := FailbackTarget(value.levels, value.state.active)
		if target < 0 {
			return ErrFailbackUnavailable
		}
		return s.switchTx(ctx, tx, siteID, value, target, ReasonManualFailback, &actor, requestKey, now)
	})
}

// SiteScope is the site's scope (ErrNotFound: missing or deleted).
func (s *Store) SiteScope(ctx context.Context, siteID uuid.UUID) (uuid.UUID, error) {
	var scopeID uuid.UUID
	err := s.pool.QueryRow(ctx, `SELECT scope_id FROM sites WHERE id=$1 AND deleted_at IS NULL`, siteID).Scan(&scopeID)
	if errors.Is(err, pgx.ErrNoRows) {
		return uuid.Nil, ErrNotFound
	}
	return scopeID, err
}

// PoolStatus is the site's pool state (see model.go).
func (s *Store) PoolStatus(ctx context.Context, siteID uuid.UUID) (PoolStatus, error) {
	result := PoolStatus{SiteID: siteID, Levels: []LevelStatus{}, Origins: []OriginStatus{}}
	err := pgx.BeginTxFunc(ctx, s.pool, pgx.TxOptions{IsoLevel: pgx.RepeatableRead, AccessMode: pgx.ReadOnly}, func(tx pgx.Tx) error {
		err := tx.QueryRow(ctx, `SELECT pool.failback_mode, COALESCE(state.active_level,0), COALESCE(state.failback_ready,false),
				state.switched_at, state.checked_at
			FROM sites site JOIN site_origin_pools pool ON pool.site_id=site.id
			LEFT JOIN site_origin_failover_states state ON state.site_id=site.id
			WHERE site.id=$1 AND site.deleted_at IS NULL`, siteID).
			Scan(&result.FailbackMode, &result.ActiveLevel, &result.FailbackReady, &result.SwitchedAt, &result.CheckedAt)
		if errors.Is(err, pgx.ErrNoRows) {
			return ErrNotFound
		}
		if err != nil {
			return err
		}
		rows, err := tx.Query(ctx, `SELECT origin.position, origin.host, origin.port, origin.level, origin.enabled,
				CASE WHEN origin.enabled THEN COALESCE(probe.status,'unknown') ELSE 'unknown' END,
				COALESCE(probe.reason,''), probe.checked_at
			FROM site_origins origin LEFT JOIN site_origin_probe_states probe
			  ON probe.site_id=origin.site_id AND probe.host=origin.host AND probe.port=origin.port
			WHERE origin.site_id=$1 ORDER BY origin.position`, siteID)
		if err != nil {
			return err
		}
		result.Origins, err = pgx.CollectRows(rows, func(row pgx.CollectableRow) (OriginStatus, error) {
			var origin OriginStatus
			return origin, row.Scan(&origin.Position, &origin.Host, &origin.Port, &origin.Level, &origin.Enabled,
				&origin.Status, &origin.Reason, &origin.CheckedAt)
		})
		return err
	})
	if err != nil {
		return PoolStatus{}, err
	}
	var origins []LevelOrigin
	for _, origin := range result.Origins {
		if origin.Enabled {
			origins = append(origins, LevelOrigin{Level: origin.Level, Status: origin.Status})
		}
	}
	result.Levels = LevelStatuses(origins)
	result.Overall = Overall(result.Levels)
	return result, nil
}

func endpointKey(host string, port int) string { return host + "|" + strconv.Itoa(port) }

// LevelName is the zh-CN name of a level in notices.
func LevelName(level int) string {
	if level == 0 {
		return "主源"
	}
	return "备用源 " + strconv.Itoa(level)
}

func reasonText(reason string) string {
	switch reason {
	case "level_down":
		return "当前级别的源站全部不可用"
	case "recovered":
		return "更高级别的源站已恢复"
	case ReasonAllDown:
		return "全部源站不可用，保持当前级别"
	}
	return reason
}

func modeText(mode string) string {
	if mode == "manual" {
		return "手动"
	}
	return "自动"
}

func actionText(mode string) string {
	if mode == "manual" {
		return "，主源恢复后请在该页点击“切回主源”"
	}
	return ""
}

func shanghai(value time.Time) string {
	return value.In(time.FixedZone("CST", 8*3600)).Format("2006-01-02 15:04:05")
}
