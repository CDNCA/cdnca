package nodednspupprobe

import (
	"context"
	"encoding/json"
	"errors"
	"log/slog"
	"net/netip"
	"sort"
	"strconv"
	"sync"
	"time"

	"github.com/cdnca/cdnca/services/control-api/internal/audit"
	"github.com/cdnca/cdnca/services/control-api/internal/dnspupprobe"
	"github.com/cdnca/cdnca/services/control-api/internal/nodemonitoringconfig"
	"github.com/cdnca/cdnca/services/control-api/internal/notification"
	"github.com/cdnca/cdnca/services/control-api/internal/systemconfig"
	"github.com/google/uuid"
	"github.com/jackc/pgx/v5"
	"github.com/jackc/pgx/v5/pgxpool"
)

const (
	// ResultRetention keeps the availability log one day past its 7-day window.
	ResultRetention = 8 * 24 * time.Hour
	// MaxAddressesPerRound bounds the charged jobs of one round
	// (dnspupprobe.MaxJobsPerRound); further addresses rotate in later rounds.
	MaxAddressesPerRound = dnspupprobe.MaxJobsPerRound
	probeConcurrency     = 8
	// ExhaustedRecheck: with no balance left the account is read again this
	// often (not metered) to resume once the user has topped up.
	ExhaustedRecheck = 5 * time.Minute

	EventTypeUnreachable      = notification.EventTypeNodeDNSPupUnreachable
	EventTypeRecovered        = notification.EventTypeNodeDNSPupRecovered
	EventTypeBalanceLow       = notification.EventTypeProbeDNSPupBalanceLow
	EventTypeBalanceExhausted = notification.EventTypeProbeDNSPupBalanceExhausted

	ActionNodeSettings = "system.probe_dnspup.node_settings"
	ActionBudget       = "system.probe_dnspup.node_budget"
	ActionNodeVerdict  = "node.dnspup_probe.verdict"

	nodeAlertPermission   = "nodes.manage"
	budgetAlertPermission = dnspupprobe.PermissionManage
)

// Sources is dnspupprobe.Service.Runtime.
type Sources func(context.Context) dnspupprobe.Runtime

// AlertEnqueuer is notification.Store's transactional enqueue.
type AlertEnqueuer interface {
	EnqueueTx(context.Context, pgx.Tx, notification.EnqueueRequest) (notification.EnqueueResult, error)
}

// Runner runs dnspup node probe rounds.
type Runner struct {
	pool    *pgxpool.Pool
	sources Sources
	alerts  AlertEnqueuer
	auditor *audit.Log
	now     func() time.Time
	logger  *slog.Logger

	mu       sync.Mutex
	lastRun  time.Time
	rotation int
}

type Config struct {
	Pool    *pgxpool.Pool
	Sources Sources
	Alerts  AlertEnqueuer // nil: verdicts and budget are recorded, not notified
	Now     func() time.Time
	Logger  *slog.Logger
}

func NewRunner(config Config) (*Runner, error) {
	if config.Pool == nil || config.Sources == nil {
		return nil, errors.New("dnspup node probe runner requires a pool and the dnspup source")
	}
	if config.Now == nil {
		config.Now = time.Now
	}
	if config.Logger == nil {
		config.Logger = slog.Default()
	}
	return &Runner{pool: config.Pool, sources: config.Sources, alerts: config.Alerts,
		auditor: audit.NewWithClock(config.Pool, config.Now), now: config.Now, logger: config.Logger}, nil
}

// Run ticks every 30 s; RunOnce probes when the effective interval is due.
func (runner *Runner) Run(ctx context.Context) {
	ticker := time.NewTicker(30 * time.Second)
	defer ticker.Stop()
	for {
		if err := runner.RunOnce(ctx); err != nil && ctx.Err() == nil {
			runner.logger.Warn("dnspup node probe round failed", "error", err)
		}
		select {
		case <-ctx.Done():
			return
		case <-ticker.C:
		}
	}
}

// Target is one published node address.
type Target struct {
	NodeID, ScopeID uuid.UUID
	Address         netip.Addr
	Port            uint16
}

func (target Target) key() string {
	return target.NodeID.String() + "|" + netip.AddrPortFrom(target.Address, target.Port).String()
}

// RoundReport is what one RunOnce did (tests).
type RoundReport struct {
	Probed  bool
	Budget  string
	Targets int
}

// RunOnce reads the settings and the dnspup account, updates the budget
// state, and, when the effective interval is due, probes the published node
// addresses and applies the verdicts.
func (runner *Runner) RunOnce(ctx context.Context) (err error) {
	_, err = runner.round(ctx)
	return err
}

func (runner *Runner) round(ctx context.Context) (RoundReport, error) {
	now := runner.now().UTC().Truncate(time.Second)
	settings, budget, err := ReadSettings(ctx, runner.pool)
	if err != nil {
		return RoundReport{}, err
	}
	report := RoundReport{Budget: budget}
	if settings.IntervalSeconds == 0 {
		return report, nil
	}
	runtime := runner.sources(ctx)
	if runtime.Probe == nil || runtime.Account == nil || runtime.Checkpoints == nil {
		// Not licensed, disabled, no key pair or paused: the local probe decides.
		return report, nil
	}
	wait := EffectiveInterval(settings, budget)
	if budget == BudgetExhausted {
		wait = ExhaustedRecheck
	}
	runner.mu.Lock()
	due := runner.lastRun.IsZero() || now.Sub(runner.lastRun) >= wait
	if due {
		runner.lastRun = now
	}
	runner.mu.Unlock()
	if !due {
		return report, nil
	}
	// The account read is not metered; it decides the budget for this round.
	account, err := runtime.Account(ctx)
	if err != nil {
		return report, err
	}
	if next := BudgetFor(account.MonthlyLimit, account.MonthlyUsed, settings.LowBalance); next != budget {
		if err := runner.changeBudget(ctx, budget, next, account, settings, now); err != nil {
			return report, err
		}
		budget, report.Budget = next, next
	}
	interval := EffectiveInterval(settings, budget)
	if interval == 0 {
		return report, nil
	}
	checkpoints, err := runtime.Checkpoints(ctx)
	if err != nil {
		return report, err
	}
	targets, err := runner.targets(ctx)
	if err != nil {
		return report, err
	}
	// More addresses than one round's job budget rotate: a node is probed
	// every cycles rounds, and its verdict stays fresh that long.
	cycles := max((len(targets)+MaxAddressesPerRound-1)/MaxAddressesPerRound, 1)
	runner.mu.Lock()
	targets = runner.rotate(targets)
	runner.mu.Unlock()
	report.Probed, report.Targets = true, len(targets)
	roundNumber := dnspupprobe.Round(now, interval)
	nodeIDs := SelectCheckpoints(checkpoints, settings, roundNumber)
	if len(nodeIDs) == 0 || len(targets) == 0 {
		return report, nil
	}
	rounds := runner.probe(ctx, runtime, targets, nodeIDs, settings, roundNumber)
	return report, runner.apply(ctx, targets, rounds, settings, interval*time.Duration(cycles), now)
}

// rotate keeps at most MaxAddressesPerRound targets, starting where the
// previous round stopped.
func (runner *Runner) rotate(targets []Target) []Target {
	if len(targets) <= MaxAddressesPerRound {
		runner.rotation = 0
		return targets
	}
	start := runner.rotation % len(targets)
	out := make([]Target, 0, MaxAddressesPerRound)
	for index := range MaxAddressesPerRound {
		out = append(out, targets[(start+index)%len(targets)])
	}
	runner.rotation = (start + MaxAddressesPerRound) % len(targets)
	return out
}

func (runner *Runner) probe(ctx context.Context, runtime dnspupprobe.Runtime, targets []Target, nodeIDs []string,
	settings Settings, round int64) map[string]RoundResult {
	var mu sync.Mutex
	out := map[string]RoundResult{}
	var wait sync.WaitGroup
	slots := make(chan struct{}, probeConcurrency)
	for _, target := range targets {
		wait.Add(1)
		slots <- struct{}{}
		go func(target Target) {
			defer wait.Done()
			defer func() { <-slots }()
			ipVersion := "4"
			if target.Address.Is6() {
				ipVersion = "6"
			}
			results, err := runtime.Probe(ctx, dnspupprobe.ConsumerNode, target.NodeID.String(),
				netip.AddrPortFrom(target.Address, target.Port).String(), round,
				dnspupprobe.ProbeRequest{Type: "tcping", Target: target.Address.String(), Port: int(target.Port),
					IPVersion: ipVersion, NodeIDs: nodeIDs})
			if err != nil {
				if !errors.Is(err, dnspupprobe.ErrDelivered) && ctx.Err() == nil {
					runner.logger.Debug("dnspup node probe skipped", "node", target.NodeID, "error", err)
				}
				return
			}
			result := Round(results, settings)
			mu.Lock()
			out[target.key()] = result
			mu.Unlock()
		}(target)
	}
	wait.Wait()
	return out
}

// targets are the published addresses of active / draining nodes whose
// monitoring is on (port: the monitoring port override, else the endpoint's).
func (runner *Runner) targets(ctx context.Context) ([]Target, error) {
	tx, err := runner.pool.BeginTx(ctx, pgx.TxOptions{IsoLevel: pgx.RepeatableRead, AccessMode: pgx.ReadOnly})
	if err != nil {
		return nil, err
	}
	defer func() { _ = tx.Rollback(context.Background()) }()
	rows, err := tx.Query(ctx, `SELECT DISTINCT published.node_id,node.scope_id,host(published.address),endpoint.port
		FROM node_line_endpoint_published published
		JOIN node_line_groups line_group ON line_group.tenant_scope_id=published.tenant_scope_id
		 AND line_group.id=published.line_group_id AND line_group.current_revision=published.config_revision
		 AND line_group.deleted_at IS NULL
		JOIN node_line_endpoints endpoint ON endpoint.tenant_scope_id=published.tenant_scope_id
		 AND endpoint.line_group_id=published.line_group_id AND endpoint.config_revision=published.config_revision
		 AND endpoint.id=published.endpoint_id
		JOIN nodes node ON node.id=published.node_id AND node.admin_state IN ('active','draining')
		WHERE published.node_id IS NOT NULL AND endpoint.enabled
		ORDER BY 1,3,4`)
	if err != nil {
		return nil, err
	}
	var targets []Target
	for rows.Next() {
		var target Target
		var address string
		var port int32
		if err := rows.Scan(&target.NodeID, &target.ScopeID, &address, &port); err != nil {
			rows.Close()
			return nil, err
		}
		parsed, err := netip.ParseAddr(address)
		if err != nil || port < 1 || port > 65535 {
			continue
		}
		target.Address, target.Port = parsed, uint16(port)
		targets = append(targets, target)
	}
	rows.Close()
	if err := rows.Err(); err != nil {
		return nil, err
	}
	policies := map[uuid.UUID]*systemconfig.NodeMonitoringConfiguration{}
	out := targets[:0]
	seen := map[string]bool{}
	for _, target := range targets {
		value, ok := policies[target.ScopeID]
		if !ok {
			configuration, current, err := systemconfig.ReadActiveNodeMonitoring(ctx, tx, target.ScopeID)
			switch {
			case errors.Is(err, systemconfig.ErrPermissionDenied):
			case err != nil:
				return nil, err
			case configuration.State == "active":
				value = &current
			}
			policies[target.ScopeID] = value
		}
		if value == nil {
			continue
		}
		override, err := readOverride(ctx, tx, target.NodeID, target.ScopeID)
		if err != nil {
			return nil, err
		}
		effective := nodemonitoringconfig.ApplyOverride(*value, override)
		if effective.MonitorEnabled != nil && !*effective.MonitorEnabled {
			continue
		}
		if effective.MonitorPort != nil && *effective.MonitorPort > 0 {
			target.Port = *effective.MonitorPort
		}
		if seen[target.key()] {
			continue
		}
		seen[target.key()] = true
		out = append(out, target)
	}
	return out, tx.Commit(ctx)
}

func readOverride(ctx context.Context, tx pgx.Tx, nodeID, scopeID uuid.UUID) (nodemonitoringconfig.Override, error) {
	var override nodemonitoringconfig.Override
	var revision *int64
	var port *int32
	err := tx.QueryRow(ctx, `SELECT revision,monitor_enabled,monitor_port FROM node_monitoring_overrides
		WHERE node_id=$1 AND scope_id=$2`, nodeID, scopeID).Scan(&revision, &override.MonitorEnabled, &port)
	if errors.Is(err, pgx.ErrNoRows) {
		return nodemonitoringconfig.Override{}, nil
	}
	if err != nil {
		return nodemonitoringconfig.Override{}, err
	}
	if revision != nil {
		override.Revision = *revision
	}
	if port != nil && *port > 0 && *port <= 65535 {
		value := uint16(*port)
		override.MonitorPort = &value
	}
	return override, nil
}

// apply writes the log rows and moves each node's verdict: a node's round
// fails when every probed address with votes failed.
func (runner *Runner) apply(ctx context.Context, targets []Target, rounds map[string]RoundResult, settings Settings,
	interval time.Duration, now time.Time) error {
	byNode := map[uuid.UUID][]Target{}
	var order []uuid.UUID
	for _, target := range targets {
		if _, ok := byNode[target.NodeID]; !ok {
			order = append(order, target.NodeID)
		}
		byNode[target.NodeID] = append(byNode[target.NodeID], target)
	}
	var first error
	for _, nodeID := range order {
		if err := runner.applyNode(ctx, byNode[nodeID], rounds, settings, interval, now); err != nil && first == nil {
			first = err
		}
	}
	if _, err := runner.pool.Exec(ctx, `DELETE FROM node_dnspup_probe_results WHERE observed_at<$1`,
		now.Add(-ResultRetention)); err != nil && first == nil {
		first = err
	}
	return first
}

func (runner *Runner) applyNode(ctx context.Context, targets []Target, rounds map[string]RoundResult, settings Settings,
	interval time.Duration, now time.Time) error {
	nodeID, scopeID := targets[0].NodeID, targets[0].ScopeID
	return pgx.BeginFunc(ctx, runner.pool, func(tx pgx.Tx) error {
		decided, failed := false, true
		var failedChecks, totalChecks int
		for _, target := range targets {
			round, ok := rounds[target.key()]
			if !ok {
				continue
			}
			checkpoints, err := json.Marshal(round.Checkpoints)
			if err != nil {
				return err
			}
			if round.Checkpoints == nil {
				checkpoints = []byte("[]")
			}
			if _, err := tx.Exec(ctx, `INSERT INTO node_dnspup_probe_results(node_id,address,port,observed_at,
				total_checks,failed_checks,failed,checkpoints) VALUES($1,$2,$3,$4,$5,$6,$7,$8)
				ON CONFLICT DO NOTHING`, nodeID, target.Address.String(), int(target.Port), now, round.Total, round.Failed,
				round.RoundFailed(), checkpoints); err != nil {
				return err
			}
			if round.Total > 0 {
				decided = true
				failed = failed && round.RoundFailed()
				failedChecks += round.Failed
				totalChecks += round.Total
			}
		}
		var previous State
		var alertRevision int64
		var exists bool
		err := tx.QueryRow(ctx, `SELECT consecutive_failed,consecutive_ok,failing,observed_at,alert_revision
			FROM node_dnspup_probe_states WHERE node_id=$1 FOR UPDATE`, nodeID).Scan(&previous.ConsecutiveFailed,
			&previous.ConsecutiveOK, &previous.Failing, &previous.ObservedAt, &alertRevision)
		switch {
		case errors.Is(err, pgx.ErrNoRows):
		case err != nil:
			return err
		default:
			exists = true
		}
		if !decided {
			return nil
		}
		next := previous.Next(true, failed, settings, now)
		changed := exists && next.Failing != previous.Failing || !exists && next.Failing
		if changed {
			alertRevision++
		}
		if _, err := tx.Exec(ctx, `INSERT INTO node_dnspup_probe_states(node_id,consecutive_failed,consecutive_ok,failing,
				observed_at,fresh_until,alert_revision,updated_at) VALUES($1,$2,$3,$4,$5,$6,$7,$5)
			ON CONFLICT (node_id) DO UPDATE SET consecutive_failed=EXCLUDED.consecutive_failed,
				consecutive_ok=EXCLUDED.consecutive_ok,failing=EXCLUDED.failing,observed_at=EXCLUDED.observed_at,
				fresh_until=EXCLUDED.fresh_until,alert_revision=EXCLUDED.alert_revision,updated_at=EXCLUDED.updated_at`,
			nodeID, next.ConsecutiveFailed, next.ConsecutiveOK, next.Failing, now, now.Add(FreshFor(interval)),
			alertRevision); err != nil {
			return err
		}
		if !changed {
			return nil
		}
		if err := runner.auditor.Append(ctx, tx, audit.Event{ScopeID: scopeID, Action: ActionNodeVerdict,
			ResourceType: "node", ResourceID: nodeID.String(), RequestID: ActionNodeVerdict + "." + uuid.NewString(),
			Result: "success", ActorKind: "system", ActorRef: "job:node_dnspup_probe",
			Payload: map[string]any{"actor": "system", "ip": "", "changes": map[string]any{
				"dnspup_failing": map[string]any{"before": previous.Failing, "after": next.Failing}},
				"failed_checks": failedChecks, "total_checks": totalChecks}}); err != nil {
			return err
		}
		return runner.alertNode(ctx, tx, nodeID, scopeID, next.Failing, alertRevision, failedChecks, totalChecks, now)
	})
}

func (runner *Runner) alertNode(ctx context.Context, tx pgx.Tx, nodeID, scopeID uuid.UUID, failing bool, revision int64,
	failed, total int, now time.Time) error {
	if runner.alerts == nil {
		return nil
	}
	var name, address string
	var platform bool
	if err := tx.QueryRow(ctx, `SELECT node.name,COALESCE(host(node.ipv4),host(node.ipv6),'-'),
			scope.kind='platform' AND scope.tenant_id IS NULL
		FROM nodes node JOIN access_scopes scope ON scope.id=node.scope_id WHERE node.id=$1`, nodeID).Scan(&name,
		&address, &platform); err != nil {
		return err
	}
	if !platform {
		// Tenant-owned (marketplace seller) nodes are not alerted, like node offline alerts.
		return nil
	}
	sms := notification.TemplateContext{"node_name": notification.PublicValue(name), "node_ip": notification.PublicValue(address)}
	eventType := EventTypeRecovered
	if failing {
		eventType = EventTypeUnreachable
		sms["failed"] = notification.PublicValue(strconv.Itoa(failed))
		sms["total"] = notification.PublicValue(strconv.Itoa(total))
	}
	email := notification.TemplateContext{"occurred_at": notification.PublicValue(now.UTC().Format(time.RFC3339))}
	for key, value := range sms {
		email[key] = value
	}
	return runner.enqueue(ctx, tx, scopeID, nodeAlertPermission, eventType,
		"node-dnspup/"+nodeID.String()+"/"+strconv.FormatInt(revision, 10), sms, email)
}

// enqueue sends eventType to the scope members holding permission (in a
// savepoint: a notification failure never undoes the recorded state).
func (runner *Runner) enqueue(ctx context.Context, tx pgx.Tx, scopeID uuid.UUID, permission, eventType, source string,
	sms, email notification.TemplateContext) error {
	rows, err := tx.Query(ctx, `SELECT DISTINCT membership.user_id FROM memberships membership
		JOIN users member ON member.id=membership.user_id AND member.status='active'
		JOIN role_assignments assignment ON assignment.scope_id=membership.scope_id AND assignment.user_id=membership.user_id
		JOIN role_permissions grant_row ON grant_row.role_id=assignment.role_id AND grant_row.permission_name=$2
		WHERE membership.scope_id=$1 AND membership.status='active' ORDER BY membership.user_id`, scopeID, permission)
	if err != nil {
		return err
	}
	recipients, err := pgx.CollectRows(rows, pgx.RowTo[uuid.UUID])
	if err != nil {
		return err
	}
	templates := map[notification.Channel]notification.TemplateRef{
		notification.ChannelSMS:   {ID: eventType + ".zh-cn", Version: 1, Channel: notification.ChannelSMS},
		notification.ChannelEmail: {ID: eventType + ".zh-cn", Version: 1, Channel: notification.ChannelEmail},
	}
	savepoint, err := tx.Begin(ctx)
	if err != nil {
		return err
	}
	for _, recipient := range recipients {
		if _, err := runner.alerts.EnqueueTx(ctx, savepoint, notification.EnqueueRequest{ScopeID: scopeID,
			RecipientID: recipient, SourceEventID: source, EventType: eventType,
			Policy: notification.DeliverySystemRequired, Templates: templates,
			Contexts:       map[notification.Channel]notification.TemplateContext{notification.ChannelSMS: sms, notification.ChannelEmail: email},
			AuditRequestID: source}); err != nil {
			_ = savepoint.Rollback(ctx)
			runner.logger.Warn("dnspup node probe alert not enqueued", "event_type", eventType, "error", err)
			return nil
		}
	}
	return savepoint.Commit(ctx)
}

// changeBudget records a budget transition (CAS on the stored state) and
// tells the dnspup managers when the balance turns low or runs out.
func (runner *Runner) changeBudget(ctx context.Context, before, after string, account dnspupprobe.Account,
	settings Settings, now time.Time) error {
	return pgx.BeginFunc(ctx, runner.pool, func(tx pgx.Tx) error {
		var sequence int64
		err := tx.QueryRow(ctx, `UPDATE node_dnspup_probe_settings SET budget_state=$1,budget_checked_at=$2,
			budget_sequence=budget_sequence+1 WHERE singleton AND budget_state=$3 RETURNING budget_sequence`,
			after, now, before).Scan(&sequence)
		if errors.Is(err, pgx.ErrNoRows) {
			return nil
		}
		if err != nil {
			return err
		}
		var platform uuid.UUID
		err = tx.QueryRow(ctx, `SELECT id FROM access_scopes WHERE kind='platform' AND tenant_id IS NULL ORDER BY id LIMIT 1`).Scan(&platform)
		if errors.Is(err, pgx.ErrNoRows) {
			return nil
		}
		if err != nil {
			return err
		}
		remaining := max(account.MonthlyLimit-account.MonthlyUsed, 0)
		if err := runner.auditor.Append(ctx, tx, audit.Event{ScopeID: platform, Action: ActionBudget,
			ResourceType: "probe_dnspup", ResourceID: "probe_dnspup", RequestID: ActionBudget + "." + uuid.NewString(),
			Result: "success", ActorKind: "system", ActorRef: "job:node_dnspup_probe",
			Payload: map[string]any{"actor": "system", "ip": "", "changes": map[string]any{
				"budget_state": map[string]any{"before": before, "after": after}},
				"remaining": remaining, "monthly_limit": account.MonthlyLimit, "low_balance": settings.LowBalance}}); err != nil {
			return err
		}
		if runner.alerts == nil || after == BudgetNormal {
			return nil
		}
		eventType := EventTypeBalanceLow
		values := notification.TemplateContext{"link": notification.PublicValue(dnspupprobe.SettingsPagePath)}
		if after == BudgetExhausted {
			eventType = EventTypeBalanceExhausted
		} else {
			values["remaining"] = notification.PublicValue(strconv.FormatInt(remaining, 10))
			values["threshold"] = notification.PublicValue(strconv.FormatInt(settings.LowBalance, 10))
		}
		return runner.enqueue(ctx, tx, platform, budgetAlertPermission, eventType,
			"node-dnspup-budget/"+strconv.FormatInt(sequence, 10), values, values)
	})
}

// sortedGroups returns a copy sorted in catalog order (stable settings digest).
func sortedGroups(groups []string) []string {
	order := map[string]int{}
	for index, group := range allGroups {
		order[group] = index
	}
	out := append([]string(nil), groups...)
	sort.Slice(out, func(left, right int) bool { return order[out[left]] < order[out[right]] })
	return out
}
