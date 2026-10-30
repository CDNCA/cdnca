package nodeprobe

import (
	"context"
	"errors"
	"log/slog"
	"net/netip"
	"slices"
	"sort"
	"sync"
	"time"

	agentv1 "github.com/cdnca/cdnca/proto/gen/go/agent/v1"
	"github.com/cdnca/cdnca/services/control-api/internal/marketprobe"
	"github.com/cdnca/cdnca/services/control-api/internal/nodemonitoringconfig"
	"github.com/cdnca/cdnca/services/control-api/internal/nodescheduler"
	"github.com/cdnca/cdnca/services/control-api/internal/nodeserving"
	"github.com/cdnca/cdnca/services/control-api/internal/systemconfig"
	"github.com/google/uuid"
	"github.com/jackc/pgx/v5"
	"github.com/jackc/pgx/v5/pgxpool"
)

const (
	// probersPerGroup peers vote per group and endpoint each round.
	probersPerGroup = 3
	// minPeersPerEndpoint peers vote per endpoint when that many are online,
	// whatever their location.
	minPeersPerEndpoint = 5
	peerConcurrency     = 16
	ctlConcurrency      = 64
	defaultTimeout      = 3 * time.Second
)

// Recorder records one endpoint verdict (nodescheduler.Service.RecordProbe).
type Recorder interface {
	RecordProbe(context.Context, nodescheduler.ProbeRequest) (nodescheduler.ProbeResult, error)
}

// Runner runs probe rounds.
type Runner struct {
	pool       *pgxpool.Pool
	recorder   Recorder
	holds      *nodeserving.Store
	controller *ControllerProber
	peers      *PeerProber
	now        func() time.Time
	logger     *slog.Logger
}

type Config struct {
	Pool       *pgxpool.Pool
	Recorder   Recorder
	Holds      *nodeserving.Store
	Controller *ControllerProber
	// Peers may be nil (no NATS connection): only the controller votes.
	Peers  *PeerProber
	Now    func() time.Time
	Logger *slog.Logger
}

func NewRunner(config Config) (*Runner, error) {
	if config.Pool == nil || config.Recorder == nil || config.Holds == nil || config.Controller == nil {
		return nil, errors.New("node probe runner requires pool, recorder, holds and a controller prober")
	}
	if config.Now == nil {
		config.Now = time.Now
	}
	if config.Logger == nil {
		config.Logger = slog.Default()
	}
	return &Runner{pool: config.Pool, recorder: config.Recorder, holds: config.Holds, controller: config.Controller,
		peers: config.Peers, now: config.Now, logger: config.Logger}, nil
}

// Run ticks until ctx ends.
func (runner *Runner) Run(ctx context.Context, interval time.Duration) {
	if interval <= 0 {
		interval = 30 * time.Second
	}
	ticker := time.NewTicker(interval)
	defer ticker.Stop()
	for {
		if err := runner.RunOnce(ctx); err != nil && ctx.Err() == nil {
			runner.logger.Warn("node external probe round failed", "error", err)
		}
		select {
		case <-ctx.Done():
			return
		case <-ticker.C:
		}
	}
}

// endpoint is one published endpoint of a current line-group revision.
type endpoint struct {
	scopeID, groupID, endpointID, nodeID uuid.UUID
	nodeScopeID                          uuid.UUID
	revision, lastSequence               int64
	address                              netip.Addr
	port                                 uint16
	region, carrier                      string
}

func (point endpoint) key() string { return point.endpointID.String() }

type policy struct {
	active  bool
	enabled bool
	value   systemconfig.NodeMonitoringConfiguration
}

// RunOnce probes every published node endpoint once and applies the verdicts.
func (runner *Runner) RunOnce(ctx context.Context) error {
	endpoints, policies, err := runner.load(ctx)
	if err != nil {
		return err
	}
	byNode := map[uuid.UUID][]endpoint{}
	for _, point := range endpoints {
		byNode[point.nodeID] = append(byNode[point.nodeID], point)
	}
	votes := runner.collect(ctx, endpoints, policies, byNode)
	if ctx.Err() != nil {
		return ctx.Err()
	}
	var first error
	nodeVerdicts := map[uuid.UUID][]Verdict{}
	var logged []logEntry
	for _, point := range endpoints {
		effective := policies[point.nodeID]
		if !effective.active || !effective.enabled {
			continue
		}
		ratio := 0
		if effective.value.FailureRatio != nil {
			ratio = int(*effective.value.FailureRatio)
		}
		verdict := Decide(votes[point.key()], ratio)
		nodeVerdicts[point.nodeID] = append(nodeVerdicts[point.nodeID], verdict)
		if verdict.Decided {
			logged = append(logged, logEntry{point: point, verdict: verdict, votes: votes[point.key()]})
		}
		if !verdict.Decided {
			continue
		}
		_, err := runner.recorder.RecordProbe(ctx, nodescheduler.ProbeRequest{TenantScopeID: point.scopeID,
			GroupID: point.groupID, Revision: point.revision, EndpointID: point.endpointID,
			Sequence: point.lastSequence + 1, ObservedAt: runner.now().UTC(), Healthy: verdict.Healthy})
		if err != nil && !errors.Is(err, nodescheduler.ErrRevisionConflict) && !errors.Is(err, nodescheduler.ErrStaleProbe) &&
			first == nil {
			first = err
		}
	}
	if err := runner.applyHolds(ctx, byNode, policies, nodeVerdicts); err != nil && first == nil {
		first = err
	}
	if err := runner.writeLog(ctx, logged); err != nil && first == nil {
		first = err
	}
	return first
}

func (runner *Runner) load(ctx context.Context) ([]endpoint, map[uuid.UUID]policy, error) {
	tx, err := runner.pool.BeginTx(ctx, pgx.TxOptions{IsoLevel: pgx.RepeatableRead, AccessMode: pgx.ReadOnly})
	if err != nil {
		return nil, nil, err
	}
	defer func() { _ = tx.Rollback(context.Background()) }()
	rows, err := tx.Query(ctx, `SELECT published.tenant_scope_id,published.line_group_id,published.config_revision,
			published.endpoint_id,published.node_id,node.scope_id,host(published.address),endpoint.port,
			endpoint.region,endpoint.carrier,health.last_sequence
		FROM node_line_endpoint_published published
		JOIN node_line_groups line_group ON line_group.tenant_scope_id=published.tenant_scope_id
		 AND line_group.id=published.line_group_id AND line_group.current_revision=published.config_revision
		 AND line_group.deleted_at IS NULL
		JOIN node_line_endpoints endpoint ON endpoint.tenant_scope_id=published.tenant_scope_id
		 AND endpoint.line_group_id=published.line_group_id AND endpoint.config_revision=published.config_revision
		 AND endpoint.id=published.endpoint_id
		JOIN node_line_endpoint_health health ON health.tenant_scope_id=published.tenant_scope_id
		 AND health.line_group_id=published.line_group_id AND health.config_revision=published.config_revision
		 AND health.endpoint_id=published.endpoint_id
		JOIN nodes node ON node.id=published.node_id AND node.admin_state IN ('active','draining')
		WHERE published.node_id IS NOT NULL AND endpoint.enabled
		ORDER BY published.node_id,published.endpoint_id`)
	if err != nil {
		return nil, nil, err
	}
	var endpoints []endpoint
	for rows.Next() {
		var point endpoint
		var address string
		var port int32
		if err := rows.Scan(&point.scopeID, &point.groupID, &point.revision, &point.endpointID, &point.nodeID,
			&point.nodeScopeID, &address, &port, &point.region, &point.carrier, &point.lastSequence); err != nil {
			rows.Close()
			return nil, nil, err
		}
		parsed, err := netip.ParseAddr(address)
		if err != nil || port < 1 || port > 65535 {
			continue
		}
		point.address, point.port = parsed, uint16(port)
		endpoints = append(endpoints, point)
	}
	rows.Close()
	if err := rows.Err(); err != nil {
		return nil, nil, err
	}
	scopes := map[uuid.UUID]policy{}
	policies := map[uuid.UUID]policy{}
	for _, point := range endpoints {
		if _, done := policies[point.nodeID]; done {
			continue
		}
		base, ok := scopes[point.nodeScopeID]
		if !ok {
			configuration, value, err := systemconfig.ReadActiveNodeMonitoring(ctx, tx, point.nodeScopeID)
			switch {
			case errors.Is(err, systemconfig.ErrPermissionDenied):
			case err != nil:
				return nil, nil, err
			default:
				base = policy{active: configuration.State == "active", value: value}
			}
			scopes[point.nodeScopeID] = base
		}
		effective := base
		if base.active {
			override, err := readOverride(ctx, tx, point.nodeID, point.nodeScopeID)
			if err != nil {
				return nil, nil, err
			}
			effective.value = nodemonitoringconfig.ApplyOverride(base.value, override)
			effective.enabled = effective.value.MonitorEnabled == nil || *effective.value.MonitorEnabled
		}
		policies[point.nodeID] = effective
	}
	return endpoints, policies, tx.Commit(ctx)
}

func readOverride(ctx context.Context, tx pgx.Tx, nodeID, scopeID uuid.UUID) (nodemonitoringconfig.Override, error) {
	var override nodemonitoringconfig.Override
	var revision *int64
	var protocol, action *string
	var timeout, port *int32
	err := tx.QueryRow(ctx, `SELECT revision,monitor_enabled,protocol,probe_timeout_ms,monitor_port,monitor_action
		FROM node_monitoring_overrides WHERE node_id=$1 AND scope_id=$2`, nodeID, scopeID).Scan(&revision,
		&override.MonitorEnabled, &protocol, &timeout, &port, &action)
	if errors.Is(err, pgx.ErrNoRows) {
		return nodemonitoringconfig.Override{}, nil
	}
	if err != nil {
		return nodemonitoringconfig.Override{}, err
	}
	if revision != nil {
		override.Revision = *revision
	}
	if protocol != nil {
		override.Protocol = *protocol
	}
	if action != nil {
		override.MonitorAction = *action
	}
	if timeout != nil {
		value := int(*timeout)
		override.ProbeTimeoutMS = &value
	}
	if port != nil && *port > 0 && *port <= 65535 {
		value := uint16(*port)
		override.MonitorPort = &value
	}
	if !nodemonitoringconfig.ValidOverride(override) {
		return nodemonitoringconfig.Override{}, nil
	}
	return override, nil
}

func probeTarget(point endpoint, value systemconfig.NodeMonitoringConfiguration) Target {
	protocol := "tcp"
	if value.Protocol == "http" {
		protocol = "http"
	}
	port := point.port
	if value.MonitorPort != nil && *value.MonitorPort > 0 {
		port = *value.MonitorPort
	}
	return Target{Key: point.key(), Address: point.address, Port: port, Protocol: protocol}
}

func probeTimeout(value systemconfig.NodeMonitoringConfiguration) time.Duration {
	if value.ProbeTimeoutMS > 0 {
		return time.Duration(value.ProbeTimeoutMS) * time.Millisecond
	}
	return defaultTimeout
}

// collect runs the controller probe of every monitored endpoint and, for each
// endpoint, asks up to probersPerGroup peers of every group (never the node
// itself) to probe it.
func (runner *Runner) collect(ctx context.Context, endpoints []endpoint, policies map[uuid.UUID]policy,
	byNode map[uuid.UUID][]endpoint) map[string][]Vote {
	var mu sync.Mutex
	votes := map[string][]Vote{}
	add := func(key string, vote Vote) {
		mu.Lock()
		votes[key] = append(votes[key], vote)
		mu.Unlock()
	}
	monitored := endpoints[:0:0]
	for _, point := range endpoints {
		if effective := policies[point.nodeID]; effective.active && effective.enabled {
			monitored = append(monitored, point)
		}
	}
	var wait sync.WaitGroup
	slots := make(chan struct{}, ctlConcurrency)
	for _, point := range monitored {
		wait.Add(1)
		slots <- struct{}{}
		go func(point endpoint) {
			defer wait.Done()
			defer func() { <-slots }()
			value := policies[point.nodeID].value
			started := time.Now()
			if ok, voted := runner.controller.Probe(ctx, probeTarget(point, value), probeTimeout(value)); voted {
				add(point.key(), Vote{Prober: ControllerProberID, Groups: []string{GroupDomestic}, OK: ok,
					LatencyMS: int(time.Since(started).Milliseconds())})
			}
		}(point)
	}
	if runner.peers != nil {
		assignments := runner.assignPeers(ctx, monitored, policies)
		peerSlots := make(chan struct{}, peerConcurrency)
		for peer, assignment := range assignments {
			wait.Add(1)
			peerSlots <- struct{}{}
			go func(peer string, assignment peerAssignment) {
				defer wait.Done()
				defer func() { <-peerSlots }()
				for key, answer := range runner.peers.Probe(ctx, peer, assignment.targets, assignment.timeout) {
					add(key, Vote{Prober: peer, Name: assignment.name, Address: assignment.address,
						Groups: assignment.groups, OK: answer.OK, LatencyMS: answer.LatencyMS})
				}
			}(peer, assignment)
		}
	}
	wait.Wait()
	return votes
}

type prober struct {
	id, name, address string
	// groups is nil when the peer's region and carrier are unknown: it only
	// fills endpoints up to minPeersPerEndpoint.
	groups []string
}

type peerAssignment struct {
	name, address string
	groups        []string
	targets       []Target
	timeout       time.Duration
}

// assignPeers picks the probing peers: online nodes running MARKET_PROBE
// (fix-probe: region/carrier no longer required). For each endpoint, first up
// to probersPerGroup peers of every selected monitoring group, then any other
// peer (unknown location included) until minPeersPerEndpoint vote, rotating
// by endpoint so the load spreads. Peers probe the endpoint IP on
// PeerProbePort.
func (runner *Runner) assignPeers(ctx context.Context, monitored []endpoint, policies map[uuid.UUID]policy) map[string]peerAssignment {
	candidates, err := runner.peerCandidates(ctx)
	if err != nil || len(candidates) == 0 {
		return nil
	}
	assignments := map[string]peerAssignment{}
	for _, point := range monitored {
		value := policies[point.nodeID].value
		selected := []string{GroupDomestic}
		if value.MonitorGroups != nil && len(*value.MonitorGroups) > 0 {
			selected = *value.MonitorGroups
		}
		target := probeTarget(point, value)
		target.Port, target.Protocol = PeerProbePort, "http"
		ordered := rotate(candidates, point.endpointID)
		chosen := map[string]bool{}
		assign := func(candidate prober) {
			chosen[candidate.id] = true
			assignment := assignments[candidate.id]
			assignment.name, assignment.address, assignment.groups = candidate.name, candidate.address, candidate.groups
			assignment.targets = append(assignment.targets, target)
			assignment.timeout = max(assignment.timeout, probeTimeout(value))
			assignments[candidate.id] = assignment
		}
		perGroup := map[string]int{}
		for _, candidate := range ordered {
			if candidate.id == point.nodeID.String() {
				continue
			}
			useful := false
			for _, group := range candidate.groups {
				if slices.Contains(selected, group) && perGroup[group] < probersPerGroup {
					useful = true
				}
			}
			if !useful {
				continue
			}
			for _, group := range candidate.groups {
				perGroup[group]++
			}
			assign(candidate)
		}
		for _, candidate := range ordered {
			if len(chosen) >= minPeersPerEndpoint {
				break
			}
			if candidate.id != point.nodeID.String() && !chosen[candidate.id] {
				assign(candidate)
			}
		}
	}
	return assignments
}

func rotate(candidates []prober, seed uuid.UUID) []prober {
	if len(candidates) == 0 {
		return nil
	}
	offset := int(seed[0])<<8 | int(seed[1])
	offset %= len(candidates)
	return append(append([]prober(nil), candidates[offset:]...), candidates[:offset]...)
}

func (runner *Runner) peerCandidates(ctx context.Context) ([]prober, error) {
	rows, err := runner.pool.Query(ctx, `SELECT DISTINCT ON (node.id) node.id::text,node.name,host(published.address),
			endpoint.region,endpoint.carrier,
			(SELECT facts.capabilities_snapshot FROM node_session_capabilities facts WHERE facts.node_id=node.id
			 ORDER BY facts.session_epoch DESC LIMIT 1)
		FROM nodes node
		JOIN node_presence presence ON presence.node_id=node.id AND presence.status='online'
		JOIN node_line_endpoint_published published ON published.node_id=node.id AND published.published
		JOIN node_line_endpoints endpoint ON endpoint.tenant_scope_id=published.tenant_scope_id
		 AND endpoint.line_group_id=published.line_group_id AND endpoint.config_revision=published.config_revision
		 AND endpoint.id=published.endpoint_id
		WHERE node.admin_state='active'
		  AND COALESCE((node.management_settings->>'external_probe')::boolean, true)
		ORDER BY node.id, published.address_family, published.address`)
	if err != nil {
		return nil, err
	}
	defer rows.Close()
	var candidates []prober
	for rows.Next() {
		var id, name, address, region, carrier string
		var snapshot []byte
		if err := rows.Scan(&id, &name, &address, &region, &carrier, &snapshot); err != nil {
			return nil, err
		}
		if !marketprobe.HasCapability(snapshot, agentv1.CapabilityName_CAPABILITY_NAME_MARKET_PROBE, 1) {
			continue
		}
		candidates = append(candidates, prober{id: id, name: name, address: address, groups: ProberGroups(region, carrier)})
	}
	sort.Slice(candidates, func(left, right int) bool { return candidates[left].id < candidates[right].id })
	return candidates, rows.Err()
}

// applyHolds puts a node whose every published endpoint is unhealthy in
// the line groups' health (after RecordProbe's thresholds and debounce) on
// the external_probe hold, and releases it once one is healthy again. The
// hold follows the monitoring failure action: with action "none" nothing is
// held. A node without a decided verdict this round keeps its state (the
// probe path is down, not the node).
func (runner *Runner) applyHolds(ctx context.Context, byNode map[uuid.UUID][]endpoint, policies map[uuid.UUID]policy,
	verdicts map[uuid.UUID][]Verdict) error {
	states, err := runner.healthStates(ctx)
	if err != nil {
		return err
	}
	holds, err := runner.currentHolds(ctx)
	if err != nil {
		return err
	}
	dnspup, err := runner.dnspupNodes(ctx)
	if err != nil {
		return err
	}
	var first error
	for nodeID, points := range byNode {
		effective := policies[nodeID]
		current := holds[nodeID]
		decided := false
		for _, verdict := range verdicts[nodeID] {
			decided = decided || verdict.Decided
		}
		want := current.held
		reason := current.reason
		switch {
		case !effective.active || !effective.enabled || effective.value.MonitorAction != "pause":
			want, reason = false, nodeserving.ReasonActionNone
		case dnspup[nodeID]:
			// A fresh dnspup verdict decides (with the Agent probe, in the
			// availability monitor); the peer probe is only logged.
			want, reason = false, ReasonDNSPupAuthoritative
		case !decided:
			continue
		default:
			healthy, unhealthy := 0, 0
			for _, point := range points {
				switch states[point.key()] {
				case nodescheduler.HealthHealthy:
					healthy++
				case nodescheduler.HealthUnhealthy:
					unhealthy++
				}
			}
			switch {
			case healthy > 0:
				want, reason = false, ReasonExternalRecovered
			case unhealthy == len(points):
				want, reason = true, ReasonExternalUnreachable
			default:
				continue
			}
		}
		if want == current.held {
			continue
		}
		detail := map[string]any{"endpoints": len(points)}
		failed, total := 0, 0
		for _, verdict := range verdicts[nodeID] {
			failed, total = failed+verdict.Failed(), total+verdict.Total()
		}
		if total > 0 {
			detail["failed_checks"], detail["total_checks"] = failed, total
		}
		if _, err := runner.holds.Apply(ctx, nodeID, points[0].nodeScopeID, nodeserving.SourceExternalProbe,
			current.revision, nodeserving.Decision{Held: want, Reason: reason, Detail: detail}); err != nil && first == nil {
			first = err
		}
	}
	return first
}

// Hold reasons of the external probe.
const (
	ReasonExternalUnreachable = "external_probe_unreachable"
	ReasonExternalRecovered   = "external_probe_recovered"
	// ReasonDNSPupAuthoritative releases the hold while dnspup decides.
	ReasonDNSPupAuthoritative = "dnspup_authoritative"
)

// dnspupNodes are the nodes with a fresh dnspup verdict
// (internal/nodednspupprobe; nodeserving.DecideMonitor reads the same rows).
func (runner *Runner) dnspupNodes(ctx context.Context) (map[uuid.UUID]bool, error) {
	rows, err := runner.pool.Query(ctx, `SELECT node_id FROM node_dnspup_probe_states WHERE fresh_until>clock_timestamp()`)
	if err != nil {
		return nil, err
	}
	defer rows.Close()
	nodes := map[uuid.UUID]bool{}
	for rows.Next() {
		var nodeID uuid.UUID
		if err := rows.Scan(&nodeID); err != nil {
			return nil, err
		}
		nodes[nodeID] = true
	}
	return nodes, rows.Err()
}

func (runner *Runner) healthStates(ctx context.Context) (map[string]string, error) {
	rows, err := runner.pool.Query(ctx, `SELECT health.endpoint_id::text,health.status
		FROM node_line_endpoint_health health JOIN node_line_groups line_group
		  ON line_group.tenant_scope_id=health.tenant_scope_id AND line_group.id=health.line_group_id
		 AND line_group.current_revision=health.config_revision AND line_group.deleted_at IS NULL`)
	if err != nil {
		return nil, err
	}
	defer rows.Close()
	states := map[string]string{}
	for rows.Next() {
		var key, status string
		if err := rows.Scan(&key, &status); err != nil {
			return nil, err
		}
		states[key] = status
	}
	return states, rows.Err()
}

type holdState struct {
	held     bool
	reason   string
	revision int64
}

func (runner *Runner) currentHolds(ctx context.Context) (map[uuid.UUID]holdState, error) {
	rows, err := runner.pool.Query(ctx, `SELECT node_id,held,reason_code,revision FROM node_serving_holds WHERE source=$1`,
		nodeserving.SourceExternalProbe)
	if err != nil {
		return nil, err
	}
	defer rows.Close()
	holds := map[uuid.UUID]holdState{}
	for rows.Next() {
		var nodeID uuid.UUID
		var state holdState
		if err := rows.Scan(&nodeID, &state.held, &state.reason, &state.revision); err != nil {
			return nil, err
		}
		holds[nodeID] = state
	}
	return holds, rows.Err()
}
