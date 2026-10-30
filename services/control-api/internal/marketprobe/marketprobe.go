// Package marketprobe is the leaf side of node-market probing
// (docs/marketplace/05-scheduling-quality.md §3): it reports the probe-ready
// nodes of the pools this controller's own offers use, and relays the probe
// tasks the market assigns to those nodes through agent-gateway.
//
// Only nodes whose current session advertises CAPABILITY_NAME_MARKET_PROBE
// (v1 or later; v2 adds host targets for the aggregated edge) are reported:
// agents without it neither answer the probe path nor execute probes,
// and must not be counted as failures. A probe the agent skipped (refused
// address, rate limit, busy, expired) is never submitted as a vote.
package marketprobe

import (
	"context"
	"errors"
	"fmt"
	"log/slog"
	"net/netip"
	"slices"
	"sync"
	"time"

	contract "github.com/cdnca/cdnca/libs/edgeconfig/marketprobe"
	"github.com/cdnca/cdnca/libs/marketproto/nodeaction"
	"github.com/cdnca/cdnca/libs/marketproto/nodeload"
	agentv1 "github.com/cdnca/cdnca/proto/gen/go/agent/v1"
	commonv1 "github.com/cdnca/cdnca/proto/gen/go/common/v1"
	"github.com/cdnca/cdnca/services/control-api/internal/marketclient"
	"github.com/cdnca/cdnca/services/control-api/internal/marketsupplyguard"
	"github.com/google/uuid"
	"github.com/jackc/pgx/v5"
	"github.com/jackc/pgx/v5/pgxpool"
	"google.golang.org/protobuf/proto"
	"google.golang.org/protobuf/types/known/timestamppb"
)

// ErrOffline means the node has no live gateway session.
var ErrOffline = errors.New("market probe: node is offline")

// Market is the subset of marketclient.Client this package drives.
type Market interface {
	OwnOffers(ctx context.Context) ([]marketclient.OwnOffer, error)
	ReportPoolNodes(ctx context.Context, pool string, nodes []marketclient.PoolNode, online *int) error
	ProbeTasks(ctx context.Context) ([]marketclient.ProbeTask, error)
	SubmitProbeResults(ctx context.Context, results []marketclient.ProbeResult) (int, error)
	ReportNodeLoad(ctx context.Context, self marketclient.Identity, report nodeload.Report) (marketclient.NodeLoadResult, error)
	ReportNodeActions(ctx context.Context, self marketclient.Identity, report nodeaction.Report) (marketclient.NodeActionResult, error)
}

// Requester sends one encoded MarketProbeCommand to a node's gateway session
// and returns the encoded reply (empty when the gateway refused).
type Requester interface {
	Request(ctx context.Context, nodeID string, command []byte) ([]byte, error)
}

type Config struct {
	InventoryEvery time.Duration // default 5m
	DispatchEvery  time.Duration // default 30s
	Concurrency    int           // nodes probed in parallel, default 16
	Now            func() time.Time
	// Identity returns the registered member (zero until registered); node
	// load reports are signed with its key. Nil turns load reporting off.
	Identity func() marketclient.Identity
	// Plugins returns each node's licensed and installed node plugins
	// (marketsupply.SupplyGroups.NodePluginCodes); reported per node so the
	// market can bound an offer's plugins (ADR 0012, ML-02). Nil reports none.
	Plugins NodePlugins
	// Serving reports whether a pool still has normal subscribers
	// (marketsupply.SupplyGroups.PoolServing). Such a pool keeps being
	// reported when only delisted offers use it: delisting stops new sales,
	// not the supply already sold (ADR 0012 §18.4, U3). Nil: none serve.
	Serving PoolServing
	// Grants resolves a market key to its current grant, for whole-node
	// actions on market sites (ADR 0012 §19.4). Nil reports them without a site.
	Grants GrantResolver
}

// PoolServing reports whether a node pool still serves subscribers.
type PoolServing interface {
	PoolServing(ctx context.Context, ref string) (bool, error)
}

// NodePlugins reads the market plugin codes each node has.
type NodePlugins interface {
	NodePluginCodes(ctx context.Context, nodeIDs []uuid.UUID) (map[uuid.UUID][]string, error)
}

type Service struct {
	pool   *pgxpool.Pool
	market Market
	nodes  Requester
	cfg    Config
	log    *slog.Logger

	mu        sync.Mutex
	known     map[string]bool      // probe-ready node IDs last reported
	benchable map[string]bool      // of those, the ones that run benchmarks (capability 34)
	pools     map[string][]string  // pool → node IDs last reported (node load, ADR 0012 §6.1)
	logged    map[string]time.Time // rate limit for skip reasons
	// legacyMarket: the market predates benchmarks (rejected the
	// benchmark inventory field or has no benchmark routes); benchmark
	// reporting and relay stay off for this process.
	legacyMarket bool
}

func New(pool *pgxpool.Pool, market Market, nodes Requester, cfg Config, log *slog.Logger) *Service {
	if cfg.InventoryEvery <= 0 {
		cfg.InventoryEvery = 5 * time.Minute
	}
	if cfg.DispatchEvery <= 0 {
		cfg.DispatchEvery = 30 * time.Second
	}
	if cfg.Concurrency <= 0 {
		cfg.Concurrency = 16
	}
	if cfg.Now == nil {
		cfg.Now = time.Now
	}
	return &Service{pool: pool, market: market, nodes: nodes, cfg: cfg, log: log,
		known: map[string]bool{}, benchable: map[string]bool{}, logged: map[string]time.Time{}}
}

// Run reports inventory and relays probe tasks until ctx ends.
func (s *Service) Run(ctx context.Context) error {
	var lastInventory, lastLoad time.Time
	timer := time.NewTimer(0)
	defer timer.Stop()
	for {
		select {
		case <-ctx.Done():
			return ctx.Err()
		case <-timer.C:
		}
		if s.cfg.Now().Sub(lastInventory) >= s.cfg.InventoryEvery {
			if err := s.SyncInventory(ctx); err != nil && ctx.Err() == nil {
				s.log.Warn("market probe inventory failed", "err", err)
			} else {
				lastInventory = s.cfg.Now()
			}
		}
		// Node load once per closed minute (ADR 0012 §6.1), after the
		// inventory so only nodes the market knows are reported.
		if minute := s.cfg.Now().UTC().Truncate(time.Minute); minute.After(lastLoad) && !lastInventory.IsZero() {
			if _, err := s.ReportLoad(ctx, minute); err != nil && ctx.Err() == nil {
				s.log.Warn("market node load report failed", "err", err)
			}
			lastLoad = minute
			// Whole-node actions once a minute too (ADR 0012 §19.3).
			if _, err := s.ReportNodeActions(ctx); err != nil && ctx.Err() == nil {
				s.log.Warn("market node action report failed", "err", err)
			}
		}
		if _, err := s.Dispatch(ctx); err != nil && ctx.Err() == nil {
			s.log.Warn("market probe dispatch failed", "err", err)
		}
		if _, err := s.DispatchBenchmarks(ctx); err != nil && ctx.Err() == nil {
			s.log.Warn("market benchmark dispatch failed", "err", err)
		}
		timer.Reset(s.cfg.DispatchEvery)
	}
}

// skip logs why a node or task is left out, at most once an hour per key.
func (s *Service) skip(key, reason string, attrs ...any) {
	s.mu.Lock()
	now := s.cfg.Now()
	last, seen := s.logged[key+"\x00"+reason]
	if seen && now.Sub(last) < time.Hour {
		s.mu.Unlock()
		return
	}
	s.logged[key+"\x00"+reason] = now
	s.mu.Unlock()
	s.log.Info("market probe skipped", append([]any{"key", key, "reason", reason}, attrs...)...)
}

// candidate is one serving line endpoint of a pool, before filtering.
type candidate struct {
	NodeID       uuid.UUID
	Address      netip.Addr
	Region       string
	Carrier      string
	Capabilities []byte
	// Role is node_presence.market_probe_role of the latest heartbeat; only
	// join_market nodes take part in the node market (nil: not reported).
	Role *string
}

// SyncInventory reports the probe-ready nodes of every pool used by an offer
// that is not delisted or still serving subscribers (Config.Serving), and an
// empty list for other pools only delisted offers use.
func (s *Service) SyncInventory(ctx context.Context) error {
	offers, err := s.market.OwnOffers(ctx)
	if err != nil {
		return err
	}
	active, retired := map[string]bool{}, map[string]bool{}
	for _, offer := range offers {
		for _, component := range offer.Components {
			if component.Kind != "own_pool" || component.NodePoolRef == "" {
				continue
			}
			if offer.Status == "delisted" {
				retired[component.NodePoolRef] = true
			} else {
				active[component.NodePoolRef] = true
			}
		}
	}
	var errs []error
	for _, ref := range sortedKeys(retired) {
		if active[ref] || s.cfg.Serving == nil {
			continue
		}
		serving, err := s.cfg.Serving.PoolServing(ctx, ref)
		if err != nil {
			// Unknown: keep reporting rather than pull a sold supply from DNS.
			errs = append(errs, fmt.Errorf("pool %s serving: %w", ref, err))
		}
		if serving || err != nil {
			active[ref] = true
		}
	}
	known, benchable, pools := map[string]bool{}, map[string]bool{}, map[string][]string{}
	for _, ref := range sortedKeys(active) {
		candidates, err := s.loadCandidates(ctx, ref)
		if err != nil {
			errs = append(errs, fmt.Errorf("pool %s: %w", ref, err))
			continue
		}
		nodes := s.filter(ref, candidates)
		if err := s.withPlugins(ctx, nodes); err != nil {
			errs = append(errs, fmt.Errorf("pool %s plugins: %w", ref, err))
			continue
		}
		online, err := s.onlineAvailable(ctx, ref)
		if err != nil {
			errs = append(errs, fmt.Errorf("pool %s online nodes: %w", ref, err))
			continue
		}
		if err := s.reportPool(ctx, ref, nodes, online); err != nil {
			errs = append(errs, fmt.Errorf("report pool %s: %w", ref, err))
			continue
		}
		for _, node := range nodes {
			pools[ref] = append(pools[ref], node.NodeID)
			known[node.NodeID] = true
			benchable[node.NodeID] = node.Benchmark
		}
	}
	for _, ref := range sortedKeys(retired) {
		if active[ref] {
			continue
		}
		if err := s.market.ReportPoolNodes(ctx, ref, nil, nil); err != nil {
			errs = append(errs, fmt.Errorf("clear pool %s: %w", ref, err))
		}
	}
	s.mu.Lock()
	s.known, s.benchable, s.pools = known, benchable, pools
	s.mu.Unlock()
	return errors.Join(errs...)
}

// withPlugins fills each node's plugins. A pool whose plugins cannot be read
// is not reported this round: reporting it without them would make the
// market mark the offers' plugins unavailable.
func (s *Service) withPlugins(ctx context.Context, nodes []marketclient.PoolNode) error {
	if s.cfg.Plugins == nil || len(nodes) == 0 {
		return nil
	}
	ids := make([]uuid.UUID, len(nodes))
	for i, node := range nodes {
		ids[i] = uuid.MustParse(node.NodeID)
	}
	codes, err := s.cfg.Plugins.NodePluginCodes(ctx, ids)
	if err != nil {
		return err
	}
	for i := range nodes {
		nodes[i].Plugins = codes[ids[i]]
	}
	return nil
}

// reportPool reports one pool. An older market rejects the benchmark field
// (strict JSON: 400 invalid_json); then the report is sent again without it
// and benchmarks stay off, so a controller upgraded before its market keeps
// reporting inventory.
func (s *Service) reportPool(ctx context.Context, ref string, nodes []marketclient.PoolNode, online *int) error {
	s.mu.Lock()
	legacy := s.legacyMarket
	s.mu.Unlock()
	if legacy {
		nodes = withoutBenchmark(nodes)
	}
	err := s.market.ReportPoolNodes(ctx, ref, nodes, online)
	if status, code, rejected := marketclient.Rejected(err); !legacy && rejected && status == 400 && code == "invalid_json" &&
		slices.ContainsFunc(nodes, func(n marketclient.PoolNode) bool { return n.Benchmark }) {
		s.markLegacyMarket("inventory_benchmark_field_rejected")
		return s.market.ReportPoolNodes(ctx, ref, withoutBenchmark(nodes), online)
	}
	return err
}

// onlineAvailable is the pool's online available node count (same count as
// the ML-18 guard), nil for a pool that is not a local line group.
func (s *Service) onlineAvailable(ctx context.Context, ref string) (*int, error) {
	groupID, err := uuid.Parse(ref)
	if err != nil {
		return nil, nil
	}
	n, err := marketsupplyguard.OnlineAvailable(ctx, s.pool, groupID)
	if err != nil {
		return nil, err
	}
	return &n, nil
}

func withoutBenchmark(nodes []marketclient.PoolNode) []marketclient.PoolNode {
	out := slices.Clone(nodes)
	for i := range out {
		out[i].Benchmark = false
	}
	return out
}

// markLegacyMarket turns benchmark relay off for an older market.
func (s *Service) markLegacyMarket(reason string) {
	s.mu.Lock()
	already := s.legacyMarket
	s.legacyMarket = true
	s.mu.Unlock()
	if !already {
		s.log.Info("market does not support node benchmarks; benchmark relay off", "reason", reason)
	}
}

// loadCandidates reads the serving endpoints of a local node group on its
// current revision, with each node's latest session capabilities.
func (s *Service) loadCandidates(ctx context.Context, ref string) ([]candidate, error) {
	groupID, err := uuid.Parse(ref)
	if err != nil {
		s.skip(ref, "pool_not_local_group")
		return nil, nil
	}
	rows, err := s.pool.Query(ctx, `SELECT serving.node_id, host(serving.address), endpoint.region, endpoint.carrier,
			(SELECT facts.capabilities_snapshot FROM node_session_capabilities facts WHERE facts.node_id=serving.node_id
			 ORDER BY facts.session_epoch DESC LIMIT 1),
			(SELECT presence.market_probe_role FROM node_presence presence WHERE presence.node_id=serving.node_id)
		FROM node_line_groups line_group
		JOIN access_scopes scope ON scope.id=line_group.tenant_scope_id AND scope.kind='platform'
		JOIN node_line_endpoint_serving serving ON serving.tenant_scope_id=line_group.tenant_scope_id
		  AND serving.line_group_id=line_group.id AND serving.config_revision=line_group.current_revision AND serving.serving
		JOIN node_line_endpoints endpoint ON endpoint.tenant_scope_id=serving.tenant_scope_id
		  AND endpoint.line_group_id=serving.line_group_id AND endpoint.config_revision=serving.config_revision
		  AND endpoint.id=serving.endpoint_id
		JOIN nodes node ON node.id=serving.node_id AND node.admin_state='active'
		WHERE line_group.id=$1 AND line_group.deleted_at IS NULL
		ORDER BY serving.node_id, serving.address_family, serving.address`, groupID)
	if err != nil {
		return nil, err
	}
	return pgx.CollectRows(rows, func(row pgx.CollectableRow) (candidate, error) {
		var c candidate
		var address string
		if err := row.Scan(&c.NodeID, &address, &c.Region, &c.Carrier, &c.Capabilities, &c.Role); err != nil {
			return candidate{}, err
		}
		parsed, parseErr := netip.ParseAddr(address)
		c.Address = parsed
		return c, parseErr
	})
}

// roleJoinMarket is nodepresence.MarketProbeRoleJoinMarket (the heartbeat's
// MARKET_PROBE_ROLE_JOIN_MARKET as stored).
const roleJoinMarket = "join_market"

// filter keeps one public address per probe-capable, join_market node whose region and
// carrier map, preferring IPv4; everything left out is logged with a reason.
func (s *Service) filter(ref string, candidates []candidate) []marketclient.PoolNode {
	var out []marketclient.PoolNode
	seen := map[uuid.UUID]bool{}
	for _, c := range candidates {
		if seen[c.NodeID] {
			continue
		}
		key := c.NodeID.String()
		if !probeCapable(c.Capabilities) {
			seen[c.NodeID] = true
			s.skip(key, "agent_lacks_market_probe", "pool", ref)
			continue
		}
		// A probe-only (installer default), disabled or older Agent does
		// not join the node market even when its line group is in an offer.
		if c.Role == nil || *c.Role != roleJoinMarket {
			seen[c.NodeID] = true
			s.skip(key, "node_not_join_market", "pool", ref)
			continue
		}
		if !contract.Public(c.Address) {
			s.skip(key, "address_not_public", "pool", ref, "address", c.Address.String())
			continue // a later endpoint of the same node may be public
		}
		seen[c.NodeID] = true
		region, okRegion := Region(c.Region)
		carrier, okCarrier := Carrier(c.Carrier)
		if !okRegion {
			s.skip(key, reasonRegion, "pool", ref, "region", c.Region)
			continue
		}
		if !okCarrier {
			s.skip(key, reasonCarrier, "pool", ref, "carrier", c.Carrier)
			continue
		}
		out = append(out, marketclient.PoolNode{NodeID: key, IP: c.Address.Unmap().String(), Region: region, Carrier: carrier,
			Benchmark: hasCapability(c.Capabilities, agentv1.CapabilityName_CAPABILITY_NAME_MARKET_BENCHMARK)})
	}
	return out
}

// HostProbeVersion is the MARKET_PROBE version that executes host targets
// (third-party CDN access names, ADR 0008 §6.2).
const HostProbeVersion = 2

func probeCapable(snapshot []byte) bool {
	return hasCapability(snapshot, agentv1.CapabilityName_CAPABILITY_NAME_MARKET_PROBE)
}

// hasCapability reports whether a session snapshot advertises name v1 or later.
func hasCapability(snapshot []byte, name agentv1.CapabilityName) bool {
	return HasCapability(snapshot, name, 1)
}

// HasCapability reports whether a session snapshot advertises name at
// minVersion or later.
func HasCapability(snapshot []byte, name agentv1.CapabilityName, minVersion uint32) bool {
	if len(snapshot) == 0 {
		return false
	}
	var capabilities agentv1.AgentCapabilities
	if proto.Unmarshal(snapshot, &capabilities) != nil {
		return false
	}
	return slices.ContainsFunc(capabilities.Features, func(c *agentv1.Capability) bool {
		return c.GetName() == name && c.GetApiVersion() >= minVersion
	})
}

// Dispatch relays the open tasks of this member's probe-ready nodes and
// submits what was actually probed. It returns the number of accepted results.
func (s *Service) Dispatch(ctx context.Context) (int, error) {
	tasks, err := s.market.ProbeTasks(ctx)
	if err != nil || len(tasks) == 0 {
		return 0, err
	}
	now := s.cfg.Now()
	s.mu.Lock()
	known := s.known
	s.mu.Unlock()
	byNode := map[string][]marketclient.ProbeTask{}
	for _, task := range tasks {
		if reason := admitTask(task, known, now); reason != "" {
			s.skip(task.ProberNodeID, reason)
			continue
		}
		byNode[task.ProberNodeID] = append(byNode[task.ProberNodeID], task)
	}
	var (
		mu      sync.Mutex
		results []marketclient.ProbeResult
		wg      sync.WaitGroup
		slots   = make(chan struct{}, s.cfg.Concurrency)
	)
	for _, nodeID := range sortedKeys(byNode) {
		for chunk := range slices.Chunk(byNode[nodeID], contract.MaxTargets) {
			slots <- struct{}{}
			wg.Add(1)
			go func() {
				defer func() { <-slots; wg.Done() }()
				probed := s.probe(ctx, nodeID, chunk)
				mu.Lock()
				results = append(results, probed...)
				mu.Unlock()
			}()
		}
	}
	wg.Wait()
	accepted := 0
	for batch := range slices.Chunk(results, 1000) {
		n, err := s.market.SubmitProbeResults(ctx, batch)
		accepted += n
		if err != nil {
			return accepted, err
		}
	}
	return accepted, nil
}

// admitTask returns why a task cannot be relayed, or "".
func admitTask(task marketclient.ProbeTask, known map[string]bool, now time.Time) string {
	switch {
	case !known[task.ProberNodeID]:
		return "prober_not_reported"
	case task.Path != contract.Path:
		return "probe_path_unsupported"
	case task.Port != 80 && task.Port != 443:
		return "probe_port_unsupported"
	case !now.Before(task.ExpiresAt):
		return "task_expired"
	}
	ip, err := netip.ParseAddr(task.TargetIP)
	if err != nil || !contract.Public(ip) {
		return "target_not_public"
	}
	return ""
}

// probe sends one command for tasks (one node, at most MaxTargets) and maps
// the reply to results; anything not executed yields no result.
func (s *Service) probe(ctx context.Context, nodeID string, tasks []marketclient.ProbeTask) []marketclient.ProbeResult {
	expires := tasks[0].ExpiresAt
	timeout := tasks[0].TimeoutMillis
	targets := make([]*agentv1.MarketProbeTarget, len(tasks))
	for i, task := range tasks {
		if task.ExpiresAt.Before(expires) {
			expires = task.ExpiresAt
		}
		timeout = min(timeout, task.TimeoutMillis)
		targets[i] = &agentv1.MarketProbeTarget{TaskId: task.RoundID.String(), Ip: task.TargetIP, Port: uint32(task.Port)}
	}
	timeout = max(contract.MinTimeoutMillis, min(contract.MaxTimeoutMillis, timeout))
	command := &agentv1.MarketProbeCommand{
		Event:  &commonv1.EventMetadata{EventId: uuid.NewString(), RequestId: uuid.NewString(), OccurredTime: timestamppb.New(s.cfg.Now())},
		NodeId: nodeID, Targets: targets, TimeoutMillis: uint32(timeout), ExpireTime: timestamppb.New(expires),
	}
	payload, err := proto.MarshalOptions{Deterministic: true}.Marshal(command)
	if err != nil {
		return nil
	}
	ctx, cancel := context.WithDeadline(ctx, expires)
	defer cancel()
	reply, err := s.nodes.Request(ctx, nodeID, payload)
	if err != nil {
		if !errors.Is(err, ErrOffline) && !errors.Is(err, context.DeadlineExceeded) {
			s.log.Warn("market probe request failed", "node", nodeID, "err", err)
		}
		return nil
	}
	if len(reply) == 0 {
		s.skip(nodeID, "gateway_refused")
		return nil
	}
	var result agentv1.MarketProbeResult
	if proto.Unmarshal(reply, &result) != nil || result.NodeId != nodeID ||
		result.CommandEventId != command.Event.EventId || len(result.Results) != len(tasks) {
		s.skip(nodeID, "invalid_result")
		return nil
	}
	var out []marketclient.ProbeResult
	for i, item := range result.Results {
		if item.GetTaskId() != targets[i].TaskId {
			s.skip(nodeID, "invalid_result")
			return nil
		}
		switch item.Outcome {
		case agentv1.MarketProbeOutcome_MARKET_PROBE_OUTCOME_OK:
			out = append(out, marketclient.ProbeResult{RoundID: tasks[i].RoundID, ProberNodeID: nodeID, OK: true,
				LatencyMs: int(item.LatencyMillis)})
		case agentv1.MarketProbeOutcome_MARKET_PROBE_OUTCOME_FAILED:
			out = append(out, marketclient.ProbeResult{RoundID: tasks[i].RoundID, ProberNodeID: nodeID, OK: false,
				LatencyMs: int(item.LatencyMillis)})
		default:
			s.skip(nodeID, "agent_skipped_"+item.ErrorCode)
		}
	}
	return out
}

func sortedKeys[V any](m map[string]V) []string {
	keys := make([]string, 0, len(m))
	for key := range m {
		keys = append(keys, key)
	}
	slices.Sort(keys)
	return keys
}
