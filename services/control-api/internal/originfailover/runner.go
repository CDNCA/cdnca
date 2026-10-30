package originfailover

import (
	"context"
	"crypto/tls"
	"crypto/x509"
	"encoding/binary"
	"errors"
	"io"
	"log/slog"
	"net"
	"net/http"
	"net/netip"
	"net/url"
	"strconv"
	"strings"
	"sync"
	"syscall"
	"time"

	contract "github.com/cdnca/cdnca/libs/edgeconfig/marketprobe"
	agentv1 "github.com/cdnca/cdnca/proto/gen/go/agent/v1"
	commonv1 "github.com/cdnca/cdnca/proto/gen/go/common/v1"
	"github.com/cdnca/cdnca/services/control-api/internal/dnscustomhttp"
	"github.com/cdnca/cdnca/services/control-api/internal/dnspupprobe"
	"github.com/cdnca/cdnca/services/control-api/internal/marketprobe"
	"github.com/google/uuid"
	"github.com/jackc/pgx/v5/pgxpool"
	"google.golang.org/protobuf/proto"
	"google.golang.org/protobuf/types/known/timestamppb"
)

const (
	// RoundInterval is one probe round; RoundSites the sites per round
	// (least recently probed first).
	RoundInterval = 30 * time.Second
	RoundSites    = 500
	probeTimeout  = 5 * time.Second
	concurrency   = 16
	// PeerProbers is how many of the tenant's own nodes probe a site per
	// round; MinPeerVotes the OK/FAILED answers a node verdict needs.
	PeerProbers  = 3
	MinPeerVotes = 2
	// OriginProbeVersion is the MARKET_PROBE version that executes origin
	// targets (scheme, any port, IP or name, separate Host/SNI, custom CA).
	OriginProbeVersion = 3
)

// Target is one origin as the edge reaches it.
type Target struct {
	Host, HostHeader, ServerName, Path string
	Port                               int
	HTTPS                              bool
	CAPEM                              string // custom trust; empty: system roots
	// NoVerify: the pool does not verify the origin certificate (tls_trust
	// none, fix-originnoverify); only the control plane probes it so.
	NoVerify bool
}

// Prober probes one target.
type Prober interface {
	Probe(ctx context.Context, target Target) Outcome
}

// PeerProber asks a node to probe targets (MARKET_PROBE v3 origin targets);
// nil results are not votes.
type PeerProber interface {
	Probe(ctx context.Context, nodeID string, targets []Target) []*Outcome
}

// TargetOf is the target of origin in pool: the pool's scheme and port
// (follow: the plain-HTTP side on the origin's port), its origin Host,
// SNI and health check path.
func TargetOf(pool Pool, origin Origin) Target {
	target := Target{Host: origin.Host, Port: origin.Port, Path: pool.HealthCheckPath, HostHeader: pool.HostHeader(origin)}
	if pool.Scheme == "https" {
		target.HTTPS = true
		target.ServerName = pool.SNI
		if target.ServerName == "" {
			target.ServerName = target.HostHeader
		}
		if pool.Trust == "custom" {
			target.CAPEM = pool.CAPEM
		}
		target.NoVerify = pool.Trust == "none"
	}
	return target
}

// peerEligible: what a MARKET_PROBE v3 node executes (agent marketprobe
// admitOrigin); a wildcard Host/SNI, a CA past the carrier bound or an
// unverified origin (a node always verifies) is left to the control plane.
func peerEligible(target Target) bool {
	return !target.NoVerify && target.Host != "" && target.Port >= 1 && target.Port <= 65_535 && target.HostHeader != "" &&
		!strings.Contains(target.HostHeader, "*") && len(target.CAPEM) <= contract.MaxCAPEMBytes &&
		(!target.HTTPS || target.ServerName != "" && !strings.Contains(target.ServerName, "*"))
}

// SourcesFunc reads the probe source order and the dnspup source of a
// round (dnspupprobe.Service.Runtime).
type SourcesFunc func(context.Context) dnspupprobe.Runtime

type Runner struct {
	pool       *pgxpool.Pool
	store      *Store
	controller Prober
	peers      PeerProber
	sources    SourcesFunc
	now        func() time.Time
	logger     *slog.Logger
}

func NewRunner(pool *pgxpool.Pool, store *Store, controller Prober, peers PeerProber, logger *slog.Logger) *Runner {
	if logger == nil {
		logger = slog.Default()
	}
	now := time.Now
	if store != nil && store.now != nil {
		now = store.now // dnspup rounds follow the recorded probe times
	}
	return &Runner{pool: pool, store: store, controller: controller, peers: peers, now: now, logger: logger}
}

// WithSources sets the probe source order (module.probe.dnspup); without
// it the order is nodes, then the control plane.
func (runner *Runner) WithSources(sources SourcesFunc) *Runner {
	runner.sources = sources
	return runner
}

func (runner *Runner) Run(ctx context.Context, interval time.Duration) {
	ticker := time.NewTicker(interval)
	defer ticker.Stop()
	for {
		if err := runner.RunOnce(ctx); err != nil && ctx.Err() == nil {
			runner.logger.Warn("origin probe round failed", "error", err)
		}
		select {
		case <-ctx.Done():
			return
		case <-ticker.C:
		}
	}
}

// RunOnce probes the due pools and records each.
func (runner *Runner) RunOnce(ctx context.Context) error {
	pools, err := runner.store.DuePools(ctx, RoundSites)
	if err != nil {
		return err
	}
	nodes, err := runner.peerNodes(ctx)
	if err != nil {
		runner.logger.Warn("origin probe peers unavailable", "error", err)
	}
	plan := dnspupprobe.Runtime{OriginSources: []string{dnspupprobe.SourceNode, dnspupprobe.SourceController}}
	if runner.sources != nil {
		plan = runner.sources(ctx)
	}
	round := dnspupprobe.Round(runner.now(), RoundInterval)
	slots := make(chan struct{}, concurrency)
	var group sync.WaitGroup
	for _, pool := range pools {
		slots <- struct{}{}
		group.Add(1)
		go func(pool Pool) {
			defer func() { <-slots; group.Done() }()
			outcomes := runner.probe(ctx, pool, nodes[pool.ScopeID], plan, round)
			if err := runner.store.Record(ctx, pool, outcomes); err != nil && ctx.Err() == nil {
				runner.logger.Warn("origin probe record failed", "site_id", pool.SiteID, "error", err)
			}
		}(pool)
	}
	group.Wait()
	return ctx.Err()
}

// probe asks the sources in plan.OriginSources order for the origins not
// decided yet: node = up to PeerProbers of the tenant's own MARKET_PROBE v3
// nodes, dnspup = each dnspup checkpoint one vote (only origins dnspup's http
// probe can express), controller = the control plane's direct probe. Node and
// dnspup votes add up; a verdict needs MinPeerVotes votes and a strict
// majority (Tally). An origin no source decided is not recorded this round.
func (runner *Runner) probe(ctx context.Context, pool Pool, nodes []string, plan dnspupprobe.Runtime,
	round int64) map[string]Outcome {
	outcomes := map[string]Outcome{}
	votes := map[string][]*Outcome{}
	var enabled []Origin
	for _, origin := range pool.Origins {
		if origin.Enabled {
			enabled = append(enabled, origin)
		}
	}
	undecided := func() []Origin {
		var out []Origin
		for _, origin := range enabled {
			if _, done := outcomes[endpointKey(origin.Host, origin.Port)]; !done {
				out = append(out, origin)
			}
		}
		return out
	}
	decide := func(origins []Origin) {
		for _, origin := range origins {
			key := endpointKey(origin.Host, origin.Port)
			if outcome := tallyOne(votes[key]); outcome != nil {
				outcomes[key] = *outcome
			}
		}
	}
	dnspupLater := plan.Uses(plan.OriginSources, dnspupprobe.SourceDNSPup)
	for _, source := range plan.OriginSources {
		pending := undecided()
		if len(pending) == 0 {
			break
		}
		switch source {
		case dnspupprobe.SourceNode:
			// One node alone is asked only when dnspup can add votes.
			if runner.peers == nil || len(nodes) == 0 || len(nodes) < MinPeerVotes && !dnspupLater {
				continue
			}
			var targets []Target
			var origins []Origin
			for _, origin := range pending {
				if target := TargetOf(pool, origin); len(targets) < contract.MaxTargets && peerEligible(target) {
					targets, origins = append(targets, target), append(origins, origin)
				}
			}
			if len(targets) == 0 {
				continue
			}
			for _, answers := range runner.askPeers(ctx, pickPeers(pool.SiteID, nodes), targets) {
				for index, answer := range answers {
					if index < len(origins) && answer != nil && answer.Voted {
						key := endpointKey(origins[index].Host, origins[index].Port)
						votes[key] = append(votes[key], answer)
					}
				}
			}
			decide(origins)
		case dnspupprobe.SourceDNSPup:
			if plan.Probe == nil {
				continue
			}
			runner.askDNSPup(ctx, pool, pending, plan, round, votes)
			decide(pending)
		case dnspupprobe.SourceController:
			for _, origin := range pending {
				outcomes[endpointKey(origin.Host, origin.Port)] = runner.controller.Probe(ctx, TargetOf(pool, origin))
			}
		}
	}
	return outcomes
}

// dnspupTarget: dnspup verifies with public roots only, so a custom CA and
// an unverified origin are both beyond it (CustomCA: HTTPURL refuses).
func dnspupTarget(target Target) dnspupprobe.HTTPTarget {
	return dnspupprobe.HTTPTarget{Host: target.Host, Port: target.Port, HTTPS: target.HTTPS,
		HostHeader: target.HostHeader, ServerName: target.ServerName, Path: target.Path,
		CustomCA: target.CAPEM != "" || target.NoVerify}
}

// askDNSPup adds one vote per dnspup checkpoint for the pending origins
// dnspup's http probe can express (concurrently; each is one charged job per
// round, the idempotency key is (site, origin, round)).
func (runner *Runner) askDNSPup(ctx context.Context, pool Pool, pending []Origin, plan dnspupprobe.Runtime, round int64,
	votes map[string][]*Outcome) {
	var mu sync.Mutex
	var group sync.WaitGroup
	for _, origin := range pending {
		address, ok := dnspupprobe.HTTPURL(dnspupTarget(TargetOf(pool, origin)))
		if !ok {
			continue
		}
		key := endpointKey(origin.Host, origin.Port)
		group.Add(1)
		go func() {
			defer group.Done()
			results, err := plan.Probe(ctx, dnspupprobe.ConsumerOrigin, pool.SiteID.String(), key, round,
				dnspupprobe.ProbeRequest{Type: "http", Target: address, Method: http.MethodGet})
			if err != nil {
				return
			}
			mu.Lock()
			defer mu.Unlock()
			for _, vote := range dnspupprobe.HTTPVotes(results, 0) {
				if vote.Voted {
					votes[key] = append(votes[key], &Outcome{OK: vote.OK, Voted: true, Reason: vote.Reason})
				}
			}
		}()
	}
	group.Wait()
}

// pickPeers: up to PeerProbers of nodes, starting at a site-dependent
// offset so sites spread over the tenant's nodes.
func pickPeers(siteID uuid.UUID, nodes []string) []string {
	picked := make([]string, 0, min(PeerProbers, len(nodes)))
	start := int(binary.BigEndian.Uint16(siteID[14:])) % max(len(nodes), 1)
	for index := range min(PeerProbers, len(nodes)) {
		picked = append(picked, nodes[(start+index)%len(nodes)])
	}
	return picked
}

// askPeers sends the targets to every node at once; one answer list per node.
func (runner *Runner) askPeers(ctx context.Context, nodes []string, targets []Target) [][]*Outcome {
	answers := make([][]*Outcome, len(nodes))
	var group sync.WaitGroup
	for index, node := range nodes {
		group.Add(1)
		go func() {
			defer group.Done()
			answers[index] = runner.peers.Probe(ctx, node, targets)
		}()
	}
	group.Wait()
	return answers
}

// Tally merges the nodes' answers per target: with at least MinPeerVotes
// OK/FAILED answers and a strict majority the majority decides (a failure
// carries the most common failure reason); otherwise nil (the control
// plane probes it).
func Tally(answers [][]*Outcome) []*Outcome {
	size := 0
	for _, list := range answers {
		size = max(size, len(list))
	}
	out := make([]*Outcome, size)
	for index := range out {
		var votes []*Outcome
		for _, list := range answers {
			if index < len(list) {
				votes = append(votes, list[index])
			}
		}
		out[index] = tallyOne(votes)
	}
	return out
}

// tallyOne is one target's verdict over all its votes (nodes and dnspup
// checkpoints alike); nil: not decided.
func tallyOne(votes []*Outcome) *Outcome {
	ok, failed := 0, 0
	reasons := map[string]int{}
	top := ""
	for _, vote := range votes {
		if vote == nil || !vote.Voted {
			continue
		}
		if vote.OK {
			ok++
			continue
		}
		failed++
		reason := vote.Reason
		reasons[reason]++
		if top == "" || reasons[reason] > reasons[top] || reasons[reason] == reasons[top] && reason < top {
			top = reason
		}
	}
	switch {
	case ok+failed < MinPeerVotes || ok == failed:
		return nil
	case ok > failed:
		return &Outcome{OK: true, Voted: true}
	default:
		return &Outcome{Voted: true, Reason: top}
	}
}

// peerNodes: per tenant scope, its own online active nodes running
// MARKET_PROBE v3 with external probing allowed.
func (runner *Runner) peerNodes(ctx context.Context) (map[uuid.UUID][]string, error) {
	if runner.peers == nil {
		return nil, nil
	}
	rows, err := runner.pool.Query(ctx, `SELECT node.scope_id, node.id::text,
			(SELECT facts.capabilities_snapshot FROM node_session_capabilities facts WHERE facts.node_id=node.id
			 ORDER BY facts.session_epoch DESC LIMIT 1)
		FROM nodes node JOIN node_presence presence ON presence.node_id=node.id AND presence.status='online'
		JOIN access_scopes scope ON scope.id=node.scope_id AND scope.kind='tenant'
		WHERE node.admin_state='active' AND COALESCE((node.management_settings->>'external_probe')::boolean, true)
		ORDER BY node.scope_id, node.id`)
	if err != nil {
		return nil, err
	}
	defer rows.Close()
	nodes := map[uuid.UUID][]string{}
	for rows.Next() {
		var scopeID uuid.UUID
		var id string
		var snapshot []byte
		if err := rows.Scan(&scopeID, &id, &snapshot); err != nil {
			return nil, err
		}
		if marketprobe.HasCapability(snapshot, agentv1.CapabilityName_CAPABILITY_NAME_MARKET_PROBE, OriginProbeVersion) {
			nodes[scopeID] = append(nodes[scopeID], id)
		}
	}
	return nodes, rows.Err()
}

// ControllerProber probes from the control plane: public addresses only
// (checked at dial time), no redirects, at most 1 KiB read; any answer
// below 500 is healthy.
type ControllerProber struct {
	blocked func(netip.Addr) bool
	timeout time.Duration
}

func NewControllerProber(blocked func(netip.Addr) bool) *ControllerProber {
	if blocked == nil {
		blocked = dnscustomhttp.Blocked
	}
	return &ControllerProber{blocked: blocked, timeout: probeTimeout}
}

var errBlocked = errors.New("origin probe: address not allowed")

func (prober *ControllerProber) Probe(parent context.Context, target Target) Outcome {
	ctx, cancel := context.WithTimeout(parent, prober.timeout)
	defer cancel()
	dialer := &net.Dialer{Control: func(_, address string, _ syscall.RawConn) error {
		host, _, err := net.SplitHostPort(address)
		if err != nil {
			return errBlocked
		}
		parsed, err := netip.ParseAddr(host)
		if err != nil || prober.blocked(parsed.Unmap()) {
			return errBlocked
		}
		return nil
	}}
	config := &tls.Config{ServerName: target.ServerName, MinVersion: tls.VersionTLS12}
	if target.NoVerify {
		// 不校验源站证书: as the edge does (any chain, no name check)
		config.InsecureSkipVerify = true //nolint:gosec // the site chose it (tls_trust none)
	} else if target.CAPEM != "" {
		roots := x509.NewCertPool()
		if !roots.AppendCertsFromPEM([]byte(target.CAPEM)) {
			return Outcome{Voted: true, Reason: "tls"}
		}
		config.RootCAs = roots
	}
	transport := &http.Transport{Proxy: nil, DialContext: dialer.DialContext, DisableKeepAlives: true,
		MaxResponseHeaderBytes: 8 << 10, TLSClientConfig: config}
	defer transport.CloseIdleConnections()
	client := &http.Client{Transport: transport, CheckRedirect: func(*http.Request, []*http.Request) error {
		return http.ErrUseLastResponse
	}}
	scheme := "http"
	if target.HTTPS {
		scheme = "https"
	}
	path, query, _ := cutQuery(target.Path)
	address := &url.URL{Scheme: scheme, Host: net.JoinHostPort(target.Host, strconv.Itoa(target.Port)), Path: path, RawQuery: query}
	request, err := http.NewRequestWithContext(ctx, http.MethodGet, address.String(), nil)
	if err != nil {
		return Outcome{}
	}
	request.Host = target.HostHeader
	request.Header.Set("User-Agent", "cdnca-control-api/origin-probe")
	response, err := client.Do(request)
	if err != nil {
		var certificate *tls.CertificateVerificationError
		switch {
		case errors.Is(err, errBlocked):
			return Outcome{Reason: "blocked_address"} // not probed: no vote
		case parent.Err() != nil:
			return Outcome{}
		case errors.As(err, &certificate):
			return Outcome{Voted: true, Reason: "tls"}
		case ctx.Err() != nil:
			return Outcome{Voted: true, Reason: "timeout"}
		}
		return Outcome{Voted: true, Reason: "connect"}
	}
	_, _ = io.CopyN(io.Discard, response.Body, 1<<10)
	_ = response.Body.Close()
	if response.StatusCode >= http.StatusInternalServerError {
		return Outcome{Voted: true, Reason: "status_5xx"}
	}
	return Outcome{OK: true, Voted: true}
}

func cutQuery(path string) (string, string, bool) {
	for index := range len(path) {
		if path[index] == '?' {
			return path[:index], path[index+1:], true
		}
	}
	return path, "", false
}

// NodePeerProber sends MARKET_PROBE v3 origin targets over the gateway with
// no expected status, so the node applies the control plane's rule (an
// answer below 500 is up). SKIPPED and lost answers are nil (no vote).
type NodePeerProber struct {
	requester marketprobe.Requester
}

func NewNodePeerProber(requester marketprobe.Requester) *NodePeerProber {
	return &NodePeerProber{requester: requester}
}

func (prober *NodePeerProber) Probe(ctx context.Context, nodeID string, targets []Target) []*Outcome {
	results := make([]*Outcome, len(targets))
	if prober == nil || prober.requester == nil || len(targets) == 0 || len(targets) > contract.MaxTargets {
		return results
	}
	now := time.Now()
	timeoutMillis := uint32(probeTimeout.Milliseconds())
	expires := now.Add(probeTimeout + 5*time.Second)
	commandTargets := make([]*agentv1.MarketProbeTarget, len(targets))
	for index, target := range targets {
		commandTargets[index] = OriginProbeTarget("of-"+strconv.Itoa(index), target)
	}
	command := &agentv1.MarketProbeCommand{
		Event:  &commonv1.EventMetadata{EventId: uuid.NewString(), RequestId: uuid.NewString(), OccurredTime: timestamppb.New(now)},
		NodeId: nodeID, Targets: commandTargets, TimeoutMillis: timeoutMillis, ExpireTime: timestamppb.New(expires),
	}
	payload, err := proto.MarshalOptions{Deterministic: true}.Marshal(command)
	if err != nil || len(payload) > contract.MaxCarrierBytes {
		return results
	}
	ctx, cancel := context.WithDeadline(ctx, expires)
	defer cancel()
	reply, err := prober.requester.Request(ctx, nodeID, payload)
	if err != nil {
		return results
	}
	var result agentv1.MarketProbeResult
	if proto.Unmarshal(reply, &result) != nil || result.NodeId != nodeID || result.CommandEventId != command.Event.EventId ||
		len(result.Results) != len(targets) {
		return results
	}
	for index, item := range result.Results {
		if item.GetTaskId() != commandTargets[index].TaskId {
			return make([]*Outcome, len(targets))
		}
		switch {
		case item.Outcome == agentv1.MarketProbeOutcome_MARKET_PROBE_OUTCOME_OK:
			results[index] = &Outcome{OK: true, Voted: true}
		case item.Outcome == agentv1.MarketProbeOutcome_MARKET_PROBE_OUTCOME_FAILED:
			results[index] = &Outcome{Voted: true, Reason: nodeReason(item)}
		}
	}
	return results
}

// OriginProbeTarget is target as a MARKET_PROBE v3 origin target.
func OriginProbeTarget(taskID string, target Target) *agentv1.MarketProbeTarget {
	item := &agentv1.MarketProbeTarget{TaskId: taskID, Scheme: "http", Host: target.Host, Port: uint32(target.Port),
		HostHeader: target.HostHeader, Path: target.Path}
	if target.HTTPS {
		item.Scheme, item.ServerName, item.CaPem = "https", target.ServerName, target.CAPEM
	}
	return item
}

// nodeReason maps a node failure code to the origin status reasons.
func nodeReason(item *agentv1.MarketProbeTargetResult) string {
	switch item.ErrorCode {
	case "status":
		return "status_5xx"
	case "timeout", "tls":
		return item.ErrorCode
	}
	return "connect"
}
