package main

import (
	"bufio"
	"bytes"
	"context"
	"encoding/json"
	"errors"
	"log/slog"
	"sort"
	"strconv"
	"sync"
	"time"

	"github.com/cdnca/cdnca/agents/edge-agent/internal/gatewayclient"
	"github.com/cdnca/cdnca/libs/edgeconfig/autodefense"
)

// ccStats sums the CC engine's rule statistics frames (ccv2 engine.lua
// stats(), drained once a second by the runtime status poller) and sends
// them every ccStatsInterval as cc_stats reports on the AUTO_DEFENSE
// upstream (the CC page and automatic defense read the
// same counts). Sending never blocks: a full queue or an over-large pending
// set drops and counts. Seq is the Unix millisecond, raised past the
// previous one (node scoped, like node_event).
type ccStats struct {
	nodeID string
	now    func() time.Time
	out    chan []byte

	mu        sync.Mutex
	pending   map[ccStatKey]*ccStatRow
	lastFlush time.Time
	lastSeq   uint64
	dropped   uint64
}

const (
	ccStatsInterval = 10 * time.Second
	ccStatsQueue    = 64
	// ccStatsMaxPending bounds one interval (about 80 reports of
	// autodefense.MaxCCStats rows).
	ccStatsMaxPending = 10000
	ccStatsFrameBytes = 1 << 20
	ccStatsSchema     = "cdnca.edge.cc-stats-frame/v1"
)

type ccStatKey struct {
	tenant, site, policy, rule string
	version                    uint64
	minute                     int64
}

type ccStatRow struct {
	counts         [6]int64 // matched, triggered, challenged, blocked, passed, ja4_unavailable
	clients, paths map[string]int64
}

// ccStatsFrameRow is one row of a Lua frame. policy_version is decimal text
// (cjson writes numbers with 14 significant digits).
type ccStatsFrameRow struct {
	TenantScopeID  string          `json:"tenant_scope_id"`
	SiteID         string          `json:"site_id"`
	PolicyID       string          `json:"policy_id"`
	PolicyVersion  string          `json:"policy_version"`
	RuleID         string          `json:"rule_id"`
	Minute         int64           `json:"minute"`
	Matched        int64           `json:"matched"`
	Triggered      int64           `json:"triggered"`
	Challenged     int64           `json:"challenged"`
	Blocked        int64           `json:"blocked"`
	Passed         int64           `json:"passed"`
	JA4Unavailable int64           `json:"ja4_unavailable"`
	TopClients     json.RawMessage `json:"top_clients"`
	TopPaths       json.RawMessage `json:"top_paths"`
}

func newCCStats(nodeID string, now func() time.Time) *ccStats {
	return &ccStats{nodeID: nodeID, now: now, out: make(chan []byte, ccStatsQueue),
		pending: map[ccStatKey]*ccStatRow{}, lastFlush: now()}
}

// decodeTop reads a Lua top table; cjson encodes an empty one as {} and
// never as an array with entries.
func decodeTop(raw json.RawMessage) (map[string]int64, bool) {
	top := map[string]int64{}
	if len(raw) == 0 || string(raw) == "{}" || string(raw) == "[]" {
		return top, true
	}
	if json.Unmarshal(raw, &top) != nil || len(top) > autodefense.MaxCCTop {
		return nil, false
	}
	return top, true
}

// add sums one drained body; it sends what the interval collected once it
// has elapsed (the poller calls add every second, also with a nil body).
func (stats *ccStats) add(body []byte) {
	if stats == nil {
		return
	}
	stats.mu.Lock()
	defer stats.mu.Unlock()
	scanner := bufio.NewScanner(bytes.NewReader(body))
	scanner.Buffer(make([]byte, 64<<10), ccStatsFrameBytes)
	for scanner.Scan() {
		var frame struct {
			Schema  string            `json:"schema"`
			Rows    []ccStatsFrameRow `json:"rows"`
			Dropped uint64            `json:"dropped"`
		}
		if json.Unmarshal(scanner.Bytes(), &frame) != nil {
			stats.dropped++
			continue
		}
		if frame.Schema == "" {
			stats.dropped += frame.Dropped // the engine's own drops
			continue
		}
		if frame.Schema != ccStatsSchema {
			stats.dropped++
			continue
		}
		for _, row := range frame.Rows {
			stats.addRow(row)
		}
	}
	if stats.now().Sub(stats.lastFlush) >= ccStatsInterval {
		stats.flush()
	}
}

func (stats *ccStats) addRow(row ccStatsFrameRow) {
	version, err := strconv.ParseUint(row.PolicyVersion, 10, 64)
	clients, clientsOK := decodeTop(row.TopClients)
	paths, pathsOK := decodeTop(row.TopPaths)
	if err != nil || !clientsOK || !pathsOK {
		stats.dropped++
		return
	}
	key := ccStatKey{tenant: row.TenantScopeID, site: row.SiteID, policy: row.PolicyID, rule: row.RuleID, version: version, minute: row.Minute}
	sum := stats.pending[key]
	if sum == nil {
		if len(stats.pending) >= ccStatsMaxPending {
			stats.dropped++
			return
		}
		sum = &ccStatRow{clients: map[string]int64{}, paths: map[string]int64{}}
		stats.pending[key] = sum
	}
	for index, value := range []int64{row.Matched, row.Triggered, row.Challenged, row.Blocked, row.Passed, row.JA4Unavailable} {
		if value > 0 {
			sum.counts[index] += value
		}
	}
	for value, count := range clients {
		sum.clients[value] += count
	}
	for value, count := range paths {
		sum.paths[value] += count
	}
}

// ccTop keeps the MaxCCTop largest counts (count descending, value ascending)
// bounded by triggered.
func ccTop(values map[string]int64, triggered int64) []autodefense.Count {
	top := make([]autodefense.Count, 0, len(values))
	for value, count := range values {
		if value != "" && len(value) <= autodefense.MaxCCTopText && count > 0 {
			top = append(top, autodefense.Count{Value: value, Count: min(count, triggered)})
		}
	}
	sort.Slice(top, func(i, j int) bool {
		return top[i].Count > top[j].Count || top[i].Count == top[j].Count && top[i].Value < top[j].Value
	})
	if len(top) > autodefense.MaxCCTop {
		top = top[:autodefense.MaxCCTop]
	}
	return top
}

// flush encodes the pending rows in reports of at most MaxCCStats rows. A
// row the contract rejects (a corrupt frame) is dropped alone.
func (stats *ccStats) flush() {
	now := stats.now()
	stats.lastFlush = now
	if len(stats.pending) == 0 && stats.dropped == 0 {
		return
	}
	keys := make([]ccStatKey, 0, len(stats.pending))
	for key := range stats.pending {
		keys = append(keys, key)
	}
	sort.Slice(keys, func(i, j int) bool {
		a, b := keys[i], keys[j]
		if a.site != b.site {
			return a.site < b.site
		}
		if a.minute != b.minute {
			return a.minute < b.minute
		}
		return a.rule < b.rule
	})
	var batch []autodefense.CCStat
	send := func() {
		if len(batch) == 0 {
			return
		}
		seq := max(stats.lastSeq+1, uint64(now.UnixMilli()))
		encoded, err := autodefense.EncodeReport(autodefense.Report{Schema: autodefense.ReportSchema, Kind: autodefense.ReportCCStats,
			NodeID: stats.nodeID, Seq: seq, At: now.Unix(), CCStats: batch})
		if err != nil {
			stats.dropped += uint64(len(batch))
		} else {
			stats.lastSeq = seq
			select {
			case stats.out <- encoded:
			default:
				stats.dropped += uint64(len(batch))
			}
		}
		batch = nil
	}
	for _, key := range keys {
		row := stats.pending[key]
		stat := autodefense.CCStat{TenantID: key.tenant, SiteID: key.site, PolicyID: key.policy, PolicyVersion: key.version,
			RuleID: key.rule, Minute: key.minute, Matched: row.counts[0], Triggered: row.counts[1], Challenged: row.counts[2],
			Blocked: row.counts[3], Passed: row.counts[4], JA4Unavailable: row.counts[5],
			TopClients: ccTop(row.clients, row.counts[1]), TopPaths: ccTop(row.paths, row.counts[1])}
		// Validate alone so one corrupt row does not take its batch down.
		if autodefense.ValidateReport(autodefense.Report{Schema: autodefense.ReportSchema, Kind: autodefense.ReportCCStats,
			NodeID: stats.nodeID, Seq: 1, At: now.Unix(), CCStats: []autodefense.CCStat{stat}}) != nil {
			stats.dropped++
			continue
		}
		batch = append(batch, stat)
		if len(batch) == autodefense.MaxCCStats {
			send()
		}
	}
	send()
	clear(stats.pending)
	if stats.dropped > 0 {
		slog.Warn("CC rule statistics dropped", "rows", stats.dropped)
		stats.dropped = 0
	}
}

// withCCStats drains the CC engine's rule statistics into stats.
func (poller *runtimeStatusPoller) withCCStats(stats *ccStats) *runtimeStatusPoller {
	if poller != nil && stats != nil {
		poller.ccStats = stats
	}
	return poller
}

func (poller *runtimeStatusPoller) pollCCStats(ctx context.Context) {
	if poller.ccStats == nil {
		return
	}
	body, err := poller.get(ctx, ccStatsSuffix)
	if errors.Is(err, errRuntimeStatusAbsent) {
		body = nil
	} else if err != nil {
		slog.Warn("CC rule statistics unavailable", "error", err)
		body = nil
	}
	poller.ccStats.add(body)
}

// Reports is the queue the AUTO_DEFENSE session drains.
func (stats *ccStats) Reports() <-chan []byte {
	if stats == nil {
		return nil
	}
	return stats.out
}

// ccStatsUpstream adds the CC rule statistics to the AUTO_DEFENSE receiver's reports; snapshot parts go to the
// receiver unchanged. Whether AUTO_DEFENSE is declared stays the receiver's decision.
type ccStatsUpstream struct {
	gatewayclient.AutoDefenseRuntime
	stats       *ccStats
	reportsOnce sync.Once
	reports     <-chan []byte
}

func withCCStatsReports(runtime gatewayclient.AutoDefenseRuntime, stats *ccStats) gatewayclient.AutoDefenseRuntime {
	if stats == nil {
		return runtime
	}
	return &ccStatsUpstream{AutoDefenseRuntime: runtime, stats: stats}
}

// Reports implements gatewayclient.AutoDefenseRuntime.
func (upstream *ccStatsUpstream) Reports() <-chan []byte {
	upstream.reportsOnce.Do(func() {
		upstream.reports = mergeReports(upstream.AutoDefenseRuntime.Reports(), upstream.stats.Reports())
	})
	return upstream.reports
}
