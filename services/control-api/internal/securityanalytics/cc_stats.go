package securityanalytics

import (
	"bufio"
	"bytes"
	"context"
	"encoding/json"
	"fmt"
	"sort"
	"strconv"
	"strings"
	"time"

	contract "github.com/cdnca/cdnca/libs/edgeconfig/autodefense"
	"github.com/google/uuid"
	"github.com/jackc/pgx/v5"
)

// CC rule statistics: nodes report the
// activity of their CC rules (cc_stats); the CC page reads it for manual
// tuning and automatic defense reads the same table. The rows are display
// facts with no PostgreSQL side effect, so they take no receipt: CCStatTable
// is a ReplacingMergeTree and each row ID derives from node, seq and index,
// so a redelivered report replaces its own rows.

// CCStatTable is the ClickHouse table of migration cc_rule_stats.
const CCStatTable = "cc_rule_stats_v1"

// CCStatFact is one row of CCStatTable. RuleID is uuid.Nil for the site
// level counts outside any rule.
type CCStatFact struct {
	ID, TenantID, SiteID, NodeID, RuleID                            uuid.UUID
	PolicyID                                                        string
	PolicyVersion, Seq                                              uint64
	Minute                                                          time.Time
	Matched, Triggered, Challenged, Blocked, Passed, JA4Unavailable int64
	TopClients, TopPaths                                            map[string]int64
}

// CCStatWriter writes CCStatTable rows.
type CCStatWriter interface {
	WriteCCStats(ctx context.Context, rows []CCStatFact) error
}

// IngestCCStats keeps the rows of sites the node serves (the tenant boundary
// of ingest, as nodeServesSite) and writes them. Rows of other sites are
// dropped; the outcome is ignored when none is left. It is the cc_stats
// handler of the control-api report router (the report is decoded and its
// node matched to the subject there); no receipt is kept: redelivery of
// node + seq rewrites the same row IDs (ReplacingMergeTree).
func (ingestor *Ingestor) IngestCCStats(ctx context.Context, report contract.Report) (string, error) {
	writer, ok := ingestor.facts.(CCStatWriter)
	if !ok {
		return OutcomeIgnored, nil
	}
	nodeID := uuid.MustParse(report.NodeID)
	tenants := make([]uuid.UUID, 0, len(report.CCStats))
	sites := make([]uuid.UUID, 0, len(report.CCStats))
	for _, stat := range report.CCStats {
		tenants = append(tenants, uuid.MustParse(stat.TenantID))
		sites = append(sites, uuid.MustParse(stat.SiteID))
	}
	var exists bool
	served := map[[2]uuid.UUID]bool{}
	err := pgx.BeginFunc(ctx, ingestor.pool, func(tx pgx.Tx) error {
		if err := tx.QueryRow(ctx, `SELECT EXISTS(SELECT 1 FROM nodes WHERE id=$1)`, nodeID).Scan(&exists); err != nil || !exists {
			return err
		}
		// D2: sites following their package's line group (node_group_id
		// NULL) were dropped here as out of scope (siteServedByNode).
		rows, err := tx.Query(ctx, `SELECT DISTINCT s.scope_id, s.id
			FROM unnest($1::uuid[], $2::uuid[]) AS reported(tenant, site)
			JOIN sites s ON s.scope_id=reported.tenant AND s.id=reported.site AND s.deleted_at IS NULL
			WHERE `+siteServedByNode, tenants, sites, nodeID)
		if err != nil {
			return err
		}
		defer rows.Close()
		for rows.Next() {
			var tenant, site uuid.UUID
			if err := rows.Scan(&tenant, &site); err != nil {
				return err
			}
			served[[2]uuid.UUID{tenant, site}] = true
		}
		return rows.Err()
	})
	if err != nil {
		return "", err
	}
	if !exists {
		return "", ErrInvalidReport
	}
	seq := strconv.FormatUint(report.Seq, 10)
	facts := make([]CCStatFact, 0, len(report.CCStats))
	for index, stat := range report.CCStats {
		if !served[[2]uuid.UUID{tenants[index], sites[index]}] {
			continue
		}
		rule := uuid.Nil
		if stat.RuleID != "" {
			rule = uuid.MustParse(stat.RuleID)
		}
		facts = append(facts, CCStatFact{ID: deterministicID(report.NodeID, "cc_stats", seq, strconv.Itoa(index)),
			TenantID: tenants[index], SiteID: sites[index], NodeID: nodeID, RuleID: rule, PolicyID: stat.PolicyID,
			PolicyVersion: stat.PolicyVersion, Seq: report.Seq, Minute: time.Unix(stat.Minute, 0).UTC(),
			Matched: stat.Matched, Triggered: stat.Triggered, Challenged: stat.Challenged, Blocked: stat.Blocked,
			Passed: stat.Passed, JA4Unavailable: stat.JA4Unavailable,
			TopClients: countMap(stat.TopClients), TopPaths: countMap(stat.TopPaths)})
	}
	if len(facts) == 0 {
		return OutcomeScope, nil
	}
	// Partly out of scope: the served rows are kept.
	if err := writer.WriteCCStats(ctx, facts); err != nil {
		return "", err
	}
	return OutcomeApplied, nil
}

func countMap(counts []contract.Count) map[string]int64 {
	out := make(map[string]int64, len(counts))
	for _, count := range counts {
		out[count.Value] = count.Count
	}
	return out
}

type ccStatRow struct {
	TenantID       string           `json:"tenant_id"`
	SiteID         string           `json:"site_id"`
	PolicyID       string           `json:"policy_id"`
	PolicyVersion  uint64           `json:"policy_version"`
	RuleID         string           `json:"rule_id"`
	Minute         string           `json:"minute"`
	NodeID         string           `json:"node_id"`
	RowID          string           `json:"row_id"`
	Matched        int64            `json:"matched"`
	Triggered      int64            `json:"triggered"`
	Challenged     int64            `json:"challenged"`
	Blocked        int64            `json:"blocked"`
	Passed         int64            `json:"passed"`
	JA4Unavailable int64            `json:"ja4_unavailable"`
	TopClients     map[string]int64 `json:"top_clients"`
	TopPaths       map[string]int64 `json:"top_paths"`
	ReportSeq      uint64           `json:"report_seq"`
}

// WriteCCStats implements CCStatWriter.
func (ch *ClickHouse) WriteCCStats(ctx context.Context, facts []CCStatFact) error {
	rows := make([]any, len(facts))
	for index, fact := range facts {
		rows[index] = ccStatRow{TenantID: fact.TenantID.String(), SiteID: fact.SiteID.String(), PolicyID: fact.PolicyID,
			PolicyVersion: fact.PolicyVersion, RuleID: fact.RuleID.String(), Minute: fact.Minute.UTC().Format(time.DateTime),
			NodeID: fact.NodeID.String(), RowID: fact.ID.String(), Matched: fact.Matched, Triggered: fact.Triggered,
			Challenged: fact.Challenged, Blocked: fact.Blocked, Passed: fact.Passed, JA4Unavailable: fact.JA4Unavailable,
			TopClients: fact.TopClients, TopPaths: fact.TopPaths, ReportSeq: fact.Seq}
	}
	return ch.insert(ctx, CCStatTable, rows)
}

// CCCounts are the summed counts of CCStatTable rows.
type CCCounts struct {
	Matched        int64 `json:"matched"`
	Triggered      int64 `json:"triggered"`
	Challenged     int64 `json:"challenged"`
	Blocked        int64 `json:"blocked"`
	Passed         int64 `json:"passed"`
	JA4Unavailable int64 `json:"ja4_unavailable"`
}

// CCStatPoint is one step of a site's series.
type CCStatPoint struct {
	At time.Time `json:"at"`
	CCCounts
}

// CCRuleTotal is one rule's total over the range (RuleID nil: site level).
type CCRuleTotal struct {
	RuleID   *uuid.UUID `json:"rule_id"`
	PolicyID string     `json:"policy_id"`
	CCCounts
}

// CCTopValue is one entry of a top list.
type CCTopValue struct {
	Value string `json:"value"`
	Count int64  `json:"count"`
}

// CCSiteStats is a site's CC rule statistics over [From, To).
type CCSiteStats struct {
	SiteID      uuid.UUID     `json:"site_id"`
	From        time.Time     `json:"from"`
	To          time.Time     `json:"to"`
	StepSeconds int64         `json:"step_seconds"`
	Series      []CCStatPoint `json:"series"`
	Rules       []CCRuleTotal `json:"rules"`
	TopClients  []CCTopValue  `json:"top_clients"`
	TopPaths    []CCTopValue  `json:"top_paths"`
}

// CCStatsTop is the length of the range's top lists.
const CCStatsTop = 20

const ccStatsSums = `sum(matched) AS matched, sum(triggered) AS triggered, sum(challenged) AS challenged,
	sum(blocked) AS blocked, sum(passed) AS passed, sum(ja4_unavailable) AS ja4_unavailable`

// The FINAL subquery removes redelivered rows before summing; output aliases
// differ from column names (see verdictSelect).
const ccStatsSource = `(SELECT * FROM ` + CCStatTable + ` FINAL WHERE tenant_id = {tenant:UUID} AND site_id = {site:UUID}
	AND minute >= {from:DateTime} AND minute < {to:DateTime})`

// SiteCCStats reads the statistics of one site of tenant. from and to are
// aligned to step by the caller (a multiple of 60 seconds).
func (ch *ClickHouse) SiteCCStats(ctx context.Context, tenant, site uuid.UUID, from, to time.Time, step time.Duration) (CCSiteStats, error) {
	seconds := int64(step / time.Second)
	if seconds < 60 || seconds%60 != 0 || !to.After(from) {
		return CCSiteStats{}, ErrInvalidConfig
	}
	params := map[string]string{"tenant": tenant.String(), "site": site.String(), "step": strconv.FormatInt(seconds, 10),
		"from": from.UTC().Format(time.DateTime), "to": to.UTC().Format(time.DateTime), "top": strconv.Itoa(CCStatsTop)}
	out := CCSiteStats{SiteID: site, From: from.UTC(), To: to.UTC(), StepSeconds: seconds,
		Series: []CCStatPoint{}, Rules: []CCRuleTotal{}, TopClients: []CCTopValue{}, TopPaths: []CCTopValue{}}

	if err := ch.queryRows(ctx, `SELECT toUnixTimestamp(toStartOfInterval(minute, toIntervalSecond({step:UInt32}))) AS out_at, `+
		ccStatsSums+` FROM `+ccStatsSource+` GROUP BY out_at ORDER BY out_at`, params, func(line []byte) error {
		var row struct {
			At int64 `json:"out_at"`
			CCCounts
		}
		if err := json.Unmarshal(line, &row); err != nil {
			return err
		}
		out.Series = append(out.Series, CCStatPoint{At: time.Unix(row.At, 0).UTC(), CCCounts: row.CCCounts})
		return nil
	}); err != nil {
		return CCSiteStats{}, err
	}

	if err := ch.queryRows(ctx, `SELECT toString(rule_id) AS out_rule_id, any(policy_id) AS out_policy_id, `+ccStatsSums+
		` FROM `+ccStatsSource+` GROUP BY rule_id ORDER BY triggered DESC, matched DESC, out_rule_id`, params, func(line []byte) error {
		var row struct {
			RuleID   uuid.UUID `json:"out_rule_id"`
			PolicyID string    `json:"out_policy_id"`
			CCCounts
		}
		if err := json.Unmarshal(line, &row); err != nil {
			return err
		}
		total := CCRuleTotal{PolicyID: row.PolicyID, CCCounts: row.CCCounts}
		if row.RuleID != uuid.Nil {
			rule := row.RuleID
			total.RuleID = &rule
		}
		out.Rules = append(out.Rules, total)
		return nil
	}); err != nil {
		return CCSiteStats{}, err
	}

	if err := ch.queryRows(ctx, `SELECT sumMap(top_clients) AS out_clients, sumMap(top_paths) AS out_paths FROM `+ccStatsSource,
		params, func(line []byte) error {
			var row struct {
				Clients map[string]int64 `json:"out_clients"`
				Paths   map[string]int64 `json:"out_paths"`
			}
			if err := json.Unmarshal(line, &row); err != nil {
				return err
			}
			out.TopClients, out.TopPaths = ccTopValues(row.Clients), ccTopValues(row.Paths)
			return nil
		}); err != nil {
		return CCSiteStats{}, err
	}
	return out, nil
}

// ccTopValues: count descending, value ascending, at most CCStatsTop.
func ccTopValues(values map[string]int64) []CCTopValue {
	out := make([]CCTopValue, 0, len(values))
	for value, count := range values {
		if count > 0 {
			out = append(out, CCTopValue{Value: value, Count: count})
		}
	}
	sort.Slice(out, func(i, j int) bool {
		return out[i].Count > out[j].Count || out[i].Count == out[j].Count && out[i].Value < out[j].Value
	})
	if len(out) > CCStatsTop {
		out = out[:CCStatsTop]
	}
	return out
}

// queryRows runs query in JSONEachRow and hands each line to scan (64-bit
// sums as JSON numbers, not quoted strings).
func (ch *ClickHouse) queryRows(ctx context.Context, query string, params map[string]string, scan func([]byte) error) error {
	data, err := ch.do(ctx, query+" SETTINGS output_format_json_quote_64bit_integers = 0 FORMAT JSONEachRow", params, nil)
	if err != nil {
		return err
	}
	scanner := bufio.NewScanner(bytes.NewReader(data))
	scanner.Buffer(make([]byte, 64<<10), 4<<20)
	for scanner.Scan() {
		if err := scan(scanner.Bytes()); err != nil {
			return fmt.Errorf("%w: cc stats row: %v", ErrClickHouse, err)
		}
	}
	return scanner.Err()
}

// CCSiteRuleTotal is one (site, policy, rule) total over a range, across
// every tenant of this control plane (rule intel report, RI-08).
type CCSiteRuleTotal struct {
	SiteID   uuid.UUID `json:"out_site_id"`
	PolicyID string    `json:"out_policy_id"`
	RuleID   uuid.UUID `json:"out_rule_id"`
	CCCounts
}

// RuleCCTotals sums the rows of the given rule IDs in [from, to) per site,
// policy and rule. The rule IDs are node rule IDs of official packs
// (rulepack.NodeRuleID does not depend on the site), so the filter is short.
func (ch *ClickHouse) RuleCCTotals(ctx context.Context, rules []uuid.UUID, from, to time.Time) ([]CCSiteRuleTotal, error) {
	if len(rules) == 0 || !to.After(from) {
		return nil, nil
	}
	list := make([]string, len(rules))
	for index, rule := range rules {
		list[index] = "'" + rule.String() + "'"
	}
	params := map[string]string{"rules": "[" + strings.Join(list, ",") + "]",
		"from": from.UTC().Format(time.DateTime), "to": to.UTC().Format(time.DateTime)}
	var out []CCSiteRuleTotal
	err := ch.queryRows(ctx, `SELECT toString(site_id) AS out_site_id, policy_id AS out_policy_id, toString(rule_id) AS out_rule_id, `+
		ccStatsSums+` FROM (SELECT * FROM `+CCStatTable+` FINAL WHERE rule_id IN {rules:Array(UUID)}
		AND minute >= {from:DateTime} AND minute < {to:DateTime}) GROUP BY site_id, policy_id, rule_id
		ORDER BY out_site_id, out_policy_id, out_rule_id`, params, func(line []byte) error {
		var row CCSiteRuleTotal
		if err := json.Unmarshal(line, &row); err != nil {
			return err
		}
		out = append(out, row)
		return nil
	})
	return out, err
}
