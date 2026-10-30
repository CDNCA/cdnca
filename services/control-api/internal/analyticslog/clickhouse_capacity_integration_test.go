package analyticslog

import (
	"context"
	"errors"
	"fmt"
	"net/url"
	"os"
	"path/filepath"
	"regexp"
	"runtime"
	"sort"
	"strconv"
	"strings"
	"testing"
	"time"
)

const (
	productionCapacityRows = 5000
	productionPageSize     = 100
	productionP95Limit     = 2 * time.Second
	productionP99Limit     = 5 * time.Second
)

var explainPartsPattern = regexp.MustCompile(`Parts:\s*([0-9]+)/([0-9]+)`)

func TestClickHouseRuntimeGate(t *testing.T) {
	tests := []struct {
		name     string
		endpoint string
		required string
		wantSkip bool
		wantErr  bool
	}{
		{name: "ordinary missing runtime skips", wantSkip: true},
		{name: "formal missing runtime fails", required: "1", wantErr: true},
		{name: "ordinary configured runtime runs", endpoint: "http://127.0.0.1:8123"},
		{name: "formal configured runtime runs", endpoint: "http://127.0.0.1:8123", required: "1"},
		{name: "invalid formal flag fails", required: "true", wantErr: true},
	}
	for _, test := range tests {
		t.Run(test.name, func(t *testing.T) {
			_, skip, err := clickHouseRuntimeEndpoint(test.endpoint, test.required)
			if skip != test.wantSkip || (err != nil) != test.wantErr {
				t.Fatalf("skip=%t error=%v", skip, err)
			}
		})
	}
}

func TestCapacityPercentileNearestRank(t *testing.T) {
	samples := []time.Duration{10, 50, 20, 40, 30}
	if got := nearestRankDuration(samples, 95); got != 50 {
		t.Fatalf("p95=%s, want 50ns", got)
	}
	if got := nearestRankDuration(samples, 50); got != 30 {
		t.Fatalf("p50=%s, want 30ns", got)
	}
}

func TestProductionCandidateScanExtraction(t *testing.T) {
	for _, test := range []struct {
		name            string
		query           string
		candidateSource string
	}{
		{name: "access", query: accessPageSQL, candidateSource: "access_event_query_index_state_v1"},
		{name: "security", query: blockEventPageSQL, candidateSource: "security_event_query_index_state_v1"},
	} {
		t.Run(test.name, func(t *testing.T) {
			candidate, err := productionCandidateScan(test.query)
			if err != nil {
				t.Fatal(err)
			}
			for _, clause := range []string{
				"SELECT event_id",
				"FROM " + test.candidateSource,
				"occurred_at >= fromUnixTimestamp64Milli({from_ms:Int64}, 'UTC')",
				"occurred_at < fromUnixTimestamp64Milli({to_ms:Int64}, 'UTC')",
				"ingested_at <= snapshot_at",
				"GROUP BY event_id",
			} {
				if !strings.Contains(candidate, clause) {
					t.Fatalf("candidate scan is missing %q", clause)
				}
			}
			if strings.Contains(candidate, "FINAL") {
				t.Fatal("candidate scan must not substitute alternate FINAL SQL")
			}
		})
	}
}

func TestClickHouseFormalRunbookGateContract(t *testing.T) {
	_, currentFile, _, ok := runtime.Caller(0)
	if !ok {
		t.Fatal("locate analyticslog capacity test")
	}
	repositoryRoot := filepath.Clean(filepath.Join(filepath.Dir(currentFile), "..", "..", "..", ".."))
	runbook, err := os.ReadFile(filepath.Join(repositoryRoot, "docs", "runbooks", "analytics-logs-query-api.md"))
	if err != nil {
		t.Fatal(err)
	}
	contract := string(runbook)
	for _, required := range []string{
		"TEST_CLICKHOUSE_REQUIRED=1",
		"25.3.6.56",
		"-run '^(TestClickHouseAnalyticsLogIntegration|TestClickHouseMutableOccurredAtCandidateResolution|TestClickHouseProductionClientCapacity)$'",
		"rg -q -- '^--- SKIP:'",
		`rg -q -- "^--- PASS: ${test_name} "`,
	} {
		if !strings.Contains(contract, required) {
			t.Fatalf("formal ClickHouse runbook is missing %q", required)
		}
	}
}

func TestClickHouseProductionClientCapacity(t *testing.T) {
	database := newIntegrationDatabase(t)
	database.create(t)
	assertClickHouseVersion(t, database)

	now := time.Now().UTC()
	from := time.Date(now.Year(), now.Month(), 1, 0, 0, 0, 0, time.UTC)
	to := from.AddDate(0, 1, 0)
	occurredBase := time.Date(now.Year(), now.Month(), now.Day(), 1, 0, 0, 0, time.UTC)
	ingestedAt := now.Add(-time.Minute).Truncate(time.Millisecond)
	accessTenant := "10000000-0000-4000-8000-000000000071"
	securityTenant := "10000000-0000-4000-8000-000000000072"
	seedProductionCapacityRows(t, database, occurredBase, to.Add(time.Hour), ingestedAt, accessTenant, securityTenant)

	client, err := NewClient(ClientConfig{
		Endpoint: database.endpoint, Database: database.name, Username: database.username, Password: database.password,
		QueryTimeout: 6 * time.Second, CursorKeyring: testLogCursorKeyring(),
	}, database.http)
	if err != nil {
		t.Fatal(err)
	}
	filter := Filter{From: from, To: to}
	assertProductionCandidatePrunesPartitions(t, database, accessPageSQL, accessTenant, filter)
	assertProductionCandidatePrunesPartitions(t, database, blockEventPageSQL, securityTenant, filter)

	ctx, cancel := context.WithTimeout(context.Background(), 3*time.Minute)
	defer cancel()
	results := make(chan capacityPaginationResult, 2)
	go func() {
		results <- paginateProductionClient(ctx, "access", "capacity-access-", func(ctx context.Context, cursor string) (capacityPage, error) {
			page, err := client.ListAccess(ctx, scope{tenantID: accessTenant}, filter, productionPageSize, cursor)
			if err != nil {
				return capacityPage{}, err
			}
			return capacityPage{IDs: integrationAccessItemIDs(page.Items), SnapshotAt: page.SnapshotAt, NextCursor: page.NextCursor}, nil
		})
	}()
	go func() {
		results <- paginateProductionClient(ctx, "security", "capacity-security-", func(ctx context.Context, cursor string) (capacityPage, error) {
			page, err := client.ListBlockEvents(ctx, scope{tenantID: securityTenant}, filter, productionPageSize, cursor)
			if err != nil {
				return capacityPage{}, err
			}
			return capacityPage{IDs: integrationBlockEventItemIDs(page.Items), SnapshotAt: page.SnapshotAt, NextCursor: page.NextCursor}, nil
		})
	}()

	completed := make([]capacityPaginationResult, 0, 2)
	for range 2 {
		completed = append(completed, <-results)
	}
	for _, result := range completed {
		if result.Err != nil {
			t.Fatalf("%s production Client pagination: %v", result.Kind, result.Err)
		}
		assertCapacityPaginationResult(t, result)
	}
}

type capacityPage struct {
	IDs        []string
	SnapshotAt time.Time
	NextCursor string
}

type capacityPaginationResult struct {
	Kind      string
	Prefix    string
	IDs       []string
	Latencies []time.Duration
	Err       error
}

func seedProductionCapacityRows(
	t *testing.T,
	database *integrationDatabase,
	occurredBase, nextPartition, ingestedAt time.Time,
	accessTenant, securityTenant string,
) {
	t.Helper()
	parameters := url.Values{
		"param_occurred_base_ms":  {strconv.FormatInt(occurredBase.UnixMilli(), 10)},
		"param_ingested_at_ms":    {strconv.FormatInt(ingestedAt.UnixMilli(), 10)},
		"param_access_tenant":     {accessTenant},
		"param_security_tenant":   {securityTenant},
		"param_site_id":           {siteA},
		"param_node_id":           {nodeA},
		"param_config_version_id": {configA},
	}
	accessInsert := `INSERT INTO access_events
(metric_version, event_id, occurred_at, ingested_at, tenant_id, site_id, node_id, request_id, trace_id,
 config_version_id, host, path, client_ip, country_code, carrier, method, protocol, cache_status,
 upstream_result, status_code, request_bytes, response_bytes, duration_us)
SELECT
 1, concat('capacity-access-', leftPad(toString(number), 6, '0')),
 fromUnixTimestamp64Milli({occurred_base_ms:Int64}, 'UTC') + toIntervalMillisecond(number),
 fromUnixTimestamp64Milli({ingested_at_ms:Int64}, 'UTC'), toUUID({access_tenant:String}),
 toUUID({site_id:String}), toUUID({node_id:String}), concat('access-request-', toString(number)),
 concat('access-trace-', toString(number)), {config_version_id:String}, 'capacity.example.test',
 concat('/capacity/access/', toString(number)), toIPv6('2001:db8::71'), 'CN', 'capacity-carrier',
 'GET', 'HTTP/2', 'HIT', 'ok', 200, 100, 1000 + number, 1000
FROM numbers(5000)`
	securityInsert := `INSERT INTO security_events
(metric_version, event_id, occurred_at, ingested_at, tenant_id, site_id, node_id, request_id, trace_id,
 config_version_id, host, path, client_ip, country_code, carrier, event_type, action, severity, rule_id,
 status_code, request_bytes, response_bytes)
SELECT
 1, concat('capacity-security-', leftPad(toString(number), 6, '0')),
 fromUnixTimestamp64Milli({occurred_base_ms:Int64}, 'UTC') + toIntervalMillisecond(number),
 fromUnixTimestamp64Milli({ingested_at_ms:Int64}, 'UTC'), toUUID({security_tenant:String}),
 toUUID({site_id:String}), toUUID({node_id:String}), concat('security-request-', toString(number)),
 concat('security-trace-', toString(number)), {config_version_id:String}, 'capacity.example.test',
 concat('/capacity/security/', toString(number)), toIPv6('2001:db8::72'), 'CN', 'capacity-carrier',
 'waf', 'block', 'high', 'capacity-rule', 403, 100, 1000 + number
FROM numbers(5000)`
	for _, query := range []string{accessInsert, securityInsert} {
		if _, err := database.execute(context.Background(), query, true, parameters); err != nil {
			t.Fatal(err)
		}
	}
	insertIntegrationRows(t, database, "access_events", []integrationAccessRow{
		integrationAccess("capacity-access-decoy", nextPartition, ingestedAt, accessTenant, siteA, nodeA, "/decoy", "2001:db8::71"),
	})
	insertIntegrationRows(t, database, "security_events", []integrationSecurityRow{
		integrationSecurity("capacity-security-decoy", nextPartition, ingestedAt, securityTenant, "block", "/decoy"),
	})
}

func assertProductionCandidatePrunesPartitions(
	t *testing.T,
	database *integrationDatabase,
	productionQuery, tenantID string,
	filter Filter,
) {
	t.Helper()
	candidate, err := productionCandidateScan(productionQuery)
	if err != nil {
		t.Fatal(err)
	}
	parameters := filterParameters(scope{tenantID: tenantID}, filter, productionPageSize)
	parameters.Set("param_snapshot_ms", strconv.FormatInt(time.Now().UTC().UnixMilli(), 10))
	body, err := database.execute(context.Background(), "EXPLAIN indexes=1 "+candidate, true, parameters)
	if err != nil {
		t.Fatal(err)
	}
	explain := string(body)
	indexesAt := strings.Index(explain, "Indexes:")
	partitionIndex := strings.Index(explain, "Partition")
	if indexesAt < 0 || partitionIndex < indexesAt {
		t.Fatalf("production candidate EXPLAIN has no Partition index: %s", strings.TrimSpace(explain))
	}
	// ClickHouse 25.3 runs the MinMax index (same occurred_at key) before
	// Partition, so the other month's part is already gone there and the
	// Partition step alone reads 1/1: the part total is the first index
	// step's, the selected count the Partition step's.
	first := explainPartsPattern.FindStringSubmatch(explain[indexesAt:])
	match := explainPartsPattern.FindStringSubmatch(explain[partitionIndex:])
	if len(first) != 3 || len(match) != 3 {
		t.Fatalf("production candidate EXPLAIN has no partition Parts ratio: %s", strings.TrimSpace(explain))
	}
	selected, selectedErr := strconv.Atoi(match[1])
	total, totalErr := strconv.Atoi(first[2])
	if selectedErr != nil || totalErr != nil || selected < 1 || selected >= total {
		t.Fatalf("production candidate partition pruning Parts=%s/%s: %s", match[1], first[2], strings.TrimSpace(explain))
	}
}

func productionCandidateScan(productionQuery string) (string, error) {
	startMarker := "candidate_event_ids AS\n(\n"
	start := strings.Index(productionQuery, startMarker)
	if start < 0 {
		return "", errors.New("production query has no candidate_event_ids CTE")
	}
	start += len(startMarker)
	end := strings.Index(productionQuery[start:], "\n),\nselected_rows AS")
	if end < 0 {
		return "", errors.New("production query candidate_event_ids CTE is not extractable")
	}
	candidate := productionQuery[start : start+end]
	return "WITH fromUnixTimestamp64Milli({snapshot_ms:Int64}, 'UTC') AS snapshot_at\n" + candidate, nil
}

func paginateProductionClient(
	ctx context.Context,
	kind, prefix string,
	query func(context.Context, string) (capacityPage, error),
) capacityPaginationResult {
	result := capacityPaginationResult{Kind: kind, Prefix: prefix, IDs: make([]string, 0, productionCapacityRows)}
	seenCursors := make(map[string]struct{})
	var snapshot time.Time
	cursor := ""
	for {
		started := time.Now()
		page, err := query(ctx, cursor)
		result.Latencies = append(result.Latencies, time.Since(started))
		if err != nil {
			result.Err = err
			return result
		}
		if page.SnapshotAt.IsZero() {
			result.Err = errors.New("production Client returned an empty snapshot")
			return result
		}
		if snapshot.IsZero() {
			snapshot = page.SnapshotAt
		} else if !page.SnapshotAt.Equal(snapshot) {
			result.Err = fmt.Errorf("snapshot changed from %s to %s", snapshot, page.SnapshotAt)
			return result
		}
		result.IDs = append(result.IDs, page.IDs...)
		if page.NextCursor == "" {
			return result
		}
		if _, duplicate := seenCursors[page.NextCursor]; duplicate {
			result.Err = errors.New("production Client repeated a pagination cursor")
			return result
		}
		seenCursors[page.NextCursor] = struct{}{}
		cursor = page.NextCursor
	}
}

func assertCapacityPaginationResult(t *testing.T, result capacityPaginationResult) {
	t.Helper()
	if len(result.IDs) != productionCapacityRows {
		t.Fatalf("%s rows=%d, want %d", result.Kind, len(result.IDs), productionCapacityRows)
	}
	if len(result.Latencies) != productionCapacityRows/productionPageSize {
		t.Fatalf("%s pages=%d, want %d", result.Kind, len(result.Latencies), productionCapacityRows/productionPageSize)
	}
	seen := make(map[string]struct{}, len(result.IDs))
	for index, id := range result.IDs {
		want := fmt.Sprintf("%s%06d", result.Prefix, productionCapacityRows-1-index)
		if id != want {
			t.Fatalf("%s ordered id[%d]=%q, want %q", result.Kind, index, id, want)
		}
		if _, duplicate := seen[id]; duplicate {
			t.Fatalf("%s duplicate id %q", result.Kind, id)
		}
		seen[id] = struct{}{}
	}
	p95 := nearestRankDuration(result.Latencies, 95)
	p99 := nearestRankDuration(result.Latencies, 99)
	if p95 > productionP95Limit || p99 > productionP99Limit {
		t.Fatalf("%s production Client latency p95=%s p99=%s, limits=%s/%s",
			result.Kind, p95, p99, productionP95Limit, productionP99Limit)
	}
	t.Logf("%s production Client capacity rows=%d pages=%d p95=%s p99=%s",
		result.Kind, len(result.IDs), len(result.Latencies), p95, p99)
}

func nearestRankDuration(samples []time.Duration, percentile int) time.Duration {
	ordered := append([]time.Duration(nil), samples...)
	sort.Slice(ordered, func(left, right int) bool { return ordered[left] < ordered[right] })
	if len(ordered) == 0 || percentile < 1 || percentile > 100 {
		return 0
	}
	rank := (len(ordered)*percentile + 99) / 100
	return ordered[rank-1]
}
