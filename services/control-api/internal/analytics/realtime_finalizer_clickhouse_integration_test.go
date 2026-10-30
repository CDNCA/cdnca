package analytics

import (
	"bytes"
	"context"
	"crypto/sha256"
	"encoding/hex"
	"io"
	"net/http"
	"os"
	"path/filepath"
	"runtime"
	"strings"
	"testing"
	"time"
)

type realtimeConnectionReceiptIntegrationRow struct {
	SchemaVersion         uint32    `json:"schema_version"`
	ReceiptID             string    `json:"receipt_id"`
	BatchID               string    `json:"batch_id"`
	EventID               string    `json:"event_id"`
	TenantID              string    `json:"tenant_id"`
	NodeID                string    `json:"node_id"`
	Domain                string    `json:"domain"`
	ListenPort            uint16    `json:"listen_port"`
	InstallationID        string    `json:"installation_id"`
	SiteID                string    `json:"site_id"`
	PackageSubscriptionID string    `json:"package_subscription_id"`
	OccurredAt            time.Time `json:"occurred_at"`
	Connections           uint64    `json:"connections"`
	PayloadSHA256         string    `json:"payload_sha256"`
	CanonicalEventSHA256  string    `json:"canonical_event_sha256"`
	EvidenceSHA256        string    `json:"evidence_sha256"`
	SourceWatermark       uint64    `json:"source_watermark"`
	FinalizedThrough      time.Time `json:"finalized_through"`
	NATSStream            string    `json:"nats_stream"`
	NATSDurable           string    `json:"nats_durable"`
	NATSStreamSequence    uint64    `json:"nats_stream_sequence"`
	NATSConsumerSequence  uint64    `json:"nats_consumer_sequence"`
	PubackStream          string    `json:"puback_stream"`
	PubackSequence        uint64    `json:"puback_sequence"`
	PubackDuplicate       uint8     `json:"puback_duplicate"`
	ClickHouseInsertToken string    `json:"clickhouse_insert_token"`
	State                 string    `json:"state"`
	StateRank             uint8     `json:"state_rank"`
	ReceivedAt            time.Time `json:"received_at"`
	UpdatedAt             time.Time `json:"updated_at"`
}

type realtimeClickHouseErrorCapture struct {
	body []byte
}

func (capture *realtimeClickHouseErrorCapture) RoundTrip(request *http.Request) (*http.Response, error) {
	response, err := http.DefaultTransport.RoundTrip(request)
	if err != nil || response.StatusCode < http.StatusMultipleChoices {
		return response, err
	}
	capture.body, _ = io.ReadAll(io.LimitReader(response.Body, 64<<10))
	_ = response.Body.Close()
	response.Body = io.NopCloser(bytes.NewReader(capture.body))
	return response, nil
}

func TestClickHouseRealtimeConnectionEvidenceRoundTrip(t *testing.T) {
	database := newRankTestDatabase(t)
	database.reset(t)
	applyRealtimeFinalizerClickHouseMigrations(t, database)
	candidate, _, _, _ := realtimeCoverageFixture(t)
	nodeA := "018f0000-0000-7000-8000-000000000004"
	nodeB := "018f0000-0000-7000-8000-000000000005"
	packageID := "018f0000-0000-7000-8000-000000000007"
	rows := []realtimeConnectionReceiptIntegrationRow{
		realtimeConnectionReceiptRow(candidate, nodeA, packageID, "node-a-11", 11, strings.Repeat("a", 64), 1, "received", 1),
		realtimeConnectionReceiptRow(candidate, nodeA, packageID, "node-a-11", 11, strings.Repeat("a", 64), 1, "ch_prepared", 2),
		realtimeConnectionReceiptRow(candidate, nodeA, packageID, "node-a-12", 12, strings.Repeat("b", 64), 2, "broker_ack_observed", 3),
		realtimeConnectionReceiptRow(candidate, nodeB, packageID, "node-b-21", 21, strings.Repeat("c", 64), 3, "ch_prepared", 2),
	}
	for index, mutate := range []func(*realtimeConnectionReceiptIntegrationRow){
		func(row *realtimeConnectionReceiptIntegrationRow) {
			row.TenantID = "018f0000-0000-7000-8000-000000000008"
		},
		func(row *realtimeConnectionReceiptIntegrationRow) {
			row.SiteID = "018f0000-0000-7000-8000-000000000009"
		},
		func(row *realtimeConnectionReceiptIntegrationRow) { row.Domain = "foreign.example.test" },
		func(row *realtimeConnectionReceiptIntegrationRow) { row.ListenPort = 8443 },
	} {
		row := realtimeConnectionReceiptRow(candidate, nodeA, packageID, "foreign-"+string(rune('a'+index)), uint64(30+index), strings.Repeat("d", 64), uint64(10+index), "ch_prepared", 2)
		mutate(&row)
		rows = append(rows, row)
	}
	insertRankRows(t, database, "INSERT INTO connections_ingest_receipts_v1 FORMAT JSONEachRow", rows)
	errorCapture := new(realtimeClickHouseErrorCapture)
	client, err := NewClient(Config{
		Endpoint: database.endpoint, Database: database.name, Username: database.username, Password: database.password,
		QueryTimeout: 3 * time.Second,
	}, &http.Client{Transport: errorCapture, Timeout: 5 * time.Second})
	if err != nil {
		t.Fatal(err)
	}
	reader, err := NewClickHouseRealtimeConnectionEvidenceReader(client)
	if err != nil {
		t.Fatal(err)
	}
	evidence, err := reader.RealtimeConnectionEvidence(t.Context(), candidate)
	if err != nil || len(evidence) != 2 || evidence[0].NodeID != nodeA || evidence[0].SourceWatermark != 12 ||
		evidence[1].NodeID != nodeB || evidence[1].SourceWatermark != 21 {
		t.Fatalf("connection evidence=%#v error=%v clickhouse=%s", evidence, err, strings.TrimSpace(string(errorCapture.body)))
	}
	wantNodeADigest := sha256.Sum256([]byte("11:" + strings.Repeat("a", 64) + "\n12:" + strings.Repeat("b", 64)))
	wantNodeBDigest := sha256.Sum256([]byte("21:" + strings.Repeat("c", 64)))
	if evidence[0].EvidenceSHA256 != wantNodeADigest || evidence[1].EvidenceSHA256 != wantNodeBDigest ||
		!evidence[0].RecordedAt.Equal(candidate.WindowEnd) || !evidence[1].FinalizedThrough.Equal(candidate.WindowEnd) {
		t.Fatalf("aggregated evidence=%#v", evidence)
	}

	conflict := realtimeConnectionReceiptRow(candidate, nodeA, packageID, "node-a-12-conflict", 12, strings.Repeat("e", 64), 4, "ch_prepared", 2)
	insertRankRows(t, database, "INSERT INTO connections_ingest_receipts_v1 FORMAT JSONEachRow", []realtimeConnectionReceiptIntegrationRow{conflict})
	if _, err := reader.RealtimeConnectionEvidence(t.Context(), candidate); err != ErrRealtimeCoverageConflict {
		t.Fatalf("conflicting source evidence error=%v", err)
	}
}

func realtimeConnectionReceiptRow(
	candidate RealtimeCoverageCandidateV1,
	nodeID string,
	packageID string,
	eventID string,
	watermark uint64,
	evidence string,
	sequence uint64,
	state string,
	stateRank uint8,
) realtimeConnectionReceiptIntegrationRow {
	digestBytes := sha256.Sum256([]byte(eventID))
	digest := hex.EncodeToString(digestBytes[:])
	return realtimeConnectionReceiptIntegrationRow{
		SchemaVersion: 1, ReceiptID: eventID, BatchID: eventID, EventID: eventID,
		TenantID: candidate.TenantID, NodeID: nodeID, Domain: candidate.Host, ListenPort: candidate.ListenPort,
		InstallationID: "installation-v1", SiteID: candidate.SiteID, PackageSubscriptionID: packageID,
		OccurredAt: candidate.WindowStart.Add(time.Duration(sequence) * time.Minute), Connections: sequence,
		PayloadSHA256: digest, CanonicalEventSHA256: digest, EvidenceSHA256: evidence,
		SourceWatermark: watermark, FinalizedThrough: candidate.WindowEnd,
		NATSStream: "ANALYTICS", NATSDurable: "analytics", NATSStreamSequence: sequence,
		NATSConsumerSequence: sequence, PubackStream: "ANALYTICS", PubackSequence: sequence,
		ClickHouseInsertToken: digest, State: state, StateRank: stateRank,
		ReceivedAt: candidate.WindowEnd, UpdatedAt: candidate.WindowEnd.Add(time.Duration(stateRank) * time.Second),
	}
}

func applyRealtimeFinalizerClickHouseMigrations(t *testing.T, database *rankTestDatabase) {
	t.Helper()
	_, currentFile, _, ok := runtime.Caller(0)
	if !ok {
		t.Fatal("locate realtime finalizer integration test")
	}
	root := filepath.Clean(filepath.Join(filepath.Dir(currentFile), "..", "..", "..", ".."))
	migrationRoot := filepath.Join(root, "infra", "clickhouse", "migrations")
	if override := os.Getenv("ANALYTICS_TEST_CH_MIGRATIONS"); override != "" {
		migrationRoot = override
	}
	for _, name := range []string{
		"005_package_monitor_metrics.up.sql", "006_access_event_state.up.sql", "007_connections_ingest_receipts.up.sql",
		"008_security_event_state.up.sql", "009_site_realtime_monitoring.up.sql", "010_global_firewall_events.up.sql",
		"011_l4_session_facts.up.sql", "012_analytics_log_query_projection.up.sql",
		"013_connections_finalized_dimensions.up.sql", "014_analytics_access_listen_port_projection.up.sql",
		"015_site_realtime_coverage_authority.up.sql", "016_independent_connection_observations.up.sql",
	} {
		migration, err := os.ReadFile(filepath.Join(migrationRoot, name))
		if err != nil {
			t.Fatal(err)
		}
		for _, statement := range realtimeFinalizerMigrationStatements(string(migration)) {
			if err := database.execute(context.Background(), statement, true, nil); err != nil {
				t.Fatalf("apply ClickHouse migration %s: %v", name, err)
			}
		}
	}
}

func realtimeFinalizerMigrationStatements(migration string) []string {
	lines := make([]string, 0)
	for _, line := range strings.Split(migration, "\n") {
		if !strings.HasPrefix(strings.TrimSpace(line), "--") {
			lines = append(lines, line)
		}
	}
	statements := make([]string, 0)
	for _, raw := range strings.Split(strings.Join(lines, "\n"), ";") {
		if statement := strings.TrimSpace(raw); statement != "" {
			statements = append(statements, statement)
		}
	}
	return statements
}
