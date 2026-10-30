package analytics

import (
	"net/http"
	"os"
	"testing"
	"time"

	"github.com/jackc/pgx/v5/pgxpool"
)

// Explicit opt-in read-only acceptance against an already settled real window.
// No fixture, source evidence, ACK or coverage fact is created by this test.
func TestRealtimeLiveReadOnlySettledWindow(t *testing.T) {
	if os.Getenv("REALTIME_LIVE_READ_ONLY") != "1" {
		t.Skip("explicit read-only live acceptance opt-in required")
	}
	from, err := time.Parse(time.RFC3339, os.Getenv("REALTIME_LIVE_FROM"))
	if err != nil {
		t.Fatal(err)
	}
	pool, err := pgxpool.New(t.Context(), os.Getenv("DATABASE_URL"))
	if err != nil {
		t.Fatal(err)
	}
	defer pool.Close()
	reader, _ := NewPostgresRealtimeExpectedCountReader(pool)
	filter := RealtimeFilter{From: from.UTC(), To: from.Add(time.Hour).UTC()}
	evidence, err := reader.ExpectedRealtimeEvidence(t.Context(), AdminScope(), filter)
	if err != nil {
		t.Fatalf("Postgres source coverage: %v", err)
	}
	t.Logf("covered=%d/%d access=%d/%d connections=%d/%d expected_events=%d", evidence.CoveredWindows, evidence.RequestedWindows, evidence.AccessSourcesFinalized, evidence.AccessSourcesExpected, evidence.ConnectionSourcesFinalized, evidence.ConnectionSourcesExpected, evidence.ExpectedEvents)
	capture := &realtimeClickHouseErrorCapture{}
	client, err := NewClient(Config{Endpoint: os.Getenv("CLICKHOUSE_URL"), Database: os.Getenv("CLICKHOUSE_DATABASE"), Username: os.Getenv("CLICKHOUSE_USERNAME"), Password: os.Getenv("CLICKHOUSE_PASSWORD")}, &http.Client{Transport: capture, Timeout: 10 * time.Second})
	if err != nil {
		t.Fatal(err)
	}
	result, err := client.Realtime(t.Context(), AdminScope(), filter)
	if err != nil {
		t.Fatalf("ClickHouse realtime: %v; diagnostic=%s", err, capture.body)
	}
	t.Logf("summary=%+v evidence=%+v", result.Summary, result.Evidence)
	service, _ := NewServiceWithRealtimeExpectedCounts(client, reader)
	if _, err := service.Realtime(t.Context(), Actor{ScopeKind: "platform", Permissions: []string{"platform.admin"}}, RealtimeRequest{Audience: AudiencePlatform, From: filter.From, To: filter.To}); err != nil {
		t.Fatalf("service validation: %v", err)
	}
}
