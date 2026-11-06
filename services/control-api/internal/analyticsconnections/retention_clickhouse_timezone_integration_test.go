//go:build integration

package analyticsconnections

import (
	"context"
	"net/http"
	"os"
	"strings"
	"testing"
	"time"

	"github.com/google/uuid"
)

// The retention range is sent as UTC "YYYY-MM-DD hh:mm:ss.sss" typed
// DateTime64(3, 'UTC'). Before, it was RFC3339 with a trailing Z, which
// ClickHouse refuses as a DateTime64 query parameter (BAD_QUERY_PARAMETER), and
// a bare DateTime64(3) would read it in the server's time zone. The session
// time zone is pinned to Asia/Shanghai (CDNCA_TEST_CLICKHOUSE_URL with the
// ClickHouse migrations applied).
func TestClickHouseRetentionReaderReadsUTCRangeOnShanghaiServer(t *testing.T) {
	endpoint := strings.TrimSpace(os.Getenv("CDNCA_TEST_CLICKHOUSE_URL"))
	if endpoint == "" {
		t.Skip("CDNCA_TEST_CLICKHOUSE_URL is not set")
	}
	client := retentionHTTPClient(func(request *http.Request) (*http.Response, error) {
		values := request.URL.Query()
		values.Set("session_timezone", "Asia/Shanghai")
		request.URL.RawQuery = values.Encode()
		return http.DefaultClient.Do(request)
	})
	config := ClickHouseConfig{Endpoint: endpoint, Database: "default", OperationTimeout: 10 * time.Second, MaxResponseBytes: 1 << 20}
	writer, err := NewClickHouseWriter(config, client)
	if err != nil {
		t.Fatal(err)
	}
	tenant, subscription := uuid.NewString(), uuid.NewString()
	start := time.Date(2026, 11, 6, 2, 0, 0, 0, time.UTC)
	// package_metric_finalized_v1 is a view; its connections rows come from the hourly max of these samples.
	insert := `INSERT INTO package_metric_connection_facts_v1 (metric_version, tenant_id, package_subscription_id, installation_id,
sample_id, sampled_at, window_start, window_end, active_connections) VALUES (1, '` + tenant + `', '` + subscription + `', 'tz-test',
'tz-` + uuid.NewString() + `', toDateTime64('2026-11-06 02:15:00.000', 3, 'UTC'), toDateTime64('2026-11-06 02:10:00.000', 3, 'UTC'),
toDateTime64('2026-11-06 02:15:00.000', 3, 'UTC'), 42)`
	if _, err := writer.execute(context.Background(), insert, nil, nil, false); err != nil {
		t.Fatalf("insert: %v", err)
	}
	reader, err := NewClickHouseRetentionReader(config, RetentionConfig{MaxRows: 10, MaxResponseBytes: 1 << 16, TTL: DefaultRetentionTTL,
		Now: func() time.Time { return start.Add(2 * time.Hour) }}, client)
	if err != nil {
		t.Fatal(err)
	}
	rows, err := reader.Read(t.Context(), RetentionQuery{TenantID: tenant, SubscriptionID: subscription, From: start, To: start.Add(time.Hour)})
	if err != nil {
		t.Fatalf("read: %v", err)
	}
	if len(rows) != 1 || rows[0].Value != 42 || !rows[0].PeriodStart.Equal(start) {
		t.Fatalf("rows = %+v; want the 02:00-03:00 UTC period", rows)
	}
}
