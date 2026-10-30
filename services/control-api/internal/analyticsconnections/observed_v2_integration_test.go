package analyticsconnections

import (
	"bytes"
	"context"
	"encoding/json"
	"errors"
	"io"
	"net/http"
	"net/url"
	"os"
	"path/filepath"
	"strings"
	"testing"
	"time"

	"github.com/google/uuid"
	"google.golang.org/protobuf/types/known/timestamppb"
)

type observedV2ErrorTransport struct{ body string }

func (transport *observedV2ErrorTransport) RoundTrip(request *http.Request) (*http.Response, error) {
	response, err := http.DefaultTransport.RoundTrip(request)
	if err == nil && response.StatusCode >= 300 {
		body, _ := io.ReadAll(io.LimitReader(response.Body, 4096))
		response.Body.Close()
		response.Body = io.NopCloser(bytes.NewReader(body))
		transport.body = string(body)
	}
	return response, err
}

// This creates a uniquely named database and never writes to the configured
// production database. Credentials are read only from the test environment.
func TestObservedV2ClickHouseRoundTrip(t *testing.T) {
	endpoint := os.Getenv("REALTIME_TEST_CH_URL")
	if endpoint == "" {
		t.Skip("REALTIME_TEST_CH_URL required")
	}
	name := "realtime_task_test_" + strings.ReplaceAll(uuid.NewString(), "-", "")
	diagnostic := &observedV2ErrorTransport{}
	writer, err := NewClickHouseWriter(ClickHouseConfig{Endpoint: endpoint, Database: name,
		Username: os.Getenv("REALTIME_TEST_CH_USER"), Password: os.Getenv("REALTIME_TEST_CH_PASSWORD")}, &http.Client{Transport: diagnostic})
	if err != nil {
		t.Fatal(err)
	}
	if _, err := writer.execute(t.Context(), "CREATE DATABASE "+name, nil, nil, false); err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() {
		ctx, cancel := context.WithTimeout(context.Background(), 10*time.Second)
		defer cancel()
		if _, err := writer.execute(ctx, "DROP DATABASE "+name+" SYNC", nil, nil, false); err != nil {
			t.Errorf("cleanup task database: %v", err)
		}
	})
	values := url.Values{"database": {name}}
	root := os.Getenv("REALTIME_TEST_CH_MIGRATIONS")
	if root == "" {
		root = "../../../../infra/clickhouse/migrations"
	}
	for _, file := range []string{"007_connections_ingest_receipts.up.sql", "013_connections_finalized_dimensions.up.sql", "016_independent_connection_observations.up.sql"} {
		data, err := os.ReadFile(filepath.Join(root, file))
		if err != nil {
			t.Fatal(err)
		}
		var sql []string
		for _, line := range strings.Split(string(data), "\n") {
			if !strings.HasPrefix(strings.TrimSpace(line), "--") {
				sql = append(sql, line)
			}
		}
		for _, statement := range strings.Split(strings.Join(sql, "\n"), ";") {
			if strings.TrimSpace(statement) == "" {
				continue
			}
			if _, err := writer.execute(t.Context(), statement, values, nil, false); err != nil {
				t.Fatalf("%s: %v", file, err)
			}
		}
	}
	delivery := runtimeRedeliveryDelivery(t, 1, 8)
	delivery.Envelope.SchemaVersion, delivery.Envelope.Connections = 2, 0
	delivery.Envelope.PackageSubscriptionId = ""
	delivery.Envelope.ConfigVersionId = uuid.NewString()
	now := time.Now().UTC().Truncate(time.Millisecond)
	delivery.Envelope.Event.OccurredTime = timestamppb.New(now)
	delivery.Envelope.FinalizedThrough = timestamppb.New(now)
	receipt, err := ValidateDelivery(delivery)
	if err != nil {
		t.Fatal(err)
	}
	for attempt := 0; attempt < 2; attempt++ {
		if err := writer.Prepare(t.Context(), receipt); err != nil {
			t.Fatalf("prepare attempt %d: %v; ClickHouse: %s", attempt, err, diagnostic.body)
		}
	}
	if err := writer.MarkBrokerAckObserved(t.Context(), receipt, receipt.PubAck); err != nil {
		t.Fatal(err)
	}
	rows, err := writer.lookup(t.Context(), receipt)
	if err != nil || len(rows) != 1 || rows[0].Connections != 0 || rows[0].State != StateBrokerAckObserved || rows[0].ConfigVersionID != receipt.ConfigVersionID {
		t.Fatalf("v2 zero receipt: rows=%d err=%v", len(rows), err)
	}
	conflict := receipt
	conflict.ConfigVersionID = uuid.NewString()
	conflict.ClickHouseToken = ClickHouseInsertToken(conflict)
	if err := writer.Prepare(t.Context(), conflict); !errors.Is(err, ErrReceiptConflict) {
		t.Fatalf("config conflict: %v", err)
	}
	for _, legacy := range []bool{false, true} {
		row, _ := newReceiptInsertRow(receipt)
		row.EventID, row.ReceiptID = uuid.NewString(), uuid.NewString()
		row.ConfigVersionID = uuid.Nil.String()
		if legacy {
			row.SchemaVersion = 1
			row.PackageSubscriptionID = uuid.NewString()
		}
		encoded, _ := json.Marshal(row)
		if _, err := writer.execute(t.Context(), insertReceiptSQL, values, encoded, false); err == nil {
			t.Fatalf("invalid schema=%d zero/config accepted", row.SchemaVersion)
		}
	}
}
