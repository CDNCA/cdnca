package analytics

import (
	"encoding/json"
	"os"
	"path/filepath"
	"reflect"
	"strings"
	"testing"
	"time"
)

func TestOBSUsageAFiniteDeliveryAndHAStateContract(t *testing.T) {
	t.Parallel()
	config := DefaultJetStreamConfig()
	if got := expectedConsumer(config).MaxDeliver; got != -1 || config.MaxDeliver < 2 {
		t.Fatalf("broker MaxDeliver=%d application MaxDeliver=%d", got, config.MaxDeliver)
	}
	consumer := reflect.TypeOf(NATSIngestConsumer{})
	for _, field := range []string{"stateStore", "leaseStore", "streamCreated", "leaseRevision"} {
		if _, ok := consumer.FieldByName(field); !ok {
			t.Errorf("NATSIngestConsumer is missing durable HA field %q", field)
		}
	}
}

func TestOBSUsageAClickHousePersistentRollupAndReplicationContracts(t *testing.T) {
	t.Parallel()
	repoRoot := filepath.Clean(filepath.Join("..", "..", "..", ".."))
	checks := []struct {
		path  string
		parts []string
	}{
		{
			path: filepath.Join(repoRoot, "infra", "clickhouse", "migrations", "003_analytics_hourly_rollup.up.sql"),
			parts: []string{
				"CREATE TABLE IF NOT EXISTS access_hourly_facts_v1",
				"CREATE MATERIALIZED VIEW IF NOT EXISTS access_hourly_mv_v1",
				"ORDER BY (tenant_id, event_id)",
				"PARTITION BY toYYYYMM(hour)",
				"INSERT INTO access_hourly_facts_v1",
			},
		},
		{
			path: filepath.Join(repoRoot, "infra", "clickhouse", "rebuild-hourly-v1.sql"),
			parts: []string{
				"CREATE TABLE {access_shadow:Identifier} AS access_hourly_facts_v1",
				"EXCHANGE TABLES access_hourly_facts_v1 AND {access_shadow:Identifier}",
				"EXCHANGE TABLES security_hourly_facts_v1 AND {security_shadow:Identifier}",
			},
		},
		{
			path:  filepath.Join(repoRoot, "infra", "clickhouse", "replicated", "001_analytics.up.sql"),
			parts: []string{"ON CLUSTER", "ReplicatedReplacingMergeTree", "{shard}", "{replica}"},
		},
	}
	for _, check := range checks {
		contents, err := os.ReadFile(check.path)
		if err != nil {
			t.Errorf("required ClickHouse contract %s: %v", check.path, err)
			continue
		}
		for _, part := range check.parts {
			if !strings.Contains(string(contents), part) {
				t.Errorf("ClickHouse contract %s is missing %q", check.path, part)
			}
		}
	}
}

func TestOBSUsageASecretSegmentFinalAuthorityMatrix(t *testing.T) {
	now := time.Date(2026, time.August, 3, 0, 0, 0, 0, time.UTC)
	decoder, err := NewIngestDecoder(IngestDecoderConfig{Now: func() time.Time { return now }})
	if err != nil {
		t.Fatal(err)
	}
	validEvent := validAccessEvent("secret-authority-valid")
	validEvent.OccurredAt = now.Add(-time.Second)
	validEvent.Path = "/callback?client_secret=%5BREDACTED%5D&clientSecret=%5BREDACTED%5D&refreshSecret=%5BREDACTED%5D&secretary=query-neighbor&secretaryId=query-id&clientSecretive=query-secretive"
	validPayload := accessCapturePayload(t, validEvent, map[string]any{
		"request_headers": map[string]string{
			"X-Api-Secret": redactedCaptureValue, "X-Api-Secretary": "header-neighbor",
		},
		"request_body": map[string]any{
			"client_secret": redactedCaptureValue, "clientSecret": redactedCaptureValue, "refreshSecret": redactedCaptureValue,
			"secretary": "body-neighbor", "secretaryId": "body-id", "clientSecretive": "body-secretive",
			"nested": map[string]any{
				"client_secret": redactedCaptureValue, "clientSecret": redactedCaptureValue, "refreshSecret": redactedCaptureValue,
				"secretary": "nested-neighbor", "secretaryId": "nested-id", "clientSecretive": "nested-secretive",
			},
		},
	}, now)
	decoded, err := decoder.Decode(IngestSubjectPrefix+"."+testNodeID, "capture-message", validPayload)
	if err != nil {
		t.Fatalf("Control rejected the redacted secret marker matrix: %v", err)
	}
	got := decoded.AccessEvents[0]
	nested := got.RequestBody["nested"].(map[string]any)
	if got.RequestHeaders["X-Api-Secretary"] != "header-neighbor" ||
		got.RequestBody["secretary"] != "body-neighbor" || got.RequestBody["secretaryId"] != "body-id" ||
		got.RequestBody["clientSecretive"] != "body-secretive" || nested["secretary"] != "nested-neighbor" ||
		nested["secretaryId"] != "nested-id" || nested["clientSecretive"] != "nested-secretive" {
		t.Fatalf("non-sensitive neighbors changed: %#v", got)
	}

	for _, test := range []struct {
		name     string
		path     string
		captures map[string]any
	}{
		{name: "query", path: "/callback?client_secret=query-secret"},
		{name: "camel query", path: "/callback?clientSecret=camel-secret&refreshSecret=refresh-secret"},
		{name: "header", captures: map[string]any{"request_headers": map[string]string{"X-Api-Secret": "header-secret"}}},
		{name: "top-level body", captures: map[string]any{"request_body": map[string]any{"client_secret": "body-secret"}}},
		{name: "camel top-level body", captures: map[string]any{"request_body": map[string]any{"clientSecret": "body-secret", "refreshSecret": "refresh-secret"}}},
		{name: "nested body", captures: map[string]any{"request_body": map[string]any{"nested": map[string]any{"client_secret": "nested-secret"}}}},
		{name: "camel nested body", captures: map[string]any{"request_body": map[string]any{"nested": map[string]any{"clientSecret": "nested-secret", "refreshSecret": "nested-refresh"}}}},
	} {
		t.Run(test.name, func(t *testing.T) {
			event := validAccessEvent("secret-authority-" + strings.ReplaceAll(test.name, " ", "-"))
			event.OccurredAt = now.Add(-time.Second)
			if test.path != "" {
				event.Path = test.path
			}
			payload := accessCapturePayload(t, event, test.captures, now)
			if _, err := decoder.Decode(IngestSubjectPrefix+"."+testNodeID, "capture-message", payload); RejectionCode(err) != RejectInvalidEvent {
				t.Fatalf("Control accepted unredacted secret segment: %v payload=%s", err, json.RawMessage(payload))
			}
		})
	}
}
