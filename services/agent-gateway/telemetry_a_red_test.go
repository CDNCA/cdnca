package gateway

import (
	"testing"
	"time"

	agentv1 "github.com/cdnca/cdnca/proto/gen/go/agent/v1"
	"github.com/nats-io/nats.go"
)

func TestOBSUsageARejectsUnavailableTaskAndJA4Authority(t *testing.T) {
	t.Parallel()
	for _, kind := range []agentv1.TelemetryKind{
		agentv1.TelemetryKind_TELEMETRY_KIND_ACCESS_V1,
		agentv1.TelemetryKind_TELEMETRY_KIND_SECURITY_V1,
	} {
		for _, field := range []string{"task_id", "ja4"} {
			t.Run(kind.String()+"/"+field, func(t *testing.T) {
				batch := telemetryCaptureBatch(t, kind, map[string]any{field: "authoritative-looking-but-unavailable"})
				if _, err := validateTelemetryBatch(batch, 1, nodeIdentity{NodeID: testNodeID},
					telemetryTestAuthorization(), DefaultTelemetryConfig(), time.Now()); err == nil {
					t.Fatalf("Gateway accepted self-reported %s while capability authority is unavailable", field)
				}
			})
		}
		// The node's own $cdnca_ja4 (one JA4 exactly) is accepted.
		t.Run(kind.String()+"/ja4-fingerprint", func(t *testing.T) {
			batch := telemetryCaptureBatch(t, kind, map[string]any{"ja4": "t13d1516h2_8daaf6152771_e5627efa2ab1"})
			if _, err := validateTelemetryBatch(batch, 1, nodeIdentity{NodeID: testNodeID},
				telemetryTestAuthorization(), DefaultTelemetryConfig(), time.Now()); err != nil {
				t.Fatalf("Gateway rejected a node JA4 fingerprint: %v", err)
			}
		})
	}
}

func TestOBSUsageARejectsTelemetryStreamRetentionHoles(t *testing.T) {
	t.Parallel()
	valid := nats.StreamConfig{
		Name: "ANALYTICS_INGEST_V1", Subjects: []string{TelemetryIngestSubjectPrefix + ".*"},
		Retention: nats.WorkQueuePolicy, MaxConsumers: 1, MaxMsgs: 10_000_000, MaxBytes: 10 << 30,
		Discard: nats.DiscardNew, MaxAge: 0, MaxMsgsPerSubject: -1, MaxMsgSize: 1 << 20,
		Storage: nats.FileStorage, Replicas: 1, Duplicates: 10 * time.Minute,
	}
	if !validTelemetryStreamInfo(&nats.StreamInfo{Config: valid}) {
		t.Fatal("authoritative durable telemetry stream was rejected")
	}
	tests := map[string]func(*nats.StreamConfig){
		"limits retention":       func(config *nats.StreamConfig) { config.Retention = nats.LimitsPolicy },
		"discard old":            func(config *nats.StreamConfig) { config.Discard = nats.DiscardOld },
		"age eviction":           func(config *nats.StreamConfig) { config.MaxAge = time.Hour },
		"unbounded bytes":        func(config *nats.StreamConfig) { config.MaxBytes = -1 },
		"unbounded messages":     func(config *nats.StreamConfig) { config.MaxMsgs = -1 },
		"multiple consumers":     func(config *nats.StreamConfig) { config.MaxConsumers = -1 },
		"per-subject eviction":   func(config *nats.StreamConfig) { config.MaxMsgsPerSubject = 1 },
		"undersized message cap": func(config *nats.StreamConfig) { config.MaxMsgSize = (1 << 20) - 1 },
	}
	for name, mutate := range tests {
		t.Run(name, func(t *testing.T) {
			actual := valid
			mutate(&actual)
			if validTelemetryStreamInfo(&nats.StreamInfo{Config: actual}) {
				t.Fatalf("retention-hole stream %q was accepted", name)
			}
		})
	}
}

func TestOBSUsageASecretSegmentAuthorityMatrix(t *testing.T) {
	valid := map[string]any{
		"path": "/callback?client_secret=%5BREDACTED%5D&clientSecret=%5BREDACTED%5D&refreshSecret=%5BREDACTED%5D&secretary=query-neighbor&secretaryId=query-id&clientSecretive=query-secretive",
		"request_headers": map[string]any{
			"X-Api-Secret": "[REDACTED]", "X-Api-Secretary": "header-neighbor",
		},
		"request_body": map[string]any{
			"client_secret": "[REDACTED]", "clientSecret": "[REDACTED]", "refreshSecret": "[REDACTED]",
			"secretary": "body-neighbor", "secretaryId": "body-id", "clientSecretive": "body-secretive",
			"nested": map[string]any{
				"client_secret": "[REDACTED]", "clientSecret": "[REDACTED]", "refreshSecret": "[REDACTED]",
				"secretary": "nested-neighbor", "secretaryId": "nested-id", "clientSecretive": "nested-secretive",
			},
		},
	}
	if _, err := validateTelemetryBatch(telemetryCaptureBatch(t,
		agentv1.TelemetryKind_TELEMETRY_KIND_ACCESS_V1, valid), 1, nodeIdentity{NodeID: testNodeID},
		telemetryTestAuthorization(), DefaultTelemetryConfig(), time.Now()); err != nil {
		t.Fatalf("redacted secret marker matrix was rejected: %v", err)
	}
	for _, test := range []struct {
		name    string
		capture map[string]any
	}{
		{name: "query", capture: map[string]any{"path": "/callback?client_secret=query-secret"}},
		{name: "camel query", capture: map[string]any{"path": "/callback?clientSecret=camel-secret&refreshSecret=refresh-secret"}},
		{name: "header", capture: map[string]any{"request_headers": map[string]any{"X-Api-Secret": "header-secret"}}},
		{name: "top-level body", capture: map[string]any{"request_body": map[string]any{"client_secret": "body-secret"}}},
		{name: "camel top-level body", capture: map[string]any{"request_body": map[string]any{"clientSecret": "body-secret", "refreshSecret": "refresh-secret"}}},
		{name: "nested body", capture: map[string]any{"request_body": map[string]any{"nested": map[string]any{"client_secret": "nested-secret"}}}},
		{name: "camel nested body", capture: map[string]any{"request_body": map[string]any{"nested": map[string]any{"clientSecret": "nested-secret", "refreshSecret": "nested-refresh"}}}},
	} {
		t.Run(test.name, func(t *testing.T) {
			if _, err := validateTelemetryBatch(telemetryCaptureBatch(t,
				agentv1.TelemetryKind_TELEMETRY_KIND_ACCESS_V1, test.capture), 1,
				nodeIdentity{NodeID: testNodeID}, telemetryTestAuthorization(), DefaultTelemetryConfig(), time.Now()); err == nil {
				t.Fatal("Gateway accepted an unredacted secret segment")
			}
		})
	}
}
