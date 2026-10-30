package l4analytics

import (
	"net/http/httptest"
	"os"
	"path/filepath"
	"runtime"
	"strings"
	"testing"
	"time"

	agentv1 "github.com/cdnca/cdnca/proto/gen/go/agent/v1"
	commonv1 "github.com/cdnca/cdnca/proto/gen/go/common/v1"
	"google.golang.org/protobuf/types/known/timestamppb"
)

// L4-USAGE-01：检查点写 l4_usage_checkpoints_v1（按检查点时间、会话+序号为
// 去重键），结束事实写 checkpointed_bytes_up/down；检查点信封不写事实与会话日志。
func TestFactWriterWritesUsageCheckpointsAndCheckpointedBytes(t *testing.T) {
	fake := &fakeClickHouse{exists: true}
	server := httptest.NewServer(fake.handler(t))
	defer server.Close()
	source, err := NewClickHouseSource(ClickHouseConfig{Endpoint: server.URL, Database: "facts", QueryTimeout: time.Second, HTTPClient: server.Client()})
	if err != nil {
		t.Fatal(err)
	}
	writer, err := NewClickHouseFactWriterWithSessionLogs(t.Context(), source)
	if err != nil {
		t.Fatal(err)
	}
	at := time.Date(2026, 2, 1, 0, 0, 0, 0, time.UTC)
	checkpoint := &agentv1.L4UsageCheckpointV1{
		Event: &commonv1.EventMetadata{EventId: "l4ckpt_one"}, TenantId: testTenant, NodeId: testNode, SiteId: testSite,
		StreamId: testStream, ListenerId: testStream, ConfigVersionId: testStream, ConfigRevision: 1, Protocol: "tcp",
		ListenPort: 18080, SessionId: "17", StartedAt: timestamppb.New(at.Add(-2 * time.Minute)), CheckpointAt: timestamppb.New(at),
		Sequence: 2, BytesUp: 50, BytesDown: 4000, PackageSubscriptionId: "66666666-6666-4666-8666-666666666666",
	}
	envelope := &agentv1.L4SessionEnvelopeV1{SourceWatermark: 7, Checkpoints: []*agentv1.L4UsageCheckpointV1{checkpoint}}
	if err := writer.WriteEnvelope(t.Context(), envelope); err != nil {
		t.Fatal(err)
	}
	rows := fake.inserts["l4_usage_checkpoints_v1"]
	if len(rows) != 1 || len(fake.inserts["l4_session_facts_v1"]) != 0 || len(fake.inserts[sessionLogTable]) != 0 {
		t.Fatalf("inserts = %v", fake.inserts)
	}
	row := rows[0]
	if row["checkpoint_at"] != "2026-02-01 00:00:00.000" || row["sequence"] != float64(2) || row["bytes_down"] != float64(4000) ||
		row["session_id"] != "17" || row["started_at"] != "2026-01-31 23:58:00.000" || row["source_watermark"] != float64(7) ||
		row["package_subscription_id"] != "66666666-6666-4666-8666-666666666666" || row["event_id"] != "l4ckpt_one" {
		t.Fatalf("checkpoint row = %v", row)
	}
	checkpoint.PackageSubscriptionId = ""
	if err := writer.WriteEnvelope(t.Context(), envelope); err != nil {
		t.Fatal(err)
	}
	if got := fake.inserts["l4_usage_checkpoints_v1"][1]["package_subscription_id"]; got != "00000000-0000-0000-0000-000000000000" {
		t.Fatalf("unpackaged checkpoint package = %v", got)
	}

	ended := sessionEvent("ended", nil)
	ended.CheckpointedBytesUp, ended.CheckpointedBytesDown = 2, 3
	if err := writer.WriteEnvelope(t.Context(), &agentv1.L4SessionEnvelopeV1{SourceWatermark: 8,
		Events: []*agentv1.L4SessionEventV1{ended}}); err != nil {
		t.Fatal(err)
	}
	facts := fake.inserts["l4_session_facts_v1"]
	if len(facts) != 1 || facts[0]["checkpointed_bytes_up"] != float64(2) || facts[0]["checkpointed_bytes_down"] != float64(3) {
		t.Fatalf("facts = %v", facts)
	}
	if err := writer.WriteEnvelope(t.Context(), &agentv1.L4SessionEnvelopeV1{SourceWatermark: 9}); err == nil {
		t.Fatal("empty envelope accepted")
	}
}

// 摄取校验：检查点信封与事件信封一样要 tenant/site/node/config 一致、时间有效。
func TestDecodeL4EnvelopeAcceptsCheckpoints(t *testing.T) {
	at := time.Date(2026, 2, 1, 0, 0, 0, 0, time.UTC)
	checkpoint := &agentv1.L4UsageCheckpointV1{
		Event: &commonv1.EventMetadata{EventId: "l4ckpt_one"}, TenantId: testTenant, NodeId: testNode, SiteId: testSite,
		StreamId: testStream, ListenerId: testStream, ConfigVersionId: testStream, ConfigRevision: 1, Protocol: "tcp",
		ListenPort: 18080, SessionId: "17", StartedAt: timestamppb.New(at.Add(-time.Minute)), CheckpointAt: timestamppb.New(at),
		Sequence: 1, BytesUp: 1,
	}
	envelope := &agentv1.L4SessionEnvelopeV1{SchemaVersion: 1, MessageId: "l4msg_x", ProducedAt: timestamppb.New(at),
		TenantId: testTenant, NodeId: testNode, SiteId: testSite, ConfigVersionId: testStream, SourceWatermark: 1,
		FinalizedThrough: timestamppb.New(at), Checkpoints: []*agentv1.L4UsageCheckpointV1{checkpoint}}
	if err := validL4EnvelopeContents(envelope); err != nil {
		t.Fatalf("checkpoint envelope refused: %v", err)
	}
	checkpoint.TenantId = testSite
	if validL4EnvelopeContents(envelope) == nil {
		t.Fatal("checkpoint of another tenant accepted")
	}
	checkpoint.TenantId, checkpoint.CheckpointAt = testTenant, nil
	if validL4EnvelopeContents(envelope) == nil {
		t.Fatal("checkpoint without its time accepted")
	}
	checkpoint.CheckpointAt = timestamppb.New(at)
	envelope.Events = []*agentv1.L4SessionEventV1{sessionEvent("x", nil)}
	if validL4EnvelopeContents(envelope) == nil {
		t.Fatal("mixed envelope accepted")
	}
}

// CH 029：检查点表按检查点时间分区（跨月落各自月份）、会话+序号为替换键、
// 与计费事实同为 400 天；事实表加已检查点字节两列。不存原始地址。
func TestUsageCheckpointMigration(t *testing.T) {
	_, file, _, _ := runtime.Caller(0)
	root := filepath.Clean(filepath.Join(filepath.Dir(file), "../../../../"))
	up, err := os.ReadFile(filepath.Join(root, "infra/clickhouse/migrations/029_l4_usage_checkpoints.up.sql"))
	if err != nil {
		t.Fatal(err)
	}
	text := string(up)
	for _, want := range []string{
		"CREATE TABLE IF NOT EXISTS l4_usage_checkpoints_v1", "checkpoint_at DateTime64(3, 'UTC')", "sequence UInt32",
		"ENGINE = ReplacingMergeTree(source_watermark)", "PARTITION BY toYYYYMM(checkpoint_at)",
		"ORDER BY (tenant_id, node_id, listener_id, session_id, started_at, sequence)",
		"TTL toDateTime(checkpoint_at, 'UTC') + INTERVAL 400 DAY DELETE",
		"ADD COLUMN IF NOT EXISTS checkpointed_bytes_up UInt64 DEFAULT 0", "ADD COLUMN IF NOT EXISTS checkpointed_bytes_down UInt64 DEFAULT 0",
	} {
		if !strings.Contains(text, want) {
			t.Fatalf("checkpoint migration omitted %q", want)
		}
	}
	if strings.Contains(strings.ToLower(text), "client_ip") || strings.Contains(strings.ToLower(text), "upstream_addr") {
		t.Fatal("checkpoint schema persisted a raw address")
	}
}
