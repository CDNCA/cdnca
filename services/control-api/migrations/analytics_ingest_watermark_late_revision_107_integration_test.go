package migrations

import (
	"crypto/sha256"
	"fmt"
	"os"
	"strings"
	"testing"
)

func TestAnalyticsIngestWatermarkLateRevision107StaticContract(t *testing.T) {
	up := readAnalyticsIngestWatermarkLateRevision107(t, "107_analytics_ingest_watermark_late_revision.up.sql")
	down := readAnalyticsIngestWatermarkLateRevision107(t, "107_analytics_ingest_watermark_late_revision.down.sql")
	goSource := readAnalyticsIngestWatermarkLateRevision107(t, "../internal/analytics/watermark.go")

	for _, fragment := range []string{
		"migration 107 requires the exact verified 106 release head",
		"migration_id='106_dns_provider_credential_lifecycle'",
		"checksum_sha256='097ca7d3fcdf878ff11cc891e8a8b05abe3dfd923b9153fdc15ee616d3415adf'",
		"down_checksum_sha256='08ce9a086b6b9be1a78a466e62303bafa76d7cdd6cef060b001d4f0db14dd1df'",
		"REQUIRED_MIGRATION_106_INTEGRATION_SHA256=9af7dcdf823cf088718e8573059d4f6ac6bc6ba4852a7d954db31d093fdab861",
		"USING ERRCODE='P1070'",
		"CREATE TABLE analytics_ingest_watermarks_107",
		"tenant_id uuid NOT NULL REFERENCES tenants(id) ON DELETE RESTRICT",
		"installation_id text NOT NULL",
		"REFERENCES control_installation_entitlement(installation_id) ON DELETE RESTRICT",
		"kind text NOT NULL",
		"history_epoch uuid NOT NULL",
		"REFERENCES analytics_history_streams(history_epoch) ON DELETE RESTRICT",
		"watermark_sequence numeric(20,0) NOT NULL",
		"allowed_lateness interval NOT NULL",
		"finalized_through timestamptz NOT NULL",
		"dependency_state text NOT NULL",
		"dependency_state IN ('ready','unknown','unavailable')",
		"last_event_at timestamptz NOT NULL",
		"last_known_good_sequence numeric(20,0) NOT NULL",
		"last_known_good_revision numeric(20,0) NOT NULL",
		"CREATE TABLE analytics_ingest_watermark_decisions_107",
		"decision text NOT NULL CHECK (decision IN (",
		"'accepted','replay','late_revision','baseline_off','rejected'",
		"'baseline_off','accepted','replay','late_revision','finalized_window'",
		"'late_revision_exceeded','out_of_order','digest_conflict'",
		"'dependency_unknown','dependency_unavailable'",
		"UNIQUE (tenant_id,installation_id,kind,event_id)",
		"UNIQUE (tenant_id,installation_id,kind,idempotency_key)",
		"FOREIGN KEY (tenant_id,installation_id,kind)",
		"CREATE FUNCTION guard_analytics_ingest_watermark_107()",
		"CREATE FUNCTION guard_analytics_ingest_watermark_decision_107()",
		"CREATE FUNCTION analytics_history_generation_digest_107(",
		"cdnca.analytics-history-generation/v1",
		"CREATE FUNCTION analytics_ingest_commit_watermark_107(",
		"FOR UPDATE",
		"p_occurred_at<=watermark.finalized_through",
		"watermark.watermark_at-p_occurred_at>watermark.allowed_lateness",
		"p_event_sequence<=watermark.watermark_sequence",
		"p_event_sequence<generation.history_start_sequence",
		"FROM analytics_ingest_receipts",
		"durable_receipt.receipt_identity_sha256 IS DISTINCT FROM p_receipt_identity_sha256",
		"durable_receipt.canonical_event_sha256 IS DISTINCT FROM p_event_digest_sha256",
		"current_generation_digest",
		"durable_receipt.generation_sha256 IS DISTINCT FROM current_generation_digest",
		"same receipt and digest replay",
		"preserve the last known good state",
		"analytics_ingest_watermarks_append_only_107",
		"BEFORE TRUNCATE ON analytics_ingest_watermarks_107",
		"BEFORE TRUNCATE ON analytics_ingest_watermark_decisions_107",
		"REVOKE ALL ON analytics_ingest_watermarks_107,analytics_ingest_watermark_decisions_107 FROM PUBLIC",
	} {
		if !strings.Contains(up, fragment) {
			t.Errorf("107 up missing %q", fragment)
		}
	}
	for _, field := range []string{
		"Watermark", "FinalizedThrough", "Revision", "LastEventAt",
		"LastReceiptIdentitySHA256", "LastEventDigestSHA256", "LastKnownGood",
	} {
		if !strings.Contains(goSource, field) {
			t.Errorf("Go watermark contract missing %q", field)
		}
	}
	if !strings.Contains(up, "allowed_lateness <= interval '24 hours'") ||
		strings.Contains(up, "interval '90 days'") {
		t.Fatal("107 SQL must enforce the 24-hour maximum lateness bound")
	}
	if strings.Contains(up, "authority_unavailable") {
		t.Fatal("107 SQL must use dependency-specific stable reasons")
	}
	if strings.Index(up, "USING ERRCODE='P1070'") > strings.Index(up, "CREATE TABLE") {
		t.Fatal("107 up predecessor guard must fail before schema writes")
	}

	for _, fragment := range []string{
		"migration 107 rollback requires the exact verified 107 head; release checksum is not frozen",
		"USING ERRCODE='P1070'",
		"migration 107 rollback would discard analytics watermark decisions or watermark state",
		"DROP TRIGGER analytics_ingest_watermark_decisions_truncate_guard_107",
		"DROP TRIGGER analytics_ingest_watermarks_truncate_guard_107",
		"DROP FUNCTION analytics_ingest_commit_watermark_107(",
		"DROP FUNCTION analytics_history_generation_digest_107(",
		"DROP TABLE analytics_ingest_watermark_decisions_107",
		"DROP TABLE analytics_ingest_watermarks_107",
	} {
		if !strings.Contains(down, fragment) {
			t.Errorf("107 down missing %q", fragment)
		}
	}
	if strings.Contains(down, "DELETE FROM schema_migrations") {
		t.Fatal("107 down must not delete its own schema_migrations row")
	}
	if strings.Contains(down, "checksum_sha256='") || strings.Contains(down, "down_checksum_sha256='") {
		t.Fatal("107 down must not guess the unfrozen release hashes")
	}
	if strings.Index(down, "USING ERRCODE='P1070'") > strings.Index(down, "DROP TRIGGER") {
		t.Fatal("107 down predecessor guard must run before any DROP")
	}
	data, err := os.ReadFile("dns_provider_credential_lifecycle_106_integration_test.go")
	if err != nil {
		t.Fatal(err)
	}
	actual106IntegrationSHA := fmt.Sprintf("%x", sha256.Sum256(data))
	if actual106IntegrationSHA != "9af7dcdf823cf088718e8573059d4f6ac6bc6ba4852a7d954db31d093fdab861" {
		t.Fatalf("106 integration SHA=%s, authoritative SHA drifted", actual106IntegrationSHA)
	}
	if !strings.Contains(up, "REQUIRED_MIGRATION_106_INTEGRATION_SHA256="+actual106IntegrationSHA) {
		t.Fatalf("107 up does not bind computed 106 integration SHA %s", actual106IntegrationSHA)
	}
}

func readAnalyticsIngestWatermarkLateRevision107(t *testing.T, name string) string {
	t.Helper()
	data, err := os.ReadFile(name)
	if err != nil {
		t.Fatal(err)
	}
	return string(data)
}
