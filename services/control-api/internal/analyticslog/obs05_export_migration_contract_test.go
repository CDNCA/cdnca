package analyticslog

import (
	"os"
	"strings"
	"testing"
)

func TestOBS05Migration132DurabilityAndGrantFences(t *testing.T) {
	up, err := os.ReadFile("../../migrations/132_analytics_log_export.up.sql")
	if err != nil {
		t.Fatal(err)
	}
	down, err := os.ReadFile("../../migrations/132_analytics_log_export.down.sql")
	if err != nil {
		t.Fatal(err)
	}
	for _, required := range []string{
		"analytics_log_exports_v1", "analytics_log_export_events_v1", "analytics_log_export_grants_v1",
		"idempotency_key", "request_digest", "lease_expires_at", "artifact_expires_at",
		"token_sha256", "consumed_at", "prevent_analytics_log_export_fact_mutation_132",
		"FOREIGN KEY (scope_id,tenant_id) REFERENCES access_scopes(id,tenant_id)",
		"credential_kind text NOT NULL CHECK (credential_kind = 'session')",
		"state = 'completed' AND snapshot_at IS NOT NULL", "lease_expires_at > updated_at",
		"artifact_expires_at > created_at", "expires_at > created_at",
		"UNIQUE (actor_scope_id,actor_user_id,credential_kind,credential_id,idempotency_key)",
		"latest.state IN ('pending','running')", "lease.lease_expires_at <= p_now",
		"131_analytics_realtime_expected_counts", "analytics_log.export.create", "analytics_log.export.complete",
		"analytics_log.export.grant", "analytics_log.export.download", "analytics_log.export.reject",
		"FOR UPDATE OF request SKIP LOCKED",
		"CHECK (octet_length(token_sha256) = 32)", "INTERVAL '1 hour'",
	} {
		if !strings.Contains(string(up), required) {
			t.Fatalf("migration 132 up missing %q", required)
		}
	}
	if !strings.Contains(string(down), "rollback would discard analytics log export facts") {
		t.Fatal("migration 132 down lacks destructive rollback fence")
	}
}
