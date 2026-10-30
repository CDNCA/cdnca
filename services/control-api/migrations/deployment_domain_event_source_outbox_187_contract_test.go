package migrations_test

import (
	"crypto/sha256"
	"fmt"
	"os"
	"strings"
	"testing"
)

func TestDeploymentDomainEventSourceOutbox187Contract(t *testing.T) {
	up := readMigration187(t, "187_deployment_domain_event_source_outbox.up.sql")
	down := readMigration187(t, "187_deployment_domain_event_source_outbox.down.sql")
	if got := fmt.Sprintf("%x", sha256.Sum256([]byte(up))); !strings.Contains(down, got) {
		t.Fatalf("187 down must pin up checksum %s", got)
	}
	for _, marker := range []string{
		"migration 187 requires the exact verified 186 release head",
		"version=186 AND migration_id='186_site_domain_export_rbac'",
		"fa30f9adc3f68d6bddca97311f1345fb39327cb06cb28e8d640ee824e4466203",
		"a10c012d16f9bf4e00789b8ba5a96ee59607509cd557e2051e6de3b4a0049fef",
		"CREATE TABLE deployment_domain_event_source_outbox",
		"io.cdnca.deployment.v1.status_changed",
		"tenant_scope_id", "configuration_scope_id", "transition_sequence",
		"payload_sha256", "dedup_key", "append-only", "lease",
		"sha256(NEW.payload) IS DISTINCT FROM NEW.payload_sha256",
		"NEW.payload IS DISTINCT FROM expected_payload",
		"FROM deployment_status_events",
		"WHERE event_id=NEW.id AND deployment_id=NEW.deployment_id AND attempt=NEW.attempt",
		"NEW.transition_sequence IS DISTINCT FROM bound_transition_sequence",
		"NEW.created_at IS DISTINCT FROM bound_received_at",
		"OLD.delivery_state IN ('pending','failed') AND NEW.delivery_state='leased'",
		"OLD.delivery_state='leased' AND NEW.delivery_state='published'",
		"OLD.delivery_state='leased' AND NEW.delivery_state='failed'",
	} {
		if !strings.Contains(up+down, marker) {
			t.Errorf("187 migration missing %q", marker)
		}
	}
	if strings.Contains(strings.ToUpper(up+down), "CASCADE") ||
		strings.Contains(up+down, "DELETE FROM schema_migrations") ||
		strings.Contains(up+down, "__UP_SHA256__") || strings.Contains(up+down, "__DOWN_SHA256__") {
		t.Fatal("187 migration must not use destructive migration shortcuts")
	}
	if !strings.Contains(down, "deployment domain event source outbox contains durable events") {
		t.Fatal("187 down must refuse to discard durable events")
	}
}

func readMigration187(t *testing.T, name string) string {
	t.Helper()
	for _, root := range []string{".", "services/control-api/migrations"} {
		if body, err := os.ReadFile(root + "/" + name); err == nil {
			return string(body)
		}
	}
	t.Fatalf("migration %s not found", name)
	return ""
}
