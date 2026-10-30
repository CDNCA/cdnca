package migrations_test

import (
	"crypto/sha256"
	"fmt"
	"strings"
	"testing"

	controlmigrations "github.com/cdnca/cdnca/services/control-api/migrations"
)

const (
	runtimePatch156UpSHA256   = "34cc982875f728e86af11479e9f49a5326a1fff85fe2d6b91efe4c0b84448788"
	runtimePatch156DownSHA256 = "a29ada54fad54860ca7da7f200bd99cd95132e91e4015d5ebfaf5835f215d495"
)

func TestSEC10JA4BlockWorkflow157Contract(t *testing.T) {
	upBytes, err := controlmigrations.FS.ReadFile("157_ja4_block_workflow.up.sql")
	if err != nil {
		t.Fatal(err)
	}
	downBytes, err := controlmigrations.FS.ReadFile("157_ja4_block_workflow.down.sql")
	if err != nil {
		t.Fatal(err)
	}
	up, down := string(upBytes), string(downBytes)
	for _, required := range []string{
		"migration 157 requires a contiguous verified 156 release head",
		"version=156 AND migration_id='156_runtime_patch_policy'", runtimePatch156UpSHA256, runtimePatch156DownSHA256,
		"CREATE TABLE ja4_block_workflows_157", "CREATE TABLE ja4_block_outbox_157", "CREATE TABLE ja4_block_receipts_157",
		"tenant_scope_id uuid NOT NULL REFERENCES access_scopes(id)",
		"actor_scope_id uuid NOT NULL REFERENCES access_scopes(id)",
		"UNIQUE(tenant_scope_id,idempotency_key)", "request_sha256=sha256(request_bytes)",
		"FOREIGN KEY(session_id,actor_scope_id,actor_user_id)", "REFERENCES auth_sessions(id,scope_id,user_id)",
		"phase IN ('queued','policy_ready','edge_pending','active','failed','expired')",
		"action IN ('apply_policy','publish_binding')", "receipt_kind IN ('policy','binding','edge')",
		"claim_token", "claim_expires_at", "attempt_count", "available_at",
		"guard_ja4_block_receipt_157", "prevent_ja4_block_truncate_157", "BEFORE UPDATE OR DELETE", "BEFORE TRUNCATE",
		"REVOKE ALL ON ja4_block_workflows_157 FROM PUBLIC", "REVOKE ALL ON ja4_block_outbox_157 FROM PUBLIC", "REVOKE ALL ON ja4_block_receipts_157 FROM PUBLIC",
	} {
		if !strings.Contains(up, required) {
			t.Errorf("157 up missing %q", required)
		}
	}
	if guard, mutation := strings.Index(up, "migration 157 requires a contiguous verified 156 release head"), strings.Index(up, "CREATE TABLE ja4_block_workflows_157"); guard < 0 || mutation < 0 || guard > mutation {
		t.Fatal("157 predecessor guard must precede the first mutation")
	}
	upSHA := fmt.Sprintf("%x", sha256.Sum256(upBytes))
	for _, required := range []string{
		"migration 157 rollback requires the exact verified 157 head", "version=157 AND migration_id='157_ja4_block_workflow'", upSHA,
		"migration 157 rollback would discard JA4 block workflow facts", "DROP TABLE ja4_block_receipts_157", "DROP TABLE ja4_block_outbox_157", "DROP TABLE ja4_block_workflows_157",
		"version=156 AND migration_id='156_runtime_patch_policy'", runtimePatch156UpSHA256, runtimePatch156DownSHA256,
	} {
		if !strings.Contains(down, required) {
			t.Errorf("157 down missing %q", required)
		}
	}
	for _, forbidden := range []string{"REFERENCES scopes(id)", "DELETE FROM schema_migrations", "CASCADE", "DROP SCHEMA", "__UP_SHA256__"} {
		if strings.Contains(up+down, forbidden) {
			t.Errorf("157 migration contains forbidden marker %q", forbidden)
		}
	}
}
