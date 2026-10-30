package migrations_test

import (
	"crypto/sha256"
	"fmt"
	"strings"
	"testing"

	controlmigrations "github.com/cdnca/cdnca/services/control-api/migrations"
)

const (
	runtimePatch154UpSHA256   = "b3925e3c4a28ad73a9487aae6356c39dddc11291064d2f691d4d76a58ad7278a"
	runtimePatch154DownSHA256 = "85c925f408b65ce15c79a4bab9fb81ad6d9e2e8fb0feeb99c612426cbd35070f"
	runtimePatch155UpSHA256   = "d19d14aee41a7b17ba69cb02e4d0a6d256496b1d84ce8a9f7eb376796de51e48"
	runtimePatch155DownSHA256 = "db2bd655adda8eab882f08957fa5fa1a31233c87f36ab0555eff48bd46fc661b"
)

func TestOPS15RuntimePatchPolicy156Contract(t *testing.T) {
	upBytes, err := controlmigrations.FS.ReadFile("156_runtime_patch_policy.up.sql")
	if err != nil {
		t.Fatal(err)
	}
	downBytes, err := controlmigrations.FS.ReadFile("156_runtime_patch_policy.down.sql")
	if err != nil {
		t.Fatal(err)
	}
	up, down := string(upBytes), string(downBytes)
	for _, required := range []string{
		"migration 156 requires a contiguous verified 155 release head",
		"version=155 AND migration_id='155_dns_provider_retry_states'",
		runtimePatch155UpSHA256, runtimePatch155DownSHA256,
		"version=154 AND migration_id='154_control_upgrade_systemd_repository'",
		runtimePatch154UpSHA256, runtimePatch154DownSHA256,
		"CREATE TABLE runtime_patch_policy_candidates_156",
		"CREATE TABLE runtime_patch_policy_receipts_156",
		"CREATE TABLE runtime_patch_policy_heads_156",
		"PRIMARY KEY(installation_id,target_kind,target_id,channel,revision)",
		"receipt_kind IN ('decision','rollback_approval','activation')",
		"target_kind IN ('control','agent')",
		"channel IN ('stable','beta','lts','security-hotfix')",
		"action IN ('canary','pause','expand','withdraw','rollback')",
		"octet_length(candidate_sha256)=32",
		"candidate_wire_sha256=sha256(candidate_wire)",
		"receipt_sha256=sha256(receipt_bytes)",
		"snapshot_sha256=sha256(snapshot_bytes)",
		"guard_runtime_patch_policy_candidate_156",
		"guard_runtime_patch_policy_receipt_156",
		"guard_runtime_patch_policy_head_156",
		"prevent_runtime_patch_policy_truncate_156",
		"NEW.resource_version<>OLD.resource_version+1",
		"BEFORE INSERT OR UPDATE OR DELETE",
		"BEFORE TRUNCATE",
		"REVOKE ALL ON runtime_patch_policy_candidates_156 FROM PUBLIC",
		"REVOKE ALL ON runtime_patch_policy_receipts_156 FROM PUBLIC",
		"REVOKE ALL ON runtime_patch_policy_heads_156 FROM PUBLIC",
	} {
		if !strings.Contains(up, required) {
			t.Errorf("156 up missing %q", required)
		}
	}
	if guard, mutation := strings.Index(up, "migration 156 requires a contiguous verified 155 release head"), strings.Index(up, "CREATE TABLE runtime_patch_policy_candidates_156"); guard < 0 || mutation < 0 || guard > mutation {
		t.Fatal("156 predecessor guard must precede the first mutation")
	}
	upSHA := fmt.Sprintf("%x", sha256.Sum256(upBytes))
	for _, required := range []string{
		"migration 156 rollback requires the exact verified 156 head",
		"version=156 AND migration_id='156_runtime_patch_policy'",
		upSHA,
		"migration 156 rollback would discard runtime patch policy facts",
		"DROP TABLE runtime_patch_policy_heads_156",
		"DROP TABLE runtime_patch_policy_receipts_156",
		"DROP TABLE runtime_patch_policy_candidates_156",
		"version=155 AND migration_id='155_dns_provider_retry_states'",
		runtimePatch155UpSHA256, runtimePatch155DownSHA256,
		"version=154 AND migration_id='154_control_upgrade_systemd_repository'",
		runtimePatch154UpSHA256, runtimePatch154DownSHA256,
	} {
		if !strings.Contains(down, required) {
			t.Errorf("156 down missing %q", required)
		}
	}
	if guard, mutation := strings.Index(down, "migration 156 rollback requires the exact verified 156 head"), strings.Index(down, "DROP TRIGGER"); guard < 0 || mutation < 0 || guard > mutation {
		t.Fatal("156 rollback guard must precede the first mutation")
	}
	for _, forbidden := range []string{"DELETE FROM schema_migrations", "CASCADE", "DROP SCHEMA", "__UP_SHA256__", "__DOWN_SHA256__"} {
		if strings.Contains(up+down, forbidden) {
			t.Errorf("156 migration contains forbidden marker %q", forbidden)
		}
	}
}
