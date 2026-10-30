package migrations_test

import (
	"crypto/sha256"
	"fmt"
	"strings"
	"testing"

	controlmigrations "github.com/cdnca/cdnca/services/control-api/migrations"
)

const (
	siteCapturePolicy146UpSHA256   = "9763f9d3bbba5f12560e3254e2ab22281fb0d0e63b3b412e807b121ef3643a25"
	siteCapturePolicy146DownSHA256 = "1d9986f1c21d13957a57b00c63c7c06b0f7a5497c53df19695d6c2ad1a8b16ad"
)

func TestSiteCapturePolicy147Contract(t *testing.T) {
	upBytes, err := controlmigrations.FS.ReadFile("147_site_capture_policy.up.sql")
	if err != nil {
		t.Fatal(err)
	}
	downBytes, err := controlmigrations.FS.ReadFile("147_site_capture_policy.down.sql")
	if err != nil {
		t.Fatal(err)
	}
	up, down := string(upBytes), string(downBytes)

	for _, required := range []string{
		"migration 147 requires the exact verified 146 release head",
		"version = 146 AND migration_id = '146_package_cycle_enforcement'",
		siteCapturePolicy146UpSHA256,
		siteCapturePolicy146DownSHA256,
		"CREATE TABLE site_capture_policy_revisions",
		"CREATE TABLE site_capture_policy_heads",
		"CREATE TABLE site_capture_policy_receipts",
		"FOREIGN KEY (scope_id,site_id) REFERENCES sites(scope_id,id)",
		"FOREIGN KEY (actor_session_id,actor_scope_id,actor_user_id)",
		"REFERENCES auth_sessions(id,scope_id,user_id)",
		"site_capture.read",
		"site_capture.manage",
		"grant_site_capture_permissions_147",
		"site capture policy revisions are append-only",
		"site capture policy head revision must advance by one",
		"site capture policy receipts only allow pending to completed",
		"site capture policy authority tables cannot be truncated",
		"REVOKE ALL ON site_capture_policy_revisions",
	} {
		if !strings.Contains(up, required) {
			t.Errorf("147 up missing %q", required)
		}
	}
	if guard, mutation := strings.Index(up, "migration 147 requires the exact verified 146 release head"), strings.Index(up, "INSERT INTO permissions"); guard < 0 || mutation < 0 || guard > mutation {
		t.Fatal("147 predecessor guard must run before the first mutation")
	}

	upSHA := fmt.Sprintf("%x", sha256.Sum256(upBytes))
	for _, required := range []string{
		"migration 147 rollback requires the exact verified 147 head",
		"version = 147 AND migration_id = '147_site_capture_policy'",
		upSHA,
		"version = 146 AND migration_id = '146_package_cycle_enforcement'",
		siteCapturePolicy146UpSHA256,
		siteCapturePolicy146DownSHA256,
		"migration 147 rollback would discard site capture policy facts",
		"migration 147 rollback requires all non-system grants to be removed",
		"DROP TABLE site_capture_policy_receipts",
		"DROP TABLE site_capture_policy_heads",
		"DROP TABLE site_capture_policy_revisions",
	} {
		if !strings.Contains(down, required) {
			t.Errorf("147 down missing %q", required)
		}
	}
	if guard, mutation := strings.Index(down, "migration 147 rollback requires the exact verified 147 head"), strings.Index(down, "DROP TRIGGER"); guard < 0 || mutation < 0 || guard > mutation {
		t.Fatal("147 rollback guard must run before the first mutation")
	}
	for _, forbidden := range []string{"DELETE FROM schema_migrations", "CASCADE", "__UP_SHA256__", "__DOWN_SHA256__"} {
		if strings.Contains(up+down, forbidden) {
			t.Errorf("147 migration contains forbidden marker %q", forbidden)
		}
	}
	t.Logf("147 up sha256=%s down sha256=%x", upSHA, sha256.Sum256(downBytes))
}
