package migrations_test

import (
	"crypto/sha256"
	"fmt"
	"os"
	"strings"
	"testing"

	controlmigrations "github.com/cdnca/cdnca/services/control-api/migrations"
)

const (
	migration114UpSHA115   = "438ff725214147c5bd10462396d715a47ba29aa554c7e180ff7a48b7bb37e5a3"
	migration114DownSHA115 = "60497e9b06e0157adf01fd1e01084fe25513118cad6ff8fcaf594a3147bb8415"
	migration114TestSHA115 = "999cac668f8c568171c27a91871ac83f8c07fe34db99ebe5a3d2b7e4f6026b13"
)

func TestDNSRetryAfterVoluntaryYield115Contract(t *testing.T) {
	up := readMigration115(t, "115_dns_retry_after_voluntary_yield.up.sql")
	down := readMigration115(t, "115_dns_retry_after_voluntary_yield.down.sql")
	upSHA := fmt.Sprintf("%x", sha256.Sum256([]byte(up)))
	assertMigrationSHA115(t, "114_package_monitor_metric_authority.up.sql", migration114UpSHA115)
	assertMigrationSHA115(t, "114_package_monitor_metric_authority.down.sql", migration114DownSHA115)
	assertRepositoryFileSHA115(t, "package_monitor_metric_authority_114_integration_test.go", migration114TestSHA115)

	for _, required := range []string{
		"migration 115 requires the exact verified 114 release head",
		"migration_id='114_package_monitor_metric_authority'",
		"checksum_sha256='" + migration114UpSHA115 + "'",
		"down_checksum_sha256='" + migration114DownSHA115 + "'",
		"REQUIRED_MIGRATION_114_INTEGRATION_SHA256=" + migration114TestSHA115,
		"CREATE TABLE background_job_yield_facts_115",
		"yield_xact_id xid8 NOT NULL",
		"yield_xact_id=pg_current_xact_id()",
		"CREATE OR REPLACE FUNCTION protect_background_job()",
		"CREATE OR REPLACE FUNCTION protect_background_job_attempt()",
		"NEW.state = 'deferred'",
		"current_attempt.state NOT IN ('failed','partial_failed','lease_expired','deferred')",
		"CREATE CONSTRAINT TRIGGER background_job_yield_facts_final_115",
		"DEFERRABLE INITIALLY DEFERRED",
		"background job yield facts are append-only",
	} {
		if !strings.Contains(up, required) {
			t.Errorf("115 up missing %q", required)
		}
	}
	guard := strings.Index(up, "migration 115 requires the exact verified 114 release head")
	mutation := strings.Index(up, "ALTER TABLE background_job_attempts")
	if guard < 0 || mutation < 0 || guard > mutation {
		t.Fatal("115 predecessor guard must precede the first mutation")
	}
	for _, required := range []string{
		"migration 115 rollback requires the exact verified 115 head",
		"checksum_sha256='" + upSHA + "'",
		"rollback would discard DNS Retry-After voluntary yield facts",
		"state='deferred'",
		"DROP TABLE background_job_yield_facts_115",
		"CREATE OR REPLACE FUNCTION protect_background_job()",
		"CREATE OR REPLACE FUNCTION protect_background_job_attempt()",
	} {
		if !strings.Contains(down, required) {
			t.Errorf("115 down missing %q", required)
		}
	}
	factGuard := strings.Index(down, "rollback would discard DNS Retry-After voluntary yield facts")
	firstMutation := strings.Index(down, "DROP TRIGGER")
	if factGuard < 0 || firstMutation < 0 || factGuard > firstMutation {
		t.Fatal("115 rollback fact guard must precede the first mutation")
	}
}

func readMigration115(t *testing.T, name string) string {
	t.Helper()
	content, err := controlmigrations.FS.ReadFile(name)
	if err != nil {
		t.Fatal(err)
	}
	return string(content)
}

func assertMigrationSHA115(t *testing.T, name, want string) {
	t.Helper()
	content, err := controlmigrations.FS.ReadFile(name)
	if err != nil {
		t.Fatal(err)
	}
	if got := fmt.Sprintf("%x", sha256.Sum256(content)); got != want {
		t.Fatalf("%s SHA-256=%s, want %s", name, got, want)
	}
}

func assertRepositoryFileSHA115(t *testing.T, name, want string) {
	t.Helper()
	content, err := os.ReadFile(name)
	if err != nil {
		t.Fatal(err)
	}
	if got := fmt.Sprintf("%x", sha256.Sum256(content)); got != want {
		t.Fatalf("%s SHA-256=%s, want %s", name, got, want)
	}
}
