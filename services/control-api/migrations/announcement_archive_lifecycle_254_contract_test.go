package migrations_test

import (
	"crypto/sha256"
	"fmt"
	"strings"
	"testing"

	controlmigrations "github.com/cdnca/cdnca/services/control-api/migrations"
)

const announcementArchiveLifecycle254UpSHA = "27753a49a290dd4e66c3455f239365f9181d068875776473067ad34af27e5bdb"
const announcementArchiveLifecycle254DownSHA = "5c20769769af5607ede0b8febc20bd63b0906ce7810bf45fb724210b26bd774f"

func TestAnnouncementArchiveLifecycle254Contract(t *testing.T) {
	up := readAnnouncementArchiveLifecycle254(t, "254_announcement_archive_lifecycle.up.sql")
	if got := fmt.Sprintf("%x", sha256.Sum256([]byte(up))); got != announcementArchiveLifecycle254UpSHA {
		t.Fatalf("migration 254 up SHA drifted: got %s", got)
	}
	for _, required := range []string{
		"migration 254 requires the exact verified 253 release head",
		"CREATE TABLE announcement_archive_254",
		"CREATE TABLE announcement_lifecycle_facts_254",
		"migration-254-baseline-",
		"revision,state,actor_user_id,occurred_at,request_id",
		"watermark bigint NOT NULL DEFAULT 0 CHECK (watermark >= 0)",
		"NEW.watermark := next_announcement_state_watermark(NEW.tenant_scope_id)",
		"BEFORE INSERT OR UPDATE OR DELETE ON announcement_lifecycle_facts_254",
		"archived boolean NOT NULL DEFAULT false",
		"announcement lifecycle facts are append-only",
		"announcement.archive",
		"announcement.restore",
		"ON DELETE RESTRICT",
		"GRANT SELECT,INSERT,UPDATE ON announcement_archive_254",
	} {
		if !strings.Contains(up, required) {
			t.Errorf("migration 254 up missing %q", required)
		}
	}
	if strings.Contains(up, "DELETE FROM schema_migrations") || strings.Contains(up, "TRUNCATE announcement") {
		t.Fatal("migration 254 up must preserve migration metadata and announcement facts")
	}
	down := readAnnouncementArchiveLifecycle254(t, "254_announcement_archive_lifecycle.down.sql")
	if got := fmt.Sprintf("%x", sha256.Sum256([]byte(down))); got != announcementArchiveLifecycle254DownSHA {
		t.Fatalf("migration 254 down SHA drifted: got %s", got)
	}
	for _, required := range []string{
		"migration 254 rollback requires every announcement to be active",
		"EXISTS (SELECT 1 FROM announcement_lifecycle_facts_254 WHERE state='archived')",
		"DROP TABLE announcement_lifecycle_facts_254",
		"DROP TABLE announcement_archive_254",
	} {
		if !strings.Contains(down, required) {
			t.Errorf("migration 254 down missing %q", required)
		}
	}
}

func readAnnouncementArchiveLifecycle254(t *testing.T, name string) string {
	t.Helper()
	content, err := controlmigrations.FS.ReadFile(name)
	if err != nil {
		t.Fatal(err)
	}
	return string(content)
}
