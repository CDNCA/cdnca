package migrations_test

import (
	"crypto/sha256"
	"fmt"
	"strings"
	"testing"

	controlmigrations "github.com/cdnca/cdnca/services/control-api/migrations"
)

const platformGlobalAnnouncements141UpSHA = "d078248a163d03698eb559bec8c45b5f7ebc6b682603ed6e1f6448958c26af7f"

func TestPlatformGlobalAnnouncements141Contract(t *testing.T) {
	up := readPlatformGlobalAnnouncements141(t, "141_platform_global_announcements.up.sql")
	actualSHA := fmt.Sprintf("%x", sha256.Sum256([]byte(up)))
	if actualSHA != platformGlobalAnnouncements141UpSHA {
		t.Fatalf("migration 141 up SHA drifted: got %s", actualSHA)
	}
	for _, required := range []string{
		"migration 141 requires the exact verified 140 release head",
		"migration_id = '140_package_subscription_manual_open'",
		"a89707a1033c0b192569081af1119ca1e075016a06cdd40df71fb8d7d28d5489",
		"58a58b9c789b244eff9eb88b35eab2c924f4721c00f1fc9a6cbb44d2b2bfd542",
		"CREATE TABLE platform_announcements_141",
		"CREATE TABLE platform_announcement_recipients_141",
		"FOREIGN KEY (platform_scope_id, created_by_user_id)",
		"FOREIGN KEY (tenant_scope_id, user_id)",
		"OLD.status = 'draft' AND NEW.status = 'published'",
		"OLD.status = 'published' AND NEW.status = 'withdrawn'",
		"platform global announcement publication must seal a non-empty audience",
		"NEW.revision <> OLD.revision + 1",
		"recipient state must advance monotonically",
		"BEFORE TRUNCATE ON platform_announcements_141",
		"BEFORE TRUNCATE ON platform_announcement_recipients_141",
		"ENABLE ALWAYS TRIGGER platform_announcements_141_guard",
		"ENABLE ALWAYS TRIGGER platform_announcement_recipients_141_guard",
		"record_platform_announcement_recipient_facts_141",
		"record_platform_announcement_recipient_state_fact_141",
		"record_platform_announcement_version_facts_141",
		"next_announcement_state_watermark(NEW.tenant_scope_id)",
		"next_announcement_state_watermark(requested_scope_id)",
		"'inbox_event'",
		"'inbox_state'",
		"'version'",
		"'source', 'platform_global'",
		"'announcement.global.create'",
		"'announcement.global.update'",
		"'announcement.global.publish'",
		"'announcement.global.withdraw'",
	} {
		if !strings.Contains(up, required) {
			t.Errorf("migration 141 up missing %q", required)
		}
	}
	if guard, mutation := strings.Index(up, "migration 141 requires the exact verified 140 release head"),
		strings.Index(up, "ALTER TABLE announcement_write_requests DROP CONSTRAINT"); guard < 0 || mutation < 0 || guard > mutation {
		t.Fatal("migration 141 predecessor guard must run before the first schema mutation")
	}
	if strings.Contains(up, "DELETE FROM schema_migrations") {
		t.Fatal("migration 141 up must leave migration metadata ownership to the runner")
	}
}

func TestPlatformGlobalAnnouncements141RollbackFailsClosed(t *testing.T) {
	down := readPlatformGlobalAnnouncements141(t, "141_platform_global_announcements.down.sql")
	for _, required := range []string{
		"migration 141 rollback requires the exact verified 141 head",
		"version = 141 AND migration_id = '141_platform_global_announcements'",
		"checksum_sha256 = '" + platformGlobalAnnouncements141UpSHA + "'",
		"migration 141 rollback would discard durable platform global announcement facts",
		"EXISTS (SELECT 1 FROM platform_announcements_141)",
		"EXISTS (SELECT 1 FROM platform_announcement_recipients_141)",
		"payload->>'source' = 'platform_global'",
		"DROP TABLE platform_announcement_recipients_141",
		"DROP TABLE platform_announcements_141",
		"DROP CONSTRAINT announcement_write_requests_operation_141_check",
		"ADD CONSTRAINT announcement_write_requests_operation_check",
	} {
		if !strings.Contains(down, required) {
			t.Errorf("migration 141 down missing %q", required)
		}
	}
	if guard, mutation := strings.Index(down, "migration 141 rollback requires the exact verified 141 head"),
		strings.Index(down, "DROP TRIGGER platform_announcements_141_version_facts"); guard < 0 || mutation < 0 || guard > mutation {
		t.Fatal("migration 141 rollback guard must run before the first schema mutation")
	}
	if strings.Contains(down, "DELETE FROM schema_migrations") {
		t.Fatal("migration 141 down must leave migration metadata ownership to the runner")
	}
}

func readPlatformGlobalAnnouncements141(t *testing.T, name string) string {
	t.Helper()
	content, err := controlmigrations.FS.ReadFile(name)
	if err != nil {
		t.Fatal(err)
	}
	return string(content)
}
