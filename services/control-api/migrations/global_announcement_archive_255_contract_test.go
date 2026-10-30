package migrations_test

import (
	"crypto/sha256"
	"fmt"
	"strings"
	"testing"

	controlmigrations "github.com/cdnca/cdnca/services/control-api/migrations"
)

func TestGlobalAnnouncementArchive255Contract(t *testing.T) {
	for _, file := range []struct{ name, digest string }{
		{"255_global_announcement_archive.up.sql", "0b49d5118389ab946f26cacccd0cce04a5f16862d430215eeaec2aa073809d60"},
		{"255_global_announcement_archive.down.sql", "b6d31da1485234471b93dfe9c8d667c1b13ce02d5e40c93f06d75c6e5e71ba92"},
	} {
		data, err := controlmigrations.FS.ReadFile(file.name)
		if err != nil {
			t.Fatal(err)
		}
		if fmt.Sprintf("%x", sha256.Sum256(data)) != file.digest {
			t.Fatalf("migration digest drift: %s", file.name)
		}
	}
	up, _ := controlmigrations.FS.ReadFile("255_global_announcement_archive.up.sql")
	for _, required := range []string{
		"checksum_sha256='27753a49a290dd4e66c3455f239365f9181d068875776473067ad34af27e5bdb'",
		"platform_announcement_archive_255", "platform_announcement_snapshots_255",
		"trigger-owned append-only facts", "NEW.watermark := next_announcement_state_watermark(NEW.platform_scope_id)",
		"ENABLE ALWAYS TRIGGER", "'announcement.global.archive','announcement.global.restore'",
	} {
		if !strings.Contains(string(up), required) {
			t.Errorf("migration missing %q", required)
		}
	}
	down, _ := controlmigrations.FS.ReadFile("255_global_announcement_archive.down.sql")
	if strings.Index(string(down), "USING ERRCODE='P2553'") > strings.Index(string(down), "DROP TABLE") {
		t.Fatal("rollback must reject history loss before dropping tables")
	}
}
