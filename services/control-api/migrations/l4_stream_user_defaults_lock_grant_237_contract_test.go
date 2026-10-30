package migrations

import (
	"crypto/sha256"
	"fmt"
	"strings"
	"testing"
)

const (
	l4StreamUserDefaultsLockGrant237UpSHA      = "e45850337ba6918c65ee6887926cd991644025e8bf8aad12353081b7fdb2611a"
	l4StreamUserDefaultsLockGrant237DownSHA    = "9e4c9ccbbbcaa02d75794eb43ccb7bb4961bbbbb0532d05dd306c1ec63757791"
	l4StreamUserDefaultsLockGrant237ParentUp   = l4StreamGroupsAndDefaults236UpSHA
	l4StreamUserDefaultsLockGrant237ParentDown = l4StreamGroupsAndDefaults236DownSHA
)

func TestL4StreamUserDefaultsLockGrant237Contract(t *testing.T) {
	files := map[string]struct{ name, sha string }{
		"up":   {"237_l4_stream_user_defaults_lock_grant.up.sql", l4StreamUserDefaultsLockGrant237UpSHA},
		"down": {"237_l4_stream_user_defaults_lock_grant.down.sql", l4StreamUserDefaultsLockGrant237DownSHA},
	}
	contents := make(map[string]string, len(files))
	for label, file := range files {
		payload, err := FS.ReadFile(file.name)
		if err != nil {
			t.Fatalf("read migration 237 %s: %v", label, err)
		}
		if got := fmt.Sprintf("%x", sha256.Sum256(payload)); got != file.sha {
			t.Fatalf("migration 237 %s checksum = %s, want %s", label, got, file.sha)
		}
		contents[label] = string(payload)
	}

	up := contents["up"]
	for _, required := range []string{
		"(SELECT count(*) FROM schema_migrations) <> 236",
		"version = 236 AND migration_id = '236_l4_stream_groups_and_defaults'",
		l4StreamUserDefaultsLockGrant237ParentUp,
		l4StreamUserDefaultsLockGrant237ParentDown,
		"GRANT UPDATE ON l4_stream_user_defaults TO cdnca_control_app",
		"rolname = 'cdnca_control_app'",
		"USING ERRCODE = 'P2370'",
	} {
		if !strings.Contains(up, required) {
			t.Errorf("migration 237 up is missing %q", required)
		}
	}

	down := contents["down"]
	for _, required := range []string{
		"(SELECT count(*) FROM schema_migrations) <> 237",
		"version = 237 AND migration_id = '237_l4_stream_user_defaults_lock_grant'",
		l4StreamUserDefaultsLockGrant237UpSHA,
		"REVOKE UPDATE ON l4_stream_user_defaults FROM cdnca_control_app",
		"USING ERRCODE = 'P2371'",
	} {
		if !strings.Contains(down, required) {
			t.Errorf("migration 237 down is missing %q", required)
		}
	}

	combined := strings.ToUpper(up + down)
	for _, forbidden := range []string{" CASCADE", "DELETE FROM SCHEMA_MIGRATIONS", "DROP SCHEMA", "__UP_SHA256__", "__DOWN_SHA256__"} {
		if strings.Contains(combined, forbidden) {
			t.Errorf("migration 237 contains forbidden token %q", forbidden)
		}
	}
}
