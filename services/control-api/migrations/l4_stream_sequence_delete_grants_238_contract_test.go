package migrations

import (
	"crypto/sha256"
	"fmt"
	"strings"
	"testing"
)

const (
	l4StreamSequenceDeleteGrants238UpSHA      = "1408c479408d540459eb5d78d7ae98c75c6382b6a40c330170a4c0976f5a28f7"
	l4StreamSequenceDeleteGrants238DownSHA    = "3b8bf691cfa55800344620895fb587c82dce74de5cf97ef6a2f6a26d389010a9"
	l4StreamSequenceDeleteGrants238ParentUp   = l4StreamUserDefaultsLockGrant237UpSHA
	l4StreamSequenceDeleteGrants238ParentDown = l4StreamUserDefaultsLockGrant237DownSHA
)

func TestL4StreamSequenceDeleteGrants238Contract(t *testing.T) {
	files := map[string]struct{ name, sha string }{
		"up":   {"238_l4_stream_sequence_delete_grants.up.sql", l4StreamSequenceDeleteGrants238UpSHA},
		"down": {"238_l4_stream_sequence_delete_grants.down.sql", l4StreamSequenceDeleteGrants238DownSHA},
	}
	contents := make(map[string]string, len(files))
	for label, file := range files {
		payload, err := FS.ReadFile(file.name)
		if err != nil {
			t.Fatalf("read migration 238 %s: %v", label, err)
		}
		if got := fmt.Sprintf("%x", sha256.Sum256(payload)); got != file.sha {
			t.Fatalf("migration 238 %s checksum = %s, want %s", label, got, file.sha)
		}
		contents[label] = string(payload)
	}

	up := contents["up"]
	for _, required := range []string{
		"(SELECT count(*) FROM schema_migrations) <> 237",
		"version = 237 AND migration_id = '237_l4_stream_user_defaults_lock_grant'",
		l4StreamSequenceDeleteGrants238ParentUp,
		l4StreamSequenceDeleteGrants238ParentDown,
		"GRANT DELETE ON l4_stream_group_display_id_sequences TO cdnca_control_app",
		"GRANT DELETE ON l4_stream_user_default_display_id_sequences TO cdnca_control_app",
		"rolname = 'cdnca_control_app'",
		"USING ERRCODE = 'P2380'",
	} {
		if !strings.Contains(up, required) {
			t.Errorf("migration 238 up is missing %q", required)
		}
	}

	down := contents["down"]
	for _, required := range []string{
		"(SELECT count(*) FROM schema_migrations) <> 238",
		"version = 238 AND migration_id = '238_l4_stream_sequence_delete_grants'",
		l4StreamSequenceDeleteGrants238UpSHA,
		"REVOKE DELETE ON l4_stream_group_display_id_sequences FROM cdnca_control_app",
		"REVOKE DELETE ON l4_stream_user_default_display_id_sequences FROM cdnca_control_app",
		"USING ERRCODE = 'P2381'",
	} {
		if !strings.Contains(down, required) {
			t.Errorf("migration 238 down is missing %q", required)
		}
	}

	combined := strings.ToUpper(up + down)
	for _, forbidden := range []string{" CASCADE", "DELETE FROM SCHEMA_MIGRATIONS", "DROP SCHEMA", "__UP_SHA256__", "__DOWN_SHA256__"} {
		if strings.Contains(combined, forbidden) {
			t.Errorf("migration 238 contains forbidden token %q", forbidden)
		}
	}
}
