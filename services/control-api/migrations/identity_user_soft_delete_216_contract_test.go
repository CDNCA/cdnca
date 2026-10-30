package migrations

import (
	"strings"
	"testing"
)

func TestIdentityUserSoftDelete216Contract(t *testing.T) {
	up, err := FS.ReadFile("216_identity_user_soft_delete.up.sql")
	if err != nil {
		t.Fatal(err)
	}
	down, err := FS.ReadFile("216_identity_user_soft_delete.down.sql")
	if err != nil {
		t.Fatal(err)
	}
	for _, required := range []string{
		"CREATE TABLE identity_user_deletions",
		"deleted_by_user_id uuid NOT NULL REFERENCES users(id) ON DELETE RESTRICT",
		"CREATE TRIGGER identity_user_deletions_guard_216",
		"CREATE TRIGGER identity_user_deletions_truncate_guard_216",
		"GRANT SELECT, INSERT ON TABLE identity_user_deletions TO cdnca_control_app",
	} {
		if !strings.Contains(string(up), required) {
			t.Errorf("up migration missing %q", required)
		}
	}
	for _, required := range []string{
		"DROP TABLE identity_user_deletions",
		"DROP FUNCTION guard_identity_user_deletions_216()",
	} {
		if !strings.Contains(string(down), required) {
			t.Errorf("down migration missing %q", required)
		}
	}
}
