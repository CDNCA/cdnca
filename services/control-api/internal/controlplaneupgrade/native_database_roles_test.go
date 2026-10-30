package controlplaneupgrade

import (
	"strings"
	"testing"
)

// FX01: the role script is idempotent and grants the cleanup role to the
// control login named in DATABASE_URL, without inherit.
func TestNativeEnsureRolesSQL(t *testing.T) {
	sql, err := nativeEnsureRolesSQL("cdnca")
	if err != nil {
		t.Fatal(err)
	}
	for _, token := range []string{
		"to_regrole('cdnca_retention_cleanup') IS NULL",
		"CREATE ROLE cdnca_retention_cleanup NOLOGIN NOSUPERUSER NOCREATEDB NOCREATEROLE NOINHERIT NOREPLICATION NOBYPASSRLS",
		"pg_has_role('cdnca', 'cdnca_retention_cleanup', 'MEMBER')",
		"GRANT cdnca_retention_cleanup TO \"cdnca\"",
	} {
		if !strings.Contains(sql, token) {
			t.Errorf("role script missing %q:\n%s", token, sql)
		}
	}
	for _, unsafe := range []string{"", "Cdnca", "cdnca;drop", "a b"} {
		if _, err := nativeEnsureRolesSQL(unsafe); err == nil {
			t.Errorf("unsafe login %q accepted", unsafe)
		}
	}
}
