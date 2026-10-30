package migrations

import (
	"crypto/sha256"
	"fmt"
	"strings"
	"testing"
)

func TestIdentityUserLoginSecurity252Contract(t *testing.T) {
	read := func(name string) string {
		t.Helper()
		raw, err := FS.ReadFile(name)
		if err != nil {
			t.Fatal(err)
		}
		return string(raw)
	}
	up, down := read("252_identity_user_login_security.up.sql"), read("252_identity_user_login_security.down.sql")
	for _, name := range []string{"251_identity_user_metadata.up.sql", "251_identity_user_metadata.down.sql"} {
		if !strings.Contains(up, fmt.Sprintf("%x", sha256.Sum256([]byte(read(name))))) {
			t.Fatalf("predecessor not pinned: %s", name)
		}
	}
	if !strings.Contains(down, fmt.Sprintf("%x", sha256.Sum256([]byte(up)))) {
		t.Fatal("down does not pin exact up")
	}
	guard, drop := strings.Index(down, "EXISTS (SELECT 1 FROM identity_user_login_security)"), strings.Index(down, "DROP TABLE identity_user_login_security")
	if guard < 0 || drop < guard || !strings.Contains(down, "preserve policy and receipts") {
		t.Fatal("rollback can silently discard policy")
	}
	for _, fragment := range []string{"FOREIGN KEY (scope_id,user_id) REFERENCES memberships", "GRANT SELECT, INSERT, UPDATE ON identity_user_login_security TO cdnca_control_app", "ADD COLUMN login_security_revision", "'identity.user.password.reset','identity.user.delete','identity.user.login_security.update'"} {
		if !strings.Contains(up, fragment) {
			t.Fatalf("missing migration contract: %s", fragment)
		}
	}
}
