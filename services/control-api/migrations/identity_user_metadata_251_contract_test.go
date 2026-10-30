package migrations

import (
	"crypto/sha256"
	"fmt"
	"strings"
	"testing"
)

func TestIdentityUserMetadata251Contract(t *testing.T) {
	read := func(name string) string {
		t.Helper()
		data, err := FS.ReadFile(name)
		if err != nil {
			t.Fatal(err)
		}
		return string(data)
	}
	up := read("251_identity_user_metadata.up.sql")
	down := read("251_identity_user_metadata.down.sql")
	for _, predecessor := range []string{"250_notification_policy_write_receipts.up.sql", "250_notification_policy_write_receipts.down.sql"} {
		if !strings.Contains(up, fmt.Sprintf("%x", sha256.Sum256([]byte(read(predecessor))))) {
			t.Fatalf("up migration does not pin %s", predecessor)
		}
	}
	if !strings.Contains(down, fmt.Sprintf("%x", sha256.Sum256([]byte(up)))) {
		t.Fatal("down migration does not pin the exact up migration")
	}
	guard := strings.Index(down, "SELECT 1 FROM users WHERE remark IS NOT NULL OR qq IS NOT NULL")
	mutation := strings.Index(down, "ALTER TABLE users DROP COLUMN")
	if guard < 0 || mutation < guard || !strings.Contains(down, "USING ERRCODE='P2511'") {
		t.Fatal("rollback must refuse to discard stored metadata before dropping columns")
	}
}
