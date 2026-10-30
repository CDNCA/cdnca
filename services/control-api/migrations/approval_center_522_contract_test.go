package migrations

import (
	"crypto/sha256"
	"fmt"
	"strings"
	"testing"
)

// Migration 522 (branch placeholder 530, renumbered at
// merge): the up guard pins the predecessor 521's migration_id and
// checksums. Everything that changes with the renumbering is in this block.
const (
	migration522Version         = 522
	migration522ID              = "522_approval_center"
	migration522PreviousID      = "521_site_protocol_batch_drop"
	migration522PreviousUpSHA   = "209c85d996838d9659529214b46ad4c66cdc77e9471aa25e3b9131d628ee6a61"
	migration522PreviousDownSHA = "99ccc20dce56fa2e9944e0721bfa41a2653a8f83b91e049686601ca362f942d7"
	migration522UpSHA           = "9e260151953eddb91c6142bbbc0de3e3d6e5b85df8a093731da8d62b9b723b8f"
	migration522DownSHA         = "ee13721bcd5edd674f411ba6f69b2b0ec0c708718ea27c6badd77af0c83c9992"
)

func TestApprovalCenter522Contract(t *testing.T) {
	for _, script := range []struct {
		name, sha string
		required  []string
	}{
		{migration522ID + ".up.sql", migration522UpSHA, []string{
			fmt.Sprintf("(SELECT count(*) FROM schema_migrations) <> %d", migration522Version-1),
			fmt.Sprintf("(SELECT max(version) FROM schema_migrations) <> %d", migration522Version-1),
			"migration_id='" + migration522PreviousID + "'", migration522PreviousUpSHA, migration522PreviousDownSHA,
			"ERRCODE='P5220'", "CREATE TABLE approval_center_settings", "CREATE TABLE approval_requests",
			"('approvals.read',", "('approvals.approve',", "('approvals.manage',",
			"role.name IN ('platform_owner', 'platform_admin')",
			"state IN ('pending', 'rejected', 'executing', 'unknown', 'executed', 'failed')",
			"CHECK (NOT self_approved OR decided_by_user_id = requested_by_user_id)",
		}},
		{migration522ID + ".down.sql", migration522DownSHA, []string{
			fmt.Sprintf("(SELECT count(*) FROM schema_migrations) <> %d", migration522Version),
			"migration_id='" + migration522ID + "'", "ERRCODE='P5221'",
			"DROP TABLE approval_requests", "DROP TABLE approval_center_settings",
		}},
	} {
		raw, err := FS.ReadFile(script.name)
		if err != nil {
			t.Fatal(err)
		}
		if sum := fmt.Sprintf("%x", sha256.Sum256(raw)); sum != script.sha {
			t.Errorf("%s sha256 = %s, want %s", script.name, sum, script.sha)
		}
		for _, fragment := range script.required {
			if !strings.Contains(string(raw), fragment) {
				t.Errorf("%s is missing %q", script.name, fragment)
			}
		}
	}
	// 183's table stays (Q6: the old high-risk operation code is removed, the released table is kept).
	if _, err := FS.ReadFile("183_high_risk_operations.up.sql"); err != nil {
		t.Fatal(err)
	}
}
