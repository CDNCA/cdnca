package migrations

import (
	"crypto/sha256"
	"fmt"
	"strings"
	"testing"
)

// Migration 435 (the platform administrator may decide its
// own billing adjustment, recharge approval and high-risk operation) is a
// placeholder number; the merge renumbers it after the head it lands on.
// Everything that changes with the renumbering is here.
const (
	migration435Version         = 435
	migration435ID              = "435_admin_self_approval"
	migration435PreviousID      = "434_node_certificate_recovery"
	migration435PreviousUpSHA   = "9213fec1fc5f7be37590c698594ddf787fbdcf2d870f042025eb897832e58b81"
	migration435PreviousDownSHA = "ae56e51e2cf3bb831ff4f7206423dced4ff93de0027daeacdcc66171df9b5a45"
	migration435UpSHA           = "be4c6888bfcf672c29a4a4a0b986d152285f6c946065bbfaf997737dbb11c0ac"
	migration435DownSHA         = "d1a36297a2f979e16236409e532aa3e6544f6c83ec198211656734bf980b041b"
)

func TestAdminSelfApproval435Contract(t *testing.T) {
	for _, script := range []struct {
		name, sha string
		required  []string
	}{
		{migration435ID + ".up.sql", migration435UpSHA, []string{
			fmt.Sprintf("(SELECT count(*) FROM schema_migrations) <> %d", migration435Version-1),
			fmt.Sprintf("(SELECT max(version) FROM schema_migrations) <> %d", migration435Version-1),
			"migration_id='" + migration435PreviousID + "'", migration435PreviousUpSHA, migration435PreviousDownSHA,
			"ERRCODE='P4350'", "grant_row.permission_name='platform.admin'",
			"NOT control_platform_admin_435(NEW.approved_by_user_id,NEW.approved_by_scope_id)",
			"NOT control_platform_admin_435(NEW.decided_by_user_id,NEW.decided_by_scope_id)",
			"NOT control_platform_admin_435(NEW.approved_by,NULL)",
		}},
		{migration435ID + ".down.sql", migration435DownSHA, []string{
			fmt.Sprintf("(SELECT count(*) FROM schema_migrations) <> %d", migration435Version),
			"migration_id='" + migration435ID + "'", "ERRCODE='P4351'", "ERRCODE='P4352'",
			"DROP FUNCTION control_platform_admin_435(uuid,uuid)",
		}},
	} {
		raw, err := FS.ReadFile(script.name)
		if err != nil {
			t.Skipf("%s not embedded under this number (local renumbering): %v", script.name, err)
		}
		if got := fmt.Sprintf("%x", sha256.Sum256(raw)); got != script.sha {
			t.Fatalf("%s checksum drift: %s", script.name, got)
		}
		for _, required := range script.required {
			if !strings.Contains(string(raw), required) {
				t.Errorf("%s missing %q", script.name, required)
			}
		}
	}
	// The down script restores the exact maker-checker bodies of 100/171/183.
	down, _ := FS.ReadFile(migration435ID + ".down.sql")
	for _, original := range []string{
		"    IF NEW.approved_by_user_id=request.proposed_by_user_id THEN\n",
		"        IF request.id IS NULL OR NEW.decided_by_user_id=request.proposed_by_user_id OR\n",
		"            IF NEW.approved_by IS NULL OR NEW.approved_by=NEW.proposed_by OR\n",
	} {
		if !strings.Contains(string(down), original) {
			t.Errorf("down script lacks the original rule %q", original)
		}
	}
}
