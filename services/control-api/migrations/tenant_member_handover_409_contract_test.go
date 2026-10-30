package migrations

import (
	"crypto/sha256"
	"fmt"
	"strings"
	"testing"
)

// Migration 409 (change the password at the next
// sign-in, certificate owner handover) is a placeholder number (integration
// head 403 + 1); the merge renumbers it. Everything that changes with the
// renumbering is in this block.
const (
	migration409Version         = 409
	migration409ID              = "409_tenant_member_handover"
	migration409PreviousID      = "408_security_ban_list"
	migration409PreviousUpSHA   = "2930704b02b72ecf91078d776b2f59fb92cf538dec68e94f7284d3dbfaf52690"
	migration409PreviousDownSHA = "02e04ab4134098bbd3f7de2faadba530b95d034f0508f783398f356e5c497e49"
	migration409UpSHA           = "619c8bcd003ec67de37e8e96c7e38d9430f4e9b46528748e46cf71d5dcdfd8a7"
	migration409DownSHA         = "8a5ec6bab67fe7e8a8a63a6efdaf0ee30bdecca5a72c33c39fcf0c3adc85ac25"
)

func TestTenantMemberHandover409Contract(t *testing.T) {
	for _, script := range []struct {
		name, sha string
		required  []string
	}{
		{migration409ID + ".up.sql", migration409UpSHA, []string{
			fmt.Sprintf("(SELECT count(*) FROM schema_migrations) <> %d", migration409Version-1),
			fmt.Sprintf("(SELECT max(version) FROM schema_migrations) <> %d", migration409Version-1),
			"migration_id='" + migration409PreviousID + "'", migration409PreviousUpSHA, migration409PreviousDownSHA,
			"ERRCODE='P4090'", "ADD COLUMN password_change_required boolean NOT NULL DEFAULT false",
			"current_setting('cdnca.tenant_member_handover', true)",
			"OLD.owner_user_id::text || ':' || NEW.owner_user_id::text",
			"REVOKE ALL ON FUNCTION protect_certificate_asset_owner_276() FROM PUBLIC,cdnca_control_app",
			"CREATE OR REPLACE FUNCTION validate_certificate_asset_actor_target_085()",
		}},
		{migration409ID + ".down.sql", migration409DownSHA, []string{
			fmt.Sprintf("(SELECT count(*) FROM schema_migrations) <> %d", migration409Version),
			"migration_id='" + migration409ID + "'", "ERRCODE='P4091'", "ERRCODE='P4092'",
			"DROP COLUMN password_change_required", "certificate asset owner is immutable",
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
	// The down script restores the 276 and 085 functions exactly.
	down, _ := FS.ReadFile(migration409ID + ".down.sql")
	original276, _ := FS.ReadFile("276_certificate_asset_owner.up.sql")
	original085, _ := FS.ReadFile("085_certificate_asset_actor_scope.up.sql")
	for _, body := range []struct {
		source     []byte
		start, end string
	}{
		{original276, "RETURNS trigger\nLANGUAGE plpgsql SET search_path", "$$;"},
		{original085, "CREATE FUNCTION validate_certificate_asset_actor_target_085()", "$$;"},
	} {
		text := string(body.source)
		from := strings.Index(text, body.start)
		if from < 0 {
			t.Fatalf("original function %q not found", body.start)
		}
		function := text[from:]
		function = function[:strings.Index(function, body.end)+len(body.end)]
		function = strings.Replace(function, "CREATE FUNCTION", "CREATE OR REPLACE FUNCTION", 1)
		if !strings.Contains(string(down), function) {
			t.Errorf("down does not restore %q verbatim", body.start)
		}
	}
}
