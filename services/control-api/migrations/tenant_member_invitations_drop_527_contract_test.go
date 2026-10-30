package migrations

import (
	"crypto/sha256"
	"fmt"
	"strings"
	"testing"
)

// Migration 527 (member invitations removed with the tenant
// member endpoints; branch-local 527, dispatch placeholder
// 529, renumbered at merge): the up guard pins 524, drops the 398/487 tables
// and restores 198's anonymous event CHECK and 276's certificate owner guard;
// down rebuilds 398/409/487's definitions byte for byte.
const (
	migration527Version         = 527
	migration527ID              = "527_tenant_member_invitations_drop"
	migration527PreviousID      = "526_cache_cancel_deliveries"
	migration527PreviousUpSHA   = "a8072a592d876d9a710dc0b9efd3c6e3ec1805897c41ce58e40e78c9840f6b0b"
	migration527PreviousDownSHA = "13d617fc73f2411420a930185aabd38d5059fcf7fd1f23e6ceaaaa5fcbf3a9b0"
	migration527UpSHA           = "810266afb33ef34a711d3da3e5606ea14819ca09491604e23ca24d1d822e2ce5"
	migration527DownSHA         = "856a4c33b26b0e83167ce2185a1f3e84e3cf66ad3cd61ab2e5b046bcf263bb5d"
)

func TestTenantMemberInvitationsDrop527Contract(t *testing.T) {
	read := func(name string) string {
		t.Helper()
		raw, err := FS.ReadFile(name)
		if err != nil {
			t.Fatal(err)
		}
		return string(raw)
	}
	between := func(text, from, to string) string {
		t.Helper()
		start := strings.Index(text, from)
		end := strings.Index(text[start+1:], to)
		if start < 0 || end < 0 {
			t.Fatalf("missing %q..%q", from, to)
		}
		return text[start : start+1+end]
	}
	m398, d398 := read("398_tenant_member_invitations.up.sql"), read("398_tenant_member_invitations.down.sql")
	m409, d409 := read("409_tenant_member_handover.up.sql"), read("409_tenant_member_handover.down.sql")
	m487 := read("487_tenant_member_password_reset_results.up.sql")
	up := []string{
		fmt.Sprintf("(SELECT count(*) FROM schema_migrations) <> %d", migration527Version-1),
		fmt.Sprintf("(SELECT max(version) FROM schema_migrations) <> %d", migration527Version-1),
		"migration_id='" + migration527PreviousID + "'", migration527PreviousUpSHA, migration527PreviousDownSHA,
		"ERRCODE='P5270'", "ERRCODE='P5271'",
		"DROP TABLE tenant_member_invitations_398;", "DROP FUNCTION guard_tenant_member_invitations_398();",
		"DROP TABLE tenant_member_password_reset_results;",
		"DELETE FROM notification_templates WHERE template_id='tenant_member_invitation'",
		// 198's CHECK (398's down) and 276's owner guard (409's down).
		d398[strings.Index(d398, "ALTER TABLE notification_events"):],
		between(d409, "CREATE OR REPLACE FUNCTION protect_certificate_asset_owner_276", "CREATE OR REPLACE FUNCTION validate_certificate_asset_actor_target_085"),
	}
	down := []string{
		fmt.Sprintf("(SELECT count(*) FROM schema_migrations) <> %d", migration527Version),
		"migration_id='" + migration527ID + "'", "ERRCODE='P5272'",
		m398[strings.Index(m398, "CREATE TABLE tenant_member_invitations_398"):],
		m487[strings.Index(m487, "CREATE TABLE tenant_member_password_reset_results"):],
		between(m409, "CREATE OR REPLACE FUNCTION protect_certificate_asset_owner_276", "CREATE OR REPLACE FUNCTION validate_certificate_asset_actor_target_085"),
	}
	for _, script := range []struct {
		name, sha string
		required  []string
	}{
		{migration527ID + ".up.sql", migration527UpSHA, up},
		{migration527ID + ".down.sql", migration527DownSHA, down},
	} {
		raw := read(script.name)
		if got := fmt.Sprintf("%x", sha256.Sum256([]byte(raw))); got != script.sha {
			t.Fatalf("%s checksum drift: %s", script.name, got)
		}
		for _, required := range script.required {
			if !strings.Contains(raw, strings.TrimRight(required, "\n")) {
				t.Errorf("%s missing %.80q", script.name, required)
			}
		}
	}
	// users.password_change_required (409) stays: migration import and the
	// sign-in password change gate still use it.
	if raw := read(migration527ID + ".up.sql"); strings.Contains(raw, "DROP COLUMN") {
		t.Error("527 up must not drop users.password_change_required")
	}
}
