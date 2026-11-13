//go:build integration

package migrations_test

import "testing"

// 666: 665 -> 666 -> 665 -> 666. The 398 invitation table/guard/template and the 487 reset
// results table come back (empty) and go again, and the certificate owner guard regains the 409 handover branch.
func TestTenantMembersRestore666UpDownUp(t *testing.T) {
	const version = 666
	pool := migrationPoolAt(t, version-1)
	ctx := t.Context()
	state := func() [4]int {
		t.Helper()
		var tables, functions, templates int
		var handover bool
		if err := pool.QueryRow(ctx, `SELECT
			(SELECT count(*) FROM unnest(ARRAY['tenant_member_invitations_398','tenant_member_password_reset_results']) name
				WHERE to_regclass(name) IS NOT NULL),
			(SELECT count(*) FROM pg_proc WHERE proname='guard_tenant_member_invitations_398'),
			(SELECT count(*) FROM notification_templates WHERE template_id='tenant_member_invitation'),
			(SELECT position('tenant_member_handover' IN prosrc) > 0 FROM pg_proc WHERE proname='protect_certificate_asset_owner_276')`).Scan(
			&tables, &functions, &templates, &handover); err != nil {
			t.Fatal(err)
		}
		return [4]int{tables, functions, templates, map[bool]int{true: 1}[handover]}
	}
	if got := state(); got != [4]int{0, 0, 0, 0} {
		t.Fatalf("before 666: %v", got)
	}
	for _, step := range []struct {
		direction string
		want      [4]int
	}{{"up", [4]int{2, 1, 1, 1}}, {"down", [4]int{0, 0, 0, 0}}, {"up", [4]int{2, 1, 1, 1}}} {
		if err := migrateVersionIsolated(ctx, pool, step.direction, version); err != nil {
			t.Fatalf("%s %d: %v", step.direction, version, err)
		}
		if got := state(); got != step.want {
			t.Fatalf("after %s: got %v want %v", step.direction, got, step.want)
		}
	}
}
