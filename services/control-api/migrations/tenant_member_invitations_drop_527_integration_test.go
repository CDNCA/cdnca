//go:build integration

package migrations_test

import "testing"

// TestTenantMemberInvitationsDrop527Migration rolls 527 up, down and up: the
// 398 invitation table/guard/template and the 487 password reset results
// table disappear and come back empty, the anonymous event CHECK rejects
// identity.tenant_member_invitation after up, and the certificate owner guard
// loses the 409 handover branch. Up refuses while invitation history exists
// (fz-x9b). 待出包前全量跑.
func TestTenantMemberInvitationsDrop527Migration(t *testing.T) {
	const version = 527
	pool := migrationPoolAt(t, version-1)
	state := func() (tables, functions, templates int, handover bool) {
		t.Helper()
		if err := pool.QueryRow(t.Context(), `SELECT
			(SELECT count(*) FROM unnest(ARRAY['tenant_member_invitations_398','tenant_member_password_reset_results']) name
				WHERE to_regclass(name) IS NOT NULL),
			(SELECT count(*) FROM pg_proc WHERE proname='guard_tenant_member_invitations_398'),
			(SELECT count(*) FROM notification_templates WHERE template_id='tenant_member_invitation'),
			(SELECT position('tenant_member_handover' IN prosrc) > 0 FROM pg_proc WHERE proname='protect_certificate_asset_owner_276')`).Scan(
			&tables, &functions, &templates, &handover); err != nil {
			t.Fatal(err)
		}
		return
	}
	if tables, functions, templates, handover := state(); tables != 2 || functions != 1 || templates != 1 || !handover {
		t.Fatalf("before 527: tables=%d functions=%d templates=%d handover=%v", tables, functions, templates, handover)
	}
	for _, step := range []struct {
		direction string
		present   bool
	}{{"up", false}, {"down", true}, {"up", false}} {
		if err := migrateVersionIsolated(t.Context(), pool, step.direction, version); err != nil {
			t.Fatalf("%s %d: %v", step.direction, version, err)
		}
		tables, functions, templates, handover := state()
		want := map[bool][4]int{true: {2, 1, 1, 1}, false: {0, 0, 0, 0}}[step.present]
		got := [4]int{tables, functions, templates, map[bool]int{true: 1}[handover]}
		if got != want {
			t.Fatalf("after %s: got %v want %v", step.direction, got, want)
		}
	}
	mustExec(t, pool, `INSERT INTO access_scopes(id,kind) VALUES('00000000-0000-4000-8000-000000000527','platform')`)
	if _, err := pool.Exec(t.Context(), `INSERT INTO notification_events(id,scope_id,recipient_user_id,source_event_id,event_type,
		delivery_policy,request_digest,created_at,recipient_kind,anonymous_dispatch_reference)
		VALUES(gen_random_uuid(),'00000000-0000-4000-8000-000000000527',NULL,'invitation-527','identity.tenant_member_invitation',
		'system_required',decode(repeat('ab',32),'hex'),now(),'anonymous',gen_random_uuid())`); err == nil {
		t.Fatal("anonymous invitation event accepted after 527")
	}
	// With invitation history present (down, then a queued invitation event), up refuses.
	if err := migrateVersionIsolated(t.Context(), pool, "down", version); err != nil {
		t.Fatal(err)
	}
	mustExec(t, pool, `INSERT INTO notification_events(id,scope_id,recipient_user_id,source_event_id,event_type,delivery_policy,
		request_digest,created_at,recipient_kind,anonymous_dispatch_reference)
		VALUES(gen_random_uuid(),'00000000-0000-4000-8000-000000000527',NULL,'invitation-527b','identity.tenant_member_invitation',
		'system_required',decode(repeat('ab',32),'hex'),now(),'anonymous',gen_random_uuid())`)
	if err := migrateVersionIsolated(t.Context(), pool, "up", version); err == nil {
		t.Fatal("527 up succeeded with invitation history")
	}
}
