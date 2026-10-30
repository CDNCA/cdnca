//go:build integration

package migrations_test

import (
	"testing"
)

// TestTenantMemberInvitations398 rolls 398 up, down and up, then checks that
// the invitation event is accepted as an anonymous system_required event and
// that down refuses while invitation mails exist.
func TestTenantMemberInvitations398(t *testing.T) {
	const version = 398
	pool := migrationPoolAt(t, version-1)
	ctx := t.Context()
	for _, step := range []string{"up", "down", "up"} {
		if err := migrateVersionIsolated(ctx, pool, step, version); err != nil {
			t.Fatalf("%s %d: %v", step, version, err)
		}
	}
	var templates int
	if err := pool.QueryRow(ctx, `SELECT count(*) FROM notification_templates
		WHERE template_id='tenant_member_invitation' AND version=1 AND channel='email'`).Scan(&templates); err != nil || templates != 1 {
		t.Fatalf("template rows=%d err=%v", templates, err)
	}
	mustExec(t, pool, `INSERT INTO access_scopes(id,kind) VALUES('00000000-0000-4000-8000-000000000395','platform')`)
	mustExec(t, pool, `INSERT INTO notification_events(id,scope_id,recipient_user_id,source_event_id,event_type,delivery_policy,
		request_digest,created_at,recipient_kind,anonymous_dispatch_reference)
		VALUES(gen_random_uuid(),'00000000-0000-4000-8000-000000000395',NULL,'invitation-398','identity.tenant_member_invitation',
		'system_required',decode(repeat('ab',32),'hex'),now(),'anonymous',gen_random_uuid())`)
	if err := migrateVersionIsolated(ctx, pool, "down", version); err == nil {
		t.Fatal("down succeeded with invitation history")
	}
}
