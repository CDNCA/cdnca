//go:build integration

package migrations_test

import (
	"testing"
	"time"

	"github.com/google/uuid"
)

// TestTickets302Migration rolls 302 up, down and up on a 301 schema, checks
// the grants, the status/timestamp invariants and that the rollback refuses
// to discard customer tickets.
func TestTickets302Migration(t *testing.T) {
	const version = 302
	pool := migrationPoolAt(t, version-1)
	ctx := t.Context()
	for _, step := range []string{"up", "down", "up"} {
		if err := migrateVersionIsolated(ctx, pool, step, version); err != nil {
			t.Fatalf("%s %d: %v", step, version, err)
		}
	}
	var granted bool
	if err := pool.QueryRow(ctx, `SELECT has_table_privilege('cdnca_control_app','tickets','UPDATE') AND
		has_table_privilege('cdnca_control_app','ticket_messages','INSERT') AND
		NOT has_table_privilege('cdnca_control_app','ticket_messages','UPDATE') AND
		NOT has_table_privilege('cdnca_control_app','tickets','DELETE') AND
		NOT has_table_privilege('cdnca_control_app','ticket_attachments','DELETE')`).Scan(&granted); err != nil || !granted {
		t.Fatalf("grants = %v (%v)", granted, err)
	}
	var events, templates int
	if err := pool.QueryRow(ctx, `SELECT
		(SELECT count(*) FROM notification_event_policies WHERE event_type LIKE 'ticket.%' AND supported),
		(SELECT count(*) FROM notification_templates WHERE template_id LIKE 'ticket\_%')`).Scan(&events, &templates); err != nil {
		t.Fatal(err)
	}
	if events != 3 || templates != 6 {
		t.Fatalf("events=%d templates=%d", events, templates)
	}

	now := time.Now().UTC()
	tenantID, scopeID, userID := uuid.New(), uuid.New(), uuid.New()
	for _, statement := range []struct {
		query string
		args  []any
	}{
		{`INSERT INTO tenants(id,display_name,status,created_at,updated_at) VALUES($1,'t302','active',$2,$2)`, []any{tenantID, now}},
		{`INSERT INTO access_scopes(id,kind,tenant_id,created_at) VALUES($1,'tenant',$2,$3)`, []any{scopeID, tenantID, now}},
		{`INSERT INTO users(id,username,display_name,password_hash,status,created_at,updated_at)
			VALUES($1,'u302','u302','x','active',$2,$2)`, []any{userID, now}},
		{`INSERT INTO memberships(scope_id,user_id,status,created_at) VALUES($1,$2,'active',$3)`, []any{scopeID, userID, now}},
	} {
		if _, err := pool.Exec(ctx, statement.query, statement.args...); err != nil {
			t.Fatal(err)
		}
	}
	insert := `INSERT INTO tickets(id,tenant_scope_id,user_id,category,subject,status,resolved_at,closed_at,
		last_message_at,created_at,updated_at) VALUES($1,$2,$3,'technical',$4,$5,$6,$7,$8,$8,$8)`
	if _, err := pool.Exec(ctx, insert, uuid.New(), scopeID, userID, "x", "closed", nil, nil, now); err == nil {
		t.Fatal("closed ticket without closed_at was accepted")
	}
	if _, err := pool.Exec(ctx, insert, uuid.New(), scopeID, uuid.New(), "x", "open", nil, nil, now); err == nil {
		t.Fatal("ticket for a non-member was accepted")
	}
	ticketID := uuid.New()
	if _, err := pool.Exec(ctx, insert, ticketID, scopeID, userID, "需要帮助", "open", nil, nil, now); err != nil {
		t.Fatal(err)
	}
	if _, err := pool.Exec(ctx, `INSERT INTO ticket_messages(id,ticket_id,author_user_id,author_kind,body,internal,created_at)
		VALUES($1,$2,$3,'customer','x',true,$4)`, uuid.New(), ticketID, userID, now); err == nil {
		t.Fatal("customer internal note was accepted")
	}
	if err := migrateVersionIsolated(ctx, pool, "down", version); err == nil {
		t.Fatal("rollback discarded a customer ticket")
	}
}
