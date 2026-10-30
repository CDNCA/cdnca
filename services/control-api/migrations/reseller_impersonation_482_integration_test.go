//go:build integration

package migrations_test

import (
	"crypto/sha256"
	"strings"
	"testing"
	"time"

	"github.com/google/uuid"
)

// TestResellerImpersonation482 rolls 482 up, down and up, then checks the
// relaxed 038 triggers (ADR 0018 RS-07): an active reseller's member holding
// reseller.customers.manage may record a grant for its own customer but not
// for another reseller's customer, nor once suspended; down refuses while a
// reseller grant exists (P4822).
func TestResellerImpersonation482(t *testing.T) {
	const version = 482
	pool := migrationPoolAt(t, version-1)
	ctx := t.Context()
	for _, step := range []string{"up", "down", "up"} {
		if err := migrateVersionIsolated(ctx, pool, step, version); err != nil {
			t.Fatalf("%s %d: %v", step, version, err)
		}
	}
	now := time.Now().UTC().Truncate(time.Microsecond)
	exec := func(sql string, args ...any) {
		t.Helper()
		if _, err := pool.Exec(ctx, sql, args...); err != nil {
			t.Fatalf("%s: %v", sql, err)
		}
	}
	opener := uuid.New()
	exec(`INSERT INTO users(id,username,display_name,password_hash) VALUES($1,$2,'opener','hash')`, opener, "rs-482-"+opener.String())
	type member struct{ tenant, scope, user, session uuid.UUID }
	tenant := func(name string, reseller bool) member {
		m := member{uuid.New(), uuid.New(), uuid.New(), uuid.New()}
		exec(`INSERT INTO tenants(id,display_name) VALUES($1,$2)`, m.tenant, name)
		exec(`INSERT INTO access_scopes(id,kind,tenant_id) VALUES($1,'tenant',$2)`, m.scope, m.tenant)
		exec(`INSERT INTO users(id,username,display_name,password_hash) VALUES($1,$2,$3,'hash')`, m.user, "rs-482-"+m.user.String(), name)
		exec(`INSERT INTO memberships(scope_id,user_id) VALUES($1,$2)`, m.scope, m.user)
		refresh := sha256.Sum256(m.session[:])
		exec(`INSERT INTO auth_sessions(id,family_id,user_id,scope_id,refresh_token_hash,created_at,expires_at)
			VALUES($1,$1,$2,$3,$4,$5,$6)`, m.session, m.user, m.scope, refresh[:], now.Add(-time.Hour), now.Add(time.Hour))
		if reseller {
			role := uuid.New()
			exec(`INSERT INTO roles(id,scope_id,name,description,system_role) VALUES($1,$2,'tenant_owner','owner',true)`, role, m.scope)
			exec(`INSERT INTO role_assignments(scope_id,user_id,role_id) VALUES($1,$2,$3)`, m.scope, m.user, role)
			exec(`INSERT INTO reseller_profiles(scope_id,status,revision,created_by_user_id,created_at,updated_by_user_id,updated_at)
				VALUES($1,'active',1,$2,$3,$2,$3)`, m.scope, opener, now)
		}
		return m
	}
	agent, otherAgent := tenant("reseller a", true), tenant("reseller b", true)
	customer, foreign := tenant("customer a", false), tenant("customer b", false)
	exec(`UPDATE tenants SET parent_scope_id=$2 WHERE id=$1`, customer.tenant, agent.scope)
	exec(`UPDATE tenants SET parent_scope_id=$2 WHERE id=$1`, foreign.tenant, otherAgent.scope)
	grant := func(actor, target member) (uuid.UUID, error) {
		id := uuid.New()
		code := sha256.Sum256(id[:])
		_, err := pool.Exec(ctx, `INSERT INTO admin_impersonation_grants(
			id,tenant_id,tenant_scope_id,actor_user_id,actor_scope_id,subject_user_id,primary_auth_session_id,
			code_digest,subject_permissions_digest,reason,idempotency_key,request_digest,request_id,trace_id,created_at,expires_at)
			VALUES($1,$2,$3,$4,$5,$6,$7,$8,$9,'user_list_switch',$10,$9,'r','t',$11,$12)`,
			id, target.tenant, target.scope, actor.user, actor.scope, target.user, actor.session,
			code[:], make([]byte, 32), "k"+id.String()[:8], now, now.Add(time.Minute))
		return id, err
	}
	if _, err := grant(agent, foreign); err == nil || !strings.Contains(err.Error(), "invalid admin impersonation principals") {
		t.Fatalf("reseller grant for another reseller's customer: %v", err)
	}
	if _, err := grant(customer, foreign); err == nil {
		t.Fatal("plain tenant grant accepted")
	}
	own, err := grant(agent, customer)
	if err != nil {
		t.Fatalf("reseller grant for own customer: %v", err)
	}
	// The reseller ends its own switch.
	exec(`INSERT INTO admin_impersonation_revocations(id,grant_id,tenant_id,tenant_scope_id,original_actor_user_id,
		original_actor_scope_id,subject_user_id,revoked_by_user_id,revoked_by_scope_id,reason,idempotency_key,request_digest,
		request_id,trace_id,revoked_at) VALUES($1,$2,$3,$4,$5,$6,$7,$5,$6,'exit','exit-1',$8,'r','t',$9)`,
		uuid.New(), own, customer.tenant, customer.scope, agent.user, agent.scope, customer.user, make([]byte, 32), now)
	// Down keeps the recorded reseller switch rather than dropping it.
	if err := migrateVersionIsolated(ctx, pool, "down", version); err == nil || !strings.Contains(err.Error(), "P4822") {
		t.Fatalf("down with a reseller grant: %v", err)
	}
	exec(`UPDATE reseller_profiles SET status='suspended',suspended_at=$2,revision=2 WHERE scope_id=$1`, agent.scope, now)
	if _, err := grant(agent, customer); err == nil {
		t.Fatal("suspended reseller grant accepted")
	}
	var head int
	if err := pool.QueryRow(ctx, `SELECT max(version) FROM schema_migrations`).Scan(&head); err != nil || head != version {
		t.Fatalf("head = %d, %v", head, err)
	}
}
