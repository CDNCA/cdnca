package impersonation

import (
	"context"
	"crypto/sha256"
	"errors"
	"testing"
	"time"

	"github.com/google/uuid"
)

type resellerFixture struct {
	actor     Actor
	customer  tenantFixture
	foreign   tenantFixture
	scopeID   uuid.UUID
	ownerRole uuid.UUID
}

// seedResellerSwitch makes a reseller whose owner holds
// reseller.customers.manage (480 grants it on opening), puts tenant A under
// it and tenant B under another reseller.
func seedResellerSwitch(t *testing.T, fixture integrationFixture) resellerFixture {
	t.Helper()
	ctx := context.Background()
	exec := func(query string, args ...any) {
		t.Helper()
		if _, err := fixture.pool.Exec(ctx, query, args...); err != nil {
			t.Fatalf("%s: %v", query, err)
		}
	}
	opener := fixture.actor.UserID
	open := func(name string) (uuid.UUID, uuid.UUID, uuid.UUID, uuid.UUID) {
		tenantID, scopeID, userID, roleID, sessionID := uuid.New(), uuid.New(), uuid.New(), uuid.New(), uuid.New()
		exec(`INSERT INTO tenants(id,display_name) VALUES($1,$2)`, tenantID, name)
		exec(`INSERT INTO access_scopes(id,kind,tenant_id) VALUES($1,'tenant',$2)`, scopeID, tenantID)
		exec(`INSERT INTO users(id,username,display_name,password_hash) VALUES($1,$2,$3,'integration-password-hash')`,
			userID, "reseller-"+userID.String(), name)
		exec(`INSERT INTO memberships(scope_id,user_id) VALUES($1,$2)`, scopeID, userID)
		exec(`INSERT INTO roles(id,scope_id,name,description,system_role) VALUES($1,$2,'tenant_owner','owner',true)`, roleID, scopeID)
		exec(`INSERT INTO role_assignments(scope_id,user_id,role_id) VALUES($1,$2,$3)`, scopeID, userID, roleID)
		exec(`INSERT INTO reseller_profiles(scope_id,status,revision,created_by_user_id,created_at,updated_by_user_id,updated_at)
			VALUES($1,'active',1,$2,now(),$2,now())`, scopeID, opener)
		refresh := sha256.Sum256(sessionID[:])
		exec(`INSERT INTO auth_sessions(id,family_id,user_id,scope_id,refresh_token_hash,created_at,expires_at)
			VALUES($1,$1,$2,$3,$4,$5,$6)`, sessionID, userID, scopeID, refresh[:],
			fixture.clock.Now().Add(-time.Hour), fixture.clock.Now().Add(time.Hour))
		return scopeID, userID, sessionID, roleID
	}
	scopeID, userID, sessionID, roleID := open("Reseller A")
	otherScope, _, _, _ := open("Reseller B")
	exec(`UPDATE tenants SET parent_scope_id=$2 WHERE id=$1`, fixture.tenantA.id, scopeID)
	exec(`UPDATE tenants SET parent_scope_id=$2 WHERE id=$1`, fixture.tenantB.id, otherScope)
	return resellerFixture{
		actor: Actor{UserID: userID, ScopeID: scopeID, PrimaryAuthSessionID: sessionID, ScopeKind: "tenant",
			SessionKind: SessionKindPrimary},
		customer: fixture.tenantA, foreign: fixture.tenantB, scopeID: scopeID, ownerRole: roleID,
	}
}

func countImpersonationAudits(t *testing.T, fixture integrationFixture, scopeID uuid.UUID, action, result string) int {
	t.Helper()
	var count int
	if err := fixture.pool.QueryRow(t.Context(), `SELECT count(*) FROM audit_events
		WHERE scope_id=$1 AND action=$2 AND result=$3`, scopeID, action, result).Scan(&count); err != nil {
		t.Fatal(err)
	}
	return count
}

// TestResellerSwitchesOnlyToOwnCustomers (ADR 0018 RS-07 acceptance, Q4,
// with the platform switch rules): a reseller switches
// directly to its own customer (audited in both scopes) and back out, is
// refused for another reseller's customer (audited, no grant), cannot reach
// a platform administrator, cannot end a platform administrator's switch,
// and loses switching when suspended. The database refuses a reseller grant
// for a foreign customer even if the service were bypassed.
//
// Before RS-07 every tenant actor was refused (validatePrimaryActor required
// a platform scope and 038's trigger a platform actor).
func TestResellerSwitchesOnlyToOwnCustomers(t *testing.T) {
	fixture := newIntegrationFixture(t)
	reseller := seedResellerSwitch(t, fixture)
	ctx := t.Context()

	// Another reseller's customer: denied, nothing granted, audited.
	foreign := CreateRequest{TenantID: reseller.foreign.id, TenantScopeID: reseller.foreign.scopeID,
		SubjectUserID: reseller.foreign.userID, IdempotencyKey: "rs-foreign", Context: requestContext("rs-foreign")}
	if _, err := fixture.service.Create(ctx, reseller.actor, foreign); !errors.Is(err, ErrPermissionDenied) {
		t.Fatalf("switch to another reseller's customer = %v, want permission denied", err)
	}
	if n := countImpersonationAudits(t, fixture, reseller.scopeID, actionCreate, "denied"); n != 1 {
		t.Fatalf("reseller-scope denial audits = %d", n)
	}
	if n := countImpersonationAudits(t, fixture, reseller.foreign.scopeID, actionCreate, "denied"); n != 1 {
		t.Fatalf("target-scope denial audits = %d", n)
	}
	assertRowCount(t, fixture.pool, "admin_impersonation_grants", "actor_scope_id", reseller.scopeID, 0)

	// The database refuses it too.
	if _, err := fixture.pool.Exec(ctx, `INSERT INTO admin_impersonation_grants(
		id,tenant_id,tenant_scope_id,actor_user_id,actor_scope_id,subject_user_id,primary_auth_session_id,
		code_digest,subject_permissions_digest,reason,idempotency_key,request_digest,request_id,trace_id,created_at,expires_at)
		VALUES($1,$2,$3,$4,$5,$6,$7,$8,$8,'user_list_switch','direct',$8,'r','t',$9,$10)`,
		uuid.New(), reseller.foreign.id, reseller.foreign.scopeID, reseller.actor.UserID, reseller.actor.ScopeID,
		reseller.foreign.userID, reseller.actor.PrimaryAuthSessionID, make([]byte, 32), fixture.clock.Now(),
		fixture.clock.Now().Add(time.Minute)); err == nil {
		t.Fatal("database accepted a reseller grant for another reseller's customer")
	}

	// Own customer: direct switch, banner names the reseller, audited in
	// both scopes; the session acts as the customer.
	created, err := fixture.service.Create(ctx, reseller.actor, fixture.createRequest(t, "rs-own", reseller.customer))
	if err != nil {
		t.Fatalf("switch to own customer = %v", err)
	}
	session, err := fixture.service.Exchange(ctx, fixture.exchangeRequest(created, "rs-own-exchange"))
	if err != nil || session.Principal.ScopeID != reseller.customer.scopeID || session.Banner.ActorUserID != reseller.actor.UserID {
		t.Fatalf("exchange = %+v, %v", session, err)
	}
	if _, err := fixture.service.Authorize(ctx, UseRequest{Session: session, Action: "sites.read",
		Context: requestContext("rs-use")}); err != nil {
		t.Fatalf("use as customer = %v", err)
	}
	for _, scope := range []uuid.UUID{reseller.scopeID, reseller.customer.scopeID} {
		if n := countImpersonationAudits(t, fixture, scope, actionCreate, "success"); n != 1 {
			t.Fatalf("switch audits in scope %s = %d, want 1", scope, n)
		}
	}
	if n := countImpersonationAudits(t, fixture, reseller.customer.scopeID, actionExchange, "success"); n != 1 {
		t.Fatalf("exchange audits = %d", n)
	}

	// A platform administrator's switch cannot be ended by the reseller;
	// the reseller ends its own.
	platform := fixture.mustCreate(t, "platform-switch", reseller.customer)
	if _, err := fixture.service.Revoke(ctx, reseller.actor, fixture.revokeRequest(platform.Grant, "rs-revoke-platform")); !errors.Is(err, ErrPermissionDenied) {
		t.Fatalf("reseller ending a platform switch = %v", err)
	}
	if _, err := fixture.service.Revoke(ctx, reseller.actor, fixture.revokeRequest(created.Grant, "rs-revoke-own")); err != nil {
		t.Fatalf("reseller exit = %v", err)
	}
	assertUseError(t, fixture, session, "rs-after-exit", ErrSessionRevoked)

	// No switching to a platform administrator: the target must be a
	// tenant member, and the platform scope is never a reseller's customer.
	if _, err := fixture.service.Create(ctx, reseller.actor, CreateRequest{TenantID: reseller.customer.id,
		TenantScopeID: reseller.customer.scopeID, SubjectUserID: fixture.actor.UserID, IdempotencyKey: "rs-admin",
		Context: requestContext("rs-admin")}); !errors.Is(err, ErrPrincipalChanged) {
		t.Fatalf("switch to a platform administrator = %v", err)
	}

	// Suspending the reseller (480 revokes reseller.*) ends switching.
	if _, err := fixture.pool.Exec(ctx, `UPDATE reseller_profiles SET status='suspended',suspended_at=now(),revision=revision+1
		WHERE scope_id=$1`, reseller.scopeID); err != nil {
		t.Fatal(err)
	}
	if _, err := fixture.service.Create(ctx, reseller.actor, fixture.createRequest(t, "rs-suspended", reseller.customer)); !errors.Is(err, ErrPermissionDenied) {
		t.Fatalf("suspended reseller switch = %v", err)
	}
}
