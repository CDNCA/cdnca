//go:build integration

package securityactivation

import (
	"errors"
	"testing"

	"github.com/cdnca/cdnca/services/control-api/internal/securitypolicy"
	"github.com/google/uuid"
	"github.com/jackc/pgx/v5"
)

// platformActivationAdmin is a platform scope member holding platform.admin
// (the platform administrator of the site edit page, site-parity3b).
func platformActivationAdmin(t *testing.T, fixture activationFixture, permissions ...string) securitypolicy.Actor {
	t.Helper()
	var scopeID uuid.UUID
	if err := fixture.pool.QueryRow(t.Context(), `SELECT id FROM access_scopes WHERE kind='platform' LIMIT 1`).
		Scan(&scopeID); err != nil {
		if !errors.Is(err, pgx.ErrNoRows) {
			t.Fatal(err)
		}
		scopeID = uuid.New()
		if _, err := fixture.pool.Exec(t.Context(), `INSERT INTO access_scopes(id,kind) VALUES($1,'platform')`, scopeID); err != nil {
			t.Fatal(err)
		}
	}
	userID, roleID := uuid.New(), uuid.New()
	for _, statement := range []struct {
		sql  string
		args []any
	}{
		{`INSERT INTO users(id,username,display_name,password_hash) VALUES($1,$2,'platform admin','hash')`,
			[]any{userID, "activation-platform-" + userID.String()}},
		{`INSERT INTO memberships(scope_id,user_id) VALUES($1,$2)`, []any{scopeID, userID}},
		{`INSERT INTO roles(id,scope_id,name,description,system_role) VALUES($1,$2,$3,'',true)`,
			[]any{roleID, scopeID, "activation_platform_" + roleID.String()[:8]}},
		{`INSERT INTO role_permissions(role_id,permission_name) SELECT $1,unnest($2::text[])`, []any{roleID, permissions}},
		{`INSERT INTO role_assignments(scope_id,user_id,role_id) VALUES($1,$2,$3)`, []any{scopeID, userID, roleID}},
	} {
		if _, err := fixture.pool.Exec(t.Context(), statement.sql, statement.args...); err != nil {
			t.Fatal(err)
		}
	}
	return securitypolicy.Actor{UserID: userID, ScopeID: scopeID, ScopeKind: "platform"}
}

// site-parity3b: a platform administrator reads and starts a tenant site's
// security activation without switching identity. The start runs in the
// site's tenant scope; the candidate and the audit event name the platform
// actor (actor_scope_id = platform scope) and the tenant (scope_id = the
// site's tenant scope). A platform member without the permission and another
// tenant's member stay refused.
func TestPlatformAdministratorStartsTenantSiteActivation(t *testing.T) {
	fixture := newActivationFixture(t)
	store := newProductionActivationStore(t, fixture)
	// As the platform owner/admin system roles hold (identity store.go, 026).
	admin := platformActivationAdmin(t, fixture, "platform.admin", "security_policies.read", "security_policies.manage")

	scope, err := store.SiteTenantScope(t.Context(), admin, fixture.siteID)
	if err != nil || scope != fixture.scopeID {
		t.Fatalf("platform site tenant scope = (%s, %v), want %s", scope, err, fixture.scopeID)
	}
	if own, err := store.SiteTenantScope(t.Context(), fixture.actor, fixture.siteID); err != nil || own != fixture.scopeID {
		t.Fatalf("tenant site tenant scope = (%s, %v)", own, err)
	}
	status, err := store.Status(t.Context(), admin, fixture.siteID, securitypolicy.KindWAF)
	if err != nil || status.Binding == nil || status.Binding.ID != fixture.bindingID {
		t.Fatalf("platform status = (%+v, %v)", status, err)
	}

	input := prepareProductionStart(t, fixture, store, "platform-admin-start",
		[]uuid.UUID{fixture.canaryNodeID, fixture.expandNodeID}, 1)
	input.TenantScopeID = scope

	unpermitted := platformActivationAdmin(t, fixture, "sites.read")
	if _, err := store.Start(t.Context(), unpermitted, input); !errors.Is(err, ErrPermissionDenied) {
		t.Fatalf("platform member without permission start error = %v, want ErrPermissionDenied", err)
	}
	foreign := fixture.newPermissionActor(t, "security_policies.manage").actor
	foreign.ScopeID = uuid.New()
	if _, err := store.Status(t.Context(), foreign, fixture.siteID, securitypolicy.KindWAF); !errors.Is(err, ErrPermissionDenied) {
		t.Fatalf("foreign tenant status error = %v, want ErrPermissionDenied", err)
	}
	if _, err := store.Start(t.Context(), foreign, input); !errors.Is(err, ErrPermissionDenied) {
		t.Fatalf("foreign tenant start error = %v, want ErrPermissionDenied", err)
	}

	started, err := store.Start(t.Context(), admin, input)
	if err != nil {
		t.Fatal(err)
	}
	if started.Candidate.TenantScopeID != fixture.scopeID || started.Candidate.SiteID != fixture.siteID {
		t.Fatalf("platform candidate = %+v", started.Candidate)
	}
	var actorScope, actorUser uuid.UUID
	if err := fixture.pool.QueryRow(t.Context(), `SELECT actor_scope_id,actor_user_id
		FROM security_policy_activation_candidates WHERE id=$1`, started.Candidate.ID).Scan(&actorScope, &actorUser); err != nil ||
		actorScope != admin.ScopeID || actorUser != admin.UserID {
		t.Fatalf("candidate actor scope=%s user=%s err=%v", actorScope, actorUser, err)
	}
	var auditScope, auditActor uuid.UUID
	if err := fixture.pool.QueryRow(t.Context(), `SELECT scope_id,actor_user_id FROM audit_events
		WHERE action='security_policy.activation.start' AND resource_id=$1 AND result='success'`,
		started.Candidate.ID.String()).Scan(&auditScope, &auditActor); err != nil ||
		auditScope != fixture.scopeID || auditActor != admin.UserID {
		t.Fatalf("activation audit scope=%s actor=%s err=%v", auditScope, auditActor, err)
	}
	// The site's tenant still sees the platform-started candidate as its own.
	tenantStatus, err := store.Status(t.Context(), fixture.actor, fixture.siteID, securitypolicy.KindWAF)
	if err != nil || tenantStatus.LatestCandidate == nil || tenantStatus.LatestCandidate.ID != started.Candidate.ID {
		t.Fatalf("tenant status after platform start = (%+v, %v)", tenantStatus, err)
	}
	if _, _, err := store.rollbackSite(t.Context(), foreign, started.Candidate.ID); !errors.Is(err, ErrNotFound) {
		t.Fatalf("foreign rollback lookup error = %v, want ErrNotFound", err)
	}
	if site, rollbackScope, err := store.rollbackSite(t.Context(), admin, started.Candidate.ID); err != nil ||
		site != fixture.siteID || rollbackScope != fixture.scopeID {
		t.Fatalf("platform rollback lookup = (%s, %s, %v)", site, rollbackScope, err)
	}
}
