//go:build integration

package plugininstallation

import (
	"context"
	"crypto/sha256"
	"errors"
	"strings"
	"testing"
	"time"

	"github.com/cdnca/cdnca/services/control-api/internal/database/databasetest"
	"github.com/google/uuid"
	"github.com/jackc/pgx/v5/pgxpool"
)

type platformTargetsFixture struct {
	t    *testing.T
	pool *pgxpool.Pool
	now  time.Time
}

func (f platformTargetsFixture) exec(query string, args ...any) {
	f.t.Helper()
	if _, err := f.pool.Exec(f.t.Context(), query, args...); err != nil {
		f.t.Fatalf("%v\n%s", err, query)
	}
}

func (f platformTargetsFixture) member(scopeID uuid.UUID, scopeKind string, permissions ...string) Actor {
	f.t.Helper()
	userID, sessionID, roleID := uuid.New(), uuid.New(), uuid.New()
	refresh := sha256.Sum256(sessionID[:])
	f.exec(`INSERT INTO users(id,username,display_name,password_hash) VALUES($1,$2,'成员','unused')`,
		userID, "pt-"+strings.ReplaceAll(userID.String(), "-", "")[:12])
	f.exec(`INSERT INTO memberships(scope_id,user_id) VALUES($1,$2)`, scopeID, userID)
	f.exec(`INSERT INTO roles(id,scope_id,name,description,system_role) VALUES($1,$2,$3,'test',true)`,
		roleID, scopeID, "role-"+roleID.String()[:8])
	for _, permission := range permissions {
		f.exec(`INSERT INTO role_permissions(role_id,permission_name) VALUES($1,$2)`, roleID, permission)
	}
	f.exec(`INSERT INTO role_assignments(scope_id,user_id,role_id) VALUES($1,$2,$3)`, scopeID, userID, roleID)
	f.exec(`INSERT INTO auth_sessions(id,family_id,user_id,scope_id,refresh_token_hash,created_at,expires_at)
		VALUES($1,$2,$3,$4,$5,$6,$7)`, sessionID, uuid.New(), userID, scopeID, refresh[:], f.now.Add(-time.Minute),
		f.now.Add(time.Hour))
	return Actor{UserID: userID, SessionID: sessionID, TenantID: scopeID, ScopeKind: scopeKind, RequestID: "pt-req",
		Username: "pt-admin"}
}

func (f platformTargetsFixture) tenant(name string) uuid.UUID {
	id := uuid.New()
	f.exec(`INSERT INTO tenants(id,display_name) VALUES($1,$2)`, id, name)
	f.exec(`INSERT INTO access_scopes(id,kind,tenant_id) VALUES($1,'tenant',$1)`, id)
	return id
}

// 真实 PG：平台管理员在平台作用域确认租户插件并选租户（迁移 636）——head 与 targets
// 同一事务写入；被选中的租户只读看到它（managed_by=platform，不能写），没选中的看不到；平台视图带 targets 与
// 租户名；改 targets 走 If-Match + Idempotency-Key（同 key 同体回放、同 key 异体冲突、旧 revision 冲突）；
// 主题仍不能带 targets。
func TestPostgresPlatformConfirmsTenantPluginForChosenTenants(t *testing.T) {
	pool := databasetest.MigratedPool(t, nil)
	f := platformTargetsFixture{t: t, pool: pool, now: time.Now().UTC().Truncate(time.Second)}
	var platformScope uuid.UUID
	if err := pool.QueryRow(t.Context(), `SELECT id FROM access_scopes WHERE kind='platform'`).Scan(&platformScope); err != nil {
		platformScope = uuid.New()
		f.exec(`INSERT INTO access_scopes(id,kind) VALUES($1,'platform')`, platformScope)
	}
	tenantA, tenantB := f.tenant("甲租户"), f.tenant("乙租户")
	platform := f.member(platformScope, ScopePlatform, PermissionPlatformRead, PermissionPlatformManage)
	readerA := f.member(tenantA, ScopeTenant, PermissionRead, PermissionManage)
	readerB := f.member(tenantB, ScopeTenant, PermissionRead, PermissionManage)
	repository, err := NewPostgresRepository(pool, func() time.Time { return f.now })
	if err != nil {
		t.Fatal(err)
	}
	candidate := Candidate{TenantID: platformScope, InstallationID: uuid.New(), AuthorizationID: uuid.New(),
		VerificationID: uuid.New(), PluginID: "io.cdnca.cf-optimize", Version: "1.0.0", ResourceScope: ResourceScopeTenant,
		EntrypointType: EntrypointUIPage, ManifestSHA256: digest("a"), ConfigurationSchemaSHA256: digest("1"),
		ManifestScopes: []string{}, ApprovedScopes: []string{}, SensitiveScopes: []string{}}
	command := Command{TenantID: platformScope, InstallationID: candidate.InstallationID,
		AuthorizationID: candidate.AuthorizationID, Action: ActionConfirm, ExpectedRevision: 1,
		IdempotencyKey: "pt-confirm-1", RequestID: "pt-req", Candidate: candidate, Applied: true,
		Targets: &Targets{TenantScopeIDs: []uuid.UUID{tenantA}}}

	// Without targets a platform-held tenant head is refused (validCommand or the commit-time check).
	noTargets := command
	noTargets.Targets, noTargets.IdempotencyKey = nil, "pt-confirm-0"
	if _, err := repository.Apply(t.Context(), platform, noTargets, exactCandidateVerifier{candidate}); err == nil {
		t.Fatal("platform-held tenant plugin without targets was stored")
	}
	result, err := repository.Apply(t.Context(), platform, command, exactCandidateVerifier{candidate})
	if err != nil || result.Installation.Status != StatusEnabled || result.Installation.TenantID != platformScope {
		t.Fatalf("platform confirm=%+v err=%v", result.Installation, err)
	}
	// Replay of the same confirmation: same head, targets untouched.
	if replay, err := repository.Apply(t.Context(), platform, command, exactCandidateVerifier{candidate}); err != nil ||
		replay.Installation.Revision != result.Installation.Revision {
		t.Fatalf("confirm replay=%+v err=%v", replay.Installation, err)
	}

	view, err := repository.Get(t.Context(), platform, candidate.AuthorizationID)
	if err != nil || view.ManagedBy != ManagedByPlatform || view.Targets == nil || view.Targets.AllTenants ||
		view.Targets.Revision != 1 || len(view.Targets.Tenants) != 1 || view.Targets.Tenants[0].ScopeID != tenantA ||
		view.Targets.Tenants[0].DisplayName != "甲租户" {
		t.Fatalf("platform view=%+v targets=%+v err=%v", view, view.Targets, err)
	}
	// Tenant A reads it (managed by the platform, no targets disclosed); tenant B does not see it.
	if got, err := repository.Get(t.Context(), readerA, candidate.AuthorizationID); err != nil || got.ManagedBy != ManagedByPlatform ||
		got.Targets != nil {
		t.Fatalf("tenant A view=%+v err=%v", got, err)
	}
	if page, err := repository.List(t.Context(), readerA, ListRequest{TenantID: tenantA, Limit: 50}); err != nil ||
		len(page.Items) != 1 || page.Items[0].Installation.AuthorizationID != candidate.AuthorizationID {
		t.Fatalf("tenant A list=%+v err=%v", page.Items, err)
	}
	if _, err := repository.Get(t.Context(), readerB, candidate.AuthorizationID); !errors.Is(err, ErrNotFound) {
		t.Fatalf("tenant B get err=%v", err)
	}
	// A tenant cannot write the platform's head (exact-scope write path).
	pause := protectiveCommand(result.Installation, ActionDisable, "租户想暂停", "pt-pause")
	pause.TenantID, pause.Candidate.TenantID = tenantA, tenantA
	if _, err := repository.Apply(t.Context(), readerA, pause, nil); err == nil {
		t.Fatal("tenant wrote the platform-held head")
	}

	// Targets: all tenants → tenant B sees it.
	update := TargetsUpdate{AuthorizationID: candidate.AuthorizationID, ExpectedRevision: 1, IdempotencyKey: "pt-targets-1",
		RequestID: "pt-req", Targets: Targets{AllTenants: true}}
	changed, err := repository.UpdateTargets(t.Context(), platform, update)
	if err != nil || changed.Targets == nil || !changed.Targets.AllTenants || changed.Targets.Revision != 2 {
		t.Fatalf("targets all=%+v err=%v", changed.Targets, err)
	}
	if _, err := repository.Get(t.Context(), readerB, candidate.AuthorizationID); err != nil {
		t.Fatalf("tenant B after all tenants: %v", err)
	}
	if again, err := repository.UpdateTargets(t.Context(), platform, update); err != nil || again.Targets.Revision != 2 {
		t.Fatalf("targets replay=%+v err=%v", again.Targets, err)
	}
	conflicting := update
	conflicting.Targets = Targets{TenantScopeIDs: []uuid.UUID{tenantB}}
	if _, err := repository.UpdateTargets(t.Context(), platform, conflicting); !errors.Is(err, ErrIdempotencyConflict) {
		t.Fatalf("same key other body err=%v", err)
	}
	stale := conflicting
	stale.IdempotencyKey = "pt-targets-2"
	if _, err := repository.UpdateTargets(t.Context(), platform, stale); !errors.Is(err, ErrRevisionConflict) {
		t.Fatalf("stale revision err=%v", err)
	}
	unknown := stale
	unknown.ExpectedRevision, unknown.Targets = 2, Targets{TenantScopeIDs: []uuid.UUID{uuid.New()}}
	if _, err := repository.UpdateTargets(t.Context(), platform, unknown); !errors.Is(err, ErrTargetsInvalid) {
		t.Fatalf("unknown tenant err=%v", err)
	}
	only := stale
	only.ExpectedRevision = 2
	if changed, err = repository.UpdateTargets(t.Context(), platform, only); err != nil || changed.Targets.Revision != 3 {
		t.Fatalf("targets only B=%+v err=%v", changed.Targets, err)
	}
	if _, err := repository.Get(t.Context(), readerA, candidate.AuthorizationID); !errors.Is(err, ErrNotFound) {
		t.Fatalf("tenant A after removal err=%v", err)
	}
	// Tenants cannot change targets.
	if _, err := repository.UpdateTargets(t.Context(), readerB, only); err == nil {
		t.Fatal("tenant changed targets")
	}
	var audits int
	if err := pool.QueryRow(t.Context(), `SELECT count(*) FROM audit_events WHERE scope_id=$1 AND
		action='plugin_installation.targets' AND resource_id=$2`, platformScope, candidate.AuthorizationID.String()).
		Scan(&audits); err != nil || audits != 3 {
		t.Fatalf("targets audits=%d err=%v", audits, err)
	}

	// A theme carries no targets.
	theme := candidate
	theme.AuthorizationID, theme.InstallationID, theme.VerificationID = uuid.New(), uuid.New(), uuid.New()
	theme.PluginID, theme.ResourceScope, theme.EntrypointType = "acme.theme", ResourceScopePlatform, EntrypointTheme
	themeCommand := command
	themeCommand.AuthorizationID, themeCommand.InstallationID, themeCommand.Candidate = theme.AuthorizationID,
		theme.InstallationID, theme
	themeCommand.IdempotencyKey = "pt-theme-1"
	if _, err := repository.Apply(t.Context(), platform, themeCommand, exactCandidateVerifier{theme}); !errors.Is(err, ErrInvalidInput) {
		t.Fatalf("theme with targets err=%v", err)
	}
}

type exactCandidateVerifier struct{ candidate Candidate }

func (verifier exactCandidateVerifier) VerifyCandidate(_ context.Context, candidate Candidate,
	_ []SignedRuntimeFact) error {
	if candidate.ResourceScope != verifier.candidate.ResourceScope || candidate.TenantID != verifier.candidate.TenantID {
		return ErrFactDenied
	}
	return nil
}
