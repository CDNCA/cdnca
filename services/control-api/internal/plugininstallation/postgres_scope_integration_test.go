//go:build integration

package plugininstallation_test

import (
	"context"
	"crypto/sha256"
	"errors"
	"strings"
	"testing"
	"time"

	"github.com/cdnca/cdnca/services/control-api/internal/database/databasetest"
	"github.com/cdnca/cdnca/services/control-api/internal/identity"
	"github.com/cdnca/cdnca/services/control-api/internal/plugininstallation"
	"github.com/google/uuid"
)

type exactVerifier struct{ candidate plugininstallation.Candidate }

func (verifier exactVerifier) VerifyCandidate(_ context.Context, candidate plugininstallation.Candidate,
	_ []plugininstallation.SignedRuntimeFact) error {
	if candidate.ResourceScope != verifier.candidate.ResourceScope || candidate.TenantID != verifier.candidate.TenantID {
		return plugininstallation.ErrFactDenied
	}
	return nil
}

// 报告 A：平台主题的 head 写在平台 access scope 下（resource_scope=platform），确认人是持
// plugin_installations.platform.manage 的平台管理员；租户会话无论权限如何都不能读写平台 head，
// 平台会话也不能用租户权限冒充；审计事件记在平台作用域并带 resource_scope。
func TestPostgresRepositoryPlatformScopeInstallation(t *testing.T) {
	pool := databasetest.MigratedPool(t, nil)
	ctx := t.Context()
	now := time.Now().UTC().Truncate(time.Second)
	exec := func(query string, args ...any) {
		t.Helper()
		if _, err := pool.Exec(ctx, query, args...); err != nil {
			t.Fatalf("%v\n%s", err, query)
		}
	}
	member := func(scopeID uuid.UUID, permissions ...string) plugininstallation.Actor {
		userID, sessionID, roleID := uuid.New(), uuid.New(), uuid.New()
		refresh := sha256.Sum256(sessionID[:])
		exec(`INSERT INTO users(id,username,display_name,password_hash) VALUES($1,$2,'成员','unused')`,
			userID, "scope-"+strings.ReplaceAll(userID.String(), "-", "")[:10])
		exec(`INSERT INTO memberships(scope_id,user_id) VALUES($1,$2)`, scopeID, userID)
		// 非系统角色只能经 custom RBAC 事实创建（042）；夹具直接建系统角色。
		exec(`INSERT INTO roles(id,scope_id,name,description,system_role) VALUES($1,$2,$3,'test',true)`,
			roleID, scopeID, "role-"+roleID.String()[:8])
		for _, permission := range permissions {
			exec(`INSERT INTO role_permissions(role_id,permission_name) VALUES($1,$2)`, roleID, permission)
		}
		exec(`INSERT INTO role_assignments(scope_id,user_id,role_id) VALUES($1,$2,$3)`, scopeID, userID, roleID)
		exec(`INSERT INTO auth_sessions(id,family_id,user_id,scope_id,refresh_token_hash,created_at,expires_at)
			VALUES($1,$2,$3,$4,$5,$6,$7)`, sessionID, uuid.New(), userID, scopeID, refresh[:], now.Add(-time.Minute),
			now.Add(time.Hour))
		return plugininstallation.Actor{UserID: userID, SessionID: sessionID, TenantID: scopeID, RequestID: "scope-req",
			Username: "scope-admin"}
	}
	var platformScope uuid.UUID
	if err := pool.QueryRow(ctx, `SELECT id FROM access_scopes WHERE kind='platform'`).Scan(&platformScope); err != nil {
		platformScope = uuid.New()
		exec(`INSERT INTO access_scopes(id,kind) VALUES($1,'platform')`, platformScope)
	}
	tenantID := uuid.New()
	exec(`INSERT INTO tenants(id,display_name) VALUES($1,'作用域租户')`, tenantID)
	exec(`INSERT INTO access_scopes(id,kind,tenant_id) VALUES($1,'tenant',$1)`, tenantID)

	platform := member(platformScope, plugininstallation.PermissionPlatformRead, plugininstallation.PermissionPlatformManage)
	platform.ScopeKind = plugininstallation.ResourceScopePlatform
	platformWithTenantPermissions := member(platformScope, plugininstallation.PermissionRead, plugininstallation.PermissionManage)
	platformWithTenantPermissions.ScopeKind = plugininstallation.ResourceScopePlatform
	tenant := member(tenantID, plugininstallation.PermissionRead, plugininstallation.PermissionManage,
		plugininstallation.PermissionPlatformRead, plugininstallation.PermissionPlatformManage)

	repository, err := plugininstallation.NewPostgresRepository(pool, func() time.Time { return now })
	if err != nil {
		t.Fatal(err)
	}
	digest := strings.Repeat("a", 64)
	candidate := plugininstallation.Candidate{TenantID: platformScope, InstallationID: uuid.New(),
		AuthorizationID: uuid.New(), VerificationID: uuid.New(), PluginID: "acme.theme", Version: "1.0.0",
		ResourceScope: plugininstallation.ResourceScopePlatform, EntrypointType: plugininstallation.EntrypointTheme, ManifestSHA256: digest, ConfigurationSchemaSHA256: digest,
		ManifestScopes: []string{}, ApprovedScopes: []string{}, SensitiveScopes: []string{}}
	command := plugininstallation.Command{TenantID: platformScope, InstallationID: candidate.InstallationID,
		AuthorizationID: candidate.AuthorizationID, Action: plugininstallation.ActionConfirm, ExpectedRevision: 1,
		IdempotencyKey: "platform-confirm-1", RequestID: "scope-req", Candidate: candidate, Applied: true}

	if _, err := repository.Apply(ctx, platformWithTenantPermissions, command, exactVerifier{candidate}); !errors.Is(err, identity.ErrPermissionDenied) {
		t.Fatalf("tenant permissions in the platform scope err=%v", err)
	}
	result, err := repository.Apply(ctx, platform, command, exactVerifier{candidate})
	if err != nil || result.Installation.ResourceScope != plugininstallation.ResourceScopePlatform ||
		result.Installation.Status != plugininstallation.StatusEnabled {
		t.Fatalf("platform confirm result=%+v err=%v", result.Installation, err)
	}
	var storedScope string
	var audited int
	if err := pool.QueryRow(ctx, `SELECT resource_scope FROM plugin_installation_heads WHERE tenant_scope_id=$1 AND
		authorization_id=$2`, platformScope, candidate.AuthorizationID).Scan(&storedScope); err != nil || storedScope != "platform" {
		t.Fatalf("stored resource_scope=%q err=%v", storedScope, err)
	}
	if err := pool.QueryRow(ctx, `SELECT count(*) FROM audit_events WHERE scope_id=$1 AND action='plugin_installation.confirm'
		AND resource_id=$2 AND payload->>'resource_scope'='platform'`, platformScope, candidate.AuthorizationID.String()).
		Scan(&audited); err != nil || audited != 1 {
		t.Fatalf("platform confirm audit=%d err=%v", audited, err)
	}
	if _, err := repository.Get(ctx, platform, candidate.AuthorizationID); err != nil {
		t.Fatalf("platform get: %v", err)
	}
	// A tenant session (even holding the platform permission names) cannot read the platform head.
	if _, err := repository.Get(ctx, tenant, candidate.AuthorizationID); !errors.Is(err, plugininstallation.ErrNotFound) {
		t.Fatalf("tenant get of platform head err=%v", err)
	}
	// A platform candidate cannot be written into a tenant scope (head trigger P5852 / scope mismatch).
	tenantCandidate := candidate
	tenantCandidate.TenantID, tenantCandidate.AuthorizationID = tenantID, uuid.New()
	tenantCommand := command
	tenantCommand.TenantID, tenantCommand.AuthorizationID, tenantCommand.Candidate = tenantID,
		tenantCandidate.AuthorizationID, tenantCandidate
	tenantCommand.IdempotencyKey = "tenant-confirm-1"
	if _, err := repository.Apply(ctx, tenant, tenantCommand, exactVerifier{tenantCandidate}); err == nil {
		t.Fatal("a platform resource was installed into a tenant scope")
	}
	// Idempotent replay of the platform confirmation returns the same head.
	replay, err := repository.Apply(ctx, platform, command, exactVerifier{candidate})
	if err != nil || replay.Installation.Revision != result.Installation.Revision {
		t.Fatalf("replay=%+v err=%v", replay.Installation, err)
	}
}
