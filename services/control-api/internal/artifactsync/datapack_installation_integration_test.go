//go:build integration

package artifactsync_test

import (
	"context"
	"crypto/sha256"
	"errors"
	"strings"
	"testing"
	"time"

	"github.com/cdnca/cdnca/libs/entitlement/artifactcatalog"
	"github.com/cdnca/cdnca/libs/themepack"
	"github.com/cdnca/cdnca/services/control-api/internal/identity"
	"github.com/cdnca/cdnca/services/control-api/internal/plugininstallation"
	"github.com/google/uuid"
)

// fix-plugverify A（DEV-PLUG-01/02）：迁移/恢复后数据库保留旧安装 B 的平台确认（head + receipt），
// 当前已验签目录的安装目标是 A、插件与版本相同。旧 B 的确认不能批准 A 的主题：物化 0 份，
// 旧确认保留不动，等当前主控管理员重新确认。
func TestMarketDataPacksIgnoreConfirmationOfAnotherInstallation(t *testing.T) {
	f := newFixture(t)
	currentID := installationID
	oldID := uuid.MustParse("00000000-0000-4000-8000-0000000000b2")
	content := marketTheme(t)
	entry, err := artifactcatalog.DataPackEntry(artifactcatalog.KindMarketTheme, marketThemePlugin, "1.0.0", 1, content, "")
	if err != nil {
		t.Fatal(err)
	}
	f.license.Publish(entry, content)
	func() {
		installationID = oldID
		defer func() { installationID = currentID }()
		f.confirmInstallation(marketThemePlugin)
	}()
	f.sync()
	var signedID, confirmedID string
	if err := f.pool.QueryRow(t.Context(), `SELECT convert_from(signed_document,'UTF8')::jsonb->'envelope'->>'installation_id'
		FROM artifact_catalog_state`).Scan(&signedID); err != nil {
		t.Fatal(err)
	}
	if err := f.pool.QueryRow(t.Context(), `SELECT installation_id::text FROM plugin_installation_heads WHERE plugin_id=$1`,
		marketThemePlugin).Scan(&confirmedID); err != nil {
		t.Fatal(err)
	}
	if signedID != currentID.String() || confirmedID != oldID.String() {
		t.Fatalf("fixture identities signed=%s confirmed=%s", signedID, confirmedID)
	}
	if themes := f.count(`SELECT count(*) FROM theme_packages WHERE theme_id=$1`, themepack.MarketThemeID(marketThemePlugin)); themes != 0 {
		t.Fatalf("old installation's confirmation approved the current installation's theme: themes=%d", themes)
	}
	// 旧确认原样保留（不删、不改写）。
	if f.count(`SELECT count(*) FROM plugin_installation_receipts WHERE tenant_scope_id=$1`, f.platform) != 1 ||
		f.count(`SELECT count(*) FROM plugin_installation_heads WHERE installation_id=$1 AND status='enabled'`, oldID) != 1 {
		t.Fatal("old installation confirmation was rewritten")
	}
	// 当前安装 A 的管理员确认后才物化。
	f.confirmInstallation(marketThemePlugin)
	f.sync()
	if themes := f.count(`SELECT count(*) FROM theme_packages WHERE theme_id=$1`, themepack.MarketThemeID(marketThemePlugin)); themes != 1 {
		t.Fatalf("current installation's confirmation did not materialize the theme: themes=%d", themes)
	}
}

type platformOnlyVerifier struct{}

func (platformOnlyVerifier) VerifyCandidate(_ context.Context, candidate plugininstallation.Candidate,
	_ []plugininstallation.SignedRuntimeFact) error {
	if candidate.ResourceScope != plugininstallation.ResourceScopePlatform {
		return plugininstallation.ErrFactDenied
	}
	return nil
}

// fix-plugverify A 正控：合法 platform_owner 经真实 Repository.Apply 确认后，签名目录同步即物化
// （下载人 = 回执操作人），主题不会被自动启用；普通 tenant_owner 读不到平台确认。
func TestMarketThemeMaterializesAfterPlatformOwnerConfirmation(t *testing.T) {
	f := newFixture(t)
	exec := func(query string, args ...any) {
		t.Helper()
		if _, err := f.pool.Exec(t.Context(), query, args...); err != nil {
			t.Fatalf("%v\n%s", err, query)
		}
	}
	role, session := uuid.New(), uuid.New()
	exec(`INSERT INTO memberships(scope_id,user_id) VALUES($1,$2) ON CONFLICT DO NOTHING`, f.platform, f.admin)
	exec(`INSERT INTO roles(id,scope_id,name,description,system_role) VALUES($1,$2,'platform_owner','fixture platform owner',true)`, role, f.platform)
	exec(`INSERT INTO role_permissions(role_id,permission_name) SELECT $1,name FROM permissions WHERE name <> 'jobs.manage' ON CONFLICT DO NOTHING`, role)
	exec(`INSERT INTO role_assignments(scope_id,user_id,role_id) VALUES($1,$2,$3)`, f.platform, f.admin, role)
	refresh := sha256.Sum256(session[:])
	exec(`INSERT INTO auth_sessions(id,family_id,user_id,scope_id,refresh_token_hash,created_at,expires_at)
		VALUES($1,$1,$2,$3,$4,$5,$6)`, session, f.admin, f.platform, refresh[:], f.now.Add(-time.Minute), f.now.Add(time.Hour))
	actor := plugininstallation.Actor{TenantID: f.platform, ScopeKind: "platform", UserID: f.admin, SessionID: session,
		RequestID: "platform-confirm"}
	repository, err := plugininstallation.NewPostgresRepository(f.pool, func() time.Time { return f.now })
	if err != nil {
		t.Fatal(err)
	}
	content := marketTheme(t)
	entry, err := artifactcatalog.DataPackEntry(artifactcatalog.KindMarketTheme, marketThemePlugin, "1.0.0", 1, content, "")
	if err != nil {
		t.Fatal(err)
	}
	f.license.Publish(entry, content)
	f.sync()
	if f.count(`SELECT count(*) FROM theme_packages`) != 0 {
		t.Fatal("materialized before the administrator confirmed")
	}
	candidate := plugininstallation.Candidate{TenantID: f.platform, ResourceScope: plugininstallation.ResourceScopePlatform,
		EntrypointType: plugininstallation.EntrypointTheme, InstallationID: installationID, AuthorizationID: uuid.New(),
		VerificationID: uuid.New(), PluginID: marketThemePlugin, Version: "1.0.0",
		ManifestSHA256: strings.Repeat("a", 64), ConfigurationSchemaSHA256: strings.Repeat("b", 64),
		ManifestScopes: []string{}, ApprovedScopes: []string{}, SensitiveScopes: []string{}}
	command := plugininstallation.Command{TenantID: f.platform, InstallationID: installationID,
		AuthorizationID: candidate.AuthorizationID, Action: plugininstallation.ActionConfirm, Candidate: candidate,
		Applied: true, ExpectedRevision: 1, IdempotencyKey: "platform-confirm", RequestID: actor.RequestID}
	result, err := repository.Apply(t.Context(), actor, command, platformOnlyVerifier{})
	if err != nil || result.Installation.Status != plugininstallation.StatusEnabled {
		t.Fatalf("confirmation status=%s err=%v", result.Installation.Status, err)
	}
	f.sync()
	var downloader uuid.UUID
	if err := f.pool.QueryRow(t.Context(), `SELECT downloaded_by_user_id FROM theme_packages WHERE theme_id=$1`,
		themepack.MarketThemeID(marketThemePlugin)).Scan(&downloader); err != nil || downloader != f.admin {
		t.Fatalf("theme downloader=%s want receipt actor=%s err=%v", downloader, f.admin, err)
	}
	if f.count(`SELECT count(*) FROM theme_activations`) != 0 {
		t.Fatal("confirmation activated the theme by itself")
	}
	tenant, tenantUser, tenantRole, tenantSession := uuid.New(), uuid.New(), uuid.New(), uuid.New()
	exec(`INSERT INTO tenants(id,display_name) VALUES($1,'物化租户')`, tenant)
	exec(`INSERT INTO access_scopes(id,kind,tenant_id) VALUES($1,'tenant',$1)`, tenant)
	exec(`INSERT INTO users(id,username,display_name,password_hash) VALUES($1,$2,'物化租户','unused')`, tenantUser, "t-"+tenantUser.String())
	exec(`INSERT INTO memberships(scope_id,user_id) VALUES($1,$2)`, tenant, tenantUser)
	exec(`INSERT INTO roles(id,scope_id,name,description,system_role) VALUES($1,$2,'tenant_owner','tenant owner',true)`, tenantRole, tenant)
	exec(`INSERT INTO role_assignments(scope_id,user_id,role_id) VALUES($1,$2,$3)`, tenant, tenantUser, tenantRole)
	tenantRefresh := sha256.Sum256(tenantSession[:])
	exec(`INSERT INTO auth_sessions(id,family_id,user_id,scope_id,refresh_token_hash,created_at,expires_at)
		VALUES($1,$1,$2,$3,$4,$5,$6)`, tenantSession, tenantUser, tenant, tenantRefresh[:], f.now.Add(-time.Minute), f.now.Add(time.Hour))
	tenantActor := plugininstallation.Actor{TenantID: tenant, ScopeKind: "tenant", UserID: tenantUser, SessionID: tenantSession,
		RequestID: "tenant-read"}
	if _, err := repository.Get(t.Context(), tenantActor, candidate.AuthorizationID); !errors.Is(err, identity.ErrPermissionDenied) &&
		!errors.Is(err, plugininstallation.ErrNotFound) {
		t.Fatalf("tenant read the platform confirmation err=%v", err)
	}
}
