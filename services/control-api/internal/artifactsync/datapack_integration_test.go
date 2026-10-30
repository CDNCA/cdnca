//go:build integration

package artifactsync_test

import (
	"crypto/sha256"
	"encoding/json"
	"os"
	"testing"
	"time"

	"github.com/cdnca/cdnca/libs/entitlement/artifactcatalog"
	"github.com/cdnca/cdnca/libs/rulepack"
	"github.com/cdnca/cdnca/libs/themepack"
	"github.com/cdnca/cdnca/services/control-api/internal/rulepackcontrol"
	"github.com/google/uuid"
)

const (
	marketRulePlugin  = "io.cdnca.examples.sqli-extra"
	marketThemePlugin = "io.cdnca.examples.slate-dark"
	marketPackID      = "dev/io.cdnca.examples/sqli-extra"
)

func marketRulePack(t *testing.T, version string) []byte {
	t.Helper()
	raw, err := os.ReadFile("../../../../libs/rulepack/testdata/packs/system-sqli.json")
	if err != nil {
		t.Fatal(err)
	}
	var document map[string]any
	if err := json.Unmarshal(raw, &document); err != nil {
		t.Fatal(err)
	}
	document["pack_id"], document["layer"], document["version"] = marketPackID, "developer", version
	encoded, _ := json.Marshal(document)
	compiled, err := rulepack.Compile(encoded)
	if err != nil {
		t.Fatal(err)
	}
	return compiled.Canonical
}

func marketTheme(t *testing.T) []byte {
	t.Helper()
	var document map[string]any
	if err := json.Unmarshal(themepack.BuiltinCatalog()[0].Raw, &document); err != nil {
		t.Fatal(err)
	}
	document["id"], document["version"] = themepack.MarketThemeID(marketThemePlugin), "1.0.0"
	encoded, _ := json.Marshal(document)
	return encoded
}

// confirmInstallation records the platform administrator's confirmation of a market plugin in the
// controller's platform scope (what plugininstallation.Service.Apply writes for a resource_scope=platform
// theme or rule pack).
func (f *fixture) confirmInstallation(pluginID string) (scope uuid.UUID, authorization uuid.UUID) {
	return f.recordInstallation(f.platform, "platform", pluginID, "1.0.0", false)
}

// recordInstallation writes an enabled head and its installed receipt. In a tenant scope it creates the
// tenant; mismatchedReceipt makes the receipt snapshot name another verification than the head.
// entrypointOverride records another signed plugin type than the plugin's own.
func (f *fixture) recordInstallation(scope uuid.UUID, resourceScope, pluginID, version string,
	mismatchedReceipt bool, entrypointOverride ...string) (uuid.UUID, uuid.UUID) {
	f.t.Helper()
	authorization, session, verification := uuid.New(), uuid.New(), uuid.New()
	digest := sha256.Sum256([]byte(pluginID))
	// auth_sessions.refresh_token_hash 要 32 字节（001 CHECK）。
	sessionHash := sha256.Sum256(session[:])
	// The signed plugin type of the head: theme / rule_pack in the platform scope, external_https in a tenant.
	entrypoint := map[string]string{marketThemePlugin: "theme", marketRulePlugin: "rule_pack"}[pluginID]
	if resourceScope == "tenant" {
		entrypoint = "external_https"
	}
	if len(entrypointOverride) == 1 {
		entrypoint = entrypointOverride[0]
	}
	snapshotVerification := verification
	if mismatchedReceipt {
		snapshotVerification = uuid.New()
	}
	statements := []struct {
		sql  string
		args []any
	}{}
	if resourceScope == "tenant" {
		statements = append(statements, struct {
			sql  string
			args []any
		}{`INSERT INTO tenants(id,display_name) VALUES($1,'市场联调租户')`, []any{scope}}, struct {
			sql  string
			args []any
		}{`INSERT INTO access_scopes(id,kind,tenant_id) VALUES($1,'tenant',$1)`, []any{scope}})
	}
	statements = append(statements, []struct {
		sql  string
		args []any
	}{
		{`INSERT INTO memberships(scope_id,user_id) VALUES($1,$2) ON CONFLICT DO NOTHING`, []any{scope, f.admin}},
		{`INSERT INTO auth_sessions(id,family_id,user_id,scope_id,refresh_token_hash,created_at,expires_at)
			VALUES($1,$1,$2,$3,$4,now(),now()+interval '1 day')`, []any{session, f.admin, scope, sessionHash[:]}},
		{`INSERT INTO plugin_installation_heads(tenant_scope_id,authorization_id,installation_id,verification_id,plugin_id,
			plugin_version,manifest_sha256,configuration_schema_sha256,manifest_scopes,approved_scopes,sensitive_scopes,status,
			revision,identity_generation,lkg_verification_id,lkg_version,created_at,updated_at,resource_scope,entrypoint_type)
			VALUES($1,$2,$3,$4,$5,$6,$7,$7,'{security.rule_packs.provide}','{security.rule_packs.provide}','{}','enabled',
			1,1,$4,$6,now(),now(),$8,$9)`, []any{scope, authorization, installationID, verification, pluginID, version,
			digest[:], resourceScope, entrypoint}},
		{`INSERT INTO plugin_installation_receipts(id,tenant_scope_id,authorization_id,action,idempotency_key,request_id,
			request_digest,from_revision,to_revision,result,response_snapshot,actor_user_id,actor_session_id,occurred_at)
			VALUES($1,$2,$3,'confirm','confirm-1','confirm-1',$4,0,1,'installed',jsonb_build_object('verification_id',$7::text),
			$5,$6,now())`, []any{uuid.New(), scope, authorization, digest[:], f.admin, session, snapshotVerification.String()}},
	}...)
	for _, statement := range statements {
		if _, err := f.pool.Exec(f.t.Context(), statement.sql, statement.args...); err != nil {
			f.t.Fatalf("%s: %v", statement.sql, err)
		}
	}
	return scope, authorization
}

// Acceptance (PA-18): an authorized market rule pack and theme are downloaded
// right away; once the installation is confirmed here they become a
// developer-layer local rule pack and a downloadable market theme, never
// enabled or activated by themselves; when the license service stops serving
// them they are withdrawn (kept, not usable).
func TestMarketDataPacksMaterialize(t *testing.T) {
	f := newFixture(t)
	ctx := t.Context()
	packBytes := marketRulePack(t, "1.0.0")
	packEntry, err := artifactcatalog.DataPackEntry(artifactcatalog.KindMarketRulePack, marketRulePlugin, "1.0.0", 1, packBytes, "")
	if err != nil {
		t.Fatal(err)
	}
	themeBytes := marketTheme(t)
	themeEntry, err := artifactcatalog.DataPackEntry(artifactcatalog.KindMarketTheme, marketThemePlugin, "1.0.0", 2, themeBytes, "")
	if err != nil {
		t.Fatal(err)
	}
	f.license.Publish(packEntry, packBytes)
	f.license.Publish(themeEntry, themeBytes)
	f.sync()
	if local := f.local(); local[packEntry.ArtifactID] != 1 || local[themeEntry.ArtifactID] != 2 {
		t.Fatalf("data packs not downloaded: %v", local)
	}
	var packs, themes int
	if err := f.pool.QueryRow(ctx, `SELECT (SELECT count(*) FROM rule_packs),(SELECT count(*) FROM theme_packages)`).
		Scan(&packs, &themes); err != nil || packs != 0 || themes != 0 {
		t.Fatalf("materialized before the installation was confirmed here: packs=%d themes=%d err=%v", packs, themes, err)
	}

	f.confirmInstallation(marketRulePlugin)
	f.confirmInstallation(marketThemePlugin)
	f.sync()
	var layer, source, state string
	if err := f.pool.QueryRow(ctx, `SELECT pack.layer,artifact.source,artifact.state FROM rule_packs pack
		JOIN rule_pack_artifacts artifact ON artifact.pack_id=pack.pack_id AND artifact.version=pack.current_version
		WHERE pack.pack_id=$1`, marketPackID).Scan(&layer, &source, &state); err != nil {
		t.Fatalf("market rule pack: %v", err)
	}
	if layer != "developer" || source != rulepackcontrol.SourceMarket || state != "downloaded" {
		t.Fatalf("market rule pack layer=%s source=%s state=%s", layer, source, state)
	}
	var enabled int
	if err := f.pool.QueryRow(ctx, `SELECT count(*) FROM rule_pack_enablements`).Scan(&enabled); err != nil || enabled != 0 {
		t.Fatalf("market pack enabled by itself: %d %v", enabled, err)
	}
	var themeID, themeSource string
	if err := f.pool.QueryRow(ctx, `SELECT theme_id,source FROM theme_packages WHERE theme_id=$1`,
		themepack.MarketThemeID(marketThemePlugin)).Scan(&themeID, &themeSource); err != nil || themeSource != "market" {
		t.Fatalf("market theme: %s %s %v", themeID, themeSource, err)
	}
	var activations int
	if err := f.pool.QueryRow(ctx, `SELECT count(*) FROM theme_activations`).Scan(&activations); err != nil || activations != 0 {
		t.Fatalf("market theme activated by itself: %d %v", activations, err)
	}
	var audited int
	if err := f.pool.QueryRow(ctx, `SELECT count(*) FROM audit_events WHERE action='rule.pack.version.create'
		AND payload->>'source'='market' AND payload->>'plugin_id'=$1 AND jsonb_array_length(changes) > 0`,
		marketRulePlugin).Scan(&audited); err != nil || audited != 1 {
		t.Fatalf("market rule pack audit: %d %v", audited, err)
	}

	// The platform administrator sees it as a developer pack (ADR 0007 §5.2).
	service := rulepackcontrol.NewService(f.pool, func() time.Time { return f.now })
	platformAdmin := rulepackcontrol.Actor{UserID: f.admin, ScopeID: f.platform, ScopeKind: "platform"}
	listed := func() bool {
		view, err := service.View(ctx, platformAdmin, rulepackcontrol.LevelInput{Level: rulepack.LevelPlatform})
		if err != nil {
			t.Fatalf("platform view: %v", err)
		}
		for _, pack := range view.Packs {
			if pack.PackID == marketPackID {
				return pack.Layer == "developer"
			}
		}
		return false
	}
	if !listed() {
		t.Fatal("market pack not listed as a developer pack")
	}

	// The license service stops serving the rule pack (authorization disabled).
	f.license.Withdraw(packEntry.ArtifactID)
	f.sync()
	var status string
	if err := f.pool.QueryRow(ctx, `SELECT status FROM market_data_pack_sources WHERE artifact_id=$1`, packEntry.ArtifactID).
		Scan(&status); err != nil || status != "withdrawn" {
		t.Fatalf("withdrawn market pack status=%s err=%v", status, err)
	}
	if err := f.pool.QueryRow(ctx, `SELECT count(*) FROM rule_pack_artifacts WHERE pack_id=$1`, marketPackID).Scan(&packs); err != nil || packs != 1 {
		t.Fatalf("withdrawn pack bytes must stay: %d %v", packs, err)
	}
	if err := f.pool.QueryRow(ctx, `SELECT count(*) FROM audit_events WHERE action='plugin.artifact.withdraw' AND resource_id=$1
		AND category='plugin' AND jsonb_array_length(changes) > 0`,
		packEntry.ArtifactID).Scan(&audited); err != nil || audited != 1 {
		t.Fatalf("withdraw audit: %d %v", audited, err)
	}
	if listed() {
		t.Fatal("withdrawn market pack still listed")
	}
	// Served again (authorization re-enabled): usable again.
	f.license.Publish(packEntry, packBytes)
	f.sync()
	if !listed() {
		t.Fatal("re-served market pack not listed")
	}
}

// 报告 A：全局主题/规则包只按“平台作用域、同版本、回执与 head 同一校验”的确认记录物化；
// 任意租户的启用回执、别的版本或不匹配的回执都不能批准实例级资源。
func TestMarketDataPacksRequireMatchingPlatformConfirmation(t *testing.T) {
	f := newFixture(t)
	ctx := t.Context()
	themeBytes := marketTheme(t)
	themeEntry, err := artifactcatalog.DataPackEntry(artifactcatalog.KindMarketTheme, marketThemePlugin, "1.0.0", 1, themeBytes, "")
	if err != nil {
		t.Fatal(err)
	}
	f.license.Publish(themeEntry, themeBytes)
	themes := func() int {
		var count int
		if err := f.pool.QueryRow(ctx, `SELECT count(*) FROM theme_packages WHERE theme_id=$1`,
			themepack.MarketThemeID(marketThemePlugin)).Scan(&count); err != nil {
			t.Fatal(err)
		}
		return count
	}
	f.recordInstallation(uuid.New(), "tenant", marketThemePlugin, "1.0.0", false)
	f.sync()
	if themes() != 0 {
		t.Fatal("a tenant installation receipt approved a platform theme")
	}
	f.recordInstallation(f.platform, "platform", marketThemePlugin, "0.9.0", false)
	f.sync()
	if themes() != 0 {
		t.Fatal("a platform confirmation of another version approved the theme")
	}
	f.recordInstallation(f.platform, "platform", marketThemePlugin, "1.0.0", true)
	f.sync()
	if themes() != 0 {
		t.Fatal("a receipt of another verification approved the theme")
	}
	// fix-plugconfirm3: a confirmed rule pack head of the same plugin ID does not approve the theme.
	f.recordInstallation(f.platform, "platform", marketThemePlugin, "1.0.0", false, "rule_pack")
	f.sync()
	if themes() != 0 {
		t.Fatal("a head of another plugin type approved the theme")
	}
	f.confirmInstallation(marketThemePlugin)
	f.sync()
	if themes() != 1 {
		t.Fatal("matching platform confirmation did not materialize the theme")
	}
}
