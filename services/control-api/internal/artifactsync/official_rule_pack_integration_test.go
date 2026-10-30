//go:build integration

package artifactsync_test

import (
	"os"
	"path/filepath"
	"testing"

	"github.com/cdnca/cdnca/libs/entitlement/artifactcatalog"
	"github.com/cdnca/cdnca/libs/rulepack"
	"github.com/google/uuid"
	"github.com/jackc/pgx/v5"
)

func plainPackEntry(t *testing.T, content []byte, feature string) (artifactcatalog.Entry, []byte) {
	t.Helper()
	compiled, err := rulepack.Compile(content)
	if err != nil {
		t.Fatal(err)
	}
	entry := artifactcatalog.Entry{ArtifactID: artifactcatalog.RulePackArtifactID(compiled.Pack.PackID), Kind: artifactcatalog.KindRulePack,
		MediaType: artifactcatalog.MediaTypeRulePack, Encryption: artifactcatalog.EncryptionNone, Resident: true,
		RequiresFeature: feature, Revision: 1, Version: compiled.Pack.Version, SHA256: compiled.SHA256,
		Size: int64(len(compiled.Canonical)), LicenseSPDX: compiled.Pack.LicenseSPDX}
	if err := artifactcatalog.ValidateEntry(entry); err != nil {
		t.Fatal(err)
	}
	return entry, compiled.Canonical
}

// An official free system pack (license migration 097) is materialized with
// the control plane's own platform row (enabled since migration 544,
// allow_lower, no user), audited once; a paid system pack (requires a
// feature) stays locked.
func TestOfficialFreeRulePackOpensToLowerLevels(t *testing.T) {
	f := newFixture(t)
	content, err := os.ReadFile(filepath.Join("..", "..", "..", "..", "scripts", "security", "datasets", "rulepacks",
		"system-bot-scanner-ua.json"))
	if err != nil {
		t.Fatal(err)
	}
	entry, canonical := plainPackEntry(t, content, "")
	f.license.Publish(entry, canonical)
	paid, paidContent := plainPackEntry(t, []byte(`{"schema":"cdnca.rule-pack/v1","pack_id":"system/paid-x","version":"1.0.0",
		"layer":"system","engine":"waf_v2","engine_min_version":1,"name":"paid","description":"","params_schema":{},"exports":[],
		"rules":[{"id":"r","name":"r","waf":{"match":{"path":{"kind":"prefix","value":"/paid"}},"action":"log","flow":"continue"}}],
		"defaults":{}}`), "module.waf.pro")
	f.grants.features["module.waf.pro"] = true
	f.license.Publish(paid, paidContent)
	f.sync()
	if got := f.count(`SELECT count(*) FROM rule_pack_artifacts WHERE pack_id IN ('system/bot-scanner-ua','system/paid-x')`); got != 2 {
		t.Fatalf("materialized %d packs", got)
	}
	if got := f.count(`SELECT count(*) FROM rule_pack_enablements WHERE level='platform' AND pack_id='system/bot-scanner-ua'
		AND state='enabled' AND allow_lower AND updated_by_user_id IS NULL`); got != 1 {
		t.Fatalf("official pack platform rows = %d", got)
	}
	if got := f.count(`SELECT count(*) FROM rule_pack_enablements WHERE pack_id='system/paid-x'`); got != 0 {
		t.Fatalf("paid pack opened: %d rows", got)
	}
	if f.audits("rule.pack.override.put", "success") != 1 {
		t.Fatal("opening the official pack not audited")
	}
	// A later sync (or a newer version) never rewrites the row.
	f.sync()
	if f.audits("rule.pack.override.put", "success") != 1 {
		t.Fatal("official pack opened twice")
	}
}

// The official PHP virtual patch pack arrives enabled at
// platform level (the control plane's own row, migration 454); the same
// materialization mounts it on every live tenant site and asks for the
// republication of their scopes. The next sync with nothing new changes
// nothing.
func TestDefaultOnOfficialPackMountsEverySite(t *testing.T) {
	f := newFixture(t)
	ctx := t.Context()
	tenant, owner := uuid.New(), uuid.New()
	scope := uuid.New()
	site := uuid.New()
	for _, statement := range []string{
		`INSERT INTO tenants(id,display_name) VALUES('` + tenant.String() + `','vpatch')`,
		`INSERT INTO access_scopes(id,kind,tenant_id) VALUES('` + scope.String() + `','tenant','` + tenant.String() + `')`,
		`INSERT INTO users(id,username,display_name,password_hash) VALUES('` + owner.String() + `','vpatch-owner','o','unused')`,
		`INSERT INTO memberships(scope_id,user_id) VALUES('` + scope.String() + `','` + owner.String() + `')`,
	} {
		f.replica(t, statement)
	}
	err := pgx.BeginFunc(ctx, f.pool, func(tx pgx.Tx) error {
		for _, statement := range []struct {
			query string
			args  []any
		}{
			{`INSERT INTO sites(id,scope_id,owner_user_id,domain,origins,origin_hosts,created_by_user_id,updated_by_user_id,
				display_id) VALUES($1,$2,$3,'vpatch.example.test',ARRAY['origin.example.test:80'],ARRAY['origin.example.test'],$3,$3,901)`,
				[]any{site, scope, owner}},
			{`INSERT INTO site_origin_pools(site_id) VALUES($1)`, []any{site}},
			{`INSERT INTO site_origins(site_id,position,host,port) VALUES($1,1,'origin.example.test',80)`, []any{site}},
		} {
			if _, err := tx.Exec(ctx, statement.query, statement.args...); err != nil {
				return err
			}
		}
		return nil
	})
	if err != nil {
		t.Fatal(err)
	}
	content, err := os.ReadFile(filepath.Join("..", "..", "..", "..", "scripts", "security", "datasets", "rulepacks",
		"vpatch", "system-waf-php-vpatch.json"))
	if err != nil {
		t.Fatal(err)
	}
	entry, canonical := plainPackEntry(t, content, "")
	f.license.Publish(entry, canonical)
	f.sync()
	if got := f.count(`SELECT count(*) FROM rule_pack_enablements WHERE level='platform' AND pack_id='system/waf-php-vpatch'
		AND state='enabled' AND allow_lower AND updated_by_user_id IS NULL`); got != 1 {
		t.Fatalf("default-on platform rows = %d", got)
	}
	if got := f.count(`SELECT count(*) FROM rule_pack_site_mount_artifacts WHERE site_id=$1 AND pack_id='system/waf-php-vpatch'`,
		site); got != 1 {
		t.Fatalf("site mounts of the pack = %d", got)
	}
	if got := f.count(`SELECT count(*) FROM site_security_mounts WHERE site_id=$1 AND published_by_user_id IS NULL`, site); got != 1 {
		t.Fatalf("system published mounts = %d", got)
	}
	if len(f.recorder.defaultOn) != 1 || len(f.recorder.defaultOn[0]) != 1 || f.recorder.defaultOn[0][0].ScopeID != scope {
		t.Fatalf("republications = %+v", f.recorder.defaultOn)
	}
	if mounted, err := f.store.MountedRulePacks(ctx); err != nil || len(mounted) != 1 || mounted[0].SHA256 != entry.SHA256 {
		t.Fatalf("node items = %+v, %v", mounted, err)
	}
	f.sync()
	if len(f.recorder.defaultOn) != 1 {
		t.Fatalf("second sync republished %+v", f.recorder.defaultOn)
	}
}

// Migration 544: every official free pack is on by
// default, including for a site that already published its mounts. A pack
// that arrived inherit before 544 is turned on by the migration, which
// clears the materialization mark; the next sync re-materializes it and
// recomputes every site, so the published site mounts both packs.
func TestOfficialFreePacksDefaultOnAfterMigration544(t *testing.T) {
	f := newFixture(t)
	ctx := t.Context()
	tenant, owner, scope, site := uuid.New(), uuid.New(), uuid.New(), uuid.New()
	for _, statement := range []string{
		`INSERT INTO tenants(id,display_name) VALUES('` + tenant.String() + `','u544')`,
		`INSERT INTO access_scopes(id,kind,tenant_id) VALUES('` + scope.String() + `','tenant','` + tenant.String() + `')`,
		`INSERT INTO users(id,username,display_name,password_hash) VALUES('` + owner.String() + `','u544-owner','o','unused')`,
		`INSERT INTO memberships(scope_id,user_id) VALUES('` + scope.String() + `','` + owner.String() + `')`,
	} {
		f.replica(t, statement)
	}
	err := pgx.BeginFunc(ctx, f.pool, func(tx pgx.Tx) error {
		for _, statement := range []struct {
			query string
			args  []any
		}{
			{`INSERT INTO sites(id,scope_id,owner_user_id,domain,origins,origin_hosts,created_by_user_id,updated_by_user_id,
				display_id) VALUES($1,$2,$3,'u544.example.test',ARRAY['origin.example.test:80'],ARRAY['origin.example.test'],$3,$3,902)`,
				[]any{site, scope, owner}},
			{`INSERT INTO site_origin_pools(site_id) VALUES($1)`, []any{site}},
			{`INSERT INTO site_origins(site_id,position,host,port) VALUES($1,1,'origin.example.test',80)`, []any{site}},
		} {
			if _, err := tx.Exec(ctx, statement.query, statement.args...); err != nil {
				return err
			}
		}
		return nil
	})
	if err != nil {
		t.Fatal(err)
	}
	read := func(parts ...string) []byte {
		t.Helper()
		content, err := os.ReadFile(filepath.Join(append([]string{"..", "..", "..", "..", "scripts", "security", "datasets", "rulepacks"}, parts...)...))
		if err != nil {
			t.Fatal(err)
		}
		return content
	}
	mounts := func() string {
		t.Helper()
		var ids string
		if err := f.pool.QueryRow(ctx, `SELECT coalesce(string_agg(pack_id, ',' ORDER BY pack_id), '') FROM rule_pack_site_mount_artifacts
			WHERE site_id=$1`, site).Scan(&ids); err != nil {
			t.Fatal(err)
		}
		return ids
	}
	// A newly arriving official free pack is enabled at once and the site mounts it.
	vpatch, vpatchContent := plainPackEntry(t, read("vpatch", "system-waf-php-vpatch.json"), "")
	f.license.Publish(vpatch, vpatchContent)
	scanner, scannerContent := plainPackEntry(t, read("system-bot-scanner-ua.json"), "")
	f.license.Publish(scanner, scannerContent)
	f.sync()
	if got := mounts(); got != "system/bot-scanner-ua,system/waf-php-vpatch" {
		t.Fatalf("site mounts after arrival = %q", got)
	}
	// The state before 544: the scanner pack's row was inherit and the site
	// published with only the virtual patches (a full recompute drops it).
	clearMarks := `UPDATE local_artifacts local SET materialized_sha256=NULL, updated_at=CURRENT_TIMESTAMP
		FROM artifact_catalog_entries entry WHERE entry.artifact_id=local.artifact_id AND entry.kind='rule_pack' AND
		entry.requires_feature='' AND local.materialized_sha256 IS NOT NULL`
	f.replica(t, `UPDATE rule_pack_enablements SET state='inherit' WHERE level='platform' AND pack_id='system/bot-scanner-ua'`)
	f.replica(t, clearMarks)
	f.sync()
	if got := mounts(); got != "system/waf-php-vpatch" {
		t.Fatalf("site mounts before 544 = %q", got)
	}
	// Migration 544's statements (544_official_rule_packs_enabled.up.sql).
	f.replica(t, `UPDATE rule_pack_enablements enablement SET state='enabled', updated_at=CURRENT_TIMESTAMP
		FROM rule_packs pack WHERE pack.pack_id=enablement.pack_id AND pack.layer='system' AND enablement.level='platform' AND
		enablement.rule_id IS NULL AND enablement.updated_by_user_id IS NULL AND enablement.state='inherit'`)
	f.replica(t, clearMarks)
	f.sync()
	if got := mounts(); got != "system/bot-scanner-ua,system/waf-php-vpatch" {
		t.Fatalf("site mounts after 544 = %q", got)
	}
}
