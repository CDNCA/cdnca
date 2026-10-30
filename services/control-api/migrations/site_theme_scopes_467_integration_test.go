//go:build integration

package migrations_test

import (
	"crypto/sha256"
	"testing"
	"time"

	"github.com/google/uuid"
)

// TestSiteThemeScopes467 rolls 467 up, down and up; checks the activation
// slots (admin never takes a third-party market theme), the v1/v2 shapes of
// website theme plugins and that only the official namespace is official;
// and that down refuses once anything only 467 can hold exists (content of
// v2 plugins is in the 456 document and does not block it).
func TestSiteThemeScopes467(t *testing.T) {
	// Placeholder numbers: keep equal to migration467Version and
	// migration467PreviousVersion in site_theme_scopes_467_contract_test.go.
	const version, previous = 467, 466
	pool := migrationPoolAt(t, previous)
	ctx := t.Context()
	now := time.Now().UTC()
	platform, user := uuid.New(), uuid.New()
	mustExec(t, pool, `INSERT INTO users(id,username,display_name,password_hash) VALUES($1,'theme-467','Theme 467','unused')`, user)
	mustExec(t, pool, `INSERT INTO access_scopes(id,kind) VALUES($1,'platform')`, platform)
	mustExec(t, pool, `INSERT INTO memberships(scope_id,user_id,status) VALUES($1,$2,'active')`, platform, user)
	consoleTheme := func(id, source string) []byte {
		raw := []byte(id + source)
		digest := sha256.Sum256(raw)
		mustExec(t, pool, `INSERT INTO theme_packages(package_sha256,theme_id,version,source,package_body,css_sha256,css_body,json_sha256,json_body,downloaded_by_user_id,downloaded_at)
			VALUES($1,$2,'1.0.0',$3,$4,sha256('c'::bytea),'c'::bytea,sha256('j'::bytea),'j'::bytea,$5,now())`, digest[:], id, source, raw, user)
		return digest[:]
	}
	// Before 467: an activation for both consoles and a v1 market website theme.
	builtin := consoleTheme("official.tech", "builtin")
	mustExec(t, pool, `INSERT INTO theme_activations(revision,platform_scope_id,package_sha256,activated_by_user_id,request_id,activated_at)
		VALUES(1,$1,$2,$3,'r-1',$4)`, platform, builtin, user, now)
	siteTheme := func(id, source string, installed bool) {
		var by *uuid.UUID
		var at *time.Time
		if installed {
			by, at = &user, &now
		}
		mustExec(t, pool, `INSERT INTO site_theme_packages(theme_id,version,source,layout,name,description,tokens,seed,package_sha256,
			package_body,created_by_user_id,created_at,updated_at,installed_by_user_id,installed_at)
			VALUES($1,'1.0.0',$2,'xmf','{"zh-CN":"x"}','{}','{}','{}',sha256(convert_to($1,'UTF8')),convert_to($1,'UTF8'),$3,$4,$4,$5,$6)`, id, source, user, now, by, at)
	}
	siteTheme("official.site-jidun", "builtin", true)
	siteTheme("market.acme.v1site", "market", false)

	for _, step := range []string{"up", "down", "up"} {
		if err := migrateVersionIsolated(ctx, pool, step, version); err != nil {
			t.Fatalf("%s %d: %v", step, version, err)
		}
	}
	// A4: existing rows are described, not rewritten.
	var slot, publisher, schema string
	var scopes []string
	if err := pool.QueryRow(ctx, `SELECT slot FROM theme_activations WHERE revision=1`).Scan(&slot); err != nil || slot != "all" {
		t.Fatalf("existing activation slot %q: %v", slot, err)
	}
	for id, want := range map[string]string{"official.site-jidun": "official", "market.acme.v1site": "third_party"} {
		if err := pool.QueryRow(ctx, `SELECT schema,publisher,applies_to FROM site_theme_packages WHERE theme_id=$1`, id).
			Scan(&schema, &publisher, &scopes); err != nil || schema != "cdnca.site-theme/v1" || publisher != want || len(scopes) != 1 || scopes[0] != "site" {
			t.Fatalf("%s: %s %s %v: %v", id, schema, publisher, scopes, err)
		}
	}

	// Console slots: a third-party market theme only on the user console.
	third := consoleTheme("market.acme.blue", "market")
	official := consoleTheme("market.io.cdnca.tech", "market")
	activate := func(revision int, digest []byte, slot string) error {
		_, err := pool.Exec(ctx, `INSERT INTO theme_activations(revision,platform_scope_id,package_sha256,activated_by_user_id,request_id,activated_at,slot)
			VALUES($1,$2,$3,$4,'r',$5,$6)`, revision, platform, digest, user, now, slot)
		return err
	}
	for _, refused := range []string{"admin", "all"} {
		if err := activate(2, third, refused); sqlState(err) != "P4671" {
			t.Fatalf("third-party market theme on %s: %v, want P4671", refused, err)
		}
	}
	if err := activate(2, third, "both"); sqlState(err) != "23514" {
		t.Fatalf("unknown slot: %v, want 23514", err)
	}
	if err := activate(2, third, "user"); err != nil {
		t.Fatalf("third-party market theme on user: %v", err)
	}
	if err := activate(3, official, "admin"); err != nil {
		t.Fatalf("official market theme on admin: %v", err)
	}

	// Website theme plugins of v2.
	v2 := func(id, source string, scopes []string, entry *string, console []byte, contentSchema *string) error {
		var bundle []byte
		if entry != nil {
			sum := sha256.Sum256([]byte(id))
			bundle = sum[:]
		}
		_, err := pool.Exec(ctx, `INSERT INTO site_theme_packages(theme_id,version,source,layout,name,description,tokens,seed,package_sha256,
			package_body,created_by_user_id,created_at,updated_at,installed_by_user_id,installed_at,schema,applies_to,bundle_entry,bundle_sha256,
			console_package_sha256,content_schema)
			VALUES($1,'1.0.0',$2,NULL,'{"zh-CN":"x"}','{}','{}','{}',sha256(convert_to($1,'UTF8')),convert_to($1,'UTF8'),$3,$4,$4,NULL,NULL,'cdnca.site-theme/v2',$5,$6,$7,$8,$9)`,
			id, source, user, now, scopes, entry, bundle, console, contentSchema)
		return err
	}
	index, schemaJSON := "index.html", `[{"key":"title","type":"text","label":{"zh-CN":"标题"}}]`
	for name, bad := range map[string]func() error{
		"third party admin":        func() error { return v2("market.acme.admin", "market", []string{"admin"}, nil, official, nil) },
		"third party admin+user":   func() error { return v2("market.acme.au", "market", []string{"admin", "user"}, nil, official, nil) },
		"unordered scopes":         func() error { return v2("market.acme.su", "market", []string{"site", "user"}, &index, third, nil) },
		"site without bundle":      func() error { return v2("market.acme.nob", "market", []string{"site"}, nil, nil, nil) },
		"user without console":     func() error { return v2("market.acme.noc", "market", []string{"user"}, nil, nil, nil) },
		"bundle without site":      func() error { return v2("market.acme.bns", "market", []string{"user"}, &index, third, nil) },
		"content schema, no site":  func() error { return v2("market.acme.cs", "market", []string{"user"}, nil, third, &schemaJSON) },
		"console theme, site only": func() error { return v2("market.acme.cso", "market", []string{"site"}, &index, third, nil) },
		"upload declaring admin":   func() error { return v2("custom.admin", "upload", []string{"admin"}, nil, official, nil) },
	} {
		if err := bad(); sqlState(err) != "23514" {
			t.Fatalf("%s: %v, want 23514", name, err)
		}
	}
	if err := v2("market.acme.suite", "market", []string{"user", "site"}, &index, third, &schemaJSON); err != nil {
		t.Fatalf("third-party user+site: %v", err)
	}
	if err := v2("market.io.cdnca.suite", "market", []string{"admin", "user", "site"}, &index, official, nil); err != nil {
		t.Fatalf("official admin+user+site: %v", err)
	}
	if err := pool.QueryRow(ctx, `SELECT publisher FROM site_theme_packages WHERE theme_id='market.io.cdnca.suite'`).Scan(&publisher); err != nil || publisher != "official" {
		t.Fatalf("official namespace publisher %q: %v", publisher, err)
	}
	if err := v2("market.acme.useronly", "market", []string{"user"}, nil, third, nil); err != nil {
		t.Fatalf("third-party user: %v", err)
	}
	// The site slot takes only plugins that apply to the website.
	if _, err := pool.Exec(ctx, `INSERT INTO site_theme_activations(platform_scope_id,theme_id,revision,activated_by_user_id,activated_at)
		VALUES($1,'market.acme.useronly',1,$2,$3)`, platform, user, now); sqlState(err) != "P4672" {
		t.Fatalf("user-only plugin on the site slot: %v, want P4672", err)
	}
	mustExec(t, pool, `INSERT INTO site_theme_activations(platform_scope_id,theme_id,revision,activated_by_user_id,activated_at)
		VALUES($1,'official.site-jidun',1,$2,$3)`, platform, user, now)

	// Down refuses while anything only 467 holds exists.
	if err := migrateVersionIsolated(ctx, pool, "down", version); sqlState(err) != "P4674" {
		t.Fatalf("down with per-console activations and v2 plugins: %v, want P4674", err)
	}
	mustExec(t, pool, `ALTER TABLE theme_activations DISABLE TRIGGER theme_activations_protected_360`)
	mustExec(t, pool, `DELETE FROM theme_activations WHERE slot <> 'all'`)
	mustExec(t, pool, `ALTER TABLE theme_activations ENABLE TRIGGER theme_activations_protected_360`)
	if err := migrateVersionIsolated(ctx, pool, "down", version); sqlState(err) != "P4674" {
		t.Fatalf("down with v2 plugins: %v, want P4674", err)
	}
	mustExec(t, pool, `DELETE FROM site_theme_packages WHERE schema='cdnca.site-theme/v2'`)
	// Website content of v2 plugins lives in the 456 document and survives.
	mustExec(t, pool, `INSERT INTO control_site_content(platform_scope_id,revision,draft,updated_by_user_id,updated_at)
		VALUES($1,1,'{"schema":"cdnca.control-site/v1","plugin_content":{"market.acme.suite":{"title":"x"}}}',$2,$3)`, platform, user, now)
	// Only what 456 already had (v1 plugins, an 'all' activation): down passes and up again.
	if err := migrateVersionIsolated(ctx, pool, "down", version); err != nil {
		t.Fatalf("down with v1 data only: %v", err)
	}
	if err := migrateVersionIsolated(ctx, pool, "up", version); err != nil {
		t.Fatal(err)
	}
}
