//go:build integration

package migrations_test

import (
	"testing"
	"time"

	"github.com/google/uuid"
)

// TestControlSiteContent456 rolls 456 up, down and up, checks the image
// table rejects a body whose digest does not match, and that down refuses
// once the website is published or holds an uploaded image.
func TestControlSiteContent456(t *testing.T) {
	const version = 456
	pool := migrationPoolAt(t, version-1)
	ctx := t.Context()
	for _, step := range []string{"up", "down", "up"} {
		if err := migrateVersionIsolated(ctx, pool, step, version); err != nil {
			t.Fatalf("%s %d: %v", step, version, err)
		}
	}
	platform, user := uuid.New(), uuid.New()
	now := time.Now().UTC()
	mustExec(t, pool, `INSERT INTO access_scopes(id,kind) VALUES($1,'platform')`, platform)
	if _, err := pool.Exec(ctx, `INSERT INTO control_site_assets(asset_sha256,mime_type,body,created_by_user_id,created_at)
		VALUES(decode(repeat('00',32),'hex'),'image/png','x',$1,$2)`, user, now); err == nil {
		t.Fatal("an image whose digest does not match its body was stored")
	}
	mustExec(t, pool, `INSERT INTO control_site_content(platform_scope_id,revision,draft,updated_by_user_id,updated_at)
		VALUES($1,1,'{"schema":"cdnca.control-site/v1"}',$2,$3)`, platform, user, now)
	// An unpublished draft alone does not block the rollback.
	if err := migrateVersionIsolated(ctx, pool, "down", version); err != nil {
		t.Fatalf("down with a draft only: %v", err)
	}
	if err := migrateVersionIsolated(ctx, pool, "up", version); err != nil {
		t.Fatal(err)
	}
	mustExec(t, pool, `INSERT INTO control_site_content(platform_scope_id,revision,draft,published,published_revision,updated_by_user_id,updated_at,published_by_user_id,published_at)
		VALUES($1,1,'{}','{}',1,$2,$3,$2,$3)`, platform, user, now)
	if err := migrateVersionIsolated(ctx, pool, "down", version); sqlState(err) != "P4562" {
		t.Fatalf("down with a published website: %v, want P4562", err)
	}
	mustExec(t, pool, `DELETE FROM control_site_content`)
	mustExec(t, pool, `INSERT INTO control_site_assets(asset_sha256,mime_type,body,created_by_user_id,created_at)
		VALUES(sha256('<svg/>'::bytea),'image/svg+xml','<svg/>'::bytea,$1,$2)`, user, now)
	if err := migrateVersionIsolated(ctx, pool, "down", version); sqlState(err) != "P4562" {
		t.Fatalf("down with an uploaded image: %v, want P4562", err)
	}
	mustExec(t, pool, `DELETE FROM control_site_assets`)

	// Website theme plugins: the source follows the id prefix, only a
	// market plugin may be stored without being installed, and an active
	// plugin cannot be deleted.
	insertTheme := func(id, source string, installed bool) error {
		var by *uuid.UUID
		var at *time.Time
		if installed {
			by, at = &user, &now
		}
		_, err := pool.Exec(ctx, `INSERT INTO site_theme_packages(theme_id,version,source,layout,name,description,tokens,seed,package_sha256,
			package_body,created_by_user_id,created_at,updated_at,installed_by_user_id,installed_at)
			VALUES($1,'1.0.0',$2,'xmf','{"zh-CN":"x"}','{}','{}','{}',sha256('{}'::bytea),'{}'::bytea,$3,$4,$4,$5,$6)`, id, source, user, now, by, at)
		return err
	}
	for _, bad := range []struct {
		id, source string
		installed  bool
	}{{"custom.a", "builtin", true}, {"official.site-a", "upload", true}, {"custom.a", "upload", false}, {"evil", "upload", true}} {
		if err := insertTheme(bad.id, bad.source, bad.installed); err == nil {
			t.Fatalf("stored %+v", bad)
		}
	}
	if err := insertTheme("official.site-jidun", "builtin", true); err != nil {
		t.Fatal(err)
	}
	if err := insertTheme("market.acme.blue", "market", false); err != nil {
		t.Fatal(err)
	}
	mustExec(t, pool, `INSERT INTO site_theme_activations(platform_scope_id,theme_id,revision,activated_by_user_id,activated_at) VALUES($1,'official.site-jidun',1,$2,$3)`, platform, user, now)
	if _, err := pool.Exec(ctx, `DELETE FROM site_theme_packages WHERE theme_id='official.site-jidun'`); err == nil {
		t.Fatal("the active website theme was deleted")
	}
	if err := migrateVersionIsolated(ctx, pool, "down", version); sqlState(err) != "P4562" {
		t.Fatalf("down with a market website theme: %v, want P4562", err)
	}
	mustExec(t, pool, `DELETE FROM site_theme_packages WHERE source='market'`)
	// Only built-in plugins (which come back from the binary): down passes.
	if err := migrateVersionIsolated(ctx, pool, "down", version); err != nil {
		t.Fatalf("down with built-in plugins only: %v", err)
	}
	if err := migrateVersionIsolated(ctx, pool, "up", version); err != nil {
		t.Fatal(err)
	}
}
