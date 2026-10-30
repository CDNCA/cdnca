//go:build integration

package rulepackcontrol

import (
	"os"
	"path/filepath"
	"testing"

	"github.com/cdnca/cdnca/libs/rulepack"
	"github.com/google/uuid"
)

// The official PHP virtual patch pack is on by default.
// With the control plane's own platform row (state enabled, allow_lower, no
// user: migration 454) every site gets it mounted without its owner
// publishing; a site that switches it off loses it on the next recompute; a
// second recompute with nothing changed writes nothing (no source revision
// advance for the system republication to explain).
func TestDefaultOnPackRecomputesEverySite(t *testing.T) {
	w := newWorld(t)
	ctx := t.Context()
	content, err := os.ReadFile(filepath.Join("..", "..", "..", "..", "scripts", "security", "datasets", "rulepacks",
		"vpatch", "system-waf-php-vpatch.json"))
	if err != nil {
		t.Fatal(err)
	}
	if _, err := w.service.Import(ctx, w.platform, content); err != nil {
		t.Fatal(err)
	}
	if !DefaultOn(rulepack.LayerSystem, "") || DefaultOn(rulepack.LayerSystem, "module.waf.pro") || DefaultOn(rulepack.LayerUser, "") {
		t.Fatal("default-on is every official free system pack, and only those")
	}
	mustExec(t, w.pool, `INSERT INTO rule_pack_enablements(id,level,level_object_id,pack_id,rule_id,state,allow_lower,
		priority,params,updated_by_user_id,updated_at) VALUES($1,'platform',NULL,'system/waf-php-vpatch',NULL,'enabled',true,
		NULL,NULL,NULL,now())`, uuid.New())
	// The 419 shape (inherit only) is gone; other system rows stay restricted.
	if _, err := w.pool.Exec(ctx, `INSERT INTO rule_pack_enablements(id,level,level_object_id,pack_id,rule_id,state,allow_lower,
		updated_by_user_id,updated_at) VALUES($1,'platform',NULL,'system/x-other',NULL,'disabled',true,NULL,now())`, uuid.New()); err == nil {
		t.Fatal("a system row disabling a pack was accepted")
	}
	// Scope A has published before (revision 7); scope B never did.
	mustExec(t, w.pool, `UPDATE edge_configuration_scopes SET source_revision=7 WHERE scope_id=$1`, w.tenantA.ScopeID)
	mustExec(t, w.pool, `DELETE FROM edge_configuration_scopes WHERE scope_id=$1`, w.tenantB.ScopeID)

	recompute := func(all bool) []DefaultOnScope {
		t.Helper()
		var scopes []DefaultOnScope
		tx, err := w.pool.Begin(ctx)
		if err != nil {
			t.Fatal(err)
		}
		defer tx.Rollback(ctx)
		if enabled, err := DefaultOnPackEnabledTx(ctx, tx); err != nil || !enabled {
			t.Fatalf("default-on enabled = %v, %v", enabled, err)
		}
		sites, err := DefaultOnSitesTx(ctx, tx, all)
		if err != nil {
			t.Fatal(err)
		}
		if scopes, err = w.service.RecomputeDefaultOnMountsTx(ctx, tx, sites, "test-default-on"); err != nil {
			t.Fatal(err)
		}
		if err := tx.Commit(ctx); err != nil {
			t.Fatal(err)
		}
		return scopes
	}
	scopes := recompute(true)
	if len(scopes) != 2 || scopes[0].ScopeID == scopes[1].ScopeID {
		t.Fatalf("changed scopes = %+v", scopes)
	}
	for _, scope := range scopes {
		want := int64(0)
		if scope.ScopeID == w.tenantA.ScopeID {
			want = 7
		}
		if scope.FromRevision != want {
			t.Fatalf("scope %s from revision %d, want %d", scope.ScopeID, scope.FromRevision, want)
		}
	}
	for _, siteID := range []uuid.UUID{w.siteA1, w.siteA2, w.siteB1} {
		published, err := loadPublished(ctx, w.pool, siteID)
		if err != nil || published == nil || published.PublishedBy != nil || len(published.Security.Mounts) != 1 ||
			published.Security.Mounts[0].PackID != "system/waf-php-vpatch" {
			t.Fatalf("site %s published %+v, %v", siteID, published, err)
		}
	}
	var audits int
	if err := w.pool.QueryRow(ctx, `SELECT count(*) FROM audit_events WHERE action=$1 AND actor_user_id IS NULL
		AND payload->>'reason'='default_on_pack'`, AuditSitePublish).Scan(&audits); err != nil || audits != 3 {
		t.Fatalf("system site publish audits = %d, %v", audits, err)
	}
	// Nothing changed: nothing written.
	if again := recompute(true); len(again) != 0 {
		t.Fatalf("second recompute changed %+v", again)
	}
	// Site a2 switches the pack off (allowed: the platform row allows lower).
	if err := w.put(t, w.tenantA, with(ref(rulepack.LevelSite, w.siteA2), "system/waf-php-vpatch", rulepack.StateDisabled, false)); err != nil {
		t.Fatal(err)
	}
	if scopes := recompute(true); len(scopes) != 1 || scopes[0].ScopeID != w.tenantA.ScopeID {
		t.Fatalf("switch-off scopes = %+v", scopes)
	}
	if published, _ := loadPublished(ctx, w.pool, w.siteA2); published == nil || len(published.Security.Mounts) != 0 {
		t.Fatalf("site a2 still mounts %+v", published)
	}
	// A new site is picked up by the incremental run; sites with mounts are not read again.
	newSite := insertSite(t, w.pool, w.tenantB, "b2.example.test", 4)
	if scopes := recompute(false); len(scopes) != 1 || scopes[0].ScopeID != w.tenantB.ScopeID {
		t.Fatalf("incremental scopes = %+v", scopes)
	}
	if published, _ := loadPublished(ctx, w.pool, newSite); published == nil || len(published.Security.Mounts) != 1 {
		t.Fatalf("new site published %+v", published)
	}
	// The owner sees the mounts as up to date (publishing would change nothing).
	view, err := w.service.Site(ctx, w.tenantB, newSite)
	if err != nil || !view.UpToDate {
		t.Fatalf("site view up_to_date=%v, %v", view.UpToDate, err)
	}
	// each level's "inherit" shows what it follows. Tenant A's
	// account follows the platform (on); site a2, switched off, still
	// follows its account (on).
	for _, item := range []struct {
		level LevelInput
		want  bool
	}{
		{LevelInput{Level: rulepack.LevelTenant, ObjectID: &w.tenantA.ScopeID}, true},
		{LevelInput{Level: rulepack.LevelSite, ObjectID: &w.siteA2}, true},
	} {
		levelView, err := w.service.View(ctx, w.tenantA, item.level)
		if err != nil || len(levelView.Packs) != 1 || levelView.Packs[0].Effect == nil ||
			levelView.Packs[0].Effect.Inherited != item.want {
			t.Fatalf("%s view = %+v, %v", item.level.Level, levelView.Packs, err)
		}
	}
	if siteView, _ := w.service.View(ctx, w.tenantA, LevelInput{Level: rulepack.LevelSite, ObjectID: &w.siteA2}); siteView.Packs[0].Effect.Enabled {
		t.Fatal("site a2 switched the pack off but it shows enabled")
	}
}
