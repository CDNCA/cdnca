//go:build integration

package rulepackcontrol

import (
	"encoding/json"
	"errors"
	"os"
	"path/filepath"
	"testing"

	"github.com/cdnca/cdnca/libs/rulepack"
	"github.com/google/uuid"
)

// An official free system pack (license migration 097) arrives from the
// catalog with the control plane's own platform row (inherit, allow_lower;
// artifactsync.openOfficialPack, migration 418): no site runs it until a
// site owner enables it, the owner can switch its action from log to block,
// and the platform administrator can still lock it.
func TestOfficialPackSiteEnableAndAction(t *testing.T) {
	w := newWorld(t)
	ctx := t.Context()
	content, err := os.ReadFile(filepath.Join("..", "..", "..", "..", "scripts", "security", "datasets", "rulepacks",
		"system-bot-bad-ua.json"))
	if err != nil {
		t.Fatal(err)
	}
	compiled, err := rulepack.Compile(content)
	if err != nil {
		t.Fatal(err)
	}
	packID := compiled.Pack.PackID
	mustExec(t, w.pool, `INSERT INTO rule_packs(pack_id,layer,owner_scope_id,current_version,update_policy,created_by_user_id,
		updated_by_user_id,created_at,updated_at) VALUES($1,'system',NULL,NULL,'auto',NULL,NULL,now(),now())`, packID)
	mustExec(t, w.pool, `INSERT INTO rule_pack_artifacts(pack_id,version,engine,engine_min_version,name,sha256,size_bytes,content,
		source,state,downloaded_at,created_by_user_id,created_at) VALUES($1,$2,'waf_v2',1,$3,$4,$5,$6,'catalog','downloaded',now(),NULL,now())`,
		packID, compiled.Pack.Version, compiled.Pack.Name, compiled.SHA256, len(compiled.Canonical), compiled.Canonical)
	mustExec(t, w.pool, `UPDATE rule_packs SET current_version=$2 WHERE pack_id=$1`, packID, compiled.Pack.Version)
	mustExec(t, w.pool, `INSERT INTO rule_pack_enablements(id,level,level_object_id,pack_id,rule_id,state,allow_lower,priority,params,
		updated_by_user_id,updated_at) VALUES($1,'platform',NULL,$2,NULL,'inherit',true,NULL,NULL,NULL,now())`, uuid.New(), packID)
	// Only the system row may lack a user (migration 418).
	if _, err := w.pool.Exec(ctx, `INSERT INTO rule_pack_enablements(id,level,level_object_id,pack_id,rule_id,state,allow_lower,
		updated_by_user_id,updated_at) VALUES($1,'site',$2,$3,NULL,'enabled',false,NULL,now())`, uuid.New(), w.siteA1, packID); err == nil {
		t.Fatal("a user-less site row was accepted")
	}

	view, err := w.service.View(ctx, w.tenantA, LevelInput{Level: rulepack.LevelSite, ObjectID: &w.siteA1})
	if err != nil {
		t.Fatal(err)
	}
	if len(view.Packs) != 1 || view.Packs[0].Effect == nil || view.Packs[0].Effect.Enabled {
		t.Fatalf("official pack before enabling: %+v", view.Packs)
	}
	if site, err := w.service.Site(ctx, w.tenantA, w.siteA1); err != nil || mountIDs(site) != "" {
		t.Fatalf("mounted before enabling: %q %v", mountIDs(site), err)
	}
	site := ref(rulepack.LevelSite, w.siteA1)
	site.PackID, site.State = packID, rulepack.StateEnabled
	site.Params = json.RawMessage(`{"action":"block"}`)
	if err := w.put(t, w.tenantA, site); err != nil {
		t.Fatalf("site owner enables the official pack: %v", err)
	}
	published, err := w.service.PublishSite(ctx, w.tenantA, w.siteA1)
	if err != nil || mountIDs(published) != packID {
		t.Fatalf("publish: %q %v", mountIDs(published), err)
	}
	mount := published.Resolution.Security.Mounts[0]
	if string(mount.Params["action"]) != `"block"` {
		t.Fatalf("mount params = %s", mount.Params)
	}
	for _, rule := range published.Resolution.Rules {
		if rule.WAF == nil || rule.WAF.Action != "block" {
			t.Fatalf("resolved rule %s action %+v", rule.RuleID, rule.WAF)
		}
	}
	if other, err := w.service.Site(ctx, w.tenantA, w.siteA2); err != nil || mountIDs(other) != "" {
		t.Fatalf("site A2 mounts %q (%v)", mountIDs(other), err)
	}
	bad := site
	bad.Params = json.RawMessage(`{"action":"allow"}`)
	if err := w.put(t, w.tenantA, bad); !errors.Is(err, ErrInvalidInput) {
		t.Fatalf("action outside the enum: %v", err)
	}
	// The platform administrator's own row replaces the system row and can lock it.
	level, object := platformLevel()
	if err := w.put(t, w.platform, with(OverrideInput{Level: level, LevelObjectID: object}, packID, rulepack.StateInherit, false)); err != nil {
		t.Fatal(err)
	}
	var owner *uuid.UUID
	if err := w.pool.QueryRow(ctx, `SELECT updated_by_user_id FROM rule_pack_enablements WHERE level='platform' AND pack_id=$1`,
		packID).Scan(&owner); err == nil {
		t.Fatalf("platform row still present (owner %v)", owner)
	}
	if after, err := w.service.Site(ctx, w.tenantA, w.siteA1); err != nil || mountIDs(after) != "" {
		t.Fatalf("locked pack still mounted: %q %v", mountIDs(after), err)
	}
}
