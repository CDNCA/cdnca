//go:build integration

package migrations_test

import (
	"strings"
	"testing"

	"github.com/google/uuid"
)

// TestOfficialRulePacksEnabled544: up turns the control plane's own inherit
// platform rows of system packs into enabled (an administrator's row and a
// user pack's row stay) and clears the materialization mark of free rule
// pack artifacts; down puts them back to inherit except the 454 virtual
// patches.
func TestOfficialRulePacksEnabled544(t *testing.T) {
	const version = 544
	pool := migrationPoolAt(t, version-1)
	ctx := t.Context()
	exec := func(query string, args ...any) {
		t.Helper()
		if _, err := pool.Exec(ctx, query, args...); err != nil {
			t.Fatalf("%s: %v", query, err)
		}
	}
	admin, delivery := uuid.New(), uuid.New()
	exec(`INSERT INTO users(id,username,display_name,password_hash) VALUES($1,'rp544-admin','a','unused')`, admin)
	for _, pack := range []string{"system/bot-bad-ua", "system/waf-php-vpatch", "system/admin-kept"} {
		exec(`INSERT INTO rule_packs(pack_id,layer,owner_scope_id,current_version,update_policy,created_by_user_id,updated_by_user_id,
			created_at,updated_at) VALUES($1,'system',NULL,NULL,'auto',NULL,NULL,now(),now())`, pack)
	}
	exec(`INSERT INTO rule_pack_enablements(id,level,level_object_id,pack_id,rule_id,state,allow_lower,priority,params,
		updated_by_user_id,updated_at) VALUES($1,'platform',NULL,'system/bot-bad-ua',NULL,'inherit',true,NULL,NULL,NULL,now()),
		($2,'platform',NULL,'system/waf-php-vpatch',NULL,'enabled',true,NULL,NULL,NULL,now()),
		($3,'platform',NULL,'system/admin-kept',NULL,'inherit',true,NULL,NULL,$4,now())`, uuid.New(), uuid.New(), uuid.New(), admin)
	digest := strings.Repeat("ab", 32)
	exec(`INSERT INTO artifact_objects(sha256,size,content,stored_at) VALUES($1,1,'\x00',now())`, digest)
	for _, item := range []struct{ id, feature string }{{"rule_pack/system:bot-bad-ua", ""}, {"rule_pack/system:paid", "module.waf.pro"}} {
		exec(`INSERT INTO artifact_catalog_entries(artifact_id,kind,version,revision,sha256,size,media_type,requires_feature,resident,
			encryption,status,delivery_id,first_seen_at,updated_at) VALUES($1,'rule_pack','1.0.0',1,$2,1,'application/json',$3,true,
			'none','active',$4,now(),now())`, item.id, digest, item.feature, delivery)
		exec(`INSERT INTO local_artifacts(artifact_id,current_revision,current_sha256,current_version,downloaded_at,materialized_sha256,
			updated_at) VALUES($1,1,$2,'1.0.0',now(),$2,now())`, item.id, digest)
	}
	states := func() map[string]string {
		t.Helper()
		rows, err := pool.Query(ctx, `SELECT pack_id,state FROM rule_pack_enablements WHERE level='platform'`)
		if err != nil {
			t.Fatal(err)
		}
		defer rows.Close()
		out := map[string]string{}
		for rows.Next() {
			var pack, state string
			if err := rows.Scan(&pack, &state); err != nil {
				t.Fatal(err)
			}
			out[pack] = state
		}
		return out
	}
	marked := func(id string) bool {
		t.Helper()
		var set bool
		if err := pool.QueryRow(ctx, `SELECT materialized_sha256 IS NOT NULL FROM local_artifacts WHERE artifact_id=$1`, id).Scan(&set); err != nil {
			t.Fatal(err)
		}
		return set
	}

	if err := migrateVersionIsolated(ctx, pool, "up", version); err != nil {
		t.Fatalf("up %d: %v", version, err)
	}
	if got := states(); got["system/bot-bad-ua"] != "enabled" || got["system/waf-php-vpatch"] != "enabled" ||
		got["system/admin-kept"] != "inherit" {
		t.Fatalf("after up: %v", got)
	}
	if marked("rule_pack/system:bot-bad-ua") || !marked("rule_pack/system:paid") {
		t.Fatal("up must re-materialize free rule packs only")
	}
	if err := migrateVersionIsolated(ctx, pool, "down", version); err != nil {
		t.Fatalf("down %d: %v", version, err)
	}
	if got := states(); got["system/bot-bad-ua"] != "inherit" || got["system/waf-php-vpatch"] != "enabled" ||
		got["system/admin-kept"] != "inherit" {
		t.Fatalf("after down: %v", got)
	}
	if err := migrateVersionIsolated(ctx, pool, "up", version); err != nil {
		t.Fatalf("up again %d: %v", version, err)
	}
}
