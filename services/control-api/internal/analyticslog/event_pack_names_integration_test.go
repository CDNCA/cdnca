//go:build integration

package analyticslog

import (
	"os"
	"path/filepath"
	"testing"

	"github.com/cdnca/cdnca/libs/rulepack"
	"github.com/cdnca/cdnca/services/control-api/internal/database/databasetest"
	"github.com/google/uuid"
)

// fix-wafname: the lookup names rule pack rules from rule_pack_artifacts —
// a downloaded official system pack for every tenant and the platform, a
// tenant's own user pack only for that tenant (and the platform).
func TestPostgresEventNameLookupNamesRulePacks(t *testing.T) {
	pool := databasetest.MigratedPool(t, nil)
	ctx := t.Context()
	exec := func(sql string, args ...any) {
		t.Helper()
		if _, err := pool.Exec(ctx, sql, args...); err != nil {
			t.Fatal(err)
		}
	}
	tenantA, tenantB, scopeA, scopeB, user := uuid.New(), uuid.New(), uuid.New(), uuid.New(), uuid.New()
	exec(`INSERT INTO tenants(id,display_name) VALUES($1,'Pack names A'),($2,'Pack names B')`, tenantA, tenantB)
	exec(`INSERT INTO access_scopes(id,kind,tenant_id) VALUES($1,'tenant',$2),($3,'tenant',$4)`, scopeA, tenantA, scopeB, tenantB)
	exec(`INSERT INTO users(id,username,display_name,password_hash) VALUES($1,'pack-names','pack-names','test-only')`, user)
	exec(`INSERT INTO memberships(scope_id,user_id) VALUES($1,$2)`, scopeA, user)

	content, err := os.ReadFile(filepath.Join("..", "..", "..", "..", "scripts", "security", "datasets", "rulepacks",
		"imported", "system-naxsi-websec.json"))
	if err != nil {
		t.Fatal(err)
	}
	official, err := rulepack.Compile(content)
	if err != nil {
		t.Fatal(err)
	}
	exec(`INSERT INTO rule_packs(pack_id,layer,owner_scope_id,current_version,update_policy,created_by_user_id,
		updated_by_user_id,created_at,updated_at) VALUES($1,'system',NULL,NULL,'auto',NULL,NULL,now(),now())`, official.Pack.PackID)
	exec(`INSERT INTO rule_pack_artifacts(pack_id,version,engine,engine_min_version,name,sha256,size_bytes,content,
		source,state,downloaded_at,created_by_user_id,created_at) VALUES($1,$2,'waf_v2',1,$3,$4,$5,$6,'catalog','downloaded',now(),NULL,now())`,
		official.Pack.PackID, official.Pack.Version, official.Pack.Name, official.SHA256, len(official.Canonical), official.Canonical)
	exec(`UPDATE rule_packs SET current_version=$2 WHERE pack_id=$1`, official.Pack.PackID, official.Pack.Version)

	userPackID := "user/" + scopeA.String() + "/mine"
	own, err := rulepack.Compile([]byte(`{"schema":"cdnca.rule-pack/v1","pack_id":"` + userPackID + `","version":"1.0.0",` +
		`"layer":"user","engine":"waf_v2","engine_min_version":1,"name":"我的规则包","description":"","params_schema":{},` +
		`"exports":[],"defaults":{},"rules":[{"id":"r1","name":"拦截后台","waf":{"action":"block","flow":"stop",` +
		`"match":{"inspect":[{"target":"args","operator":"contains","values":["/admin"]}]}}}]}`))
	if err != nil {
		t.Fatal(err)
	}
	exec(`INSERT INTO rule_packs(pack_id,layer,owner_scope_id,current_version,update_policy,created_by_user_id,
		updated_by_user_id,created_at,updated_at) VALUES($1,'user',$2,NULL,'manual',$3,$3,now(),now())`, userPackID, scopeA, user)
	exec(`INSERT INTO rule_pack_artifacts(pack_id,version,engine,engine_min_version,name,sha256,size_bytes,content,
		source,state,downloaded_at,created_by_user_id,created_at) VALUES($1,'1.0.0','waf_v2',1,$2,$3,$4,$5,'tenant','downloaded',now(),$6,now())`,
		userPackID, own.Pack.Name, own.SHA256, len(own.Canonical), own.Canonical, user)
	exec(`UPDATE rule_packs SET current_version='1.0.0' WHERE pack_id=$1`, userPackID)

	lookup := NewPostgresEventNameLookup(pool, nil)
	officialRef := EventNameRef{PolicyID: "aa96383a-a68f-544c-b6c2-69e991717cea", RuleID: "50d1c058-f720-5065-87df-f95e7f0a91f1"}
	ownRef := EventNameRef{RuleID: rulepack.NodeRuleID(userPackID, "r1")}
	const officialName = "敏感路径与漏洞探测（naxsi） · 路径含已知特征 第 2 组"
	for _, item := range []struct {
		tenant  string
		ownName string
	}{
		{tenantA.String(), "我的规则包 · 拦截后台"},
		{tenantB.String(), "未命名规则（" + ownRef.RuleID[:8] + "）"},
		{"", "我的规则包 · 拦截后台"},
	} {
		// Twice: the second lookup is served by the artifact cache.
		for range 2 {
			names := lookup.Lookup(ctx, item.tenant, []EventNameRef{officialRef, ownRef})
			if got := names.rule(officialRef.PolicyID, officialRef.RuleID); got != officialName {
				t.Fatalf("tenant %q official rule = %q", item.tenant, got)
			}
			if got := names.RuleName("", ownRef.RuleID); got != item.ownName {
				t.Fatalf("tenant %q user pack rule = %q", item.tenant, got)
			}
		}
	}
}
