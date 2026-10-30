package edgeconfig

import (
	"strings"
	"testing"
)

// 生产发布都带非零 ConfigRevision（会生成缓存契约清单 cache_policy.json）。
// JS 挑战的 init_by_lua（每站点 loadfile 引擎 + package.loaded 登记）此前被
// 缓存新鲜度身份写入扫描当成可疑写入，导致挑战站点 Build 失败。

const challengeRevisionPolicyID = "55555555-5555-4555-8555-555555555555"

func challengeRevisionSpec(mutate func(*Spec)) Spec {
	spec := productionCacheSpec()
	spec.Sites[0].Challenge = &ChallengeBinding{PolicyID: challengeRevisionPolicyID, PolicyVersion: 3}
	if mutate != nil {
		mutate(&spec)
	}
	return spec
}

func challengeRevisionFreshness(spec *Spec) {
	spec.Sites[0].CacheFreshness = &CacheFreshnessPolicy{
		SchemaVersion: CacheFreshnessSchemaVersion, PolicyVersion: 7, ConfigurationVersion: spec.ConfigRevision,
		TenantID: spec.TenantID, SiteID: spec.Sites[0].ID, Mode: CacheFreshnessModeEnhancement,
		ListenAddress: "0.0.0.0", ListenPort: spec.Sites[0].ListenPort, Hosts: []string{spec.Sites[0].Domain},
		OriginHost: "127.0.0.1", OriginPort: 19001, CacheMaxBytes: spec.Sites[0].Cache.MaxSizeBytes,
		CacheInactiveSeconds: 3600, FreshSeconds: 30, CacheableStatuses: []uint16{200},
		Enhancement: CacheFreshnessEnhancementPolicy{Enabled: true, StaleWindowSeconds: 60},
	}
}

func TestCacheContractStillRejectsForgedChallengeInit(t *testing.T) {
	canonical := strings.Join([]string{
		`local chunk_0001, load_error_0001 = loadfile("/usr/local/share/cdnca/challenge/engine.lua")`,
		`if not chunk_0001 then error(load_error_0001) end`,
		`local module_0001 = chunk_0001()`,
		`if type(module_0001) ~= "table" or type(module_0001.init) ~= "function" then error("invalid challenge module") end`,
		`module_0001.init({ policy_path = "/var/lib/cdnca-edge/challenge/policies/` + challengeRevisionPolicyID + `/versions/00000000000000000003.json", state_dict = "cdnca_challenge_state" })`,
		`package.loaded["cdnca_challenge_site_0001"] = module_0001`,
	}, "\n")
	scan := func(body string) (bool, bool) {
		budget := cacheFreshnessLuaBudget{remaining: cacheFreshnessLuaMaxWork}
		return cacheFreshnessLuaIdentityAssignmentScanWithBudget(body, &budget)
	}
	if writes, valid := scan(canonical); writes || !valid {
		t.Fatalf("canonical challenge init scan = writes %v valid %v", writes, valid)
	}
	for name, body := range map[string]string{
		"other engine": strings.Replace(canonical, "/usr/local/share/cdnca/challenge/engine.lua", "/tmp/engine.lua", 1),
		"guard override": strings.Replace(canonical, `package.loaded["cdnca_challenge_site_0001"]`,
			`package.loaded["cachefreshness.guard"]`, 1),
		"index mismatch": strings.Replace(canonical, `package.loaded["cdnca_challenge_site_0001"] = module_0001`,
			`package.loaded["cdnca_challenge_site_0001"] = module_0002`, 1),
		"policy escape": strings.Replace(canonical, `/versions/00000000000000000003.json"`,
			`/versions/00000000000000000003.json" .. loadstring("x")()`, 1),
		"partial template": strings.Join(strings.Split(canonical, "\n")[:1], "\n") +
			"\nlocal module_0001 = chunk_0001()",
		"identity write after init":  canonical + "\nngx.var.cache_freshness_identity = \"forged\"",
		"same line identity write":   strings.Replace(canonical, "local module_0001 = chunk_0001()", "local module_0001 = chunk_0001(); ngx.var.cache_freshness_identity = \"forged\"", 1),
		"extra package.loaded write": canonical + "\npackage.loaded[\"cachefreshness.guard\"] = module_0001",
		"extra loadfile":             canonical + "\nloadfile(\"/tmp/x.lua\")()",
	} {
		if writes, valid := scan(body); valid && !writes {
			t.Fatalf("%s: forged challenge init accepted", name)
		}
	}
}
