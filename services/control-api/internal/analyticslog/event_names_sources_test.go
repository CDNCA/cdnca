package analyticslog

import (
	"os"
	"path/filepath"
	"strings"
	"testing"

	"github.com/cdnca/cdnca/libs/rulepack"
	"github.com/cdnca/cdnca/services/control-api/internal/securitypolicy"
	"github.com/google/uuid"
)

// fix-wafname: the 73 WAF log row (rule 50d1c058…, policy aa96383a…) is the
// official system pack system/naxsi-websec rule nx-web-path-01: rule packs
// run on the node under NodeRuleID(pack_id, rule_id) in a segment whose
// policy is NodeRuleID(pack_id, "@pack"), so the security policy tables
// never hold them.
func TestOfficialPackRuleNamedFromArtifact(t *testing.T) {
	content, err := os.ReadFile(filepath.Join("..", "..", "..", "..", "scripts", "security", "datasets", "rulepacks",
		"imported", "system-naxsi-websec.json"))
	if err != nil {
		t.Fatal(err)
	}
	compiled, err := rulepack.Compile(content)
	if err != nil {
		t.Fatal(err)
	}
	const ruleID, policyID = "50d1c058-f720-5065-87df-f95e7f0a91f1", "aa96383a-a68f-544c-b6c2-69e991717cea"
	if rulepack.NodeRuleID("system/naxsi-websec", "nx-web-path-01") != ruleID ||
		rulepack.NodeRuleID("system/naxsi-websec", "@pack") != policyID {
		t.Fatal("node IDs of the 73 row no longer derive from the pack")
	}
	names := EventNames{}
	names.addPack(packNamesOf(compiled.Canonical))
	want := "敏感路径与漏洞探测（naxsi） · 路径含已知特征 第 2 组"
	if got := names.rule(policyID, strings.ToUpper(ruleID)); got != want {
		t.Fatalf("pack rule with its segment policy = %q", got)
	}
	if got := names.RuleName("", ruleID); got != want {
		t.Fatalf("pack rule without a policy (attack types) = %q", got)
	}
	// A rule the stored versions no longer hold still names its pack.
	if got := names.rule(policyID, "0f0e0d0c-0000-5000-8000-000000000001"); got != "敏感路径与漏洞探测（naxsi） · 未命名规则（0f0e0d0c）" {
		t.Fatalf("unknown rule of a known pack segment = %q", got)
	}
}

// A sealed (encrypted) pack names only its exported rules from the manifest;
// other rules of it are named by the pack through the segment policy.
func TestSealedPackNamesExportedRules(t *testing.T) {
	document := []byte(`{"schema":"cdnca.rule-pack-sealed/v1","manifest":{"pack_id":"dev/acme/bots","name":"Acme 机器人",` +
		`"export_names":{"r1":"坏爬虫"}},"nonce":"x","ciphertext":"y"}`)
	names := EventNames{}
	names.addPack(packNamesOf(document))
	if got := names.RuleName("", rulepack.NodeRuleID("dev/acme/bots", "r1")); got != "Acme 机器人 · 坏爬虫" {
		t.Fatalf("exported sealed rule = %q", got)
	}
	hidden := rulepack.NodeRuleID("dev/acme/bots", "r2")
	if got := names.rule(rulepack.NodeRuleID("dev/acme/bots", "@pack"), hidden); got != "Acme 机器人 · 未命名规则（"+hidden[:8]+"）" {
		t.Fatalf("unexported sealed rule = %q", got)
	}
	if packNamesOf([]byte(`not json`)).packID != "" {
		t.Fatal("malformed artifact named")
	}
}

// System-managed rules get Chinese names; an unknown UUID is never shown
// whole.
func TestSystemRuleNamesAndFallback(t *testing.T) {
	policy := uuid.MustParse("6f1b0e2a-7c55-4a39-9c6e-8f1a3a1c2d01")
	quick := securitypolicy.QuickBlockRuleID(policy, 1).String()
	names := EventNames{
		Policies: map[string]string{policy.String(): "主站规则库"},
		Rules: map[string]map[string]string{policy.String(): {
			quick: "quick-block:idc", "018f0000-0000-7000-8000-0000000000b2": "JA4 block",
			"018f0000-0000-7000-8000-0000000000b3": "cccoord-018f0000-0000-7000-8000-0000000000c9",
		}},
	}
	for _, item := range []struct{ policy, rule, want string }{
		{policy.String(), quick, "快速屏蔽 · IDC 机房"},
		{policy.String(), "018f0000-0000-7000-8000-0000000000b2", "JA4 自动封禁"},
		{"", "018f0000-0000-7000-8000-0000000000b3", "CC 跨节点协同封禁"},
		// A site override's quick block rule is compiled at release only.
		{"", securitypolicy.QuickBlockRuleID(uuid.New(), 2).String(), "快速屏蔽"},
		{policy.String(), policy.String() + ":default", "主站规则库 · 默认动作"},
		{"", "0a0b0c0d-0000-4000-8000-000000000001:default", "默认动作（策略 0a0b0c0d）"},
		{"", "autodefense:l3", "自动防御 · 第 3 级拦截"},
		{"", "autodefense:l1", "自动防御 · 第 1 级挑战"},
		{"", "autodefense:bot.mismatch", "自动防御 · 浏览器指纹不符"},
		{"", "autodefense:bot.ai_crawler", "自动防御 · AI 爬虫"},
		{"", "autodefense:sig-42", "自动防御 · 攻击签名 sig-42"},
		{"", "managed-waf-30100", "托管 WAF · 规则集判定"},
		{"", "50D1C058-F720-5065-87DF-F95E7F0A91F1", "未命名规则（50d1c058）"},
		{policy.String(), "11111111-2222-4333-8444-555555555555", "主站规则库 · 未命名规则（11111111）"},
		{"", "smoke-rule", ""},
		{"", "__unknown__", ""},
	} {
		if got := names.rule(item.policy, item.rule); got != item.want {
			t.Errorf("rule(%q, %q) = %q, want %q", item.policy, item.rule, got, item.want)
		}
	}
}

// Names are bounded to the page's 128 bytes on a rune boundary.
func TestPackRuleNameBounded(t *testing.T) {
	names := EventNames{}
	long := strings.Repeat("长", 40)
	names.addPack(packNames{packID: "user/x/y", name: long, rules: map[string]string{"r": long}})
	got := names.RuleName("", rulepack.NodeRuleID("user/x/y", "r"))
	if len(got) > 128 || !strings.HasPrefix(got, long) || !strings.HasSuffix(got, "长") {
		t.Fatalf("bounded name %q (%d bytes)", got, len(got))
	}
}

func TestEventNameIDsCollectsDefaultPolicies(t *testing.T) {
	_, policies, _ := eventNameIDs([]EventNameRef{{RuleID: "018f0000-0000-7000-8000-0000000000a1:default"}})
	if len(policies) != 1 || policies[0] != "018f0000-0000-7000-8000-0000000000a1" {
		t.Fatalf("policies = %v", policies)
	}
}
