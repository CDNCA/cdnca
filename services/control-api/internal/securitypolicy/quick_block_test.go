package securitypolicy

import (
	"errors"
	"slices"
	"strconv"
	"testing"

	"github.com/google/uuid"
)

var quickBlockPolicyID = uuid.MustParse("018f7a5e-0000-7000-8000-00000000a001")

func googlebot() TrustedCrawler {
	return TrustedCrawler{Networks: []string{"66.249.64.0/19", "2001:4860:4801::/48"},
		UserAgentPrefixes: []string{"Mozilla/5.0 (compatible; Googlebot/2.1"}}
}

func TestNormalizeQuickBlock(t *testing.T) {
	block := QuickBlock{BlockIDCCN: true, Carriers: []string{"Carrier:CN-Unicom", "carrier:cn-telecom"},
		AllowedCrawlers: []TrustedCrawler{googlebot()}}
	if err := NormalizeQuickBlock(&block); err != nil {
		t.Fatalf("normalize: %v", err)
	}
	if !slices.Equal(block.Carriers, []string{"carrier:cn-telecom", "carrier:cn-unicom"}) || !block.Active() {
		t.Fatalf("normalized = %+v", block)
	}
	if empty := (QuickBlock{}); NormalizeQuickBlock(&empty) != nil || empty.Active() || empty.Carriers == nil || empty.AllowedCrawlers == nil {
		t.Fatalf("empty = %+v", empty)
	}
	for name, invalid := range map[string]QuickBlock{
		"idc carrier":      {Carriers: []string{"idc:cn"}},
		"unknown carrier":  {Carriers: []string{"carrier:cn-other"}},
		"duplicate":        {Carriers: []string{"carrier:cn-mobile", "carrier:CN-mobile"}},
		"crawler no ua":    {AllowedCrawlers: []TrustedCrawler{{Networks: []string{"66.249.64.0/19"}}}},
		"crawler bad cidr": {AllowedCrawlers: []TrustedCrawler{{Networks: []string{"66.249.64.1/19"}, UserAgentPrefixes: []string{"Googlebot"}}}},
		"too many networks": {AllowedCrawlers: []TrustedCrawler{{Networks: quickBlockNetworks(MaxQuickBlockCrawlerNetworks + 1),
			UserAgentPrefixes: []string{"Googlebot"}}}},
	} {
		if err := NormalizeQuickBlock(&invalid); !errors.Is(err, ErrInvalidInput) {
			t.Errorf("%s: err = %v, want ErrInvalidInput", name, err)
		}
	}
}

func quickBlockNetworks(count int) []string {
	networks := make([]string, count)
	for index := range networks {
		networks[index] = "10." + strconv.Itoa(index/256) + "." + strconv.Itoa(index%256) + ".0/24"
	}
	return networks
}


// G3-d #13: the switches expand to system-managed WAF rules placed before
// every user rule (priority 1, IDs sorting first): block IDC (one rule over
// the chosen idc:* tags), block carriers (one rule over carrier:*), then one
// allow per crawler network that cancels the quick block for the verified
// crawler (client network and UA prefix) without skipping the user's rules.
func TestQuickBlockRules(t *testing.T) {
	block := QuickBlock{BlockIDCCN: true, BlockIDCGlobal: true, Carriers: []string{"carrier:cn-mobile"},
		AllowedCrawlers: []TrustedCrawler{googlebot()}}
	if err := NormalizeQuickBlock(&block); err != nil {
		t.Fatal(err)
	}
	rules := QuickBlockRules(quickBlockPolicyID, block)
	if len(rules) != 4 {
		t.Fatalf("rules = %+v", rules)
	}
	idc, carrier := rules[0], rules[1]
	if idc.Action != ActionBlock || idc.Flow != FlowContinue || idc.Priority != 1 || len(idc.Conditions) != 1 ||
		idc.Conditions[0].Field != "ip_tag" || idc.Conditions[0].Operator != "in" ||
		!slices.Equal(idc.Conditions[0].Values, []string{"idc:cn", "idc:global"}) {
		t.Fatalf("idc rule = %+v", idc)
	}
	if carrier.Action != ActionBlock || carrier.Flow != FlowContinue || carrier.Conditions[0].Field != "carrier" ||
		!slices.Equal(carrier.Conditions[0].Values, []string{"carrier:cn-mobile"}) {
		t.Fatalf("carrier rule = %+v", carrier)
	}
	for index, network := range []string{"2001:4860:4801::/48", "66.249.64.0/19"} {
		allow := rules[2+index]
		if allow.Action != ActionAllow || allow.Flow != FlowContinue || len(allow.Conditions) != 2 {
			t.Fatalf("crawler rule %d = %+v", index, allow)
		}
		if allow.Conditions[0].Field != "client_ip" || allow.Conditions[0].Values[0] != network ||
			allow.Conditions[1].Field != "user_agent" || allow.Conditions[1].Operator != "regex" ||
			allow.Conditions[1].Values[0] != `^Mozilla/5\.0 \(compatible; Googlebot/2\.1` {
			t.Fatalf("crawler rule %d conditions = %+v", index, allow.Conditions)
		}
	}
	for index, rule := range rules {
		if rule.ID != QuickBlockRuleID(quickBlockPolicyID, index+1) || !IsQuickBlockRuleID(rule.ID) || !rule.Enabled {
			t.Fatalf("rule %d id %s", index, rule.ID)
		}
	}
	// System rule IDs sort before every time-ordered (v7) rule ID at the same priority.
	user := Rule{ID: uuid.Must(uuid.NewV7()), Priority: 1}
	all := append([]Rule{user}, rules...)
	sortRules(all)
	if all[len(all)-1].ID != user.ID {
		t.Fatalf("user rule sorted before system rules: %v", all)
	}
	if IsQuickBlockRuleID(user.ID) || IsQuickBlockRuleID(uuid.Nil) {
		t.Fatal("ordinary IDs taken for system rules")
	}
	// Generated rules pass the publishable gate.
	fields := PolicyFields{Kind: KindWAF, Name: "site", Enabled: true, DefaultAction: ActionAllow, Rules: rules}
	if err := normalizePublishableFields(&fields, false); err != nil {
		t.Fatalf("generated rules rejected: %v", err)
	}
	if got := QuickBlockRules(quickBlockPolicyID, QuickBlock{AllowedCrawlers: block.AllowedCrawlers}); len(got) != 0 {
		t.Fatalf("crawlers alone (nothing blocked) produced rules: %+v", got)
	}
}

func TestMergeQuickBlockRulesReplacesSystemRules(t *testing.T) {
	block := QuickBlock{BlockIDCGlobal: true}
	user := Rule{ID: uuid.Must(uuid.NewV7()), Name: "admin", Priority: 5, Enabled: true, Action: ActionBlock, Flow: FlowStop,
		Conditions: []Condition{{Field: "path", Operator: "prefix", Values: []string{"/admin"}}}}
	forged := Rule{ID: QuickBlockRuleID(quickBlockPolicyID, 1), Name: "edited", Priority: 9, Enabled: false, Action: ActionAllow,
		Flow: FlowStop, Conditions: []Condition{{Field: "path", Operator: "prefix", Values: []string{"/"}}}}
	merged := MergeQuickBlockRules(quickBlockPolicyID, []Rule{forged, user}, &block)
	if len(merged) != 2 || merged[0].ID != QuickBlockRuleID(quickBlockPolicyID, 1) || merged[0].Action != ActionBlock ||
		merged[1].ID != user.ID {
		t.Fatalf("merged = %+v", merged)
	}
	if stripped := MergeQuickBlockRules(quickBlockPolicyID, merged, nil); len(stripped) != 1 || stripped[0].ID != user.ID {
		t.Fatalf("stripped = %+v", stripped)
	}
}

func TestQuickBlockFieldsGuards(t *testing.T) {
	policy := Policy{ID: quickBlockPolicyID, Kind: KindWAF, Name: "site", Enabled: true, DefaultAction: ActionAllow,
		Rules: QuickBlockRules(quickBlockPolicyID, QuickBlock{BlockIDCCN: true})}
	if _, err := quickBlockFields(policy, QuickBlock{}); !errors.Is(err, ErrQuickBlockLastRules) {
		t.Fatalf("turning the only rules off: err = %v", err)
	}
	user := make([]Rule, 0, 99)
	for index := range 99 {
		user = append(user, Rule{ID: uuid.Must(uuid.NewV7()), Name: "r", Priority: index + 2, Enabled: true, Action: ActionBlock,
			Flow: FlowStop, Conditions: []Condition{{Field: "path", Operator: "prefix", Values: []string{"/p" + strconv.Itoa(index)}}}})
	}
	policy.Rules = user
	if _, err := quickBlockFields(policy, QuickBlock{BlockIDCCN: true, Carriers: []string{"carrier:cn-mobile"}}); !errors.Is(err, ErrQuickBlockRuleBudget) {
		t.Fatalf("101 rules: err = %v", err)
	}
	fields, err := quickBlockFields(policy, QuickBlock{BlockIDCCN: true})
	if err != nil || len(fields.Rules) != 100 || fields.Rules[0].ID != QuickBlockRuleID(quickBlockPolicyID, 1) {
		t.Fatalf("100 rules: %d rules, %v", len(fields.Rules), err)
	}
}
