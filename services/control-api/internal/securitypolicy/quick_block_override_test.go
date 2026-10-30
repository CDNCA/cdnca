package securitypolicy

import (
	"context"
	"errors"
	"testing"

	"github.com/google/uuid"
)

func boolPointer(value bool) *bool { return &value }

// Each item of a site's override is inherit (nil), on
// or off; lists replace the library's as a whole ([] is off).
func TestEffectiveQuickBlockAppliesOverridePerItem(t *testing.T) {
	library := &QuickBlock{BlockIDCCN: true, Carriers: []string{"carrier:cn-mobile"},
		AllowedCrawlers: []TrustedCrawler{{Networks: []string{"66.249.64.0/19"}, UserAgentPrefixes: []string{"Googlebot"}}}}
	if err := NormalizeQuickBlock(library); err != nil {
		t.Fatal(err)
	}
	// No override: the library's, unchanged.
	if got := EffectiveQuickBlock(library, QuickBlockOverride{}); !got.BlockIDCCN || got.BlockIDCGlobal ||
		len(got.Carriers) != 1 || len(got.AllowedCrawlers) != 1 {
		t.Fatalf("inherit = %+v", got)
	}
	carriers := []string{"carrier:cn-unicom", "carrier:cn-telecom"}
	override := QuickBlockOverride{BlockIDCCN: boolPointer(false), BlockIDCGlobal: boolPointer(true), Carriers: &carriers,
		AllowedCrawlers: &[]TrustedCrawler{}}
	if err := NormalizeQuickBlockOverride(&override); err != nil {
		t.Fatal(err)
	}
	if (*override.Carriers)[0] != "carrier:cn-telecom" {
		t.Fatalf("carriers not canonical: %v", *override.Carriers)
	}
	got := EffectiveQuickBlock(library, override)
	if got.BlockIDCCN || !got.BlockIDCGlobal || len(got.Carriers) != 2 || got.Carriers[0] != "carrier:cn-telecom" ||
		len(got.AllowedCrawlers) != 0 {
		t.Fatalf("override = %+v", got)
	}
	// The library is not changed by the merge.
	if !library.BlockIDCCN || len(library.Carriers) != 1 {
		t.Fatalf("library mutated: %+v", library)
	}
	// A library that never configured a quick block is all off.
	if got := EffectiveQuickBlock(nil, QuickBlockOverride{BlockIDCCN: boolPointer(true)}); !got.BlockIDCCN ||
		got.Carriers == nil || got.AllowedCrawlers == nil {
		t.Fatalf("nil library = %+v", got)
	}
	if !(QuickBlockOverride{}).Inherits() || override.Inherits() {
		t.Fatal("Inherits")
	}
	if !override.TurnsOn() || (QuickBlockOverride{BlockIDCCN: boolPointer(false), Carriers: &[]string{}}).TurnsOn() {
		t.Fatal("TurnsOn")
	}
}

func TestNormalizeQuickBlockOverrideRejectsInvalidItems(t *testing.T) {
	for name, override := range map[string]QuickBlockOverride{
		"unknown carrier":    {Carriers: &[]string{"carrier:nope"}},
		"idc tag as carrier": {Carriers: &[]string{"idc:cn"}},
		"bad crawler":        {AllowedCrawlers: &[]TrustedCrawler{{Networks: []string{"not-a-cidr"}, UserAgentPrefixes: []string{"x"}}}},
	} {
		if err := NormalizeQuickBlockOverride(&override); !errors.Is(err, ErrInvalidInput) {
			t.Errorf("%s: %v", name, err)
		}
	}
}

// SiteQuickBlockPolicy is the site's copy of its library policy with the
// effective quick block in place of the library's: the system rules keep
// their reserved IDs and slot (first, priority 1); user rules follow.
func TestSiteQuickBlockPolicyReplacesSystemRules(t *testing.T) {
	policyID := uuid.MustParse("018f7a5e-0000-7000-8000-00000000a001")
	user := Rule{ID: uuid.MustParse("018f7a5e-0000-7000-8000-00000000b001"), Name: "admin", Priority: 10, Enabled: true,
		Conditions: []Condition{{Field: "path", Operator: "prefix", Values: []string{"/admin"}}}, Action: ActionBlock, Flow: FlowStop}
	library := QuickBlock{BlockIDCCN: true}
	if err := NormalizeQuickBlock(&library); err != nil {
		t.Fatal(err)
	}
	policy := Policy{ID: policyID, Kind: KindWAF, Enabled: true, DefaultAction: ActionAllow, Revision: 3,
		Rules: MergeQuickBlockRules(policyID, []Rule{user}, &library), QuickBlock: &library}

	carriers := []string{"carrier:cn-mobile"}
	site, err := SiteQuickBlockPolicy(policy, QuickBlockOverride{BlockIDCCN: boolPointer(false), Carriers: &carriers})
	if err != nil {
		t.Fatal(err)
	}
	if len(site.Rules) != 2 || site.Rules[0].ID != QuickBlockRuleID(policyID, 1) || site.Rules[0].Name != quickBlockRuleCarrier ||
		site.Rules[0].Priority != 1 || site.Rules[1].ID != user.ID || site.QuickBlock.BlockIDCCN || len(site.QuickBlock.Carriers) != 1 {
		t.Fatalf("site policy = %+v", site)
	}
	if len(policy.Rules) != 2 || policy.Rules[0].Name != quickBlockRuleIDC || !policy.QuickBlock.BlockIDCCN {
		t.Fatalf("library policy mutated: %+v", policy)
	}
	// Off everywhere: only the user rule.
	off, err := SiteQuickBlockPolicy(policy, QuickBlockOverride{BlockIDCCN: boolPointer(false)})
	if err != nil || len(off.Rules) != 1 || off.Rules[0].ID != user.ID {
		t.Fatalf("off = %+v, %v", off.Rules, err)
	}
	// Turning the last rules off is refused, as on the library.
	only := Policy{ID: policyID, Kind: KindWAF, Enabled: true, DefaultAction: ActionAllow, Revision: 3,
		Rules: MergeQuickBlockRules(policyID, nil, &library), QuickBlock: &library}
	if _, err := SiteQuickBlockPolicy(only, QuickBlockOverride{BlockIDCCN: boolPointer(false)}); !errors.Is(err, ErrQuickBlockLastRules) {
		t.Fatalf("last rules: %v", err)
	}
	// Turning on in a policy that cannot carry it is refused.
	for name, unsupported := range map[string]Policy{
		"default block": {ID: policyID, Kind: KindWAF, DefaultAction: ActionBlock, Revision: 1, Rules: []Rule{user}},
		"acl":           {ID: policyID, Kind: KindACL, DefaultAction: ActionAllow, Revision: 1, Rules: []Rule{user}},
	} {
		if _, err := SiteQuickBlockPolicy(unsupported, QuickBlockOverride{BlockIDCGlobal: boolPointer(true)}); !errors.Is(err, ErrQuickBlockUnsupported) {
			t.Errorf("%s: %v", name, err)
		}
	}
	// An override that only turns things off applies anywhere a WAF policy is.
	if _, err := SiteQuickBlockPolicy(Policy{ID: policyID, Kind: KindWAF, DefaultAction: ActionBlock, Revision: 1, Rules: []Rule{user}},
		QuickBlockOverride{BlockIDCGlobal: boolPointer(false)}); err != nil {
		t.Fatalf("off on default block: %v", err)
	}
}

// A stored override (site_quick_block_overrides.override) decodes strictly:
// known items only, canonical form, at least one item set.
func TestDecodeQuickBlockOverride(t *testing.T) {
	override, err := DecodeQuickBlockOverride([]byte(`{"block_idc_cn":true,"block_idc_global":null,"carriers":[],"allowed_crawlers":null}`))
	if err != nil || override.BlockIDCCN == nil || !*override.BlockIDCCN || override.BlockIDCGlobal != nil ||
		override.Carriers == nil || len(*override.Carriers) != 0 || override.AllowedCrawlers != nil {
		t.Fatalf("decode = %+v, %v", override, err)
	}
	for name, raw := range map[string]string{
		"unknown field":  `{"block_idc_cn":true,"extra":1}`,
		"inherits all":   `{}`,
		"all null":       `{"block_idc_cn":null}`,
		"bad carrier":    `{"carriers":["carrier:nope"]}`,
		"trailing value": `{"block_idc_cn":true} {}`,
		"not an object":  `[]`,
	} {
		if _, err := DecodeQuickBlockOverride([]byte(raw)); err == nil {
			t.Errorf("%s: decoded", name)
		}
	}
}

// The library write guard's error names the sites whose override the change
// would break, and still matches its sentinel.
func TestQuickBlockSiteOverrideError(t *testing.T) {
	siteID := uuid.MustParse("41111111-1111-4111-8111-11111111111a")
	err := error(&QuickBlockSiteOverrideError{SiteIDs: []uuid.UUID{siteID}, Cause: ErrQuickBlockLastRules})
	var conflict *QuickBlockSiteOverrideError
	if !errors.Is(err, ErrQuickBlockSiteOverrides) || !errors.As(err, &conflict) || len(conflict.SiteIDs) != 1 ||
		errors.Is(err, ErrQuickBlockLastRules) {
		t.Fatalf("error = %v", err)
	}
}

// Overrides ride on a site's WAF binding only: a CC/ACL library write is
// never checked against them (nor reads them).
func TestCheckSiteQuickBlockOverridesSkipsNonWAF(t *testing.T) {
	for _, kind := range []string{KindCC, KindACL} {
		if err := CheckSiteQuickBlockOverridesTx(context.Background(), nil, Policy{ID: uuid.New(), Kind: kind}); err != nil {
			t.Fatalf("%s: %v", kind, err)
		}
	}
}
