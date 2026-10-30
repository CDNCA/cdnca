package edgeconfig

import (
	"bytes"
	"encoding/json"
	"errors"
	"fmt"
	"strings"
	"testing"
)

const (
	guardRuleA = "66666666-6666-4666-8666-666666666661"
	guardRuleB = "66666666-6666-4666-8666-666666666662"
)

// guard_rules (tcp/udp v10) is optional: unset or empty keeps the signed
// artifact byte-identical; rules are carried in order, canonicalized.
func TestL4GuardRulesAreOptionalAndCanonical(t *testing.T) {
	unset, err := buildStreams(multiListenerBundleSpec())
	if err != nil {
		t.Fatal(err)
	}
	if bytes.Contains(unset.Files[L4RuntimeV2ArtifactPath], []byte("guard_rules")) {
		t.Fatal("unset guard rules changed the signed L4 artifact")
	}
	empty := multiListenerBundleSpec()
	empty.L4StreamsV2[0].GuardRules = []L4GuardRuleV2{}
	emptyBundle, err := buildStreams(empty)
	if err != nil || emptyBundle.ManifestSHA256 != unset.ManifestSHA256 {
		t.Fatalf("empty guard rules changed the signed artifact: %v", err)
	}

	spec := multiListenerBundleSpec()
	spec.L4StreamsV2[0].GuardRules = []L4GuardRuleV2{
		{ID: guardRuleB, Action: L4GuardActionBan, BanSeconds: 600, Threshold: 5, WindowSeconds: 60,
			FirstPacket: &L4GuardFirstPacket{Match: L4GuardMatchPrefixHex, Value: "16030100"},
			ClientIP:    &L4GuardClientIP{CIDRs: []string{"198.51.100.0/24", "192.0.2.7/32", "2001:db8::/32"}}},
		{ID: guardRuleA, Action: L4GuardActionDrop,
			Geo: []WAFIPIntel{{Field: WAFIPIntelCountry, Values: []string{"US", "CN"}}, {Field: WAFIPIntelTag, Values: []string{"idc:global"}}}},
	}
	bundle, err := buildStreams(spec)
	if err != nil {
		t.Fatal(err)
	}
	var set l4StreamSetV2
	if err := json.Unmarshal(bundle.Files[L4RuntimeV2ArtifactPath], &set); err != nil {
		t.Fatal(err)
	}
	rules := set.Streams[0].GuardRules
	if len(rules) != 2 || rules[0].ID != guardRuleB || rules[1].ID != guardRuleA {
		t.Fatalf("rule order not kept: %+v", rules)
	}
	if got := strings.Join(rules[0].ClientIP.CIDRs, ","); got != "192.0.2.7/32,198.51.100.0/24,2001:db8::/32" {
		t.Fatalf("CIDRs not canonical: %s", got)
	}
	if rules[1].Geo[0].Field != WAFIPIntelCountry || strings.Join(rules[1].Geo[0].Values, ",") != "CN,US" {
		t.Fatalf("geo not canonical: %+v", rules[1].Geo)
	}
	if !bytes.Contains(bundle.Files[L4RuntimeV2ArtifactPath], []byte(`"guard_rules":[{"id":"`+guardRuleB+`","action":"ban","first_packet":{"match":"prefix_hex","value":"16030100"}`)) {
		t.Fatalf("guard_rules wire shape changed: %s", bundle.Files[L4RuntimeV2ArtifactPath])
	}
	if !L4GuardRulesUsed(set.Streams[0]) || !L4StreamsUseIPIntel(set.Streams) {
		t.Fatal("guard rule predicates")
	}
	if L4GuardRulesUseIPIntel(rules[:1]) {
		t.Fatal("a rule without geo reported IP intelligence")
	}
}

func TestL4GuardRulesRejectInvalid(t *testing.T) {
	valid := func() L4GuardRuleV2 {
		return L4GuardRuleV2{ID: guardRuleA, Action: L4GuardActionDrop, ClientIP: &L4GuardClientIP{CIDRs: []string{"192.0.2.0/24"}}}
	}
	many := make([]string, L4GuardCIDRsPerRuleMax+1)
	for index := range many {
		many[index] = fmt.Sprintf("10.%d.%d.0/24", index/256, index%256)
	}
	cases := map[string]func(*L4GuardRuleV2){
		"bad id":               func(rule *L4GuardRuleV2) { rule.ID = "rule-1" },
		"unknown action":       func(rule *L4GuardRuleV2) { rule.Action = "reject" },
		"no condition":         func(rule *L4GuardRuleV2) { rule.ClientIP = nil },
		"drop with ban":        func(rule *L4GuardRuleV2) { rule.BanSeconds = 60 },
		"allow with threshold": func(rule *L4GuardRuleV2) { rule.Action = L4GuardActionAllow; rule.Threshold = 2 },
		"ban without seconds":  func(rule *L4GuardRuleV2) { rule.Action = L4GuardActionBan; rule.Threshold = 1 },
		"ban without threshold": func(rule *L4GuardRuleV2) {
			rule.Action, rule.BanSeconds = L4GuardActionBan, 60
		},
		"threshold without window": func(rule *L4GuardRuleV2) {
			rule.Action, rule.BanSeconds, rule.Threshold = L4GuardActionBan, 60, 5
		},
		"window with threshold 1": func(rule *L4GuardRuleV2) {
			rule.Action, rule.BanSeconds, rule.Threshold, rule.WindowSeconds = L4GuardActionBan, 60, 1, 60
		},
		"ban too long": func(rule *L4GuardRuleV2) {
			rule.Action, rule.BanSeconds, rule.Threshold = L4GuardActionBan, L4GuardBanSecondsMax+1, 1
		},
		"window too long": func(rule *L4GuardRuleV2) {
			rule.Action, rule.BanSeconds, rule.Threshold, rule.WindowSeconds = L4GuardActionBan, 60, 2, L4GuardWindowMax+1
		},
		"unmasked cidr":       func(rule *L4GuardRuleV2) { rule.ClientIP.CIDRs = []string{"192.0.2.1/24"} },
		"duplicate cidr":      func(rule *L4GuardRuleV2) { rule.ClientIP.CIDRs = []string{"192.0.2.0/24", "192.0.2.0/24"} },
		"mapped cidr":         func(rule *L4GuardRuleV2) { rule.ClientIP.CIDRs = []string{"::ffff:192.0.2.0/120"} },
		"empty cidrs":         func(rule *L4GuardRuleV2) { rule.ClientIP.CIDRs = nil },
		"too many cidrs":      func(rule *L4GuardRuleV2) { rule.ClientIP.CIDRs = many },
		"sni not passthrough": func(rule *L4GuardRuleV2) { rule.ServerNames = []string{"a.example.com"} },
		"hex odd": func(rule *L4GuardRuleV2) {
			rule.FirstPacket = &L4GuardFirstPacket{Match: L4GuardMatchPrefixHex, Value: "160"}
		},
		"hex upper": func(rule *L4GuardRuleV2) {
			rule.FirstPacket = &L4GuardFirstPacket{Match: L4GuardMatchPrefixHex, Value: "AB"}
		},
		"hex long": func(rule *L4GuardRuleV2) {
			rule.FirstPacket = &L4GuardFirstPacket{Match: L4GuardMatchPrefixHex, Value: strings.Repeat("ab", L4GuardPrefixBytesMax+1)}
		},
		"contains empty": func(rule *L4GuardRuleV2) { rule.FirstPacket = &L4GuardFirstPacket{Match: L4GuardMatchContains} },
		"contains long": func(rule *L4GuardRuleV2) {
			rule.FirstPacket = &L4GuardFirstPacket{Match: L4GuardMatchContains, Value: strings.Repeat("a", L4GuardContainsMax+1)}
		},
		"regex invalid": func(rule *L4GuardRuleV2) {
			rule.FirstPacket = &L4GuardFirstPacket{Match: L4GuardMatchRegex, Value: "(a"}
		},
		"regex long": func(rule *L4GuardRuleV2) {
			rule.FirstPacket = &L4GuardFirstPacket{Match: L4GuardMatchRegex, Value: strings.Repeat("a", L4GuardRegexMax+1)}
		},
		"regex unicode class": func(rule *L4GuardRuleV2) {
			rule.FirstPacket = &L4GuardFirstPacket{Match: L4GuardMatchRegex, Value: `\pL+`}
		},
		"unknown match": func(rule *L4GuardRuleV2) { rule.FirstPacket = &L4GuardFirstPacket{Match: "suffix", Value: "a"} },
		"geo bad value": func(rule *L4GuardRuleV2) { rule.Geo = []WAFIPIntel{{Field: WAFIPIntelCountry, Values: []string{"cn"}}} },
		"geo empty":     func(rule *L4GuardRuleV2) { rule.Geo = []WAFIPIntel{} },
	}
	for name, change := range cases {
		t.Run(name, func(t *testing.T) {
			spec := multiListenerBundleSpec()
			rule := valid()
			change(&rule)
			spec.L4StreamsV2[0].GuardRules = []L4GuardRuleV2{rule}
			if _, err := buildStreams(spec); !errors.Is(err, ErrInvalidConfig) {
				t.Fatalf("accepted: %v", err)
			}
		})
	}
	t.Run("duplicate ids", func(t *testing.T) {
		spec := multiListenerBundleSpec()
		spec.L4StreamsV2[0].GuardRules = []L4GuardRuleV2{valid(), valid()}
		if _, err := buildStreams(spec); !errors.Is(err, ErrInvalidConfig) {
			t.Fatalf("accepted: %v", err)
		}
	})
	t.Run("too many rules", func(t *testing.T) {
		rules := make([]L4GuardRuleV2, L4GuardRulesMax+1)
		for index := range rules {
			rules[index] = valid()
			rules[index].ID = fmt.Sprintf("66666666-6666-4666-8666-%012d", index)
		}
		if _, err := NormalizeL4GuardRules(rules, false); !errors.Is(err, ErrInvalidConfig) {
			t.Fatalf("accepted %d rules: %v", len(rules), err)
		}
		if _, err := NormalizeL4GuardRules(rules[:L4GuardRulesMax], false); err != nil {
			t.Fatalf("%d rules refused: %v", L4GuardRulesMax, err)
		}
	})
	t.Run("too many cidrs in total", func(t *testing.T) {
		rules := make([]L4GuardRuleV2, 5)
		for index := range rules {
			rules[index] = valid()
			rules[index].ID = fmt.Sprintf("66666666-6666-4666-8666-%012d", index)
			cidrs := make([]string, 900)
			for item := range cidrs {
				cidrs[item] = fmt.Sprintf("10.%d.%d.0/24", item/256, item%256)
			}
			rules[index].ClientIP = &L4GuardClientIP{CIDRs: cidrs}
		}
		if _, err := NormalizeL4GuardRules(rules, false); !errors.Is(err, ErrInvalidConfig) {
			t.Fatalf("accepted 4500 CIDRs: %v", err)
		}
		if _, err := NormalizeL4GuardRules(rules[:4], false); err != nil {
			t.Fatalf("3600 CIDRs refused: %v", err)
		}
	})
}

// Valid matches of each kind, and SNI on a passthrough stream.
func TestL4GuardRulesAcceptEachCondition(t *testing.T) {
	for name, rule := range map[string]L4GuardRuleV2{
		"contains": {ID: guardRuleA, Action: L4GuardActionDrop, FirstPacket: &L4GuardFirstPacket{Match: L4GuardMatchContains, Value: "GET /admin"}},
		"regex":    {ID: guardRuleA, Action: L4GuardActionAllow, FirstPacket: &L4GuardFirstPacket{Match: L4GuardMatchRegex, Value: `^SSH-2\.0-(?i:openssh)`}},
		"ban once": {ID: guardRuleA, Action: L4GuardActionBan, BanSeconds: 1, Threshold: 1, ClientIP: &L4GuardClientIP{CIDRs: []string{"0.0.0.0/0"}, Negate: true}},
		"geo":      {ID: guardRuleA, Action: L4GuardActionDrop, Geo: []WAFIPIntel{{Field: WAFIPIntelTag, Negate: true, Values: []string{"carrier:cn-telecom"}}}},
	} {
		if _, err := NormalizeL4GuardRules([]L4GuardRuleV2{rule}, false); err != nil {
			t.Fatalf("%s refused: %v", name, err)
		}
	}
	names, err := NormalizeL4GuardRules([]L4GuardRuleV2{{ID: guardRuleA, Action: L4GuardActionDrop,
		ServerNames: []string{"b.example.com", "*.example.com"}}}, true)
	if err != nil || strings.Join(names[0].ServerNames, ",") != "*.example.com,b.example.com" {
		t.Fatalf("server names: %+v %v", names, err)
	}
	if _, err := NormalizeL4GuardRules([]L4GuardRuleV2{{ID: guardRuleA, Action: L4GuardActionDrop,
		ServerNames: []string{"Example.com"}}}, true); !errors.Is(err, ErrInvalidConfig) {
		t.Fatalf("non-canonical server name accepted: %v", err)
	}
}
