package edgeconfig

import (
	"errors"
	"fmt"
	"reflect"
	"strings"
	"testing"
)

func ipIntelSecurityPolicy(conditions ...WAFIPIntel) SecurityPolicy {
	policy := ja4SecurityPolicy(testJA4Chrome)
	policy.Rules[0].Match = WAFMatch{IPIntel: conditions}
	return policy
}

func TestRenderWAFIPIntelRegions(t *testing.T) {
	for condition, want := range map[*WAFIPIntel]string{
		{Field: WAFIPIntelProvince, Values: []string{"440000"}}:                     `require("cdnca_iplib").match("province=440000")`,
		{Field: WAFIPIntelCity, Negate: true, Values: []string{"429004", "440300"}}: `require("cdnca_iplib").match("city!=429004,440300")`,
		{Field: WAFIPIntelTag, Values: []string{"idc:cn"}}:                          `require("cdnca_iplib").match("tag=0000000000010000")`,
	} {
		if got := RenderWAFIPIntelCondition(*condition); got != want {
			t.Errorf("render %+v = %s, want %s", *condition, got, want)
		}
	}
}

func TestBoundSecurityIPIntelRejectsInvalidConditions(t *testing.T) {
	tooMany := make([]string, MaxWAFIPIntelValues+1)
	for index := range tooMany {
		tooMany[index] = fmt.Sprint(index + 1)
	}
	for name, conditions := range map[string][]WAFIPIntel{
		"empty list":          {},
		"no values":           {{Field: WAFIPIntelCountry}},
		"unknown field":       {{Field: "carrier", Values: []string{"cn-telecom"}}},
		"unknown tag":         {{Field: WAFIPIntelTag, Values: []string{"carrier:cn-other"}}},
		"tag without prefix":  {{Field: WAFIPIntelTag, Values: []string{"cn-telecom"}}},
		"lower country":       {{Field: WAFIPIntelCountry, Values: []string{"cn"}}},
		"asn zero":            {{Field: WAFIPIntelASN, Values: []string{"0"}}},
		"asn leading zero":    {{Field: WAFIPIntelASN, Values: []string{"013335"}}},
		"asn overflow":        {{Field: WAFIPIntelASN, Values: []string{"4294967296"}}},
		"city as province":    {{Field: WAFIPIntelProvince, Values: []string{"440300"}}},
		"province as city":    {{Field: WAFIPIntelCity, Values: []string{"440000"}}},
		"short region":        {{Field: WAFIPIntelProvince, Values: []string{"44000"}}},
		"duplicate value":     {{Field: WAFIPIntelCountry, Values: []string{"CN", "CN"}}},
		"duplicate condition": {{Field: WAFIPIntelCountry, Values: []string{"CN"}}, {Field: WAFIPIntelCountry, Values: []string{"CN"}}},
		"injection":           {{Field: WAFIPIntelCountry, Values: []string{`CN") or true or ("`}}},
		"too many values":     {{Field: WAFIPIntelASN, Values: tooMany}},
		"too many conditions": {{Field: WAFIPIntelASN, Values: []string{"1"}}, {Field: WAFIPIntelASN, Values: []string{"2"}},
			{Field: WAFIPIntelASN, Values: []string{"3"}}, {Field: WAFIPIntelASN, Values: []string{"4"}}, {Field: WAFIPIntelASN, Values: []string{"5"}}},
	} {
		t.Run(name, func(t *testing.T) {
			if _, err := normalizeSecurityPolicies([]SecurityPolicy{ipIntelSecurityPolicy(conditions...)}); !errors.Is(err, ErrInvalidConfig) {
				t.Fatalf("err = %v, want ErrInvalidConfig", err)
			}
		})
	}
}

func TestLegacySiteWAFRefusesIPIntel(t *testing.T) {
	_, err := normalizeWAF(WAFPolicy{Rules: []WAFRule{{Match: WAFMatch{IPIntel: []WAFIPIntel{{Field: WAFIPIntelCountry, Values: []string{"CN"}}}},
		Action: WAFDeny, Control: WAFStop}}})
	if !errors.Is(err, ErrInvalidConfig) {
		t.Fatalf("legacy WAF with IP intelligence err = %v, want ErrInvalidConfig", err)
	}
}

func TestWAFIPIntelCovers(t *testing.T) {
	telecom := WAFIPIntel{Field: WAFIPIntelTag, Values: []string{"carrier:cn-telecom"}}
	carriers := WAFIPIntel{Field: WAFIPIntelTag, Values: []string{"carrier:cn-telecom", "carrier:cn-unicom"}}
	notCN := WAFIPIntel{Field: WAFIPIntelCountry, Negate: true, Values: []string{"CN"}}
	notCNUS := WAFIPIntel{Field: WAFIPIntelCountry, Negate: true, Values: []string{"CN", "US"}}
	for name, test := range map[string]struct {
		previous, current []WAFIPIntel
		covers            bool
	}{
		"no previous condition":        {nil, []WAFIPIntel{telecom}, true},
		"previous only":                {[]WAFIPIntel{telecom}, nil, false},
		"wider set covers":             {[]WAFIPIntel{carriers}, []WAFIPIntel{telecom}, true},
		"narrower set does not":        {[]WAFIPIntel{telecom}, []WAFIPIntel{carriers}, false},
		"negated fewer covers more":    {[]WAFIPIntel{notCN}, []WAFIPIntel{notCNUS}, true},
		"negated more does not":        {[]WAFIPIntel{notCNUS}, []WAFIPIntel{notCN}, false},
		"other sense does not":         {[]WAFIPIntel{notCN}, []WAFIPIntel{{Field: WAFIPIntelCountry, Values: []string{"US"}}}, false},
		"extra current condition ok":   {[]WAFIPIntel{telecom}, []WAFIPIntel{telecom, notCN}, true},
		"every previous one is needed": {[]WAFIPIntel{telecom, notCN}, []WAFIPIntel{telecom}, false},
	} {
		if got := WAFIPIntelCovers(test.previous, test.current); got != test.covers {
			t.Errorf("%s: covers = %v", name, got)
		}
	}
}

func TestIPIntelTagNamesFollowBits(t *testing.T) {
	names := IPIntelTagNames()
	if len(names) != 9 || names[0] != "carrier:cn-telecom" || names[6] != "carrier:cn-cbn" || names[8] != "idc:global" {
		t.Fatalf("tag names = %v", names)
	}
}

func TestSecurityFragmentsIPIntelAddsSecurityLuaPath(t *testing.T) {
	listener := SecurityListener{SiteID: "bbbbbbbb-bbbb-4bbb-8bbb-bbbbbbbbbbbb", Domain: "ip.example.test", Port: 80, Protocol: ProtocolHTTP,
		Security: ListenerSecurity{Policies: []SecurityPolicy{ipIntelSecurityPolicy(WAFIPIntel{Field: WAFIPIntelTag, Values: []string{"idc:cn"}})}}}
	fragments, err := RenderSecurityFragments("aaaaaaaa-aaaa-4aaa-8aaa-aaaaaaaaaaaa", "v1", []SecurityListener{listener})
	if err != nil {
		t.Fatal(err)
	}
	if !fragments.NeedsCC || !strings.Contains(fragments.Location[0], `require("cdnca_iplib").match("tag=0000000000010000")`) {
		t.Fatalf("fragments = %+v", fragments)
	}
}

func TestIPIntelPolicyCondition(t *testing.T) {
	for name, test := range map[string]struct {
		field, operator string
		values          []string
		want            WAFIPIntel
	}{
		"carrier in":      {"carrier", "in", []string{"carrier:cn-unicom", "carrier:cn-telecom"}, WAFIPIntel{Field: WAFIPIntelTag, Values: []string{"carrier:cn-telecom", "carrier:cn-unicom"}}},
		"idc equals":      {"ip_tag", "equals", []string{"idc:cn"}, WAFIPIntel{Field: WAFIPIntelTag, Values: []string{"idc:cn"}}},
		"asn number_eq":   {"asn", "number_eq", []string{"13335"}, WAFIPIntel{Field: WAFIPIntelASN, Values: []string{"13335"}}},
		"asn not_in":      {"asn", "not_in", []string{"4134", "45"}, WAFIPIntel{Field: WAFIPIntelASN, Negate: true, Values: []string{"45", "4134"}}},
		"country not_eq":  {"country", "not_equals", []string{"CN"}, WAFIPIntel{Field: WAFIPIntelCountry, Negate: true, Values: []string{"CN"}}},
		"province equals": {"province", "equals", []string{"440000"}, WAFIPIntel{Field: WAFIPIntelProvince, Values: []string{"440000"}}},
		"city in":         {"city", "in", []string{"440300", "110100"}, WAFIPIntel{Field: WAFIPIntelCity, Values: []string{"110100", "440300"}}},
	} {
		got, ok, err := IPIntelPolicyCondition(test.field, test.operator, "", test.values)
		if !ok || err != nil || !reflect.DeepEqual(got, test.want) {
			t.Errorf("%s: %#v %v %v", name, got, ok, err)
		}
	}
	if _, ok, _ := IPIntelPolicyCondition("path", "equals", "", []string{"/"}); ok {
		t.Fatal("path is not an IP intelligence field")
	}
	for name, test := range map[string]struct {
		field, operator, key string
		values               []string
	}{
		"carrier given idc":     {"carrier", "in", "", []string{"idc:cn"}},
		"idc given carrier":     {"ip_tag", "in", "", []string{"carrier:cn-telecom"}},
		"bare carrier":          {"carrier", "equals", "", []string{"cn-telecom"}},
		"equals two values":     {"country", "equals", "", []string{"CN", "US"}},
		"number_eq on country":  {"country", "number_eq", "", []string{"CN"}},
		"asn range operator":    {"asn", "number_gte", "", []string{"100"}},
		"asn zero":              {"asn", "equals", "", []string{"0"}},
		"keyed":                 {"country", "equals", "x", []string{"CN"}},
		"prefix":                {"country", "prefix", "", []string{"C"}},
		"no values":             {"country", "in", "", nil},
		"duplicate value":       {"country", "in", "", []string{"CN", "CN"}},
		"province code as city": {"city", "equals", "", []string{"440000"}},
	} {
		if _, ok, err := IPIntelPolicyCondition(test.field, test.operator, test.key, test.values); !ok || !errors.Is(err, ErrInvalidConfig) {
			t.Errorf("%s: ok=%v err=%v, want ErrInvalidConfig", name, ok, err)
		}
	}
}
