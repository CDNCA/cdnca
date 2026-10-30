package edgeconfig

import (
	"strings"
	"testing"
)

func countByCCV2Policy(countBy []CCV2CountKey, target CCV2ActionTarget) CCV2Policy {
	policy := testCCV2Policy("aaaaaaaa-aaaa-4aaa-8aaa-aaaaaaaaaaaa", "11111111-1111-4111-8111-111111111111")
	policy.Rules[0].Flow = CCV2FlowStop
	policy.Rules[0].Action = CCV2Action{Kind: CCV2ActionTemporaryBan, BanSeconds: 60, Target: target}
	policy.Rules[0].CountBy = countBy
	return policy
}

func TestCCV2CountByEncodesOnlyWhenSetAndNeedsCCV4(t *testing.T) {
	plain := countByCCV2Policy(nil, "")
	encoded, err := CanonicalCCV2Policy(plain)
	if err != nil {
		t.Fatal(err)
	}
	if strings.Contains(string(encoded), "count_by") || strings.Contains(string(encoded), "target") ||
		CCV2PolicyCountsByKey(plain) || CCV2PolicyAPIVersion(plain) != 2 {
		t.Fatalf("default policy changed: %s", encoded)
	}
	counted := countByCCV2Policy([]CCV2CountKey{{Key: CCV2CountClientCIDR, IPv4Prefix: 24, IPv6Prefix: 64},
		{Key: CCV2CountURI}}, CCV2ActionTargetCountKey)
	encoded, err = CanonicalCCV2Policy(counted)
	if err != nil {
		t.Fatalf("count_by policy rejected: %v", err)
	}
	want := `"dimension":"client_ip","count_by":[{"key":"client_cidr","ipv4_prefix":24,"ipv6_prefix":64},{"key":"uri"}],"limit":{"algorithm":"fixed_window","requests":2,"window_seconds":60},"action":{"kind":"temporary_ban","ban_seconds":60,"target":"count_key"}`
	if !strings.Contains(string(encoded), want) {
		t.Fatalf("encoded:\n%s\nwant %s", encoded, want)
	}
	if decoded, err := DecodeCCV2Policy(encoded); err != nil || len(decoded.Rules[0].CountBy) != 2 {
		t.Fatalf("decode: %v %#v", err, decoded)
	}
	if !CCV2PolicyCountsByKey(counted) || CCV2PolicyAPIVersion(counted) != 4 {
		t.Fatal("count_by policy does not need CC v4")
	}
}

func TestCCV2CountByRejectsNonCanonicalForms(t *testing.T) {
	cases := map[string]CCV2Policy{
		"empty":           countByCCV2Policy([]CCV2CountKey{}, ""),
		"default ip":      countByCCV2Policy([]CCV2CountKey{{Key: CCV2CountClientIP}}, ""),
		"unsorted":        countByCCV2Policy([]CCV2CountKey{{Key: CCV2CountURI}, {Key: CCV2CountHost}}, ""),
		"duplicate":       countByCCV2Policy([]CCV2CountKey{{Key: CCV2CountHost}, {Key: CCV2CountHost}}, ""),
		"three":           countByCCV2Policy([]CCV2CountKey{{Key: CCV2CountClientIP}, {Key: CCV2CountHost}, {Key: CCV2CountJA4}}, ""),
		"ip and cidr":     countByCCV2Policy([]CCV2CountKey{{Key: CCV2CountClientIP}, {Key: CCV2CountClientCIDR, IPv4Prefix: 24, IPv6Prefix: 64}}, ""),
		"uri and path":    countByCCV2Policy([]CCV2CountKey{{Key: CCV2CountURI}, {Key: CCV2CountURIPath}}, ""),
		"cidr no prefix":  countByCCV2Policy([]CCV2CountKey{{Key: CCV2CountClientCIDR}}, ""),
		"cidr prefix big": countByCCV2Policy([]CCV2CountKey{{Key: CCV2CountClientCIDR, IPv4Prefix: 33, IPv6Prefix: 64}}, ""),
		"host prefix":     countByCCV2Policy([]CCV2CountKey{{Key: CCV2CountHost, IPv4Prefix: 24}}, ""),
		"unknown":         countByCCV2Policy([]CCV2CountKey{{Key: "ja3"}}, ""),
		"target alone":    countByCCV2Policy(nil, CCV2ActionTargetCountKey),
		"target ip":       countByCCV2Policy([]CCV2CountKey{{Key: CCV2CountJA4}}, "client_ip"),
	}
	reject := countByCCV2Policy([]CCV2CountKey{{Key: CCV2CountJA4}}, CCV2ActionTargetCountKey)
	reject.Rules[0].Action = CCV2Action{Kind: CCV2ActionReject429, Target: CCV2ActionTargetCountKey}
	cases["target on reject"] = reject
	always := countByCCV2Policy([]CCV2CountKey{{Key: CCV2CountHost}}, "")
	always.Rules[0].Limit = CCV2Limit{Algorithm: CCV2AlgorithmAlways}
	always.Rules[0].Action = CCV2Action{Kind: CCV2ActionChallenge, BanSeconds: 60, Challenge: &CCV2Challenge{Mode: "js",
		FailureWindowSeconds: 60, MaxFailures: 5, PassSeconds: 3600, PowBits: 16, ChallengeSeconds: 120,
		BindIPv4Prefix: 24, BindIPv6Prefix: 64, KeyRotateSeconds: 86400}}
	cases["challenge always"] = always
	stats := countByCCV2Policy([]CCV2CountKey{{Key: CCV2CountHost}}, "")
	stats.Rules[0].Match.DistinctUserAgents = 3
	cases["distinct ua"] = stats
	for name, policy := range cases {
		t.Run(name, func(t *testing.T) {
			if _, err := CanonicalCCV2Policy(policy); err == nil {
				t.Fatal("accepted")
			}
		})
	}
}

// fix-ja4rule ③ (CC_MATCH_KEYS v1): counting by User-Agent, Referer and a
// named header / cookie / query argument, and rules matching on JA4.
func TestCCV2MatchKeysCountByAndJA4Match(t *testing.T) {
	counted := countByCCV2Policy([]CCV2CountKey{{Key: CCV2CountJA4}, {Key: CCV2CountHeader, Name: "x-api-key"}}, CCV2ActionTargetCountKey)
	encoded, err := CanonicalCCV2Policy(counted)
	if err != nil {
		t.Fatalf("header count_by rejected: %v", err)
	}
	if !strings.Contains(string(encoded), `"count_by":[{"key":"ja4"},{"key":"header","name":"x-api-key"}]`) {
		t.Fatalf("encoded %s", encoded)
	}
	if !CCV2PolicyNeedsMatchKeys(counted) || CCV2PolicyNeedsMatchKeys(countByCCV2Policy([]CCV2CountKey{{Key: CCV2CountJA4}}, "")) {
		t.Fatal("CCV2PolicyNeedsMatchKeys wrong")
	}
	if !CCV2PolicyCountsByJA4(counted) {
		t.Fatal("ja4 count key must still need JA4")
	}
	for _, keys := range [][]CCV2CountKey{{{Key: CCV2CountUserAgent}}, {{Key: CCV2CountReferer}}, {{Key: CCV2CountURIPath}, {Key: CCV2CountCookie, Name: "sid"}},
		{{Key: CCV2CountQuery, Name: "token"}}, {{Key: CCV2CountUserAgent}, {Key: CCV2CountReferer}}} {
		if _, err := CanonicalCCV2Policy(countByCCV2Policy(keys, "")); err != nil {
			t.Errorf("%v rejected: %v", keys, err)
		}
	}
	for name, keys := range map[string][]CCV2CountKey{
		"header no name":    {{Key: CCV2CountHeader}},
		"header upper":      {{Key: CCV2CountHeader, Name: "X-Api-Key"}},
		"cookie bad name":   {{Key: CCV2CountCookie, Name: "a b"}},
		"ua with name":      {{Key: CCV2CountUserAgent, Name: "x"}},
		"ja4 with name":     {{Key: CCV2CountJA4, Name: "x"}},
		"two headers":       {{Key: CCV2CountHeader, Name: "a"}, {Key: CCV2CountHeader, Name: "b"}},
		"unsorted new keys": {{Key: CCV2CountReferer}, {Key: CCV2CountUserAgent}},
	} {
		if _, err := CanonicalCCV2Policy(countByCCV2Policy(keys, "")); err == nil {
			t.Errorf("%s accepted", name)
		}
	}
	matched := countByCCV2Policy(nil, "")
	matched.Rules[0].Match.JA4 = []string{"t13d3112h2_e8f1e7e78f70_6bebaf5329ac", "t13d1516h2_8daaf6152771_e5627efa2ab1"}
	if _, err := CanonicalCCV2Policy(matched); err == nil {
		t.Fatal("unsorted ja4 match accepted")
	}
	matched.Rules[0].Match.JA4 = []string{"t13d1516h2_8daaf6152771_e5627efa2ab1", "t13d3112h2_e8f1e7e78f70_6bebaf5329ac"}
	if _, err := CanonicalCCV2Policy(matched); err != nil {
		t.Fatalf("ja4 match rejected: %v", err)
	}
	if !CCV2PolicyNeedsMatchKeys(matched) || !CCV2PolicyUsesJA4(matched) || CCV2PolicyAPIVersion(matched) != 7 {
		t.Fatalf("ja4 match needs CC_MATCH_KEYS + JA4, CC v7 (got v%d)", CCV2PolicyAPIVersion(matched))
	}
	matched.Rules[0].Match.JA4 = []string{"forged"}
	if _, err := CanonicalCCV2Policy(matched); err == nil {
		t.Fatal("malformed ja4 match accepted")
	}
}
