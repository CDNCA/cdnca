package edgeconfig

import (
	"regexp"
	"sort"
	"strconv"
	"strings"
)

// JA4Variable is the nginx variable the native OpenResty module
// ngx_http_cdnca_ja4_module (edge/openresty/native/ja4) sets to the JA4 TLS
// client fingerprint of the connection's ClientHello. It is empty for plain
// HTTP and HTTP/3 (QUIC) requests and on runtimes without the module.
const JA4Variable = "cdnca_ja4"

// MaxWAFJA4Values bounds one rule's JA4 set (equals or in).
const MaxWAFJA4Values = 64

// JA4Pattern is the exact shape the module emits: protocol t/q/d, a TLS
// version code, d/i, two 2-digit counts, the two ALPN marker characters and
// the two 12-hex truncated SHA-256 sections.
var JA4Pattern = regexp.MustCompile(`^[tqd](?:1[0-3]|s[23]|d[1-3]|00)[di][0-9]{4}[0-9A-Za-z]{2}_[0-9a-f]{12}_[0-9a-f]{12}$`)

// ValidJA4 reports whether value is one JA4 fingerprint as the node emits it.
func ValidJA4(value string) bool { return JA4Pattern.MatchString(value) }

// normalizeWAFJA4 sorts and de-duplicates a rule's JA4 set; nil means the
// rule does not look at the fingerprint.
func normalizeWAFJA4(values []string) ([]string, error) {
	if values == nil {
		return nil, nil
	}
	if len(values) == 0 || len(values) > MaxWAFJA4Values {
		return nil, ErrInvalidConfig
	}
	result := append([]string(nil), values...)
	sort.Strings(result)
	for index, value := range result {
		if !ValidJA4(value) || index > 0 && value == result[index-1] {
			return nil, ErrInvalidConfig
		}
	}
	return result, nil
}

// NormalizeWAFJA4 validates a JA4 set the way the renderer does, so the node
// precheck can independently re-derive the rendered condition.
func NormalizeWAFJA4(values []string) ([]string, error) { return normalizeWAFJA4(values) }

// RenderWAFJA4Condition is the Lua condition for a JA4 set: the request's
// fingerprint equals one of the values. A request without a fingerprint
// (plain HTTP, HTTP/3) never matches.
func RenderWAFJA4Condition(values []string) string {
	variable := "ngx.var." + JA4Variable
	if len(values) == 1 {
		return variable + " == " + strconv.Quote(values[0])
	}
	quoted := make([]string, len(values))
	for index, value := range values {
		quoted[index] = "[" + strconv.Quote(value) + "]=true"
	}
	return "({" + strings.Join(quoted, ",") + "})[" + variable + " or \"\"] == true"
}

// RenderWAFNotJA4Condition is the Lua condition for a negated JA4 set: the
// request has a fingerprint and it is none of the values. A request without
// one (plain HTTP, HTTP/3) never matches: a rule "not this tool" must not
// catch every plaintext request.
func RenderWAFNotJA4Condition(values []string) string {
	variable := "ngx.var." + JA4Variable
	present := "(" + variable + " or \"\") ~= \"\""
	if len(values) == 1 {
		return present + " and " + variable + " ~= " + strconv.Quote(values[0])
	}
	quoted := make([]string, len(values))
	for index, value := range values {
		quoted[index] = "[" + strconv.Quote(value) + "]=true"
	}
	return present + " and ({" + strings.Join(quoted, ",") + "})[" + variable + "] ~= true"
}

// JA4NegationAPIVersion is CAPABILITY_NAME_WAF_JA4_NEGATION v1: the node
// runs WAFMatch.NotJA4 (rule plan op ja4_not_in).
const JA4NegationAPIVersion uint32 = 1

// WAFJA4NegationCapability / CCMatchKeysCapability are the site runtime v2
// document names of CAPABILITY_NAME_WAF_JA4_NEGATION and
// CAPABILITY_NAME_CC_MATCH_KEYS (siteobject.RuntimeCapabilityNames).
const (
	WAFJA4NegationCapability = "waf_ja4_negation"
	CCMatchKeysCapability    = "cc_match_keys"
)

// ListenerSecurityUsesJA4Negation reports a site runtime v2 listener with a
// WAF rule on NotJA4.
func ListenerSecurityUsesJA4Negation(security *ListenerSecurity) bool {
	return security != nil && SecurityPoliciesUseJA4Negation(security.Policies)
}

// SecurityPoliciesUseJA4Negation reports a bound rule with NotJA4.
func SecurityPoliciesUseJA4Negation(policies []SecurityPolicy) bool {
	for _, policy := range policies {
		for _, rule := range policy.Rules {
			if rule.Match.NotJA4 != nil {
				return true
			}
		}
	}
	return false
}

// WAFJA4Covers reports whether every request a rule with JA4 set current can
// match is also matched by the JA4 set previous (nil = any fingerprint).
func WAFJA4Covers(previous, current []string) bool {
	if previous == nil {
		return true
	}
	if current == nil {
		return false
	}
	for _, value := range current {
		if index := sort.SearchStrings(previous, value); index == len(previous) || previous[index] != value {
			return false
		}
	}
	return true
}

// SpecUsesJA4 reports whether any bound security rule of the sites matches
// on the JA4 fingerprint (a release that needs CAPABILITY_NAME_JA4).
func SpecUsesJA4(sites []Site) bool {
	for _, site := range sites {
		if SecurityPoliciesUseJA4(site.SecurityPolicies) {
			return true
		}
	}
	return false
}

// SecurityPoliciesUseJA4 is SpecUsesJA4 for one listener's policies.
func SecurityPoliciesUseJA4(policies []SecurityPolicy) bool {
	for _, policy := range policies {
		for _, rule := range policy.Rules {
			if rule.Match.JA4 != nil || rule.Match.NotJA4 != nil {
				return true
			}
		}
	}
	return false
}

// CCV2PolicyCountsByJA4 reports a CC policy counting by TLS fingerprint: it
// reads $cdnca_ja4, so the node needs CAPABILITY_NAME_JA4 as well as CC v4.
func CCV2PolicyCountsByJA4(policy CCV2Policy) bool {
	return CCV2PolicyUsesJA4(policy)
}

// CCV2PolicyUsesJA4 reports a CC policy that counts by, or (CC v7) matches
// on, the TLS fingerprint: the node needs CAPABILITY_NAME_JA4.
func CCV2PolicyUsesJA4(policy CCV2Policy) bool {
	for _, rule := range CCV2PolicyRules(policy) {
		if rule.Match.JA4 != nil {
			return true
		}
		for _, key := range rule.CountBy {
			if key.Key == CCV2CountJA4 {
				return true
			}
		}
	}
	return false
}

// ListenerSecurityUsesJA4 reports a site runtime v2 listener whose WAF rules
// match on, or whose CC rules count by, the JA4 fingerprint.
func ListenerSecurityUsesJA4(security *ListenerSecurity) bool {
	return security != nil && (SecurityPoliciesUseJA4(security.Policies) ||
		security.CC != nil && CCV2PolicyUsesJA4(security.CC.Policy))
}
