package edgeconfig

// Generator of the rule plan differential test (rule_plan_diff_integration_test.go):
// random security rule sets x random requests, compiled two ways - the
// rendered rewrite Lua (renderWAF, the oracle) and the plan the interpreter
// runs. Kept outside the integration tag so the unit tests below exercise it.

import (
	"encoding/json"
	"fmt"
	"math/rand/v2"
	"net/netip"
	"net/url"
	"sort"
	"strconv"
	"strings"
	"testing"
)

type fuzzRuleset struct {
	Layered        bool                   `json:"layered"`
	OverflowBlocks bool                   `json:"overflow_blocks"`
	Telemetry      bool                   `json:"telemetry"`
	Policies       []SecurityPolicy       `json:"policies,omitempty"`
	Segments       []RulePlanSegmentInput `json:"segments,omitempty"`
}

type fuzzHeader struct {
	Name  string `json:"name"`
	Value string `json:"value"`
}

type fuzzRequest struct {
	Port        int          `json:"port"`
	Method      string       `json:"method"`
	Target      string       `json:"target"`
	Host        string       `json:"host"`
	RealIP      string       `json:"real_ip,omitempty"`
	JA4         string       `json:"ja4,omitempty"`
	Headers     []fuzzHeader `json:"headers,omitempty"`
	Filler      int          `json:"filler,omitempty"`
	ContentType string       `json:"content_type,omitempty"`
	Body        string       `json:"body,omitempty"`
	// HTTP10: the request line says HTTP/1.0 (ge36-waf http_version).
	HTTP10 bool `json:"http10,omitempty"`
}

const fuzzBasePort = 18080

// fuzzSiteID is the site of every generated rule set (WAF v2 ban scope).
const fuzzSiteID = "5ee00000-0000-4000-8000-000000000001"

var (
	fuzzHosts   = []string{"a.example.com", "b.example.com", "api.example.net", "x.test"}
	fuzzPorts   = []uint16{fuzzBasePort, fuzzBasePort + 1, fuzzBasePort + 2, 443}
	fuzzMethods = []string{"GET", "POST", "PUT", "DELETE", "PATCH", "OPTIONS"}
	fuzzPaths   = []WAFPathMatch{
		{Kind: WAFPathExact, Value: "/"}, {Kind: WAFPathExact, Value: "/login"}, {Kind: WAFPathExact, Value: "/api/v1"},
		{Kind: WAFPathPrefix, Value: "/api"}, {Kind: WAFPathPrefix, Value: "/admin"}, {Kind: WAFPathPrefix, Value: "/static/img"},
		{Kind: WAFPathRawPrefix, Value: "/api"}, {Kind: WAFPathRawPrefix, Value: "/ad"}, {Kind: WAFPathRawPrefix, Value: "/s"},
	}
	fuzzHeaderRules = []WAFHeaderMatch{
		{Name: "x-token", Kind: WAFHeaderExists}, {Name: "x-token", Kind: WAFHeaderExact, Value: "secret"},
		{Name: "user-agent", Kind: WAFHeaderExact, Value: "curl/8.0"}, {Name: "x-forwarded-for", Kind: WAFHeaderExists},
		{Name: "Referer", Kind: WAFHeaderExact, Value: "https://evil.test/"}, {Name: "cookie", Kind: WAFHeaderExists},
		{Name: "x-debug", Kind: WAFHeaderExact, Value: "1"},
	}
	fuzzCIDRs = []string{
		"10.0.0.0/8", "10.1.0.0/16", "10.1.2.3/32", "192.0.2.0/24", "198.51.100.128/25", "203.0.113.7/32", "0.0.0.0/0",
		"172.16.0.0/12", "2001:db8::/32", "2001:db8:1::/48", "2001:db8::1/128", "::/0", "fd00::/8", "2001:db8:abcd:12::/64",
	}
	fuzzJA4s = []string{
		"t13d1516h2_8daaf6152771_b0da82dd1658", "t13d1517h2_8daaf6152771_e5627efa2ab1",
		"t12d1209h1_d34a8e72043a_b39be8c56a14", "q13d0310h3_55b375c5d22e_cd85d2d88918",
	}
	fuzzIPIntel = map[WAFIPIntelField][]string{
		WAFIPIntelTag:     {"carrier:cn-telecom", "carrier:cn-unicom", "idc:cn", "idc:global"},
		WAFIPIntelCountry: {"CN", "US", "JP"},
		WAFIPIntelASN:     {"4134", "13335", "16509"},
	}
	fuzzInspects = []WAFInspect{
		{Target: "args", Operator: "contains", Values: []string{"select"}},
		{Target: "query", Operator: "contains", Values: []string{"<script", "1=1"}},
		{Target: "body", Operator: "contains", Values: []string{"admin"}},
		{Target: "path", Operator: "regex", Values: []string{`\.(php|asp)$`}},
		{Target: "request_uri", Operator: "regex", Values: []string{`(?i)union\s+select`}},
		{Target: "header", Key: "x-token", Operator: "contains", Values: []string{"evil"}},
		{Target: "cookie", Operator: "contains", Values: []string{"session=bad"}},
		{Target: "user_agent", Operator: "regex", Values: []string{"(?i)sqlmap|nikto"}},
		{Target: "referer", Operator: "contains", Values: []string{"evil.test"}},
		{Target: "args", Operator: "detect", Values: []string{"sqli"}},
		{Target: "body", Operator: "detect", Values: []string{"xss", "sqli"}},
		{Target: "args", Operator: "detect", Values: []string{"ssti", "java_deser", "php_deser"}},
		// ge-waf: named values, negated / number operators, filters, overflow.
		{Target: "query", Key: "q", Operator: "not_contains", Values: []string{"select"}},
		{Target: "body", Key: "k", Operator: "contains_all", Values: []string{"or", "1"}},
		{Target: "args", Key: "a", Operator: "equals", Values: []string{"admin"}},
		{Target: "user_agent", Operator: "eq", Values: []string{"0"}, Filters: []string{"length"}},
		{Target: "uri_length", Operator: "gt", Values: []string{"12"}},
		{Target: "header_names", Operator: "equals", Values: []string{"x-debug"}},
		{Target: "query", Operator: "contains", Values: []string{"<script"}, Filters: []string{"html_unescape", "lowercase"}},
		{Target: "body", Operator: "not_regex", Values: []string{"^ok$"}, BodyOverflow: WAFInspectBodyOverflowMatch},
		// ge36-waf W1: Content-Type and HTTP version.
		{Target: "content_type", Operator: "prefix", Values: []string{"application/json"}},
		{Target: "content_type", Operator: "regex", Values: []string{`(?i)^text/`}},
		{Target: "http_version", Operator: "equals", Values: []string{"1.0"}},
		{Target: "http_version", Operator: "not_equals", Values: []string{"1.1", "2"}},
	}
	fuzzPayloads = []string{"hello", "select name from t", "1' or '1'='1", "<script>alert(1)</script>", "admin",
		"../../etc/passwd", "union   SELECT 1", "%27%20or%201%3D1", "ok",
		"{{7*7}}", "{{name}}", "rO0ABXNyABNjb20uZXhhbXBsZS5TZXNzaW9uAAAAAAAAAAECAAB4cA%3D%3D", "O:8:%22stdClass%22:0:{}", "phar://x"}
	fuzzRealIPs = []string{"10.1.2.3", "10.1.9.9", "10.200.0.1", "192.0.2.55", "198.51.100.200", "198.51.100.5", "203.0.113.7",
		"172.20.1.1", "8.8.8.8", "2001:db8::1", "2001:db8:1::5", "2001:db8:abcd:12::99", "fd12::1", "2400:cb00::1",
		"::ffff:10.1.2.3", "::ffff:192.0.2.9", "not-an-ip", ""}
	fuzzHeaderNames = []string{"X-Token", "x-token", "X-TOKEN", "User-Agent", "X-Forwarded-For", "Referer", "Cookie", "X-Debug", "Accept"}
	fuzzHeaderVals  = []string{"secret", "curl/8.0", "https://evil.test/", "1", "evil-token", "session=bad", "a=1; session=ok", "Mozilla/5.0 sqlmap"}
)

type fuzzGenerator struct {
	rng *rand.Rand
	// actions: generate WAF v2 actions, observe mode and auto block (off for
	// the recorded golden corpus, which predates them).
	actions bool
}

func newFuzzGenerator(seed uint64) *fuzzGenerator {
	return &fuzzGenerator{rng: rand.New(rand.NewPCG(seed, seed^0x9e3779b97f4a7c15)), actions: true}
}

func (g *fuzzGenerator) chance(percent int) bool { return g.rng.IntN(100) < percent }

func pick[T any](g *fuzzGenerator, values []T) T { return values[g.rng.IntN(len(values))] }

func (g *fuzzGenerator) uuid() string {
	var raw [16]byte
	for index := range raw {
		raw[index] = byte(g.rng.UintN(256))
	}
	raw[6] = raw[6]&0x0f | 0x40
	raw[8] = raw[8]&0x3f | 0x80
	text := fmt.Sprintf("%x", raw[:])
	return text[0:8] + "-" + text[8:12] + "-" + text[12:16] + "-" + text[16:20] + "-" + text[20:32]
}

func (g *fuzzGenerator) rule() WAFRule {
	for {
		rule := WAFRule{RuleID: g.uuid(), Action: pick(g, []WAFAction{WAFAllow, WAFBlock, WAFLog, WAFLog}),
			Control: pick(g, []WAFControl{WAFContinue, WAFStop})}
		// ge-waf S3: WAF v2 challenge / ban rules.
		if g.actions && g.chance(25) {
			rule.Action = pick(g, []WAFAction{WAFChallenge, WAFBan})
			if rule.Action == WAFBan {
				rule.ActionConfig = &WAFActionConfig{BanSeconds: 60 + g.rng.IntN(600)}
			} else {
				rule.ActionConfig = &WAFActionConfig{PassSeconds: 300, PowBits: 8 + g.rng.IntN(4)}
			}
		}
		match := &rule.Match
		if g.chance(25) {
			match.Host = pick(g, fuzzHosts)
			if g.chance(20) {
				match.Host = strings.ToUpper(match.Host)
			}
		}
		if g.chance(20) {
			match.Port = pick(g, fuzzPorts)
		}
		if g.chance(30) {
			match.Method = pick(g, fuzzMethods)
			if g.chance(20) {
				match.Method = strings.ToLower(match.Method)
			}
		}
		if g.chance(45) {
			path := pick(g, fuzzPaths)
			match.Path = &path
		}
		if g.chance(25) {
			header := pick(g, fuzzHeaderRules)
			match.Header = &header
		}
		if g.chance(35) {
			match.SourceCIDR = pick(g, fuzzCIDRs)
			if g.chance(20) {
				rule.Comment = "fuzz"
			}
			if g.chance(30) {
				rule.ExpiresAt = pick(g, []string{"2001-02-03T04:05:06Z", "2099-12-31T23:59:59Z", "1970-01-01T00:00:00Z"})
			}
		}
		if g.chance(12) {
			values := map[string]bool{}
			for count := 1 + g.rng.IntN(3); count > 0; count-- {
				values[pick(g, fuzzJA4s)] = true
			}
			for value := range values {
				match.JA4 = append(match.JA4, value)
			}
			sort.Strings(match.JA4) // map order is random; keep a seed reproducible
		}
		if g.chance(12) {
			for count := 1 + g.rng.IntN(2); count > 0; count-- {
				field := pick(g, []WAFIPIntelField{WAFIPIntelTag, WAFIPIntelCountry, WAFIPIntelASN})
				pool := fuzzIPIntel[field]
				condition := WAFIPIntel{Field: field, Negate: g.chance(30)}
				for _, index := range g.rng.Perm(len(pool))[:1+g.rng.IntN(len(pool))] {
					condition.Values = append(condition.Values, pool[index])
				}
				match.IPIntel = append(match.IPIntel, condition)
			}
		}
		if g.actions && g.chance(15) {
			// ge36-waf W2: named IP lists (the same pools as source CIDRs).
			for count := 1 + g.rng.IntN(2); count > 0; count-- {
				raw := make([]string, 0, 4)
				for _, index := range g.rng.Perm(len(fuzzCIDRs))[:1+g.rng.IntN(4)] {
					raw = append(raw, fuzzCIDRs[index])
				}
				cidrs, _ := CanonicalIPListCIDRs(raw)
				match.IPLists = append(match.IPLists, WAFIPList{ListID: g.uuid(), Revision: int64(1 + g.rng.IntN(9)),
					CIDRs: cidrs, Negate: g.chance(30)})
			}
		}
		if g.chance(15) {
			for count := 1 + g.rng.IntN(2); count > 0; count-- {
				match.Inspect = append(match.Inspect, pick(g, fuzzInspects))
			}
		}
		if _, err := normalizeSecurityRule(rule); err == nil {
			return rule
		}
	}
}

func (g *fuzzGenerator) policy(kind SecurityKind, rules int) SecurityPolicy {
	policy := SecurityPolicy{Kind: kind, PolicyID: g.uuid(), PolicyVersion: int64(1 + g.rng.IntN(9)),
		BindingRevision: int64(1 + g.rng.IntN(9)), RuntimeSHA256: strings.Repeat("ab", 32),
		Enabled: !g.chance(10), DefaultAction: WAFAllow}
	if g.chance(20) {
		policy.DefaultAction = WAFBlock
	}
	for index := 0; index < rules; index++ {
		rule := g.rule()
		if kind != SecurityWAF && (rule.Action == WAFChallenge || rule.Action == WAFBan) {
			rule.Action, rule.ActionConfig = WAFBlock, nil
		}
		policy.Rules = append(policy.Rules, rule)
	}
	if kind == SecurityWAF && g.actions {
		if g.chance(15) {
			policy.Mode = WAFModeObserve
		}
		if g.chance(25) {
			policy.AutoBlock = &WAFAutoBlock{WindowSeconds: 60, HitThreshold: 1 + g.rng.IntN(2), BlockSeconds: 120}
		}
	}
	return policy
}

func (g *fuzzGenerator) ruleset(layered bool) fuzzRuleset {
	set := fuzzRuleset{Layered: layered, OverflowBlocks: g.chance(40), Telemetry: !g.chance(15)}
	if layered {
		layers := []RulePlanLayer{RulePlanLayerUser, RulePlanLayerDeveloper, RulePlanLayerSystem}
		count := 1 + g.rng.IntN(6)
		ranks := make([]int, count)
		for index := range ranks {
			ranks[index] = g.rng.IntN(3)
		}
		sort.Ints(ranks)
		for _, rank := range ranks {
			set.Segments = append(set.Segments, RulePlanSegmentInput{Layer: layers[rank],
				Policy: g.policy(pick(g, []SecurityKind{SecurityACL, SecurityWAF}), 1+g.rng.IntN(20))})
		}
		return set
	}
	kinds := [][]SecurityKind{{}, {SecurityACL}, {SecurityWAF}, {SecurityACL, SecurityWAF}, {SecurityWAF, SecurityACL}}[g.rng.IntN(5)]
	for _, kind := range kinds {
		set.Policies = append(set.Policies, g.policy(kind, g.rng.IntN(25)))
	}
	return set
}

// normalized returns the policies renderWAFBlock runs and the plan.
func (set fuzzRuleset) compile() ([]SecurityPolicy, RulePlan, error) {
	if set.Layered {
		policies, layers, err := normalizeRulePlanSegments(set.Segments)
		if err != nil {
			return nil, RulePlan{}, err
		}
		plan, err := buildRulePlan(policies, layers, set.OverflowBlocks, set.Telemetry, fuzzSiteID)
		return policies, plan, err
	}
	policies, err := normalizeSecurityPolicies(set.Policies)
	if err != nil {
		return nil, RulePlan{}, err
	}
	plan, err := CompileSiteSecurityRulePlan(fuzzSiteID, set.Policies, set.OverflowBlocks, set.Telemetry)
	return policies, plan, err
}

func (set fuzzRuleset) rules() []WAFRule {
	var rules []WAFRule
	for _, policy := range set.Policies {
		rules = append(rules, policy.Rules...)
	}
	for _, segment := range set.Segments {
		rules = append(rules, segment.Policy.Rules...)
	}
	return rules
}

// request is random, or (half the time) aimed at one rule so rules match.
func (g *fuzzGenerator) request(set fuzzRuleset) fuzzRequest {
	request := fuzzRequest{Port: fuzzBasePort + g.rng.IntN(3), Method: pick(g, []string{"GET", "GET", "POST", "PUT", "DELETE", "PROPFIND"}),
		Host: pick(g, fuzzHosts)}
	path := pick(g, []string{"/", "/login", "/api", "/api/", "/api/v1", "/apix", "/admin", "/admin/x", "/ad", "/static/img/a.png",
		"/s", "/x.php", "/index.asp", "/API/v1"})
	if g.actions && g.chance(3) {
		path = "/.cdnca/waf/verify"
	}
	query := ""
	if g.chance(30) {
		query = "?q=" + url.QueryEscape(pick(g, fuzzPayloads))
	}
	if g.chance(40) {
		request.RealIP = pick(g, fuzzRealIPs)
	}
	if g.chance(20) {
		request.JA4 = pick(g, fuzzJA4s)
	}
	for count := g.rng.IntN(4); count > 0; count-- {
		request.Headers = append(request.Headers, fuzzHeader{Name: pick(g, fuzzHeaderNames), Value: pick(g, fuzzHeaderVals)})
	}
	if rules := set.rules(); len(rules) > 0 && g.chance(55) {
		match := pick(g, rules).Match
		if match.Method != "" {
			request.Method = strings.ToUpper(match.Method)
		}
		if match.Host != "" {
			request.Host = strings.ToLower(match.Host)
		}
		if match.Port >= fuzzBasePort && match.Port < fuzzBasePort+3 {
			request.Port = int(match.Port)
		}
		if match.Path != nil {
			path = match.Path.Value
			if match.Path.Kind != WAFPathExact && g.chance(60) {
				path += pick(g, []string{"/", "/x", "x", "/deep/er"})
			}
		}
		if match.Header != nil {
			value := match.Header.Value
			if value == "" || g.chance(20) {
				value = pick(g, fuzzHeaderVals)
			}
			request.Headers = append(request.Headers, fuzzHeader{Name: match.Header.Name, Value: value})
			if g.chance(15) {
				request.Headers = append(request.Headers, fuzzHeader{Name: strings.ToUpper(match.Header.Name), Value: value})
			}
		}
		if match.SourceCIDR != "" && g.chance(85) {
			request.RealIP = fuzzAddressIn(g, match.SourceCIDR)
		}
		if match.JA4 != nil && g.chance(80) {
			request.JA4 = pick(g, match.JA4)
		}
		if match.IPLists != nil && g.chance(70) {
			request.RealIP = fuzzAddressIn(g, pick(g, pick(g, match.IPLists).CIDRs))
		}
	}
	if g.chance(15) {
		request.Host = strings.ToUpper(request.Host[:1]) + request.Host[1:] + pick(g, []string{"", ":" + strconv.Itoa(request.Port)})
	}
	if g.chance(6) {
		request.Filler = 95 + g.rng.IntN(12)
	}
	if request.Method != "GET" && request.Method != "DELETE" && g.chance(70) {
		payload := pick(g, fuzzPayloads)
		switch g.rng.IntN(3) {
		case 0:
			request.ContentType, request.Body = "application/x-www-form-urlencoded", "a="+url.QueryEscape(payload)+"&b=2"
		case 1:
			encoded, _ := json.Marshal(map[string]string{"k": payload})
			request.ContentType, request.Body = "application/json", string(encoded)
		default:
			request.ContentType, request.Body = "text/plain", payload
		}
	}
	request.Target = path + query
	if g.actions && g.chance(12) {
		request.HTTP10 = true
	}
	return request
}

func fuzzAddressIn(g *fuzzGenerator, cidr string) string {
	prefix := netip.MustParsePrefix(cidr)
	address := prefix.Addr().AsSlice()
	for bit := prefix.Bits(); bit < len(address)*8; bit++ {
		if g.chance(50) {
			address[bit/8] ^= 0x80 >> (bit % 8)
		}
	}
	parsed, _ := netip.AddrFromSlice(address)
	if parsed.Is4() && g.chance(15) {
		return "::ffff:" + parsed.String()
	}
	return parsed.String()
}

// raw is the request bytes; caseHeader selects the ruleset and mode on the
// harness server. Everything else is identical between the two modes.
func (request fuzzRequest) raw(caseHeader string) []byte {
	var out strings.Builder
	version := "1.1"
	if request.HTTP10 {
		version = "1.0"
	}
	fmt.Fprintf(&out, "%s %s HTTP/%s\r\nHost: %s\r\nX-Cdnca-Case: %s\r\nConnection: close\r\n", request.Method, request.Target, version, request.Host, caseHeader)
	if request.RealIP != "" {
		fmt.Fprintf(&out, "X-Real-IP: %s\r\n", request.RealIP)
	}
	if request.JA4 != "" {
		fmt.Fprintf(&out, "X-Test-JA4: %s\r\n", request.JA4)
	}
	for _, header := range request.Headers {
		fmt.Fprintf(&out, "%s: %s\r\n", header.Name, header.Value)
	}
	for index := 0; index < request.Filler; index++ {
		fmt.Fprintf(&out, "X-Filler-%d: %d\r\n", index, index)
	}
	if request.Body != "" {
		fmt.Fprintf(&out, "Content-Type: %s\r\nContent-Length: %d\r\n", request.ContentType, len(request.Body))
	}
	out.WriteString("\r\n")
	out.WriteString(request.Body)
	return []byte(out.String())
}

// renderCompiledRuleModule renders the oracle: renderWAF's rewrite Lua for
// the policies as a module with run(trace) (trace gets "kind:action:rule"
// per segment that reaches its verdict, as the interpreter records it), plus
// the http-level geo blocks of its source CIDR rules.
func renderCompiledRuleModule(siteIndex int, policies []SecurityPolicy, overflowBlocks, telemetry bool) (string, string) {
	var geo strings.Builder
	for policyIndex, policy := range policies {
		for ruleIndex, rule := range policy.Rules {
			if rule.Match.SourceCIDR != "" {
				fmt.Fprintf(&geo, "  geo $%s {\n    default 0;\n    %s 1;\n  }\n", securitySourceVariable(siteIndex, policyIndex, ruleIndex), rule.Match.SourceCIDR)
			}
		}
	}
	var block strings.Builder
	renderWAF(&block, siteIndex, fuzzSiteID, WAFPolicy{}, policies, overflowBlocks, telemetry)
	body := block.String()
	body = strings.TrimPrefix(body, "      rewrite_by_lua_block {\n")
	body = strings.TrimSuffix(body, "      }\n")
	for index, policy := range policies {
		marker := fmt.Sprintf("        if cdnca_security_action_%d == %q then\n", index+1, WAFBlock)
		if SecurityPolicyUsesWAFActions(policy) {
			marker = fmt.Sprintf("        if cdnca_security_action_%d ~= %q then\n", index+1, WAFAllow)
		}
		trace := fmt.Sprintf("        if trace then trace[#trace + 1] = %q .. \":\" .. cdnca_security_action_%d .. \":\" .. cdnca_security_rule_%d end\n",
			string(policy.Kind), index+1, index+1)
		body = strings.Replace(body, marker, trace+marker, 1)
	}
	return "local _M = {}\nfunction _M.run(trace)\n" + body + "end\nreturn _M\n", geo.String()
}

// The generator must produce rule sets both compilers accept, and the oracle
// must carry one trace hook per segment.
func TestRulePlanFuzzGeneratorProducesCompilableSets(t *testing.T) {
	g := newFuzzGenerator(1)
	for index := 0; index < 400; index++ {
		set := g.ruleset(index%3 == 0)
		policies, plan, err := set.compile()
		if err != nil {
			t.Fatalf("ruleset %d: %v", index, err)
		}
		module, _ := renderCompiledRuleModule(index, policies, set.OverflowBlocks, set.Telemetry)
		if got := strings.Count(module, "if trace then"); got != len(policies) || len(plan.Segments) != len(policies) {
			t.Fatalf("ruleset %d: %d trace hooks, %d segments, %d policies", index, got, len(plan.Segments), len(policies))
		}
		for request := 0; request < 5; request++ {
			if raw := g.request(set).raw("c:1"); !strings.Contains(string(raw), "\r\n\r\n") {
				t.Fatalf("malformed request %q", raw)
			}
		}
	}
}

// benchRuleset is a 1000-rule plan in the shape the interpreter is for:
// layered rule packs (user 100 / developer 400 / system 500, ten 100-rule
// segments) of path/method/host/header/CIDR rules, none matching the bench
// request, so every rule is evaluated - the worst case for both modes.
// Inspect / IP library conditions are left out: they cost the same in both
// modes and would only dilute the dispatch cost being compared.
func benchRuleset() fuzzRuleset {
	g := newFuzzGenerator(1000)
	set := fuzzRuleset{Layered: true, OverflowBlocks: true, Telemetry: true}
	layers := []RulePlanLayer{RulePlanLayerUser, RulePlanLayerDeveloper, RulePlanLayerDeveloper, RulePlanLayerDeveloper,
		RulePlanLayerDeveloper, RulePlanLayerSystem, RulePlanLayerSystem, RulePlanLayerSystem, RulePlanLayerSystem, RulePlanLayerSystem}
	for segment, layer := range layers {
		policy := SecurityPolicy{Kind: SecurityWAF, PolicyID: g.uuid(), PolicyVersion: 1, BindingRevision: 1,
			RuntimeSHA256: strings.Repeat("ab", 32), Enabled: true, DefaultAction: WAFAllow}
		if segment%2 == 0 {
			policy.Kind = SecurityACL
		}
		for index := 0; index < 100; index++ {
			n := segment*100 + index
			rule := WAFRule{RuleID: g.uuid(), Action: WAFBlock, Control: WAFStop}
			match := &rule.Match
			switch n % 5 {
			case 0:
				match.Path = &WAFPathMatch{Kind: WAFPathPrefix, Value: fmt.Sprintf("/blocked/%d", n)}
			case 1:
				match.Method, match.Path = "POST", &WAFPathMatch{Kind: WAFPathExact, Value: fmt.Sprintf("/api/%d", n)}
			case 2:
				match.Host = fmt.Sprintf("h%d.example.com", n)
			case 3:
				match.Header = &WAFHeaderMatch{Name: "x-token", Kind: WAFHeaderExact, Value: fmt.Sprintf("bad-%d", n)}
			default:
				match.SourceCIDR = fmt.Sprintf("10.%d.%d.0/24", n/256, n%256)
			}
			policy.Rules = append(policy.Rules, rule)
		}
		set.Segments = append(set.Segments, RulePlanSegmentInput{Layer: layer, Policy: policy})
	}
	return set
}

func TestRulePlanBenchRulesetCompiles(t *testing.T) {
	set := benchRuleset()
	policies, plan, err := set.compile()
	if err != nil {
		t.Fatal(err)
	}
	rules := 0
	for _, segment := range plan.Segments {
		rules += len(segment.Rules)
	}
	if rules != 1000 || len(policies) != 10 || plan.HeaderOverflow != RulePlanHeaderBlock {
		t.Fatalf("rules %d policies %d overflow %s", rules, len(policies), plan.HeaderOverflow)
	}
}
