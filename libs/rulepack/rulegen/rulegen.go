// Package rulegen generates rule plans and requests for the match index
// differential test and benchmark (libs/rulepack, ADR 0011 §6.5) and for
// cdnca-waf-check -only perf. Distribution:
// literal 60 %, regex 25 %, IP / discrete 15 %, 30 % of rules with a second
// condition. Every rule carries a token unique to it (atk<n>, /p<n>, ...),
// so a request aimed at rule n can match it; requests are attack (aimed at
// one or two rules) or normal, without body, with a large JSON body or with
// a long query.

package rulegen

import (
	"embed"
	"fmt"
	"math/rand/v2"
	"net/url"
	"strconv"
	"strings"

	"github.com/cdnca/cdnca/libs/edgeconfig"
)

// Lua holds the OpenResty side: index_harness.lua (programs, timing and
// memory stats), cdnca_iplib.lua (deterministic IP library stand-in) and
// rule_client.lua (raw request client).
//
//go:embed lua/*.lua
var Lua embed.FS

type genRule struct {
	n    int
	rule edgeconfig.WAFRule
}

// Gen is a seeded generator; Plan resets the rules Request aims at.
type Gen struct {
	rng   *rand.Rand
	rules []genRule
}

func New(seed uint64) *Gen {
	return &Gen{rng: rand.New(rand.NewPCG(seed, seed^0x5851f42d4c957f2d))}
}

// Pct is true with the given percentage.
func (g *Gen) Pct(percent int) bool { return g.rng.IntN(100) < percent }

// UUID is the n-th UUID of salt.
func UUID(n int, salt uint32) string {
	return fmt.Sprintf("%08x-0000-4000-8000-%012x", salt, n)
}

var genTextTargets = []string{"args", "query", "user_agent", "request_uri", "path", "cookie", "referer", "body"}

func (g *Gen) inspectLiteral(n int) edgeconfig.WAFInspect {
	target := genTextTargets[g.rng.IntN(len(genTextTargets))]
	token := fmt.Sprintf("atk%d", n)
	switch g.rng.IntN(6) {
	case 0:
		return edgeconfig.WAFInspect{Target: target, Operator: "contains", Values: []string{token, "zz" + token}}
	case 1:
		return edgeconfig.WAFInspect{Target: "query", Key: "q", Operator: "equals", Values: []string{token}}
	case 2:
		return edgeconfig.WAFInspect{Target: target, Operator: "prefix", Values: []string{token}}
	case 3:
		return edgeconfig.WAFInspect{Target: "header", Key: "x-probe", Operator: "contains", Values: []string{token}}
	case 4:
		return edgeconfig.WAFInspect{Target: target, Operator: "contains", Values: []string{"<" + token}, Filters: []string{"html_unescape", "lowercase"}}
	}
	return edgeconfig.WAFInspect{Target: target, Operator: "contains_all", Values: []string{token, "="}}
}

func (g *Gen) inspectRegex(n int) edgeconfig.WAFInspect {
	target := genTextTargets[g.rng.IntN(len(genTextTargets))]
	patterns := []string{
		fmt.Sprintf(`(?i)atk%d\s*=\s*\d+`, n),
		// A per-rule third literal: rules sharing only "union select"
		// would exceed DefaultMatchBudget.MaxBucket (quality gate).
		fmt.Sprintf(`(?:union|atk%d)\s+select\s+col%d`, n, n),
		fmt.Sprintf(`^/?(?:x|y)atk%d(?:\.php|\.asp)$`, n),
		fmt.Sprintf(`atk%d[a-z]{0,8}`, n),
		fmt.Sprintf(`(?i)(?:ATK%d|rx%d)`, n, n),
	}
	return edgeconfig.WAFInspect{Target: target, Operator: "regex", Values: []string{patterns[g.rng.IntN(len(patterns))]}}
}

// rule n of a generated plan.
func (g *Gen) rule(n int) edgeconfig.WAFRule {
	rule := edgeconfig.WAFRule{RuleID: UUID(n, 0x7a11), Action: []edgeconfig.WAFAction{edgeconfig.WAFBlock, edgeconfig.WAFLog,
		edgeconfig.WAFLog, edgeconfig.WAFAllow}[g.rng.IntN(4)], Control: edgeconfig.WAFContinue}
	if g.Pct(30) {
		rule.Control = edgeconfig.WAFStop
	}
	match := &rule.Match
	roll := g.rng.IntN(100)
	switch {
	case roll < 30: // literal, pure condition
		switch g.rng.IntN(5) {
		case 0:
			match.Path = &edgeconfig.WAFPathMatch{Kind: edgeconfig.WAFPathExact, Value: fmt.Sprintf("/p%d", n)}
		case 1:
			match.Path = &edgeconfig.WAFPathMatch{Kind: edgeconfig.WAFPathPrefix, Value: fmt.Sprintf("/d%d", n)}
		case 2:
			match.Path = &edgeconfig.WAFPathMatch{Kind: edgeconfig.WAFPathRawPrefix, Value: fmt.Sprintf("/r%d", n%97)}
		case 3:
			match.Host = fmt.Sprintf("h%d.example.com", n)
		default:
			match.Header = &edgeconfig.WAFHeaderMatch{Name: "x-token", Kind: edgeconfig.WAFHeaderExact, Value: fmt.Sprintf("t%d", n)}
		}
	case roll < 60: // literal inspect
		match.Inspect = []edgeconfig.WAFInspect{g.inspectLiteral(n)}
	case roll < 85:
		match.Inspect = []edgeconfig.WAFInspect{g.inspectRegex(n)}
	default: // IP / discrete
		switch g.rng.IntN(3) {
		case 0:
			match.SourceCIDR = fmt.Sprintf("10.%d.%d.0/24", (n/256)%256, n%256)
		case 1:
			match.SourceCIDR = fmt.Sprintf("2001:db8:%x::/48", n%65536)
		default:
			match.JA4 = []string{fmt.Sprintf("t13d%04dh2_aaaaaaaaaaaa_bbbbbbbbbbbb", n%10000)}
		}
	}
	if match.SourceCIDR != "" && g.Pct(20) {
		rule.ExpiresAt = []string{"2001-02-03T04:05:06Z", "2099-12-31T23:59:59Z"}[g.rng.IntN(2)]
	}
	if g.Pct(5) {
		match.Port = 18080
	}
	if match.Header == nil && g.Pct(5) {
		match.Header = &edgeconfig.WAFHeaderMatch{Name: "x-probe", Kind: edgeconfig.WAFHeaderExists}
	}
	if g.Pct(30) {
		switch g.rng.IntN(4) {
		case 0:
			match.Method = []string{"GET", "POST"}[g.rng.IntN(2)]
		case 1:
			match.Inspect = append(match.Inspect, edgeconfig.WAFInspect{Target: "user_agent", Operator: "contains", Values: []string{"bot"}})
		case 2:
			match.IPIntel = []edgeconfig.WAFIPIntel{{Field: edgeconfig.WAFIPIntelCountry, Values: []string{"CN", "US"}}}
		default:
			if match.Path == nil {
				match.Path = &edgeconfig.WAFPathMatch{Kind: edgeconfig.WAFPathPrefix, Value: "/api"}
			} else {
				match.Method = "POST"
			}
		}
	}
	return rule
}

// Plan builds a layered plan of total rules (24 segments, user /
// developer / system order) without its index (rulepack.AttachMatchIndex).
func (g *Gen) Plan(total int) (edgeconfig.RulePlan, error) {
	g.rules = g.rules[:0]
	var segments []edgeconfig.RulePlanSegmentInput
	layers := []edgeconfig.RulePlanLayer{edgeconfig.RulePlanLayerUser, edgeconfig.RulePlanLayerDeveloper, edgeconfig.RulePlanLayerSystem}
	per := max(1, (total+23)/24)
	for n := 0; n < total; n++ {
		if n%per == 0 {
			layer := layers[min(2, (n/per)*3/24)]
			kind := edgeconfig.SecurityWAF
			if len(segments)%3 == 1 {
				kind = edgeconfig.SecurityACL
			}
			segments = append(segments, edgeconfig.RulePlanSegmentInput{Layer: layer, Policy: edgeconfig.SecurityPolicy{
				Kind: kind, PolicyID: UUID(len(segments), 0x5e9), PolicyVersion: 1, BindingRevision: 1,
				RuntimeSHA256: strings.Repeat("ab", 32), Enabled: true, DefaultAction: edgeconfig.WAFAllow}})
		}
		rule := g.rule(n)
		g.rules = append(g.rules, genRule{n: n, rule: rule})
		segment := &segments[len(segments)-1]
		segment.Policy.Rules = append(segment.Policy.Rules, rule)
	}
	plan, err := edgeconfig.CompileLayeredRulePlan(segments, true, true)
	if err != nil {
		return edgeconfig.RulePlan{}, fmt.Errorf("plan of %d rules: %w", total, err)
	}
	return plan, nil
}

// Request is one HTTP/1.1 request.
type Request struct {
	Method, Target, Host, RealIP, JA4 string
	Headers                           [][2]string
	ContentType, Body                 string
}

// Class: "json" (large JSON body), "query" (long query) or "nobody".
func (request Request) Class() string {
	switch {
	case request.ContentType == "application/json":
		return "json"
	case len(request.Target) > 1000:
		return "query"
	}
	return "nobody"
}

// Raw is the request with X-Cdnca-Case: caseHeader (more header lines may
// follow it after CRLF).
func (request Request) Raw(caseHeader string) []byte {
	var out strings.Builder
	fmt.Fprintf(&out, "%s %s HTTP/1.1\r\nHost: %s\r\nX-Cdnca-Case: %s\r\nConnection: close\r\nX-Real-IP: %s\r\n",
		request.Method, request.Target, request.Host, caseHeader, request.RealIP)
	if request.JA4 != "" {
		fmt.Fprintf(&out, "X-Test-JA4: %s\r\n", request.JA4)
	}
	for _, header := range request.Headers {
		fmt.Fprintf(&out, "%s: %s\r\n", header[0], header[1])
	}
	if request.Body != "" {
		fmt.Fprintf(&out, "Content-Type: %s\r\nContent-Length: %d\r\n", request.ContentType, len(request.Body))
	}
	out.WriteString("\r\n")
	out.WriteString(request.Body)
	return []byte(out.String())
}

// Request: attack (aimed at one or two generated rules) or normal; no body,
// large JSON body or long query.
func (g *Gen) Request(attack bool) Request {
	request := Request{Method: []string{"GET", "GET", "POST"}[g.rng.IntN(3)], Target: "/index.html", Host: "www.example.com",
		RealIP: "192.0.2.10"}
	query := url.Values{"page": {"1"}}
	userAgent := "Mozilla/5.0"
	if attack && len(g.rules) > 0 {
		for aim := 1 + g.rng.IntN(2); aim > 0; aim-- {
			target := g.rules[g.rng.IntN(len(g.rules))]
			token := fmt.Sprintf("atk%d", target.n)
			match := target.rule.Match
			switch {
			case match.Path != nil:
				request.Target = match.Path.Value + []string{"", "/x", "x"}[g.rng.IntN(3)]
			case match.Host != "":
				request.Host = match.Host
			case match.Header != nil:
				request.Headers = append(request.Headers, [2]string{"X-Token", match.Header.Value})
			case match.SourceCIDR != "":
				prefix := strings.SplitN(match.SourceCIDR, "/", 2)[0]
				request.RealIP = strings.TrimSuffix(prefix, "0") + "7"
				if strings.Contains(prefix, ":") {
					request.RealIP = prefix + "1"
				}
			case match.JA4 != nil:
				request.JA4 = match.JA4[0]
			}
			switch g.rng.IntN(6) {
			case 0:
				query.Set("q", token)
			case 1:
				query.Set("id", strings.ToUpper(token)+" = 12 select col"+strconv.Itoa(target.n))
			case 2:
				userAgent = token + " bot"
			case 3:
				request.Headers = append(request.Headers, [2]string{"X-Probe", "zz" + token}, [2]string{"Cookie", "s=" + token})
			case 4:
				request.Target = "/x" + token + ".php"
			default:
				query.Set("h", "&lt;"+token)
			}
			if request.Method == "POST" {
				request.ContentType, request.Body = "application/x-www-form-urlencoded", "a="+token+"%3D1"
			}
		}
	}
	switch g.rng.IntN(3) {
	case 1: // large JSON body
		request.Method = "POST"
		var body strings.Builder
		body.WriteString(`{"items":[`)
		for index := 0; index < 400; index++ {
			if index > 0 {
				body.WriteString(",")
			}
			fmt.Fprintf(&body, `{"id":%d,"name":"item-%d","note":"lorem ipsum dolor sit amet"}`, index, index)
		}
		if attack {
			fmt.Fprintf(&body, `,{"x":"%s"}`, query.Get("q"))
		}
		body.WriteString(`]}`)
		request.ContentType, request.Body = "application/json", body.String()
	case 2: // long query
		for index := 0; index < 60; index++ {
			query.Set(fmt.Sprintf("f%d", index), strings.Repeat("v", 30))
		}
	}
	request.Headers = append(request.Headers, [2]string{"User-Agent", userAgent})
	request.Target += "?" + query.Encode()
	return request
}
