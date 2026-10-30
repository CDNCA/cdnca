package eventspool

import (
	"encoding/json"
	"os"
	"strings"
	"testing"
)

const evidenceCanary = "canary-0f3a9"

func evidenceSecurityLine(t *testing.T, matched, excerpt string) []byte {
	t.Helper()
	security := sourceAccess(tenantOne)
	security.Type = EventSecurity
	security.ListenPort, security.Protocol, security.RequestClass = 443, "https", "standard"
	security.CacheStatus, security.StatusCode = "", 0
	security.SecurityType, security.Action, security.Severity = "waf", "block", "high"
	security.Method, security.Path = "POST", "/login"
	security.Detector, security.Matched, security.RequestBodyExcerpt = "sqli", matched, excerpt
	return sourceLine(t, security)
}

// TF-E01：站点未开请求体采集时，安全事件即便带着节点写入的正文片段与敏感命中值，
// Agent 也不能把它们送进 spool；规则、检测器、动作保留。
func TestSecurityEvidenceWithoutBodyCaptureDropsExcerptAndRedactsMatched(t *testing.T) {
	body := `{"user":"alice","password":"` + evidenceCanary + `","nested":{"client_secret":"` + evidenceCanary + `"}}`
	line := evidenceSecurityLine(t, "password="+evidenceCanary, body)
	for name, policy := range map[string]CapturePolicy{
		"capture off":          {},
		"headers only":         {Enabled: true, RequestHeaders: []string{"User-Agent"}},
		"body for another uri": {Enabled: true, URIPrefixes: []string{"/api/"}, RequestBodyFields: []string{"user"}},
	} {
		t.Run(name, func(t *testing.T) {
			parsed, err := ParseSourceLine(line, policy)
			if err != nil {
				t.Fatalf("ParseSourceLine() error = %v", err)
			}
			if parsed.RequestBodyExcerpt != "" {
				t.Fatalf("excerpt = %q, want dropped", parsed.RequestBodyExcerpt)
			}
			if strings.Contains(parsed.Matched, evidenceCanary) || parsed.Matched != "password=[REDACTED]" {
				t.Fatalf("matched = %q", parsed.Matched)
			}
			if parsed.Detector != "sqli" || parsed.Action != "block" || parsed.SecurityType != "waf" {
				t.Fatalf("decision metadata lost: %#v", parsed)
			}
		})
	}
}

// 开启请求体采集且请求命中策略时，JSON / form 片段保留结构，敏感值被替换；
// 无法安全解析的文本（截断 JSON、其他格式）整段省略。
func TestSecurityEvidenceWithBodyCaptureRedactsStructuredExcerpt(t *testing.T) {
	policy := CapturePolicy{Enabled: true, RequestBodyFields: []string{"user"}}
	for _, test := range []struct {
		name, excerpt, want string
	}{
		{name: "json nested", excerpt: `{"user":"alice","password":"` + evidenceCanary + `","nested":{"clientSecret":"` + evidenceCanary + `"}}`,
			want: `{"nested":{"clientSecret":"[REDACTED]"},"password":"[REDACTED]","user":"alice"}`},
		{name: "form", excerpt: "user=alice&api_key=" + evidenceCanary + "&q=1", want: "user=alice&api_key=[REDACTED]&q=1"},
		{name: "truncated json", excerpt: `{"user":"alice","password":"` + evidenceCanary, want: ""},
		{name: "free text", excerpt: "password is " + evidenceCanary, want: ""},
	} {
		t.Run(test.name, func(t *testing.T) {
			parsed, err := ParseSourceLine(evidenceSecurityLine(t, "", test.excerpt), policy)
			if err != nil {
				t.Fatalf("ParseSourceLine() error = %v", err)
			}
			if parsed.RequestBodyExcerpt != test.want {
				t.Fatalf("excerpt = %q, want %q", parsed.RequestBodyExcerpt, test.want)
			}
		})
	}
}

func TestScrubEvidenceTextKeepsPlainFragments(t *testing.T) {
	for input, want := range map[string]string{
		"id=1 union select":                          "id=1 union select",
		"keyword=" + evidenceCanary:                  "keyword=" + evidenceCanary,
		`{"token":"` + evidenceCanary + `","a":"b"`:  `{"token":"[REDACTED]","a":"b"`,
		"x=<script>&refreshSecret=" + evidenceCanary: "x=<script>&refreshSecret=[REDACTED]",
		"body over inspection limit":                 "body over inspection limit",
	} {
		if got := scrubEvidenceText(input); got != want {
			t.Fatalf("scrubEvidenceText(%q) = %q, want %q", input, got, want)
		}
	}
}

// 共用向量：Go sensitiveName 与 Lua（cdnca_telemetry.sensitive_name、
// cdnca_waf evidence.sensitive，见 edge/openresty/dynroute/evidence_privacy_test.sh）一致。
func TestSensitiveNameSharedVectors(t *testing.T) {
	raw, err := os.ReadFile("testdata/sensitive_names.json")
	if err != nil {
		t.Fatal(err)
	}
	var vectors struct {
		Sensitive []string `json:"sensitive"`
		Plain     []string `json:"plain"`
	}
	if err := json.Unmarshal(raw, &vectors); err != nil {
		t.Fatal(err)
	}
	for _, name := range vectors.Sensitive {
		if !sensitiveName(name) {
			t.Errorf("sensitiveName(%q) = false, want true", name)
		}
	}
	for _, name := range vectors.Plain {
		if sensitiveName(name) {
			t.Errorf("sensitiveName(%q) = true, want false", name)
		}
	}
}
