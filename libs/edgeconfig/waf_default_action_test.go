package edgeconfig

import (
	"strings"
	"testing"
)

func TestLegacyWAFDefaultActionNormalization(t *testing.T) {
	tests := []struct {
		name   string
		input  WAFAction
		expect WAFAction
	}{
		{name: "omitted defaults to allow", expect: WAFAllow},
		{name: "explicit allow", input: WAFAllow, expect: WAFAllow},
		{name: "explicit block", input: WAFBlock, expect: WAFBlock},
	}
	for _, test := range tests {
		t.Run(test.name, func(t *testing.T) {
			policy := WAFPolicy{DefaultAction: test.input}
			normalized, err := normalizeWAF(policy)
			if err != nil {
				t.Fatalf("normalizeWAF() error = %v", err)
			}
			if normalized.DefaultAction != test.expect {
				t.Fatalf("normalized default action = %q, want %q", normalized.DefaultAction, test.expect)
			}
			if policy.DefaultAction != test.input || len(policy.Rules) != 0 {
				t.Fatalf("normalizeWAF() mutated input: %+v", policy)
			}
		})
	}
}

func TestRenderLegacyWAFDefaultActionProgram(t *testing.T) {
	tests := []struct {
		name   string
		policy WAFPolicy
		want   string
	}{
		{
			name:   "block default with allow continue",
			policy: WAFPolicy{DefaultAction: WAFBlock, Rules: []WAFRule{{Match: WAFMatch{Method: "GET"}, Action: WAFAllow, Control: WAFContinue}}},
			want: `      rewrite_by_lua_block {
        local method = ngx.req.get_method()
        local cdnca_waf_action = "block"
        local cdnca_waf_stopped = false
        -- WAF rule 1
        if not cdnca_waf_stopped and method == "GET" then
          cdnca_waf_action = "allow"
        end
        if cdnca_waf_action == "block" then
          return ngx.exit(403)
        end
      }
`,
		},
		{
			name: "allow continue can reach deny stop",
			policy: WAFPolicy{DefaultAction: WAFBlock, Rules: []WAFRule{
				{Match: WAFMatch{Header: &WAFHeaderMatch{Name: "X-Flow", Kind: WAFHeaderExists}}, Action: WAFAllow, Control: WAFContinue},
				{Match: WAFMatch{Header: &WAFHeaderMatch{Name: "X-Flow", Kind: WAFHeaderExact, Value: "block"}}, Action: WAFDeny, Control: WAFStop},
			}},
			want: `      rewrite_by_lua_block {
        local raw_headers, header_error = ngx.req.get_headers(100, true)
        if header_error == "truncated" then
          return ngx.exit(403)
        end
        local cdnca_headers = {}
        local cdnca_duplicate_headers = {}
        for name, value in pairs(raw_headers) do
          local normalized_name = string.lower(name)
          if cdnca_headers[normalized_name] ~= nil or type(value) == "table" then
            cdnca_duplicate_headers[normalized_name] = true
          end
          cdnca_headers[normalized_name] = value
        end
        local function cdnca_header_exists(name)
          return cdnca_headers[name] ~= nil
        end
        local function cdnca_header_exact(name, expected)
          local value = cdnca_headers[name]
          return not cdnca_duplicate_headers[name] and type(value) == "string" and value == expected
        end
        local cdnca_waf_action = "block"
        local cdnca_waf_stopped = false
        -- WAF rule 1
        if not cdnca_waf_stopped and cdnca_header_exists("x-flow") then
          cdnca_waf_action = "allow"
        end
        -- WAF rule 2
        if not cdnca_waf_stopped and cdnca_header_exact("x-flow", "block") then
          cdnca_waf_action = "block"
          cdnca_waf_stopped = true
        end
        if cdnca_waf_action == "block" then
          return ngx.exit(403)
        end
      }
`,
		},
		{
			name: "allow stop prevents later deny",
			policy: WAFPolicy{DefaultAction: WAFBlock, Rules: []WAFRule{
				{Match: WAFMatch{Header: &WAFHeaderMatch{Name: "X-Stop", Kind: WAFHeaderExists}}, Action: WAFAllow, Control: WAFStop},
				{Match: WAFMatch{Path: &WAFPathMatch{Kind: WAFPathExact, Value: "/blocked"}}, Action: WAFDeny, Control: WAFStop},
			}},
			want: `      rewrite_by_lua_block {
        local uri = ngx.var.uri
        local raw_headers, header_error = ngx.req.get_headers(100, true)
        if header_error == "truncated" then
          return ngx.exit(403)
        end
        local cdnca_headers = {}
        local cdnca_duplicate_headers = {}
        for name, value in pairs(raw_headers) do
          local normalized_name = string.lower(name)
          if cdnca_headers[normalized_name] ~= nil or type(value) == "table" then
            cdnca_duplicate_headers[normalized_name] = true
          end
          cdnca_headers[normalized_name] = value
        end
        local function cdnca_header_exists(name)
          return cdnca_headers[name] ~= nil
        end
        local function cdnca_header_exact(name, expected)
          local value = cdnca_headers[name]
          return not cdnca_duplicate_headers[name] and type(value) == "string" and value == expected
        end
        local cdnca_waf_action = "block"
        local cdnca_waf_stopped = false
        -- WAF rule 1
        if not cdnca_waf_stopped and cdnca_header_exists("x-stop") then
          cdnca_waf_action = "allow"
          cdnca_waf_stopped = true
        end
        -- WAF rule 2
        if not cdnca_waf_stopped and uri == "/blocked" then
          cdnca_waf_action = "block"
          cdnca_waf_stopped = true
        end
        if cdnca_waf_action == "block" then
          return ngx.exit(403)
        end
      }
`,
		},
	}
	for _, test := range tests {
		t.Run(test.name, func(t *testing.T) {
			policy, err := normalizeWAF(test.policy)
			if err != nil {
				t.Fatalf("normalizeWAF() error = %v", err)
			}
			var output strings.Builder
			renderWAFBlock(&output, 0, "", policy, nil, nil, true, false)
			if got := output.String(); got != test.want {
				t.Fatalf("legacy WAF program mismatch\n--- got ---\n%s--- want ---\n%s", got, test.want)
			}
		})
	}
}
