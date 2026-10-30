package edgeconfig

import (
	"bytes"
	"compress/gzip"
	"encoding/base64"
	"encoding/json"
	"io"
	"os"
	"strings"
	"testing"
	"time"
)

const (
	managedWAFTestSiteID   = "11111111-1111-4111-8111-111111111111"
	managedWAFTestPolicyID = "22222222-2222-4222-8222-222222222222"
)

// testCRSProfile is a CRS profile pack as rulepack.CRSProfileOf yields it:
// SQLi at paranoia 2 (block), XSS at paranoia 1 (log); exports are every
// scoring rule the profile evaluates.
func testCRSProfile(digest string) CRSProfile {
	profile := CRSProfile{Ref: CRSProfileRef{PackID: "system/crs-test", Version: "1.0.0", SHA256: digest},
		Name: "测试档位", Sets: []ManagedWAFSet{
			{Key: "waf_set:sqli", Name: "SQL注入", Action: "block", Paranoia: 2, Threshold: 5, Files: []string{"REQUEST-942"}},
			{Key: "waf_set:xss", Name: "XSS", Action: "log", Paranoia: 1, Threshold: 5, Files: []string{"REQUEST-941"}},
		}}
	manifest, err := DeriveCRSManifest(testCRSRuleText())
	if err != nil {
		panic(err)
	}
	for _, rule := range manifest.Rules {
		if strings.HasPrefix(rule.File, "REQUEST-942-") && rule.Paranoia <= 2 || strings.HasPrefix(rule.File, "REQUEST-941-") && rule.Paranoia <= 1 {
			profile.Exports = append(profile.Exports, rule.ID)
		}
	}
	return profile
}

var testCRSProfileSHA256 = strings.Repeat("a", 64)

func managedWAFTestSite() Site {
	return Site{
		ID: managedWAFTestSiteID, Domain: "waf.example.test", ListenPort: 8080,
		Protocol: ProtocolHTTP, Origins: []Origin{{Host: "127.0.0.1", Port: 9000, Weight: 1}},
		Balance: BalanceRoundRobin, FailoverTries: 1, ConnectTimeout: time.Second, ReadTimeout: 5 * time.Second,
		ACL: ACLPolicy{DefaultAction: ACLAllow},
		ManagedWAF: &ManagedWAF{
			PolicyID: managedWAFTestPolicyID, PolicyVersion: 3,
			RequestBodyLimit: 1 << 20, RequestBodyNoFilesLimit: 128 << 10, RequestBodyLimitAction: "reject",
			ArgumentsLimit: 1000, JSONDepthLimit: 512, PCREMatchLimit: 100000,
			Profile:    testCRSProfile(testCRSProfileSHA256).Ref,
			Exclusions: []int{942100, 941100},
			AllowCIDRs: []string{"192.0.2.0/24"},
		},
	}
}

func managedWAFSpec(sites ...Site) Spec {
	return Spec{ConfigVersionID: "managed-waf-test", TenantID: "33333333-3333-4333-8333-333333333333",
		StateRoot: "/runtime", HealthPort: 18080, Sites: sites, CRSRules: testCRSRuleText(),
		CRSProfiles: []CRSProfile{testCRSProfile(testCRSProfileSHA256)}}
}

// testCRSRuleText decodes the catalog's CRS rule text bundle
// (libs/entitlement/rulecatalog/crs/rules.json), the data control-api passes
// as Spec.CRSRules.
func testCRSRuleText() *CRSRuleText {
	raw, err := os.ReadFile("../entitlement/rulecatalog/crs/rules.json")
	if err != nil {
		panic(err)
	}
	var bundle struct {
		Version string `json:"version"`
		Files   []struct {
			Name string `json:"name"`
			Gzip string `json:"gzip"`
		} `json:"files"`
	}
	if err := json.Unmarshal(raw, &bundle); err != nil {
		panic(err)
	}
	result := &CRSRuleText{Version: bundle.Version, Files: map[string][]byte{}}
	for _, file := range bundle.Files {
		compressed, err := base64.RawStdEncoding.DecodeString(file.Gzip)
		if err != nil {
			panic(err)
		}
		reader, err := gzip.NewReader(bytes.NewReader(compressed))
		if err != nil {
			panic(err)
		}
		content, err := io.ReadAll(reader)
		if err != nil {
			panic(err)
		}
		result.Files[file.Name] = content
	}
	return result
}

func TestWAFEngineIncludeAllowlistIsExact(t *testing.T) {
	for _, value := range []string{
		"/var/lib/cdnca-edge/waf-engine/0190a1b2-c3d4-7e5f-8a9b-0c1d2e3f4a5b/load[.]conf",
		"/runtime/waf-engine/managed-waf-test/http[.]conf",
		"/runtime/waf-engine/v1/site-11111111-1111-4111-8111-111111111111[.]conf",
	} {
		if !IsWAFEngineInclude(value) {
			t.Fatalf("rejected %s", value)
		}
	}
	for _, value := range []string{
		"/runtime/waf-engine/v1/load.conf", "/runtime/waf-engine/v1/*.conf", "/etc/nginx/load[.]conf",
		"/runtime/waf-engine/v1/../x/load[.]conf", "/runtime/waf-engine/v1/other[.]conf", "waf-engine/v1/load[.]conf",
		"/runtime//waf-engine/v1/load[.]conf",
	} {
		if IsWAFEngineInclude(value) {
			t.Fatalf("accepted %s", value)
		}
	}
	document, ok := parseNginxDirectives("include /runtime/waf-engine/v1/load[.]conf;\nhttp { include /runtime/waf-engine/v1/http[.]conf; }\n")
	if !ok || document.hasInclude {
		t.Fatal("gate includes counted as foreign includes")
	}
	for _, content := range []string{
		"include /etc/nginx/conf.d/*.conf;\n",
		"http { include /runtime/waf-engine/v1/load[.]conf; }\n",
		"include /runtime/waf-engine/v1/http[.]conf;\n",
		"include \"/runtime/waf-engine/v1/load[.]conf\";\n",
	} {
		document, ok := parseNginxDirectives(content)
		if ok && !document.hasInclude {
			t.Fatalf("foreign include accepted: %q", content)
		}
	}
}
