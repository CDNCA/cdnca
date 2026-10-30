package edgeconfig

import (
	"reflect"
	"strings"
	"testing"
)

func sourceCIDRListener(siteID string) SecurityListener {
	return SecurityListener{
		SiteID: siteID, Domain: "www.example.com", Port: 18081, Protocol: ProtocolHTTP,
		Security: ListenerSecurity{Policies: []SecurityPolicy{{
			Kind: SecurityACL, PolicyID: "cccccccc-cccc-4ccc-8ccc-cccccccccccc",
			PolicyVersion: 2, BindingRevision: 4,
			RuntimeSHA256: "0123456789abcdef0123456789abcdef0123456789abcdef0123456789abcdef",
			Enabled:       true, DefaultAction: WAFAllow,
			Rules: []WAFRule{{
				RuleID: "dddddddd-dddd-4ddd-8ddd-dddddddddddd",
				Match:  WAFMatch{Host: "www.example.com", Port: 18081, SourceCIDR: "198.51.100.0/24"},
				Action: WAFBlock, Control: WAFContinue,
			}},
		}}},
	}
}

func TestRenderSecurityFragmentsAtZeroOffsetMatchesLegacy(t *testing.T) {
	listeners := []SecurityListener{sourceCIDRListener("bbbbbbbb-bbbb-4bbb-8bbb-bbbbbbbbbbbb")}
	legacy, err := RenderSecurityFragments("aaaaaaaa-aaaa-4aaa-8aaa-aaaaaaaaaaaa", "cfg-1", listeners)
	if err != nil {
		t.Fatal(err)
	}
	offset, err := RenderSecurityFragmentsAt("aaaaaaaa-aaaa-4aaa-8aaa-aaaaaaaaaaaa", "cfg-1", listeners, 0)
	if err != nil || !reflect.DeepEqual(legacy, offset) {
		t.Fatalf("offset 0 differs from legacy: err=%v\nlegacy=%+v\noffset=%+v", err, legacy, offset)
	}
	if !strings.Contains(legacy.HTTP, "$cdnca_security_0001_01_0001_source") {
		t.Fatalf("legacy fixture lost its source variable:\n%s", legacy.HTTP)
	}
}

func TestRenderSecurityFragmentsAtOffsetIsolatesSourceVariables(t *testing.T) {
	listeners := []SecurityListener{sourceCIDRListener("bbbbbbbb-bbbb-4bbb-8bbb-bbbbbbbbbbbb")}
	first, err := RenderSecurityFragmentsAt("aaaaaaaa-aaaa-4aaa-8aaa-aaaaaaaaaaaa", "cfg-1", listeners, 0)
	if err != nil {
		t.Fatal(err)
	}
	second, err := RenderSecurityFragmentsAt("eeeeeeee-eeee-4eee-8eee-eeeeeeeeeeee", "cfg-2", listeners, 1)
	if err != nil {
		t.Fatal(err)
	}
	if !strings.Contains(second.HTTP, "$cdnca_security_0002_01_0001_source") ||
		strings.Contains(second.HTTP, "$cdnca_security_0001_01_0001_source") {
		t.Fatalf("offset geo variable not shifted:\n%s", second.HTTP)
	}
	if !strings.Contains(second.Location[0], "cdnca_security_0002_01_0001_source") ||
		strings.Contains(second.Location[0], "cdnca_security_0001_01_0001_source") {
		t.Fatalf("offset location does not reference its own geo variable:\n%s", second.Location[0])
	}
	if first.HTTP == second.HTTP {
		t.Fatal("two scopes rendered identical http fragments")
	}
	if _, err := RenderSecurityFragmentsAt("aaaaaaaa-aaaa-4aaa-8aaa-aaaaaaaaaaaa", "cfg-1", listeners, -1); err == nil {
		t.Fatal("negative listener offset was accepted")
	}
}
