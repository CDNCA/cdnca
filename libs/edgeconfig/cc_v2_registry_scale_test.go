package edgeconfig

import (
	"crypto/sha256"
	"fmt"
	"regexp"
	"strings"
	"testing"
)

// nginx 配置解析器单个 token 上限 4096 字节（openresty 1.27/1.31 实测：长字符串
// 3900 字节通过、4000 字节报 "missing the closing long bracket"）。注册表的每个
// Lua 长字符串都必须留在这个上限之下。
const nginxLuaTokenSafeBytes = 3900

var luaLongStringPattern = regexp.MustCompile(`(?s)\[==\[.*?\]==\]`)

func ccV2ScaleSiteID(index int) string {
	return fmt.Sprintf("%08x-0000-4000-8000-%012x", index+1, index+1)
}

func ccV2ScaleBinding(t *testing.T, tenantID, siteID string) *CCV2SiteBinding {
	t.Helper()
	policy := testCCV2Policy(tenantID, siteID)
	canonical, err := CanonicalCCV2Policy(policy)
	if err != nil {
		t.Fatal(err)
	}
	return &CCV2SiteBinding{SourceSHA256: strings.Repeat("a", 64), CompiledSHA256: fmt.Sprintf("%x", sha256.Sum256(canonical)), Policy: policy}
}

func ccV2ScaleSites(t *testing.T, tenantID string, count int) []Site {
	t.Helper()
	sites := make([]Site, count)
	for index := range sites {
		siteID := ccV2ScaleSiteID(index)
		sites[index] = testCCV2Site(siteID, fmt.Sprintf("cc%03d.example.test", index), 8080, ccV2ScaleBinding(t, tenantID, siteID))
	}
	return sites
}

func assertCCV2LuaTokensFit(t *testing.T, nginx string) {
	t.Helper()
	tokens := luaLongStringPattern.FindAllString(nginx, -1)
	if len(tokens) == 0 {
		t.Fatal("no CC v2 registry long string rendered")
	}
	for _, token := range tokens {
		if len(token) > nginxLuaTokenSafeBytes {
			t.Fatalf("Lua long string is %d bytes, nginx rejects tokens >= 4096 bytes", len(token))
		}
	}
}

func TestRenderSecurityFragmentsCCV2RegistryOfFiftyListenersFitsNginxTokenLimit(t *testing.T) {
	tenantID := "aaaaaaaa-aaaa-4aaa-8aaa-aaaaaaaaaaaa"
	var listeners []SecurityListener
	for _, site := range ccV2ScaleSites(t, tenantID, 50) {
		listeners = append(listeners, SecurityListener{SiteID: site.ID, Domain: site.Domain, Port: site.ListenPort,
			Protocol: site.Protocol, Security: ListenerSecurity{CC: site.CCV2}})
	}
	fragments, err := RenderSecurityFragments(tenantID, "cfg-1", listeners)
	if err != nil {
		t.Fatalf("RenderSecurityFragments: %v", err)
	}
	assertCCV2LuaTokensFit(t, fragments.HTTP)
	composed, err := RenderComposedCCV2("composed-1", []CCV2Registry{*fragments.CCV2Registry})
	if err != nil {
		t.Fatalf("RenderComposedCCV2: %v", err)
	}
	assertCCV2LuaTokensFit(t, composed)
	if !strings.Contains(composed, "scoped_state = true") {
		t.Fatalf("composed init lost scoped_state:\n%s", composed)
	}
}
