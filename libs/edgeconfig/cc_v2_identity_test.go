package edgeconfig

import (
	"strings"
	"testing"
)

const ccV2IdentitySubscriptionID = "018f47a2-5b9c-7d31-8a60-104c9c0b71a3"

// The site runtime v2 server fragment assigns the listener's identity before
// the CC decision; without an identity it is the plain hook.
func TestRenderSecurityFragmentsCCV2HookAssignsListenerIdentity(t *testing.T) {
	policy := testCCV2Policy(ccV2BundleTenantID, ccV2BundleSiteID)
	content, err := CanonicalCCV2Policy(policy)
	if err != nil {
		t.Fatal(err)
	}
	listener := SecurityListener{SiteID: ccV2BundleSiteID, Domain: "cc.example.test", Port: 8080, Protocol: ProtocolHTTP, Telemetry: true,
		Security: ListenerSecurity{CC: &CCV2SiteBinding{SourceSHA256: strings.Repeat("a", 64), CompiledSHA256: ccV2Digest(content), Policy: policy}}}
	plain, err := RenderSecurityFragments(ccV2BundleTenantID, ccV2BundleVersion, []SecurityListener{listener})
	if err != nil {
		t.Fatal(err)
	}
	entryID := plain.CCV2Registry.Entries[0].EntryID
	call := `return require("cc").access("` + entryID + `")`
	if !strings.Contains(plain.Server[0], "server_rewrite_by_lua_block { "+call+" }") {
		t.Fatalf("plain hook = %q", plain.Server[0])
	}
	listener.Identity = &ServerTelemetryIdentity{TenantID: "018f47a2-5b9c-7d31-8a60-104c9c0b71a1", SiteID: ccV2BundleSiteID,
		PackageSubscriptionID: "", ConfigVersionID: ccV2BundleVersion}
	withIdentity, err := RenderSecurityFragments(ccV2BundleTenantID, ccV2BundleVersion, []SecurityListener{listener})
	if err != nil {
		t.Fatal(err)
	}
	want := `server_rewrite_by_lua_block { ngx.var.cdnca_tenant_id = "018f47a2-5b9c-7d31-8a60-104c9c0b71a1"; ngx.var.cdnca_site_id = "` +
		ccV2BundleSiteID + `"; ngx.var.cdnca_package_subscription_id = ""; ngx.var.cdnca_config_version_id = "` + ccV2BundleVersion +
		`"; ` + call + " }"
	if !strings.Contains(withIdentity.Server[0], want) {
		t.Fatalf("hook = %q\nwant %q", withIdentity.Server[0], want)
	}
	// A value Lua could not hold literally renders no prelude.
	listener.Identity.SiteID = `x"; os.exit() --`
	unsafe, err := RenderSecurityFragments(ccV2BundleTenantID, ccV2BundleVersion, []SecurityListener{listener})
	if err != nil || unsafe.Server[0] != plain.Server[0] {
		t.Fatalf("unsafe identity hook = %q, %v", unsafe.Server[0], err)
	}
}
