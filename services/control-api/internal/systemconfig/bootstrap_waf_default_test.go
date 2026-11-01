package systemconfig

import "testing"

// 新装主控的
// 「系统设置 > 网站默认 > 安全设置」默认开启 WAF，十个自研模块默认拦截，
// 站点一键开启即有官方规则可用（securitypolicy.BuildDefaultWAFPolicy）。
func TestProjectBootstrapEnablesOfficialWAFModules(t *testing.T) {
	security := ProjectBootstrapConfiguration().Defaults.Website.Security
	if !security.WAFEnabled {
		t.Fatal("bootstrap waf_enabled must be true")
	}
	if security.WAFModules != defaultWAFModules("on") {
		t.Fatalf("bootstrap waf_modules = %+v, want all on", security.WAFModules)
	}
	if _, _, _, err := CanonicalSnapshot(ProjectBootstrapConfiguration()); err != nil {
		t.Fatalf("bootstrap snapshot: %v", err)
	}
}
