package entitlementguard

import (
	"slices"
	"testing"
	"time"

	"github.com/cdnca/cdnca/libs/entitlement"
)

// GET /v1/modules 的 features 列出可用许可授予的非模块功能码
// （packages.manage 等），与 modules 同一状态规则：许可不可用（过期等）时为空。
func TestGrantedModulesListsBaseFeaturesOfAUsableLease(t *testing.T) {
	fixture := newWebhookFeatureFixture(t)
	if grants := fixture.grantedModules(t); grants.Features == nil || len(grants.Features) != 0 {
		t.Fatalf("GrantedModules(no lease).Features = %#v", grants.Features)
	}

	fixture.install(t, fixture.moduleLease(1, testModule), fixture.now)
	if grants := fixture.grantedModules(t); slices.Contains(grants.Features, "packages.manage") ||
		!slices.Contains(grants.Features, FeatureExtensionsWebhooks) || slices.Contains(grants.Features, testModule) {
		t.Fatalf("GrantedModules(without packages.manage) = %+v", grants)
	}

	fixture.install(t, fixture.moduleLease(2, testModule, "packages.manage"), fixture.now)
	grants := fixture.grantedModules(t)
	if !slices.Contains(grants.Features, "packages.manage") || slices.Contains(grants.Codes, "packages.manage") ||
		!grants.Has(testModule) {
		t.Fatalf("GrantedModules(with packages.manage) = %+v", grants)
	}

	expired := fixture.moduleLease(3, testModule, "packages.manage")
	expired.NotBefore = fixture.now.Add(-3 * time.Hour).Unix()
	expired.ExpiresAt = fixture.now.Add(-2 * time.Hour).Unix()
	expired.GraceUntil = fixture.now.Add(-time.Hour).Unix()
	fixture.install(t, expired, fixture.now)
	if grants := fixture.grantedModules(t); grants.Status != string(entitlement.StatusExpired) || len(grants.Features) != 0 {
		t.Fatalf("GrantedModules(expired) = %+v", grants)
	}
}
