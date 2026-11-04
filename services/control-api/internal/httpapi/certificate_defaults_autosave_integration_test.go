package httpapi

// 证书管理 → 默认设置改选即保存。前端每次只改一项（证书类型或 DNS API），
// 把另一项按当前值带上整份 PATCH；“系统默认设置”= 不带 issuer。这里按前端的保存序列
// 验证两项互不覆盖、旧“上传证书”默认读作无签发机构/无 DNS API、管理员代用户保存、租户不能改别人、版本过期 409。
// 需要 PG（TEST_DATABASE_URL）。

import (
	"bytes"
	"context"
	"net/http"
	"net/http/httptest"
	"net/url"
	"testing"
	"time"

	"github.com/cdnca/cdnca/services/control-api/internal/certdefaults"
	"github.com/cdnca/cdnca/services/control-api/internal/dnsacme"
	"github.com/cdnca/cdnca/services/control-api/internal/entitlementguard"
	"github.com/cdnca/cdnca/services/control-api/internal/identity"
)

func TestCertificateDefaultsAutosaveSequence(t *testing.T) {
	pool := isolatedTestPool(t)
	passwordHash, err := identity.HashPassword(testPassword)
	if err != nil {
		t.Fatal(err)
	}
	identityStore := identity.NewStore(pool)
	platform, err := identityStore.BootstrapPlatformUser(context.Background(), "certdefaultsadmin", "Cert Defaults Admin", passwordHash, "certdefaults-bootstrap")
	if err != nil {
		t.Fatal(err)
	}
	permissions := []string{"dns.read", "dns.manage", "certificates.read", "certificates.manage"}
	tenant := insertDNSTenant(t, pool, "certdefaults-tenant", "certdefaults-user", passwordHash, permissions)
	other := insertDNSTenant(t, pool, "certdefaults-other", "certdefaults-other-user", passwordHash, permissions)
	tokens, err := identity.NewTokenManager("certdefaults-integration-secret-at-least-32-bytes", 5*time.Minute)
	if err != nil {
		t.Fatal(err)
	}
	identityService, err := identity.NewService(identityStore, tokens, 24*time.Hour)
	if err != nil {
		t.Fatal(err)
	}
	cipher, err := dnsacme.NewAESGCMCredentialCipher("certdefaults-test-v1", bytes.Repeat([]byte{5}, 32))
	if err != nil {
		t.Fatal(err)
	}
	leaseKey := newSiteTestKey(t, "certdefaults-test-key")
	trust := newSiteTestTrust(t, leaseKey)
	installSiteTestEntitlement(t, pool, trust, time.Now(), siteTestLeaseOptions{
		serial: 1, limit: 100, key: leaseKey, extraFeatures: []string{entitlementguard.FeatureCertificatesIssue},
	})
	server := httptest.NewServer(New(pool, identityService, Config{APIKeyPepper: bytes.Repeat([]byte{0x54}, 32),
		CookieSecure: false, DNSCredentialCipher: cipher, EntitlementTrust: trust,
	}).Handler())
	t.Cleanup(server.Close)
	client := server.Client()
	token := loginForScope(t, client, server.URL, tenant.username, tenant.scopeID).AccessToken
	provider := createDNSProvider(t, client, server.URL, token, "certdefaults-provider", createDNSProviderRequest{
		Name: "certdefaults cloudflare", ProviderType: "cloudflare", Credentials: map[string]string{"api_token": "certdefaults-secret"},
	})
	providerID := provider.ID.String()
	letsEncrypt := "lets_encrypt"

	get := func(t *testing.T, accessToken, query string) certdefaults.Defaults {
		t.Helper()
		response := siteRequest(t, client, http.MethodGet, server.URL+"/v1/certificate-defaults"+query, nil, accessToken, "", "")
		var result certdefaults.Defaults
		decodeResponse(t, response, http.StatusOK, &result)
		response.Body.Close()
		return result
	}
	patch := func(t *testing.T, accessToken, key string, body certificateDefaultsRequest) certdefaults.Defaults {
		t.Helper()
		response := siteRequest(t, client, http.MethodPatch, server.URL+"/v1/certificate-defaults", body, accessToken, key, "")
		var result certdefaults.Defaults
		decodeResponse(t, response, http.StatusOK, &result)
		response.Body.Close()
		return result
	}
	issuerOf := func(value certdefaults.Defaults) string {
		if value.Issuer == nil {
			return ""
		}
		return *value.Issuer
	}
	providerOf := func(value certdefaults.Defaults) string {
		if value.DNSProviderID == nil {
			return ""
		}
		return value.DNSProviderID.String()
	}

	initial := get(t, token, "")
	t.Run("picking a CA keeps the DNS API and picking a DNS API keeps the CA", func(t *testing.T) {
		withDNS := patch(t, token, "autosave-dns", certificateDefaultsRequest{CertificateType: "acme", DNSProviderID: &providerID, ExpectedRevision: initial.Revision})
		withCA := patch(t, token, "autosave-ca", certificateDefaultsRequest{CertificateType: "acme", DNSProviderID: &providerID, Issuer: &letsEncrypt, ExpectedRevision: withDNS.Revision})
		if issuerOf(withCA) != letsEncrypt || providerOf(withCA) != providerID || withCA.Revision != withDNS.Revision+1 {
			t.Fatalf("after CA pick = %#v", withCA)
		}
		// 系统默认设置：不带 issuer，DNS API 照旧
		system := patch(t, token, "autosave-system", certificateDefaultsRequest{CertificateType: "acme", DNSProviderID: &providerID, ExpectedRevision: withCA.Revision})
		reread := get(t, token, "")
		if system.Issuer != nil || providerOf(reread) != providerID || reread.Issuer != nil || reread.Revision != system.Revision {
			t.Fatalf("after 系统默认设置 = %#v reread = %#v", system, reread)
		}
		// 清空 DNS API：签发机构照旧
		withCA = patch(t, token, "autosave-ca-2", certificateDefaultsRequest{CertificateType: "acme", DNSProviderID: &providerID, Issuer: &letsEncrypt, ExpectedRevision: reread.Revision})
		cleared := patch(t, token, "autosave-clear-dns", certificateDefaultsRequest{CertificateType: "acme", Issuer: &letsEncrypt, ExpectedRevision: withCA.Revision})
		if issuerOf(cleared) != letsEncrypt || cleared.DNSProviderID != nil {
			t.Fatalf("after clearing DNS API = %#v", cleared)
		}
		// 新订单不带签发机构时冻结默认签发机构
		order := createCertificateOrder(t, client, server.URL, token, "autosave-order", createCertificateOrderRequest{
			Domains: []string{"autosave.example.com"}, ChallengeType: "http-01", AutoRenew: true,
		})
		if order.Issuer == nil || *order.Issuer != letsEncrypt {
			t.Fatalf("order issuer = %v, want %s", order.Issuer, letsEncrypt)
		}
	})

	t.Run("a stale revision is refused with 409 and nothing changes", func(t *testing.T) {
		current := get(t, token, "")
		response := siteRequest(t, client, http.MethodPatch, server.URL+"/v1/certificate-defaults", certificateDefaultsRequest{
			CertificateType: "acme", ExpectedRevision: current.Revision - 1,
		}, token, "autosave-stale", "")
		assertError(t, response, http.StatusConflict, "version_conflict", "")
		response.Body.Close()
		if after := get(t, token, ""); after.Revision != current.Revision || issuerOf(after) != issuerOf(current) {
			t.Fatalf("stale write changed defaults: %#v -> %#v", current, after)
		}
	})

	t.Run("a legacy uploaded default reads as no CA and no DNS API, and the page can switch it to acme", func(t *testing.T) {
		current := get(t, token, "")
		uploaded := patch(t, token, "autosave-legacy-uploaded", certificateDefaultsRequest{CertificateType: "uploaded", Issuer: &letsEncrypt, DNSProviderID: &providerID, ExpectedRevision: current.Revision})
		if uploaded.Issuer != nil || uploaded.DNSProviderID != nil {
			t.Fatalf("legacy uploaded defaults = %#v", uploaded)
		}
		switched := patch(t, token, "autosave-from-uploaded", certificateDefaultsRequest{CertificateType: "acme", Issuer: &letsEncrypt, ExpectedRevision: uploaded.Revision})
		if switched.CertificateType != "acme" || issuerOf(switched) != letsEncrypt {
			t.Fatalf("switched from uploaded = %#v", switched)
		}
	})

	t.Run("the platform admin saves for a picked user and a tenant cannot target another user", func(t *testing.T) {
		admin := loginForScope(t, client, server.URL, "certdefaultsadmin", platform.ScopeID).AccessToken
		query := "?" + url.Values{"target_scope_id": {tenant.scopeID.String()}, "target_user_id": {tenant.userID.String()}}.Encode()
		current := get(t, admin, query)
		saved := patch(t, admin, "autosave-admin", certificateDefaultsRequest{
			TargetScopeID: tenant.scopeID.String(), TargetUserID: tenant.userID.String(),
			CertificateType: "acme", DNSProviderID: &providerID, ExpectedRevision: current.Revision,
		})
		if saved.Issuer != nil || providerOf(saved) != providerID {
			t.Fatalf("admin saved = %#v", saved)
		}
		if mine := get(t, token, ""); mine.Revision != saved.Revision || providerOf(mine) != providerID {
			t.Fatalf("tenant reads %#v after admin save %#v", mine, saved)
		}
		response := siteRequest(t, client, http.MethodPatch, server.URL+"/v1/certificate-defaults", certificateDefaultsRequest{
			TargetScopeID: other.scopeID.String(), TargetUserID: other.userID.String(), CertificateType: "acme", ExpectedRevision: 0,
		}, token, "autosave-cross-tenant", "")
		assertError(t, response, http.StatusForbidden, "permission_denied", "")
		response.Body.Close()
	})
}
