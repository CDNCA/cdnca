package httpapi

import (
	"bytes"
	"context"
	"net/http"
	"net/http/httptest"
	"testing"
	"time"

	"github.com/cdnca/cdnca/services/control-api/internal/identity"
	"github.com/cdnca/cdnca/services/control-api/internal/site"
	"github.com/google/uuid"
)

// The HTTP layer of the administrator CNAME names. A
// tenant session answers 403, a bad name 400, a used name or a package-mode
// site 409, and only the platform session reads cname_custom_label.
func TestCNAMELabelHTTP(t *testing.T) {
	pool := isolatedTestPool(t)
	key := newSiteTestKey(t, "control-site-test-key")
	trust := newSiteTestTrust(t, key)
	installSiteTestEntitlement(t, pool, trust, time.Now(), siteTestLeaseOptions{serial: 1, limit: 100, key: key})
	passwordHash, err := identity.HashPassword(testPassword)
	if err != nil {
		t.Fatal(err)
	}
	identityStore := identity.NewStore(pool)
	if _, err := identityStore.BootstrapPlatformUser(context.Background(), "labeladmin", "Label Administrator", passwordHash, "label-bootstrap"); err != nil {
		t.Fatal(err)
	}
	tenant := insertSiteTenant(t, pool, "tenant-label", "tenant-label-user", "Tenant Label User", passwordHash)
	tokens, err := identity.NewTokenManager("label-integration-secret-at-least-thirty-two-bytes", 5*time.Minute)
	if err != nil {
		t.Fatal(err)
	}
	identityService, err := identity.NewService(identityStore, tokens, 24*time.Hour)
	if err != nil {
		t.Fatal(err)
	}
	server := httptest.NewServer(New(pool, identityService, Config{
		EntitlementTrust: trust,
		APIKeyPepper:     bytes.Repeat([]byte{0x52}, 32),
	}).Handler())
	t.Cleanup(server.Close)
	client := server.Client()
	platform, _ := loginOK(t, client, server.URL, "labeladmin")
	tenantAuth := loginForScope(t, client, server.URL, tenant.username, tenant.scopeID)

	newSite := func(name, host string) uuid.UUID {
		body := createSiteRequest{TargetScopeID: tenant.scopeID.String(), OwnerID: tenant.userID.String(),
			Basic: validSiteBasic(host, "192.0.2.10:8080")}
		return createSite(t, client, server.URL, platform.AccessToken, "label-create-"+name, body).ID
	}
	first, second := newSite("one", "one.label.example"), newSite("two", "two.label.example")
	url := func(kind string, id uuid.UUID, suffix string) string {
		return server.URL + "/v1/admin/cname-labels/" + kind + "/" + id.String() + suffix
	}
	put := func(token, kind string, id uuid.UUID, label, idem string) *http.Response {
		return siteRequest(t, client, http.MethodPut, url(kind, id, ""), map[string]string{"label": label}, token, idem, "")
	}

	t.Run("a tenant session is refused with 403", func(t *testing.T) {
		for name, response := range map[string]*http.Response{
			"get":        siteRequest(t, client, http.MethodGet, url("site", first, ""), nil, tenantAuth.AccessToken, "", ""),
			"put":        put(tenantAuth.AccessToken, "site", first, "mine", "label-tenant-put"),
			"affected":   siteRequest(t, client, http.MethodGet, url("line-group", uuid.New(), "/affected"), nil, tenantAuth.AccessToken, "", ""),
			"regenerate": siteRequest(t, client, http.MethodPost, url("line-group", uuid.New(), "/regenerate"), nil, tenantAuth.AccessToken, "label-tenant-regen", ""),
		} {
			t.Run(name, func(t *testing.T) {
				assertError(t, response, http.StatusForbidden, "permission_denied", "")
				response.Body.Close()
			})
		}
	})

	t.Run("a bad name is 400", func(t *testing.T) {
		for label, code := range map[string]string{"a_b": "cname_label_invalid", "-x": "cname_label_invalid", "www": "cname_label_reserved"} {
			response := put(platform.AccessToken, "site", first, label, "label-bad-"+label)
			assertError(t, response, http.StatusBadRequest, code, "")
			response.Body.Close()
		}
		response := put(platform.AccessToken, "no-such-kind", first, "ok", "label-bad-kind")
		assertError(t, response, http.StatusBadRequest, "validation_error", "")
		response.Body.Close()
	})

	t.Run("an unknown object is 404", func(t *testing.T) {
		response := put(platform.AccessToken, "site", uuid.New(), "ghost", "label-ghost")
		assertError(t, response, http.StatusNotFound, "not_found", "")
		response.Body.Close()
	})

	t.Run("a used name is 409", func(t *testing.T) {
		response := put(platform.AccessToken, "site", first, "Brand", "label-brand")
		var saved struct {
			Label string `json:"label"`
		}
		decodeResponse(t, response, http.StatusOK, &saved)
		response.Body.Close()
		if saved.Label != "brand" {
			t.Fatalf("label = %q", saved.Label)
		}
		conflict := put(platform.AccessToken, "site", second, "brand", "label-brand-2")
		assertError(t, conflict, http.StatusConflict, "cname_label_taken", "")
		conflict.Body.Close()
	})

	t.Run("only the platform session reads cname_custom_label", func(t *testing.T) {
		platformView := getSite(t, client, server.URL, first, platform.AccessToken)
		if platformView.Basic.CNAMECustomLabel == nil || *platformView.Basic.CNAMECustomLabel != "brand" {
			t.Fatalf("platform view = %v", platformView.Basic.CNAMECustomLabel)
		}
		tenantView := getSite(t, client, server.URL, first, tenantAuth.AccessToken)
		if tenantView.Basic.CNAMECustomLabel != nil {
			t.Fatalf("tenant view leaks %q", *tenantView.Basic.CNAMECustomLabel)
		}
	})
}

// 套餐模式站点改名返回 409：store 层用真实订阅测过 ErrCNAMELabelFollowsPackage，这里钉 HTTP 映射。
func TestCNAMELabelFollowsPackageIs409(t *testing.T) {
	recorder := httptest.NewRecorder()
	request := httptest.NewRequest(http.MethodPut, "/v1/admin/cname-labels/site/"+uuid.NewString(), nil)
	(&Server{}).writeCNAMELabelError(recorder, request, site.ErrCNAMELabelFollowsPackage)
	if recorder.Code != http.StatusConflict || !bytes.Contains(recorder.Body.Bytes(), []byte("cname_label_follows_package")) {
		t.Fatalf("status=%d body=%s", recorder.Code, recorder.Body.String())
	}
}
