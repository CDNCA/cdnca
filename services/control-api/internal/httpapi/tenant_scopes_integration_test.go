package httpapi

import (
	"bytes"
	"context"
	"net/http"
	"net/http/httptest"
	"regexp"
	"testing"
	"time"

	"github.com/cdnca/cdnca/services/control-api/internal/identity"
	"github.com/google/uuid"
)

func TestTenantScopesHTTPFlowIsPlatformScopedAndSearchable(t *testing.T) {
	pool := isolatedTestPool(t)
	passwordHash, err := identity.HashPassword(testPassword)
	if err != nil {
		t.Fatal(err)
	}
	store := identity.NewStore(pool)
	bootstrap, err := store.BootstrapPlatformUser(t.Context(), "scope-admin", "Scope Admin", passwordHash, "tenant-scopes-bootstrap")
	if err != nil {
		t.Fatal(err)
	}
	tokens, err := identity.NewTokenManager("tenant-scopes-test-secret-at-least-thirty-two-bytes", 5*time.Minute)
	if err != nil {
		t.Fatal(err)
	}
	identityService, err := identity.NewService(store, tokens, 24*time.Hour)
	if err != nil {
		t.Fatal(err)
	}
	server := httptest.NewServer(New(pool, identityService, Config{
		CookieSecure: false,
		APIKeyPepper: bytes.Repeat([]byte{0x52}, 32),
	}).Handler())
	t.Cleanup(server.Close)
	client := server.Client()
	admin, _ := loginWithPassword(t, client, server.URL, "scope-admin", testPassword)
	if bootstrap.ScopeID == (uuid.UUID{}) {
		t.Fatal("bootstrap returned an empty platform scope")
	}
	displayIDPattern := regexp.MustCompile(`^[1-9][0-9]{0,18}$`)
	legacyTenantID := uuid.New()
	legacyScopeID := uuid.New()
	if _, err := pool.Exec(context.Background(),
		`INSERT INTO tenants(id,display_name) VALUES($1,'Legacy Tenant')`, legacyTenantID); err != nil {
		t.Fatal(err)
	}
	if _, err := pool.Exec(context.Background(),
		`INSERT INTO access_scopes(id,kind,tenant_id) VALUES($1,'tenant',$2)`, legacyScopeID, legacyTenantID); err != nil {
		t.Fatal(err)
	}

	first := createManagedUser(t, client, server.URL, admin.AccessToken, "scope-create-first", map[string]any{
		"username": "scope-first", "password": tenantPassword, "display_name": "Alpha Tenant", "role": identity.UserRoleOwner,
	})
	second := createManagedUser(t, client, server.URL, admin.AccessToken, "scope-create-second", map[string]any{
		"username": "scope-second", "password": tenantPassword, "display_name": "Beta Tenant", "role": identity.UserRoleOwner,
	})
	if _, err := pool.Exec(context.Background(), `UPDATE tenants SET status='suspended' WHERE id=$1`, *second.TenantID); err != nil {
		t.Fatal(err)
	}

	response := identityRequest(t, client, http.MethodGet,
		server.URL+"/v1/admin/tenant-scopes?page=1&limit=1", nil, admin.AccessToken, "", "tenant-scopes-page")
	var page identity.TenantScopeList
	decodeResponse(t, response, http.StatusOK, &page)
	response.Body.Close()
	if page.Page != 1 || page.Limit != 1 || page.Total != 3 || len(page.Items) != 1 {
		t.Fatalf("tenant scope page = %#v", page)
	}
	if !displayIDPattern.MatchString(page.Items[0].DisplayID) {
		t.Fatalf("tenant scope display ID = %q, want a positive decimal string", page.Items[0].DisplayID)
	}

	response = identityRequest(t, client, http.MethodGet,
		server.URL+"/v1/admin/tenant-scopes?page=1&limit=100", nil, admin.AccessToken, "", "tenant-scopes-all")
	var all identity.TenantScopeList
	decodeResponse(t, response, http.StatusOK, &all)
	response.Body.Close()
	if all.Total != 3 || len(all.Items) != 3 {
		t.Fatalf("all tenant scopes = %#v, want three rows", all)
	}
	byTenant := make(map[uuid.UUID]identity.TenantScope, len(all.Items))
	displayIDs := make(map[string]struct{}, len(all.Items))
	for _, item := range all.Items {
		if !displayIDPattern.MatchString(item.DisplayID) {
			t.Fatalf("tenant %s display ID = %q, want a positive decimal string", item.TenantID, item.DisplayID)
		}
		if _, duplicate := displayIDs[item.DisplayID]; duplicate {
			t.Fatalf("duplicate tenant display ID %q in %#v", item.DisplayID, all.Items)
		}
		displayIDs[item.DisplayID] = struct{}{}
		byTenant[item.TenantID] = item
	}
	if legacy := byTenant[legacyTenantID]; legacy.ScopeID != legacyScopeID || legacy.TenantName != "Legacy Tenant" {
		t.Fatalf("legacy tenant scope = %#v", legacy)
	}
	if created := byTenant[*first.TenantID]; created.ScopeID != first.ScopeID || created.TenantName != "Alpha Tenant" {
		t.Fatalf("first managed tenant scope = %#v", created)
	}
	if created := byTenant[*second.TenantID]; created.ScopeID != second.ScopeID || created.TenantName != "Beta Tenant" {
		t.Fatalf("second managed tenant scope = %#v", created)
	}

	// An empty page must retain the count of the filtered result set. A
	// window-count-only query loses that information when OFFSET skips every row.
	response = identityRequest(t, client, http.MethodGet,
		server.URL+"/v1/admin/tenant-scopes?page=4&limit=1", nil, admin.AccessToken, "", "tenant-scopes-empty-page")
	var emptyPage identity.TenantScopeList
	decodeResponse(t, response, http.StatusOK, &emptyPage)
	response.Body.Close()
	if emptyPage.Page != 4 || emptyPage.Limit != 1 || emptyPage.Total != 3 || len(emptyPage.Items) != 0 {
		t.Fatalf("empty tenant scope page = %#v, want page=4 limit=1 total=3 items=[]", emptyPage)
	}

	response = identityRequest(t, client, http.MethodGet,
		server.URL+"/v1/admin/tenant-scopes?search=Beta%20Tenant", nil, admin.AccessToken, "", "tenant-scopes-search")
	var filtered identity.TenantScopeList
	decodeResponse(t, response, http.StatusOK, &filtered)
	response.Body.Close()
	if filtered.Total != 1 || len(filtered.Items) != 1 || filtered.Items[0].ScopeID != second.ScopeID ||
		filtered.Items[0].TenantID != *second.TenantID || filtered.Items[0].TenantName != "Beta Tenant" ||
		filtered.Items[0].DisplayID != byTenant[*second.TenantID].DisplayID || filtered.Items[0].Status != "suspended" {
		t.Fatalf("filtered tenant scopes = %#v", filtered)
	}

	response = identityRequest(t, client, http.MethodGet,
		server.URL+"/v1/admin/tenant-scopes?search="+byTenant[*second.TenantID].DisplayID,
		nil, admin.AccessToken, "", "tenant-scopes-display-id-search")
	var displayIDMatch identity.TenantScopeList
	decodeResponse(t, response, http.StatusOK, &displayIDMatch)
	response.Body.Close()
	if displayIDMatch.Total != 1 || len(displayIDMatch.Items) != 1 || displayIDMatch.Items[0].TenantID != *second.TenantID ||
		displayIDMatch.Items[0].DisplayID != byTenant[*second.TenantID].DisplayID {
		t.Fatalf("display-ID filtered tenant scopes = %#v", displayIDMatch)
	}

	response = identityRequest(t, client, http.MethodGet,
		server.URL+"/v1/admin/tenant-scopes?search="+second.ScopeID.String(),
		nil, admin.AccessToken, "", "tenant-scopes-scope-id-search")
	var scopeIDMatch identity.TenantScopeList
	decodeResponse(t, response, http.StatusOK, &scopeIDMatch)
	response.Body.Close()
	if scopeIDMatch.Total != 1 || len(scopeIDMatch.Items) != 1 || scopeIDMatch.Items[0].TenantID != *second.TenantID {
		t.Fatalf("scope-ID filtered tenant scopes = %#v", scopeIDMatch)
	}

	if _, err := pool.Exec(context.Background(), `UPDATE tenants SET status='closed' WHERE id=$1`, *first.TenantID); err != nil {
		t.Fatal(err)
	}
	response = identityRequest(t, client, http.MethodGet,
		server.URL+"/v1/admin/tenant-scopes?search=Alpha%20Tenant", nil, admin.AccessToken, "", "tenant-scopes-closed")
	var closed identity.TenantScopeList
	decodeResponse(t, response, http.StatusOK, &closed)
	response.Body.Close()
	if closed.Total != 1 || len(closed.Items) != 1 || closed.Items[0].TenantID != *first.TenantID || closed.Items[0].Status != "closed" {
		t.Fatalf("closed tenant scope = %#v", closed)
	}

	response = identityRequest(t, client, http.MethodGet,
		server.URL+"/v1/admin/tenant-scopes?search=does-not-exist", nil, admin.AccessToken, "", "tenant-scopes-no-match")
	var noMatch identity.TenantScopeList
	decodeResponse(t, response, http.StatusOK, &noMatch)
	response.Body.Close()
	if noMatch.Total != 0 || len(noMatch.Items) != 0 {
		t.Fatalf("no-match tenant scopes = %#v, want total=0 items=[]", noMatch)
	}

	for _, path := range []string{
		"/v1/admin/tenant-scopes?page=1&page=2",
		"/v1/admin/tenant-scopes?unknown=value",
	} {
		response = identityRequest(t, client, http.MethodGet, server.URL+path, nil, admin.AccessToken, "", "tenant-scopes-invalid")
		assertError(t, response, http.StatusBadRequest, "validation_error", "tenant-scopes-invalid")
		response.Body.Close()
	}

	tenant, _ := loginWithPassword(t, client, server.URL, "scope-first", tenantPassword)
	response = identityRequest(t, client, http.MethodGet, server.URL+"/v1/admin/tenant-scopes", nil, tenant.AccessToken, "", "tenant-scopes-tenant-denied")
	assertError(t, response, http.StatusForbidden, "permission_denied", "tenant-scopes-tenant-denied")
	response.Body.Close()

	// Keep the first fixture referenced so a future test change does not
	// accidentally stop creating two independent tenant scopes.
	if first.ScopeID == second.ScopeID {
		t.Fatal("tenant fixtures unexpectedly share a scope")
	}
}
