package httpapi

import (
	"bytes"
	"context"
	"encoding/json"
	"net/http"
	"net/http/httptest"
	"reflect"
	"testing"
	"time"

	"github.com/cdnca/cdnca/libs/entitlement"
	"github.com/cdnca/cdnca/services/control-api/internal/entitlementguard"
	"github.com/cdnca/cdnca/services/control-api/internal/identity"
	"github.com/jackc/pgx/v5/pgxpool"
)

const moduleProbe = "module.pa15_probe"

func installModuleTestLease(t *testing.T, pool *pgxpool.Pool, trust *entitlementguard.TrustStore, key siteTestKey,
	now time.Time, serial uint64, modules ...string) {
	t.Helper()
	features := []entitlement.Feature{}
	for _, code := range modules {
		features = append(features, entitlement.Feature{Code: code})
	}
	features = append(features, entitlement.Feature{Code: entitlementguard.FeatureSitesManage})
	lease := entitlement.Lease{
		Schema: entitlement.SchemaV1, Audience: entitlement.ControlAudience,
		CustomerID:     "11111111-1111-4111-8111-111111111111",
		InstallationID: "22222222-2222-4222-8222-222222222222",
		LicenseID:      "33333333-3333-4333-8333-333333333333",
		Serial:         serial, NotBefore: now.Add(-time.Hour).Unix(), ExpiresAt: now.Add(time.Hour).Unix(),
		GraceUntil: now.Add(2 * time.Hour).Unix(),
		Version:    entitlement.VersionRange{Channel: "stable", Min: "0.1.0", Max: "1.0.0"},
		Features:   features,
		Quotas:     []entitlement.Quota{{Code: entitlementguard.QuotaDomainsCount, Limit: 10}},
	}
	ensureHTTPTestRevocation(t, pool, trust, key, now, lease)
	signed, err := entitlement.Sign(context.Background(), lease, key)
	if err != nil {
		t.Fatalf("Sign() error = %v", err)
	}
	if _, err := entitlementguard.NewService(pool, trust).Install(context.Background(), entitlementguard.InstallBundle{
		InstallationID: lease.InstallationID, SignedLease: signed}, now); err != nil {
		t.Fatalf("Install() error = %v", err)
	}
}

// Acceptance (PA-15 API entry and menu source): with the module granted,
// GET /v1/modules lists it and the module route answers; re-signing the lease
// without it removes it from GET /v1/modules and the route answers 403
// entitlement_feature_denied; granting it again restores both.
func TestModuleEntitlementHTTPFlow(t *testing.T) {
	pool := isolatedTestPool(t)
	passwordHash, err := identity.HashPassword(testPassword)
	if err != nil {
		t.Fatal(err)
	}
	identityStore := identity.NewStore(pool)
	if _, err := identityStore.BootstrapPlatformUser(context.Background(), "moduleadmin", "Module Admin",
		passwordHash, "module-bootstrap"); err != nil {
		t.Fatal(err)
	}
	tenant := insertSiteTenant(t, pool, "module-tenant", "module-user", "Module User", passwordHash)
	tokens, err := identity.NewTokenManager("module-test-secret-at-least-thirty-two-bytes", 5*time.Minute)
	if err != nil {
		t.Fatal(err)
	}
	identityService, err := identity.NewService(identityStore, tokens, 24*time.Hour)
	if err != nil {
		t.Fatal(err)
	}
	var now time.Time
	if err := pool.QueryRow(t.Context(), `SELECT date_trunc('second',clock_timestamp())`).Scan(&now); err != nil {
		t.Fatal(err)
	}
	key := newSiteTestKey(t, "module-test-key-1")
	trust := newSiteTestTrust(t, key)
	api := New(pool, identityService, Config{APIKeyPepper: bytes.Repeat([]byte{0x52}, 32),
		Now: func() time.Time { return now }, EntitlementTrust: trust})
	mux := http.NewServeMux()
	mux.Handle("/v1/modules", api.Handler())
	mux.Handle("/v1/probe", api.withRequestID(api.requireModule(moduleProbe, "module_probe", "module_probe.use",
		http.HandlerFunc(func(w http.ResponseWriter, _ *http.Request) { w.WriteHeader(http.StatusNoContent) }))))
	mux.Handle("/", api.Handler())
	server := httptest.NewServer(mux)
	t.Cleanup(server.Close)
	client := server.Client()
	admin, _ := loginOK(t, client, server.URL, "moduleadmin")
	user := loginForScope(t, client, server.URL, tenant.username, tenant.scopeID)

	listModules := func(token string) modulesResponse {
		t.Helper()
		request, _ := http.NewRequest(http.MethodGet, server.URL+"/v1/modules", nil)
		request.Header.Set("Authorization", "Bearer "+token)
		response, err := client.Do(request)
		if err != nil {
			t.Fatal(err)
		}
		defer response.Body.Close()
		if response.StatusCode != http.StatusOK {
			t.Fatalf("GET /v1/modules = %d %s", response.StatusCode, readBody(response.Body))
		}
		var body modulesResponse
		if err := json.NewDecoder(response.Body).Decode(&body); err != nil {
			t.Fatal(err)
		}
		return body
	}
	probe := func(token, requestID string) *http.Response {
		t.Helper()
		request, _ := http.NewRequest(http.MethodGet, server.URL+"/v1/probe", nil)
		request.Header.Set("Authorization", "Bearer "+token)
		request.Header.Set("X-Request-ID", requestID)
		response, err := client.Do(request)
		if err != nil {
			t.Fatal(err)
		}
		return response
	}

	unauthenticated, err := client.Get(server.URL + "/v1/modules")
	if err != nil {
		t.Fatal(err)
	}
	if unauthenticated.StatusCode != http.StatusUnauthorized {
		t.Fatalf("GET /v1/modules without session = %d", unauthenticated.StatusCode)
	}
	unauthenticated.Body.Close()
	if got := listModules(admin.AccessToken); got.Status != entitlementguard.StatusUninstalled || len(got.Modules) != 0 {
		t.Fatalf("modules without lease = %+v", got)
	}

	installModuleTestLease(t, pool, trust, key, now, 1, moduleProbe, "pack.crs")
	for _, token := range []string{admin.AccessToken, user.AccessToken} {
		if got := listModules(token); got.Status != "valid" || got.LeaseSerial != 1 ||
			!reflect.DeepEqual(got.Modules, []string{moduleProbe, "pack.crs"}) {
			t.Fatalf("modules granted = %+v", got)
		}
	}
	if response := probe(user.AccessToken, "module-probe-granted"); response.StatusCode != http.StatusNoContent {
		t.Fatalf("probe granted = %d %s", response.StatusCode, readBody(response.Body))
	}

	installModuleTestLease(t, pool, trust, key, now, 2, "pack.crs")
	if got := listModules(user.AccessToken); !reflect.DeepEqual(got.Modules, []string{"pack.crs"}) {
		t.Fatalf("modules revoked = %+v", got)
	}
	response := probe(user.AccessToken, "module-probe-revoked")
	assertError(t, response, http.StatusForbidden, "entitlement_feature_denied", "module-probe-revoked")
	response.Body.Close()
	var reason string
	if err := pool.QueryRow(t.Context(), `SELECT payload->>'reason' FROM audit_events
		WHERE action='entitlement.guard.reject' AND request_id='module-probe-revoked'`).Scan(&reason); err != nil ||
		reason != "feature_missing" {
		t.Fatalf("probe denial audit reason = %q, %v", reason, err)
	}

	installModuleTestLease(t, pool, trust, key, now, 3, moduleProbe, "pack.crs")
	if got := listModules(admin.AccessToken); !reflect.DeepEqual(got.Modules, []string{moduleProbe, "pack.crs"}) {
		t.Fatalf("modules restored = %+v", got)
	}
	if response := probe(user.AccessToken, "module-probe-restored"); response.StatusCode != http.StatusNoContent {
		t.Fatalf("probe restored = %d %s", response.StatusCode, readBody(response.Body))
	}
	var changes int
	if err := pool.QueryRow(t.Context(), `SELECT count(*) FROM audit_events WHERE action=$1`,
		entitlementguard.ModulesChangedAction).Scan(&changes); err != nil || changes != 3 {
		t.Fatalf("module change audits = %d, %v", changes, err)
	}
}
