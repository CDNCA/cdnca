//go:build integration

package httpapi

import (
	"bytes"
	"context"
	"fmt"
	"net/http"
	"net/http/httptest"
	"reflect"
	"testing"
	"time"

	"github.com/cdnca/cdnca/services/control-api/internal/identity"
	"github.com/cdnca/cdnca/services/control-api/internal/site"
)

func TestSiteConditionalOriginHTTPFlowTenantRBACCASAndIdempotency(t *testing.T) {
	pool := isolatedTestPool(t)
	key := newSiteTestKey(t, "control-site-conditional-origin-key")
	trust := newSiteTestTrust(t, key)
	installSiteTestEntitlement(t, pool, trust, time.Now(), siteTestLeaseOptions{serial: 1, limit: 100, key: key})
	passwordHash, err := identity.HashPassword(testPassword)
	if err != nil {
		t.Fatal(err)
	}
	// Site creation inherits the platform configuration (bdc9144a), so the
	// installation needs its bootstrapped platform scope like production.
	if _, err := identity.NewStore(pool).BootstrapPlatformUser(t.Context(), "conditional-admin",
		"Conditional Admin", passwordHash, "conditional-bootstrap"); err != nil {
		t.Fatal(err)
	}
	tenantA := insertSiteTenant(t, pool, "conditional-a", "conditional-a-user", "Conditional A", passwordHash)
	tenantB := insertSiteTenant(t, pool, "conditional-b", "conditional-b-user", "Conditional B", passwordHash)
	insertSiteScopeUser(t, pool, tenantA.scopeID, "conditional-reader", "Conditional Reader", passwordHash, []string{"sites.read"})
	tokens, err := identity.NewTokenManager("conditional-origin-secret-at-least-32-bytes", 5*time.Minute)
	if err != nil {
		t.Fatal(err)
	}
	identityService, err := identity.NewService(identity.NewStore(pool), tokens, 24*time.Hour)
	if err != nil {
		t.Fatal(err)
	}
	server := httptest.NewServer(New(pool, identityService, Config{APIKeyPepper: bytes.Repeat([]byte{0x52}, 32), EntitlementTrust: trust}).Handler())
	t.Cleanup(server.Close)
	authA := loginForScope(t, server.Client(), server.URL, tenantA.username, tenantA.scopeID)
	authB := loginForScope(t, server.Client(), server.URL, tenantB.username, tenantB.scopeID)
	reader := loginForScope(t, server.Client(), server.URL, "conditional-reader", tenantA.scopeID)
	created := createSite(t, server.Client(), server.URL, authA.AccessToken, "conditional-create", createSiteRequest{Basic: validSiteBasic("conditional.example.test", "192.0.2.10")})
	path := server.URL + "/v1/sites/" + created.ID.String() + "/origin-routing"
	document := validHTTPConditionalOriginDocument()

	denied := siteRequest(t, server.Client(), http.MethodPut, path, document, reader.AccessToken, "conditional-denied", `"1"`)
	assertError(t, denied, http.StatusForbidden, "permission_denied", "")
	denied.Body.Close()
	crossScope := siteRequest(t, server.Client(), http.MethodGet, path, nil, authB.AccessToken, "", "")
	assertError(t, crossScope, http.StatusNotFound, "site_not_found", "")
	crossScope.Body.Close()

	updated := siteRequest(t, server.Client(), http.MethodPut, path, document, authA.AccessToken, "conditional-put", `"1"`)
	var state site.ConditionalOriginState
	decodeResponse(t, updated, http.StatusOK, &state)
	updated.Body.Close()
	if state.Version != 2 || state.Document.Schema != site.ConditionalOriginSchemaV1 {
		t.Fatalf("updated state = %#v", state)
	}
	replayed := siteRequest(t, server.Client(), http.MethodPut, path, document, authA.AccessToken, "conditional-put", `"1"`)
	var replayedState site.ConditionalOriginState
	decodeResponse(t, replayed, http.StatusOK, &replayedState)
	replayed.Body.Close()
	if replayedState.Version != state.Version {
		t.Fatalf("replayed version = %d, want %d", replayedState.Version, state.Version)
	}

	different := document
	different.Retry.MaxAttempts = 4
	conflict := siteRequest(t, server.Client(), http.MethodPut, path, different, authA.AccessToken, "conditional-put", `"1"`)
	assertError(t, conflict, http.StatusConflict, "idempotency_conflict", "")
	conflict.Body.Close()
	stale := siteRequest(t, server.Client(), http.MethodPut, path, document, authA.AccessToken, "conditional-stale", `"1"`)
	assertError(t, stale, http.StatusConflict, "version_conflict", "")
	stale.Body.Close()

	read := siteRequest(t, server.Client(), http.MethodGet, path, nil, reader.AccessToken, "", "")
	var readState site.ConditionalOriginState
	decodeResponse(t, read, http.StatusOK, &readState)
	read.Body.Close()
	if readState.SiteID != created.ID || readState.Version != 2 {
		t.Fatalf("read state = %#v", readState)
	}
	var audits int
	if err := pool.QueryRow(context.Background(), `SELECT count(*) FROM audit_events
		WHERE scope_id=$1 AND action='site.origin_route.update' AND resource_id=$2`, tenantA.scopeID, created.ID.String()).Scan(&audits); err != nil {
		t.Fatal(err)
	}
	if audits != 1 {
		t.Fatalf("audit count = %d, want 1", audits)
	}
}

// TestSiteConditionalOriginDNSOriginSavesAndReadsBack (Codex A15/ORIGIN-DB-01):
// a DNS origin host in the default pool used to hit the inet column (22P02)
// and the PUT returned 500; it now saves (200), reads back identically and
// enters the published route facts. IP still works, an invalid host is 400
// before any write, a stale version is 409 and the stored document survives.
func TestSiteConditionalOriginDNSOriginSavesAndReadsBack(t *testing.T) {
	pool := isolatedTestPool(t)
	key := newSiteTestKey(t, "control-site-conditional-origin-dns-key")
	trust := newSiteTestTrust(t, key)
	installSiteTestEntitlement(t, pool, trust, time.Now(), siteTestLeaseOptions{serial: 1, limit: 100, key: key})
	passwordHash, err := identity.HashPassword(testPassword)
	if err != nil {
		t.Fatal(err)
	}
	if _, err := identity.NewStore(pool).BootstrapPlatformUser(t.Context(), "conditional-dns-admin",
		"Conditional DNS Admin", passwordHash, "conditional-dns-bootstrap"); err != nil {
		t.Fatal(err)
	}
	tenant := insertSiteTenant(t, pool, "conditional-dns", "conditional-dns-user", "Conditional DNS", passwordHash)
	tokens, err := identity.NewTokenManager("conditional-origin-dns-secret-at-least-32-bytes", 5*time.Minute)
	if err != nil {
		t.Fatal(err)
	}
	identityService, err := identity.NewService(identity.NewStore(pool), tokens, 24*time.Hour)
	if err != nil {
		t.Fatal(err)
	}
	server := httptest.NewServer(New(pool, identityService, Config{APIKeyPepper: bytes.Repeat([]byte{0x53}, 32), EntitlementTrust: trust}).Handler())
	t.Cleanup(server.Close)
	auth := loginForScope(t, server.Client(), server.URL, tenant.username, tenant.scopeID)
	created := createSite(t, server.Client(), server.URL, auth.AccessToken, "conditional-dns-create",
		createSiteRequest{Basic: validSiteBasic("conditional-dns.example.test", "192.0.2.10")})
	path := server.URL + "/v1/sites/" + created.ID.String() + "/origin-routing"

	readState := func() site.ConditionalOriginState {
		t.Helper()
		response := siteRequest(t, server.Client(), http.MethodGet, path, nil, auth.AccessToken, "", "")
		var state site.ConditionalOriginState
		decodeResponse(t, response, http.StatusOK, &state)
		response.Body.Close()
		return state
	}
	initial := readState()

	// the reported browser body: the default document with its endpoint host
	// changed to a DNS name (upper case and a trailing dot are canonicalised)
	dns := initial.Document
	dns.Pools = append([]site.ConditionalOriginPool(nil), dns.Pools...)
	dns.Pools[0].Endpoints = []site.ConditionalOriginEndpoint{{ID: "origin-01", Host: "Origin.Example.Test.", Port: 443, Weight: 10}}
	dns.Pools = append(dns.Pools, site.ConditionalOriginPool{ID: "mixed", Endpoints: []site.ConditionalOriginEndpoint{
		{ID: "dns-b", Host: "backup.example.test", Port: 8080, Weight: 1},
		{ID: "v6", Host: "2001:db8::20", Port: 80, Weight: 1},
	}})
	dns.Retry.MaxAttempts = 2
	saved := siteRequest(t, server.Client(), http.MethodPut, path, dns, auth.AccessToken, "conditional-dns-put",
		fmt.Sprintf(`"%d"`, initial.Version))
	var savedState site.ConditionalOriginState
	decodeResponse(t, saved, http.StatusOK, &savedState)
	saved.Body.Close()
	read := readState()
	if read.Version != initial.Version+1 || !reflect.DeepEqual(read.Document, savedState.Document) {
		t.Fatalf("read back %#v, saved %#v", read.Document, savedState.Document)
	}
	hosts := map[string]string{}
	for _, item := range read.Document.Pools {
		for _, endpoint := range item.Endpoints {
			hosts[endpoint.ID] = endpoint.Host
		}
	}
	if hosts["origin-01"] != "origin.example.test" || hosts["dns-b"] != "backup.example.test" || hosts["v6"] != "2001:db8::20" ||
		read.Document.Retry.MaxAttempts != 2 {
		t.Fatalf("stored hosts %v retry %d", hosts, read.Document.Retry.MaxAttempts)
	}
	var stored string
	if err := pool.QueryRow(t.Context(), `SELECT host FROM site_origin_route_endpoints
		WHERE site_id=$1 AND endpoint_id='origin-01'`, created.ID).Scan(&stored); err != nil || stored != "origin.example.test" {
		t.Fatalf("stored endpoint host = %q, %v", stored, err)
	}

	// IP regression on the next version
	ip := read.Document
	ip.Pools = append([]site.ConditionalOriginPool(nil), ip.Pools...)
	for index := range ip.Pools {
		if ip.Pools[index].ID == read.Document.DefaultPoolID {
			ip.Pools[index].Endpoints = []site.ConditionalOriginEndpoint{{ID: "origin-01", Host: "198.51.100.30", Port: 80, Weight: 5}}
		}
	}
	ipSaved := siteRequest(t, server.Client(), http.MethodPut, path, ip, auth.AccessToken, "conditional-dns-ip",
		fmt.Sprintf(`"%d"`, read.Version))
	decodeResponse(t, ipSaved, http.StatusOK, &savedState)
	ipSaved.Body.Close()
	afterIP := readState()
	if !reflect.DeepEqual(afterIP.Document, savedState.Document) {
		t.Fatalf("IP read back %#v, saved %#v", afterIP.Document, savedState.Document)
	}

	for index, host := range []string{"localhost", "origin", "0.0.0.0", "169.254.0.1", "fe80::1", "a_b.example.test", "192.0.2.0/24"} {
		bad := afterIP.Document
		bad.Pools = append([]site.ConditionalOriginPool(nil), bad.Pools...)
		bad.Pools[0].Endpoints = []site.ConditionalOriginEndpoint{{ID: "bad", Host: host, Port: 80, Weight: 1}}
		response := siteRequest(t, server.Client(), http.MethodPut, path, bad, auth.AccessToken,
			fmt.Sprintf("conditional-dns-bad-%d", index), fmt.Sprintf(`"%d"`, afterIP.Version))
		assertError(t, response, http.StatusBadRequest, "validation_error", "")
		response.Body.Close()
	}
	stale := siteRequest(t, server.Client(), http.MethodPut, path, dns, auth.AccessToken, "conditional-dns-stale",
		fmt.Sprintf(`"%d"`, initial.Version))
	assertError(t, stale, http.StatusConflict, "version_conflict", "")
	stale.Body.Close()
	if final := readState(); final.Version != afterIP.Version || !reflect.DeepEqual(final.Document, afterIP.Document) {
		t.Fatalf("rejected writes changed the stored document: %#v", final)
	}
}

func validHTTPConditionalOriginDocument() site.ConditionalOriginDocument {
	return site.ConditionalOriginDocument{
		Schema: site.ConditionalOriginSchemaV1,
		Pools: []site.ConditionalOriginPool{
			{ID: "primary", Endpoints: []site.ConditionalOriginEndpoint{{ID: "primary-a", Host: "192.0.2.10", Port: 80, Weight: 100}}},
			{ID: "backup", Endpoints: []site.ConditionalOriginEndpoint{{ID: "backup-a", Host: "198.51.100.10", Port: 8080, Weight: 100}}},
		},
		DefaultPoolID: "primary",
		Routes:        []site.ConditionalOriginRoute{{ID: "private", Priority: 100, PathPrefix: "/private", NodeRegions: []string{"cn-east"}, ClientCIDRs: []string{"203.0.113.0/24"}, PoolID: "primary", FallbackPoolID: "backup"}},
		Retry:         site.ConditionalOriginRetry{Methods: []string{"GET", "HEAD"}, MaxAttempts: 3, ConnectTimeoutMS: 500, ReadTimeoutMS: 1500, TotalBudgetMS: 5000},
	}
}
