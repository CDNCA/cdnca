//go:build integration

package httpapi

import (
	"bytes"
	"context"
	"net/http"
	"net/http/httptest"
	"os"
	"path/filepath"
	"sync/atomic"
	"testing"
	"time"

	"github.com/cdnca/cdnca/libs/rulepack"
	"github.com/cdnca/cdnca/services/control-api/internal/identity"
	"github.com/cdnca/cdnca/services/control-api/internal/rulepackcontrol"
)

// Publishing a site's rule pack mounts wakes the node artifact set
// distributor (Config.RuleMountsPublished); a refused publication does not.
func TestPublishSiteSecurityMountsWakesArtifactSets(t *testing.T) {
	pool := isolatedTestPool(t)
	passwordHash, err := identity.HashPassword(testPassword)
	if err != nil {
		t.Fatal(err)
	}
	identityStore := identity.NewStore(pool)
	if _, err := identityStore.BootstrapPlatformUser(context.Background(), "mountadmin", "Mount Admin", passwordHash, "mount-bootstrap"); err != nil {
		t.Fatal(err)
	}
	tenant := insertSecurityTenant(t, pool, "Mount Tenant", "mount-tenant", passwordHash)
	siteID := insertQuickBlockSite(t, pool, tenant.scopeID, tenant.userID)
	tokens, err := identity.NewTokenManager("rule-mounts-publish-integration-32b", 5*time.Minute)
	if err != nil {
		t.Fatal(err)
	}
	identityService, err := identity.NewService(identityStore, tokens, 24*time.Hour)
	if err != nil {
		t.Fatal(err)
	}
	var wakes atomic.Int32
	server := httptest.NewServer(New(pool, identityService, Config{APIKeyPepper: bytes.Repeat([]byte{0x52}, 32),
		RuleMountsPublished: func() { wakes.Add(1) }}).Handler())
	t.Cleanup(server.Close)
	client := server.Client()
	platformAuth, _ := loginOK(t, client, server.URL, "mountadmin")
	tenantAuth := loginForScope(t, client, server.URL, tenant.username, tenant.scopeID)
	call := func(method, path string, body any, token string) *http.Response {
		return siteRequest(t, client, method, server.URL+path, body, token, "", "")
	}
	publish := "/v1/sites/" + siteID.String() + "/security-mounts/publish"

	// Another tenant's request is refused before publishing: no wake.
	response := call(http.MethodPost, "/v1/sites/"+tenant.scopeID.String()+"/security-mounts/publish", nil, tenantAuth.AccessToken)
	if response.StatusCode < 400 {
		t.Fatalf("publish of an unknown site = %d", response.StatusCode)
	}
	response.Body.Close()
	if wakes.Load() != 0 {
		t.Fatalf("refused publication woke the distributor %d times", wakes.Load())
	}

	content, err := os.ReadFile(filepath.Join("..", "..", "..", "..", "libs", "rulepack", "testdata", "packs", "system-sqli.json"))
	if err != nil {
		t.Fatal(err)
	}
	request, _ := http.NewRequest(http.MethodPost, server.URL+"/v1/rule-packs", bytes.NewReader(content))
	request.Header.Set("Authorization", "Bearer "+platformAuth.AccessToken)
	imported, err := client.Do(request)
	if err != nil {
		t.Fatal(err)
	}
	var pack rulepackcontrol.Pack
	decodeResponse(t, imported, http.StatusCreated, &pack)
	response = call(http.MethodPut, "/v1/rule-packs/enablements", rulepackcontrol.OverrideInput{Level: rulepack.LevelPlatform,
		PackID: pack.PackID, State: rulepack.StateEnabled, AllowLower: true}, platformAuth.AccessToken)
	if response.StatusCode != http.StatusOK {
		t.Fatalf("enable = %d %s", response.StatusCode, readBody(response.Body))
	}
	response.Body.Close()

	var published rulepackcontrol.SiteMounts
	decodeResponse(t, call(http.MethodPost, publish, nil, tenantAuth.AccessToken), http.StatusOK, &published)
	if published.Published == nil || published.Published.Security.ResolvedSHA256 == "" || len(published.Published.Security.Mounts) != 1 {
		t.Fatalf("published = %+v", published.Published)
	}
	if wakes.Load() != 1 {
		t.Fatalf("publication woke the distributor %d times, want 1", wakes.Load())
	}
}
