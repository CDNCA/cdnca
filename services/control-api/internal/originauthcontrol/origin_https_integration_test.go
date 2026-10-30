//go:build integration

package originauthcontrol

import (
	"net/http"
	"testing"
)

// The signature names https://<bucket>, so a rule is
// accepted only on an HTTPS origin, and the site's pool cannot leave HTTPS
// while an enabled rule signs it.
func TestOriginAuthRuleRequiresHTTPSOrigin(t *testing.T) {
	fixture := newRuntimePGFixture(t)
	if _, err := fixture.pool.Exec(t.Context(), `UPDATE site_origin_pools SET origin_scheme='http' WHERE site_id=$1`, fixture.siteA); err != nil {
		t.Fatal(err)
	}
	base := "/v1/tenant-scopes/" + fixture.tenantScopeID.String() + "/origin-auth"
	credential := createVerifiedRuntimeCredential(t, fixture, "https-only")
	create := createRuleBody{SiteID: fixture.siteA.String(), SourcePosition: 1,
		Config: s3RuleConfig(credential.ID, credential.Revision), Enabled: true}
	response := runtimeServe(fixture.handler, http.MethodPost, base+"/rules", create, fixture.ownerToken, "https-only-plain", "")
	if response.Code == http.StatusCreated {
		t.Fatal("a rule was accepted on a plain HTTP origin")
	}
	if _, err := fixture.pool.Exec(t.Context(), `UPDATE site_origin_pools SET origin_scheme='https' WHERE site_id=$1`, fixture.siteA); err != nil {
		t.Fatal(err)
	}
	assertRuntimeStatus(t, runtimeServe(fixture.handler, http.MethodPost, base+"/rules", create, fixture.ownerToken,
		"https-only-tls", ""), http.StatusCreated)
	// The site's own guard (site.checkOriginAuthHTTPS) is covered by
	// httpapi's TestSiteOriginHTTPFlow subtest against this same rule shape.
}
