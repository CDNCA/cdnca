package marketsupply

import (
	"context"
	"encoding/json"
	"testing"

	"github.com/cdnca/cdnca/libs/marketproto/siteconf"
	"github.com/cdnca/cdnca/services/control-api/internal/httppolicycontrol"
	"github.com/google/uuid"
)

type recordingHTTPPolicies struct{ writes []httppolicycontrol.SystemSiteWrite }

func (r *recordingHTTPPolicies) SetSiteSystem(_ context.Context, request httppolicycontrol.SystemSiteWrite) (bool, error) {
	r.writes = append(r.writes, request)
	return true, nil
}

func httpPolicyConfig(t *testing.T, raw string) siteconf.Config {
	t.Helper()
	cfg := settingsConfig()
	cfg.HTTPPolicy = json.RawMessage(raw)
	if err := cfg.Normalize(); err != nil {
		t.Fatal(err)
	}
	return cfg
}

const sampleHTTPPolicy = `{"max_upload_bytes":1048576,"request_headers":[{"kind":"set","name":"X-From","values":["cdn"]}],` +
	`"response_headers":[],"rewrites":[],"redirect_allowed_hosts":[],"redirects":[],"cors":null,"referer_check":null}`

// fix-mktsiteconf3 ③: an http_policy block is written as the leaf site's
// HTTP policy by the tenant owner through the system write; absent removes it.
func TestHTTPPolicyBlockIsWrittenThroughTheSystemWrite(t *testing.T) {
	cfg := httpPolicyConfig(t, sampleHTTPPolicy)
	service := &Service{}
	if b := service.httpPolicyBlockers(cfg); len(b) != 1 || b[0].Code != "unsupported_http_policy" {
		t.Fatalf("unwired: %v", b)
	}
	recorder := &recordingHTTPPolicies{}
	service.WithHTTPPolicies(recorder)
	if b := service.httpPolicyBlockers(cfg); len(b) != 0 {
		t.Fatalf("blockers %v", b)
	}
	tenant := tenantRef{scopeID: uuid.New(), userID: uuid.New()}
	leaf := uuid.New()
	if err := service.applyHTTPPolicy(t.Context(), tenant, leaf, siteconf.CommitRequest{SiteID: uuid.New(), Revision: 3, Config: cfg}); err != nil {
		t.Fatal(err)
	}
	if err := service.applyHTTPPolicy(t.Context(), tenant, leaf, siteconf.CommitRequest{SiteID: uuid.New(), Revision: 4, Config: settingsConfig()}); err != nil {
		t.Fatal(err)
	}
	w := recorder.writes
	if len(w) != 2 || w[0].Config == nil || w[0].Config.RequestHeaders[0].Name != "X-From" || w[0].OwnerUserID != tenant.userID ||
		w[0].ScopeID != tenant.scopeID || w[0].SiteID != leaf || w[0].ActorRef != "job:market_leaf_sync" || w[1].Config != nil {
		t.Fatalf("writes %+v", w)
	}
}

func TestHTTPPolicyBlockersRefuseInvalidConfig(t *testing.T) {
	service := (&Service{}).WithHTTPPolicies(&recordingHTTPPolicies{})
	for name, raw := range map[string]string{
		"unknown field": `{"max_upload_bytes":1048576,"x":1}`,
		"no upload cap": `{"max_upload_bytes":0,"request_headers":[],"response_headers":[],"rewrites":[],"redirect_allowed_hosts":[],"redirects":[]}`,
	} {
		if b := service.httpPolicyBlockers(httpPolicyConfig(t, raw)); len(b) != 1 || b[0].Code != "http_policy_invalid" {
			t.Fatalf("%s: %v", name, b)
		}
	}
}
