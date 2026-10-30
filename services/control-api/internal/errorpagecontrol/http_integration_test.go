package errorpagecontrol

import (
	"bytes"
	"encoding/json"
	"net/http"
	"net/http/httptest"
	"strconv"
	"testing"
	"time"

	"github.com/cdnca/cdnca/services/control-api/internal/audit"
)

func TestErrorPageHTTPPostgreSQLSmoke(t *testing.T) {
	fixture := openErrorPageDatabase(t)
	identities := seedErrorPageIdentities(t, fixture.pool)
	store := newMemoryContentStore()
	service, err := NewServiceWithDependencies(
		fixture.pool,
		store,
		&testScanner{name: "http-smoke-scanner"},
		staticLimits{quota: AssetQuota{MaxAssetBytes: MaxEdgeResourceBytes, MaxAssets: 100, MaxTotalBytes: 8 << 20}},
		audit.New(fixture.pool),
		time.Now,
		testTxAuthorizer{},
	)
	if err != nil {
		t.Fatal(err)
	}
	tenantHandler, err := NewHandler(service, fixedAuthenticator{actor: identities.tenantOwner})
	if err != nil {
		t.Fatal(err)
	}
	platformHandler, err := NewHandler(service, fixedAuthenticator{actor: identities.platform})
	if err != nil {
		t.Fatal(err)
	}

	content := []byte("temporarily unavailable")
	response := serveErrorPageSmoke(t, tenantHandler, http.MethodPost, apiPrefix+"/assets/initiate",
		initiateAssetBody{
			ScopeID: identities.tenantScope, MIMEType: "text/plain",
			SizeBytes: int64(len(content)), SHA256: digestBytes(content),
		}, "asset-initiate", "", "application/json")
	assertSmokeStatus(t, response, http.StatusCreated)
	asset := decodeSmokeBody[WriteResult[Asset]](t, response).Value

	response = serveErrorPageSmoke(t, tenantHandler, http.MethodPut,
		apiPrefix+"/assets/"+asset.ID.String()+"/content", content, "asset-upload", "", "text/plain")
	assertSmokeStatus(t, response, http.StatusOK)
	response = serveErrorPageSmoke(t, tenantHandler, http.MethodPost,
		apiPrefix+"/assets/"+asset.ID.String()+"/finalize", nil, "asset-finalize", "", "")
	assertSmokeStatus(t, response, http.StatusOK)
	ready := decodeSmokeBody[WriteResult[Asset]](t, response).Value
	if ready.Status != StatusReady {
		t.Fatalf("finalized asset status=%s", ready.Status)
	}

	response = serveErrorPageSmoke(t, tenantHandler, http.MethodGet,
		apiPrefix+"/assets/"+asset.ID.String(), nil, "", "", "")
	assertSmokeStatus(t, response, http.StatusOK)
	response = serveErrorPageSmoke(t, tenantHandler, http.MethodGet,
		apiPrefix+"/assets?scope_id="+identities.tenantScope.String()+"&limit=10", nil, "", "", "")
	assertSmokeStatus(t, response, http.StatusOK)
	if page := decodeSmokeBody[AssetPage](t, response); len(page.Items) != 1 {
		t.Fatalf("asset list count=%d", len(page.Items))
	}

	response = serveErrorPageSmoke(t, tenantHandler, http.MethodPost, apiPrefix+"/rules", createRuleBody{
		Target: RuleTarget{Kind: ScopeSite, ScopeID: identities.tenantScope, SiteID: &identities.siteID},
		Fields: RuleFields{
			Category: CategoryEdgeRoute, Match: StatusSelector{Kind: MatchExact, From: 404},
			AssetID: asset.ID, Enabled: false,
		},
	}, "rule-create", "", "application/json")
	assertSmokeStatus(t, response, http.StatusCreated)
	rule := decodeSmokeBody[WriteResult[Rule]](t, response).Value

	fields := rule.Fields
	fields.Match.From, fields.Match.To = 403, 403
	response = serveErrorPageSmoke(t, tenantHandler, http.MethodPatch,
		apiPrefix+"/rules/"+rule.ID.String(), fields, "rule-update", revisionTag(rule.Revision), "application/json")
	assertSmokeStatus(t, response, http.StatusOK)
	rule = decodeSmokeBody[WriteResult[Rule]](t, response).Value
	response = serveErrorPageSmoke(t, tenantHandler, http.MethodPost,
		apiPrefix+"/rules/"+rule.ID.String()+"/enable", nil, "rule-enable", revisionTag(rule.Revision), "")
	assertSmokeStatus(t, response, http.StatusOK)
	rule = decodeSmokeBody[WriteResult[Rule]](t, response).Value
	response = serveErrorPageSmoke(t, tenantHandler, http.MethodPost,
		apiPrefix+"/rules/"+rule.ID.String()+"/disable", nil, "rule-disable", revisionTag(rule.Revision), "")
	assertSmokeStatus(t, response, http.StatusOK)
	rule = decodeSmokeBody[WriteResult[Rule]](t, response).Value

	response = serveErrorPageSmoke(t, tenantHandler, http.MethodGet,
		apiPrefix+"/rules/"+rule.ID.String(), nil, "", "", "")
	assertSmokeStatus(t, response, http.StatusOK)
	response = serveErrorPageSmoke(t, tenantHandler, http.MethodGet,
		apiPrefix+"/rules?scope_id="+identities.tenantScope.String()+"&site_id="+identities.siteID.String()+"&limit=10",
		nil, "", "", "")
	assertSmokeStatus(t, response, http.StatusOK)
	if page := decodeSmokeBody[RulePage](t, response); len(page.Items) != 1 {
		t.Fatalf("rule list count=%d", len(page.Items))
	}

	response = serveErrorPageSmoke(t, platformHandler, http.MethodGet,
		apiPrefix+"/publication-snapshot", nil, "", "", "")
	assertSmokeStatus(t, response, http.StatusOK)
	snapshot := decodeSmokeBody[PublicationSnapshot](t, response)
	if snapshot.Policy.Schema != SchemaV1 || snapshot.Policy.Revision < 1 || snapshot.SHA256 == "" {
		t.Fatalf("publication snapshot=%#v", snapshot)
	}

	response = serveErrorPageSmoke(t, tenantHandler, http.MethodDelete,
		apiPrefix+"/rules/"+rule.ID.String(), nil, "rule-delete", revisionTag(rule.Revision), "")
	assertSmokeStatus(t, response, http.StatusAccepted)
	response = serveErrorPageSmoke(t, tenantHandler, http.MethodDelete,
		apiPrefix+"/assets/"+asset.ID.String(), nil, "asset-delete", revisionTag(ready.Revision), "")
	assertSmokeStatus(t, response, http.StatusAccepted)
}

func serveErrorPageSmoke(
	t *testing.T,
	handler http.Handler,
	method, target string,
	body any,
	writeKey, revision, contentType string,
) *httptest.ResponseRecorder {
	t.Helper()
	var encoded []byte
	switch value := body.(type) {
	case nil:
	case []byte:
		encoded = value
	default:
		var err error
		encoded, err = json.Marshal(value)
		if err != nil {
			t.Fatal(err)
		}
	}
	request := httptest.NewRequest(method, "http://control.test"+target, bytes.NewReader(encoded))
	if contentType != "" {
		request.Header.Set("Content-Type", contentType)
	}
	if writeKey != "" {
		request.Header.Set("Idempotency-Key", writeKey)
		request.Header.Set("X-Request-ID", writeKey+"-request")
		request.Header.Set("X-Trace-ID", writeKey+"-trace")
	}
	if revision != "" {
		request.Header.Set("If-Match", revision)
	}
	response := httptest.NewRecorder()
	handler.ServeHTTP(response, request)
	return response
}

func assertSmokeStatus(t *testing.T, response *httptest.ResponseRecorder, expected int) {
	t.Helper()
	if response.Code != expected {
		t.Fatalf("status=%d want=%d body=%s", response.Code, expected, response.Body.String())
	}
	if response.Header().Get("Content-Security-Policy") == "" {
		t.Fatal("missing Content-Security-Policy")
	}
}

func decodeSmokeBody[T any](t *testing.T, response *httptest.ResponseRecorder) T {
	t.Helper()
	var result T
	if err := json.Unmarshal(response.Body.Bytes(), &result); err != nil {
		t.Fatalf("decode response body %q: %v", response.Body.String(), err)
	}
	return result
}

func revisionTag(revision int64) string {
	return `"` + strconv.FormatInt(revision, 10) + `"`
}
