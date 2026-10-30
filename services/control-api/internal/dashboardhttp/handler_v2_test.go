package dashboardhttp

import (
	"net/http"
	"net/http/httptest"
	"testing"
)

func TestHandlerPassesCanonicalSiteAndNodeDrilldown(t *testing.T) {
	auth := tenantAuthenticator()
	reader := new(fakeReader)
	handler := newTestHandler(t, auth, reader, 1<<20)
	request := httptest.NewRequest(http.MethodGet,
		"/v1/dashboard?range=today&timezone=UTC&site_id=018f0000-0000-7000-8000-000000000001&node_id=018f0000-0000-7000-8000-000000000002", nil)
	request.Header.Set("Authorization", "Bearer signed-session")
	response := httptest.NewRecorder()
	handler.ServeHTTP(response, request)
	if response.Code != http.StatusOK || reader.tenantCalls != 1 {
		t.Fatalf("status=%d body=%s calls=%d", response.Code, response.Body.String(), reader.tenantCalls)
	}
	if reader.query.SiteID != "018f0000-0000-7000-8000-000000000001" ||
		reader.query.NodeID != "018f0000-0000-7000-8000-000000000002" {
		t.Fatalf("drilldown query = %#v", reader.query)
	}
}
