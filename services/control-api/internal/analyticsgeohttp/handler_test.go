package analyticsgeohttp

import (
	"context"
	"crypto/sha256"
	"fmt"
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"
	"time"

	"github.com/cdnca/cdnca/services/control-api/internal/analyticsgeo"
	"github.com/cdnca/cdnca/services/control-api/internal/analyticslog"
)

type sourceStub struct{ page analyticsgeo.SourcePage }

var _ lookupService = (*analyticsgeo.AuthorityReaderAdapter)(nil)

func (source sourceStub) ReadEvents(_ context.Context, _ analyticsgeo.Actor, _ analyticsgeo.QueryRequest) (analyticsgeo.SourcePage, error) {
	return source.page, nil
}

func TestHandlerServesTenantGeoEvidenceAndRejectsTenantOverride(t *testing.T) {
	data := []byte(`{"version":"geo-2026.08","provider":"example-geo","published_at":"2026-08-01T00:00:00Z","effective_at":"2026-08-02T00:00:00Z","entries":[{"prefix":"2001:db8::/32","country_code":"CN","region":"CN-BJ","city":"Beijing","carrier":"IPv6-NET","asn":64512}]}`)
	digest := sha256.Sum256(data)
	catalog, err := analyticsgeo.NewCatalog([]analyticsgeo.CatalogInput{{Data: data, ExpectedSHA256: fmt.Sprintf("%x", digest)}}, "geo-2026.08")
	if err != nil {
		t.Fatal(err)
	}
	at := time.Date(2026, 8, 8, 3, 0, 0, 0, time.UTC)
	service, _ := analyticsgeo.NewService(sourceStub{page: analyticsgeo.SourcePage{Items: []analyticsgeo.SourceEvent{{
		EventID: "event-1", OccurredAt: at, SiteID: "018f0000-0000-7000-8000-000000000002",
		NodeID: "018f0000-0000-7000-8000-000000000003", ClientIP: "2001:db8::7", CountryCode: "CN", Carrier: "IPv6-NET",
	}}}}, catalog)
	handler, err := NewHandler(service, func(*http.Request) (analyticsgeo.Actor, error) {
		return analyticsgeo.Actor{ScopeKind: "tenant", TenantID: "018f0000-0000-7000-8000-000000000001", Permissions: []string{analyticslog.ReadPermission}}, nil
	}, Config{QueryTimeout: time.Second})
	if err != nil {
		t.Fatal(err)
	}
	query := "?from=2026-08-08T03:00:00Z&to=2026-08-08T03:00:00.001Z&site_id=018f0000-0000-7000-8000-000000000002&node_id=018f0000-0000-7000-8000-000000000003&client_ip=2001:db8::7"
	request := httptest.NewRequest(http.MethodGet, "/v1/analytics/logs/access/geo-evidence/event-1"+query, nil)
	response := httptest.NewRecorder()
	handler.ServeHTTP(response, request)
	if response.Code != http.StatusOK || !strings.Contains(response.Body.String(), `"database_provider":"example-geo"`) ||
		!strings.Contains(response.Body.String(), `"database_effective_at":"2026-08-02T00:00:00Z"`) ||
		!strings.Contains(response.Body.String(), `"address_family":"ipv6"`) ||
		!strings.Contains(response.Body.String(), `"lookup_reason":"prefix_match"`) ||
		!strings.Contains(response.Body.String(), `"city":"Beijing"`) || strings.Contains(response.Body.String(), "2001:db8") {
		t.Fatalf("response = %d %s", response.Code, response.Body.String())
	}

	request = httptest.NewRequest(http.MethodGet, "/v1/analytics/logs/access/geo-evidence/event-1"+query+"&tenant_id=018f0000-0000-7000-8000-000000000001", nil)
	response = httptest.NewRecorder()
	handler.ServeHTTP(response, request)
	if response.Code != http.StatusForbidden {
		t.Fatalf("tenant override status = %d body=%s", response.Code, response.Body.String())
	}
}
