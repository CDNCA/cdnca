package certificateassethttp

import (
	"net/http"
	"slices"
	"testing"

	"github.com/google/uuid"
)

// CERT-05：高级筛选进服务端查询，HTTP 层逐项解析，非法值不进服务。
func TestHandlerListPassesAdvancedFiltersToService(t *testing.T) {
	fixture := newFixture()
	handler := fixture.handler(t, tenantSession(fixture.tenantID, "certificates.read"))
	provider := uuid.MustParse("6f1c8d0e-3b2a-4c5d-8e9f-0a1b2c3d4e5f")
	response := fixture.serve(handler, http.MethodGet, "/v1/certificate-assets?page=2&limit=10"+
		"&domain=example&domains=a.example.com,b.example.com&user=13800&certificate_id=12&name=prod&remark=cdn"+
		"&source=acme&dns_provider_id="+provider.String()+"&expiry=within90&auto_renew=false&issue=failed&sync=pending", "", nil)
	assertResponse(t, response, http.StatusOK, "")
	filters := fixture.service.listRequest.Filters
	if filters.Domain != "example" || !slices.Equal(filters.Domains, []string{"a.example.com", "b.example.com"}) ||
		filters.User != "13800" || filters.CertificateID != "12" || filters.Name != "prod" || filters.Remark != "cdn" ||
		filters.Source != "acme" || filters.DNSProviderID == nil || *filters.DNSProviderID != provider ||
		filters.Expiry != "within90" || filters.AutoRenew == nil || *filters.AutoRenew || filters.Issue != "failed" ||
		filters.Sync != "pending" {
		t.Fatalf("filters = %#v", filters)
	}
	for _, query := range []string{
		"domain=", "remark=", "dns_provider_id=not-a-uuid", "dns_provider_id=" + uuid.Nil.String(),
		"auto_renew=1", "auto_renew=", "expiry=&expiry=", "sync=a&sync=b",
	} {
		calls := fixture.service.listCalls
		response := fixture.serve(handler, http.MethodGet, "/v1/certificate-assets?"+query, "", nil)
		assertResponse(t, response, http.StatusBadRequest, "certificate_asset_invalid_request")
		if fixture.service.listCalls != calls {
			t.Fatalf("invalid query %q reached service", query)
		}
	}
}
