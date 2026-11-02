package httpapi

import (
	"encoding/json"
	"fmt"
	"net/http"
	"net/http/httptest"
	"os/exec"
	"strings"
	"testing"

	"github.com/cdnca/cdnca/services/control-api/internal/dnsacme"
)

// 受理时拒绝的证书申请是 422，带要改的域名与页面标记的字段，并符合 dns-acme.yaml 的 Error。
func TestCertificateOrderDomainErrors(t *testing.T) {
	server := &Server{}
	var bodies []json.RawMessage
	for _, sample := range []struct {
		err          error
		code, field  string
		wantDomain   string
		statusWanted int
	}{
		{fmt.Errorf("create: %w", &dnsacme.OrderDomainError{Err: dnsacme.ErrDNSZoneUnavailable, Domain: "tenant.example.com"}),
			"certificate_dns_zone_unavailable", "dns_provider_id", "tenant.example.com", http.StatusUnprocessableEntity},
		{&dnsacme.OrderDomainError{Err: dnsacme.ErrHTTP01NotServing, Domain: "www.tenant.example.com"},
			"certificate_http01_not_serving", "domains", "www.tenant.example.com", http.StatusUnprocessableEntity},
	} {
		recorder := httptest.NewRecorder()
		server.writeError(recorder, httptest.NewRequest(http.MethodPost, "/v1/certificate-orders", nil), sample.err)
		var envelope struct {
			Error struct {
				Code    string `json:"code"`
				Domain  string `json:"domain"`
				Details struct {
					Field string `json:"field"`
				} `json:"details"`
			} `json:"error"`
		}
		if recorder.Code != sample.statusWanted || json.Unmarshal(recorder.Body.Bytes(), &envelope) != nil ||
			envelope.Error.Code != sample.code || envelope.Error.Domain != sample.wantDomain ||
			envelope.Error.Details.Field != sample.field {
			t.Fatalf("%v -> %d %s", sample.err, recorder.Code, recorder.Body.String())
		}
		bodies = append(bodies, json.RawMessage(strings.TrimSpace(recorder.Body.String())))
	}
	if _, err := exec.LookPath("node"); err != nil {
		t.Skip("node is not installed")
	}
	assertOpenAPIErrorBodies(t, "../../../../api/openapi/v1/dns-acme.yaml", "Error", bodies, []json.RawMessage{})
}
