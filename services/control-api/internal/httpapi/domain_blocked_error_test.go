package httpapi

import (
	"encoding/json"
	"fmt"
	"net/http"
	"net/http/httptest"
	"testing"

	"github.com/cdnca/cdnca/services/control-api/internal/domaintrust"
)

// Certificate orders and CNAME names reuse the site 422 domain_blocked shape.
func TestBlockedDomainErrorIs422WithoutReason(t *testing.T) {
	server := &Server{}
	recorder := httptest.NewRecorder()
	err := fmt.Errorf("create order: %w", &domaintrust.DomainError{Err: domaintrust.ErrDomainBlocked, Domain: "www.evil.test"})
	server.writeError(recorder, httptest.NewRequest(http.MethodPost, "/v1/certificates/orders", nil), err)
	var body struct {
		Error map[string]string `json:"error"`
	}
	if decodeErr := json.Unmarshal(recorder.Body.Bytes(), &body); decodeErr != nil {
		t.Fatal(decodeErr)
	}
	if recorder.Code != http.StatusUnprocessableEntity || body.Error["code"] != "domain_blocked" ||
		body.Error["domain"] != "www.evil.test" || body.Error["message"] != "site domain is not allowed" {
		t.Fatalf("response %d %v", recorder.Code, body.Error)
	}
}
