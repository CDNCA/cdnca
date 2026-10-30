package httpapi

import (
	"encoding/json"
	"fmt"
	"net/http"
	"net/http/httptest"
	"testing"

	"github.com/cdnca/cdnca/services/control-api/internal/site"
)

// site-edit-parity2: a refused site field is reported by name (73 PATCH
// /v1/sites/01a163c0… answered a bare "request fields are invalid").
func TestWriteSiteErrorNamesTheRefusedField(t *testing.T) {
	recorder := httptest.NewRecorder()
	request := httptest.NewRequest(http.MethodPatch, "/v1/sites/x", nil)
	err := fmt.Errorf("update site: %w", &site.FieldError{Field: "cname_domain", Reason: "follows the package subscription (cdn.cdnca.com)"})
	(&Server{}).writeSiteError(recorder, request, err)
	if recorder.Code != http.StatusBadRequest {
		t.Fatalf("status = %d, want 400", recorder.Code)
	}
	var body struct {
		Error struct {
			Code    string `json:"code"`
			Details struct {
				Field string `json:"field"`
			} `json:"details"`
		} `json:"error"`
	}
	if err := json.Unmarshal(recorder.Body.Bytes(), &body); err != nil {
		t.Fatal(err)
	}
	if body.Error.Code != "validation_error" || body.Error.Details.Field != "cname_domain" {
		t.Fatalf("body = %s", recorder.Body.String())
	}
}
