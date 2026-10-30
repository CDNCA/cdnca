package httpapi

import (
	"encoding/json"
	"fmt"
	"net/http"
	"net/http/httptest"
	"testing"

	"github.com/cdnca/cdnca/services/control-api/internal/securitypolicy"
	"github.com/google/uuid"
)

// sec-ui-polish D3: a refused delete of a library still running on sites
// carries the sites in details.sites, so the page can list and link them.
func TestSecurityPolicyInUseNamesTheSites(t *testing.T) {
	server := &Server{}
	for name, check := range map[string]struct {
		err  error
		want string
	}{
		"named": {fmt.Errorf("delete: %w", &securitypolicy.InUseError{Domains: []string{"a.example.com", "b.example.com"},
			SiteIDs: []uuid.UUID{uuid.MustParse("11111111-1111-4111-8111-111111111111"), uuid.MustParse("22222222-2222-4222-8222-222222222222")}}),
			`{"sites":[{"id":"11111111-1111-4111-8111-111111111111","domain":"a.example.com"},{"id":"22222222-2222-4222-8222-222222222222","domain":"b.example.com"}]}`},
		"unnamed": {securitypolicy.ErrInUse, `{"sites":[]}`},
	} {
		recorder := httptest.NewRecorder()
		server.writeError(recorder, httptest.NewRequest(http.MethodDelete, "/v1/security-policies/x", nil), check.err)
		var body struct {
			Error struct {
				Code      string          `json:"code"`
				Message   string          `json:"message"`
				RequestID *string         `json:"request_id"`
				Details   json.RawMessage `json:"details"`
			} `json:"error"`
		}
		if err := json.Unmarshal(recorder.Body.Bytes(), &body); err != nil {
			t.Fatal(err)
		}
		if recorder.Code != http.StatusConflict || body.Error.Code != "security_policy_in_use" ||
			string(body.Error.Details) != check.want || body.Error.Message == "" || body.Error.RequestID == nil {
			t.Fatalf("%s: %d %s", name, recorder.Code, recorder.Body.String())
		}
	}
}
