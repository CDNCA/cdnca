package httpapi

import (
	"encoding/json"
	"fmt"
	"net/http"
	"net/http/httptest"
	"testing"

	"github.com/cdnca/cdnca/services/control-api/internal/entitlementguard"
)

// 发布被许可拒绝时，403 entitlement_feature_denied 在
// details.required_feature 里写明缺的功能码；未带功能码的拒绝保持原样（不带 details）。
func TestEntitlementFeatureDeniedNamesTheRequiredFeature(t *testing.T) {
	server := &Server{}
	for name, check := range map[string]struct {
		err  error
		want string
	}{
		"named":   {fmt.Errorf("publish: %w", &entitlementguard.FeatureDeniedError{Feature: "packages.manage"}), `{"required_feature":"packages.manage"}`},
		"unnamed": {entitlementguard.ErrFeatureDenied, ``},
	} {
		recorder := httptest.NewRecorder()
		server.writeError(recorder, httptest.NewRequest(http.MethodPost, "/v1/admin/packages/x/publish", nil), check.err)
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
		if recorder.Code != http.StatusForbidden || body.Error.Code != "entitlement_feature_denied" ||
			string(body.Error.Details) != check.want || body.Error.Message == "" || body.Error.RequestID == nil {
			t.Fatalf("%s: %d %s", name, recorder.Code, recorder.Body.String())
		}
	}
}

func TestFeatureDeniedErrorIsTheFeatureDenial(t *testing.T) {
	err := fmt.Errorf("wrapped: %w", &entitlementguard.FeatureDeniedError{Feature: "packages.manage"})
	if !entitlementguard.IsDenial(err) {
		t.Fatalf("FeatureDeniedError is not a denial: %v", err)
	}
}
