package httpapi

import (
	"encoding/json"
	"fmt"
	"net/http"
	"net/http/httptest"
	"testing"

	"github.com/cdnca/cdnca/services/control-api/internal/identity"
)

// A member that must change its password gets 403 password_change_required.
func TestPasswordChangeRequiredIs403(t *testing.T) {
	server := &Server{}
	recorder := httptest.NewRecorder()
	server.writeError(recorder, httptest.NewRequest(http.MethodGet, "/v1/sites", nil), fmt.Errorf("auth: %w", identity.ErrPasswordChangeRequired))
	var body struct {
		Error map[string]string `json:"error"`
	}
	if err := json.Unmarshal(recorder.Body.Bytes(), &body); err != nil {
		t.Fatal(err)
	}
	if recorder.Code != http.StatusForbidden || body.Error["code"] != "password_change_required" {
		t.Fatalf("response %d %v", recorder.Code, body.Error)
	}
}

// The deletion refusal carries the counts; an invalid receiver is 422.
func TestTenantMemberOwnsResourcesCarriesCounts(t *testing.T) {
	server := &Server{}
	recorder := httptest.NewRecorder()
	err := fmt.Errorf("delete: %w", &identity.TenantMemberOwnsResourcesError{Resources: identity.TenantMemberBlockingResources{
		PackageSubscriptions: 1, L4Forwards: 2, PackageSites: 3, Transferable: 4}})
	server.writeTenantMemberError(recorder, httptest.NewRequest(http.MethodDelete, "/v1/tenant/members/x", nil), err)
	var body struct {
		Error struct {
			Code      string                                 `json:"code"`
			Resources identity.TenantMemberBlockingResources `json:"resources"`
		} `json:"error"`
	}
	if decodeErr := json.Unmarshal(recorder.Body.Bytes(), &body); decodeErr != nil {
		t.Fatal(decodeErr)
	}
	if recorder.Code != http.StatusConflict || body.Error.Code != "tenant_member_owns_resources" ||
		body.Error.Resources != (identity.TenantMemberBlockingResources{PackageSubscriptions: 1, L4Forwards: 2, PackageSites: 3, Transferable: 4}) {
		t.Fatalf("response %d %s", recorder.Code, recorder.Body.String())
	}
	recorder = httptest.NewRecorder()
	server.writeTenantMemberError(recorder, httptest.NewRequest(http.MethodDelete, "/v1/tenant/members/x", nil), identity.ErrTenantMemberTransferTarget)
	if recorder.Code != http.StatusUnprocessableEntity {
		t.Fatalf("transfer target %d", recorder.Code)
	}
}

// TENANT-PWRESET-UNKNOWN: a retrieved/expired result is 410 (nothing reset
// again); another actor/member under the same key is 409 idempotency_conflict.
func TestTenantMemberPasswordResetResultErrors(t *testing.T) {
	server := &Server{}
	for _, item := range []struct {
		err    error
		status int
		code   string
	}{
		{identity.ErrTenantMemberPasswordResetGone, http.StatusGone, "tenant_member_password_reset_result_gone"},
		{identity.ErrIdempotencyConflict, http.StatusConflict, "idempotency_conflict"},
		{identity.ErrTenantMemberPasswordResetUnavailable, http.StatusServiceUnavailable, "tenant_member_password_reset_unavailable"},
	} {
		recorder := httptest.NewRecorder()
		server.writeTenantMemberError(recorder, httptest.NewRequest(http.MethodPost, "/v1/tenant/members/x/password-reset", nil), fmt.Errorf("reset: %w", item.err))
		var body struct {
			Error map[string]any `json:"error"`
		}
		if err := json.Unmarshal(recorder.Body.Bytes(), &body); err != nil {
			t.Fatal(err)
		}
		if recorder.Code != item.status || body.Error["code"] != item.code {
			t.Errorf("%v: %d %v", item.err, recorder.Code, body.Error)
		}
	}
}

// 越权的错误码与状态：tenant_member_outranks 403。
func TestTenantMemberOutranksErrorCode(t *testing.T) {
	server := &Server{}
	for _, tc := range []struct {
		err    error
		status int
		code   string
	}{
		{identity.ErrTenantMemberOutranks, http.StatusForbidden, "tenant_member_outranks"},
	} {
		recorder := httptest.NewRecorder()
		server.writeTenantMemberError(recorder, httptest.NewRequest(http.MethodPost, "/v1/tenant/members", nil), fmt.Errorf("wrapped: %w", tc.err))
		var body struct {
			Error map[string]any `json:"error"`
		}
		if err := json.Unmarshal(recorder.Body.Bytes(), &body); err != nil {
			t.Fatal(err)
		}
		if recorder.Code != tc.status || body.Error["code"] != tc.code {
			t.Errorf("%v: response %d %v, want %d %s", tc.err, recorder.Code, body.Error, tc.status, tc.code)
		}
	}
}
