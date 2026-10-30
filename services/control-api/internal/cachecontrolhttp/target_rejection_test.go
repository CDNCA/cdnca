package cachecontrolhttp

import (
	"context"
	"net/http"
	"strings"
	"testing"

	"github.com/cdnca/cdnca/services/control-api/internal/cachecontrol"
	"github.com/cdnca/cdnca/services/control-api/internal/identity"
	"github.com/google/uuid"
)

// ADD-10: a refused target comes back as invalid_request with details
// (field, target_ordinal, stage, reason) and the request ID; other invalid
// input keeps the plain envelope.
func TestHandlerCreateTargetRejectionDetails(t *testing.T) {
	scopeID, userID, siteID := uuid.New(), uuid.New(), uuid.New()
	var refuse error = &cachecontrol.TargetError{Ordinal: 2, Reason: cachecontrol.TargetReasonListenerNotEnabled}
	control := &fakeControl{createOperation: func(context.Context, cachecontrol.Actor, cachecontrol.CreateOperationRequest) (cachecontrol.OperationWriteResult, error) {
		return cachecontrol.OperationWriteResult{}, refuse
	}}
	handler := testHandler(t, control, &fakeReader{}, func(*http.Request) (identity.Principal, error) {
		return principal(userID, scopeID, "tenant", PermissionOperationsManage), nil
	})
	body := map[string]any{
		"site_id": siteID, "action": "purge", "target_type": "exact_url",
		"targets":  []string{"http://example.com/a", "https://example.com/b"},
		"node_ids": []string{}, "max_retries": 1,
	}
	response := serve(t, handler, http.MethodPost, "/v1/cache-operations", body, "tenant", "reject-1")
	want := `"details":{"field":"targets","target_ordinal":2,"stage":"target_validation","reason":"target_listener_not_enabled"}`
	if response.Code != http.StatusBadRequest || !strings.Contains(response.Body.String(), `"code":"invalid_request"`) ||
		!strings.Contains(response.Body.String(), want) || !strings.Contains(response.Body.String(), `"request_id":"`) {
		t.Fatalf("status=%d body=%s", response.Code, response.Body.String())
	}
	refuse = cachecontrol.ErrInvalidInput
	response = serve(t, handler, http.MethodPost, "/v1/cache-operations", body, "tenant", "reject-2")
	if response.Code != http.StatusBadRequest || strings.Contains(response.Body.String(), `"details"`) {
		t.Fatalf("plain invalid: status=%d body=%s", response.Code, response.Body.String())
	}
}
