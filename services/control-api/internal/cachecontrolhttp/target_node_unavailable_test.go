package cachecontrolhttp

import (
	"context"
	"encoding/json"
	"net/http"
	"testing"

	"github.com/cdnca/cdnca/services/control-api/internal/cachecontrol"
	"github.com/cdnca/cdnca/services/control-api/internal/identity"
	"github.com/google/uuid"
)

// fix-cacheflow2 P2-11 (CACHE-ADD-10): a site the caller may manage with a
// named node that cannot serve it is a node-selection refusal (409, field
// node_ids), not "task not found" (no task exists yet).
func TestCreateWithUnavailableNodeIsANodeSelectionRefusal(t *testing.T) {
	userID, scopeID, siteID := uuid.New(), uuid.New(), uuid.New()
	control := &fakeControl{createOperation: func(context.Context, cachecontrol.Actor, cachecontrol.CreateOperationRequest) (cachecontrol.OperationWriteResult, error) {
		return cachecontrol.OperationWriteResult{}, cachecontrol.ErrTargetNodeUnavailable
	}}
	handler := testHandler(t, control, &fakeReader{}, func(*http.Request) (identity.Principal, error) {
		return principal(userID, scopeID, "tenant", PermissionOperationsManage), nil
	})
	response := serve(t, handler, http.MethodPost, "/v1/cache-operations", map[string]any{
		"site_id": siteID, "action": "purge", "target_type": "exact_url",
		"targets": []string{"https://example.com/a"}, "node_ids": []string{uuid.NewString()}, "max_retries": 0,
	}, "tenant", "node-unavailable")
	var envelope struct {
		Error struct {
			Code    string `json:"code"`
			Details *struct {
				Field string `json:"field"`
				Stage string `json:"stage"`
			} `json:"details"`
		} `json:"error"`
	}
	if err := json.Unmarshal(response.Body.Bytes(), &envelope); err != nil {
		t.Fatal(err)
	}
	if response.Code != http.StatusConflict || envelope.Error.Code != "target_node_unavailable" ||
		envelope.Error.Details == nil || envelope.Error.Details.Field != "node_ids" ||
		envelope.Error.Details.Stage != "node_selection" {
		t.Fatalf("status=%d body=%s", response.Code, response.Body.String())
	}
}
