package cachecontrolhttp

import (
	"context"
	"encoding/json"
	"net/http"
	"strings"
	"testing"
	"time"

	"github.com/cdnca/cdnca/services/control-api/internal/cachecontrol"
	"github.com/cdnca/cdnca/services/control-api/internal/identity"
	"github.com/google/uuid"
)

// fix-cacheflow5: GET .../cache-operation-requests/{idempotency_key} answers
// accepted (with the operation), rejected (with the code) or 404 when the
// key names nothing of this actor.
func TestWriteReceiptAnswersAcceptedRejectedAndUnknown(t *testing.T) {
	userID, scopeID, operationID, siteID := uuid.New(), uuid.New(), uuid.New(), uuid.New()
	decided := time.Date(2026, 10, 28, 7, 0, 0, 0, time.UTC)
	var calls []cachecontrol.WriteReceiptRequest
	var actors []cachecontrol.Actor
	control := &fakeControl{writeReceipt: func(_ context.Context, actor cachecontrol.Actor, request cachecontrol.WriteReceiptRequest) (cachecontrol.WriteReceipt, error) {
		calls, actors = append(calls, request), append(actors, actor)
		switch request.IdempotencyKey {
		case "key-accepted":
			return cachecontrol.WriteReceipt{Status: cachecontrol.WriteAccepted, DecidedAt: decided, Operation: cachecontrol.Operation{
				ID: operationID, DisplayID: "9", ScopeID: actor.ScopeID, SiteID: siteID, SiteDisplayID: "3",
				Action: cachecontrol.ActionPurge, TargetType: cachecontrol.TargetExactURL, State: cachecontrol.StateQueued,
				MaxAttempts: 1, CreatedAt: decided, UpdatedAt: decided,
			}}, nil
		case "key-rejected":
			return cachecontrol.WriteReceipt{Status: cachecontrol.WriteRejected, DecidedAt: decided, Rejection: cachecontrol.WriteRejection{
				Code: "invalid_request", TargetOrdinal: 2, TargetReason: cachecontrol.TargetReasonHostNotServed,
			}}, nil
		default:
			return cachecontrol.WriteReceipt{}, cachecontrol.ErrNotFound
		}
	}}
	handler := testHandler(t, control, &fakeReader{}, func(*http.Request) (identity.Principal, error) {
		return principal(userID, scopeID, "tenant", PermissionOperationsRead), nil
	})

	response := serve(t, handler, http.MethodGet, "/v1/cache-operation-requests/key-accepted?action=create", nil, "tenant", "")
	if response.Code != http.StatusOK || response.Header().Get("Cache-Control") != "no-store" {
		t.Fatalf("accepted status=%d body=%s", response.Code, response.Body.String())
	}
	var accepted WriteReceiptView
	if err := json.Unmarshal(response.Body.Bytes(), &accepted); err != nil {
		t.Fatal(err)
	}
	if accepted.Status != "accepted" || accepted.Operation == nil || accepted.Operation.ID != operationID ||
		accepted.Rejection != nil || !accepted.DecidedAt.Equal(decided) {
		t.Fatalf("accepted view=%+v", accepted)
	}

	response = serve(t, handler, http.MethodGet, "/v1/cache-operation-requests/key-rejected?action=retry&operation_id="+operationID.String(), nil, "tenant", "")
	if response.Code != http.StatusOK {
		t.Fatalf("rejected status=%d body=%s", response.Code, response.Body.String())
	}
	var rejected WriteReceiptView
	if err := json.Unmarshal(response.Body.Bytes(), &rejected); err != nil {
		t.Fatal(err)
	}
	if rejected.Status != "rejected" || rejected.Operation != nil || rejected.Rejection == nil ||
		rejected.Rejection.Code != "invalid_request" || rejected.Rejection.Details == nil ||
		rejected.Rejection.Details.TargetOrdinal != 2 || rejected.Rejection.Details.Reason != cachecontrol.TargetReasonHostNotServed {
		t.Fatalf("rejected view=%s", response.Body.String())
	}

	response = serve(t, handler, http.MethodGet, "/v1/cache-operation-requests/key-unknown?action=cancel&operation_id="+operationID.String(), nil, "tenant", "")
	if response.Code != http.StatusNotFound || !strings.Contains(response.Body.String(), `"code":"not_found"`) {
		t.Fatalf("unknown status=%d body=%s", response.Code, response.Body.String())
	}
	if len(calls) != 3 || calls[1].Action != cachecontrol.WriteRetry || calls[1].OperationID != operationID ||
		calls[2].Action != cachecontrol.WriteCancel || actors[0].ScopeID != scopeID || actors[0].UserID != userID ||
		actors[0].ActorScopeID != scopeID {
		t.Fatalf("calls=%+v actors=%+v", calls, actors)
	}
}

// Another actor's key, or a key the store refuses to read for the actor, is
// the same 404 as a key never sent: the receipt never tells whether it exists.
func TestWriteReceiptHidesOtherActorsAndBindsPlatformScope(t *testing.T) {
	userID, platformScope, tenantScope := uuid.New(), uuid.New(), uuid.New()
	var seen cachecontrol.Actor
	control := &fakeControl{writeReceipt: func(_ context.Context, actor cachecontrol.Actor, _ cachecontrol.WriteReceiptRequest) (cachecontrol.WriteReceipt, error) {
		seen = actor
		return cachecontrol.WriteReceipt{}, cachecontrol.ErrPermissionDenied
	}}
	handler := testHandler(t, control, &fakeReader{}, func(*http.Request) (identity.Principal, error) {
		return principal(userID, platformScope, "platform", PermissionOperationsRead), nil
	})
	response := serve(t, handler, http.MethodGet,
		"/v1/admin/cache-operation-requests/key-1?action=create&scope_id="+tenantScope.String(), nil, "platform", "")
	if response.Code != http.StatusNotFound {
		t.Fatalf("status=%d body=%s", response.Code, response.Body.String())
	}
	if seen.ScopeID != tenantScope || seen.ActorScopeID != platformScope || seen.UserID != userID {
		t.Fatalf("actor=%+v", seen)
	}
}

func TestWriteReceiptValidatesTheRequest(t *testing.T) {
	userID, scopeID, operationID := uuid.New(), uuid.New(), uuid.New()
	calls := 0
	control := &fakeControl{writeReceipt: func(context.Context, cachecontrol.Actor, cachecontrol.WriteReceiptRequest) (cachecontrol.WriteReceipt, error) {
		calls++
		return cachecontrol.WriteReceipt{}, cachecontrol.ErrNotFound
	}}
	permissions := []string{PermissionOperationsRead}
	handler := testHandler(t, control, &fakeReader{}, func(*http.Request) (identity.Principal, error) {
		return principal(userID, scopeID, "tenant", permissions...), nil
	})
	for _, path := range []string{
		"/v1/cache-operation-requests/key-1",
		"/v1/cache-operation-requests/key-1?action=delete",
		"/v1/cache-operation-requests/key-1?action=create&operation_id=" + operationID.String(),
		"/v1/cache-operation-requests/key-1?action=retry",
		"/v1/cache-operation-requests/key-1?action=retry&operation_id=not-a-uuid",
		"/v1/cache-operation-requests/-bad?action=create",
		"/v1/cache-operation-requests/" + strings.Repeat("k", 129) + "?action=create",
		"/v1/cache-operation-requests/key-1?action=create&extra=1",
		"/v1/admin/cache-operation-requests/key-1?action=create",
	} {
		if response := serve(t, handler, http.MethodGet, path, nil, "tenant", ""); response.Code != http.StatusBadRequest &&
			response.Code != http.StatusForbidden {
			t.Errorf("%s status=%d body=%s", path, response.Code, response.Body.String())
		}
	}
	if response := serve(t, handler, http.MethodPost, "/v1/cache-operation-requests/key-1?action=create", nil, "tenant", ""); response.Code != http.StatusMethodNotAllowed {
		t.Fatalf("POST status=%d", response.Code)
	}
	permissions = nil
	if response := serve(t, handler, http.MethodGet, "/v1/cache-operation-requests/key-1?action=create", nil, "tenant", ""); response.Code != http.StatusForbidden {
		t.Fatalf("without sites.read status=%d", response.Code)
	}
	if calls != 0 {
		t.Fatalf("store calls=%d, want 0", calls)
	}
}
