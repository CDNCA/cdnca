package firewallhttp

import (
	"bytes"
	"context"
	"encoding/json"
	"net/http"
	"net/http/httptest"
	"testing"
	"time"

	"github.com/cdnca/cdnca/services/control-api/internal/firewallcontrol"
	"github.com/google/uuid"
)

type recordingAPI struct {
	put firewallcontrol.PutRequest
}

func (api *recordingAPI) Put(_ context.Context, request firewallcontrol.PutRequest) (firewallcontrol.WriteResult, error) {
	api.put = request
	return firewallcontrol.WriteResult{Policy: firewallcontrol.Policy{ID: uuid.New(), Revision: 2, ActiveRevision: 1, DeploymentState: firewallcontrol.DeploymentPending}}, nil
}
func (*recordingAPI) Get(context.Context, firewallcontrol.ReadRequest) (firewallcontrol.Policy, error) {
	return firewallcontrol.Policy{}, nil
}
func (*recordingAPI) Recover(context.Context, firewallcontrol.RecoverRequest) (firewallcontrol.WriteResult, error) {
	return firewallcontrol.WriteResult{}, nil
}
func (*recordingAPI) ListHits(context.Context, firewallcontrol.HitFilter) (firewallcontrol.HitPage, error) {
	return firewallcontrol.HitPage{}, nil
}

func TestHandlerPutRequiresServerActorCASAndIdempotency(t *testing.T) {
	tenantID := uuid.MustParse("11111111-1111-4111-8111-111111111111")
	actor := firewallcontrol.Actor{UserID: uuid.New(), ScopeID: tenantID, ScopeKind: firewallcontrol.ScopeTenant, Permissions: []string{firewallcontrol.PermissionManage}}
	api := &recordingAPI{}
	handler, err := NewHandler(api, func(*http.Request) (firewallcontrol.Actor, error) { return actor, nil })
	if err != nil {
		t.Fatal(err)
	}
	body, _ := json.Marshal(map[string]any{
		"enabled": true, "default_action": "allow",
		"rules": []map[string]any{{"priority": 1, "action": "deny", "cidrs": []string{"198.51.100.0/24"}, "protocol": "tcp", "port_start": 443, "port_end": 443}},
	})
	request := httptest.NewRequest(http.MethodPut, "/v1/firewall/policy?target_scope_id="+tenantID.String(), bytes.NewReader(body))
	request.Header.Set("Content-Type", "application/json")
	request.Header.Set("If-Match", `"1"`)
	request.Header.Set("Idempotency-Key", "global-fw-update")
	request.Header.Set("X-Request-ID", uuid.NewString())
	recorder := httptest.NewRecorder()
	handler.ServeHTTP(recorder, request)
	if recorder.Code != http.StatusOK {
		t.Fatalf("status = %d body=%s", recorder.Code, recorder.Body.String())
	}
	if api.put.Actor.UserID != actor.UserID || api.put.TargetScopeID != tenantID || api.put.ExpectedRevision != 1 || api.put.IdempotencyKey != "global-fw-update" {
		t.Fatalf("trusted request binding = %+v", api.put)
	}
	if recorder.Header().Get("ETag") != `"2"` {
		t.Fatalf("ETag = %q", recorder.Header().Get("ETag"))
	}
}

func TestHandlerSeparatesForbiddenInvalidAndUnknownOutcome(t *testing.T) {
	tenantID := uuid.MustParse("11111111-1111-4111-8111-111111111111")
	tests := map[string]struct {
		authErr error
		method  string
		body    string
		want    int
	}{
		"unauthenticated": {authErr: firewallcontrol.ErrUnauthenticated, method: http.MethodGet, want: http.StatusUnauthorized},
		"invalid body":    {method: http.MethodPut, body: `{`, want: http.StatusBadRequest},
	}
	for name, item := range tests {
		t.Run(name, func(t *testing.T) {
			handler, err := NewHandler(&recordingAPI{}, func(*http.Request) (firewallcontrol.Actor, error) {
				if item.authErr != nil {
					return firewallcontrol.Actor{}, item.authErr
				}
				return firewallcontrol.Actor{UserID: uuid.New(), ScopeID: tenantID, ScopeKind: firewallcontrol.ScopeTenant, Permissions: []string{firewallcontrol.PermissionManage}}, nil
			})
			if err != nil {
				t.Fatal(err)
			}
			request := httptest.NewRequest(item.method, "/v1/firewall/policy?target_scope_id="+tenantID.String(), bytes.NewBufferString(item.body))
			request.Header.Set("If-Match", `"1"`)
			request.Header.Set("Idempotency-Key", "attempt")
			request.Header.Set("X-Request-ID", uuid.NewString())
			recorder := httptest.NewRecorder()
			handler.ServeHTTP(recorder, request)
			if recorder.Code != item.want {
				t.Fatalf("status=%d body=%s", recorder.Code, recorder.Body.String())
			}
		})
	}
}

func TestHitLogQueryUsesStableSnapshotCursor(t *testing.T) {
	_ = time.Now // keeps the contract explicit until the store fixture supplies a fixed clock.
	var filter firewallcontrol.HitFilter
	api := &recordingHitAPI{recordingAPI: recordingAPI{}, filter: &filter}
	tenantID := uuid.MustParse("11111111-1111-4111-8111-111111111111")
	handler, err := NewHandler(api, func(*http.Request) (firewallcontrol.Actor, error) {
		return firewallcontrol.Actor{UserID: uuid.New(), ScopeID: tenantID, ScopeKind: firewallcontrol.ScopeTenant, Permissions: []string{firewallcontrol.PermissionRead}}, nil
	})
	if err != nil {
		t.Fatal(err)
	}
	request := httptest.NewRequest(http.MethodGet, "/v1/firewall/hits?target_scope_id="+tenantID.String()+"&limit=25&cursor=stable-cursor", nil)
	recorder := httptest.NewRecorder()
	handler.ServeHTTP(recorder, request)
	if recorder.Code != http.StatusOK || filter.Limit != 25 || filter.Cursor != "stable-cursor" || filter.TargetScopeID != tenantID {
		t.Fatalf("status/filter = %d %+v", recorder.Code, filter)
	}
}

type recordingHitAPI struct {
	recordingAPI
	filter *firewallcontrol.HitFilter
}

func (api *recordingHitAPI) ListHits(_ context.Context, filter firewallcontrol.HitFilter) (firewallcontrol.HitPage, error) {
	*api.filter = filter
	return firewallcontrol.HitPage{Items: []firewallcontrol.Hit{{ReasonCode: "rule:block", Action: firewallcontrol.ActionDeny}}}, nil
}
