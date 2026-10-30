package ja4blockhttp

import (
	"context"
	"encoding/json"
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"
	"time"

	"github.com/cdnca/cdnca/services/control-api/internal/identity"
	"github.com/cdnca/cdnca/services/control-api/internal/ja4block"
	"github.com/google/uuid"
)

func TestPostRequiresLiveScopedSessionPermissionAndStepUp(t *testing.T) {
	tenantID, userID, sessionID, workflowID := uuid.New(), uuid.New(), uuid.New(), uuid.New()
	application := &applicationStub{workflow: ja4block.Workflow{ID: workflowID, TenantScopeID: tenantID,
		SiteID: uuid.New(), Phase: ja4block.PhaseQueued, Revision: 1, JA4SHA256: strings.Repeat("a", 64)}}
	verified := false
	handler, err := NewHandler(Dependencies{
		Application: application,
		AuthenticateSession: func(_ context.Context, token string) (identity.AuthenticatedSession, error) {
			if token != "live-session" {
				return identity.AuthenticatedSession{}, identity.ErrInvalidSession
			}
			return session("tenant", tenantID, userID, sessionID, []string{PermissionManage}), nil
		},
		VerifyStepUp: func(_ context.Context, check StepUpCheck) (StepUpEvidence, error) {
			verified = check.SessionID == sessionID && check.Token == "step-up" && check.Action == "security.ja4_block.create" &&
				check.TargetTenantScopeID == tenantID
			return StepUpEvidence{ID: uuid.New(), VerifiedAt: time.Date(2026, 8, 8, 10, 0, 0, 0, time.UTC)}, nil
		},
	})
	if err != nil {
		t.Fatal(err)
	}
	body := `{"site_id":"` + application.workflow.SiteID.String() + `","ja4":"t13d1516h2_8daaf6152771_e5627efa2ab1","snapshot_at":"2026-08-08T09:59:00Z","duration_seconds":3600,"reason":"credential_stuffing"}`
	request := httptest.NewRequest(http.MethodPost, TenantCollectionRoute, strings.NewReader(body))
	request.Header.Set("Authorization", "Bearer live-session")
	request.Header.Set("Content-Type", "application/json")
	request.Header.Set("X-Request-ID", "request-1")
	request.Header.Set("Idempotency-Key", "ja4-block-1")
	request.Header.Set("If-Match", `"0"`)
	request.Header.Set("X-Step-Up-Token", "step-up")
	response := httptest.NewRecorder()
	handler.ServeHTTP(response, request)
	if response.Code != http.StatusAccepted || !verified || application.submit.TenantScopeID != tenantID ||
		application.actor.SessionID != sessionID {
		t.Fatalf("POST status=%d verified=%v input=%#v body=%s", response.Code, verified, application.submit, response.Body.String())
	}
	if strings.Contains(response.Body.String(), "t13d1516") || !strings.Contains(response.Body.String(), workflowID.String()) {
		t.Fatalf("response leaked JA4 or omitted workflow: %s", response.Body.String())
	}
}

func TestHandlerRejectsAPIKeyScopeSpoofAndMissingStepUp(t *testing.T) {
	tenantID := uuid.New()
	app := &applicationStub{}
	handler, err := NewHandler(Dependencies{Application: app,
		AuthenticateSession: func(context.Context, string) (identity.AuthenticatedSession, error) {
			return session("tenant", tenantID, uuid.New(), uuid.New(), []string{PermissionManage}), nil
		}, VerifyStepUp: func(context.Context, StepUpCheck) (StepUpEvidence, error) { return StepUpEvidence{}, ErrStepUpRequired }})
	if err != nil {
		t.Fatal(err)
	}
	body := `{"site_id":"` + uuid.NewString() + `","ja4":"t13d1516h2_8daaf6152771_e5627efa2ab1","snapshot_at":"2026-08-08T09:59:00Z","duration_seconds":3600,"reason":"credential_stuffing"}`
	for name, test := range map[string]struct {
		mutate func(*http.Request)
		want   int
	}{
		"API key":     {func(r *http.Request) { r.Header.Set("X-API-Key", "secret") }, http.StatusUnauthorized},
		"scope spoof": {func(r *http.Request) { r.Header.Set("X-Tenant-ID", uuid.NewString()) }, http.StatusBadRequest},
		"step-up":     {func(*http.Request) {}, http.StatusPreconditionRequired},
	} {
		t.Run(name, func(t *testing.T) {
			request := httptest.NewRequest(http.MethodPost, TenantCollectionRoute, strings.NewReader(body))
			request.Header.Set("Authorization", "Bearer token")
			request.Header.Set("Content-Type", "application/json")
			request.Header.Set("X-Request-ID", "request-1")
			request.Header.Set("Idempotency-Key", "ja4-block-1")
			request.Header.Set("If-Match", `"0"`)
			request.Header.Set("X-Step-Up-Token", "proof")
			test.mutate(request)
			response := httptest.NewRecorder()
			handler.ServeHTTP(response, request)
			if response.Code != test.want {
				t.Fatalf("status=%d body=%s", response.Code, response.Body.String())
			}
		})
	}
	if app.submitCalls != 0 {
		t.Fatalf("denied requests reached application: %d", app.submitCalls)
	}
}

func TestGetReturnsFixedWorkflowStateWithoutRawEvents(t *testing.T) {
	tenantID, workflowID := uuid.New(), uuid.New()
	app := &applicationStub{workflow: ja4block.Workflow{ID: workflowID, TenantScopeID: tenantID,
		SiteID: uuid.New(), Phase: ja4block.PhaseEdgePending, Revision: 3, JA4: "must-not-leak",
		JA4SHA256: strings.Repeat("b", 64), PolicyID: uuid.New(), PolicyRevision: 2,
		BindingID: uuid.New(), BindingRevision: 4, RolloutID: uuid.New(), EdgeState: "pending"}}
	handler, err := NewHandler(Dependencies{Application: app,
		AuthenticateSession: func(context.Context, string) (identity.AuthenticatedSession, error) {
			return session("tenant", tenantID, uuid.New(), uuid.New(), []string{PermissionRead}), nil
		}, VerifyStepUp: func(context.Context, StepUpCheck) (StepUpEvidence, error) {
			return StepUpEvidence{ID: uuid.New(), VerifiedAt: time.Now()}, nil
		}})
	if err != nil {
		t.Fatal(err)
	}
	request := httptest.NewRequest(http.MethodGet, TenantCollectionRoute+"/"+workflowID.String(), nil)
	request.Header.Set("Authorization", "Bearer token")
	request.Header.Set("X-Request-ID", "request-get")
	response := httptest.NewRecorder()
	handler.ServeHTTP(response, request)
	if response.Code != http.StatusOK || strings.Contains(response.Body.String(), "must-not-leak") || strings.Contains(response.Body.String(), "events") {
		t.Fatalf("GET status=%d body=%s", response.Code, response.Body.String())
	}
	var decoded map[string]any
	if json.Unmarshal(response.Body.Bytes(), &decoded) != nil || decoded["phase"] != string(ja4block.PhaseEdgePending) {
		t.Fatalf("GET response=%s", response.Body.String())
	}
}

type applicationStub struct {
	workflow    ja4block.Workflow
	submit      ja4block.SubmitInput
	actor       ja4block.Actor
	submitCalls int
}

func (stub *applicationStub) Submit(_ context.Context, actor ja4block.Actor, input ja4block.SubmitInput) (ja4block.Workflow, error) {
	stub.submitCalls++
	stub.actor = actor
	stub.submit = input
	return stub.workflow, nil
}
func (stub *applicationStub) Get(_ context.Context, _ ja4block.Actor, _ uuid.UUID, _ uuid.UUID) (ja4block.Workflow, error) {
	return stub.workflow, nil
}

func session(kind string, scopeID, userID, sessionID uuid.UUID, permissions []string) identity.AuthenticatedSession {
	principal := identity.Principal{UserID: userID, ScopeID: scopeID, ScopeKind: kind, Permissions: permissions}
	if kind == "tenant" {
		// 真实租户的 tenants.id 与 access_scopes.id 是两个独立 UUID（001_identity）。
		tenantID := uuid.New()
		principal.TenantID = &tenantID
	}
	return identity.AuthenticatedSession{SessionID: sessionID, Principal: principal}
}

var _ Application = (*applicationStub)(nil)
