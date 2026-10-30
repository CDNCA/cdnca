package approvalcenter

import (
	"context"
	"io"
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"

	"github.com/google/uuid"
)

// fakeService records the approve/finish calls; decisions themselves are
// covered by the PostgreSQL tests (store_integration_test.go).
type fakeService struct {
	request     Request
	approveErr  error
	approvedBy  Session
	finished    []StepResult
	stepUpToken string
}

func (f *fakeService) Settings(context.Context) (Settings, error) { return Settings{Rules: []string{}}, nil }
func (f *fakeService) SaveSettings(_ context.Context, _ Session, input Settings, _ string) (Settings, error) {
	return input, nil
}
func (f *fakeService) List(context.Context, Session, string, int) ([]Request, error) {
	return []Request{f.request}, nil
}
func (f *fakeService) Get(context.Context, Session, uuid.UUID) (Request, error) { return f.request, nil }
func (f *fakeService) MFAActive(context.Context, Session) (bool, error)         { return true, nil }
func (f *fakeService) Approve(_ context.Context, actor Session, _ uuid.UUID, _ int64, _, token, _ string) (Request, error) {
	f.approvedBy, f.stepUpToken = actor, token
	if f.approveErr != nil {
		return Request{}, f.approveErr
	}
	approved := f.request
	approved.State = StateExecuting
	return approved, nil
}
func (f *fakeService) Reject(context.Context, Session, uuid.UUID, int64, string, string) (Request, error) {
	rejected := f.request
	rejected.State = StateRejected
	return rejected, nil
}
func (f *fakeService) Finish(_ context.Context, _ Session, _ uuid.UUID, results []StepResult, _ string) (Request, error) {
	f.finished = results
	done := f.request
	done.State, done.Results = StateExecuted, results
	return done, nil
}

func TestApproveReplaysWithApproverSession(t *testing.T) {
	id := uuid.New()
	service := &fakeService{request: Request{ID: id, Rule: RuleFirewallPolicy, State: StatePending, Revision: 1,
		Steps: []Step{{Method: http.MethodPut, Path: "/v1/firewall/policy", Headers: map[string]string{"Idempotency-Key": "k"}, Body: []byte(`{"x":1}`)}}}}
	var replayedAuth, replayedBody string
	target := http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		replayedAuth = r.Header.Get("Authorization")
		body, _ := io.ReadAll(r.Body)
		replayedBody = string(body)
		w.WriteHeader(http.StatusOK)
	})
	approver := Session{UserID: uuid.New(), ScopeID: uuid.New(), ScopeKind: "platform", Permissions: []string{PermissionApprove}}
	mux := http.NewServeMux()
	Handler{Service: service, Session: func(*http.Request) (Session, bool) { return approver, true },
		Target: func() http.Handler { return target }}.Routes(mux)
	request := httptest.NewRequest(http.MethodPost, "/v1/admin/approval-requests/"+id.String()+"/approve",
		strings.NewReader(`{"expected_revision":1,"step_up_token":"proof"}`))
	request.Header.Set("Authorization", "Bearer approver-token")
	response := httptest.NewRecorder()
	mux.ServeHTTP(response, request)
	if response.Code != http.StatusOK || replayedAuth != "Bearer approver-token" || replayedBody != `{"x":1}` {
		t.Fatalf("status=%d auth=%q body=%q (%s)", response.Code, replayedAuth, replayedBody, response.Body.String())
	}
	if service.stepUpToken != "proof" || service.approvedBy.UserID != approver.UserID || len(service.finished) != 1 ||
		service.finished[0].Status != http.StatusOK || !strings.Contains(response.Body.String(), `"executed"`) {
		t.Fatalf("approve=%+v finished=%+v body=%s", service.approvedBy, service.finished, response.Body.String())
	}
}

func TestApproveErrorsDoNotReplay(t *testing.T) {
	for _, test := range []struct {
		err    error
		status int
		code   string
	}{
		{ErrSameOperator, http.StatusForbidden, "approval_same_operator"},
		{ErrExpired, http.StatusConflict, "approval_expired"},
		{ErrStepUpRequired, http.StatusPreconditionRequired, "mfa_step_up_required"},
		{ErrConflict, http.StatusConflict, "revision_conflict"},
	} {
		service := &fakeService{request: Request{ID: uuid.New()}, approveErr: test.err}
		replayed := false
		mux := http.NewServeMux()
		Handler{Service: service, Session: func(*http.Request) (Session, bool) { return Session{ScopeKind: "platform"}, true },
			Target: func() http.Handler {
				return http.HandlerFunc(func(http.ResponseWriter, *http.Request) { replayed = true })
			}}.Routes(mux)
		response := httptest.NewRecorder()
		mux.ServeHTTP(response, httptest.NewRequest(http.MethodPost, "/v1/admin/approval-requests/"+uuid.NewString()+"/approve",
			strings.NewReader(`{"expected_revision":1}`)))
		if response.Code != test.status || !strings.Contains(response.Body.String(), test.code) || replayed || service.finished != nil {
			t.Fatalf("%v: status=%d body=%s replayed=%v", test.err, response.Code, response.Body.String(), replayed)
		}
	}
}

func TestRoutesRequirePlatformSession(t *testing.T) {
	mux := http.NewServeMux()
	Handler{Service: &fakeService{}, Session: func(*http.Request) (Session, bool) { return Session{ScopeKind: "tenant"}, true },
		Target: func() http.Handler { return http.NotFoundHandler() }}.Routes(mux)
	response := httptest.NewRecorder()
	mux.ServeHTTP(response, httptest.NewRequest(http.MethodGet, "/v1/admin/approval-requests", nil))
	if response.Code != http.StatusForbidden {
		t.Fatalf("tenant session: status=%d", response.Code)
	}
}
