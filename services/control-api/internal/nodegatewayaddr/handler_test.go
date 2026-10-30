package nodegatewayaddr

import (
	"context"
	"encoding/json"
	"errors"
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"

	"github.com/cdnca/cdnca/services/control-api/internal/identity"
	"github.com/google/uuid"
)

type handlerStore struct {
	created []CreateRequest
	retried []uuid.UUID
	err     error
}

func (s *handlerStore) Create(_ context.Context, _ Actor, request CreateRequest) (Change, error) {
	if s.err != nil {
		return Change{}, s.err
	}
	s.created = append(s.created, request)
	return Change{ID: uuid.New(), Address: request.Address, ServerName: request.ServerName, TargetKind: request.TargetKind, NodeCount: 2}, nil
}
func (s *handlerStore) Retry(_ context.Context, _ Actor, id uuid.UUID, _ []uuid.UUID) (int, error) {
	s.retried = append(s.retried, id)
	return 1, s.err
}
func (s *handlerStore) List(context.Context, uuid.UUID, int) ([]Change, error) {
	return []Change{}, nil
}
func (s *handlerStore) Get(_ context.Context, _, id uuid.UUID) (Change, error) {
	return Change{ID: id}, s.err
}

type recordingStepUp struct {
	bindings [][32]byte
	actions  []string
	err      error
}

func (s *recordingStepUp) Consume(_ context.Context, _ Actor, token, action string, binding [32]byte) error {
	if token != "proof" {
		return ErrStepUpRequired
	}
	s.bindings, s.actions = append(s.bindings, binding), append(s.actions, action)
	return s.err
}

func testHandler(store *handlerStore, stepUp StepUp, permissions []string, scopeKind string) (*Handler, *int) {
	woken := 0
	return &Handler{Store: store, StepUp: stepUp, Ready: func() bool { return true }, OnChange: func() { woken++ },
		Authenticate: func(_ context.Context, token string) (identity.AuthenticatedSession, error) {
			if token != "session" {
				return identity.AuthenticatedSession{}, errors.New("bad token")
			}
			return identity.AuthenticatedSession{SessionID: uuid.New(), Principal: identity.Principal{UserID: uuid.New(),
				ScopeID: uuid.New(), ScopeKind: scopeKind, Permissions: permissions}}, nil
		}}, &woken
}

func call(handler http.Handler, method, path, body string) (int, string) {
	request := httptest.NewRequest(method, path, strings.NewReader(body))
	request.Header.Set("Authorization", "Bearer session")
	if body != "" {
		request.Header.Set("Content-Type", "application/json")
	}
	recorder := httptest.NewRecorder()
	handler.ServeHTTP(recorder, request)
	var decoded struct {
		Error struct {
			Code string `json:"code"`
		} `json:"error"`
	}
	_ = json.Unmarshal(recorder.Body.Bytes(), &decoded)
	return recorder.Code, decoded.Error.Code
}

func TestCreateNeedsManagePermissionAndStepUpBoundToRequest(t *testing.T) {
	store, stepUp := &handlerStore{}, &recordingStepUp{}
	handler, woken := testHandler(store, stepUp, []string{PermissionManage}, "platform")
	body := `{"address":"gateway.cdnca.com:9443","server_name":"","target_kind":"all","step_up_token":"proof"}`
	if status, code := call(handler, http.MethodPost, Route, body); status != http.StatusCreated {
		t.Fatalf("create = %d %s", status, code)
	}
	want, _ := CreateRequest{Address: "gateway.cdnca.com:9443", TargetKind: TargetAll}.Normalize()
	if len(store.created) != 1 || store.created[0].ServerName != "gateway.cdnca.com" || stepUp.bindings[0] != StepUpBinding(want) ||
		stepUp.actions[0] != StepUpAction || *woken != 1 {
		t.Fatalf("created %+v binding ok=%v woken=%d", store.created, stepUp.bindings[0] == StepUpBinding(want), *woken)
	}
	noProof := strings.Replace(body, `"proof"`, `""`, 1)
	if status, code := call(handler, http.MethodPost, Route, noProof); status != http.StatusForbidden || code != "mfa_step_up_required" {
		t.Fatalf("no step-up = %d %s", status, code)
	}
	nilStepUp, _ := testHandler(store, nil, []string{PermissionManage}, "platform")
	if status, code := call(nilStepUp, http.MethodPost, Route, body); status != http.StatusForbidden || code != "mfa_step_up_required" {
		t.Fatalf("MFA off = %d %s", status, code)
	}
	readOnly, _ := testHandler(store, stepUp, []string{PermissionRead}, "platform")
	if status, code := call(readOnly, http.MethodPost, Route, body); status != http.StatusForbidden || code != "permission_denied" {
		t.Fatalf("read only = %d %s", status, code)
	}
	tenant, _ := testHandler(store, stepUp, []string{PermissionManage}, "tenant")
	if status, _ := call(tenant, http.MethodPost, Route, body); status != http.StatusForbidden {
		t.Fatalf("tenant = %d", status)
	}
	if len(store.created) != 1 {
		t.Fatal("a refused request created a change")
	}
}

func TestCreateRejectsInvalidInputBeforeStepUp(t *testing.T) {
	store, stepUp := &handlerStore{}, &recordingStepUp{}
	handler, _ := testHandler(store, stepUp, []string{PermissionAdmin}, "platform")
	for _, body := range []string{
		`{"address":"gateway.cdnca.com","target_kind":"all","step_up_token":"proof"}`,
		`{"address":"gateway.cdnca.com:443","target_kind":"region","step_up_token":"proof"}`,
		`{"address":"gateway.cdnca.com:443","target_kind":"nodes","node_ids":["x"],"step_up_token":"proof"}`,
		`{"address":"gateway.cdnca.com:443","target_kind":"all","extra":1}`,
	} {
		if status, _ := call(handler, http.MethodPost, Route, body); status != http.StatusBadRequest {
			t.Fatalf("%s = %d", body, status)
		}
	}
	if len(stepUp.bindings) != 0 {
		t.Fatal("step-up consumed for an invalid request")
	}
	store.err = ErrNoNodes
	if status, code := call(handler, http.MethodPost, Route, `{"address":"g.cdnca.com:443","target_kind":"region","region":"hk","step_up_token":"proof"}`); status != http.StatusUnprocessableEntity || code != "gateway_address_no_nodes" {
		t.Fatalf("no nodes = %d %s", status, code)
	}
}

func TestRetryAndReadRoutes(t *testing.T) {
	store, stepUp := &handlerStore{}, &recordingStepUp{}
	handler, woken := testHandler(store, stepUp, []string{PermissionManage, PermissionRead}, "platform")
	id := uuid.New()
	if status, code := call(handler, http.MethodPost, Route+"/"+id.String()+"/retry", `{"step_up_token":"proof"}`); status != http.StatusOK {
		t.Fatalf("retry = %d %s", status, code)
	}
	if len(store.retried) != 1 || store.retried[0] != id || stepUp.bindings[0] != RetryBinding(id) || *woken != 1 {
		t.Fatal("retry not bound to the change")
	}
	if status, _ := call(handler, http.MethodGet, Route+"/"+id.String(), ""); status != http.StatusOK {
		t.Fatalf("get = %d", status)
	}
	if status, _ := call(handler, http.MethodGet, Route, ""); status != http.StatusOK {
		t.Fatalf("list = %d", status)
	}
	if status, _ := call(handler, http.MethodGet, Route+"/not-a-uuid", ""); status != http.StatusNotFound {
		t.Fatalf("bad id = %d", status)
	}
	store.err = ErrNothingToRetry
	if status, code := call(handler, http.MethodPost, Route+"/"+id.String()+"/retry", `{"step_up_token":"proof"}`); status != http.StatusConflict || code != "gateway_address_nothing_to_retry" {
		t.Fatalf("nothing to retry = %d %s", status, code)
	}
	notReady, _ := testHandler(store, stepUp, []string{PermissionManage}, "platform")
	notReady.Ready = func() bool { return false }
	if status, code := call(notReady, http.MethodPost, Route+"/"+id.String()+"/retry", `{"step_up_token":"proof"}`); status != http.StatusServiceUnavailable || code != "gateway_address_unavailable" {
		t.Fatalf("not ready = %d %s", status, code)
	}
}
