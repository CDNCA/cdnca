package approvalcenter

import (
	"context"
	"encoding/json"
	"io"
	"net/http"
	"net/http/httptest"
	"net/url"
	"strings"
	"testing"

	"github.com/google/uuid"
)

type gateFixture struct {
	settings  Settings
	session   Session
	sessionOK bool
	submitted []Step
	rules     []string
	groups    []string
	reasons   []string
	forwarded int
}

func (f *gateFixture) handler() http.Handler {
	gate := Gate{
		Settings: func(context.Context) (Settings, error) { return f.settings, nil },
		Session:  func(*http.Request) (Session, bool) { return f.session, f.sessionOK },
		Submit: func(_ context.Context, _ Session, rule Rule, group, reason string, step Step, _ string) (Request, error) {
			f.submitted = append(f.submitted, step)
			f.rules = append(f.rules, rule.Name)
			f.groups = append(f.groups, group)
			f.reasons = append(f.reasons, reason)
			return Request{ID: uuid.New(), Rule: rule.Name, State: StatePending, Revision: 1}, nil
		},
	}
	return gate.Wrap(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		f.forwarded++
		body, _ := io.ReadAll(r.Body)
		w.WriteHeader(http.StatusOK)
		_, _ = w.Write(body)
	}))
}

func newFixture(enabled bool, rules ...string) *gateFixture {
	return &gateFixture{
		settings:  Settings{Enabled: enabled, Rules: rules, Revision: 1},
		session:   Session{UserID: uuid.New(), ScopeID: uuid.New(), ScopeKind: "platform"},
		sessionOK: true,
	}
}

func send(t *testing.T, handler http.Handler, method, path, body string, headers map[string]string) *httptest.ResponseRecorder {
	t.Helper()
	request := httptest.NewRequest(method, path, strings.NewReader(body))
	request.Header.Set("Authorization", "Bearer token")
	request.Header.Set("Content-Type", "application/json")
	for name, value := range headers {
		request.Header.Set(name, value)
	}
	response := httptest.NewRecorder()
	handler.ServeHTTP(response, request)
	return response
}

func TestGateOffPassesEveryRequest(t *testing.T) {
	fixture := newFixture(false, DefaultRules()...)
	handler := fixture.handler()
	response := send(t, handler, http.MethodPost, "/v1/sites/batch-action", `{"action":"delete","items":[]}`, nil)
	if response.Code != http.StatusOK || fixture.forwarded != 1 || len(fixture.submitted) != 0 {
		t.Fatalf("off: status=%d forwarded=%d submitted=%d", response.Code, fixture.forwarded, len(fixture.submitted))
	}
	if response.Body.String() != `{"action":"delete","items":[]}` {
		t.Fatalf("body was not passed through: %q", response.Body.String())
	}
}

func TestGateRequiresReasonThenStoresRequest(t *testing.T) {
	fixture := newFixture(true, DefaultRules()...)
	handler := fixture.handler()
	body := `{"action":"delete","items":[{"id":"x"}]}`
	response := send(t, handler, http.MethodPost, "/v1/sites/batch-action", body, map[string]string{"Idempotency-Key": "k1"})
	if response.Code != http.StatusPreconditionRequired || fixture.forwarded != 0 {
		t.Fatalf("no reason: status=%d forwarded=%d", response.Code, fixture.forwarded)
	}
	var envelope struct {
		Error struct {
			Code    string            `json:"code"`
			Details map[string]string `json:"details"`
		} `json:"error"`
	}
	if err := json.Unmarshal(response.Body.Bytes(), &envelope); err != nil || envelope.Error.Code != "approval_required" ||
		envelope.Error.Details["rule"] != RuleSiteBatchDelete {
		t.Fatalf("428 envelope = %s (%v)", response.Body.String(), err)
	}
	response = send(t, handler, http.MethodPost, "/v1/sites/batch-action?x=1", body, map[string]string{
		"Idempotency-Key": "k1", "If-Match": `"3"`, headerApprovalReason: url.QueryEscape("清理测试站点"),
	})
	if response.Code != http.StatusAccepted || fixture.forwarded != 0 || len(fixture.submitted) != 1 {
		t.Fatalf("with reason: status=%d forwarded=%d submitted=%d", response.Code, fixture.forwarded, len(fixture.submitted))
	}
	step := fixture.submitted[0]
	if step.Method != http.MethodPost || step.Path != "/v1/sites/batch-action" || step.Query != "x=1" || string(step.Body) != body ||
		step.Headers["Idempotency-Key"] != "k1" || step.Headers["If-Match"] != `"3"` || step.Headers["Authorization"] != "" ||
		fixture.reasons[0] != "清理测试站点" {
		t.Fatalf("stored step = %+v reason=%q", step, fixture.reasons[0])
	}
	if !strings.Contains(response.Body.String(), `"approval_submitted"`) {
		t.Fatalf("202 body = %s", response.Body.String())
	}
}

func TestGateRejectsInvalidReason(t *testing.T) {
	fixture := newFixture(true, DefaultRules()...)
	response := send(t, fixture.handler(), http.MethodPut, "/v1/firewall/policy", `{}`, map[string]string{headerApprovalReason: "%zz"})
	if response.Code != http.StatusBadRequest || len(fixture.submitted) != 0 {
		t.Fatalf("status=%d submitted=%d", response.Code, len(fixture.submitted))
	}
}

func TestGatePassesUnmanagedAndUncheckedOperations(t *testing.T) {
	fixture := newFixture(true, DefaultRules()...)
	handler := fixture.handler()
	for _, request := range []struct{ method, path, body string }{
		{http.MethodPost, "/v1/sites/batch-action", `{"action":"enable"}`},
		{http.MethodPost, "/v1/sites/batch-action", `{"action":"disable"}`}, // second batch, unchecked
		{http.MethodPost, "/v1/admin/cache-operations", `{"target_type":"url"}`},
		{http.MethodGet, "/v1/firewall/policy", ``},
		{http.MethodDelete, "/v1/streams/11111111-1111-4111-8111-111111111111", ``},
		{http.MethodPost, "/v1/admin/control-upgrade-rollouts/abc/pause", ``},
	} {
		if response := send(t, handler, request.method, request.path, request.body, nil); response.Code != http.StatusOK {
			t.Fatalf("%s %s: status=%d", request.method, request.path, response.Code)
		}
	}
	if fixture.forwarded != 6 {
		t.Fatalf("forwarded=%d", fixture.forwarded)
	}
}

func TestGateHoldsEveryCatalogEntryWhenChecked(t *testing.T) {
	all := make([]string, 0, len(Catalog))
	for _, rule := range Catalog {
		all = append(all, rule.Name)
	}
	for _, test := range []struct{ rule, method, path, body string }{
		{RuleSiteBatchDelete, http.MethodPost, "/v1/sites/batch-action", `{"action":"delete"}`},
		{RuleCacheWholeSite, http.MethodPost, "/v1/admin/cache-operations", `{"target_type":"whole_site"}`},
		{RuleFirewallPolicy, http.MethodPut, "/v1/firewall/policy", `{}`},
		{RuleFirewallPolicy, http.MethodPost, "/v1/firewall/policy/recover", `{}`},
		{RuleFirewallPolicy, http.MethodPut, "/v1/firewall-actions/policy", `{}`},
		{RuleFirewallPolicy, http.MethodPost, "/v1/firewall-actions/policy/recover", `{}`},
		{RuleControlUpgrade, http.MethodPost, "/v1/admin/control-upgrade-plan/issue", `{}`},
		{RuleControlUpgrade, http.MethodPost, "/v1/admin/control-upgrade-rollouts/r1/start", ``},
		{RuleControlUpgrade, http.MethodPost, "/v1/admin/control-upgrade-rollouts/r1/rollback", ``},
		{RuleSiteBatchDisable, http.MethodPost, "/v1/sites/batch-action", `{"action":"disable"}`},
		{RuleNodeBatchDisable, http.MethodPost, "/v1/nodes/batch-admin-state", `{"admin_state":"disabled"}`},
		{RuleStreamBatchDelete, http.MethodDelete, "/v1/streams/11111111-1111-4111-8111-111111111111", ``},
		{RuleUserDelete, http.MethodDelete, "/v1/admin/users/11111111-1111-4111-8111-111111111111", `{"expected_revision":2}`},
	} {
		fixture := newFixture(true, all...)
		response := send(t, fixture.handler(), test.method, test.path, test.body, nil)
		var envelope struct {
			Error struct {
				Details map[string]string `json:"details"`
			} `json:"error"`
		}
		_ = json.Unmarshal(response.Body.Bytes(), &envelope)
		if response.Code != http.StatusPreconditionRequired || envelope.Error.Details["rule"] != test.rule {
			t.Fatalf("%s %s: status=%d rule=%q", test.method, test.path, response.Code, envelope.Error.Details["rule"])
		}
	}
}

// Q4 API keys pass; Q5 tenant sessions pass; unauthenticated requests reach
// the business handler, which answers 401 as before.
func TestGatePassesAPIKeysTenantsAndAnonymous(t *testing.T) {
	fixture := newFixture(true, DefaultRules()...)
	handler := fixture.handler()
	request := httptest.NewRequest(http.MethodPut, "/v1/firewall/policy", strings.NewReader(`{}`))
	request.Header.Set("Authorization", "CdncaKey key")
	response := httptest.NewRecorder()
	handler.ServeHTTP(response, request)
	if response.Code != http.StatusOK {
		t.Fatalf("api key: status=%d", response.Code)
	}
	fixture.session.ScopeKind = "tenant"
	if response := send(t, handler, http.MethodPut, "/v1/firewall/policy", `{}`, nil); response.Code != http.StatusOK {
		t.Fatalf("tenant: status=%d", response.Code)
	}
	fixture.sessionOK = false
	if response := send(t, handler, http.MethodPut, "/v1/firewall/policy", `{}`, nil); response.Code != http.StatusOK {
		t.Fatalf("invalid session: status=%d", response.Code)
	}
	if fixture.forwarded != 3 || len(fixture.submitted) != 0 {
		t.Fatalf("forwarded=%d submitted=%d", fixture.forwarded, len(fixture.submitted))
	}
}

func TestGateGroupHeaderOnlyForGroupedRules(t *testing.T) {
	fixture := newFixture(true, RuleStreamBatchDelete)
	handler := fixture.handler()
	headers := map[string]string{headerApprovalReason: "batch", headerApprovalGroup: "stream-delete-1"}
	for range 2 {
		if response := send(t, handler, http.MethodDelete, "/v1/streams/11111111-1111-4111-8111-111111111111", ``, headers); response.Code != http.StatusAccepted {
			t.Fatalf("status=%d", response.Code)
		}
	}
	if len(fixture.groups) != 2 || fixture.groups[0] != "stream-delete-1" {
		t.Fatalf("groups=%v", fixture.groups)
	}
	headers[headerApprovalGroup] = "-bad"
	if response := send(t, handler, http.MethodDelete, "/v1/streams/11111111-1111-4111-8111-111111111111", ``, headers); response.Code != http.StatusBadRequest {
		t.Fatalf("invalid group: status=%d", response.Code)
	}
}

func TestReplayMarksExecutionAndStopsAtFirstFailure(t *testing.T) {
	fixture := newFixture(true, DefaultRules()...)
	var seen []string
	target := Gate{
		Settings: func(context.Context) (Settings, error) { return fixture.settings, nil },
		Session:  func(*http.Request) (Session, bool) { return fixture.session, true },
		Submit: func(context.Context, Session, Rule, string, string, Step, string) (Request, error) {
			t.Fatal("a replay must not be held again")
			return Request{}, nil
		},
	}.Wrap(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		seen = append(seen, r.Header.Get("Authorization")+" "+r.Header.Get("Idempotency-Key")+" "+r.URL.RawQuery)
		if r.URL.Path == "/v1/firewall/policy/recover" {
			w.WriteHeader(http.StatusConflict)
			_, _ = w.Write([]byte(`{"error":{"code":"revision_conflict"}}`))
			return
		}
		w.WriteHeader(http.StatusNoContent)
	}))
	results := Replay(t.Context(), target, "Bearer approver", []Step{
		{Method: http.MethodPut, Path: "/v1/firewall/policy", Query: "a=1", Headers: map[string]string{"Idempotency-Key": "k1"}, Body: []byte(`{}`)},
		{Method: http.MethodPost, Path: "/v1/firewall/policy/recover", Headers: map[string]string{"Idempotency-Key": "k2"}},
		{Method: http.MethodPut, Path: "/v1/firewall/policy"},
	})
	if len(results) != 2 || results[0].Status != http.StatusNoContent || results[1].Status != http.StatusConflict ||
		!strings.Contains(results[1].Body, "revision_conflict") {
		t.Fatalf("results=%+v", results)
	}
	if len(seen) != 2 || seen[0] != "Bearer approver k1 a=1" || seen[1] != "Bearer approver k2 " {
		t.Fatalf("seen=%v", seen)
	}
}

func TestValidRules(t *testing.T) {
	if !ValidRules(DefaultRules()) || len(DefaultRules()) != 4 {
		t.Fatalf("default rules = %v", DefaultRules())
	}
	if ValidRules([]string{RuleUserDelete, RuleUserDelete}) || ValidRules([]string{"unknown"}) {
		t.Fatal("duplicate or unknown rules accepted")
	}
}
