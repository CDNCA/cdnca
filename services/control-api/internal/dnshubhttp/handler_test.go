package dnshubhttp

import (
	"context"
	"encoding/json"
	"errors"
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"
	"time"

	"github.com/cdnca/cdnca/services/control-api/internal/dnsproviderremote"
	"github.com/cdnca/cdnca/services/control-api/internal/dnsproviderremotesource"
	"github.com/cdnca/cdnca/services/control-api/internal/identity"
	"github.com/google/uuid"
)

type fakeHub struct {
	actors    []dnsproviderremotesource.HubActor
	mutations []dnsproviderremotesource.HubMutation
	err       error
	result    dnsproviderremotesource.HubMutationResult
}

func (hub *fakeHub) ListDomains(_ context.Context, actor dnsproviderremotesource.HubActor, _ dnsproviderremotesource.HubDomainQuery) (dnsproviderremotesource.HubDomainPage, error) {
	hub.actors = append(hub.actors, actor)
	return dnsproviderremotesource.HubDomainPage{Accounts: []dnsproviderremotesource.HubAccount{},
		Items: []dnsproviderremotesource.HubDomain{}}, hub.err
}

func (hub *fakeHub) RefreshDomains(_ context.Context, actor dnsproviderremotesource.HubActor, _ uuid.UUID) ([]dnsproviderremotesource.HubRefreshResult, error) {
	hub.actors = append(hub.actors, actor)
	return []dnsproviderremotesource.HubRefreshResult{}, hub.err
}

func (hub *fakeHub) ListRecords(_ context.Context, actor dnsproviderremotesource.HubActor, providerID uuid.UUID, apex string, _ dnsproviderremotesource.HubRecordQuery) (dnsproviderremotesource.HubRecordList, error) {
	hub.actors = append(hub.actors, actor)
	return dnsproviderremotesource.HubRecordList{ProviderID: providerID, Apex: apex, Items: []dnsproviderremotesource.HubRecord{}}, hub.err
}

func (hub *fakeHub) Mutate(_ context.Context, actor dnsproviderremotesource.HubActor, mutation dnsproviderremotesource.HubMutation) (dnsproviderremotesource.HubMutationResult, error) {
	hub.actors = append(hub.actors, actor)
	hub.mutations = append(hub.mutations, mutation)
	return hub.result, hub.err
}

var (
	tenantUser, tenantScope = uuid.New(), uuid.New()
)

func authenticate(_ context.Context, token string) (identity.AuthenticatedSession, error) {
	switch token {
	case "tenant":
		return identity.AuthenticatedSession{SessionID: uuid.New(), Principal: identity.Principal{
			UserID: tenantUser, ScopeID: tenantScope, ScopeKind: "tenant"}}, nil
	case "platform":
		return identity.AuthenticatedSession{SessionID: uuid.New(), Principal: identity.Principal{
			UserID: uuid.New(), ScopeID: uuid.New(), ScopeKind: "platform"}}, nil
	default:
		return identity.AuthenticatedSession{}, errors.New("bad token")
	}
}

func serve(t *testing.T, hub *fakeHub, method, target, token, body string, headers map[string]string) *httptest.ResponseRecorder {
	t.Helper()
	handler, err := NewHandler(hub, authenticate)
	if err != nil {
		t.Fatal(err)
	}
	request := httptest.NewRequest(method, target, strings.NewReader(body))
	if token != "" {
		request.Header.Set("Authorization", "Bearer "+token)
	}
	if body != "" {
		request.Header.Set("Content-Type", "application/json")
	}
	for key, value := range headers {
		request.Header.Set(key, value)
	}
	recorder := httptest.NewRecorder()
	handler.ServeHTTP(recorder, request)
	return recorder
}

func errorCode(t *testing.T, recorder *httptest.ResponseRecorder) (string, map[string]any) {
	t.Helper()
	var body struct {
		Error map[string]any `json:"error"`
	}
	if err := json.Unmarshal(recorder.Body.Bytes(), &body); err != nil {
		t.Fatalf("body %s: %v", recorder.Body.String(), err)
	}
	code, _ := body.Error["code"].(string)
	return code, body.Error
}

func TestSessionGate(t *testing.T) {
	hub := &fakeHub{}
	if recorder := serve(t, hub, http.MethodGet, "/v1/dns/hub/domains", "", "", nil); recorder.Code != http.StatusUnauthorized {
		t.Fatalf("anonymous status %d", recorder.Code)
	}
	if recorder := serve(t, hub, http.MethodGet, "/v1/dns/hub/domains", "platform", "", nil); recorder.Code != http.StatusForbidden {
		t.Fatalf("platform session status %d", recorder.Code)
	}
	if len(hub.actors) != 0 {
		t.Fatal("hub called without a tenant session")
	}
	recorder := serve(t, hub, http.MethodGet, "/v1/dns/hub/domains?limit=10", "tenant", "", map[string]string{"X-Request-ID": "req-1"})
	if recorder.Code != http.StatusOK || len(hub.actors) != 1 || hub.actors[0].ScopeID != tenantScope ||
		hub.actors[0].UserID != tenantUser || hub.actors[0].RequestID != "req-1" {
		t.Fatalf("status %d actors %+v", recorder.Code, hub.actors)
	}
	if recorder.Header().Get("Cache-Control") != "no-store" {
		t.Fatal("hub responses must not be cached")
	}
}

func TestQueryValidation(t *testing.T) {
	for _, target := range []string{
		"/v1/dns/hub/domains?limit=0", "/v1/dns/hub/domains?limit=01", "/v1/dns/hub/domains?provider_id=x",
		"/v1/dns/hub/domains?unknown=1", "/v1/dns/hub/domains?q=a&q=b",
	} {
		recorder := serve(t, &fakeHub{}, http.MethodGet, target, "tenant", "", nil)
		if code, _ := errorCode(t, recorder); recorder.Code != http.StatusBadRequest || code != "validation_error" {
			t.Fatalf("%s: %d %s", target, recorder.Code, code)
		}
	}
}

func TestMutationRequiresIdempotencyKeyAndPassesFields(t *testing.T) {
	hub := &fakeHub{result: dnsproviderremotesource.HubMutationResult{OpID: uuid.New(), State: "applied", Status: http.StatusCreated}}
	provider := uuid.New()
	target := "/v1/dns/hub/domains/" + provider.String() + "/example.com/records"
	body := `{"name":"www","type":"TXT","value":"v=spf1 -all","ttl":600,"line":"默认"}`
	if recorder := serve(t, hub, http.MethodPost, target, "tenant", body, nil); recorder.Code != http.StatusBadRequest {
		t.Fatalf("missing key status %d", recorder.Code)
	}
	recorder := serve(t, hub, http.MethodPost, target, "tenant", body, map[string]string{"Idempotency-Key": "key-1"})
	if recorder.Code != http.StatusCreated || len(hub.mutations) != 1 {
		t.Fatalf("status %d body %s", recorder.Code, recorder.Body.String())
	}
	mutation := hub.mutations[0]
	if mutation.Action != "create" || mutation.ProviderID != provider || mutation.Apex != "example.com" ||
		mutation.Record.Value != "v=spf1 -all" || mutation.IdempotencyKey != "key-1" {
		t.Fatalf("mutation %+v", mutation)
	}
	var result map[string]any
	_ = json.Unmarshal(recorder.Body.Bytes(), &result)
	if result["state"] != "applied" || result["op_id"] == nil {
		t.Fatalf("result %v", result)
	}
	// Unknown body fields are refused (no silent typo such as "expect").
	recorder = serve(t, hub, http.MethodPatch, target+"/r1.cg", "tenant", `{"expect":{}}`, map[string]string{"Idempotency-Key": "key-2"})
	if recorder.Code != http.StatusBadRequest {
		t.Fatalf("unknown field status %d", recorder.Code)
	}
	recorder = serve(t, hub, http.MethodDelete, target+"/r1.cg", "tenant",
		`{"expected":{"name":"www","type":"A","value":"192.0.2.1","ttl":600},"confirm_managed":true}`,
		map[string]string{"Idempotency-Key": "key-3"})
	last := hub.mutations[len(hub.mutations)-1]
	if recorder.Code != http.StatusCreated || last.Action != "delete" || last.RecordRef != "r1.cg" || !last.ConfirmManaged ||
		last.Expected == nil || last.Expected.Value != "192.0.2.1" {
		t.Fatalf("delete %d %+v", recorder.Code, last)
	}
}

func TestServiceErrorMapping(t *testing.T) {
	current := &dnsproviderremotesource.HubRecord{RecordRef: "r1.x", Name: "www", Type: "A", Value: "192.0.2.9", TTL: 600}
	for _, test := range []struct {
		err    error
		status int
		code   string
		key    string
	}{
		{dnsproviderremotesource.ErrHubNotFound, 404, "dns_hub_not_found", ""},
		{dnsproviderremotesource.ErrHubPermission, 403, "permission_denied", ""},
		{&dnsproviderremotesource.HubFieldError{Field: "ttl"}, 400, "validation_error", "field"},
		{dnsproviderremotesource.ErrHubIdempotency, 409, "idempotency_conflict", ""},
		{&dnsproviderremotesource.HubChangedError{Current: current}, 409, "dns_record_changed", "current"},
		{&dnsproviderremotesource.HubManagedError{Managed: dnsproviderremotesource.HubManaged{Kind: "site_cname"}}, 409, "dns_record_managed", "managed"},
		{dnsproviderremotesource.ErrHubConflict, 409, "dns_record_conflict", ""},
		{dnsproviderremotesource.ErrHubUnsupported, 422, "dns_record_unsupported", ""},
		{&dnsproviderremote.Error{Code: dnsproviderremote.CodeRateLimited, Temporary: true, RetryAfter: 3 * time.Second}, 502, "dns_provider_error", "provider_code"},
		{errors.New("pool closed"), 503, "dns_hub_unavailable", ""},
	} {
		recorder := serve(t, &fakeHub{err: test.err}, http.MethodGet,
			"/v1/dns/hub/domains/"+uuid.NewString()+"/example.com/records", "tenant", "", nil)
		code, body := errorCode(t, recorder)
		if recorder.Code != test.status || code != test.code {
			t.Fatalf("%v: %d %s", test.err, recorder.Code, code)
		}
		if test.key != "" && body[test.key] == nil {
			t.Fatalf("%v: %s missing in %v", test.err, test.key, body)
		}
		if test.code == "dns_provider_error" && (body["provider_code"] != "rate_limited" || recorder.Header().Get("Retry-After") != "3") {
			t.Fatalf("provider error body %v header %q", body, recorder.Header().Get("Retry-After"))
		}
		if strings.Contains(recorder.Body.String(), "pool closed") {
			t.Fatal("internal error text leaked")
		}
	}
}

func TestBatchRunsItemsWithDerivedKeys(t *testing.T) {
	hub := &fakeHub{result: dnsproviderremotesource.HubMutationResult{OpID: uuid.New(), State: "applied", Status: 200}}
	provider := uuid.NewString()
	body := `{"items":[
		{"provider_id":"` + provider + `","apex":"a.com","action":"update","record_ref":"r1.cg","name":"@","type":"TXT","value":"x","ttl":300,
		 "expected":{"name":"@","type":"TXT","value":"y","ttl":600}},
		{"provider_id":"bad","apex":"b.com","action":"create"},
		{"provider_id":"` + provider + `","apex":"c.com","action":"upsert"}]}`
	recorder := serve(t, hub, http.MethodPost, "/v1/dns/hub/records/batch", "tenant", body, map[string]string{"Idempotency-Key": "batch-1"})
	if recorder.Code != http.StatusOK {
		t.Fatalf("status %d %s", recorder.Code, recorder.Body.String())
	}
	var parsed struct {
		Results []struct {
			Index  int            `json:"index"`
			Status int            `json:"status"`
			Error  map[string]any `json:"error"`
		} `json:"results"`
	}
	if err := json.Unmarshal(recorder.Body.Bytes(), &parsed); err != nil || len(parsed.Results) != 3 {
		t.Fatalf("results %s", recorder.Body.String())
	}
	if parsed.Results[0].Status != 200 || parsed.Results[1].Status != 404 || parsed.Results[2].Status != 400 {
		t.Fatalf("statuses %+v", parsed.Results)
	}
	if len(hub.mutations) != 1 || hub.mutations[0].IdempotencyKey != "batch-1.0" || hub.mutations[0].Apex != "a.com" {
		t.Fatalf("mutations %+v", hub.mutations)
	}
	empty := serve(t, hub, http.MethodPost, "/v1/dns/hub/records/batch", "tenant", `{"items":[]}`, map[string]string{"Idempotency-Key": "batch-2"})
	if empty.Code != http.StatusBadRequest {
		t.Fatalf("empty batch status %d", empty.Code)
	}
}
