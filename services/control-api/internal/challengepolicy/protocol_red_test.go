package challengepolicy

import (
	"bytes"
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"net/http"
	"net/http/httptest"
	"net/url"
	"strings"
	"testing"
)

func TestProtocolAuthenticatorDependencyErrorsAreUnavailable(t *testing.T) {
	tests := []struct {
		name   string
		err    error
		status int
		code   string
	}{
		{name: "unavailable", err: ErrUnavailable, status: http.StatusServiceUnavailable, code: "service_unavailable"},
		{name: "dependency failure", err: errors.New("identity dependency failed"), status: http.StatusServiceUnavailable, code: "service_unavailable"},
		{name: "invalid session", err: ErrUnauthenticated, status: http.StatusUnauthorized, code: "authentication_required"},
	}
	for _, test := range tests {
		t.Run(test.name, func(t *testing.T) {
			handler, err := NewHandler(&Service{store: &Store{}}, AuthenticatorFunc(func(*http.Request) (Actor, error) {
				return Actor{}, test.err
			}))
			if err != nil {
				t.Fatal(err)
			}
			request := httptest.NewRequest(http.MethodGet, collectionPath(testUUID(1)), nil)
			request.Header.Set("X-Request-ID", "auth-contract-request")
			request.Header.Set("X-Trace-ID", "auth-contract-trace")
			response := httptest.NewRecorder()
			handler.ServeHTTP(response, request)
			assertHTTPError(t, response, test.status, test.code)
		})
	}
}

func TestProtocolRejectsNonCanonicalRoutesBeforeAuthentication(t *testing.T) {
	authenticationCalls := 0
	handler, err := NewHandler(&Service{store: &Store{}}, AuthenticatorFunc(func(*http.Request) (Actor, error) {
		authenticationCalls++
		return Actor{}, ErrUnauthenticated
	}))
	if err != nil {
		t.Fatal(err)
	}
	canonical := collectionPath(testUUID(1))
	for _, requestPath := range []string{
		canonical + "/",
		strings.Replace(canonical, "/challenge-policies", "/./challenge-policies", 1),
		canonical + "/unknown/operation",
	} {
		request := httptest.NewRequest(http.MethodGet, requestPath, nil)
		request.Header.Set("X-Request-ID", "strict-route-request")
		request.Header.Set("X-Trace-ID", "strict-route-trace")
		response := httptest.NewRecorder()
		handler.ServeHTTP(response, request)
		if response.Code != http.StatusNotFound {
			t.Fatalf("path=%q status=%d body=%s", requestPath, response.Code, response.Body)
		}
	}
	if authenticationCalls != 0 {
		t.Fatalf("non-canonical routes reached authentication %d times", authenticationCalls)
	}
}

func TestProtocolRejectsDuplicateSecurityAndCorrelationHeaders(t *testing.T) {
	fixture := newFixture(t, allowGate())
	tests := []struct {
		header string
		values []string
	}{
		{header: "Authorization", values: []string{"Bearer owner-a", "Bearer owner-b"}},
		{header: "X-Request-ID", values: []string{"duplicate-request-a", "duplicate-request-b"}},
		{header: "X-Trace-ID", values: []string{"duplicate-trace-a", "duplicate-trace-b"}},
		{header: "Idempotency-Key", values: []string{"duplicate-key-a", "duplicate-key-b"}},
		{header: "If-Match", values: []string{`"1"`, `"1"`}},
	}
	for index, test := range tests {
		t.Run(test.header, func(t *testing.T) {
			domain := fmt.Sprintf("duplicate-%d.example.test", index)
			siteID := insertSite(t, fixture.pool, fixture.tenantA, fixture.ownerA.UserID, domain)
			policy := createServicePolicy(t, fixture, siteID, domain, fmt.Sprintf("duplicate-seed-%d", index))
			request := protocolPatchRequest(t, fixture, policy, fmt.Sprintf("duplicate-write-%d", index), `"1"`)
			request.Header.Del(test.header)
			for _, value := range test.values {
				request.Header.Add(test.header, value)
			}
			response := httptest.NewRecorder()
			fixture.handler.ServeHTTP(response, request)
			assertHTTPError(t, response, http.StatusBadRequest, "invalid_request")
		})
	}
}

func TestProtocolPreservesSingleHeadersAndRequiresJSONWrites(t *testing.T) {
	fixture := newFixture(t, allowGate())

	domain := "single-headers.example.test"
	siteID := insertSite(t, fixture.pool, fixture.tenantA, fixture.ownerA.UserID, domain)
	policy := createServicePolicy(t, fixture, siteID, domain, "single-headers-seed")
	request := protocolPatchRequest(t, fixture, policy, "single-headers-write", `"1"`)
	response := httptest.NewRecorder()
	fixture.handler.ServeHTTP(response, request)
	if response.Code != http.StatusOK {
		t.Fatalf("single-value headers status=%d body=%s", response.Code, response.Body)
	}

	domain = "content-type.example.test"
	siteID = insertSite(t, fixture.pool, fixture.tenantA, fixture.ownerA.UserID, domain)
	policy = createServicePolicy(t, fixture, siteID, domain, "content-type-seed")
	request = protocolPatchRequest(t, fixture, policy, "content-type-write", `"1"`)
	request.Header.Set("Content-Type", "text/plain")
	response = httptest.NewRecorder()
	fixture.handler.ServeHTTP(response, request)
	assertHTTPError(t, response, http.StatusBadRequest, "invalid_request")
}

func TestProtocolCommandBodyRequiresJSONContentType(t *testing.T) {
	authenticationCalls := 0
	handler, err := NewHandler(&Service{store: &Store{}}, AuthenticatorFunc(func(*http.Request) (Actor, error) {
		authenticationCalls++
		return Actor{}, ErrUnauthenticated
	}))
	if err != nil {
		t.Fatal(err)
	}
	request := httptest.NewRequest(http.MethodPost,
		itemPath(testUUID(1), testUUID(2))+"/enable", strings.NewReader("{}"))
	request.Header.Set("Authorization", "Bearer invalid")
	request.Header.Set("X-Request-ID", "command-content-type-request")
	request.Header.Set("X-Trace-ID", "command-content-type-trace")
	request.Header.Set("Idempotency-Key", "command-content-type-key")
	request.Header.Set("If-Match", `"1"`)
	request.Header.Set("Content-Type", "text/plain")
	response := httptest.NewRecorder()
	handler.ServeHTTP(response, request)
	assertHTTPError(t, response, http.StatusBadRequest, "invalid_request")
	if authenticationCalls != 0 {
		t.Fatalf("invalid command media type reached authentication %d times", authenticationCalls)
	}
}

func TestProtocolRequiresCanonicalIfMatch(t *testing.T) {
	fixture := newFixture(t, allowGate())
	tests := []struct {
		name   string
		value  string
		status int
	}{
		{name: "leading zero", value: `"01"`, status: http.StatusBadRequest},
		{name: "explicit plus", value: `"+1"`, status: http.StatusBadRequest},
		{name: "canonical", value: `"1"`, status: http.StatusOK},
	}
	for index, test := range tests {
		t.Run(test.name, func(t *testing.T) {
			domain := fmt.Sprintf("if-match-%d.example.test", index)
			siteID := insertSite(t, fixture.pool, fixture.tenantA, fixture.ownerA.UserID, domain)
			policy := createServicePolicy(t, fixture, siteID, domain, fmt.Sprintf("if-match-seed-%d", index))
			request := protocolPatchRequest(t, fixture, policy, fmt.Sprintf("if-match-write-%d", index), test.value)
			response := httptest.NewRecorder()
			fixture.handler.ServeHTTP(response, request)
			if response.Code != test.status {
				t.Fatalf("If-Match %q status=%d want=%d body=%s", test.value, response.Code, test.status, response.Body)
			}
		})
	}
}

func TestProtocolLargeLegalPageFitsResponseBudgetAndContinues(t *testing.T) {
	fixture := newFixture(t, allowGate())
	siteID := insertSite(t, fixture.pool, fixture.tenantA, fixture.ownerA.UserID, "*.budget.example.test")
	config := validConfig(ModeClick)
	config.BypassRoutes = make([]BypassRoute, 0, 32)
	for index := 0; index < 32; index++ {
		config.BypassRoutes = append(config.BypassRoutes, BypassRoute{
			Kind: BypassExact,
			Path: fmt.Sprintf("/%02d/%s", index, strings.Repeat("a", 508)),
		})
	}
	for index := 0; index < 100; index++ {
		host := fmt.Sprintf("policy-%03d.budget.example.test", index)
		_, err := fixture.service.Create(context.Background(), fixture.ownerA, CreateRequest{
			TargetScopeID: fixture.tenantA,
			SiteID:        siteID,
			Host:          host,
			Enabled:       true,
			Config:        config,
			WriteMetadata: metadata(fmt.Sprintf("budget-create-%03d", index)),
		})
		if err != nil {
			t.Fatalf("create large policy %d: %v", index, err)
		}
	}

	firstResponse := fixture.request(t, "owner-a", http.MethodGet, collectionPath(fixture.tenantA)+"?limit=100", nil, "", "")
	first := decodeProtocolList(t, firstResponse)
	if len(first.Items) == 0 || first.NextCursor == "" {
		t.Fatalf("first budget page items=%d next_cursor=%q", len(first.Items), first.NextCursor)
	}
	repeatedResponse := fixture.request(t, "owner-a", http.MethodGet, collectionPath(fixture.tenantA)+"?limit=100", nil, "", "")
	repeated := decodeProtocolList(t, repeatedResponse)
	if repeated.NextCursor != first.NextCursor {
		t.Fatalf("unstable budget cursor: first=%q repeated=%q", first.NextCursor, repeated.NextCursor)
	}
	continuationPath := collectionPath(fixture.tenantA) + "?limit=100&cursor=" + url.QueryEscape(first.NextCursor)
	continued := decodeProtocolList(t, fixture.request(t, "owner-a", http.MethodGet, continuationPath, nil, "", ""))
	if len(continued.Items) == 0 {
		t.Fatal("budget continuation returned no items")
	}
}

func protocolPatchRequest(t *testing.T, fixture *testFixture, policy Policy, key, ifMatch string) *http.Request {
	t.Helper()
	config := validConfig(ModeClick)
	config.Priority++
	body, err := json.Marshal(map[string]any{"config": config})
	if err != nil {
		t.Fatal(err)
	}
	request := httptest.NewRequest(http.MethodPatch, itemPath(fixture.tenantA, policy.ID), bytes.NewReader(body))
	request.Header.Set("Authorization", "Bearer owner-a")
	request.Header.Set("X-Request-ID", key+"-request")
	request.Header.Set("X-Trace-ID", key+"-trace")
	request.Header.Set("Idempotency-Key", key)
	request.Header.Set("If-Match", ifMatch)
	request.Header.Set("Content-Type", "application/json")
	return request
}

func decodeProtocolList(t *testing.T, response *httptest.ResponseRecorder) ListResult {
	t.Helper()
	if response.Code == http.StatusServiceUnavailable {
		t.Fatalf("schema-legal page exceeded response budget: %s", response.Body)
	}
	if response.Code != http.StatusOK {
		t.Fatalf("list status=%d body=%s", response.Code, response.Body)
	}
	var result ListResult
	if err := json.Unmarshal(response.Body.Bytes(), &result); err != nil {
		t.Fatalf("decode list response: %v", err)
	}
	return result
}

func testUUID(value byte) [16]byte {
	var id [16]byte
	id[15] = value
	return id
}
