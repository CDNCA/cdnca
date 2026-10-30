package challengepolicy

import (
	"bytes"
	"context"
	"encoding/json"
	"net/http"
	"net/http/httptest"
	"testing"

	"github.com/cdnca/cdnca/services/control-api/internal/challengepublication"
	"github.com/google/uuid"
)

type publicationDomainStub struct {
	result       PublicationStatus
	publishCalls int
	statusCalls  int
	promoteCalls int
	request      PublicationRequest
}

func (stub *publicationDomainStub) Publish(_ context.Context, request PublicationRequest) (PublicationStatus, error) {
	stub.publishCalls++
	stub.request = request
	return stub.result, nil
}

func (stub *publicationDomainStub) Status(_ context.Context, request PublicationRequest) (PublicationStatus, error) {
	stub.statusCalls++
	stub.request = request
	return stub.result, nil
}

func (stub *publicationDomainStub) Promote(_ context.Context, request PublicationRequest) (PublicationStatus, error) {
	stub.promoteCalls++
	stub.request = request
	return stub.result, nil
}

func TestPublicationHandlerUsesAuthenticatedCASCommandsAndSideEffectFreeStatus(t *testing.T) {
	tenantScopeID, policyID, rolloutID := uuid.New(), uuid.New(), uuid.New()
	domain := &publicationDomainStub{result: testPublicationStatus(policyID, rolloutID)}
	actor := Actor{UserID: uuid.New(), ScopeID: tenantScopeID, ScopeKind: "tenant",
		Permissions: []string{PermissionManage}, Credential: CredentialReference{Kind: CredentialKindSession, ID: uuid.New()}}
	handler, err := NewPublicationHandler(AuthenticatorFunc(func(*http.Request) (Actor, error) { return actor, nil }), domain)
	if err != nil {
		t.Fatal(err)
	}
	base := "/v1/tenant-scopes/" + tenantScopeID.String() + "/challenge-policies/" + policyID.String() + "/publications"

	publish := publicationRequest(t, http.MethodPost, base, true)
	publishResponse := httptest.NewRecorder()
	handler.ServeHTTP(publishResponse, publish)
	assertPublicationHTTPResponse(t, publishResponse, http.StatusAccepted, policyID, rolloutID)
	if domain.publishCalls != 1 || domain.request.Actor.UserID != actor.UserID || domain.request.ExpectedRevision != 7 ||
		domain.request.RolloutID != uuid.Nil || domain.request.Metadata.IdempotencyKey != "challenge-publication-test" {
		t.Fatalf("publish request = %+v calls=%d", domain.request, domain.publishCalls)
	}

	status := publicationRequest(t, http.MethodGet, base+"/"+rolloutID.String(), false)
	statusResponse := httptest.NewRecorder()
	handler.ServeHTTP(statusResponse, status)
	assertPublicationHTTPResponse(t, statusResponse, http.StatusOK, policyID, rolloutID)
	if domain.statusCalls != 1 || domain.request.RolloutID != rolloutID || domain.request.ExpectedRevision != 0 ||
		domain.request.Metadata.IdempotencyKey != "" {
		t.Fatalf("status request = %+v calls=%d", domain.request, domain.statusCalls)
	}

	promote := publicationRequest(t, http.MethodPost, base+"/"+rolloutID.String()+"/promote", true)
	promoteResponse := httptest.NewRecorder()
	handler.ServeHTTP(promoteResponse, promote)
	assertPublicationHTTPResponse(t, promoteResponse, http.StatusOK, policyID, rolloutID)
	if domain.promoteCalls != 1 || domain.request.RolloutID != rolloutID || domain.request.ExpectedRevision != 7 {
		t.Fatalf("promote request = %+v calls=%d", domain.request, domain.promoteCalls)
	}
}

func TestPublicationHandlerRejectsMalformedOrAmbiguousRequestsBeforeDomain(t *testing.T) {
	tenantScopeID, policyID, rolloutID := uuid.New(), uuid.New(), uuid.New()
	domain := &publicationDomainStub{result: testPublicationStatus(policyID, rolloutID)}
	handler, err := NewPublicationHandler(AuthenticatorFunc(func(*http.Request) (Actor, error) {
		return Actor{UserID: uuid.New(), ScopeID: tenantScopeID, ScopeKind: "tenant"}, nil
	}), domain)
	if err != nil {
		t.Fatal(err)
	}
	base := "/v1/tenant-scopes/" + tenantScopeID.String() + "/challenge-policies/" + policyID.String() + "/publications"
	cases := []*http.Request{
		publicationRequest(t, http.MethodGet, base+"/"+rolloutID.String()+"?unexpected=1", false),
		publicationRequest(t, http.MethodPost, base, false),
		publicationRequest(t, http.MethodGet, base+"/not-a-uuid", false),
		publicationRequest(t, http.MethodPost, base+"/"+rolloutID.String()+"/promote/", true),
	}
	cases[1].Header.Set("If-Match", `"7"`)
	cases[2].Header.Add("Authorization", "Bearer duplicate")
	for index, request := range cases {
		response := httptest.NewRecorder()
		handler.ServeHTTP(response, request)
		if response.Code < 400 {
			t.Fatalf("case %d status=%d body=%s", index, response.Code, response.Body.String())
		}
	}
	if domain.publishCalls != 0 || domain.statusCalls != 0 || domain.promoteCalls != 0 {
		t.Fatalf("invalid requests reached domain: publish=%d status=%d promote=%d",
			domain.publishCalls, domain.statusCalls, domain.promoteCalls)
	}
}

func publicationRequest(t *testing.T, method, target string, write bool) *http.Request {
	t.Helper()
	var body *bytes.Reader
	if write {
		body = bytes.NewReader([]byte("{}"))
	} else {
		body = bytes.NewReader(nil)
	}
	request := httptest.NewRequest(method, target, body)
	request.Header.Set("Authorization", "Bearer challenge-session")
	request.Header.Set("X-Request-ID", uuid.NewString())
	request.Header.Set("X-Trace-ID", uuid.NewString())
	if write {
		request.Header.Set("Content-Type", "application/json")
		request.Header.Set("Idempotency-Key", "challenge-publication-test")
		request.Header.Set("If-Match", `"7"`)
	}
	return request
}

func testPublicationStatus(policyID, rolloutID uuid.UUID) PublicationStatus {
	return PublicationStatus{PolicyID: policyID, PolicyRevision: 7, RolloutID: rolloutID,
		ConfigVersionID: uuid.New(), State: challengepublication.StateRunning,
		Reason: challengepublication.ReasonWaitingForNodes, Total: 2, Pending: 1, Healthy: 1}
}

func assertPublicationHTTPResponse(t *testing.T, response *httptest.ResponseRecorder, status int, policyID, rolloutID uuid.UUID) {
	t.Helper()
	if response.Code != status {
		t.Fatalf("status=%d want=%d body=%s", response.Code, status, response.Body.String())
	}
	var body PublicationStatus
	if err := json.Unmarshal(response.Body.Bytes(), &body); err != nil || body.PolicyID != policyID || body.RolloutID != rolloutID {
		t.Fatalf("response=%+v err=%v body=%s", body, err, response.Body.String())
	}
}
