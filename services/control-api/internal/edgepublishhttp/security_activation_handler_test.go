package edgepublishhttp

import (
	"bytes"
	"context"
	"encoding/json"
	"errors"
	"net/http"
	"net/http/httptest"
	"testing"
	"time"

	"github.com/cdnca/cdnca/services/control-api/internal/identity"
	"github.com/cdnca/cdnca/services/control-api/internal/securityactivation"
	"github.com/cdnca/cdnca/services/control-api/internal/securitypolicy"
	"github.com/google/uuid"
)

type fakeSecurityActivationDomain struct {
	statusResult securityactivation.StatusResult
	statusErr    error
	statusActor  securitypolicy.Actor
	statusSiteID uuid.UUID
	statusKind   string
	statusCalls  int
	startResult  securityactivation.StartResult
	startErr     error
	startActor   securitypolicy.Actor
	startInput   securityactivation.StartInput
	startCalls   int
	rebindKind   string
	rebindActor  securitypolicy.Actor
	siteScope    uuid.UUID
	rebindCalls  int
}

func (domain *fakeSecurityActivationDomain) SiteTenantScope(
	_ context.Context,
	actor securitypolicy.Actor,
	_ uuid.UUID,
) (uuid.UUID, error) {
	if actor.ScopeKind == AudiencePlatform {
		return domain.siteScope, nil
	}
	return actor.ScopeID, nil
}

func (domain *fakeSecurityActivationDomain) RebindStatus(
	_ context.Context,
	actor securitypolicy.Actor,
	policyKind string,
) (securityactivation.RebindStatus, error) {
	domain.rebindCalls++
	domain.rebindActor, domain.rebindKind = actor, policyKind
	return securityactivation.RebindStatus{PendingSites: 3, PackageDeniedSites: 2}, nil
}

func (domain *fakeSecurityActivationDomain) Status(
	_ context.Context,
	actor securitypolicy.Actor,
	siteID uuid.UUID,
	policyKind string,
) (securityactivation.StatusResult, error) {
	domain.statusCalls++
	domain.statusActor, domain.statusSiteID, domain.statusKind = actor, siteID, policyKind
	return domain.statusResult, domain.statusErr
}

func (domain *fakeSecurityActivationDomain) Start(
	_ context.Context,
	actor securitypolicy.Actor,
	input securityactivation.StartInput,
) (securityactivation.StartResult, error) {
	domain.startCalls++
	domain.startActor, domain.startInput = actor, input
	return domain.startResult, domain.startErr
}

func (domain *fakeSecurityActivationDomain) Get(
	context.Context,
	securitypolicy.Actor,
	uuid.UUID,
) (securityactivation.Candidate, error) {
	return securityactivation.Candidate{}, securityactivation.ErrNotFound
}

func (domain *fakeSecurityActivationDomain) Reconcile(
	context.Context,
	securitypolicy.Actor,
	securityactivation.ReconcileInput,
) (securityactivation.ReconcileResult, error) {
	return securityactivation.ReconcileResult{}, securityactivation.ErrConflict
}

func (domain *fakeSecurityActivationDomain) Rollback(
	context.Context,
	securitypolicy.Actor,
	securityactivation.RollbackInput,
) (securityactivation.StartResult, error) {
	return securityactivation.StartResult{}, securityactivation.ErrConflict
}

func TestSecurityActivationTenantRouteRequiresLivePermissionAndIdempotency(t *testing.T) {
	scopeID, userID := uuid.New(), uuid.New()
	candidate := securityactivation.Candidate{
		ID: uuid.New(), TenantScopeID: scopeID, SiteID: uuid.New(),
		Status: securityactivation.StatusClaimed,
	}
	domain := &fakeSecurityActivationDomain{
		startResult: securityactivation.StartResult{Candidate: candidate, Replayed: true},
	}
	permissions := []string{"security_policies.manage"}
	handler, err := NewSecurityActivationHandler(domain, func(request *http.Request) (AuthenticatedSession, error) {
		principal := identity.Principal{
			UserID: userID, ScopeID: scopeID, ScopeKind: AudienceTenant,
			Permissions: permissions,
		}
		return newAuthenticatedSession(principal, uuid.New(), "security-activation-token")
	}, nil)
	if err != nil {
		t.Fatal(err)
	}
	body := map[string]any{
		"site_id":                        candidate.SiteID,
		"policy_id":                      uuid.New(),
		"policy_version":                 9,
		"expected_binding_revision":      4,
		"expected_active_policy_version": 7,
		"target_node_ids":                []uuid.UUID{uuid.New(), uuid.New()},
		"canary_size":                    1,
		"expires_at":                     time.Now().UTC().Add(time.Hour).Format(time.RFC3339),
	}
	call := func(withMetadata bool) *httptest.ResponseRecorder {
		raw, marshalErr := json.Marshal(body)
		if marshalErr != nil {
			t.Fatal(marshalErr)
		}
		request := httptest.NewRequest(http.MethodPost,
			"/v1/site-publications/security-activations", bytes.NewReader(raw))
		request.Header.Set("Authorization", "Bearer security-activation-token")
		request.Header.Set("Content-Type", "application/json")
		if withMetadata {
			request.Header.Set("Idempotency-Key", "security-activation-start")
			request.Header.Set("X-Request-ID", uuid.NewString())
			request.Header.Set("Traceparent", testTraceparent())
		}
		response := httptest.NewRecorder()
		handler.ServeHTTP(response, request)
		return response
	}

	if response := call(false); response.Code != http.StatusBadRequest {
		t.Fatalf("missing idempotency status = %d, want 400", response.Code)
	}
	if domain.startCalls != 0 {
		t.Fatal("domain called without idempotency metadata")
	}
	permissions = nil
	if response := call(true); response.Code != http.StatusForbidden {
		t.Fatalf("revoked permission status = %d, want 403", response.Code)
	}
	if domain.startCalls != 0 {
		t.Fatal("domain called after permission revocation")
	}
	permissions = []string{"security_policies.manage"}
	response := call(true)
	if response.Code != http.StatusCreated || response.Header().Get("Idempotency-Replayed") != "true" {
		t.Fatalf("activation response = %d headers=%v body=%s", response.Code, response.Header(), response.Body.String())
	}
	if domain.startCalls != 1 || domain.startActor.ScopeID != scopeID ||
		domain.startInput.TenantScopeID != scopeID ||
		domain.startInput.IdempotencyKey != "security-activation-start" ||
		domain.startInput.ExpectedActivePolicyVersion != 7 {
		t.Fatalf("activation domain input = actor=%#v input=%#v", domain.startActor, domain.startInput)
	}
}

func TestSecurityActivationStatusUsesReadPermissionAndCanonicalQuery(t *testing.T) {
	scopeID, userID, siteID := uuid.New(), uuid.New(), uuid.New()
	operation := securityactivation.OperationActivation
	domain := &fakeSecurityActivationDomain{statusResult: securityactivation.StatusResult{
		Binding: &securityactivation.Binding{
			ID: uuid.New(), PolicyID: uuid.New(), BindingRevision: 4,
			ActivePolicyVersion: 2, LastClaimedPolicyVersion: 3,
		},
		LatestCandidate: &securityactivation.Candidate{ID: uuid.New(), SiteID: siteID},
		Operation:       &operation,
	}}
	permissions := []string{"security_policies.read"}
	handler, err := NewSecurityActivationHandler(domain, func(*http.Request) (AuthenticatedSession, error) {
		return newAuthenticatedSession(identity.Principal{
			UserID: userID, ScopeID: scopeID, ScopeKind: AudienceTenant, Permissions: permissions,
		}, uuid.New(), "security-activation-reader")
	}, nil)
	if err != nil {
		t.Fatal(err)
	}
	call := func(target string) *httptest.ResponseRecorder {
		request := httptest.NewRequest(http.MethodGet, target, nil)
		request.Header.Set("Authorization", "Bearer security-activation-reader")
		response := httptest.NewRecorder()
		handler.ServeHTTP(response, request)
		return response
	}
	target := "/v1/site-publications/security-activations?site_id=" + siteID.String() + "&policy_kind=waf"
	response := call(target)
	if response.Code != http.StatusOK || domain.statusCalls != 1 || domain.statusActor.ScopeID != scopeID ||
		domain.statusSiteID != siteID || domain.statusKind != securitypolicy.KindWAF {
		t.Fatalf("status response=%d calls=%d actor=%+v site=%s kind=%s body=%s",
			response.Code, domain.statusCalls, domain.statusActor, domain.statusSiteID, domain.statusKind, response.Body.String())
	}
	permissions = []string{"security_policies.manage"}
	if response := call(target); response.Code != http.StatusForbidden || domain.statusCalls != 1 {
		t.Fatalf("manage-only GET status=%d calls=%d", response.Code, domain.statusCalls)
	}
	permissions = []string{"security_policies.read"}
	for _, invalid := range []string{
		"/v1/site-publications/security-activations?site_id=not-a-uuid&policy_kind=waf",
		"/v1/site-publications/security-activations?site_id=" + siteID.String() + "&policy_kind=unknown",
		"/v1/site-publications/security-activations?site_id=" + siteID.String() + "&policy_kind=waf&extra=1",
	} {
		if response := call(invalid); response.Code != http.StatusBadRequest {
			t.Fatalf("invalid query %s status=%d body=%s", invalid, response.Code, response.Body.String())
		}
	}
}

func TestSecurityActivationRoutesRejectNeighborsAndMapStaleCAS(t *testing.T) {
	scopeID, userID := uuid.New(), uuid.New()
	domain := &fakeSecurityActivationDomain{}
	handler, err := NewSecurityActivationHandler(domain, func(*http.Request) (AuthenticatedSession, error) {
		return newAuthenticatedSession(identity.Principal{
			UserID: userID, ScopeID: scopeID, ScopeKind: AudienceTenant,
			Permissions: []string{"security_policies.manage"},
		}, uuid.New(), "security-activation-token")
	}, nil)
	if err != nil {
		t.Fatal(err)
	}
	candidateID := uuid.New()
	for _, path := range []string{
		"/v1/site-publications/security-activations-neighbor",
		"/v1/site-publications/security-activations/" + candidateID.String() + "/reconcile/neighbor",
		"/v1/site-publications/security-activations/" + candidateID.String() + "/rollback/neighbor",
	} {
		request := httptest.NewRequest(http.MethodGet, path, nil)
		request.Header.Set("Authorization", "Bearer security-activation-token")
		response := httptest.NewRecorder()
		handler.ServeHTTP(response, request)
		if response.Code != http.StatusNotFound {
			t.Fatalf("neighbor %s status = %d, want 404", path, response.Code)
		}
	}

	cas := securityactivation.PromotionCAS{
		TenantScopeID: scopeID, BindingID: uuid.New(), BindingRevision: 4,
		LastBundleID: uuid.New(), LastClaimedPolicyVersion: 9, ExpectedActivePolicyVersion: 7,
		CandidateSourceRevision: 12, CandidateConfigVersionID: uuid.New(),
		CandidateArtifactSHA256: [32]byte{1}, TargetSnapshotSHA256: [32]byte{2},
	}
	raw, err := json.Marshal(map[string]any{"promotion_cas": cas})
	if err != nil {
		t.Fatal(err)
	}
	request := httptest.NewRequest(http.MethodPost,
		"/v1/site-publications/security-activations/"+candidateID.String()+"/reconcile",
		bytes.NewReader(raw))
	request.Header.Set("Authorization", "Bearer security-activation-token")
	request.Header.Set("Content-Type", "application/json")
	request.Header.Set("Idempotency-Key", "security-reconcile")
	request.Header.Set("X-Request-ID", uuid.NewString())
	request.Header.Set("Traceparent", testTraceparent())
	response := httptest.NewRecorder()
	handler.ServeHTTP(response, request)
	if response.Code != http.StatusConflict {
		t.Fatalf("stale CAS status = %d body=%s", response.Code, response.Body.String())
	}
	if !errors.Is(domain.startErr, nil) {
		t.Fatal("unexpected fake state")
	}
}

// waf-rebind: the rules page reads, per policy kind, how many bound sites are
// behind and how many of them the package does not entitle, in the session's
// own tenant scope (the actor is the session's; no scope in the query).
func TestSecurityActivationRebindStatusRouteUsesSessionScope(t *testing.T) {
	scopeID, userID := uuid.New(), uuid.New()
	domain := &fakeSecurityActivationDomain{}
	handler, err := NewSecurityActivationHandler(domain, func(*http.Request) (AuthenticatedSession, error) {
		return newAuthenticatedSession(identity.Principal{
			UserID: userID, ScopeID: scopeID, ScopeKind: AudienceTenant,
			Permissions: []string{"security_policies.read"},
		}, uuid.New(), "security-activation-token")
	}, nil)
	if err != nil {
		t.Fatal(err)
	}
	call := func(path string) *httptest.ResponseRecorder {
		request := httptest.NewRequest(http.MethodGet, path, nil)
		request.Header.Set("Authorization", "Bearer security-activation-token")
		response := httptest.NewRecorder()
		handler.ServeHTTP(response, request)
		return response
	}
	response := call("/v1/site-publications/security-activations/rebind-status?policy_kind=cc")
	if response.Code != http.StatusOK {
		t.Fatalf("status=%d body=%s", response.Code, response.Body.String())
	}
	var body map[string]int
	if err := json.Unmarshal(response.Body.Bytes(), &body); err != nil {
		t.Fatal(err)
	}
	if body["pending_sites"] != 3 || body["package_denied_sites"] != 2 {
		t.Fatalf("body = %v", body)
	}
	if domain.rebindKind != "cc" || domain.rebindActor.ScopeID != scopeID || domain.rebindActor.UserID != userID {
		t.Fatalf("domain got kind=%q actor=%+v", domain.rebindKind, domain.rebindActor)
	}
	for _, invalid := range []string{
		"/v1/site-publications/security-activations/rebind-status",
		"/v1/site-publications/security-activations/rebind-status?policy_kind=acl",
		"/v1/site-publications/security-activations/rebind-status?policy_kind=waf&tenant_scope_id=" + uuid.NewString(),
	} {
		if response := call(invalid); response.Code != http.StatusBadRequest {
			t.Fatalf("invalid %s status=%d", invalid, response.Code)
		}
	}
}

// site-parity3b: a platform administrator (platform.admin or the permission
// itself) reads and starts a tenant site's activation; the start runs in the
// site's tenant scope, the actor stays the platform session's. Other scope
// kinds and a platform session without the permission are refused, and the
// tenant-wide rebind summary stays tenant only.
func TestSecurityActivationPlatformAdministratorActsInSiteTenantScope(t *testing.T) {
	platformScope, userID, siteID, tenantScope := uuid.New(), uuid.New(), uuid.New(), uuid.New()
	domain := &fakeSecurityActivationDomain{siteScope: tenantScope,
		startResult: securityactivation.StartResult{Candidate: securityactivation.Candidate{ID: uuid.New()}}}
	kind, permissions := AudiencePlatform, []string{"platform.admin"}
	handler, err := NewSecurityActivationHandler(domain, func(*http.Request) (AuthenticatedSession, error) {
		return newAuthenticatedSession(identity.Principal{
			UserID: userID, ScopeID: platformScope, ScopeKind: kind, Permissions: permissions,
		}, uuid.New(), "platform-token")
	}, nil)
	if err != nil {
		t.Fatal(err)
	}
	start := func() *httptest.ResponseRecorder {
		raw, _ := json.Marshal(map[string]any{
			"site_id": siteID, "policy_id": uuid.New(), "policy_version": 2,
			"expected_binding_revision": 1, "expected_active_policy_version": 1,
			"expires_at": time.Now().UTC().Add(10 * time.Minute).Format(time.RFC3339),
		})
		request := httptest.NewRequest(http.MethodPost, "/v1/site-publications/security-activations", bytes.NewReader(raw))
		request.Header.Set("Authorization", "Bearer platform-token")
		request.Header.Set("Content-Type", "application/json")
		request.Header.Set("Idempotency-Key", "platform-start")
		request.Header.Set("X-Request-ID", uuid.NewString())
		request.Header.Set("Traceparent", testTraceparent())
		response := httptest.NewRecorder()
		handler.ServeHTTP(response, request)
		return response
	}
	get := func(path string) *httptest.ResponseRecorder {
		request := httptest.NewRequest(http.MethodGet, path, nil)
		request.Header.Set("Authorization", "Bearer platform-token")
		response := httptest.NewRecorder()
		handler.ServeHTTP(response, request)
		return response
	}
	statusPath := "/v1/site-publications/security-activations?site_id=" + siteID.String() + "&policy_kind=cc"
	if response := get(statusPath); response.Code != http.StatusOK || domain.statusActor.ScopeID != platformScope ||
		domain.statusActor.ScopeKind != AudiencePlatform {
		t.Fatalf("platform status=%d actor=%+v body=%s", response.Code, domain.statusActor, response.Body)
	}
	if response := start(); response.Code != http.StatusCreated || domain.startInput.TenantScopeID != tenantScope ||
		domain.startActor.ScopeID != platformScope || domain.startActor.UserID != userID {
		t.Fatalf("platform start=%d input=%+v actor=%+v body=%s", response.Code, domain.startInput, domain.startActor, response.Body)
	}
	if response := get("/v1/site-publications/security-activations/rebind-status?policy_kind=waf"); response.Code != http.StatusForbidden || domain.rebindCalls != 0 {
		t.Fatalf("platform rebind status=%d calls=%d", response.Code, domain.rebindCalls)
	}
	permissions = []string{"sites.read"}
	if response := start(); response.Code != http.StatusForbidden || domain.startCalls != 1 {
		t.Fatalf("platform without permission start=%d calls=%d", response.Code, domain.startCalls)
	}
	kind, permissions = "node", []string{"platform.admin", "security_policies.manage"}
	if response := start(); response.Code != http.StatusForbidden || domain.startCalls != 1 {
		t.Fatalf("unknown scope kind start=%d calls=%d", response.Code, domain.startCalls)
	}
	// A tenant session with platform.admin in its list gains nothing.
	kind, permissions = AudienceTenant, []string{"platform.admin"}
	if response := start(); response.Code != http.StatusForbidden || domain.startCalls != 1 {
		t.Fatalf("tenant platform.admin start=%d calls=%d", response.Code, domain.startCalls)
	}
}
