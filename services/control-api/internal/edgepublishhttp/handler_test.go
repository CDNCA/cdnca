package edgepublishhttp

import (
	"bytes"
	"context"
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"log/slog"
	"net/http"
	"net/http/httptest"
	"slices"
	"strings"
	"sync"
	"testing"
	"time"

	agentv1 "github.com/cdnca/cdnca/proto/gen/go/agent/v1"
	"github.com/cdnca/cdnca/services/control-api/internal/edgedeployment"
	"github.com/cdnca/cdnca/services/control-api/internal/edgepublish"
	"github.com/cdnca/cdnca/services/control-api/internal/identity"
	"github.com/google/uuid"
)

var testClock = time.Date(2026, 7, 23, 8, 0, 0, 0, time.UTC)

func TestAuthenticatedSessionRedactsAllFormattingAndJSON(t *testing.T) {
	rawToken := "platform-manage-secret"
	session, err := newAuthenticatedSession(identity.Principal{
		UserID: uuid.New(), ScopeID: uuid.New(), ScopeKind: AudiencePlatform,
	}, uuid.New(), rawToken)
	if err != nil {
		t.Fatal(err)
	}
	encoded, err := json.Marshal(session)
	if err != nil {
		t.Fatal(err)
	}
	for _, output := range []string{
		fmt.Sprintf("%v", session), fmt.Sprintf("%+v", session), fmt.Sprintf("%#v", session),
		fmt.Sprintf("%s", session), fmt.Sprintf("%q", session), fmt.Sprintf("%x", session),
		fmt.Sprintf("%d", session), fmt.Sprintf("%p", session), session.String(), session.GoString(), string(encoded),
	} {
		if strings.Contains(output, rawToken) || strings.Contains(output, hex.EncodeToString([]byte(rawToken))) {
			t.Fatalf("authenticated session leaked token through %q", output)
		}
	}
}

func TestResponseViewsRejectOpenAPIOutOfBoundsBackendSnapshots(t *testing.T) {
	scopeID := testTenantScopeID()

	type rolloutMutation struct {
		name   string
		mutate func(*edgedeployment.RolloutSnapshot)
	}
	rolloutTests := []rolloutMutation{
		{name: "max attempts above ten", mutate: func(item *edgedeployment.RolloutSnapshot) {
			item.MaxAttempts = 11
		}},
		{name: "progress total above ten thousand", mutate: func(item *edgedeployment.RolloutSnapshot) {
			item.Progress = edgedeployment.RolloutProgress{Total: 10001, Succeeded: 10001}
		}},
	}
	progressFields := []struct {
		name string
		set  func(*edgedeployment.RolloutProgress, int)
	}{
		{name: "pending", set: func(progress *edgedeployment.RolloutProgress, value int) { progress.Pending = value }},
		{name: "running", set: func(progress *edgedeployment.RolloutProgress, value int) { progress.Running = value }},
		{name: "succeeded", set: func(progress *edgedeployment.RolloutProgress, value int) { progress.Succeeded = value }},
		{name: "failed", set: func(progress *edgedeployment.RolloutProgress, value int) { progress.Failed = value }},
		{name: "cancelled", set: func(progress *edgedeployment.RolloutProgress, value int) { progress.Cancelled = value }},
	}
	for _, field := range progressFields {
		field := field
		rolloutTests = append(rolloutTests,
			rolloutMutation{name: field.name + " below zero", mutate: func(item *edgedeployment.RolloutSnapshot) {
				item.Progress = edgedeployment.RolloutProgress{Total: 1}
				if field.name == "succeeded" {
					item.Progress.Pending = 2
				} else {
					item.Progress.Succeeded = 2
				}
				field.set(&item.Progress, -1)
			}},
			rolloutMutation{name: field.name + " above ten thousand", mutate: func(item *edgedeployment.RolloutSnapshot) {
				item.Progress = edgedeployment.RolloutProgress{Total: 10000}
				if field.name == "succeeded" {
					item.Progress.Pending = -1
				} else {
					item.Progress.Succeeded = -1
				}
				field.set(&item.Progress, 10001)
			}},
		)
	}
	for _, test := range rolloutTests {
		t.Run("rollout/"+test.name, func(t *testing.T) {
			item := testRollout(scopeID, edgedeployment.RolloutStateSucceeded)
			test.mutate(&item)
			if _, err := rolloutView(item, AudiencePlatform, false); !errors.Is(err, ErrInvalidResponse) {
				t.Fatalf("rolloutView error=%v want=%v", err, ErrInvalidResponse)
			}
		})
	}

	t.Run("deployment/max attempts above ten", func(t *testing.T) {
		item := testDeployment("failed")
		item.MaxAttempts = 11
		if _, err := deploymentView(item, AudiencePlatform); !errors.Is(err, ErrInvalidResponse) {
			t.Fatalf("deploymentView error=%v want=%v", err, ErrInvalidResponse)
		}
	})
}

type fakeDomain struct {
	mu sync.Mutex

	publishFn         func(context.Context, edgepublish.PublishRequest) (edgepublish.PublishResult, error)
	rollbackFn        func(context.Context, edgepublish.RollbackRequest) (edgepublish.RollbackResult, error)
	getPublicationFn  func(context.Context, edgepublish.Actor, uuid.UUID, uuid.UUID) (edgepublish.PublishResult, error)
	listPublicationFn func(context.Context, edgepublish.Actor, uuid.UUID, edgepublish.PublicationPageRequest) (edgepublish.PublicationPage, error)
	getRolloutFn      func(context.Context, edgedeployment.Actor, uuid.UUID, uuid.UUID) (edgedeployment.RolloutSnapshot, error)
	listRolloutFn     func(context.Context, edgedeployment.Actor, uuid.UUID, edgedeployment.RolloutPageRequest) (edgedeployment.RolloutPage, error)
	listDeploymentFn  func(context.Context, edgedeployment.Actor, uuid.UUID, uuid.UUID, edgedeployment.DeploymentPageRequest) (edgedeployment.DeploymentPage, error)
	cancelFn          func(context.Context, edgedeployment.RolloutCommandRequest) (edgedeployment.RolloutCommandResult, error)
	retryFn           func(context.Context, edgedeployment.RolloutCommandRequest) (edgedeployment.RolloutCommandResult, error)

	publishRequests        []edgepublish.PublishRequest
	rollbackRequests       []edgepublish.RollbackRequest
	publicationActors      []edgepublish.Actor
	publicationScopes      []uuid.UUID
	publicationPageRequest []edgepublish.PublicationPageRequest
	rolloutActors          []edgedeployment.Actor
	rolloutScopes          []uuid.UUID
	rolloutPageRequests    []edgedeployment.RolloutPageRequest
	deploymentPageRequests []edgedeployment.DeploymentPageRequest
	commandRequests        []edgedeployment.RolloutCommandRequest
}

var _ PublicationDomain = (*fakeDomain)(nil)
var _ RolloutDomain = (*fakeDomain)(nil)
var _ PublicationDomain = (*edgepublish.Service)(nil)
var _ RolloutDomain = (*edgedeployment.Store)(nil)

func (domain *fakeDomain) Publish(ctx context.Context, request edgepublish.PublishRequest) (edgepublish.PublishResult, error) {
	domain.mu.Lock()
	domain.publishRequests = append(domain.publishRequests, request)
	callback := domain.publishFn
	domain.mu.Unlock()
	if callback != nil {
		return callback(ctx, request)
	}
	return testPublication(request.ConfigurationScopeID), nil
}

func (domain *fakeDomain) Rollback(ctx context.Context, request edgepublish.RollbackRequest) (edgepublish.RollbackResult, error) {
	domain.mu.Lock()
	domain.rollbackRequests = append(domain.rollbackRequests, request)
	callback := domain.rollbackFn
	domain.mu.Unlock()
	if callback != nil {
		return callback(ctx, request)
	}
	targetKind := edgepublish.TargetKindExplicit
	if request.TargetSnapshot != nil {
		targetKind = edgepublish.TargetKindResolver
	}
	return edgepublish.RollbackResult{
		PublicationID: request.PublicationID, ConfigurationScopeID: request.ConfigurationScopeID,
		ConfigVersionID: uuid.New(), RolloutID: uuid.New(), NodeCount: len(request.NodeIDs),
		TargetKind: targetKind, TargetSnapshot: request.TargetSnapshot,
		TargetSnapshotSHA256: sha256.Sum256([]byte("rollback-target")), CreatedAt: testClock,
	}, nil
}

func (domain *fakeDomain) GetPublication(ctx context.Context, actor edgepublish.Actor, scopeID, publicationID uuid.UUID) (edgepublish.PublishResult, error) {
	domain.mu.Lock()
	domain.publicationActors = append(domain.publicationActors, actor)
	domain.publicationScopes = append(domain.publicationScopes, scopeID)
	callback := domain.getPublicationFn
	domain.mu.Unlock()
	if callback != nil {
		return callback(ctx, actor, scopeID, publicationID)
	}
	item := testPublication(scopeID)
	item.PublicationID = publicationID
	return item, nil
}

func (domain *fakeDomain) ListPublications(ctx context.Context, actor edgepublish.Actor, scopeID uuid.UUID, request edgepublish.PublicationPageRequest) (edgepublish.PublicationPage, error) {
	domain.mu.Lock()
	domain.publicationActors = append(domain.publicationActors, actor)
	domain.publicationScopes = append(domain.publicationScopes, scopeID)
	domain.publicationPageRequest = append(domain.publicationPageRequest, request)
	callback := domain.listPublicationFn
	domain.mu.Unlock()
	if callback != nil {
		return callback(ctx, actor, scopeID, request)
	}
	return edgepublish.PublicationPage{
		Items: []edgepublish.PublishResult{testPublication(scopeID)}, CurrentSourceRevision: 7,
	}, nil
}

func (domain *fakeDomain) GetRollout(ctx context.Context, actor edgedeployment.Actor, scopeID, rolloutID uuid.UUID) (edgedeployment.RolloutSnapshot, error) {
	domain.mu.Lock()
	domain.rolloutActors = append(domain.rolloutActors, actor)
	domain.rolloutScopes = append(domain.rolloutScopes, scopeID)
	callback := domain.getRolloutFn
	domain.mu.Unlock()
	if callback != nil {
		return callback(ctx, actor, scopeID, rolloutID)
	}
	item := testRollout(scopeID, edgedeployment.RolloutStateQueued)
	item.ID = rolloutID
	return item, nil
}

func (domain *fakeDomain) ListRollouts(ctx context.Context, actor edgedeployment.Actor, scopeID uuid.UUID, request edgedeployment.RolloutPageRequest) (edgedeployment.RolloutPage, error) {
	domain.mu.Lock()
	domain.rolloutActors = append(domain.rolloutActors, actor)
	domain.rolloutScopes = append(domain.rolloutScopes, scopeID)
	domain.rolloutPageRequests = append(domain.rolloutPageRequests, request)
	callback := domain.listRolloutFn
	domain.mu.Unlock()
	if callback != nil {
		return callback(ctx, actor, scopeID, request)
	}
	return edgedeployment.RolloutPage{Items: []edgedeployment.RolloutSnapshot{
		testRollout(scopeID, edgedeployment.RolloutStateQueued),
	}}, nil
}

func (domain *fakeDomain) ListDeployments(ctx context.Context, actor edgedeployment.Actor, scopeID, rolloutID uuid.UUID, request edgedeployment.DeploymentPageRequest) (edgedeployment.DeploymentPage, error) {
	domain.mu.Lock()
	domain.rolloutActors = append(domain.rolloutActors, actor)
	domain.rolloutScopes = append(domain.rolloutScopes, scopeID)
	domain.deploymentPageRequests = append(domain.deploymentPageRequests, request)
	callback := domain.listDeploymentFn
	domain.mu.Unlock()
	if callback != nil {
		return callback(ctx, actor, scopeID, rolloutID, request)
	}
	return edgedeployment.DeploymentPage{Items: []edgedeployment.DeploymentSnapshot{testDeployment("failed")}}, nil
}

func (domain *fakeDomain) CancelRollout(ctx context.Context, request edgedeployment.RolloutCommandRequest) (edgedeployment.RolloutCommandResult, error) {
	domain.mu.Lock()
	domain.commandRequests = append(domain.commandRequests, request)
	callback := domain.cancelFn
	domain.mu.Unlock()
	if callback != nil {
		return callback(ctx, request)
	}
	rollout := testRollout(request.ConfigurationScopeID, edgedeployment.RolloutStateCancelled)
	rollout.ID = request.RolloutID
	return edgedeployment.RolloutCommandResult{Rollout: rollout}, nil
}

func (domain *fakeDomain) StartRollout(ctx context.Context, request edgedeployment.RolloutCommandRequest) (edgedeployment.RolloutCommandResult, error) {
	rollout := testRollout(request.ConfigurationScopeID, edgedeployment.RolloutStateRunning)
	rollout.ID, rollout.CanPause = request.RolloutID, true
	rollout.Policy = edgedeployment.RolloutPolicy{Strategy: edgedeployment.RolloutStrategyCanary,
		CanarySize: 1, BatchSize: 1, FailureThreshold: 1, CohortCount: 2}
	return edgedeployment.RolloutCommandResult{Rollout: rollout}, nil
}

func (domain *fakeDomain) PauseRollout(ctx context.Context, request edgedeployment.RolloutCommandRequest) (edgedeployment.RolloutCommandResult, error) {
	rollout := testRollout(request.ConfigurationScopeID, edgedeployment.RolloutStatePaused)
	rollout.ID, rollout.CanResume = request.RolloutID, true
	rollout.Policy = edgedeployment.RolloutPolicy{Strategy: edgedeployment.RolloutStrategyCanary,
		CanarySize: 1, BatchSize: 1, FailureThreshold: 1, CohortCount: 2}
	rollout.PauseReason = "operator"
	return edgedeployment.RolloutCommandResult{Rollout: rollout}, nil
}

func (domain *fakeDomain) ResumeRollout(ctx context.Context, request edgedeployment.RolloutCommandRequest) (edgedeployment.RolloutCommandResult, error) {
	return domain.StartRollout(ctx, request)
}

func (domain *fakeDomain) RetryRollout(ctx context.Context, request edgedeployment.RolloutCommandRequest) (edgedeployment.RolloutCommandResult, error) {
	domain.mu.Lock()
	domain.commandRequests = append(domain.commandRequests, request)
	callback := domain.retryFn
	domain.mu.Unlock()
	if callback != nil {
		return callback(ctx, request)
	}
	rollout := testRollout(request.ConfigurationScopeID, edgedeployment.RolloutStateRunning)
	rollout.ID = request.RolloutID
	return edgedeployment.RolloutCommandResult{Rollout: rollout}, nil
}

func (domain *fakeDomain) CancelRolloutSession(
	ctx context.Context,
	_ AuthenticatedSession,
	request edgedeployment.RolloutCommandRequest,
) (edgedeployment.RolloutCommandResult, error) {
	return domain.CancelRollout(ctx, request)
}

func (domain *fakeDomain) RetryRolloutSession(
	ctx context.Context,
	_ AuthenticatedSession,
	request edgedeployment.RolloutCommandRequest,
) (edgedeployment.RolloutCommandResult, error) {
	return domain.RetryRollout(ctx, request)
}

func TestHandlerAuthenticationRBACScopeAndTenantRedaction(t *testing.T) {
	domain := &fakeDomain{}
	handler := newTestHandler(t, domain)
	scopeID := testTenantScopeID()
	publicationID, rolloutID := uuid.New(), uuid.New()

	unauthenticated := performRequest(handler, http.MethodGet, "/v1/site-publications", "", nil, false)
	assertAPIError(t, unauthenticated, http.StatusUnauthorized, "authentication_required")

	platformDenied := performRequest(handler, http.MethodGet,
		"/v1/admin/site-publications?scope_id="+scopeID.String(), "platform-none", nil, false)
	assertAPIError(t, platformDenied, http.StatusForbidden, "permission_denied")

	tenantList := performRequest(handler, http.MethodGet, "/v1/site-publications", "tenant-read", nil, false)
	if tenantList.Code != http.StatusOK {
		t.Fatalf("tenant list status=%d body=%s", tenantList.Code, tenantList.Body.String())
	}
	assertJSONOmits(t, tenantList.Body.Bytes(), "configuration_scope_id", "canonical_source_sha256",
		"artifact_sha256", "snapshot_id", "resolver_sha256", "resolved_sha256")
	domain.mu.Lock()
	if len(domain.publicationActors) != 1 || domain.publicationActors[0].ScopeKind != AudienceTenant ||
		len(domain.publicationScopes) != 1 || domain.publicationScopes[0] != scopeID {
		t.Fatalf("tenant query actors=%+v scopes=%v", domain.publicationActors, domain.publicationScopes)
	}
	domain.mu.Unlock()

	override := performRequest(handler, http.MethodGet,
		"/v1/site-publications?scope_id="+uuid.NewString(), "tenant-read", nil, false)
	assertAPIError(t, override, http.StatusForbidden, "permission_denied")

	platformOnTenantRoute := performRequest(handler, http.MethodGet, "/v1/site-publications", "platform-read", nil, false)
	assertAPIError(t, platformOnTenantRoute, http.StatusForbidden, "permission_denied")

	tenantWrite := performRequest(handler, http.MethodPost, "/v1/admin/site-publications", "tenant-read",
		validPublishBody(scopeID, []uuid.UUID{uuid.New()}), true)
	assertAPIError(t, tenantWrite, http.StatusForbidden, "permission_denied")

	domain.getPublicationFn = func(_ context.Context, _ edgepublish.Actor, gotScope, gotID uuid.UUID) (edgepublish.PublishResult, error) {
		if gotScope != scopeID || gotID != publicationID {
			return edgepublish.PublishResult{}, edgepublish.ErrNotFound
		}
		item := testPublication(gotScope)
		item.PublicationID = gotID
		return item, nil
	}
	tenantDetail := performRequest(handler, http.MethodGet,
		"/v1/site-publications/"+publicationID.String(), "tenant-read", nil, false)
	if tenantDetail.Code != http.StatusOK {
		t.Fatalf("tenant detail status=%d body=%s", tenantDetail.Code, tenantDetail.Body.String())
	}
	foreign := performRequest(handler, http.MethodGet,
		"/v1/site-publications/"+uuid.NewString(), "tenant-read", nil, false)
	assertAPIError(t, foreign, http.StatusNotFound, "publication_resource_not_found")

	tenantDeployments := performRequest(handler, http.MethodGet,
		"/v1/site-rollouts/"+rolloutID.String()+"/deployments", "tenant-read", nil, false)
	if tenantDeployments.Code != http.StatusOK {
		t.Fatalf("tenant deployments status=%d body=%s", tenantDeployments.Code, tenantDeployments.Body.String())
	}
	assertJSONOmits(t, tenantDeployments.Body.Bytes(), "node_id")

	platformDetail := performRequest(handler, http.MethodGet,
		"/v1/admin/site-publications/"+publicationID.String()+"?scope_id="+scopeID.String(),
		"platform-read", nil, false)
	if platformDetail.Code != http.StatusOK {
		t.Fatalf("platform detail status=%d body=%s", platformDetail.Code, platformDetail.Body.String())
	}
	assertJSONHas(t, platformDetail.Body.Bytes(), "configuration_scope_id", "canonical_source_sha256",
		"artifact_sha256", "snapshot_id", "resolver_sha256", "resolved_sha256")
}

func TestPublishStrictValidationAndMetadata(t *testing.T) {
	domain := &fakeDomain{}
	handler := newTestHandler(t, domain)
	scopeID, firstNode, secondNode := testTenantScopeID(), uuid.New(), uuid.New()

	success := performRequest(handler, http.MethodPost, "/v1/admin/site-publications", "platform-manage",
		validPublishBody(scopeID, []uuid.UUID{secondNode, firstNode}), true)
	if success.Code != http.StatusCreated {
		t.Fatalf("publish status=%d body=%s", success.Code, success.Body.String())
	}
	if success.Header().Get("X-Request-ID") == "" || success.Header().Get("Cache-Control") != "no-store" {
		t.Fatalf("publish headers=%v", success.Header())
	}
	domain.mu.Lock()
	if len(domain.publishRequests) != 1 {
		t.Fatalf("publish calls=%d", len(domain.publishRequests))
	}
	captured := domain.publishRequests[0]
	domain.mu.Unlock()
	if captured.ConfigurationScopeID != scopeID || captured.ExpectedSourceRevision != 7 ||
		!slices.Equal(captured.NodeIDs, []uuid.UUID{secondNode, firstNode}) ||
		captured.IdempotencyKey != "publish-test" || captured.Traceparent != testTraceparent() ||
		captured.RequestID == "" || captured.CorrelationID == "" {
		t.Fatalf("captured publish=%+v", captured)
	}

	lineGroupBody := map[string]any{
		"configuration_scope_id": scopeID.String(), "expected_source_revision": 7,
		"target": map[string]any{
			"kind": TargetLineGroup, "snapshot_id": uuid.NewString(), "revision": 3,
			"resolver_sha256": fmt.Sprintf("%x", sha256.Sum256([]byte("line-group-snapshot"))),
		},
		"health_check": map[string]any{
			"activation_timeout_ms": 60000, "observation_window_ms": 5000,
			"required_consecutive_successes": 2,
		},
		"max_attempts": 3, "deadline": testClock.Add(time.Hour).Format(time.RFC3339),
	}
	lineGroup := performRequest(handler, http.MethodPost, "/v1/admin/site-publications", "platform-manage", lineGroupBody, true)
	if lineGroup.Code != http.StatusCreated {
		t.Fatalf("line group publish status=%d body=%s", lineGroup.Code, lineGroup.Body.String())
	}
	domain.mu.Lock()
	lineGroupRequest := domain.publishRequests[len(domain.publishRequests)-1]
	domain.mu.Unlock()
	if lineGroupRequest.TargetSnapshot == nil || len(lineGroupRequest.NodeIDs) != 0 || lineGroupRequest.TargetSnapshot.Revision != 3 {
		t.Fatalf("line group target=%+v nodes=%v", lineGroupRequest.TargetSnapshot, lineGroupRequest.NodeIDs)
	}

	invalidCases := []struct {
		name    string
		body    any
		headers func(*http.Request)
	}{
		{name: "zero revision", body: mutateBody(validPublishBody(scopeID, []uuid.UUID{uuid.New()}), "expected_source_revision", int64(0))},
		{name: "duplicate target", body: validPublishBody(scopeID, []uuid.UUID{firstNode, firstNode})},
		{name: "unknown target", body: mutateTarget(validPublishBody(scopeID, []uuid.UUID{firstNode}), "kind", "group")},
		{name: "invalid snapshot digest", body: mutateTarget(lineGroupBody, "resolver_sha256", "ABC")},
		{name: "unknown JSON field", body: mutateBody(validPublishBody(scopeID, []uuid.UUID{uuid.New()}), "unexpected", true)},
		{name: "invalid request ID", body: validPublishBody(scopeID, []uuid.UUID{uuid.New()}), headers: func(request *http.Request) {
			request.Header.Set("X-Request-ID", "not-a-uuid")
		}},
		{name: "invalid traceparent", body: validPublishBody(scopeID, []uuid.UUID{uuid.New()}), headers: func(request *http.Request) {
			request.Header.Set("Traceparent", "00-00000000000000000000000000000000-0000000000000000-01")
		}},
	}
	for _, test := range invalidCases {
		t.Run(test.name, func(t *testing.T) {
			request := newRequest(t, http.MethodPost, "/v1/admin/site-publications", "platform-manage", test.body, true)
			if test.headers != nil {
				test.headers(request)
			}
			response := httptest.NewRecorder()
			handler.ServeHTTP(response, request)
			assertAPIError(t, response, http.StatusBadRequest, "validation_error")
		})
	}

	invalidCursor := performRequest(handler, http.MethodGet,
		"/v1/admin/site-publications?scope_id="+scopeID.String()+"&cursor=%25", "platform-read", nil, false)
	assertAPIError(t, invalidCursor, http.StatusBadRequest, "validation_error")
	repeatedLimit := performRequest(handler, http.MethodGet,
		"/v1/admin/site-publications?scope_id="+scopeID.String()+"&limit=1&limit=2", "platform-read", nil, false)
	assertAPIError(t, repeatedLimit, http.StatusBadRequest, "validation_error")
}

func TestTenantPublicationWriteIsScopeBoundAndCannotReachPlatformRoute(t *testing.T) {
	domain := &fakeDomain{}
	handler := newTestHandler(t, domain)
	scopeID := testTenantScopeID()
	body := validPublishBody(scopeID, []uuid.UUID{uuid.New()})

	success := performRequest(handler, http.MethodPost, "/v1/site-publications", "tenant-manage", body, true)
	if success.Code != http.StatusCreated {
		t.Fatalf("tenant publish status=%d body=%s", success.Code, success.Body.String())
	}
	domain.mu.Lock()
	if len(domain.publishRequests) != 1 || domain.publishRequests[0].ConfigurationScopeID != scopeID ||
		domain.publishRequests[0].Actor.ScopeKind != AudienceTenant {
		domain.mu.Unlock()
		t.Fatalf("tenant publish requests=%+v", domain.publishRequests)
	}
	domain.publishRequests = nil
	domain.mu.Unlock()

	tests := []struct {
		name, token, path string
		body              map[string]any
	}{
		{name: "missing sites manage", token: "tenant-read", path: "/v1/site-publications", body: body},
		{name: "cross scope", token: "tenant-manage", path: "/v1/site-publications",
			body: validPublishBody(uuid.New(), []uuid.UUID{uuid.New()})},
		{name: "platform route", token: "tenant-manage", path: "/v1/admin/site-publications", body: body},
	}
	for _, test := range tests {
		t.Run(test.name, func(t *testing.T) {
			response := performRequest(handler, http.MethodPost, test.path, test.token, test.body, true)
			assertAPIError(t, response, http.StatusForbidden, "permission_denied")
			domain.mu.Lock()
			defer domain.mu.Unlock()
			if len(domain.publishRequests) != 0 {
				t.Fatalf("denied request reached publisher: %+v", domain.publishRequests)
			}
		})
	}
}

func TestPublicationRollbackStrictValidationAndMetadata(t *testing.T) {
	domain := &fakeDomain{}
	handler := newTestHandler(t, domain)
	scopeID, publicationID, firstNode, secondNode := testTenantScopeID(), uuid.New(), uuid.New(), uuid.New()
	body := validRollbackBody(scopeID, []uuid.UUID{secondNode, firstNode})

	success := performRequest(handler, http.MethodPost,
		"/v1/admin/site-publications/"+publicationID.String()+"/rollback",
		"platform-manage", body, true)
	if success.Code != http.StatusCreated {
		t.Fatalf("rollback status=%d body=%s", success.Code, success.Body.String())
	}
	domain.mu.Lock()
	if len(domain.rollbackRequests) != 1 {
		t.Fatalf("rollback calls=%d", len(domain.rollbackRequests))
	}
	captured := domain.rollbackRequests[0]
	domain.mu.Unlock()
	if captured.ConfigurationScopeID != scopeID || captured.PublicationID != publicationID ||
		!slices.Equal(captured.NodeIDs, []uuid.UUID{secondNode, firstNode}) ||
		captured.IdempotencyKey != "publish-test" || captured.Traceparent != testTraceparent() ||
		captured.RequestID == "" || captured.CorrelationID == "" {
		t.Fatalf("captured rollback=%+v", captured)
	}

	denied := performRequest(handler, http.MethodPost,
		"/v1/admin/site-publications/"+publicationID.String()+"/rollback",
		"platform-read", body, true)
	assertAPIError(t, denied, http.StatusForbidden, "permission_denied")

	invalidCases := []struct {
		name string
		path string
		body any
	}{
		{name: "invalid publication id", path: "/v1/admin/site-publications/not-a-uuid/rollback", body: body},
		{name: "duplicate target", path: "/v1/admin/site-publications/" + publicationID.String() + "/rollback",
			body: validRollbackBody(scopeID, []uuid.UUID{firstNode, firstNode})},
		{name: "unknown JSON field", path: "/v1/admin/site-publications/" + publicationID.String() + "/rollback",
			body: mutateBody(validRollbackBody(scopeID, []uuid.UUID{firstNode}), "unexpected", true)},
	}
	for _, test := range invalidCases {
		t.Run(test.name, func(t *testing.T) {
			response := performRequest(handler, http.MethodPost, test.path, "platform-manage", test.body, true)
			assertAPIError(t, response, http.StatusBadRequest, "validation_error")
		})
	}
}

func TestRequestAndDomainResponseSizeLimits(t *testing.T) {
	domain := &fakeDomain{}
	handler := newTestHandler(t, domain)
	scopeID := testTenantScopeID()
	payload, err := json.Marshal(validPublishBody(scopeID, []uuid.UUID{uuid.New()}))
	if err != nil {
		t.Fatal(err)
	}
	request := httptest.NewRequest(http.MethodPost, "/v1/admin/site-publications",
		bytes.NewReader(append(payload, bytes.Repeat([]byte(" "), maxRequestBytes+1)...)))
	request.Header.Set("Authorization", "Bearer platform-manage")
	request.Header.Set("Content-Type", "application/json")
	request.Header.Set("Idempotency-Key", "oversized-request")
	request.Header.Set("X-Request-ID", uuid.NewString())
	request.Header.Set("Traceparent", testTraceparent())
	response := httptest.NewRecorder()
	handler.ServeHTTP(response, request)
	assertAPIError(t, response, http.StatusBadRequest, "validation_error")

	domain.listPublicationFn = func(context.Context, edgepublish.Actor, uuid.UUID, edgepublish.PublicationPageRequest) (edgepublish.PublicationPage, error) {
		return edgepublish.PublicationPage{
			NextCursor: string(bytes.Repeat([]byte("a"), maxCursorBytes+1)), CurrentSourceRevision: 7,
		}, nil
	}
	invalidDomainResponse := performRequest(handler, http.MethodGet,
		"/v1/admin/site-publications?scope_id="+scopeID.String(), "platform-read", nil, false)
	assertAPIError(t, invalidDomainResponse, http.StatusServiceUnavailable, "publication_service_unavailable")
}

func TestPublishErrorMappingEntitlementAuditStorageAndCancellation(t *testing.T) {
	scopeID := testTenantScopeID()
	cases := []struct {
		name   string
		err    error
		status int
		code   string
	}{
		{name: "session revoked", err: edgepublish.ErrUnauthenticated, status: 401, code: "authentication_required"},
		{name: "deployment session revoked", err: edgedeployment.ErrUnauthenticated, status: 401, code: "authentication_required"},
		{name: "entitlement denied", err: edgepublish.ErrEntitlementDenied, status: 422, code: "publication_not_allowed"},
		{name: "entitlement grace", err: fmt.Errorf("grace: %w", edgepublish.ErrEntitlementDenied), status: 422, code: "publication_not_allowed"},
		{name: "entitlement quota", err: fmt.Errorf("quota: %w", edgepublish.ErrEntitlementDenied), status: 422, code: "publication_not_allowed"},
		{name: "source revision", err: edgepublish.ErrRevisionConflict, status: 412, code: "revision_conflict"},
		{name: "target snapshot", err: edgepublish.ErrTargetSnapshotConflict, status: 409, code: "target_snapshot_conflict"},
		{name: "target ineligible", err: edgepublish.ErrTargetIneligible, status: 422, code: "publication_not_ready"},
		{name: "idempotency", err: edgepublish.ErrIdempotencyConflict, status: 409, code: "idempotency_conflict"},
		{name: "audit rollback", err: errors.New("audit append failed"), status: 503, code: "publication_service_unavailable"},
		{name: "storage unavailable", err: edgepublish.ErrPersistence, status: 503, code: "publication_service_unavailable"},
	}
	for _, test := range cases {
		t.Run(test.name, func(t *testing.T) {
			domain := &fakeDomain{publishFn: func(context.Context, edgepublish.PublishRequest) (edgepublish.PublishResult, error) {
				return edgepublish.PublishResult{}, test.err
			}}
			handler := newTestHandler(t, domain)
			response := performRequest(handler, http.MethodPost, "/v1/admin/site-publications", "platform-manage",
				validPublishBody(scopeID, []uuid.UUID{uuid.New()}), true)
			assertAPIError(t, response, test.status, test.code)
			if bytes.Contains(response.Body.Bytes(), []byte(test.err.Error())) {
				t.Fatalf("internal error leaked in %s", response.Body.String())
			}
		})
	}

	domain := &fakeDomain{publishFn: func(ctx context.Context, _ edgepublish.PublishRequest) (edgepublish.PublishResult, error) {
		<-ctx.Done()
		return edgepublish.PublishResult{}, ctx.Err()
	}}
	handler := newTestHandler(t, domain)
	request := newRequest(t, http.MethodPost, "/v1/admin/site-publications", "platform-manage",
		validPublishBody(scopeID, []uuid.UUID{uuid.New()}), true)
	ctx, cancel := context.WithCancel(request.Context())
	cancel()
	request = request.WithContext(ctx)
	response := httptest.NewRecorder()
	handler.ServeHTTP(response, request)
	assertAPIError(t, response, http.StatusServiceUnavailable, "publication_service_unavailable")
}

func TestRolloutDeadlineExpiredMapsToConflict(t *testing.T) {
	status, code, message := classifyError(edgedeployment.ErrDeadlineExpired)
	if status != http.StatusConflict || code != "publication_deadline_expired" ||
		message != "the rollout deadline has expired" {
		t.Fatalf("deadline mapping=(%d,%q,%q)", status, code, message)
	}
}

func TestMissingChallengePolicyMapsToNamedRefusal(t *testing.T) {
	refusal := &edgepublish.ChallengePolicyUnavailableError{NodeID: uuid.New(), SiteID: uuid.NewString(),
		Domain: "www.example.com", PolicyID: uuid.NewString(), PolicyVersion: 2}
	status, code, message := classifyError(fmt.Errorf("publish: %w", refusal))
	if status != http.StatusUnprocessableEntity || code != "challenge_policy_unavailable" || message != refusal.Error() ||
		!strings.Contains(message, refusal.NodeID.String()) || !strings.Contains(message, "www.example.com") {
		t.Fatalf("challenge mapping=(%d,%q,%q)", status, code, message)
	}
	other := uuid.New()
	refusal.OtherNodeIDs = []uuid.UUID{other}
	details := challengeDetails(fmt.Errorf("publish: %w", refusal))
	if details == nil || details.NodeID != refusal.NodeID.String() || details.SiteID != refusal.SiteID ||
		details.Domain != "www.example.com" || details.PolicyVersion != 2 || len(details.OtherNodeIDs) != 1 ||
		details.OtherNodeIDs[0] != other.String() || challengeDetails(edgepublish.ErrTargetIneligible) != nil {
		t.Fatalf("challenge details = %+v", details)
	}
}

// A capability refusal names its nodes in a structured field: the page must
// not read the free-text message (the web client discards server text).
func TestCapabilityRefusalBodyNamesNodes(t *testing.T) {
	node, other := uuid.New(), uuid.New()
	refusal := &edgepublish.TargetCapabilityError{NodeID: node, AgentVersion: "1.0.35",
		Feature: "CC rules counting by network, host, URI or TLS fingerprint", Capability: agentv1.CapabilityName_CAPABILITY_NAME_CC,
		Required: 4, Advertised: 3, OtherNodeIDs: []uuid.UUID{other}, AutoResume: true}
	response := httptest.NewRecorder()
	response.Header().Set("X-Request-ID", uuid.NewString())
	(&Handler{}).writeError(response, httptest.NewRequest(http.MethodPost, "/v1/site-publications/security-activations", nil),
		fmt.Errorf("publish: %w", refusal))
	assertAPIError(t, response, http.StatusUnprocessableEntity, "node_capability_unavailable")
	var body struct {
		Error struct {
			Capability *struct {
				NodeID          string   `json:"node_id"`
				Capability      string   `json:"capability"`
				RequiredVersion uint32   `json:"required_version"`
				OtherNodeIDs    []string `json:"other_node_ids"`
			} `json:"capability"`
		} `json:"error"`
	}
	if err := json.Unmarshal(response.Body.Bytes(), &body); err != nil {
		t.Fatal(err)
	}
	got := body.Error.Capability
	if got == nil || got.NodeID != node.String() || got.Capability != "CAPABILITY_NAME_CC" || got.RequiredVersion != 4 ||
		len(got.OtherNodeIDs) != 1 || got.OtherNodeIDs[0] != other.String() {
		t.Fatalf("capability details = %+v body=%s", got, response.Body.String())
	}
	if capabilityDetails(edgepublish.ErrTargetIneligible) != nil {
		t.Fatal("details without a capability refusal")
	}
	refusal.OtherNodeIDs = nil
	if details := capabilityDetails(refusal); details == nil || details.OtherNodeIDs == nil || len(details.OtherNodeIDs) != 0 {
		t.Fatalf("other_node_ids must be an empty list, got %+v", details)
	}
}

func TestRuntimeCanaryRetryRequiresRetryableDeployment(t *testing.T) {
	result := edgedeployment.RolloutSnapshot{
		Action: "apply", Policy: edgedeployment.RolloutPolicy{Strategy: edgedeployment.RolloutStrategyCanary},
		ReleasedCohort: 0,
	}
	deployments := []edgedeployment.DeploymentSnapshot{{
		State: "failed", Cohort: 0, Attempt: 1, MaxAttempts: 2,
	}}
	applyRuntimeRolloutAggregate(&result, "paused", deployments)
	if result.CanRetry {
		t.Fatalf("expired deployment produced retryable rollout: %+v", result)
	}
	result = edgedeployment.RolloutSnapshot{
		Action: "apply", Policy: edgedeployment.RolloutPolicy{Strategy: edgedeployment.RolloutStrategyCanary},
		ReleasedCohort: 0,
	}
	deployments[0].CanRetry = true
	applyRuntimeRolloutAggregate(&result, "paused", deployments)
	if !result.CanRetry {
		t.Fatalf("eligible deployment did not produce retryable rollout: %+v", result)
	}
}

func TestWriteMetadataRejectsDuplicateHeaders(t *testing.T) {
	for _, name := range []string{
		"Idempotency-Key", "X-Request-ID", "X-Correlation-ID", "Traceparent", "X-Task-ID", "Content-Type",
	} {
		t.Run(name, func(t *testing.T) {
			handler := newTestHandler(t, &fakeDomain{})
			request := newRequest(t, http.MethodPost, "/v1/admin/site-publications", "platform-manage",
				validPublishBody(testTenantScopeID(), []uuid.UUID{uuid.New()}), true)
			request.Header.Add(name, request.Header.Get(name))
			response := httptest.NewRecorder()
			handler.ServeHTTP(response, request)
			assertAPIError(t, response, http.StatusBadRequest, "validation_error")
		})
	}
}

func TestWriteMetadataEnforcesIdempotencyKeyBoundary(t *testing.T) {
	request := newRequest(t, http.MethodPost, "/v1/admin/site-publications", "platform-manage",
		validPublishBody(testTenantScopeID(), []uuid.UUID{uuid.New()}), true)
	request.Header.Set("Idempotency-Key", "a")
	if _, err := parseWriteMetadata(request); err != nil {
		t.Fatalf("1-byte Idempotency-Key rejected: %v", err)
	}
	request.Header.Set("Idempotency-Key", strings.Repeat("a", 128))
	if _, err := parseWriteMetadata(request); err != nil {
		t.Fatalf("128-byte Idempotency-Key rejected: %v", err)
	}
	request.Header.Set("Idempotency-Key", "\xc3\xa9")
	if _, err := parseWriteMetadata(request); !errors.Is(err, ErrInvalidRequest) {
		t.Fatalf("non-ASCII Idempotency-Key error = %v", err)
	}
	request.Header.Set("Idempotency-Key", strings.Repeat("a", 129))
	if _, err := parseWriteMetadata(request); !errors.Is(err, ErrInvalidRequest) {
		t.Fatalf("129-byte Idempotency-Key error = %v", err)
	}
}

func TestWriteMetadataRejectsExplicitEmptyHeaders(t *testing.T) {
	for _, name := range []string{
		"Idempotency-Key", "X-Request-ID", "X-Correlation-ID", "Traceparent", "X-Task-ID", "Content-Type",
	} {
		t.Run(name, func(t *testing.T) {
			handler := newTestHandler(t, &fakeDomain{})
			request := newRequest(t, http.MethodPost, "/v1/admin/site-publications", "platform-manage",
				validPublishBody(testTenantScopeID(), []uuid.UUID{uuid.New()}), true)
			request.Header.Set(name, "")
			response := httptest.NewRecorder()
			handler.ServeHTTP(response, request)
			assertAPIError(t, response, http.StatusBadRequest, "validation_error")
		})
	}
}

func TestPublishIdempotencyReplayPayloadConflictAndConcurrentCAS(t *testing.T) {
	scopeID, firstNode, secondNode := testTenantScopeID(), uuid.New(), uuid.New()
	type record struct {
		digest [32]byte
		result edgepublish.PublishResult
	}
	var mutex sync.Mutex
	records := map[string]record{}
	publishedRevision := false
	domain := &fakeDomain{}
	domain.publishFn = func(_ context.Context, request edgepublish.PublishRequest) (edgepublish.PublishResult, error) {
		encoded, _ := json.Marshal(struct {
			Revision int64
			Nodes    []uuid.UUID
			Deadline string
		}{request.ExpectedSourceRevision, request.NodeIDs, request.Deadline.UTC().Format(time.RFC3339Nano)})
		digest := sha256.Sum256(encoded)
		mutex.Lock()
		defer mutex.Unlock()
		if existing, found := records[request.IdempotencyKey]; found {
			if existing.digest != digest {
				return edgepublish.PublishResult{}, edgepublish.ErrIdempotencyConflict
			}
			result := existing.result
			result.Replayed = true
			return result, nil
		}
		if publishedRevision {
			return edgepublish.PublishResult{}, edgepublish.ErrRevisionConflict
		}
		publishedRevision = true
		result := testPublication(request.ConfigurationScopeID)
		records[request.IdempotencyKey] = record{digest: digest, result: result}
		return result, nil
	}
	handler := newTestHandler(t, domain)
	body := validPublishBody(scopeID, []uuid.UUID{firstNode})
	first := performRequest(handler, http.MethodPost, "/v1/admin/site-publications", "platform-manage", body, true)
	if first.Code != http.StatusCreated || first.Header().Get("Idempotency-Replayed") != "" {
		t.Fatalf("first publish status=%d headers=%v body=%s", first.Code, first.Header(), first.Body.String())
	}
	replay := performRequest(handler, http.MethodPost, "/v1/admin/site-publications", "platform-manage", body, true)
	if replay.Code != http.StatusCreated || replay.Header().Get("Idempotency-Replayed") != "true" {
		t.Fatalf("replay status=%d headers=%v body=%s", replay.Code, replay.Header(), replay.Body.String())
	}
	changed := validPublishBody(scopeID, []uuid.UUID{secondNode})
	conflict := performRequest(handler, http.MethodPost, "/v1/admin/site-publications", "platform-manage", changed, true)
	assertAPIError(t, conflict, http.StatusConflict, "idempotency_conflict")

	mutex.Lock()
	records = map[string]record{}
	publishedRevision = false
	mutex.Unlock()
	statuses := make(chan int, 2)
	start := make(chan struct{})
	for _, key := range []string{"publish-a", "publish-b"} {
		go func(key string) {
			<-start
			request := newRequest(t, http.MethodPost, "/v1/admin/site-publications", "platform-manage", body, true)
			request.Header.Set("Idempotency-Key", key)
			response := httptest.NewRecorder()
			handler.ServeHTTP(response, request)
			statuses <- response.Code
		}(key)
	}
	close(start)
	got := []int{<-statuses, <-statuses}
	slices.Sort(got)
	if !slices.Equal(got, []int{http.StatusCreated, http.StatusPreconditionFailed}) {
		t.Fatalf("concurrent publish statuses=%v", got)
	}
}

func TestRolloutReadPartialFailureAndCommandsBlocked(t *testing.T) {
	domain := &fakeDomain{}
	handler := newTestHandler(t, domain)
	scopeID, rolloutID := testTenantScopeID(), uuid.New()

	domain.getRolloutFn = func(_ context.Context, _ edgedeployment.Actor, _ uuid.UUID, rolloutID uuid.UUID) (edgedeployment.RolloutSnapshot, error) {
		result := testRollout(scopeID, edgedeployment.RolloutStatePartialFailed)
		result.ID = rolloutID
		return result, nil
	}
	partial := performRequest(handler, http.MethodGet,
		"/v1/admin/site-rollouts/"+rolloutID.String()+"?scope_id="+scopeID.String(), "platform-read", nil, false)
	if partial.Code != http.StatusOK || !bytes.Contains(partial.Body.Bytes(), []byte(`"state":"partial_failed"`)) ||
		!bytes.Contains(partial.Body.Bytes(), []byte(`"succeeded":1`)) || !bytes.Contains(partial.Body.Bytes(), []byte(`"failed":1`)) {
		t.Fatalf("partial rollout status=%d body=%s", partial.Code, partial.Body.String())
	}

	commandBody := map[string]any{"configuration_scope_id": scopeID.String(), "expected_revision": 4}
	for _, suffix := range []string{"cancel", "retry-failed"} {
		response := performRequest(handler, http.MethodPost,
			"/v1/admin/site-rollouts/"+rolloutID.String()+"/"+suffix,
			"platform-manage", commandBody, true)
		assertAPIError(t, response, http.StatusServiceUnavailable, "publication_service_unavailable")
	}
}

func TestRuntimeRolloutCommandsUseAuthenticatedSessionAndWriteMetadata(t *testing.T) {
	domain := &fakeDomain{}
	service, err := newRuntimeService(domain, domain, domain, newTestCursorCodec(t))
	if err != nil {
		t.Fatal(err)
	}
	handler, err := newSessionHandler(service, testAuthenticateSession,
		slog.New(slog.NewTextHandler(io.Discard, nil)))
	if err != nil {
		t.Fatal(err)
	}
	scopeID, rolloutID := testTenantScopeID(), uuid.New()
	body := map[string]any{
		"configuration_scope_id": scopeID.String(),
		"expected_revision":      int64(4),
	}
	for _, command := range []struct {
		suffix string
		key    string
	}{
		{suffix: "cancel", key: "runtime-cancel"},
		{suffix: "retry-failed", key: "runtime-retry"},
	} {
		request := newRequest(t, http.MethodPost,
			"/v1/admin/site-rollouts/"+rolloutID.String()+"/"+command.suffix,
			"platform-manage", body, true)
		request.Header.Set("Idempotency-Key", command.key)
		request.Header.Set("X-Task-ID", "runtime-command")
		request.Header.Set("X-Actor-User-ID", uuid.NewString())
		response := httptest.NewRecorder()
		handler.ServeHTTP(response, request)
		if response.Code != http.StatusOK {
			t.Fatalf("%s status=%d body=%s", command.suffix, response.Code, response.Body)
		}
	}

	domain.mu.Lock()
	defer domain.mu.Unlock()
	if len(domain.commandRequests) != 2 {
		t.Fatalf("command requests=%d, want 2", len(domain.commandRequests))
	}
	for index, request := range domain.commandRequests {
		if request.Actor.UserID == uuid.Nil || request.Actor.ScopeID == uuid.Nil ||
			request.Actor.ScopeKind != AudiencePlatform || request.Actor.SessionID == uuid.Nil ||
			request.ConfigurationScopeID != scopeID || request.RolloutID != rolloutID ||
			request.ExpectedRevision != 4 || request.TaskID == nil || *request.TaskID != "runtime-command" ||
			request.Traceparent != testTraceparent() || request.RequestID == "" || request.CorrelationID == "" {
			t.Fatalf("command[%d]=%+v", index, request)
		}
		if got := fmt.Sprintf("%+v %#v", request.Actor, request.Actor); strings.Contains(got, "platform-manage") {
			t.Fatalf("actor leaked session: %s", got)
		}
	}
	if domain.commandRequests[0].IdempotencyKey != "runtime-cancel" ||
		domain.commandRequests[1].IdempotencyKey != "runtime-retry" {
		t.Fatalf("idempotency keys=%q/%q", domain.commandRequests[0].IdempotencyKey,
			domain.commandRequests[1].IdempotencyKey)
	}
}

func TestRolloutCommandsRejectCallerSuppliedStructuralCapability(t *testing.T) {
	domain := &fakeDomain{}
	handler := newTestHandler(t, domain)
	scopeID, rolloutID := testTenantScopeID(), uuid.New()
	body := map[string]any{
		"configuration_scope_id": scopeID.String(),
		"expected_revision":      int64(1),
	}
	for _, suffix := range []string{"cancel", "retry-failed"} {
		response := performRequest(handler, http.MethodPost,
			"/v1/admin/site-rollouts/"+rolloutID.String()+"/"+suffix,
			"platform-manage", body, true)
		assertAPIError(t, response, http.StatusServiceUnavailable, "publication_service_unavailable")
	}
	domain.mu.Lock()
	defer domain.mu.Unlock()
	if len(domain.commandRequests) != 0 {
		t.Fatalf("caller-supplied structural capability invoked %d commands", len(domain.commandRequests))
	}
}

func TestPlatformAPIKeyRejectedBeforeAuthenticationDependency(t *testing.T) {
	domain := &fakeDomain{}
	service, err := NewService(domain, domain, newTestCursorCodec(t))
	if err != nil {
		t.Fatal(err)
	}
	authenticationCalls := 0
	handler, err := newSessionHandler(service, func(*http.Request) (AuthenticatedSession, error) {
		authenticationCalls++
		return AuthenticatedSession{}, ErrUnauthenticated
	}, slog.New(slog.NewTextHandler(io.Discard, nil)))
	if err != nil {
		t.Fatal(err)
	}
	scopeID, resourceID := testTenantScopeID().String(), uuid.NewString()
	for _, route := range []struct{ method, target string }{
		{http.MethodGet, "/v1/admin/site-publications?scope_id=" + scopeID},
		{http.MethodPost, "/v1/admin/site-publications"},
		{http.MethodGet, "/v1/admin/site-publications/" + resourceID + "?scope_id=" + scopeID},
		{http.MethodGet, "/v1/admin/site-rollouts?scope_id=" + scopeID},
		{http.MethodGet, "/v1/admin/site-rollouts/" + resourceID + "?scope_id=" + scopeID},
		{http.MethodGet, "/v1/admin/site-rollouts/" + resourceID + "/deployments?scope_id=" + scopeID},
		{http.MethodPost, "/v1/admin/site-rollouts/" + resourceID + "/cancel"},
		{http.MethodPost, "/v1/admin/site-rollouts/" + resourceID + "/retry-failed"},
	} {
		request := httptest.NewRequest(route.method, route.target, nil)
		request.Header.Set("Authorization", "CdncaKey key.secret")
		response := httptest.NewRecorder()
		handler.ServeHTTP(response, request)
		assertAPIError(t, response, http.StatusUnauthorized, "authentication_required")
	}
	if authenticationCalls != 0 {
		t.Fatalf("platform API key reached authentication dependency %d times", authenticationCalls)
	}
}

func TestStablePaginationNoDuplicatesAndDomainResponseGuards(t *testing.T) {
	scopeID := testTenantScopeID()
	publicationIDs := []uuid.UUID{uuid.New(), uuid.New(), uuid.New()}
	domain := &fakeDomain{}
	domain.listPublicationFn = func(_ context.Context, _ edgepublish.Actor, gotScope uuid.UUID, request edgepublish.PublicationPageRequest) (edgepublish.PublicationPage, error) {
		if gotScope != scopeID || request.Limit != 2 {
			return edgepublish.PublicationPage{}, ErrInvalidRequest
		}
		if request.Cursor == "" {
			first, second := testPublication(scopeID), testPublication(scopeID)
			first.PublicationID, second.PublicationID = publicationIDs[0], publicationIDs[1]
			return edgepublish.PublicationPage{
				Items: []edgepublish.PublishResult{first, second}, NextCursor: "next_cursor", CurrentSourceRevision: 7,
			}, nil
		}
		if request.Cursor == "next_cursor" {
			last := testPublication(scopeID)
			last.PublicationID = publicationIDs[2]
			return edgepublish.PublicationPage{Items: []edgepublish.PublishResult{last}, CurrentSourceRevision: 7}, nil
		}
		return edgepublish.PublicationPage{}, edgepublish.ErrInvalidInput
	}
	handler := newTestHandler(t, domain)
	first := performRequest(handler, http.MethodGet,
		"/v1/admin/site-publications?scope_id="+scopeID.String()+"&limit=2", "platform-read", nil, false)
	var firstPage PublicationPageView
	if err := json.Unmarshal(first.Body.Bytes(), &firstPage); err != nil {
		t.Fatal(err)
	}
	second := performRequest(handler, http.MethodGet,
		"/v1/admin/site-publications?scope_id="+scopeID.String()+"&limit=2&cursor="+firstPage.NextCursor,
		"platform-read", nil, false)
	if first.Code != http.StatusOK || second.Code != http.StatusOK {
		t.Fatalf("pagination statuses=%d/%d bodies=%s / %s", first.Code, second.Code, first.Body.String(), second.Body.String())
	}
	seen := map[string]bool{}
	for _, response := range []*httptest.ResponseRecorder{first, second} {
		var page PublicationPageView
		if err := json.Unmarshal(response.Body.Bytes(), &page); err != nil {
			t.Fatal(err)
		}
		for _, item := range page.Items {
			if seen[item.ID.String()] {
				t.Fatalf("duplicate publication %s", item.ID)
			}
			seen[item.ID.String()] = true
		}
	}
	if len(seen) != len(publicationIDs) {
		t.Fatalf("seen publications=%v", seen)
	}

	domain.getRolloutFn = func(context.Context, edgedeployment.Actor, uuid.UUID, uuid.UUID) (edgedeployment.RolloutSnapshot, error) {
		item := testRollout(scopeID, "invented")
		return item, nil
	}
	unknownStatus := performRequest(handler, http.MethodGet,
		"/v1/admin/site-rollouts/"+uuid.NewString()+"?scope_id="+scopeID.String(), "platform-read", nil, false)
	assertAPIError(t, unknownStatus, http.StatusServiceUnavailable, "publication_service_unavailable")
}

func TestPublicationListReturnsCurrentSourceRevisionForEmptyPage(t *testing.T) {
	scopeID := testTenantScopeID()
	domain := &fakeDomain{}
	domain.listPublicationFn = func(
		context.Context,
		edgepublish.Actor,
		uuid.UUID,
		edgepublish.PublicationPageRequest,
	) (edgepublish.PublicationPage, error) {
		return edgepublish.PublicationPage{CurrentSourceRevision: 7}, nil
	}
	handler := newTestHandler(t, domain)
	response := performRequest(handler, http.MethodGet,
		"/v1/admin/site-publications?scope_id="+scopeID.String(), "platform-read", nil, false)
	if response.Code != http.StatusOK {
		t.Fatalf("empty publication page status=%d body=%s", response.Code, response.Body.String())
	}
	var payload map[string]json.RawMessage
	if err := json.Unmarshal(response.Body.Bytes(), &payload); err != nil {
		t.Fatal(err)
	}
	var revision int64
	if raw, ok := payload["current_source_revision"]; !ok || json.Unmarshal(raw, &revision) != nil || revision <= 0 {
		t.Fatalf("empty publication current_source_revision=%s", raw)
	}
}

func TestAuditFailureDoesNotExposeSuccessAndStorageUnavailableIs503(t *testing.T) {
	scopeID := testTenantScopeID()
	var committed bool
	domain := &fakeDomain{}
	domain.publishFn = func(context.Context, edgepublish.PublishRequest) (edgepublish.PublishResult, error) {
		return edgepublish.PublishResult{}, errors.New("forced audit failure before commit")
	}
	domain.listPublicationFn = func(context.Context, edgepublish.Actor, uuid.UUID, edgepublish.PublicationPageRequest) (edgepublish.PublicationPage, error) {
		if committed {
			return edgepublish.PublicationPage{
				Items: []edgepublish.PublishResult{testPublication(scopeID)}, CurrentSourceRevision: 7,
			}, nil
		}
		return edgepublish.PublicationPage{Items: []edgepublish.PublishResult{}, CurrentSourceRevision: 7}, nil
	}
	handler := newTestHandler(t, domain)
	failed := performRequest(handler, http.MethodPost, "/v1/admin/site-publications", "platform-manage",
		validPublishBody(scopeID, []uuid.UUID{uuid.New()}), true)
	assertAPIError(t, failed, http.StatusServiceUnavailable, "publication_service_unavailable")
	list := performRequest(handler, http.MethodGet,
		"/v1/admin/site-publications?scope_id="+scopeID.String(), "platform-read", nil, false)
	if list.Code != http.StatusOK || !bytes.Contains(list.Body.Bytes(), []byte(`"items":[]`)) {
		t.Fatalf("post-failure list status=%d body=%s", list.Code, list.Body.String())
	}

	domain.listPublicationFn = func(context.Context, edgepublish.Actor, uuid.UUID, edgepublish.PublicationPageRequest) (edgepublish.PublicationPage, error) {
		return edgepublish.PublicationPage{}, edgepublish.ErrPersistence
	}
	unavailable := performRequest(handler, http.MethodGet,
		"/v1/admin/site-publications?scope_id="+scopeID.String(), "platform-read", nil, false)
	assertAPIError(t, unavailable, http.StatusServiceUnavailable, "publication_service_unavailable")
}

func TestConstructorsRejectMissingPorts(t *testing.T) {
	domain := &fakeDomain{}
	cursors := newTestCursorCodec(t)
	if _, err := NewService(nil, domain, cursors); !errors.Is(err, ErrInvalidRequest) {
		t.Fatalf("nil publication domain error=%v", err)
	}
	if _, err := NewService(domain, domain, nil); !errors.Is(err, ErrInvalidRequest) {
		t.Fatalf("nil cursor codec error=%v", err)
	}
	service, err := NewService(domain, domain, cursors)
	if err != nil {
		t.Fatal(err)
	}
	if _, err := NewHandler(service, nil, nil); !errors.Is(err, ErrInvalidRequest) {
		t.Fatalf("nil authenticator error=%v", err)
	}
	if handler, err := NewHandler(service, func(*http.Request) (identity.Principal, error) {
		return identity.Principal{}, nil
	}, nil); handler != nil || !errors.Is(err, ErrUnsafeRolloutCommands) {
		t.Fatalf("legacy handler = (%T, %v), want fail closed", handler, err)
	}
	_, err = service.Publish(context.Background(), identity.Principal{
		UserID: uuid.New(), ScopeID: uuid.New(), ScopeKind: AudiencePlatform,
		Permissions: []string{edgepublish.PermissionManage},
	}, PublishInput{
		ConfigurationScopeID: uuid.New(), ExpectedSourceRevision: 1, TargetKind: TargetNodes,
		TargetSnapshot: &edgepublish.TargetSnapshotReference{ID: uuid.New(), Revision: 1, SHA256: [32]byte{1}},
	}, WriteMetadata{})
	if !errors.Is(err, ErrInvalidRequest) {
		t.Fatalf("mixed direct service target error=%v", err)
	}
}

func TestDirectPublishRejectsCallerSuppliedPrincipal(t *testing.T) {
	domain := &fakeDomain{}
	service, err := NewService(domain, domain, newTestCursorCodec(t))
	if err != nil {
		t.Fatal(err)
	}
	scopeID := testTenantScopeID()
	_, err = service.Publish(context.Background(), identity.Principal{
		UserID: uuid.New(), ScopeID: uuid.New(), ScopeKind: AudiencePlatform,
		Permissions: []string{edgepublish.PermissionManage},
	}, PublishInput{
		ConfigurationScopeID: scopeID, ExpectedSourceRevision: 1, TargetKind: TargetNodes,
		NodeIDs: []uuid.UUID{uuid.New()}, MaxAttempts: 3,
		HealthCheck: edgedeployment.HealthCheckPolicy{
			ActivationTimeout: time.Minute, ObservationWindow: time.Second, RequiredConsecutiveSuccesses: 1,
		}, Deadline: testClock.Add(time.Hour),
	}, WriteMetadata{
		IdempotencyKey: "direct-publish", RequestID: uuid.NewString(), CorrelationID: uuid.NewString(),
		Traceparent: testTraceparent(),
	})
	if !errors.Is(err, ErrUnsafeRolloutCommands) {
		t.Fatalf("direct publish error = %v, want unsafe production path", err)
	}
	domain.mu.Lock()
	defer domain.mu.Unlock()
	if len(domain.publishRequests) != 0 {
		t.Fatalf("direct publish reached domain: %d calls", len(domain.publishRequests))
	}
}

func newTestHandler(t *testing.T, domain *fakeDomain) *Handler {
	t.Helper()
	service, err := NewService(domain, domain, newTestCursorCodec(t))
	if err != nil {
		t.Fatal(err)
	}
	handler, err := newSessionHandler(service, testAuthenticateSession, slog.New(slog.NewTextHandler(io.Discard, nil)))
	if err != nil {
		t.Fatal(err)
	}
	return handler
}

func newTestCursorCodec(t *testing.T) CursorCodec {
	t.Helper()
	codec, err := NewHMACCursorCodec(CursorKey{
		ID: "test-active", Secret: bytes.Repeat([]byte{0x42}, 32),
	})
	if err != nil {
		t.Fatal(err)
	}
	return codec
}

func testAuthenticate(request *http.Request) (identity.Principal, error) {
	platformScopeID := uuid.MustParse("00000000-0000-0000-0000-000000000001")
	principal := identity.Principal{UserID: uuid.MustParse("00000000-0000-0000-0000-000000000002")}
	switch request.Header.Get("Authorization") {
	case "Bearer platform-manage":
		principal.ScopeID, principal.ScopeKind = platformScopeID, AudiencePlatform
		principal.Permissions = []string{edgepublish.PermissionRead, edgepublish.PermissionManage}
	case "Bearer platform-read":
		principal.ScopeID, principal.ScopeKind = platformScopeID, AudiencePlatform
		principal.Permissions = []string{edgepublish.PermissionRead}
	case "Bearer platform-none":
		principal.ScopeID, principal.ScopeKind = platformScopeID, AudiencePlatform
	case "Bearer tenant-read":
		principal.ScopeID, principal.ScopeKind = testTenantScopeID(), AudienceTenant
		principal.Permissions = []string{tenantReadPermission}
	case "Bearer tenant-manage":
		principal.ScopeID, principal.ScopeKind = testTenantScopeID(), AudienceTenant
		principal.Permissions = []string{tenantReadPermission, tenantManagePermission}
	default:
		return identity.Principal{}, identity.ErrInvalidSession
	}
	return principal, nil
}

func testAuthenticateSession(request *http.Request) (AuthenticatedSession, error) {
	principal, err := testAuthenticate(request)
	if err != nil {
		return AuthenticatedSession{}, err
	}
	rawToken := strings.TrimPrefix(request.Header.Get("Authorization"), "Bearer ")
	return newAuthenticatedSession(principal, uuid.NewSHA1(principal.UserID, []byte(rawToken)), rawToken)
}

func performRequest(handler http.Handler, method, target, authorization string, body any, write bool) *httptest.ResponseRecorder {
	request := newRequest(nil, method, target, authorization, body, write)
	response := httptest.NewRecorder()
	handler.ServeHTTP(response, request)
	return response
}

func newRequest(t *testing.T, method, target, authorization string, body any, write bool) *http.Request {
	var encoded io.Reader
	if body != nil {
		payload, err := json.Marshal(body)
		if err != nil {
			if t != nil {
				t.Fatal(err)
			}
			panic(err)
		}
		encoded = bytes.NewReader(payload)
	}
	request := httptest.NewRequest(method, target, encoded)
	if authorization != "" {
		request.Header.Set("Authorization", "Bearer "+authorization)
	}
	if body != nil {
		request.Header.Set("Content-Type", "application/json")
	}
	request.Header.Set("X-Request-ID", uuid.NewString())
	if write {
		request.Header.Set("Idempotency-Key", "publish-test")
		request.Header.Set("X-Correlation-ID", uuid.NewString())
		request.Header.Set("Traceparent", testTraceparent())
	}
	return request
}

func validPublishBody(scopeID uuid.UUID, nodeIDs []uuid.UUID) map[string]any {
	encodedNodes := make([]string, len(nodeIDs))
	for index, nodeID := range nodeIDs {
		encodedNodes[index] = nodeID.String()
	}
	return map[string]any{
		"configuration_scope_id": scopeID.String(), "expected_source_revision": int64(7),
		"target": map[string]any{"kind": TargetNodes, "node_ids": encodedNodes},
		"health_check": map[string]any{
			"activation_timeout_ms": int64(60000), "observation_window_ms": int64(5000),
			"required_consecutive_successes": uint32(2),
		},
		"max_attempts": uint32(3), "deadline": testClock.Add(time.Hour).Format(time.RFC3339),
	}
}

func validRollbackBody(scopeID uuid.UUID, nodeIDs []uuid.UUID) map[string]any {
	result := validPublishBody(scopeID, nodeIDs)
	delete(result, "expected_source_revision")
	return result
}

func mutateBody(body map[string]any, key string, value any) map[string]any {
	result := cloneMap(body)
	result[key] = value
	return result
}

func mutateTarget(body map[string]any, key string, value any) map[string]any {
	result := cloneMap(body)
	target := cloneMap(result["target"].(map[string]any))
	target[key] = value
	result["target"] = target
	return result
}

func cloneMap(value map[string]any) map[string]any {
	result := make(map[string]any, len(value))
	for key, item := range value {
		result[key] = item
	}
	return result
}

func testPublication(scopeID uuid.UUID) edgepublish.PublishResult {
	reference := edgepublish.TargetSnapshotReference{
		ID: uuid.New(), Revision: 3, SHA256: sha256.Sum256([]byte("resolver-snapshot")),
	}
	return edgepublish.PublishResult{
		PublicationID: uuid.New(), ConfigurationScopeID: scopeID, SourceRevision: 7,
		ConfigVersionID: uuid.New(), RolloutID: uuid.New(),
		CanonicalSnapshotSHA256: sha256.Sum256([]byte("source")), ArtifactSHA256: sha256.Sum256([]byte("artifact")),
		TargetKind: edgepublish.TargetKindResolver, TargetSnapshot: &reference,
		TargetSnapshotSHA256: sha256.Sum256([]byte("resolved-target")), NodeCount: 2, CreatedAt: testClock,
	}
}

func testRollout(scopeID uuid.UUID, state string) edgedeployment.RolloutSnapshot {
	progress := edgedeployment.RolloutProgress{Total: 2}
	canCancel, canRetry := false, false
	switch state {
	case edgedeployment.RolloutStateQueued:
		progress.Pending, canCancel = 2, true
	case edgedeployment.RolloutStateRunning:
		progress.Pending, progress.Succeeded = 1, 1
	case edgedeployment.RolloutStateSucceeded:
		progress.Succeeded = 2
	case edgedeployment.RolloutStatePartialFailed:
		progress.Succeeded, progress.Failed, canRetry = 1, 1, true
	case edgedeployment.RolloutStateFailed:
		progress.Failed, canRetry = 2, true
	case edgedeployment.RolloutStateCancelled:
		progress.Cancelled = 2
	default:
		progress.Succeeded = 2
	}
	return edgedeployment.RolloutSnapshot{
		ID: uuid.New(), ConfigurationScopeID: scopeID, ConfigVersionID: uuid.New(), Action: "apply",
		State: state, Revision: 4, MaxAttempts: 3, Progress: progress, CanCancel: canCancel, CanRetry: canRetry,
		CreatedAt: testClock, UpdatedAt: testClock.Add(time.Minute),
	}
}

func testDeployment(state string) edgedeployment.DeploymentSnapshot {
	return edgedeployment.DeploymentSnapshot{
		ID: uuid.New(), NodeID: uuid.New(), Attempt: 1, MaxAttempts: 3, State: state,
		ErrorCode: "ERROR_CODE_CONFIG_PRECHECK_FAILED", CreatedAt: testClock,
		UpdatedAt: testClock.Add(time.Minute), CanRetry: state == "failed",
	}
}

func testTenantScopeID() uuid.UUID {
	return uuid.MustParse("00000000-0000-0000-0000-000000000010")
}

func testTraceparent() string {
	return "00-4bf92f3577b34da6a3ce929d0e0e4736-00f067aa0ba902b7-01"
}

func assertAPIError(t *testing.T, response *httptest.ResponseRecorder, status int, code string) {
	t.Helper()
	if response.Code != status {
		t.Fatalf("status=%d want=%d body=%s", response.Code, status, response.Body.String())
	}
	var envelope errorEnvelope
	if err := json.Unmarshal(response.Body.Bytes(), &envelope); err != nil {
		t.Fatalf("decode error response: %v body=%s", err, response.Body.String())
	}
	if envelope.Error.Code != code || envelope.Error.RequestID == "" {
		t.Fatalf("error=%+v want code=%s", envelope.Error, code)
	}
}

func assertJSONOmits(t *testing.T, encoded []byte, keys ...string) {
	t.Helper()
	for _, key := range keys {
		if bytes.Contains(encoded, []byte(`"`+key+`"`)) {
			t.Fatalf("response leaked %q: %s", key, encoded)
		}
	}
}

func assertJSONHas(t *testing.T, encoded []byte, keys ...string) {
	t.Helper()
	for _, key := range keys {
		if !bytes.Contains(encoded, []byte(`"`+key+`"`)) {
			t.Fatalf("response missing %q: %s", key, encoded)
		}
	}
}
