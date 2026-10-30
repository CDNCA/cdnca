package edgepublishhttp

import (
	"context"
	"encoding/json"
	"net/http"
	"testing"

	"github.com/cdnca/cdnca/services/control-api/internal/edgedeployment"
	"github.com/cdnca/cdnca/services/control-api/internal/edgepublish"
	"github.com/google/uuid"
)

func TestHTTPCursorEnvelopeBindingsAndPagination(t *testing.T) {
	scopeID := testTenantScopeID()
	domain := &fakeDomain{}
	domain.listPublicationFn = func(
		_ context.Context,
		_ edgepublish.Actor,
		_ uuid.UUID,
		request edgepublish.PublicationPageRequest,
	) (edgepublish.PublicationPage, error) {
		item := testPublication(scopeID)
		if request.Cursor == "" {
			return edgepublish.PublicationPage{
				Items: []edgepublish.PublishResult{item}, NextCursor: "publication_inner", CurrentSourceRevision: 7,
			}, nil
		}
		if request.Cursor != "publication_inner" {
			return edgepublish.PublicationPage{}, edgepublish.ErrInvalidInput
		}
		return edgepublish.PublicationPage{Items: []edgepublish.PublishResult{item}, CurrentSourceRevision: 7}, nil
	}
	handler := newTestHandler(t, domain)
	first := performRequest(handler, http.MethodGet,
		"/v1/admin/site-publications?scope_id="+scopeID.String()+"&limit=1", "platform-read", nil, false)
	if first.Code != http.StatusOK {
		t.Fatalf("first page status=%d body=%s", first.Code, first.Body.String())
	}
	var page PublicationPageView
	if err := json.Unmarshal(first.Body.Bytes(), &page); err != nil {
		t.Fatal(err)
	}
	if page.NextCursor == "" || page.NextCursor == "publication_inner" {
		t.Fatalf("public cursor=%q", page.NextCursor)
	}
	second := performRequest(handler, http.MethodGet,
		"/v1/admin/site-publications?scope_id="+scopeID.String()+"&limit=1&cursor="+page.NextCursor,
		"platform-read", nil, false)
	if second.Code != http.StatusOK {
		t.Fatalf("second page status=%d body=%s", second.Code, second.Body.String())
	}
	domain.mu.Lock()
	inner := domain.publicationPageRequest[len(domain.publicationPageRequest)-1].Cursor
	domain.mu.Unlock()
	if inner != "publication_inner" {
		t.Fatalf("domain cursor=%q", inner)
	}

	otherScope := uuid.New()
	crossScope := performRequest(handler, http.MethodGet,
		"/v1/admin/site-publications?scope_id="+otherScope.String()+"&cursor="+page.NextCursor,
		"platform-read", nil, false)
	assertAPIError(t, crossScope, http.StatusBadRequest, "validation_error")
	crossAudience := performRequest(handler, http.MethodGet,
		"/v1/site-publications?cursor="+page.NextCursor, "tenant-read", nil, false)
	assertAPIError(t, crossAudience, http.StatusBadRequest, "validation_error")
	crossKind := performRequest(handler, http.MethodGet,
		"/v1/admin/site-rollouts?scope_id="+scopeID.String()+"&cursor="+page.NextCursor,
		"platform-read", nil, false)
	assertAPIError(t, crossKind, http.StatusBadRequest, "validation_error")
	tampered := page.NextCursor[:len(page.NextCursor)-1] + differentCursorCharacter(page.NextCursor[len(page.NextCursor)-1])
	tamperResponse := performRequest(handler, http.MethodGet,
		"/v1/admin/site-publications?scope_id="+scopeID.String()+"&cursor="+tampered,
		"platform-read", nil, false)
	assertAPIError(t, tamperResponse, http.StatusBadRequest, "validation_error")

	firstRolloutID, secondRolloutID := uuid.New(), uuid.New()
	domain.listDeploymentFn = func(
		_ context.Context,
		_ edgedeployment.Actor,
		_, _ uuid.UUID,
		request edgedeployment.DeploymentPageRequest,
	) (edgedeployment.DeploymentPage, error) {
		if request.Cursor == "" {
			return edgedeployment.DeploymentPage{
				Items: []edgedeployment.DeploymentSnapshot{testDeployment("queued")}, NextCursor: "deployment_inner",
			}, nil
		}
		return edgedeployment.DeploymentPage{}, nil
	}
	deploymentFirst := performRequest(handler, http.MethodGet,
		"/v1/admin/site-rollouts/"+firstRolloutID.String()+"/deployments?scope_id="+scopeID.String()+"&limit=1",
		"platform-read", nil, false)
	if deploymentFirst.Code != http.StatusOK {
		t.Fatalf("deployment first page status=%d body=%s", deploymentFirst.Code, deploymentFirst.Body.String())
	}
	var deploymentPage DeploymentPageView
	if err := json.Unmarshal(deploymentFirst.Body.Bytes(), &deploymentPage); err != nil {
		t.Fatal(err)
	}
	crossRollout := performRequest(handler, http.MethodGet,
		"/v1/admin/site-rollouts/"+secondRolloutID.String()+"/deployments?scope_id="+scopeID.String()+
			"&cursor="+deploymentPage.NextCursor,
		"platform-read", nil, false)
	assertAPIError(t, crossRollout, http.StatusBadRequest, "validation_error")
}

func TestDomainResponseIdentityMismatchFailsClosed(t *testing.T) {
	scopeID, otherScope := testTenantScopeID(), uuid.New()

	t.Run("publication list scope", func(t *testing.T) {
		domain := &fakeDomain{}
		domain.listPublicationFn = func(context.Context, edgepublish.Actor, uuid.UUID, edgepublish.PublicationPageRequest) (edgepublish.PublicationPage, error) {
			return edgepublish.PublicationPage{
				Items: []edgepublish.PublishResult{testPublication(otherScope)}, CurrentSourceRevision: 7,
			}, nil
		}
		response := performRequest(newTestHandler(t, domain), http.MethodGet,
			"/v1/admin/site-publications?scope_id="+scopeID.String(), "platform-read", nil, false)
		assertAPIError(t, response, http.StatusServiceUnavailable, "publication_service_unavailable")
	})

	for _, mismatch := range []string{"scope", "id"} {
		t.Run("publication detail "+mismatch, func(t *testing.T) {
			publicationID := uuid.New()
			domain := &fakeDomain{}
			domain.getPublicationFn = func(context.Context, edgepublish.Actor, uuid.UUID, uuid.UUID) (edgepublish.PublishResult, error) {
				result := testPublication(scopeID)
				result.PublicationID = publicationID
				if mismatch == "scope" {
					result.ConfigurationScopeID = otherScope
				} else {
					result.PublicationID = uuid.New()
				}
				return result, nil
			}
			response := performRequest(newTestHandler(t, domain), http.MethodGet,
				"/v1/admin/site-publications/"+publicationID.String()+"?scope_id="+scopeID.String(),
				"platform-read", nil, false)
			assertAPIError(t, response, http.StatusServiceUnavailable, "publication_service_unavailable")
		})
	}

	t.Run("rollout list scope", func(t *testing.T) {
		domain := &fakeDomain{}
		domain.listRolloutFn = func(context.Context, edgedeployment.Actor, uuid.UUID, edgedeployment.RolloutPageRequest) (edgedeployment.RolloutPage, error) {
			return edgedeployment.RolloutPage{Items: []edgedeployment.RolloutSnapshot{
				testRollout(otherScope, edgedeployment.RolloutStateQueued),
			}}, nil
		}
		response := performRequest(newTestHandler(t, domain), http.MethodGet,
			"/v1/admin/site-rollouts?scope_id="+scopeID.String(), "platform-read", nil, false)
		assertAPIError(t, response, http.StatusServiceUnavailable, "publication_service_unavailable")
	})

	for _, mismatch := range []string{"scope", "id"} {
		t.Run("rollout detail "+mismatch, func(t *testing.T) {
			rolloutID := uuid.New()
			domain := &fakeDomain{}
			domain.getRolloutFn = mismatchedRollout(scopeID, otherScope, rolloutID, mismatch)
			response := performRequest(newTestHandler(t, domain), http.MethodGet,
				"/v1/admin/site-rollouts/"+rolloutID.String()+"?scope_id="+scopeID.String(),
				"platform-read", nil, false)
			assertAPIError(t, response, http.StatusServiceUnavailable, "publication_service_unavailable")
		})

		t.Run("deployment rollout "+mismatch, func(t *testing.T) {
			rolloutID := uuid.New()
			domain := &fakeDomain{}
			domain.getRolloutFn = mismatchedRollout(scopeID, otherScope, rolloutID, mismatch)
			response := performRequest(newTestHandler(t, domain), http.MethodGet,
				"/v1/admin/site-rollouts/"+rolloutID.String()+"/deployments?scope_id="+scopeID.String(),
				"platform-read", nil, false)
			assertAPIError(t, response, http.StatusServiceUnavailable, "publication_service_unavailable")
		})
	}
}

func mismatchedRollout(
	scopeID, otherScope, rolloutID uuid.UUID,
	mismatch string,
) func(context.Context, edgedeployment.Actor, uuid.UUID, uuid.UUID) (edgedeployment.RolloutSnapshot, error) {
	return func(context.Context, edgedeployment.Actor, uuid.UUID, uuid.UUID) (edgedeployment.RolloutSnapshot, error) {
		result := testRollout(scopeID, edgedeployment.RolloutStateQueued)
		result.ID = rolloutID
		if mismatch == "scope" {
			result.ConfigurationScopeID = otherScope
		} else {
			result.ID = uuid.New()
		}
		return result, nil
	}
}
