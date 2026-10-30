package edgepublishhttp

import (
	"net/http"
	"testing"

	"github.com/google/uuid"
)

func TestHandlerRoutesMatchPublicationFragmentAndRejectNeighbors(t *testing.T) {
	handler := newTestHandler(t, &fakeDomain{})
	scopeID := testTenantScopeID()
	publicationID := uuid.New()
	rolloutID := uuid.New()
	publicationBody := validPublishBody(scopeID, []uuid.UUID{uuid.New()})
	rollbackBody := validRollbackBody(scopeID, []uuid.UUID{uuid.New()})
	commandBody := map[string]any{
		"configuration_scope_id": scopeID.String(),
		"expected_revision":      int64(1),
	}

	exact := []struct {
		method string
		path   string
		auth   string
		body   any
		write  bool
	}{
		{http.MethodGet, "/v1/admin/site-publications?scope_id=" + scopeID.String(), "platform-read", nil, false},
		{http.MethodPost, "/v1/admin/site-publications", "platform-manage", publicationBody, true},
		{http.MethodGet, "/v1/admin/site-publications/" + publicationID.String() + "?scope_id=" + scopeID.String(), "platform-read", nil, false},
		{http.MethodPost, "/v1/admin/site-publications/" + publicationID.String() + "/rollback", "platform-manage", rollbackBody, true},
		{http.MethodGet, "/v1/admin/site-rollouts?scope_id=" + scopeID.String(), "platform-read", nil, false},
		{http.MethodGet, "/v1/admin/site-rollouts/" + rolloutID.String() + "?scope_id=" + scopeID.String(), "platform-read", nil, false},
		{http.MethodGet, "/v1/admin/site-rollouts/" + rolloutID.String() + "/deployments?scope_id=" + scopeID.String(), "platform-read", nil, false},
		{http.MethodPost, "/v1/admin/site-rollouts/" + rolloutID.String() + "/start", "platform-manage", commandBody, true},
		{http.MethodPost, "/v1/admin/site-rollouts/" + rolloutID.String() + "/pause", "platform-manage", commandBody, true},
		{http.MethodPost, "/v1/admin/site-rollouts/" + rolloutID.String() + "/resume", "platform-manage", commandBody, true},
		{http.MethodPost, "/v1/admin/site-rollouts/" + rolloutID.String() + "/cancel", "platform-manage", commandBody, true},
		{http.MethodPost, "/v1/admin/site-rollouts/" + rolloutID.String() + "/retry-failed", "platform-manage", commandBody, true},
		{http.MethodGet, "/v1/site-publications", "tenant-read", nil, false},
		{http.MethodGet, "/v1/site-publications/" + publicationID.String(), "tenant-read", nil, false},
		{http.MethodGet, "/v1/site-rollouts", "tenant-read", nil, false},
		{http.MethodGet, "/v1/site-rollouts/" + rolloutID.String(), "tenant-read", nil, false},
		{http.MethodGet, "/v1/site-rollouts/" + rolloutID.String() + "/deployments", "tenant-read", nil, false},
	}
	for _, route := range exact {
		response := performRequest(handler, route.method, route.path, route.auth, route.body, route.write)
		if response.Code == http.StatusNotFound {
			t.Fatalf("fragment route %s %s returned 404", route.method, route.path)
		}
	}

	for _, path := range []string{
		"/v1/admin/site-publications-neighbor",
		"/v1/admin/site-publications/" + publicationID.String() + "/neighbor",
		"/v1/admin/site-publications/" + publicationID.String() + "/rollback/neighbor",
		"/v1/admin/site-rollouts/" + rolloutID.String() + "/cancel/neighbor",
		"/v1/site-publications/" + publicationID.String() + "/neighbor",
		"/v1/site-rollouts/" + rolloutID.String() + "/deployments/neighbor",
	} {
		response := performRequest(handler, http.MethodGet, path, "platform-read", nil, false)
		if response.Code != http.StatusNotFound {
			t.Fatalf("neighbor %s status = %d, want 404", path, response.Code)
		}
	}
}
