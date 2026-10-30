package httpapi

import (
	"bytes"
	"net/http"
	"net/http/httptest"
	"testing"
)

type challengePublicationMountObservation struct {
	method, path, tenantScopeID, policyID, rolloutID, authorization string
}

func TestChallengePublicationMountForwardsOnlyExactRoutes(t *testing.T) {
	observations := make([]challengePublicationMountObservation, 0, 3)
	probe := http.HandlerFunc(func(response http.ResponseWriter, request *http.Request) {
		observations = append(observations, challengePublicationMountObservation{
			method: request.Method, path: request.URL.Path,
			tenantScopeID: request.PathValue("tenant_scope_id"), policyID: request.PathValue("policy_id"),
			rolloutID: request.PathValue("rollout_id"), authorization: request.Header.Get("Authorization"),
		})
		response.WriteHeader(http.StatusNoContent)
	})
	api := New(nil, nil, Config{APIKeyPepper: bytes.Repeat([]byte{0x52}, 32), ChallengePolicyHandlerFactory: func() (http.Handler, error) {
		return probe, nil
	}})
	if err := api.InitializationError(); err != nil {
		t.Fatalf("initialize challenge publication mount: %v", err)
	}
	tenantScopeID := "11111111-1111-4111-8111-111111111111"
	policyID := "22222222-2222-4222-8222-222222222222"
	rolloutID := "33333333-3333-4333-8333-333333333333"
	base := "/v1/tenant-scopes/" + tenantScopeID + "/challenge-policies/" + policyID + "/publications"
	routes := []struct{ method, path string }{
		{http.MethodPost, base},
		{http.MethodGet, base + "/" + rolloutID},
		{http.MethodPost, base + "/" + rolloutID + "/promote"},
	}
	handler := api.Handler()
	for _, route := range routes {
		request := httptest.NewRequest(route.method, route.path, nil)
		request.Header.Set("Authorization", "Bearer challenge-session")
		response := httptest.NewRecorder()
		handler.ServeHTTP(response, request)
		if response.Code != http.StatusNoContent {
			t.Fatalf("%s %s status=%d, want 204", route.method, route.path, response.Code)
		}
	}
	if len(observations) != len(routes) {
		t.Fatalf("forwarded calls=%d, want %d", len(observations), len(routes))
	}
	for index, observation := range observations {
		if observation.method != routes[index].method || observation.path != routes[index].path ||
			observation.tenantScopeID != tenantScopeID || observation.policyID != policyID ||
			observation.authorization != "Bearer challenge-session" {
			t.Errorf("observation[%d]=%+v", index, observation)
		}
		if index == 0 && observation.rolloutID != "" || index > 0 && observation.rolloutID != rolloutID {
			t.Errorf("observation[%d] rollout_id=%q", index, observation.rolloutID)
		}
	}

	response := httptest.NewRecorder()
	handler.ServeHTTP(response, httptest.NewRequest(http.MethodPost, base+"/"+rolloutID+"/promote/neighbor", nil))
	if response.Code != http.StatusNotFound || len(observations) != len(routes) {
		t.Fatalf("adjacent route status=%d forwarded=%d", response.Code, len(observations))
	}
}
