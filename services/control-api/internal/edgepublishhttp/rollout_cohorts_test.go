package edgepublishhttp

import (
	"io"
	"log/slog"
	"net/http"
	"testing"

	"github.com/google/uuid"
)

func TestRolloutCohortCommandRoutesAndPolicyInput(t *testing.T) {
	domain := &fakeDomain{}
	service, err := newRuntimeService(domain, domain, domain, newTestCursorCodec(t))
	if err != nil {
		t.Fatal(err)
	}
	handler, err := newSessionHandler(service, testAuthenticateSession, slog.New(slog.NewTextHandler(io.Discard, nil)))
	if err != nil {
		t.Fatal(err)
	}
	scopeID, rolloutID := testTenantScopeID(), uuid.New()
	body := map[string]any{"configuration_scope_id": scopeID.String(), "expected_revision": int64(1)}
	for _, action := range []string{"start", "pause", "resume"} {
		response := performRequest(handler, http.MethodPost,
			"/v1/admin/site-rollouts/"+rolloutID.String()+"/"+action, "platform-manage", body, true)
		if response.Code != http.StatusOK {
			t.Fatalf("%s status=%d body=%s", action, response.Code, response.Body.String())
		}
	}

	publish := map[string]any{
		"configuration_scope_id": scopeID.String(), "expected_source_revision": int64(7),
		"target": map[string]any{"kind": "nodes", "node_ids": []string{
			"018cc251-f400-7def-8000-000000000003", "018cc251-f400-7def-8000-000000000001",
			"018cc251-f400-7def-8000-000000000002",
		}},
		"health_check": map[string]any{"activation_timeout_ms": int64(60000), "observation_window_ms": int64(30000), "required_consecutive_successes": uint32(3)},
		"rollout":      map[string]any{"strategy": "canary", "canary_size": uint32(1), "batch_size": uint32(1), "failure_threshold": uint32(1), "auto_start": false},
		"max_attempts": uint32(3), "deadline": "2026-08-09T09:00:00Z",
	}
	response := performRequest(handler, http.MethodPost, "/v1/admin/site-publications", "platform-manage", publish, true)
	if response.Code != http.StatusCreated {
		t.Fatalf("publish status=%d body=%s", response.Code, response.Body.String())
	}
	domain.mu.Lock()
	if len(domain.publishRequests) != 1 || domain.publishRequests[0].Rollout.Strategy != "canary" ||
		domain.publishRequests[0].Rollout.CanarySize != 1 || domain.publishRequests[0].Rollout.AutoStart {
		t.Fatalf("captured rollout policy=%+v", domain.publishRequests)
	}
	domain.mu.Unlock()
	rollback := validRollbackBody(scopeID, []uuid.UUID{uuid.New()})
	rollback["rollout"] = map[string]any{
		"strategy": "canary", "canary_size": uint32(1), "batch_size": uint32(2),
		"failure_threshold": uint32(1), "auto_start": true,
	}
	response = performRequest(handler, http.MethodPost,
		"/v1/admin/site-publications/"+uuid.NewString()+"/rollback", "platform-manage", rollback, true)
	if response.Code != http.StatusCreated {
		t.Fatalf("rollback status=%d body=%s", response.Code, response.Body.String())
	}
	domain.mu.Lock()
	if len(domain.rollbackRequests) != 1 || domain.rollbackRequests[0].Rollout.Strategy != "canary" ||
		domain.rollbackRequests[0].Rollout.BatchSize != 2 || !domain.rollbackRequests[0].Rollout.AutoStart {
		t.Fatalf("captured rollback rollout=%+v", domain.rollbackRequests)
	}
	domain.mu.Unlock()
}
