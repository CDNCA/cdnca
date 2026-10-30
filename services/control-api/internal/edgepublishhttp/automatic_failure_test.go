package edgepublishhttp

import (
	"context"
	"encoding/json"
	"net/http"
	"testing"
	"time"

	"github.com/cdnca/cdnca/services/control-api/internal/edgepublish"
	"github.com/google/uuid"
)

// O2 (live-site2 10-22): node_artifacts_syncing reaches the publication page
// with the node artifact sync progress; progress on another reason, or
// beyond its total, fails closed.
func TestPublicationPageCarriesNodeArtifactSyncProgress(t *testing.T) {
	scopeID := testTenantScopeID()
	failedAt := time.Date(2026, 10, 22, 4, 47, 48, 0, time.UTC)
	page := func(failure *edgepublish.AutomaticPublicationFailure) *fakeDomain {
		domain := &fakeDomain{}
		domain.listPublicationFn = func(context.Context, edgepublish.Actor, uuid.UUID, edgepublish.PublicationPageRequest) (edgepublish.PublicationPage, error) {
			return edgepublish.PublicationPage{Items: []edgepublish.PublishResult{testPublication(scopeID)},
				CurrentSourceRevision: 11, AutomaticFailure: failure}, nil
		}
		return domain
	}
	read := func(domain *fakeDomain) *http.Response {
		return performRequest(newTestHandler(t, domain), http.MethodGet,
			"/v1/admin/site-publications?scope_id="+scopeID.String(), "platform-read", nil, false).Result()
	}

	response := read(page(&edgepublish.AutomaticPublicationFailure{Reason: "node_artifacts_syncing", SourceRevision: 11,
		FailedAt: failedAt, ArtifactSync: &edgepublish.ArtifactSyncProgress{ReceivedSegments: 7, TotalSegments: 21, RemainingMinutes: 15}}))
	var body struct {
		AutomaticFailure map[string]any `json:"automatic_failure"`
	}
	if response.StatusCode != http.StatusOK || json.NewDecoder(response.Body).Decode(&body) != nil {
		t.Fatalf("status %d", response.StatusCode)
	}
	sync, _ := body.AutomaticFailure["artifact_sync"].(map[string]any)
	if body.AutomaticFailure["reason"] != "node_artifacts_syncing" || sync["received_segments"] != float64(7) ||
		sync["total_segments"] != float64(21) || sync["remaining_minutes"] != float64(15) {
		t.Fatalf("automatic_failure = %v", body.AutomaticFailure)
	}

	// B15 NODE-PUB-01: a request ended by another tenant's configuration on a
	// shared node is explained, not dropped.
	response = read(page(&edgepublish.AutomaticPublicationFailure{Reason: "node_scope_conflict", SourceRevision: 11, FailedAt: failedAt}))
	body.AutomaticFailure = nil
	if response.StatusCode != http.StatusOK || json.NewDecoder(response.Body).Decode(&body) != nil ||
		body.AutomaticFailure["reason"] != "node_scope_conflict" {
		t.Fatalf("node_scope_conflict: status %d, automatic_failure = %v", response.StatusCode, body.AutomaticFailure)
	}

	for name, failure := range map[string]*edgepublish.AutomaticPublicationFailure{
		"progress on a capability refusal": {Reason: "node_capability_unavailable", SourceRevision: 11, FailedAt: failedAt,
			ArtifactSync: &edgepublish.ArtifactSyncProgress{ReceivedSegments: 1, TotalSegments: 2, RemainingMinutes: 1}},
		"received beyond total": {Reason: "node_artifacts_syncing", SourceRevision: 11, FailedAt: failedAt,
			ArtifactSync: &edgepublish.ArtifactSyncProgress{ReceivedSegments: 3, TotalSegments: 2, RemainingMinutes: 1}},
		"unknown reason": {Reason: "publish_outcome_unknown", SourceRevision: 11, FailedAt: failedAt},
	} {
		if status := read(page(failure)).StatusCode; status != http.StatusServiceUnavailable {
			t.Fatalf("%s: status %d, want 503", name, status)
		}
	}
}
