package httpapi

import (
	"bytes"
	"context"
	"errors"
	"net/http"
	"net/http/httptest"
	"testing"
	"time"

	"github.com/cdnca/cdnca/services/control-api/internal/identity"
	"github.com/cdnca/cdnca/services/control-api/internal/nodepresence"
	"github.com/google/uuid"
	"github.com/jackc/pgx/v5/pgxpool"
)

type testPresenceLeases struct {
	present map[uuid.UUID]bool
	err     error
}

func (l *testPresenceLeases) Exists(_ context.Context, nodeID uuid.UUID) (bool, error) {
	if l.err != nil {
		return false, l.err
	}
	return l.present[nodeID], nil
}

func TestNodePresenceInventoryAPI(t *testing.T) {
	pool := isolatedTestPool(t)
	passwordHash, err := identity.HashPassword(testPassword)
	if err != nil {
		t.Fatal(err)
	}
	identityStore := identity.NewStore(pool)
	bootstrap, err := identityStore.BootstrapPlatformUser(context.Background(), "presenceadmin", "Presence Admin", passwordHash, "presence-bootstrap")
	if err != nil {
		t.Fatal(err)
	}
	tokens, err := identity.NewTokenManager("presence-integration-secret-at-least-thirty-two-bytes", 5*time.Minute)
	if err != nil {
		t.Fatal(err)
	}
	identityService, err := identity.NewService(identityStore, tokens, 24*time.Hour)
	if err != nil {
		t.Fatal(err)
	}
	now := time.Now().UTC().Truncate(time.Second)
	freshID := uuid.MustParse("00000000-0000-4000-8000-000000000001")
	unknownID := uuid.MustParse("00000000-0000-4000-8000-000000000002")
	legacyID := uuid.MustParse("00000000-0000-4000-8000-000000000003")
	staleID := uuid.MustParse("00000000-0000-4000-8000-000000000004")
	for index, fixture := range []struct {
		id   uuid.UUID
		name string
	}{
		{freshID, "Fresh Agent"},
		{unknownID, "Never Connected"},
		{legacyID, "Legacy Agent"},
		{staleID, "Stale Agent"},
	} {
		insertPresenceNode(t, pool, bootstrap.ScopeID, bootstrap.UserID, fixture.id, int64(index+1), fixture.name, now)
	}
	freshVersion := "2.4.1"
	insertConfirmedPresence(t, pool, freshID, now.Add(-5*time.Second), &freshVersion)
	insertConfirmedPresence(t, pool, legacyID, now.Add(-10*time.Second), nil)
	insertConfirmedPresence(t, pool, staleID, now.Add(-time.Minute), &freshVersion)

	leases := &testPresenceLeases{present: map[uuid.UUID]bool{freshID: true, legacyID: true}}
	server := httptest.NewServer(New(pool, identityService, Config{
		CookieSecure: false, APIKeyPepper: bytes.Repeat([]byte{0x52}, 32), Now: func() time.Time { return now },
		NodePresenceLeases: leases, NodePresenceOfflineAfter: 45 * time.Second,
	}).Handler())
	t.Cleanup(server.Close)
	client := server.Client()
	auth, _ := loginOK(t, client, server.URL, "presenceadmin")

	firstResponse := doRequest(t, client, http.MethodGet, server.URL+"/v1/nodes?presence=online&limit=1", nil, nil, auth.AccessToken, "presence-list-request")
	var first nodeListResponse
	decodeResponse(t, firstResponse, http.StatusOK, &first)
	if firstResponse.Header.Get("X-Request-ID") != "presence-list-request" {
		t.Fatalf("X-Request-ID = %q", firstResponse.Header.Get("X-Request-ID"))
	}
	firstResponse.Body.Close()
	if len(first.Items) != 1 || first.Items[0].ID != freshID || first.Items[0].DisplayID != "1" ||
		first.NextCursor == nil || *first.NextCursor != freshID {
		t.Fatalf("first online page = %#v", first)
	}
	assertPresence(t, first.Items[0].Presence, nodepresence.StatusOnline, nodepresence.FreshnessFresh, nodepresence.LeasePresent)
	if first.Items[0].Presence.AgentVersion == nil || *first.Items[0].Presence.AgentVersion != freshVersion {
		t.Fatalf("fresh agent version = %v", first.Items[0].Presence.AgentVersion)
	}

	second := getPresencePage(t, client, server.URL+"/v1/nodes?presence=online&limit=1&cursor="+first.NextCursor.String(), auth.AccessToken)
	if len(second.Items) != 1 || second.Items[0].ID != legacyID || second.Items[0].DisplayID != "3" || second.NextCursor != nil {
		t.Fatalf("second online page = %#v", second)
	}
	if second.Items[0].Presence.AgentVersion != nil {
		t.Fatalf("legacy agent version = %v, want omitted", second.Items[0].Presence.AgentVersion)
	}

	offline := getPresencePage(t, client, server.URL+"/v1/nodes?presence=offline", auth.AccessToken)
	if len(offline.Items) != 1 || offline.Items[0].ID != staleID || offline.Items[0].DisplayID != "4" {
		t.Fatalf("offline page = %#v", offline)
	}
	assertPresence(t, offline.Items[0].Presence, nodepresence.StatusOffline, nodepresence.FreshnessStale, nodepresence.LeaseAbsent)

	unknown := getPresencePage(t, client, server.URL+"/v1/nodes?presence=unknown", auth.AccessToken)
	if len(unknown.Items) != 1 || unknown.Items[0].ID != unknownID || unknown.Items[0].DisplayID != "2" {
		t.Fatalf("unknown page = %#v", unknown)
	}
	assertPresence(t, unknown.Items[0].Presence, nodepresence.StatusUnknown, nodepresence.FreshnessNever, nodepresence.LeaseAbsent)
	if unknown.Items[0].Presence.LastHeartbeatAt != nil || unknown.Items[0].Presence.SessionEpoch != nil {
		t.Fatalf("unknown presence exposed unconfirmed fields = %#v", unknown.Items[0].Presence)
	}

	bad := doRequest(t, client, http.MethodGet, server.URL+"/v1/nodes?presence=bad", nil, nil, auth.AccessToken)
	assertError(t, bad, http.StatusBadRequest, "validation_error", "")
	bad.Body.Close()

	leases.err = errors.New("redis unavailable")
	degraded := getPresencePage(t, client, server.URL+"/v1/nodes?presence=online&limit=1", auth.AccessToken)
	if len(degraded.Items) != 1 || degraded.Items[0].Presence.LastHeartbeatAt == nil || degraded.Items[0].Presence.AgentVersion == nil {
		t.Fatalf("Redis failure lost confirmed PostgreSQL presence = %#v", degraded)
	}
	assertPresence(t, degraded.Items[0].Presence, nodepresence.StatusOnline, nodepresence.FreshnessFresh, nodepresence.LeaseUnavailable)
}

func insertPresenceNode(t *testing.T, pool *pgxpool.Pool, scopeID, userID, nodeID uuid.UUID, displayID int64, name string, now time.Time) {
	t.Helper()
	if _, err := pool.Exec(context.Background(), `
		INSERT INTO nodes (id, display_id, scope_id, name, admin_state, created_by_user_id, created_at, updated_at)
		VALUES ($1, $2, $3, $4, 'active', $5, $6, $6)`, nodeID, displayID, scopeID, name, userID, now); err != nil {
		t.Fatal(err)
	}
}

func insertConfirmedPresence(t *testing.T, pool *pgxpool.Pool, nodeID uuid.UUID, lastSeen time.Time, agentVersion *string) {
	t.Helper()
	eventID := uuid.New()
	requestID := uuid.New()
	digest := make([]byte, 32)
	if _, err := pool.Exec(context.Background(), `
		INSERT INTO node_presence (
			node_id, status, session_epoch, heartbeat_sequence, event_id, request_id, payload_digest,
			occurred_at, projected_at, last_seen_at, agent_version,
			confirmed_session_epoch, confirmed_heartbeat_sequence, confirmed_event_id,
			confirmed_request_id, confirmed_payload_digest, confirmed_agent_version,
			online_since, current_config_version_id, previous_config_version_id, loaded_config_version_id,
			openresty_state, firewall_state, filesystem_total_bytes, filesystem_available_bytes,
			cache_used_bytes, active_deployments, revision, updated_at
		) VALUES (
			$1, 'online', 1, 1, $2, $3, $4, $5, $5, $5, $6,
			1, 1, $2, $3, $4, $6, $5, NULL, NULL, NULL,
			'running', 'running', 0, 0, 0, '[]'::jsonb, 1, $5
		)`, nodeID, eventID, requestID, digest, lastSeen, agentVersion); err != nil {
		t.Fatal(err)
	}
}

func getPresencePage(t *testing.T, client *http.Client, url, accessToken string) nodeListResponse {
	t.Helper()
	response := doRequest(t, client, http.MethodGet, url, nil, nil, accessToken)
	var page nodeListResponse
	decodeResponse(t, response, http.StatusOK, &page)
	response.Body.Close()
	return page
}

func assertPresence(t *testing.T, actual nodepresence.Presence, status, freshness, lease string) {
	t.Helper()
	if actual.Status != status || actual.ProjectionFreshness != freshness || actual.LeaseSignal != lease {
		t.Fatalf("presence = %#v, want status=%s freshness=%s lease=%s", actual, status, freshness, lease)
	}
}
