//go:build integration

package edgepublishhttp

import (
	"bytes"
	"context"
	"crypto/ed25519"
	"crypto/rand"
	"crypto/sha256"
	"encoding/json"
	"fmt"
	"net/http"
	"net/http/httptest"
	"os"
	"regexp"
	"strings"
	"sync"
	"testing"
	"time"

	"github.com/cdnca/cdnca/libs/edgeconfig"
	agentv1 "github.com/cdnca/cdnca/proto/gen/go/agent/v1"
	"github.com/cdnca/cdnca/services/control-api/internal/apikey"
	"github.com/cdnca/cdnca/services/control-api/internal/apikeycredential"
	"github.com/cdnca/cdnca/services/control-api/internal/audit"
	"github.com/cdnca/cdnca/services/control-api/internal/database"
	"github.com/cdnca/cdnca/services/control-api/internal/edgedeployment"
	"github.com/cdnca/cdnca/services/control-api/internal/edgepublish"
	"github.com/cdnca/cdnca/services/control-api/internal/edgepublish/capabilitytest"
	"github.com/cdnca/cdnca/services/control-api/internal/iamlock"
	"github.com/cdnca/cdnca/services/control-api/internal/identity"
	"github.com/cdnca/cdnca/services/control-api/internal/securityactivation"
	"github.com/cdnca/cdnca/services/control-api/internal/securitypolicy"
	"github.com/cdnca/cdnca/services/control-api/internal/sessioncredential"
	"github.com/google/uuid"
	"github.com/jackc/pgx/v5"
	"github.com/jackc/pgx/v5/pgxpool"
)

type integrationSigner struct {
	public  ed25519.PublicKey
	private ed25519.PrivateKey
}

func (s *integrationSigner) KeyID() string { return "site-publication-http-integration" }

func (s *integrationSigner) PublicKey() ed25519.PublicKey {
	return append(ed25519.PublicKey(nil), s.public...)
}

func (s *integrationSigner) Sign(_ context.Context, payload []byte) ([]byte, error) {
	return ed25519.Sign(s.private, payload), nil
}

type integrationEntitlement struct{}

func (integrationEntitlement) AuthorizePublication(
	_ context.Context,
	_ pgx.Tx,
	_ edgepublish.EntitlementRequest,
) (edgepublish.EntitlementDecision, error) {
	return edgepublish.EntitlementDecision{
		Allowed: true, LocallyVerified: true, Status: edgepublish.EntitlementStatusValid,
		LeaseSerial: 1, EvaluatedAt: testClock,
	}, nil
}

type integrationFixture struct {
	pool             *pgxpool.Pool
	handler          http.Handler
	queryTrace       *integrationQueryTrace
	publisherClock   *integrationAuthClock
	tenantScopeID    uuid.UUID
	tenantUserID     uuid.UUID
	tenantRoleID     uuid.UUID
	platformScope    uuid.UUID
	platformUserID   uuid.UUID
	platformRoleID   uuid.UUID
	adminSessionID   uuid.UUID
	adminToken       string
	tenantToken      string
	tenantAPIKey     string
	unknownToken     string
	crossTenantToken string
	nodeID           uuid.UUID
}

type integrationAuthClock struct {
	mu  sync.Mutex
	now time.Time
}

type integrationQueryTraceKey struct{}

type integrationQueryTrace struct {
	mu      sync.Mutex
	queries map[string][]string
}

func (trace *integrationQueryTrace) TraceQueryStart(
	ctx context.Context,
	_ *pgx.Conn,
	data pgx.TraceQueryStartData,
) context.Context {
	traceID, _ := ctx.Value(integrationQueryTraceKey{}).(string)
	if traceID == "" {
		return ctx
	}
	query := strings.ToLower(strings.Join(strings.Fields(data.SQL), " "))
	trace.mu.Lock()
	defer trace.mu.Unlock()
	if trace.queries == nil {
		trace.queries = make(map[string][]string)
	}
	trace.queries[traceID] = append(trace.queries[traceID], query)
	return ctx
}

func (*integrationQueryTrace) TraceQueryEnd(context.Context, *pgx.Conn, pgx.TraceQueryEndData) {}

func (trace *integrationQueryTrace) snapshot(traceID string) []string {
	trace.mu.Lock()
	defer trace.mu.Unlock()
	return append([]string(nil), trace.queries[traceID]...)
}

func (clock *integrationAuthClock) Now() time.Time {
	clock.mu.Lock()
	defer clock.mu.Unlock()
	return clock.now
}

func (clock *integrationAuthClock) Set(now time.Time) {
	clock.mu.Lock()
	defer clock.mu.Unlock()
	clock.now = now
}

func TestEdgePublishPackageSmoke(t *testing.T) {
	fixture := newIntegrationFixture(t)
	sourceResponse := performAuthorizedGET(fixture.handler,
		"/v1/admin/site-publications?scope_id="+fixture.tenantScopeID.String(), "Bearer "+fixture.adminToken)
	if sourceResponse.Code != http.StatusOK {
		t.Fatalf("read publication source revision status=%d body=%s", sourceResponse.Code, sourceResponse.Body.String())
	}
	var sourcePage struct {
		CurrentSourceRevision int64 `json:"current_source_revision"`
	}
	if err := json.Unmarshal(sourceResponse.Body.Bytes(), &sourcePage); err != nil {
		t.Fatal(err)
	}
	if sourcePage.CurrentSourceRevision <= 0 {
		t.Fatalf("publication source revision=%d", sourcePage.CurrentSourceRevision)
	}
	revision := sourcePage.CurrentSourceRevision
	body := validPublishBody(fixture.tenantScopeID, []uuid.UUID{fixture.nodeID})
	body["expected_source_revision"] = revision

	missingIdempotency := newRequest(t, http.MethodPost, "/v1/admin/site-publications", fixture.adminToken, body, true)
	missingIdempotency.Header.Del("Idempotency-Key")
	missingIdempotencyResponse := httptest.NewRecorder()
	fixture.handler.ServeHTTP(missingIdempotencyResponse, missingIdempotency)
	assertAPIError(t, missingIdempotencyResponse, http.StatusBadRequest, "validation_error")
	fixture.assertNoPublishFacts(t)

	unknownSession := performRequest(fixture.handler, http.MethodPost,
		"/v1/admin/site-publications", fixture.unknownToken, body, true)
	assertAPIError(t, unknownSession, http.StatusUnauthorized, "authentication_required")
	fixture.assertNoPublishFacts(t)

	crossTenant := performRequest(fixture.handler, http.MethodPost,
		"/v1/admin/site-publications", fixture.crossTenantToken, body, true)
	assertAPIError(t, crossTenant, http.StatusForbidden, "permission_denied")
	fixture.assertNoPublishFacts(t)

	fixture.setManagePermission(t, false)
	revokedPermission := performRequest(fixture.handler, http.MethodPost,
		"/v1/admin/site-publications", fixture.adminToken, body, true)
	assertAPIError(t, revokedPermission, http.StatusForbidden, "permission_denied")
	fixture.assertNoPublishFacts(t)
	fixture.setManagePermission(t, true)
	fixture.assertSessionRevokedBetweenAuthenticationAndWrite(t, body)
	fixture.assertBoundedPoolCancellation(t, body)

	if _, err := fixture.pool.Exec(context.Background(),
		`ALTER TABLE edge_configuration_scopes RENAME TO edge_configuration_scopes_smoke_unavailable`); err != nil {
		t.Fatal(err)
	}
	tableRenamed := true
	t.Cleanup(func() {
		if tableRenamed {
			_, _ = fixture.pool.Exec(context.Background(),
				`ALTER TABLE edge_configuration_scopes_smoke_unavailable RENAME TO edge_configuration_scopes`)
		}
	})
	storageFailure := performRequest(fixture.handler, http.MethodPost,
		"/v1/admin/site-publications", fixture.adminToken, body, true)
	assertAPIError(t, storageFailure, http.StatusServiceUnavailable, "publication_service_unavailable")
	for _, leaked := range []string{"sqlstate", "edge_configuration_scopes", "42p01"} {
		if strings.Contains(strings.ToLower(storageFailure.Body.String()), leaked) {
			t.Fatalf("storage error leaked %q: %s", leaked, storageFailure.Body.String())
		}
	}
	if _, err := fixture.pool.Exec(context.Background(),
		`ALTER TABLE edge_configuration_scopes_smoke_unavailable RENAME TO edge_configuration_scopes`); err != nil {
		t.Fatal(err)
	}
	tableRenamed = false
	fixture.assertNoPublishFacts(t)

	createdRequest := newRequest(t, http.MethodPost, "/v1/admin/site-publications", fixture.adminToken, body, true)
	createdRequest.Header.Set("X-Task-ID", "edgepublish-package-smoke")
	wantRequestID := createdRequest.Header.Get("X-Request-ID")
	wantCorrelationID := createdRequest.Header.Get("X-Correlation-ID")
	createdResponse := httptest.NewRecorder()
	fixture.handler.ServeHTTP(createdResponse, createdRequest)
	if createdResponse.Code != http.StatusCreated {
		t.Fatalf("publish status=%d body=%s", createdResponse.Code, createdResponse.Body.String())
	}
	var publication PublicationView
	if err := json.Unmarshal(createdResponse.Body.Bytes(), &publication); err != nil {
		t.Fatal(err)
	}
	if publication.ConfigurationScopeID == nil || *publication.ConfigurationScopeID != fixture.tenantScopeID ||
		publication.SourceRevision != revision || publication.NodeCount != 1 || publication.Target.Kind != TargetNodes {
		t.Fatalf("publication=%+v", publication)
	}
	tenantRoutes := []string{
		"/v1/site-publications?limit=1",
		"/v1/site-publications/" + publication.ID.String(),
		"/v1/site-rollouts?limit=1",
		"/v1/site-rollouts/" + publication.RolloutID.String(),
		"/v1/site-rollouts/" + publication.RolloutID.String() + "/deployments?limit=1",
	}
	for _, target := range tenantRoutes {
		response := performAuthorizedGET(fixture.handler, target, "Bearer "+fixture.tenantToken)
		if response.Code != http.StatusOK {
			t.Fatalf("tenant route %s status=%d body=%s", target, response.Code, response.Body.String())
		}
		apiKeyResponse := performAuthorizedGET(fixture.handler, target, "CdncaKey "+fixture.tenantAPIKey)
		if apiKeyResponse.Code != http.StatusOK {
			t.Fatalf("tenant API key route %s status=%d body=%s", target,
				apiKeyResponse.Code, apiKeyResponse.Body.String())
		}
	}
	fixture.assertRevokedBetweenAuthenticationAndRead(t, "Bearer "+fixture.tenantToken, tenantRoutes[0])
	fixture.assertRevokedBetweenAuthenticationAndRead(t, "CdncaKey "+fixture.tenantAPIKey, tenantRoutes[0])
	crossGet := performAuthorizedGET(fixture.handler, tenantRoutes[1],
		"Bearer "+fixture.crossTenantToken)
	assertAPIError(t, crossGet, http.StatusNotFound, "publication_resource_not_found")
	crossList := performAuthorizedGET(fixture.handler, tenantRoutes[0],
		"Bearer "+fixture.crossTenantToken)
	if crossList.Code != http.StatusOK || strings.Contains(crossList.Body.String(), publication.ID.String()) {
		t.Fatalf("cross-tenant list status=%d body=%s", crossList.Code, crossList.Body.String())
	}

	replay := performRequest(fixture.handler, http.MethodPost,
		"/v1/admin/site-publications", fixture.adminToken, body, true)
	if replay.Code != http.StatusCreated || replay.Header().Get("Idempotency-Replayed") != "true" {
		t.Fatalf("publish replay status=%d headers=%v body=%s", replay.Code, replay.Header(), replay.Body.String())
	}
	changedBody := validPublishBody(fixture.tenantScopeID, []uuid.UUID{fixture.nodeID})
	changedBody["expected_source_revision"] = revision
	changedBody["max_attempts"] = uint32(4)
	changed := performRequest(fixture.handler, http.MethodPost,
		"/v1/admin/site-publications", fixture.adminToken, changedBody, true)
	assertAPIError(t, changed, http.StatusConflict, "idempotency_conflict")

	adminList := performRequest(fixture.handler, http.MethodGet,
		"/v1/admin/site-publications?scope_id="+fixture.tenantScopeID.String()+"&limit=1",
		fixture.adminToken, nil, false)
	if adminList.Code != http.StatusOK || !strings.Contains(adminList.Body.String(), publication.ID.String()) {
		t.Fatalf("admin publication list status=%d body=%s", adminList.Code, adminList.Body.String())
	}
	tenantList := performRequest(fixture.handler, http.MethodGet,
		"/v1/site-publications?limit=1", fixture.tenantToken, nil, false)
	if tenantList.Code != http.StatusOK || !strings.Contains(tenantList.Body.String(), publication.ID.String()) {
		t.Fatalf("tenant publication list status=%d body=%s", tenantList.Code, tenantList.Body.String())
	}
	assertJSONOmits(t, tenantList.Body.Bytes(), "configuration_scope_id", "canonical_source_sha256",
		"artifact_sha256", "snapshot_id", "revision", "resolver_sha256", "resolved_sha256")

	tenantRollout := performRequest(fixture.handler, http.MethodGet,
		"/v1/site-rollouts/"+publication.RolloutID.String(), fixture.tenantToken, nil, false)
	if tenantRollout.Code != http.StatusOK {
		t.Fatalf("tenant rollout status=%d body=%s", tenantRollout.Code, tenantRollout.Body.String())
	}
	assertJSONOmits(t, tenantRollout.Body.Bytes(), "configuration_scope_id")
	tenantDeployments := performRequest(fixture.handler, http.MethodGet,
		"/v1/site-rollouts/"+publication.RolloutID.String()+"/deployments?limit=1",
		fixture.tenantToken, nil, false)
	if tenantDeployments.Code != http.StatusOK {
		t.Fatalf("tenant deployments status=%d body=%s", tenantDeployments.Code, tenantDeployments.Body.String())
	}
	assertJSONOmits(t, tenantDeployments.Body.Bytes(), "node_id")

	adminRollout := performRequest(fixture.handler, http.MethodGet,
		"/v1/admin/site-rollouts/"+publication.RolloutID.String()+"?scope_id="+fixture.tenantScopeID.String(),
		fixture.adminToken, nil, false)
	if adminRollout.Code != http.StatusOK {
		t.Fatalf("admin rollout status=%d body=%s", adminRollout.Code, adminRollout.Body.String())
	}
	var rollout RolloutView
	if err := json.Unmarshal(adminRollout.Body.Bytes(), &rollout); err != nil {
		t.Fatal(err)
	}
	if rollout.State != edgedeployment.RolloutStateQueued || !rollout.CanCancel {
		t.Fatalf("queued rollout=%+v", rollout)
	}
	fixture.assertPersistedFacts(t, publication, wantRequestID, wantCorrelationID, "edgepublish-package-smoke")
	commandBody := map[string]any{
		"configuration_scope_id": fixture.tenantScopeID.String(),
		"expected_revision":      rollout.Revision,
	}
	fixture.setManagePermission(t, false)
	denied := newRequest(t, http.MethodPost,
		"/v1/admin/site-rollouts/"+publication.RolloutID.String()+"/cancel",
		fixture.adminToken, commandBody, true)
	denied.Header.Set("Idempotency-Key", "cancel-after-revocation")
	deniedResponse := httptest.NewRecorder()
	fixture.handler.ServeHTTP(deniedResponse, denied)
	assertAPIError(t, deniedResponse, http.StatusForbidden, "permission_denied")
	fixture.assertNoRolloutCommandFacts(t, publication.RolloutID)
	fixture.setManagePermission(t, true)

	cancelRequest := newRequest(t, http.MethodPost,
		"/v1/admin/site-rollouts/"+publication.RolloutID.String()+"/cancel",
		fixture.adminToken, commandBody, true)
	cancelRequest.Header.Set("Idempotency-Key", "cancel-publication-rollout")
	cancelRequest.Header.Set("X-Task-ID", "edgepublish-cancel-smoke")
	cancelled := httptest.NewRecorder()
	fixture.handler.ServeHTTP(cancelled, cancelRequest)
	if cancelled.Code != http.StatusOK || !strings.Contains(cancelled.Body.String(), `"state":"cancelled"`) {
		t.Fatalf("cancel status=%d body=%s", cancelled.Code, cancelled.Body)
	}
	cancelReplay := newRequest(t, http.MethodPost,
		"/v1/admin/site-rollouts/"+publication.RolloutID.String()+"/cancel",
		fixture.adminToken, commandBody, true)
	cancelReplay.Header.Set("Idempotency-Key", "cancel-publication-rollout")
	cancelReplay.Header.Set("X-Task-ID", "edgepublish-cancel-smoke")
	replayResponse := httptest.NewRecorder()
	fixture.handler.ServeHTTP(replayResponse, cancelReplay)
	if replayResponse.Code != http.StatusOK || replayResponse.Header().Get("Idempotency-Replayed") != "true" {
		t.Fatalf("cancel replay status=%d headers=%v body=%s", replayResponse.Code,
			replayResponse.Header(), replayResponse.Body)
	}
	conflictBody := map[string]any{
		"configuration_scope_id": fixture.tenantScopeID.String(),
		"expected_revision":      rollout.Revision + 1,
	}
	conflict := newRequest(t, http.MethodPost,
		"/v1/admin/site-rollouts/"+publication.RolloutID.String()+"/cancel",
		fixture.adminToken, conflictBody, true)
	conflict.Header.Set("Idempotency-Key", "cancel-publication-rollout")
	conflictResponse := httptest.NewRecorder()
	fixture.handler.ServeHTTP(conflictResponse, conflict)
	assertAPIError(t, conflictResponse, http.StatusConflict, "idempotency_conflict")

	commandBody["expected_revision"] = rollout.Revision + 1
	retried := performRequest(fixture.handler, http.MethodPost,
		"/v1/admin/site-rollouts/"+publication.RolloutID.String()+"/retry-failed",
		fixture.adminToken, commandBody, true)
	assertAPIError(t, retried, http.StatusConflict, "publication_state_conflict")
	fixture.assertCancelledRolloutFacts(t, publication.RolloutID)
}

func TestHTTPPublishReplayAfterDeadline(t *testing.T) {
	tests := []struct {
		name   string
		target string
		token  func(*integrationFixture) string
	}{
		{name: "admin", target: "/v1/admin/site-publications", token: func(f *integrationFixture) string { return f.adminToken }},
		{name: "tenant", target: "/v1/site-publications", token: func(f *integrationFixture) string { return f.tenantToken }},
	}
	for _, test := range tests {
		t.Run(test.name, func(t *testing.T) {
			fixture := newIntegrationFixture(t)
			deadline := testClock.Add(time.Minute)
			body := validPublishBody(fixture.tenantScopeID, []uuid.UUID{fixture.nodeID})
			body["expected_source_revision"] = fixture.sourceRevision(t)
			body["deadline"] = deadline.Format(time.RFC3339Nano)
			key := "http-publish-expired-replay-" + test.name

			created := newRequest(t, http.MethodPost, test.target, test.token(fixture), body, true)
			created.Header.Set("Idempotency-Key", key)
			createdResponse := httptest.NewRecorder()
			fixture.handler.ServeHTTP(createdResponse, created)
			if createdResponse.Code != http.StatusCreated || createdResponse.Header().Get("Idempotency-Replayed") != "" {
				t.Fatalf("publish status=%d headers=%v body=%s", createdResponse.Code,
					createdResponse.Header(), createdResponse.Body.String())
			}
			var first PublicationView
			if err := json.Unmarshal(createdResponse.Body.Bytes(), &first); err != nil {
				t.Fatal(err)
			}
			wantFacts := fixture.publicationWriteSnapshot(t)
			fixture.publisherClock.Set(deadline)

			fresh := newRequest(t, http.MethodPost, test.target, test.token(fixture), body, true)
			fresh.Header.Set("Idempotency-Key", key+"-new")
			freshResponse := httptest.NewRecorder()
			fixture.handler.ServeHTTP(freshResponse, fresh)
			assertAPIError(t, freshResponse, http.StatusBadRequest, "validation_error")
			fixture.assertPublicationWriteSnapshot(t, wantFacts)

			replay := newRequest(t, http.MethodPost, test.target, test.token(fixture), body, true)
			replay.Header.Set("Idempotency-Key", key)
			replayResponse := httptest.NewRecorder()
			fixture.handler.ServeHTTP(replayResponse, replay)
			if replayResponse.Code != http.StatusCreated || replayResponse.Header().Get("Idempotency-Replayed") != "true" {
				t.Fatalf("expired publish replay status=%d headers=%v body=%s", replayResponse.Code,
					replayResponse.Header(), replayResponse.Body.String())
			}
			var replayed PublicationView
			if err := json.Unmarshal(replayResponse.Body.Bytes(), &replayed); err != nil {
				t.Fatal(err)
			}
			if replayed.ID != first.ID || replayed.RolloutID != first.RolloutID || !replayed.Replayed {
				t.Fatalf("expired publish replay=%+v first=%+v", replayed, first)
			}
			fixture.assertPublicationWriteSnapshot(t, wantFacts)

			conflictBody := mutateBody(body, "max_attempts", uint32(4))
			conflict := newRequest(t, http.MethodPost, test.target, test.token(fixture), conflictBody, true)
			conflict.Header.Set("Idempotency-Key", key)
			conflictResponse := httptest.NewRecorder()
			fixture.handler.ServeHTTP(conflictResponse, conflict)
			assertAPIError(t, conflictResponse, http.StatusConflict, "idempotency_conflict")
			fixture.assertPublicationWriteSnapshot(t, wantFacts)
		})
	}
}

func TestHTTPRollbackReplayAfterDeadline(t *testing.T) {
	fixture := newIntegrationFixture(t)
	deadline := testClock.Add(time.Minute)
	publish := func(key string) PublicationView {
		t.Helper()
		body := validPublishBody(fixture.tenantScopeID, []uuid.UUID{fixture.nodeID})
		body["expected_source_revision"] = fixture.sourceRevision(t)
		body["deadline"] = deadline.Format(time.RFC3339Nano)
		request := newRequest(t, http.MethodPost, "/v1/admin/site-publications", fixture.adminToken, body, true)
		request.Header.Set("Idempotency-Key", key)
		response := httptest.NewRecorder()
		fixture.handler.ServeHTTP(response, request)
		if response.Code != http.StatusCreated {
			t.Fatalf("publish %q status=%d body=%s", key, response.Code, response.Body.String())
		}
		var result PublicationView
		if err := json.Unmarshal(response.Body.Bytes(), &result); err != nil {
			t.Fatal(err)
		}
		return result
	}

	first := publish("http-rollback-first")
	fixture.finishPublishDeployment(t, first, &first.ConfigVersionID, nil)
	if _, err := fixture.pool.Exec(t.Context(), `UPDATE sites
		SET revision=revision+1,updated_at=$2 WHERE scope_id=$1`, fixture.tenantScopeID, testClock); err != nil {
		t.Fatal(err)
	}
	second := publish("http-rollback-second")
	fixture.finishPublishDeployment(t, second, &second.ConfigVersionID, &first.ConfigVersionID)

	body := validRollbackBody(fixture.tenantScopeID, []uuid.UUID{fixture.nodeID})
	body["deadline"] = deadline.Format(time.RFC3339Nano)
	target := "/v1/admin/site-publications/" + first.ID.String() + "/rollback"
	key := "http-rollback-expired-replay"
	request := newRequest(t, http.MethodPost, target, fixture.adminToken, body, true)
	request.Header.Set("Idempotency-Key", key)
	response := httptest.NewRecorder()
	fixture.handler.ServeHTTP(response, request)
	if response.Code != http.StatusCreated || response.Header().Get("Idempotency-Replayed") != "" {
		t.Fatalf("rollback status=%d headers=%v body=%s", response.Code, response.Header(), response.Body.String())
	}
	var firstRollback RollbackView
	if err := json.Unmarshal(response.Body.Bytes(), &firstRollback); err != nil {
		t.Fatal(err)
	}
	wantFacts := fixture.publicationWriteSnapshot(t)
	fixture.publisherClock.Set(deadline)

	fresh := newRequest(t, http.MethodPost, target, fixture.adminToken, body, true)
	fresh.Header.Set("Idempotency-Key", key+"-new")
	freshResponse := httptest.NewRecorder()
	fixture.handler.ServeHTTP(freshResponse, fresh)
	assertAPIError(t, freshResponse, http.StatusBadRequest, "validation_error")
	fixture.assertPublicationWriteSnapshot(t, wantFacts)

	replay := newRequest(t, http.MethodPost, target, fixture.adminToken, body, true)
	replay.Header.Set("Idempotency-Key", key)
	for _, name := range []string{"X-Request-ID", "X-Correlation-ID", "Traceparent"} {
		replay.Header.Set(name, request.Header.Get(name))
	}
	replayResponse := httptest.NewRecorder()
	fixture.handler.ServeHTTP(replayResponse, replay)
	if replayResponse.Code != http.StatusCreated || replayResponse.Header().Get("Idempotency-Replayed") != "true" {
		t.Fatalf("expired rollback replay status=%d headers=%v body=%s", replayResponse.Code,
			replayResponse.Header(), replayResponse.Body.String())
	}
	var replayed RollbackView
	if err := json.Unmarshal(replayResponse.Body.Bytes(), &replayed); err != nil {
		t.Fatal(err)
	}
	if replayed.RolloutID != firstRollback.RolloutID || replayed.PublicationID != firstRollback.PublicationID || !replayed.Replayed {
		t.Fatalf("expired rollback replay=%+v first=%+v", replayed, firstRollback)
	}
	fixture.assertPublicationWriteSnapshot(t, wantFacts)

	conflictBody := mutateBody(body, "max_attempts", uint32(4))
	conflict := newRequest(t, http.MethodPost, target, fixture.adminToken, conflictBody, true)
	conflict.Header.Set("Idempotency-Key", key)
	for _, name := range []string{"X-Request-ID", "X-Correlation-ID", "Traceparent"} {
		conflict.Header.Set(name, request.Header.Get(name))
	}
	conflictResponse := httptest.NewRecorder()
	fixture.handler.ServeHTTP(conflictResponse, conflict)
	assertAPIError(t, conflictResponse, http.StatusConflict, "idempotency_conflict")
	fixture.assertPublicationWriteSnapshot(t, wantFacts)
}

func TestTenantAPIKeyReadRevocationAfterAuthentication(t *testing.T) {
	fixture := newIntegrationFixture(t)
	body := validPublishBody(fixture.tenantScopeID, []uuid.UUID{fixture.nodeID})
	body["expected_source_revision"] = fixture.sourceRevision(t)
	created := newRequest(t, http.MethodPost, "/v1/admin/site-publications", fixture.adminToken, body, true)
	created.Header.Set("Idempotency-Key", "tenant-api-key-read-revocation")
	createdResponse := httptest.NewRecorder()
	fixture.handler.ServeHTTP(createdResponse, created)
	if createdResponse.Code != http.StatusCreated {
		t.Fatalf("publish status=%d body=%s", createdResponse.Code, createdResponse.Body.String())
	}
	var publication PublicationView
	if err := json.Unmarshal(createdResponse.Body.Bytes(), &publication); err != nil {
		t.Fatal(err)
	}
	routes := []struct {
		name string
		path string
	}{
		{name: "list-publications", path: "/v1/site-publications?limit=1"},
		{name: "get-publication", path: "/v1/site-publications/" + publication.ID.String()},
		{name: "list-rollouts", path: "/v1/site-rollouts?limit=1"},
		{name: "get-rollout", path: "/v1/site-rollouts/" + publication.RolloutID.String()},
		{name: "list-rollout-deployments", path: "/v1/site-rollouts/" + publication.RolloutID.String() + "/deployments?limit=1"},
	}
	for _, route := range routes {
		t.Run(route.name, func(t *testing.T) {
			control := performAuthorizedGET(fixture.handler, route.path, "CdncaKey "+fixture.tenantAPIKey)
			if control.Code != http.StatusOK {
				t.Fatalf("control request status=%d body=%s", control.Code, control.Body.String())
			}
			fixture.assertRevokedBetweenAuthenticationAndRead(
				t, "CdncaKey "+fixture.tenantAPIKey, route.path,
			)
		})
	}
}

func TestSecurityActivationStatusRechecksLiveReadPermission(t *testing.T) {
	fixture := newIntegrationFixture(t)
	if _, err := fixture.pool.Exec(t.Context(), `INSERT INTO role_permissions(role_id,permission_name)
		VALUES($1,'security_policies.read') ON CONFLICT DO NOTHING`, fixture.tenantRoleID); err != nil {
		t.Fatal(err)
	}
	store, err := securityactivation.NewStore(fixture.pool, time.Now)
	if err != nil {
		t.Fatal(err)
	}
	principal := identity.Principal{
		UserID: fixture.tenantUserID, ScopeID: fixture.tenantScopeID, ScopeKind: AudienceTenant,
		Permissions: []string{"security_policies.read"},
	}
	handler, err := NewSecurityActivationHandler(store, func(*http.Request) (AuthenticatedSession, error) {
		return newAuthenticatedSession(principal, uuid.New(), "security-activation-read-cache")
	}, nil)
	if err != nil {
		t.Fatal(err)
	}
	var siteID uuid.UUID
	if err := fixture.pool.QueryRow(t.Context(), `SELECT id FROM sites WHERE scope_id=$1`, fixture.tenantScopeID).Scan(&siteID); err != nil {
		t.Fatal(err)
	}
	target := "/v1/site-publications/security-activations?site_id=" + siteID.String() +
		"&policy_kind=" + securitypolicy.KindWAF
	request := httptest.NewRequest(http.MethodGet, target, nil)
	request.Header.Set("Authorization", "Bearer security-activation-read-cache")
	response := httptest.NewRecorder()
	handler.ServeHTTP(response, request)
	if response.Code != http.StatusOK || response.Body.String() != "{\"binding\":null,\"latest_candidate\":null,\"operation\":null,\"latest_detach\":false}\n" {
		t.Fatalf("empty status=%d body=%s", response.Code, response.Body.String())
	}
	if _, err := fixture.pool.Exec(t.Context(), `DELETE FROM role_assignments
		WHERE scope_id=$1 AND user_id=$2 AND role_id=$3`, fixture.tenantScopeID,
		fixture.tenantUserID, fixture.tenantRoleID); err != nil {
		t.Fatal(err)
	}
	response = httptest.NewRecorder()
	handler.ServeHTTP(response, request)
	assertAPIError(t, response, http.StatusForbidden, "permission_denied")
}

func newIntegrationFixture(t *testing.T) *integrationFixture {
	t.Helper()
	queryTrace := &integrationQueryTrace{}
	pool := openIntegrationDatabase(t, queryTrace)
	tenantScopeID, tenantUserID, platformScopeID, platformAdminID, _, platformRoleID, nodeID :=
		seedIntegrationFacts(t, pool)
	publicKey, privateKey, err := ed25519.GenerateKey(rand.Reader)
	if err != nil {
		t.Fatal(err)
	}
	publisherClock := &integrationAuthClock{now: testClock}
	config := edgepublish.DefaultConfig()
	config.Clock = publisherClock.Now
	config.EntitlementAuthorizer = integrationEntitlement{}
	authClock := &integrationAuthClock{now: time.Now().UTC().Truncate(time.Millisecond)}
	tokens, err := identity.NewTokenManager("edgepublish-http-integration-access-token-secret", time.Hour)
	if err != nil {
		t.Fatal(err)
	}
	identityService, err := identity.NewService(identity.NewStore(pool), tokens, time.Hour)
	if err != nil {
		t.Fatal(err)
	}
	pepper := bytes.Repeat([]byte{0x71}, 32)
	apiKeyService := apikey.NewService(pool, pepper, authClock.Now)
	sessions, err := sessioncredential.NewVerifier(tokens, authClock.Now)
	if err != nil {
		t.Fatal(err)
	}
	apiKeyVerifier, err := apikeycredential.NewVerifier(pepper, authClock.Now)
	if err != nil {
		t.Fatal(err)
	}
	authorizer, err := iamlock.NewAuthorizer(sessions, apiKeyVerifier)
	if err != nil {
		t.Fatal(err)
	}
	publisher, err := edgepublish.NewRuntime(edgepublish.RuntimeConfig{Publisher: config}, edgepublish.RuntimeDependencies{
		Pool: pool, Signer: &integrationSigner{public: publicKey, private: privateKey}, IAM: authorizer,
	})
	if err != nil {
		t.Fatal(err)
	}
	admin := identity.Principal{
		UserID: platformAdminID, ScopeID: platformScopeID, ScopeKind: AudiencePlatform,
		Permissions: []string{edgepublish.PermissionRead, edgepublish.PermissionManage},
	}
	var tenantID uuid.UUID
	if err := pool.QueryRow(t.Context(), `SELECT tenant_id FROM access_scopes WHERE id=$1`, tenantScopeID).Scan(&tenantID); err != nil {
		t.Fatal(err)
	}
	tenant := identity.Principal{
		UserID: tenantUserID, ScopeID: tenantScopeID, ScopeKind: AudienceTenant,
		TenantID: &tenantID, Permissions: []string{tenantReadPermission, "sites.manage", "api_keys.self.manage"},
	}
	issuedAPIKey, err := apiKeyService.CreateSelf(t.Context(), tenant, apikey.CreateInput{
		Name: "site publication integration", Scopes: []string{tenantReadPermission},
		IdempotencyKey: "site-publication-integration-key", RequestID: uuid.NewString(),
	})
	if err != nil {
		t.Fatal(err)
	}
	tenantAPIKey := issuedAPIKey.Key.KeyID + "." + issuedAPIKey.Secret
	newSession := func(principal identity.Principal, persist bool) (uuid.UUID, string) {
		sessionID := uuid.New()
		if persist {
			refreshDigest := sha256.Sum256(sessionID[:])
			if _, err := pool.Exec(context.Background(), `INSERT INTO auth_sessions(
				id,family_id,user_id,scope_id,refresh_token_hash,created_at,expires_at
			) VALUES($1,$2,$3,$4,$5,$6,$7)`, sessionID, uuid.New(), principal.UserID,
				principal.ScopeID, refreshDigest[:], authClock.Now().Add(-time.Minute), authClock.Now().Add(time.Hour)); err != nil {
				t.Fatal(err)
			}
		}
		rawToken, _, err := tokens.Mint(principal.UserID, principal.ScopeID, sessionID)
		if err != nil {
			t.Fatal(err)
		}
		return sessionID, rawToken
	}
	adminSessionID, adminToken := newSession(admin, true)
	_, tenantToken := newSession(tenant, true)
	_, unknownToken := newSession(admin, false)
	crossTenant := seedCrossTenantReader(t, pool)
	_, crossTenantToken := newSession(crossTenant, true)
	handler, err := NewRuntimeHandler(RuntimeConfig{
		Enabled:         true,
		CursorActiveKey: CursorKey{ID: "integration-active", Secret: []byte("integration-cursor-key-32-bytes!!")},
	}, RuntimeDependencies{
		Pool: pool, Identity: identityService, APIKeys: apiKeyService, IAM: authorizer, Publisher: publisher,
	})
	if err != nil {
		t.Fatal(err)
	}
	var tenantRoleID uuid.UUID
	if err := pool.QueryRow(t.Context(), `SELECT id FROM roles
		WHERE scope_id=$1 AND name='http_tenant_reader'`, tenantScopeID).Scan(&tenantRoleID); err != nil {
		t.Fatal(err)
	}
	fixture := &integrationFixture{
		pool: pool, handler: handler, queryTrace: queryTrace, publisherClock: publisherClock,
		tenantScopeID: tenantScopeID, tenantUserID: tenantUserID, tenantRoleID: tenantRoleID,
		platformScope:  platformScopeID,
		tenantAPIKey:   tenantAPIKey,
		platformUserID: platformAdminID, platformRoleID: platformRoleID,
		adminSessionID: adminSessionID, adminToken: adminToken, tenantToken: tenantToken,
		unknownToken: unknownToken, crossTenantToken: crossTenantToken, nodeID: nodeID,
	}
	return fixture
}

func openIntegrationDatabase(t *testing.T, queryTrace *integrationQueryTrace) *pgxpool.Pool {
	t.Helper()
	databaseURL := os.Getenv("TEST_DATABASE_URL")
	if databaseURL == "" {
		t.Skip("TEST_DATABASE_URL is not set")
	}
	ctx := context.Background()
	admin, err := pgxpool.New(ctx, databaseURL)
	if err != nil {
		t.Fatal(err)
	}
	if err := admin.Ping(ctx); err != nil {
		admin.Close()
		t.Fatal(err)
	}
	schema := "edge_publish_http_test_" + strings.ReplaceAll(uuid.NewString(), "-", "")
	if !regexp.MustCompile(`^edge_publish_http_test_[a-f0-9]{32}$`).MatchString(schema) {
		t.Fatalf("unsafe schema name %q", schema)
	}
	identifier := pgx.Identifier{schema}.Sanitize()
	if _, err := admin.Exec(ctx, "CREATE SCHEMA "+identifier); err != nil {
		admin.Close()
		t.Fatal(err)
	}
	config, err := pgxpool.ParseConfig(databaseURL)
	if err != nil {
		admin.Close()
		t.Fatal(err)
	}
	config.ConnConfig.RuntimeParams["search_path"] = schema
	config.ConnConfig.Tracer = queryTrace
	config.MaxConns = 4
	pool, err := pgxpool.NewWithConfig(ctx, config)
	if err != nil {
		admin.Close()
		t.Fatal(err)
	}
	t.Cleanup(func() {
		pool.Close()
		if _, err := admin.Exec(context.Background(), "DROP SCHEMA "+identifier+" CASCADE"); err != nil {
			t.Errorf("drop edge publication HTTP schema: %v", err)
		}
		admin.Close()
	})
	if err := database.Migrate(ctx, pool, "up"); err != nil {
		t.Fatal(err)
	}
	return pool
}

func seedIntegrationFacts(
	t *testing.T,
	pool *pgxpool.Pool,
) (tenantScopeID, tenantUserID, platformScopeID, platformAdminID, platformReaderID, platformRoleID, nodeID uuid.UUID) {
	t.Helper()
	tenantID := uuid.New()
	tenantScopeID, tenantUserID = uuid.New(), uuid.New()
	platformScopeID, platformAdminID, platformReaderID = uuid.New(), uuid.New(), uuid.New()
	platformRoleID = uuid.New()
	readerRoleID, tenantRoleID, tenantAuxRoleID := uuid.New(), uuid.New(), uuid.New()
	siteID := uuid.New()
	nodeID = uuid.New()
	ctx := context.Background()
	err := pgx.BeginFunc(ctx, pool, func(tx pgx.Tx) error {
		statements := []struct {
			sql  string
			args []any
		}{
			{`INSERT INTO control_installation_entitlement(singleton,installation_id,last_status)
				VALUES(true,$1,'uninstalled')`, []any{uuid.NewString()}},
			{`INSERT INTO tenants (id,display_name) VALUES ($1,'HTTP publication tenant')`, []any{tenantID}},
			{`INSERT INTO access_scopes (id,kind,tenant_id) VALUES ($1,'tenant',$2),($3,'platform',NULL)`, []any{tenantScopeID, tenantID, platformScopeID}},
			{`INSERT INTO users (id,username,display_name,password_hash) VALUES
				($1,$2,'HTTP tenant user','not-used'),
				($3,$4,'HTTP platform admin','not-used'),
				($5,$6,'HTTP platform reader','not-used')`, []any{
				tenantUserID, "http-tenant-" + compactID(tenantUserID),
				platformAdminID, "http-admin-" + compactID(platformAdminID),
				platformReaderID, "http-reader-" + compactID(platformReaderID),
			}},
			{`INSERT INTO memberships (scope_id,user_id) VALUES ($1,$2),($3,$4),($3,$5)`, []any{tenantScopeID, tenantUserID, platformScopeID, platformAdminID, platformReaderID}},
			{`INSERT INTO roles (id,scope_id,name,system_role) VALUES
					($1,$2,'http_admin',true),($3,$2,'http_reader',true),
					($4,$5,'http_tenant_reader',true),($6,$5,'http_tenant_aux',true)`,
				[]any{platformRoleID, platformScopeID, readerRoleID, tenantRoleID, tenantScopeID, tenantAuxRoleID}},
			{`INSERT INTO role_permissions (role_id,permission_name) VALUES
					($1,'edge_publications.read'),($1,'edge_publications.manage'),
					($2,'edge_publications.read'),($3,'sites.read'),($3,'api_keys.self.manage'),
					($4,'sites.manage')`, []any{platformRoleID, readerRoleID, tenantRoleID, tenantAuxRoleID}},
			{`INSERT INTO role_assignments (scope_id,user_id,role_id) VALUES
				($1,$2,$3),($1,$4,$5),($6,$7,$8),($6,$7,$9)`,
				[]any{platformScopeID, platformAdminID, platformRoleID, platformReaderID, readerRoleID,
					tenantScopeID, tenantUserID, tenantRoleID, tenantAuxRoleID}},
			{`INSERT INTO sites (
				id,display_id,scope_id,owner_user_id,domain,http_ports,origins,origin_hosts,
				created_by_user_id,updated_by_user_id
			) VALUES ($1,1,$2,$3,'http-publication.example',ARRAY['80'],
				ARRAY['203.0.113.10:8080'],ARRAY['203.0.113.10'],$3,$3)`, []any{siteID, tenantScopeID, tenantUserID}},
			{`INSERT INTO site_origin_pools (site_id) VALUES ($1)`, []any{siteID}},
			{`INSERT INTO site_origins (site_id,position,host,port,weight,enabled)
				VALUES ($1,1,'203.0.113.10',8080,1,true)`, []any{siteID}},
			{`INSERT INTO nodes (id,display_id,scope_id,name,admin_state,created_by_user_id,created_at,updated_at)
				VALUES ($1,1,$2,'http-publication-node','active',$3,$4,$4)`,
				[]any{nodeID, tenantScopeID, tenantUserID, testClock.Add(-20 * time.Minute)}},
		}
		for _, statement := range statements {
			if _, err := tx.Exec(ctx, statement.sql, statement.args...); err != nil {
				return err
			}
		}
		return nil
	})
	if err != nil {
		t.Fatal(err)
	}
	// The HTTP API never chooses a site runtime: publications are the
	// default, v2, which needs the node's issued identity and capabilities.
	capabilitytest.SeedNodePublicationIdentityForTest(t, pool, tenantScopeID, tenantUserID, nodeID,
		&agentv1.AgentCapabilities{AgentVersion: "1.0.35", BuildId: "http-publication", OperatingSystem: "linux",
			Architecture: "amd64", Features: httpPublicationNodeFeatures()}, testClock.Add(-10*time.Minute), true)
	return tenantScopeID, tenantUserID, platformScopeID, platformAdminID, platformReaderID, platformRoleID, nodeID
}

// httpPublicationNodeFeatures is what a 1.0.35 edge agent declares.
func httpPublicationNodeFeatures() []*agentv1.Capability {
	features := []*agentv1.Capability{}
	for name, version := range map[agentv1.CapabilityName]uint32{
		agentv1.CapabilityName_CAPABILITY_NAME_HTTP_1_1: 1, agentv1.CapabilityName_CAPABILITY_NAME_HTTP_2: 1,
		agentv1.CapabilityName_CAPABILITY_NAME_SITE_QUIC: 1, agentv1.CapabilityName_CAPABILITY_NAME_WEBSOCKET: 1,
		agentv1.CapabilityName_CAPABILITY_NAME_IPV4: 1, agentv1.CapabilityName_CAPABILITY_NAME_IPV6: 1,
		agentv1.CapabilityName_CAPABILITY_NAME_SITE_RUNTIME:   edgeconfig.MaxSiteRuntimeVersion,
		agentv1.CapabilityName_CAPABILITY_NAME_ATOMIC_RELEASE: 1, agentv1.CapabilityName_CAPABILITY_NAME_CONFIG_PRECHECK: 1,
	} {
		features = append(features, &agentv1.Capability{Name: name, ApiVersion: version})
	}
	return features
}

func (f *integrationFixture) sourceRevision(t *testing.T) int64 {
	t.Helper()
	var revision int64
	if err := f.pool.QueryRow(context.Background(),
		`SELECT source_revision FROM edge_configuration_scopes WHERE scope_id=$1`, f.tenantScopeID).Scan(&revision); err != nil {
		t.Fatal(err)
	}
	return revision
}

type publicationWriteFacts struct {
	configs      int
	publications int
	rollouts     int
	deployments  int
	outbox       int
	audits       int
}

func (f *integrationFixture) publicationWriteSnapshot(t *testing.T) publicationWriteFacts {
	t.Helper()
	var result publicationWriteFacts
	if err := f.pool.QueryRow(t.Context(), `SELECT
		(SELECT count(*) FROM config_versions WHERE configuration_scope_id=$1),
		(SELECT count(*) FROM edge_config_publications WHERE configuration_scope_id=$1),
		(SELECT count(*) FROM rollouts WHERE configuration_scope_id=$1),
		(SELECT count(*) FROM node_deployments deployment
		 JOIN rollouts rollout ON rollout.id=deployment.rollout_id
		 WHERE rollout.configuration_scope_id=$1),
		(SELECT count(*) FROM edge_command_outbox outbox
		 JOIN node_deployments deployment ON deployment.id=outbox.deployment_id
		 JOIN rollouts rollout ON rollout.id=deployment.rollout_id
		 WHERE rollout.configuration_scope_id=$1),
		(SELECT count(*) FROM audit_events)`, f.tenantScopeID).Scan(
		&result.configs, &result.publications, &result.rollouts,
		&result.deployments, &result.outbox, &result.audits); err != nil {
		t.Fatal(err)
	}
	return result
}

func (f *integrationFixture) assertPublicationWriteSnapshot(t *testing.T, want publicationWriteFacts) {
	t.Helper()
	if got := f.publicationWriteSnapshot(t); got != want {
		t.Fatalf("publication write facts=%+v, want %+v", got, want)
	}
}

func (f *integrationFixture) finishPublishDeployment(
	t *testing.T,
	publication PublicationView,
	current, previous *uuid.UUID,
) {
	t.Helper()
	var deploymentID uuid.UUID
	var attempt int
	var transitionSequence int64
	if err := f.pool.QueryRow(t.Context(), `
		SELECT deployment.id,deployment.attempt,COALESCE(max(event.transition_sequence),0)
		FROM node_deployments deployment
		LEFT JOIN deployment_status_events event
		  ON event.deployment_id=deployment.id AND event.attempt=deployment.attempt
		WHERE deployment.rollout_id=$1 AND deployment.node_id=$2
		GROUP BY deployment.id,deployment.attempt`, publication.RolloutID, f.nodeID).Scan(
		&deploymentID, &attempt, &transitionSequence); err != nil {
		t.Fatal(err)
	}
	now := f.publisherClock.Now()
	for index, state := range []string{"delivered", "staged", "prechecked", "activated", "healthy"} {
		transitionSequence++
		at := now.Add(time.Duration(index+1) * time.Second)
		payload := []byte("edge-publish-http-status-" + state)
		digest := sha256.Sum256(payload)
		if err := pgx.BeginFunc(t.Context(), f.pool, func(tx pgx.Tx) error {
			if _, err := tx.Exec(t.Context(), `INSERT INTO deployment_status_events(
				id,deployment_id,event_id,attempt,transition_sequence,state,payload,payload_sha256,occurred_at,received_at)
				VALUES($1,$2,$3,$4,$5,$6,$7,$8,$9,$9)`, uuid.New(), deploymentID, uuid.New(), attempt,
				transitionSequence, state, payload, digest[:], at); err != nil {
				return err
			}
			_, err := tx.Exec(t.Context(), `UPDATE node_deployments SET state=$2,updated_at=$3
				WHERE id=$1 AND attempt=$4`, deploymentID, state, at, attempt)
			return err
		}); err != nil {
			t.Fatal(err)
		}
	}
	if _, err := f.pool.Exec(t.Context(), `UPDATE node_config_state
		SET configuration_scope_id=$2,current_config_version_id=$3,previous_config_version_id=$4,
		    revision=revision+1,updated_at=$5
		WHERE node_id=$1`, f.nodeID, f.tenantScopeID, current, previous, now); err != nil {
		t.Fatal(err)
	}
}

func (f *integrationFixture) assertRevokedBetweenAuthenticationAndRead(
	t *testing.T,
	authorization, target string,
) {
	t.Helper()
	traceID := uuid.NewString()
	holder, err := f.pool.Begin(t.Context())
	if err != nil {
		t.Fatal(err)
	}
	defer func() { _ = holder.Rollback(context.Background()) }()
	if err := iamlock.AcquireExclusive(t.Context(), holder); err != nil {
		t.Fatal(err)
	}
	if _, err := iamlock.AcquireScopes(t.Context(), holder, []uuid.UUID{f.tenantScopeID}); err != nil {
		t.Fatal(err)
	}
	response := make(chan *httptest.ResponseRecorder, 1)
	go func() {
		response <- performTracedAuthorizedGET(f.handler, target, authorization, traceID)
	}()
	f.waitForIAMSharedWait(t)
	if strings.HasPrefix(authorization, "CdncaKey ") {
		queries := f.queryTrace.snapshot(traceID)
		if !integrationTraceContains(queries, "from api_keys k") {
			t.Fatal("API key request reached the IAM barrier before outer authentication completed")
		}
		if integrationTraceContains(queries, "select id,user_id,scope_id,tenant_id from api_keys where key_id=$1") {
			t.Fatal("transactional API key authorization crossed the IAM barrier before grant revocation")
		}
	}
	deleted, err := holder.Exec(t.Context(), `DELETE FROM role_assignments
		WHERE scope_id=$1 AND user_id=$2 AND role_id=$3`,
		f.tenantScopeID, f.tenantUserID, f.tenantRoleID)
	if err != nil {
		t.Fatal(err)
	}
	if deleted.RowsAffected() != 1 {
		t.Fatalf("revoked tenant read grants=%d, want 1", deleted.RowsAffected())
	}
	if err := holder.Commit(t.Context()); err != nil {
		t.Fatal(err)
	}
	defer func() {
		if err := pgx.BeginFunc(context.Background(), f.pool, func(tx pgx.Tx) error {
			if err := iamlock.AcquireExclusive(context.Background(), tx); err != nil {
				return err
			}
			if _, err := iamlock.AcquireScopes(context.Background(), tx, []uuid.UUID{f.tenantScopeID}); err != nil {
				return err
			}
			restored, err := tx.Exec(context.Background(), `INSERT INTO role_assignments(scope_id,user_id,role_id)
				VALUES($1,$2,$3) ON CONFLICT DO NOTHING`, f.tenantScopeID, f.tenantUserID, f.tenantRoleID)
			if err != nil {
				return err
			}
			if restored.RowsAffected() != 1 {
				return fmt.Errorf("restored tenant read grants=%d, want 1", restored.RowsAffected())
			}
			return nil
		}); err != nil {
			t.Errorf("restore tenant read grant: %v", err)
		}
	}()
	select {
	case result := <-response:
		assertAPIError(t, result, http.StatusForbidden, "permission_denied")
	case <-time.After(5 * time.Second):
		t.Fatal("authorization request did not finish after revocation")
	}
	queries := f.queryTrace.snapshot(traceID)
	if strings.HasPrefix(authorization, "CdncaKey ") &&
		!integrationTraceContains(queries, "select id,user_id,scope_id,tenant_id from api_keys where key_id=$1") {
		t.Fatal("request did not execute transactional API key authorization after grant revocation")
	}
	for _, table := range []string{
		"edge_config_publications", "rollouts", "node_deployments", "deployment_status_events",
	} {
		if integrationTraceContains(queries, "from "+table) || integrationTraceContains(queries, "join "+table) {
			t.Fatalf("revoked request crossed authorization into %s business reads", table)
		}
	}
}

func integrationTraceContains(queries []string, fragment string) bool {
	for _, query := range queries {
		if strings.Contains(query, fragment) {
			return true
		}
	}
	return false
}

func (f *integrationFixture) assertSessionRevokedBetweenAuthenticationAndWrite(
	t *testing.T,
	body map[string]any,
) {
	t.Helper()
	holder, err := f.pool.Begin(t.Context())
	if err != nil {
		t.Fatal(err)
	}
	defer func() { _ = holder.Rollback(context.Background()) }()
	if err := iamlock.AcquireExclusive(t.Context(), holder); err != nil {
		t.Fatal(err)
	}
	if _, err := iamlock.AcquireScopes(t.Context(), holder, []uuid.UUID{f.platformScope, f.tenantScopeID}); err != nil {
		t.Fatal(err)
	}
	response := make(chan *httptest.ResponseRecorder, 1)
	go func() {
		response <- performRequest(f.handler, http.MethodPost,
			"/v1/admin/site-publications", f.adminToken, body, true)
	}()
	f.waitForIAMSharedWait(t)
	if _, err := holder.Exec(t.Context(), `DELETE FROM auth_sessions WHERE id=$1`, f.adminSessionID); err != nil {
		t.Fatal(err)
	}
	if err := holder.Commit(t.Context()); err != nil {
		t.Fatal(err)
	}
	select {
	case result := <-response:
		assertAPIError(t, result, http.StatusUnauthorized, "authentication_required")
	case <-time.After(5 * time.Second):
		t.Fatal("publication request did not finish after session revocation")
	}
	f.assertNoPublishFacts(t)
	refreshDigest := sha256.Sum256(f.adminSessionID[:])
	if _, err := f.pool.Exec(t.Context(), `INSERT INTO auth_sessions(
		id,family_id,user_id,scope_id,refresh_token_hash,created_at,expires_at
	) VALUES($1,$2,$3,$4,$5,$6,$7)`, f.adminSessionID, uuid.New(), f.platformUserID,
		f.platformScope, refreshDigest[:], time.Now().Add(-time.Minute), time.Now().Add(time.Hour)); err != nil {
		t.Fatal(err)
	}
}

func (f *integrationFixture) waitForIAMSharedWait(t *testing.T) {
	t.Helper()
	deadline := time.Now().Add(5 * time.Second)
	for time.Now().Before(deadline) {
		var waiting bool
		if err := f.pool.QueryRow(t.Context(), `SELECT EXISTS (
			SELECT 1 FROM pg_stat_activity
			WHERE pid <> pg_backend_pid() AND state='active' AND wait_event_type='Lock'
			  AND query LIKE '%iam_global_lock_shared_v1%'
		)`).Scan(&waiting); err != nil {
			t.Fatal(err)
		}
		if waiting {
			return
		}
		time.Sleep(10 * time.Millisecond)
	}
	t.Fatal("request did not reach the transactional IAM shared lock")
}

func performAuthorizedGET(handler http.Handler, target, authorization string) *httptest.ResponseRecorder {
	return performTracedAuthorizedGET(handler, target, authorization, "")
}

func performTracedAuthorizedGET(
	handler http.Handler,
	target, authorization, traceID string,
) *httptest.ResponseRecorder {
	request := httptest.NewRequest(http.MethodGet, target, nil)
	if traceID != "" {
		request = request.WithContext(context.WithValue(request.Context(), integrationQueryTraceKey{}, traceID))
	}
	request.Header.Set("Authorization", authorization)
	request.Header.Set("X-Request-ID", uuid.NewString())
	response := httptest.NewRecorder()
	handler.ServeHTTP(response, request)
	return response
}

func seedCrossTenantReader(t *testing.T, pool *pgxpool.Pool) identity.Principal {
	t.Helper()
	tenantID, scopeID, userID, roleID := uuid.New(), uuid.New(), uuid.New(), uuid.New()
	statements := []struct {
		sql  string
		args []any
	}{
		{`INSERT INTO tenants(id,display_name) VALUES($1,'Edge publication other tenant')`, []any{tenantID}},
		{`INSERT INTO access_scopes(id,kind,tenant_id) VALUES($1,'tenant',$2)`, []any{scopeID, tenantID}},
		{`INSERT INTO users(id,username,display_name,password_hash)
			VALUES($1,$2,'Other tenant user','not-used')`, []any{userID, "edge-other-" + compactID(userID)}},
		{`INSERT INTO memberships(scope_id,user_id) VALUES($1,$2)`, []any{scopeID, userID}},
		{`INSERT INTO roles(id,scope_id,name,system_role)
			VALUES($1,$2,'other_tenant_reader',true)`, []any{roleID, scopeID}},
		{`INSERT INTO role_permissions(role_id,permission_name) VALUES($1,'sites.read')`, []any{roleID}},
		{`INSERT INTO role_assignments(scope_id,user_id,role_id) VALUES($1,$2,$3)`, []any{scopeID, userID, roleID}},
	}
	if err := pgx.BeginFunc(t.Context(), pool, func(tx pgx.Tx) error {
		for _, statement := range statements {
			if _, err := tx.Exec(t.Context(), statement.sql, statement.args...); err != nil {
				return err
			}
		}
		return nil
	}); err != nil {
		t.Fatal(err)
	}
	return identity.Principal{
		UserID: userID, ScopeID: scopeID, ScopeKind: AudienceTenant, TenantID: &tenantID,
		Permissions: []string{tenantReadPermission},
	}
}

func (f *integrationFixture) assertBoundedPoolCancellation(t *testing.T, body map[string]any) {
	t.Helper()
	limit := int(f.pool.Config().MaxConns)
	if limit != 4 {
		t.Fatalf("test pool max connections=%d, want 4", limit)
	}
	connections := make([]*pgxpool.Conn, 0, limit)
	for range limit {
		connection, err := f.pool.Acquire(t.Context())
		if err != nil {
			t.Fatal(err)
		}
		connections = append(connections, connection)
	}
	request := newRequest(t, http.MethodPost, "/v1/admin/site-publications", f.adminToken, body, true)
	request.Header.Set("Idempotency-Key", "bounded-pool-cancel")
	ctx, cancel := context.WithTimeout(request.Context(), 100*time.Millisecond)
	defer cancel()
	request = request.WithContext(ctx)
	started := time.Now()
	response := httptest.NewRecorder()
	f.handler.ServeHTTP(response, request)
	for _, connection := range connections {
		connection.Release()
	}
	if elapsed := time.Since(started); elapsed > time.Second {
		t.Fatalf("bounded pool cancellation took %s", elapsed)
	}
	assertAPIError(t, response, http.StatusServiceUnavailable, "publication_service_unavailable")
	f.assertNoPublishFacts(t)
}

func (f *integrationFixture) assertNoRolloutCommandFacts(t *testing.T, rolloutID uuid.UUID) {
	t.Helper()
	var requests, audits int
	var rolloutState, deploymentState, outboxState string
	if err := f.pool.QueryRow(t.Context(), `SELECT
		(SELECT count(*) FROM edge_rollout_write_requests WHERE rollout_id=$1),
		(SELECT count(*) FROM audit_events WHERE resource_id=$1::text AND action LIKE 'edge_rollout.%'),
		(SELECT status FROM rollouts WHERE id=$1),
		(SELECT state FROM node_deployments WHERE rollout_id=$1),
		(SELECT outbox.status FROM edge_command_outbox outbox
		 JOIN node_deployments deployment ON deployment.id=outbox.deployment_id
		 WHERE deployment.rollout_id=$1)`, rolloutID).Scan(
		&requests, &audits, &rolloutState, &deploymentState, &outboxState); err != nil {
		t.Fatal(err)
	}
	if requests != 0 || audits != 0 || rolloutState != "queued" ||
		deploymentState != "queued" || outboxState != "pending" {
		t.Fatalf("rejected command facts requests=%d audits=%d rollout=%s deployment=%s outbox=%s",
			requests, audits, rolloutState, deploymentState, outboxState)
	}
}

func (f *integrationFixture) assertCancelledRolloutFacts(t *testing.T, rolloutID uuid.UUID) {
	t.Helper()
	var requests, audits int
	var rolloutState, deploymentState, outboxState string
	var requestID uuid.UUID
	if err := f.pool.QueryRow(t.Context(), `SELECT
		(SELECT count(*) FROM edge_rollout_write_requests WHERE rollout_id=$1),
		(SELECT count(*) FROM audit_events WHERE resource_id=$1::text AND action='edge_rollout.cancel'),
		(SELECT status FROM rollouts WHERE id=$1),
		(SELECT state FROM node_deployments WHERE rollout_id=$1),
		(SELECT outbox.status FROM edge_command_outbox outbox
		 JOIN node_deployments deployment ON deployment.id=outbox.deployment_id
		 WHERE deployment.rollout_id=$1),
		(SELECT request_id FROM edge_rollout_write_requests WHERE rollout_id=$1)`, rolloutID).Scan(
		&requests, &audits, &rolloutState, &deploymentState, &outboxState, &requestID); err != nil {
		t.Fatal(err)
	}
	if requests != 1 || audits != 1 || requestID == uuid.Nil || rolloutState != "cancelled" ||
		deploymentState != "cancelled" || outboxState != "cancelled" {
		t.Fatalf("cancel facts requests=%d audits=%d request=%s rollout=%s deployment=%s outbox=%s",
			requests, audits, requestID, rolloutState, deploymentState, outboxState)
	}
	if err := audit.New(f.pool).VerifyScope(t.Context(), f.platformScope); err != nil {
		t.Fatalf("verify platform audit chain after cancel: %v", err)
	}
}

func (f *integrationFixture) assertNoPublishFacts(t *testing.T) {
	t.Helper()
	var configs, publications, rollouts, deployments, outbox, commandRequests, publishAudits int
	if err := f.pool.QueryRow(context.Background(), `SELECT
		(SELECT count(*) FROM config_versions),
		(SELECT count(*) FROM edge_config_publications),
		(SELECT count(*) FROM rollouts),
		(SELECT count(*) FROM node_deployments),
		(SELECT count(*) FROM edge_command_outbox),
		(SELECT count(*) FROM edge_rollout_write_requests),
		(SELECT count(*) FROM audit_events WHERE action LIKE 'edge_publication.%')`).Scan(
		&configs, &publications, &rollouts, &deployments, &outbox, &commandRequests, &publishAudits); err != nil {
		t.Fatal(err)
	}
	if configs != 0 || publications != 0 || rollouts != 0 || deployments != 0 || outbox != 0 ||
		commandRequests != 0 || publishAudits != 0 {
		t.Fatalf("unexpected rejected-write facts configs=%d publications=%d rollouts=%d deployments=%d outbox=%d commands=%d audits=%d",
			configs, publications, rollouts, deployments, outbox, commandRequests, publishAudits)
	}
}

func (f *integrationFixture) setManagePermission(t *testing.T, enabled bool) {
	t.Helper()
	if err := pgx.BeginFunc(context.Background(), f.pool, func(tx pgx.Tx) error {
		if err := iamlock.AcquireExclusive(context.Background(), tx); err != nil {
			return err
		}
		if _, err := iamlock.AcquireScopes(context.Background(), tx, []uuid.UUID{f.platformScope}); err != nil {
			return err
		}
		if enabled {
			_, err := tx.Exec(context.Background(), `INSERT INTO role_assignments(scope_id,user_id,role_id)
				VALUES($1,$2,$3) ON CONFLICT DO NOTHING`, f.platformScope, f.platformUserID, f.platformRoleID)
			return err
		}
		_, err := tx.Exec(context.Background(), `DELETE FROM role_assignments
			WHERE scope_id=$1 AND user_id=$2 AND role_id=$3`, f.platformScope, f.platformUserID, f.platformRoleID)
		return err
	}); err != nil {
		t.Fatal(err)
	}
}

func (f *integrationFixture) assertPersistedFacts(
	t *testing.T,
	publication PublicationView,
	wantRequestID, wantCorrelationID, wantTaskID string,
) {
	t.Helper()
	var publications, rollouts, deployments, outbox, commandRequests, publishAudits, rolloutCommandAudits int
	err := f.pool.QueryRow(context.Background(), `SELECT
		(SELECT count(*) FROM edge_config_publications WHERE configuration_scope_id=$1),
		(SELECT count(*) FROM rollouts WHERE configuration_scope_id=$1 AND status='queued'),
		(SELECT count(*) FROM node_deployments WHERE rollout_id=$2),
		(SELECT count(*) FROM edge_command_outbox outbox
		 JOIN node_deployments deployment ON deployment.id=outbox.deployment_id
		 WHERE deployment.rollout_id=$2),
		(SELECT count(*) FROM edge_rollout_write_requests WHERE rollout_id=$2),
		(SELECT count(*) FROM audit_events WHERE scope_id=$3 AND action='edge_publication.publish' AND result='success'),
		(SELECT count(*) FROM audit_events WHERE scope_id=$3
		 AND action IN ('edge_rollout.cancel','edge_rollout.retry_failed'))`,
		f.tenantScopeID, publication.RolloutID, f.platformScope).Scan(
		&publications, &rollouts, &deployments, &outbox, &commandRequests, &publishAudits, &rolloutCommandAudits)
	if err != nil {
		t.Fatal(err)
	}
	if publications != 1 || rollouts != 1 || deployments != 1 || outbox != 1 || commandRequests != 0 ||
		publishAudits != 1 || rolloutCommandAudits != 0 {
		t.Fatalf("facts publications=%d rollouts=%d deployments=%d outbox=%d commands=%d publish_audits=%d rollout_command_audits=%d",
			publications, rollouts, deployments, outbox, commandRequests, publishAudits, rolloutCommandAudits)
	}
	var requestID uuid.UUID
	var actorUserID, actorScopeID uuid.UUID
	if err := f.pool.QueryRow(context.Background(), `SELECT request_id,actor_user_id,actor_scope_id
		FROM edge_config_publications WHERE id=$1`, publication.ID).Scan(&requestID, &actorUserID, &actorScopeID); err != nil {
		t.Fatal(err)
	}
	if requestID.String() != wantRequestID || actorUserID != f.platformUserID || actorScopeID != f.platformScope {
		t.Fatalf("publication metadata request=%s actor=%s/%s", requestID, actorUserID, actorScopeID)
	}
	var payload map[string]any
	if err := f.pool.QueryRow(context.Background(), `SELECT payload FROM audit_events
		WHERE action='edge_publication.publish' AND resource_id=$1`, publication.ID.String()).Scan(&payload); err != nil {
		t.Fatal(err)
	}
	for key, want := range map[string]string{
		"authentication_scope_id": f.platformScope.String(),
		"session_id":              f.adminSessionID.String(),
		"correlation_id":          wantCorrelationID,
		"traceparent":             testTraceparent(),
		"task_id":                 wantTaskID,
	} {
		if payload[key] != want {
			t.Fatalf("audit metadata %s=%#v, want %q", key, payload[key], want)
		}
	}
	if err := audit.New(f.pool).VerifyScope(context.Background(), f.platformScope); err != nil {
		t.Fatalf("verify platform audit chain: %v", err)
	}
}

func compactID(id uuid.UUID) string {
	return strings.ReplaceAll(id.String(), "-", "")[:16]
}

var _ edgepublish.ArtifactSigner = (*integrationSigner)(nil)
var _ edgepublish.EntitlementAuthorizer = integrationEntitlement{}
