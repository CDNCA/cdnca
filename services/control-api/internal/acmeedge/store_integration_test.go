//go:build integration

package acmeedge

import (
	"context"
	"crypto/hmac"
	"crypto/sha256"
	"encoding/base64"
	"encoding/json"
	"errors"
	"fmt"
	"io/fs"
	"os"
	"regexp"
	"strings"
	"sync"
	"sync/atomic"
	"testing"
	"time"

	"github.com/cdnca/cdnca/services/control-api/internal/audit"
	"github.com/cdnca/cdnca/services/control-api/internal/database"
	"github.com/cdnca/cdnca/services/control-api/internal/database/databasetest"
	controlmigrations "github.com/cdnca/cdnca/services/control-api/migrations"
	"github.com/google/uuid"
	"github.com/jackc/pgx/v5"
	"github.com/jackc/pgx/v5/pgconn"
	"github.com/jackc/pgx/v5/pgxpool"
)

type integrationCipher struct{}

func (integrationCipher) Seal(_ context.Context, request SealRequest) (SealResult, error) {
	mac := hmac.New(sha256.New, []byte("acme-http01-overlay-integration-key"))
	_, _ = mac.Write(request.AAD)
	_, _ = mac.Write([]byte(request.Token))
	_, _ = mac.Write([]byte{0})
	_, _ = mac.Write([]byte(request.ExactValue))
	nonce := sha256.Sum256(append([]byte("nonce/"), request.AAD...))
	return SealResult{KeyID: "integration-key-v1", Nonce: nonce[:12], Ciphertext: mac.Sum(nil)}, nil
}

type rotatingIntegrationCipher struct {
	marker byte
}

func (cipher rotatingIntegrationCipher) Seal(_ context.Context, _ SealRequest) (SealResult, error) {
	return SealResult{
		KeyID:      fmt.Sprintf("integration-key-%d", cipher.marker),
		Nonce:      []byte{cipher.marker, 1, 2, 3, 4, 5, 6, 7, 8, 9, 10, 11},
		Ciphertext: []byte{cipher.marker, 12, 13},
	}, nil
}

type integrationAuthorizer struct {
	now time.Time
}

type blockedAuthorizer struct {
	decision EntitlementDecision
	err      error
	calls    atomic.Int64
}

func (authorizer *blockedAuthorizer) AuthorizeOverlay(
	context.Context,
	pgx.Tx,
	EntitlementRequest,
) (EntitlementDecision, error) {
	authorizer.calls.Add(1)
	return authorizer.decision, authorizer.err
}

func (authorizer integrationAuthorizer) AuthorizeOverlay(
	context.Context,
	pgx.Tx,
	EntitlementRequest,
) (EntitlementDecision, error) {
	return EntitlementDecision{
		Allowed: true, LocallyVerified: true, Status: EntitlementStatusValid,
		LeaseSerial: 1, EvaluatedAt: authorizer.now,
	}, nil
}

type failingAuditAppender struct{}

func (failingAuditAppender) Append(context.Context, pgx.Tx, audit.Event) error {
	return errors.New("forced audit failure")
}

type integrationFixture struct {
	pool       *pgxpool.Pool
	service    *Service
	now        time.Time
	scopeID    uuid.UUID
	tenantID   uuid.UUID
	userID     uuid.UUID
	siteID     uuid.UUID
	domain     string
	nodeIDs    []uuid.UUID
	challenges []ChallengeReference
	plaintext  []string
}

func newIntegrationFixture(t *testing.T, nodeCount, challengeCount int) *integrationFixture {
	t.Helper()
	pool := openIntegrationDatabase(t)
	now := databaseNow(t, pool)
	fixture := &integrationFixture{
		pool: pool, now: now, scopeID: uuid.New(), tenantID: uuid.New(), userID: uuid.New(), siteID: uuid.New(),
		domain: "overlay.example.test",
	}
	seedIntegrationTenant(t, fixture)
	for index := 0; index < nodeCount; index++ {
		nodeID := uuid.New()
		seedIntegrationNode(t, fixture, nodeID)
		fixture.nodeIDs = append(fixture.nodeIDs, nodeID)
	}
	for index := 0; index < challengeCount; index++ {
		reference, plaintext := seedHTTP01Challenge(t, fixture, index+1)
		fixture.challenges = append(fixture.challenges, reference)
		fixture.plaintext = append(fixture.plaintext, plaintext...)
	}
	fixture.service = fixture.newService(t, nil)
	return fixture
}

func (fixture *integrationFixture) newService(t *testing.T, auditor AuditAppender) *Service {
	t.Helper()
	config := DefaultConfig()
	config.Clock = func() time.Time { return fixture.now }
	config.Cipher = integrationCipher{}
	config.EntitlementAuthorizer = integrationAuthorizer{now: fixture.now}
	config.Auditor = auditor
	service, err := NewService(fixture.pool, config)
	if err != nil {
		t.Fatal(err)
	}
	return service
}

func (fixture *integrationFixture) newServiceWithAuthorizer(t *testing.T, authorizer EntitlementAuthorizer) *Service {
	t.Helper()
	config := DefaultConfig()
	config.Clock = func() time.Time { return fixture.now }
	config.Cipher = integrationCipher{}
	config.EntitlementAuthorizer = authorizer
	service, err := NewService(fixture.pool, config)
	if err != nil {
		t.Fatal(err)
	}
	return service
}

func (fixture *integrationFixture) request(key string, expectedRevision int64, challenges []ChallengeReference) PublishRequest {
	return PublishRequest{
		Mode: ModeApply, TenantScopeID: fixture.scopeID, SiteID: fixture.siteID, ExpectedRevision: expectedRevision,
		Challenges: challenges, NodeIDs: fixture.nodeIDs, MaxAttempts: 3,
		Deadline: fixture.now.Add(10 * time.Minute), IdempotencyKey: key, RequestID: uuid.NewString(),
	}
}

func (fixture *integrationFixture) cleanupRequest(key string, expectedRevision int64, challenges []ChallengeReference) PublishRequest {
	request := fixture.request(key, expectedRevision, challenges)
	request.Mode = ModeCleanup
	request.NodeIDs = nil
	return request
}

func TestPublishSnapshotSealsPersistsAndReplaysWithoutPlaintext(t *testing.T) {
	fixture := newIntegrationFixture(t, 2, 2)
	request := fixture.request("publish-sealed", 0, fixture.challenges)
	publication, err := fixture.service.PublishSnapshot(t.Context(), request)
	if err != nil {
		t.Fatal(err)
	}
	if publication.Revision != 1 || publication.TokenCount != 2 || publication.NodeCount != 2 || publication.Replayed {
		t.Fatalf("publication = %+v", publication)
	}
	replayRequest := request
	replayRequest.RequestID = uuid.NewString()
	replay, err := fixture.service.PublishSnapshot(t.Context(), replayRequest)
	if err != nil || !replay.Replayed || replay.ID != publication.ID || replay.VersionID != publication.VersionID {
		t.Fatalf("replay = %+v, %v", replay, err)
	}
	conflict := replayRequest
	conflict.Deadline = conflict.Deadline.Add(time.Second)
	if _, err := fixture.service.PublishSnapshot(t.Context(), conflict); !errors.Is(err, ErrIdempotencyConflict) {
		t.Fatalf("changed replay error = %v", err)
	}
	assertOverlayCounts(t, fixture.pool, 1, 1, 2, 2, 2, 2)

	deliveries, err := fixture.service.ClaimDeliveries(t.Context(), ClaimRequest{Limit: 10, LeaseDuration: time.Minute})
	if err != nil || len(deliveries) != 2 {
		t.Fatalf("deliveries = %d, %v", len(deliveries), err)
	}
	for _, delivery := range deliveries {
		if len(delivery.Tokens) != 2 || delivery.PayloadSHA256 == ([32]byte{}) {
			t.Fatalf("delivery = %+v", delivery)
		}
	}
	assertNoOverlayPlaintext(t, fixture)
}

func TestPublishSnapshotConcurrentCASRequiresExplicitMerge(t *testing.T) {
	fixture := newIntegrationFixture(t, 1, 2)
	requests := []PublishRequest{
		fixture.request("publish-cas-a", 0, fixture.challenges[:1]),
		fixture.request("publish-cas-b", 0, fixture.challenges[1:]),
	}
	start := make(chan struct{})
	type outcome struct {
		publication Publication
		err         error
	}
	outcomes := make(chan outcome, 2)
	var wait sync.WaitGroup
	for _, request := range requests {
		request := request
		wait.Add(1)
		go func() {
			defer wait.Done()
			<-start
			publication, err := fixture.service.PublishSnapshot(context.Background(), request)
			outcomes <- outcome{publication: publication, err: err}
		}()
	}
	close(start)
	wait.Wait()
	close(outcomes)
	var winner Publication
	revisionConflicts := 0
	for outcome := range outcomes {
		if outcome.err == nil {
			winner = outcome.publication
		} else if errors.Is(outcome.err, ErrRevisionConflict) {
			revisionConflicts++
		} else {
			t.Fatalf("concurrent publish error = %v", outcome.err)
		}
	}
	if winner.Revision != 1 || revisionConflicts != 1 {
		t.Fatalf("winner=%+v conflicts=%d", winner, revisionConflicts)
	}
	merged, err := fixture.service.PublishSnapshot(t.Context(), fixture.request("publish-cas-merged", 1, fixture.challenges))
	if err != nil || merged.Revision != 2 || merged.TokenCount != 2 {
		t.Fatalf("merged = %+v, %v", merged, err)
	}
	var revisions, latestTokens int
	if err := fixture.pool.QueryRow(t.Context(), `SELECT
		(SELECT count(*) FROM acme_http01_overlay_versions),
		(SELECT count(*) FROM acme_http01_overlay_token_facts WHERE version_id=$1)`, merged.VersionID).Scan(
		&revisions, &latestTokens); err != nil {
		t.Fatal(err)
	}
	if revisions != 2 || latestTokens != 2 {
		t.Fatalf("revisions=%d latest_tokens=%d", revisions, latestTokens)
	}
}

func TestReceiptRetryPartialFailureAndLatestHealthy(t *testing.T) {
	fixture := newIntegrationFixture(t, 2, 2)
	first, err := fixture.service.PublishSnapshot(t.Context(), fixture.request("healthy-v1", 0, fixture.challenges[:1]))
	if err != nil {
		t.Fatal(err)
	}
	makeVersionHealthy(t, fixture, first)
	latest, err := fixture.service.LatestHealthy(t.Context(), fixture.scopeID, fixture.siteID)
	if err != nil || latest.Revision != 1 {
		t.Fatalf("latest v1 = %+v, %v", latest, err)
	}

	second, err := fixture.service.PublishSnapshot(t.Context(), fixture.request("partial-v2", 1, fixture.challenges))
	if err != nil {
		t.Fatal(err)
	}
	deliveries, err := fixture.service.ClaimDeliveries(t.Context(), ClaimRequest{Limit: 10, LeaseDuration: time.Minute})
	if err != nil || len(deliveries) != 2 {
		t.Fatalf("claim v2 = %d, %v", len(deliveries), err)
	}
	for index, delivery := range deliveries {
		if err := fixture.service.CompleteDelivery(t.Context(), CompleteDeliveryRequest{
			OutboxID: delivery.OutboxID, LeaseToken: delivery.LeaseToken, Published: true,
		}); err != nil {
			t.Fatal(err)
		}
		applied := Receipt{
			DeploymentID: delivery.DeploymentID, DeploymentAttempt: 1, ReceiptID: uuid.New(),
			State: DeploymentApplied, OccurredAt: fixture.now,
		}
		state, err := fixture.service.RecordReceipt(t.Context(), applied)
		if err != nil || state.State != DeploymentApplied {
			t.Fatalf("applied = %+v, %v", state, err)
		}
		replay, err := fixture.service.RecordReceipt(t.Context(), applied)
		if err != nil || !replay.Replayed {
			t.Fatalf("receipt replay = %+v, %v", replay, err)
		}
		conflict := applied
		conflict.State = DeploymentHealthy
		if _, err := fixture.service.RecordReceipt(t.Context(), conflict); !errors.Is(err, ErrReceiptConflict) {
			t.Fatalf("receipt digest conflict = %v", err)
		}
		terminal := Receipt{
			DeploymentID: delivery.DeploymentID, DeploymentAttempt: 1, ReceiptID: uuid.New(),
			OccurredAt: fixture.now,
		}
		if index == 0 {
			terminal.State = DeploymentHealthy
		} else {
			terminal.State = DeploymentFailed
			terminal.FailureCode = "edge_apply_failed"
		}
		if _, err := fixture.service.RecordReceipt(t.Context(), terminal); err != nil {
			t.Fatal(err)
		}
	}
	health, err := fixture.service.VersionHealth(t.Context(), fixture.scopeID, fixture.siteID, second.Revision)
	if err != nil || health.Healthy || health.FailedCount != 1 || health.HealthyCount != 1 {
		t.Fatalf("partial health = %+v, %v", health, err)
	}
	latest, err = fixture.service.LatestHealthy(t.Context(), fixture.scopeID, fixture.siteID)
	if err != nil || latest.Revision != 1 {
		t.Fatalf("LKG after partial failure = %+v, %v", latest, err)
	}

	failed := latestDeploymentWithState(t, fixture.pool, second.VersionID, DeploymentFailed)
	retry, err := fixture.service.RetryDeployment(t.Context(), RetryRequest{
		DeploymentID: failed.DeploymentID, Deadline: fixture.now.Add(10 * time.Minute), RequestID: uuid.NewString(),
	})
	if err != nil || retry.DeploymentAttempt != 2 {
		t.Fatalf("retry = %+v, %v", retry, err)
	}
	if _, err := fixture.service.RecordReceipt(t.Context(), Receipt{
		DeploymentID: failed.DeploymentID, DeploymentAttempt: 1, ReceiptID: uuid.New(),
		State: DeploymentApplied, OccurredAt: fixture.now,
	}); !errors.Is(err, ErrStaleAttempt) {
		t.Fatalf("stale receipt = %v", err)
	}
	retryDeliveries, err := fixture.service.ClaimDeliveries(t.Context(), ClaimRequest{Limit: 10, LeaseDuration: time.Minute})
	if err != nil || len(retryDeliveries) != 1 || retryDeliveries[0].DeploymentAttempt != 2 {
		t.Fatalf("retry deliveries = %+v, %v", retryDeliveries, err)
	}
	completeDeliveryHealthy(t, fixture, retryDeliveries[0])
	health, err = fixture.service.VersionHealth(t.Context(), fixture.scopeID, fixture.siteID, second.Revision)
	if err != nil || !health.Healthy {
		t.Fatalf("retried health = %+v, %v", health, err)
	}
	latest, err = fixture.service.LatestHealthy(t.Context(), fixture.scopeID, fixture.siteID)
	if err != nil || latest.Revision != 2 {
		t.Fatalf("latest v2 = %+v, %v", latest, err)
	}
}

func TestTimeoutRetryAuditRollbackAndOrdinaryDeploymentIsolation(t *testing.T) {
	fixture := newIntegrationFixture(t, 1, 1)
	seedOrdinaryActiveDeployment(t, fixture)
	publication, err := fixture.service.PublishSnapshot(t.Context(), fixture.request("timeout", 0, fixture.challenges))
	if err != nil {
		t.Fatalf("overlay publish beside ordinary deployment: %v", err)
	}
	count, err := fixture.service.MarkTimedOut(t.Context(), fixture.now.Add(11*time.Minute), 10)
	if err != nil || count != 1 {
		t.Fatalf("mark timed out = %d, %v", count, err)
	}
	timedOut := latestDeploymentWithState(t, fixture.pool, publication.VersionID, DeploymentTimedOut)
	if _, err := fixture.service.RetryDeployment(t.Context(), RetryRequest{
		DeploymentID: timedOut.DeploymentID, Deadline: fixture.now.Add(10 * time.Minute), RequestID: uuid.NewString(),
	}); err != nil {
		t.Fatal(err)
	}

	rollbackFixture := newIntegrationFixture(t, 1, 1)
	failingService := rollbackFixture.newService(t, failingAuditAppender{})
	if _, err := failingService.PublishSnapshot(t.Context(), rollbackFixture.request("audit-rollback", 0, rollbackFixture.challenges)); err == nil {
		t.Fatal("publish with failing audit unexpectedly succeeded")
	}
	assertOverlayCounts(t, rollbackFixture.pool, 0, 0, 0, 0, 0, 0)
}

func TestOverlayFactsRejectMutationAndMigrationRoundTrip(t *testing.T) {
	fixture := newIntegrationFixture(t, 1, 1)
	publication, err := fixture.service.PublishSnapshot(t.Context(), fixture.request("tamper", 0, fixture.challenges))
	if err != nil {
		t.Fatal(err)
	}
	deliveries, err := fixture.service.ClaimDeliveries(t.Context(), ClaimRequest{Limit: 1, LeaseDuration: time.Minute})
	if err != nil || len(deliveries) != 1 {
		t.Fatal(err)
	}
	factTables := []struct {
		name         string
		mutableProbe string
	}{
		{"acme_http01_overlay_publications", "created_at"},
		{"acme_http01_overlay_versions", "created_at"},
		{"acme_http01_overlay_token_facts", "created_at"},
		{"acme_http01_overlay_targets", "created_at"},
		{"acme_http01_overlay_deployments", "created_at"},
		{"acme_http01_overlay_deployment_events", "occurred_at"},
		{"acme_http01_overlay_outbox", "created_at"},
		{"acme_http01_overlay_outbox_attempts", "occurred_at"},
	}
	for _, table := range factTables {
		t.Run(table.name+"_update", func(t *testing.T) {
			_, err := fixture.pool.Exec(t.Context(), "UPDATE "+table.name+" SET "+table.mutableProbe+"="+table.mutableProbe)
			assertSQLState(t, err, "P0001")
		})
		t.Run(table.name+"_delete", func(t *testing.T) {
			_, err := fixture.pool.Exec(t.Context(), "DELETE FROM "+table.name)
			assertSQLState(t, err, "P0001")
		})
		t.Run(table.name+"_truncate", func(t *testing.T) {
			_, err := fixture.pool.Exec(t.Context(), "TRUNCATE "+table.name+" CASCADE")
			assertSQLState(t, err, "P0001")
		})
	}
	if publication.ID == uuid.Nil {
		t.Fatal("missing publication")
	}

	pool := openIntegrationDatabaseThrough063(t)
	before := overlayCatalogSnapshot(t, pool)
	if err := applyOverlayMigration(t.Context(), pool, "down"); err != nil {
		t.Fatal(err)
	}
	var version int
	var exists bool
	if err := pool.QueryRow(t.Context(), `SELECT max(version),to_regclass('acme_http01_overlay_states') IS NOT NULL FROM schema_migrations`).Scan(&version, &exists); err != nil {
		t.Fatal(err)
	}
	if version != 62 || exists {
		t.Fatalf("after down version=%d exists=%t", version, exists)
	}
	if err := applyOverlayMigration(t.Context(), pool, "up"); err != nil {
		t.Fatal(err)
	}
	after := overlayCatalogSnapshot(t, pool)
	if before != after {
		t.Fatalf("063 catalog changed across down/up\nbefore=%s\nafter=%s", before, after)
	}
}

func TestCleanupRemovesLastTokenWhenLicenseUnavailableAndTargetDraining(t *testing.T) {
	tests := []struct {
		name       string
		authorizer *blockedAuthorizer
	}{
		{name: "license_expired", authorizer: &blockedAuthorizer{decision: EntitlementDecision{Status: "expired"}}},
		{name: "authorizer_unavailable", authorizer: &blockedAuthorizer{err: errors.New("license service unavailable")}},
	}
	for _, test := range tests {
		t.Run(test.name, func(t *testing.T) {
			fixture := newIntegrationFixture(t, 1, 1)
			first, err := fixture.service.PublishSnapshot(t.Context(), fixture.request("cleanup-base", 0, fixture.challenges))
			if err != nil {
				t.Fatal(err)
			}
			makeVersionHealthy(t, fixture, first)
			if _, err := fixture.pool.Exec(t.Context(), `UPDATE nodes SET admin_state='draining' WHERE id=$1`, fixture.nodeIDs[0]); err != nil {
				t.Fatal(err)
			}
			if _, err := fixture.pool.Exec(t.Context(), `UPDATE sites SET enabled=false,status='disabled' WHERE id=$1`, fixture.siteID); err != nil {
				t.Fatal(err)
			}
			cleanupService := fixture.newServiceWithAuthorizer(t, test.authorizer)
			cleanup, err := cleanupService.PublishSnapshot(t.Context(), fixture.cleanupRequest("cleanup-empty", 1, nil))
			if err != nil {
				t.Fatal(err)
			}
			if cleanup.Mode != ModeCleanup || cleanup.Revision != 2 || cleanup.TokenCount != 0 || cleanup.NodeCount != 1 {
				t.Fatalf("cleanup = %+v", cleanup)
			}
			if test.authorizer.calls.Load() != 0 {
				t.Fatalf("cleanup called entitlement authorizer %d times", test.authorizer.calls.Load())
			}
			deliveries, err := cleanupService.ClaimDeliveries(t.Context(), ClaimRequest{Limit: 10, LeaseDuration: time.Minute})
			if err != nil || len(deliveries) != 1 || deliveries[0].Mode != ModeCleanup ||
				deliveries[0].VersionID != cleanup.VersionID || len(deliveries[0].Tokens) != 0 {
				t.Fatalf("empty cleanup delivery = %+v, %v", deliveries, err)
			}
			var action, reason string
			if err := fixture.pool.QueryRow(t.Context(), `
				SELECT action,payload->>'reason' FROM audit_events
				WHERE resource_id=$1 ORDER BY stream_position DESC LIMIT 1`, cleanup.VersionID.String()).Scan(&action, &reason); err != nil {
				t.Fatal(err)
			}
			if action != "acme_http01_overlay.cleanup" || reason != "token_set_shrunk" {
				t.Fatalf("cleanup audit action=%q reason=%q", action, reason)
			}
		})
	}
}

func TestCleanupCannotAddTokensOrTargetsAndApplyRejectsUnreachableChallenge(t *testing.T) {
	fixture := newIntegrationFixture(t, 1, 2)
	if _, err := fixture.service.PublishSnapshot(t.Context(), fixture.request("guard-base", 0, fixture.challenges[:1])); err != nil {
		t.Fatal(err)
	}
	addToken := fixture.cleanupRequest("fake-cleanup-token", 1, fixture.challenges)
	if _, err := fixture.service.PublishSnapshot(t.Context(), addToken); !errors.Is(err, ErrChallengeIneligible) {
		t.Fatalf("fake cleanup token error = %v", err)
	}
	extraNode := uuid.New()
	seedIntegrationNode(t, fixture, extraNode)
	addTarget := fixture.cleanupRequest("fake-cleanup-target", 1, fixture.challenges[:1])
	addTarget.NodeIDs = []uuid.UUID{fixture.nodeIDs[0], extraNode}
	if _, err := fixture.service.PublishSnapshot(t.Context(), addTarget); !errors.Is(err, ErrTargetIneligible) {
		t.Fatalf("fake cleanup target error = %v", err)
	}
	assertOverlayCounts(t, fixture.pool, 1, 1, 1, 1, 1, 1)

	badReference, _ := seedHTTP01Challenge(t, fixture, 3, [2]string{"short", "short.invalid"})
	invalidMaterial := fixture.request("invalid-key-authorization", 1, []ChallengeReference{fixture.challenges[0], badReference})
	if _, err := fixture.service.PublishSnapshot(t.Context(), invalidMaterial); !errors.Is(err, ErrChallengeIneligible) {
		t.Fatalf("invalid key authorization error = %v", err)
	}
	assertOverlayCounts(t, fixture.pool, 1, 1, 1, 1, 1, 1)

	if _, err := fixture.pool.Exec(t.Context(), `UPDATE sites SET http_ports=ARRAY['8080'] WHERE id=$1`, fixture.siteID); err != nil {
		t.Fatal(err)
	}
	unreachable := fixture.request("unreachable-http01", 1, fixture.challenges)
	if _, err := fixture.service.PublishSnapshot(t.Context(), unreachable); !errors.Is(err, ErrChallengeIneligible) {
		t.Fatalf("unreachable HTTP-01 site error = %v", err)
	}
	assertOverlayCounts(t, fixture.pool, 1, 1, 1, 1, 1, 1)
}

func TestCleanupCommitRejectsRetainedTokenIdentityTamperingAndAllowsReseal(t *testing.T) {
	fixture := newIntegrationFixture(t, 1, 1)
	first, err := fixture.service.PublishSnapshot(t.Context(), fixture.request("cleanup-identity-base", 0, fixture.challenges))
	if err != nil {
		t.Fatal(err)
	}
	for _, field := range []string{"domain", "token_sha256", "value_sha256", "aad_sha256"} {
		t.Run(field, func(t *testing.T) {
			assertDirectCleanupIdentityTamperRejected(t, fixture, first.VersionID, field)
		})
	}

	config := DefaultConfig()
	config.Clock = func() time.Time { return fixture.now }
	config.Cipher = rotatingIntegrationCipher{marker: 42}
	config.EntitlementAuthorizer = &blockedAuthorizer{err: errors.New("must not authorize cleanup")}
	resealService, err := NewService(fixture.pool, config)
	if err != nil {
		t.Fatal(err)
	}
	resealed, err := resealService.PublishSnapshot(t.Context(), fixture.cleanupRequest(
		"cleanup-retained-reseal", first.Revision, fixture.challenges,
	))
	if err != nil || resealed.TokenCount != 1 || resealed.Revision != 2 {
		t.Fatalf("retained token reseal = %+v, %v", resealed, err)
	}
	var keyID string
	if err := fixture.pool.QueryRow(t.Context(), `
		SELECT key_id FROM acme_http01_overlay_token_facts WHERE version_id=$1`, resealed.VersionID).Scan(&keyID); err != nil {
		t.Fatal(err)
	}
	if keyID != "integration-key-42" {
		t.Fatalf("resealed key id = %q", keyID)
	}
}

func TestOutboxProjectionRejectsDirectStateForgery(t *testing.T) {
	tests := []struct {
		name   string
		update string
		args   func(time.Time) []any
	}{
		{
			name:   "published_without_attempt",
			update: `SET status='published',updated_at=$2 WHERE outbox_id=$1`,
			args:   func(now time.Time) []any { return []any{now} },
		},
		{
			name: "claimed_without_attempt",
			update: `SET status='claimed',publish_attempts=1,lease_token=$2,
				lease_expires_at=$3,updated_at=$4 WHERE outbox_id=$1`,
			args: func(now time.Time) []any { return []any{uuid.New(), now.Add(time.Minute), now} },
		},
		{
			name: "retry_without_attempt",
			update: `SET status='retry',publish_attempts=1,available_at=$2,
				last_failure_code='forged_retry',updated_at=$3 WHERE outbox_id=$1`,
			args: func(now time.Time) []any { return []any{now.Add(time.Minute), now} },
		},
		{
			name:   "forged_attempt_count",
			update: `SET publish_attempts=1,updated_at=$2 WHERE outbox_id=$1`,
			args:   func(now time.Time) []any { return []any{now} },
		},
	}
	for _, test := range tests {
		t.Run(test.name, func(t *testing.T) {
			fixture := newIntegrationFixture(t, 1, 1)
			publication, err := fixture.service.PublishSnapshot(t.Context(), fixture.request("outbox-projection", 0, fixture.challenges))
			if err != nil {
				t.Fatal(err)
			}
			var outboxID uuid.UUID
			if err := fixture.pool.QueryRow(t.Context(), `
				SELECT id FROM acme_http01_overlay_outbox WHERE version_id=$1`, publication.VersionID).Scan(&outboxID); err != nil {
				t.Fatal(err)
			}
			tx, err := fixture.pool.Begin(t.Context())
			if err != nil {
				t.Fatal(err)
			}
			args := append([]any{outboxID}, test.args(fixture.now.Add(time.Second))...)
			if _, err := tx.Exec(t.Context(), "UPDATE acme_http01_overlay_outbox_states "+test.update, args...); err != nil {
				_ = tx.Rollback(t.Context())
				t.Fatalf("forged update failed before deferred projection check: %v", err)
			}
			assertSQLState(t, tx.Commit(t.Context()), "P0001")
		})
	}

	t.Run("attempt_without_projection_update", func(t *testing.T) {
		fixture := newIntegrationFixture(t, 1, 1)
		publication, err := fixture.service.PublishSnapshot(t.Context(), fixture.request("outbox-ledger-orphan", 0, fixture.challenges))
		if err != nil {
			t.Fatal(err)
		}
		var outboxID uuid.UUID
		if err := fixture.pool.QueryRow(t.Context(), `
			SELECT id FROM acme_http01_overlay_outbox WHERE version_id=$1`, publication.VersionID).Scan(&outboxID); err != nil {
			t.Fatal(err)
		}
		tx, err := fixture.pool.Begin(t.Context())
		if err != nil {
			t.Fatal(err)
		}
		if _, err := tx.Exec(t.Context(), `
			INSERT INTO acme_http01_overlay_outbox_attempts(
				outbox_id,sequence,publish_attempt,event_type,lease_token,occurred_at
			) VALUES($1,1,1,'claimed',$2,$3)`, outboxID, uuid.New(), fixture.now.Add(time.Second)); err != nil {
			_ = tx.Rollback(t.Context())
			t.Fatalf("orphan attempt failed before deferred projection check: %v", err)
		}
		assertSQLState(t, tx.Commit(t.Context()), "P0001")
	})
}

func TestOutboxProjectionAcceptsRetryExpiryAndTimeoutLedgers(t *testing.T) {
	t.Run("retry_then_publish", func(t *testing.T) {
		fixture := newIntegrationFixture(t, 1, 1)
		if _, err := fixture.service.PublishSnapshot(t.Context(), fixture.request("projection-retry", 0, fixture.challenges)); err != nil {
			t.Fatal(err)
		}
		deliveries, err := fixture.service.ClaimDeliveries(t.Context(), ClaimRequest{Limit: 1, LeaseDuration: time.Minute})
		if err != nil || len(deliveries) != 1 {
			t.Fatalf("initial claim = %+v, %v", deliveries, err)
		}
		if err := fixture.service.CompleteDelivery(t.Context(), CompleteDeliveryRequest{
			OutboxID: deliveries[0].OutboxID, LeaseToken: deliveries[0].LeaseToken,
			Retryable: true, FailureCode: "temporary_publish_failure",
		}); err != nil {
			t.Fatal(err)
		}
		fixture.now = fixture.now.Add(3 * time.Second)
		deliveries, err = fixture.service.ClaimDeliveries(t.Context(), ClaimRequest{Limit: 1, LeaseDuration: time.Minute})
		if err != nil || len(deliveries) != 1 || deliveries[0].PublishAttempt != 2 {
			t.Fatalf("retry claim = %+v, %v", deliveries, err)
		}
		if err := fixture.service.CompleteDelivery(t.Context(), CompleteDeliveryRequest{
			OutboxID: deliveries[0].OutboxID, LeaseToken: deliveries[0].LeaseToken, Published: true,
		}); err != nil {
			t.Fatal(err)
		}
	})

	t.Run("expired_claim", func(t *testing.T) {
		fixture := newIntegrationFixture(t, 1, 1)
		if _, err := fixture.service.PublishSnapshot(t.Context(), fixture.request("projection-expiry", 0, fixture.challenges)); err != nil {
			t.Fatal(err)
		}
		if deliveries, err := fixture.service.ClaimDeliveries(t.Context(), ClaimRequest{Limit: 1, LeaseDuration: time.Second}); err != nil || len(deliveries) != 1 {
			t.Fatalf("claim = %+v, %v", deliveries, err)
		}
		fixture.now = fixture.now.Add(2 * time.Second)
		if deliveries, err := fixture.service.ClaimDeliveries(t.Context(), ClaimRequest{Limit: 1, LeaseDuration: time.Minute}); err != nil || len(deliveries) != 0 {
			t.Fatalf("expiry sweep = %+v, %v", deliveries, err)
		}
		var status string
		if err := fixture.pool.QueryRow(t.Context(), `SELECT status FROM acme_http01_overlay_outbox_states`).Scan(&status); err != nil {
			t.Fatal(err)
		}
		if status != "retry" {
			t.Fatalf("expired claim status = %q", status)
		}
	})

	t.Run("retry_timed_out", func(t *testing.T) {
		fixture := newIntegrationFixture(t, 1, 1)
		if _, err := fixture.service.PublishSnapshot(t.Context(), fixture.request("projection-retry-timeout", 0, fixture.challenges)); err != nil {
			t.Fatal(err)
		}
		deliveries, err := fixture.service.ClaimDeliveries(t.Context(), ClaimRequest{Limit: 1, LeaseDuration: time.Minute})
		if err != nil || len(deliveries) != 1 {
			t.Fatalf("claim = %+v, %v", deliveries, err)
		}
		if err := fixture.service.CompleteDelivery(t.Context(), CompleteDeliveryRequest{
			OutboxID: deliveries[0].OutboxID, LeaseToken: deliveries[0].LeaseToken,
			Retryable: true, FailureCode: "temporary_publish_failure",
		}); err != nil {
			t.Fatal(err)
		}
		if count, err := fixture.service.MarkTimedOut(t.Context(), fixture.now.Add(11*time.Minute), 1); err != nil || count != 1 {
			t.Fatalf("timeout retry = %d, %v", count, err)
		}
		var status, eventType string
		var publishAttempt int
		if err := fixture.pool.QueryRow(t.Context(), `
			SELECT state.status,event.event_type,event.publish_attempt
			FROM acme_http01_overlay_outbox_states state
			JOIN LATERAL (
				SELECT event_type,publish_attempt FROM acme_http01_overlay_outbox_attempts
				WHERE outbox_id=state.outbox_id ORDER BY sequence DESC LIMIT 1
			) event ON true`).Scan(&status, &eventType, &publishAttempt); err != nil {
			t.Fatal(err)
		}
		if status != "exhausted" || eventType != "exhausted" || publishAttempt != 1 {
			t.Fatalf("retry timeout projection = %q/%q/%d", status, eventType, publishAttempt)
		}
	})
}

func TestTerminalDeliveryFailureAtomicallyConvergesAndReplays(t *testing.T) {
	fixture := newIntegrationFixture(t, 1, 1)
	publication, err := fixture.service.PublishSnapshot(t.Context(), fixture.request("terminal-delivery", 0, fixture.challenges))
	if err != nil {
		t.Fatal(err)
	}
	deliveries, err := fixture.service.ClaimDeliveries(t.Context(), ClaimRequest{Limit: 1, LeaseDuration: time.Minute})
	if err != nil || len(deliveries) != 1 {
		t.Fatalf("claim = %+v, %v", deliveries, err)
	}
	request := CompleteDeliveryRequest{
		OutboxID: deliveries[0].OutboxID, LeaseToken: deliveries[0].LeaseToken,
		FailureCode: "artifact_integrity",
	}
	if err := fixture.service.CompleteDelivery(t.Context(), request); err != nil {
		t.Fatal(err)
	}
	if err := fixture.service.CompleteDelivery(t.Context(), request); err != nil {
		t.Fatalf("idempotent completion = %v", err)
	}
	conflict := request
	conflict.FailureCode = "subject_binding"
	if err := fixture.service.CompleteDelivery(t.Context(), conflict); !errors.Is(err, ErrClaimLost) {
		t.Fatalf("conflicting completion = %v", err)
	}
	var outboxStatus, outboxFailure, deploymentState, deploymentFailure string
	var eventCount, auditCount int
	if err := fixture.pool.QueryRow(t.Context(), `
		SELECT state.status,state.last_failure_code,event.state,event.failure_code,
		       (SELECT count(*) FROM acme_http01_overlay_deployment_events
		        WHERE deployment_id=$2 AND deployment_attempt=$3),
		       (SELECT count(*) FROM audit_events
		        WHERE action='acme_http01_overlay.delivery_failed' AND resource_id=$2::text)
		FROM acme_http01_overlay_outbox_states state
		JOIN LATERAL (
			SELECT state,failure_code FROM acme_http01_overlay_deployment_events
			WHERE deployment_id=$2 AND deployment_attempt=$3 ORDER BY sequence DESC LIMIT 1
		) event ON true
		WHERE state.outbox_id=$1`, request.OutboxID, deliveries[0].DeploymentID,
		deliveries[0].DeploymentAttempt).Scan(
		&outboxStatus, &outboxFailure, &deploymentState, &deploymentFailure, &eventCount, &auditCount,
	); err != nil {
		t.Fatal(err)
	}
	if outboxStatus != "exhausted" || outboxFailure != request.FailureCode ||
		deploymentState != DeploymentFailed || deploymentFailure != request.FailureCode ||
		eventCount != 2 || auditCount != 1 {
		t.Fatalf("terminal state = %q/%q %q/%q events=%d audits=%d", outboxStatus,
			outboxFailure, deploymentState, deploymentFailure, eventCount, auditCount)
	}
	health, err := fixture.service.AwaitHealthy(t.Context(), fixture.scopeID, fixture.siteID, publication.Revision, time.Millisecond)
	if err != nil || health.Healthy || health.FailedCount != 1 || health.PendingCount != 0 {
		t.Fatalf("failed health = %+v, %v", health, err)
	}
}

func TestTerminalDeliveryFailureConcurrentCompletionHasOneFact(t *testing.T) {
	fixture := newIntegrationFixture(t, 1, 1)
	if _, err := fixture.service.PublishSnapshot(t.Context(), fixture.request("terminal-concurrent", 0, fixture.challenges)); err != nil {
		t.Fatal(err)
	}
	deliveries, err := fixture.service.ClaimDeliveries(t.Context(), ClaimRequest{Limit: 1, LeaseDuration: time.Minute})
	if err != nil || len(deliveries) != 1 {
		t.Fatalf("claim = %+v, %v", deliveries, err)
	}
	request := CompleteDeliveryRequest{
		OutboxID: deliveries[0].OutboxID, LeaseToken: deliveries[0].LeaseToken,
		FailureCode: "artifact_integrity",
	}
	start := make(chan struct{})
	errorsByCall := make(chan error, 2)
	var wait sync.WaitGroup
	for range 2 {
		wait.Add(1)
		go func() {
			defer wait.Done()
			<-start
			errorsByCall <- fixture.service.CompleteDelivery(context.Background(), request)
		}()
	}
	close(start)
	wait.Wait()
	close(errorsByCall)
	for err := range errorsByCall {
		if err != nil {
			t.Fatalf("concurrent completion = %v", err)
		}
	}
	var events, audits int
	if err := fixture.pool.QueryRow(t.Context(), `SELECT
		(SELECT count(*) FROM acme_http01_overlay_deployment_events
		 WHERE deployment_id=$1 AND state='failed'),
		(SELECT count(*) FROM audit_events
		 WHERE action='acme_http01_overlay.delivery_failed' AND resource_id=$1::text)`,
		deliveries[0].DeploymentID).Scan(&events, &audits); err != nil {
		t.Fatal(err)
	}
	if events != 1 || audits != 1 {
		t.Fatalf("terminal events=%d audits=%d", events, audits)
	}
}

func TestTerminalDeliveryFailureAuditRollbackPreservesClaim(t *testing.T) {
	fixture := newIntegrationFixture(t, 1, 1)
	if _, err := fixture.service.PublishSnapshot(t.Context(), fixture.request("terminal-audit-rollback", 0, fixture.challenges)); err != nil {
		t.Fatal(err)
	}
	deliveries, err := fixture.service.ClaimDeliveries(t.Context(), ClaimRequest{Limit: 1, LeaseDuration: time.Minute})
	if err != nil || len(deliveries) != 1 {
		t.Fatalf("claim = %+v, %v", deliveries, err)
	}
	failing := fixture.newService(t, failingAuditAppender{})
	request := CompleteDeliveryRequest{
		OutboxID: deliveries[0].OutboxID, LeaseToken: deliveries[0].LeaseToken,
		FailureCode: "artifact_integrity",
	}
	if err := failing.CompleteDelivery(t.Context(), request); err == nil {
		t.Fatal("terminal delivery with failing audit unexpectedly succeeded")
	}
	var status, eventState string
	var failure *string
	var eventCount int
	if err := fixture.pool.QueryRow(t.Context(), `
		SELECT outbox.status,outbox.last_failure_code,event.state,
		       (SELECT count(*) FROM acme_http01_overlay_deployment_events
		        WHERE deployment_id=$2 AND deployment_attempt=$3)
		FROM acme_http01_overlay_outbox_states outbox
		JOIN LATERAL (
			SELECT state FROM acme_http01_overlay_deployment_events
			WHERE deployment_id=$2 AND deployment_attempt=$3 ORDER BY sequence DESC LIMIT 1
		) event ON true WHERE outbox.outbox_id=$1`, request.OutboxID,
		deliveries[0].DeploymentID, deliveries[0].DeploymentAttempt).Scan(
		&status, &failure, &eventState, &eventCount,
	); err != nil {
		t.Fatal(err)
	}
	if status != "claimed" || failure != nil || eventState != DeploymentQueued || eventCount != 1 {
		t.Fatalf("rolled back state = %q failure=%v event=%q count=%d", status, failure, eventState, eventCount)
	}
	if err := fixture.service.CompleteDelivery(t.Context(), request); err != nil {
		t.Fatalf("completion after rollback = %v", err)
	}
}

func TestRetryableDeliveryFailureExhaustsAtAttemptOneHundred(t *testing.T) {
	fixture := newIntegrationFixture(t, 1, 1)
	if _, err := fixture.service.PublishSnapshot(t.Context(), fixture.request("delivery-attempt-limit", 0, fixture.challenges)); err != nil {
		t.Fatal(err)
	}
	for attempt := 1; attempt <= maximumOutboxPublishAttempts; attempt++ {
		deliveries, err := fixture.service.ClaimDeliveries(t.Context(), ClaimRequest{Limit: 1, LeaseDuration: time.Minute})
		if err != nil || len(deliveries) != 1 || deliveries[0].PublishAttempt != attempt {
			t.Fatalf("claim attempt %d = %+v, %v", attempt, deliveries, err)
		}
		if err := fixture.service.CompleteDelivery(t.Context(), CompleteDeliveryRequest{
			OutboxID: deliveries[0].OutboxID, LeaseToken: deliveries[0].LeaseToken,
			Retryable: true, FailureCode: "publish_unavailable",
		}); err != nil {
			t.Fatalf("complete attempt %d = %v", attempt, err)
		}
		var status, deploymentState string
		if err := fixture.pool.QueryRow(t.Context(), `
			SELECT outbox.status,event.state
			FROM acme_http01_overlay_outbox_states outbox
			JOIN acme_http01_overlay_outbox fact ON fact.id=outbox.outbox_id
			JOIN LATERAL (
				SELECT state FROM acme_http01_overlay_deployment_events
				WHERE deployment_id=fact.deployment_id AND deployment_attempt=fact.deployment_attempt
				ORDER BY sequence DESC LIMIT 1
			) event ON true`).Scan(&status, &deploymentState); err != nil {
			t.Fatal(err)
		}
		if attempt < maximumOutboxPublishAttempts {
			if status != "retry" || deploymentState != DeploymentQueued {
				t.Fatalf("attempt %d state = %q/%q", attempt, status, deploymentState)
			}
			fixture.now = fixture.now.Add(3 * time.Second)
			continue
		}
		if status != "exhausted" || deploymentState != DeploymentFailed {
			t.Fatalf("terminal attempt state = %q/%q", status, deploymentState)
		}
	}
}

func TestReconcilePublishedNoStatusTimesOutAndRetriesAtomically(t *testing.T) {
	fixture := newIntegrationFixture(t, 1, 1)
	publication, err := fixture.service.PublishSnapshot(t.Context(), fixture.request("reconcile-no-status", 0, fixture.challenges))
	if err != nil {
		t.Fatal(err)
	}
	deliveries, err := fixture.service.ClaimDeliveries(t.Context(), ClaimRequest{Limit: 1, LeaseDuration: time.Minute})
	if err != nil || len(deliveries) != 1 {
		t.Fatalf("claim = %+v, %v", deliveries, err)
	}
	if err := fixture.service.CompleteDelivery(t.Context(), CompleteDeliveryRequest{
		OutboxID: deliveries[0].OutboxID, LeaseToken: deliveries[0].LeaseToken, Published: true,
	}); err != nil {
		t.Fatal(err)
	}
	reconcileAt := fixture.now.Add(2 * time.Minute)
	result, err := fixture.service.ReconcileDeployments(t.Context(), ReconcileRequest{
		Now: reconcileAt, AttemptTimeout: time.Minute, Limit: 10,
	})
	if err != nil || result != (ReconcileResult{TimedOut: 1, Retried: 1}) {
		t.Fatalf("reconcile = %+v, %v", result, err)
	}
	expectedRequestID := uuid.NewSHA1(deliveries[0].DeploymentID, []byte("acme-http01/reconcile/2"))
	var latestAttempt int
	var latestState string
	var retryRequestID uuid.UUID
	var deadline time.Time
	if err := fixture.pool.QueryRow(t.Context(), `
		SELECT deployment.attempt,event.state,deployment.retry_request_id,deployment.deadline_at
		FROM acme_http01_overlay_deployments deployment
		JOIN LATERAL (
			SELECT state FROM acme_http01_overlay_deployment_events
			WHERE deployment_id=deployment.id AND deployment_attempt=deployment.attempt
			ORDER BY sequence DESC LIMIT 1
		) event ON true
		WHERE deployment.id=$1 ORDER BY deployment.attempt DESC LIMIT 1`, deliveries[0].DeploymentID).Scan(
		&latestAttempt, &latestState, &retryRequestID, &deadline,
	); err != nil {
		t.Fatal(err)
	}
	if latestAttempt != 2 || latestState != DeploymentRetryQueued || retryRequestID != expectedRequestID ||
		!deadline.Equal(fixture.now.Add(10*time.Minute)) {
		t.Fatalf("retry = attempt=%d state=%q request=%s deadline=%s publication=%+v", latestAttempt,
			latestState, retryRequestID, deadline, publication)
	}
	var timedOutEvents, timeoutAudits, retryAudits int
	if err := fixture.pool.QueryRow(t.Context(), `SELECT
		(SELECT count(*) FROM acme_http01_overlay_deployment_events
		 WHERE deployment_id=$1 AND state='timed_out'),
		(SELECT count(*) FROM audit_events
		 WHERE resource_id=$1::text AND action='acme_http01_overlay.timeout'),
		(SELECT count(*) FROM audit_events
		 WHERE resource_id=$1::text AND action='acme_http01_overlay.retry')`,
		deliveries[0].DeploymentID).Scan(&timedOutEvents, &timeoutAudits, &retryAudits); err != nil {
		t.Fatal(err)
	}
	if timedOutEvents != 1 || timeoutAudits != 1 || retryAudits != 1 {
		t.Fatalf("events=%d timeout_audits=%d retry_audits=%d", timedOutEvents, timeoutAudits, retryAudits)
	}
	replay, err := fixture.newService(t, nil).ReconcileDeployments(t.Context(), ReconcileRequest{
		Now: reconcileAt, AttemptTimeout: time.Minute, Limit: 10,
	})
	if err != nil || replay != (ReconcileResult{}) {
		t.Fatalf("restart replay = %+v, %v", replay, err)
	}
}

func TestReconcilePendingAndLiveClaimDoNotConsumeAttempts(t *testing.T) {
	t.Run("pending waits for global deadline", func(t *testing.T) {
		fixture := newIntegrationFixture(t, 1, 1)
		if _, err := fixture.service.PublishSnapshot(t.Context(), fixture.request("reconcile-pending", 0, fixture.challenges)); err != nil {
			t.Fatal(err)
		}
		result, err := fixture.service.ReconcileDeployments(t.Context(), ReconcileRequest{
			Now: fixture.now.Add(2 * time.Minute), AttemptTimeout: time.Minute, Limit: 10,
		})
		if err != nil || result != (ReconcileResult{}) {
			t.Fatalf("pending reconcile = %+v, %v", result, err)
		}
		result, err = fixture.service.ReconcileDeployments(t.Context(), ReconcileRequest{
			Now: fixture.now.Add(11 * time.Minute), AttemptTimeout: time.Minute, Limit: 10,
		})
		if err != nil || result != (ReconcileResult{TimedOut: 1}) {
			t.Fatalf("global deadline reconcile = %+v, %v", result, err)
		}
	})

	t.Run("live claim is not fenced", func(t *testing.T) {
		fixture := newIntegrationFixture(t, 1, 1)
		if _, err := fixture.service.PublishSnapshot(t.Context(), fixture.request("reconcile-live-claim", 0, fixture.challenges)); err != nil {
			t.Fatal(err)
		}
		publishedAt := fixture.now
		fixture.now = publishedAt.Add(9 * time.Minute)
		if deliveries, err := fixture.service.ClaimDeliveries(t.Context(), ClaimRequest{Limit: 1, LeaseDuration: 5 * time.Minute}); err != nil || len(deliveries) != 1 {
			t.Fatalf("claim = %+v, %v", deliveries, err)
		}
		result, err := fixture.service.ReconcileDeployments(t.Context(), ReconcileRequest{
			Now: publishedAt.Add(11 * time.Minute), AttemptTimeout: time.Minute, Limit: 10,
		})
		if err != nil || result != (ReconcileResult{}) {
			t.Fatalf("live claim reconcile = %+v, %v", result, err)
		}
		result, err = fixture.service.ReconcileDeployments(t.Context(), ReconcileRequest{
			Now: publishedAt.Add(15 * time.Minute), AttemptTimeout: time.Minute, Limit: 10,
		})
		if err != nil || result != (ReconcileResult{TimedOut: 1}) {
			t.Fatalf("expired claim reconcile = %+v, %v", result, err)
		}
	})
}

func TestReconcileHonorsMaxAttemptsAndAuditRollback(t *testing.T) {
	t.Run("max attempts", func(t *testing.T) {
		fixture := newIntegrationFixture(t, 1, 1)
		request := fixture.request("reconcile-max", 0, fixture.challenges)
		request.MaxAttempts = 1
		if _, err := fixture.service.PublishSnapshot(t.Context(), request); err != nil {
			t.Fatal(err)
		}
		deliveries, err := fixture.service.ClaimDeliveries(t.Context(), ClaimRequest{Limit: 1, LeaseDuration: time.Minute})
		if err != nil || len(deliveries) != 1 {
			t.Fatalf("claim = %+v, %v", deliveries, err)
		}
		if err := fixture.service.CompleteDelivery(t.Context(), CompleteDeliveryRequest{
			OutboxID: deliveries[0].OutboxID, LeaseToken: deliveries[0].LeaseToken, Published: true,
		}); err != nil {
			t.Fatal(err)
		}
		result, err := fixture.service.ReconcileDeployments(t.Context(), ReconcileRequest{
			Now: fixture.now.Add(2 * time.Minute), AttemptTimeout: time.Minute, Limit: 10,
		})
		if err != nil || result != (ReconcileResult{TimedOut: 1}) {
			t.Fatalf("max attempts reconcile = %+v, %v", result, err)
		}
	})

	t.Run("audit rollback", func(t *testing.T) {
		fixture := newIntegrationFixture(t, 1, 1)
		if _, err := fixture.service.PublishSnapshot(t.Context(), fixture.request("reconcile-audit", 0, fixture.challenges)); err != nil {
			t.Fatal(err)
		}
		deliveries, err := fixture.service.ClaimDeliveries(t.Context(), ClaimRequest{Limit: 1, LeaseDuration: time.Minute})
		if err != nil || len(deliveries) != 1 {
			t.Fatalf("claim = %+v, %v", deliveries, err)
		}
		if err := fixture.service.CompleteDelivery(t.Context(), CompleteDeliveryRequest{
			OutboxID: deliveries[0].OutboxID, LeaseToken: deliveries[0].LeaseToken, Published: true,
		}); err != nil {
			t.Fatal(err)
		}
		reconcileRequest := ReconcileRequest{Now: fixture.now.Add(2 * time.Minute), AttemptTimeout: time.Minute, Limit: 10}
		if result, err := fixture.newService(t, failingAuditAppender{}).ReconcileDeployments(t.Context(), reconcileRequest); err == nil || result != (ReconcileResult{}) {
			t.Fatalf("failing audit reconcile = %+v, %v", result, err)
		}
		var attempts int
		var state string
		if err := fixture.pool.QueryRow(t.Context(), `
			SELECT count(*),(
				SELECT event.state FROM acme_http01_overlay_deployment_events event
				WHERE event.deployment_id=$1 ORDER BY event.deployment_attempt DESC,event.sequence DESC LIMIT 1
			) FROM acme_http01_overlay_deployments WHERE id=$1`, deliveries[0].DeploymentID).Scan(&attempts, &state); err != nil {
			t.Fatal(err)
		}
		if attempts != 1 || state != DeploymentDispatched {
			t.Fatalf("rollback attempts=%d state=%q", attempts, state)
		}
		if result, err := fixture.service.ReconcileDeployments(t.Context(), reconcileRequest); err != nil ||
			result != (ReconcileResult{TimedOut: 1, Retried: 1}) {
			t.Fatalf("reconcile after rollback = %+v, %v", result, err)
		}
	})
}

func TestReconcileConcurrentWorkersProduceOneRetry(t *testing.T) {
	fixture := newIntegrationFixture(t, 1, 1)
	if _, err := fixture.service.PublishSnapshot(t.Context(), fixture.request("reconcile-concurrent", 0, fixture.challenges)); err != nil {
		t.Fatal(err)
	}
	deliveries, err := fixture.service.ClaimDeliveries(t.Context(), ClaimRequest{Limit: 1, LeaseDuration: time.Minute})
	if err != nil || len(deliveries) != 1 {
		t.Fatalf("claim = %+v, %v", deliveries, err)
	}
	if err := fixture.service.CompleteDelivery(t.Context(), CompleteDeliveryRequest{
		OutboxID: deliveries[0].OutboxID, LeaseToken: deliveries[0].LeaseToken, Published: true,
	}); err != nil {
		t.Fatal(err)
	}
	request := ReconcileRequest{Now: fixture.now.Add(2 * time.Minute), AttemptTimeout: time.Minute, Limit: 10}
	start := make(chan struct{})
	results := make(chan ReconcileResult, 2)
	errorsByWorker := make(chan error, 2)
	var wait sync.WaitGroup
	for range 2 {
		wait.Add(1)
		go func() {
			defer wait.Done()
			<-start
			result, err := fixture.service.ReconcileDeployments(context.Background(), request)
			results <- result
			errorsByWorker <- err
		}()
	}
	close(start)
	wait.Wait()
	close(results)
	close(errorsByWorker)
	for err := range errorsByWorker {
		if err != nil {
			t.Fatalf("concurrent reconcile = %v", err)
		}
	}
	var total ReconcileResult
	for result := range results {
		total.TimedOut += result.TimedOut
		total.Retried += result.Retried
	}
	if total != (ReconcileResult{TimedOut: 1, Retried: 1}) {
		t.Fatalf("combined result = %+v", total)
	}
	var attempts int
	if err := fixture.pool.QueryRow(t.Context(), `SELECT count(*) FROM acme_http01_overlay_deployments WHERE id=$1`,
		deliveries[0].DeploymentID).Scan(&attempts); err != nil {
		t.Fatal(err)
	}
	if attempts != 2 {
		t.Fatalf("deployment attempts = %d", attempts)
	}
}

func TestRetryDeploymentAndReconcilerRaceProducesOneRetry(t *testing.T) {
	fixture := newIntegrationFixture(t, 1, 1)
	if _, err := fixture.service.PublishSnapshot(t.Context(), fixture.request("retry-reconcile-race", 0, fixture.challenges)); err != nil {
		t.Fatal(err)
	}
	deliveries, err := fixture.service.ClaimDeliveries(t.Context(), ClaimRequest{Limit: 1, LeaseDuration: time.Minute})
	if err != nil || len(deliveries) != 1 {
		t.Fatalf("claim = %+v, %v", deliveries, err)
	}
	if err := fixture.service.CompleteDelivery(t.Context(), CompleteDeliveryRequest{
		OutboxID: deliveries[0].OutboxID, LeaseToken: deliveries[0].LeaseToken, Published: true,
	}); err != nil {
		t.Fatal(err)
	}
	markDeliveryTimedOut(t, fixture, deliveries[0])

	start := make(chan struct{})
	reconcileResults := make(chan ReconcileResult, 1)
	manualErrors := make(chan error, 1)
	reconcileErrors := make(chan error, 1)
	var wait sync.WaitGroup
	wait.Add(2)
	go func() {
		defer wait.Done()
		<-start
		_, err := fixture.service.RetryDeployment(context.Background(), RetryRequest{
			DeploymentID: deliveries[0].DeploymentID,
			Deadline:     fixture.now.Add(10 * time.Minute),
			RequestID:    uuid.NewString(),
		})
		manualErrors <- err
	}()
	go func() {
		defer wait.Done()
		<-start
		result, err := fixture.service.ReconcileDeployments(context.Background(), ReconcileRequest{
			Now: fixture.now.Add(3 * time.Second), AttemptTimeout: time.Minute, Limit: 10,
		})
		reconcileResults <- result
		reconcileErrors <- err
	}()
	close(start)
	wait.Wait()
	if err := <-manualErrors; err != nil && !errors.Is(err, ErrInvalidTransition) {
		t.Fatalf("manual retry race = %v", err)
	}
	if err := <-reconcileErrors; err != nil {
		t.Fatalf("reconcile race = %v", err)
	}
	if result := <-reconcileResults; result != (ReconcileResult{}) && result != (ReconcileResult{Retried: 1}) {
		t.Fatalf("reconcile result = %+v", result)
	}
	var attempts, retryAudits int
	if err := fixture.pool.QueryRow(t.Context(), `SELECT
		(SELECT count(*) FROM acme_http01_overlay_deployments WHERE id=$1),
		(SELECT count(*) FROM audit_events
		 WHERE resource_id=$1::text AND action='acme_http01_overlay.retry')`,
		deliveries[0].DeploymentID).Scan(&attempts, &retryAudits); err != nil {
		t.Fatal(err)
	}
	if attempts != 2 || retryAudits != 1 {
		t.Fatalf("attempts=%d retry_audits=%d", attempts, retryAudits)
	}
}

func TestRetryDeploymentConcurrentSameRequestReplaysWinner(t *testing.T) {
	fixture := newIntegrationFixture(t, 1, 1)
	if _, err := fixture.service.PublishSnapshot(t.Context(), fixture.request("retry-idempotency-race", 0, fixture.challenges)); err != nil {
		t.Fatal(err)
	}
	deliveries, err := fixture.service.ClaimDeliveries(t.Context(), ClaimRequest{Limit: 1, LeaseDuration: time.Minute})
	if err != nil || len(deliveries) != 1 {
		t.Fatalf("claim = %+v, %v", deliveries, err)
	}
	if err := fixture.service.CompleteDelivery(t.Context(), CompleteDeliveryRequest{
		OutboxID: deliveries[0].OutboxID, LeaseToken: deliveries[0].LeaseToken, Published: true,
	}); err != nil {
		t.Fatal(err)
	}
	markDeliveryTimedOut(t, fixture, deliveries[0])
	request := RetryRequest{
		DeploymentID: deliveries[0].DeploymentID,
		Deadline:     fixture.now.Add(10 * time.Minute),
		RequestID:    uuid.NewString(),
	}
	start := make(chan struct{})
	results := make(chan Outbox, 2)
	errorsByCall := make(chan error, 2)
	var wait sync.WaitGroup
	for range 2 {
		wait.Add(1)
		go func() {
			defer wait.Done()
			<-start
			outbox, err := fixture.service.RetryDeployment(context.Background(), request)
			results <- outbox
			errorsByCall <- err
		}()
	}
	close(start)
	wait.Wait()
	close(results)
	close(errorsByCall)
	for err := range errorsByCall {
		if err != nil {
			t.Fatalf("concurrent retry replay = %v", err)
		}
	}
	var winner uuid.UUID
	for outbox := range results {
		if outbox.DeploymentAttempt != 2 || outbox.DeploymentID != deliveries[0].DeploymentID {
			t.Fatalf("retry outbox = %+v", outbox)
		}
		if winner == uuid.Nil {
			winner = outbox.ID
		} else if outbox.ID != winner {
			t.Fatalf("retry outbox IDs differ: %s != %s", outbox.ID, winner)
		}
	}
	var attempts, retryAudits int
	if err := fixture.pool.QueryRow(t.Context(), `SELECT
		(SELECT count(*) FROM acme_http01_overlay_deployments WHERE id=$1),
		(SELECT count(*) FROM audit_events
		 WHERE resource_id=$1::text AND action='acme_http01_overlay.retry')`,
		deliveries[0].DeploymentID).Scan(&attempts, &retryAudits); err != nil {
		t.Fatal(err)
	}
	if attempts != 2 || retryAudits != 1 {
		t.Fatalf("attempts=%d retry_audits=%d", attempts, retryAudits)
	}
}

func TestRetryDeploymentReplayRejectsDifferentBinding(t *testing.T) {
	fixture := newIntegrationFixture(t, 2, 1)
	if _, err := fixture.service.PublishSnapshot(t.Context(), fixture.request("retry-binding", 0, fixture.challenges)); err != nil {
		t.Fatal(err)
	}
	deliveries, err := fixture.service.ClaimDeliveries(t.Context(), ClaimRequest{Limit: 10, LeaseDuration: time.Minute})
	if err != nil || len(deliveries) != 2 {
		t.Fatalf("claim = %+v, %v", deliveries, err)
	}
	for _, delivery := range deliveries {
		if err := fixture.service.CompleteDelivery(t.Context(), CompleteDeliveryRequest{
			OutboxID: delivery.OutboxID, LeaseToken: delivery.LeaseToken, Published: true,
		}); err != nil {
			t.Fatal(err)
		}
		markDeliveryTimedOut(t, fixture, delivery)
	}
	requestID := uuid.NewString()
	deadline := fixture.now.Add(10 * time.Minute)
	if _, err := fixture.service.RetryDeployment(t.Context(), RetryRequest{
		DeploymentID: deliveries[0].DeploymentID, Deadline: deadline, RequestID: requestID,
	}); err != nil {
		t.Fatal(err)
	}
	tests := []struct {
		name       string
		deployment uuid.UUID
		deadline   time.Time
	}{
		{name: "different deployment", deployment: deliveries[1].DeploymentID, deadline: deadline},
		{name: "different deadline", deployment: deliveries[0].DeploymentID, deadline: deadline.Add(-time.Minute)},
	}
	for _, test := range tests {
		t.Run(test.name, func(t *testing.T) {
			if _, err := fixture.service.RetryDeployment(t.Context(), RetryRequest{
				DeploymentID: test.deployment, Deadline: test.deadline, RequestID: requestID,
			}); !errors.Is(err, ErrIdempotencyConflict) {
				t.Fatalf("retry replay binding error = %v", err)
			}
		})
	}
	var attempts, retryAudits int
	if err := fixture.pool.QueryRow(t.Context(), `SELECT
		(SELECT count(*) FROM acme_http01_overlay_deployments),
		(SELECT count(*) FROM audit_events WHERE action='acme_http01_overlay.retry')`).Scan(
		&attempts, &retryAudits,
	); err != nil {
		t.Fatal(err)
	}
	if attempts != 3 || retryAudits != 1 {
		t.Fatalf("attempts=%d retry_audits=%d", attempts, retryAudits)
	}
}

func TestCompleteDeliveryAndReconcilerRaceConvergesWithoutDeadlock(t *testing.T) {
	fixture := newIntegrationFixture(t, 1, 1)
	if _, err := fixture.service.PublishSnapshot(t.Context(), fixture.request("complete-reconcile-race", 0, fixture.challenges)); err != nil {
		t.Fatal(err)
	}
	deliveries, err := fixture.service.ClaimDeliveries(t.Context(), ClaimRequest{Limit: 1, LeaseDuration: time.Minute})
	if err != nil || len(deliveries) != 1 {
		t.Fatalf("claim = %+v, %v", deliveries, err)
	}

	start := make(chan struct{})
	reconcileResults := make(chan ReconcileResult, 1)
	errorsByCall := make(chan error, 2)
	var wait sync.WaitGroup
	wait.Add(2)
	go func() {
		defer wait.Done()
		<-start
		errorsByCall <- fixture.service.CompleteDelivery(context.Background(), CompleteDeliveryRequest{
			OutboxID: deliveries[0].OutboxID, LeaseToken: deliveries[0].LeaseToken, Published: true,
		})
	}()
	go func() {
		defer wait.Done()
		<-start
		result, err := fixture.service.ReconcileDeployments(context.Background(), ReconcileRequest{
			Now: fixture.now.Add(11 * time.Minute), AttemptTimeout: time.Minute, Limit: 10,
		})
		reconcileResults <- result
		errorsByCall <- err
	}()
	close(start)
	wait.Wait()
	close(errorsByCall)
	for err := range errorsByCall {
		if err != nil && !errors.Is(err, ErrClaimLost) {
			t.Fatalf("complete/reconcile race = %v", err)
		}
	}
	first := <-reconcileResults
	second, err := fixture.service.ReconcileDeployments(t.Context(), ReconcileRequest{
		Now: fixture.now.Add(11 * time.Minute), AttemptTimeout: time.Minute, Limit: 10,
	})
	if err != nil {
		t.Fatal(err)
	}
	if first.TimedOut+second.TimedOut != 1 || first.Retried != 0 || second.Retried != 0 {
		t.Fatalf("reconcile results first=%+v second=%+v", first, second)
	}
	state := latestDeploymentWithState(t, fixture.pool, deliveries[0].VersionID, DeploymentTimedOut)
	if state.DeploymentAttempt != 1 {
		t.Fatalf("timed out state = %+v", state)
	}
}

func TestReconcileExcludesHealthyFailedAndStaleAttempts(t *testing.T) {
	fixture := newIntegrationFixture(t, 3, 1)
	publication, err := fixture.service.PublishSnapshot(t.Context(), fixture.request("reconcile-terminal-exclusion", 0, fixture.challenges))
	if err != nil {
		t.Fatal(err)
	}
	deliveries, err := fixture.service.ClaimDeliveries(t.Context(), ClaimRequest{Limit: 10, LeaseDuration: time.Minute})
	if err != nil || len(deliveries) != 3 {
		t.Fatalf("claim = %+v, %v", deliveries, err)
	}
	completeDeliveryHealthy(t, fixture, deliveries[0])
	for _, delivery := range deliveries[1:] {
		if err := fixture.service.CompleteDelivery(t.Context(), CompleteDeliveryRequest{
			OutboxID: delivery.OutboxID, LeaseToken: delivery.LeaseToken, Published: true,
		}); err != nil {
			t.Fatal(err)
		}
	}
	if _, err := fixture.service.RecordReceipt(t.Context(), Receipt{
		DeploymentID: deliveries[1].DeploymentID, DeploymentAttempt: 1, ReceiptID: uuid.New(),
		State: DeploymentFailed, FailureCode: "edge_apply_failed", OccurredAt: fixture.now,
	}); err != nil {
		t.Fatal(err)
	}
	markDeliveryTimedOut(t, fixture, deliveries[2])
	if _, err := fixture.service.RetryDeployment(t.Context(), RetryRequest{
		DeploymentID: deliveries[2].DeploymentID,
		Deadline:     fixture.now.Add(10 * time.Minute),
		RequestID:    uuid.NewString(),
	}); err != nil {
		t.Fatal(err)
	}
	result, err := fixture.service.ReconcileDeployments(t.Context(), ReconcileRequest{
		Now: fixture.now.Add(3 * time.Second), AttemptTimeout: time.Minute, Limit: 10,
	})
	if err != nil || result != (ReconcileResult{}) {
		t.Fatalf("terminal/stale reconcile = %+v, %v", result, err)
	}
	var attempts int
	if err := fixture.pool.QueryRow(t.Context(), `
		SELECT count(*) FROM acme_http01_overlay_deployments WHERE version_id=$1`, publication.VersionID).Scan(&attempts); err != nil {
		t.Fatal(err)
	}
	if attempts != 4 {
		t.Fatalf("deployment attempts = %d", attempts)
	}
}

func TestMigrationDownRejectsExistingOverlayFacts(t *testing.T) {
	fixture := newIntegrationFixture(t, 1, 1)
	if _, err := fixture.service.PublishSnapshot(t.Context(), fixture.request("down-rejects-facts", 0, fixture.challenges)); err != nil {
		t.Fatal(err)
	}
	var before int
	if err := fixture.pool.QueryRow(t.Context(), `SELECT max(version) FROM schema_migrations`).Scan(&before); err != nil {
		t.Fatal(err)
	}
	assertSQLState(t, applyOverlayMigration(t.Context(), fixture.pool, "down"), "P0001")
	var version int
	if err := fixture.pool.QueryRow(t.Context(), `SELECT max(version) FROM schema_migrations`).Scan(&version); err != nil {
		t.Fatal(err)
	}
	if version != before || !relationExistsForOverlay(t, fixture.pool) {
		t.Fatalf("migration version after refused down = %d, want %d with overlay tables kept", version, before)
	}
}

func TestConcurrentApplyAndCleanupAndConcurrentRemovalsNeverReintroduceTokens(t *testing.T) {
	fixture := newIntegrationFixture(t, 1, 2)
	if _, err := fixture.service.PublishSnapshot(t.Context(), fixture.request("concurrent-base", 0, fixture.challenges[:1])); err != nil {
		t.Fatal(err)
	}
	type outcome struct {
		request     PublishRequest
		publication Publication
		err         error
	}
	runConcurrent := func(requests ...PublishRequest) []outcome {
		start := make(chan struct{})
		results := make(chan outcome, len(requests))
		var wait sync.WaitGroup
		for _, request := range requests {
			request := request
			wait.Add(1)
			go func() {
				defer wait.Done()
				<-start
				publication, err := fixture.service.PublishSnapshot(context.Background(), request)
				results <- outcome{request: request, publication: publication, err: err}
			}()
		}
		close(start)
		wait.Wait()
		close(results)
		var collected []outcome
		for result := range results {
			collected = append(collected, result)
		}
		return collected
	}

	apply := fixture.request("concurrent-add", 1, fixture.challenges)
	remove := fixture.cleanupRequest("concurrent-remove", 1, nil)
	results := runConcurrent(apply, remove)
	var winner outcome
	conflicts := 0
	for _, result := range results {
		if result.err == nil {
			winner = result
		} else if errors.Is(result.err, ErrRevisionConflict) {
			conflicts++
		} else {
			t.Fatalf("concurrent add/remove error = %v", result.err)
		}
	}
	if winner.publication.Revision != 2 || conflicts != 1 {
		t.Fatalf("add/remove winner=%+v conflicts=%d", winner.publication, conflicts)
	}
	currentRevision := int64(2)
	if winner.request.Mode == ModeCleanup {
		retryApply := fixture.request("concurrent-add-retry", currentRevision, fixture.challenges)
		publication, err := fixture.service.PublishSnapshot(t.Context(), retryApply)
		if err != nil {
			t.Fatal(err)
		}
		currentRevision = publication.Revision
	}

	removeFirst := fixture.cleanupRequest("remove-first", currentRevision, fixture.challenges[:1])
	removeSecond := fixture.cleanupRequest("remove-second", currentRevision, fixture.challenges[1:])
	results = runConcurrent(removeFirst, removeSecond)
	conflicts = 0
	winner = outcome{}
	for _, result := range results {
		if result.err == nil {
			winner = result
		} else if errors.Is(result.err, ErrRevisionConflict) {
			conflicts++
		} else {
			t.Fatalf("concurrent removes error = %v", result.err)
		}
	}
	if winner.publication.TokenCount != 1 || conflicts != 1 {
		t.Fatalf("remove winner=%+v conflicts=%d", winner.publication, conflicts)
	}
	currentRevision = winner.publication.Revision
	currentRefs := currentVersionReferences(t, fixture.pool, fixture.siteID, currentRevision)
	staleDesired := fixture.challenges[:1]
	if currentRefs[0] == fixture.challenges[0] {
		staleDesired = fixture.challenges[1:]
	}
	staleRetry := fixture.cleanupRequest("stale-remove-must-not-readd", currentRevision, staleDesired)
	if _, err := fixture.service.PublishSnapshot(t.Context(), staleRetry); !errors.Is(err, ErrChallengeIneligible) {
		t.Fatalf("stale cleanup reintroduction error = %v", err)
	}
	empty, err := fixture.service.PublishSnapshot(t.Context(), fixture.cleanupRequest("remove-final", currentRevision, nil))
	if err != nil || empty.TokenCount != 0 {
		t.Fatalf("final empty cleanup = %+v, %v", empty, err)
	}
	deliveries, err := fixture.service.ClaimDeliveries(t.Context(), ClaimRequest{Limit: 100, LeaseDuration: time.Minute})
	if err != nil {
		t.Fatal(err)
	}
	foundEmpty := false
	for _, delivery := range deliveries {
		if delivery.VersionID == empty.VersionID {
			foundEmpty = delivery.Mode == ModeCleanup && len(delivery.Tokens) == 0
		}
	}
	if !foundEmpty {
		t.Fatal("final empty cleanup snapshot was not dispatched")
	}
}

func makeVersionHealthy(t *testing.T, fixture *integrationFixture, publication Publication) {
	t.Helper()
	deliveries, err := fixture.service.ClaimDeliveries(t.Context(), ClaimRequest{Limit: 10, LeaseDuration: time.Minute})
	if err != nil || len(deliveries) != publication.NodeCount {
		t.Fatalf("claim version = %d, %v", len(deliveries), err)
	}
	for _, delivery := range deliveries {
		completeDeliveryHealthy(t, fixture, delivery)
	}
}

func markDeliveryTimedOut(t *testing.T, fixture *integrationFixture, delivery SealedDelivery) {
	t.Helper()
	if err := pgx.BeginFunc(t.Context(), fixture.pool, func(tx pgx.Tx) error {
		_, err := appendDeploymentEvent(t.Context(), tx, delivery.DeploymentID, delivery.DeploymentAttempt,
			DeploymentTimedOut, uuid.Nil, [32]byte{}, "deployment_timed_out", fixture.now)
		return err
	}); err != nil {
		t.Fatal(err)
	}
}

func completeDeliveryHealthy(t *testing.T, fixture *integrationFixture, delivery SealedDelivery) {
	t.Helper()
	if err := fixture.service.CompleteDelivery(t.Context(), CompleteDeliveryRequest{
		OutboxID: delivery.OutboxID, LeaseToken: delivery.LeaseToken, Published: true,
	}); err != nil {
		t.Fatal(err)
	}
	for _, state := range []string{DeploymentApplied, DeploymentHealthy} {
		if _, err := fixture.service.RecordReceipt(t.Context(), Receipt{
			DeploymentID: delivery.DeploymentID, DeploymentAttempt: delivery.DeploymentAttempt,
			ReceiptID: uuid.New(), State: state, OccurredAt: fixture.now,
		}); err != nil {
			t.Fatalf("record %s: %v", state, err)
		}
	}
}

func assertDirectCleanupIdentityTamperRejected(
	t *testing.T,
	fixture *integrationFixture,
	priorVersionID uuid.UUID,
	field string,
) {
	t.Helper()
	tx, err := fixture.pool.Begin(t.Context())
	if err != nil {
		t.Fatal(err)
	}
	defer func() { _ = tx.Rollback(context.Background()) }()

	var operationID, domain, keyID string
	var attemptID uuid.UUID
	var tokenDigest, valueDigest, nonce, ciphertext, aadDigest []byte
	if err := tx.QueryRow(t.Context(), `
		SELECT operation_id,challenge_attempt_id,domain,token_sha256,value_sha256,
		       key_id,nonce,ciphertext,aad_sha256
		FROM acme_http01_overlay_token_facts WHERE version_id=$1`, priorVersionID).Scan(
		&operationID, &attemptID, &domain, &tokenDigest, &valueDigest,
		&keyID, &nonce, &ciphertext, &aadDigest,
	); err != nil {
		t.Fatal(err)
	}
	flip := func(value []byte) []byte {
		result := append([]byte(nil), value...)
		result[0] ^= 0xff
		return result
	}
	switch field {
	case "domain":
		domain = "tampered.example.test"
	case "token_sha256":
		tokenDigest = flip(tokenDigest)
	case "value_sha256":
		valueDigest = flip(valueDigest)
	case "aad_sha256":
		aadDigest = flip(aadDigest)
	default:
		t.Fatalf("unknown tamper field %q", field)
	}

	publicationID, versionID := uuid.New(), uuid.New()
	deploymentID, outboxID := uuid.New(), uuid.New()
	createdAt := fixture.now.Add(time.Second)
	requestDigest := sha256.Sum256([]byte("cleanup-request/" + field))
	snapshotDigest := sha256.Sum256([]byte("cleanup-snapshot/" + field))
	payloadDigest := sha256.Sum256([]byte("cleanup-payload/" + field))
	statements := []struct {
		query string
		args  []any
	}{
		{`INSERT INTO acme_http01_overlay_publications(
			id,mode,tenant_scope_id,site_id,expected_revision,revision,idempotency_key,
			request_digest,request_id,token_count,node_count,max_attempts,deadline_at,created_at
		) VALUES($1,'cleanup',$2,$3,1,2,$4,$5,$6,1,1,3,$7,$8)`, []any{
			publicationID, fixture.scopeID, fixture.siteID, "direct-cleanup-" + field,
			requestDigest[:], uuid.New(), createdAt.Add(10 * time.Minute), createdAt,
		}},
		{`INSERT INTO acme_http01_overlay_versions(
			id,publication_id,tenant_scope_id,site_id,revision,sealed_snapshot_sha256,created_at
		) VALUES($1,$2,$3,$4,2,$5,$6)`, []any{
			versionID, publicationID, fixture.scopeID, fixture.siteID, snapshotDigest[:], createdAt,
		}},
		{`INSERT INTO acme_http01_overlay_token_facts(
			version_id,tenant_scope_id,site_id,revision,ordinal,operation_id,challenge_attempt_id,
			domain,token_sha256,value_sha256,key_id,nonce,ciphertext,aad_sha256,created_at
		) VALUES($1,$2,$3,2,1,$4,$5,$6,$7,$8,$9,$10,$11,$12,$13)`, []any{
			versionID, fixture.scopeID, fixture.siteID, operationID, attemptID, domain,
			tokenDigest, valueDigest, keyID, nonce, ciphertext, aadDigest, createdAt,
		}},
		{`INSERT INTO acme_http01_overlay_targets(
			version_id,tenant_scope_id,site_id,revision,ordinal,node_id,created_at
		) VALUES($1,$2,$3,2,1,$4,$5)`, []any{
			versionID, fixture.scopeID, fixture.siteID, fixture.nodeIDs[0], createdAt,
		}},
		{`INSERT INTO acme_http01_overlay_deployments(
			id,attempt,version_id,tenant_scope_id,site_id,revision,node_id,retry_request_id,
			deadline_at,max_attempts,created_at
		) VALUES($1,1,$2,$3,$4,2,$5,NULL,$6,3,$7)`, []any{
			deploymentID, versionID, fixture.scopeID, fixture.siteID, fixture.nodeIDs[0],
			createdAt.Add(10 * time.Minute), createdAt,
		}},
		{`INSERT INTO acme_http01_overlay_deployment_events(
			deployment_id,deployment_attempt,sequence,state,occurred_at
		) VALUES($1,1,1,'queued',$2)`, []any{deploymentID, createdAt}},
		{`INSERT INTO acme_http01_overlay_outbox(
			id,deployment_id,deployment_attempt,version_id,node_id,subject,payload_sha256,created_at
		) VALUES($1,$2,1,$3,$4,$5,$6,$7)`, []any{
			outboxID, deploymentID, versionID, fixture.nodeIDs[0],
			"edge.acme.http01." + fixture.nodeIDs[0].String(), payloadDigest[:], createdAt,
		}},
		{`INSERT INTO acme_http01_overlay_outbox_states(
			outbox_id,status,publish_attempts,available_at,updated_at
		) VALUES($1,'pending',0,$2,$2)`, []any{outboxID, createdAt}},
		{`UPDATE acme_http01_overlay_states
		 SET current_revision=2,updated_at=$3
		 WHERE tenant_scope_id=$1 AND site_id=$2 AND current_revision=1`, []any{
			fixture.scopeID, fixture.siteID, createdAt,
		}},
	}
	for _, statement := range statements {
		if _, err := tx.Exec(t.Context(), statement.query, statement.args...); err != nil {
			assertSQLState(t, err, "P0001")
			return
		}
	}
	assertSQLState(t, tx.Commit(t.Context()), "P0001")
}

func latestDeploymentWithState(t *testing.T, pool *pgxpool.Pool, versionID uuid.UUID, state string) DeploymentState {
	t.Helper()
	var result DeploymentState
	err := pool.QueryRow(t.Context(), `
		SELECT deployment.id,deployment.attempt,deployment.version_id,deployment.node_id,
		       event.state,event.sequence,deployment.deadline_at,event.occurred_at
		FROM acme_http01_overlay_deployments deployment
		JOIN LATERAL (
			SELECT state,sequence,occurred_at FROM acme_http01_overlay_deployment_events
			WHERE deployment_id=deployment.id AND deployment_attempt=deployment.attempt
			ORDER BY sequence DESC LIMIT 1
		) event ON event.state=$2
		WHERE deployment.version_id=$1
		ORDER BY deployment.attempt DESC LIMIT 1`, versionID, state).Scan(
		&result.DeploymentID, &result.DeploymentAttempt, &result.VersionID, &result.NodeID,
		&result.State, &result.Sequence, &result.Deadline, &result.OccurredAt,
	)
	if err != nil {
		t.Fatal(err)
	}
	return result
}

func assertOverlayCounts(t *testing.T, pool *pgxpool.Pool, publications, versions, tokens, targets, deployments, outbox int) {
	t.Helper()
	var actual [6]int
	if err := pool.QueryRow(t.Context(), `SELECT
		(SELECT count(*) FROM acme_http01_overlay_publications),
		(SELECT count(*) FROM acme_http01_overlay_versions),
		(SELECT count(*) FROM acme_http01_overlay_token_facts),
		(SELECT count(*) FROM acme_http01_overlay_targets),
		(SELECT count(*) FROM acme_http01_overlay_deployments),
		(SELECT count(*) FROM acme_http01_overlay_outbox)`).Scan(
		&actual[0], &actual[1], &actual[2], &actual[3], &actual[4], &actual[5]); err != nil {
		t.Fatal(err)
	}
	expected := [6]int{publications, versions, tokens, targets, deployments, outbox}
	if actual != expected {
		t.Fatalf("overlay counts=%v want=%v", actual, expected)
	}
}

func assertNoOverlayPlaintext(t *testing.T, fixture *integrationFixture) {
	t.Helper()
	var material string
	if err := fixture.pool.QueryRow(t.Context(), `SELECT concat_ws('|',
		COALESCE((SELECT string_agg(encode(ciphertext,'escape'),'|') FROM acme_http01_overlay_token_facts),''),
		COALESCE((SELECT string_agg(payload::text,'|') FROM audit_events WHERE action LIKE 'acme_http01_overlay.%'),''),
		COALESCE((SELECT string_agg(subject,'|') FROM acme_http01_overlay_outbox),'')
	)`).Scan(&material); err != nil {
		t.Fatal(err)
	}
	for _, secret := range fixture.plaintext {
		if strings.Contains(material, secret) {
			t.Fatalf("overlay persistence contains challenge plaintext")
		}
	}
}

func currentVersionReferences(
	t *testing.T,
	pool *pgxpool.Pool,
	siteID uuid.UUID,
	revision int64,
) []ChallengeReference {
	t.Helper()
	rows, err := pool.Query(t.Context(), `
		SELECT token.operation_id,token.challenge_attempt_id
		FROM acme_http01_overlay_versions version
		JOIN acme_http01_overlay_token_facts token ON token.version_id=version.id
		WHERE version.site_id=$1 AND version.revision=$2
		ORDER BY token.operation_id,token.challenge_attempt_id`, siteID, revision)
	if err != nil {
		t.Fatal(err)
	}
	defer rows.Close()
	var references []ChallengeReference
	for rows.Next() {
		var reference ChallengeReference
		if err := rows.Scan(&reference.OperationID, &reference.AttemptID); err != nil {
			t.Fatal(err)
		}
		references = append(references, reference)
	}
	if err := rows.Err(); err != nil {
		t.Fatal(err)
	}
	return references
}

func seedIntegrationTenant(t *testing.T, fixture *integrationFixture) {
	t.Helper()
	tenantID := fixture.tenantID
	username := "overlay-" + strings.ReplaceAll(fixture.userID.String(), "-", "")[:16]
	tx, err := fixture.pool.Begin(t.Context())
	if err != nil {
		t.Fatal(err)
	}
	defer func() { _ = tx.Rollback(context.Background()) }()
	queries := []struct {
		sql  string
		args []any
	}{
		{`INSERT INTO tenants(id,display_name) VALUES($1,'Overlay tenant')`, []any{tenantID}},
		{`INSERT INTO access_scopes(id,kind,tenant_id) VALUES($1,'tenant',$2)`, []any{fixture.scopeID, tenantID}},
		{`INSERT INTO users(id,username,display_name,password_hash) VALUES($1,$2,'Overlay user','unused')`, []any{fixture.userID, username}},
		{`INSERT INTO memberships(scope_id,user_id) VALUES($1,$2)`, []any{fixture.scopeID, fixture.userID}},
		{`INSERT INTO sites(id,scope_id,owner_user_id,domain,http_ports,origins,origin_hosts,
			created_by_user_id,updated_by_user_id,display_id) VALUES($1,$2,$3,$4,ARRAY['80'],ARRAY['192.0.2.1'],
			ARRAY['192.0.2.1'],$3,$3,1)`, []any{fixture.siteID, fixture.scopeID, fixture.userID, fixture.domain}},
		{`INSERT INTO site_origin_pools(site_id) VALUES($1)`, []any{fixture.siteID}},
		{`INSERT INTO site_origins(site_id,position,host,port) VALUES($1,1,'192.0.2.1',80)`, []any{fixture.siteID}},
	}
	for _, query := range queries {
		if _, err := tx.Exec(t.Context(), query.sql, query.args...); err != nil {
			t.Fatal(err)
		}
	}
	if err := tx.Commit(t.Context()); err != nil {
		t.Fatal(err)
	}
}

func seedIntegrationNode(t *testing.T, fixture *integrationFixture, nodeID uuid.UUID) {
	t.Helper()
	// display_id is required from migration 211 on and is unique per scope.
	if _, err := fixture.pool.Exec(t.Context(), `
		INSERT INTO nodes(id,scope_id,name,admin_state,created_by_user_id,display_id)
		VALUES($1,$2,$3,'active',$4,(SELECT COALESCE(max(display_id),0)+1 FROM nodes WHERE scope_id=$2))`, nodeID, fixture.scopeID,
		"overlay-node-"+strings.ReplaceAll(nodeID.String(), "-", "")[:12], fixture.userID); err != nil {
		t.Fatal(err)
	}
}

func seedHTTP01Challenge(
	t *testing.T,
	fixture *integrationFixture,
	ordinal int,
	materialOverride ...[2]string,
) (ChallengeReference, []string) {
	t.Helper()
	operationID := uuid.New()
	attemptID := uuid.New()
	leaseToken := uuid.New()
	tokenDigest := sha256.Sum256([]byte(fmt.Sprintf("http-token/%d/%s", ordinal, uuid.NewString())))
	thumbprintDigest := sha256.Sum256([]byte(fmt.Sprintf("http-thumbprint/%d/%s", ordinal, uuid.NewString())))
	token := base64.RawURLEncoding.EncodeToString(tokenDigest[:])
	exactValue := token + "." + base64.RawURLEncoding.EncodeToString(thumbprintDigest[:])
	if len(materialOverride) > 0 {
		token = materialOverride[0][0]
		exactValue = materialOverride[0][1]
	}
	accountKeyRef := fmt.Sprintf("account-key-%d", ordinal)
	certificateKeyRef := fmt.Sprintf("certificate-key-%d", ordinal)
	now := databaseNow(t, fixture.pool)
	snapshot := map[string]any{
		// Migration 047 binds the snapshot to the tenant, its tenant scope and an
		// active member of that scope.
		"TenantID": fixture.tenantID.String(), "ScopeID": fixture.scopeID.String(),
		"OperationID":  operationID.String(),
		"DirectoryURL": "https://ca.example/directory", "CertificateKeyRef": certificateKeyRef,
		"ActorUserID": fixture.userID.String(), "AccountKeyRef": accountKeyRef, "ProviderRef": "",
		"Domains": []string{fixture.domain}, "ChallengeType": "http-01",
	}
	snapshotBytes, err := json.Marshal(snapshot)
	if err != nil {
		t.Fatal(err)
	}
	requestDigest := sha256.Sum256(snapshotBytes)
	authorizationURL := "https://ca.example/authorization/" + operationID.String()
	accountURI := "https://ca.example/account/" + operationID.String()
	orderURL := "https://ca.example/order/" + operationID.String()
	finalizeURL := "https://ca.example/finalize/" + operationID.String()
	tx, err := fixture.pool.Begin(t.Context())
	if err != nil {
		t.Fatal(err)
	}
	defer func() { _ = tx.Rollback(context.Background()) }()
	var accountKeyID uuid.UUID
	for index, key := range []struct {
		ref, purpose string
	}{{accountKeyRef, "account"}, {certificateKeyRef, "certificate"}} {
		keyID := uuid.New()
		if key.purpose == "account" {
			accountKeyID = keyID
		}
		publicDigest := sha256.Sum256([]byte(fmt.Sprintf("%s/%d", operationID, index)))
		if _, err := tx.Exec(t.Context(), `
			INSERT INTO acme_tenant_key_facts(
				tenant_scope_id,id,key_ref,purpose,algorithm,public_key_spki_sha256,
				external_key_reference,created_by_user_id
			) VALUES($1,$2,$3,$4,'ecdsa',$5,$6,$7)`, fixture.scopeID, keyID, key.ref,
			key.purpose, publicDigest[:], "kms://overlay/"+key.ref, fixture.userID); err != nil {
			t.Fatal(err)
		}
	}
	if _, err := tx.Exec(t.Context(), `
		INSERT INTO certificate_orders(
			id,scope_id,domains,challenge_type,created_by_user_id,updated_by_user_id
		) VALUES($1,$2,$3,'http-01',$4,$4)`, operationID, fixture.scopeID,
		[]string{fixture.domain}, fixture.userID); err != nil {
		t.Fatal(err)
	}
	if _, err := tx.Exec(t.Context(), `
		INSERT INTO acme_account_registration_facts(
			tenant_scope_id,id,account_key_id,directory_url,account_uri,contacts,
			terms_agreed_at,registered_at,created_by_user_id
		) VALUES($1,$2,$3,'https://ca.example/directory',$4,ARRAY['mailto:ops@example.test'],
			$5,$5,$6)`, fixture.scopeID, uuid.New(), accountKeyID, accountURI, now, fixture.userID); err != nil {
		t.Fatal(err)
	}
	if _, err := tx.Exec(t.Context(), `
		INSERT INTO acme_issuance_operations(
			tenant_scope_id,operation_id,request_digest,request_snapshot,directory_url,
			certificate_key_ref,certificate_order_id,actor_user_id,dns_provider_id,
			account_key_ref,created_at
		) VALUES($1,$2,$3,$4,'https://ca.example/directory',$5,$6,$7,NULL,$8,$9)`,
		fixture.scopeID, operationID.String(), requestDigest[:], snapshotBytes, certificateKeyRef,
		operationID, fixture.userID, accountKeyRef, now); err != nil {
		t.Fatal(err)
	}
	events := []struct {
		revision    int
		eventType   string
		phase       string
		orderIntent bool
		accountURI  *string
		orderURL    *string
		finalizeURL *string
		authURLs    []string
	}{
		{revision: 1, eventType: "claim_created", phase: "claimed", authURLs: []string{}},
		{revision: 2, eventType: "account_registered", phase: "claimed", accountURI: &accountURI, authURLs: []string{}},
		{revision: 3, eventType: "order_intent", phase: "claimed", orderIntent: true, accountURI: &accountURI, authURLs: []string{}},
		{revision: 4, eventType: "order_created", phase: "ordered", accountURI: &accountURI,
			orderURL: &orderURL, finalizeURL: &finalizeURL, authURLs: []string{authorizationURL}},
		{revision: 5, eventType: "authorizing", phase: "authorizing", accountURI: &accountURI,
			orderURL: &orderURL, finalizeURL: &finalizeURL, authURLs: []string{authorizationURL}},
	}
	for _, event := range events {
		if _, err := tx.Exec(t.Context(), `
			INSERT INTO acme_issuance_operation_events(
				tenant_scope_id,operation_id,revision,event_type,phase,status,fence_token,
				order_intent_pending,lease_token,lease_expires_at,account_uri,order_url,
				finalize_url,authorization_urls,occurred_at
			) VALUES($1,$2,$3,$4,$5,'active',$6,$7,$6,$8,$9,$10,$11,$12,$13)`,
			fixture.scopeID, operationID.String(), event.revision, event.eventType, event.phase,
			leaseToken, event.orderIntent, now.Add(time.Hour), event.accountURI, event.orderURL,
			event.finalizeURL, event.authURLs, now); err != nil {
			t.Fatal(err)
		}
	}
	if _, err := tx.Exec(t.Context(), `
		INSERT INTO acme_issuance_challenge_attempts(
			tenant_scope_id,operation_id,attempt_id,attempt_number,authorization_url,
			challenge_url,challenge_type,identifier,wildcard,record_name,token,exact_value,created_at
		) VALUES($1,$2,$3,1,$4,$5,'http-01',$6,false,$6,$7,$8,$9)`, fixture.scopeID,
		operationID.String(), attemptID, authorizationURL,
		"https://ca.example/challenge/"+attemptID.String(), fixture.domain, token, exactValue, now); err != nil {
		t.Fatal(err)
	}
	if _, err := tx.Exec(t.Context(), `
		INSERT INTO acme_issuance_challenge_events(
			tenant_scope_id,operation_id,attempt_id,revision,state,lease_token,occurred_at
		) VALUES($1,$2,$3,1,'intent',$4,$5)`, fixture.scopeID, operationID.String(),
		attemptID, leaseToken, now); err != nil {
		t.Fatal(err)
	}
	if err := tx.Commit(t.Context()); err != nil {
		t.Fatal(err)
	}
	return ChallengeReference{OperationID: operationID.String(), AttemptID: attemptID}, []string{token, exactValue}
}

func seedOrdinaryActiveDeployment(t *testing.T, fixture *integrationFixture) {
	t.Helper()
	configID, rolloutID, deploymentID := uuid.New(), uuid.New(), uuid.New()
	snapshot := []byte(`{"ordinary":true}`)
	digest := sha256.Sum256(snapshot)
	command := []byte("ordinary-command")
	commandDigest := sha256.Sum256(command)
	tx, err := fixture.pool.Begin(t.Context())
	if err != nil {
		t.Fatal(err)
	}
	defer func() { _ = tx.Rollback(context.Background()) }()
	if _, err := tx.Exec(t.Context(), `
		INSERT INTO config_versions(
			id,configuration_scope_id,canonical_snapshot,canonical_snapshot_sha256,
			generator_name,generator_version,status,idempotency_key,request_digest,created_at,published_at
		) VALUES($1,$2,$3,$4,'integration','1','releasable',$5,$4,$6,$6)`,
		configID, fixture.scopeID, snapshot, digest[:], "ordinary-"+uuid.NewString(), fixture.now); err != nil {
		t.Fatal(err)
	}
	if _, err := tx.Exec(t.Context(), `
		INSERT INTO rollouts(
			id,configuration_scope_id,config_version_id,action,status,idempotency_key,
			request_digest,request_id,correlation_id,activation_timeout_ms,
			observation_window_ms,required_consecutive_successes,deadline_at,created_at,queued_at,updated_at
		) VALUES($1,$2,$3,'apply','queued',$4,$5,$6,$7,1000,1000,1,$8,$9,$9,$9)`,
		rolloutID, fixture.scopeID, configID, "ordinary-rollout-"+uuid.NewString(), digest[:],
		uuid.New(), uuid.New(), fixture.now.Add(time.Hour), fixture.now); err != nil {
		t.Fatal(err)
	}
	if _, err := tx.Exec(t.Context(), `
		INSERT INTO node_deployments(
			id,rollout_id,node_id,attempt,config_version_id,action,state,command_event_id,
			command_bytes,command_sha256,deadline_at,created_at,updated_at
		) VALUES($1,$2,$3,1,$4,'apply','queued',$5,$6,$7,$8,$9,$9)`, deploymentID,
		rolloutID, fixture.nodeIDs[0], configID, uuid.New(), command, commandDigest[:],
		fixture.now.Add(time.Hour), fixture.now); err != nil {
		t.Fatal(err)
	}
	if err := tx.Commit(t.Context()); err != nil {
		t.Fatal(err)
	}
}

func overlayCatalogSnapshot(t *testing.T, pool *pgxpool.Pool) string {
	t.Helper()
	var snapshot string
	if err := pool.QueryRow(t.Context(), `
		SELECT string_agg(kind||':'||name||':'||definition,E'\n' ORDER BY kind,name,definition)
		FROM (
			SELECT 'table' AS kind,c.relname AS name,
			       COALESCE(string_agg(a.attname||':'||format_type(a.atttypid,a.atttypmod)||':'||a.attnotnull,
			           ',' ORDER BY a.attnum),'') AS definition
			FROM pg_class c
			JOIN pg_attribute a ON a.attrelid=c.oid AND a.attnum > 0 AND NOT a.attisdropped
			WHERE c.relkind='r' AND c.relname LIKE 'acme_http01_overlay_%'
			GROUP BY c.relname
			UNION ALL
			SELECT 'index',indexname,indexdef FROM pg_indexes
			WHERE indexname LIKE 'acme_http01_overlay_%'
			UNION ALL
			SELECT 'function',p.proname,pg_get_functiondef(p.oid)
			FROM pg_proc p WHERE p.proname LIKE '%acme_http01_overlay%'
			UNION ALL
			SELECT 'trigger',t.tgname,pg_get_triggerdef(t.oid)
			FROM pg_trigger t WHERE NOT t.tgisinternal AND t.tgname LIKE 'acme_http01_overlay_%'
		) catalog`).Scan(&snapshot); err != nil {
		t.Fatal(err)
	}
	return snapshot
}

func assertSQLState(t *testing.T, err error, code string) {
	t.Helper()
	var postgresError *pgconn.PgError
	if !errors.As(err, &postgresError) || postgresError.Code != code {
		t.Fatalf("SQL error = %v, want state %s", err, code)
	}
}

func databaseNow(t *testing.T, pool *pgxpool.Pool) time.Time {
	t.Helper()
	var now time.Time
	if err := pool.QueryRow(t.Context(), "SELECT statement_timestamp()").Scan(&now); err != nil {
		t.Fatal(err)
	}
	return now.UTC().Truncate(time.Microsecond)
}

// openIntegrationDatabase returns a schema at the release head (a clone of
// TEST_DATABASE_TEMPLATE when it is set).
func openIntegrationDatabase(t *testing.T) *pgxpool.Pool {
	t.Helper()
	if os.Getenv("TEST_DATABASE_URL") == "" {
		t.Skip("TEST_DATABASE_URL is not set")
	}
	if pool := databasetest.ClonedMigratedPool(t, nil); pool != nil {
		return pool
	}
	pool := openIntegrationSchema(t)
	if err := database.Migrate(t.Context(), pool, "up"); err != nil {
		t.Fatalf("migrate ACME edge schema: %v", err)
	}
	return pool
}

// openIntegrationDatabaseThrough063 applies only migrations 1..063 so the 063
// overlay migration can round-trip on its own.
func openIntegrationDatabaseThrough063(t *testing.T) *pgxpool.Pool {
	t.Helper()
	pool := openIntegrationSchema(t)
	applyIntegrationMigrations(t, pool, 63)
	return pool
}

func openIntegrationSchema(t *testing.T) *pgxpool.Pool {
	t.Helper()
	databaseURL := os.Getenv("TEST_DATABASE_URL")
	if databaseURL == "" {
		t.Skip("TEST_DATABASE_URL is not set")
	}
	admin, err := pgxpool.New(t.Context(), databaseURL)
	if err != nil {
		t.Fatal(err)
	}
	schema := "acme_edge_" + strings.ReplaceAll(uuid.NewString(), "-", "")
	if !regexp.MustCompile(`^acme_edge_[a-f0-9]{32}$`).MatchString(schema) {
		t.Fatalf("unsafe schema %q", schema)
	}
	identifier := pgx.Identifier{schema}.Sanitize()
	if _, err := admin.Exec(t.Context(), "CREATE SCHEMA "+identifier); err != nil {
		admin.Close()
		t.Fatal(err)
	}
	config, err := pgxpool.ParseConfig(databaseURL)
	if err != nil {
		admin.Close()
		t.Fatal(err)
	}
	config.ConnConfig.RuntimeParams["search_path"] = schema
	pool, err := pgxpool.NewWithConfig(t.Context(), config)
	if err != nil {
		admin.Close()
		t.Fatal(err)
	}
	t.Cleanup(func() {
		pool.Close()
		if _, err := admin.Exec(context.Background(), "DROP SCHEMA "+identifier+" CASCADE"); err != nil {
			t.Errorf("drop integration schema: %v", err)
		}
		admin.Close()
	})
	return pool
}

func applyIntegrationMigrations(t *testing.T, pool *pgxpool.Pool, target int) {
	t.Helper()
	if _, err := pool.Exec(t.Context(), `CREATE TABLE schema_migrations(
		version bigint PRIMARY KEY,
		applied_at timestamptz NOT NULL DEFAULT statement_timestamp()
	)`); err != nil {
		t.Fatal(err)
	}
	for version := 1; version <= target; version++ {
		matches, err := fs.Glob(controlmigrations.FS, fmt.Sprintf("%03d_*.up.sql", version))
		if err != nil || len(matches) != 1 {
			t.Fatalf("migration %03d match count=%d error=%v", version, len(matches), err)
		}
		script, err := fs.ReadFile(controlmigrations.FS, matches[0])
		if err != nil {
			t.Fatal(err)
		}
		if err := pgx.BeginFunc(t.Context(), pool, func(tx pgx.Tx) error {
			if _, err := tx.Exec(t.Context(), string(script)); err != nil {
				return err
			}
			_, err := tx.Exec(t.Context(), `INSERT INTO schema_migrations(version) VALUES($1)`, version)
			return err
		}); err != nil {
			t.Fatalf("apply migration %03d (%s): %v", version, matches[0], err)
		}
	}
}

func relationExistsForOverlay(t *testing.T, pool *pgxpool.Pool) bool {
	t.Helper()
	var exists bool
	if err := pool.QueryRow(t.Context(),
		`SELECT to_regclass('acme_http01_overlay_states') IS NOT NULL`).Scan(&exists); err != nil {
		t.Fatal(err)
	}
	return exists
}

func applyOverlayMigration(ctx context.Context, pool *pgxpool.Pool, direction string) error {
	if direction != "up" && direction != "down" {
		return fmt.Errorf("invalid overlay migration direction %q", direction)
	}
	script, err := fs.ReadFile(controlmigrations.FS, "063_acme_http01_overlay."+direction+".sql")
	if err != nil {
		return err
	}
	return pgx.BeginFunc(ctx, pool, func(tx pgx.Tx) error {
		if _, err := tx.Exec(ctx, string(script)); err != nil {
			return err
		}
		if direction == "up" {
			_, err = tx.Exec(ctx, `INSERT INTO schema_migrations(version) VALUES(63)`)
		} else {
			_, err = tx.Exec(ctx, `DELETE FROM schema_migrations WHERE version=63`)
		}
		return err
	})
}
