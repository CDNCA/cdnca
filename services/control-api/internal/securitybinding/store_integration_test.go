package securitybinding

import (
	"bytes"
	"context"
	"crypto/ed25519"
	"crypto/sha256"
	"encoding/json"
	"errors"
	"os"
	"regexp"
	"slices"
	"strings"
	"sync"
	"sync/atomic"
	"testing"
	"time"

	"github.com/cdnca/cdnca/services/control-api/internal/audit"
	"github.com/cdnca/cdnca/services/control-api/internal/database"
	"github.com/cdnca/cdnca/services/control-api/internal/database/databasetest"
	"github.com/cdnca/cdnca/services/control-api/internal/securitybundle"
	"github.com/cdnca/cdnca/services/control-api/internal/securitypolicy"
	"github.com/google/uuid"
	"github.com/jackc/pgx/v5"
	"github.com/jackc/pgx/v5/pgxpool"
)

var bindingTestNow = time.Date(2026, 7, 22, 15, 0, 0, 0, time.UTC)

type testClock struct {
	mu  sync.RWMutex
	now time.Time
}

func (clock *testClock) Now() time.Time {
	clock.mu.RLock()
	defer clock.mu.RUnlock()
	return clock.now
}

func (clock *testClock) Advance(duration time.Duration) {
	clock.mu.Lock()
	defer clock.mu.Unlock()
	clock.now = clock.now.Add(duration)
}

type recordingSigner struct {
	keyID     string
	private   ed25519.PrivateKey
	public    ed25519.PublicKey
	fail      bool
	afterSign func()
	calls     atomic.Int64
}

func newRecordingSigner() *recordingSigner {
	seed := sha256.Sum256([]byte("security-binding-integration-signing-key"))
	private := ed25519.NewKeyFromSeed(seed[:])
	return &recordingSigner{
		keyID: "security-binding-test-key-v1", private: private,
		public: slices.Clone(private.Public().(ed25519.PublicKey)),
	}
}

func (signer *recordingSigner) KeyID() string { return signer.keyID }

func (signer *recordingSigner) PublicKey() ed25519.PublicKey {
	return slices.Clone(signer.public)
}

func (signer *recordingSigner) Sign(_ context.Context, payload []byte) ([]byte, error) {
	signer.calls.Add(1)
	if signer.fail {
		return nil, errors.New("injected signing failure")
	}
	signature := ed25519.Sign(signer.private, payload)
	if signer.afterSign != nil {
		signer.afterSign()
	}
	return signature, nil
}

type tenantResources struct {
	tenantID uuid.UUID
	scopeID  uuid.UUID
	userID   uuid.UUID
	siteID   uuid.UUID
	nodeID   uuid.UUID
	policyID uuid.UUID
	kind     string
}

type bindingFixture struct {
	pool     *pgxpool.Pool
	platform securitypolicy.Actor
	tenantA  tenantResources
	tenantB  tenantResources
}

func TestSecurityPublicationMigrationUpDownUp(t *testing.T) {
	// Migration 268's down is a deliberate one-way gate (P2682), so the 031
	// round trip loads only migrations 1..031 and then rolls forward to the head.
	pool := isolatedBindingSchema(t, false)
	const roundTripHead = 31
	if err := databasetest.MigrateThrough(context.Background(), pool, "up", roundTripHead); err != nil {
		t.Fatalf("up migration through %d: %v", roundTripHead, err)
	}
	if !relationExists(t, pool, "security_policy_publications") {
		t.Fatal("security_policy_publications is missing after up migration 031")
	}
	for migrationVersion(t, pool) > 30 {
		if err := databasetest.MigrateThrough(context.Background(), pool, "down", roundTripHead); err != nil {
			t.Fatalf("down migration %d: %v", migrationVersion(t, pool), err)
		}
	}
	if relationExists(t, pool, "security_policy_publications") {
		t.Fatal("security_policy_publications still exists after down migration")
	}
	if err := database.Migrate(context.Background(), pool, "up"); err != nil {
		t.Fatalf("second up migration 031: %v", err)
	}
	if !relationExists(t, pool, "security_policy_publications") {
		t.Fatal("security_policy_publications is missing after second up migration")
	}
}

func TestPublishPersistsReplaysAndEnforcesScopeAndVersions(t *testing.T) {
	fixture := newBindingFixture(t)
	clock := &testClock{now: bindingTestNow}
	signer := newRecordingSigner()
	store := newBindingStore(t, fixture.pool, signer, clock, 5*time.Minute)

	request := publishRequest(fixture.tenantA, "tenant-a-v1", 1, 0, 0)
	publication, err := store.Publish(context.Background(), tenantActor(fixture.tenantA), request)
	if err != nil {
		t.Fatalf("Publish: %v", err)
	}
	if publication.Replayed || publication.BindingRevision != 1 || publication.PolicyVersion != 1 ||
		publication.SigningKeyID != signer.keyID || !slices.Equal(publication.TargetNodeIDs, []uuid.UUID{fixture.tenantA.nodeID}) {
		t.Fatalf("publication = %#v", publication)
	}
	assertPersistedPublication(t, fixture.pool, publication, signer)
	for _, fact := range []struct {
		table   string
		trigger string
	}{
		{table: "security_policy_publications", trigger: "security_policy_publications_no_truncate"},
		{table: "security_policy_site_bindings", trigger: "security_policy_site_bindings_no_truncate"},
		{table: "security_policy_publication_targets", trigger: "security_policy_publication_targets_no_truncate"},
	} {
		var installed bool
		if err := fixture.pool.QueryRow(context.Background(), `
			SELECT EXISTS (
				SELECT 1 FROM pg_trigger
				WHERE tgrelid = to_regclass($1) AND tgname = $2 AND NOT tgisinternal
			)`, fact.table, fact.trigger).Scan(&installed); err != nil || !installed {
			t.Fatalf("truncate guard %s installed = %v, error = %v", fact.trigger, installed, err)
		}
		if _, err := fixture.pool.Exec(context.Background(),
			"TRUNCATE "+pgx.Identifier{fact.table}.Sanitize()+" CASCADE"); err == nil {
			t.Fatalf("truncate guard %s allowed %s to be cleared", fact.trigger, fact.table)
		}
	}

	replayed, err := store.Publish(context.Background(), tenantActor(fixture.tenantA), request)
	if err != nil {
		t.Fatalf("replay Publish: %v", err)
	}
	if !replayed.Replayed || replayed.BundleID != publication.BundleID || !bytes.Equal(replayed.BundleJSON, publication.BundleJSON) ||
		signer.calls.Load() != 1 {
		t.Fatalf("replay changed publication or resigned it: %#v calls=%d", replayed, signer.calls.Load())
	}

	changed := request
	changed.RolloutID = uuid.New()
	if _, err := store.Publish(context.Background(), tenantActor(fixture.tenantA), changed); !errors.Is(err, ErrIdempotencyConflict) {
		t.Fatalf("changed idempotent request error = %v, want ErrIdempotencyConflict", err)
	}
	if _, err := store.Publish(context.Background(), tenantActor(fixture.tenantA), publishRequest(fixture.tenantB, "cross-tenant", 1, 0, 0)); !errors.Is(err, ErrPermissionDenied) {
		t.Fatalf("cross-tenant Publish error = %v, want ErrPermissionDenied", err)
	}
	platformPublication, err := store.Publish(context.Background(), fixture.platform,
		publishRequest(fixture.tenantB, "platform-tenant-b", 1, 0, 0))
	if err != nil {
		t.Fatalf("platform Publish for tenant B: %v", err)
	}
	if _, err := fixture.pool.Exec(context.Background(), `UPDATE security_policy_site_bindings SET
		last_claimed_policy_version=2,last_bundle_id=$2,revision=revision+1,updated_at=$3
		WHERE id=$1`, publication.BindingID, platformPublication.BundleID, clock.Now()); err == nil {
		t.Fatal("binding accepted a last bundle from another tenant and binding")
	}

	addPolicyVersion(t, fixture.pool, fixture.tenantA, 2)
	if _, err := store.Publish(context.Background(), tenantActor(fixture.tenantA), publishRequest(fixture.tenantA, "stale-binding", 2, 0, 0)); !errors.Is(err, ErrBindingRevision) {
		t.Fatalf("stale binding error = %v, want ErrBindingRevision", err)
	}
	if _, err := store.Publish(context.Background(), tenantActor(fixture.tenantA), publishRequest(fixture.tenantA, "active-mismatch", 2, 1, 1)); !errors.Is(err, ErrActiveVersionConflict) {
		t.Fatalf("active mismatch error = %v, want ErrActiveVersionConflict", err)
	}
	if _, err := store.Publish(context.Background(), tenantActor(fixture.tenantA), publishRequest(fixture.tenantA, "non-monotonic", 1, 1, 0)); !errors.Is(err, ErrPolicyVersionConflict) {
		t.Fatalf("non-monotonic error = %v, want ErrPolicyVersionConflict", err)
	}
	oversized := publishRequest(fixture.tenantA, "too-many-targets", 2, 1, 0)
	oversized.TargetNodeIDs = make([]uuid.UUID, 10_001)
	if _, err := store.Publish(context.Background(), tenantActor(fixture.tenantA), oversized); !errors.Is(err, ErrInvalidInput) {
		t.Fatalf("oversized target error = %v, want ErrInvalidInput", err)
	}
	if err := audit.New(fixture.pool).VerifyScope(context.Background(), fixture.tenantA.scopeID); err != nil {
		t.Fatalf("VerifyScope: %v", err)
	}
}

func TestPublishRechecksLiveSecurityManagePermissionInsideClaimTransaction(t *testing.T) {
	fixture := newBindingFixture(t)
	clock := &testClock{now: bindingTestNow}
	store := newBindingStore(t, fixture.pool, newRecordingSigner(), clock, time.Minute)
	actor := tenantActor(fixture.tenantA)

	roleID := assignedSecurityManagerRole(t, fixture.pool, actor.ScopeID, actor.UserID)
	if _, err := fixture.pool.Exec(t.Context(), `DELETE FROM role_assignments
		WHERE scope_id=$1 AND user_id=$2 AND role_id=$3`, actor.ScopeID, actor.UserID, roleID); err != nil {
		t.Fatal(err)
	}
	if _, err := store.Publish(t.Context(), actor,
		publishRequest(fixture.tenantA, "permission-revoked", 1, 0, 0)); !errors.Is(err, ErrPermissionDenied) {
		t.Fatalf("Publish after live permission revocation error = %v, want ErrPermissionDenied", err)
	}
	assertCounts(t, fixture.pool, 0, 0, 0, 0)

	if _, err := fixture.pool.Exec(t.Context(), `INSERT INTO role_assignments(scope_id,user_id,role_id)
		VALUES($1,$2,$3)`, actor.ScopeID, actor.UserID, roleID); err != nil {
		t.Fatal(err)
	}
	publication, err := store.Publish(t.Context(), actor,
		publishRequest(fixture.tenantA, "permission-restored", 1, 0, 0))
	if err != nil || publication.BundleID == uuid.Nil {
		t.Fatalf("Publish after live permission restoration = (%#v, %v)", publication, err)
	}
}

func TestPublishRejectsUnsafeRequestIDs(t *testing.T) {
	fixture := newBindingFixture(t)
	clock := &testClock{now: bindingTestNow}
	store := newBindingStore(t, fixture.pool, newRecordingSigner(), clock, 5*time.Minute)

	for index, requestID := range []string{"bad\nrequest", "bad\x00request", "bad\u2028request", "bad\u2029request"} {
		request := publishRequest(fixture.tenantA, "unsafe-request-"+string(rune('a'+index)), 1, 0, 0)
		request.RequestID = requestID
		if _, err := store.Publish(context.Background(), tenantActor(fixture.tenantA), request); !errors.Is(err, ErrInvalidInput) {
			t.Fatalf("Publish request ID %q error = %v, want ErrInvalidInput", requestID, err)
		}
	}
	assertCounts(t, fixture.pool, 0, 0, 0, 0)

	publication, err := store.Publish(context.Background(), tenantActor(fixture.tenantA),
		publishRequest(fixture.tenantA, "safe-request", 1, 0, 0))
	if err != nil {
		t.Fatalf("Publish valid request: %v", err)
	}
	for _, requestID := range []string{"bad\nrequest", "bad\u2028request", "bad\u2029request"} {
		tx, err := fixture.pool.Begin(context.Background())
		if err != nil {
			t.Fatal(err)
		}
		if _, err = tx.Exec(context.Background(),
			"ALTER TABLE security_policy_publications DISABLE TRIGGER security_policy_publications_append_only"); err != nil {
			_ = tx.Rollback(context.Background())
			t.Fatal(err)
		}
		_, err = tx.Exec(context.Background(), `UPDATE security_policy_publications SET request_id=$2 WHERE id=$1`,
			publication.BundleID, requestID)
		_ = tx.Rollback(context.Background())
		if err == nil {
			t.Fatalf("database accepted unsafe request ID %q", requestID)
		}
	}
}

func TestPublishOnlyReleasesExpiredTargetsWithinTenant(t *testing.T) {
	fixture := newBindingFixture(t)
	clock := &testClock{now: bindingTestNow}
	store := newBindingStore(t, fixture.pool, newRecordingSigner(), clock, 2*time.Second)

	tenantBPublication, err := store.Publish(context.Background(), fixture.platform,
		publishRequest(fixture.tenantB, "tenant-b-expiring", 1, 0, 0))
	if err != nil {
		t.Fatalf("Publish tenant B: %v", err)
	}
	clock.Advance(3 * time.Second)
	if _, err := store.Publish(context.Background(), tenantActor(fixture.tenantA),
		publishRequest(fixture.tenantA, "tenant-a-after-b-expiry", 1, 0, 0)); err != nil {
		t.Fatalf("Publish tenant A: %v", err)
	}
	var releasedAt *time.Time
	if err := fixture.pool.QueryRow(context.Background(), `SELECT released_at
		FROM security_policy_publication_targets WHERE publication_id=$1 AND node_id=$2`,
		tenantBPublication.BundleID, fixture.tenantB.nodeID).Scan(&releasedAt); err != nil {
		t.Fatal(err)
	}
	if releasedAt != nil {
		t.Fatalf("tenant A publication released tenant B target at %v", *releasedAt)
	}
}

func TestConcurrentNodeClaimHasOneWinner(t *testing.T) {
	fixture := newBindingFixture(t)
	clock := &testClock{now: bindingTestNow}
	store := newBindingStore(t, fixture.pool, newRecordingSigner(), clock, 5*time.Minute)
	secondSite := insertSite(t, fixture.pool, fixture.tenantA, "second.example.test")
	secondPolicy := insertPolicy(t, fixture.pool, fixture.tenantA, securitypolicy.KindACL, "second-policy", 1)

	requests := []PublishRequest{
		publishRequest(fixture.tenantA, "claim-one", 1, 0, 0),
		{
			TenantScopeID: fixture.tenantA.scopeID, SiteID: secondSite, PolicyID: secondPolicy,
			PolicyVersion: 1, TargetNodeIDs: []uuid.UUID{fixture.tenantA.nodeID}, RolloutID: uuid.New(),
			IdempotencyKey: "claim-two", RequestID: "claim-two", ExpectedBindingRevision: 0,
		},
	}
	errorsFound := make(chan error, len(requests))
	var wait sync.WaitGroup
	for _, request := range requests {
		wait.Add(1)
		go func(input PublishRequest) {
			defer wait.Done()
			_, err := store.Publish(context.Background(), tenantActor(fixture.tenantA), input)
			errorsFound <- err
		}(request)
	}
	wait.Wait()
	close(errorsFound)
	var successes, conflicts int
	for err := range errorsFound {
		switch {
		case err == nil:
			successes++
		case errors.Is(err, ErrTargetConflict):
			conflicts++
		default:
			t.Fatalf("unexpected concurrent Publish error: %v", err)
		}
	}
	if successes != 1 || conflicts != 1 {
		t.Fatalf("successes/conflicts = %d/%d, want 1/1", successes, conflicts)
	}
	assertCounts(t, fixture.pool, 1, 1, 1, 1)
}

func TestPublishFailuresRollbackAllState(t *testing.T) {
	fixture := newBindingFixture(t)
	clock := &testClock{now: bindingTestNow}

	failingSigner := newRecordingSigner()
	failingSigner.fail = true
	failingStore := newBindingStore(t, fixture.pool, failingSigner, clock, time.Minute)
	if _, err := failingStore.Publish(context.Background(), tenantActor(fixture.tenantA),
		publishRequest(fixture.tenantA, "signing-failure", 1, 0, 0)); !errors.Is(err, securitybundle.ErrSigningFailed) {
		t.Fatalf("signing failure error = %v, want ErrSigningFailed", err)
	}
	assertCounts(t, fixture.pool, 0, 0, 0, 0)

	if _, err := fixture.pool.Exec(context.Background(), `
		CREATE FUNCTION reject_security_publication_audit() RETURNS trigger LANGUAGE plpgsql AS $$
		BEGIN
			IF NEW.action='security_policy.publication.claim' THEN
				RAISE EXCEPTION 'injected security publication audit failure';
			END IF;
			RETURN NEW;
		END $$;
		CREATE TRIGGER reject_security_publication_audit_trigger
		BEFORE INSERT ON audit_events FOR EACH ROW EXECUTE FUNCTION reject_security_publication_audit()`); err != nil {
		t.Fatalf("install audit failure trigger: %v", err)
	}
	goodStore := newBindingStore(t, fixture.pool, newRecordingSigner(), clock, time.Minute)
	if _, err := goodStore.Publish(context.Background(), tenantActor(fixture.tenantA),
		publishRequest(fixture.tenantA, "audit-failure", 1, 0, 0)); err == nil || !strings.Contains(err.Error(), "injected security publication audit failure") {
		t.Fatalf("audit failure error = %v", err)
	}
	if _, err := fixture.pool.Exec(context.Background(), `
		DROP TRIGGER reject_security_publication_audit_trigger ON audit_events;
		DROP FUNCTION reject_security_publication_audit()`); err != nil {
		t.Fatalf("remove audit failure trigger: %v", err)
	}
	assertCounts(t, fixture.pool, 0, 0, 0, 0)

	slowSigner := newRecordingSigner()
	slowSigner.afterSign = func() { clock.Advance(2 * time.Second) }
	slowStore := newBindingStore(t, fixture.pool, slowSigner, clock, time.Second)
	if _, err := slowStore.Publish(context.Background(), tenantActor(fixture.tenantA),
		publishRequest(fixture.tenantA, "expired-before-claim", 1, 0, 0)); !errors.Is(err, ErrPlanExpired) {
		t.Fatalf("expired plan error = %v, want ErrPlanExpired", err)
	}
	assertCounts(t, fixture.pool, 0, 0, 0, 0)
}

func TestExpiredReplayReleaseAndActiveStateSurvivePolicyDeletion(t *testing.T) {
	fixture := newBindingFixture(t)
	clock := &testClock{now: bindingTestNow}
	signer := newRecordingSigner()
	store := newBindingStore(t, fixture.pool, signer, clock, 2*time.Second)
	request := publishRequest(fixture.tenantA, "expiring-v1", 1, 0, 0)
	first, err := store.Publish(context.Background(), tenantActor(fixture.tenantA), request)
	if err != nil {
		t.Fatalf("Publish v1: %v", err)
	}
	clock.Advance(3 * time.Second)
	replayed, err := store.Publish(context.Background(), tenantActor(fixture.tenantA), request)
	if err != nil || !replayed.Replayed || replayed.BundleID != first.BundleID || signer.calls.Load() != 1 {
		t.Fatalf("expired replay = (%#v, %v), signer calls=%d", replayed, err, signer.calls.Load())
	}
	var publications, targets, openTargets int
	if err := fixture.pool.QueryRow(context.Background(), `SELECT count(*) FROM security_policy_publications`).Scan(&publications); err != nil {
		t.Fatal(err)
	}
	if err := fixture.pool.QueryRow(context.Background(), `SELECT count(*),count(*) FILTER (WHERE released_at IS NULL) FROM security_policy_publication_targets`).
		Scan(&targets, &openTargets); err != nil {
		t.Fatal(err)
	}
	if publications != 1 || targets != 1 || openTargets != 1 {
		t.Fatalf("expired replay publications/targets/open = %d/%d/%d, want 1/1/1", publications, targets, openTargets)
	}

	addPolicyVersion(t, fixture.pool, fixture.tenantA, 2)
	secondRequest := publishRequest(fixture.tenantA, "replacement-v2", 2, 1, 0)
	second, err := store.Publish(context.Background(), tenantActor(fixture.tenantA), secondRequest)
	if err != nil {
		t.Fatalf("Publish v2 after expiry: %v", err)
	}
	var expired, open int
	if err := fixture.pool.QueryRow(context.Background(), `SELECT
		count(*) FILTER (WHERE release_reason='expired'), count(*) FILTER (WHERE released_at IS NULL)
		FROM security_policy_publication_targets`).Scan(&expired, &open); err != nil {
		t.Fatal(err)
	}
	if expired != 1 || open != 1 {
		t.Fatalf("expired/open claims = %d/%d, want 1/1", expired, open)
	}

	clock.Advance(time.Second)
	if _, err := fixture.pool.Exec(context.Background(), `UPDATE security_policy_site_bindings
		SET active_policy_version=2,revision=revision+1,updated_at=$2 WHERE id=$1`, second.BindingID, clock.Now()); err != nil {
		t.Fatalf("simulate activation: %v", err)
	}
	if _, err := fixture.pool.Exec(context.Background(), `UPDATE security_policies
		SET enabled=false,deleted_at=$2,updated_at=$2 WHERE id=$1`, fixture.tenantA.policyID, clock.Now()); err != nil {
		t.Fatalf("disable and delete policy: %v", err)
	}
	replayedSecond, err := store.Publish(context.Background(), tenantActor(fixture.tenantA), secondRequest)
	if err != nil || !replayedSecond.Replayed || replayedSecond.BundleID != second.BundleID || signer.calls.Load() != 2 {
		t.Fatalf("deleted-policy replay = (%#v, %v), signer calls=%d", replayedSecond, err, signer.calls.Load())
	}
	var activeVersion int64
	if err := fixture.pool.QueryRow(context.Background(), `SELECT active_policy_version
		FROM security_policy_site_bindings WHERE id=$1`, second.BindingID).Scan(&activeVersion); err != nil {
		t.Fatal(err)
	}
	if activeVersion != 2 {
		t.Fatalf("active policy version = %d, want 2", activeVersion)
	}
	if err := fixture.pool.QueryRow(context.Background(), `SELECT count(*) FROM security_policy_publications`).Scan(&publications); err != nil {
		t.Fatal(err)
	}
	if publications != 2 {
		t.Fatalf("publication count after policy deletion = %d, want 2", publications)
	}
}

func newBindingStore(t *testing.T, pool *pgxpool.Pool, signer *recordingSigner, clock *testClock, validity time.Duration) *Store {
	t.Helper()
	publisher, err := securitybundle.NewPublisher(signer, securitybundle.Config{Clock: clock.Now, Validity: validity})
	if err != nil {
		t.Fatalf("NewPublisher: %v", err)
	}
	store, err := NewStore(pool, publisher, clock.Now)
	if err != nil {
		t.Fatalf("NewStore: %v", err)
	}
	return store
}

func publishRequest(resources tenantResources, key string, policyVersion, bindingRevision, activeVersion int64) PublishRequest {
	return PublishRequest{
		TenantScopeID: resources.scopeID, SiteID: resources.siteID, PolicyID: resources.policyID,
		PolicyVersion: policyVersion, TargetNodeIDs: []uuid.UUID{resources.nodeID},
		ExpectedBindingRevision: bindingRevision, ExpectedActiveVersion: activeVersion,
		RolloutID: uuid.New(), IdempotencyKey: key, RequestID: key,
	}
}

func tenantActor(resources tenantResources) securitypolicy.Actor {
	return securitypolicy.Actor{UserID: resources.userID, ScopeID: resources.scopeID, ScopeKind: "tenant"}
}

func newBindingFixture(t *testing.T) bindingFixture {
	t.Helper()
	pool := isolatedBindingPool(t)
	platformScope, platformUser := uuid.New(), uuid.New()
	insertScopeUser(t, pool, platformScope, platformUser, uuid.Nil, "platform", "binding-platform")
	return bindingFixture{
		pool:     pool,
		platform: securitypolicy.Actor{UserID: platformUser, ScopeID: platformScope, ScopeKind: "platform"},
		tenantA:  insertTenantResources(t, pool, "a", securitypolicy.KindCC),
		tenantB:  insertTenantResources(t, pool, "b", securitypolicy.KindWAF),
	}
}

func insertTenantResources(t *testing.T, pool *pgxpool.Pool, suffix, kind string) tenantResources {
	t.Helper()
	resources := tenantResources{
		tenantID: uuid.New(), scopeID: uuid.New(), userID: uuid.New(), nodeID: uuid.New(), kind: kind,
	}
	insertScopeUser(t, pool, resources.scopeID, resources.userID, resources.tenantID, "tenant", "binding-"+suffix)
	resources.siteID = insertSite(t, pool, resources, suffix+".example.test")
	resources.policyID = insertPolicy(t, pool, resources, kind, "policy-"+suffix, 1)
	if _, err := pool.Exec(context.Background(), `INSERT INTO nodes
		(id,display_id,scope_id,name,admin_state,created_by_user_id) VALUES($1,1,$2,$3,'active',$4)`,
		resources.nodeID, resources.scopeID, "node-"+suffix, resources.userID); err != nil {
		t.Fatalf("insert node: %v", err)
	}
	return resources
}

func insertScopeUser(t *testing.T, pool *pgxpool.Pool, scopeID, userID, tenantID uuid.UUID, kind, username string) {
	t.Helper()
	if kind == "tenant" {
		if _, err := pool.Exec(context.Background(), `INSERT INTO tenants(id,display_name) VALUES($1,$2)`, tenantID, username); err != nil {
			t.Fatalf("insert tenant: %v", err)
		}
		if _, err := pool.Exec(context.Background(), `INSERT INTO access_scopes(id,kind,tenant_id) VALUES($1,'tenant',$2)`, scopeID, tenantID); err != nil {
			t.Fatalf("insert tenant scope: %v", err)
		}
	} else if _, err := pool.Exec(context.Background(), `INSERT INTO access_scopes(id,kind) VALUES($1,'platform')`, scopeID); err != nil {
		t.Fatalf("insert platform scope: %v", err)
	}
	if _, err := pool.Exec(context.Background(), `INSERT INTO users(id,username,display_name,password_hash)
		VALUES($1,$2,$2,'test-password-hash')`, userID, username); err != nil {
		t.Fatalf("insert user: %v", err)
	}
	if _, err := pool.Exec(context.Background(), `INSERT INTO memberships(scope_id,user_id) VALUES($1,$2)`, scopeID, userID); err != nil {
		t.Fatalf("insert membership: %v", err)
	}
	roleID := uuid.New()
	roleName := "platform_admin"
	if kind == "tenant" {
		roleName = "tenant_owner"
	}
	if _, err := pool.Exec(context.Background(), `INSERT INTO roles(id,scope_id,name,description,system_role)
		VALUES($1,$2,$3,'security publication integration manager',true)`, roleID, scopeID, roleName); err != nil {
		t.Fatalf("insert security manager role: %v", err)
	}
	if _, err := pool.Exec(context.Background(), `INSERT INTO role_permissions(role_id,permission_name)
		VALUES($1,'security_policies.manage') ON CONFLICT DO NOTHING`, roleID); err != nil {
		t.Fatalf("grant security manager permission: %v", err)
	}
	if _, err := pool.Exec(context.Background(), `INSERT INTO role_assignments(scope_id,user_id,role_id)
		VALUES($1,$2,$3)`, scopeID, userID, roleID); err != nil {
		t.Fatalf("assign security manager role: %v", err)
	}
}

func assignedSecurityManagerRole(t *testing.T, pool *pgxpool.Pool, scopeID, userID uuid.UUID) uuid.UUID {
	t.Helper()
	var roleID uuid.UUID
	if err := pool.QueryRow(t.Context(), `SELECT assignment.role_id
		FROM role_assignments assignment
		JOIN role_permissions permission ON permission.role_id=assignment.role_id
		WHERE assignment.scope_id=$1 AND assignment.user_id=$2
		  AND permission.permission_name='security_policies.manage'`, scopeID, userID).Scan(&roleID); err != nil {
		t.Fatal(err)
	}
	return roleID
}

func insertSite(t *testing.T, pool *pgxpool.Pool, resources tenantResources, domain string) uuid.UUID {
	t.Helper()
	siteID := uuid.New()
	err := pgx.BeginFunc(context.Background(), pool, func(tx pgx.Tx) error {
		if _, err := tx.Exec(context.Background(), `INSERT INTO sites
			(id,display_id,scope_id,owner_user_id,domain,origins,origin_hosts,created_by_user_id,updated_by_user_id)
			VALUES($1,(SELECT COALESCE(max(display_id),0)+1 FROM sites WHERE scope_id=$2),$2,$3,$4,ARRAY['192.0.2.10:80'],ARRAY['192.0.2.10'],$3,$3)`,
			siteID, resources.scopeID, resources.userID, domain); err != nil {
			return err
		}
		if _, err := tx.Exec(context.Background(), `INSERT INTO site_origin_pools(site_id) VALUES($1)`, siteID); err != nil {
			return err
		}
		_, err := tx.Exec(context.Background(), `INSERT INTO site_origins(site_id,position,host,port)
			VALUES($1,1,'192.0.2.10',80)`, siteID)
		return err
	})
	if err != nil {
		t.Fatalf("insert site: %v", err)
	}
	subscriptionID := insertFeatureSubscription(t, pool, resources.scopeID, resources.userID, bindingTestNow, true, true)
	linkFeatureSubscription(t, pool, siteID, subscriptionID)
	return siteID
}

func insertPolicy(t *testing.T, pool *pgxpool.Pool, resources tenantResources, kind, name string, revision int64) uuid.UUID {
	t.Helper()
	policyID := uuid.New()
	policy := policyDocument(policyID, resources.scopeID, kind, name, revision)
	rules, err := json.Marshal(policy.Rules)
	if err != nil {
		t.Fatal(err)
	}
	document, err := json.Marshal(policy)
	if err != nil {
		t.Fatal(err)
	}
	if _, err := pool.Exec(context.Background(), `INSERT INTO security_policies
		(id,scope_id,tenant_id,owner_user_id,kind,name,enabled,default_action,rules,revision,
		 created_by_user_id,updated_by_user_id,created_at,updated_at)
		VALUES($1,$2,$3,$4,$5,$6,true,'allow',$7,$8,$4,$4,$9,$9)`,
		policyID, resources.scopeID, resources.tenantID, resources.userID, kind, name, rules, revision, bindingTestNow); err != nil {
		t.Fatalf("insert policy: %v", err)
	}
	if _, err := pool.Exec(context.Background(), `INSERT INTO security_policy_versions
		(policy_id,revision,document,created_by_user_id,created_at) VALUES($1,$2,$3,$4,$5)`,
		policyID, revision, document, resources.userID, bindingTestNow); err != nil {
		t.Fatalf("insert policy version: %v", err)
	}
	return policyID
}

func addPolicyVersion(t *testing.T, pool *pgxpool.Pool, resources tenantResources, revision int64) {
	t.Helper()
	policy := policyDocument(resources.policyID, resources.scopeID, resources.kind, "policy-updated", revision)
	rules, err := json.Marshal(policy.Rules)
	if err != nil {
		t.Fatal(err)
	}
	document, err := json.Marshal(policy)
	if err != nil {
		t.Fatal(err)
	}
	if _, err := pool.Exec(context.Background(), `UPDATE security_policies SET
		name=$2,rules=$3,revision=$4,updated_at=$5 WHERE id=$1`, resources.policyID, policy.Name, rules, revision, bindingTestNow); err != nil {
		t.Fatalf("update policy: %v", err)
	}
	if _, err := pool.Exec(context.Background(), `INSERT INTO security_policy_versions
		(policy_id,revision,document,created_by_user_id,created_at) VALUES($1,$2,$3,$4,$5)`,
		resources.policyID, revision, document, resources.userID, bindingTestNow); err != nil {
		t.Fatalf("insert policy version: %v", err)
	}
}

func policyDocument(policyID, scopeID uuid.UUID, kind, name string, revision int64) securitypolicy.Policy {
	return securitypolicy.Policy{
		ID: policyID, ScopeID: scopeID, Kind: kind, Name: name, Enabled: true,
		DefaultAction: securitypolicy.ActionAllow, Revision: revision,
		Rules: []securitypolicy.Rule{{
			ID: uuid.NewSHA1(policyID, []byte("rule")), Name: "block-login", Priority: 100, Enabled: true,
			Conditions: []securitypolicy.Condition{{Field: "path", Operator: "prefix", Values: []string{"/login"}}},
			Action:     securitypolicy.ActionBlock, Flow: securitypolicy.FlowStop,
		}},
	}
}

func assertPersistedPublication(t *testing.T, pool *pgxpool.Pool, publication Publication, signer *recordingSigner) {
	t.Helper()
	var payload, runtime, bundle, bundleHash []byte
	var keyID string
	if err := pool.QueryRow(context.Background(), `SELECT canonical_payload_sha256,runtime_snapshot_sha256,
		bundle_bytes,bundle_sha256,signing_key_id FROM security_policy_publications WHERE id=$1`, publication.BundleID).
		Scan(&payload, &runtime, &bundle, &bundleHash, &keyID); err != nil {
		t.Fatalf("read persisted publication: %v", err)
	}
	if !bytes.Equal(payload, publication.CanonicalPayloadSHA256[:]) ||
		!bytes.Equal(runtime, publication.RuntimeSnapshotSHA256[:]) || !bytes.Equal(bundle, publication.BundleJSON) ||
		!bytes.Equal(bundleHash, publication.BundleSHA256[:]) || keyID != publication.SigningKeyID ||
		bytes.Contains(bundle, signer.private) {
		t.Fatal("persisted publication hashes, bundle, or key material do not match the generated plan")
	}
	var privateColumns int
	if err := pool.QueryRow(context.Background(), `SELECT count(*) FROM information_schema.columns
		WHERE table_schema=current_schema() AND table_name='security_policy_publications'
		AND (column_name LIKE '%private%' OR column_name LIKE '%secret%')`).Scan(&privateColumns); err != nil {
		t.Fatal(err)
	}
	if privateColumns != 0 {
		t.Fatalf("security_policy_publications has %d private/secret columns", privateColumns)
	}
}

func assertCounts(t *testing.T, pool *pgxpool.Pool, bindings, publications, targets, audits int) {
	t.Helper()
	for table, expected := range map[string]int{
		"security_policy_site_bindings": bindings, "security_policy_publications": publications,
		"security_policy_publication_targets": targets, "audit_events": audits,
	} {
		var actual int
		query := "SELECT count(*) FROM " + pgx.Identifier{table}.Sanitize()
		if table == "audit_events" {
			query += " WHERE action='security_policy.publication.claim'"
		}
		if err := pool.QueryRow(context.Background(), query).Scan(&actual); err != nil {
			t.Fatalf("count %s: %v", table, err)
		}
		if actual != expected {
			t.Fatalf("%s count = %d, want %d", table, actual, expected)
		}
	}
}

func relationExists(t *testing.T, pool *pgxpool.Pool, name string) bool {
	t.Helper()
	var exists bool
	if err := pool.QueryRow(context.Background(), `SELECT to_regclass($1) IS NOT NULL`, name).Scan(&exists); err != nil {
		t.Fatal(err)
	}
	return exists
}

func migrationVersion(t *testing.T, pool *pgxpool.Pool) int64 {
	t.Helper()
	var version int64
	if err := pool.QueryRow(context.Background(), `SELECT COALESCE(max(version),0) FROM schema_migrations`).Scan(&version); err != nil {
		t.Fatal(err)
	}
	return version
}

// isolatedBindingPool returns a schema at the release head (a clone of
// TEST_DATABASE_TEMPLATE when it is set).
func isolatedBindingPool(t *testing.T) *pgxpool.Pool {
	t.Helper()
	if os.Getenv("TEST_DATABASE_URL") == "" {
		t.Skip("TEST_DATABASE_URL is not set")
	}
	if pool := databasetest.ClonedMigratedPool(t, nil); pool != nil {
		return pool
	}
	return isolatedBindingSchema(t, true)
}

func isolatedBindingSchema(t *testing.T, migrate bool) *pgxpool.Pool {
	t.Helper()
	databaseURL := os.Getenv("TEST_DATABASE_URL")
	if databaseURL == "" {
		t.Skip("TEST_DATABASE_URL is not set")
	}
	ctx, cancel := context.WithTimeout(context.Background(), 5*time.Minute)
	defer cancel()
	adminPool, err := pgxpool.New(ctx, databaseURL)
	if err != nil {
		t.Fatal(err)
	}
	schema := "security_binding_test_" + strings.ReplaceAll(uuid.NewString(), "-", "")
	if !regexp.MustCompile(`^security_binding_test_[a-f0-9]{32}$`).MatchString(schema) {
		adminPool.Close()
		t.Fatalf("refusing unexpected schema %q", schema)
	}
	identifier := pgx.Identifier{schema}.Sanitize()
	if _, err := adminPool.Exec(ctx, "CREATE SCHEMA "+identifier); err != nil {
		adminPool.Close()
		t.Fatal(err)
	}
	config, err := pgxpool.ParseConfig(databaseURL)
	if err != nil {
		adminPool.Close()
		t.Fatal(err)
	}
	config.ConnConfig.RuntimeParams["search_path"] = schema
	pool, err := pgxpool.NewWithConfig(ctx, config)
	if err != nil {
		_, _ = adminPool.Exec(context.Background(), "DROP SCHEMA "+identifier+" CASCADE")
		adminPool.Close()
		t.Fatal(err)
	}
	if migrate {
		if err := database.Migrate(ctx, pool, "up"); err != nil {
			pool.Close()
			_, _ = adminPool.Exec(context.Background(), "DROP SCHEMA "+identifier+" CASCADE")
			adminPool.Close()
			t.Fatalf("migrate isolated security binding schema: %v", err)
		}
	}
	t.Cleanup(func() {
		pool.Close()
		// A release-head schema holds ~1600 objects; on a loaded server the
		// cascade drop measured 16.6s, so a 15s budget cancelled it and left the
		// schema behind in the shared database.
		cleanupCtx, cleanupCancel := databasetest.CleanupContext()
		defer cleanupCancel()
		if _, err := adminPool.Exec(cleanupCtx, "DROP SCHEMA "+identifier+" CASCADE"); err != nil {
			t.Errorf("drop isolated security binding schema: %v", err)
		}
		adminPool.Close()
	})
	return pool
}
