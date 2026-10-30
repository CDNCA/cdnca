package challengepolicy

import (
	"bytes"
	"context"
	"crypto/ed25519"
	"crypto/rand"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"io/fs"
	"net/http"
	"net/http/httptest"
	"os"
	"regexp"
	"strings"
	"sync"
	"testing"
	"time"

	"github.com/cdnca/cdnca/libs/entitlement"
	"github.com/cdnca/cdnca/services/control-api/internal/audit"
	"github.com/cdnca/cdnca/services/control-api/internal/database"
	"github.com/cdnca/cdnca/services/control-api/internal/database/databasetest"
	"github.com/cdnca/cdnca/services/control-api/internal/entitlementguard"
	"github.com/cdnca/cdnca/services/control-api/internal/entitlementguard/guardtest"
	"github.com/cdnca/cdnca/services/control-api/internal/rbacmanager"
	"github.com/cdnca/cdnca/services/control-api/migrations"
	"github.com/google/uuid"
	"github.com/jackc/pgx/v5"
	"github.com/jackc/pgx/v5/pgxpool"
)

type gateFunc func(context.Context, pgx.Tx, entitlementCheck) error

func (function gateFunc) Check(ctx context.Context, tx pgx.Tx, check entitlementCheck) error {
	return function(ctx, tx, check)
}

type testFixture struct {
	pool          *pgxpool.Pool
	now           time.Time
	service       *Service
	handler       http.Handler
	cursor        *CursorCodec
	platform      Actor
	ownerA        Actor
	viewerA       Actor
	memberA       Actor
	ownerB        Actor
	ownerASession uuid.UUID
	platformScope uuid.UUID
	tenantA       uuid.UUID
	tenantB       uuid.UUID
	siteA         uuid.UUID
	siteB         uuid.UUID
}

func TestChallengePolicyHTTPCRUDIsolationAndRBAC(t *testing.T) {
	fixture := newFixture(t, allowGate())

	unauthenticated := fixture.request(t, "unknown", http.MethodGet, collectionPath(fixture.tenantA), nil, "", "")
	assertHTTPError(t, unauthenticated, http.StatusUnauthorized, "authentication_required")

	create := createPayload(fixture.siteA, "a.example.test", validConfig(ModeClick), true)
	missingEnabled := createPayload(fixture.siteA, "a.example.test", validConfig(ModeClick), true)
	delete(missingEnabled, "enabled")
	assertHTTPError(t,
		fixture.request(t, "owner-a", http.MethodPost, collectionPath(fixture.tenantA), missingEnabled, "missing-enabled", ""),
		http.StatusBadRequest, "invalid_request")
	nullEnabled := createPayload(fixture.siteA, "a.example.test", validConfig(ModeClick), true)
	nullEnabled["enabled"] = nil
	assertHTTPError(t,
		fixture.request(t, "owner-a", http.MethodPost, collectionPath(fixture.tenantA), nullEnabled, "null-enabled", ""),
		http.StatusBadRequest, "invalid_request")
	response := fixture.request(t, "owner-a", http.MethodPost, collectionPath(fixture.tenantA), create, "create-a", "")
	assertHTTPError(t, response, http.StatusCreated, "")
	created := decodePolicyResponse(t, response)
	if created.Revision != 1 || !created.Enabled || !created.KeyReferenceConfigured || created.ExternalProviderConfigured {
		t.Fatalf("created policy = %#v", created)
	}
	assertNoPrivateReferences(t, response.Body.Bytes(), "keyref:challenge-2026-07", "appref:", ProviderTencent)

	replay := fixture.request(t, "owner-a", http.MethodPost, collectionPath(fixture.tenantA), create, "create-a", "")
	if replay.Code != http.StatusCreated || replay.Header().Get("X-Idempotent-Replay") != "true" {
		t.Fatalf("create replay status=%d replay=%q body=%s", replay.Code, replay.Header().Get("X-Idempotent-Replay"), replay.Body)
	}
	changedCreate := createPayload(fixture.siteA, "a.example.test", validConfig(ModeClick), true)
	changedConfig := changedCreate["config"].(Config)
	changedConfig.Priority = 11
	changedCreate["config"] = changedConfig
	conflict := fixture.request(t, "owner-a", http.MethodPost, collectionPath(fixture.tenantA), changedCreate, "create-a", "")
	assertHTTPError(t, conflict, http.StatusConflict, "idempotency_conflict")

	viewerRead := fixture.request(t, "viewer-a", http.MethodGet, itemPath(fixture.tenantA, created.ID), nil, "", "")
	if viewerRead.Code != http.StatusOK {
		t.Fatalf("tenant viewer read status=%d body=%s", viewerRead.Code, viewerRead.Body)
	}
	viewerWrite := fixture.request(t, "viewer-a", http.MethodPost, collectionPath(fixture.tenantA), create, "viewer-write", "")
	assertHTTPError(t, viewerWrite, http.StatusForbidden, "permission_denied")
	memberRead := fixture.request(t, "member-a", http.MethodGet, itemPath(fixture.tenantA, created.ID), nil, "", "")
	assertHTTPError(t, memberRead, http.StatusForbidden, "permission_denied")
	crossTenant := fixture.request(t, "owner-b", http.MethodGet, itemPath(fixture.tenantA, created.ID), nil, "", "")
	assertHTTPError(t, crossTenant, http.StatusNotFound, "not_found")

	wrongSite := createPayload(fixture.siteB, "b.example.test", validConfig(ModeClick), true)
	platformWrongScope := fixture.request(t, "platform", http.MethodPost, collectionPath(fixture.tenantA), wrongSite, "platform-wrong-site", "")
	assertHTTPError(t, platformWrongScope, http.StatusNotFound, "not_found")
	platformCreate := fixture.request(t, "platform", http.MethodPost, collectionPath(fixture.tenantB), wrongSite, "platform-create-b", "")
	if platformCreate.Code != http.StatusCreated {
		t.Fatalf("platform scoped create status=%d body=%s", platformCreate.Code, platformCreate.Body)
	}

	external := validConfig(ModeExternal)
	updatedResponse := fixture.request(t, "owner-a", http.MethodPatch, itemPath(fixture.tenantA, created.ID),
		map[string]any{"config": external}, "update-external", quoteRevision(1))
	if updatedResponse.Code != http.StatusOK {
		t.Fatalf("external update status=%d body=%s", updatedResponse.Code, updatedResponse.Body)
	}
	updated := decodePolicyResponse(t, updatedResponse)
	if updated.Revision != 2 || updated.Mode != ModeExternal || !updated.ExternalProviderConfigured {
		t.Fatalf("updated policy = %#v", updated)
	}
	assertNoPrivateReferences(t, updatedResponse.Body.Bytes(), external.KeyReference,
		external.ExternalProvider.AppReference, external.ExternalProvider.Provider)

	stale := fixture.request(t, "owner-a", http.MethodPatch, itemPath(fixture.tenantA, created.ID),
		map[string]any{"config": external}, "stale-update", quoteRevision(1))
	assertHTTPError(t, stale, http.StatusPreconditionFailed, "revision_conflict")

	disabledResponse := fixture.request(t, "owner-a", http.MethodPost,
		itemPath(fixture.tenantA, created.ID)+"/disable", nil, "disable-a", quoteRevision(2))
	disabled := decodePolicyResponse(t, disabledResponse)
	if disabledResponse.Code != http.StatusOK || disabled.Enabled || disabled.Revision != 3 {
		t.Fatalf("disable status=%d policy=%#v body=%s", disabledResponse.Code, disabled, disabledResponse.Body)
	}
	enabledResponse := fixture.request(t, "owner-a", http.MethodPost,
		itemPath(fixture.tenantA, created.ID)+"/enable", map[string]any{}, "enable-a", quoteRevision(3))
	enabled := decodePolicyResponse(t, enabledResponse)
	if enabledResponse.Code != http.StatusOK || !enabled.Enabled || enabled.Revision != 4 {
		t.Fatalf("enable status=%d policy=%#v body=%s", enabledResponse.Code, enabled, enabledResponse.Body)
	}

	deletedResponse := fixture.request(t, "owner-a", http.MethodDelete,
		itemPath(fixture.tenantA, created.ID), nil, "delete-a", quoteRevision(4))
	deleted := decodePolicyResponse(t, deletedResponse)
	if deletedResponse.Code != http.StatusOK || !deleted.Deleted || deleted.Enabled || deleted.Revision != 5 {
		t.Fatalf("delete status=%d policy=%#v body=%s", deletedResponse.Code, deleted, deletedResponse.Body)
	}
	missing := fixture.request(t, "owner-a", http.MethodGet, itemPath(fixture.tenantA, created.ID), nil, "", "")
	assertHTTPError(t, missing, http.StatusNotFound, "not_found")
	rebuilt := fixture.request(t, "owner-a", http.MethodPost, collectionPath(fixture.tenantA), create, "rebuild-a", "")
	if rebuilt.Code != http.StatusCreated || decodePolicyResponse(t, rebuilt).ID == created.ID {
		t.Fatalf("soft-delete rebuild status=%d body=%s", rebuilt.Code, rebuilt.Body)
	}

	unknown := fixture.rawRequest(t, "owner-a", http.MethodPost, collectionPath(fixture.tenantA),
		`{"site_id":"`+fixture.siteA.String()+`","host":"a.example.test","enabled":true,"config":{},"unknown":true}`,
		"unknown-field", "")
	assertHTTPError(t, unknown, http.StatusBadRequest, "invalid_request")
	duplicate := fixture.rawRequest(t, "owner-a", http.MethodPost, collectionPath(fixture.tenantA),
		`{"site_id":"`+fixture.siteA.String()+`","site_id":"`+fixture.siteA.String()+`","host":"a.example.test","enabled":true,"config":{}}`,
		"duplicate-field", "")
	assertHTTPError(t, duplicate, http.StatusBadRequest, "invalid_request")
	badMode := createPayload(fixture.siteA, "a.example.test", validConfig(ModeClick), true)
	badConfig := badMode["config"].(Config)
	badConfig.Mode = "rotate"
	badMode["config"] = badConfig
	invalid := fixture.request(t, "owner-a", http.MethodPost, collectionPath(fixture.tenantA), badMode, "bad-mode", "")
	assertHTTPError(t, invalid, http.StatusUnprocessableEntity, "validation_error")

	assertRolePermission(t, fixture.pool, fixture.tenantA, "tenant_owner", PermissionManage)
	assertRolePermission(t, fixture.pool, fixture.tenantA, "tenant_viewer", PermissionRead)
	assertNoRolePermission(t, fixture.pool, fixture.tenantA, "tenant_viewer", PermissionManage)
}

func TestChallengePolicyHandlerOperationalErrors(t *testing.T) {
	t.Run("resource_conflict", func(t *testing.T) {
		fixture := newFixture(t, allowGate())
		payload := createPayload(fixture.siteA, "a.example.test", validConfig(ModeClick), true)
		created := fixture.request(t, "owner-a", http.MethodPost, collectionPath(fixture.tenantA), payload, "handler-conflict-first", "")
		if created.Code != http.StatusCreated {
			t.Fatalf("prepare conflict status=%d body=%s", created.Code, created.Body)
		}
		conflict := fixture.request(t, "owner-a", http.MethodPost, collectionPath(fixture.tenantA), payload, "handler-conflict-second", "")
		assertHTTPError(t, conflict, http.StatusConflict, "resource_conflict")
	})

	for _, test := range []struct {
		name string
		err  error
		code string
	}{
		{name: "entitlement_denied", err: entitlementguard.ErrFeatureDenied, code: "entitlement_denied"},
		{name: "entitlement_unavailable", err: entitlementguard.ErrUnavailable, code: "entitlement_unavailable"},
	} {
		t.Run(test.name, func(t *testing.T) {
			fixture := newFixture(t, gateFunc(func(context.Context, pgx.Tx, entitlementCheck) error {
				return test.err
			}))
			response := fixture.request(t, "owner-a", http.MethodPost, collectionPath(fixture.tenantA),
				createPayload(fixture.siteA, "a.example.test", validConfig(ModeClick), true), "handler-"+test.name, "")
			status := http.StatusServiceUnavailable
			if test.name == "entitlement_denied" {
				status = http.StatusForbidden
			}
			assertHTTPError(t, response, status, test.code)
		})
	}

	t.Run("request_canceled", func(t *testing.T) {
		fixture := newFixture(t, allowGate())
		ctx, cancel := context.WithCancel(context.Background())
		cancel()
		request := httptest.NewRequest(http.MethodGet, collectionPath(fixture.tenantA), nil).WithContext(ctx)
		request.Header.Set("Authorization", "Bearer owner-a")
		request.Header.Set("X-Request-ID", "handler-canceled-request")
		request.Header.Set("X-Trace-ID", "handler-canceled-trace")
		response := httptest.NewRecorder()
		fixture.handler.ServeHTTP(response, request)
		assertHTTPError(t, response, http.StatusServiceUnavailable, "request_canceled")
	})
}

func TestChallengePolicyCreateReplayPrecedesSiteAndEntitlementDrift(t *testing.T) {
	gateUnavailable := false
	gateCalls := 0
	fixture := newFixture(t, gateFunc(func(context.Context, pgx.Tx, entitlementCheck) error {
		gateCalls++
		if gateUnavailable {
			return entitlementguard.ErrUnavailable
		}
		return nil
	}))
	request := CreateRequest{
		TargetScopeID: fixture.tenantA, SiteID: fixture.siteA, Host: "a.example.test", Enabled: true,
		Config: validConfig(ModeClick), WriteMetadata: metadata("drift-replay"),
	}
	created, err := fixture.service.Create(context.Background(), fixture.ownerA, request)
	if err != nil || gateCalls != 1 {
		t.Fatalf("initial create = (%#v, %v), gate calls=%d", created, err, gateCalls)
	}
	gateUnavailable = true
	replayed, err := fixture.service.Create(context.Background(), fixture.ownerA, request)
	if err != nil || !replayed.Replayed || replayed.Policy.ID != created.Policy.ID || gateCalls != 1 {
		t.Fatalf("entitlement drift replay = (%#v, %v), gate calls=%d", replayed, err, gateCalls)
	}
	if _, err := fixture.pool.Exec(context.Background(), `UPDATE sites SET deleted_at=now() WHERE id=$1`, fixture.siteA); err != nil {
		t.Fatalf("soft-delete replay site: %v", err)
	}
	replayed, err = fixture.service.Create(context.Background(), fixture.ownerA, request)
	if err != nil || !replayed.Replayed || replayed.Policy.ID != created.Policy.ID || gateCalls != 1 {
		t.Fatalf("site drift replay = (%#v, %v), gate calls=%d", replayed, err, gateCalls)
	}
	request.WriteMetadata = metadata("drift-new-request")
	if _, err := fixture.service.Create(context.Background(), fixture.ownerA, request); !errors.Is(err, ErrNotFound) {
		t.Fatalf("new request after site drift error = %v", err)
	}
	var newClaims int
	if err := fixture.pool.QueryRow(context.Background(), `
		SELECT count(*) FROM challenge_policy_write_requests WHERE idempotency_key='drift-new-request'`).Scan(&newClaims); err != nil || newClaims != 0 {
		t.Fatalf("invalid new request claims=%d error=%v", newClaims, err)
	}
}

func TestChallengePolicyReplayRechecksDatabaseAuthorization(t *testing.T) {
	fixture := newFixture(t, allowGate())
	request := CreateRequest{
		TargetScopeID: fixture.tenantA, SiteID: fixture.siteA, Host: "a.example.test", Enabled: true,
		Config: validConfig(ModeClick), WriteMetadata: metadata("revoked-replay"),
	}
	created, err := fixture.service.Create(context.Background(), fixture.ownerA, request)
	if err != nil {
		t.Fatalf("initial create: %v", err)
	}
	if _, err := fixture.pool.Exec(context.Background(), `
		DELETE FROM role_assignments WHERE scope_id=$1 AND user_id=$2`,
		fixture.ownerA.ScopeID, fixture.ownerA.UserID); err != nil {
		t.Fatalf("revoke role assignment: %v", err)
	}

	var beforeRevisions, beforeAudits, beforeWrites int
	if err := fixture.pool.QueryRow(context.Background(), `
		SELECT
			(SELECT count(*) FROM challenge_policy_revisions WHERE policy_id=$1),
			(SELECT count(*) FROM audit_events WHERE request_id=$2),
			(SELECT count(*) FROM challenge_policy_write_requests WHERE idempotency_key=$3)`,
		created.Policy.ID, request.RequestID, request.IdempotencyKey).Scan(
		&beforeRevisions, &beforeAudits, &beforeWrites); err != nil {
		t.Fatal(err)
	}

	if _, err := fixture.service.Create(context.Background(), fixture.ownerA, request); !errors.Is(err, ErrPermissionDenied) {
		t.Fatalf("replay after assignment revoke error = %v", err)
	}

	var afterRevisions, afterAudits, afterWrites int
	if err := fixture.pool.QueryRow(context.Background(), `
		SELECT
			(SELECT count(*) FROM challenge_policy_revisions WHERE policy_id=$1),
			(SELECT count(*) FROM audit_events WHERE request_id=$2),
			(SELECT count(*) FROM challenge_policy_write_requests WHERE idempotency_key=$3)`,
		created.Policy.ID, request.RequestID, request.IdempotencyKey).Scan(
		&afterRevisions, &afterAudits, &afterWrites); err != nil {
		t.Fatal(err)
	}
	if afterRevisions != beforeRevisions || afterAudits != beforeAudits || afterWrites != beforeWrites {
		t.Fatalf("denied replay changed facts: revisions %d->%d audits %d->%d writes %d->%d",
			beforeRevisions, afterRevisions, beforeAudits, afterAudits, beforeWrites, afterWrites)
	}
}

func TestChallengePolicyCASIdempotencyAuditRollbackAndPagination(t *testing.T) {
	fixture := newFixture(t, allowGate())
	created := createServicePolicy(t, fixture, fixture.siteA, "a.example.test", "seed-a")
	beforeCAS := readChallengeFactCounts(t, fixture.pool)

	configs := []Config{validConfig(ModeClick), validConfig(ModeSlider)}
	configs[0].Priority = 20
	configs[1].Priority = 30
	type casResult struct {
		index int
		key   string
		err   error
	}
	results := make(chan casResult, 2)
	start := make(chan struct{})
	var wait sync.WaitGroup
	for index := range configs {
		wait.Add(1)
		go func(index int) {
			defer wait.Done()
			<-start
			key := fmt.Sprintf("cas-%d", index)
			_, err := fixture.service.Update(context.Background(), fixture.ownerA, UpdateRequest{
				TargetScopeID: fixture.tenantA, ID: created.ID, ExpectedRevision: 1,
				Config: configs[index], WriteMetadata: metadata(key),
			})
			results <- casResult{index: index, key: key, err: err}
		}(index)
	}
	close(start)
	wait.Wait()
	close(results)
	successes, conflicts := 0, 0
	loserKey := ""
	loserIndex := -1
	for result := range results {
		switch {
		case result.err == nil:
			successes++
		case errors.Is(result.err, ErrRevisionConflict):
			conflicts++
			loserKey = result.key
			loserIndex = result.index
		default:
			t.Fatalf("concurrent CAS error = %v", result.err)
		}
	}
	if successes != 1 || conflicts != 1 {
		t.Fatalf("concurrent CAS successes=%d conflicts=%d", successes, conflicts)
	}
	current, err := fixture.service.Get(context.Background(), fixture.ownerA, fixture.tenantA, created.ID)
	if err != nil || current.Revision != 2 {
		t.Fatalf("Get after CAS = (%#v, %v)", current, err)
	}
	winnerIndex := 1 - loserIndex
	if loserIndex < 0 || current.Priority != configs[winnerIndex].Priority ||
		current.Priority == configs[loserIndex].Priority {
		t.Fatalf("CAS business winner priority=%d loser=%d winner=%d",
			current.Priority, configs[loserIndex].Priority, configs[winnerIndex].Priority)
	}
	afterCAS := readChallengeFactCounts(t, fixture.pool)
	expectedCAS := beforeCAS
	expectedCAS.revisions++
	expectedCAS.writes++
	expectedCAS.audits++
	if afterCAS != expectedCAS {
		t.Fatalf("CAS facts got=%+v want=%+v", afterCAS, expectedCAS)
	}
	var loserWrites, loserAudits, loserRevisions int
	if err := fixture.pool.QueryRow(context.Background(), `SELECT
		(SELECT count(*) FROM challenge_policy_write_requests WHERE idempotency_key=$1),
		(SELECT count(*) FROM audit_events WHERE request_id=$2),
		(SELECT count(*) FROM challenge_policy_revisions WHERE policy_id=$3 AND request_id=$2)`,
		loserKey, loserKey+"-request", created.ID).Scan(&loserWrites, &loserAudits, &loserRevisions); err != nil {
		t.Fatal(err)
	}
	if loserWrites != 0 || loserAudits != 0 || loserRevisions != 0 {
		t.Fatalf("CAS loser %q side effects writes=%d audits=%d revisions=%d",
			loserKey, loserWrites, loserAudits, loserRevisions)
	}

	replayRequest := UpdateRequest{
		TargetScopeID: fixture.tenantA, ID: created.ID, ExpectedRevision: 2,
		Config: validConfig(ModeCaptcha), WriteMetadata: metadata("idempotent-update"),
	}
	first, err := fixture.service.Update(context.Background(), fixture.ownerA, replayRequest)
	if err != nil {
		t.Fatalf("first idempotent update: %v", err)
	}
	replay, err := fixture.service.Update(context.Background(), fixture.ownerA, replayRequest)
	if err != nil || !replay.Replayed || replay.Policy.Revision != first.Policy.Revision {
		t.Fatalf("idempotent replay = (%#v, %v)", replay, err)
	}
	replayRequest.Config.Priority++
	if _, err := fixture.service.Update(context.Background(), fixture.ownerA, replayRequest); !errors.Is(err, ErrIdempotencyConflict) {
		t.Fatalf("different payload replay error = %v", err)
	}

	if _, err := fixture.pool.Exec(context.Background(), `
		CREATE FUNCTION fail_challenge_audit_test() RETURNS trigger LANGUAGE plpgsql AS $$
		BEGIN
		    IF NEW.action LIKE 'challenge_policy.%' THEN
		        RAISE EXCEPTION 'forced audit failure';
		    END IF;
		    RETURN NEW;
		END;
		$$;
		CREATE TRIGGER fail_challenge_audit_test BEFORE INSERT ON audit_events
		FOR EACH ROW EXECUTE FUNCTION fail_challenge_audit_test()`); err != nil {
		t.Fatalf("install audit failure trigger: %v", err)
	}
	before := first.Policy.Revision
	failedConfig := validConfig(ModeClick)
	failedConfig.Priority = 99
	_, err = fixture.service.Update(context.Background(), fixture.ownerA, UpdateRequest{
		TargetScopeID: fixture.tenantA, ID: created.ID, ExpectedRevision: before,
		Config: failedConfig, WriteMetadata: metadata("audit-failure"),
	})
	if !errors.Is(err, ErrUnavailable) {
		t.Fatalf("audit failure error = %v", err)
	}
	if _, err := fixture.pool.Exec(context.Background(), `
		DROP TRIGGER fail_challenge_audit_test ON audit_events;
		DROP FUNCTION fail_challenge_audit_test()`); err != nil {
		t.Fatalf("remove audit failure trigger: %v", err)
	}
	afterFailure, err := fixture.service.Get(context.Background(), fixture.ownerA, fixture.tenantA, created.ID)
	if err != nil || afterFailure.Revision != before || afterFailure.Priority == failedConfig.Priority {
		t.Fatalf("audit failure did not roll back: policy=%#v error=%v", afterFailure, err)
	}
	var failedWrites int
	if err := fixture.pool.QueryRow(context.Background(), `
		SELECT count(*) FROM challenge_policy_write_requests WHERE idempotency_key = 'audit-failure'`).Scan(&failedWrites); err != nil || failedWrites != 0 {
		t.Fatalf("rolled back idempotency facts count=%d error=%v", failedWrites, err)
	}

	pageSites := make([]uuid.UUID, 0, 4)
	for index := 0; index < 4; index++ {
		domain := fmt.Sprintf("page-%d.example.test", index)
		siteID := insertSite(t, fixture.pool, fixture.tenantA, fixture.ownerA.UserID, domain)
		pageSites = append(pageSites, siteID)
		createServicePolicy(t, fixture, siteID, domain, fmt.Sprintf("page-create-%d", index))
	}
	firstPage, err := fixture.service.List(context.Background(), fixture.ownerA, ListFilter{TargetScopeID: fixture.tenantA, Limit: 2})
	if err != nil || len(firstPage.Items) != 2 || firstPage.NextCursor == "" {
		t.Fatalf("first page = (%#v, %v)", firstPage, err)
	}
	lateSite := insertSite(t, fixture.pool, fixture.tenantA, fixture.ownerA.UserID, "page-late.example.test")
	late := createServicePolicy(t, fixture, lateSite, "page-late.example.test", "page-late")
	secondPage, err := fixture.service.List(context.Background(), fixture.ownerA, ListFilter{
		TargetScopeID: fixture.tenantA, Limit: 2, Cursor: firstPage.NextCursor,
	})
	if err != nil || len(secondPage.Items) == 0 {
		t.Fatalf("second page = (%#v, %v)", secondPage, err)
	}
	seen := map[uuid.UUID]bool{}
	for _, item := range firstPage.Items {
		seen[item.ID] = true
	}
	for _, item := range secondPage.Items {
		if seen[item.ID] || item.ID == late.ID {
			t.Fatalf("unstable cursor returned duplicate or late insert: %s", item.ID)
		}
	}

	for _, scopeID := range []uuid.UUID{fixture.tenantA, fixture.tenantB} {
		if err := audit.New(fixture.pool).VerifyScope(context.Background(), scopeID); err != nil {
			t.Fatalf("VerifyScope(%s) error = %v", scopeID, err)
		}
	}
}

func TestChallengePolicyEntitlementDenialAndGrace(t *testing.T) {
	pool := openChallengeTestPool(t)
	seed := seedFixture(t, pool)
	// The revocation LKG trigger (084) checks the set's window against the database's physical clock.
	now := time.Now().UTC().Truncate(time.Second)
	current := now
	publicKey, privateKey, err := ed25519.GenerateKey(rand.Reader)
	if err != nil {
		t.Fatal(err)
	}
	trust, err := entitlementguard.NewTrustStore([]entitlementguard.VerificationKey{{KeyID: "challenge-test-key", PublicKey: publicKey}})
	if err != nil {
		t.Fatal(err)
	}
	cursor := testCursorCodec(t, 1)
	store, err := NewStoreWithDependencies(pool, func() time.Time { return current }, trust, cursor, testTxAuthorizer{})
	if err != nil {
		t.Fatal(err)
	}
	service := NewService(store)

	installLease(t, pool, trust, privateKey, now, 1, false)
	_, err = service.Create(context.Background(), seed.ownerA, CreateRequest{
		TargetScopeID: seed.tenantA, SiteID: seed.siteA, Host: "a.example.test", Enabled: true,
		Config: validConfig(ModeClick), WriteMetadata: metadata("feature-denied"),
	})
	if !errors.Is(err, ErrEntitlementDenied) {
		t.Fatalf("missing feature create error = %v", err)
	}
	if _, err := service.Create(context.Background(), seed.ownerA, CreateRequest{
		TargetScopeID: seed.tenantA, SiteID: seed.siteA, Host: "a.example.test", Enabled: true,
		Config: validConfig(ModeClick), WriteMetadata: metadata("feature-denied"),
	}); !errors.Is(err, ErrEntitlementDenied) {
		t.Fatalf("denial replay error = %v", err)
	}
	var deniedAuditCount int
	if err := pool.QueryRow(context.Background(), `
		SELECT count(*) FROM audit_events
		WHERE request_id = 'feature-denied-request'
		  AND action = 'challenge_policy.create' AND result = 'denied'`).Scan(&deniedAuditCount); err != nil || deniedAuditCount != 1 {
		t.Fatalf("denial audit count=%d error=%v", deniedAuditCount, err)
	}

	installLease(t, pool, trust, privateKey, now, 2, true)
	created, err := service.Create(context.Background(), seed.ownerA, CreateRequest{
		TargetScopeID: seed.tenantA, SiteID: seed.siteA, Host: "a.example.test", Enabled: true,
		Config: validConfig(ModeClick), WriteMetadata: metadata("entitlement-valid"),
	})
	if err != nil {
		t.Fatalf("valid entitlement create: %v", err)
	}
	// A lease in grace keeps the control plane fully usable (entitlementguard.leaseUsable).
	current = now.Add(90 * time.Minute)
	graceConfig := validConfig(ModeSlider)
	updated, err := service.Update(context.Background(), seed.ownerA, UpdateRequest{
		TargetScopeID: seed.tenantA, ID: created.Policy.ID, ExpectedRevision: 1,
		Config: graceConfig, WriteMetadata: metadata("grace-update"),
	})
	if err != nil || updated.Policy.Revision != 2 {
		t.Fatalf("grace update = (%#v, %v)", updated, err)
	}
	read, err := service.Get(context.Background(), seed.ownerA, seed.tenantA, created.Policy.ID)
	if err != nil || read.Revision != 2 {
		t.Fatalf("grace read = (%#v, %v)", read, err)
	}
	disabled, err := service.SetEnabled(context.Background(), seed.ownerA, StateRequest{
		TargetScopeID: seed.tenantA, ID: created.Policy.ID, ExpectedRevision: 2, Enabled: false,
		WriteMetadata: metadata("grace-disable"),
	})
	if err != nil || disabled.Policy.Enabled {
		t.Fatalf("grace disable = (%#v, %v)", disabled, err)
	}
	if _, err := service.Delete(context.Background(), seed.ownerA, DeleteRequest{
		TargetScopeID: seed.tenantA, ID: created.Policy.ID, ExpectedRevision: 3,
		WriteMetadata: metadata("grace-delete"),
	}); err != nil {
		t.Fatalf("grace delete: %v", err)
	}
}

func TestChallengePolicyMigrationAndDirectSQLGuards(t *testing.T) {
	ctx := context.Background()
	// 053's empty down/up round trip runs on a schema migrated through 053 only:
	// later migrations (138 publication facts and on) reference its tables, so
	// a lone 053 down can never succeed on the head schema.
	roundTrip := databasetest.MigratedThroughPool(t, "challenge_policy_053", 53)
	if err := runChallengeMigration053(ctx, roundTrip, "down"); err != nil {
		t.Fatalf("053 empty down: %v", err)
	}
	var tableName *string
	if err := roundTrip.QueryRow(ctx, `SELECT to_regclass('challenge_policies')::text`).Scan(&tableName); err != nil || tableName != nil {
		t.Fatalf("challenge_policies after down = %v, error=%v", tableName, err)
	}
	platformScope, tenantA, tenantB := uuid.New(), uuid.New(), uuid.New()
	tenantAID, tenantBID := uuid.New(), uuid.New()
	if _, err := roundTrip.Exec(ctx, `INSERT INTO tenants(id,display_name) VALUES($1,'Tenant A'),($2,'Tenant B')`,
		tenantAID, tenantBID); err != nil {
		t.Fatalf("seed 053 tenants: %v", err)
	}
	if _, err := roundTrip.Exec(ctx, `INSERT INTO access_scopes(id,kind,tenant_id) VALUES
		($1,'platform',NULL),($2,'tenant',$4),($3,'tenant',$5)`,
		platformScope, tenantA, tenantB, tenantAID, tenantBID); err != nil {
		t.Fatalf("seed 053 scopes: %v", err)
	}
	insertSystemRole(t, roundTrip, platformScope, "platform_owner")
	insertSystemRole(t, roundTrip, tenantA, "tenant_owner")
	insertSystemRole(t, roundTrip, tenantA, "tenant_viewer")
	insertSystemRole(t, roundTrip, tenantA, "platform_admin")
	insertSystemRole(t, roundTrip, platformScope, "tenant_admin")
	insertSystemRole(t, roundTrip, platformScope, "tenant_member")
	if err := runChallengeMigration053(ctx, roundTrip, "up"); err != nil {
		t.Fatalf("053 up after down: %v", err)
	}
	assertRolePermission(t, roundTrip, platformScope, "platform_owner", PermissionManage)
	assertRolePermission(t, roundTrip, tenantA, "tenant_owner", PermissionManage)
	assertRolePermission(t, roundTrip, tenantA, "tenant_viewer", PermissionRead)
	assertNoRolePermission(t, roundTrip, tenantA, "platform_admin", PermissionRead)
	assertNoRolePermission(t, roundTrip, platformScope, "tenant_admin", PermissionRead)
	assertNoRolePermission(t, roundTrip, platformScope, "tenant_member", PermissionRead)

	insertSystemRole(t, roundTrip, platformScope, "platform_admin")
	insertSystemRole(t, roundTrip, tenantA, "tenant_admin")
	insertSystemRole(t, roundTrip, tenantA, "tenant_member")
	insertSystemRole(t, roundTrip, tenantB, "platform_owner")
	insertSystemRole(t, roundTrip, platformScope, "tenant_owner")
	assertRolePermission(t, roundTrip, platformScope, "platform_admin", PermissionManage)
	assertRolePermission(t, roundTrip, tenantA, "tenant_admin", PermissionManage)
	assertRolePermission(t, roundTrip, tenantA, "tenant_member", PermissionRead)
	assertNoRolePermission(t, roundTrip, tenantA, "tenant_member", PermissionManage)
	assertNoRolePermission(t, roundTrip, tenantB, "platform_owner", PermissionRead)
	assertNoRolePermission(t, roundTrip, platformScope, "tenant_owner", PermissionRead)

	pool := openChallengeTestPool(t)
	seed := seedFixture(t, pool)

	store, err := newStoreWithGate(pool, time.Now, allowGate(), testCursorCodec(t, 1), testTxAuthorizer{})
	if err != nil {
		t.Fatal(err)
	}
	service := NewService(store)
	created, err := service.Create(ctx, seed.ownerA, CreateRequest{
		TargetScopeID: seed.tenantA, SiteID: seed.siteA, Host: "a.example.test", Enabled: true,
		Config: validConfig(ModeClick), WriteMetadata: metadata("guard-create"),
	})
	if err != nil {
		t.Fatalf("create guarded policy: %v", err)
	}
	for name, statement := range map[string]string{
		"head update":            `UPDATE challenge_policies SET current_enabled=false WHERE id='` + created.Policy.ID.String() + `'`,
		"head truncate":          `TRUNCATE challenge_policies`,
		"revision update":        `UPDATE challenge_policy_revisions SET priority=999 WHERE policy_id='` + created.Policy.ID.String() + `'`,
		"revision delete":        `DELETE FROM challenge_policy_revisions WHERE policy_id='` + created.Policy.ID.String() + `'`,
		"revision truncate":      `TRUNCATE challenge_policy_revisions`,
		"write request update":   `UPDATE challenge_policy_write_requests SET trace_id='tampered' WHERE idempotency_key='guard-create'`,
		"write request delete":   `DELETE FROM challenge_policy_write_requests WHERE idempotency_key='guard-create'`,
		"write request truncate": `TRUNCATE challenge_policy_write_requests`,
	} {
		t.Run(name, func(t *testing.T) {
			if _, err := pool.Exec(ctx, statement); err == nil {
				t.Fatalf("direct SQL %s unexpectedly succeeded", name)
			}
		})
	}

	tx, err := pool.Begin(ctx)
	if err != nil {
		t.Fatal(err)
	}
	_, err = tx.Exec(ctx, `
		INSERT INTO challenge_policy_revisions (
			policy_id, tenant_scope_id, tenant_id, site_id, host, revision, action,
			priority, mode, min_delay_seconds, challenge_ttl_seconds, pass_ttl_seconds,
			clock_skew_seconds, attempts_per_nonce, failure_window_seconds, max_failures_per_window,
			ip_binding, bind_user_agent, bypass_routes, key_reference, external_provider,
			external_app_reference, enabled, deleted, document, created_by_scope_id,
			created_by_user_id, request_id, trace_id, created_at
		)
		SELECT policy_id, tenant_scope_id, tenant_id, site_id, host, 2, 'update',
		       priority, mode, min_delay_seconds, challenge_ttl_seconds, pass_ttl_seconds,
		       clock_skew_seconds, attempts_per_nonce, failure_window_seconds, max_failures_per_window,
		       ip_binding, bind_user_agent, bypass_routes, key_reference, external_provider,
		       external_app_reference, enabled, deleted,
		       jsonb_set(document, '{revision}', '2'::jsonb), created_by_scope_id,
		       created_by_user_id, 'direct-no-audit', 'direct-no-audit-trace', now()
		FROM challenge_policy_revisions WHERE policy_id=$1 AND revision=1`, created.Policy.ID)
	if err != nil {
		_ = tx.Rollback(ctx)
		t.Fatalf("prepare unaudited revision: %v", err)
	}
	if err := tx.Commit(ctx); err == nil {
		t.Fatal("unaudited direct revision commit unexpectedly succeeded")
	}
	var revision int64
	if err := pool.QueryRow(ctx, `SELECT current_revision FROM challenge_policies WHERE id=$1`, created.Policy.ID).Scan(&revision); err != nil || revision != 1 {
		t.Fatalf("unaudited revision rollback head=%d error=%v", revision, err)
	}
	assertAuditedStateConfigTamperRejected(t, pool, seed.ownerA, created.Policy, 1, "disable", false, false)
	assertAuditedStateConfigTamperRejected(t, pool, seed.ownerA, created.Policy, 1, "delete", false, true)
	disabled, err := service.SetEnabled(ctx, seed.ownerA, StateRequest{
		TargetScopeID: seed.tenantA, ID: created.Policy.ID, ExpectedRevision: 1, Enabled: false,
		WriteMetadata: metadata("guard-disable"),
	})
	if err != nil || disabled.Policy.Revision != 2 || disabled.Policy.Enabled {
		t.Fatalf("prepare guarded enable = (%#v, %v)", disabled, err)
	}
	assertAuditedStateConfigTamperRejected(t, pool, seed.ownerA, disabled.Policy, 2, "enable", true, false)
	if err := runChallengeMigration053(ctx, pool, "down"); err == nil || !strings.Contains(err.Error(), "irreversible challenge policy facts") {
		t.Fatalf("053 down with facts error = %v", err)
	}
	if err := pool.QueryRow(ctx, `SELECT current_revision FROM challenge_policies WHERE id=$1`, created.Policy.ID).Scan(&revision); err != nil || revision != 2 {
		t.Fatalf("failed down changed facts head=%d error=%v", revision, err)
	}
}

func TestChallengePolicyRequestCancellationAndStorageUnavailable(t *testing.T) {
	fixture := newFixture(t, allowGate())
	ctx, cancel := context.WithCancel(context.Background())
	cancel()
	if _, err := fixture.service.List(ctx, fixture.ownerA, ListFilter{TargetScopeID: fixture.tenantA, Limit: 10}); !errors.Is(err, context.Canceled) {
		t.Fatalf("canceled list error = %v", err)
	}
	fixture.pool.Close()
	invalidCursorResponse := fixture.request(t, "owner-a", http.MethodGet,
		collectionPath(fixture.tenantA)+"?cursor=invalid", nil, "", "")
	assertHTTPError(t, invalidCursorResponse, http.StatusBadRequest, "invalid_request")
	if _, err := fixture.service.List(context.Background(), fixture.ownerA, ListFilter{TargetScopeID: fixture.tenantA, Limit: 10}); !errors.Is(err, ErrUnavailable) {
		t.Fatalf("closed storage list error = %v", err)
	}
	response := fixture.request(t, "owner-a", http.MethodGet, collectionPath(fixture.tenantA), nil, "", "")
	assertHTTPError(t, response, http.StatusServiceUnavailable, "service_unavailable")
	if strings.Contains(strings.ToLower(response.Body.String()), "pool") || strings.Contains(strings.ToLower(response.Body.String()), "sql") {
		t.Fatalf("storage error leaked internal detail: %s", response.Body)
	}
}

type nilTenantSessionAuthorizer struct{}

func (*nilTenantSessionAuthorizer) AuthorizeTenantSessionTx(
	context.Context,
	pgx.Tx,
	rbacmanager.AuthenticatedSessionReference,
	string,
) (uuid.UUID, error) {
	return uuid.Nil, nil
}

func TestChallengePolicyConstructorsFailClosed(t *testing.T) {
	pool := &pgxpool.Pool{}
	cursor := &CursorCodec{}
	var typedNilGate gateFunc
	var typedNilAuthorizer *testTxAuthorizer
	for _, test := range []struct {
		name       string
		pool       *pgxpool.Pool
		now        func() time.Time
		gate       entitlementGate
		cursor     *CursorCodec
		authorizer TxAuthorizer
	}{
		{name: "pool", now: time.Now, gate: allowGate(), cursor: cursor, authorizer: testTxAuthorizer{}},
		{name: "clock", pool: pool, gate: allowGate(), cursor: cursor, authorizer: testTxAuthorizer{}},
		{name: "gate", pool: pool, now: time.Now, cursor: cursor, authorizer: testTxAuthorizer{}},
		{name: "typed_nil_gate", pool: pool, now: time.Now, gate: typedNilGate, cursor: cursor, authorizer: testTxAuthorizer{}},
		{name: "cursor", pool: pool, now: time.Now, gate: allowGate(), authorizer: testTxAuthorizer{}},
		{name: "authorizer", pool: pool, now: time.Now, gate: allowGate(), cursor: cursor},
		{name: "typed_nil_authorizer", pool: pool, now: time.Now, gate: allowGate(), cursor: cursor, authorizer: typedNilAuthorizer},
	} {
		t.Run("store_"+test.name, func(t *testing.T) {
			if _, err := newStoreWithGate(test.pool, test.now, test.gate, test.cursor, test.authorizer); !errors.Is(err, ErrInvalidStoreConfig) {
				t.Fatalf("newStoreWithGate() error = %v", err)
			}
		})
	}

	if service := NewService(nil); service != nil {
		t.Fatalf("NewService(nil) = %#v", service)
	}
	if _, err := NewHandler(nil, AuthenticatorFunc(func(*http.Request) (Actor, error) {
		return Actor{}, nil
	})); !errors.Is(err, ErrInvalidHandlerConfig) {
		t.Fatalf("NewHandler(nil service) error = %v", err)
	}
	if _, err := NewHandler(&Service{}, AuthenticatorFunc(func(*http.Request) (Actor, error) {
		return Actor{}, nil
	})); !errors.Is(err, ErrInvalidHandlerConfig) {
		t.Fatalf("NewHandler(nil store) error = %v", err)
	}
	var typedNilAuthenticator AuthenticatorFunc
	if _, err := NewHandler(&Service{store: &Store{}}, typedNilAuthenticator); !errors.Is(err, ErrInvalidHandlerConfig) {
		t.Fatalf("NewHandler(typed nil authenticator) error = %v", err)
	}
	if _, err := NewTenantSessionTxAuthorizer(nil); !errors.Is(err, ErrInvalidStoreConfig) {
		t.Fatalf("NewTenantSessionTxAuthorizer(nil) error = %v", err)
	}
	var typedNilSessions *nilTenantSessionAuthorizer
	if _, err := NewTenantSessionTxAuthorizer(typedNilSessions); !errors.Is(err, ErrInvalidStoreConfig) {
		t.Fatalf("NewTenantSessionTxAuthorizer(typed nil) error = %v", err)
	}
}

func allowGate() entitlementGate {
	return gateFunc(func(context.Context, pgx.Tx, entitlementCheck) error { return nil })
}

func newFixture(t *testing.T, gate entitlementGate) *testFixture {
	return newFixtureWithAuthorizer(t, gate, testTxAuthorizer{})
}

func newFixtureWithAuthorizer(t *testing.T, gate entitlementGate, authorizer TxAuthorizer) *testFixture {
	t.Helper()
	pool := openChallengeTestPool(t)
	fixture := seedFixture(t, pool)
	fixture.now = time.Date(2026, 7, 23, 2, 0, 0, 0, time.UTC)
	fixture.cursor = testCursorCodec(t, 1)
	store, err := newStoreWithGate(pool, func() time.Time { return fixture.now }, gate, fixture.cursor, authorizer)
	if err != nil {
		t.Fatalf("new challenge policy store: %v", err)
	}
	fixture.service = NewService(store)
	authenticator := AuthenticatorFunc(func(request *http.Request) (Actor, error) {
		switch strings.TrimPrefix(request.Header.Get("Authorization"), "Bearer ") {
		case "platform":
			return fixture.platform, nil
		case "owner-a":
			return fixture.ownerA, nil
		case "viewer-a":
			return fixture.viewerA, nil
		case "member-a":
			return fixture.memberA, nil
		case "owner-b":
			return fixture.ownerB, nil
		default:
			return Actor{}, ErrUnauthenticated
		}
	})
	handler, err := NewHandler(fixture.service, authenticator)
	if err != nil {
		t.Fatalf("NewHandler: %v", err)
	}
	fixture.handler = handler
	return fixture
}

func seedFixture(t *testing.T, pool *pgxpool.Pool) *testFixture {
	t.Helper()
	fixture := &testFixture{
		pool: pool, platformScope: uuid.New(), tenantA: uuid.New(), tenantB: uuid.New(),
		siteA: uuid.New(), siteB: uuid.New(),
	}
	tenantAID, tenantBID := uuid.New(), uuid.New()
	platformUser, ownerAUser, viewerAUser, memberAUser, ownerBUser := uuid.New(), uuid.New(), uuid.New(), uuid.New(), uuid.New()
	fixture.ownerASession = uuid.New()
	platformSession, viewerASession, memberASession, ownerBSession := uuid.New(), uuid.New(), uuid.New(), uuid.New()
	ctx := context.Background()
	if _, err := pool.Exec(ctx, `
		INSERT INTO tenants(id,display_name) VALUES($1,'Tenant A'),($2,'Tenant B')`,
		tenantAID, tenantBID); err != nil {
		t.Fatalf("seed tenants: %v", err)
	}
	if _, err := pool.Exec(ctx, `
		INSERT INTO access_scopes(id,kind,tenant_id) VALUES
			($1,'platform',NULL),($2,'tenant',$4),($3,'tenant',$5)`,
		fixture.platformScope, fixture.tenantA, fixture.tenantB, tenantAID, tenantBID); err != nil {
		t.Fatalf("seed scopes: %v", err)
	}
	if _, err := pool.Exec(ctx, `
		WITH inserted_users AS (
			INSERT INTO users(id,username,display_name,password_hash) VALUES
				($4,'platform-test','Platform Test','hash'),
				($5,'owner-a-test','Owner A','hash'),
				($6,'viewer-a-test','Viewer A','hash'),
				($7,'member-a-test','Member A','hash'),
				($8,'owner-b-test','Owner B','hash')
			RETURNING id
		)
		INSERT INTO memberships(scope_id,user_id)
		SELECT value.scope_id, value.user_id
		FROM (VALUES ($1::uuid,$4::uuid),($2,$5),($2,$6),($2,$7),($3,$8)) value(scope_id,user_id)
		JOIN inserted_users ON inserted_users.id = value.user_id`,
		fixture.platformScope, fixture.tenantA, fixture.tenantB,
		platformUser, ownerAUser, viewerAUser, memberAUser, ownerBUser); err != nil {
		t.Fatalf("seed identities: %v", err)
	}
	for index, session := range []struct {
		id, userID, scopeID uuid.UUID
	}{
		{platformSession, platformUser, fixture.platformScope},
		{fixture.ownerASession, ownerAUser, fixture.tenantA},
		{viewerASession, viewerAUser, fixture.tenantA},
		{memberASession, memberAUser, fixture.tenantA},
		{ownerBSession, ownerBUser, fixture.tenantB},
	} {
		if _, err := pool.Exec(ctx, `INSERT INTO auth_sessions(
			id,family_id,user_id,scope_id,refresh_token_hash,created_at,expires_at
		) VALUES($1,$2,$3,$4,$5,$6,$7)`, session.id, uuid.New(), session.userID,
			session.scopeID, bytes.Repeat([]byte{byte(0x50 + index)}, 32),
			time.Date(2026, 7, 22, 0, 0, 0, 0, time.UTC), time.Date(2027, 7, 22, 0, 0, 0, 0, time.UTC)); err != nil {
			t.Fatalf("seed session: %v", err)
		}
	}
	roles := []struct {
		scopeID uuid.UUID
		userID  uuid.UUID
		name    string
	}{
		{fixture.platformScope, platformUser, "platform_owner"},
		{fixture.tenantA, ownerAUser, "tenant_owner"},
		{fixture.tenantA, viewerAUser, "tenant_viewer"},
		{fixture.tenantB, ownerBUser, "tenant_owner"},
	}
	for _, role := range roles {
		roleID := uuid.New()
		if _, err := pool.Exec(ctx, `
			WITH inserted_role AS (
				INSERT INTO roles(id,scope_id,name,system_role) VALUES($1,$2,$3,true)
				RETURNING id
			)
			INSERT INTO role_assignments(scope_id,user_id,role_id)
			SELECT $2,$4,id FROM inserted_role`,
			roleID, role.scopeID, role.name, role.userID); err != nil {
			t.Fatalf("seed role %s: %v", role.name, err)
		}
		if role.name == "platform_owner" {
			if _, err := pool.Exec(ctx, `INSERT INTO role_permissions(role_id,permission_name)
				VALUES($1,'platform.admin')`, roleID); err != nil {
				t.Fatalf("seed platform administrator permission: %v", err)
			}
		}
	}
	insertSiteWithID(t, pool, fixture.siteA, fixture.tenantA, ownerAUser, "a.example.test")
	insertSiteWithID(t, pool, fixture.siteB, fixture.tenantB, ownerBUser, "b.example.test")
	fixture.platform = Actor{UserID: platformUser, ScopeID: fixture.platformScope, ScopeKind: "platform", Permissions: []string{PermissionRead, PermissionManage}, Credential: CredentialReference{Kind: CredentialKindSession, ID: platformSession}}
	fixture.ownerA = Actor{UserID: ownerAUser, ScopeID: fixture.tenantA, ScopeKind: "tenant", Permissions: []string{PermissionRead, PermissionManage}, Credential: CredentialReference{Kind: CredentialKindSession, ID: fixture.ownerASession}}
	fixture.viewerA = Actor{UserID: viewerAUser, ScopeID: fixture.tenantA, ScopeKind: "tenant", Permissions: []string{PermissionRead}, Credential: CredentialReference{Kind: CredentialKindSession, ID: viewerASession}}
	fixture.memberA = Actor{UserID: memberAUser, ScopeID: fixture.tenantA, ScopeKind: "tenant", Permissions: []string{}, Credential: CredentialReference{Kind: CredentialKindSession, ID: memberASession}}
	fixture.ownerB = Actor{UserID: ownerBUser, ScopeID: fixture.tenantB, ScopeKind: "tenant", Permissions: []string{PermissionRead, PermissionManage}, Credential: CredentialReference{Kind: CredentialKindSession, ID: ownerBSession}}
	return fixture
}

func openChallengeTestPool(t *testing.T) *pgxpool.Pool {
	t.Helper()
	databaseURL := strings.TrimSpace(os.Getenv("TEST_DATABASE_URL"))
	if databaseURL == "" {
		t.Skip("TEST_DATABASE_URL is not set")
	}
	if pool := databasetest.ClonedMigratedPool(t, nil); pool != nil {
		return pool
	}
	ctx, cancel := context.WithTimeout(context.Background(), 30*time.Second)
	defer cancel()
	adminPool, err := pgxpool.New(ctx, databaseURL)
	if err != nil {
		t.Fatalf("open test administration pool: %v", err)
	}
	schema := "challenge_policy_test_" + strings.ReplaceAll(uuid.NewString(), "-", "")
	if !regexp.MustCompile(`^challenge_policy_test_[a-f0-9]{32}$`).MatchString(schema) {
		adminPool.Close()
		t.Fatalf("refusing unexpected schema %q", schema)
	}
	identifier := pgx.Identifier{schema}.Sanitize()
	if _, err := adminPool.Exec(ctx, "CREATE SCHEMA "+identifier); err != nil {
		adminPool.Close()
		t.Fatalf("create isolated schema: %v", err)
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
	if err := migrateChallengeTestSchema(ctx, pool); err != nil {
		pool.Close()
		_, _ = adminPool.Exec(context.Background(), "DROP SCHEMA "+identifier+" CASCADE")
		adminPool.Close()
		t.Fatalf("migrate challenge policy schema: %v", err)
	}
	t.Cleanup(func() {
		pool.Close()
		cleanupCtx, cleanupCancel := databasetest.CleanupContext()
		defer cleanupCancel()
		if _, err := adminPool.Exec(cleanupCtx, "DROP SCHEMA "+identifier+" CASCADE"); err != nil {
			t.Errorf("drop isolated schema: %v", err)
		}
		adminPool.Close()
	})
	return pool
}

func migrateChallengeTestSchema(ctx context.Context, pool *pgxpool.Pool) error {
	return database.Migrate(ctx, pool, "up")
}

func runChallengeMigration053(ctx context.Context, pool *pgxpool.Pool, direction string) error {
	if direction != "up" && direction != "down" {
		return fmt.Errorf("invalid migration direction %q", direction)
	}
	return executeChallengeMigration(ctx, pool, "053_challenge_policies."+direction+".sql")
}

func executeChallengeMigration(ctx context.Context, pool *pgxpool.Pool, name string) error {
	script, err := fs.ReadFile(migrations.FS, name)
	if err != nil {
		return err
	}
	tx, err := pool.Begin(ctx)
	if err != nil {
		return err
	}
	defer func() { _ = tx.Rollback(context.Background()) }()
	if _, err := tx.Exec(ctx, string(script)); err != nil {
		return err
	}
	return tx.Commit(ctx)
}

func insertSite(t *testing.T, pool *pgxpool.Pool, scopeID, ownerID uuid.UUID, domain string) uuid.UUID {
	t.Helper()
	id := uuid.New()
	insertSiteWithID(t, pool, id, scopeID, ownerID, domain)
	return id
}

func insertSiteWithID(t *testing.T, pool *pgxpool.Pool, id, scopeID, ownerID uuid.UUID, domain string) {
	t.Helper()
	ctx := context.Background()
	err := pgx.BeginFunc(ctx, pool, func(tx pgx.Tx) error {
		if _, err := tx.Exec(ctx, `
			INSERT INTO sites(
				id,scope_id,owner_user_id,domain,origins,origin_hosts,enabled,status,
				created_by_user_id,updated_by_user_id,display_id
			) VALUES($1,$2,$3,$4,ARRAY['192.0.2.10'],ARRAY['192.0.2.10'],true,'active',$3,$3,
				COALESCE((SELECT max(display_id) FROM sites WHERE scope_id=$2),0)+1)`,
			id, scopeID, ownerID, domain); err != nil {
			return err
		}
		if _, err := tx.Exec(ctx, `INSERT INTO site_origin_pools(site_id) VALUES($1)`, id); err != nil {
			return err
		}
		_, err := tx.Exec(ctx, `
			INSERT INTO site_origins(site_id,position,host,port,weight,enabled)
			VALUES($1,1,'192.0.2.10',80,1,true)`, id)
		return err
	})
	if err != nil {
		t.Fatalf("insert site %s: %v", domain, err)
	}
}

func insertSystemRole(t *testing.T, pool *pgxpool.Pool, scopeID uuid.UUID, name string) uuid.UUID {
	t.Helper()
	id := uuid.New()
	if _, err := pool.Exec(context.Background(), `
		INSERT INTO roles(id,scope_id,name,system_role) VALUES($1,$2,$3,true)`, id, scopeID, name); err != nil {
		t.Fatalf("insert system role %s: %v", name, err)
	}
	return id
}

func assertAuditedStateConfigTamperRejected(
	t *testing.T,
	pool *pgxpool.Pool,
	actor Actor,
	policy Policy,
	expectedRevision int64,
	action string,
	enabled, deleted bool,
) {
	t.Helper()
	ctx := context.Background()
	requestID := "direct-" + action + "-config-tamper"
	traceID := requestID + "-trace"
	tx, err := pool.Begin(ctx)
	if err != nil {
		t.Fatal(err)
	}
	actorUserID := actor.UserID
	if err := audit.New(pool).Append(ctx, tx, audit.Event{
		ScopeID: policy.TenantScopeID, ActorUserID: &actorUserID,
		Action: "challenge_policy." + action, ResourceType: "challenge_policy",
		ResourceID: policy.ID.String(), RequestID: requestID, Result: "success",
		Payload: map[string]any{"trace_id": traceID, "revision": expectedRevision + 1},
	}); err != nil {
		_ = tx.Rollback(ctx)
		t.Fatalf("append valid tamper audit: %v", err)
	}
	_, err = tx.Exec(ctx, `
		INSERT INTO challenge_policy_revisions (
			policy_id, tenant_scope_id, tenant_id, site_id, host, revision, action,
			priority, mode, min_delay_seconds, challenge_ttl_seconds, pass_ttl_seconds,
			clock_skew_seconds, attempts_per_nonce, failure_window_seconds, max_failures_per_window,
			ip_binding, bind_user_agent, bypass_routes, key_reference, external_provider,
			external_app_reference, enabled, deleted, document, created_by_scope_id,
			created_by_user_id, request_id, trace_id, created_at
		)
		SELECT policy_id, tenant_scope_id, tenant_id, site_id, host, revision+1, $2,
		       priority+1, mode, min_delay_seconds, challenge_ttl_seconds, pass_ttl_seconds,
		       clock_skew_seconds, attempts_per_nonce, failure_window_seconds, max_failures_per_window,
		       ip_binding, bind_user_agent, bypass_routes, key_reference, external_provider,
		       external_app_reference, $3, $4,
		       jsonb_set(jsonb_set(jsonb_set(jsonb_set(
		           document, '{revision}', to_jsonb((revision+1)::bigint)),
		           '{priority}', to_jsonb(priority+1)),
		           '{enabled}', to_jsonb($3::boolean)),
		           '{deleted}', to_jsonb($4::boolean)),
		       $5, $6, $7, $8, now()
		FROM challenge_policy_revisions
		WHERE policy_id=$1 AND revision=$9`,
		policy.ID, action, enabled, deleted, actor.ScopeID, actor.UserID, requestID, traceID, expectedRevision)
	if err == nil {
		_ = tx.Rollback(ctx)
		t.Fatalf("audited %s config tamper unexpectedly succeeded", action)
	}
	_ = tx.Rollback(ctx)
	var revision int64
	if err := pool.QueryRow(ctx, `SELECT current_revision FROM challenge_policies WHERE id=$1`, policy.ID).Scan(&revision); err != nil || revision != expectedRevision {
		t.Fatalf("%s config tamper head=%d error=%v", action, revision, err)
	}
	var auditCount int
	if err := pool.QueryRow(ctx, `SELECT count(*) FROM audit_events WHERE request_id=$1`, requestID).Scan(&auditCount); err != nil || auditCount != 0 {
		t.Fatalf("%s config tamper audit count=%d error=%v", action, auditCount, err)
	}
}

func createServicePolicy(t *testing.T, fixture *testFixture, siteID uuid.UUID, host, key string) Policy {
	t.Helper()
	result, err := fixture.service.Create(context.Background(), fixture.ownerA, CreateRequest{
		TargetScopeID: fixture.tenantA, SiteID: siteID, Host: host, Enabled: true,
		Config: validConfig(ModeClick), WriteMetadata: metadata(key),
	})
	if err != nil {
		t.Fatalf("create policy %s: %v", host, err)
	}
	return result.Policy
}

func metadata(key string) WriteMetadata {
	return WriteMetadata{IdempotencyKey: key, RequestID: key + "-request", TraceID: key + "-trace"}
}

func testCursorCodec(t *testing.T, keyByte byte) *CursorCodec {
	t.Helper()
	codec, err := NewCursorCodec("challenge-policy-test", "test-key-2026-07", bytes.Repeat([]byte{keyByte}, minCursorKeyBytes))
	if err != nil {
		t.Fatalf("NewCursorCodec: %v", err)
	}
	return codec
}

func createPayload(siteID uuid.UUID, host string, config Config, enabled bool) map[string]any {
	return map[string]any{"site_id": siteID.String(), "host": host, "enabled": enabled, "config": config}
}

func collectionPath(scopeID uuid.UUID) string {
	return "/v1/tenant-scopes/" + scopeID.String() + "/challenge-policies"
}

func itemPath(scopeID, policyID uuid.UUID) string {
	return collectionPath(scopeID) + "/" + policyID.String()
}

func (fixture *testFixture) request(
	t *testing.T, token, method, path string, body any, key, ifMatch string,
) *httptest.ResponseRecorder {
	t.Helper()
	var encoded []byte
	if body != nil {
		var err error
		encoded, err = json.Marshal(body)
		if err != nil {
			t.Fatal(err)
		}
	}
	return fixture.rawRequest(t, token, method, path, string(encoded), key, ifMatch)
}

func (fixture *testFixture) rawRequest(
	t *testing.T, token, method, path, body, key, ifMatch string,
) *httptest.ResponseRecorder {
	t.Helper()
	request := httptest.NewRequest(method, path, strings.NewReader(body))
	request.Header.Set("Authorization", "Bearer "+token)
	request.Header.Set("X-Request-ID", "http-request-"+strings.ReplaceAll(key, "_", "-"))
	request.Header.Set("X-Trace-ID", "http-trace-"+strings.ReplaceAll(key, "_", "-"))
	if key == "" {
		request.Header.Set("X-Request-ID", "http-read-request")
		request.Header.Set("X-Trace-ID", "http-read-trace")
	} else {
		request.Header.Set("Idempotency-Key", key)
	}
	if ifMatch != "" {
		request.Header.Set("If-Match", ifMatch)
	}
	if body != "" {
		request.Header.Set("Content-Type", "application/json")
	}
	response := httptest.NewRecorder()
	fixture.handler.ServeHTTP(response, request)
	return response
}

func decodePolicyResponse(t *testing.T, response *httptest.ResponseRecorder) Policy {
	t.Helper()
	var policy Policy
	if err := json.Unmarshal(response.Body.Bytes(), &policy); err != nil {
		t.Fatalf("decode policy response status=%d body=%s: %v", response.Code, response.Body, err)
	}
	return policy
}

func assertHTTPError(t *testing.T, response *httptest.ResponseRecorder, status int, code string) {
	t.Helper()
	if response.Code != status {
		t.Fatalf("HTTP status=%d want=%d body=%s", response.Code, status, response.Body)
	}
	if code == "" {
		return
	}
	var envelope errorEnvelope
	if err := json.Unmarshal(response.Body.Bytes(), &envelope); err != nil || envelope.Error.Code != code {
		t.Fatalf("HTTP error code=%q want=%q body=%s error=%v", envelope.Error.Code, code, response.Body, err)
	}
	if envelope.Error.RequestID == "" || envelope.Error.TraceID == "" {
		t.Fatalf("HTTP error omitted request correlation: %s", response.Body)
	}
}

func assertNoPrivateReferences(t *testing.T, body []byte, forbidden ...string) {
	t.Helper()
	for _, value := range forbidden {
		if value != "" && bytes.Contains(body, []byte(value)) {
			t.Fatalf("response leaked private reference %q: %s", value, body)
		}
	}
	var object map[string]any
	if err := json.Unmarshal(body, &object); err != nil {
		t.Fatal(err)
	}
	for _, key := range []string{"key_reference", "external_provider", "app_reference"} {
		if _, exists := object[key]; exists {
			t.Fatalf("response leaked field %q: %s", key, body)
		}
	}
}

func assertRolePermission(t *testing.T, pool *pgxpool.Pool, scopeID uuid.UUID, roleName, permission string) {
	t.Helper()
	var exists bool
	if err := pool.QueryRow(context.Background(), `
		SELECT EXISTS(
			SELECT 1 FROM roles role JOIN role_permissions item ON item.role_id=role.id
			WHERE role.scope_id=$1 AND role.name=$2 AND item.permission_name=$3
		)`, scopeID, roleName, permission).Scan(&exists); err != nil || !exists {
		t.Fatalf("role %s permission %s exists=%v error=%v", roleName, permission, exists, err)
	}
}

func assertNoRolePermission(t *testing.T, pool *pgxpool.Pool, scopeID uuid.UUID, roleName, permission string) {
	t.Helper()
	var exists bool
	if err := pool.QueryRow(context.Background(), `
		SELECT EXISTS(
			SELECT 1 FROM roles role JOIN role_permissions item ON item.role_id=role.id
			WHERE role.scope_id=$1 AND role.name=$2 AND item.permission_name=$3
		)`, scopeID, roleName, permission).Scan(&exists); err != nil || exists {
		t.Fatalf("role %s unexpected permission %s exists=%v error=%v", roleName, permission, exists, err)
	}
}

type testSigner struct {
	private ed25519.PrivateKey
}

func (testSigner) KeyID() string { return "challenge-test-key" }
func (signer testSigner) Sign(_ context.Context, payload []byte) ([]byte, error) {
	return ed25519.Sign(signer.private, payload), nil
}

func installLease(
	t *testing.T,
	pool *pgxpool.Pool,
	trust *entitlementguard.TrustStore,
	privateKey ed25519.PrivateKey,
	now time.Time,
	serial uint64,
	includeFeature bool,
) {
	t.Helper()
	features := []entitlement.Feature{}
	if includeFeature {
		features = []entitlement.Feature{{Code: entitlementguard.FeatureSitesManage}}
	}
	lease := entitlement.Lease{
		Schema: entitlement.SchemaV1, Audience: entitlement.ControlAudience,
		// Revocation sets accept only canonical UUIDs.
		CustomerID: "11111111-1111-4111-8111-111111111111", InstallationID: "22222222-2222-4222-8222-222222222222",
		LicenseID: "33333333-3333-4333-8333-333333333333", Serial: serial, NotBefore: now.Add(-time.Hour).Unix(),
		ExpiresAt: now.Add(time.Hour).Unix(), GraceUntil: now.Add(2 * time.Hour).Unix(),
		Version:  entitlement.VersionRange{Channel: "stable", Min: "0.1.0", Max: "1.0.0"},
		Features: features,
		Quotas:   []entitlement.Quota{{Code: entitlementguard.QuotaDomainsCount, Limit: 10}},
	}
	signed, err := entitlement.Sign(context.Background(), lease, testSigner{private: privateKey})
	if err != nil {
		t.Fatalf("sign entitlement: %v", err)
	}
	// Install needs the keyset LKG and an accepted revocation set (once per schema; later serials reuse it).
	var accepted bool
	if err := pool.QueryRow(context.Background(),
		`SELECT EXISTS(SELECT 1 FROM entitlement_signing_keyset_lkg)`).Scan(&accepted); err != nil {
		t.Fatal(err)
	}
	if !accepted {
		guardtest.AcceptRevocation(t, pool, trust, testSigner{private: privateKey}, lease, now)
	}
	if _, err := entitlementguard.NewService(pool, trust).Install(context.Background(), entitlementguard.InstallBundle{
		InstallationID: lease.InstallationID, SignedLease: signed,
	}, now); err != nil {
		t.Fatalf("install entitlement: %v", err)
	}
}

func readAll(t *testing.T, reader io.Reader) string {
	t.Helper()
	value, err := io.ReadAll(reader)
	if err != nil {
		t.Fatal(err)
	}
	return string(value)
}
