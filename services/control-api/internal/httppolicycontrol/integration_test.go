package httppolicycontrol

import (
	"context"
	"crypto/ed25519"
	"crypto/rand"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	iofs "io/fs"
	"net/http"
	"net/http/httptest"
	"os"
	"regexp"
	"sort"
	"strconv"
	"strings"
	"sync"
	"testing"
	"time"

	"github.com/cdnca/cdnca/libs/entitlement"
	"github.com/cdnca/cdnca/services/control-api/internal/audit"
	"github.com/cdnca/cdnca/services/control-api/internal/database/databasetest"
	"github.com/cdnca/cdnca/services/control-api/internal/entitlementguard"
	"github.com/cdnca/cdnca/services/control-api/internal/entitlementguard/guardtest"
	controlmigrations "github.com/cdnca/cdnca/services/control-api/migrations"
	"github.com/google/uuid"
	"github.com/jackc/pgx/v5"
	"github.com/jackc/pgx/v5/pgxpool"
)

type gateFunc func(context.Context, pgx.Tx, entitlementCheck) error

func (function gateFunc) Check(ctx context.Context, tx pgx.Tx, check entitlementCheck) error {
	return function(ctx, tx, check)
}

type failingAudit struct{}

func (failingAudit) Append(context.Context, pgx.Tx, audit.Event) error {
	return errors.New("forced audit failure")
}

type integrationFixture struct {
	pool              *pgxpool.Pool
	service           *Service
	handler           *Handler
	now               time.Time
	platformScope     uuid.UUID
	tenantA           uuid.UUID
	tenantB           uuid.UUID
	siteA             uuid.UUID
	siteB             uuid.UUID
	siteOwnedByMember uuid.UUID
	platform          Actor
	legacyPlatform    Actor
	ownerA            Actor
	viewerA           Actor
	memberA           Actor
	ownerB            Actor
}

func TestHTTPPolicyHTTPCRUDIsolationAndRBAC(t *testing.T) {
	fixture := newIntegrationFixture(t, allowTestGate())
	config := validTestConfig()
	invalidMetadata := httptest.NewRequest(http.MethodGet, collectionPath(fixture.tenantA), nil)
	invalidMetadata.Header.Set("Authorization", "Bearer owner-a")
	invalidMetadata.Header.Set("X-Request-ID", strings.Repeat("x", maxResponseBytes+1))
	invalidMetadata.Header.Set("X-Trace-ID", "valid-trace")
	response := httptest.NewRecorder()
	fixture.handler.ServeHTTP(response, invalidMetadata)
	assertHTTPError(t, response, http.StatusBadRequest, "invalid_request")
	if strings.Contains(response.Body.String(), strings.Repeat("x", 1024)) ||
		!strings.Contains(response.Body.String(), `"request_id":"invalid"`) {
		t.Fatalf("invalid correlation ID was reflected: body bytes=%d", response.Body.Len())
	}

	response = fixture.request(t, "", http.MethodGet, collectionPath(fixture.tenantA), nil, "", "")
	assertHTTPError(t, response, http.StatusUnauthorized, "authentication_required")

	response = fixture.request(t, "member-a", http.MethodGet, collectionPath(fixture.tenantA), nil, "", "")
	assertHTTPError(t, response, http.StatusForbidden, "permission_denied")

	response = fixture.request(t, "owner-a", http.MethodPost, collectionPath(fixture.tenantA),
		createPayload(fixture.siteA, config, true), "http-create", "")
	if response.Code != http.StatusCreated || response.Header().Get("ETag") != `"1"` {
		t.Fatalf("create status=%d ETag=%q body=%s", response.Code, response.Header().Get("ETag"), response.Body)
	}
	created := decodePolicyResponse(t, response)
	if created.SiteID != fixture.siteA || created.SiteOwnerUserID != fixture.ownerA.UserID || created.PublicationRevision != 1 {
		t.Fatalf("created policy = %#v", created)
	}
	response = fixture.request(t, "owner-a", http.MethodPost, collectionPath(fixture.tenantA),
		createPayload(fixture.siteA, config, true), "duplicate-live-site", "")
	assertHTTPError(t, response, http.StatusConflict, "resource_conflict")

	response = fixture.request(t, "owner-a", http.MethodGet, collectionPath(fixture.tenantA), nil, "", "")
	if response.Code != http.StatusOK || !strings.Contains(response.Body.String(), created.ID.String()) {
		t.Fatalf("list status=%d body=%s", response.Code, response.Body)
	}
	response = fixture.request(t, "owner-a", http.MethodGet, itemPath(fixture.tenantA, created.ID), nil, "", "")
	if response.Code != http.StatusOK || response.Header().Get("ETag") != `"1"` {
		t.Fatalf("detail status=%d ETag=%q body=%s", response.Code, response.Header().Get("ETag"), response.Body)
	}

	updatedConfig := validTestConfig()
	updatedConfig.MaxUploadBytes = 32
	response = fixture.request(t, "owner-a", http.MethodPatch, itemPath(fixture.tenantA, created.ID),
		map[string]any{"config": updatedConfig}, "http-update", `"1"`)
	if response.Code != http.StatusOK || decodePolicyResponse(t, response).Revision != 2 {
		t.Fatalf("update status=%d body=%s", response.Code, response.Body)
	}

	response = fixture.request(t, "owner-a", http.MethodPost, itemPath(fixture.tenantA, created.ID)+"/disable",
		map[string]any{}, "http-disable", `"2"`)
	if response.Code != http.StatusOK || decodePolicyResponse(t, response).Enabled {
		t.Fatalf("disable status=%d body=%s", response.Code, response.Body)
	}
	response = fixture.request(t, "owner-a", http.MethodPost, itemPath(fixture.tenantA, created.ID)+"/enable",
		map[string]any{}, "http-enable", `"3"`)
	if response.Code != http.StatusOK || !decodePolicyResponse(t, response).Enabled {
		t.Fatalf("enable status=%d body=%s", response.Code, response.Body)
	}

	response = fixture.request(t, "owner-a", http.MethodGet, collectionPath(fixture.tenantA)+"/publication-preview", nil, "", "")
	if response.Code != http.StatusOK || response.Header().Get("ETag") == "" ||
		!strings.Contains(response.Body.String(), EdgeSchemaVersion) || !strings.Contains(response.Body.String(), `"state":"preview"`) {
		t.Fatalf("publication preview status=%d body=%s", response.Code, response.Body)
	}

	response = fixture.request(t, "owner-a", http.MethodDelete, itemPath(fixture.tenantA, created.ID), nil, "http-delete", `"4"`)
	if response.Code != http.StatusOK || !decodePolicyResponse(t, response).Deleted {
		t.Fatalf("delete status=%d body=%s", response.Code, response.Body)
	}
	response = fixture.request(t, "owner-a", http.MethodGet, itemPath(fixture.tenantA, created.ID), nil, "", "")
	assertHTTPError(t, response, http.StatusNotFound, "not_found")

	response = fixture.request(t, "owner-a", http.MethodPost, collectionPath(fixture.tenantA),
		createPayload(fixture.siteOwnedByMember, config, true), "not-owner", "")
	assertHTTPError(t, response, http.StatusNotFound, "not_found")
	response = fixture.request(t, "owner-a", http.MethodGet, collectionPath(fixture.tenantB), nil, "", "")
	assertHTTPError(t, response, http.StatusNotFound, "not_found")
	response = fixture.request(t, "owner-b", http.MethodGet, itemPath(fixture.tenantB, created.ID), nil, "", "")
	assertHTTPError(t, response, http.StatusNotFound, "not_found")
	response = fixture.request(t, "viewer-a", http.MethodGet, itemPath(fixture.tenantA, created.ID), nil, "", "")
	assertHTTPError(t, response, http.StatusNotFound, "not_found")

	// site-parity3b: a platform administrator writes the tenant site's HTTP
	// policy in the tenant's scope; the revision and audit name the platform
	// actor and the site's tenant.
	response = fixture.request(t, "platform", http.MethodPost, collectionPath(fixture.tenantA),
		createPayload(fixture.siteOwnedByMember, config, false), "platform-explicit-tenant", "")
	if response.Code != http.StatusCreated {
		t.Fatalf("platform create status=%d body=%s", response.Code, response.Body)
	}
	platformCreated := decodePolicyResponse(t, response)
	if platformCreated.TenantScopeID != fixture.tenantA || platformCreated.SiteOwnerUserID != fixture.memberA.UserID {
		t.Fatalf("platform created policy = %#v", platformCreated)
	}
	var revisionScope, revisionUser, auditScope, auditActor uuid.UUID
	if err := fixture.pool.QueryRow(context.Background(), `SELECT created_by_scope_id,created_by_user_id
		FROM http_policy_revisions WHERE policy_id=$1 AND revision=1`, platformCreated.ID).Scan(&revisionScope, &revisionUser); err != nil ||
		revisionScope != fixture.platformScope || revisionUser != fixture.platform.UserID {
		t.Fatalf("platform revision actor scope=%s user=%s err=%v", revisionScope, revisionUser, err)
	}
	if err := fixture.pool.QueryRow(context.Background(), `SELECT scope_id,actor_user_id FROM audit_events
		WHERE action='http_policy.create' AND resource_id=$1 AND result='success'`, platformCreated.ID.String()).
		Scan(&auditScope, &auditActor); err != nil || auditScope != fixture.tenantA || auditActor != fixture.platform.UserID {
		t.Fatalf("platform audit scope=%s actor=%s err=%v", auditScope, auditActor, err)
	}
	// A tenant owner still cannot write another tenant's site policy.
	response = fixture.request(t, "owner-b", http.MethodPatch, itemPath(fixture.tenantA, platformCreated.ID),
		map[string]any{"config": config}, "cross-tenant-update", `"1"`)
	assertHTTPError(t, response, http.StatusNotFound, "not_found")
	if _, err := fixture.service.List(context.Background(), fixture.legacyPlatform, ListFilter{
		TargetScopeID: fixture.tenantA, Limit: 10,
	}); !errors.Is(err, ErrPermissionDenied) {
		t.Fatalf("platform.admin wildcard list error=%v", err)
	}

	response = fixture.rawRequest(t, "owner-a", http.MethodPost, collectionPath(fixture.tenantA),
		`{"site_id":"`+fixture.siteA.String()+`","enabled":true,"config":{},"unknown":true}`,
		"unknown-field", "", "application/json")
	assertHTTPError(t, response, http.StatusBadRequest, "invalid_request")
	response = fixture.rawRequest(t, "owner-a", http.MethodPost, collectionPath(fixture.tenantA),
		`{"site_id":"`+fixture.siteA.String()+`","site_id":"`+fixture.siteB.String()+`","enabled":true,"config":{}}`,
		"duplicate-field", "", "application/json")
	assertHTTPError(t, response, http.StatusBadRequest, "invalid_request")
	response = fixture.request(t, "owner-a", http.MethodPost, collectionPath(fixture.tenantA),
		map[string]any{"site_id": fixture.siteA.String(), "config": config}, "missing-enabled", "")
	assertHTTPError(t, response, http.StatusBadRequest, "invalid_request")
	configObject := func() map[string]any {
		encoded, err := json.Marshal(config)
		if err != nil {
			t.Fatal(err)
		}
		var object map[string]any
		if err := json.Unmarshal(encoded, &object); err != nil {
			t.Fatal(err)
		}
		return object
	}
	missingCORS := configObject()
	delete(missingCORS, "cors")
	response = fixture.request(t, "owner-a", http.MethodPost, collectionPath(fixture.tenantA),
		map[string]any{"site_id": fixture.siteA.String(), "enabled": true, "config": missingCORS}, "missing-cors", "")
	assertHTTPError(t, response, http.StatusBadRequest, "invalid_request")
	missingRewriteFlag := configObject()
	delete(missingRewriteFlag["rewrites"].([]any)[0].(map[string]any), "preserve_cookie")
	response = fixture.request(t, "owner-a", http.MethodPost, collectionPath(fixture.tenantA),
		map[string]any{"site_id": fixture.siteA.String(), "enabled": true, "config": missingRewriteFlag}, "missing-rewrite-flag", "")
	assertHTTPError(t, response, http.StatusBadRequest, "invalid_request")
	missingHeaderValues := configObject()
	delete(missingHeaderValues["response_headers"].([]any)[0].(map[string]any), "values")
	response = fixture.request(t, "owner-a", http.MethodPost, collectionPath(fixture.tenantA),
		map[string]any{"site_id": fixture.siteA.String(), "enabled": true, "config": missingHeaderValues}, "missing-header-values", "")
	assertHTTPError(t, response, http.StatusBadRequest, "invalid_request")
	missingCORSFlag := configObject()
	delete(missingCORSFlag["cors"].(map[string]any), "allow_credentials")
	response = fixture.request(t, "owner-a", http.MethodPost, collectionPath(fixture.tenantA),
		map[string]any{"site_id": fixture.siteA.String(), "enabled": true, "config": missingCORSFlag}, "missing-cors-flag", "")
	assertHTTPError(t, response, http.StatusBadRequest, "invalid_request")
	response = fixture.rawRequest(t, "owner-a", http.MethodPost, collectionPath(fixture.tenantA),
		strings.Repeat("x", maxRequestBytes+1), "oversized", "", "application/json")
	assertHTTPError(t, response, http.StatusBadRequest, "invalid_request")
	response = fixture.rawRequest(t, "owner-a", http.MethodPost, collectionPath(fixture.tenantA),
		`{}`, "wrong-media", "", "text/plain")
	assertHTTPError(t, response, http.StatusBadRequest, "invalid_request")
	response = fixture.request(t, "owner-a", http.MethodPatch, itemPath(fixture.tenantA, uuid.New()),
		map[string]any{"config": config}, "missing-if-match", "")
	assertHTTPError(t, response, http.StatusPreconditionFailed, "precondition_required")
}

func TestHTTPPolicyCASIdempotencyAuditRollbackPaginationAndPublication(t *testing.T) {
	fixture := newIntegrationFixture(t, allowTestGate())
	first := createServicePolicy(t, fixture, fixture.siteA, "first")
	replayRequest := CreateRequest{
		TargetScopeID: fixture.tenantA, SiteID: fixture.siteA, Enabled: true,
		Config: validTestConfig(), WriteMetadata: testMetadata("first"),
	}
	replayed, err := fixture.service.Create(context.Background(), fixture.ownerA, replayRequest)
	if err != nil || !replayed.Replayed || replayed.Policy.ID != first.ID {
		t.Fatalf("create replay = (%#v, %v)", replayed, err)
	}
	replayRequest.Config.MaxUploadBytes = 17
	if _, err := fixture.service.Create(context.Background(), fixture.ownerA, replayRequest); !errors.Is(err, ErrIdempotencyConflict) {
		t.Fatalf("changed idempotent request error=%v", err)
	}

	var wait sync.WaitGroup
	errorsByWriter := make(chan error, 2)
	for index := 0; index < 2; index++ {
		wait.Add(1)
		go func(index int) {
			defer wait.Done()
			config := validTestConfig()
			config.MaxUploadBytes = int64(100 + index)
			_, err := fixture.service.Update(context.Background(), fixture.ownerA, UpdateRequest{
				TargetScopeID: fixture.tenantA, ID: first.ID, ExpectedRevision: 1,
				Config: config, WriteMetadata: testMetadata(fmt.Sprintf("cas-%d", index)),
			})
			errorsByWriter <- err
		}(index)
	}
	wait.Wait()
	close(errorsByWriter)
	var success, conflict int
	for err := range errorsByWriter {
		if err == nil {
			success++
		} else if errors.Is(err, ErrRevisionConflict) {
			conflict++
		} else {
			t.Fatalf("unexpected CAS error=%v", err)
		}
	}
	if success != 1 || conflict != 1 {
		t.Fatalf("CAS success=%d conflict=%d", success, conflict)
	}

	secondSite := insertTestSite(t, fixture.pool, fixture.tenantA, fixture.ownerA.UserID, "second.example.test")
	thirdSite := insertTestSite(t, fixture.pool, fixture.tenantA, fixture.ownerA.UserID, "third.example.test")
	second := createServicePolicy(t, fixture, secondSite, "second")
	third := createServicePolicy(t, fixture, thirdSite, "third")
	pageOne, err := fixture.service.List(context.Background(), fixture.ownerA, ListFilter{TargetScopeID: fixture.tenantA, Limit: 2})
	if err != nil || len(pageOne.Items) != 2 || pageOne.NextCursor == "" {
		t.Fatalf("page one=%#v error=%v", pageOne, err)
	}
	pageTwo, err := fixture.service.List(context.Background(), fixture.ownerA, ListFilter{
		TargetScopeID: fixture.tenantA, Limit: 2, Cursor: pageOne.NextCursor,
	})
	if err != nil || len(pageTwo.Items) != 1 || pageTwo.NextCursor != "" {
		t.Fatalf("page two=%#v error=%v", pageTwo, err)
	}
	seen := map[uuid.UUID]bool{}
	for _, item := range append(pageOne.Items, pageTwo.Items...) {
		seen[item.ID] = true
	}
	if !seen[first.ID] || !seen[second.ID] || !seen[third.ID] {
		t.Fatalf("pagination lost policy: %#v", seen)
	}

	previewA, err := fixture.service.PublicationPreview(context.Background(), fixture.ownerA, fixture.tenantA)
	if err != nil {
		t.Fatal(err)
	}
	previewB, err := fixture.service.PublicationPreview(context.Background(), fixture.ownerA, fixture.tenantA)
	if err != nil || previewA.SHA256 != previewB.SHA256 || previewA.Snapshot.PolicyVersion != previewB.Snapshot.PolicyVersion {
		t.Fatalf("publication not deterministic: %#v %#v %v", previewA, previewB, err)
	}
	if !sort.SliceIsSorted(previewA.Snapshot.Sites, func(left, right int) bool {
		return previewA.Snapshot.Sites[left].SiteID < previewA.Snapshot.Sites[right].SiteID
	}) {
		t.Fatalf("publication sites not sorted: %#v", previewA.Snapshot.Sites)
	}

	failureSite := insertTestSite(t, fixture.pool, fixture.tenantA, fixture.ownerA.UserID, "audit-failure.example.test")
	failingStore, err := newStoreWithDependencies(
		fixture.pool, func() time.Time { return fixture.now }, allowTestGate(), failingAudit{}, databaseTxAuthorizer{})
	if err != nil {
		t.Fatal(err)
	}
	failingService := NewService(failingStore)
	if _, err := failingService.Create(context.Background(), fixture.ownerA, CreateRequest{
		TargetScopeID: fixture.tenantA, SiteID: failureSite, Enabled: true,
		Config: validTestConfig(), WriteMetadata: testMetadata("audit-failure"),
	}); !errors.Is(err, ErrUnavailable) {
		t.Fatalf("audit failure create error=%v", err)
	}
	var facts int
	if err := fixture.pool.QueryRow(context.Background(), `
		SELECT (SELECT count(*) FROM http_policies WHERE site_id=$1) +
		       (SELECT count(*) FROM http_policy_write_requests WHERE idempotency_key='audit-failure')`, failureSite).Scan(&facts); err != nil || facts != 0 {
		t.Fatalf("audit failure facts=%d error=%v", facts, err)
	}
	for _, scopeID := range []uuid.UUID{fixture.tenantA, fixture.tenantB} {
		if err := audit.New(fixture.pool).VerifyScope(context.Background(), scopeID); err != nil {
			t.Fatalf("VerifyScope(%s)=%v", scopeID, err)
		}
	}
}

func TestHTTPPolicyEntitlementDenialAndGrace(t *testing.T) {
	pool := openHTTPPolicyTestPool(t)
	fixture := seedIntegrationFixture(t, pool)
	now := httpPolicyTestBase.Add(3 * time.Minute)
	current := now
	publicKey, privateKey, err := ed25519.GenerateKey(rand.Reader)
	if err != nil {
		t.Fatal(err)
	}
	trust, err := entitlementguard.NewTrustStore([]entitlementguard.VerificationKey{{KeyID: "http-policy-test-key", PublicKey: publicKey}})
	if err != nil {
		t.Fatal(err)
	}
	store, err := newStoreWithAuthorizer(pool, func() time.Time { return current }, trust, databaseTxAuthorizer{})
	if err != nil {
		t.Fatal(err)
	}
	service := NewService(store)

	installTestLease(t, pool, trust, privateKey, now, 1, false)
	_, err = service.Create(context.Background(), fixture.ownerA, CreateRequest{
		TargetScopeID: fixture.tenantA, SiteID: fixture.siteA, Enabled: true,
		Config: validTestConfig(), WriteMetadata: testMetadata("feature-denied"),
	})
	if !errors.Is(err, ErrEntitlementDenied) {
		t.Fatalf("feature denial error=%v", err)
	}
	if _, err := service.Create(context.Background(), fixture.ownerA, CreateRequest{
		TargetScopeID: fixture.tenantA, SiteID: fixture.siteA, Enabled: true,
		Config: validTestConfig(), WriteMetadata: testMetadata("feature-denied"),
	}); !errors.Is(err, ErrEntitlementDenied) {
		t.Fatalf("feature denial replay error=%v", err)
	}
	var denialAudits int
	if err := pool.QueryRow(context.Background(), `
		SELECT count(*) FROM audit_events WHERE request_id='feature-denied-request'
		  AND action='http_policy.create' AND result='denied'`).Scan(&denialAudits); err != nil || denialAudits != 1 {
		t.Fatalf("denial audit count=%d error=%v", denialAudits, err)
	}

	installTestLease(t, pool, trust, privateKey, now, 2, true)
	created, err := service.Create(context.Background(), fixture.ownerA, CreateRequest{
		TargetScopeID: fixture.tenantA, SiteID: fixture.siteA, Enabled: true,
		Config: validTestConfig(), WriteMetadata: testMetadata("entitlement-valid"),
	})
	if err != nil {
		t.Fatalf("valid entitlement create=%v", err)
	}
	current = now.Add(90 * time.Minute)
	updated := validTestConfig()
	updated.MaxUploadBytes = 64
	// Grace keeps updates allowed.
	if _, err := service.Update(context.Background(), fixture.ownerA, UpdateRequest{
		TargetScopeID: fixture.tenantA, ID: created.Policy.ID, ExpectedRevision: 1,
		Config: updated, WriteMetadata: testMetadata("grace-update"),
	}); err != nil {
		t.Fatalf("grace update error=%v", err)
	}
	read, err := service.Get(context.Background(), fixture.ownerA, fixture.tenantA, created.Policy.ID)
	if err != nil || read.Revision != 2 {
		t.Fatalf("grace read=(%#v,%v)", read, err)
	}
	disabled, err := service.SetEnabled(context.Background(), fixture.ownerA, StateRequest{
		TargetScopeID: fixture.tenantA, ID: created.Policy.ID, ExpectedRevision: 2,
		Enabled: false, WriteMetadata: testMetadata("grace-disable"),
	})
	if err != nil || disabled.Policy.Enabled {
		t.Fatalf("grace disable=(%#v,%v)", disabled, err)
	}
	if _, err := service.Delete(context.Background(), fixture.ownerA, DeleteRequest{
		TargetScopeID: fixture.tenantA, ID: created.Policy.ID, ExpectedRevision: 3,
		WriteMetadata: testMetadata("grace-delete"),
	}); err != nil {
		t.Fatalf("grace delete=%v", err)
	}
}

func TestHTTPPolicyMigrationAndDirectSQLGuards(t *testing.T) {
	pool := openHTTPPolicyTestPool056(t)
	ctx := context.Background()
	down := httpPolicyMigrationScript(t, "056_http_policy_control.down.sql")
	up := httpPolicyMigrationScript(t, "056_http_policy_control.up.sql")
	var versionText string
	if err := pool.QueryRow(ctx, `SHOW server_version_num`).Scan(&versionText); err != nil || parseServerVersion(t, versionText)/10000 != 17 {
		t.Fatalf("PostgreSQL version=%q error=%v, want 17.x", versionText, err)
	}
	if err := execHTTPPolicyMigration(ctx, pool, down); err != nil {
		t.Fatalf("056 empty down=%v", err)
	}
	var tableName *string
	if err := pool.QueryRow(ctx, `SELECT to_regclass('http_policies')::text`).Scan(&tableName); err != nil || tableName != nil {
		t.Fatalf("http_policies after down=%v error=%v", tableName, err)
	}
	if err := execHTTPPolicyMigration(ctx, pool, up); err != nil {
		t.Fatalf("056 up after down=%v", err)
	}
	applyHTTPPolicyDocumentRules(t, pool)
	fixture := seedIntegrationFixture(t, pool)
	store, err := newStoreWithDependencies(pool, time.Now, allowTestGate(), nil, databaseTxAuthorizer{})
	if err != nil {
		t.Fatal(err)
	}
	service := NewService(store)
	created, err := service.Create(ctx, fixture.ownerA, CreateRequest{
		TargetScopeID: fixture.tenantA, SiteID: fixture.siteA, Enabled: true,
		Config: validTestConfig(), WriteMetadata: testMetadata("guard-create"),
	})
	if err != nil {
		t.Fatalf("create guarded policy=%v", err)
	}
	for name, expression := range map[string]string{
		"zero upload":          `jsonb_set(document,'{max_upload_bytes}','0')`,
		"hop by hop header":    `jsonb_set(document,'{request_headers,0,name}',to_jsonb('host'::text))`,
		"header CRLF":          `jsonb_set(document,'{request_headers,0,values,0}',to_jsonb(E'ok\r\nbad'::text))`,
		"encoded traversal":    `jsonb_set(document,'{rewrites,0,match_path}',to_jsonb('/%252e%252e/x'::text))`,
		"exact trailing slash": `jsonb_set(document,'{rewrites,0,match_path}',to_jsonb('/legacy/'::text))`,
		"prefix suffix rewrite loop": `jsonb_set(document,'{rewrites}','[
			{"rule_id":"loop-a","priority":1,"match_kind":"prefix","match_path":"/a/","target_path":"/b/","preserve_query":false,"preserve_cookie":false},
			{"rule_id":"loop-b","priority":2,"match_kind":"exact","match_path":"/b/x","target_path":"/a/x","preserve_query":false,"preserve_cookie":false}
		]'::jsonb)`,
		"rewrite hop overflow": `jsonb_set(document,'{rewrites}',(
			SELECT jsonb_agg(jsonb_build_object(
				'rule_id','hop-'||lpad(position::text,2,'0'),'priority',position,
				'match_kind','exact','match_path','/hop-'||position,
				'target_path','/hop-'||(position+1),'preserve_query',false,'preserve_cookie',false
			) ORDER BY position) FROM generate_series(0,16) position
		))`,
		"cross kind duplicate rule ID": `jsonb_set(document,'{redirects,0,rule_id}',to_jsonb('rewrite-v1'::text))`,
		"cross kind overlap": `jsonb_set(jsonb_set(document,'{redirects,0,priority}','10'),
			'{redirects,0,match_path}',to_jsonb('/legacy'::text))`,
		"redirect overlap": `jsonb_set(document,'{redirects}',(document->'redirects')||jsonb_build_array(
			jsonb_set(document->'redirects'->0,'{rule_id}',to_jsonb('redirect-other'::text))))`,
		"hostname label overflow":      `jsonb_set(document,'{redirect_allowed_hosts,0}',to_jsonb(repeat('a',64)||'.test'))`,
		"authority port overflow":      `jsonb_set(document,'{redirect_allowed_hosts,0}',to_jsonb('redirect.example.test:70000'::text))`,
		"malformed IPv6":               `jsonb_set(document,'{redirect_allowed_hosts,0}',to_jsonb('[::::]'::text))`,
		"redirect traversal":           `jsonb_set(document,'{redirects,0,target_url}',to_jsonb('https://redirect.example.test/a/../x'::text))`,
		"CORS hostname label overflow": `jsonb_set(document,'{cors,allowed_origins,0}',to_jsonb('https://'||repeat('a',64)||'.test'))`,
		// ge-waf S8 (migration 404): hotlink protection.
		"referer check missing":           `document-'referer_check'`,
		"referer check restricts nothing": `jsonb_set(document,'{referer_check}','{"allow_empty":true,"allow_same_domain":false,"allowed_domains":[],"denied_domains":[],"check_origin":false,"extensions":[]}')`,
		"referer check both lists":        `jsonb_set(document,'{referer_check}','{"allow_empty":true,"allow_same_domain":false,"allowed_domains":["a.example.test"],"denied_domains":["a.example.test"],"check_origin":false,"extensions":[]}')`,
		"referer check bare wildcard":     `jsonb_set(document,'{referer_check}','{"allow_empty":true,"allow_same_domain":false,"allowed_domains":["*.test"],"denied_domains":[],"check_origin":false,"extensions":[]}')`,
		"referer check bad extension":     `jsonb_set(document,'{referer_check}','{"allow_empty":true,"allow_same_domain":true,"allowed_domains":[],"denied_domains":[],"check_origin":false,"extensions":[".jpg"]}')`,
		"referer check extra key":         `jsonb_set(document,'{referer_check}','{"allow_empty":true,"allow_same_domain":true,"allowed_domains":[],"denied_domains":[],"check_origin":false,"extensions":[],"x":1}')`,
	} {
		t.Run("document "+name, func(t *testing.T) {
			var valid bool
			if err := pool.QueryRow(ctx, `SELECT http_policy_document_valid_056(`+expression+`)
				FROM http_policy_revisions WHERE policy_id=$1 AND revision=1`, created.Policy.ID).Scan(&valid); err != nil {
				t.Fatal(err)
			}
			if valid {
				t.Fatalf("database accepted invalid HTTP policy document: %s", name)
			}
		})
	}
	var refererValid bool
	if err := pool.QueryRow(ctx, `SELECT http_policy_document_valid_056(jsonb_set(document,'{referer_check}',
		'{"allow_empty":false,"allow_same_domain":true,"allowed_domains":["*.partner.example.test","cdn.example.test"],"denied_domains":["bad.partner.example.test"],"check_origin":true,"extensions":["jpg","png"]}'))
		FROM http_policy_revisions WHERE policy_id=$1 AND revision=1`, created.Policy.ID).Scan(&refererValid); err != nil || !refererValid {
		t.Fatalf("valid referer_check rejected: %v %v", refererValid, err)
	}
	for _, authority := range []string{"redirect.example.test", "192.0.2.1:8443", "[2001:db8::1]:8443"} {
		var valid bool
		if err := pool.QueryRow(ctx, `SELECT http_policy_authority_valid_056($1)`, authority).Scan(&valid); err != nil || !valid {
			t.Fatalf("valid authority %q = %v error=%v", authority, valid, err)
		}
	}
	assertSQLFailure := func(name, expected string, statement string, arguments ...any) {
		t.Helper()
		if _, err := pool.Exec(ctx, statement, arguments...); err == nil || !strings.Contains(err.Error(), expected) {
			t.Fatalf("%s error=%v, want %q", name, err, expected)
		}
	}
	assertSQLFailure("nonmonotonic revision", "not monotonic", `
		INSERT INTO http_policy_revisions(
			policy_id,tenant_scope_id,tenant_id,site_id,site_owner_user_id,revision,
			action,enabled,deleted,document,created_by_scope_id,created_by_user_id,
			request_id,trace_id,created_at
		)
		SELECT policy_id,tenant_scope_id,tenant_id,site_id,site_owner_user_id,3,
		       'update',enabled,deleted,jsonb_set(document,'{revision}','3'),
		       created_by_scope_id,created_by_user_id,'direct-gap','direct-gap-trace',now()
		FROM http_policy_revisions WHERE policy_id=$1 AND revision=1`, created.Policy.ID)
	unauthorizedPolicyID := uuid.New()
	assertSQLFailure("unauthorized actor", "actor is not authorized", `
		INSERT INTO http_policy_revisions(
			policy_id,tenant_scope_id,tenant_id,site_id,site_owner_user_id,revision,
			action,enabled,deleted,document,created_by_scope_id,created_by_user_id,
			request_id,trace_id,created_at
		)
		SELECT $2::uuid,tenant_scope_id,tenant_id,site_id,site_owner_user_id,1,
		       'create',enabled,deleted,jsonb_set(document,'{policy_id}',to_jsonb(($2::uuid)::text)),
		       $3::uuid,$4::uuid,'direct-actor','direct-actor-trace',now()
		FROM http_policy_revisions WHERE policy_id=$1 AND revision=1`,
		created.Policy.ID, unauthorizedPolicyID, fixture.tenantA, fixture.viewerA.UserID)
	mismatchedPolicyID := uuid.New()
	assertSQLFailure("site scope mismatch", "site ownership mismatch", `
		INSERT INTO http_policy_revisions(
			policy_id,tenant_scope_id,tenant_id,site_id,site_owner_user_id,revision,
			action,enabled,deleted,document,created_by_scope_id,created_by_user_id,
			request_id,trace_id,created_at
		)
		SELECT $2::uuid,tenant_scope_id,tenant_id,$3::uuid,$4::uuid,1,'create',enabled,deleted,
		       jsonb_set(jsonb_set(jsonb_set(document,'{policy_id}',to_jsonb(($2::uuid)::text)),
		           '{site_id}',to_jsonb(($3::uuid)::text)),'{site_owner_user_id}',to_jsonb(($4::uuid)::text)),
		       created_by_scope_id,created_by_user_id,'direct-site','direct-site-trace',now()
		FROM http_policy_revisions WHERE policy_id=$1 AND revision=1`,
		created.Policy.ID, mismatchedPolicyID, fixture.siteB, fixture.ownerB.UserID)
	duplicatePolicyID := uuid.New()
	assertSQLFailure("duplicate live site", "duplicate key", `
		INSERT INTO http_policy_revisions(
			policy_id,tenant_scope_id,tenant_id,site_id,site_owner_user_id,revision,
			action,enabled,deleted,document,created_by_scope_id,created_by_user_id,
			request_id,trace_id,created_at
		)
		SELECT $2::uuid,tenant_scope_id,tenant_id,site_id,site_owner_user_id,1,
		       'create',enabled,deleted,jsonb_set(document,'{policy_id}',to_jsonb(($2::uuid)::text)),
		       created_by_scope_id,created_by_user_id,'direct-duplicate','direct-duplicate-trace',now()
		FROM http_policy_revisions WHERE policy_id=$1 AND revision=1`, created.Policy.ID, duplicatePolicyID)
	for name, statement := range map[string]string{
		"head update":            `UPDATE http_policies SET current_enabled=false WHERE id='` + created.Policy.ID.String() + `'`,
		"head delete":            `DELETE FROM http_policies WHERE id='` + created.Policy.ID.String() + `'`,
		"head truncate":          `TRUNCATE http_policies`,
		"publication update":     `UPDATE http_policy_publication_heads SET revision=999 WHERE tenant_scope_id='` + fixture.tenantA.String() + `'`,
		"publication truncate":   `TRUNCATE http_policy_publication_heads`,
		"revision update":        `UPDATE http_policy_revisions SET enabled=false WHERE policy_id='` + created.Policy.ID.String() + `'`,
		"revision delete":        `DELETE FROM http_policy_revisions WHERE policy_id='` + created.Policy.ID.String() + `'`,
		"revision truncate":      `TRUNCATE http_policy_revisions`,
		"write request update":   `UPDATE http_policy_write_requests SET trace_id='tampered' WHERE idempotency_key='guard-create'`,
		"write request delete":   `DELETE FROM http_policy_write_requests WHERE idempotency_key='guard-create'`,
		"write request truncate": `TRUNCATE http_policy_write_requests`,
	} {
		t.Run(name, func(t *testing.T) {
			if _, err := pool.Exec(ctx, statement); err == nil {
				t.Fatalf("direct SQL %s unexpectedly succeeded", name)
			}
		})
	}

	if _, err := pool.Exec(ctx, `
		INSERT INTO http_policy_revisions(
			policy_id,tenant_scope_id,tenant_id,site_id,site_owner_user_id,revision,
			action,enabled,deleted,document,created_by_scope_id,created_by_user_id,
			request_id,trace_id,created_at
		)
		SELECT policy_id,tenant_scope_id,tenant_id,site_id,site_owner_user_id,2,
		       'update',enabled,deleted,
		       jsonb_set(jsonb_set(document,'{revision}','2'),'{max_upload_bytes}','0'),
		       created_by_scope_id,created_by_user_id,'direct-invalid','direct-invalid-trace',now()
		FROM http_policy_revisions WHERE policy_id=$1 AND revision=1`, created.Policy.ID); err == nil {
		t.Fatal("direct invalid document unexpectedly succeeded")
	}

	tx, err := pool.Begin(ctx)
	if err != nil {
		t.Fatal(err)
	}
	_, err = tx.Exec(ctx, `
		INSERT INTO http_policy_revisions(
			policy_id,tenant_scope_id,tenant_id,site_id,site_owner_user_id,revision,
			action,enabled,deleted,document,created_by_scope_id,created_by_user_id,
			request_id,trace_id,created_at
		)
		SELECT policy_id,tenant_scope_id,tenant_id,site_id,site_owner_user_id,2,
		       'update',enabled,deleted,jsonb_set(document,'{revision}','2'),
		       created_by_scope_id,created_by_user_id,'direct-no-audit','direct-no-audit-trace',now()
		FROM http_policy_revisions WHERE policy_id=$1 AND revision=1`, created.Policy.ID)
	if err != nil {
		_ = tx.Rollback(ctx)
		t.Fatalf("prepare unaudited revision=%v", err)
	}
	if err := tx.Commit(ctx); err == nil {
		t.Fatal("unaudited direct revision commit unexpectedly succeeded")
	}
	var revision int64
	if err := pool.QueryRow(ctx, `SELECT current_revision FROM http_policies WHERE id=$1`, created.Policy.ID).Scan(&revision); err != nil || revision != 1 {
		t.Fatalf("unaudited revision rollback head=%d error=%v", revision, err)
	}
	if err := execHTTPPolicyMigration(ctx, pool, down); err == nil || !strings.Contains(err.Error(), "irreversible HTTP policy facts") {
		t.Fatalf("056 down with facts error=%v", err)
	}
	if err := pool.QueryRow(ctx, `SELECT current_revision FROM http_policies WHERE id=$1`, created.Policy.ID).Scan(&revision); err != nil || revision != 1 {
		t.Fatalf("failed down changed facts head=%d error=%v", revision, err)
	}
}

func TestHTTPPolicyCancellationAndStorageUnavailable(t *testing.T) {
	fixture := newIntegrationFixture(t, allowTestGate())
	ctx, cancel := context.WithCancel(context.Background())
	cancel()
	if _, err := fixture.service.List(ctx, fixture.ownerA, ListFilter{TargetScopeID: fixture.tenantA, Limit: 10}); !errors.Is(err, context.Canceled) {
		t.Fatalf("canceled list error=%v", err)
	}
	fixture.pool.Close()
	if _, err := fixture.service.List(context.Background(), fixture.ownerA, ListFilter{TargetScopeID: fixture.tenantA, Limit: 10}); !errors.Is(err, ErrUnavailable) {
		t.Fatalf("closed storage error=%v", err)
	}
	response := fixture.request(t, "owner-a", http.MethodGet, collectionPath(fixture.tenantA), nil, "", "")
	assertHTTPError(t, response, http.StatusServiceUnavailable, "service_unavailable")
	if strings.Contains(strings.ToLower(response.Body.String()), "pool") || strings.Contains(strings.ToLower(response.Body.String()), "sql") {
		t.Fatalf("storage detail leaked: %s", response.Body)
	}
}

func allowTestGate() entitlementGate {
	return gateFunc(func(context.Context, pgx.Tx, entitlementCheck) error { return nil })
}

func newIntegrationFixture(t *testing.T, gate entitlementGate) *integrationFixture {
	return newIntegrationFixtureWithAuthorizer(t, gate, databaseTxAuthorizer{})
}

func newIntegrationFixtureWithAuthorizer(
	t *testing.T,
	gate entitlementGate,
	authorizer TxAuthorizer,
) *integrationFixture {
	t.Helper()
	pool := openHTTPPolicyTestPool(t)
	fixture := seedIntegrationFixture(t, pool)
	fixture.now = httpPolicyTestBase.Add(2 * time.Minute)
	store, err := newStoreWithDependencies(
		pool, func() time.Time { return fixture.now }, gate, nil, authorizer)
	if err != nil {
		t.Fatal(err)
	}
	fixture.service = NewService(store)
	authenticator := AuthenticatorFunc(func(request *http.Request) (Actor, error) {
		switch strings.TrimPrefix(request.Header.Get("Authorization"), "Bearer ") {
		case "platform":
			return fixture.platform, nil
		case "legacy-platform":
			return fixture.legacyPlatform, nil
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
		t.Fatal(err)
	}
	fixture.handler = handler
	return fixture
}

func seedIntegrationFixture(t *testing.T, pool *pgxpool.Pool) *integrationFixture {
	t.Helper()
	fixture := &integrationFixture{
		pool: pool, platformScope: uuid.New(), tenantA: uuid.New(), tenantB: uuid.New(),
		siteA: uuid.New(), siteB: uuid.New(), siteOwnedByMember: uuid.New(),
	}
	tenantAID, tenantBID := uuid.New(), uuid.New()
	platformUser, legacyPlatformUser := uuid.New(), uuid.New()
	ownerAUser, viewerAUser, memberAUser, ownerBUser := uuid.New(), uuid.New(), uuid.New(), uuid.New()
	platformSession, legacyPlatformSession := uuid.New(), uuid.New()
	ownerASession, viewerASession, memberASession, ownerBSession := uuid.New(), uuid.New(), uuid.New(), uuid.New()
	ctx := context.Background()
	if _, err := pool.Exec(ctx, `INSERT INTO tenants(id,display_name) VALUES($1,'Tenant A'),($2,'Tenant B')`, tenantAID, tenantBID); err != nil {
		t.Fatalf("seed tenants=%v", err)
	}
	if _, err := pool.Exec(ctx, `
		INSERT INTO access_scopes(id,kind,tenant_id) VALUES
			($1,'platform',NULL),($2,'tenant',$4),($3,'tenant',$5)`,
		fixture.platformScope, fixture.tenantA, fixture.tenantB, tenantAID, tenantBID); err != nil {
		t.Fatalf("seed scopes=%v", err)
	}
	if _, err := pool.Exec(ctx, `
		WITH inserted_users AS (
			INSERT INTO users(id,username,display_name,password_hash) VALUES
				($4,'http-platform','HTTP Platform','hash'),
				($5,'http-legacy-platform','HTTP Legacy Platform','hash'),
				($6,'http-owner-a','HTTP Owner A','hash'),
				($7,'http-viewer-a','HTTP Viewer A','hash'),
				($8,'http-member-a','HTTP Member A','hash'),
				($9,'http-owner-b','HTTP Owner B','hash')
			RETURNING id
		)
		INSERT INTO memberships(scope_id,user_id)
		SELECT value.scope_id,value.user_id
		FROM (VALUES ($1::uuid,$4::uuid),($1,$5),($2,$6),($2,$7),($2,$8),($3,$9)) value(scope_id,user_id)
		JOIN inserted_users ON inserted_users.id=value.user_id`,
		fixture.platformScope, fixture.tenantA, fixture.tenantB,
		platformUser, legacyPlatformUser, ownerAUser, viewerAUser, memberAUser, ownerBUser); err != nil {
		t.Fatalf("seed identities=%v", err)
	}
	for _, session := range []struct {
		id      uuid.UUID
		userID  uuid.UUID
		scopeID uuid.UUID
	}{
		{platformSession, platformUser, fixture.platformScope},
		{legacyPlatformSession, legacyPlatformUser, fixture.platformScope},
		{ownerASession, ownerAUser, fixture.tenantA},
		{viewerASession, viewerAUser, fixture.tenantA},
		{memberASession, memberAUser, fixture.tenantA},
		{ownerBSession, ownerBUser, fixture.tenantB},
	} {
		refreshHash := make([]byte, 32)
		copy(refreshHash, session.id[:])
		copy(refreshHash[16:], session.id[:])
		if _, err := pool.Exec(ctx, `INSERT INTO auth_sessions(
			id,family_id,user_id,scope_id,refresh_token_hash,created_at,expires_at
		) VALUES($1,$1,$2,$3,$4,$5,$6)`, session.id, session.userID, session.scopeID,
			refreshHash, httpPolicyTestBase,
			httpPolicyTestBase.AddDate(1, 0, 0)); err != nil {
			t.Fatalf("seed session %s=%v", session.id, err)
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
				INSERT INTO roles(id,scope_id,name,system_role) VALUES($1,$2,$3,true) RETURNING id
			)
			INSERT INTO role_assignments(scope_id,user_id,role_id) SELECT $2,$4,id FROM inserted_role`,
			roleID, role.scopeID, role.name, role.userID); err != nil {
			t.Fatalf("seed role %s=%v", role.name, err)
		}
	}
	legacyRole := uuid.New()
	if _, err := pool.Exec(ctx, `
		WITH inserted_role AS (
			INSERT INTO roles(id,scope_id,name,system_role) VALUES($1,$2,'legacy_platform_admin',true) RETURNING id
		), granted AS (
			INSERT INTO role_permissions(role_id,permission_name) SELECT id,'platform.admin' FROM inserted_role RETURNING role_id
		)
		INSERT INTO role_assignments(scope_id,user_id,role_id) SELECT $2,$3,role_id FROM granted`,
		legacyRole, fixture.platformScope, legacyPlatformUser); err != nil {
		t.Fatalf("seed legacy platform role=%v", err)
	}
	insertTestSiteWithID(t, pool, fixture.siteA, fixture.tenantA, ownerAUser, "a.example.test")
	insertTestSiteWithID(t, pool, fixture.siteB, fixture.tenantB, ownerBUser, "b.example.test")
	insertTestSiteWithID(t, pool, fixture.siteOwnedByMember, fixture.tenantA, memberAUser, "member.example.test")
	fixture.platform = Actor{UserID: platformUser, ScopeID: fixture.platformScope, ScopeKind: "platform",
		Permissions: []string{PermissionRead, PermissionManage}, Credential: CredentialReference{Kind: CredentialKindSession, ID: platformSession}}
	fixture.legacyPlatform = Actor{UserID: legacyPlatformUser, ScopeID: fixture.platformScope, ScopeKind: "platform",
		Permissions: []string{"platform.admin"}, Credential: CredentialReference{Kind: CredentialKindSession, ID: legacyPlatformSession}}
	fixture.ownerA = Actor{UserID: ownerAUser, ScopeID: fixture.tenantA, ScopeKind: "tenant",
		Permissions: []string{PermissionRead, PermissionManage}, Credential: CredentialReference{Kind: CredentialKindSession, ID: ownerASession}}
	fixture.viewerA = Actor{UserID: viewerAUser, ScopeID: fixture.tenantA, ScopeKind: "tenant",
		Permissions: []string{PermissionRead}, Credential: CredentialReference{Kind: CredentialKindSession, ID: viewerASession}}
	fixture.memberA = Actor{UserID: memberAUser, ScopeID: fixture.tenantA, ScopeKind: "tenant",
		Credential: CredentialReference{Kind: CredentialKindSession, ID: memberASession}}
	fixture.ownerB = Actor{UserID: ownerBUser, ScopeID: fixture.tenantB, ScopeKind: "tenant",
		Permissions: []string{PermissionRead, PermissionManage}, Credential: CredentialReference{Kind: CredentialKindSession, ID: ownerBSession}}
	return fixture
}

// openHTTPPolicyTestPool is a release-head schema: the service, IAM,
// entitlement guard and audit log under test read today's schema.
func openHTTPPolicyTestPool(t *testing.T) *pgxpool.Pool {
	t.Helper()
	return databasetest.MigratedPool(t, nil)
}

// openHTTPPolicyTestPool056 stops the schema at 056 for the 056 migration
// guard case; today's audit writer needs 361's columns, added on their own.
func openHTTPPolicyTestPool056(t *testing.T) *pgxpool.Pool {
	t.Helper()
	pool := openHTTPPolicyTestPoolThrough056(t)
	databasetest.AddUnifiedAuditColumns(t, pool)
	return pool
}

// applyHTTPPolicyDocumentRules replaces 056's stored document checks with
// 391's (regex rules, preserve_path) and then 406's (referer_check): today's
// store writes preserve_path on every redirect and referer_check on every
// document, which 056 alone rejects. Only the HTTP policy document checks are
// applied; the head guards and the rest of 391/406 need their release heads.
func applyHTTPPolicyDocumentRules(t *testing.T, pool *pgxpool.Pool) {
	t.Helper()
	script := httpPolicyMigrationScript(t, "391_http_policy_regex_rules.up.sql")
	start := strings.Index(script, "CREATE FUNCTION http_policy_regex_valid_391")
	end := strings.Index(script, "-- A site's request handling")
	if start < 0 || end <= start {
		t.Fatal("391 HTTP policy document section not found")
	}
	if err := execHTTPPolicyMigration(context.Background(), pool, script[start:end]); err != nil {
		t.Fatalf("apply 391 HTTP policy document rules=%v", err)
	}
	// 056 down keeps the 406 referer_check helpers the fixture applied, but
	// 056 up restores the document check without referer_check; restore 406's.
	script = httpPolicyMigrationScript(t, "406_http_policy_referer_check.up.sql")
	start = strings.Index(script, "CREATE OR REPLACE FUNCTION http_policy_document_valid_056")
	if start < 0 {
		t.Fatal("406 HTTP policy document check not found")
	}
	if err := execHTTPPolicyMigration(context.Background(), pool, script[start:]); err != nil {
		t.Fatalf("apply 406 HTTP policy referer_check rules=%v", err)
	}
}

func openHTTPPolicyTestPoolThrough056(t *testing.T) *pgxpool.Pool {
	t.Helper()
	databaseURL := strings.TrimSpace(os.Getenv("TEST_DATABASE_URL"))
	if databaseURL == "" {
		t.Skip("TEST_DATABASE_URL is not set")
	}
	ctx, cancel := context.WithTimeout(context.Background(), 45*time.Second)
	defer cancel()
	adminPool, err := pgxpool.New(ctx, databaseURL)
	if err != nil {
		t.Fatalf("open administration pool=%v", err)
	}
	schema := "http_policy_test_" + strings.ReplaceAll(uuid.NewString(), "-", "")
	if !regexp.MustCompile(`^http_policy_test_[a-f0-9]{32}$`).MatchString(schema) {
		adminPool.Close()
		t.Fatalf("refusing unexpected schema %q", schema)
	}
	identifier := pgx.Identifier{schema}.Sanitize()
	if _, err := adminPool.Exec(ctx, "CREATE SCHEMA "+identifier); err != nil {
		adminPool.Close()
		t.Fatalf("create isolated schema=%v", err)
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
	if err := migrateHTTPPolicyThrough056(ctx, pool); err != nil {
		pool.Close()
		_, _ = adminPool.Exec(context.Background(), "DROP SCHEMA "+identifier+" CASCADE")
		adminPool.Close()
		t.Fatalf("migrate 001..056=%v", err)
	}
	t.Cleanup(func() {
		pool.Close()
		cleanupCtx, cleanupCancel := databasetest.CleanupContext()
		defer cleanupCancel()
		if _, err := adminPool.Exec(cleanupCtx, "DROP SCHEMA "+identifier+" CASCADE"); err != nil {
			t.Errorf("drop isolated schema=%v", err)
		}
		adminPool.Close()
	})
	return pool
}

func migrateHTTPPolicyThrough056(ctx context.Context, pool *pgxpool.Pool) error {
	if _, err := pool.Exec(ctx, `CREATE TABLE schema_migrations(
		version bigint PRIMARY KEY, applied_at timestamptz NOT NULL DEFAULT now())`); err != nil {
		return err
	}
	entries, err := iofs.ReadDir(controlmigrations.FS, ".")
	if err != nil {
		return err
	}
	type migration struct {
		version int
		name    string
	}
	items := make([]migration, 0, 56)
	for _, entry := range entries {
		name := entry.Name()
		if entry.IsDir() || !strings.HasSuffix(name, ".up.sql") {
			continue
		}
		separator := strings.IndexByte(name, '_')
		version, err := strconv.Atoi(name[:separator])
		if err != nil {
			return err
		}
		if version <= 56 {
			items = append(items, migration{version: version, name: name})
		}
	}
	sort.Slice(items, func(left, right int) bool { return items[left].version < items[right].version })
	if len(items) != 56 {
		return fmt.Errorf("migration count through 056 = %d, want 56", len(items))
	}
	for index, item := range items {
		if item.version != index+1 {
			return fmt.Errorf("migration gap at %d", index+1)
		}
		script, err := iofs.ReadFile(controlmigrations.FS, item.name)
		if err != nil {
			return err
		}
		if err := pgx.BeginFunc(ctx, pool, func(tx pgx.Tx) error {
			if _, err := tx.Exec(ctx, string(script)); err != nil {
				return err
			}
			_, err := tx.Exec(ctx, `INSERT INTO schema_migrations(version) VALUES($1)`, item.version)
			return err
		}); err != nil {
			return fmt.Errorf("apply %s: %w", item.name, err)
		}
	}
	// The HTTP policy document contract is extended by migration 406 (ge-waf
	// referer_check); its body, after the release-head guard, is applied on
	// top of 056 so the fixture validates the documents the code writes.
	script, err := iofs.ReadFile(controlmigrations.FS, "406_http_policy_referer_check.up.sql")
	if err != nil {
		return err
	}
	_, body, found := strings.Cut(string(script), "$migration_406_up$;\n")
	if !found {
		return fmt.Errorf("406 guard not found")
	}
	if _, err := pool.Exec(ctx, body); err != nil {
		return fmt.Errorf("apply 404 body: %w", err)
	}
	return nil
}

func httpPolicyMigrationScript(t *testing.T, name string) string {
	t.Helper()
	script, err := iofs.ReadFile(controlmigrations.FS, name)
	if err != nil {
		t.Fatal(err)
	}
	return string(script)
}

func execHTTPPolicyMigration(ctx context.Context, pool *pgxpool.Pool, script string) error {
	return pgx.BeginFunc(ctx, pool, func(tx pgx.Tx) error {
		_, err := tx.Exec(ctx, script)
		return err
	})
}

func insertTestSite(t *testing.T, pool *pgxpool.Pool, scopeID, ownerID uuid.UUID, domain string) uuid.UUID {
	t.Helper()
	id := uuid.New()
	insertTestSiteWithID(t, pool, id, scopeID, ownerID, domain)
	return id
}

func insertTestSiteWithID(t *testing.T, pool *pgxpool.Pool, id, scopeID, ownerID uuid.UUID, domain string) {
	t.Helper()
	ctx := context.Background()
	err := pgx.BeginFunc(ctx, pool, func(tx pgx.Tx) error {
		// From 210 on a site's display ID comes from its scope's sequence, as
		// site.Store allocates it; the 056 schema has neither.
		var displayIDs bool
		if err := tx.QueryRow(ctx, `SELECT to_regclass('site_display_id_sequences') IS NOT NULL`).Scan(&displayIDs); err != nil {
			return err
		}
		if displayIDs {
			if _, err := tx.Exec(ctx, `WITH display AS (
				INSERT INTO site_display_id_sequences(scope_id,next_value,updated_at) VALUES($2,2,now())
				ON CONFLICT(scope_id) DO UPDATE SET next_value=site_display_id_sequences.next_value+1,
					updated_at=EXCLUDED.updated_at
				RETURNING next_value-1 AS display_id
			)
			INSERT INTO sites(
				id,display_id,scope_id,owner_user_id,domain,origins,origin_hosts,enabled,status,
				created_by_user_id,updated_by_user_id
			) SELECT $1,display.display_id,$2,$3,$4,ARRAY['192.0.2.10'],ARRAY['192.0.2.10'],true,'active',$3,$3
			FROM display`, id, scopeID, ownerID, domain); err != nil {
				return err
			}
			// Active domains (domains.count) are counted from site domain
			// facts since 148; site.Store writes the activation with the site.
			if _, err := tx.Exec(ctx, `INSERT INTO site_domain_facts(
				scope_id,site_id,site_revision,action,canonical_domain,
				actor_scope_id,actor_user_id,request_id,occurred_at
			) VALUES($1,$2,1,'activate',$3,$1,$4,'http-policy-site-seed',now())`,
				scopeID, id, domain, ownerID); err != nil {
				return err
			}
		} else if _, err := tx.Exec(ctx, `
			INSERT INTO sites(
				id,scope_id,owner_user_id,domain,origins,origin_hosts,enabled,status,
				created_by_user_id,updated_by_user_id
			) VALUES($1,$2,$3,$4,ARRAY['192.0.2.10'],ARRAY['192.0.2.10'],true,'active',$3,$3)`,
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
		t.Fatalf("insert site %s=%v", domain, err)
	}
}

func createServicePolicy(t *testing.T, fixture *integrationFixture, siteID uuid.UUID, key string) Policy {
	t.Helper()
	result, err := fixture.service.Create(context.Background(), fixture.ownerA, CreateRequest{
		TargetScopeID: fixture.tenantA, SiteID: siteID, Enabled: true,
		Config: validTestConfig(), WriteMetadata: testMetadata(key),
	})
	if err != nil {
		t.Fatalf("create policy %s=%v", key, err)
	}
	return result.Policy
}

func testMetadata(key string) WriteMetadata {
	return WriteMetadata{IdempotencyKey: key, RequestID: key + "-request", TraceID: key + "-trace"}
}

func createPayload(siteID uuid.UUID, config Config, enabled bool) map[string]any {
	return map[string]any{"site_id": siteID.String(), "enabled": enabled, "config": config}
}

func collectionPath(scopeID uuid.UUID) string {
	return "/v1/tenant-scopes/" + scopeID.String() + "/http-policies"
}

func itemPath(scopeID, policyID uuid.UUID) string {
	return collectionPath(scopeID) + "/" + policyID.String()
}

func (fixture *integrationFixture) request(t *testing.T, token, method, path string, body any, key, ifMatch string) *httptest.ResponseRecorder {
	t.Helper()
	var encoded []byte
	if body != nil {
		var err error
		encoded, err = json.Marshal(body)
		if err != nil {
			t.Fatal(err)
		}
	}
	contentType := ""
	if body != nil {
		contentType = "application/json"
	}
	return fixture.rawRequest(t, token, method, path, string(encoded), key, ifMatch, contentType)
}

func (fixture *integrationFixture) rawRequest(
	t *testing.T, token, method, path, body, key, ifMatch, contentType string,
) *httptest.ResponseRecorder {
	t.Helper()
	request := httptest.NewRequest(method, path, strings.NewReader(body))
	if token != "" {
		request.Header.Set("Authorization", "Bearer "+token)
	}
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
	if contentType != "" {
		request.Header.Set("Content-Type", contentType)
	}
	response := httptest.NewRecorder()
	fixture.handler.ServeHTTP(response, request)
	return response
}

func decodePolicyResponse(t *testing.T, response *httptest.ResponseRecorder) Policy {
	t.Helper()
	var policy Policy
	if err := json.Unmarshal(response.Body.Bytes(), &policy); err != nil {
		t.Fatalf("decode policy status=%d body=%s error=%v", response.Code, response.Body, err)
	}
	return policy
}

func assertHTTPError(t *testing.T, response *httptest.ResponseRecorder, status int, code string) {
	t.Helper()
	if response.Code != status {
		t.Fatalf("HTTP status=%d want=%d body=%s", response.Code, status, response.Body)
	}
	var envelope errorEnvelope
	if err := json.Unmarshal(response.Body.Bytes(), &envelope); err != nil || envelope.Error.Code != code {
		t.Fatalf("HTTP code=%q want=%q body=%s error=%v", envelope.Error.Code, code, response.Body, err)
	}
	if envelope.Error.RequestID == "" || envelope.Error.TraceID == "" {
		t.Fatalf("HTTP error omitted correlation: %s", response.Body)
	}
}

type testLeaseSigner struct {
	private ed25519.PrivateKey
}

func (signer testLeaseSigner) KeyID() string { return "http-policy-test-key" }

func (signer testLeaseSigner) Sign(_ context.Context, payload []byte) ([]byte, error) {
	return ed25519.Sign(signer.private, payload), nil
}

func installTestLease(
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
		// Canonical UUIDs: a revocation set accepts nothing else.
		CustomerID: "6e1b0c5a-4c1f-4a52-9a0c-56d1f0c11001", InstallationID: "6e1b0c5a-4c1f-4a52-9a0c-56d1f0c11002",
		LicenseID: "6e1b0c5a-4c1f-4a52-9a0c-56d1f0c11003", Serial: serial, NotBefore: now.Add(-time.Hour).Unix(),
		ExpiresAt: now.Add(time.Hour).Unix(), GraceUntil: now.Add(2 * time.Hour).Unix(),
		Version:  entitlement.VersionRange{Channel: "stable", Min: "0.1.0", Max: "1.0.0"},
		Features: features,
		Quotas:   []entitlement.Quota{{Code: entitlementguard.QuotaDomainsCount, Limit: 100}},
	}
	signed, err := entitlement.Sign(context.Background(), lease, testLeaseSigner{private: privateKey})
	if err != nil {
		t.Fatalf("sign entitlement=%v", err)
	}
	// Since the revocation guard an install needs the keyset LKG and an
	// accepted revocation set (once per schema; later serials reuse it).
	var accepted bool
	if err := pool.QueryRow(context.Background(),
		`SELECT EXISTS(SELECT 1 FROM entitlement_signing_keyset_lkg)`).Scan(&accepted); err != nil {
		t.Fatal(err)
	}
	if !accepted {
		guardtest.AcceptRevocation(t, pool, trust, testLeaseSigner{private: privateKey}, lease, now)
	}
	if _, err := entitlementguard.NewService(pool, trust).Install(context.Background(), entitlementguard.InstallBundle{
		InstallationID: lease.InstallationID, SignedLease: signed,
	}, now); err != nil {
		t.Fatalf("install entitlement=%v", err)
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

func parseServerVersion(t *testing.T, raw string) int {
	t.Helper()
	value, err := strconv.Atoi(strings.TrimSpace(raw))
	if err != nil {
		t.Fatal(err)
	}
	return value
}

// httpPolicyTestBase anchors the fixtures' clocks near the real time: the
// entitlement revocation LKG is checked against the database's physical
// clock, and a revocation set is valid for 15 minutes from its issue, so a
// fixed calendar date is outside that window. The fixtures only depend on
// minute offsets from it, all at or before the real time.
var httpPolicyTestBase = time.Now().UTC().Truncate(time.Second).Add(-10 * time.Minute)
