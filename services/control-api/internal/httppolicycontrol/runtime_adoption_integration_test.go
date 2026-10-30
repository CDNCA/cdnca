//go:build integration

package httppolicycontrol

import (
	"bytes"
	"context"
	"encoding/json"
	"errors"
	"fmt"
	iofs "io/fs"
	"net/http"
	"net/http/httptest"
	"strconv"
	"strings"
	"testing"
	"time"

	"github.com/cdnca/cdnca/services/control-api/internal/apikeycredential"
	"github.com/cdnca/cdnca/services/control-api/internal/iamlock"
	"github.com/cdnca/cdnca/services/control-api/internal/identity"
	"github.com/cdnca/cdnca/services/control-api/internal/sessioncredential"
	controlmigrations "github.com/cdnca/cdnca/services/control-api/migrations"
	"github.com/google/uuid"
	"github.com/jackc/pgx/v5"
	"github.com/jackc/pgx/v5/pgxpool"
)

type httpPolicyRuntimeFixture struct {
	proof         *reviewerLeaseFixture
	pool          *pgxpool.Pool
	handler       http.Handler
	ownerToken    string
	platformToken string
	manageRoleID  uuid.UUID
}

type httpPolicyRuntimeOperation struct {
	name       string
	relation   string
	wantStatus int
	invoke     func(string) *httptest.ResponseRecorder
}

func TestHTTPPolicyRuntimeCurrentHeadAllOperations(t *testing.T) {
	fixture := newHTTPPolicyRuntimeFixture(t, "read committed")
	assertHTTPPolicyCurrentHead(t, fixture.pool)

	createdResponse := fixture.request(http.MethodPost, collectionPath(fixture.proof.fixture.tenantA),
		createPayload(fixture.proof.fixture.siteA, validTestConfig(), true), fixture.ownerToken, "runtime-create", "")
	assertHTTPPolicyRuntimeStatus(t, createdResponse, http.StatusCreated)
	created := decodeHTTPPolicyRuntime[Policy](t, createdResponse)
	replay := fixture.request(http.MethodPost, collectionPath(fixture.proof.fixture.tenantA),
		createPayload(fixture.proof.fixture.siteA, validTestConfig(), true), fixture.ownerToken, "runtime-create", "")
	assertHTTPPolicyRuntimeStatus(t, replay, http.StatusCreated)
	if replay.Header().Get("X-Idempotent-Replay") != "true" || decodeHTTPPolicyRuntime[Policy](t, replay).ID != created.ID {
		t.Fatalf("create replay status=%d headers=%v body=%s", replay.Code, replay.Header(), replay.Body)
	}

	list := fixture.request(http.MethodGet, collectionPath(fixture.proof.fixture.tenantA), nil, fixture.ownerToken, "", "")
	assertHTTPPolicyRuntimeStatus(t, list, http.StatusOK)
	if page := decodeHTTPPolicyRuntime[ListResult](t, list); len(page.Items) != 1 || page.Items[0].ID != created.ID {
		t.Fatalf("runtime list = %#v", page)
	}
	get := fixture.request(http.MethodGet, itemPath(fixture.proof.fixture.tenantA, created.ID), nil,
		fixture.ownerToken, "", "")
	assertHTTPPolicyRuntimeStatus(t, get, http.StatusOK)
	preview := fixture.request(http.MethodGet,
		collectionPath(fixture.proof.fixture.tenantA)+"/publication-preview", nil, fixture.ownerToken, "", "")
	assertHTTPPolicyRuntimeStatus(t, preview, http.StatusOK)

	config := validTestConfig()
	config.MaxUploadBytes++
	updated := fixture.request(http.MethodPatch, itemPath(fixture.proof.fixture.tenantA, created.ID),
		map[string]any{"config": config}, fixture.ownerToken, "runtime-update", quoteRevision(created.Revision))
	assertHTTPPolicyRuntimeStatus(t, updated, http.StatusOK)
	policy := decodeHTTPPolicyRuntime[Policy](t, updated)
	disabled := fixture.request(http.MethodPost, itemPath(fixture.proof.fixture.tenantA, policy.ID)+"/disable",
		map[string]any{}, fixture.ownerToken, "runtime-disable", quoteRevision(policy.Revision))
	assertHTTPPolicyRuntimeStatus(t, disabled, http.StatusOK)
	policy = decodeHTTPPolicyRuntime[Policy](t, disabled)
	enabled := fixture.request(http.MethodPost, itemPath(fixture.proof.fixture.tenantA, policy.ID)+"/enable",
		map[string]any{}, fixture.ownerToken, "runtime-enable", quoteRevision(policy.Revision))
	assertHTTPPolicyRuntimeStatus(t, enabled, http.StatusOK)
	policy = decodeHTTPPolicyRuntime[Policy](t, enabled)
	deleted := fixture.request(http.MethodDelete, itemPath(fixture.proof.fixture.tenantA, policy.ID), nil,
		fixture.ownerToken, "runtime-delete", quoteRevision(policy.Revision))
	assertHTTPPolicyRuntimeStatus(t, deleted, http.StatusOK)

	platform := fixture.request(http.MethodGet, collectionPath(fixture.proof.fixture.tenantA), nil,
		fixture.platformToken, "", "")
	assertHTTPPolicyRuntimeStatus(t, platform, http.StatusOK)
	before := readHTTPPolicyReviewerFacts(t, fixture.pool)
	crossTenant := fixture.request(http.MethodGet, collectionPath(fixture.proof.fixture.tenantB), nil,
		fixture.ownerToken, "", "")
	assertHTTPPolicyRuntimeStatus(t, crossTenant, http.StatusNotFound)
	assertHTTPPolicyReviewerFacts(t, fixture.pool, before)

	t.Run("empty required arrays publication preview", func(t *testing.T) {
		fixture := newHTTPPolicyRuntimeFixture(t, "read committed")
		config := validTestConfig()
		config.RequestHeaders = []HeaderAction{}
		config.ResponseHeaders = []HeaderAction{}
		config.Rewrites = []RewriteRule{}
		config.RedirectAllowedHosts = []string{}
		config.Redirects = []RedirectRule{}

		createdResponse := fixture.request(http.MethodPost, collectionPath(fixture.proof.fixture.tenantA),
			createPayload(fixture.proof.fixture.siteA, config, true), fixture.ownerToken, "runtime-empty-arrays", "")
		assertHTTPPolicyRuntimeStatus(t, createdResponse, http.StatusCreated)
		created := decodeHTTPPolicyRuntime[Policy](t, createdResponse)
		if created.RequestHeaders == nil || created.ResponseHeaders == nil || created.Rewrites == nil ||
			created.RedirectAllowedHosts == nil || created.Redirects == nil {
			t.Fatalf("created policy required arrays contain nil: %#v", created)
		}

		previewResponse := fixture.request(http.MethodGet,
			collectionPath(fixture.proof.fixture.tenantA)+"/publication-preview", nil, fixture.ownerToken, "", "")
		assertHTTPPolicyRuntimeStatus(t, previewResponse, http.StatusOK)
		encoded := previewResponse.Body.String()
		preview := decodeHTTPPolicyRuntime[PublicationPreview](t, previewResponse)
		if len(preview.Snapshot.Sites) != 1 {
			t.Fatalf("publication preview sites = %#v", preview.Snapshot.Sites)
		}
		site := preview.Snapshot.Sites[0]
		if site.RequestHeaders == nil || site.ResponseHeaders == nil || site.Rewrites == nil ||
			site.RedirectAllowedHosts == nil || site.Redirects == nil {
			t.Fatalf("publication preview required arrays contain nil: %#v", site)
		}
		for _, field := range []string{
			"request_headers", "response_headers", "rewrites", "redirect_allowed_hosts", "redirects",
		} {
			if strings.Contains(encoded, fmt.Sprintf("%q:null", field)) ||
				!strings.Contains(encoded, fmt.Sprintf("%q:[]", field)) {
				t.Fatalf("publication preview field %s is not an empty array: %s", field, encoded)
			}
		}
	})
}

func TestHTTPPolicyRuntimeCurrentHeadListByteBudgetPagination(t *testing.T) {
	fixture := newHTTPPolicyRuntimeFixture(t, "read committed")
	assertHTTPPolicyCurrentHead(t, fixture.pool)
	runtimeHandler, ok := fixture.handler.(*Handler)
	if !ok {
		t.Fatalf("runtime handler type = %T, want *Handler", fixture.handler)
	}
	authenticationRequest := httptest.NewRequest(http.MethodGet, "/", nil)
	authenticationRequest.Header.Set("Authorization", "Bearer "+fixture.ownerToken)
	actor, err := runtimeHandler.authenticator.Authenticate(authenticationRequest)
	if err != nil {
		t.Fatal(err)
	}
	sites := []uuid.UUID{
		fixture.proof.fixture.siteA,
		insertTestSite(t, fixture.pool, fixture.proof.fixture.tenantA,
			fixture.proof.fixture.ownerA.UserID, "list-budget-two.example.test"),
		insertTestSite(t, fixture.pool, fixture.proof.fixture.tenantA,
			fixture.proof.fixture.ownerA.UserID, "list-budget-three.example.test"),
	}
	config := maxSizedListTestConfig(t)
	created := make(map[uuid.UUID]struct{}, len(sites))
	all := ListResult{Items: make([]Policy, 0, len(sites))}
	for index, siteID := range sites {
		result, err := runtimeHandler.service.Create(t.Context(), actor, CreateRequest{
			TargetScopeID: fixture.proof.fixture.tenantA, SiteID: siteID, Enabled: false,
			Config: config, WriteMetadata: testMetadata(fmt.Sprintf("runtime-list-budget-%d", index)),
		})
		if err != nil {
			t.Fatalf("create large policy %d: %v", index, err)
		}
		created[result.Policy.ID] = struct{}{}
		all.Items = append(all.Items, result.Policy)
	}
	if encoded, err := json.Marshal(all); err != nil || len(encoded)+1 <= maxResponseBytes {
		t.Fatalf("unpaginated runtime list bytes=%d error=%v, want over %d", len(encoded)+1, err, maxResponseBytes)
	}

	seen := make(map[uuid.UUID]struct{}, len(created))
	cursor := ""
	pages := 0
	for len(seen) < len(created) {
		path := collectionPath(fixture.proof.fixture.tenantA) + "?limit=100"
		if cursor != "" {
			path += "&cursor=" + cursor
		}
		response := fixture.request(http.MethodGet, path, nil, fixture.ownerToken, "", "")
		assertHTTPPolicyRuntimeStatus(t, response, http.StatusOK)
		if response.Body.Len() > maxResponseBytes {
			t.Fatalf("page %d bytes=%d, max=%d", pages, response.Body.Len(), maxResponseBytes)
		}
		page := decodeHTTPPolicyRuntime[ListResult](t, response)
		if len(page.Items) != 1 {
			t.Fatalf("page %d emitted %d maximum policies, want 1", pages, len(page.Items))
		}
		for _, item := range page.Items {
			if _, expected := created[item.ID]; !expected {
				t.Fatalf("unexpected policy %s", item.ID)
			}
			if _, duplicate := seen[item.ID]; duplicate {
				t.Fatalf("duplicate policy %s", item.ID)
			}
			seen[item.ID] = struct{}{}
		}
		pages++
		if len(seen) < len(created) {
			if page.NextCursor == "" {
				t.Fatalf("page %d omitted next cursor", pages-1)
			}
			decoded, err := decodeCursor(page.NextCursor)
			last := page.Items[len(page.Items)-1]
			if err != nil || decoded.ID != last.ID || !decoded.CreatedAt.Equal(last.CreatedAt) {
				t.Fatalf("page %d cursor=%#v error=%v last=%s/%s", pages-1, decoded, err, last.CreatedAt, last.ID)
			}
		} else if page.NextCursor != "" {
			t.Fatalf("final page cursor=%q, want empty", page.NextCursor)
		}
		cursor = page.NextCursor
	}
	if pages < 2 || len(seen) != len(created) {
		t.Fatalf("pages=%d unique policies=%d want=%d", pages, len(seen), len(created))
	}
}

func TestHTTPPolicyRuntimeCurrentHeadIAMGlobalLockIsFirst(t *testing.T) {
	for _, operationName := range []string{"create", "update", "enable", "disable", "delete", "get", "list", "publication_preview"} {
		t.Run(operationName, func(t *testing.T) {
			fixture := newHTTPPolicyRuntimeFixture(t, "read committed")
			operation := prepareHTTPPolicyRuntimeOperation(t, fixture, operationName)
			holder, err := fixture.pool.Begin(t.Context())
			if err != nil {
				t.Fatal(err)
			}
			defer holder.Rollback(t.Context())
			if _, err := holder.Exec(t.Context(), "LOCK TABLE "+operation.relation+" IN ACCESS EXCLUSIVE MODE"); err != nil {
				t.Fatal(err)
			}
			response := make(chan *httptest.ResponseRecorder, 1)
			go func() { response <- operation.invoke("first-lock-" + operation.name) }()
			backendPID := waitForHTTPPolicyRuntimeBusinessWaiter(t, fixture.pool, operation.relation)
			assertNoHTTPPolicyBusinessLocks(t, fixture.pool, backendPID)
			if err := holder.Rollback(t.Context()); err != nil {
				t.Fatal(err)
			}
			assertHTTPPolicyRuntimeStatus(t, receiveHTTPPolicyRuntimeResponse(t, response), operation.wantStatus)
		})
	}
}

func TestHTTPPolicyRuntimeCurrentHeadRevocationFirst(t *testing.T) {
	for _, isolation := range []string{"repeatable read", "serializable"} {
		for _, revocation := range httpPolicyTenantSessionRevocations {
			for _, replay := range []bool{false, true} {
				name := strings.ReplaceAll(isolation, " ", "_") + "/" + revocation + "/replay_" + strconv.FormatBool(replay)
				t.Run(name, func(t *testing.T) {
					fixture := newHTTPPolicyRuntimeFixture(t, isolation)
					key := "revocation-first-" + revocation + "-" + strconv.FormatBool(replay)
					payload := createPayload(fixture.proof.fixture.siteA, validTestConfig(), true)
					if replay {
						assertHTTPPolicyRuntimeStatus(t, fixture.request(http.MethodPost,
							collectionPath(fixture.proof.fixture.tenantA), payload, fixture.ownerToken, key, ""), http.StatusCreated)
					}
					before := readHTTPPolicyReviewerFacts(t, fixture.pool)
					revocationTx, err := fixture.pool.Begin(t.Context())
					if err != nil {
						t.Fatal(err)
					}
					defer revocationTx.Rollback(t.Context())
					if err := applyHTTPPolicyRuntimeRevocation(t.Context(), revocationTx, fixture, revocation); err != nil {
						t.Fatal(err)
					}
					response := make(chan *httptest.ResponseRecorder, 1)
					go func() {
						response <- fixture.request(http.MethodPost, collectionPath(fixture.proof.fixture.tenantA),
							payload, fixture.ownerToken, key, "")
					}()
					waitForHTTPPolicyRuntimeSharedWaiter(t, fixture.pool, false)
					if err := revocationTx.Commit(t.Context()); err != nil {
						t.Fatal(err)
					}
					denied := receiveHTTPPolicyRuntimeResponse(t, response)
					assertHTTPPolicyRuntimeDenied(t, denied)
					assertHTTPPolicyReviewerFacts(t, fixture.pool, before)
				})
			}
		}
	}
}

func TestHTTPPolicyRuntimeCurrentHeadBusinessFirst(t *testing.T) {
	for _, isolation := range []string{"repeatable read", "serializable"} {
		for _, revocation := range httpPolicyTenantSessionRevocations {
			for _, replay := range []bool{false, true} {
				name := strings.ReplaceAll(isolation, " ", "_") + "/" + revocation + "/replay_" + strconv.FormatBool(replay)
				t.Run(name, func(t *testing.T) {
					fixture := newHTTPPolicyRuntimeFixture(t, isolation)
					key := "business-first-" + revocation + "-" + strconv.FormatBool(replay)
					payload := createPayload(fixture.proof.fixture.siteA, validTestConfig(), true)
					if replay {
						assertHTTPPolicyRuntimeStatus(t, fixture.request(http.MethodPost,
							collectionPath(fixture.proof.fixture.tenantA), payload, fixture.ownerToken, key, ""), http.StatusCreated)
					}
					holder, err := fixture.pool.Begin(t.Context())
					if err != nil {
						t.Fatal(err)
					}
					defer holder.Rollback(t.Context())
					if _, err := holder.Exec(t.Context(), "LOCK TABLE sites IN ACCESS EXCLUSIVE MODE"); err != nil {
						t.Fatal(err)
					}
					response := make(chan *httptest.ResponseRecorder, 1)
					go func() {
						response <- fixture.request(http.MethodPost, collectionPath(fixture.proof.fixture.tenantA),
							payload, fixture.ownerToken, key, "")
					}()
					waitForHTTPPolicyRuntimeBusinessWaiter(t, fixture.pool, "sites")
					revoked := make(chan error, 1)
					go func() {
						revoked <- pgx.BeginFunc(t.Context(), fixture.pool, func(tx pgx.Tx) error {
							return applyHTTPPolicyRuntimeRevocation(t.Context(), tx, fixture, revocation)
						})
					}()
					waitForHTTPPolicyRuntimeSharedWaiter(t, fixture.pool, true)
					if err := holder.Rollback(t.Context()); err != nil {
						t.Fatal(err)
					}
					succeeded := receiveHTTPPolicyRuntimeResponse(t, response)
					assertHTTPPolicyRuntimeStatus(t, succeeded, http.StatusCreated)
					if replay && succeeded.Header().Get("X-Idempotent-Replay") != "true" {
						t.Fatalf("completed replay header missing: %v", succeeded.Header())
					}
					if err := receiveHTTPPolicyRuntimeError(t, revoked); err != nil {
						t.Fatal(err)
					}
					afterSuccess := readHTTPPolicyReviewerFacts(t, fixture.pool)
					assertHTTPPolicyRuntimeDenied(t, fixture.request(http.MethodPost,
						collectionPath(fixture.proof.fixture.tenantA), payload, fixture.ownerToken, key, ""))
					assertHTTPPolicyReviewerFacts(t, fixture.pool, afterSuccess)
				})
			}
		}
	}
}

func newHTTPPolicyRuntimeFixture(t *testing.T, isolation string) *httpPolicyRuntimeFixture {
	t.Helper()
	proof := newReviewerLeaseFixture(t)
	installReviewerLease(t, proof, 1, 100)
	pool := proof.fixture.pool
	if isolation != "read committed" {
		pool = newHTTPPolicyIsolationPool(t, proof.fixture.pool, isolation)
	}
	manageRoleID := grantHTTPPolicyRuntimePermissions(t, proof.fixture)
	tokens, err := identity.NewTokenManager("http-policy-runtime-integration-secret-2026", time.Hour)
	if err != nil {
		t.Fatal(err)
	}
	identityService, err := identity.NewService(identity.NewStore(pool), tokens, 24*time.Hour)
	if err != nil {
		t.Fatal(err)
	}
	sessions, err := sessioncredential.NewVerifier(tokens, time.Now)
	if err != nil {
		t.Fatal(err)
	}
	apiKeys, err := apikeycredential.NewVerifier(bytes.Repeat([]byte{0x71}, 32), time.Now)
	if err != nil {
		t.Fatal(err)
	}
	iam, err := iamlock.NewAuthorizer(sessions, apiKeys)
	if err != nil {
		t.Fatal(err)
	}
	handler, err := NewRuntimeHandler(RuntimeConfig{Enabled: true}, RuntimeDependencies{
		Pool: pool, Identity: identityService, IAM: iam,
		EntitlementTrust: proof.trust, Now: func() time.Time { return proof.now },
	})
	if err != nil {
		t.Fatal(err)
	}
	ownerToken, _, err := tokens.Mint(proof.fixture.ownerA.UserID, proof.fixture.ownerA.ScopeID,
		proof.fixture.ownerA.Credential.ID)
	if err != nil {
		t.Fatal(err)
	}
	platformToken, _, err := tokens.Mint(proof.fixture.legacyPlatform.UserID, proof.fixture.legacyPlatform.ScopeID,
		proof.fixture.legacyPlatform.Credential.ID)
	if err != nil {
		t.Fatal(err)
	}
	return &httpPolicyRuntimeFixture{
		proof: proof, pool: pool, handler: handler, ownerToken: ownerToken,
		platformToken: platformToken, manageRoleID: manageRoleID,
	}
}

func assertHTTPPolicyCurrentHead(t *testing.T, pool *pgxpool.Pool) {
	t.Helper()
	var first, head, count int
	if err := pool.QueryRow(t.Context(), `SELECT min(version),max(version),count(*) FROM schema_migrations`).
		Scan(&first, &head, &count); err != nil {
		t.Fatal(err)
	}
	want := httpPolicyReleaseHead(t)
	if first != 1 || head != want || count != want {
		t.Fatalf("migration ledger first=%d head=%d count=%d, want continuous 001..%03d", first, head, count, want)
	}
}

func grantHTTPPolicyRuntimePermissions(t *testing.T, fixture *integrationFixture) uuid.UUID {
	t.Helper()
	roleID := uuid.New()
	grantID := uuid.New()
	now := httpPolicyTestBase.Add(9 * time.Minute)
	if err := pgx.BeginFunc(t.Context(), fixture.pool, func(tx pgx.Tx) error {
		if err := iamlock.AcquireExclusive(t.Context(), tx); err != nil {
			return err
		}
		if _, err := iamlock.AcquireScopes(t.Context(), tx, []uuid.UUID{fixture.ownerA.ScopeID}); err != nil {
			return err
		}
		if _, err := tx.Exec(t.Context(), `INSERT INTO role_assignments(scope_id,user_id,role_id)
			SELECT $1,$2,id FROM roles WHERE scope_id=$1 AND name='tenant_owner' AND system_role
			ON CONFLICT DO NOTHING`, fixture.ownerA.ScopeID, fixture.memberA.UserID); err != nil {
			return err
		}
		if _, err := tx.Exec(t.Context(), `DELETE FROM role_assignments WHERE scope_id=$1 AND user_id=$2`,
			fixture.ownerA.ScopeID, fixture.ownerA.UserID); err != nil {
			return err
		}
		var tenantID uuid.UUID
		if err := tx.QueryRow(t.Context(), `SELECT tenant_id FROM access_scopes
			WHERE id=$1 AND kind='tenant'`, fixture.ownerA.ScopeID).Scan(&tenantID); err != nil {
			return err
		}
		name := "http_policy_runtime_" + strings.ReplaceAll(roleID.String(), "-", "")
		if _, err := tx.Exec(t.Context(), `INSERT INTO custom_roles(
			id,tenant_id,tenant_scope_id,current_revision,current_name,created_by_user_id,
			created_by_scope_id,created_at,updated_at
		) VALUES($1,$2,$3,0,$4,$5,$3,$6,$6)`, roleID, tenantID, fixture.ownerA.ScopeID,
			name, fixture.memberA.UserID, now); err != nil {
			return err
		}
		if _, err := tx.Exec(t.Context(), `INSERT INTO custom_role_revisions(
			role_id,tenant_id,tenant_scope_id,revision,name,permissions,action,
			created_by_user_id,created_by_scope_id,created_at
		) VALUES($1,$2,$3,1,$4,$5,'identity.custom_role.create',$6,$3,$7)`,
			roleID, tenantID, fixture.ownerA.ScopeID, name,
			[]string{PermissionManage, PermissionRead}, fixture.memberA.UserID, now); err != nil {
			return err
		}
		if _, err := tx.Exec(t.Context(), `UPDATE custom_roles SET current_revision=1,updated_at=$2
			WHERE id=$1 AND current_revision=0`, roleID, now); err != nil {
			return err
		}
		if _, err := tx.Exec(t.Context(), `INSERT INTO custom_role_grants(
			id,tenant_id,tenant_scope_id,role_id,role_revision,subject_user_id,
			granted_by_user_id,granted_by_scope_id,granted_at
		) VALUES($1,$2,$3,$4,1,$5,$6,$3,$7)`, grantID, tenantID, fixture.ownerA.ScopeID,
			roleID, fixture.ownerA.UserID, fixture.memberA.UserID, now); err != nil {
			return err
		}
		return nil
	}); err != nil {
		t.Fatal(err)
	}
	return roleID
}

func prepareHTTPPolicyRuntimeOperation(
	t *testing.T,
	fixture *httpPolicyRuntimeFixture,
	name string,
) httpPolicyRuntimeOperation {
	t.Helper()
	collection := collectionPath(fixture.proof.fixture.tenantA)
	if name == "create" {
		return httpPolicyRuntimeOperation{name: name, relation: "sites", wantStatus: http.StatusCreated,
			invoke: func(key string) *httptest.ResponseRecorder {
				return fixture.request(http.MethodPost, collection,
					createPayload(fixture.proof.fixture.siteA, validTestConfig(), true), fixture.ownerToken, key, "")
			}}
	}
	seed := fixture.request(http.MethodPost, collection,
		createPayload(fixture.proof.fixture.siteA, validTestConfig(), name != "enable"),
		fixture.ownerToken, "first-lock-seed-"+name, "")
	assertHTTPPolicyRuntimeStatus(t, seed, http.StatusCreated)
	policy := decodeHTTPPolicyRuntime[Policy](t, seed)
	item := itemPath(fixture.proof.fixture.tenantA, policy.ID)
	switch name {
	case "update":
		return httpPolicyRuntimeOperation{name: name, relation: "http_policies", wantStatus: http.StatusOK,
			invoke: func(key string) *httptest.ResponseRecorder {
				return fixture.request(http.MethodPatch, item, map[string]any{"config": validTestConfig()},
					fixture.ownerToken, key, quoteRevision(policy.Revision))
			}}
	case "enable", "disable":
		return httpPolicyRuntimeOperation{name: name, relation: "http_policies", wantStatus: http.StatusOK,
			invoke: func(key string) *httptest.ResponseRecorder {
				return fixture.request(http.MethodPost, item+"/"+name, map[string]any{},
					fixture.ownerToken, key, quoteRevision(policy.Revision))
			}}
	case "delete":
		return httpPolicyRuntimeOperation{name: name, relation: "http_policies", wantStatus: http.StatusOK,
			invoke: func(key string) *httptest.ResponseRecorder {
				return fixture.request(http.MethodDelete, item, nil, fixture.ownerToken, key, quoteRevision(policy.Revision))
			}}
	case "get":
		return httpPolicyRuntimeOperation{name: name, relation: "http_policies", wantStatus: http.StatusOK,
			invoke: func(string) *httptest.ResponseRecorder {
				return fixture.request(http.MethodGet, item, nil, fixture.ownerToken, "", "")
			}}
	case "list":
		return httpPolicyRuntimeOperation{name: name, relation: "http_policies", wantStatus: http.StatusOK,
			invoke: func(string) *httptest.ResponseRecorder {
				return fixture.request(http.MethodGet, collection, nil, fixture.ownerToken, "", "")
			}}
	case "publication_preview":
		return httpPolicyRuntimeOperation{name: name, relation: "http_policy_publication_heads", wantStatus: http.StatusOK,
			invoke: func(string) *httptest.ResponseRecorder {
				return fixture.request(http.MethodGet, collection+"/publication-preview", nil, fixture.ownerToken, "", "")
			}}
	default:
		t.Fatalf("unknown runtime operation %q", name)
		return httpPolicyRuntimeOperation{}
	}
}

func applyHTTPPolicyRuntimeRevocation(
	ctx context.Context,
	tx pgx.Tx,
	fixture *httpPolicyRuntimeFixture,
	revocation string,
) error {
	if err := iamlock.AcquireExclusive(ctx, tx); err != nil {
		return err
	}
	if _, err := iamlock.AcquireScopes(ctx, tx, []uuid.UUID{fixture.proof.fixture.ownerA.ScopeID}); err != nil {
		return err
	}
	actor := fixture.proof.fixture.ownerA
	switch revocation {
	case "session":
		_, err := tx.Exec(ctx, `UPDATE auth_sessions SET revoked_at=now(),revocation_reason='runtime adoption test'
			WHERE id=$1`, actor.Credential.ID)
		return err
	case "account":
		_, err := tx.Exec(ctx, `UPDATE users SET status='disabled' WHERE id=$1`, actor.UserID)
		return err
	case "membership":
		_, err := tx.Exec(ctx, `UPDATE memberships SET status='suspended' WHERE scope_id=$1 AND user_id=$2`,
			actor.ScopeID, actor.UserID)
		return err
	case "assignment":
		command, err := tx.Exec(ctx, `INSERT INTO custom_role_grant_revocations(
			id,grant_id,tenant_id,tenant_scope_id,role_id,role_revision,subject_user_id,
			revoked_by_user_id,revoked_by_scope_id,revoked_at
		) SELECT $1,grant_row.id,grant_row.tenant_id,grant_row.tenant_scope_id,grant_row.role_id,
			grant_row.role_revision,grant_row.subject_user_id,$2,grant_row.tenant_scope_id,$3
			FROM custom_role_grants grant_row
			WHERE grant_row.role_id=$4 AND grant_row.subject_user_id=$5`, uuid.New(),
			fixture.proof.fixture.memberA.UserID, fixture.proof.now.Add(time.Second),
			fixture.manageRoleID, actor.UserID)
		if err != nil {
			return err
		}
		if command.RowsAffected() != 1 {
			return fmt.Errorf("revoke runtime custom role grant rows=%d", command.RowsAffected())
		}
		return nil
	case "role_permission":
		command, err := tx.Exec(ctx, `INSERT INTO custom_role_revisions(
			role_id,tenant_id,tenant_scope_id,revision,name,permissions,action,
			created_by_user_id,created_by_scope_id,created_at
		) SELECT id,tenant_id,tenant_scope_id,2,current_name,ARRAY[$1]::text[],
			'identity.custom_role.publish',$2,tenant_scope_id,$3
			FROM custom_roles WHERE id=$4 AND current_revision=1`, PermissionRead,
			fixture.proof.fixture.memberA.UserID, fixture.proof.now.Add(time.Second), fixture.manageRoleID)
		if err != nil {
			return err
		}
		if command.RowsAffected() != 1 {
			return fmt.Errorf("publish runtime custom role rows=%d", command.RowsAffected())
		}
		command, err = tx.Exec(ctx, `UPDATE custom_roles SET current_revision=2,updated_at=$2
			WHERE id=$1 AND current_revision=1`, fixture.manageRoleID, fixture.proof.now.Add(time.Second))
		if err != nil {
			return err
		}
		if command.RowsAffected() != 1 {
			return fmt.Errorf("project runtime custom role rows=%d", command.RowsAffected())
		}
		return nil
	default:
		return fmt.Errorf("unknown runtime revocation %q", revocation)
	}
}

func (fixture *httpPolicyRuntimeFixture) request(
	method, path string,
	body any,
	token, key, revision string,
) *httptest.ResponseRecorder {
	var payload []byte
	if body != nil {
		var err error
		payload, err = json.Marshal(body)
		if err != nil {
			panic(err)
		}
	}
	request := httptest.NewRequest(method, path, bytes.NewReader(payload))
	request.Header.Set("Authorization", "Bearer "+token)
	request.Header.Set("X-Request-ID", "runtime-"+firstNonEmpty(key, "read")+"-request")
	request.Header.Set("X-Trace-ID", "runtime-"+firstNonEmpty(key, "read")+"-trace")
	if body != nil {
		request.Header.Set("Content-Type", "application/json")
	}
	if key != "" {
		request.Header.Set("Idempotency-Key", key)
	}
	if revision != "" {
		request.Header.Set("If-Match", revision)
	}
	response := httptest.NewRecorder()
	fixture.handler.ServeHTTP(response, request)
	return response
}

func firstNonEmpty(value, fallback string) string {
	if value != "" {
		return value
	}
	return fallback
}

func decodeHTTPPolicyRuntime[T any](t *testing.T, response *httptest.ResponseRecorder) T {
	t.Helper()
	var value T
	decoder := json.NewDecoder(response.Body)
	decoder.DisallowUnknownFields()
	if err := decoder.Decode(&value); err != nil {
		t.Fatalf("decode runtime response status=%d: %v body=%s", response.Code, err, response.Body)
	}
	return value
}

func assertHTTPPolicyRuntimeStatus(t *testing.T, response *httptest.ResponseRecorder, status int) {
	t.Helper()
	if response.Code != status {
		t.Fatalf("runtime status=%d want=%d body=%s", response.Code, status, response.Body)
	}
	if response.Header().Get("X-Request-ID") == "" || response.Header().Get("X-Trace-ID") == "" {
		t.Fatalf("runtime response lacks correlation headers: %v", response.Header())
	}
}

func assertHTTPPolicyRuntimeDenied(t *testing.T, response *httptest.ResponseRecorder) {
	t.Helper()
	if response.Code != http.StatusUnauthorized && response.Code != http.StatusForbidden &&
		response.Code != http.StatusServiceUnavailable {
		t.Fatalf("runtime denial status=%d body=%s", response.Code, response.Body)
	}
	for _, leaked := range []string{"SQLSTATE", "40001", "40P01", "55P03"} {
		if strings.Contains(response.Body.String(), leaked) {
			t.Fatalf("runtime denial leaked %q: %s", leaked, response.Body)
		}
	}
}

func waitForHTTPPolicyRuntimeBusinessWaiter(t *testing.T, pool *pgxpool.Pool, relation string) int {
	t.Helper()
	deadline := time.Now().Add(10 * time.Second)
	for time.Now().Before(deadline) {
		var backendPID int
		err := pool.QueryRow(t.Context(), `SELECT advisory.pid
			FROM pg_catalog.pg_locks advisory
			JOIN pg_catalog.pg_locks business ON business.pid=advisory.pid
			WHERE advisory.locktype='advisory' AND advisory.classid=1229016321::oid
			  AND advisory.objid=1::oid AND advisory.objsubid=2
			  AND advisory.mode='ShareLock' AND advisory.granted
			  AND business.relation=pg_catalog.to_regclass($1) AND NOT business.granted
			ORDER BY advisory.pid LIMIT 1`, relation).Scan(&backendPID)
		if err == nil {
			return backendPID
		}
		if !errors.Is(err, pgx.ErrNoRows) {
			t.Fatal(err)
		}
		time.Sleep(5 * time.Millisecond)
	}
	t.Fatalf("runtime request did not reach blocked business relation %s", relation)
	return 0
}

func waitForHTTPPolicyRuntimeSharedWaiter(t *testing.T, pool *pgxpool.Pool, exclusive bool) {
	t.Helper()
	mode := "ShareLock"
	if exclusive {
		mode = "ExclusiveLock"
	}
	deadline := time.Now().Add(10 * time.Second)
	for time.Now().Before(deadline) {
		var waiting bool
		if err := pool.QueryRow(t.Context(), `SELECT EXISTS(
			SELECT 1 FROM pg_catalog.pg_locks
			WHERE locktype='advisory' AND classid=1229016321::oid AND objid=1::oid AND objsubid=2
			  AND mode=$1 AND NOT granted)`, mode).Scan(&waiting); err != nil {
			t.Fatal(err)
		}
		if waiting {
			return
		}
		time.Sleep(5 * time.Millisecond)
	}
	t.Fatalf("runtime %s IAM waiter not observed", mode)
}

func receiveHTTPPolicyRuntimeResponse(
	t *testing.T,
	responses <-chan *httptest.ResponseRecorder,
) *httptest.ResponseRecorder {
	t.Helper()
	select {
	case response := <-responses:
		return response
	case <-time.After(10 * time.Second):
		t.Fatal("runtime response timed out")
		return nil
	}
}

func receiveHTTPPolicyRuntimeError(t *testing.T, errorsChannel <-chan error) error {
	t.Helper()
	select {
	case err := <-errorsChannel:
		return err
	case <-time.After(10 * time.Second):
		t.Fatal("runtime revocation timed out")
		return nil
	}
}

// httpPolicyReleaseHead is the highest embedded migration version.
func httpPolicyReleaseHead(t *testing.T) int {
	t.Helper()
	entries, err := iofs.ReadDir(controlmigrations.FS, ".")
	if err != nil {
		t.Fatal(err)
	}
	head := 0
	for _, entry := range entries {
		name := entry.Name()
		if entry.IsDir() || !strings.HasSuffix(name, ".up.sql") {
			continue
		}
		version, err := strconv.Atoi(name[:strings.IndexByte(name, '_')])
		if err != nil {
			t.Fatal(err)
		}
		head = max(head, version)
	}
	return head
}
