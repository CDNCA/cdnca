package httpapi

import (
	"bytes"
	"context"
	"net/http"
	"net/http/httptest"
	"net/url"
	"strings"
	"testing"
	"time"

	"github.com/cdnca/cdnca/services/control-api/internal/database/databasetest"
	"github.com/cdnca/cdnca/services/control-api/internal/identity"
	"github.com/cdnca/cdnca/services/control-api/internal/jobhttp"
	"github.com/cdnca/cdnca/services/control-api/internal/jobstate"
	"github.com/google/uuid"
	"github.com/jackc/pgx/v5/pgxpool"
)

func TestJobQueryRuntimeRBACCursorRotationAndChildRoutes(t *testing.T) {
	pool := isolatedTestPool(t)
	passwordHash, err := identity.HashPassword(testPassword)
	if err != nil {
		t.Fatal(err)
	}
	identityStore := identity.NewStore(pool)
	_, err = identityStore.BootstrapPlatformUser(
		context.Background(), "job-runtime-admin", "Job Runtime Admin", passwordHash, "job-runtime-bootstrap",
	)
	if err != nil {
		t.Fatal(err)
	}
	tokens, err := identity.NewTokenManager("job-runtime-secret-at-least-thirty-two-bytes", 5*time.Minute)
	if err != nil {
		t.Fatal(err)
	}
	identityService, err := identity.NewService(identityStore, tokens, 24*time.Hour)
	if err != nil {
		t.Fatal(err)
	}
	reader, err := jobhttp.NewPostgresReader(pool)
	if err != nil {
		t.Fatal(err)
	}

	oldKey := bytes.Repeat([]byte{0x57}, 32)
	oldServer := newJobQueryRuntimeServer(t, pool, identityService, reader, "old", map[string][]byte{"old": oldKey})
	client := oldServer.Client()
	adminAuth, _ := loginWithPassword(t, client, oldServer.URL, "job-runtime-admin", testPassword)
	tenantUser := createManagedUser(t, client, oldServer.URL, adminAuth.AccessToken, "job-runtime-create-tenant", map[string]any{
		"username": "job-runtime-tenant", "password": tenantPassword, "display_name": "Job Runtime Tenant",
		"email": nil, "phone": nil, "role": identity.UserRoleOwner,
	})
	tenantAuth, _ := loginWithPassword(t, client, oldServer.URL, tenantUser.Username, tenantPassword)
	if tenantAuth.Principal.TenantID == nil {
		t.Fatal("tenant principal is missing tenant ID")
	}

	now := time.Now().UTC().Truncate(time.Microsecond)
	store, err := jobstate.NewStore(pool, func() time.Time { return now })
	if err != nil {
		t.Fatal(err)
	}
	completedJob := createHTTPJob(t, store, *tenantAuth.Principal.TenantID, "cache.purge", "site/runtime-old")
	claims, err := store.Claim(t.Context(), jobstate.ClaimInput{
		TenantID: *tenantAuth.Principal.TenantID, Kind: "cache.purge", WorkerID: "job-runtime-worker",
		Limit: 1, LeaseDuration: 30 * time.Second,
	})
	if err != nil || len(claims) != 1 {
		t.Fatalf("claim job = %+v, err=%v", claims, err)
	}
	now = now.Add(time.Second)
	reported, err := store.Report(t.Context(), jobstate.ReportInput{
		TenantID: *tenantAuth.Principal.TenantID, JobID: completedJob.ID,
		WorkerID: claims[0].WorkerID, LeaseID: claims[0].LeaseID,
		Report: jobstate.Report{ItemID: "item-1", State: jobstate.ItemSucceeded, Attempt: 1, Sequence: 1},
	})
	if err != nil || !reported.Applied {
		t.Fatalf("report job = %+v, err=%v", reported, err)
	}
	now = now.Add(time.Second)
	newerJob := createHTTPJob(t, store, *tenantAuth.Principal.TenantID, "dns.repair", "site/runtime-new")
	window := url.Values{
		"from":  {now.Add(-time.Hour).Format(time.RFC3339)},
		"to":    {now.Add(time.Hour).Format(time.RFC3339)},
		"limit": {"1"},
	}

	first := jobQueryRequest(t, client, oldServer.URL+"/v1/admin/jobs?"+window.Encode(),
		"Bearer "+adminAuth.AccessToken, "job-runtime-first")
	var firstPage jobhttp.JobPage
	decodeResponse(t, first, http.StatusOK, &firstPage)
	first.Body.Close()
	if len(firstPage.Data) != 1 || firstPage.Data[0].TaskID != newerJob.ID || firstPage.Page.NextCursor == "" {
		t.Fatalf("first job page = %+v", firstPage)
	}

	newKey := bytes.Repeat([]byte{0x91}, 32)
	rotatedServer := newJobQueryRuntimeServer(t, pool, identityService, reader, "new", map[string][]byte{
		"old": oldKey,
		"new": newKey,
	})
	rotatedQuery := cloneValues(window)
	rotatedQuery.Set("cursor", firstPage.Page.NextCursor)
	second := jobQueryRequest(t, rotatedServer.Client(), rotatedServer.URL+"/v1/admin/jobs?"+rotatedQuery.Encode(),
		"Bearer "+adminAuth.AccessToken, "job-runtime-rotated")
	var secondPage jobhttp.JobPage
	decodeResponse(t, second, http.StatusOK, &secondPage)
	second.Body.Close()
	if len(secondPage.Data) != 1 || secondPage.Data[0].TaskID != completedJob.ID {
		t.Fatalf("rotated-key job page = %+v", secondPage)
	}

	for _, test := range []struct {
		name  string
		path  string
		check func(*testing.T, *http.Response)
	}{
		{
			name: "detail", path: "/v1/jobs/" + completedJob.ID.String(),
			check: func(t *testing.T, response *http.Response) {
				var envelope struct {
					Data jobhttp.Job `json:"data"`
				}
				decodeResponse(t, response, http.StatusOK, &envelope)
				if envelope.Data.TaskID != completedJob.ID || envelope.Data.Status != jobhttp.StateSucceeded {
					t.Fatalf("job detail = %+v", envelope.Data)
				}
			},
		},
		{
			name: "attempts", path: "/v1/jobs/" + completedJob.ID.String() + "/attempts?limit=20",
			check: func(t *testing.T, response *http.Response) {
				var page jobhttp.AttemptPage
				decodeResponse(t, response, http.StatusOK, &page)
				if len(page.Data) != 1 || page.Data[0].Number != 1 || page.Data[0].Status != jobhttp.AttemptSucceeded {
					t.Fatalf("job attempts = %+v", page)
				}
			},
		},
		{
			name: "results", path: "/v1/jobs/" + completedJob.ID.String() + "/results?limit=20",
			check: func(t *testing.T, response *http.Response) {
				var page jobhttp.ResultPage
				decodeResponse(t, response, http.StatusOK, &page)
				if len(page.Data) != 1 || page.Data[0].ItemID != "item-1" || page.Data[0].Status != jobhttp.ResultSucceeded {
					t.Fatalf("job results = %+v", page)
				}
			},
		},
	} {
		t.Run(test.name, func(t *testing.T) {
			response := jobQueryRequest(t, rotatedServer.Client(), rotatedServer.URL+test.path,
				"Bearer "+tenantAuth.AccessToken, "job-runtime-"+test.name)
			defer response.Body.Close()
			test.check(t, response)
		})
	}

	issued := createSelfAPIKey(t, rotatedServer.Client(), rotatedServer.URL, tenantAuth.AccessToken, "job-runtime-key", map[string]any{
		"name": "runtime job reader", "scopes": []string{"jobs.read"},
		"expires_at": time.Now().UTC().Add(24 * time.Hour).Format(time.RFC3339),
	})
	credential := issued.Key.KeyID + "." + issued.Secret
	withKey := jobQueryRequest(t, rotatedServer.Client(), rotatedServer.URL+"/v1/jobs/"+completedJob.ID.String(),
		"CdncaKey "+credential, "job-runtime-key-before-revoke")
	if withKey.StatusCode != http.StatusOK {
		t.Fatalf("API key before revoke status=%d body=%s", withKey.StatusCode, readBody(withKey.Body))
	}
	withKey.Body.Close()
	revoke := apiKeyRequest(t, rotatedServer.Client(), http.MethodPost,
		rotatedServer.URL+"/v1/account/api-keys/"+issued.Key.ID.String()+"/revoke", map[string]any{},
		tenantAuth.AccessToken, "", "job-runtime-revoke-key", `"1"`, "job-runtime-revoke-key")
	if revoke.StatusCode != http.StatusOK {
		t.Fatalf("revoke job API key status=%d body=%s", revoke.StatusCode, readBody(revoke.Body))
	}
	revoke.Body.Close()
	revokedKey := jobQueryRequest(t, rotatedServer.Client(), rotatedServer.URL+"/v1/jobs/"+completedJob.ID.String(),
		"CdncaKey "+credential, "job-runtime-key-after-revoke")
	assertJobError(t, revokedKey, http.StatusUnauthorized, "job_authentication_required", "job-runtime-key-after-revoke")
	revokedKey.Body.Close()

	if _, err := pool.Exec(t.Context(), `DELETE FROM role_assignments WHERE scope_id=$1 AND user_id=$2`, tenantUser.ScopeID, tenantUser.ID); err != nil {
		t.Fatalf("revoke job role assignment: %v", err)
	}
	revokedRole := jobQueryRequest(t, rotatedServer.Client(), rotatedServer.URL+"/v1/jobs/"+completedJob.ID.String(),
		"Bearer "+tenantAuth.AccessToken, "job-runtime-role-revoked")
	assertJobError(t, revokedRole, http.StatusForbidden, "job_permission_denied", "job-runtime-role-revoked")
	revokedRole.Body.Close()
	if _, err := pool.Exec(t.Context(), `
		INSERT INTO role_assignments (scope_id,user_id,role_id)
		SELECT $1,$2,id FROM roles WHERE scope_id=$1 AND name='tenant_owner'`, tenantUser.ScopeID, tenantUser.ID); err != nil {
		t.Fatalf("restore job role assignment: %v", err)
	}
	if _, err := pool.Exec(t.Context(), `UPDATE memberships SET status='suspended' WHERE scope_id=$1 AND user_id=$2`, tenantUser.ScopeID, tenantUser.ID); err != nil {
		t.Fatalf("suspend job membership: %v", err)
	}
	suspended := jobQueryRequest(t, rotatedServer.Client(), rotatedServer.URL+"/v1/jobs/"+completedJob.ID.String(),
		"Bearer "+tenantAuth.AccessToken, "job-runtime-membership-suspended")
	assertJobError(t, suspended, http.StatusUnauthorized, "job_authentication_required", "job-runtime-membership-suspended")
	suspended.Body.Close()

	failureServer := newJobQueryRuntimeServer(t, pool, identityService, &jobQueryFailureReader{}, "new", map[string][]byte{"new": newKey})
	failure := jobQueryRequest(t, failureServer.Client(), failureServer.URL+"/v1/admin/jobs?"+window.Encode(),
		"Bearer "+adminAuth.AccessToken, "job-runtime-store-failure")
	assertJobError(t, failure, http.StatusServiceUnavailable, "job_store_unavailable", "job-runtime-store-failure")
	failure.Body.Close()
	ready := jobQueryRequest(t, failureServer.Client(), failureServer.URL+"/health/ready", "", "job-runtime-ready")
	if ready.StatusCode != http.StatusOK {
		t.Fatalf("readiness after job query failure status=%d body=%s", ready.StatusCode, readBody(ready.Body))
	}
	ready.Body.Close()
}

func TestJobQueryMigration057DownUpAndGlobalPlan(t *testing.T) {
	// 发布头早已超过 057，且 268 down 是单向门：只装载 1..057 做往返。
	pool := migrationRoundTripPool(t, 57)
	assertJobQueryMigrationState(t, pool, 57, true)
	assertJobQueryGlobalPlanUsesIndex(t, pool)

	if err := databasetest.MigrateThrough(t.Context(), pool, "down", 57); err != nil {
		t.Fatalf("migrate 057 down: %v", err)
	}
	assertJobQueryMigrationState(t, pool, 56, false)

	if err := databasetest.MigrateThrough(t.Context(), pool, "up", 57); err != nil {
		t.Fatalf("migrate 057 up: %v", err)
	}
	assertJobQueryMigrationState(t, pool, 57, true)
	assertJobQueryGlobalPlanUsesIndex(t, pool)

	platformScope, tenantScope, tenantID := uuid.New(), uuid.New(), uuid.New()
	if _, err := pool.Exec(t.Context(), `INSERT INTO tenants(id,display_name) VALUES($1,'Job Query Future Tenant')`, tenantID); err != nil {
		t.Fatalf("create future job query tenant: %v", err)
	}
	if _, err := pool.Exec(t.Context(), `INSERT INTO access_scopes(id,kind) VALUES($1,'platform')`, platformScope); err != nil {
		t.Fatalf("create future platform scope: %v", err)
	}
	if _, err := pool.Exec(t.Context(), `INSERT INTO access_scopes(id,kind,tenant_id) VALUES($1,'tenant',$2)`, tenantScope, tenantID); err != nil {
		t.Fatalf("create future tenant scope: %v", err)
	}
	if _, err := pool.Exec(t.Context(), `
		INSERT INTO roles(id,scope_id,name,system_role) VALUES
			(gen_random_uuid(),$1,'platform_owner',true),
			(gen_random_uuid(),$2,'tenant_owner',true),
			(gen_random_uuid(),$2,'tenant_viewer',true)`, platformScope, tenantScope); err != nil {
		t.Fatalf("create future job query roles: %v", err)
	}
	var grants int
	if err := pool.QueryRow(t.Context(), `
		SELECT count(*) FROM role_permissions permission
		JOIN roles role ON role.id=permission.role_id
		WHERE (role.name='platform_owner' AND permission.permission_name='jobs.read_all')
		   OR (role.name IN ('tenant_owner','tenant_viewer') AND permission.permission_name='jobs.read')`).Scan(&grants); err != nil {
		t.Fatalf("count future job query grants: %v", err)
	}
	if grants != 3 {
		t.Fatalf("future job query grants=%d, want 3", grants)
	}
}

func newJobQueryRuntimeServer(
	t *testing.T,
	pool *pgxpool.Pool,
	identityService *identity.Service,
	reader jobhttp.Reader,
	activeKeyID string,
	keys map[string][]byte,
) *httptest.Server {
	t.Helper()
	api := New(pool, identityService, Config{
		APIKeyPepper:   bytes.Repeat([]byte{0x57}, 32),
		JobQueryReader: reader,
		JobQueryServiceConfig: jobhttp.ServiceConfig{
			ActiveCursorKeyID: activeKeyID,
			CursorKeys:        keys,
		},
		JobQueryHandlerConfig: jobhttp.HandlerConfig{QueryTimeout: 2 * time.Second, MaxResponseBytes: 1 << 20},
	})
	if err := api.InitializationError(); err != nil {
		t.Fatalf("initialize job query runtime: %v", err)
	}
	server := httptest.NewServer(api.Handler())
	t.Cleanup(server.Close)
	return server
}

func assertJobQueryMigrationState(t *testing.T, pool *pgxpool.Pool, wantVersion int64, wantPresent bool) {
	t.Helper()
	var version int64
	var indexPresent bool
	var permissionCount int
	if err := pool.QueryRow(t.Context(), `SELECT COALESCE(max(version),0) FROM schema_migrations`).Scan(&version); err != nil {
		t.Fatalf("read migration version: %v", err)
	}
	if err := pool.QueryRow(t.Context(), `SELECT to_regclass('background_jobs_global_created_idx') IS NOT NULL`).Scan(&indexPresent); err != nil {
		t.Fatalf("inspect job query index: %v", err)
	}
	if err := pool.QueryRow(t.Context(), `SELECT count(*) FROM permissions WHERE name IN ('jobs.read','jobs.read_all')`).Scan(&permissionCount); err != nil {
		t.Fatalf("inspect job query permissions: %v", err)
	}
	wantPermissions := 0
	if wantPresent {
		wantPermissions = 2
	}
	if version != wantVersion || indexPresent != wantPresent || permissionCount != wantPermissions {
		t.Fatalf("migration state version=%d index=%t permissions=%d", version, indexPresent, permissionCount)
	}
}

func assertJobQueryGlobalPlanUsesIndex(t *testing.T, pool *pgxpool.Pool) {
	t.Helper()
	tx, err := pool.Begin(t.Context())
	if err != nil {
		t.Fatalf("begin EXPLAIN transaction: %v", err)
	}
	defer func() { _ = tx.Rollback(t.Context()) }()
	if _, err := tx.Exec(t.Context(), `SET LOCAL enable_seqscan=off`); err != nil {
		t.Fatalf("disable sequential scan for plan proof: %v", err)
	}
	rows, err := tx.Query(t.Context(), `
		EXPLAIN (COSTS OFF)
		SELECT job.id FROM background_jobs job
		WHERE ($1::uuid IS NULL OR job.tenant_id=$1)
		  AND (cardinality($2::text[])=0 OR job.state=ANY($2))
		  AND ($3='' OR job.kind=$3) AND ($4='' OR job.subject=$4)
		  AND job.created_at >= $5 AND job.created_at < $6
		  AND ($7::timestamptz IS NULL OR ROW(job.created_at,job.id)<ROW($7,$8))
		ORDER BY job.created_at DESC,job.id DESC LIMIT $9`,
		nil, []string{}, "", "", time.Unix(0, 0).UTC(), time.Now().UTC().Add(time.Hour), nil, nil, 21)
	if err != nil {
		t.Fatalf("EXPLAIN global job list: %v", err)
	}
	defer rows.Close()
	var plan []string
	for rows.Next() {
		var line string
		if err := rows.Scan(&line); err != nil {
			t.Fatalf("scan EXPLAIN plan: %v", err)
		}
		plan = append(plan, line)
	}
	if err := rows.Err(); err != nil {
		t.Fatalf("read EXPLAIN plan: %v", err)
	}
	if joined := strings.Join(plan, "\n"); !strings.Contains(joined, "background_jobs_global_created_idx") {
		t.Fatalf("global job list did not use 057 index:\n%s", joined)
	}
}
