package httpapi

import (
	"bytes"
	"context"
	"errors"
	"net/http"
	"net/http/httptest"
	"net/url"
	"testing"
	"time"

	"github.com/cdnca/cdnca/services/control-api/internal/apikeycredential"
	"github.com/cdnca/cdnca/services/control-api/internal/iamlock"
	"github.com/cdnca/cdnca/services/control-api/internal/identity"
	"github.com/cdnca/cdnca/services/control-api/internal/jobhttp"
	"github.com/cdnca/cdnca/services/control-api/internal/jobstate"
	"github.com/cdnca/cdnca/services/control-api/internal/sessioncredential"
	"github.com/google/uuid"
)

func TestJobRoutesAreAbsentWhenDisabled(t *testing.T) {
	for _, path := range []string{"/v1/admin/jobs", "/v1/admin/jobs/example", "/v1/jobs", "/v1/jobs/example"} {
		request := httptest.NewRequest(http.MethodGet, path, nil)
		response := httptest.NewRecorder()
		New(nil, nil, Config{}).Handler().ServeHTTP(response, request)
		if response.Code != http.StatusNotFound {
			t.Fatalf("disabled job route %s status=%d, want 404", path, response.Code)
		}
		if response.Header().Get("X-Request-ID") == "" {
			t.Fatalf("disabled job route %s did not pass through request ID middleware", path)
		}
	}
}

func TestJobHandlerInitializationFailureIsReported(t *testing.T) {
	api := New(nil, nil, Config{
		JobQueryReader: &jobQueryFailureReader{},
		JobQueryServiceConfig: jobhttp.ServiceConfig{
			ActiveCursorKeyID: "active", CursorKeys: map[string][]byte{"active": []byte("short")},
		},
	})
	if err := api.InitializationError(); err == nil {
		t.Fatal("invalid job query keyset was accepted")
	}
}

func TestJobQueryHTTPFlow(t *testing.T) {
	pool := isolatedTestPool(t)
	passwordHash, err := identity.HashPassword(testPassword)
	if err != nil {
		t.Fatal(err)
	}
	identityStore := identity.NewStore(pool)
	bootstrap, err := identityStore.BootstrapPlatformUser(
		context.Background(), "jobs-admin", "Jobs Admin", passwordHash, "jobs-bootstrap",
	)
	if err != nil {
		t.Fatal(err)
	}
	insertTestUser(t, pool, bootstrap.ScopeID, "jobs-no-role", "Jobs No Role", passwordHash, "active")
	tokens, err := identity.NewTokenManager("jobs-integration-secret-at-least-thirty-two-bytes", 5*time.Minute)
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
	// API-JOBS-02：命令事务内复核 API 密钥；pepper 与下方 Config.APIKeyPepper 一致。
	jobSessions, err := sessioncredential.NewVerifier(tokens, time.Now)
	if err != nil {
		t.Fatal(err)
	}
	jobAPIKeys, err := apikeycredential.NewVerifier(bytes.Repeat([]byte{0x57}, 32), time.Now)
	if err != nil {
		t.Fatal(err)
	}
	jobIAM, err := iamlock.NewAuthorizer(jobSessions, jobAPIKeys)
	if err != nil {
		t.Fatal(err)
	}
	if err := reader.UseIAM(jobIAM); err != nil {
		t.Fatal(err)
	}
	api := New(pool, identityService, Config{
		CookieSecure:   false,
		APIKeyPepper:   bytes.Repeat([]byte{0x57}, 32),
		JobQueryReader: reader,
		JobQueryServiceConfig: jobhttp.ServiceConfig{
			ActiveCursorKeyID: "jobs-v1",
			CursorKeys:        map[string][]byte{"jobs-v1": bytes.Repeat([]byte{0x91}, 32)},
		},
		JobQueryHandlerConfig: jobhttp.HandlerConfig{
			QueryTimeout: 2 * time.Second, MaxResponseBytes: 1 << 20,
		},
	})
	if err := api.InitializationError(); err != nil {
		t.Fatalf("initialize job query HTTP API: %v", err)
	}
	server := httptest.NewServer(api.Handler())
	t.Cleanup(server.Close)
	client := server.Client()

	adminAuth, _ := loginWithPassword(t, client, server.URL, "jobs-admin", testPassword)
	noRoleAuth, _ := loginWithPassword(t, client, server.URL, "jobs-no-role", testPassword)
	tenantAUser := createManagedUser(t, client, server.URL, adminAuth.AccessToken, "jobs-create-a", map[string]any{
		"username": "jobs-tenant-a", "password": tenantPassword, "display_name": "Jobs Tenant A",
		"email": nil, "phone": nil, "role": identity.UserRoleOwner,
	})
	tenantBUser := createManagedUser(t, client, server.URL, adminAuth.AccessToken, "jobs-create-b", map[string]any{
		"username": "jobs-tenant-b", "password": tenantPassword, "display_name": "Jobs Tenant B",
		"email": nil, "phone": nil, "role": identity.UserRoleOwner,
	})
	tenantAAuth, _ := loginWithPassword(t, client, server.URL, tenantAUser.Username, tenantPassword)
	tenantBAuth, _ := loginWithPassword(t, client, server.URL, tenantBUser.Username, tenantPassword)
	if tenantAAuth.Principal.TenantID == nil || tenantBAuth.Principal.TenantID == nil {
		t.Fatal("tenant principal is missing tenant ID")
	}

	now := time.Now().UTC().Truncate(time.Microsecond)
	jobStore, err := jobstate.NewStore(pool, func() time.Time { return now })
	if err != nil {
		t.Fatal(err)
	}
	jobA1 := createHTTPJob(t, jobStore, *tenantAAuth.Principal.TenantID, "cache.purge", "site/a")
	now = now.Add(time.Second)
	_ = createHTTPJob(t, jobStore, *tenantAAuth.Principal.TenantID, "dns.repair", "site/a")
	now = now.Add(time.Second)
	jobB := createHTTPJob(t, jobStore, *tenantBAuth.Principal.TenantID, "edge.publish", "site/b")
	window := url.Values{
		"from": {now.Add(-time.Hour).Format(time.RFC3339)},
		"to":   {now.Add(time.Hour).Format(time.RFC3339)},
	}

	t.Run("platform list is global and preserves request ID", func(t *testing.T) {
		query := cloneValues(window)
		query.Set("limit", "1")
		response := jobQueryRequest(t, client, server.URL+"/v1/admin/jobs?"+query.Encode(),
			"Bearer "+adminAuth.AccessToken, "jobs-platform")
		var page jobhttp.JobPage
		decodeResponse(t, response, http.StatusOK, &page)
		response.Body.Close()
		if len(page.Data) != 1 || page.Data[0].TaskID != jobB.ID || page.Page.NextCursor == "" ||
			response.Header.Get("X-Request-ID") != "jobs-platform" {
			t.Fatalf("platform job page=%+v request ID=%q", page, response.Header.Get("X-Request-ID"))
		}

		query.Set("cursor", tamperJobCursor(page.Page.NextCursor))
		tampered := jobQueryRequest(t, client, server.URL+"/v1/admin/jobs?"+query.Encode(),
			"Bearer "+adminAuth.AccessToken, "jobs-cursor-tamper")
		assertJobError(t, tampered, http.StatusBadRequest, "job_invalid_request", "jobs-cursor-tamper")
		tampered.Body.Close()
	})

	t.Run("tenant bearer and API key are scope isolated", func(t *testing.T) {
		response := jobQueryRequest(t, client, server.URL+"/v1/jobs?"+window.Encode(),
			"Bearer "+tenantAAuth.AccessToken, "jobs-tenant")
		var page jobhttp.JobPage
		decodeResponse(t, response, http.StatusOK, &page)
		response.Body.Close()
		if len(page.Data) != 2 {
			t.Fatalf("tenant A job count=%d, want 2", len(page.Data))
		}
		for _, job := range page.Data {
			if job.TenantID != *tenantAAuth.Principal.TenantID {
				t.Fatalf("tenant A received foreign job %+v", job)
			}
		}

		foreign := jobQueryRequest(t, client, server.URL+"/v1/jobs/"+jobB.ID.String(),
			"Bearer "+tenantAAuth.AccessToken, "jobs-foreign")
		assertJobError(t, foreign, http.StatusNotFound, "job_not_found", "jobs-foreign")
		foreign.Body.Close()

		issued := createSelfAPIKey(t, client, server.URL, tenantAAuth.AccessToken, "jobs-api-key", map[string]any{
			"name": "job reader", "scopes": []string{"jobs.read"},
			"expires_at": time.Now().UTC().Add(24 * time.Hour).Format(time.RFC3339),
		})
		credential := issued.Key.KeyID + "." + issued.Secret
		withKey := jobQueryRequest(t, client, server.URL+"/v1/jobs/"+jobA1.ID.String(),
			"CdncaKey "+credential, "jobs-api-key")
		defer withKey.Body.Close()
		if withKey.StatusCode != http.StatusOK {
			t.Fatalf("API key job detail status=%d body=%s", withKey.StatusCode, readBody(withKey.Body))
		}
	})

	// API-JOBS-01：所属用户（tenant_owner）有 jobs.manage，但只读密钥不得借用户角色取消/重试。
	// 待出包前全量跑（PG 集成）。
	t.Run("read-only API key cannot cancel or retry tenant job", func(t *testing.T) {
		expires := time.Now().UTC().Add(24 * time.Hour).Format(time.RFC3339)
		readOnly := createSelfAPIKey(t, client, server.URL, tenantAAuth.AccessToken, "jobs-api-key-ro", map[string]any{
			"name": "job read only", "scopes": []string{"jobs.read"}, "expires_at": expires,
		})
		readOnlyAuth := "CdncaKey " + readOnly.Key.KeyID + "." + readOnly.Secret
		detail := jobQueryRequest(t, client, server.URL+"/v1/jobs/"+jobA1.ID.String(), readOnlyAuth, "jobs-ro-detail")
		etag := detail.Header.Get("ETag")
		detail.Body.Close()
		if detail.StatusCode != http.StatusOK || etag == "" {
			t.Fatalf("read-only key detail status=%d etag=%q", detail.StatusCode, etag)
		}
		for _, operation := range []string{"cancel", "retry"} {
			requestID := "jobs-ro-" + operation
			response := jobCommandRequest(t, client, server.URL+"/v1/jobs/"+jobA1.ID.String()+"/"+operation,
				readOnlyAuth, etag, requestID)
			assertJobError(t, response, http.StatusForbidden, "job_permission_denied", requestID)
			response.Body.Close()
		}
		var status string
		var receipts int
		if err := pool.QueryRow(context.Background(), `SELECT job.state,
			(SELECT count(*) FROM background_job_command_receipts receipt WHERE receipt.job_id=job.id)
			FROM background_jobs job WHERE job.id=$1`, jobA1.ID).Scan(&status, &receipts); err != nil {
			t.Fatal(err)
		}
		if status != "queued" || receipts != 0 {
			t.Fatalf("read-only key mutated job status=%q receipts=%d", status, receipts)
		}

		manage := createSelfAPIKey(t, client, server.URL, tenantAAuth.AccessToken, "jobs-api-key-manage", map[string]any{
			"name": "job manager", "scopes": []string{"jobs.manage", "jobs.read"}, "expires_at": expires,
		})
		cancelled := jobCommandRequest(t, client, server.URL+"/v1/jobs/"+jobA1.ID.String()+"/cancel",
			"CdncaKey "+manage.Key.KeyID+"."+manage.Secret, etag, "jobs-manage-cancel")
		var result jobhttp.CommandResult
		decodeResponse(t, cancelled, http.StatusOK, &result)
		cancelled.Body.Close()
		if result.Data.TaskID != jobA1.ID || result.Data.Status != jobhttp.StateCancelled {
			t.Fatalf("manage key cancel result=%+v", result)
		}
	})

	// API-JOBS-02：认证通过后、命令事务前密钥被吊销，事务内 iamlock 复核必须拒绝（403 + denied 审计）。
	// 待出包前全量跑（PG 集成）。
	t.Run("API key revoked after authentication cannot run command", func(t *testing.T) {
		job := createHTTPJob(t, jobStore, *tenantAAuth.Principal.TenantID, "cache.purge", "site/revoke-race")
		issued := createSelfAPIKey(t, client, server.URL, tenantAAuth.AccessToken, "jobs-api-key-revoke-race", map[string]any{
			"name": "job manager revoke race", "scopes": []string{"jobs.manage", "jobs.read"},
			"expires_at": time.Now().UTC().Add(24 * time.Hour).Format(time.RFC3339),
		})
		authRequest := httptest.NewRequest(http.MethodPost, "/v1/jobs/"+job.ID.String()+"/cancel", nil)
		authRequest.Header.Set("Authorization", "CdncaKey "+issued.Key.KeyID+"."+issued.Secret)
		principal, err := api.authenticateJobQuery(authRequest)
		if err != nil || !principal.HasPermission(jobhttp.PermissionManage) {
			t.Fatalf("authenticate manage key principal=%+v err=%v", principal.Permissions, err)
		}
		revoke := apiKeyRequest(t, client, http.MethodPost,
			server.URL+"/v1/account/api-keys/"+issued.Key.ID.String()+"/revoke", map[string]any{},
			tenantAAuth.AccessToken, "", "jobs-revoke-race-revoke", `"1"`, "jobs-revoke-race-revoke")
		if revoke.StatusCode != http.StatusOK {
			t.Fatalf("revoke status=%d body=%s", revoke.StatusCode, readBody(revoke.Body))
		}
		revoke.Body.Close()

		service, err := jobhttp.NewService(reader, jobhttp.ServiceConfig{
			ActiveCursorKeyID: "jobs-v1",
			CursorKeys:        map[string][]byte{"jobs-v1": bytes.Repeat([]byte{0x91}, 32)},
		})
		if err != nil {
			t.Fatal(err)
		}
		for _, operation := range []jobhttp.CommandOperation{jobhttp.CommandCancel, jobhttp.CommandRetry} {
			_, err := service.Command(t.Context(), principal, jobhttp.CommandRequest{
				Audience: jobhttp.AudienceTenant, TaskID: job.ID, Operation: operation,
				IdempotencyKey: "jobs-revoke-race-" + string(operation),
			})
			if !errors.Is(err, jobhttp.ErrPermissionDenied) {
				t.Fatalf("%s with revoked key err=%v, want permission denied", operation, err)
			}
		}
		var status string
		var receipts, denied int
		if err := pool.QueryRow(context.Background(), `SELECT job.state,
			(SELECT count(*) FROM background_job_command_receipts receipt WHERE receipt.job_id=job.id),
			(SELECT count(*) FROM audit_events audit WHERE audit.resource_type='background_job'
			   AND audit.resource_id=job.id::text AND audit.result='denied'
			   AND audit.payload->>'reason'='permission_denied')
			FROM background_jobs job WHERE job.id=$1`, job.ID).Scan(&status, &receipts, &denied); err != nil {
			t.Fatal(err)
		}
		if status != "queued" || receipts != 0 || denied != 2 {
			t.Fatalf("revoked key job status=%q receipts=%d denied audits=%d, want queued/0/2", status, receipts, denied)
		}
	})

	t.Run("authentication audience and permission failures are closed", func(t *testing.T) {
		for _, test := range []struct {
			name, path, authorization, code string
			status                          int
		}{
			{name: "missing auth", path: "/v1/admin/jobs?" + window.Encode(), status: 401, code: "job_authentication_required"},
			{name: "platform without role", path: "/v1/admin/jobs?" + window.Encode(), authorization: "Bearer " + noRoleAuth.AccessToken, status: 403, code: "job_permission_denied"},
			{name: "tenant on admin route", path: "/v1/admin/jobs?" + window.Encode(), authorization: "Bearer " + tenantAAuth.AccessToken, status: 403, code: "job_permission_denied"},
			{name: "platform on tenant route", path: "/v1/jobs?" + window.Encode(), authorization: "Bearer " + adminAuth.AccessToken, status: 403, code: "job_permission_denied"},
		} {
			t.Run(test.name, func(t *testing.T) {
				response := jobQueryRequest(t, client, server.URL+test.path, test.authorization, "jobs-denied")
				assertJobError(t, response, test.status, test.code, "jobs-denied")
				response.Body.Close()
			})
		}
	})

	t.Run("reader unavailable and timeout map to stable errors", func(t *testing.T) {
		for _, test := range []struct {
			name string
			mode jobQueryFailureMode
			want int
			code string
		}{
			{name: "unavailable", mode: jobQueryUnavailable, want: 503, code: "job_store_unavailable"},
			{name: "timeout", mode: jobQueryTimeout, want: 504, code: "job_query_timeout"},
		} {
			t.Run(test.name, func(t *testing.T) {
				failureAPI := New(pool, identityService, Config{
					APIKeyPepper:   bytes.Repeat([]byte{0x57}, 32),
					JobQueryReader: &jobQueryFailureReader{mode: test.mode},
					JobQueryServiceConfig: jobhttp.ServiceConfig{
						ActiveCursorKeyID: "jobs-v1",
						CursorKeys:        map[string][]byte{"jobs-v1": bytes.Repeat([]byte{0x91}, 32)},
					},
					JobQueryHandlerConfig: jobhttp.HandlerConfig{QueryTimeout: 20 * time.Millisecond, MaxResponseBytes: 1024},
				})
				if err := failureAPI.InitializationError(); err != nil {
					t.Fatal(err)
				}
				failureServer := httptest.NewServer(failureAPI.Handler())
				defer failureServer.Close()
				response := jobQueryRequest(t, failureServer.Client(), failureServer.URL+"/v1/admin/jobs?"+window.Encode(),
					"Bearer "+adminAuth.AccessToken, "jobs-"+test.name)
				assertJobError(t, response, test.want, test.code, "jobs-"+test.name)
				response.Body.Close()
			})
		}
	})
}

func createHTTPJob(t *testing.T, store *jobstate.Store, tenantID uuid.UUID, kind, subject string) jobstate.StoredJob {
	t.Helper()
	result, err := store.Create(t.Context(), jobstate.CreateInput{
		TenantID: tenantID, Kind: kind, Subject: subject, IdempotencyKey: "http-" + uuid.NewString(),
		Payload: []byte(`{}`), Items: []jobstate.CreateItem{{ItemID: "item-1"}}, MaxAttempts: 2,
		RequestID: "jobs-http", TraceID: "trace-jobs-http",
	})
	if err != nil {
		t.Fatal(err)
	}
	return result.Job
}

func jobQueryRequest(t *testing.T, client *http.Client, rawURL, authorization, requestID string) *http.Response {
	t.Helper()
	request, err := http.NewRequest(http.MethodGet, rawURL, nil)
	if err != nil {
		t.Fatal(err)
	}
	if authorization != "" {
		request.Header.Set("Authorization", authorization)
	}
	request.Header.Set("X-Request-ID", requestID)
	response, err := client.Do(request)
	if err != nil {
		t.Fatal(err)
	}
	return response
}

func jobCommandRequest(t *testing.T, client *http.Client, rawURL, authorization, etag, requestID string) *http.Response {
	t.Helper()
	request, err := http.NewRequest(http.MethodPost, rawURL, bytes.NewReader([]byte("{}")))
	if err != nil {
		t.Fatal(err)
	}
	request.Header.Set("Authorization", authorization)
	request.Header.Set("Content-Type", "application/json")
	request.Header.Set("Idempotency-Key", requestID)
	request.Header.Set("If-Match", etag)
	request.Header.Set("X-Request-ID", requestID)
	response, err := client.Do(request)
	if err != nil {
		t.Fatal(err)
	}
	return response
}

func assertJobError(t *testing.T, response *http.Response, status int, code, requestID string) {
	t.Helper()
	var envelope testErrorEnvelope
	decodeResponse(t, response, status, &envelope)
	if envelope.Error.Code != code || envelope.Error.RequestID != requestID ||
		response.Header.Get("X-Request-ID") != requestID {
		t.Fatalf("job error=%#v header request ID=%q", envelope, response.Header.Get("X-Request-ID"))
	}
}

func cloneValues(values url.Values) url.Values {
	cloned := make(url.Values, len(values))
	for key, entries := range values {
		cloned[key] = append([]string(nil), entries...)
	}
	return cloned
}

func tamperJobCursor(cursor string) string {
	if cursor[len(cursor)-1] == 'A' {
		return cursor[:len(cursor)-1] + "B"
	}
	return cursor[:len(cursor)-1] + "A"
}

type jobQueryFailureMode int

const (
	jobQueryUnavailable jobQueryFailureMode = iota
	jobQueryTimeout
)

type jobQueryFailureReader struct {
	mode jobQueryFailureMode
}

func (reader *jobQueryFailureReader) List(ctx context.Context, _ jobhttp.ReadScope, _ jobhttp.ListQuery) ([]jobhttp.Job, error) {
	if reader.mode == jobQueryTimeout {
		<-ctx.Done()
		return nil, ctx.Err()
	}
	return nil, jobhttp.ErrStoreUnavailable
}

func (*jobQueryFailureReader) Get(context.Context, jobhttp.ReadScope, uuid.UUID) (jobhttp.Job, error) {
	return jobhttp.Job{}, jobhttp.ErrStoreUnavailable
}

func (*jobQueryFailureReader) Attempts(context.Context, jobhttp.ReadScope, uuid.UUID, jobhttp.AttemptQuery) ([]jobhttp.Attempt, error) {
	return nil, jobhttp.ErrStoreUnavailable
}

func (*jobQueryFailureReader) Results(context.Context, jobhttp.ReadScope, uuid.UUID, jobhttp.ResultQuery) ([]jobhttp.ItemResult, error) {
	return nil, jobhttp.ErrStoreUnavailable
}

var _ jobhttp.Reader = (*jobQueryFailureReader)(nil)
