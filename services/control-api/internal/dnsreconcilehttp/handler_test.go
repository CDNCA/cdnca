package dnsreconcilehttp

import (
	"context"
	"encoding/json"
	"errors"
	"maps"
	"net/http"
	"net/http/httptest"
	"os"
	"strings"
	"testing"
	"time"

	"github.com/cdnca/cdnca/services/control-api/internal/dnscheck"
	"github.com/cdnca/cdnca/services/control-api/internal/dnsreconcile"
	"github.com/cdnca/cdnca/services/control-api/internal/jobstate"
	"github.com/google/uuid"
	"github.com/jackc/pgx/v5/pgxpool"
)

func TestHandlerFactoryFailsClosed(t *testing.T) {
	valid := Dependencies{
		Sessions: sessionAuthenticatorFunc(func(context.Context, string) (Principal, error) {
			return Principal{SubjectID: uuid.New(), TenantID: uuid.New(), SessionID: uuid.New()}, nil
		}),
		IAM:    iamAuthorizerFunc(func(context.Context, AuthorizationRequest) error { return nil }),
		Domain: &fakeDomain{},
		Workloads: workloadAuthenticatorFunc(func(*http.Request) (WorkloadPrincipal, error) {
			return WorkloadPrincipal{WorkloadID: "dns-provider-a", TenantID: uuid.New(), SiteID: uuid.New()}, nil
		}),
	}
	if _, err := NewHandler(valid, Config{}); err != nil {
		t.Fatalf("valid dependencies: %v", err)
	}

	tests := []struct {
		name string
		cut  func(*Dependencies)
	}{
		{name: "sessions", cut: func(value *Dependencies) { value.Sessions = nil }},
		{name: "iam", cut: func(value *Dependencies) { value.IAM = nil }},
		{name: "domain", cut: func(value *Dependencies) { value.Domain = nil }},
		{name: "workloads", cut: func(value *Dependencies) { value.Workloads = nil }},
	}
	for _, test := range tests {
		t.Run(test.name, func(t *testing.T) {
			dependencies := valid
			test.cut(&dependencies)
			if _, err := NewHandler(dependencies, Config{}); !errors.Is(err, ErrInvalidConfig) {
				t.Fatalf("error = %v, want ErrInvalidConfig", err)
			}
		})
	}

	var typedNil *fakeDomain
	dependencies := valid
	dependencies.Domain = typedNil
	if _, err := NewHandler(dependencies, Config{}); !errors.Is(err, ErrInvalidConfig) {
		t.Fatalf("typed nil error = %v, want ErrInvalidConfig", err)
	}
}

func TestProductionFactoryFailsClosedOnRuntimeDependencies(t *testing.T) {
	pool := newUnconnectedPool(t, 2)
	defer pool.Close()
	valid := productionDependencies(t, pool)
	tests := []struct {
		name string
		cut  func(*ProductionDependencies)
	}{
		{name: "postgresql", cut: func(value *ProductionDependencies) { value.Pool = nil }},
		{name: "jobstate", cut: func(value *ProductionDependencies) { value.Jobs = nil }},
		{name: "checker resolver", cut: func(value *ProductionDependencies) { value.CheckerResolver = nil }},
		{name: "provider resolver", cut: func(value *ProductionDependencies) { value.ProviderResolver = nil }},
		{name: "runtime entitlement", cut: func(value *ProductionDependencies) { value.Entitlement = nil }},
		{name: "session authenticator", cut: func(value *ProductionDependencies) { value.Sessions = nil }},
		{name: "IAM authorizer", cut: func(value *ProductionDependencies) { value.IAM = nil }},
		{name: "workload authenticator", cut: func(value *ProductionDependencies) { value.Workloads = nil }},
	}
	for _, test := range tests {
		t.Run(test.name, func(t *testing.T) {
			dependencies := valid
			test.cut(&dependencies)
			if _, err := NewProductionHandler(context.Background(), ProductionConfig{}, dependencies); !errors.Is(err, ErrInvalidConfig) {
				t.Fatalf("error=%v, want ErrInvalidConfig", err)
			}
		})
	}
	typedNil := valid
	typedNil.CheckerResolver = checkerResolverFunc(nil)
	if _, err := NewProductionHandler(context.Background(), ProductionConfig{}, typedNil); !errors.Is(err, ErrInvalidConfig) {
		t.Fatalf("typed-nil resolver error=%v, want ErrInvalidConfig", err)
	}

	closedPool := newUnconnectedPool(t, 2)
	closedJobs := productionDependencies(t, closedPool).Jobs
	closedPool.Close()
	closed := valid
	closed.Pool = closedPool
	closed.Jobs = closedJobs
	if _, err := NewProductionHandler(context.Background(), ProductionConfig{}, closed); !errors.Is(err, ErrInvalidConfig) {
		t.Fatalf("closed pool error=%v, want ErrInvalidConfig", err)
	}

	tooWide := valid
	tooWide.Pool = newUnconnectedPool(t, 21)
	defer tooWide.Pool.Close()
	tooWide.Jobs = productionDependencies(t, tooWide.Pool).Jobs
	if _, err := NewProductionHandler(context.Background(), ProductionConfig{}, tooWide); !errors.Is(err, ErrInvalidConfig) {
		t.Fatalf("max-connections error=%v, want ErrInvalidConfig", err)
	}
}

func TestProductionFactoryBuildsPostgresRuntime(t *testing.T) {
	databaseURL := strings.TrimSpace(os.Getenv("TEST_DATABASE_URL"))
	if databaseURL == "" {
		t.Skip("TEST_DATABASE_URL is not set")
	}
	config, err := pgxpool.ParseConfig(databaseURL)
	if err != nil {
		t.Fatal(err)
	}
	config.MaxConns = 2
	pool, err := pgxpool.NewWithConfig(context.Background(), config)
	if err != nil {
		t.Fatal(err)
	}
	defer pool.Close()
	if _, err := NewProductionHandler(context.Background(), ProductionConfig{}, productionDependencies(t, pool)); err != nil {
		t.Fatalf("production factory: %v", err)
	}
}

func TestRuntimeConfigLeaseMustOutliveOverallTimeout(t *testing.T) {
	defaults := runtimeDefaults(dnsreconcile.RuntimeConfig{})
	if defaults.ApplyLeaseDuration != 16*time.Minute || defaults.CommitLeaseDuration != 16*time.Minute {
		t.Fatalf("default leases apply=%s commit=%s, want 16m", defaults.ApplyLeaseDuration, defaults.CommitLeaseDuration)
	}
	if !runtimeConfigValid(defaults) {
		t.Fatal("default runtime config must be valid")
	}

	for _, test := range []struct {
		name      string
		configure func(*dnsreconcile.RuntimeConfig)
	}{
		{name: "apply equal", configure: func(config *dnsreconcile.RuntimeConfig) { config.ApplyLeaseDuration = config.OverallTimeout }},
		{name: "apply shorter", configure: func(config *dnsreconcile.RuntimeConfig) {
			config.ApplyLeaseDuration = config.OverallTimeout - time.Second
		}},
		{name: "commit equal", configure: func(config *dnsreconcile.RuntimeConfig) { config.CommitLeaseDuration = config.OverallTimeout }},
		{name: "commit shorter", configure: func(config *dnsreconcile.RuntimeConfig) {
			config.CommitLeaseDuration = config.OverallTimeout - time.Second
		}},
	} {
		t.Run(test.name, func(t *testing.T) {
			config := defaults
			test.configure(&config)
			if runtimeConfigValid(config) {
				t.Fatal("runtime config accepted a lease that does not outlive the overall timeout")
			}
		})
	}
}

func TestProductionCommandTimeoutOutlivesRuntimeTimeout(t *testing.T) {
	dependencies := validDependencies(&fakeDomain{})
	handler, err := NewHandler(dependencies, Config{})
	if err != nil {
		t.Fatalf("default handler config: %v", err)
	}
	if handler.commandTimeout != 16*time.Minute {
		t.Fatalf("default command timeout=%s, want 16m", handler.commandTimeout)
	}
	if _, err := NewHandler(dependencies, Config{CommandTimeout: time.Hour}); err != nil {
		t.Fatalf("one-hour command timeout: %v", err)
	}

	runtime := runtimeDefaults(dnsreconcile.RuntimeConfig{})
	for _, test := range []struct {
		name    string
		http    Config
		runtime dnsreconcile.RuntimeConfig
		valid   bool
	}{
		{name: "defaults", runtime: runtime, valid: true},
		{name: "equal", http: Config{CommandTimeout: runtime.OverallTimeout}, runtime: runtime},
		{name: "shorter", http: Config{CommandTimeout: runtime.OverallTimeout - time.Second}, runtime: runtime},
		{name: "equal commit lease", http: Config{CommandTimeout: runtime.CommitLeaseDuration}, runtime: runtime, valid: true},
		{name: "longer than commit lease", http: Config{CommandTimeout: runtime.CommitLeaseDuration + time.Second}, runtime: runtime},
		{name: "custom longer", http: Config{CommandTimeout: 11 * time.Minute}, runtime: func() dnsreconcile.RuntimeConfig {
			custom := runtime
			custom.OverallTimeout = 10 * time.Minute
			return custom
		}(), valid: true},
	} {
		t.Run(test.name, func(t *testing.T) {
			if got := productionTimeoutsValid(test.http, test.runtime); got != test.valid {
				t.Fatalf("productionTimeoutsValid()=%t, want %t", got, test.valid)
			}
		})
	}
}

func TestTenantRoutesAuthenticateAuthorizeAndDeriveScope(t *testing.T) {
	tenantID, otherTenantID, siteID := uuid.New(), uuid.New(), uuid.New()
	domain := &fakeDomain{getSiteID: siteID}
	permissions := make([]AuthorizationRequest, 0, 2)
	handler := newTestHandler(t, Dependencies{
		Sessions: sessionAuthenticatorFunc(func(_ context.Context, raw string) (Principal, error) {
			if raw != "session-a" {
				return Principal{}, ErrUnauthenticated
			}
			return Principal{SubjectID: uuid.New(), TenantID: tenantID, SessionID: uuid.New()}, nil
		}),
		IAM: iamAuthorizerFunc(func(_ context.Context, request AuthorizationRequest) error {
			permissions = append(permissions, request)
			return nil
		}),
		Domain: domain,
		Workloads: workloadAuthenticatorFunc(func(*http.Request) (WorkloadPrincipal, error) {
			return WorkloadPrincipal{}, ErrWorkloadUnauthenticated
		}),
	})

	dryRunBody := validCheckBody(otherTenantID)
	response := serve(handler, http.MethodPost, "/v1/sites/"+siteID.String()+"/dns-reconcile/dry-run", dryRunBody,
		[]string{"Bearer session-a"}, readHeaders())
	if response.Code != http.StatusOK {
		t.Fatalf("dry-run status=%d body=%s", response.Code, response.Body)
	}
	if len(domain.dryRuns) != 1 || domain.dryRuns[0].TenantID != tenantID || domain.dryRuns[0].SiteID != siteID ||
		domain.dryRuns[0].Check.TenantID != tenantID || domain.dryRuns[0].Check.SiteID != siteID {
		t.Fatalf("dry-run scope was not derived from authenticated tenant: %#v", domain.dryRuns)
	}
	if len(permissions) != 1 || permissions[0].Permission != PermissionRead ||
		permissions[0].TenantID != tenantID || permissions[0].SiteID != siteID {
		t.Fatalf("dry-run authorization = %#v", permissions)
	}

	apply := serve(handler, http.MethodPost, "/v1/sites/"+siteID.String()+"/dns-reconcile/apply", dryRunBody,
		[]string{"Bearer session-a"}, mutationHeaders())
	if apply.Code != http.StatusAccepted {
		t.Fatalf("apply status=%d body=%s", apply.Code, apply.Body)
	}
	var applyResponse struct {
		RequiredConsecutive int `json:"required_consecutive"`
	}
	if err := json.Unmarshal(apply.Body.Bytes(), &applyResponse); err != nil || applyResponse.RequiredConsecutive != 2 {
		t.Fatalf("apply required_consecutive=%d error=%v body=%s", applyResponse.RequiredConsecutive, err, apply.Body)
	}
	if len(domain.applies) != 1 || domain.applies[0].TenantID != tenantID || domain.applies[0].SiteID != siteID ||
		domain.applies[0].ExpectedRevision != 7 || domain.applies[0].Traceparent == "" {
		t.Fatalf("apply request = %#v", domain.applies)
	}
	if len(permissions) != 2 || permissions[1].Permission != PermissionManage {
		t.Fatalf("apply authorization = %#v", permissions)
	}
	legacyApply := serve(handler, http.MethodPost, "/v1/sites/"+siteID.String()+"/dns-reconcile/tasks", dryRunBody,
		[]string{"Bearer session-a"}, mutationHeaders())
	assertError(t, legacyApply, http.StatusNotFound, "dns_reconcile_route_not_found")
	if len(domain.applies) != 1 {
		t.Fatalf("legacy apply route reached domain: %#v", domain.applies)
	}
}

func TestTenantAuthenticationAcceptsExactlyOneBearerSession(t *testing.T) {
	handler := newTestHandler(t, validDependencies(&fakeDomain{}))
	siteID := uuid.New()
	tests := []struct {
		name   string
		values []string
	}{
		{name: "missing"},
		{name: "duplicate", values: []string{"Bearer session-a", "Bearer session-b"}},
		{name: "wrong scheme", values: []string{"CdncaKey id.secret"}},
		{name: "empty", values: []string{"Bearer "}},
		{name: "whitespace", values: []string{"Bearer session a"}},
		{name: "comma combined", values: []string{"Bearer session-a,Bearer-session-b"}},
	}
	for _, test := range tests {
		t.Run(test.name, func(t *testing.T) {
			response := serve(handler, http.MethodPost, "/v1/sites/"+siteID.String()+"/dns-reconcile/dry-run",
				validCheckBody(uuid.Nil), test.values, readHeaders())
			assertError(t, response, http.StatusUnauthorized, "authentication_required")
		})
	}
}

func TestMutationsRequireCanonicalMetadataAndStrictJSON(t *testing.T) {
	handler := newTestHandler(t, validDependencies(&fakeDomain{}))
	siteID, taskID := uuid.New(), uuid.New()
	path := "/v1/sites/" + siteID.String() + "/dns-reconcile/apply"
	tests := []struct {
		name    string
		body    string
		headers http.Header
	}{
		{name: "missing idempotency", body: validCheckBody(uuid.Nil), headers: mutationHeadersWithout("Idempotency-Key")},
		{name: "missing request id", body: validCheckBody(uuid.Nil), headers: mutationHeadersWithout("X-Request-ID")},
		{name: "missing trace", body: validCheckBody(uuid.Nil), headers: mutationHeadersWithout("traceparent")},
		{name: "missing revision", body: validCheckBody(uuid.Nil), headers: mutationHeadersWithout("If-Match")},
		{name: "invalid idempotency", body: validCheckBody(uuid.Nil), headers: mutationHeadersWith("Idempotency-Key", "invalid:key")},
		{name: "duplicate header", body: validCheckBody(uuid.Nil), headers: duplicateMutationHeader("Idempotency-Key")},
		{name: "wrong content type", body: validCheckBody(uuid.Nil), headers: mutationHeadersWith("Content-Type", "text/plain")},
		{name: "unknown field", body: strings.TrimSuffix(validCheckBody(uuid.Nil), "}") + `,"unknown":true}`, headers: mutationHeaders()},
		{name: "trailing json", body: validCheckBody(uuid.Nil) + `{}`, headers: mutationHeaders()},
		{name: "oversized", body: strings.Repeat("x", int(defaultMaxRequestBytes+1)), headers: mutationHeaders()},
	}
	for _, test := range tests {
		t.Run(test.name, func(t *testing.T) {
			response := serveWithHeaders(handler, http.MethodPost, path, test.body, []string{"Bearer session-a"}, test.headers)
			assertError(t, response, http.StatusBadRequest, "dns_reconcile_invalid_request")
		})
	}

	for _, suffix := range []string{"/commit", "/cancel"} {
		response := serve(handler, http.MethodPost,
			"/v1/sites/"+siteID.String()+"/dns-reconcile/tasks/"+taskID.String()+suffix,
			`{}`, []string{"Bearer session-a"}, mutationHeadersWithout("If-Match"))
		assertError(t, response, http.StatusBadRequest, "dns_reconcile_invalid_request")
	}
}

func TestCheckRoutesRejectInvalidProviderRecordIdentifiers(t *testing.T) {
	domain := &fakeDomain{}
	handler := newTestHandler(t, validDependencies(domain))
	siteID := uuid.New()
	for _, test := range []struct {
		name     string
		recordID string
	}{
		{name: "empty", recordID: ""},
		{name: "invalid character", recordID: "record?1"},
		{name: "leading punctuation", recordID: "-record-1"},
		{name: "257 bytes", recordID: strings.Repeat("a", 257)},
	} {
		for _, route := range []struct {
			name          string
			path          string
			authorization []string
			headers       http.Header
		}{
			{name: "dry-run", path: "/v1/sites/" + siteID.String() + "/dns-reconcile/dry-run",
				authorization: []string{"Bearer session-a"}, headers: readHeaders()},
			{name: "apply", path: "/v1/sites/" + siteID.String() + "/dns-reconcile/apply",
				authorization: []string{"Bearer session-a"}, headers: mutationHeaders()},
		} {
			t.Run(route.name+"/"+test.name, func(t *testing.T) {
				body := checkBodyWithProviderRecord(t, test.recordID)
				response := serveWithHeaders(handler, http.MethodPost, route.path, body, route.authorization, route.headers)
				assertError(t, response, http.StatusBadRequest, "dns_reconcile_invalid_request")
			})
		}
	}
	for _, test := range []struct {
		name string
		body string
	}{
		{name: "unknown field", body: strings.TrimSuffix(validCheckBody(uuid.Nil), "}") + `,"unknown":true}`},
		{name: "trailing json", body: validCheckBody(uuid.Nil) + `{}`},
	} {
		t.Run("dry-run/"+test.name, func(t *testing.T) {
			response := serve(handler, http.MethodPost,
				"/v1/sites/"+siteID.String()+"/dns-reconcile/dry-run", test.body,
				[]string{"Bearer session-a"}, readHeaders())
			assertError(t, response, http.StatusBadRequest, "dns_reconcile_invalid_request")
		})
	}
	if len(domain.dryRuns) != 0 || len(domain.applies) != 0 {
		t.Fatalf("domain received invalid checks: dry-runs=%d applies=%d", len(domain.dryRuns), len(domain.applies))
	}
}

func TestProviderReportUsesIndependentWorkloadSurface(t *testing.T) {
	tenantID, siteID, taskID := uuid.New(), uuid.New(), uuid.New()
	leaseID := uuid.New()
	domain := &fakeDomain{}
	dependencies := validDependencies(domain)
	dependencies.Workloads = workloadAuthenticatorFunc(func(request *http.Request) (WorkloadPrincipal, error) {
		if request.Header.Get("X-Workload-Proof") != "sealed" {
			return WorkloadPrincipal{}, ErrWorkloadUnauthenticated
		}
		return WorkloadPrincipal{WorkloadID: "provider-worker-a", TenantID: tenantID, SiteID: siteID}, nil
	})
	handler := newTestHandler(t, dependencies)
	path := "/internal/v1/dns/reconcile/tasks/" + taskID.String() + "/provider-reports"
	body := `{"client_request_id":"operation-1","job_attempt":3,"lease_id":"` + leaseID.String() + `","provider_request_id":"provider-1","provider_record_id":"record-1","provider_revision":8,"status":"succeeded","error_class":"","error_code":"","sequence":2}`

	forged := serve(handler, http.MethodPost, path, body, []string{"Bearer session-a"}, mutationHeaders())
	assertError(t, forged, http.StatusUnauthorized, "workload_authentication_required")

	headers := mutationHeaders()
	headers.Set("X-Workload-Proof", "sealed")
	accepted := serveWithHeaders(handler, http.MethodPost, path, body, nil, headers)
	if accepted.Code != http.StatusOK {
		t.Fatalf("provider report status=%d body=%s", accepted.Code, accepted.Body)
	}
	if len(domain.reports) != 1 || domain.reports[0].TenantID != tenantID || domain.reports[0].SiteID != siteID ||
		domain.reports[0].TaskID != taskID || domain.reports[0].WorkloadID != "provider-worker-a" ||
		domain.reports[0].JobAttempt != 3 || domain.reports[0].LeaseID != leaseID {
		t.Fatalf("provider report scope = %#v", domain.reports)
	}

	for _, field := range []string{"job_attempt", "lease_id"} {
		var invalid map[string]any
		if err := json.Unmarshal([]byte(body), &invalid); err != nil {
			t.Fatal(err)
		}
		delete(invalid, field)
		encoded, err := json.Marshal(invalid)
		if err != nil {
			t.Fatal(err)
		}
		response := serveWithHeaders(handler, http.MethodPost, path, string(encoded), nil, headers)
		assertError(t, response, http.StatusBadRequest, "dns_reconcile_invalid_request")
	}
	var forgedBody map[string]any
	if err := json.Unmarshal([]byte(body), &forgedBody); err != nil {
		t.Fatal(err)
	}
	forgedBody["workload_id"] = "forged-worker"
	encoded, err := json.Marshal(forgedBody)
	if err != nil {
		t.Fatal(err)
	}
	assertError(t, serveWithHeaders(handler, http.MethodPost, path, string(encoded), nil, headers),
		http.StatusBadRequest, "dns_reconcile_invalid_request")
	if len(domain.reports) != 1 {
		t.Fatalf("domain received invalid fenced reports: %#v", domain.reports)
	}
}

func TestProviderReportRejectsInvalidProviderIdentifiers(t *testing.T) {
	tenantID, siteID, taskID := uuid.New(), uuid.New(), uuid.New()
	leaseID := uuid.New()
	domain := &fakeDomain{}
	dependencies := validDependencies(domain)
	dependencies.Workloads = workloadAuthenticatorFunc(func(*http.Request) (WorkloadPrincipal, error) {
		return WorkloadPrincipal{WorkloadID: "provider-worker-a", TenantID: tenantID, SiteID: siteID}, nil
	})
	handler := newTestHandler(t, dependencies)
	path := "/internal/v1/dns/reconcile/tasks/" + taskID.String() + "/provider-reports"
	headers := mutationHeaders()

	for _, field := range []string{"provider_request_id", "provider_record_id"} {
		for _, test := range []struct {
			name  string
			value string
		}{
			{name: "empty", value: ""},
			{name: "invalid character", value: "provider request"},
			{name: "leading punctuation", value: "-provider-1"},
			{name: "257 bytes", value: strings.Repeat("a", 257)},
		} {
			t.Run(field+"/"+test.name, func(t *testing.T) {
				body := map[string]any{
					"client_request_id": "operation-1", "provider_request_id": "provider-1",
					"job_attempt": 3, "lease_id": leaseID,
					"provider_record_id": "record-1", "provider_revision": 8,
					"status": "succeeded", "error_class": "", "error_code": "", "sequence": 2,
				}
				body[field] = test.value
				encoded, err := json.Marshal(body)
				if err != nil {
					t.Fatal(err)
				}
				response := serveWithHeaders(handler, http.MethodPost, path, string(encoded), nil, headers)
				assertError(t, response, http.StatusBadRequest, "dns_reconcile_invalid_request")
			})
		}
	}
	if len(domain.reports) != 0 {
		t.Fatalf("domain received %d invalid provider reports", len(domain.reports))
	}
}

func TestProviderReportEnforcesStatusFactConsistency(t *testing.T) {
	tenantID, siteID, taskID := uuid.New(), uuid.New(), uuid.New()
	leaseID := uuid.New()
	domain := &fakeDomain{}
	dependencies := validDependencies(domain)
	dependencies.Workloads = workloadAuthenticatorFunc(func(*http.Request) (WorkloadPrincipal, error) {
		return WorkloadPrincipal{WorkloadID: "provider-worker-a", TenantID: tenantID, SiteID: siteID}, nil
	})
	handler := newTestHandler(t, dependencies)
	path := "/internal/v1/dns/reconcile/tasks/" + taskID.String() + "/provider-reports"
	headers := mutationHeaders()
	validSucceeded := map[string]any{
		"client_request_id": "operation-1", "provider_request_id": "provider-1",
		"job_attempt": 3, "lease_id": leaseID,
		"provider_record_id": "record-1", "provider_revision": 8,
		"status": "succeeded", "error_class": "", "error_code": "", "sequence": 2,
	}

	for _, test := range []struct {
		name   string
		mutate func(map[string]any)
	}{
		{name: "succeeded missing provider request", mutate: func(body map[string]any) { delete(body, "provider_request_id") }},
		{name: "succeeded missing provider record", mutate: func(body map[string]any) { delete(body, "provider_record_id") }},
		{name: "succeeded missing revision", mutate: func(body map[string]any) { delete(body, "provider_revision") }},
		{name: "succeeded zero revision", mutate: func(body map[string]any) { body["provider_revision"] = 0 }},
		{name: "succeeded with error", mutate: func(body map[string]any) {
			body["error_class"], body["error_code"] = "permanent", "provider_rejected"
		}},
		{name: "running with error", mutate: func(body map[string]any) {
			body["status"], body["error_class"], body["error_code"] = "running", "transient", "provider_busy"
		}},
		{name: "transient failure wrong class", mutate: func(body map[string]any) {
			body["status"], body["error_class"], body["error_code"] = "transient_failed", "permanent", "provider_busy"
		}},
		{name: "failure missing error code", mutate: func(body map[string]any) {
			body["status"], body["error_class"], body["error_code"] = "permanent_failed", "permanent", ""
		}},
	} {
		t.Run(test.name, func(t *testing.T) {
			body := maps.Clone(validSucceeded)
			test.mutate(body)
			encoded, err := json.Marshal(body)
			if err != nil {
				t.Fatal(err)
			}
			response := serveWithHeaders(handler, http.MethodPost, path, string(encoded), nil, headers)
			assertError(t, response, http.StatusBadRequest, "dns_reconcile_invalid_request")
		})
	}
	encodedSucceeded, err := json.Marshal(validSucceeded)
	if err != nil {
		t.Fatal(err)
	}
	for _, test := range []struct {
		name string
		body string
	}{
		{name: "unknown field", body: strings.TrimSuffix(string(encodedSucceeded), "}") + `,"unknown":true}`},
		{name: "trailing json", body: string(encodedSucceeded) + `{}`},
	} {
		t.Run("provider report "+test.name, func(t *testing.T) {
			response := serveWithHeaders(handler, http.MethodPost, path, test.body, nil, headers)
			assertError(t, response, http.StatusBadRequest, "dns_reconcile_invalid_request")
		})
	}
	if len(domain.reports) != 0 {
		t.Fatalf("domain received %d inconsistent provider reports", len(domain.reports))
	}
	for _, report := range []struct {
		status               string
		errorClass           string
		errorCode            string
		allowProviderRequest bool
	}{
		{status: "running"},
		{status: "transient_failed", errorClass: "transient", errorCode: "provider_busy", allowProviderRequest: true},
		{status: "permanent_failed", errorClass: "permanent", errorCode: "provider_rejected", allowProviderRequest: true},
		{status: "revision_conflict", errorClass: "revision_conflict", errorCode: "provider_revision_conflict", allowProviderRequest: true},
		{status: "cancelled", errorClass: "cancelled", errorCode: "provider_cancelled", allowProviderRequest: true},
	} {
		for _, fact := range []struct {
			name  string
			value any
		}{
			{name: "provider_request_id", value: "provider-1"},
			{name: "provider_record_id", value: "record-1"},
			{name: "provider_revision", value: 8},
		} {
			t.Run(report.status+" with "+fact.name, func(t *testing.T) {
				body := map[string]any{
					"client_request_id": "operation-1", "status": report.status,
					"job_attempt": 3, "lease_id": leaseID,
					"error_class": report.errorClass, "error_code": report.errorCode, "sequence": 3,
					fact.name: fact.value,
				}
				encoded, err := json.Marshal(body)
				if err != nil {
					t.Fatal(err)
				}
				response := serveWithHeaders(handler, http.MethodPost, path, string(encoded), nil, headers)
				if fact.name == "provider_request_id" && report.allowProviderRequest {
					if response.Code != http.StatusOK {
						t.Fatalf("failure receipt status=%d body=%s", response.Code, response.Body)
					}
					accepted := domain.reports[len(domain.reports)-1].Report
					if accepted.ProviderRequestID != "provider-1" || accepted.ProviderRecordID != "" || accepted.ProviderRevision != 0 {
						t.Fatalf("failure receipt facts = %#v", accepted)
					}
					return
				}
				assertError(t, response, http.StatusBadRequest, "dns_reconcile_invalid_request")
			})
		}
	}
	if len(domain.reports) != 4 {
		t.Fatalf("accepted failure receipt count=%d, want 4", len(domain.reports))
	}

	for index, report := range []struct {
		status     string
		errorClass string
		errorCode  string
	}{
		{status: "running"},
		{status: "transient_failed", errorClass: "transient", errorCode: "provider_busy"},
		{status: "transient_failed", errorClass: "timeout", errorCode: "provider_timeout"},
		{status: "permanent_failed", errorClass: "permanent", errorCode: "provider_rejected"},
		{status: "revision_conflict", errorClass: "revision_conflict", errorCode: "provider_revision_conflict"},
		{status: "cancelled", errorClass: "cancelled", errorCode: "provider_cancelled"},
	} {
		body := map[string]any{
			"client_request_id": "operation-1", "status": report.status,
			"job_attempt": 3, "lease_id": leaseID,
			"error_class": report.errorClass, "error_code": report.errorCode, "sequence": index + 3,
		}
		encoded, err := json.Marshal(body)
		if err != nil {
			t.Fatal(err)
		}
		response := serveWithHeaders(handler, http.MethodPost, path, string(encoded), nil, headers)
		if response.Code != http.StatusOK {
			t.Fatalf("%s without success-only facts status=%d body=%s", report.status, response.Code, response.Body)
		}
	}
	if len(domain.reports) != 10 {
		t.Fatalf("accepted report count=%d, want 10", len(domain.reports))
	}
	providerReceipts := 0
	for _, report := range domain.reports {
		if report.Report.ProviderRecordID != "" || report.Report.ProviderRevision != 0 {
			t.Fatalf("non-success report contains success-only identity: %#v", report)
		}
		if report.Report.ProviderRequestID != "" {
			providerReceipts++
		}
	}
	if providerReceipts != 4 {
		t.Fatalf("provider request receipt count=%d, want 4", providerReceipts)
	}
}

func TestGetCommitCancelAndTenantSiteIsolation(t *testing.T) {
	tenantID := uuid.MustParse("11111111-1111-4111-8111-111111111111")
	siteID, taskID := uuid.New(), uuid.New()
	domain := &fakeDomain{getSiteID: siteID}
	handler := newTestHandler(t, validDependencies(domain))

	get := serve(handler, http.MethodGet,
		"/v1/sites/"+siteID.String()+"/dns-reconcile/tasks/"+taskID.String(), "",
		[]string{"Bearer session-a"}, http.Header{"X-Request-Id": []string{"get-request"}})
	if get.Code != http.StatusOK || len(domain.gets) != 1 || domain.gets[0].tenantID != tenantID || domain.gets[0].taskID != taskID {
		t.Fatalf("get status=%d calls=%#v body=%s", get.Code, domain.gets, get.Body)
	}

	for _, item := range []struct {
		suffix string
		check  func() int
	}{
		{suffix: "/commit", check: func() int { return len(domain.commits) }},
		{suffix: "/cancel", check: func() int { return len(domain.cancels) }},
	} {
		response := serve(handler, http.MethodPost,
			"/v1/sites/"+siteID.String()+"/dns-reconcile/tasks/"+taskID.String()+item.suffix,
			`{}`, []string{"Bearer session-a"}, mutationHeaders())
		if response.Code != http.StatusOK || item.check() != 1 {
			t.Fatalf("%s status=%d body=%s", item.suffix, response.Code, response.Body)
		}
	}

	domain.getSiteID = uuid.New()
	isolation := serve(handler, http.MethodGet,
		"/v1/sites/"+siteID.String()+"/dns-reconcile/tasks/"+taskID.String(), "",
		[]string{"Bearer session-a"}, http.Header{"X-Request-Id": []string{"isolation-request"}})
	assertError(t, isolation, http.StatusNotFound, "dns_reconcile_not_found")
}

func TestCancelMapsOperationInFlightToStableConflict(t *testing.T) {
	siteID, taskID := uuid.New(), uuid.New()
	domain := &fakeDomain{cancelErr: dnsreconcile.ErrOperationInFlight}
	handler := newTestHandler(t, validDependencies(domain))
	response := serve(handler, http.MethodPost,
		"/v1/sites/"+siteID.String()+"/dns-reconcile/tasks/"+taskID.String()+"/cancel",
		`{}`, []string{"Bearer session-a"}, mutationHeaders())
	assertError(t, response, http.StatusConflict, "dns_reconcile_operation_in_flight")
}

func TestIAMAndRuntimeEntitlementDenialsMapWithoutSuccessfulMutation(t *testing.T) {
	siteID := uuid.New()
	for _, test := range []struct {
		name      string
		configure func(*Dependencies, *fakeDomain)
		status    int
		code      string
	}{
		{name: "iam", status: http.StatusForbidden, code: "permission_denied", configure: func(value *Dependencies, _ *fakeDomain) {
			value.IAM = iamAuthorizerFunc(func(context.Context, AuthorizationRequest) error { return ErrPermissionDenied })
		}},
		{name: "entitlement", status: http.StatusForbidden, code: "dns_reconcile_entitlement_denied", configure: func(_ *Dependencies, domain *fakeDomain) {
			domain.applyErr = dnsreconcile.ErrEntitlementDenied
		}},
	} {
		t.Run(test.name, func(t *testing.T) {
			domain := &fakeDomain{}
			dependencies := validDependencies(domain)
			test.configure(&dependencies, domain)
			handler := newTestHandler(t, dependencies)
			response := serve(handler, http.MethodPost,
				"/v1/sites/"+siteID.String()+"/dns-reconcile/apply", validCheckBody(uuid.Nil),
				[]string{"Bearer session-a"}, mutationHeaders())
			assertError(t, response, test.status, test.code)
			if test.name == "iam" && len(domain.applies) != 0 {
				t.Fatal("domain apply was called after IAM denial")
			}
		})
	}
}

func TestMutationUnavailableMapsToResultUnknown(t *testing.T) {
	tenantID, siteID := uuid.New(), uuid.New()
	domain := &fakeDomain{applyErr: dnsreconcile.ErrUnavailable}
	handler := newTestHandler(t, Dependencies{
		Sessions: sessionAuthenticatorFunc(func(context.Context, string) (Principal, error) {
			return Principal{SubjectID: uuid.New(), TenantID: tenantID, SessionID: uuid.New()}, nil
		}),
		IAM:    iamAuthorizerFunc(func(context.Context, AuthorizationRequest) error { return nil }),
		Domain: domain,
		Workloads: workloadAuthenticatorFunc(func(*http.Request) (WorkloadPrincipal, error) {
			return WorkloadPrincipal{}, ErrWorkloadUnauthenticated
		}),
	})

	response := serve(handler, http.MethodPost, "/v1/sites/"+siteID.String()+"/dns-reconcile/apply",
		validCheckBody(uuid.Nil), []string{"Bearer session-a"}, mutationHeaders())
	if response.Code != http.StatusServiceUnavailable ||
		!strings.Contains(response.Body.String(), `"code":"dns_reconcile_result_unknown"`) {
		t.Fatalf("mutation unavailable status=%d body=%s", response.Code, response.Body)
	}
}

type fakeDomain struct {
	dryRuns   []dnsreconcile.DryRunRequest
	applies   []dnsreconcile.ApplyRequest
	reports   []dnsreconcile.ProviderReportRequest
	gets      []getCall
	commits   []dnsreconcile.CommitRequest
	cancels   []dnsreconcile.CancelRequest
	getSiteID uuid.UUID
	applyErr  error
	cancelErr error
}

type getCall struct {
	tenantID uuid.UUID
	taskID   uuid.UUID
}

func (domain *fakeDomain) DryRun(_ context.Context, request dnsreconcile.DryRunRequest) (dnscheck.ReconcileResult, error) {
	domain.dryRuns = append(domain.dryRuns, request)
	return dnscheck.ReconcileResult{TenantID: request.TenantID, SiteID: request.SiteID, Status: dnscheck.TaskDryRun}, nil
}

func (domain *fakeDomain) Apply(_ context.Context, request dnsreconcile.ApplyRequest) (dnsreconcile.Task, error) {
	domain.applies = append(domain.applies, request)
	if domain.applyErr != nil {
		return dnsreconcile.Task{}, domain.applyErr
	}
	return sampleTask(request.TenantID, request.SiteID), nil
}

func (domain *fakeDomain) Get(_ context.Context, tenantID, taskID uuid.UUID) (dnsreconcile.Task, error) {
	domain.gets = append(domain.gets, getCall{tenantID: tenantID, taskID: taskID})
	siteID := domain.getSiteID
	if siteID == uuid.Nil {
		siteID = taskID
	}
	task := sampleTask(tenantID, siteID)
	task.ID = taskID
	return task, nil
}

func (domain *fakeDomain) Commit(_ context.Context, request dnsreconcile.CommitRequest) (dnsreconcile.Task, error) {
	domain.commits = append(domain.commits, request)
	task := sampleTask(request.TenantID, request.SiteID)
	task.ID = request.TaskID
	return task, nil
}

func (domain *fakeDomain) Cancel(_ context.Context, request dnsreconcile.CancelRequest) (dnsreconcile.Task, error) {
	domain.cancels = append(domain.cancels, request)
	if domain.cancelErr != nil {
		return dnsreconcile.Task{}, domain.cancelErr
	}
	task := sampleTask(request.TenantID, request.SiteID)
	task.ID = request.TaskID
	return task, nil
}

func (domain *fakeDomain) RecordProviderReport(_ context.Context, request dnsreconcile.ProviderReportRequest) (dnsreconcile.ReportResult, error) {
	domain.reports = append(domain.reports, request)
	task := sampleTask(request.TenantID, request.SiteID)
	task.ID = request.TaskID
	return dnsreconcile.ReportResult{Task: task, Accepted: true}, nil
}

func sampleTask(tenantID, siteID uuid.UUID) dnsreconcile.Task {
	return dnsreconcile.Task{ID: uuid.New(), TenantID: tenantID, SiteID: siteID, Revision: 7, RequiredConsecutive: 2,
		Result: dnscheck.ReconcileResult{TenantID: tenantID, SiteID: siteID, Status: dnscheck.TaskApplying}}
}

func validDependencies(domain Domain) Dependencies {
	tenantID := uuid.MustParse("11111111-1111-4111-8111-111111111111")
	return Dependencies{
		Sessions: sessionAuthenticatorFunc(func(context.Context, string) (Principal, error) {
			return Principal{SubjectID: uuid.New(), TenantID: tenantID, SessionID: uuid.New()}, nil
		}),
		IAM:    iamAuthorizerFunc(func(context.Context, AuthorizationRequest) error { return nil }),
		Domain: domain,
		Workloads: workloadAuthenticatorFunc(func(*http.Request) (WorkloadPrincipal, error) {
			return WorkloadPrincipal{WorkloadID: "provider-worker", TenantID: tenantID, SiteID: uuid.New()}, nil
		}),
	}
}

func newTestHandler(t *testing.T, dependencies Dependencies) http.Handler {
	t.Helper()
	handler, err := NewHandler(dependencies, Config{})
	if err != nil {
		t.Fatal(err)
	}
	return handler
}

func validCheckBody(_ uuid.UUID) string {
	return `{"name":"www.example.com","expected":[{"type":"A","values":["192.0.2.1"]}],"authoritative_ns":["ns1.example.net"],"ttl":300,"propagation_window_seconds":600,"provider":{"zone_id":"22222222-2222-4222-8222-222222222222","revision":7,"records":[]}}`
}

func checkBodyWithProviderRecord(t *testing.T, recordID string) string {
	t.Helper()
	var body map[string]any
	if err := json.Unmarshal([]byte(validCheckBody(uuid.Nil)), &body); err != nil {
		t.Fatal(err)
	}
	provider, ok := body["provider"].(map[string]any)
	if !ok {
		t.Fatal("valid check body has no provider object")
	}
	provider["records"] = []map[string]any{{
		"record_id": recordID, "name": "www.example.com", "type": "A", "value": "192.0.2.1", "ttl": 300,
	}}
	encoded, err := json.Marshal(body)
	if err != nil {
		t.Fatal(err)
	}
	return string(encoded)
}

func readHeaders() http.Header {
	return http.Header{"Content-Type": []string{"application/json"}, "X-Request-Id": []string{"request-1"},
		"Traceparent": []string{"00-0123456789abcdef0123456789abcdef-0123456789abcdef-01"}}
}

func mutationHeaders() http.Header {
	headers := readHeaders()
	headers.Set("Idempotency-Key", "dns-reconcile-1")
	headers.Set("If-Match", `"7"`)
	return headers
}

func mutationHeadersWithout(name string) http.Header {
	headers := mutationHeaders()
	headers.Del(name)
	return headers
}

func mutationHeadersWith(name, value string) http.Header {
	headers := mutationHeaders()
	headers.Set(name, value)
	return headers
}

func duplicateMutationHeader(name string) http.Header {
	headers := mutationHeaders()
	headers.Add(name, headers.Get(name))
	return headers
}

func serve(handler http.Handler, method, path, body string, authorization []string, headers http.Header) *httptest.ResponseRecorder {
	return serveWithHeaders(handler, method, path, body, authorization, headers)
}

func serveWithHeaders(handler http.Handler, method, path, body string, authorization []string, headers http.Header) *httptest.ResponseRecorder {
	request := httptest.NewRequest(method, path, strings.NewReader(body))
	request.Header = headers.Clone()
	for _, value := range authorization {
		request.Header.Add("Authorization", value)
	}
	response := httptest.NewRecorder()
	handler.ServeHTTP(response, request)
	return response
}

func assertError(t *testing.T, response *httptest.ResponseRecorder, status int, code string) {
	t.Helper()
	if response.Code != status {
		t.Fatalf("status=%d want=%d body=%s", response.Code, status, response.Body)
	}
	var envelope struct {
		Error struct {
			Code      string `json:"code"`
			RequestID string `json:"request_id"`
		} `json:"error"`
	}
	if err := json.Unmarshal(response.Body.Bytes(), &envelope); err != nil {
		t.Fatalf("decode error envelope: %v", err)
	}
	if envelope.Error.Code != code || envelope.Error.RequestID == "" {
		t.Fatalf("error envelope = %#v", envelope)
	}
}

type sessionAuthenticatorFunc func(context.Context, string) (Principal, error)

func (function sessionAuthenticatorFunc) AuthenticateSession(ctx context.Context, raw string) (Principal, error) {
	return function(ctx, raw)
}

type iamAuthorizerFunc func(context.Context, AuthorizationRequest) error

func (function iamAuthorizerFunc) Authorize(ctx context.Context, request AuthorizationRequest) error {
	return function(ctx, request)
}

type workloadAuthenticatorFunc func(*http.Request) (WorkloadPrincipal, error)

func (function workloadAuthenticatorFunc) Authenticate(request *http.Request) (WorkloadPrincipal, error) {
	return function(request)
}

type checkerResolverFunc func(context.Context, uuid.UUID, uuid.UUID) (*dnscheck.Checker, error)

func (function checkerResolverFunc) ResolveChecker(ctx context.Context, tenantID, siteID uuid.UUID) (*dnscheck.Checker, error) {
	return function(ctx, tenantID, siteID)
}

type providerResolverFunc func(context.Context, uuid.UUID, uuid.UUID, uuid.UUID) (dnscheck.ProviderAdapter, error)

func (function providerResolverFunc) ResolveProvider(ctx context.Context, tenantID, siteID, zoneID uuid.UUID) (dnscheck.ProviderAdapter, error) {
	return function(ctx, tenantID, siteID, zoneID)
}

type runtimeEntitlementFunc func(context.Context, dnsreconcile.EntitlementRequest) error

func (function runtimeEntitlementFunc) AuthorizeDNSReconcile(ctx context.Context, request dnsreconcile.EntitlementRequest) error {
	return function(ctx, request)
}

func newUnconnectedPool(t *testing.T, maxConnections int32) *pgxpool.Pool {
	t.Helper()
	config, err := pgxpool.ParseConfig("postgres://dns:secret@127.0.0.1:1/dns?sslmode=disable&connect_timeout=1")
	if err != nil {
		t.Fatal(err)
	}
	config.MaxConns = maxConnections
	pool, err := pgxpool.NewWithConfig(context.Background(), config)
	if err != nil {
		t.Fatal(err)
	}
	return pool
}

func productionDependencies(t *testing.T, pool *pgxpool.Pool) ProductionDependencies {
	t.Helper()
	jobs, err := jobstate.NewStore(pool, time.Now)
	if err != nil {
		t.Fatal(err)
	}
	return ProductionDependencies{
		Pool: pool, Jobs: jobs,
		CheckerResolver: checkerResolverFunc(func(context.Context, uuid.UUID, uuid.UUID) (*dnscheck.Checker, error) {
			return nil, dnsreconcile.ErrUnavailable
		}),
		ProviderResolver: providerResolverFunc(func(context.Context, uuid.UUID, uuid.UUID, uuid.UUID) (dnscheck.ProviderAdapter, error) {
			return nil, dnsreconcile.ErrUnavailable
		}),
		Entitlement: runtimeEntitlementFunc(func(context.Context, dnsreconcile.EntitlementRequest) error { return nil }),
		Sessions: sessionAuthenticatorFunc(func(context.Context, string) (Principal, error) {
			return Principal{SubjectID: uuid.New(), TenantID: uuid.New(), SessionID: uuid.New()}, nil
		}),
		IAM: iamAuthorizerFunc(func(context.Context, AuthorizationRequest) error { return nil }),
		Workloads: workloadAuthenticatorFunc(func(*http.Request) (WorkloadPrincipal, error) {
			return WorkloadPrincipal{WorkloadID: "dns-worker", TenantID: uuid.New(), SiteID: uuid.New()}, nil
		}),
	}
}
