package errorpagecontrol

import (
	"encoding/json"
	"errors"
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"
	"time"

	"github.com/cdnca/cdnca/services/control-api/internal/apikey"
	"github.com/cdnca/cdnca/services/control-api/internal/apikeycredential"
	"github.com/cdnca/cdnca/services/control-api/internal/iamlock"
	"github.com/cdnca/cdnca/services/control-api/internal/identity"
	"github.com/cdnca/cdnca/services/control-api/internal/sessioncredential"
	"github.com/jackc/pgx/v5/pgxpool"
)

func TestRuntimeHandlerDisabledIsClosed(t *testing.T) {
	handler, err := NewRuntimeHandler(RuntimeConfig{}, RuntimeDependencies{})
	if err != nil {
		t.Fatal(err)
	}
	for _, path := range []string{
		apiPrefix + "/assets",
		apiPrefix + "/rules",
		apiPrefix + "/publication-snapshot",
		"/v1/error-pages-neighbor/assets",
	} {
		request := httptest.NewRequest(http.MethodGet, "http://control.test"+path, nil)
		response := httptest.NewRecorder()
		handler.ServeHTTP(response, request)
		if response.Code != http.StatusNotFound {
			t.Fatalf("disabled path %s status=%d body=%s", path, response.Code, response.Body.String())
		}
	}
}

func TestRuntimeHandlerEnabledRejectsMissingProductionDependencies(t *testing.T) {
	valid := runtimeFactoryDependencies(t, "runtime-factory")
	tests := map[string]func(*RuntimeDependencies){
		"postgres": func(dependencies *RuntimeDependencies) { dependencies.Pool = nil },
		"identity": func(dependencies *RuntimeDependencies) { dependencies.Identity = nil },
		"api_keys": func(dependencies *RuntimeDependencies) { dependencies.APIKeys = nil },
		"iam":      func(dependencies *RuntimeDependencies) { dependencies.IAM = nil },
		"object_store": func(dependencies *RuntimeDependencies) {
			dependencies.ContentStore = nil
		},
		"scanner": func(dependencies *RuntimeDependencies) { dependencies.Scanner = nil },
		"limits":  func(dependencies *RuntimeDependencies) { dependencies.Limits = nil },
	}
	for name, remove := range tests {
		t.Run(name, func(t *testing.T) {
			dependencies := valid
			remove(&dependencies)
			handler, err := NewRuntimeHandler(RuntimeConfig{Enabled: true}, dependencies)
			if handler != nil || !errors.Is(err, ErrInvalidStore) {
				t.Fatalf("NewRuntimeHandler() = (%T,%v), want nil ErrInvalidStore", handler, err)
			}
		})
	}
}

func TestRuntimeHandlerEnabledRejectsZeroProductionDependencies(t *testing.T) {
	valid := runtimeFactoryDependencies(t, "runtime-factory-zero")
	tests := map[string]func(*RuntimeDependencies){
		"postgres": func(dependencies *RuntimeDependencies) { dependencies.Pool = new(pgxpool.Pool) },
		"identity": func(dependencies *RuntimeDependencies) { dependencies.Identity = new(identity.Service) },
		"iam":      func(dependencies *RuntimeDependencies) { dependencies.IAM = new(iamlock.Authorizer) },
	}
	for name, makeZero := range tests {
		t.Run(name, func(t *testing.T) {
			dependencies := valid
			makeZero(&dependencies)
			handler, err := NewRuntimeHandler(RuntimeConfig{Enabled: true}, dependencies)
			if handler != nil || !errors.Is(err, ErrInvalidStore) {
				t.Fatalf("NewRuntimeHandler() = (%T,%v), want nil ErrInvalidStore", handler, err)
			}
		})
	}
}

func TestRuntimeMetadataHandlerGeneratesCorrelation(t *testing.T) {
	inner := http.HandlerFunc(func(response http.ResponseWriter, request *http.Request) {
		response.Header().Set("X-Request-ID", request.Header.Get("X-Request-ID"))
		response.Header().Set("X-Trace-ID", request.Header.Get("X-Trace-ID"))
		response.WriteHeader(http.StatusNoContent)
	})
	request := httptest.NewRequest(http.MethodGet, "http://control.test"+apiPrefix+"/assets", nil)
	response := httptest.NewRecorder()
	runtimeMetadataHandler{inner: inner}.ServeHTTP(response, request)
	requestID := response.Header().Get("X-Request-ID")
	if !writeMetadataPattern.MatchString(requestID) || response.Header().Get("X-Trace-ID") != requestID {
		t.Fatalf("request_id=%q trace_id=%q", requestID, response.Header().Get("X-Trace-ID"))
	}
}

func TestRuntimeMetadataHandlerRejectsInvalidCorrelationBeforeAuthentication(t *testing.T) {
	tests := []struct {
		name   string
		method string
		path   string
		header string
		values []string
	}{
		{name: "read duplicate request id", method: http.MethodGet, path: apiPrefix + "/publication-snapshot", header: "X-Request-ID", values: []string{"request-1", "request-2"}},
		{name: "read invalid request id", method: http.MethodGet, path: apiPrefix + "/publication-snapshot", header: "X-Request-ID", values: []string{"invalid request"}},
		{name: "read duplicate trace id", method: http.MethodGet, path: apiPrefix + "/publication-snapshot", header: "X-Trace-ID", values: []string{"trace-1", "trace-2"}},
		{name: "read invalid trace id", method: http.MethodGet, path: apiPrefix + "/publication-snapshot", header: "X-Trace-ID", values: []string{"invalid trace"}},
		{name: "write duplicate request id", method: http.MethodPost, path: apiPrefix + "/assets/initiate", header: "X-Request-ID", values: []string{"request-1", "request-2"}},
		{name: "write invalid request id", method: http.MethodPost, path: apiPrefix + "/assets/initiate", header: "X-Request-ID", values: []string{"invalid request"}},
		{name: "write duplicate trace id", method: http.MethodPost, path: apiPrefix + "/assets/initiate", header: "X-Trace-ID", values: []string{"trace-1", "trace-2"}},
		{name: "write invalid trace id", method: http.MethodPost, path: apiPrefix + "/assets/initiate", header: "X-Trace-ID", values: []string{"invalid trace"}},
	}
	for _, test := range tests {
		t.Run(test.name, func(t *testing.T) {
			auth := &reviewAuthenticator{actor: tenantRuntimeActor()}
			domain := &reviewPublicationDomain{fakeHTTPDomain: &fakeHTTPDomain{}}
			inner, err := NewHandler(domain, auth)
			if err != nil {
				t.Fatal(err)
			}
			request := httptest.NewRequest(test.method, "http://control.test"+test.path, nil)
			request.Header.Set("X-Request-ID", "request-valid")
			request.Header.Set("X-Trace-ID", "trace-valid")
			request.Header.Del(test.header)
			for _, value := range test.values {
				request.Header.Add(test.header, value)
			}
			response := httptest.NewRecorder()
			runtimeMetadataHandler{inner: inner}.ServeHTTP(response, request)
			if response.Code != http.StatusBadRequest ||
				!strings.Contains(response.Body.String(), `"code":"invalid_request"`) ||
				auth.calls != 0 || domain.initiateCalls != 0 || domain.calls != 0 {
				t.Fatalf("status=%d body=%s auth_calls=%d initiate_calls=%d publication_calls=%d",
					response.Code, response.Body.String(), auth.calls, domain.initiateCalls, domain.calls)
			}
		})
	}
}

func TestRuntimeHTTPErrorRequestCorrelation(t *testing.T) {
	tests := []struct {
		name          string
		requestID     string
		wantCode      string
		wantRequestID string
	}{
		{name: "present", requestID: "caller-request", wantCode: "authentication_required", wantRequestID: "caller-request"},
		{name: "missing", wantCode: "authentication_required"},
		{name: "invalid", requestID: "invalid request", wantCode: "invalid_request"},
	}
	for _, test := range tests {
		t.Run(test.name, func(t *testing.T) {
			inner, err := NewHandler(&fakeHTTPDomain{}, fixedAuthenticator{err: ErrUnauthenticated})
			if err != nil {
				t.Fatal(err)
			}
			request := httptest.NewRequest(http.MethodGet, "http://control.test"+apiPrefix+"/assets", nil)
			if test.requestID != "" {
				request.Header.Set("X-Request-ID", test.requestID)
			}
			response := httptest.NewRecorder()
			runtimeMetadataHandler{inner: inner}.ServeHTTP(response, request)
			var body struct {
				Error struct {
					Code      string `json:"code"`
					RequestID string `json:"request_id"`
				} `json:"error"`
			}
			if err := json.Unmarshal(response.Body.Bytes(), &body); err != nil {
				t.Fatal(err)
			}
			responseRequestID := response.Header().Get("X-Request-ID")
			if body.Error.Code != test.wantCode || !writeMetadataPattern.MatchString(body.Error.RequestID) ||
				responseRequestID != body.Error.RequestID ||
				test.wantRequestID != "" && body.Error.RequestID != test.wantRequestID ||
				test.requestID == "invalid request" && body.Error.RequestID == test.requestID {
				t.Fatalf("status=%d header_request_id=%q body=%s", response.Code, responseRequestID, response.Body.String())
			}
		})
	}
}

func TestNormalizeServiceErrorHidesDependencyDetails(t *testing.T) {
	err := normalizeServiceError(errors.New("SQLSTATE 57P01 bucket=/secret/path"))
	if !errors.Is(err, ErrUnavailable) {
		t.Fatalf("normalizeServiceError()=%v, want ErrUnavailable", err)
	}
	for _, secret := range []string{"57P01", "bucket", "/secret/path"} {
		if strings.Contains(err.Error(), secret) {
			t.Fatalf("normalized error leaked %q: %v", secret, err)
		}
	}
	if got := normalizeServiceError(ErrPermissionDenied); !errors.Is(got, ErrPermissionDenied) {
		t.Fatalf("known error changed: %v", got)
	}
}

func runtimeFactoryDependencies(t *testing.T, scannerName string) RuntimeDependencies {
	t.Helper()
	config, err := pgxpool.ParseConfig("postgres://runtime_factory@127.0.0.1:1/runtime_factory?sslmode=disable")
	if err != nil {
		t.Fatal(err)
	}
	pool, err := pgxpool.NewWithConfig(t.Context(), config)
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(pool.Close)
	tokens, err := identity.NewTokenManager(strings.Repeat("runtime-factory-secret-", 2), time.Hour)
	if err != nil {
		t.Fatal(err)
	}
	identityService, err := identity.NewService(identity.NewStore(pool), tokens, time.Hour)
	if err != nil {
		t.Fatal(err)
	}
	sessions, err := sessioncredential.NewVerifier(tokens, time.Now)
	if err != nil {
		t.Fatal(err)
	}
	pepper := []byte(strings.Repeat("p", 32))
	apiKeyVerifier, err := apikeycredential.NewVerifier(pepper, time.Now)
	if err != nil {
		t.Fatal(err)
	}
	iam, err := iamlock.NewAuthorizer(sessions, apiKeyVerifier)
	if err != nil {
		t.Fatal(err)
	}
	return RuntimeDependencies{
		Pool: pool, Identity: identityService, APIKeys: apikey.NewService(pool, pepper, time.Now), IAM: iam,
		ContentStore: newMemoryContentStore(), Scanner: &testScanner{name: scannerName},
		Limits: runtimeLimits(),
	}
}
