package main

import (
	"bytes"
	"context"
	"crypto/ed25519"
	"encoding/base64"
	"encoding/json"
	"errors"
	"log/slog"
	"net"
	"net/http"
	"net/http/httptest"
	"os"
	"path/filepath"
	"strings"
	"sync"
	"testing"
	"time"

	"github.com/cdnca/cdnca/services/control-api/internal/analytics"
	"github.com/cdnca/cdnca/services/control-api/internal/apikeycredential"
	"github.com/cdnca/cdnca/services/control-api/internal/cachecontrolhttp"
	"github.com/cdnca/cdnca/services/control-api/internal/config"
	"github.com/cdnca/cdnca/services/control-api/internal/dashboard"
	"github.com/cdnca/cdnca/services/control-api/internal/database"
	"github.com/cdnca/cdnca/services/control-api/internal/database/databasetest"
	"github.com/cdnca/cdnca/services/control-api/internal/entitlementguard"
	"github.com/cdnca/cdnca/services/control-api/internal/httpapi"
	"github.com/cdnca/cdnca/services/control-api/internal/iamlock"
	"github.com/cdnca/cdnca/services/control-api/internal/identity"
	"github.com/cdnca/cdnca/services/control-api/internal/mfahttp"
	"github.com/cdnca/cdnca/services/control-api/internal/sessioncredential"
	"github.com/google/uuid"
	"github.com/jackc/pgx/v5"
	"github.com/jackc/pgx/v5/pgxpool"
	"github.com/nats-io/nats.go"
)

func TestControlAPIProbeAddress(t *testing.T) {
	tests := []struct {
		name    string
		address *net.TCPAddr
		want    string
	}{
		{name: "IPv4", address: &net.TCPAddr{IP: net.ParseIP("192.0.2.1"), Port: 8080}, want: "192.0.2.1:8080"},
		{name: "IPv6", address: &net.TCPAddr{IP: net.ParseIP("2001:db8::1"), Port: 8080}, want: "[2001:db8::1]:8080"},
		{name: "scoped IPv6", address: &net.TCPAddr{IP: net.ParseIP("fe80::1"), Port: 8080, Zone: "lo0"}, want: "[fe80::1%lo0]:8080"},
		{name: "port zero", address: &net.TCPAddr{IP: net.ParseIP("127.0.0.1")}, want: "127.0.0.1:0"},
	}
	for _, test := range tests {
		t.Run(test.name, func(t *testing.T) {
			if got := controlAPIProbeAddress(test.address); got != test.want {
				t.Fatalf("controlAPIProbeAddress(%v) = %q, want %q", test.address, got, test.want)
			}
		})
	}
}

func TestRuntimeStageErrorPreservesSafeCause(t *testing.T) {
	cause := errors.New("license service returned HTTP 409 (installation_key_mismatch)")
	err := runtimeStageError{stage: "initialize entitlement lease", err: cause}

	if got, want := err.Error(), "initialize entitlement lease"; got != want {
		t.Fatalf("Error() = %q, want %q", got, want)
	}
	if strings.Contains(err.Error(), cause.Error()) {
		t.Fatal("Error() exposed the underlying cause")
	}
	if !errors.Is(err, cause) {
		t.Fatal("runtime stage error does not unwrap its cause")
	}
}

func TestNodeSchedulerSharedCompositionContracts(t *testing.T) {
	mainSource, err := os.ReadFile("main.go")
	if err != nil {
		t.Fatal(err)
	}
	normalizedMainSource := strings.Join(strings.Fields(string(mainSource)), " ")
	for _, required := range []string{
		"loadNodeSchedulerRuntimeConfig()",
		"buildNodeSchedulerHandlerFactory(",
		"APIKeys: apikey.NewServiceWithPepperKeyring(pool, cfg.APIKeyPepperKeyring, time.Now)",
		"IAM: nodeSchedulerIAM, Loads: nil, Now: time.Now",
		"NodeSchedulerHandlerFactory:",
		"nodeSchedulerHandlerFactory,",
	} {
		if !strings.Contains(normalizedMainSource, required) {
			t.Errorf("main composition missing %q", required)
		}
	}

	rootOpenAPI, err := os.ReadFile("../../../../api/openapi/v1/control.yaml")
	if err != nil {
		t.Fatal(err)
	}
	for path, escaped := range map[string]string{
		"/v1/node-line-groups":                           "~1v1~1node-line-groups",
		"/v1/node-line-groups/{id}":                      "~1v1~1node-line-groups~1{id}",
		"/v1/node-line-groups/{id}/revisions/{revision}": "~1v1~1node-line-groups~1{id}~1revisions~1{revision}",
		"/v1/node-line-groups/{id}/decisions":            "~1v1~1node-line-groups~1{id}~1decisions",
		"/v1/node-line-groups/{id}/target-snapshots":     "~1v1~1node-line-groups~1{id}~1target-snapshots",
		"/v1/node-line-groups/{id}/rollback":             "~1v1~1node-line-groups~1{id}~1rollback",
		"/v1/node-line-groups/{id}/platform-default":     "~1v1~1node-line-groups~1{id}~1platform-default",
		"/v1/l2-configs":                                 "~1v1~1l2-configs",
		"/v1/l2-configs/{id}":                            "~1v1~1l2-configs~1{id}",
		"/v1/l2-conds":                                   "~1v1~1l2-conds",
		"/v1/l2-conds/{id}":                              "~1v1~1l2-conds~1{id}",
		"/v1/l2-nodes":                                   "~1v1~1l2-nodes",
		"/v1/l2-nodes/{id}":                              "~1v1~1l2-nodes~1{id}",
	} {
		reference := "  " + path + ":\n    $ref: '../../control-node-scheduling.openapi.yaml#/paths/" + escaped
		if !bytes.Contains(rootOpenAPI, []byte(reference)) {
			t.Errorf("root OpenAPI missing exact node scheduling reference %q", reference)
		}
	}

	contracts := map[string][]string{
		"../../../../infra/helm/cdnca/values.yaml": {
			"  nodeScheduling:\n    enabled: false",
		},
		"../../../../infra/helm/cdnca/values-development.yaml": {
			"  nodeScheduling:\n    enabled: false",
		},
		"../../../../infra/helm/cdnca/values-production.yaml": {
			"  nodeScheduling:\n    enabled: false",
		},
		"../../../../infra/helm/cdnca/values.schema.json": {
			`"nodeScheduling"`, `"enabled": {"type": "boolean"}`,
		},
		"../../../../infra/helm/cdnca/templates/control-api.yaml": {
			"- name: NODE_SCHEDULING_RUNTIME_ENABLED",
			"value: {{ .Values.controlApi.nodeScheduling.enabled | quote }}",
		},
	}
	for path, required := range contracts {
		document, err := os.ReadFile(path)
		if err != nil {
			t.Fatal(err)
		}
		for _, text := range required {
			if !bytes.Contains(document, []byte(text)) {
				t.Errorf("%s missing %q", path, text)
			}
		}
	}
}

func TestCertificateAssetProductionHandlerFactory(t *testing.T) {
	poolConfig, err := pgxpool.ParseConfig("postgresql://certificate:certificate@127.0.0.1:1/certificate?sslmode=disable")
	if err != nil {
		t.Fatal(err)
	}
	pool, err := pgxpool.NewWithConfig(t.Context(), poolConfig)
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(pool.Close)
	tokens, err := identity.NewTokenManager(strings.Repeat("certificate-runtime-secret-", 2), time.Hour)
	if err != nil {
		t.Fatal(err)
	}
	identityService, err := identity.NewService(identity.NewStore(pool), tokens, time.Hour)
	if err != nil {
		t.Fatal(err)
	}

	disabled, err := buildCertificateAssetHandlerFactory(config.Config{}, nil, nil)
	if err != nil || disabled != nil {
		t.Fatalf("disabled certificate asset factory = %v, error = %v", disabled, err)
	}
	factory, err := buildCertificateAssetHandlerFactory(config.Config{
		ACMERuntimeEnabled: true,
		ACMEWrappingKeyID:  "certificate-kek-v1",
		ACMEWrappingKey:    bytes.Repeat([]byte{0x51}, 32),
	}, pool, identityService)
	if err != nil || factory == nil {
		t.Fatalf("certificate asset factory = %v, error = %v", factory, err)
	}
	handler, err := factory()
	if err != nil || handler == nil {
		t.Fatalf("certificate asset handler = %v, error = %v", handler, err)
	}

	mainSource, err := os.ReadFile("main.go")
	if err != nil {
		t.Fatal(err)
	}
	mainSource = bytes.Join(bytes.Fields(mainSource), []byte(" "))
	for _, required := range []string{
		"buildCertificateAssetHandlerFactory(cfg, pool, identityService)",
		"loadCertificatePublicationStatusRuntimeConfig(cfg.ACMERuntimeEnabled)",
		"buildAndClearCertificatePublicationStatusHandlerFactory(",
		"CertificateAssetHandlerFactory: certificateAssetHandlerFactory,",
		"CertificatePublicationStatusHandlerFactory: certificatePublicationStatusHandlerFactory,",
	} {
		if !bytes.Contains(mainSource, []byte(required)) {
			t.Errorf("main certificate composition missing %q", required)
		}
	}
}

func TestNewDashboardHandlerRequiresSharedProductionDependencies(t *testing.T) {
	poolConfig, err := pgxpool.ParseConfig("postgresql://dashboard:dashboard@127.0.0.1:1/dashboard?sslmode=disable")
	if err != nil {
		t.Fatal(err)
	}
	pool, err := pgxpool.NewWithConfig(t.Context(), poolConfig)
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(pool.Close)
	tokens, err := identity.NewTokenManager(strings.Repeat("dashboard-runtime-secret-", 2), time.Hour)
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
	apiKeys, err := apikeycredential.NewVerifier(bytes.Repeat([]byte{0x44}, 32), time.Now)
	if err != nil {
		t.Fatal(err)
	}
	iam, err := iamlock.NewAuthorizer(sessions, apiKeys)
	if err != nil {
		t.Fatal(err)
	}
	analyticsService, err := analytics.NewService(dashboardQueryStoreStub{})
	if err != nil {
		t.Fatal(err)
	}

	handler, err := newDashboardHandler(pool, identityService, iam, analyticsService)
	if err != nil || handler == nil {
		t.Fatalf("newDashboardHandler() = (%T, %v), want production handler", handler, err)
	}
	for _, dependencies := range []struct {
		pool      *pgxpool.Pool
		identity  *identity.Service
		iam       *iamlock.Authorizer
		analytics *analytics.Service
	}{
		{identity: identityService, iam: iam, analytics: analyticsService},
		{pool: pool, iam: iam, analytics: analyticsService},
		{pool: pool, identity: identityService, analytics: analyticsService},
	} {
		if handler, err := newDashboardHandler(
			dependencies.pool, dependencies.identity, dependencies.iam, dependencies.analytics,
		); err == nil || handler != nil {
			t.Fatalf("newDashboardHandler(missing dependency) = (%T, %v), want fail closed", handler, err)
		}
	}
	if handler, err := newDashboardHandler(pool, identityService, iam, nil); err != nil || handler == nil {
		t.Fatalf("newDashboardHandler(without analytics) = (%T, %v), want degraded production handler", handler, err)
	}
}

func TestNewDashboardHandlerProductionRequests(t *testing.T) {
	pool := newDashboardCompositionTestPool(t)
	analyticsService, err := analytics.NewService(dashboardQueryStoreStub{})
	if err != nil {
		t.Fatal(err)
	}
	const password = "dashboard-composition-password"
	passwordHash, err := identity.HashPassword(password)
	if err != nil {
		t.Fatal(err)
	}
	identityStore := identity.NewStore(pool)
	bootstrap, err := identityStore.BootstrapPlatformUser(
		t.Context(), "dashboard-composition-admin", "Dashboard Composition Admin", passwordHash,
		"dashboard-composition-bootstrap",
	)
	if err != nil {
		t.Fatal(err)
	}
	tokens, err := identity.NewTokenManager(strings.Repeat("dashboard-composition-secret-", 2), time.Hour)
	if err != nil {
		t.Fatal(err)
	}
	identityService, err := identity.NewService(identityStore, tokens, 24*time.Hour)
	if err != nil {
		t.Fatal(err)
	}
	managed, err := identityService.CreateUser(t.Context(), identity.Actor{
		UserID: bootstrap.UserID, ScopeID: bootstrap.ScopeID, ScopeKind: "platform",
	}, identity.CreateUserInput{
		Username: "dashboard-composition-tenant", Password: password,
		Fields: identity.UserFields{DisplayName: "Dashboard Composition Tenant"}, Role: identity.UserRoleOwner,
		IdempotencyKey: "dashboard-composition-create-tenant", RequestID: "dashboard-composition-create-tenant",
	})
	if err != nil {
		t.Fatal(err)
	}
	sessions, err := sessioncredential.NewVerifier(tokens, time.Now)
	if err != nil {
		t.Fatal(err)
	}
	apiKeys, err := apikeycredential.NewVerifier(bytes.Repeat([]byte{0x44}, 32), time.Now)
	if err != nil {
		t.Fatal(err)
	}
	iam, err := iamlock.NewAuthorizer(sessions, apiKeys)
	if err != nil {
		t.Fatal(err)
	}
	handler, err := newDashboardHandler(pool, identityService, iam, analyticsService)
	if err != nil {
		t.Fatal(err)
	}
	platformAuth, err := identityService.Login(t.Context(), identity.LoginInput{
		Username: "dashboard-composition-admin", Password: password, ScopeID: &bootstrap.ScopeID,
	}, identity.RequestInfo{RequestID: "dashboard-composition-admin-login"})
	if err != nil {
		t.Fatal(err)
	}
	tenantAuth, err := identityService.Login(t.Context(), identity.LoginInput{
		Username: "dashboard-composition-tenant", Password: password, ScopeID: &managed.ScopeID,
	}, identity.RequestInfo{RequestID: "dashboard-composition-tenant-login"})
	if err != nil {
		t.Fatal(err)
	}

	for _, test := range []struct {
		name        string
		path        string
		accessToken string
	}{
		{name: "admin", path: "/v1/admin/dashboard?range=seven_days&timezone=UTC", accessToken: platformAuth.AccessToken},
		{name: "tenant", path: "/v1/dashboard?range=today&timezone=UTC", accessToken: tenantAuth.AccessToken},
	} {
		t.Run(test.name, func(t *testing.T) {
			defer func() {
				if recovered := recover(); recovered != nil {
					t.Fatalf("production dashboard request panicked with disabled analytics: %v", recovered)
				}
			}()
			request := httptest.NewRequest(http.MethodGet, test.path, nil)
			request.Header.Set("Authorization", "Bearer "+test.accessToken)
			response := httptest.NewRecorder()
			handler.ServeHTTP(response, request)
			if response.Code != http.StatusOK {
				t.Fatalf("GET %s status = %d body=%s", test.path, response.Code, response.Body.String())
			}
			var result struct {
				DashboardVersion uint16 `json:"dashboard_version"`
				Analytics        struct {
					Available bool   `json:"available"`
					Reason    string `json:"reason"`
				} `json:"analytics"`
			}
			if err := json.Unmarshal(response.Body.Bytes(), &result); err != nil {
				t.Fatal(err)
			}
			if result.DashboardVersion != dashboard.Version || !result.Analytics.Available || result.Analytics.Reason != "" {
				t.Fatalf("GET %s result = %+v", test.path, result)
			}
		})
	}
}

func newDashboardCompositionTestPool(t *testing.T) *pgxpool.Pool {
	t.Helper()
	databaseURL := strings.TrimSpace(os.Getenv("TEST_DATABASE_URL"))
	if databaseURL == "" {
		t.Skip("TEST_DATABASE_URL is not set")
	}
	ctx, cancel := context.WithTimeout(context.Background(), 30*time.Second)
	defer cancel()
	adminPool, err := pgxpool.New(ctx, databaseURL)
	if err != nil {
		t.Fatal(err)
	}
	schema := "dashboard_composition_" + strings.ReplaceAll(uuid.NewString(), "-", "")
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
	config.MaxConns = 4
	pool, err := pgxpool.NewWithConfig(ctx, config)
	if err != nil {
		_, _ = adminPool.Exec(context.Background(), "DROP SCHEMA "+identifier+" CASCADE")
		adminPool.Close()
		t.Fatal(err)
	}
	if err := database.Migrate(ctx, pool, "up"); err != nil {
		pool.Close()
		_, _ = adminPool.Exec(context.Background(), "DROP SCHEMA "+identifier+" CASCADE")
		adminPool.Close()
		t.Fatal(err)
	}
	t.Cleanup(func() {
		pool.Close()
		cleanupCtx, cleanupCancel := databasetest.CleanupContext()
		defer cleanupCancel()
		if _, err := adminPool.Exec(cleanupCtx, "DROP SCHEMA "+identifier+" CASCADE"); err != nil {
			t.Errorf("drop dashboard composition schema: %v", err)
		}
		adminPool.Close()
	})
	return pool
}

func TestLoadErrorPageRuntimeConfigDisabledIgnoresProductionDependencies(t *testing.T) {
	t.Setenv("ERROR_PAGE_RUNTIME_ENABLED", "false")
	t.Setenv("ERROR_PAGE_OBJECT_STORE_ENDPOINT", "not-an-endpoint")
	t.Setenv("ERROR_PAGE_CLAMD_SOCKET", "relative.sock")
	config, err := loadErrorPageRuntimeConfig()
	if err != nil || config.Enabled {
		t.Fatalf("loadErrorPageRuntimeConfig(disabled) = (%+v,%v)", config, err)
	}
}

func TestLoadErrorPageRuntimeConfigEnabledRequiresProductionDependencies(t *testing.T) {
	setValidErrorPageRuntimeEnvironment(t)
	for _, name := range []string{
		"ERROR_PAGE_OBJECT_STORE_ENDPOINT",
		"ERROR_PAGE_OBJECT_STORE_REGION",
		"ERROR_PAGE_OBJECT_STORE_BUCKET",
		"ERROR_PAGE_OBJECT_STORE_ACCESS_KEY_ID",
		"ERROR_PAGE_OBJECT_STORE_SECRET_ACCESS_KEY",
		"ERROR_PAGE_CLAMD_SOCKET",
	} {
		t.Run(name, func(t *testing.T) {
			t.Setenv(name, "")
			if config, err := loadErrorPageRuntimeConfig(); err == nil || config.Enabled {
				t.Fatalf("loadErrorPageRuntimeConfig() = (%+v,%v), want fail closed", config, err)
			}
		})
	}
}

func TestLoadErrorPageRuntimeConfigEnabledMapsFrozenAdapters(t *testing.T) {
	setValidErrorPageRuntimeEnvironment(t)
	config, err := loadErrorPageRuntimeConfig()
	if err != nil {
		t.Fatal(err)
	}
	if !config.Enabled || config.ObjectStore.Endpoint != "http://127.0.0.1:19000" ||
		config.ObjectStore.Region != "us-east-1" || config.ObjectStore.Bucket != "error-pages" ||
		config.ObjectStore.Prefix != "error-pages" || config.ObjectStore.MaxObjectSize != 1<<20 ||
		config.Scanner.SocketPath != "/tmp/cdnca-error-page-clamd.sock" {
		t.Fatalf("unexpected error page config: %+v", config)
	}
	credentials, err := config.ObjectStore.Credentials.Retrieve(t.Context())
	if err != nil || credentials.AccessKeyID != "error-page-access" ||
		credentials.SecretAccessKey != "error-page-secret" || credentials.SessionToken != "error-page-session" {
		t.Fatalf("unexpected object store credentials: access=%q secret_set=%t token_set=%t error=%v",
			credentials.AccessKeyID, credentials.SecretAccessKey != "", credentials.SessionToken != "", err)
	}
}

func TestRunRequiredErrorPageRuntimeReportsTerminalFailure(t *testing.T) {
	failures := make(chan error, 1)
	runRequiredErrorPageRuntime(t.Context(), fakeRuntimeWorker{run: func(context.Context) error { return nil }}, failures)
	select {
	case err := <-failures:
		if err == nil || err.Error() != "error page runtime stopped" {
			t.Fatalf("terminal error = %v", err)
		}
	default:
		t.Fatal("terminal error was not reported")
	}
}

func TestLoadMFARuntimeConfigStrictAndClearsOwnedKeys(t *testing.T) {
	active := base64.StdEncoding.EncodeToString(make([]byte, 32))
	previousBytes := make([]byte, 32)
	for index := range previousBytes {
		previousBytes[index] = 1
	}
	previous := base64.StdEncoding.EncodeToString(previousBytes)
	valid := []string{
		"MFA_ENABLED=true",
		"MFA_ENCRYPTION_ACTIVE_KEY_ID=active",
		`MFA_ENCRYPTION_KEYS_JSON={"active":"` + active + `","previous":"` + previous + `"}`,
	}
	config, err := loadMFARuntimeConfigFromEnvEntries(valid)
	if err != nil || !config.Enabled || config.ActiveKeyID != "active" || len(config.Keys) != 2 {
		t.Fatalf("load valid MFA config = (%+v, %v)", config, err)
	}
	retained := append([][]byte(nil), config.ownedSecrets...)
	config.clearSecrets()
	for index, secret := range retained {
		for _, value := range secret {
			if value != 0 {
				t.Fatalf("owned MFA secret %d was not cleared", index)
			}
		}
	}

	for _, entries := range [][]string{{"MFA_ENABLED=false"}} {
		config, err := loadMFARuntimeConfigFromEnvEntries(entries)
		if err != nil || config.Enabled {
			t.Fatalf("load disabled MFA config %#v = (%+v, %v)", entries, config, err)
		}
	}
	invalid := [][]string{
		nil,
		{"MFA_ENABLED="},
		{"MFA_ENABLED=false", "MFA_ENCRYPTION_ACTIVE_KEY_ID=active"},
		{"MFA_ENABLED=true"},
		append(append([]string(nil), valid...), "MFA_ENABLED=true"),
		{"MFA_ENABLED=true", "MFA_ENCRYPTION_ACTIVE_KEY_ID=active", `MFA_ENCRYPTION_KEYS_JSON={"active":"%%%"}`},
		{"MFA_ENABLED=true", "MFA_ENCRYPTION_ACTIVE_KEY_ID=active", `MFA_ENCRYPTION_KEYS_JSON={"active":"` + base64.StdEncoding.EncodeToString(make([]byte, 31)) + `"}`},
		{"MFA_ENABLED=true", "MFA_ENCRYPTION_ACTIVE_KEY_ID=unknown", `MFA_ENCRYPTION_KEYS_JSON={"active":"` + active + `"}`},
		{"MFA_ENABLED=true", "MFA_ENCRYPTION_ACTIVE_KEY_ID=active", `MFA_ENCRYPTION_KEYS_JSON={"active":"` + active + `","active":"` + active + `"}`},
		{"MFA_ENABLED=true", "MFA_ENCRYPTION_ACTIVE_KEY_ID=active", `MFA_ENCRYPTION_KEYS_JSON={"active":"` + active + `"}`, "MFA_UNKNOWN=value"},
	}
	for index, entries := range invalid {
		if config, err := loadMFARuntimeConfigFromEnvEntries(entries); err == nil || config.Enabled {
			t.Errorf("invalid MFA config %d = (%+v, %v), want fail closed", index, config, err)
		}
	}
}

func TestBuildAndClearMFARuntimeUsesProductionDependencies(t *testing.T) {
	active := base64.StdEncoding.EncodeToString(bytes.Repeat([]byte{0x4d}, 32))
	config, err := loadMFARuntimeConfigFromEnvEntries([]string{
		"MFA_ENABLED=true",
		"MFA_ENCRYPTION_ACTIVE_KEY_ID=active",
		`MFA_ENCRYPTION_KEYS_JSON={"active":"` + active + `"}`,
	})
	if err != nil {
		t.Fatal(err)
	}
	retained := append([][]byte(nil), config.ownedSecrets...)
	poolConfig, err := pgxpool.ParseConfig("postgresql://mfa:mfa@127.0.0.1:1/mfa?sslmode=disable")
	if err != nil {
		t.Fatal(err)
	}
	pool, err := pgxpool.NewWithConfig(t.Context(), poolConfig)
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(pool.Close)
	tokens, err := identity.NewTokenManager(strings.Repeat("mfa-production-runtime-secret-", 2), time.Hour)
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
	apiKeys, err := apikeycredential.NewVerifier(bytes.Repeat([]byte{0x50}, 32), time.Now)
	if err != nil {
		t.Fatal(err)
	}
	iam, err := iamlock.NewAuthorizer(sessions, apiKeys)
	if err != nil {
		t.Fatal(err)
	}
	runtime, cipher, err := buildAndClearMFARuntime(&config, mfaRuntimeDependencies{
		Pool: pool, Identity: identityService, IAM: iam,
	})
	if err != nil || runtime == nil || runtime.Handler() == nil ||
		runtime.StepUpConsumer() == nil || cipher == nil {
		t.Fatalf("production MFA runtime = (%T, %T, %v)", runtime, cipher, err)
	}
	for index, secret := range retained {
		if !bytes.Equal(secret, make([]byte, len(secret))) {
			t.Fatalf("production MFA config secret %d was not cleared", index)
		}
	}
	if err := runtime.Close(); err != nil {
		t.Fatal(err)
	}
	if err := cipher.Close(); err != nil {
		t.Fatal(err)
	}

	for _, invalidate := range []func(*mfaRuntimeDependencies){
		func(value *mfaRuntimeDependencies) { value.Pool = nil },
		func(value *mfaRuntimeDependencies) { value.Identity = nil },
		func(value *mfaRuntimeDependencies) { value.IAM = nil },
	} {
		config, err := loadMFARuntimeConfigFromEnvEntries([]string{
			"MFA_ENABLED=true", "MFA_ENCRYPTION_ACTIVE_KEY_ID=active",
			`MFA_ENCRYPTION_KEYS_JSON={"active":"` + active + `"}`,
		})
		if err != nil {
			t.Fatal(err)
		}
		dependencies := mfaRuntimeDependencies{Pool: pool, Identity: identityService, IAM: iam}
		invalidate(&dependencies)
		runtime, cipher, err := buildAndClearMFARuntime(&config, dependencies)
		if err == nil || runtime != nil || cipher != nil {
			t.Fatalf("invalid production MFA dependencies = (%T, %T, %v)", runtime, cipher, err)
		}
	}
}

func TestRunRequiredMFARuntimeReportsUnexpectedStopAndHonorsCancellation(t *testing.T) {
	runtime, err := mfahttp.NewRuntime(mfahttp.RuntimeConfig{}, mfahttp.RuntimeDependencies{})
	if err != nil {
		t.Fatal(err)
	}
	failures := make(chan error, 1)
	done := make(chan struct{})
	go func() {
		runRequiredMFARuntime(context.Background(), runtime, failures)
		close(done)
	}()
	waitForMFARuntimeRunning(t, runtime)
	if err := runtime.Close(); err != nil {
		t.Fatal(err)
	}
	<-done
	select {
	case err := <-failures:
		if err == nil || err.Error() != "MFA runtime stopped" {
			t.Fatalf("MFA terminal error = %v", err)
		}
	default:
		t.Fatal("unexpected MFA runtime stop was not reported")
	}

	runtime, err = mfahttp.NewRuntime(mfahttp.RuntimeConfig{}, mfahttp.RuntimeDependencies{})
	if err != nil {
		t.Fatal(err)
	}
	ctx, cancel := context.WithCancel(context.Background())
	done = make(chan struct{})
	go func() {
		runRequiredMFARuntime(ctx, runtime, failures)
		close(done)
	}()
	waitForMFARuntimeRunning(t, runtime)
	cancel()
	<-done
	select {
	case err := <-failures:
		t.Fatalf("canceled MFA runtime reported terminal error: %v", err)
	default:
	}
	if err := runtime.Close(); err != nil {
		t.Fatal(err)
	}
}

func TestMFARuntimeCanRestartBeforeClose(t *testing.T) {
	runtime, err := mfahttp.NewRuntime(mfahttp.RuntimeConfig{}, mfahttp.RuntimeDependencies{})
	if err != nil {
		t.Fatal(err)
	}
	for attempt := range 2 {
		ctx, cancel := context.WithCancel(context.Background())
		done := make(chan error, 1)
		go func() { done <- runtime.Run(ctx) }()
		waitForMFARuntimeRunning(t, runtime)
		cancel()
		if err := <-done; err != nil {
			t.Fatalf("MFA runtime attempt %d = %v", attempt, err)
		}
	}
	if err := runtime.Close(); err != nil {
		t.Fatal(err)
	}
}

func waitForMFARuntimeRunning(t *testing.T, runtime *mfahttp.Runtime) {
	t.Helper()
	deadline := time.NewTimer(5 * time.Second)
	defer deadline.Stop()
	for {
		probeCtx, cancel := context.WithCancel(context.Background())
		cancel()
		err := runtime.Run(probeCtx)
		if errors.Is(err, mfahttp.ErrRuntimeAlreadyRunning) {
			return
		}
		if err != nil {
			t.Fatalf("probe MFA runtime state: %v", err)
		}
		select {
		case <-deadline.C:
			t.Fatal("MFA runtime did not start")
		case <-time.After(time.Millisecond):
		}
	}
}

func setValidErrorPageRuntimeEnvironment(t *testing.T) {
	t.Helper()
	t.Setenv("ERROR_PAGE_RUNTIME_ENABLED", "true")
	t.Setenv("ERROR_PAGE_OBJECT_STORE_ENDPOINT", "http://127.0.0.1:19000")
	t.Setenv("ERROR_PAGE_OBJECT_STORE_REGION", "us-east-1")
	t.Setenv("ERROR_PAGE_OBJECT_STORE_BUCKET", "error-pages")
	t.Setenv("ERROR_PAGE_OBJECT_STORE_PREFIX", "error-pages")
	t.Setenv("ERROR_PAGE_OBJECT_STORE_ACCESS_KEY_ID", "error-page-access")
	t.Setenv("ERROR_PAGE_OBJECT_STORE_SECRET_ACCESS_KEY", "error-page-secret")
	t.Setenv("ERROR_PAGE_OBJECT_STORE_SESSION_TOKEN", "error-page-session")
	t.Setenv("ERROR_PAGE_CLAMD_SOCKET", "/tmp/cdnca-error-page-clamd.sock")
}

func TestInstallEntitlementRequiresBundleFile(t *testing.T) {
	if err := run([]string{"install-entitlement"}); err == nil {
		t.Fatal("install-entitlement without --bundle unexpectedly succeeded")
	}
	path := filepath.Join(t.TempDir(), "bundle.json")
	if err := os.WriteFile(path, []byte(`{"invalid":true}`), 0o600); err != nil {
		t.Fatalf("write invalid bundle: %v", err)
	}
	publicKey, _, err := ed25519.GenerateKey(nil)
	if err != nil {
		t.Fatalf("GenerateKey() error = %v", err)
	}
	trustedKeys, err := json.Marshal(map[string]any{"keys": []map[string]string{{
		"key_id": "main-test-key", "public_key": base64.RawURLEncoding.EncodeToString(publicKey),
	}}})
	if err != nil {
		t.Fatalf("marshal trusted keys: %v", err)
	}
	trustedKeysPath := filepath.Join(t.TempDir(), "trusted-keys.json")
	if err := os.WriteFile(trustedKeysPath, trustedKeys, 0o600); err != nil {
		t.Fatalf("write trusted keys: %v", err)
	}
	if err := run([]string{"install-entitlement", "--bundle", path, "--trusted-keys", trustedKeysPath}); !errors.Is(err, entitlementguard.ErrInvalidBundle) {
		t.Fatalf("install-entitlement invalid bundle error = %v", err)
	}
}

func TestFetchEntitlementRevocationRequiresOwnerInputs(t *testing.T) {
	if err := run([]string{"fetch-entitlement-revocation"}); err == nil {
		t.Fatal("fetch-entitlement-revocation without owner inputs unexpectedly succeeded")
	}
	if err := run([]string{"fetch-entitlement-revocation", "--license-service", "http://license.example.test",
		"--installation-id", "22222222-2222-4222-8222-222222222222", "--installation-key", "/missing"}); err == nil {
		t.Fatal("fetch-entitlement-revocation accepted an HTTPS-incompatible service or missing key")
	}
}

func TestOpenEdgeDeploymentRuntimeRedactsConnectionFailure(t *testing.T) {
	sentinel := errors.New("dial failed")
	cfg := config.Config{
		EdgeDeploymentNATSURL:        "nats://operator:super-secret@127.0.0.1:4222",
		EdgeDeploymentConnectTimeout: time.Second,
		ShutdownPeriod:               time.Second,
	}
	_, err := openEdgeDeploymentRuntime(context.Background(), cfg, new(pgxpool.Pool), slog.Default(),
		func(string, ...nats.Option) (*nats.Conn, error) { return nil, sentinel })
	if !errors.Is(err, sentinel) {
		t.Fatalf("openEdgeDeploymentRuntime() error = %v, want wrapped sentinel", err)
	}
	if err.Error() != "connect edge deployment NATS" || strings.Contains(err.Error(), "super-secret") {
		t.Fatalf("connection failure was not redacted: %v", err)
	}
}

func TestOpenEdgeDeploymentRuntimePassesTLSJWTOptions(t *testing.T) {
	const userJWT = "header.payload.signature"
	directory := t.TempDir()
	credentialsFile := filepath.Join(directory, "edge-deployment.creds")
	caFile := filepath.Join(directory, "edge-deployment-ca.pem")
	if err := os.WriteFile(credentialsFile, []byte(userJWT), 0o600); err != nil {
		t.Fatal(err)
	}
	_, caPEM := smtpTestCertificate(t)
	if err := os.WriteFile(caFile, caPEM, 0o600); err != nil {
		t.Fatal(err)
	}
	sentinel := errors.New("stop after option inspection")
	cfg := config.Config{
		EdgeDeploymentNATSURL:        "tls://127.0.0.1:4222",
		EdgeDeploymentNATSCredsFile:  credentialsFile,
		EdgeDeploymentNATSCAFile:     caFile,
		EdgeDeploymentConnectTimeout: 2 * time.Second,
		ShutdownPeriod:               3 * time.Second,
	}
	_, err := openEdgeDeploymentRuntime(context.Background(), cfg, new(pgxpool.Pool), slog.Default(),
		func(rawURL string, optionFunctions ...nats.Option) (*nats.Conn, error) {
			if rawURL != cfg.EdgeDeploymentNATSURL {
				t.Fatalf("NATS URL = %q", rawURL)
			}
			options := nats.GetDefaultOptions()
			for _, apply := range optionFunctions {
				if applyErr := apply(&options); applyErr != nil {
					t.Fatalf("apply NATS option: %v", applyErr)
				}
			}
			if options.Name != "cdnca-control-api-edge-deployment" ||
				options.Timeout != cfg.EdgeDeploymentConnectTimeout || options.ReconnectWait != time.Second ||
				options.DrainTimeout != cfg.ShutdownPeriod {
				t.Fatalf("bounded NATS options = %#v", options)
			}
			if !options.Secure || options.TLSConfig == nil || options.RootCAsCB == nil ||
				options.UserJWT == nil || options.SignatureCB == nil {
				t.Fatalf("TLS/JWT NATS options = %#v", options)
			}
			jwt, jwtErr := options.UserJWT()
			if jwtErr != nil || jwt != userJWT {
				t.Fatalf("NATS user JWT = (%q, %v)", jwt, jwtErr)
			}
			return nil, sentinel
		})
	if !errors.Is(err, sentinel) || err.Error() != "connect edge deployment NATS" {
		t.Fatalf("openEdgeDeploymentRuntime() error = %v", err)
	}
}

func TestOpenEdgeDeploymentRuntimeRedactsTLSOptionFailure(t *testing.T) {
	const urlSecret = "edge-url-secret"
	directory := t.TempDir()
	missingCAFile := filepath.Join(directory, "private-edge-ca.pem")
	cfg := config.Config{
		EdgeDeploymentNATSURL:        "tls://operator:" + urlSecret + "@127.0.0.1:4222",
		EdgeDeploymentNATSCredsFile:  filepath.Join(directory, "private-edge.creds"),
		EdgeDeploymentNATSCAFile:     missingCAFile,
		EdgeDeploymentConnectTimeout: time.Second,
		ShutdownPeriod:               time.Second,
	}
	_, err := openEdgeDeploymentRuntime(context.Background(), cfg, new(pgxpool.Pool), slog.Default(),
		func(_ string, optionFunctions ...nats.Option) (*nats.Conn, error) {
			options := nats.GetDefaultOptions()
			for _, apply := range optionFunctions {
				if applyErr := apply(&options); applyErr != nil {
					return nil, applyErr
				}
			}
			return nil, errors.New("expected missing CA option failure")
		})
	if err == nil || err.Error() != "connect edge deployment NATS" ||
		strings.Contains(err.Error(), urlSecret) || strings.Contains(err.Error(), missingCAFile) {
		t.Fatalf("TLS option failure was not redacted: %v", err)
	}
}

func TestOpenCacheControlProductionRuntimeDisabledDoesNotConnect(t *testing.T) {
	connectCalls := 0
	runtime, connection, err := openCacheControlProductionRuntime(
		context.Background(), cacheControlProductionConfig{}, cacheControlRuntimeDependencies{},
		func(string, ...nats.Option) (*nats.Conn, error) {
			connectCalls++
			return nil, errors.New("unexpected cache NATS connection")
		},
	)
	if err != nil || runtime != nil || connection != nil || connectCalls != 0 {
		t.Fatalf("disabled cache composition = (%v,%v,%v), connect calls=%d", runtime, connection, err, connectCalls)
	}
}

func TestOpenCacheControlProductionRuntimeRedactsConnectionFailure(t *testing.T) {
	sentinel := errors.New("dial failed")
	config := cacheControlProductionConfig{
		Runtime: cacheControlRuntimeConfig{Enabled: true},
		NATSURL: "nats://operator:super-secret@127.0.0.1:4222", NATSName: "cache-control-runtime",
		NATSConnectTimeout: time.Second, NATSReconnectWait: time.Second, NATSDrainTimeout: time.Second,
	}
	_, connection, err := openCacheControlProductionRuntime(
		context.Background(), config, cacheControlRuntimeDependencies{},
		func(string, ...nats.Option) (*nats.Conn, error) { return nil, sentinel },
	)
	if connection != nil || !errors.Is(err, sentinel) {
		t.Fatalf("cache control NATS failure = (%v,%v), want wrapped sentinel", connection, err)
	}
	if err.Error() != "connect cache control NATS" || strings.Contains(err.Error(), "super-secret") {
		t.Fatalf("cache control connection failure was not redacted: %v", err)
	}
}

func TestOpenCacheControlProductionRuntimeEnabledConnectsExactlyOnce(t *testing.T) {
	connectCalls := 0
	sentinel := errors.New("cache control test dial failed")
	config := cacheControlProductionConfig{
		Runtime: cacheControlRuntimeConfig{Enabled: true},
		NATSURL: "nats://127.0.0.1:4222", NATSName: "cache-control-runtime",
		NATSConnectTimeout: time.Second, NATSReconnectWait: time.Second, NATSDrainTimeout: time.Second,
	}
	runtime, connection, err := openCacheControlProductionRuntime(
		context.Background(), config, cacheControlRuntimeDependencies{},
		func(rawURL string, _ ...nats.Option) (*nats.Conn, error) {
			connectCalls++
			if rawURL != config.NATSURL {
				t.Fatalf("cache control NATS URL = %q", rawURL)
			}
			return nil, sentinel
		},
	)
	if !errors.Is(err, sentinel) || runtime != nil || connection != nil || connectCalls != 1 {
		t.Fatalf("enabled cache composition = (%v,%v,%v), connect calls=%d", runtime, connection, err, connectCalls)
	}
}

func TestCacheControlProductionCompositionMountsOnlyExactRoutesWhenEnabled(t *testing.T) {
	called := 0
	factory := func(cachecontrolhttp.AuthenticateFunc) (http.Handler, error) {
		return http.HandlerFunc(func(writer http.ResponseWriter, _ *http.Request) {
			called++
			writer.WriteHeader(http.StatusNoContent)
		}), nil
	}
	enabled := httpapi.New(nil, nil, httpapi.Config{APIKeyPepper: bytes.Repeat([]byte{0x52}, 32), CacheControlHandlerFactory: factory})
	if err := enabled.InitializationError(); err != nil {
		t.Fatal(err)
	}
	exact := []string{
		"/v1/cache-policies/00000000-0000-4000-8000-000000000001",
		"/v1/cache-policies/00000000-0000-4000-8000-000000000001/revisions",
		"/v1/cache-policies/00000000-0000-4000-8000-000000000001/revisions/1",
		"/v1/cache-operations",
		"/v1/cache-operations/00000000-0000-4000-8000-000000000001",
		"/v1/cache-operations/00000000-0000-4000-8000-000000000001/retry",
		"/v1/cache-operations/00000000-0000-4000-8000-000000000001/cancel",
		"/v1/admin/cache-policies/00000000-0000-4000-8000-000000000001",
		"/v1/admin/cache-policies/00000000-0000-4000-8000-000000000001/revisions",
		"/v1/admin/cache-policies/00000000-0000-4000-8000-000000000001/revisions/1",
		"/v1/admin/cache-operations",
		"/v1/admin/cache-operations/00000000-0000-4000-8000-000000000001",
		"/v1/admin/cache-operations/00000000-0000-4000-8000-000000000001/retry",
		"/v1/admin/cache-operations/00000000-0000-4000-8000-000000000001/cancel",
	}
	for _, path := range exact {
		response := httptest.NewRecorder()
		enabled.Handler().ServeHTTP(response, httptest.NewRequest(http.MethodGet, path, nil))
		if response.Code != http.StatusNoContent {
			t.Fatalf("exact cache route %q status=%d", path, response.Code)
		}
	}
	for _, path := range []string{
		"/v1/cache-control", "/v1/cache-operations/", "/v1/cache-operations/adjacent/history",
		"/v1/admin/cache-control", "/v1/admin/cache-operations/adjacent/history",
	} {
		response := httptest.NewRecorder()
		enabled.Handler().ServeHTTP(response, httptest.NewRequest(http.MethodGet, path, nil))
		if response.Code != http.StatusNotFound {
			t.Fatalf("cache alias %q status=%d, want 404", path, response.Code)
		}
	}
	if called != len(exact) {
		t.Fatalf("cache handler calls=%d, want %d", called, len(exact))
	}

	disabled := httpapi.New(nil, nil, httpapi.Config{})
	response := httptest.NewRecorder()
	disabled.Handler().ServeHTTP(response, httptest.NewRequest(http.MethodGet, "/v1/cache-operations", nil))
	if response.Code != http.StatusNotFound {
		t.Fatalf("disabled cache route status=%d, want 404", response.Code)
	}
}

func TestCloseCacheControlProductionResourcesOrdersOwnedLifecycle(t *testing.T) {
	operations := make([]string, 0, 4)
	dependencies := configuredCacheControlRuntimeDependencies(t)
	runtime := newCacheControlRuntimeTestSubject(dependencies, &fakeCacheControlWorker{
		configured: true,
		close: func() error {
			operations = append(operations, "worker", "local consumer")
			return nil
		},
	})
	connection := cacheControlCloseRecorder{close: func() {
		operations = append(operations, "unexpected fallback close")
	}, drain: func() error {
		operations = append(operations, "cache connection")
		return nil
	}}
	if err := closeCacheControlProductionResources(runtime, connection); err != nil {
		t.Fatal(err)
	}
	dependencies.Pool.Close()
	operations = append(operations, "PG")
	if got := strings.Join(operations, ","); got != "worker,local consumer,cache connection,PG" {
		t.Fatalf("cache control close order = %q", got)
	}
}

func TestCloseCacheControlProductionResourcesFallsBackAfterDrainFailure(t *testing.T) {
	sentinel := errors.New("drain failed")
	operations := make([]string, 0, 2)
	connection := cacheControlCloseRecorder{
		drain: func() error {
			operations = append(operations, "drain")
			return sentinel
		},
		close: func() { operations = append(operations, "close") },
	}
	err := closeCacheControlProductionResources(nil, connection)
	if !errors.Is(err, sentinel) || err.Error() != "drain cache control NATS" {
		t.Fatalf("cache control drain error = %v", err)
	}
	if got := strings.Join(operations, ","); got != "drain,close" {
		t.Fatalf("cache control drain fallback = %q", got)
	}
}

func TestValidateCacheControlShutdownPeriod(t *testing.T) {
	disabled := cacheControlProductionConfig{NATSDrainTimeout: time.Minute}
	if err := validateCacheControlShutdownPeriod(time.Second, disabled); err != nil {
		t.Fatalf("disabled cache shutdown validation: %v", err)
	}
	enabled := disabled
	enabled.Runtime.Enabled = true
	if err := validateCacheControlShutdownPeriod(time.Minute, enabled); err != nil {
		t.Fatalf("equal cache shutdown validation: %v", err)
	}
	if err := validateCacheControlShutdownPeriod(time.Minute-time.Nanosecond, enabled); err == nil {
		t.Fatal("short control API shutdown period was accepted")
	}
}

func TestCacheControlRuntimeHealthDetailUsesComponentReadiness(t *testing.T) {
	disabled := httptest.NewRecorder()
	withCacheControlRuntimeHealthDetail(http.NotFoundHandler(), nil, nil, nil).ServeHTTP(
		disabled, httptest.NewRequest(http.MethodGet, "/health/detail", nil),
	)
	var disabledHealth struct {
		CacheControl cacheControlRuntimeHealthSnapshot `json:"cache_control"`
	}
	if err := json.Unmarshal(disabled.Body.Bytes(), &disabledHealth); err != nil {
		t.Fatal(err)
	}
	if disabledHealth.CacheControl.Enabled || disabledHealth.CacheControl.State != "disabled" {
		t.Fatalf("disabled cache health = %#v", disabledHealth.CacheControl)
	}

	dependencies := configuredCacheControlRuntimeDependencies(t)
	started := make(chan struct{})
	runtime := newCacheControlRuntimeTestSubject(dependencies, &fakeCacheControlWorker{
		configured: true, waitForCancellation: true, started: started,
	})
	ctx, cancel := context.WithCancel(t.Context())
	runDone := make(chan error, 1)
	go func() { runDone <- runtime.Run(ctx) }()
	<-started
	ready := httptest.NewRecorder()
	withCacheControlRuntimeHealthDetail(http.NotFoundHandler(), nil, nil, runtime).ServeHTTP(
		ready, httptest.NewRequest(http.MethodGet, "/health/detail", nil),
	)
	var readyHealth struct {
		CacheControl cacheControlRuntimeHealthSnapshot `json:"cache_control"`
	}
	if err := json.Unmarshal(ready.Body.Bytes(), &readyHealth); err != nil {
		t.Fatal(err)
	}
	if !readyHealth.CacheControl.Enabled || readyHealth.CacheControl.State != "ready" {
		t.Fatalf("ready cache health = %#v", readyHealth.CacheControl)
	}
	cancel()
	if err := <-runDone; !errors.Is(err, context.Canceled) {
		t.Fatalf("stop cache control runtime: %v", err)
	}
	unavailable := httptest.NewRecorder()
	withCacheControlRuntimeHealthDetail(http.NotFoundHandler(), nil, nil, runtime).ServeHTTP(
		unavailable, httptest.NewRequest(http.MethodGet, "/health/detail", nil),
	)
	var unavailableHealth struct {
		CacheControl cacheControlRuntimeHealthSnapshot `json:"cache_control"`
	}
	if err := json.Unmarshal(unavailable.Body.Bytes(), &unavailableHealth); err != nil {
		t.Fatal(err)
	}
	if !unavailableHealth.CacheControl.Enabled || unavailableHealth.CacheControl.State != "unavailable" {
		t.Fatalf("unavailable cache health = %#v", unavailableHealth.CacheControl)
	}
}

func TestRunRequiredCacheControlRuntimeReportsEarlyExit(t *testing.T) {
	failures := make(chan error, 1)
	runRequiredCacheControlRuntime(context.Background(), nil, failures)
	if err := <-failures; err == nil || err.Error() != "cache control runtime stopped: required runtime is missing" {
		t.Fatalf("missing cache runtime error = %v", err)
	}

	workerErr := errors.New("cache worker failed")
	runtime := newCacheControlRuntimeTestSubject(
		configuredCacheControlRuntimeDependencies(t),
		&fakeCacheControlWorker{configured: true, runErr: workerErr},
	)
	runRequiredCacheControlRuntime(context.Background(), runtime, failures)
	if err := <-failures; err == nil || err.Error() != "cache control runtime stopped" || !errors.Is(err, workerErr) {
		t.Fatalf("cache runtime early exit error = %v", err)
	}
}

func TestRunRequiredWorkersPropagatesFailureAndCancelsPeers(t *testing.T) {
	sentinel := errors.New("publisher failed")
	peerCanceled := make(chan struct{})
	err := runRequiredWorkers(context.Background(), []runtimeWorker{
		fakeRuntimeWorker{run: func(context.Context) error { return sentinel }},
		fakeRuntimeWorker{run: func(ctx context.Context) error {
			<-ctx.Done()
			close(peerCanceled)
			return ctx.Err()
		}},
	})
	if !errors.Is(err, sentinel) {
		t.Fatalf("runRequiredWorkers() error = %v, want sentinel", err)
	}
	select {
	case <-peerCanceled:
	default:
		t.Fatal("peer worker was not canceled and joined")
	}
}

func TestRunRequiredWorkersReturnsAfterContextCancellation(t *testing.T) {
	ctx, cancel := context.WithCancel(context.Background())
	canceled := make(chan struct{}, 2)
	workers := []runtimeWorker{
		fakeRuntimeWorker{run: waitForCancellation(canceled)},
		fakeRuntimeWorker{run: waitForCancellation(canceled)},
	}
	cancel()
	if err := runRequiredWorkers(ctx, workers); !errors.Is(err, context.Canceled) {
		t.Fatalf("runRequiredWorkers() canceled error = %v", err)
	}
	if len(canceled) != len(workers) {
		t.Fatalf("joined canceled workers = %d, want %d", len(canceled), len(workers))
	}
}

func TestRunRequiredACMERuntimeReportsUnexpectedExit(t *testing.T) {
	for _, sentinel := range []error{errors.New("dispatcher invariant failed"), context.Canceled} {
		failures := make(chan error, 1)
		runRequiredACMERuntime(context.Background(), fakeRuntimeWorker{
			run: func(context.Context) error { return sentinel },
		}, failures)
		select {
		case err := <-failures:
			if !errors.Is(err, sentinel) || err.Error() != "ACME runtime stopped" {
				t.Fatalf("reported ACME runtime error = %v", err)
			}
		default:
			t.Fatalf("unexpected ACME runtime exit %v was not reported", sentinel)
		}
	}
}

func TestEdgeDeploymentRuntimeFailureChangesReadiness(t *testing.T) {
	sentinel := errors.New("status consumer failed")
	runtime := &edgeDeploymentRuntime{
		connection: fakeNATSRuntimeConnection{connected: true},
		workers: []runtimeWorker{
			fakeRuntimeWorker{run: func(context.Context) error { return sentinel }},
			fakeRuntimeWorker{run: func(ctx context.Context) error { <-ctx.Done(); return ctx.Err() }},
		},
	}
	runtime.ready.Store(true)
	if err := runtime.Ready(); err != nil {
		t.Fatalf("Ready() before worker failure = %v", err)
	}
	if err := runtime.Run(context.Background()); !errors.Is(err, sentinel) {
		t.Fatalf("Run() error = %v, want sentinel", err)
	}
	if err := runtime.Ready(); err == nil {
		t.Fatal("Ready() accepted stopped edge runtime")
	}
}

func TestEdgeDeploymentRuntimeCloseOrdersAndBoundsResources(t *testing.T) {
	var mu sync.Mutex
	var operations []string
	closed := make(chan struct{})
	connection := &fakeOrderedNATSConnection{
		connected: true,
		onDrain: func() {
			mu.Lock()
			operations = append(operations, "drain NATS")
			mu.Unlock()
			close(closed)
		},
		onClose: func() {
			mu.Lock()
			operations = append(operations, "close NATS")
			mu.Unlock()
		},
	}
	status := &fakeCloseableRuntimeWorker{close: func() error {
		mu.Lock()
		operations = append(operations, "close status consumer")
		mu.Unlock()
		return nil
	}}
	runtime := &edgeDeploymentRuntime{
		connection: connection, status: status, closed: closed, shutdownTimeout: time.Second,
	}
	runtime.ready.Store(true)
	if err := runtime.Close(); err != nil {
		t.Fatalf("Close() error = %v", err)
	}
	if err := runtime.Close(); err != nil {
		t.Fatalf("second Close() error = %v", err)
	}
	mu.Lock()
	defer mu.Unlock()
	if got := strings.Join(operations, ","); got != "close status consumer,drain NATS" {
		t.Fatalf("shutdown operations = %q", got)
	}
	if runtime.ready.Load() {
		t.Fatal("runtime remained ready during shutdown")
	}
}

func TestRequireReadinessRejectsOnlyUnhealthyReadyRequests(t *testing.T) {
	called := 0
	next := http.HandlerFunc(func(w http.ResponseWriter, _ *http.Request) {
		called++
		w.WriteHeader(http.StatusNoContent)
	})
	probe := &fakeReadinessProbe{err: errors.New("stopped")}
	handler := requireReadiness(next, probe)

	request := httptest.NewRequest(http.MethodGet, "/health/ready", nil)
	request.Header.Set("X-Request-ID", "invalid request id")
	response := httptest.NewRecorder()
	handler.ServeHTTP(response, request)
	if response.Code != http.StatusServiceUnavailable || called != 0 {
		t.Fatalf("unhealthy readiness status=%d called=%d", response.Code, called)
	}
	if response.Header().Get("X-Request-ID") == "invalid request id" ||
		!strings.Contains(response.Body.String(), "service_unavailable") {
		t.Fatalf("unhealthy readiness response headers=%v body=%q", response.Header(), response.Body.String())
	}

	probe.err = nil
	response = httptest.NewRecorder()
	handler.ServeHTTP(response, httptest.NewRequest(http.MethodGet, "/health/ready", nil))
	if response.Code != http.StatusNoContent || called != 1 {
		t.Fatalf("healthy readiness status=%d called=%d", response.Code, called)
	}

	probe.err = errors.New("stopped")
	response = httptest.NewRecorder()
	handler.ServeHTTP(response, httptest.NewRequest(http.MethodGet, "/health/live", nil))
	if response.Code != http.StatusNoContent || called != 2 {
		t.Fatalf("liveness was gated status=%d called=%d", response.Code, called)
	}
}

func TestValidateEdgeStreamInfoRequiresDurableCoveredStream(t *testing.T) {
	valid := &nats.StreamInfo{Config: nats.StreamConfig{
		Subjects: []string{"cdnca.agent.commands.>"}, Storage: nats.FileStorage,
		Replicas: 1, Duplicates: time.Minute, MaxMsgSize: 1 << 20,
	}}
	if err := validateEdgeStreamInfo(valid, "cdnca.agent.commands", 1<<20); err != nil {
		t.Fatalf("valid stream rejected: %v", err)
	}
	tests := []struct {
		name string
		info *nats.StreamInfo
	}{
		{name: "memory storage", info: &nats.StreamInfo{Config: nats.StreamConfig{Subjects: valid.Config.Subjects, Storage: nats.MemoryStorage, Replicas: 1, Duplicates: time.Minute}}},
		{name: "no deduplication", info: &nats.StreamInfo{Config: nats.StreamConfig{Subjects: valid.Config.Subjects, Storage: nats.FileStorage, Replicas: 1}}},
		{name: "small messages", info: &nats.StreamInfo{Config: nats.StreamConfig{Subjects: valid.Config.Subjects, Storage: nats.FileStorage, Replicas: 1, Duplicates: time.Minute, MaxMsgSize: 1024}}},
		{name: "one node only", info: &nats.StreamInfo{Config: nats.StreamConfig{Subjects: []string{"cdnca.agent.commands.00000000-0000-4000-8000-000000000001"}, Storage: nats.FileStorage, Replicas: 1, Duplicates: time.Minute}}},
		{name: "wrong subject", info: &nats.StreamInfo{Config: nats.StreamConfig{Subjects: []string{"other.>"}, Storage: nats.FileStorage, Replicas: 1, Duplicates: time.Minute}}},
	}
	for _, test := range tests {
		t.Run(test.name, func(t *testing.T) {
			if err := validateEdgeStreamInfo(test.info, "cdnca.agent.commands", 1<<20); err == nil {
				t.Fatal("invalid stream configuration was accepted")
			}
		})
	}
}

type fakeRuntimeWorker struct {
	run func(context.Context) error
}

func (w fakeRuntimeWorker) Run(ctx context.Context) error { return w.run(ctx) }

type fakeCloseableRuntimeWorker struct {
	run   func(context.Context) error
	close func() error
}

func (w *fakeCloseableRuntimeWorker) Run(ctx context.Context) error {
	if w.run == nil {
		<-ctx.Done()
		return ctx.Err()
	}
	return w.run(ctx)
}

func (w *fakeCloseableRuntimeWorker) Close() error { return w.close() }

type fakeNATSRuntimeConnection struct {
	connected bool
}

func (c fakeNATSRuntimeConnection) IsConnected() bool { return c.connected }
func (fakeNATSRuntimeConnection) IsClosed() bool      { return false }
func (fakeNATSRuntimeConnection) Drain() error        { return nil }
func (fakeNATSRuntimeConnection) Close()              {}

type fakeOrderedNATSConnection struct {
	connected bool
	closed    bool
	onDrain   func()
	onClose   func()
}

func (c *fakeOrderedNATSConnection) IsConnected() bool { return c.connected && !c.closed }
func (c *fakeOrderedNATSConnection) IsClosed() bool    { return c.closed }
func (c *fakeOrderedNATSConnection) Drain() error {
	c.onDrain()
	c.closed = true
	return nil
}
func (c *fakeOrderedNATSConnection) Close() {
	c.closed = true
	c.onClose()
}

type fakeReadinessProbe struct {
	err error
}

type cacheControlCloseRecorder struct {
	drain func() error
	close func()
}

func (recorder cacheControlCloseRecorder) Drain() error { return recorder.drain() }
func (recorder cacheControlCloseRecorder) Close()       { recorder.close() }

func (p *fakeReadinessProbe) Ready() error { return p.err }

func waitForCancellation(canceled chan<- struct{}) func(context.Context) error {
	return func(ctx context.Context) error {
		<-ctx.Done()
		canceled <- struct{}{}
		return ctx.Err()
	}
}

// dashboardQueryStoreStub is an empty analytics query store for the dashboard
// composition tests.
type dashboardQueryStoreStub struct{}

func (dashboardQueryStoreStub) Summary(context.Context, analytics.Scope, analytics.Filter) (analytics.Summary, error) {
	// 真实存储的空结果也带当前指标版本（query.go summary()），仪表盘按版本校验汇总与趋势一致
	return analytics.Summary{MetricVersion: analytics.MetricVersion}, nil
}

func (dashboardQueryStoreStub) Trend(context.Context, analytics.Scope, analytics.Filter) ([]analytics.TrendPoint, error) {
	return nil, nil
}

func (dashboardQueryStoreStub) Rank(_ context.Context, _ analytics.Scope, filter analytics.Filter,
	_ analytics.RankDimension, _ uint16, _ string,
) (analytics.RankPage, error) {
	// 真实存储回填请求的快照时间，仪表盘据此校验排行与汇总同一快照
	return analytics.RankPage{SnapshotAt: filter.SnapshotAt}, nil
}
