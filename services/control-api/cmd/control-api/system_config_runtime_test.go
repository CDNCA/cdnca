package main

import (
	"context"
	"errors"
	"go/ast"
	"go/parser"
	"go/token"
	"os"
	"strings"
	"testing"

	"github.com/cdnca/cdnca/services/control-api/internal/systemconfig"
	"github.com/cdnca/cdnca/services/control-api/internal/systemconfighttp"
	"github.com/google/uuid"
	"github.com/jackc/pgx/v5"
)

type rejectingSystemConfigurationExpansion struct{}

func (rejectingSystemConfigurationExpansion) AuthorizeSystemConfigurationExpansion(
	context.Context,
	pgx.Tx,
	systemconfig.ExpansionCheck,
) error {
	return systemconfig.ErrEntitlementDenied
}

func TestLoadSystemConfigurationRuntimeConfigFromEnv(t *testing.T) {
	t.Parallel()

	tests := []struct {
		name        string
		environment []string
		enabled     bool
		errorText   string
	}{
		{name: "missing is disabled"},
		{name: "false is disabled", environment: []string{systemConfigurationRuntimeEnabledEnv + "=false"}},
		{name: "true is enabled", environment: []string{systemConfigurationRuntimeEnabledEnv + "=true"}, enabled: true},
		{name: "empty is disabled", environment: []string{systemConfigurationRuntimeEnabledEnv + "="}},
		{name: "uppercase is rejected", environment: []string{systemConfigurationRuntimeEnabledEnv + "=TRUE"}, errorText: "must be true or false"},
		{name: "whitespace is rejected", environment: []string{systemConfigurationRuntimeEnabledEnv + "= true"}, errorText: "must be true or false"},
		{name: "duplicate is rejected", environment: []string{systemConfigurationRuntimeEnabledEnv + "=false", systemConfigurationRuntimeEnabledEnv + "=true"}, errorText: "must be defined exactly once"},
		{name: "enabled unknown field is rejected", environment: []string{systemConfigurationRuntimeEnabledEnv + "=true", "SYSTEM_CONFIGURATION_RUNTIME_MODE=unsafe"}, errorText: "unsupported environment structure"},
		{name: "disabled unknown field is ignored", environment: []string{systemConfigurationRuntimeEnabledEnv + "=false", "SYSTEM_CONFIGURATION_RUNTIME_MODE=unsafe"}},
	}

	for _, test := range tests {
		test := test
		t.Run(test.name, func(t *testing.T) {
			t.Parallel()
			config, err := loadSystemConfigurationRuntimeConfigFromEnv(test.environment)
			if test.errorText != "" {
				if err == nil || !strings.Contains(err.Error(), test.errorText) {
					t.Fatalf("error = %v, want containing %q", err, test.errorText)
				}
				return
			}
			if err != nil {
				t.Fatalf("load config: %v", err)
			}
			if config.Enabled != test.enabled {
				t.Fatalf("enabled = %t, want %t", config.Enabled, test.enabled)
			}
		})
	}
}

func TestBuildSystemConfigurationHandlerFactory(t *testing.T) {
	t.Parallel()

	factory, err := buildSystemConfigurationHandlerFactory(systemConfigurationRuntimeConfig{}, systemConfigurationRuntimeDependencies{})
	if err != nil || factory != nil {
		t.Fatalf("disabled factory = (%v, %v), want (nil, nil)", factory, err)
	}

	_, err = buildSystemConfigurationHandlerFactory(
		systemConfigurationRuntimeConfig{Enabled: true},
		systemConfigurationRuntimeDependencies{Expansion: rejectingSystemConfigurationExpansion{}},
	)
	if err == nil || !strings.Contains(err.Error(), "dependencies are incomplete") {
		t.Fatalf("enabled incomplete dependencies error = %v", err)
	}
}

func TestSystemConfigurationRuntimeFailsClosedWithoutProductionDependencies(t *testing.T) {
	if _, err := NewSystemConfigurationRuntimeHandler(nil, nil, nil, nil); !errors.Is(err, systemconfighttp.ErrInvalidDependencies) {
		t.Fatalf("error = %v, want ErrInvalidDependencies", err)
	}
}

type systemConfigurationExpansionTestTx struct{ pgx.Tx }

func TestSystemConfigurationProductionExpansionAuthorizerAllowsCanonicalNonMeteredCategories(t *testing.T) {
	authorizer := denySystemConfigurationExpansion{}
	actor := systemconfig.Actor{UserID: uuid.New(), ScopeID: uuid.New(), ScopeKind: "platform"}
	tx := &systemConfigurationExpansionTestTx{}
	for _, category := range []string{
		systemconfig.CategoryNginx,
		systemconfig.CategoryResources,
		systemconfig.CategoryDefaults,
	} {
		t.Run(category, func(t *testing.T) {
			err := authorizer.AuthorizeSystemConfigurationExpansion(t.Context(), tx, systemconfig.ExpansionCheck{
				Actor: actor, Category: category, RequestID: "canonical-" + category,
			})
			if err != nil {
				t.Fatalf("canonical non-metered category authorization error = %v", err)
			}
		})
	}
}

func TestSystemConfigurationProductionExpansionAuthorizerDeniesOutsideCanonicalBoundary(t *testing.T) {
	authorizer := denySystemConfigurationExpansion{}
	platform := systemconfig.Actor{UserID: uuid.New(), ScopeID: uuid.New(), ScopeKind: "platform"}
	tenant := systemconfig.Actor{UserID: uuid.New(), ScopeID: uuid.New(), ScopeKind: "tenant"}
	tx := &systemConfigurationExpansionTestTx{}
	tests := []struct {
		name    string
		ctx     context.Context
		tx      pgx.Tx
		check   systemconfig.ExpansionCheck
		wantErr error
	}{
		{name: "tenant owner", ctx: t.Context(), tx: tx, check: systemconfig.ExpansionCheck{
			Actor: tenant, Category: systemconfig.CategoryNginx, RequestID: "tenant-nginx",
		}, wantErr: systemconfig.ErrEntitlementDenied},
		{name: "entitlement mapped error pages", ctx: t.Context(), tx: tx, check: systemconfig.ExpansionCheck{
			Actor: platform, Category: systemconfig.CategoryErrorPages, RequestID: "error-pages",
		}, wantErr: systemconfig.ErrEntitlementDenied},
		{name: "secrets", ctx: t.Context(), tx: tx, check: systemconfig.ExpansionCheck{
			Actor: platform, Category: systemconfig.CategorySecrets, RequestID: "secrets",
		}, wantErr: systemconfig.ErrEntitlementDenied},
		{name: "node monitoring", ctx: t.Context(), tx: tx, check: systemconfig.ExpansionCheck{
			Actor: platform, Category: systemconfig.CategoryNodeMonitoring, RequestID: "node-monitoring",
		}, wantErr: systemconfig.ErrEntitlementDenied},
		{name: "unknown category", ctx: t.Context(), tx: tx, check: systemconfig.ExpansionCheck{
			Actor: platform, Category: "unknown", RequestID: "unknown",
		}, wantErr: systemconfig.ErrEntitlementDenied},
		{name: "missing actor", ctx: t.Context(), tx: tx, check: systemconfig.ExpansionCheck{
			Category: systemconfig.CategoryResources, RequestID: "missing-actor",
		}, wantErr: systemconfig.ErrEntitlementDenied},
		{name: "missing request id", ctx: t.Context(), tx: tx, check: systemconfig.ExpansionCheck{
			Actor: platform, Category: systemconfig.CategoryDefaults,
		}, wantErr: systemconfig.ErrEntitlementDenied},
		{name: "missing transaction", ctx: t.Context(), check: systemconfig.ExpansionCheck{
			Actor: platform, Category: systemconfig.CategoryNginx, RequestID: "missing-tx",
		}, wantErr: systemconfig.ErrEntitlementDenied},
		{name: "missing context", tx: tx, check: systemconfig.ExpansionCheck{
			Actor: platform, Category: systemconfig.CategoryNginx, RequestID: "missing-context",
		}, wantErr: systemconfig.ErrEntitlementDenied},
	}
	for _, test := range tests {
		t.Run(test.name, func(t *testing.T) {
			err := authorizer.AuthorizeSystemConfigurationExpansion(test.ctx, test.tx, test.check)
			if !errors.Is(err, test.wantErr) {
				t.Fatalf("error = %v, want %v", err, test.wantErr)
			}
		})
	}
}

func TestSystemConfigurationProductionExpansionAuthorizerSavesCanonicalNonMeteredCategories(t *testing.T) {
	pool := newDashboardCompositionTestPool(t)
	actor := systemconfig.Actor{UserID: uuid.New(), ScopeID: uuid.New(), ScopeKind: "platform"}
	roleID := uuid.New()
	if _, err := pool.Exec(t.Context(), `INSERT INTO access_scopes(id,kind) VALUES($1,'platform');
		INSERT INTO users(id,username,display_name,password_hash) VALUES($2,$3,$3,'test-password-hash');
		INSERT INTO memberships(scope_id,user_id) VALUES($1,$2);
		INSERT INTO roles(id,scope_id,name,system_role) VALUES($4,$1,'platform_owner',true);
		INSERT INTO role_permissions(role_id,permission_name)
		VALUES($4,'system_configuration.read'),($4,'system_configuration.manage');
		INSERT INTO role_assignments(scope_id,user_id,role_id) VALUES($1,$2,$4)`,
		pgx.QueryExecModeSimpleProtocol, actor.ScopeID, actor.UserID, "system-config-runtime-admin", roleID); err != nil {
		t.Fatal(err)
	}
	service, err := systemconfig.NewService(pool)
	if err != nil {
		t.Fatal(err)
	}
	manager, err := systemconfig.NewCategoryManager(service, denySystemConfigurationExpansion{})
	if err != nil {
		t.Fatal(err)
	}
	bootstrap := systemconfig.ProjectBootstrapConfiguration()
	nginx := bootstrap.Nginx
	nginx.WorkerConnections++
	resources := bootstrap.Resources
	resources.MaxBlacklistIPsPerSite++
	defaults := bootstrap.Defaults
	defaults.Website.Origin.ResponseTimeoutSeconds++
	tests := []struct {
		category string
		change   systemconfig.CategoryChange
	}{
		{category: systemconfig.CategoryNginx, change: systemconfig.CategoryChange{Nginx: &nginx}},
		{category: systemconfig.CategoryResources, change: systemconfig.CategoryChange{Resources: &resources}},
		{category: systemconfig.CategoryDefaults, change: systemconfig.CategoryChange{Defaults: &defaults}},
	}
	for index, test := range tests {
		revision := int64(index)
		result, err := manager.SaveCategory(t.Context(), actor, systemconfig.SaveCategoryRequest{
			Category: test.category, ExpectedHeadRevision: revision, Change: test.change,
			IdempotencyKey: "runtime-save-" + test.category, RequestID: "runtime-save-" + test.category,
		})
		if err != nil {
			t.Fatalf("save %s: %v", test.category, err)
		}
		if result.HeadRevision != revision+1 || result.Revision != revision+1 || result.Status != systemconfig.StatusDraft {
			t.Fatalf("save %s result = %#v", test.category, result)
		}
	}

	tenantID, tenantScopeID, tenantUserID := uuid.New(), uuid.New(), uuid.New()
	if _, err := pool.Exec(t.Context(), `INSERT INTO tenants(id,display_name) VALUES($1,'runtime tenant');
		INSERT INTO access_scopes(id,kind,tenant_id) VALUES($2,'tenant',$1);
		INSERT INTO users(id,username,display_name,password_hash) VALUES($3,$4,$4,'test-password-hash');
		INSERT INTO memberships(scope_id,user_id) VALUES($2,$3)`,
		pgx.QueryExecModeSimpleProtocol, tenantID, tenantScopeID, tenantUserID, "system-config-runtime-tenant"); err != nil {
		t.Fatal(err)
	}
	nginx.WorkerConnections++
	_, err = manager.SaveCategory(t.Context(), systemconfig.Actor{
		UserID: tenantUserID, ScopeID: tenantScopeID, ScopeKind: "tenant",
	}, systemconfig.SaveCategoryRequest{
		Category: systemconfig.CategoryNginx, ExpectedHeadRevision: 3,
		Change:         systemconfig.CategoryChange{Nginx: &nginx},
		IdempotencyKey: "runtime-tenant-nginx", RequestID: "runtime-tenant-nginx",
	})
	if !errors.Is(err, systemconfig.ErrPermissionDenied) {
		t.Fatalf("tenant save error = %v, want ErrPermissionDenied", err)
	}
}

func TestRunServerComposesSystemConfigurationRuntime(t *testing.T) {
	fset := token.NewFileSet()
	parsed, err := parser.ParseFile(fset, "main.go", nil, 0)
	if err != nil {
		t.Fatal(err)
	}
	raw, err := os.ReadFile("main.go")
	if err != nil {
		t.Fatal(err)
	}
	var runServer *ast.FuncDecl
	for _, declaration := range parsed.Decls {
		function, ok := declaration.(*ast.FuncDecl)
		if ok && function.Name.Name == "runServer" {
			runServer = function
			break
		}
	}
	if runServer == nil || runServer.Body == nil {
		t.Fatal("runServer AST not found")
	}
	start := fset.Position(runServer.Body.Pos()).Offset
	end := fset.Position(runServer.Body.End()).Offset
	body := string(raw[start:end])
	for _, required := range []string{
		"loadSystemConfigurationRuntimeConfig()",
		"buildSystemConfigurationHandlerFactory(",
		"Expansion: denySystemConfigurationExpansion{Entitlement: entitlementguard.NewGuard(pool, time.Now, trust)}",
		"SystemConfigurationHandlerFactory:   systemConfigurationHandlerFactory",
		"api.InitializationError()",
	} {
		if !strings.Contains(body, required) {
			t.Errorf("runServer is missing system configuration composition %q", required)
		}
	}
}
