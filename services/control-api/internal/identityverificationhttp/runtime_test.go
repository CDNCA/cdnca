package identityverificationhttp

import (
	"bytes"
	"context"
	"errors"
	"net/http"
	"net/http/httptest"
	"testing"
	"time"

	"github.com/cdnca/cdnca/services/control-api/internal/apikeycredential"
	"github.com/cdnca/cdnca/services/control-api/internal/iamlock"
	"github.com/cdnca/cdnca/services/control-api/internal/identity"
	"github.com/cdnca/cdnca/services/control-api/internal/identityverification"
	"github.com/cdnca/cdnca/services/control-api/internal/sessioncredential"
	"github.com/google/uuid"
	"github.com/jackc/pgx/v5"
	"github.com/jackc/pgx/v5/pgxpool"
)

type reviewListAuthorizerStub struct{}

func (reviewListAuthorizerStub) AuthorizeReviewerList(
	context.Context,
	pgx.Tx,
	identityverification.Actor,
) error {
	return nil
}

func (reviewListAuthorizerStub) AuthorizePlatformAdminList(
	context.Context,
	pgx.Tx,
	identityverification.PlatformAdmin,
) error {
	return nil
}

func TestRuntimeHandlerDisabledReturnsClosed404WithoutDependencies(t *testing.T) {
	dependencies := runtimeUnitDependencies(t)
	dependencies.Resolver = resolverStub{configuredCheck: func() bool {
		t.Fatal("disabled runtime touched resolver readiness")
		return false
	}}
	handler, err := NewRuntimeHandler(RuntimeConfig{}, dependencies)
	if err != nil {
		t.Fatal(err)
	}
	response := httptest.NewRecorder()
	handler.ServeHTTP(response, httptest.NewRequest(http.MethodGet,
		apiPrefix+"/cases/00000000-0000-0000-0000-000000000001", nil))
	if response.Code != http.StatusNotFound {
		t.Fatalf("disabled runtime status=%d, want 404", response.Code)
	}
}

func TestRuntimeHandlerRejectsNilTypedNilAndZeroDependencies(t *testing.T) {
	valid := runtimeUnitDependencies(t)
	var typedNilResolver *resolverStub
	tests := map[string]func(*RuntimeDependencies){
		"nil pool":           func(value *RuntimeDependencies) { value.Pool = nil },
		"zero pool":          func(value *RuntimeDependencies) { value.Pool = new(pgxpool.Pool) },
		"nil identity":       func(value *RuntimeDependencies) { value.Identity = nil },
		"zero identity":      func(value *RuntimeDependencies) { value.Identity = new(identity.Service) },
		"nil IAM":            func(value *RuntimeDependencies) { value.IAM = nil },
		"zero IAM":           func(value *RuntimeDependencies) { value.IAM = new(iamlock.Authorizer) },
		"nil resolver":       func(value *RuntimeDependencies) { value.Resolver = nil },
		"typed nil resolver": func(value *RuntimeDependencies) { value.Resolver = typedNilResolver },
		"zero resolver":      func(value *RuntimeDependencies) { value.Resolver = resolverStub{} },
		"panicking resolver": func(value *RuntimeDependencies) {
			value.Resolver = resolverStub{configuredCheck: func() bool { panic("readiness failure") }}
		},
	}
	for name, invalidate := range tests {
		t.Run(name, func(t *testing.T) {
			dependencies := valid
			invalidate(&dependencies)
			handler, err := NewRuntimeHandler(RuntimeConfig{Enabled: true,
				Service: ServiceConfig{CursorKey: bytes.Repeat([]byte{0x71}, 32)}}, dependencies)
			if handler != nil || !errors.Is(err, ErrInvalidService) {
				t.Fatalf("NewRuntimeHandler() = (%T,%v), want nil ErrInvalidService", handler, err)
			}
		})
	}

	t.Run("zero cursor key", func(t *testing.T) {
		handler, err := NewRuntimeHandler(RuntimeConfig{Enabled: true}, valid)
		if handler != nil || !errors.Is(err, ErrInvalidService) {
			t.Fatalf("zero cursor runtime = (%T,%v)", handler, err)
		}
	})
}

func TestRuntimeHandlerOwnsProductionSessionAndIAMAssembly(t *testing.T) {
	handler, err := NewRuntimeHandler(RuntimeConfig{Enabled: true,
		Service: ServiceConfig{CursorKey: bytes.Repeat([]byte{0x72}, 32)}}, runtimeUnitDependencies(t))
	if err != nil {
		t.Fatal(err)
	}
	if handler == nil || handler.Handler() == nil {
		t.Fatalf("runtime handler = %#v", handler)
	}
}

func TestRuntimeHandlerRejectsBearerAPIKey(t *testing.T) {
	handler, err := NewRuntimeHandler(RuntimeConfig{Enabled: true,
		Service: ServiceConfig{CursorKey: bytes.Repeat([]byte{0x74}, 32)}}, runtimeUnitDependencies(t))
	if err != nil {
		t.Fatal(err)
	}
	request := httptest.NewRequest(http.MethodGet,
		apiPrefix+"/cases/00000000-0000-0000-0000-000000000002", nil)
	request.Header.Set("Authorization", "Bearer cdnca_api_key_not_a_control_session")
	response := httptest.NewRecorder()
	handler.ServeHTTP(response, request)
	if response.Code != http.StatusUnauthorized {
		t.Fatalf("Bearer API key status=%d body=%s", response.Code, response.Body.String())
	}
}

func TestPostgresReaderConstructorsFailClosedBeforeBusinessQueries(t *testing.T) {
	dependencies := runtimeUnitDependencies(t)
	actor, err := identityverification.NewSessionActor(uuid.New(), uuid.New(), "tenant", uuid.New(),
		"control-api-session-reader-constructor-test")
	if err != nil {
		t.Fatal(err)
	}
	query := CasePageQuery{Limit: 10}

	generic, err := NewPostgresReader(dependencies.Pool)
	if err != nil {
		t.Fatal(err)
	}
	for name, reader := range map[string]*PostgresReader{
		"generic": generic,
		"nil":     nil,
		"zero":    new(PostgresReader),
	} {
		t.Run(name, func(t *testing.T) {
			items, listErr := reader.ListCases(t.Context(), actor, query)
			if len(items) != 0 || !errors.Is(listErr, ErrPermissionDenied) {
				t.Fatalf("ListCases() = %#v, %v, want no items and permission denied", items, listErr)
			}
		})
	}

	var typedNil *identityverification.Service
	for name, test := range map[string]struct {
		pool       *pgxpool.Pool
		authorizer reviewListAuthorizer
	}{
		"nil authorizer":       {pool: dependencies.Pool},
		"typed nil authorizer": {pool: dependencies.Pool, authorizer: typedNil},
		"zero pool":            {pool: new(pgxpool.Pool), authorizer: reviewListAuthorizerStub{}},
	} {
		t.Run(name, func(t *testing.T) {
			reader, readerErr := newPostgresReader(test.pool, test.authorizer)
			if reader != nil || !errors.Is(readerErr, ErrInvalidService) {
				t.Fatalf("newPostgresReader() = (%T, %v), want nil ErrInvalidService", reader, readerErr)
			}
		})
	}
}

func runtimeUnitDependencies(t *testing.T) RuntimeDependencies {
	t.Helper()
	config, err := pgxpool.ParseConfig("postgresql://runtime:runtime@127.0.0.1:1/runtime?sslmode=disable")
	if err != nil {
		t.Fatal(err)
	}
	pool, err := pgxpool.NewWithConfig(context.Background(), config)
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(pool.Close)
	tokens, err := identity.NewTokenManager("identity-verification-runtime-unit-secret-2026", time.Hour)
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
	apiKeys, err := apikeycredential.NewVerifier(bytes.Repeat([]byte{0x73}, 32), time.Now)
	if err != nil {
		t.Fatal(err)
	}
	authorizer, err := iamlock.NewAuthorizer(sessions, apiKeys)
	if err != nil {
		t.Fatal(err)
	}
	return RuntimeDependencies{Pool: pool, Identity: identityService, IAM: authorizer,
		Resolver: resolverStub{configured: true}, SettlementPublisher: runtimePublisherStub{configured: true},
		Clock: time.Now}
}
