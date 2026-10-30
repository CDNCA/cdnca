package httppolicycontrol

import (
	"context"
	"errors"
	"strings"
	"testing"
	"time"

	"github.com/cdnca/cdnca/services/control-api/internal/entitlementguard"
	"github.com/cdnca/cdnca/services/control-api/internal/rbacmanager"
	"github.com/google/uuid"
	"github.com/jackc/pgx/v5"
	"github.com/jackc/pgx/v5/pgconn"
	"github.com/jackc/pgx/v5/pgxpool"
)

type tenantSessionAuthorizerStub struct {
	tenantID uuid.UUID
	err      error
	seen     rbacmanager.AuthenticatedSessionReference
	grant    string
}

func (stub *tenantSessionAuthorizerStub) AuthorizeTenantSessionTx(
	_ context.Context,
	_ pgx.Tx,
	session rbacmanager.AuthenticatedSessionReference,
	permission string,
) (uuid.UUID, error) {
	stub.seen = session
	stub.grant = permission
	return stub.tenantID, stub.err
}

func TestTenantSessionTxAuthorizerAcceptsOnlyMatchingTenantSession(t *testing.T) {
	tenantID := uuid.New()
	userID := uuid.New()
	scopeID := uuid.New()
	sessionID := uuid.New()
	stub := &tenantSessionAuthorizerStub{tenantID: tenantID}
	authorizer := tenantSessionTxAuthorizer{sessions: stub}
	actor := Actor{
		UserID: userID, ScopeID: scopeID, ScopeKind: "tenant",
		Credential: CredentialReference{Kind: CredentialKindSession, ID: sessionID},
	}

	actualTenantID, err := authorizer.AuthorizeWrite(context.Background(), tenantSessionTxStub{
		scopeID: scopeID, tenantID: tenantID,
	}, actor, scopeID, PermissionManage)
	if err != nil || actualTenantID != tenantID {
		t.Fatalf("AuthorizeWrite() = (%s, %v), want (%s, nil)", actualTenantID, err, tenantID)
	}
	wantSession := rbacmanager.AuthenticatedSessionReference{
		UserID: userID, ScopeID: scopeID, SessionID: sessionID,
	}
	if stub.seen != wantSession || stub.grant != PermissionManage {
		t.Fatalf("delegated session = %#v permission=%q, want %#v %q",
			stub.seen, stub.grant, wantSession, PermissionManage)
	}

	t.Run("returned_tenant_must_match_target_scope", func(t *testing.T) {
		stub := &tenantSessionAuthorizerStub{tenantID: uuid.New()}
		authorizer := tenantSessionTxAuthorizer{sessions: stub}
		if _, err := authorizer.AuthorizeWrite(context.Background(), tenantSessionTxStub{
			scopeID: scopeID, tenantID: tenantID,
		}, actor, scopeID, PermissionManage); !errors.Is(err, ErrPermissionDenied) {
			t.Fatalf("AuthorizeWrite() error = %v, want ErrPermissionDenied", err)
		}
	})

	for _, test := range []struct {
		name  string
		actor Actor
	}{
		{name: "missing_credential", actor: Actor{UserID: userID, ScopeID: scopeID, ScopeKind: "tenant"}},
		{name: "unknown_credential", actor: Actor{UserID: userID, ScopeID: scopeID, ScopeKind: "tenant",
			Credential: CredentialReference{Kind: "bearer", ID: uuid.New()}}},
		{name: "api_key", actor: Actor{UserID: userID, ScopeID: scopeID, ScopeKind: "tenant",
			Credential: CredentialReference{Kind: CredentialKindAPIKey, ID: uuid.New()}}},
		{name: "platform_session", actor: Actor{UserID: userID, ScopeID: scopeID, ScopeKind: "platform",
			Credential: CredentialReference{Kind: CredentialKindSession, ID: sessionID}}},
		{name: "wrong_scope", actor: Actor{UserID: userID, ScopeID: uuid.New(), ScopeKind: "tenant",
			Credential: CredentialReference{Kind: CredentialKindSession, ID: sessionID}}},
	} {
		t.Run(test.name, func(t *testing.T) {
			if _, err := authorizer.AuthorizeWrite(
				context.Background(), tenantSessionTxStub{}, test.actor, scopeID, PermissionManage,
			); !errors.Is(err, ErrPermissionDenied) {
				t.Fatalf("AuthorizeWrite() error = %v, want ErrPermissionDenied", err)
			}
		})
	}
}

func TestTenantSessionTxAuthorizerMapsRBACPermissionDenied(t *testing.T) {
	stub := &tenantSessionAuthorizerStub{err: rbacmanager.ErrPermissionDenied}
	authorizer := tenantSessionTxAuthorizer{sessions: stub}
	actor := Actor{
		UserID: uuid.New(), ScopeID: uuid.New(), ScopeKind: "tenant",
		Credential: CredentialReference{Kind: CredentialKindSession, ID: uuid.New()},
	}
	if _, err := authorizer.AuthorizeWrite(
		context.Background(), tenantSessionTxStub{}, actor, actor.ScopeID, PermissionManage,
	); !errors.Is(err, ErrPermissionDenied) {
		t.Fatalf("AuthorizeWrite() error = %v, want ErrPermissionDenied", err)
	}
}

func TestTenantSessionStoreDependenciesFailClosed(t *testing.T) {
	pool := &pgxpool.Pool{}
	trust := &entitlementguard.TrustStore{}
	service := &rbacmanager.Service{}
	for _, test := range []struct {
		name    string
		pool    *pgxpool.Pool
		now     func() time.Time
		trust   *entitlementguard.TrustStore
		session *rbacmanager.Service
	}{
		{name: "pool", now: time.Now, trust: trust, session: service},
		{name: "clock", pool: pool, trust: trust, session: service},
		{name: "trust", pool: pool, now: time.Now, session: service},
		{name: "session", pool: pool, now: time.Now, trust: trust},
	} {
		t.Run(test.name, func(t *testing.T) {
			if _, err := NewTenantSessionStore(test.pool, test.now, test.trust, test.session); !errors.Is(err, ErrInvalidStoreConfig) {
				t.Fatalf("NewTenantSessionStore() error = %v, want ErrInvalidStoreConfig", err)
			}
		})
	}
}

func TestNormalizeStoreErrorHidesDatabaseFailures(t *testing.T) {
	for _, test := range []struct {
		name string
		err  error
	}{
		{name: "serialization", err: &pgconn.PgError{Code: "40001", Message: "serialization failure"}},
		{name: "deadlock", err: &pgconn.PgError{Code: "40P01", Message: "deadlock detected"}},
		{name: "lock_not_available", err: &pgconn.PgError{Code: "55P03", Message: "lock not available"}},
		{name: "unique", err: &pgconn.PgError{Code: "23505", Message: "unique violation"}},
		{name: "unknown_postgres", err: &pgconn.PgError{Code: "XX000", Message: "internal database detail"}},
		{name: "unknown_database", err: errors.New("driver: secret database detail")},
	} {
		t.Run(test.name, func(t *testing.T) {
			actual := normalizeStoreError(test.err)
			if actual != ErrUnavailable {
				t.Fatalf("normalizeStoreError() = %v, want ErrUnavailable", actual)
			}
			for _, leaked := range []string{"SQLSTATE", "40001", "40P01", "55P03", "secret", "internal"} {
				if strings.Contains(actual.Error(), leaked) {
					t.Fatalf("normalized error leaked %q: %v", leaked, actual)
				}
			}
		})
	}
	for _, conflict := range []error{ErrRevisionConflict, ErrIdempotencyConflict} {
		if actual := normalizeStoreError(conflict); actual != conflict {
			t.Fatalf("normalizeStoreError(%v) = %v", conflict, actual)
		}
	}
}

// tenantSessionTxStub is non-nil so adapter validation reaches the delegated authorizer.
type tenantSessionTxStub struct {
	pgx.Tx
	scopeID  uuid.UUID
	tenantID uuid.UUID
}

func (stub tenantSessionTxStub) QueryRow(_ context.Context, _ string, arguments ...any) pgx.Row {
	if len(arguments) != 2 || arguments[0] != stub.scopeID || arguments[1] != stub.tenantID {
		return tenantSessionRowStub{err: pgx.ErrNoRows}
	}
	return tenantSessionRowStub{tenantID: stub.tenantID}
}

type tenantSessionRowStub struct {
	tenantID uuid.UUID
	err      error
}

func (stub tenantSessionRowStub) Scan(destinations ...any) error {
	if stub.err != nil {
		return stub.err
	}
	tenantID, ok := destinations[0].(*uuid.UUID)
	if !ok {
		return errors.New("unexpected tenant ID destination")
	}
	*tenantID = stub.tenantID
	return nil
}
