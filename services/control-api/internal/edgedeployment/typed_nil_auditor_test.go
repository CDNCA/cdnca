package edgedeployment

import (
	"bytes"
	"context"
	"errors"
	"testing"
	"time"

	"github.com/cdnca/cdnca/services/control-api/internal/apikeycredential"
	"github.com/cdnca/cdnca/services/control-api/internal/audit"
	"github.com/cdnca/cdnca/services/control-api/internal/iamlock"
	"github.com/cdnca/cdnca/services/control-api/internal/identity"
	"github.com/cdnca/cdnca/services/control-api/internal/sessioncredential"
	"github.com/google/uuid"
	"github.com/jackc/pgx/v5"
	"github.com/jackc/pgx/v5/pgxpool"
)

type typedNilAuditAppender struct{}

func (*typedNilAuditAppender) Append(context.Context, pgx.Tx, audit.Event) error { return nil }

func TestStoreRejectsTypedNilAuditor(t *testing.T) {
	var appender *typedNilAuditAppender
	pool := new(pgxpool.Pool)
	if _, err := NewStoreWithClockAndAuditor(pool, time.Now, appender); !errors.Is(err, ErrInvalidInput) {
		t.Fatalf("legacy constructor error = %v, want %v", err, ErrInvalidInput)
	}
	if _, err := NewIAMStoreWithClockAndAuditor(
		pool, time.Now, appender, new(iamlock.Authorizer),
	); !errors.Is(err, ErrInvalidInput) {
		t.Fatalf("IAM constructor error = %v, want %v", err, ErrInvalidInput)
	}
}

func TestProtectedCommandRejectsStoredTypedNilAuditorWithoutPanic(t *testing.T) {
	var appender *typedNilAuditAppender
	store := &Store{
		pool: new(pgxpool.Pool), now: time.Now, auditor: appender, authorizer: new(iamlock.Authorizer),
	}
	actor, err := NewSessionActor(uuid.New(), uuid.New(), ScopeKindPlatform, uuid.New(), "signed-access-token")
	if err != nil {
		t.Fatal(err)
	}
	_, err = store.CancelRollout(t.Context(), RolloutCommandRequest{
		Actor: actor, ConfigurationScopeID: uuid.New(), RolloutID: uuid.New(), ExpectedRevision: 1,
		IdempotencyKey: "typed-nil-auditor", RequestID: uuid.NewString(),
	})
	if !errors.Is(err, ErrUnavailable) {
		t.Fatalf("command error = %v, want %v", err, ErrUnavailable)
	}
}

func TestIAMStoreRejectsUnconfiguredDependencies(t *testing.T) {
	authorizer := newConfiguredIAMAuthorizer(t)
	if _, err := NewIAMStore(new(pgxpool.Pool), authorizer); !errors.Is(err, ErrInvalidInput) {
		t.Fatalf("zero pool error = %v, want %v", err, ErrInvalidInput)
	}

	pool := newConfiguredIAMPool(t)
	if _, err := NewIAMStore(pool, new(iamlock.Authorizer)); !errors.Is(err, ErrInvalidInput) {
		t.Fatalf("zero authorizer error = %v, want %v", err, ErrInvalidInput)
	}
	if _, err := NewIAMStoreWithClockAndAuditor(pool, time.Now, nil, authorizer); !errors.Is(err, ErrInvalidInput) {
		t.Fatalf("nil auditor error = %v, want %v", err, ErrInvalidInput)
	}
}

func TestProtectedCommandReportsUnconfiguredAuthorizerAsUnavailable(t *testing.T) {
	pool := newConfiguredIAMPool(t)
	store := &Store{
		pool: pool, now: time.Now, auditor: audit.New(pool), authorizer: new(iamlock.Authorizer),
	}
	actor, err := NewSessionActor(uuid.New(), uuid.New(), ScopeKindPlatform, uuid.New(), "signed-access-token")
	if err != nil {
		t.Fatal(err)
	}
	_, err = store.CancelRollout(t.Context(), RolloutCommandRequest{
		Actor: actor, ConfigurationScopeID: uuid.New(), RolloutID: uuid.New(), ExpectedRevision: 1,
		IdempotencyKey: "unconfigured-authorizer", RequestID: uuid.NewString(),
	})
	if !errors.Is(err, ErrUnavailable) {
		t.Fatalf("command error = %v, want %v", err, ErrUnavailable)
	}
}

func newConfiguredIAMPool(t *testing.T) *pgxpool.Pool {
	t.Helper()
	config, err := pgxpool.ParseConfig("host=127.0.0.1 port=1 dbname=edgedeployment sslmode=disable")
	if err != nil {
		t.Fatal(err)
	}
	pool, err := pgxpool.NewWithConfig(t.Context(), config)
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(pool.Close)
	return pool
}

func newConfiguredIAMAuthorizer(t *testing.T) *iamlock.Authorizer {
	t.Helper()
	tokens, err := identity.NewTokenManager("edgedeployment-readiness-test-secret", time.Hour)
	if err != nil {
		t.Fatal(err)
	}
	sessions, err := sessioncredential.NewVerifier(tokens, time.Now)
	if err != nil {
		t.Fatal(err)
	}
	apiKeys, err := apikeycredential.NewVerifier(bytes.Repeat([]byte{0x65}, 32), time.Now)
	if err != nil {
		t.Fatal(err)
	}
	authorizer, err := iamlock.NewAuthorizer(sessions, apiKeys)
	if err != nil {
		t.Fatal(err)
	}
	return authorizer
}
