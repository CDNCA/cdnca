package httppolicycontrol

import (
	"context"
	"errors"
	"testing"
	"time"

	"github.com/cdnca/cdnca/services/control-api/internal/entitlementguard"
	"github.com/google/uuid"
	"github.com/jackc/pgx/v5"
	"github.com/jackc/pgx/v5/pgxpool"
)

type allowTxAuthorizer struct{}

func (allowTxAuthorizer) AuthorizeWrite(
	context.Context,
	pgx.Tx,
	Actor,
	uuid.UUID,
	string,
) (uuid.UUID, error) {
	return uuid.New(), nil
}

type databaseTxAuthorizer struct{}

func (databaseTxAuthorizer) AuthorizeWrite(
	ctx context.Context,
	tx pgx.Tx,
	actor Actor,
	targetScopeID uuid.UUID,
	permission string,
) (uuid.UUID, error) {
	return authorizeActorTarget(ctx, tx, actor, targetScopeID, permission)
}

func TestHTTPPolicyRuntimeDependenciesFailClosed(t *testing.T) {
	pool := &pgxpool.Pool{}
	trust := &entitlementguard.TrustStore{}
	if _, err := newStoreWithAuthorizer(nil, time.Now, trust, allowTxAuthorizer{}); !errors.Is(err, ErrInvalidStoreConfig) {
		t.Fatalf("newStoreWithAuthorizer(nil pool) error = %v, want ErrInvalidStoreConfig", err)
	}
	if _, err := newStoreWithAuthorizer(pool, nil, trust, allowTxAuthorizer{}); !errors.Is(err, ErrInvalidStoreConfig) {
		t.Fatalf("newStoreWithAuthorizer(nil clock) error = %v, want ErrInvalidStoreConfig", err)
	}
	if _, err := newStoreWithAuthorizer(pool, time.Now, trust, nil); !errors.Is(err, ErrInvalidStoreConfig) {
		t.Fatalf("newStoreWithAuthorizer(nil authorizer) error = %v, want ErrInvalidStoreConfig", err)
	}
	if _, err := newStoreWithAuthorizer(pool, time.Now, nil, allowTxAuthorizer{}); !errors.Is(err, ErrInvalidStoreConfig) {
		t.Fatalf("newStoreWithAuthorizer(nil trust) error = %v, want ErrInvalidStoreConfig", err)
	}
}
