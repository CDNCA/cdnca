package securityactivation

import (
	"context"
	"errors"
	"testing"
	"time"

	"github.com/cdnca/cdnca/services/control-api/internal/securitypolicy"
	"github.com/google/uuid"
)

// A request naming nodes keeps them and its canary size; only an empty node
// list is resolved from the site (which needs the database).
func TestSiteTargetsKeepsNamedNodes(t *testing.T) {
	store := &Store{config: DefaultConfig(), clock: time.Now}
	named := []uuid.UUID{uuid.New(), uuid.New()}
	nodes, canary, err := store.siteTargets(context.Background(), uuid.New(), uuid.New(), named, 2)
	if err != nil || len(nodes) != 2 || canary != 2 {
		t.Fatalf("siteTargets(named) = %v, %d, %v", nodes, canary, err)
	}
}

func TestSiteTargetsNeedsSiteWhenResolving(t *testing.T) {
	store := &Store{config: DefaultConfig(), clock: time.Now}
	_, canary, err := store.siteTargets(context.Background(), uuid.New(), uuid.Nil, nil, 0)
	if !errors.Is(err, ErrInvalidInput) || canary != 1 {
		t.Fatalf("siteTargets(no site) = %d, %v; want canary 1, ErrInvalidInput", canary, err)
	}
}

// Past the 15-minute candidate TTL is its own error so the page can name the
// limit, instead of the generic invalid input (live-waf w8).
func TestRollbackExpiryPastTTLIsNamed(t *testing.T) {
	now := time.Date(2026, 10, 24, 8, 0, 0, 0, time.UTC)
	store := &Store{config: DefaultConfig(), clock: func() time.Time { return now }}
	actor := securitypolicy.Actor{UserID: uuid.New(), ScopeID: uuid.New(), ScopeKind: "tenant"}
	_, err := store.Rollback(context.Background(), actor, RollbackInput{
		CandidateID: uuid.New(), SourcePolicyVersion: 1, ExpectedBindingRevision: 1,
		TargetNodeIDs: []uuid.UUID{uuid.New()}, CanarySize: 1,
		ExpiresAt: now.Add(30 * time.Minute),
	})
	if !errors.Is(err, ErrExpiryTooLate) {
		t.Fatalf("Rollback(+30m) error = %v, want ErrExpiryTooLate", err)
	}
}
