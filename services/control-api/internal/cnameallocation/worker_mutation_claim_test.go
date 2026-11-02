package cnameallocation

import (
	"errors"
	"fmt"
	"testing"

	"github.com/cdnca/cdnca/services/control-api/internal/jobstate"
	"github.com/google/uuid"
	"github.com/jackc/pgx/v5/pgconn"
)

// The allocation job's round stopped on
// "active DNS provider mutation claim blocks site authority mutation (P8903)"
// while the failed child's uncertain claim awaited provider recovery, and the
// job kept its 16-minute lease. It must give the lease back on the child poll
// back-off like any other conflict.
func TestRetrySoonYieldsWhileProviderMutationClaimBlocksSiteAuthority(t *testing.T) {
	store := &fakeCNAMEStore{}
	worker := &Worker{dependencies: WorkerDependencies{Targets: store}}
	claim := jobstate.Claim{Job: jobstate.StoredJob{ID: uuid.New(), TenantID: uuid.New(),
		Kind: databaseJobKind, Attempt: 3, MaxAttempts: maximumJobAttempts}}
	blocked := fmt.Errorf("%w: %w", ErrUnavailable, &pgconn.PgError{
		Code: "P8903", Message: "active DNS provider mutation claim blocks site authority mutation",
	})

	err := worker.retrySoon(t.Context(), claim, blocked)
	if !errors.Is(err, ErrUnavailable) {
		t.Fatalf("retrySoon() = %v, want the original error returned", err)
	}
	if store.yieldCalls != 1 || store.yieldDelay != childPollDelay(claim.Job.Attempt) {
		t.Fatalf("yield calls=%d delay=%s, want one yield on the child poll back-off %s",
			store.yieldCalls, store.yieldDelay, childPollDelay(claim.Job.Attempt))
	}

	other := fmt.Errorf("%w: %w", ErrUnavailable, errors.New("connection refused"))
	if err := worker.retrySoon(t.Context(), claim, other); !errors.Is(err, ErrUnavailable) || store.yieldCalls != 1 {
		t.Fatalf("retrySoon(other) = %v yields=%d, want other unavailable errors unchanged", err, store.yieldCalls)
	}
}
