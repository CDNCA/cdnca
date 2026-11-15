package securityactivation

import (
	"errors"
	"fmt"
	"testing"
	"time"

	"github.com/google/uuid"
	"github.com/jackc/pgx/v5/pgconn"
)

// A candidate refused with P8802 used to be retried every 2 seconds for hours. The same refusal
// doubles the wait up to five minutes; another error, or success (delete), starts over.
func TestRefusalBackoffDoublesUpToFiveMinutes(t *testing.T) {
	now := time.Date(2026, 11, 15, 7, 0, 0, 0, time.UTC)
	worker := &Worker{store: &Store{clock: func() time.Time { return now }, config: DefaultConfig()},
		refused: make(map[uuid.UUID]refusal)}
	candidate := uuid.New()
	refused := fmt.Errorf("reconcile: %w", &pgconn.PgError{Code: "P8802",
		Message: "invalid security policy activation recovery rollout identity"})

	if worker.backingOff(candidate) {
		t.Fatal("a candidate never refused is backing off")
	}
	want := 2 * time.Second
	for attempt := range 12 {
		worker.refuse(candidate, refused)
		if got := worker.refused[candidate].delay; got != want {
			t.Fatalf("attempt %d delay = %s, want %s", attempt, got, want)
		}
		if !worker.backingOff(candidate) {
			t.Fatalf("attempt %d: candidate not backing off right after a refusal", attempt)
		}
		now = now.Add(want - time.Nanosecond)
		if !worker.backingOff(candidate) {
			t.Fatalf("attempt %d: retried before %s passed", attempt, want)
		}
		now = now.Add(time.Nanosecond)
		if worker.backingOff(candidate) {
			t.Fatalf("attempt %d: still backing off after %s", attempt, want)
		}
		want = min(2*want, refusalBackoffMax)
	}
	if worker.refused[candidate].delay != refusalBackoffMax {
		t.Fatalf("delay = %s, want the %s cap", worker.refused[candidate].delay, refusalBackoffMax)
	}

	worker.refuse(candidate, errors.New("another refusal"))
	if got := worker.refused[candidate].delay; got != 2*time.Second {
		t.Fatalf("a different error kept delay %s, want 2s", got)
	}
	other := uuid.New()
	if worker.backingOff(other) {
		t.Fatal("another candidate inherited the backoff")
	}
	delete(worker.refused, candidate)
	if worker.backingOff(candidate) {
		t.Fatal("a reconciled candidate is still backing off")
	}
}

// Promote failed with a source revision conflict, failPromotion's recovery rollout was refused
// with P8802, and the joined error matched ErrSourceRevisionConflict: the worker skipped the candidate as
// ordinary contention on every pass until it expired. The recovery error decides now.
func TestPromotionRecoveryErrorHidesPromotionRefusal(t *testing.T) {
	recovery := &pgconn.PgError{Code: "P8802", Message: "invalid security policy activation recovery rollout identity"}
	for _, promote := range []error{ErrSourceRevisionConflict, ErrConflict, ErrNotHealthy} {
		err := promotionRecoveryError(promote, recovery)
		if errors.Is(err, promote) || ignorableWorkerError(err) {
			t.Fatalf("%v: recovery failure still ignorable: %v", promote, err)
		}
		if !candidateLocalError(err) {
			t.Fatalf("%v: P8802 recovery failure is not candidate-local: %v", promote, err)
		}
		var pgErr *pgconn.PgError
		if !errors.As(err, &pgErr) || pgErr.Code != "P8802" {
			t.Fatalf("%v: recovery error lost: %v", promote, err)
		}
	}
	if !ignorableWorkerError(promotionRecoveryError(ErrSourceRevisionConflict, ErrConflict)) {
		t.Fatal("a recovery that lost a race (ErrConflict) must stay ignorable")
	}
}
