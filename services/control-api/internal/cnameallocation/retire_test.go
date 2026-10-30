package cnameallocation

import (
	"context"
	"errors"
	"testing"
	"time"

	"github.com/google/uuid"
)

type fakeRetirements struct {
	due      []RetiredOwner
	finished []string
}

func (store *fakeRetirements) DueRetirements(context.Context, int) ([]RetiredOwner, error) {
	return store.due, nil
}

func (store *fakeRetirements) FinishRetirement(_ context.Context, owner RetiredOwner, deleted, kept int, code string) error {
	store.finished = append(store.finished, owner.Owner+"|"+code)
	return nil
}

type fakeRetiredCleaner struct{ failures map[string]error }

func (cleaner fakeRetiredCleaner) CleanRetiredOwner(_ context.Context, owner RetiredOwner) (int, int, error) {
	if err := cleaner.failures[owner.Owner]; err != nil {
		return 0, 0, err
	}
	return 2, 0, nil
}

type permanentRetireFailure struct{}

func (permanentRetireFailure) Error() string       { return "zone gone" }
func (permanentRetireFailure) FailureCode() string { return "dns_retire_zone_unavailable" }

// n12b: each due retired owner is cleaned and settled; a provider failure
// is settled with its code (retried with back-off by FinishRetirement)
// without stopping the others.
func TestRunRetirementsSettlesEachOwner(t *testing.T) {
	store := &fakeRetirements{due: []RetiredOwner{
		{ID: uuid.New(), Owner: "ok.cdn.example.com"},
		{ID: uuid.New(), Owner: "flaky.cdn.example.com"},
		{ID: uuid.New(), Owner: "gone.cdn.example.com"},
	}}
	worker := &Worker{dependencies: WorkerDependencies{Retirements: store, RetiredOwners: fakeRetiredCleaner{
		failures: map[string]error{"flaky.cdn.example.com": errors.New("timeout"), "gone.cdn.example.com": permanentRetireFailure{}},
	}}}
	if err := worker.RunRetirements(t.Context()); err != nil {
		t.Fatal(err)
	}
	want := []string{"ok.cdn.example.com|", "flaky.cdn.example.com|dns_retire_failed", "gone.cdn.example.com|dns_retire_zone_unavailable"}
	if len(store.finished) != len(want) {
		t.Fatalf("finished = %v", store.finished)
	}
	for index := range want {
		if store.finished[index] != want[index] {
			t.Fatalf("finished[%d] = %q, want %q", index, store.finished[index], want[index])
		}
	}
	if err := (&Worker{}).RunRetirements(t.Context()); err != nil {
		t.Fatalf("worker without retirement dependencies: %v", err)
	}
}

func TestRetirementBackoff(t *testing.T) {
	for attempt, want := range map[int]time.Duration{1: time.Minute, 2: 2 * time.Minute, 5: 16 * time.Minute, 20: 6 * time.Hour} {
		if got := RetirementBackoff(attempt); got != want {
			t.Fatalf("RetirementBackoff(%d) = %s, want %s", attempt, got, want)
		}
	}
}
