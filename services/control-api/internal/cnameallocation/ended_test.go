package cnameallocation

import (
	"context"
	"testing"
	"time"

	"github.com/cdnca/cdnca/services/control-api/internal/jobstate"
)

func TestEndedFailureCode(t *testing.T) {
	for code, want := range map[string]string{
		jobstate.CodeRetriesExhausted: FailureAllocationExhausted,
		jobstate.CodeCancelled:        FailureAllocationCancelled,
	} {
		if got := endedFailureCode(code); got != want || !errorCodePattern.MatchString(got) {
			t.Fatalf("endedFailureCode(%s) = %s, want %s", code, got, want)
		}
	}
}

type countingSweeper struct{ calls int }

func (sweeper *countingSweeper) SweepEndedJobs(context.Context) (int, error) {
	sweeper.calls++
	return 0, nil
}

// The sweep runs at start-up, then at most once per endedSweepInterval.
func TestRunEndedSweepPaced(t *testing.T) {
	clock := time.Unix(1_800_000_000, 0)
	sweeper := &countingSweeper{}
	worker, err := NewWorker(WorkerConfig{WorkerID: "w", LeaseDuration: time.Minute, Now: func() time.Time { return clock }},
		WorkerDependencies{Claims: &fakeCNAMEClaims{}, Targets: &fakeCNAMEStore{}, Reconcile: &fakeCNAMEReconcile{}, EndedJobs: sweeper})
	if err != nil {
		t.Fatal(err)
	}
	for _, step := range []struct {
		advance time.Duration
		want    int
	}{{0, 1}, {time.Second, 1}, {endedSweepInterval, 2}} {
		clock = clock.Add(step.advance)
		if err := worker.RunEndedSweep(t.Context()); err != nil || sweeper.calls != step.want {
			t.Fatalf("after +%s calls=%d err=%v, want %d", step.advance, sweeper.calls, err, step.want)
		}
	}
}
