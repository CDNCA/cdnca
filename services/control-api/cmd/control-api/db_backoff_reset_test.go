package main

import (
	"context"
	"errors"
	"io"
	"log/slog"
	"strings"
	"testing"
	"time"

	"github.com/cdnca/cdnca/services/control-api/internal/database"
)

// On a test control plane needrestart restarted PostgreSQL 11 times, each
// down about 2 seconds. The failure window of runWithDBBackoff was never
// cleared after the worker recovered, so the restarts were added up into
// "5 minutes of continuous failure" and control-api exited.

// backoffAttempt is one scripted run: it keeps running for d on the fake
// clock, then fails with a transient PostgreSQL error. ok means a database
// query succeeded during the attempt (B05: the only recovery signal).
type backoffAttempt struct {
	d  time.Duration
	ok bool
}

type fakeBackoffClock struct {
	now    time.Time
	sleeps []time.Duration
	starts []time.Time // fake time at which each scripted attempt started
}

func (clock *fakeBackoffClock) Now() time.Time { return clock.now }

func (clock *fakeBackoffClock) Sleep(_ context.Context, d time.Duration) error {
	clock.sleeps = append(clock.sleeps, d)
	clock.now = clock.now.Add(d)
	return nil
}

// runScripted drives runWithDBBackoffClock through the attempts; once they
// are used up the process is stopped (ctx cancelled). It returns the result,
// the fake time elapsed and the clock.
func runScripted(t *testing.T, attempts []backoffAttempt) (error, time.Duration, *fakeBackoffClock) {
	t.Helper()
	ctx, cancel := context.WithCancel(context.Background())
	defer cancel()
	begin := time.Date(2026, 10, 24, 19, 47, 0, 0, time.UTC)
	clock := &fakeBackoffClock{now: begin}
	next := 0
	err := runWithDBBackoffClock(ctx, slog.New(slog.NewTextHandler(io.Discard, nil)), "edge deployment runtime",
		5*time.Minute, func(runCtx context.Context) error {
			if next == len(attempts) {
				cancel()
				return context.Canceled
			}
			clock.starts = append(clock.starts, clock.now)
			clock.now = clock.now.Add(attempts[next].d)
			if attempts[next].ok {
				database.MarkQuerySucceeded(runCtx)
			}
			next++
			return pgTerminatedError()
		}, clock.Now, clock.Sleep)
	return err, clock.now.Sub(begin), clock
}

func isPersistentDBFailure(err error) bool {
	return err != nil && strings.Contains(err.Error(), "persistent DB connection failure")
}

// PG restarts every 2 minutes for 10 minutes; in between the worker runs
// normally. The process must not exit.
func TestRunWithDBBackoffIntermittentRestartsDoNotExit(t *testing.T) {
	var attempts []backoffAttempt
	for i := 0; i < 6; i++ {
		attempts = append(attempts,
			backoffAttempt{d: 2 * time.Minute, ok: true}, // ran normally, then PG restarted
			backoffAttempt{d: 0},                         // PG still down on the first retry
		)
	}
	err, elapsed, clock := runScripted(t, attempts)
	if !errors.Is(err, context.Canceled) {
		t.Fatalf("runWithDBBackoff = %v after %s, want context.Canceled (no exit)", err, elapsed)
	}
	if elapsed < 10*time.Minute {
		t.Fatalf("scenario covered %s, want at least 10m", elapsed)
	}
	// Each restart starts the backoff over at 2s, then 4s for the retry.
	for i := 0; i+1 < len(clock.sleeps); i += 2 {
		if clock.sleeps[i] != 2*time.Second || clock.sleeps[i+1] != 4*time.Second {
			t.Fatalf("sleeps = %v, want 2s,4s after every recovery", clock.sleeps)
		}
	}
}

// PG stays down: every attempt fails at once. The process exits once the
// failure has lasted more than 5 minutes, and not before.
func TestRunWithDBBackoffContinuousFailureExitsAfterFiveMinutes(t *testing.T) {
	attempts := make([]backoffAttempt, 100)
	err, elapsed, clock := runScripted(t, attempts)
	if !isPersistentDBFailure(err) {
		t.Fatalf("runWithDBBackoff = %v, want persistent DB connection failure", err)
	}
	if elapsed <= 5*time.Minute || elapsed > 5*time.Minute+30*time.Second {
		t.Fatalf("exited after %s, want just past 5m", elapsed)
	}
	want := []time.Duration{2 * time.Second, 4 * time.Second, 8 * time.Second, 16 * time.Second, 30 * time.Second}
	for i, d := range want {
		if clock.sleeps[i] != d {
			t.Fatalf("sleeps = %v, want %v then 30s cap", clock.sleeps, want)
		}
	}
	for _, d := range clock.sleeps[len(want):] {
		if d != 30*time.Second {
			t.Fatalf("sleeps = %v, want 30s cap", clock.sleeps)
		}
	}
}

// 4 minutes down, 1 minute up, then down again: the second outage is timed
// from 0, so the process survives 4 more minutes and exits only after the
// second outage itself passes 5 minutes.
func TestRunWithDBBackoffRecoveryRestartsFailureWindow(t *testing.T) {
	failFor := func(d time.Duration) []backoffAttempt {
		// Instant failures; the backoff sleeps 2+4+8+16 = 30s, then 30s each.
		var out []backoffAttempt
		for total, backoff := time.Duration(0), 2*time.Second; total < d; total += backoff {
			out = append(out, backoffAttempt{})
			backoff = min(backoff*2, 30*time.Second)
		}
		return out
	}
	first := failFor(4 * time.Minute)
	attempts := append([]backoffAttempt{}, first...)
	attempts = append(attempts, backoffAttempt{d: time.Minute, ok: true}) // recovered, ran 1 minute
	attempts = append(attempts, failFor(4*time.Minute)...)
	err, elapsed, clock := runScripted(t, attempts)
	if !errors.Is(err, context.Canceled) {
		t.Fatalf("runWithDBBackoff = %v after %s, want no exit: outages of 4m each are not 5m continuous", err, elapsed)
	}
	if got := clock.sleeps[len(first)]; got != 2*time.Second {
		t.Fatalf("first backoff after recovery = %s, want 2s (sleeps %v)", got, clock.sleeps)
	}

	// The same recovery followed by an outage longer than 5 minutes exits
	// about 5 minutes into that outage.
	attempts = append(append(append([]backoffAttempt{}, first...), backoffAttempt{d: time.Minute, ok: true}), make([]backoffAttempt, 100)...)
	err, elapsed, clock = runScripted(t, attempts)
	if !isPersistentDBFailure(err) {
		t.Fatalf("runWithDBBackoff = %v, want persistent DB connection failure", err)
	}
	// The second outage starts when the 1-minute attempt fails.
	secondStart := clock.starts[len(first)].Add(time.Minute)
	second := clock.now.Sub(secondStart)
	if second <= 5*time.Minute || second > 5*time.Minute+30*time.Second {
		t.Fatalf("second outage lasted %s before exit, want just past 5m (total %s)", second, elapsed)
	}
}

// A worker that fails again within seconds of a retry has not recovered:
// short-lived attempts must not reset the failure window.
func TestRunWithDBBackoffShortAttemptsKeepFailureWindow(t *testing.T) {
	attempts := make([]backoffAttempt, 100)
	for i := range attempts {
		attempts[i].d = 5 * time.Second
	}
	err, elapsed, _ := runScripted(t, attempts)
	if !isPersistentDBFailure(err) {
		t.Fatalf("runWithDBBackoff = %v after %s, want persistent DB connection failure", err, elapsed)
	}
}

// B05 (X11): an attempt that fails slowly (connect/lock wait, 30s or more)
// without a single successful query is not a recovery. Continuous slow
// failures must still exit after 5 minutes.
func TestRunWithDBBackoffSlowFailuresWithoutSuccessExpire(t *testing.T) {
	for _, d := range []time.Duration{29 * time.Second, 30 * time.Second, 31 * time.Second, 35 * time.Second, 2 * time.Minute} {
		attempts := make([]backoffAttempt, 100)
		for i := range attempts {
			attempts[i].d = d
		}
		err, elapsed, _ := runScripted(t, attempts)
		if !isPersistentDBFailure(err) {
			t.Fatalf("attempts of %s never succeeding: runWithDBBackoff = %v after %s, want persistent DB connection failure", d, err, elapsed)
		}
		// The window opens when the first attempt fails (after d) and the
		// exit comes on the first failure past 5 minutes (one more cycle).
		if elapsed > d+5*time.Minute+d+30*time.Second {
			t.Fatalf("attempts of %s: exited after %s, want just past 5m of failures", d, elapsed)
		}
	}
}

// A short attempt that did succeed (an empty queue poll is enough) proves the
// database came back: the window and the backoff start over.
func TestRunWithDBBackoffSuccessfulQueryResetsWindow(t *testing.T) {
	var attempts []backoffAttempt
	for i := 0; i < 20; i++ {
		attempts = append(attempts, backoffAttempt{}, backoffAttempt{}, backoffAttempt{d: time.Second, ok: true})
	}
	err, elapsed, clock := runScripted(t, attempts)
	if !errors.Is(err, context.Canceled) {
		t.Fatalf("runWithDBBackoff = %v after %s, want no exit: every outage recovered", err, elapsed)
	}
	// Every successful attempt starts the backoff over at 2s, so it never
	// grows past 8s (two failures, then the succeeding attempt fails).
	for i, d := range clock.sleeps {
		if d > 8*time.Second || i%3 == 2 && d != 2*time.Second {
			t.Fatalf("sleeps = %v, want a 2s restart after each successful attempt", clock.sleeps)
		}
	}
	// The signal belongs to one attempt: a later failing attempt that did not
	// succeed must not inherit it.
	attempts = append([]backoffAttempt{{d: time.Second, ok: true}}, make([]backoffAttempt, 100)...)
	if err, elapsed, _ := runScripted(t, attempts); !isPersistentDBFailure(err) {
		t.Fatalf("runWithDBBackoff = %v after %s, want persistent failure after a single early success", err, elapsed)
	}
}
