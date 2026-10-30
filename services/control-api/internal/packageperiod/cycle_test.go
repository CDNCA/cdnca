package packageperiod

import (
	"errors"
	"sync"
	"testing"
	"time"
)

func TestDailyCycleUsesCalendarDaysAcrossDST(t *testing.T) {
	location := mustLocation(t, "America/New_York")
	start := time.Date(2026, time.March, 7, 12, 0, 0, 0, location)
	end := time.Date(2026, time.March, 12, 12, 0, 0, 0, location)
	validity := mustCustomValidity(t, start, end, location)
	at := time.Date(2026, time.March, 8, 11, 59, 59, 0, location)

	cycle, err := CurrentCycle("subscription-dst", validity, CyclePolicy{Kind: CycleDaily}, at)
	if err != nil {
		t.Fatal(err)
	}
	wantStart := time.Date(2026, time.March, 7, 12, 0, 0, 0, location).UTC()
	wantEnd := time.Date(2026, time.March, 8, 12, 0, 0, 0, location).UTC()
	if !cycle.StartsAt().Equal(wantStart) || !cycle.EndsAt().Equal(wantEnd) {
		t.Fatalf("cycle = [%s, %s), want [%s, %s)", cycle.StartsAt(), cycle.EndsAt(), wantStart, wantEnd)
	}
	if got := cycle.EndsAt().Sub(cycle.StartsAt()); got != 23*time.Hour {
		t.Fatalf("DST cycle duration = %s, want 23h", got)
	}
}

func TestMonthlyCycleKeepsOriginalMonthEndAnchor(t *testing.T) {
	location := mustLocation(t, "Asia/Shanghai")
	start := time.Date(2024, time.January, 31, 8, 0, 0, 0, location)
	end := time.Date(2024, time.May, 31, 8, 0, 0, 0, location)
	validity := mustCustomValidity(t, start, end, location)
	at := time.Date(2024, time.February, 29, 8, 0, 0, 0, location)

	cycle, err := CurrentCycle("subscription-month-end", validity, CyclePolicy{Kind: CycleMonthly}, at)
	if err != nil {
		t.Fatal(err)
	}
	wantStart := time.Date(2024, time.February, 29, 8, 0, 0, 0, location).UTC()
	wantEnd := time.Date(2024, time.March, 31, 8, 0, 0, 0, location).UTC()
	if !cycle.StartsAt().Equal(wantStart) || !cycle.EndsAt().Equal(wantEnd) {
		t.Fatalf("cycle = [%s, %s), want [%s, %s)", cycle.StartsAt(), cycle.EndsAt(), wantStart, wantEnd)
	}
}

func TestCustomDayCycleClipsFinalPeriodToValidityEnd(t *testing.T) {
	location := mustLocation(t, "Asia/Shanghai")
	start := time.Date(2026, time.April, 1, 10, 0, 0, 0, location)
	end := time.Date(2026, time.April, 10, 6, 0, 0, 0, location)
	validity := mustCustomValidity(t, start, end, location)
	at := time.Date(2026, time.April, 9, 20, 0, 0, 0, location)

	cycle, err := CurrentCycle("subscription-custom", validity,
		CyclePolicy{Kind: CycleCustomDays, CustomDays: 3}, at)
	if err != nil {
		t.Fatal(err)
	}
	wantStart := time.Date(2026, time.April, 7, 10, 0, 0, 0, location).UTC()
	if !cycle.StartsAt().Equal(wantStart) || !cycle.EndsAt().Equal(end.UTC()) {
		t.Fatalf("cycle = [%s, %s), want [%s, %s)", cycle.StartsAt(), cycle.EndsAt(), wantStart, end.UTC())
	}
	if _, err := CurrentCycle("subscription-custom", validity,
		CyclePolicy{Kind: CycleCustomDays, CustomDays: 3}, end); !errors.Is(err, ErrNoActiveCycle) {
		t.Fatalf("CurrentCycle(at validity end) error = %v, want %v", err, ErrNoActiveCycle)
	}
}

func TestCurrentCycleRejectsInvalidPolicies(t *testing.T) {
	location := mustLocation(t, "UTC")
	start := time.Date(2026, time.July, 22, 10, 0, 0, 0, location)
	validity := mustCustomValidity(t, start, start.AddDate(0, 1, 0), location)

	for _, policy := range []CyclePolicy{
		{},
		{Kind: CycleDaily, CustomDays: 2},
		{Kind: CycleMonthly, CustomDays: 1},
		{Kind: CycleCustomDays},
		{Kind: CycleCustomDays, CustomDays: MaxCustomCycleDays + 1},
	} {
		if _, err := CurrentCycle("subscription", validity, policy, start); !errors.Is(err, ErrInvalidCycle) {
			t.Fatalf("CurrentCycle(%#v) error = %v, want %v", policy, err, ErrInvalidCycle)
		}
	}
}

func TestResetKeyIsStableUnderConcurrentRecalculation(t *testing.T) {
	location := mustLocation(t, "Asia/Shanghai")
	start := time.Date(2026, time.January, 31, 8, 0, 0, 0, location)
	validity := mustCustomValidity(t, start, start.AddDate(1, 0, 0), location)
	at := time.Date(2026, time.July, 31, 8, 0, 0, 0, location)
	policy := CyclePolicy{Kind: CycleMonthly}
	want, err := CurrentCycle("subscription-concurrent", validity, policy, at)
	if err != nil {
		t.Fatal(err)
	}

	const workers = 64
	results := make(chan Cycle, workers)
	errorsFound := make(chan error, workers)
	var group sync.WaitGroup
	group.Add(workers)
	for range workers {
		go func() {
			defer group.Done()
			cycle, cycleErr := CurrentCycle("subscription-concurrent", validity, policy, at)
			if cycleErr != nil {
				errorsFound <- cycleErr
				return
			}
			results <- cycle
		}()
	}
	group.Wait()
	close(results)
	close(errorsFound)
	for err := range errorsFound {
		t.Fatalf("concurrent CurrentCycle() error = %v", err)
	}
	for got := range results {
		if got.ResetKey() != want.ResetKey() || !got.StartsAt().Equal(want.StartsAt()) || !got.EndsAt().Equal(want.EndsAt()) {
			t.Fatalf("concurrent cycle = [%s, %s) %q, want [%s, %s) %q",
				got.StartsAt(), got.EndsAt(), got.ResetKey(), want.StartsAt(), want.EndsAt(), want.ResetKey())
		}
	}
}

func mustCustomValidity(t *testing.T, start, end time.Time, location *time.Location) Validity {
	t.Helper()
	validity, err := NewValidity(start, location, Terms{EndAt: &end})
	if err != nil {
		t.Fatal(err)
	}
	return validity
}
