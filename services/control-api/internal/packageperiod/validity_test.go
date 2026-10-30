package packageperiod

import (
	"errors"
	"testing"
	"time"
)

func TestNewValidityRequiresExactlyOneEndTerm(t *testing.T) {
	location := mustLocation(t, "Asia/Shanghai")
	now := time.Date(2026, time.July, 22, 10, 0, 0, 0, location)
	duration := DurationMonth
	endAt := now.AddDate(0, 1, 0)

	for _, test := range []struct {
		name  string
		terms Terms
	}{
		{name: "neither"},
		{name: "both", terms: Terms{Duration: &duration, EndAt: &endAt}},
	} {
		t.Run(test.name, func(t *testing.T) {
			if _, err := NewValidity(now, location, test.terms); !errors.Is(err, ErrInvalidTerms) {
				t.Fatalf("NewValidity() error = %v, want %v", err, ErrInvalidTerms)
			}
		})
	}
}

func TestNewValidityRejectsInvalidAndPastEnds(t *testing.T) {
	location := mustLocation(t, "Asia/Shanghai")
	now := time.Date(2026, time.July, 22, 10, 0, 0, 0, location)
	invalidDuration := Duration("week")
	past := now.Add(-time.Nanosecond)
	exact := now

	for _, test := range []struct {
		name  string
		terms Terms
	}{
		{name: "unknown duration", terms: Terms{Duration: &invalidDuration}},
		{name: "past end", terms: Terms{EndAt: &past}},
		{name: "end equals start", terms: Terms{EndAt: &exact}},
	} {
		t.Run(test.name, func(t *testing.T) {
			if _, err := NewValidity(now, location, test.terms); !errors.Is(err, ErrInvalidTerms) {
				t.Fatalf("NewValidity() error = %v, want %v", err, ErrInvalidTerms)
			}
		})
	}
}

func TestDurationValidityClampsMonthEndAndLeapDay(t *testing.T) {
	location := mustLocation(t, "Asia/Shanghai")

	month := DurationMonth
	monthStart := time.Date(2024, time.January, 31, 8, 15, 0, 123, location)
	monthValidity, err := NewValidity(monthStart, location, Terms{Duration: &month})
	if err != nil {
		t.Fatal(err)
	}
	wantMonthEnd := time.Date(2024, time.February, 29, 8, 15, 0, 123, location).UTC()
	if !monthValidity.StartsAt().Equal(monthStart.UTC()) || !monthValidity.EndsAt().Equal(wantMonthEnd) {
		t.Fatalf("month validity = [%s, %s), want [%s, %s)",
			monthValidity.StartsAt(), monthValidity.EndsAt(), monthStart.UTC(), wantMonthEnd)
	}

	year := DurationYear
	leapStart := time.Date(2024, time.February, 29, 19, 30, 0, 0, location)
	yearValidity, err := NewValidity(leapStart, location, Terms{Duration: &year})
	if err != nil {
		t.Fatal(err)
	}
	wantYearEnd := time.Date(2025, time.February, 28, 19, 30, 0, 0, location).UTC()
	if !yearValidity.EndsAt().Equal(wantYearEnd) {
		t.Fatalf("year validity end = %s, want %s", yearValidity.EndsAt(), wantYearEnd)
	}
}

func TestDurationValidityUsesExplicitTimezoneAcrossDST(t *testing.T) {
	location := mustLocation(t, "America/New_York")
	start := time.Date(2026, time.March, 7, 12, 0, 0, 0, location)
	duration := DurationMonth

	validity, err := NewValidity(start, location, Terms{Duration: &duration})
	if err != nil {
		t.Fatal(err)
	}
	wantEnd := time.Date(2026, time.April, 7, 12, 0, 0, 0, location)
	if !validity.EndsAt().Equal(wantEnd.UTC()) || validity.TimeZone() != "America/New_York" {
		t.Fatalf("validity = end %s zone %q, want end %s zone America/New_York",
			validity.EndsAt(), validity.TimeZone(), wantEnd.UTC())
	}
	if got := validity.EndsAt().Sub(validity.StartsAt()); got != 31*24*time.Hour-time.Hour {
		t.Fatalf("elapsed validity = %s, want 743h across DST", got)
	}
}

func mustLocation(t *testing.T, name string) *time.Location {
	t.Helper()
	location, err := time.LoadLocation(name)
	if err != nil {
		t.Fatalf("time.LoadLocation(%q): %v", name, err)
	}
	return location
}
