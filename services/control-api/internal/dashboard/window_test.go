package dashboard

import (
	"errors"
	"testing"
	"time"
)

func TestNewQueryUsesAudienceCalendarRanges(t *testing.T) {
	now := time.Date(2026, time.March, 18, 3, 27, 41, 123, time.UTC)
	tests := []struct {
		name       string
		audience   Audience
		rangeValue string
		wantFrom   string
		wantTo     string
	}{
		{name: "tenant today", audience: AudienceTenant, rangeValue: "today", wantFrom: "2026-03-17T16:00:00Z", wantTo: "2026-03-18T16:00:00Z"},
		{name: "tenant yesterday", audience: AudienceTenant, rangeValue: "yesterday", wantFrom: "2026-03-16T16:00:00Z", wantTo: "2026-03-17T16:00:00Z"},
		{name: "tenant seven days", audience: AudienceTenant, rangeValue: "seven_days", wantFrom: "2026-03-11T16:00:00Z", wantTo: "2026-03-18T16:00:00Z"},
		{name: "tenant thirty days", audience: AudienceTenant, rangeValue: "thirty_days", wantFrom: "2026-02-16T16:00:00Z", wantTo: "2026-03-18T16:00:00Z"},
		{name: "admin previous month", audience: AudienceAdmin, rangeValue: "previous_month", wantFrom: "2026-01-31T16:00:00Z", wantTo: "2026-02-28T16:00:00Z"},
	}
	for _, test := range tests {
		t.Run(test.name, func(t *testing.T) {
			query, err := NewQuery(test.audience, test.rangeValue, "Asia/Shanghai", now)
			if err != nil {
				t.Fatal(err)
			}
			if got := query.From.Format(time.RFC3339); got != test.wantFrom {
				t.Fatalf("from = %s, want %s", got, test.wantFrom)
			}
			if got := query.To.Format(time.RFC3339); got != test.wantTo {
				t.Fatalf("to = %s, want %s", got, test.wantTo)
			}
			if !query.AsOf.Equal(now) || query.Timezone != "Asia/Shanghai" || query.Range != test.rangeValue {
				t.Fatalf("query metadata = %#v", query)
			}
		})
	}
}

func TestNewQueryValidatesAudienceTimezoneAndAnalyticsBounds(t *testing.T) {
	now := time.Date(2026, time.November, 5, 3, 0, 0, 0, time.UTC)
	tests := []struct {
		name       string
		audience   Audience
		rangeValue string
		timezone   string
	}{
		{name: "tenant rejects admin range", audience: AudienceTenant, rangeValue: "previous_month", timezone: "UTC"},
		{name: "admin rejects tenant range", audience: AudienceAdmin, rangeValue: "today", timezone: "UTC"},
		{name: "unknown range", audience: AudienceTenant, rangeValue: "24h", timezone: "UTC"},
		{name: "empty timezone", audience: AudienceTenant, rangeValue: "today", timezone: ""},
		{name: "local timezone", audience: AudienceTenant, rangeValue: "today", timezone: "Local"},
		{name: "non IANA timezone", audience: AudienceTenant, rangeValue: "today", timezone: "UTC+8"},
		{name: "non hour aligned offset", audience: AudienceTenant, rangeValue: "today", timezone: "Asia/Kathmandu"},
		{name: "invalid audience", audience: Audience(99), rangeValue: "today", timezone: "UTC"},
	}
	for _, test := range tests {
		t.Run(test.name, func(t *testing.T) {
			_, err := NewQuery(test.audience, test.rangeValue, test.timezone, now)
			if !errors.Is(err, ErrInvalidQuery) {
				t.Fatalf("error = %v, want ErrInvalidQuery", err)
			}
		})
	}
}

func TestNewQueryHandlesDSTWithCalendarBoundaries(t *testing.T) {
	now := time.Date(2026, time.March, 10, 18, 0, 0, 0, time.UTC)
	query, err := NewQuery(AudienceTenant, "seven_days", "America/New_York", now)
	if err != nil {
		t.Fatal(err)
	}
	if got, want := query.To.Sub(query.From), 167*time.Hour; got != want {
		t.Fatalf("DST calendar duration = %s, want %s", got, want)
	}
	if !query.From.Equal(time.Date(2026, time.March, 4, 5, 0, 0, 0, time.UTC)) ||
		!query.To.Equal(time.Date(2026, time.March, 11, 4, 0, 0, 0, time.UTC)) {
		t.Fatalf("DST window = [%s,%s)", query.From, query.To)
	}
}

func TestNewQueryAllowsPreviousMonthAcrossEuropeLondonDSTTransitions(t *testing.T) {
	tests := []struct {
		name         string
		now          time.Time
		wantFrom     time.Time
		wantTo       time.Time
		wantDuration time.Duration
	}{
		{
			name:         "spring forward",
			now:          time.Date(2026, time.April, 5, 12, 0, 0, 0, time.UTC),
			wantFrom:     time.Date(2026, time.March, 1, 0, 0, 0, 0, time.UTC),
			wantTo:       time.Date(2026, time.March, 31, 23, 0, 0, 0, time.UTC),
			wantDuration: 743 * time.Hour,
		},
		{
			name:         "fall back",
			now:          time.Date(2026, time.November, 5, 12, 0, 0, 0, time.UTC),
			wantFrom:     time.Date(2026, time.September, 30, 23, 0, 0, 0, time.UTC),
			wantTo:       time.Date(2026, time.November, 1, 0, 0, 0, 0, time.UTC),
			wantDuration: 745 * time.Hour,
		},
	}
	for _, test := range tests {
		t.Run(test.name, func(t *testing.T) {
			query, err := NewQuery(AudienceAdmin, "previous_month", "Europe/London", test.now)
			if err != nil {
				t.Fatal(err)
			}
			if !query.From.Equal(test.wantFrom) || !query.To.Equal(test.wantTo) ||
				query.To.Sub(query.From) != test.wantDuration {
				t.Fatalf("window = [%s,%s) duration=%s", query.From, query.To, query.To.Sub(query.From))
			}
		})
	}
}
