package acmeedge

import (
	"testing"
	"time"
)

func TestCompletedDeliveryRetryAfterMatches(t *testing.T) {
	occurredAt := time.Date(2026, 8, 6, 12, 34, 56, 123456000, time.UTC)
	defaultDelay := 15 * time.Second
	tests := []struct {
		name         string
		availableAt  time.Time
		requested    time.Duration
		defaultDelay time.Duration
		want         bool
	}{
		{
			name:         "same explicit delay",
			availableAt:  occurredAt.Add(30 * time.Second),
			requested:    30 * time.Second,
			defaultDelay: defaultDelay,
			want:         true,
		},
		{
			name:         "zero uses configured default",
			availableAt:  occurredAt.Add(defaultDelay),
			requested:    0,
			defaultDelay: defaultDelay,
			want:         true,
		},
		{
			name:         "explicit default is equivalent to zero",
			availableAt:  occurredAt.Add(defaultDelay),
			requested:    defaultDelay,
			defaultDelay: defaultDelay,
			want:         true,
		},
		{
			name:         "changed explicit delay conflicts",
			availableAt:  occurredAt.Add(30 * time.Second),
			requested:    45 * time.Second,
			defaultDelay: defaultDelay,
			want:         false,
		},
		{
			name:         "changed default delay conflicts",
			availableAt:  occurredAt.Add(defaultDelay),
			requested:    0,
			defaultDelay: 20 * time.Second,
			want:         false,
		},
		{
			name:         "timestamp drift conflicts",
			availableAt:  occurredAt.Add(defaultDelay + time.Microsecond),
			requested:    0,
			defaultDelay: defaultDelay,
			want:         false,
		},
		{
			name:         "database microsecond precision is deterministic",
			availableAt:  occurredAt.Add(1500 * time.Nanosecond).Truncate(time.Microsecond),
			requested:    1500 * time.Nanosecond,
			defaultDelay: defaultDelay,
			want:         true,
		},
		{
			name:         "negative requested delay is invalid",
			availableAt:  occurredAt,
			requested:    -time.Second,
			defaultDelay: defaultDelay,
			want:         false,
		},
	}
	for _, test := range tests {
		t.Run(test.name, func(t *testing.T) {
			if got := completedDeliveryRetryAfterMatches(occurredAt, test.availableAt, test.requested, test.defaultDelay); got != test.want {
				t.Fatalf("retry delay match = %v, want %v", got, test.want)
			}
		})
	}
}
