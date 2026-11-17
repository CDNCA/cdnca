package controlupgrade

import (
	"testing"
	"time"
)

// A node's accepted observed 15:32:17.751247Z, command published_at (outbox settlement)
// 15:32:17.78023Z. The status was rejected as an invalid event and the plan never saw a status.
func TestRolloutStatusObservedInWindowAcceptsObservationBeforeSettlement(t *testing.T) {
	published := time.Date(2026, 11, 17, 15, 32, 17, 780230000, time.UTC)
	now := published.Add(4 * time.Second)
	for _, test := range []struct {
		name     string
		observed time.Time
		want     bool
	}{
		{"accepted 29ms before settlement", time.Date(2026, 11, 17, 15, 32, 17, 751247000, time.UTC), true},
		{"after publication", published.Add(time.Second), true},
		{"at the past skew bound", published.Add(-rolloutStatusFutureSkew), true},
		{"beyond the past skew", published.Add(-rolloutStatusFutureSkew - time.Microsecond), false},
		{"beyond the future skew", now.Add(rolloutStatusFutureSkew + time.Microsecond), false},
	} {
		if got := rolloutStatusObservedInWindow(test.observed, &published, now); got != test.want {
			t.Errorf("%s: got %t, want %t", test.name, got, test.want)
		}
	}
	if rolloutStatusObservedInWindow(published, nil, now) {
		t.Error("unpublished command accepted a status")
	}
}
