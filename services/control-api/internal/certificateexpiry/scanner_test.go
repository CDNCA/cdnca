package certificateexpiry

import (
	"testing"
	"time"
)

func TestStageAtPicksTheNearestReachedThreshold(t *testing.T) {
	notAfter := time.Date(2026, 11, 30, 0, 0, 0, 0, time.UTC)
	for _, test := range []struct {
		before time.Duration
		want   string
	}{
		{31 * 24 * time.Hour, ""},
		{30 * 24 * time.Hour, StageExpiring30d},
		{8 * 24 * time.Hour, StageExpiring30d},
		{7 * 24 * time.Hour, StageExpiring7d},
		{3 * 24 * time.Hour, StageExpiring7d},
		{24 * time.Hour, StageExpiring1d},
		{time.Second, StageExpiring1d},
		{0, StageExpired},
		{-time.Hour, StageExpired},
	} {
		if got := StageAt(notAfter, notAfter.Add(-test.before)); got != test.want {
			t.Errorf("%s before expiry: stage %q, want %q", test.before, got, test.want)
		}
	}
}
