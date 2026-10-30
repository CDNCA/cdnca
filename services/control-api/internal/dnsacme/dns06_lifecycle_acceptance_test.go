package dnsacme

import (
	"testing"
	"time"

	"github.com/google/uuid"
)

func TestDNS06RenewalDueAndRetryScheduleAreDeterministicAndBounded(t *testing.T) {
	certificateID := uuid.MustParse("018f4f3e-7c2a-7c2b-8f21-5cb74a147e4b")
	notAfter := time.Date(2026, time.December, 1, 0, 0, 0, 123456000, time.UTC)
	renewBefore := 30 * 24 * time.Hour
	due := renewalInitialDue(certificateID, notAfter, renewBefore)
	if due != renewalInitialDue(certificateID, notAfter, renewBefore) ||
		due.Before(notAfter.Add(-renewBefore)) || due.After(notAfter.Add(-renewBefore+renewalJitterMaximum)) {
		t.Fatalf("deterministic due = %s", due)
	}

	failureAt := notAfter.Add(-48 * time.Hour)
	previous := time.Duration(0)
	for failures := int64(1); failures <= 64; failures++ {
		delay := renewalRetryDelay(failures, notAfter, failureAt, 24*time.Hour)
		if delay < previous || delay > 24*time.Hour {
			t.Fatalf("retry %d delay = %s after %s", failures, delay, previous)
		}
		previous = delay
	}
}
