package artifactsetdist

import (
	"testing"
	"time"
)

// A refused first delivery (a new node whose service ticket is not issued
// yet) is retried after a minute, not after the 30 minute ceiling.
func TestRetryWaitStartsShortAndDoublesToTheCeiling(t *testing.T) {
	distributor := &Distributor{config: Config{FirstRetryAfter: time.Minute, RetryAfter: 30 * time.Minute}}
	for attempts, want := range map[int]time.Duration{
		0: time.Minute, 1: time.Minute, 2: 2 * time.Minute, 3: 4 * time.Minute,
		5: 16 * time.Minute, 6: 30 * time.Minute, 20: 30 * time.Minute,
	} {
		if got := distributor.retryWait(attempts); got != want {
			t.Errorf("retryWait(%d) = %v, want %v", attempts, got, want)
		}
	}
}
