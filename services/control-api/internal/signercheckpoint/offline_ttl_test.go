package signercheckpoint

import (
	"context"
	"errors"
	"testing"
	"time"
)

// Offline-root checkpoints are signed by hand on an air-gapped machine, so the
// outer TTL must allow days, bounded by MaxOfflineCheckpointTTL.
func TestOfflineCheckpointTTLWindow(t *testing.T) {
	fixture := readGolden(t)
	signed := goldenSigned(t, fixture)
	trust, private := goldenTrust(t, signed)
	ref := AuthorityRef{Kind: AuthorityOfflineRoot, KeyID: "offline-root", Generation: 7}
	issued := time.Date(2026, 7, 23, 1, 2, 3, 123456000, time.UTC)
	for name, test := range map[string]struct {
		ttl     time.Duration
		now     time.Duration
		wantErr error
	}{
		"seven days, checked after six":  {ttl: 7 * 24 * time.Hour, now: 6 * 24 * time.Hour},
		"exactly the maximum":            {ttl: MaxOfflineCheckpointTTL, now: time.Hour},
		"one microsecond over maximum":   {ttl: MaxOfflineCheckpointTTL + time.Microsecond, now: time.Hour, wantErr: ErrTTLExceeded},
		"seven days, checked after nine": {ttl: 7 * 24 * time.Hour, now: 9 * 24 * time.Hour, wantErr: ErrCheckpointNotCurrent},
	} {
		t.Run(name, func(t *testing.T) {
			candidate := cloneCheckpoint(t, signed.Checkpoint)
			candidate.IssuedAt = canonicalTimeForTest(issued)
			candidate.ExpiresAt = canonicalTimeForTest(issued.Add(test.ttl))
			encoded := signCheckpoint(t, candidate, ref, private)
			_, err := VerifyCandidate(context.Background(), encoded, Snapshot{}, trust, issued.Add(test.now))
			if test.wantErr == nil && err != nil || test.wantErr != nil && !errors.Is(err, test.wantErr) {
				t.Fatalf("error = %v, want %v", err, test.wantErr)
			}
		})
	}
}

func canonicalTimeForTest(value time.Time) string {
	return value.UTC().Truncate(time.Microsecond).Format(time.RFC3339Nano)
}
