package acmedispatch

import (
	"testing"
	"time"
)

func TestCertificateValidityWindowUsesAuthoritativeDatabaseClock26(t *testing.T) {
	now := time.Date(2026, time.August, 7, 4, 5, 6, 0, time.UTC)
	tests := []struct {
		name      string
		notBefore time.Time
		notAfter  time.Time
		want      bool
	}{
		{
			name:      "exact CA skew boundary",
			notBefore: now.Add(time.Minute), notAfter: now.Add(time.Hour), want: true,
		},
		{
			name:      "beyond CA skew boundary",
			notBefore: now.Add(time.Minute + time.Nanosecond), notAfter: now.Add(time.Hour),
		},
		{
			name:      "currently valid",
			notBefore: now.Add(-time.Hour), notAfter: now.Add(time.Hour), want: true,
		},
		{
			name:      "exact expiry boundary",
			notBefore: now.Add(-time.Hour), notAfter: now,
		},
		{
			name:      "already expired",
			notBefore: now.Add(-2 * time.Hour), notAfter: now.Add(-time.Hour),
		},
	}
	for _, test := range tests {
		t.Run(test.name, func(t *testing.T) {
			if got := validCertificateWindow(now, test.notBefore, test.notAfter); got != test.want {
				t.Fatalf("validCertificateWindow() = %t, want %t", got, test.want)
			}
		})
	}
}
