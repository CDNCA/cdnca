package site

import (
	"errors"
	"testing"

	"github.com/google/uuid"
)

func TestSITE14OperationalStatusProjection(t *testing.T) {
	tests := []struct {
		stored string
		locked bool
		want   OperationalStatus
	}{
		{stored: StatusActive, want: OperationalStatusNormal},
		{stored: StatusDisabled, want: OperationalStatusNormal},
		{stored: StatusPackageExpired, want: OperationalStatusPackageExpired},
		{stored: StatusTrafficExceeded, want: OperationalStatusTrafficExceeded},
		{stored: StatusActive, locked: true, want: OperationalStatusLocked},
	}
	for _, test := range tests {
		if got := projectOperationalStatus(test.stored, test.locked); got != test.want {
			t.Fatalf("projectOperationalStatus(%q,%t)=%q want %q", test.stored, test.locked, got, test.want)
		}
	}
}

func TestSITE14RecoverySubjectBindsSiteRevisionAndEdgeSourceRevision(t *testing.T) {
	siteID := uuid.MustParse("018f47a2-5b9c-7d31-8a60-104c9c0b7103")
	subject, err := newStatusRecoverySubject(siteID, RecoveryTriggerTrafficTopUp, 17, 41)
	if err != nil {
		t.Fatal(err)
	}
	parsed, err := parseStatusRecoverySubject(subject)
	if err != nil {
		t.Fatal(err)
	}
	if parsed.SiteID != siteID || parsed.Trigger != RecoveryTriggerTrafficTopUp ||
		parsed.SiteRevision != 17 || parsed.EdgeSourceRevision != 41 {
		t.Fatalf("parsed subject=%+v", parsed)
	}
	for _, invalid := range []string{
		"", "site/status-recovery/not-a-uuid/unlock/17/41",
		"site/status-recovery/018f47a2-5b9c-7d31-8a60-104c9c0b7103/unknown/17/41",
		"site/status-recovery/018f47a2-5b9c-7d31-8a60-104c9c0b7103/unlock/0/41",
	} {
		if _, err := parseStatusRecoverySubject(invalid); !errors.Is(err, ErrInvalidInput) {
			t.Fatalf("parseStatusRecoverySubject(%q) error=%v", invalid, err)
		}
	}
}

func TestSITE14RecoveryReportFenceRejectsRegressionAndUnhealthyActivation(t *testing.T) {
	desired := uuid.MustParse("018f47a2-5b9c-7d31-8a60-104c9c0b7104")
	current := RecoveryReportCursor{Attempt: 2, Sequence: 9}
	if err := validateRecoveryReport(current, RecoveryReportCursor{Attempt: 1, Sequence: 99}, desired, desired, true); !errors.Is(err, ErrRecoveryReportStale) {
		t.Fatalf("stale attempt error=%v", err)
	}
	if err := validateRecoveryReport(current, RecoveryReportCursor{Attempt: 2, Sequence: 9}, desired, desired, true); !errors.Is(err, ErrRecoveryReportDuplicate) {
		t.Fatalf("duplicate error=%v", err)
	}
	if err := validateRecoveryReport(current, RecoveryReportCursor{Attempt: 2, Sequence: 10}, desired, uuid.New(), true); !errors.Is(err, ErrRecoveryVersionMismatch) {
		t.Fatalf("version mismatch error=%v", err)
	}
	if err := validateRecoveryReport(current, RecoveryReportCursor{Attempt: 2, Sequence: 10}, desired, desired, false); !errors.Is(err, ErrRecoveryUnhealthy) {
		t.Fatalf("unhealthy error=%v", err)
	}
	if err := validateRecoveryReport(current, RecoveryReportCursor{Attempt: 2, Sequence: 10}, desired, desired, true); err != nil {
		t.Fatalf("valid report error=%v", err)
	}
}
