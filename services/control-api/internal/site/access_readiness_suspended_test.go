package site

import (
	"testing"
	"time"

	"github.com/google/uuid"
)

// A suspended subscription's site (left out of every publication until it is
// resumed) says package_suspended on the package and the published checks,
// not site_not_in_publication; the access state is blocked.
func TestAccessReadinessSuspendedSubscription(t *testing.T) {
	subscriptionID := uuid.New()
	state := "suspended"
	reason := packageUnavailableReason(&subscriptionID, &state)
	if reason == nil || *reason != PackageUnavailableSuspended {
		t.Fatalf("package_unavailable_reason = %v, want %s", reason, PackageUnavailableSuspended)
	}
	readiness := buildAccessReadiness(accessFacts{Enabled: true, PackageUnavailable: reason, PublishState: publishExcluded},
		time.Date(2026, 11, 23, 13, 30, 0, 0, time.UTC))
	details := map[string]string{}
	for _, check := range readiness.Checks {
		details[check.Code] = check.Detail
	}
	if details[AccessCheckPackage] != PackageUnavailableSuspended || details[AccessCheckPublished] != PackageUnavailableSuspended ||
		readiness.State != AccessBlocked {
		t.Fatalf("readiness = %+v", readiness)
	}
	// Excluded for another reason it still says the publication lacks the site.
	other := buildAccessReadiness(accessFacts{Enabled: true, PublishState: publishExcluded}, time.Now())
	for _, check := range other.Checks {
		if check.Code == AccessCheckPublished && check.Detail != "site_not_in_publication" {
			t.Fatalf("published detail = %s, want site_not_in_publication", check.Detail)
		}
	}
	valid := "valid"
	if got := packageUnavailableReason(&subscriptionID, &valid); got != nil {
		t.Fatalf("valid package reason = %v", *got)
	}
}

// A cancelled (terminated) subscription's site says package_cancelled on the
// package check, never package_suspended, and is blocked.
func TestAccessReadinessCancelledSubscription(t *testing.T) {
	subscriptionID := uuid.New()
	state := "cancelled"
	reason := packageUnavailableReason(&subscriptionID, &state)
	if reason == nil || *reason != PackageUnavailableCancelled {
		t.Fatalf("package_unavailable_reason = %v, want %s", reason, PackageUnavailableCancelled)
	}
	for _, facts := range []accessFacts{
		{Enabled: true, PackageUnavailable: reason, PublishState: publishExcluded},
		{Enabled: false, PackageUnavailable: reason, PublishState: publishExcluded},
	} {
		readiness := buildAccessReadiness(facts, time.Date(2026, 11, 24, 10, 0, 0, 0, time.UTC))
		for _, check := range readiness.Checks {
			if check.Detail == PackageUnavailableSuspended {
				t.Fatalf("cancelled subscription reads as suspended: %+v", readiness)
			}
			if check.Code == AccessCheckPackage && (check.OK || check.Detail != PackageUnavailableCancelled) {
				t.Fatalf("package check = %+v", check)
			}
			// Left out of every publication as a suspended one (user).
			if facts.Enabled && check.Code == AccessCheckPublished && check.Detail != PackageUnavailableCancelled {
				t.Fatalf("published check = %+v, want %s", check, PackageUnavailableCancelled)
			}
		}
		if readiness.State != AccessBlocked {
			t.Fatalf("readiness state = %s", readiness.State)
		}
	}
}
