package site

import (
	"strings"
	"testing"

	"github.com/google/uuid"
)

// fix-nopkgpub2 ①: a site whose package is disabled or deleted is not served
// ; the list and detail say why, like an unbound site.
func TestPackageUnavailableReason(t *testing.T) {
	subscription := uuid.New()
	text := func(value string) *string { return &value }
	for _, test := range []struct {
		name         string
		subscription *uuid.UUID
		state        *string
		want         string
	}{
		// Community edition: a site needs no package, so none is no reason.
		{"no package", nil, nil, ""},
		{"valid package", &subscription, text("valid"), ""},
		{"disabled package", &subscription, text("disabled"), PackageUnavailableDisabled},
		{"deleted package", &subscription, text("deleted"), PackageUnavailableDeleted},
		{"suspended subscription", &subscription, text("suspended"), PackageUnavailableSuspended},
		// Terminated by the billing host (cancelled), whether or not it was suspended first.
		{"cancelled subscription", &subscription, text("cancelled"), PackageUnavailableCancelled},
		// A disabled package that was also deleted reads as deleted.
		{"subscription row gone", &subscription, nil, PackageUnavailableDeleted},
	} {
		t.Run(test.name, func(t *testing.T) {
			got := packageUnavailableReason(test.subscription, test.state)
			if test.want == "" {
				if got != nil {
					t.Fatalf("reason = %q, want none", *got)
				}
				return
			}
			if got == nil || *got != test.want {
				t.Fatalf("reason = %v, want %q", got, test.want)
			}
		})
	}
}

func TestSiteColumnsReadPackageValidity(t *testing.T) {
	columns := siteColumns("s")
	for _, want := range []string{"subscription.deleted_at IS NOT NULL", "subscription.admin_enabled",
		"subscription.lifecycle_status <> 'active' THEN 'cancelled'"} {
		if !strings.Contains(columns, want) {
			t.Fatalf("siteColumns() does not read the package validity (%s): %s", want, columns)
		}
	}
}

// A cancelled subscription ranks before its earlier suspension (and the
// admin switch): terminated is not "suspended, back on renewal".
func TestSiteColumnsRankCancelledBeforeSuspended(t *testing.T) {
	columns := siteColumns("s")
	cancelled := strings.Index(columns, "THEN 'cancelled'")
	if cancelled < 0 || cancelled > strings.Index(columns, "THEN 'disabled'") ||
		cancelled > strings.Index(columns, "THEN 'suspended'") || cancelled < strings.Index(columns, "THEN 'deleted'") {
		t.Fatalf("package validity order: %s", columns)
	}
}

func TestListItemCarriesPackageUnavailableReason(t *testing.T) {
	reason := PackageUnavailableDisabled
	item := toListItem(Site{PackageUnavailableReason: &reason})
	if item.PackageUnavailableReason == nil || *item.PackageUnavailableReason != reason {
		t.Fatalf("list item reason = %v, want %q", item.PackageUnavailableReason, reason)
	}
}

// the site reads who
// suspended its subscription and why (migration 698), only while suspended.
func TestSiteColumnsReadPackageSuspension(t *testing.T) {
	columns := siteColumns("s")
	for _, want := range []string{"package_subscription_suspend_source_698(subscription.id)",
		"'reason', subscription.suspend_reason", "subscription.suspended_at IS NOT NULL)"} {
		if !strings.Contains(columns, want) {
			t.Fatalf("siteColumns() does not read the package suspension (%s): %s", want, columns)
		}
	}
}
