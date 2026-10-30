package site

import (
	"fmt"
	"testing"

	"github.com/cdnca/cdnca/services/control-api/internal/packageaddon"
	"github.com/google/uuid"
)

// PJ-C01: only a write that leaves the site disabled and takes nothing new
// from the package may skip the subscription admission.
func TestPackageContractionSkipsOnlySafeExits(t *testing.T) {
	sub, other := uuid.New(), uuid.New()
	current := SiteFields{Domains: []string{"a.example.com", "b.example.com"}, HTTPPorts: []string{"80", "8080"},
		HTTPSPorts: []string{"443"}, PackageSubscriptionID: &sub}
	with := func(edit func(*SiteFields)) SiteFields {
		f := current
		f.Domains = append([]string(nil), current.Domains...)
		f.HTTPPorts = append([]string(nil), current.HTTPPorts...)
		f.HTTPSPorts = append([]string(nil), current.HTTPSPorts...)
		edit(&f)
		return f
	}
	cases := []struct {
		name string
		f    SiteFields
		want bool
	}{
		{"disable unchanged", with(func(*SiteFields) {}), true},
		{"disable and shrink", with(func(f *SiteFields) { f.Domains = f.Domains[:1]; f.HTTPPorts = f.HTTPPorts[:1] }), true},
		{"enable", with(func(f *SiteFields) { f.Enabled = true }), false},
		{"disabled new domain", with(func(f *SiteFields) { f.Domains = append(f.Domains, "c.example.com") }), false},
		{"disabled new http port", with(func(f *SiteFields) { f.HTTPPorts = append(f.HTTPPorts, "8081") }), false},
		{"disabled new https port", with(func(f *SiteFields) { f.HTTPSPorts = append(f.HTTPSPorts, "8443") }), false},
		{"rebind subscription", with(func(f *SiteFields) { f.PackageSubscriptionID = &other }), false},
		{"drop binding", with(func(f *SiteFields) { f.PackageSubscriptionID = nil }), false},
	}
	for _, tc := range cases {
		if got := packageContraction(current, tc.f); got != tc.want {
			t.Errorf("%s: packageContraction=%v want %v", tc.name, got, tc.want)
		}
	}
}

func TestBatchPackageFailureCodes(t *testing.T) {
	for err, want := range map[error]string{
		packageaddon.ErrSubscriptionInactive:                  "package_subscription_inactive",
		fmt.Errorf("wrap: %w", packageaddon.ErrQuotaExceeded): "package_resource_quota_exceeded",
		packageaddon.ErrFeatureDenied:                         "package_feature_denied",
		ErrPermissionDenied:                                   "permission_denied",
	} {
		if code, ok := batchPackageFailure(err); !ok || code != want {
			t.Errorf("%v: code=%q ok=%v want %q", err, code, ok, want)
		}
	}
	if _, ok := batchPackageFailure(packageaddon.ErrUnavailable); ok {
		t.Error("an unavailable package store must abort the batch, not become an item code")
	}
}
