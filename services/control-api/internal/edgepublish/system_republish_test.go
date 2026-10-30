package edgepublish

import (
	"errors"
	"strings"
	"testing"

	"github.com/google/uuid"
)

// Site stops and restores go out at once; node set and capability changes
// are debounced.
func TestSystemTriggerImmediate(t *testing.T) {
	for trigger, want := range map[string]bool{
		SystemTriggerTrafficEnforcement: true, SystemTriggerDomainOwnership: true,
		SystemTriggerSecondaryVerification: true, SystemTriggerLineGroup: false,
		SystemTriggerNodeSync: false, SystemTriggerNodeCapability: false,
	} {
		if got := SystemTriggerImmediate(trigger); got != want {
			t.Errorf("SystemTriggerImmediate(%s)=%v want %v", trigger, got, want)
		}
	}
}

// A CRS rule text change is a debounced content trigger: it republishes even
// to an unchanged node set, merged with the deliveries of its window.
func TestSystemTriggerRuleCatalogIsDebouncedContent(t *testing.T) {
	if !validSystemTrigger(SystemTriggerRuleCatalog) || SystemTriggerImmediate(SystemTriggerRuleCatalog) ||
		!systemContentTrigger([]string{SystemTriggerRuleCatalog}) || systemContentTrigger([]string{SystemTriggerLineGroup}) {
		t.Fatal("rule_catalog trigger contract")
	}
}

// A confirmed JS challenge policy redelivery is a debounced content trigger:
// the node that now holds the policy gets the release (and reloads the
// policy) even when the node set is unchanged.
func TestSystemTriggerChallengeDeliveryIsDebouncedContent(t *testing.T) {
	if SystemTriggerChallengeDelivery != "challenge_delivery" || !validSystemTrigger(SystemTriggerChallengeDelivery) ||
		SystemTriggerImmediate(SystemTriggerChallengeDelivery) || !systemContentTrigger([]string{SystemTriggerChallengeDelivery}) {
		t.Fatal("challenge_delivery trigger contract")
	}
}

// A node address change is an immediate content trigger: the DDoS node
// exemption goes out at once even to an unchanged node set.
func TestSystemTriggerNodeNetworksIsImmediateContent(t *testing.T) {
	if SystemTriggerNodeNetworks != "node_networks" || !validSystemTrigger(SystemTriggerNodeNetworks) ||
		!SystemTriggerImmediate(SystemTriggerNodeNetworks) || !systemContentTrigger([]string{SystemTriggerNodeNetworks}) {
		t.Fatal("node_networks trigger contract")
	}
}

// A published error page snapshot or origin auth publication is a debounced
// content trigger: the scope's site objects (site_runtime 9) carry both, so
// they go out again to an unchanged node set.
func TestSystemTriggerSiteFactsAreDebouncedContent(t *testing.T) {
	for _, trigger := range []string{SystemTriggerErrorPagePublished, SystemTriggerOriginAuthPublished} {
		if !validSystemTrigger(trigger) || SystemTriggerImmediate(trigger) || !systemContentTrigger([]string{trigger}) {
			t.Fatalf("%s trigger contract", trigger)
		}
	}
	if SystemTriggerErrorPagePublished != "error_page_published" || SystemTriggerOriginAuthPublished != "origin_auth_published" {
		t.Fatal("trigger values are the migration 416 check values")
	}
	if err := RequestSiteFactsRepublicationTx(t.Context(), nil, uuid.New(), SystemTriggerLineGroup); !errors.Is(err, ErrInvalidInput) {
		t.Fatalf("other trigger accepted: %v", err)
	}
}

func TestSystemTriggerPackageExpiryIsImmediateContent(t *testing.T) {
	if SystemTriggerPackageExpiry != "package_expiry" || !validSystemTrigger(SystemTriggerPackageExpiry) ||
		!SystemTriggerImmediate(SystemTriggerPackageExpiry) || !systemContentTrigger([]string{SystemTriggerPackageExpiry}) {
		t.Fatal("package_expiry must be a valid, immediate content trigger")
	}
}

// errpage-4 S3: an expired site is published marked, only with expiry_close
// on (a stored package_expired status always, unless a renewal restores it).
func TestPackageExpiredSitesQueryHonoursExpiryClose(t *testing.T) {
	for _, fragment := range []string{
		"subscription.lifecycle_status='active' AND subscription.ends_at<=$4",
		"(settings->>'expiry_close')::boolean",
		"site.status='package_expired' AND NOT site.id=ANY(",
	} {
		if !strings.Contains(packageExpiredSitesQuery, fragment) {
			t.Fatalf("package expired query missing %q", fragment)
		}
	}
}
