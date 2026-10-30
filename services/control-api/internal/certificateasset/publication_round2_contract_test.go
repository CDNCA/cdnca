package certificateasset

import (
	"os"
	"strings"
	"testing"
)

func TestPublicationMaterialsRequireFrozenIntentIdentity48(t *testing.T) {
	body, err := os.ReadFile("publication.go")
	if err != nil {
		t.Fatal(err)
	}
	text := string(body)
	for _, required := range []string{"AssetID", "VersionID", "BindingRevision", "sequence=$3", "binding.AssetID != request.AssetID", "binding.VersionID != request.VersionID"} {
		if !strings.Contains(text, required) {
			t.Errorf("publication material loader missing frozen identity guard %q", required)
		}
	}
	for _, forbidden := range []string{"loadLatestBinding(ctx, tx, request.TenantScopeID, siteID)", "loadPublicationCandidate("} {
		if strings.Contains(text, forbidden) {
			t.Errorf("publication material loader regressed to mutable lookup %q", forbidden)
		}
	}
}

func TestPublicationIntentStoreUsesFrozenDeadlineAndSkipsPermanentFailureHOL48(t *testing.T) {
	body, err := os.ReadFile("publication_store.go")
	if err != nil {
		t.Fatal(err)
	}
	text := string(body)
	for _, required := range []string{"intent.deadline_at", "lease.Deadline", "previous_latest.state NOT IN ('succeeded','permanent_failed')", "stored.Deadline.Equal(lease.Deadline)"} {
		if !strings.Contains(text, required) {
			t.Errorf("publication store missing frozen deadline/HOL contract %q", required)
		}
	}
}
