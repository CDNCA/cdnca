package challengepolicy

import (
	"errors"
	"testing"
)

func TestPublicationSnapshotRequiresEnabledExactCurrentRevision(t *testing.T) {
	item := storedPolicy{
		Policy: Policy{
			ID: testUUID(1), TenantScopeID: testUUID(2), SiteID: testUUID(3), Host: "challenge.example.test",
			Priority: 10, Mode: ModeClick, ChallengeTTLSeconds: 60, PassTTLSeconds: 300,
			FailureWindowSeconds: 60, MaxFailuresPerWindow: 3, IPBinding: IPBindingExact,
			BypassRoutes: []BypassRoute{}, Enabled: true, Revision: 7,
		},
		TenantID: testUUID(4), KeyReference: "keyref:challenge-primary",
	}

	snapshot, err := publicationSnapshot(item, 7)
	if err != nil {
		t.Fatal(err)
	}
	if snapshot.PolicyID != item.ID || snapshot.TenantScopeID != item.TenantScopeID ||
		snapshot.TenantID != item.TenantID || snapshot.SiteID != item.SiteID || snapshot.Revision != 7 ||
		snapshot.KeyReference != item.KeyReference || snapshot.Mode != ModeClick {
		t.Fatalf("unexpected publication snapshot: %+v", snapshot)
	}

	for name, mutate := range map[string]func(*storedPolicy, *int64){
		"disabled": func(value *storedPolicy, _ *int64) { value.Enabled = false },
		"deleted": func(value *storedPolicy, _ *int64) { value.Deleted = true },
		"stale revision": func(_ *storedPolicy, revision *int64) { *revision = 6 },
	} {
		t.Run(name, func(t *testing.T) {
			candidate := item
			expected := int64(7)
			mutate(&candidate, &expected)
			if _, err := publicationSnapshot(candidate, expected); !errors.Is(err, ErrPublicationNotReady) {
				t.Fatalf("publicationSnapshot() error = %v", err)
			}
		})
	}
}

func TestPublicationSnapshotPreservesExternalReferenceWithoutCredentials(t *testing.T) {
	item := storedPolicy{
		Policy: Policy{
			ID: testUUID(1), TenantScopeID: testUUID(2), SiteID: testUUID(3), Host: "external.example.test",
			Priority: 10, Mode: ModeExternal, ChallengeTTLSeconds: 60, PassTTLSeconds: 300,
			FailureWindowSeconds: 60, MaxFailuresPerWindow: 3, IPBinding: IPBindingExact,
			BypassRoutes: []BypassRoute{}, Enabled: true, Revision: 2,
		},
		TenantID: testUUID(4), KeyReference: "keyref:challenge-primary",
		External: &ExternalProviderReference{Provider: ProviderTencent, AppReference: "appref:tencent-primary"},
	}
	snapshot, err := publicationSnapshot(item, 2)
	if err != nil {
		t.Fatal(err)
	}
	if snapshot.ExternalProvider == nil || snapshot.ExternalProvider.Provider != ProviderTencent ||
		snapshot.ExternalProvider.AppReference != "appref:tencent-primary" {
		t.Fatalf("external reference was not preserved: %+v", snapshot.ExternalProvider)
	}
}
