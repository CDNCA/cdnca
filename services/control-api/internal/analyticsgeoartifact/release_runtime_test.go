package analyticsgeoartifact

import (
	"bytes"
	"crypto/ed25519"
	"net/netip"
	"strings"
	"testing"
	"time"

	"github.com/cdnca/cdnca/services/control-api/internal/analyticsgeo"
)

func TestReleaseRuntimeActivatesAndRestoresDurableAuthorityIdentity(t *testing.T) {
	now := time.Date(2026, 8, 8, 12, 0, 0, 0, time.UTC)
	privateKey := ed25519.NewKeyFromSeed(bytes.Repeat([]byte{0x71}, ed25519.SeedSize))
	compiler, err := NewCompiler(CompilerConfig{
		KeyID: "geo-release-key-1", PrivateKey: privateKey,
		MaxCatalogs: 4, MaxEntriesPerCatalog: 16, MaxCatalogBytes: 1 << 20, MaxArtifactBytes: 1 << 20,
	})
	if err != nil {
		t.Fatal(err)
	}
	request := CompileRequest{
		Revision: 17, IssuedAt: now, ExpiresAt: now.Add(time.Hour),
		CurrentCatalogVersion: "geo-2026.08", AddressPolicy: AddressPolicyAllowNonPublic,
		Catalogs: []CatalogFacts{
			{Version: "geo-2026.07", Entries: []Fact{
				{Prefix: "203.0.113.0/24", CountryCode: "CN", Region: "CN-SH", Carrier: "previous", ASN: 64509},
			}},
			{Version: "geo-2026.08", Entries: []Fact{
				{Prefix: "203.0.113.0/24", CountryCode: "CN", Region: "CN-SH", Carrier: "current-v4", ASN: 64510},
				{Prefix: "2001:db8::/32", CountryCode: "CN", Region: "CN-BJ", Carrier: "current-v6", ASN: 64511},
			}},
		},
	}
	artifact, err := compiler.Compile(t.Context(), request)
	if err != nil {
		t.Fatal(err)
	}

	directory := t.TempDir()
	store := newReleaseRuntimeStore(t, directory, now, privateKey)
	loader := newReleaseRuntimeLoader(t, now, privateKey)
	runtime, err := NewReleaseRuntime(store, loader)
	if err != nil {
		t.Fatal(err)
	}
	release := ReleaseRequest{
		ReleaseID: "geo-release-17",
		Artifact:  artifact,
		Source: SourceRef{
			Provider: "fixture-provider", Version: "fixture-2026.08", SHA256: strings.Repeat("a", 64),
		},
	}
	state, err := runtime.Activate(t.Context(), release)
	if err != nil {
		t.Fatal(err)
	}
	if state.LKG != nil || state.Active.ReleaseID != release.ReleaseID || state.Active.Revision != request.Revision ||
		state.Active.Source != release.Source || state.Active.KeyID != "geo-release-key-1" ||
		state.Active.CatalogVersion != request.CurrentCatalogVersion || state.Active.ArtifactSHA256 != artifact.SHA256 ||
		state.Active.CurrentCatalogSHA256 == "" || state.Active.ContentSHA256 == "" || state.Active.SignatureSHA256 == "" ||
		!state.Active.IssuedAt.Equal(request.IssuedAt) || !state.Active.ExpiresAt.Equal(request.ExpiresAt) {
		t.Fatalf("Activate() state = %#v", state)
	}

	activeLookup, err := runtime.LookupWithRelease(t.Context(), "", netip.MustParseAddr("203.0.113.7"))
	if err != nil {
		t.Fatal(err)
	}
	assertReleaseRuntimeIdentity(t, activeLookup, state.Active)
	if activeLookup.Lookup.Attribution.Carrier != "current-v4" || activeLookup.LKG != nil {
		t.Fatalf("LookupWithRelease() = %#v", activeLookup)
	}
	if _, err := runtime.Lookup(t.Context(), "geo-2026.07", netip.MustParseAddr("203.0.113.7")); err == nil {
		t.Fatal("Lookup() accepted a catalog version outside the active release identity")
	}

	restoredStore := newReleaseRuntimeStore(t, directory, now, privateKey)
	restoredLoader := newReleaseRuntimeLoader(t, now, privateKey)
	restored, err := NewReleaseRuntime(restoredStore, restoredLoader)
	if err != nil {
		t.Fatal(err)
	}
	if err := restored.Load(t.Context()); err != nil {
		t.Fatal(err)
	}
	for _, address := range []string{"192.0.2.1", "2001:db9::1"} {
		lookup, err := restored.LookupWithRelease(t.Context(), "", netip.MustParseAddr(address))
		if err != nil {
			t.Fatalf("LookupWithRelease(%s) error = %v", address, err)
		}
		assertReleaseRuntimeIdentity(t, lookup, state.Active)
		if lookup.Lookup.Attribution.Resolution != analyticsgeo.ResolutionUnknown ||
			lookup.Lookup.Provenance.Version != request.CurrentCatalogVersion || lookup.Lookup.Provenance.SHA256 == "" {
			t.Fatalf("LookupWithRelease(%s) = %#v", address, lookup)
		}
	}
}

func newReleaseRuntimeStore(t *testing.T, directory string, now time.Time, privateKey ed25519.PrivateKey) *ReleaseStore {
	t.Helper()
	store, err := NewReleaseStore(ReleaseStoreConfig{
		Directory: directory, MaxArtifactBytes: 1 << 20, Now: func() time.Time { return now },
		TrustedKeys: map[string]ed25519.PublicKey{"geo-release-key-1": privateKey.Public().(ed25519.PublicKey)},
	})
	if err != nil {
		t.Fatal(err)
	}
	return store
}

func newReleaseRuntimeLoader(t *testing.T, now time.Time, privateKey ed25519.PrivateKey) *analyticsgeo.SignedFileLoader {
	t.Helper()
	keyring, err := analyticsgeo.NewTrustedEd25519Keyring(map[string]ed25519.PublicKey{
		"geo-release-key-1": privateKey.Public().(ed25519.PublicKey),
	})
	if err != nil {
		t.Fatal(err)
	}
	loader, err := analyticsgeo.NewSignedFileLoader(analyticsgeo.SignedFileLoaderConfig{
		Keyring: keyring, Now: func() time.Time { return now },
		MaxArtifactBytes: 1 << 20, MaxAggregateCatalogBytes: 1 << 20,
	})
	if err != nil {
		t.Fatal(err)
	}
	return loader
}

func assertReleaseRuntimeIdentity(t *testing.T, lookup ReleaseLookup, active ReleaseFact) {
	t.Helper()
	if lookup.Active != active || lookup.Lookup.Revision != active.Revision ||
		lookup.Lookup.Provenance.Version != active.CatalogVersion ||
		lookup.Lookup.Provenance.SHA256 != active.CurrentCatalogSHA256 {
		t.Fatalf("release identity mismatch: lookup=%#v active=%#v", lookup, active)
	}
}

var _ analyticsgeo.AuthorityReader = (*ReleaseRuntime)(nil)
