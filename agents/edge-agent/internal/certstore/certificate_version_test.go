package certstore

import (
	"context"
	"errors"
	"os"
	"path/filepath"
	"strings"
	"testing"
	"time"
)

const (
	testTenantScopeID        = "018f47a2-5b9c-7d31-8a60-104c9c0b7101"
	testCertificateVersionV1 = "018f47a2-5b9c-7d31-8a60-104c9c0b7104"
	testCertificateVersionV2 = "018f47a2-5b9c-7d31-8a60-104c9c0b7105"
	testCertificateVersionV3 = "018f47a2-5b9c-7d31-8a60-104c9c0b7106"
)

func TestManagerResolvesCanonicalCertificateVersionAcrossRestart(t *testing.T) {
	root := managedStateRoot(t)
	now := testNow
	config := RuntimeConfig{StateRoot: root, ListenAddress: "127.0.0.1", ListenPort: 18443}
	manager, err := newManager(config, &fakeRuntime{}, func() time.Time { return now })
	if err != nil {
		t.Fatal(err)
	}

	firstBundle := validTestBundle(t, "cert-release-v1", "one.example.test")
	firstActivation := activationFor(firstBundle, "event-v1", 1, map[string]uint64{"site": 1})
	firstActivation.Certificates[0].CertificateVersionID = testCertificateVersionV1
	if _, err := manager.ApplyWithActivation(t.Context(), firstBundle, firstActivation); err != nil {
		t.Fatal(err)
	}
	firstRequest := CertificateResolveRequest{
		TenantScopeID: testTenantScopeID, SiteID: "site", CertificateID: "certificate-site",
		CertificateVersionID: testCertificateVersionV1, Domain: "one.example.test",
	}
	assertResolvedCertificateVersion(t, manager, firstRequest)

	secondBundle := validTestBundle(t, "cert-release-v2", "two.example.test")
	secondActivation := activationFor(secondBundle, "event-v2", 1, map[string]uint64{"site": 2})
	secondActivation.Certificates[0].CertificateVersionID = testCertificateVersionV2
	if _, err := manager.ApplyWithActivation(t.Context(), secondBundle, secondActivation); err != nil {
		t.Fatal(err)
	}
	if _, err := manager.ResolveCertificateVersion(t.Context(), firstRequest); !errors.Is(err, ErrCertificateUnavailable) {
		t.Fatalf("retired unreferenced version resolved: %v", err)
	}
	if err := manager.SetCertificateVersionReferences(t.Context(), CertificateVersionReferences{
		Current: []string{testCertificateVersionV1},
	}); !errors.Is(err, ErrCertificateUnavailable) {
		t.Fatalf("retired version accepted as current: %v", err)
	}
	if err := manager.SetCertificateVersionReferences(t.Context(), CertificateVersionReferences{
		Current: []string{testCertificateVersionV2}, Previous: []string{testCertificateVersionV1},
	}); err != nil {
		t.Fatal(err)
	}
	assertResolvedCertificateVersion(t, manager, firstRequest)

	restarted, err := newManager(config, &fakeRuntime{}, func() time.Time { return now })
	if err != nil {
		t.Fatal(err)
	}
	if _, err := restarted.Recover(t.Context()); err != nil {
		t.Fatal(err)
	}
	assertResolvedCertificateVersion(t, restarted, firstRequest)

	for name, mutate := range map[string]func(*CertificateResolveRequest){
		"scope": func(value *CertificateResolveRequest) { value.TenantScopeID = "018f47a2-5b9c-7d31-8a60-104c9c0b7199" },
		"site":  func(value *CertificateResolveRequest) { value.SiteID = "other-site" },
		"cert":  func(value *CertificateResolveRequest) { value.CertificateID = "other-certificate" },
		"version": func(value *CertificateResolveRequest) {
			value.CertificateVersionID = "018f47a2-5b9c-7d31-8a60-104c9c0b7199"
		},
		"domain": func(value *CertificateResolveRequest) { value.Domain = "other.example.test" },
	} {
		t.Run("wrong-"+name, func(t *testing.T) {
			request := firstRequest
			mutate(&request)
			_, err := restarted.ResolveCertificateVersion(t.Context(), request)
			if !errors.Is(err, ErrCertificateUnavailable) || errors.Is(err, ErrCertificateNotValidNow) {
				t.Fatalf("ResolveCertificateVersion() error = %v", err)
			}
		})
	}

	// Outside its validity window the binding is still the site's, but not
	// servable: the site runtime turns only that site's HTTPS off.
	now = testNow.Add(2 * time.Hour)
	if _, err := restarted.ResolveCertificateVersion(t.Context(), firstRequest); !errors.Is(err, ErrCertificateUnavailable) ||
		!errors.Is(err, ErrCertificateNotValidNow) {
		t.Fatalf("expired certificate resolved: %v", err)
	}
	now = testNow.Add(-2 * time.Hour)
	if _, err := restarted.ResolveCertificateVersion(t.Context(), firstRequest); !errors.Is(err, ErrCertificateNotValidNow) {
		t.Fatalf("not yet valid certificate resolved: %v", err)
	}
}

func TestManagerRejectsCertificateVersionIdentityConflicts(t *testing.T) {
	manager, err := newManager(
		RuntimeConfig{StateRoot: managedStateRoot(t), ListenAddress: "127.0.0.1", ListenPort: 18443},
		&fakeRuntime{}, func() time.Time { return testNow },
	)
	if err != nil {
		t.Fatal(err)
	}
	baselineBundle := validTestBundle(t, "cert-identity-v1", "one.example.test")
	baselineActivation := activationFor(baselineBundle, "event-v1", 1, map[string]uint64{"site": 1})
	baselineActivation.Certificates[0].CertificateVersionID = testCertificateVersionV1
	baseline, err := manager.ApplyWithActivation(t.Context(), baselineBundle, baselineActivation)
	if err != nil {
		t.Fatal(err)
	}
	if replay, err := manager.ApplyWithActivation(t.Context(), baselineBundle, baselineActivation); err != nil || replay.Changed {
		t.Fatalf("same UUID and bytes replay = (%#v, %v)", replay, err)
	}

	conflictBundle := validTestBundle(t, "cert-identity-v2", "different.example.test")
	conflictActivation := activationFor(conflictBundle, "event-v2", 1, map[string]uint64{"site": 2})
	conflictActivation.Certificates[0].CertificateVersionID = testCertificateVersionV1
	result, err := manager.ApplyWithActivation(t.Context(), conflictBundle, conflictActivation)
	if !errors.Is(err, ErrConflict) || !result.RunningVersionUnchanged || result.ActiveDigest != baseline.ActiveDigest {
		t.Fatalf("same UUID different bytes = (%#v, %v)", result, err)
	}

	// Every activation names its certificate version and scope.
	legacyBundle := validTestBundle(t, "legacy-v1", "legacy.example.test")
	legacyActivation := activationFor(legacyBundle, "legacy-event", 1, map[string]uint64{"site": 2})
	legacyActivation.Certificates[0].TenantScopeID = ""
	legacyActivation.Certificates[0].CertificateVersionID = ""
	if _, err := manager.ApplyWithActivation(t.Context(), legacyBundle, legacyActivation); !errors.Is(err, ErrInvalidBundle) {
		t.Fatalf("activation without version identity: %v, want ErrInvalidBundle", err)
	}
}

func TestCertificateVersionReferencesRejectUnknownAndPreservePins(t *testing.T) {
	manager, err := newManager(
		RuntimeConfig{StateRoot: managedStateRoot(t), ListenAddress: "127.0.0.1", ListenPort: 18443},
		&fakeRuntime{}, func() time.Time { return testNow },
	)
	if err != nil {
		t.Fatal(err)
	}
	bundle := validTestBundle(t, "cert-reference-v1", "one.example.test")
	activation := activationFor(bundle, "event-v1", 1, map[string]uint64{"site": 1})
	activation.Certificates[0].CertificateVersionID = testCertificateVersionV1
	if _, err := manager.ApplyWithActivation(t.Context(), bundle, activation); err != nil {
		t.Fatal(err)
	}
	valid := CertificateVersionReferences{Current: []string{testCertificateVersionV1}}
	if err := manager.SetCertificateVersionReferences(t.Context(), valid); err != nil {
		t.Fatal(err)
	}
	if err := manager.SetCertificateVersionReferences(t.Context(), CertificateVersionReferences{
		Current: []string{"018f47a2-5b9c-7d31-8a60-104c9c0b7199"},
	}); !errors.Is(err, ErrCertificateUnavailable) {
		t.Fatalf("unknown reference error = %v", err)
	}
	got, err := manager.CertificateVersionReferences(t.Context())
	if err != nil || len(got.Current) != 1 || got.Current[0] != testCertificateVersionV1 || len(got.Previous) != 0 {
		t.Fatalf("references after rejected write = (%#v, %v)", got, err)
	}
}

func TestCertificateVersionLookupIgnoresUnrelatedExpiredReleases(t *testing.T) {
	now := testNow
	manager, err := newManager(
		RuntimeConfig{StateRoot: managedStateRoot(t), ListenAddress: "127.0.0.1", ListenPort: 18443},
		&fakeRuntime{}, func() time.Time { return now },
	)
	if err != nil {
		t.Fatal(err)
	}
	apply := func(bundle Bundle, event string, version uint64, versionID string) {
		t.Helper()
		activation := activationFor(bundle, event, 1, map[string]uint64{"site": version})
		activation.Certificates[0].CertificateVersionID = versionID
		if _, err := manager.ApplyWithActivation(t.Context(), bundle, activation); err != nil {
			t.Fatal(err)
		}
	}
	apply(certificateVersionBundle(t, "expired-unrelated", "expired.example.test", testNow.Add(30*time.Minute)),
		"event-v1", 1, testCertificateVersionV1)
	apply(certificateVersionBundle(t, "previous-target", "previous.example.test", testNow.Add(2*time.Hour)),
		"event-v2", 2, testCertificateVersionV2)
	apply(certificateVersionBundle(t, "current-target", "current.example.test", testNow.Add(2*time.Hour)),
		"event-v3", 3, testCertificateVersionV3)

	references := CertificateVersionReferences{
		Current: []string{testCertificateVersionV3}, Previous: []string{testCertificateVersionV2},
	}
	if err := manager.SetCertificateVersionReferences(t.Context(), references); err != nil {
		t.Fatal(err)
	}
	now = testNow.Add(time.Hour)
	if err := manager.SetCertificateVersionReferences(t.Context(), references); err != nil {
		t.Fatalf("unrelated expired release poisoned references: %v", err)
	}
	assertResolvedCertificateVersion(t, manager, CertificateResolveRequest{
		TenantScopeID: testTenantScopeID, SiteID: "site", CertificateID: "certificate-site",
		CertificateVersionID: testCertificateVersionV2, Domain: "previous.example.test",
	})
}

func certificateVersionBundle(t *testing.T, version, domain string, notAfter time.Time) Bundle {
	t.Helper()
	material := issueTestMaterial(t, []string{domain}, testNow.Add(-time.Hour), notAfter, nil)
	return Bundle{SchemaVersion: SchemaVersion, VersionID: version, Bindings: []Binding{{
		SiteID: "site", Domains: []string{domain}, CertificateChainPEM: material.chainPEM, PrivateKeyPEM: material.privatePEM,
	}}}
}

func assertResolvedCertificateVersion(t *testing.T, manager *Manager, request CertificateResolveRequest) {
	t.Helper()
	resolved, err := manager.ResolveCertificateVersion(context.Background(), request)
	if err != nil {
		t.Fatal(err)
	}
	if resolved.CertificateVersionID != request.CertificateVersionID || resolved.TenantScopeID != request.TenantScopeID ||
		resolved.SiteID != request.SiteID || resolved.CertificateID != request.CertificateID ||
		len(resolved.Domains) != 1 || resolved.Domains[0] != request.Domain || resolved.NotBefore.IsZero() || resolved.NotAfter.IsZero() ||
		resolved.NotAfter.Before(resolved.NotBefore) || resolved.LeafSHA256 == [32]byte{} {
		t.Fatalf("resolved certificate = %#v", resolved)
	}
	for _, path := range []string{resolved.CertificatePath, resolved.PrivateKeyPath} {
		if !filepath.IsAbs(path) || !strings.HasPrefix(path, manager.config.StateRoot+string(os.PathSeparator)) {
			t.Fatalf("resolved path escaped state root: %q", path)
		}
		info, err := os.Lstat(path)
		if err != nil || !info.Mode().IsRegular() || info.Mode().Perm() != 0o400 || info.Mode()&os.ModeSymlink != 0 {
			t.Fatalf("resolved immutable file %q = (%v, %v)", path, info, err)
		}
	}
}
