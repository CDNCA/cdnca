package certstore

import (
	"errors"
	"os"
	"path/filepath"
	"testing"
	"time"
)

func newIndexTestManager(t *testing.T, root string) *Manager {
	t.Helper()
	manager, err := newManager(RuntimeConfig{StateRoot: root, ListenAddress: "127.0.0.1", ListenPort: 18443},
		&fakeRuntime{}, func() time.Time { return testNow })
	if err != nil {
		t.Fatal(err)
	}
	return manager
}

func applySite(t *testing.T, manager *Manager, siteID string, revision uint64, domains ...string) Bundle {
	t.Helper()
	bundle := siteBundle(t, siteID+"-r"+string(rune('0'+revision)), siteID, domains...)
	if _, err := manager.ApplyWithActivation(t.Context(), bundle,
		activationFor(bundle, "event-"+bundle.VersionID, 1, map[string]uint64{siteID: revision})); err != nil {
		t.Fatal(err)
	}
	return bundle
}

// A rotated version stays resolvable while the references protect it and is
// removed once they drop it.
func TestRotationKeepsReferencedVersionsAndCollectsTheRest(t *testing.T) {
	root := managedStateRoot(t)
	manager := newIndexTestManager(t, root)
	applySite(t, manager, "site-a", 1, "a.example.test")
	v1, v2, v3 := testCertificateVersionID("site-a", 1), testCertificateVersionID("site-a", 2), testCertificateVersionID("site-a", 3)
	if err := manager.SetCertificateVersionReferences(t.Context(), CertificateVersionReferences{Current: []string{v1}}); err != nil {
		t.Fatal(err)
	}
	applySite(t, manager, "site-a", 2, "a.example.test")
	applySite(t, manager, "site-a", 3, "a.example.test")
	// v1 is still the runtime's current: resolvable though retained.
	assertResolvedCertificateVersion(t, manager, resolveFor("site-a", 1, "a.example.test"))
	// v2 was never referenced: retained but not resolvable.
	if _, err := manager.ResolveCertificateVersion(t.Context(), resolveFor("site-a", 2, "a.example.test")); !errors.Is(err, ErrCertificateUnavailable) {
		t.Fatalf("unreferenced retained version resolved: %v", err)
	}
	if err := manager.SetCertificateVersionReferences(t.Context(), CertificateVersionReferences{Current: []string{v3}, Previous: []string{v1}}); err != nil {
		t.Fatal(err)
	}
	assertResolvedCertificateVersion(t, manager, resolveFor("site-a", 1, "a.example.test"))
	key := siteKey(testTenantScopeID, "site-a")
	if _, err := os.Lstat(manager.store.siteVersionDirectory(key, v2)); !errors.Is(err, os.ErrNotExist) {
		t.Fatalf("unreferenced v2 files were kept: %v", err)
	}
	if err := manager.SetCertificateVersionReferences(t.Context(), CertificateVersionReferences{Current: []string{v3}}); err != nil {
		t.Fatal(err)
	}
	if _, err := os.Lstat(manager.store.siteVersionDirectory(key, v1)); !errors.Is(err, os.ErrNotExist) {
		t.Fatalf("dropped v1 files were kept: %v", err)
	}
	record, found, err := manager.store.readSiteRecord(key)
	if err != nil || !found || record.Active == nil || record.Active.CertificateVersionID != v3 || len(record.Retained) != 0 {
		t.Fatalf("site record after collection = %#v (%v, %v)", record, found, err)
	}
	if entries, err := os.ReadDir(manager.store.gc); err != nil || len(entries) != 0 {
		t.Fatalf("collectable markers left: %v %v", entries, err)
	}
	assertResolvedCertificateVersion(t, manager, resolveFor("site-a", 3, "a.example.test"))
}

// One certificate version may be bound to several sites (a wildcard); it is
// the same material everywhere.
func TestSharedVersionAcrossSitesMustBeIdentical(t *testing.T) {
	manager := newIndexTestManager(t, managedStateRoot(t))
	material := issueTestMaterial(t, []string{"*.shared.example.test"}, testNow.Add(-time.Hour), testNow.Add(time.Hour), nil)
	shared := "018f47a2-5b9c-7d31-8a60-104c9c0b7aaa"
	apply := func(siteID, domain string, chain, key string) error {
		bundle := Bundle{SchemaVersion: SchemaVersion, VersionID: "shared-" + siteID, Bindings: []Binding{{
			SiteID: siteID, Domains: []string{domain}, CertificateChainPEM: chain, PrivateKeyPEM: key,
		}}}
		activation := activationFor(bundle, "event-shared-"+siteID, 1, map[string]uint64{siteID: 1})
		activation.Certificates[0].CertificateVersionID = shared
		activation.Certificates[0].CertificateID = "certificate-shared"
		_, err := manager.ApplyWithActivation(t.Context(), bundle, activation)
		return err
	}
	if err := apply("site-x", "*.shared.example.test", material.chainPEM, material.privatePEM); err != nil {
		t.Fatal(err)
	}
	if err := apply("site-y", "*.shared.example.test", material.chainPEM, material.privatePEM); err != nil {
		t.Fatalf("same version on a second site: %v", err)
	}
	other := issueTestMaterial(t, []string{"*.shared.example.test"}, testNow.Add(-time.Hour), testNow.Add(time.Hour), nil)
	if err := apply("site-z", "*.shared.example.test", other.chainPEM, other.privatePEM); !errors.Is(err, ErrConflict) {
		t.Fatalf("same version id with other material: %v, want conflict", err)
	}
	for _, site := range []string{"site-x", "site-y"} {
		resolved, err := manager.ResolveCertificateVersion(t.Context(), CertificateResolveRequest{
			TenantScopeID: testTenantScopeID, SiteID: site, CertificateVersionID: shared, Domain: "*.shared.example.test",
		})
		if err != nil || resolved.CertificateSHA256 == [32]byte{} || resolved.PrivateKeySHA256 == [32]byte{} {
			t.Fatalf("%s: %#v %v", site, resolved, err)
		}
	}
}

// Resolve checks the files it returns; a tampered file is unavailable.
func TestResolveRejectsTamperedSiteFiles(t *testing.T) {
	for name, tamper := range map[string]func(t *testing.T, path string){
		"broad mode": func(t *testing.T, path string) {
			if err := os.Chmod(path, 0o440); err != nil {
				t.Fatal(err)
			}
		},
		"hard link": func(t *testing.T, path string) {
			if err := os.Link(path, filepath.Join(filepath.Dir(filepath.Dir(path)), "leak")); err != nil {
				t.Fatal(err)
			}
		},
		"replaced": func(t *testing.T, path string) {
			directory := filepath.Dir(path)
			if err := os.Chmod(directory, 0o700); err != nil {
				t.Fatal(err)
			}
			if err := os.Remove(path); err != nil {
				t.Fatal(err)
			}
			if err := os.WriteFile(path, []byte("short"), 0o400); err != nil {
				t.Fatal(err)
			}
			if err := os.Chmod(directory, 0o500); err != nil {
				t.Fatal(err)
			}
		},
	} {
		t.Run(name, func(t *testing.T) {
			manager := newIndexTestManager(t, managedStateRoot(t))
			applySite(t, manager, "site-a", 1, "a.example.test")
			resolved, err := manager.ResolveCertificateVersion(t.Context(), resolveFor("site-a", 1, "a.example.test"))
			if err != nil {
				t.Fatal(err)
			}
			tamper(t, resolved.PrivateKeyPath)
			if _, err := manager.ResolveCertificateVersion(t.Context(), resolveFor("site-a", 1, "a.example.test")); !errors.Is(err, ErrCertificateUnavailable) {
				t.Fatalf("tampered key resolved: %v", err)
			}
		})
	}
}

// An apply interrupted after its release became the healthy active release
// is finished by the next operation; the change of a release that never
// became current is dropped.
func TestInterruptedIndexChangeIsSettled(t *testing.T) {
	root := managedStateRoot(t)
	manager := newIndexTestManager(t, root)
	applySite(t, manager, "site-a", 1, "a.example.test")

	bundle := siteBundle(t, "site-b-r1", "site-b", "b.example.test")
	artifact, err := CompileWithActivation(bundle, manager.config, testNow,
		activationFor(bundle, "event-site-b", 1, map[string]uint64{"site-b": 1}))
	if err != nil {
		t.Fatal(err)
	}
	journal, err := manager.planIndex(artifact)
	if err != nil || len(journal.Sites) != 1 {
		t.Fatalf("plan = %#v, %v", journal, err)
	}

	// The release never became current: the change is discarded.
	journal.Target = filepath.Join("versions", "never-"+artifact.Digest)
	if err := manager.store.writeIndexJournal(journal); err != nil {
		t.Fatal(err)
	}
	applySite(t, manager, "site-c", 1, "c.example.test")
	if _, found, _ := manager.store.readIndexJournal(); found {
		t.Fatal("journal of a release that never became current was kept")
	}
	if _, err := manager.ResolveCertificateVersion(t.Context(), resolveFor("site-b", 1, "b.example.test")); !errors.Is(err, ErrCertificateUnavailable) {
		t.Fatalf("discarded change resolved: %v", err)
	}

	// The release became current, lkg and status, then the process stopped
	// before the index changed: the next operation applies it.
	stage, err := manager.store.stage(artifact)
	if err != nil {
		t.Fatal(err)
	}
	target, err := manager.store.commit(stage, artifact)
	if err != nil {
		t.Fatal(err)
	}
	journal.Target = target
	if err := manager.store.writeIndexJournal(journal); err != nil {
		t.Fatal(err)
	}
	for _, pointer := range []string{"current", "lkg"} {
		if err := manager.store.setPointer(pointer, target); err != nil {
			t.Fatal(err)
		}
	}
	if err := manager.store.writeStatus(statusFromArtifact(artifact, testNow)); err != nil {
		t.Fatal(err)
	}
	restarted := newIndexTestManager(t, root)
	if err := restarted.SetCertificateVersionReferences(t.Context(), CertificateVersionReferences{
		Current: []string{testCertificateVersionID("site-b", 1)},
	}); err != nil {
		t.Fatalf("references after an interrupted apply: %v", err)
	}
	assertResolvedCertificateVersion(t, restarted, resolveFor("site-b", 1, "b.example.test"))
	assertResolvedCertificateVersion(t, restarted, resolveFor("site-a", 1, "a.example.test"))
}

// Only current, lkg and the release an activation replaced are kept.
func TestReleasesArePruned(t *testing.T) {
	root := managedStateRoot(t)
	manager := newIndexTestManager(t, root)
	for index, site := range []string{"site-a", "site-b", "site-c", "site-d"} {
		applySite(t, manager, site, uint64(1), string(rune('a'+index))+".example.test")
	}
	entries, err := os.ReadDir(manager.store.versions)
	if err != nil || len(entries) > 2 {
		t.Fatalf("releases kept = %d (%v)", len(entries), err)
	}
	for _, site := range []string{"site-a", "site-b", "site-c", "site-d"} {
		assertResolvedCertificateVersion(t, manager, resolveFor(site, 1, site[5:]+".example.test"))
	}
}
