package certstore

import (
	"errors"
	"fmt"
	"testing"
	"time"
)

// Certificate activations are per-site deltas: the control plane publishes one
// site's binding at a time, so a node must accumulate them instead of
// requiring each command to repeat every site it ever activated.

func siteBundle(t *testing.T, version, siteID string, domains ...string) Bundle {
	t.Helper()
	material := issueTestMaterial(t, domains, testNow.Add(-time.Hour), testNow.Add(time.Hour), nil)
	return Bundle{SchemaVersion: SchemaVersion, VersionID: version, Bindings: []Binding{{
		SiteID: siteID, Domains: domains, CertificateChainPEM: material.chainPEM, PrivateKeyPEM: material.privatePEM,
	}}}
}

func resolveFor(siteID string, revision uint64, domain string) CertificateResolveRequest {
	return CertificateResolveRequest{
		TenantScopeID: testTenantScopeID, SiteID: siteID, CertificateID: "certificate-" + siteID,
		CertificateVersionID: testCertificateVersionID(siteID, revision), Domain: domain,
	}
}

func TestIndependentSingleSiteActivationsAccumulate(t *testing.T) {
	manager, err := newManager(RuntimeConfig{StateRoot: managedStateRoot(t), ListenAddress: "127.0.0.1", ListenPort: 18443},
		&fakeRuntime{}, func() time.Time { return testNow })
	if err != nil {
		t.Fatal(err)
	}
	first := siteBundle(t, "publish-a", "site-a", "a.example.test")
	if _, err := manager.ApplyWithActivation(t.Context(), first, activationFor(first, "event-a", 1, map[string]uint64{"site-a": 1})); err != nil {
		t.Fatal(err)
	}
	second := siteBundle(t, "publish-b", "site-b", "b.example.test")
	if _, err := manager.ApplyWithActivation(t.Context(), second, activationFor(second, "event-b", 1, map[string]uint64{"site-b": 1})); err != nil {
		t.Fatalf("second site published alone: %v", err)
	}
	assertResolvedCertificateVersion(t, manager, resolveFor("site-a", 1, "a.example.test"))
	assertResolvedCertificateVersion(t, manager, resolveFor("site-b", 1, "b.example.test"))
	if err := manager.SetCertificateVersionReferences(t.Context(), CertificateVersionReferences{Current: []string{
		testCertificateVersionID("site-a", 1), testCertificateVersionID("site-b", 1),
	}}); err != nil {
		t.Fatalf("both active versions as current: %v", err)
	}
}

func TestActivationAcceptsMoreThan64BindingsAndReferences(t *testing.T) {
	manager, err := newManager(RuntimeConfig{StateRoot: managedStateRoot(t), ListenAddress: "127.0.0.1", ListenPort: 18443},
		&fakeRuntime{}, func() time.Time { return testNow })
	if err != nil {
		t.Fatal(err)
	}
	const sites = 65
	bundle := Bundle{SchemaVersion: SchemaVersion, VersionID: "bulk-65"}
	versions := map[string]uint64{}
	var current []string
	for index := 0; index < sites; index++ {
		site := fmt.Sprintf("site-%03d", index)
		one := siteBundle(t, bundle.VersionID, site, fmt.Sprintf("s%03d.example.test", index))
		bundle.Bindings = append(bundle.Bindings, one.Bindings[0])
		versions[site] = 1
		current = append(current, testCertificateVersionID(site, 1))
	}
	if _, err := manager.ApplyWithActivation(t.Context(), bundle, activationFor(bundle, "event-bulk", 1, versions)); err != nil {
		t.Fatalf("%d bindings in one activation: %v", sites, err)
	}
	extra := siteBundle(t, "publish-extra", "site-extra", "extra.example.test")
	if _, err := manager.ApplyWithActivation(t.Context(), extra, activationFor(extra, "event-extra", 1, map[string]uint64{"site-extra": 1})); err != nil {
		t.Fatalf("site %d on the node: %v", sites+1, err)
	}
	current = append(current, testCertificateVersionID("site-extra", 1))
	if err := manager.SetCertificateVersionReferences(t.Context(), CertificateVersionReferences{Current: current}); err != nil {
		t.Fatalf("%d current references: %v", len(current), err)
	}
	assertResolvedCertificateVersion(t, manager, resolveFor("site-064", 1, "s064.example.test"))
	assertResolvedCertificateVersion(t, manager, resolveFor("site-extra", 1, "extra.example.test"))
}

func TestBindingRevisionOrdersEachSite(t *testing.T) {
	manager, err := newManager(RuntimeConfig{StateRoot: managedStateRoot(t), ListenAddress: "127.0.0.1", ListenPort: 18443},
		&fakeRuntime{}, func() time.Time { return testNow })
	if err != nil {
		t.Fatal(err)
	}
	v2 := siteBundle(t, "publish-v2", "site-a", "a.example.test")
	if _, err := manager.ApplyWithActivation(t.Context(), v2, activationFor(v2, "event-v2", 1, map[string]uint64{"site-a": 2})); err != nil {
		t.Fatal(err)
	}
	older := siteBundle(t, "publish-v1", "site-a", "a.example.test")
	if _, err := manager.ApplyWithActivation(t.Context(), older, activationFor(older, "event-v1", 1, map[string]uint64{"site-a": 1})); !errors.Is(err, ErrStaleActivation) {
		t.Fatalf("lower binding revision: %v, want stale", err)
	}
	// The same binding revision delivered by another command (a retry, or a
	// recovery publication) is accepted without changing the site.
	again := cloneCertificateBundle(v2)
	again.VersionID = "publish-v2-again"
	if _, err := manager.ApplyWithActivation(t.Context(), again, activationFor(again, "event-v2-again", 1, map[string]uint64{"site-a": 2})); err != nil {
		t.Fatalf("same binding revision redelivered: %v", err)
	}
	// The same binding revision with other content is a conflict.
	other := siteBundle(t, "publish-v2-other", "site-a", "a.example.test")
	if _, err := manager.ApplyWithActivation(t.Context(), other, activationFor(other, "event-v2-other", 1, map[string]uint64{"site-a": 2})); !errors.Is(err, ErrConflict) {
		t.Fatalf("same binding revision, other certificate: %v, want conflict", err)
	}
	// A higher binding revision may bind another certificate asset.
	rebound := siteBundle(t, "publish-v3", "site-a", "a.example.test")
	activation := activationFor(rebound, "event-v3", 1, map[string]uint64{"site-a": 3})
	activation.Certificates[0].CertificateID = "certificate-other"
	activation.Certificates[0].Version = 1
	if _, err := manager.ApplyWithActivation(t.Context(), rebound, activation); err != nil {
		t.Fatalf("rebinding to another asset at a higher revision: %v", err)
	}
	// The tenant of a site never changes.
	moved := siteBundle(t, "publish-v4", "site-a", "a.example.test")
	activation = activationFor(moved, "event-v4", 1, map[string]uint64{"site-a": 4})
	activation.Certificates[0].TenantID = "tenant-other"
	if _, err := manager.ApplyWithActivation(t.Context(), moved, activation); !errors.Is(err, ErrConflict) {
		t.Fatalf("site moved to another tenant: %v, want conflict", err)
	}
}

func TestRemovedSitesRemoveOnlyTheNamedSite(t *testing.T) {
	manager, err := newManager(RuntimeConfig{StateRoot: managedStateRoot(t), ListenAddress: "127.0.0.1", ListenPort: 18443},
		&fakeRuntime{}, func() time.Time { return testNow })
	if err != nil {
		t.Fatal(err)
	}
	for _, site := range []string{"site-a", "site-b"} {
		bundle := siteBundle(t, "publish-"+site, site, site[5:]+".example.test")
		if _, err := manager.ApplyWithActivation(t.Context(), bundle, activationFor(bundle, "event-"+site, 1, map[string]uint64{site: 1})); err != nil {
			t.Fatal(err)
		}
	}
	removal := removalBundle("remove-a")
	activation := activationFor(removal, "event-remove-a", 1, nil)
	activation.RemovedSites = []RemovedSite{{TenantID: "tenant-a", TenantScopeID: testTenantScopeID, SiteID: "site-a", BindingRevision: 2}}
	if _, err := manager.ApplyWithActivation(t.Context(), removal, activation); err != nil {
		t.Fatalf("remove site-a: %v", err)
	}
	if _, err := manager.ResolveCertificateVersion(t.Context(), resolveFor("site-a", 1, "a.example.test")); !errors.Is(err, ErrCertificateUnavailable) {
		t.Fatalf("removed site resolved: %v", err)
	}
	assertResolvedCertificateVersion(t, manager, resolveFor("site-b", 1, "b.example.test"))

	// The removal is remembered: the binding it replaced cannot come back.
	stale := siteBundle(t, "publish-a-stale", "site-a", "a.example.test")
	if _, err := manager.ApplyWithActivation(t.Context(), stale, activationFor(stale, "event-a-stale", 1, map[string]uint64{"site-a": 1})); !errors.Is(err, ErrStaleActivation) {
		t.Fatalf("binding older than the removal: %v, want stale", err)
	}
	rebound := siteBundle(t, "publish-a-3", "site-a", "a.example.test")
	if _, err := manager.ApplyWithActivation(t.Context(), rebound, activationFor(rebound, "event-a-3", 1, map[string]uint64{"site-a": 3})); err != nil {
		t.Fatalf("binding newer than the removal: %v", err)
	}
	assertResolvedCertificateVersion(t, manager, resolveFor("site-a", 3, "a.example.test"))
}

// fix-dnscert4：控制端续签下发占用绑定号 N（新版本已到本节点），用户改绑后从 N+1 发布；
// 若续签撤销后号段被跳过，节点照样按更高号接受，并把已到的续签版本退到保留区。
func TestBindingRevisionAcceptsSkippedRevisionsAfterSupersededRenewal(t *testing.T) {
	manager, err := newManager(RuntimeConfig{StateRoot: managedStateRoot(t), ListenAddress: "127.0.0.1", ListenPort: 18443},
		&fakeRuntime{}, func() time.Time { return testNow })
	if err != nil {
		t.Fatal(err)
	}
	old := siteBundle(t, "publish-old", "site-a", "a.example.test")
	if _, err := manager.ApplyWithActivation(t.Context(), old, activationFor(old, "event-old", 1, map[string]uint64{"site-a": 1})); err != nil {
		t.Fatal(err)
	}
	renewed := siteBundle(t, "publish-renewed", "site-a", "a.example.test")
	if _, err := manager.ApplyWithActivation(t.Context(), renewed, activationFor(renewed, "event-renewed", 1, map[string]uint64{"site-a": 2})); err != nil {
		t.Fatal(err)
	}
	user := siteBundle(t, "publish-user", "site-a", "a.example.test")
	if _, err := manager.ApplyWithActivation(t.Context(), user, activationFor(user, "event-user", 1, map[string]uint64{"site-a": 2})); !errors.Is(err, ErrConflict) {
		t.Fatalf("user publication at the renewal's revision: %v, want conflict (the control plane must skip it)", err)
	}
	if _, err := manager.ApplyWithActivation(t.Context(), user, activationFor(user, "event-user-next", 1, map[string]uint64{"site-a": 3})); err != nil {
		t.Fatalf("user publication past the renewal's revision: %v", err)
	}
	skipped := siteBundle(t, "publish-skip", "site-a", "a.example.test")
	if _, err := manager.ApplyWithActivation(t.Context(), skipped, activationFor(skipped, "event-skip", 1, map[string]uint64{"site-a": 7})); err != nil {
		t.Fatalf("binding revision gap (a superseded renewal's reservation): %v", err)
	}
}
