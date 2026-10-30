package certstore

import (
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"os"
	"path/filepath"
	"strings"
	"sync"
	"testing"
	"time"

	"github.com/google/uuid"
)

func TestCompileWithActivationIsDeterministicAndPrivateFree(t *testing.T) {
	config := RuntimeConfig{StateRoot: filepath.Join(t.TempDir(), "state"), ListenAddress: "127.0.0.1", ListenPort: 18443}
	bundle := twoSiteBundle(t, "cert-v1")
	activation := activationFor(bundle, "event-v1", 1, map[string]uint64{"site-a": 1, "site-b": 3})
	activation.Certificates[0], activation.Certificates[1] = activation.Certificates[1], activation.Certificates[0]

	first, err := CompileWithActivation(bundle, config, testNow, activation)
	if err != nil {
		t.Fatal(err)
	}
	second, err := CompileWithActivation(bundle, config, testNow, activation)
	if err != nil {
		t.Fatal(err)
	}
	if first.Digest != second.Digest || first.Digest == "" {
		t.Fatalf("nondeterministic activation digest %q != %q", first.Digest, second.Digest)
	}
	if first.Manifest.Activation == nil || first.Manifest.Activation.Certificates[0].SiteID != "site-a" {
		t.Fatalf("activation was not normalized: %#v", first.Manifest.Activation)
	}
	manifest := artifactContent(t, first, "manifest.json")
	if containsPrivateKey(manifest) {
		t.Fatalf("manifest contains private material: %s", manifest)
	}
	var decoded Manifest
	if err := json.Unmarshal(manifest, &decoded); err != nil || decoded.Activation == nil || decoded.Activation.CommandEventID != "event-v1" {
		t.Fatalf("manifest activation = %#v, error = %v", decoded.Activation, err)
	}

	changed := activation
	changed.CommandEventID = "event-v2"
	third, err := CompileWithActivation(bundle, config, testNow, changed)
	if err != nil {
		t.Fatal(err)
	}
	if third.Digest == first.Digest {
		t.Fatal("activation binding did not affect artifact digest")
	}
}

func TestManagerActivationProgressionAndRestart(t *testing.T) {
	root := managedStateRoot(t)
	config := RuntimeConfig{StateRoot: root, ListenAddress: "127.0.0.1", ListenPort: 18443}
	runtime := &fakeRuntime{}
	manager, err := newManager(config, runtime, func() time.Time { return testNow })
	if err != nil {
		t.Fatal(err)
	}
	bundleV1 := twoSiteBundle(t, "cert-v1")
	activationV1 := activationFor(bundleV1, "event-v1", 1, map[string]uint64{"site-a": 1, "site-b": 1})
	baseline, err := manager.ApplyWithActivation(context.Background(), bundleV1, activationV1)
	if err != nil || !baseline.Changed {
		t.Fatalf("ApplyWithActivation(v1) = (%#v, %v)", baseline, err)
	}
	idempotent, err := manager.ApplyWithActivation(context.Background(), bundleV1, activationV1)
	if err != nil || idempotent.Changed || !idempotent.RunningVersionUnchanged {
		t.Fatalf("idempotent apply = (%#v, %v)", idempotent, err)
	}

	restartedRuntime := &fakeRuntime{}
	restarted, err := newManager(config, restartedRuntime, func() time.Time { return testNow })
	if err != nil {
		t.Fatal(err)
	}
	if _, err := restarted.Recover(context.Background()); err != nil {
		t.Fatal(err)
	}
	status, err := restarted.Status(context.Background())
	if err != nil || status.Activation == nil || status.Activation.CommandEventID != activationV1.CommandEventID {
		t.Fatalf("recovered status = (%#v, %v)", status, err)
	}
	statusJSON, err := os.ReadFile(filepath.Join(root, "status.json"))
	if err != nil {
		t.Fatal(err)
	}
	if containsPrivateKey(statusJSON) {
		t.Fatalf("status contains private material: %s", statusJSON)
	}

	bundleV2 := twoSiteBundle(t, "cert-v2")
	bundleV2.Bindings[1] = bundleV1.Bindings[1]
	activationV2 := activationFor(bundleV2, "event-v2", 1, map[string]uint64{"site-a": 2, "site-b": 1})
	rotated, err := restarted.ApplyWithActivation(context.Background(), bundleV2, activationV2)
	if err != nil || !rotated.Changed || rotated.ActiveVersionID != bundleV2.VersionID {
		t.Fatalf("single-site rotation = (%#v, %v)", rotated, err)
	}
}

func TestManagerRejectsStaleOrConflictingCertificateActivation(t *testing.T) {
	config := RuntimeConfig{StateRoot: managedStateRoot(t), ListenAddress: "127.0.0.1", ListenPort: 18443}
	manager, err := newManager(config, &fakeRuntime{}, func() time.Time { return testNow })
	if err != nil {
		t.Fatal(err)
	}
	baselineBundle := twoSiteBundle(t, "cert-v2")
	baselineActivation := activationFor(baselineBundle, "event-v2", 1, map[string]uint64{"site-a": 2, "site-b": 2})
	baseline, err := manager.ApplyWithActivation(context.Background(), baselineBundle, baselineActivation)
	if err != nil {
		t.Fatal(err)
	}

	tests := []struct {
		name   string
		mutate func(*Bundle, *ActivationMetadata)
		want   error
	}{
		{name: "version-downgrade", mutate: func(_ *Bundle, value *ActivationMetadata) {
			value.Certificates[0].Version, value.Certificates[0].BindingRevision = 1, 1
			value.Certificates[0].CertificateVersionID = testCertificateVersionID(value.Certificates[0].SiteID, 1)
		}, want: ErrStaleActivation},
		{name: "tenant-replaced", mutate: func(_ *Bundle, value *ActivationMetadata) { value.Certificates[0].TenantID = "tenant-other" }, want: ErrConflict},
		{name: "certificate-replaced", mutate: func(_ *Bundle, value *ActivationMetadata) { value.Certificates[0].CertificateID = "certificate-other" }, want: ErrConflict},
		// Same binding revision, other material: a conflict even while another
		// site of the command advances.
		{name: "same-version-uuid-replaced-behind-other-progress", mutate: func(bundle *Bundle, value *ActivationMetadata) {
			replacement := validTestBundle(t, bundle.VersionID, "replacement.example.test")
			replacement.Bindings[0].SiteID = "site-a"
			bundle.Bindings[0] = replacement.Bindings[0]
			value.Certificates[0].CertificateVersionID = testCertificateVersionID("site-a", 99)
			value.Certificates[1].Version, value.Certificates[1].BindingRevision = 3, 3
			value.Certificates[1].CertificateVersionID = testCertificateVersionID("site-b", 3)
		}, want: ErrConflict},
	}
	for _, test := range tests {
		t.Run(test.name, func(t *testing.T) {
			candidate := cloneCertificateBundle(baselineBundle)
			candidate.VersionID = "candidate-" + test.name
			activation := activationFor(candidate, "candidate-event-"+test.name, 1, map[string]uint64{"site-a": 2, "site-b": 2})
			test.mutate(&candidate, &activation)
			result, err := manager.ApplyWithActivation(context.Background(), candidate, activation)
			if !errors.Is(err, test.want) || !result.RunningVersionUnchanged || result.ActiveDigest != baseline.ActiveDigest {
				t.Fatalf("ApplyWithActivation() = (%#v, %v)", result, err)
			}
			status, statusErr := manager.Status(context.Background())
			if statusErr != nil || status.Digest != baseline.ActiveDigest {
				t.Fatalf("status after rejection = (%#v, %v)", status, statusErr)
			}
		})
	}
}

// A command that repeats the node's revisions, or names only some of its
// sites, is accepted: activations are per-site deltas.
func TestManagerAcceptsRedeliveryAndPartialCommands(t *testing.T) {
	manager, err := newManager(RuntimeConfig{StateRoot: managedStateRoot(t), ListenAddress: "127.0.0.1", ListenPort: 18443},
		&fakeRuntime{}, func() time.Time { return testNow })
	if err != nil {
		t.Fatal(err)
	}
	baseline := twoSiteBundle(t, "cert-v2")
	if _, err := manager.ApplyWithActivation(t.Context(), baseline, activationFor(baseline, "event-v2", 1, map[string]uint64{"site-a": 2, "site-b": 2})); err != nil {
		t.Fatal(err)
	}
	redelivered := cloneCertificateBundle(baseline)
	redelivered.VersionID = "cert-v2-redelivered"
	if _, err := manager.ApplyWithActivation(t.Context(), redelivered,
		activationFor(redelivered, "event-v2-redelivered", 1, map[string]uint64{"site-a": 2, "site-b": 2})); err != nil {
		t.Fatalf("redelivered revisions: %v", err)
	}
	partial := cloneCertificateBundle(baseline)
	partial.VersionID = "cert-only-a"
	partial.Bindings = partial.Bindings[:1]
	if _, err := manager.ApplyWithActivation(t.Context(), partial, activationFor(partial, "event-only-a", 1, map[string]uint64{"site-a": 2})); err != nil {
		t.Fatalf("command naming one of two sites: %v", err)
	}
	assertResolvedCertificateVersion(t, manager, resolveFor("site-b", 2, "b.example.test"))
}

func TestManagerRejectsInitialCrossTenantActivationBeforeRuntime(t *testing.T) {
	runtime := &fakeRuntime{}
	manager, err := newManager(RuntimeConfig{
		StateRoot: managedStateRoot(t), ListenAddress: "127.0.0.1", ListenPort: 18443,
	}, runtime, func() time.Time { return testNow })
	if err != nil {
		t.Fatal(err)
	}
	bundle := twoSiteBundle(t, "cross-tenant-v1")
	activation := activationFor(bundle, "cross-tenant-event-v1", 1, map[string]uint64{"site-a": 1, "site-b": 1})
	activation.Certificates[1].TenantID = "tenant-b"
	activation.Certificates[1].TenantScopeID = "028f47a2-5b9c-7d31-8a60-104c9c0b7102"

	result, err := manager.ApplyWithActivation(t.Context(), bundle, activation)
	if !errors.Is(err, ErrConflict) || !result.RunningVersionUnchanged ||
		result.ErrorCode != "CERTIFICATE_VERSION_CONFLICT" {
		t.Fatalf("ApplyWithActivation() = (%#v, %v)", result, err)
	}
	if runtime.prechecks != 0 || runtime.activations != 0 || runtime.healthChecks != 0 {
		t.Fatalf("cross-tenant candidate reached runtime: %#v", runtime)
	}
	status, statusErr := manager.Status(t.Context())
	if statusErr != nil || !emptyStatus(status) {
		t.Fatalf("cross-tenant candidate mutated status: (%#v, %v)", status, statusErr)
	}
}

func TestConcurrentManagersCannotDowngradeCertificateVersion(t *testing.T) {
	root := managedStateRoot(t)
	config := RuntimeConfig{StateRoot: root, ListenAddress: "127.0.0.1", ListenPort: 18443}
	first, err := newManager(config, &fakeRuntime{}, func() time.Time { return testNow })
	if err != nil {
		t.Fatal(err)
	}
	second, err := newManager(config, &fakeRuntime{}, func() time.Time { return testNow })
	if err != nil {
		t.Fatal(err)
	}
	base := validTestBundle(t, "cert-v1", "one.example.test")
	if _, err := first.ApplyWithActivation(context.Background(), base, activationFor(base, "event-v1", 1, map[string]uint64{"site": 1})); err != nil {
		t.Fatal(err)
	}
	bundleV2 := validTestBundle(t, "cert-v2", "one.example.test")
	bundleV3 := validTestBundle(t, "cert-v3", "one.example.test")

	start := make(chan struct{})
	results := make(chan error, 2)
	var wait sync.WaitGroup
	for _, candidate := range []struct {
		manager    *Manager
		bundle     Bundle
		activation ActivationMetadata
	}{
		{manager: first, bundle: bundleV2, activation: activationFor(bundleV2, "event-v2", 1, map[string]uint64{"site": 2})},
		{manager: second, bundle: bundleV3, activation: activationFor(bundleV3, "event-v3", 1, map[string]uint64{"site": 3})},
	} {
		candidate := candidate
		wait.Add(1)
		go func() {
			defer wait.Done()
			<-start
			_, applyErr := candidate.manager.ApplyWithActivation(context.Background(), candidate.bundle, candidate.activation)
			results <- applyErr
		}()
	}
	close(start)
	wait.Wait()
	close(results)
	for applyErr := range results {
		if applyErr != nil && !errors.Is(applyErr, ErrStaleActivation) {
			t.Fatalf("concurrent apply error = %v", applyErr)
		}
	}
	status, err := first.Status(context.Background())
	if err != nil || status.Activation == nil || len(status.Activation.Certificates) != 1 || status.Activation.Certificates[0].Version != 3 {
		t.Fatalf("final status = (%#v, %v)", status, err)
	}
}

func TestActivationStatusCapacityAndRecoveryRepair(t *testing.T) {
	root := managedStateRoot(t)
	store, err := newDiskStore(root)
	if err != nil {
		t.Fatal(err)
	}
	activation := &ActivationMetadata{
		SchemaVersion: ActivationSchemaVersion, ConfigVersionID: "cert-large", RecipientKeyID: "x25519:" + strings.Repeat("a", 64),
		CommandEventID: strings.Repeat("e", 128), DeploymentID: strings.Repeat("d", 128), Attempt: 1, ArtifactID: strings.Repeat("a", 128),
	}
	const certificates = 64
	for index := 0; index < certificates; index++ {
		activation.Certificates = append(activation.Certificates, CertificateRevision{
			TenantID: strings.Repeat("t", MaxSiteIDBytes), SiteID: fmt.Sprintf("site-%02d-%s", index, strings.Repeat("s", MaxSiteIDBytes-8)),
			CertificateID: strings.Repeat("c", MaxSiteIDBytes), Version: uint64(index + 1),
		})
	}
	large := Status{Active: true, VersionID: "cert-large", Digest: strings.Repeat("a", 64), Activation: activation, AppliedAt: testNow}
	if err := store.writeStatus(large); err != nil {
		t.Fatal(err)
	}
	raw, err := os.ReadFile(filepath.Join(root, "status.json"))
	if err != nil {
		t.Fatal(err)
	}
	if len(raw) <= 16<<10 {
		t.Fatalf("test status size = %d, expected to exceed legacy limit", len(raw))
	}
	if recovered, err := store.readStatus(); err != nil || len(recovered.Activation.Certificates) != certificates {
		t.Fatalf("readStatus() = (%#v, %v)", recovered, err)
	}

	config := RuntimeConfig{StateRoot: managedStateRoot(t), ListenAddress: "127.0.0.1", ListenPort: 18443}
	manager, err := newManager(config, &fakeRuntime{}, func() time.Time { return testNow })
	if err != nil {
		t.Fatal(err)
	}
	bundle := validTestBundle(t, "cert-repair", "repair.example.test")
	want := activationFor(bundle, "event-repair", 1, map[string]uint64{"site": 1})
	if _, err := manager.ApplyWithActivation(context.Background(), bundle, want); err != nil {
		t.Fatal(err)
	}
	tampered, err := manager.Status(context.Background())
	if err != nil {
		t.Fatal(err)
	}
	tampered.Activation.CommandEventID = "tampered-event"
	if err := manager.store.writeStatus(tampered); err != nil {
		t.Fatal(err)
	}
	restarted, err := newManager(config, &fakeRuntime{}, func() time.Time { return testNow })
	if err != nil {
		t.Fatal(err)
	}
	if _, err := restarted.Recover(context.Background()); err != nil {
		t.Fatal(err)
	}
	repaired, err := restarted.Status(context.Background())
	if err != nil || repaired.Activation == nil || repaired.Activation.CommandEventID != want.CommandEventID {
		t.Fatalf("repaired status = (%#v, %v)", repaired, err)
	}
}

func activationFor(bundle Bundle, eventID string, attempt uint32, versions map[string]uint64) ActivationMetadata {
	result := ActivationMetadata{
		SchemaVersion: ActivationSchemaVersion, ConfigVersionID: bundle.VersionID,
		RecipientKeyID: "x25519:test-recipient", CommandEventID: eventID,
		DeploymentID: "deployment-" + eventID, Attempt: attempt, ArtifactID: "artifact-" + eventID,
		Certificates: make([]CertificateRevision, 0, len(bundle.Bindings)),
	}
	for _, binding := range bundle.Bindings {
		result.Certificates = append(result.Certificates, CertificateRevision{
			TenantID: "tenant-a", TenantScopeID: "018f47a2-5b9c-7d31-8a60-104c9c0b7101",
			SiteID: binding.SiteID, CertificateID: "certificate-" + binding.SiteID,
			CertificateVersionID: testCertificateVersionID(binding.SiteID, versions[binding.SiteID]),
			Version:              versions[binding.SiteID], BindingRevision: versions[binding.SiteID],
		})
	}
	return result
}

func testCertificateVersionID(siteID string, version uint64) string {
	return uuid.NewSHA1(uuid.NameSpaceOID, []byte(fmt.Sprintf("%s:%d", siteID, version))).String()
}

func cloneCertificateBundle(value Bundle) Bundle {
	result := value
	result.Bindings = append([]Binding(nil), value.Bindings...)
	for index := range result.Bindings {
		result.Bindings[index].Domains = append([]string(nil), value.Bindings[index].Domains...)
	}
	return result
}

func twoSiteBundle(t *testing.T, version string) Bundle {
	t.Helper()
	first := validTestBundle(t, version, "a.example.test")
	second := validTestBundle(t, version, "b.example.test")
	first.Bindings[0].SiteID = "site-a"
	second.Bindings[0].SiteID = "site-b"
	first.Bindings = append(first.Bindings, second.Bindings[0])
	return first
}
