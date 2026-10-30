package certstore

import (
	"bytes"
	"errors"
	"path/filepath"
	"reflect"
	"testing"
	"time"
)

func TestCompileWithActivationAcceptsOnlyExplicitRemoval(t *testing.T) {
	config := RuntimeConfig{StateRoot: managedStateRoot(t), ListenAddress: "127.0.0.1", ListenPort: 18443}
	bundle := removalBundle("cert-remove-v2")
	activation := removalActivation(bundle, "remove-event-v2", "site")

	first, err := CompileWithActivation(bundle, config, testNow, activation)
	if err != nil {
		t.Fatalf("CompileWithActivation(removal) error = %v", err)
	}
	second, err := CompileWithActivation(bundle, config, testNow, activation)
	if err != nil {
		t.Fatalf("CompileWithActivation(removal replay) error = %v", err)
	}
	if !reflect.DeepEqual(first, second) {
		t.Fatal("removal compilation is not deterministic")
	}
	if first.Manifest.Bindings == nil || len(first.Manifest.Bindings) != 0 ||
		first.Activation == nil || first.Activation.Certificates == nil || len(first.Activation.Certificates) != 0 ||
		first.HealthTargets == nil || len(first.HealthTargets) != 0 {
		t.Fatalf("removal artifact is not explicitly empty: %#v", first)
	}
	if len(first.Files) != 2 || first.Files[0].Path != "manifest.json" || first.Files[1].Path != "nginx.conf" ||
		bytes.Contains(first.Files[1].Content, []byte("ssl_certificate ")) ||
		!bytes.Contains(first.Files[1].Content, []byte("ssl_reject_handshake on")) {
		t.Fatalf("removal files = %#v", first.Files)
	}

	for _, bindings := range [][]Binding{nil, make([]Binding, 0)} {
		ordinary := Bundle{SchemaVersion: SchemaVersion, VersionID: "ordinary-empty", Bindings: bindings}
		if _, err := Compile(ordinary, config, testNow); !errors.Is(err, ErrInvalidBundle) {
			t.Fatalf("Compile(%#v) error = %v, want ErrInvalidBundle", bindings, err)
		}
	}

	tests := []struct {
		name       string
		bundle     Bundle
		activation ActivationMetadata
	}{
		{name: "nil bindings", bundle: Bundle{SchemaVersion: SchemaVersion, VersionID: bundle.VersionID}, activation: activation},
		{name: "nil certificates", bundle: bundle, activation: func() ActivationMetadata {
			value := activation
			value.Certificates = nil
			return value
		}()},
		{name: "no removed sites", bundle: bundle, activation: activationFor(bundle, "remove-event-v2", 1, nil)},
		{name: "removed site without revision", bundle: bundle, activation: func() ActivationMetadata {
			value := removalActivation(bundle, "remove-event-v2", "site")
			value.RemovedSites[0].BindingRevision = 0
			return value
		}()},
		{name: "wrong bundle schema", bundle: func() Bundle {
			value := bundle
			value.SchemaVersion = "cdnca.edge.certificates/v0"
			return value
		}(), activation: activation},
		{name: "wrong activation schema", bundle: bundle, activation: func() ActivationMetadata {
			value := activation
			value.SchemaVersion = "cdnca.edge.certificate-activation/v0"
			return value
		}()},
		{name: "mismatched config version", bundle: bundle, activation: func() ActivationMetadata {
			value := activation
			value.ConfigVersionID = "different-version"
			return value
		}()},
		{name: "missing artifact identity", bundle: bundle, activation: func() ActivationMetadata {
			value := activation
			value.ArtifactID = ""
			return value
		}()},
	}
	for _, test := range tests {
		t.Run(test.name, func(t *testing.T) {
			if _, err := CompileWithActivation(test.bundle, config, testNow, test.activation); !errors.Is(err, ErrInvalidBundle) {
				t.Fatalf("CompileWithActivation() error = %v, want ErrInvalidBundle", err)
			}
		})
	}
}

func TestManagerAppliesExplicitRemovalAtomically(t *testing.T) {
	config := RuntimeConfig{StateRoot: managedStateRoot(t), ListenAddress: "127.0.0.1", ListenPort: 18443}
	manager, err := newManager(config, &fakeRuntime{}, func() time.Time { return testNow })
	if err != nil {
		t.Fatal(err)
	}
	baseline := validTestBundle(t, "cert-active-v1", "active.example.test")
	if _, err := manager.ApplyWithActivation(t.Context(), baseline, activationFor(baseline, "active-event-v1", 1, map[string]uint64{"site": 1})); err != nil {
		t.Fatalf("seed active certificate: %v", err)
	}

	removal := removalBundle("cert-remove-v2")
	result, err := manager.ApplyWithActivation(t.Context(), removal, removalActivation(removal, "remove-event-v2", "site"))
	if err != nil {
		t.Fatalf("ApplyWithActivation(removal) error = %v", err)
	}
	if !result.Changed || result.ActiveVersionID != removal.VersionID || result.ActiveDigest == "" {
		t.Fatalf("removal result = %#v", result)
	}
	current, err := manager.store.readPointer("current")
	if err != nil {
		t.Fatal(err)
	}
	lkg, err := manager.store.readPointer("lkg")
	if err != nil {
		t.Fatal(err)
	}
	if current == "" || current != lkg || filepath.Base(current) != removal.VersionID+"-"+result.ActiveDigest {
		t.Fatalf("removal pointers current=%q lkg=%q", current, lkg)
	}
	status, err := manager.Status(t.Context())
	if err != nil {
		t.Fatal(err)
	}
	if !status.Active || status.VersionID != removal.VersionID || status.Activation == nil ||
		status.Activation.Certificates == nil || len(status.Activation.Certificates) != 0 || len(status.HealthTargets) != 0 {
		t.Fatalf("removal status = %#v", status)
	}
	active, err := manager.loadArtifact(current)
	if err != nil {
		t.Fatalf("reload removal artifact: %v", err)
	}
	if len(active.Manifest.Bindings) != 0 || len(active.HealthTargets) != 0 || len(active.Files) != 2 {
		t.Fatalf("active removal artifact = %#v", active)
	}
	if _, err := manager.ResolveCertificateVersion(t.Context(), resolveFor("site", 1, "active.example.test")); !errors.Is(err, ErrCertificateUnavailable) {
		t.Fatalf("removed site resolved: %v", err)
	}
}

func TestRemovalFailuresPreservePriorState(t *testing.T) {
	tests := []struct {
		name    string
		prepare func(*fakeRuntime)
		want    error
	}{
		{name: "precheck", prepare: func(runtime *fakeRuntime) { runtime.precheckFailures = 1 }, want: ErrPrecheck},
		{name: "activation", prepare: func(runtime *fakeRuntime) { runtime.activationFailures = 1 }, want: ErrActivation},
		{name: "health", prepare: func(runtime *fakeRuntime) { runtime.healthFailures = 1 }, want: ErrHealth},
	}
	for _, test := range tests {
		t.Run(test.name, func(t *testing.T) {
			config := RuntimeConfig{StateRoot: managedStateRoot(t), ListenAddress: "127.0.0.1", ListenPort: 18443}
			runtime := &fakeRuntime{}
			manager, err := newManager(config, runtime, func() time.Time { return testNow })
			if err != nil {
				t.Fatal(err)
			}
			baseline := validTestBundle(t, "cert-active-v1", "active.example.test")
			seed, err := manager.ApplyWithActivation(t.Context(), baseline, activationFor(baseline, "active-event-v1", 1, map[string]uint64{"site": 1}))
			if err != nil {
				t.Fatalf("seed active certificate: %v", err)
			}
			beforeCurrent, _ := manager.store.readPointer("current")
			beforeLKG, _ := manager.store.readPointer("lkg")
			beforeStatus, _ := manager.store.readStatus()

			test.prepare(runtime)
			removal := removalBundle("cert-remove-v2")
			result, err := manager.ApplyWithActivation(t.Context(), removal, removalActivation(removal, "remove-event-v2", "site"))
			if !errors.Is(err, test.want) {
				t.Fatalf("ApplyWithActivation(removal) error = %v, want %v", err, test.want)
			}
			if !result.RunningVersionUnchanged || result.ActiveVersionID != seed.ActiveVersionID || result.ActiveDigest != seed.ActiveDigest {
				t.Fatalf("failed removal result = %#v, seed = %#v", result, seed)
			}
			afterCurrent, _ := manager.store.readPointer("current")
			afterLKG, _ := manager.store.readPointer("lkg")
			afterStatus, _ := manager.store.readStatus()
			if beforeCurrent != afterCurrent || beforeLKG != afterLKG || !reflect.DeepEqual(beforeStatus, afterStatus) {
				t.Fatalf("state changed after failed removal: current %q/%q lkg %q/%q status %#v/%#v",
					beforeCurrent, afterCurrent, beforeLKG, afterLKG, beforeStatus, afterStatus)
			}
			assertResolvedCertificateVersion(t, manager, resolveFor("site", 1, "active.example.test"))
		})
	}
}

func removalBundle(version string) Bundle {
	return Bundle{SchemaVersion: SchemaVersion, VersionID: version, Bindings: make([]Binding, 0)}
}

// removalActivation removes sites at binding revision 2 (activationFor binds
// version n at binding revision n).
func removalActivation(bundle Bundle, eventID string, sites ...string) ActivationMetadata {
	activation := activationFor(bundle, eventID, 1, nil)
	for _, site := range sites {
		activation.RemovedSites = append(activation.RemovedSites, RemovedSite{
			TenantID: "tenant-a", TenantScopeID: testTenantScopeID, SiteID: site, BindingRevision: 2,
		})
	}
	return activation
}
