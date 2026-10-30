package wafengine

import (
	"context"
	"crypto/ed25519"
	"crypto/sha256"
	"errors"
	"fmt"
	"os"
	"path/filepath"
	"strings"
	"testing"
	"time"

	"github.com/cdnca/cdnca/libs/edgeconfig"
	"github.com/cdnca/cdnca/libs/edgeconfig/artifactset"
	"github.com/cdnca/cdnca/libs/entitlement/enginemodule"
	"github.com/cdnca/cdnca/libs/entitlement/enginemodule/enginemoduletest"
)

const (
	testVersion = enginemoduletest.DefaultVersion
	testNginx   = enginemoduletest.DefaultOpenResty
	testSite    = "11111111-1111-4111-8111-111111111111"
)

var testArtifactID = enginemodule.ArtifactID(enginemodule.Component, enginemodule.Platform{OpenRestyVersion: testNginx, Architecture: "amd64"})

type fakeDelegate struct {
	calls          []string
	precheckFailOn func(gate bool) bool
	reloadFail     func(call int) bool
	gateFile       string
	reloads        int
}

func (delegate *fakeDelegate) gatePresent() bool {
	_, err := os.Stat(delegate.gateFile)
	return err == nil
}

func (delegate *fakeDelegate) Precheck(_ context.Context, version, _ string) error {
	gate := delegate.gatePresent()
	delegate.calls = append(delegate.calls, fmt.Sprintf("precheck %s gate=%v", version, gate))
	if delegate.precheckFailOn != nil && delegate.precheckFailOn(gate) {
		return errors.New("nginx -t failed")
	}
	return nil
}

func (delegate *fakeDelegate) Reload(_ context.Context, version, _ string) error {
	delegate.reloads++
	delegate.calls = append(delegate.calls, fmt.Sprintf("reload %s gate=%v", version, delegate.gatePresent()))
	if delegate.reloadFail != nil && delegate.reloadFail(delegate.reloads) {
		return errors.New("start failed")
	}
	return nil
}

func (delegate *fakeDelegate) Healthy(context.Context, string) error { return nil }

type fakeStopper struct{ stops int }

func (stopper *fakeStopper) Stop(context.Context, string) error { stopper.stops++; return nil }

type fixture struct {
	t        *testing.T
	root     string
	state    string
	release  string
	manager  *Manager
	delegate *fakeDelegate
	stopper  *fakeStopper
	runtime  *Runtime
	signer   enginemoduletest.Signer
}

func testSigner(name string) enginemoduletest.Signer {
	seed := sha256.Sum256([]byte(name))
	return enginemoduletest.Signer{KeyID: name, Private: ed25519.NewKeyFromSeed(seed[:])}
}

func (signer testSignerKeys) trust() Trust { return Trust{Release: map[string]ed25519.PublicKey(signer)} }

type testSignerKeys map[string]ed25519.PublicKey

func keys(signers ...enginemoduletest.Signer) testSignerKeys {
	result := testSignerKeys{}
	for _, signer := range signers {
		result[signer.KeyID] = signer.Private.Public().(ed25519.PublicKey)
	}
	return result
}

// bundle is a build signed by signers (enginemoduletest; signatures.json only).
func bundle(t *testing.T, signers []enginemoduletest.Signer, options enginemoduletest.Options) []byte {
	t.Helper()
	return enginemoduletest.Encoded(t, signers, options)
}

func newFixture(t *testing.T, withEngine bool) *fixture {
	t.Helper()
	base := t.TempDir()
	f := &fixture{t: t, root: filepath.Join(base, "extensions", "waf-crs"), state: filepath.Join(base, "edge"),
		signer: testSigner("release-1")}
	f.release = filepath.Join(f.state, "releases", "abc")
	if err := os.MkdirAll(filepath.Join(f.release, "security", "modsecurity"), 0o755); err != nil {
		t.Fatal(err)
	}
	nginx := "events {}\nhttp {}\n"
	if withEngine {
		nginx = "include " + filepath.ToSlash(filepath.Join(f.state, "waf-engine", "v1")) + "/load[.]conf;\n" + nginx
		engine := `{"schema":"cdnca.edge.waf-engine/v2","engine":"modsecurity","crs_version":"4.30.0","sites":[{"site_id":"` + testSite + `","exclusions":[]}]}`
		if err := os.WriteFile(filepath.Join(f.release, "security", "modsecurity", "engine.json"), []byte(engine), 0o644); err != nil {
			t.Fatal(err)
		}
	}
	if err := os.WriteFile(filepath.Join(f.release, "nginx.conf"), []byte(nginx), 0o644); err != nil {
		t.Fatal(err)
	}
	f.useManager(keys(f.signer).trust())
	return f
}

// useManager replaces the fixture's manager (same root) with one that
// trusts trust.
func (f *fixture) useManager(trust Trust) {
	f.t.Helper()
	manager, err := NewManager(Config{Root: f.root, StateRoot: f.state, OpenRestyVersion: testNginx, Architecture: "amd64",
		Trust: trust})
	if err != nil {
		f.t.Fatal(err)
	}
	f.manager = manager
	f.delegate = &fakeDelegate{gateFile: filepath.Join(f.state, "waf-engine", "v1", "load.conf")}
	f.stopper = &fakeStopper{}
	if f.runtime, err = NewRuntime(f.delegate, f.stopper, manager); err != nil {
		f.t.Fatal(err)
	}
}

// install runs the node artifact set path: PrepareModule then Commit.
func (f *fixture) install(content []byte, version string) error {
	f.t.Helper()
	staged, err := f.manager.PrepareModule(content, Expected{ArtifactID: testArtifactID, Version: version, Revision: 1}, time.Now())
	if err != nil {
		return err
	}
	_, err = staged.Commit()
	return err
}

func (f *fixture) installDefault() {
	f.t.Helper()
	if err := f.install(bundle(f.t, []enginemoduletest.Signer{f.signer}, enginemoduletest.Options{}), testVersion); err != nil {
		f.t.Fatal(err)
	}
}

func (f *fixture) deploy() error {
	if err := f.runtime.Precheck(context.Background(), "v1", f.release); err != nil {
		return err
	}
	return f.runtime.Reload(context.Background(), "v1", f.release)
}

func (f *fixture) gate() map[string]string {
	result := map[string]string{}
	entries, _ := os.ReadDir(filepath.Join(f.state, "waf-engine", "v1"))
	for _, entry := range entries {
		content, _ := os.ReadFile(filepath.Join(f.state, "waf-engine", "v1", entry.Name()))
		result[entry.Name()] = string(content)
	}
	return result
}

func TestInstalledModuleIsGatedAndRestartsOnce(t *testing.T) {
	f := newFixture(t, true)
	f.installDefault()
	if err := f.deploy(); err != nil {
		t.Fatal(err)
	}
	gate := f.gate()
	release, _ := filepath.EvalSymlinks(f.release)
	if len(gate) != 3 || !strings.HasPrefix(gate["load.conf"], "load_module "+filepath.ToSlash(f.root)+"/versions/") ||
		!strings.Contains(gate["http.conf"], "modsecurity_rules_file "+filepath.ToSlash(release)+"/security/modsecurity/main.conf;") ||
		!strings.Contains(gate["site-"+testSite+".conf"], "modsecurity on;") {
		t.Fatalf("gate = %q", gate)
	}
	if f.stopper.stops != 1 || !strings.HasSuffix(f.delegate.calls[len(f.delegate.calls)-1], "gate=true") {
		t.Fatalf("first load must restart: stops=%d calls=%v", f.stopper.stops, f.delegate.calls)
	}
	module := f.manager.LoadedModule()
	if info, err := os.Stat(module); err != nil || info.Mode().Perm() != 0o555 {
		t.Fatalf("loaded module %q: %v", module, err)
	}
	if status := f.manager.Status(); status.State != StateActive || status.Version != testVersion {
		t.Fatalf("status = %+v", status)
	}
	if id, version := f.manager.Installed(); id != testArtifactID || version != testVersion {
		t.Fatalf("installed = %s %s", id, version)
	}
	if err := f.deploy(); err != nil {
		t.Fatal(err)
	}
	if f.stopper.stops != 1 {
		t.Fatalf("same module must reload without restart: stops=%d", f.stopper.stops)
	}
	if summary, ok := f.manager.Status().CheckSummary(); !ok || !strings.Contains(summary, testVersion) {
		t.Fatalf("check = %q %v", summary, ok)
	}
}

// A newer build replaces the module (a restart loads it); the previous build
// stays on disk, older ones are pruned.
func TestNewerModuleReplacesAndRestarts(t *testing.T) {
	f := newFixture(t, true)
	f.installDefault()
	if err := f.deploy(); err != nil {
		t.Fatal(err)
	}
	first := f.manager.LoadedModule()
	signers := []enginemoduletest.Signer{f.signer}
	if err := f.install(bundle(t, signers, enginemoduletest.Options{Version: "3.0.18-1.0.4-1", Module: "module 2"}), "3.0.18-1.0.4-1"); err != nil {
		t.Fatal(err)
	}
	if err := f.deploy(); err != nil {
		t.Fatal(err)
	}
	if second := f.manager.LoadedModule(); second == first || f.stopper.stops != 2 || f.manager.Status().Version != "3.0.18-1.0.4-1" {
		t.Fatalf("loaded %q -> %q stops=%d status=%+v", first, second, f.stopper.stops, f.manager.Status())
	}
	if _, err := os.Stat(first); err != nil {
		t.Fatalf("previous build removed while a master may still hold it: %v", err)
	}
	if err := f.install(bundle(t, signers, enginemoduletest.Options{Version: "3.0.19-1.0.4-1", Module: "module 3"}), "3.0.19-1.0.4-1"); err != nil {
		t.Fatal(err)
	}
	if _, err := os.Stat(first); !errors.Is(err, os.ErrNotExist) {
		t.Fatalf("build two generations back kept: %v", err)
	}
}

// Rejected items carry their receipt reason and leave the active build and
// its gate alone.
func TestRejectedModuleKeepsTheInstalledOne(t *testing.T) {
	other := testSigner("not-trusted")
	cases := map[string]struct {
		content func(f *fixture) []byte
		version string
		reason  string
	}{
		"untrusted signer": {func(f *fixture) []byte {
			return bundle(f.t, []enginemoduletest.Signer{other}, enginemoduletest.Options{Version: "3.0.18-1.0.4-1"})
		}, "3.0.18-1.0.4-1", artifactset.ReasonSignatureInvalid},
		"no signature": {func(f *fixture) []byte {
			// enginemodule refuses to encode it; the four files raw.
			return rawBundle(f.t, enginemoduletest.Build(f.t, nil, enginemoduletest.Options{Version: "3.0.18-1.0.4-1"}))
		}, "3.0.18-1.0.4-1", artifactset.ReasonSignatureInvalid},
		"other architecture": {func(f *fixture) []byte {
			return bundle(f.t, []enginemoduletest.Signer{f.signer}, enginemoduletest.Options{Architecture: "arm64"})
		}, testVersion, artifactset.ReasonInstallRejected}, // the item names the amd64 id
		"other OpenResty build for this id": {func(f *fixture) []byte {
			return bundle(f.t, []enginemoduletest.Signer{f.signer}, enginemoduletest.Options{OpenRestyVersion: "1.27.1.2"})
		}, testVersion, artifactset.ReasonInstallRejected},
		"version not the item's": {func(f *fixture) []byte {
			return bundle(f.t, []enginemoduletest.Signer{f.signer}, enginemoduletest.Options{Version: "3.0.18-1.0.4-1"})
		}, testVersion, artifactset.ReasonInstallRejected},
		"file digest": {func(f *fixture) []byte {
			return bundle(f.t, []enginemoduletest.Signer{f.signer}, enginemoduletest.Options{Version: "3.0.18-1.0.4-1",
				Mutate: func(manifest *Manifest) { manifest.Files[0].SHA256 = strings.Repeat("1", 64) }})
		}, "3.0.18-1.0.4-1", artifactset.ReasonInstallRejected},
		"not a bundle": {func(*fixture) []byte { return []byte("not a bundle") }, testVersion, artifactset.ReasonInstallRejected},
	}
	for name, test := range cases {
		t.Run(name, func(t *testing.T) {
			f := newFixture(t, true)
			f.installDefault()
			if err := f.deploy(); err != nil {
				t.Fatal(err)
			}
			loaded := f.manager.LoadedModule()
			err := f.install(test.content(f), test.version)
			if reason := artifactset.RejectReason(err); err == nil || reason != test.reason {
				t.Fatalf("install err = %v reason %q, want %q", err, reason, test.reason)
			}
			if entries, _ := os.ReadDir(filepath.Join(f.root, "versions")); len(entries) != 1 {
				t.Fatalf("rejected build left files: %v", entries)
			}
			if err := f.deploy(); err != nil {
				t.Fatal(err)
			}
			if status := f.manager.Status(); status.State != StateActive || status.Version != testVersion ||
				f.manager.LoadedModule() != loaded || len(f.gate()) != 3 {
				t.Fatalf("rejection changed the active module: %+v loaded=%q", status, f.manager.LoadedModule())
			}
		})
	}
}

// A node whose OpenResty differs from the item's build id refuses it as a
// platform mismatch (the item names the build for another platform).
func TestModuleForAnotherPlatformIsPlatformMismatch(t *testing.T) {
	f := newFixture(t, true)
	arm := bundle(t, []enginemoduletest.Signer{f.signer}, enginemoduletest.Options{Architecture: "arm64"})
	armID := enginemodule.ArtifactID(enginemodule.Component, enginemodule.Platform{OpenRestyVersion: testNginx, Architecture: "arm64"})
	_, err := f.manager.PrepareModule(arm, Expected{ArtifactID: armID, Version: testVersion, Revision: 1}, time.Now())
	if artifactset.RejectReason(err) != artifactset.ReasonPlatformMismatch {
		t.Fatalf("err = %v", err)
	}
	unavailable, err := NewManager(Config{Root: filepath.Join(t.TempDir(), "x"), StateRoot: f.state})
	if err != nil {
		t.Fatal(err)
	}
	amd := bundle(t, []enginemoduletest.Signer{f.signer}, enginemoduletest.Options{})
	if _, err := unavailable.PrepareModule(amd, Expected{ArtifactID: testArtifactID, Version: testVersion, Revision: 1},
		time.Now()); artifactset.RejectReason(err) != artifactset.ReasonPlatformMismatch {
		t.Fatalf("disabled engine err = %v", err)
	}
}

func TestUndoAndRemoveModule(t *testing.T) {
	f := newFixture(t, true)
	f.installDefault()
	staged, err := f.manager.PrepareModule(bundle(t, []enginemoduletest.Signer{f.signer},
		enginemoduletest.Options{Version: "3.0.18-1.0.4-1", Module: "two"}), Expected{ArtifactID: testArtifactID,
		Version: "3.0.18-1.0.4-1", Revision: 2}, time.Now())
	if err != nil {
		t.Fatal(err)
	}
	undo, err := staged.Commit()
	if err != nil {
		t.Fatal(err)
	}
	if _, version := f.manager.Installed(); version != "3.0.18-1.0.4-1" {
		t.Fatalf("installed %s", version)
	}
	if err := undo(); err != nil {
		t.Fatal(err)
	}
	if _, version := f.manager.Installed(); version != testVersion {
		t.Fatalf("after undo installed %s", version)
	}
	if err := f.manager.RemoveModule(); err != nil {
		t.Fatal(err)
	}
	if err := f.deploy(); err != nil {
		t.Fatal(err)
	}
	if status := f.manager.Status(); status.State != StateDegraded || status.Reason != ReasonUnavailable || len(f.gate()) != 0 {
		t.Fatalf("after remove: %+v gate=%v", status, f.gate())
	}
}

func TestEngineFailuresLeaveNoGateAndReportReason(t *testing.T) {
	cases := map[string]struct {
		mutate func(f *fixture)
		reason string
	}{
		"nothing installed": {func(*fixture) {}, ReasonUnavailable},
		"installed file altered": {func(f *fixture) {
			f.installDefault()
			current, _ := f.manager.readInstalled()
			target := filepath.Join(current.Path, ModulePath)
			_ = os.Chmod(target, 0o644)
			_ = os.WriteFile(target, []byte("altered"), 0o555)
		}, ReasonPayload},
		"installed signatures altered": {func(f *fixture) {
			f.installDefault()
			current, _ := f.manager.readInstalled()
			current.Signatures = []byte("{}")
			rewriteInstalled(f, *current)
		}, ReasonSignature},
		"installed for another OpenResty": {func(f *fixture) {
			f.installDefault()
			manager, err := NewManager(Config{Root: f.root, StateRoot: f.state, OpenRestyVersion: "1.27.1.2", Architecture: "amd64",
				Trust: keys(f.signer).trust()})
			if err != nil {
				f.t.Fatal(err)
			}
			f.manager = manager
			f.runtime, _ = NewRuntime(f.delegate, f.stopper, manager)
		}, ReasonManifest},
	}
	for name, test := range cases {
		t.Run(name, func(t *testing.T) {
			f := newFixture(t, true)
			test.mutate(f)
			if err := f.deploy(); err != nil {
				t.Fatalf("engine failure must not fail the deployment: %v", err)
			}
			if gate := f.gate(); len(gate) != 0 {
				t.Fatalf("gate written after %s: %v", name, gate)
			}
			if status := f.manager.Status(); status.State != StateDegraded || status.Reason != test.reason {
				t.Fatalf("status = %+v, want %s", status, test.reason)
			}
			if f.stopper.stops != 0 || f.manager.LoadedModule() != "" {
				t.Fatalf("restart without a module change: stops=%d loaded=%q", f.stopper.stops, f.manager.LoadedModule())
			}
			if summary, ok := f.manager.Status().CheckSummary(); ok || !strings.Contains(summary, test.reason) {
				t.Fatalf("check = %q %v", summary, ok)
			}
		})
	}
}

func rewriteInstalled(f *fixture, current installed) {
	f.t.Helper()
	encoded, err := jsonMarshal(current)
	if err != nil {
		f.t.Fatal(err)
	}
	if err := os.WriteFile(f.manager.statePath(), encoded, 0o644); err != nil {
		f.t.Fatal(err)
	}
}

func TestNodeWithoutEngineStartsNormally(t *testing.T) {
	f := newFixture(t, false)
	f.installDefault()
	if err := f.deploy(); err != nil {
		t.Fatal(err)
	}
	if f.stopper.stops != 0 || len(f.gate()) != 0 || f.manager.Status().State != StateNotRequired {
		t.Fatalf("release without CRS touched the engine: stops=%d", f.stopper.stops)
	}
}

func TestPrecheckFailureWithGateFallsBackWithoutModule(t *testing.T) {
	f := newFixture(t, true)
	f.installDefault()
	f.delegate.precheckFailOn = func(gate bool) bool { return gate }
	if err := f.deploy(); err != nil {
		t.Fatal(err)
	}
	if status := f.manager.Status(); status.State != StateDegraded || status.Reason != ReasonModuleLoad || len(f.gate()) != 0 {
		t.Fatalf("status = %+v gate=%v", status, f.gate())
	}
	if want := []string{"precheck v1 gate=true", "precheck v1 gate=false", "reload v1 gate=false"}; strings.Join(f.delegate.calls, "|") != strings.Join(want, "|") {
		t.Fatalf("calls = %v", f.delegate.calls)
	}
	f.delegate.precheckFailOn = func(bool) bool { return true }
	if err := f.runtime.Precheck(context.Background(), "v1", f.release); err == nil {
		t.Fatal("a release that fails without the gate must fail the precheck")
	}
}

func TestRestartFailureRetriesWithoutModuleThenRollsBack(t *testing.T) {
	f := newFixture(t, true)
	f.installDefault()
	f.delegate.reloadFail = func(call int) bool { return call == 1 }
	if err := f.deploy(); err != nil {
		t.Fatal(err)
	}
	if status := f.manager.Status(); status.State != StateDegraded || status.Reason != ReasonRestart ||
		f.manager.LoadedModule() != "" || f.stopper.stops != 2 || len(f.gate()) != 0 {
		t.Fatalf("status=%+v loaded=%q stops=%d gate=%v", status, f.manager.LoadedModule(), f.stopper.stops, f.gate())
	}
	g := newFixture(t, true)
	g.installDefault()
	g.delegate.reloadFail = func(int) bool { return true }
	if err := g.runtime.Precheck(context.Background(), "v1", g.release); err != nil {
		t.Fatal(err)
	}
	if err := g.runtime.Reload(context.Background(), "v1", g.release); err == nil {
		t.Fatal("restart failing with and without the module must fail the reload (manager rolls back)")
	}
	if g.manager.LoadedModule() != "?" {
		t.Fatalf("unknown master state recorded as %q", g.manager.LoadedModule())
	}
	// Rollback: the previous release has no CRS; its Reload restarts again
	// because the running module set is unknown.
	h := newFixture(t, false)
	g.delegate.reloadFail = nil
	if err := g.runtime.Reload(context.Background(), "v0", h.release); err != nil {
		t.Fatal(err)
	}
	if g.manager.LoadedModule() != "" {
		t.Fatalf("after rollback loaded=%q", g.manager.LoadedModule())
	}
}

func TestGatePathMismatchDegrades(t *testing.T) {
	f := newFixture(t, true)
	f.installDefault()
	if err := os.WriteFile(filepath.Join(f.release, "nginx.conf"), []byte("include /elsewhere/waf-engine/v1/load[.]conf;\n"), 0o644); err != nil {
		t.Fatal(err)
	}
	if err := f.deploy(); err != nil {
		t.Fatal(err)
	}
	if status := f.manager.Status(); status.Reason != ReasonGatePath || len(f.gate()) != 0 {
		t.Fatalf("status = %+v", status)
	}
}

func TestExtractRejectsLinksAndExtraFiles(t *testing.T) {
	built := enginemoduletest.Build(t, []enginemoduletest.Signer{testSigner("release-1")}, enginemoduletest.Options{})
	checked, err := built.Check()
	if err != nil {
		t.Fatal(err)
	}
	reduced := checked.Manifest
	reduced.Files = checked.Manifest.Files[1:]
	if err := Extract(built.Payload, reduced, filepath.Join(t.TempDir(), "x")); !errors.Is(err, ErrPayload) {
		t.Fatalf("extra payload file err = %v", err)
	}
	if _, err := edgeconfig.ParseWAFEngineManifest([]byte(`{}`)); err == nil {
		t.Fatal("empty engine manifest accepted")
	}
}
