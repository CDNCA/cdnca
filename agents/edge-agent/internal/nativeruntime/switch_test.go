package nativeruntime

import (
	"archive/tar"
	"bytes"
	"compress/gzip"
	"context"
	"crypto/ed25519"
	"crypto/sha256"
	"encoding/base64"
	"encoding/hex"
	"encoding/json"
	"errors"
	"os"
	"path/filepath"
	"sort"
	"testing"
	"time"
)

// A fixture native node: /opt/cdnca-node with one installed release (the
// first installation's), config.json pointing at it, and the Agent of a new
// version whose release carries a native package.

type fixture struct {
	root, config, status, agent, packagePath string
	keys                                     map[string]ed25519.PublicKey
	private                                  ed25519.PrivateKey
	oldRelease                               string
}

func sha(content []byte) string {
	digest := sha256.Sum256(content)
	return hex.EncodeToString(digest[:])
}

// buildPackage writes a signed native package of version with the given
// member contents (paths not listed get defaults) and returns its manifest sha.
func (f *fixture) buildPackage(t *testing.T, path, version, openresty string, members map[string][]byte) string {
	t.Helper()
	files := map[string][]byte{
		NginxPath: []byte("nginx-" + openresty), "runtime/openresty/bin/openresty": []byte("nginx-" + openresty),
		LoaderPath: []byte("ld-musl"), AgentPath: []byte("agent-" + version),
		SecurityRoot + "/cdnca_waf.lua": []byte("waf"), SecurityRoot + "/cc.lua": []byte("cc"),
		SecurityRoot + "/cc_adaptive.lua":               []byte("adaptive"),
		"lua/share/cdnca/dynroute/cdnca_site_admin.lua": []byte("admin"),
	}
	for name, content := range members {
		files[name] = content
	}
	names := make([]string, 0, len(files))
	for name := range files {
		names = append(names, name)
	}
	sort.Strings(names)
	manifest := map[string]any{
		"schema": "cdnca.native-node.release/v1", "key_id": "test", "version": version,
		"source":   map[string]string{"commit": "aa", "tree": "bb"},
		"platform": map[string]string{"os": "linux", "arch": "amd64"},
		"runtime": map[string]any{"openresty_version": openresty, "nginx_version": "1.31.1",
			"source_sha256": sha([]byte("s")), "patch_manifest_sha256": sha([]byte("p")), "release_eligible": true},
	}
	var inventory []map[string]any
	for _, name := range names {
		mode := "0444"
		if name == NginxPath || name == "runtime/openresty/bin/openresty" || name == LoaderPath || name == AgentPath {
			mode = "0555"
		}
		inventory = append(inventory, map[string]any{"path": name, "size": len(files[name]), "mode": mode, "sha256": sha(files[name])})
	}
	manifest["files"] = inventory
	raw, err := json.Marshal(manifest)
	if err != nil {
		t.Fatal(err)
	}
	signature := base64.StdEncoding.EncodeToString(ed25519.Sign(f.private, append([]byte(signatureDomain), raw...))) + "\n"
	var buffer bytes.Buffer
	compressed := gzip.NewWriter(&buffer)
	archive := tar.NewWriter(compressed)
	write := func(name string, content []byte, mode int64) {
		if err := archive.WriteHeader(&tar.Header{Name: name, Mode: mode, Size: int64(len(content)), Typeflag: tar.TypeReg}); err != nil {
			t.Fatal(err)
		}
		if _, err := archive.Write(content); err != nil {
			t.Fatal(err)
		}
	}
	write(manifestName, raw, 0o444)
	write(signatureName, []byte(signature), 0o444)
	for index, name := range names {
		mode := int64(0o444)
		if inventory[index]["mode"] == "0555" {
			mode = 0o555
		}
		write(name, files[name], mode)
	}
	if err := archive.Close(); err != nil {
		t.Fatal(err)
	}
	if err := compressed.Close(); err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(path, buffer.Bytes(), 0o444); err != nil {
		t.Fatal(err)
	}
	return sha(raw)
}

func newFixture(t *testing.T) *fixture {
	t.Helper()
	base := t.TempDir()
	public, private, err := ed25519.GenerateKey(nil)
	if err != nil {
		t.Fatal(err)
	}
	f := &fixture{
		root: filepath.Join(base, "opt"), config: filepath.Join(base, "config.json"), status: filepath.Join(base, "state", "status.json"),
		agent: filepath.Join(base, "edge-agent"), packagePath: filepath.Join(base, "native.tar.gz"),
		keys: map[string]ed25519.PublicKey{"test": public}, private: private,
	}
	if err := os.MkdirAll(filepath.Join(f.root, "releases"), 0o755); err != nil {
		t.Fatal(err)
	}
	// The first installation: version 1.0.0 with OpenResty 1.27.1.2.
	oldPackage := filepath.Join(base, "old.tar.gz")
	oldSHA := f.buildPackage(t, oldPackage, "1.0.0", "1.27.1.2", nil)
	old, err := Verify(oldPackage, f.keys)
	if err != nil {
		t.Fatalf("verify fixture package: %v", err)
	}
	f.oldRelease = filepath.Join(f.root, "releases", oldSHA)
	if err := old.Extract(f.oldRelease); err != nil {
		t.Fatal(err)
	}
	if err := os.Symlink("releases/"+oldSHA, filepath.Join(f.root, "current")); err != nil {
		t.Fatal(err)
	}
	config := map[string]any{
		"version":   2,
		"openresty": map[string]any{"binary": "/usr/local/openresty/bin/openresty", "version": "1.27.1.2"},
		"security_runtime": map[string]any{"enabled": true, "mode": "native",
			"waf": map[string]any{"path": f.oldRelease + "/" + SecurityRoot + "/cdnca_waf.lua", "sha256": sha([]byte("waf"))}},
		"upgrade": map[string]any{"enabled": true},
	}
	raw, _ := json.Marshal(config)
	if err := os.WriteFile(f.config, raw, 0o600); err != nil {
		t.Fatal(err)
	}
	return f
}

func (f *fixture) runAgent(t *testing.T, version string) Config {
	t.Helper()
	_ = os.Remove(f.agent)
	if err := os.WriteFile(f.agent, []byte("agent-"+version), 0o555); err != nil {
		t.Fatal(err)
	}
	return Config{Root: f.root, PackagePath: f.packagePath, AgentPath: f.agent, AgentVersion: version,
		ConfigPath: f.config, StatusPath: f.status, Keys: f.keys, Clock: func() time.Time { return time.Unix(1, 0) }}
}

func (f *fixture) current(t *testing.T) string {
	t.Helper()
	target, err := os.Readlink(filepath.Join(f.root, "current"))
	if err != nil {
		t.Fatal(err)
	}
	return target
}

type fakeHTTP struct {
	err   error
	calls int
}

func (h *fakeHTTP) UpgradeBinary(context.Context) error { h.calls++; return h.err }

func TestSwitchInstallsNewRuntimeRewritesConfigAndKeepsPrevious(t *testing.T) {
	f := newFixture(t)
	newSHA := f.buildPackage(t, f.packagePath, "1.0.1", "1.31.1.1", map[string][]byte{
		"lua/share/cdnca/dynroute/cdnca_site_admin.lua": []byte("admin with /site-drop"), SecurityRoot + "/cc.lua": []byte("cc v2"),
	})
	config := f.runAgent(t, "1.0.1")
	prechecked := ""
	pending, err := Prepare(context.Background(), config, func(context.Context) error {
		prechecked = f.current(t)
		return nil
	})
	if err != nil || !pending.Switched() {
		t.Fatalf("prepare: %v switched=%v", err, pending.Switched())
	}
	if prechecked != "releases/"+newSHA {
		t.Fatalf("precheck ran through %q, want the new release", prechecked)
	}
	http := &fakeHTTP{}
	if err := pending.Commit(context.Background(), http); err != nil || http.calls != 1 {
		t.Fatalf("commit: %v calls=%d", err, http.calls)
	}
	if f.current(t) != "releases/"+newSHA {
		t.Fatalf("current = %s", f.current(t))
	}
	if content, err := os.ReadFile(filepath.Join(f.root, "current", "lua/share/cdnca/dynroute/cdnca_site_admin.lua")); err != nil || string(content) != "admin with /site-drop" {
		t.Fatalf("new Lua not active: %q %v", content, err)
	}
	var document struct {
		OpenResty       map[string]any `json:"openresty"`
		SecurityRuntime map[string]struct {
			Path   string `json:"path"`
			SHA256 string `json:"sha256"`
		} `json:"security_runtime"`
		Upgrade map[string]any `json:"upgrade"`
	}
	raw, _ := os.ReadFile(f.config)
	_ = json.Unmarshal(raw, &struct {
		OpenResty *map[string]any `json:"openresty"`
		Upgrade   *map[string]any `json:"upgrade"`
	}{&document.OpenResty, &document.Upgrade})
	var security map[string]json.RawMessage
	var outer map[string]json.RawMessage
	_ = json.Unmarshal(raw, &outer)
	_ = json.Unmarshal(outer["security_runtime"], &security)
	var cc struct {
		Path   string `json:"path"`
		SHA256 string `json:"sha256"`
	}
	_ = json.Unmarshal(security["cc"], &cc)
	newRelease := filepath.Join(f.root, "releases", newSHA)
	if document.OpenResty["version"] != "1.31.1.1" || document.Upgrade["enabled"] != true ||
		cc.Path != filepath.Join(newRelease, SecurityRoot, "cc.lua") || cc.SHA256 != sha([]byte("cc v2")) {
		t.Fatalf("config.json not rewritten: %s", raw)
	}
	if info, err := os.Stat(f.config); err != nil || info.Mode().Perm() != 0o600 {
		t.Fatalf("config.json mode: %v %v", info, err)
	}
	if _, err := os.Stat(f.oldRelease); err != nil {
		t.Fatalf("previous release was not kept for rollback: %v", err)
	}
	status, err := ReadStatus(f.status)
	if err != nil || status.State != StateSwitched || status.OpenRestyVersion != "1.31.1.1" || status.Release != newSHA ||
		status.PreviousRelease != filepath.Base(f.oldRelease) || HealthError(status, "1.0.1") != nil {
		t.Fatalf("status: %+v %v", status, err)
	}
}

func TestSameRuntimeSkipsSwitch(t *testing.T) {
	f := newFixture(t)
	// Only the Agent changes: same OpenResty, libraries and Lua.
	f.buildPackage(t, f.packagePath, "1.0.1", "1.27.1.2", nil)
	config := f.runAgent(t, "1.0.1")
	before, _ := os.ReadFile(f.config)
	called := false
	pending, err := Prepare(context.Background(), config, func(context.Context) error { called = true; return nil })
	if err != nil || pending.Switched() || called {
		t.Fatalf("prepare: %v switched=%v precheck=%v", err, pending.Switched(), called)
	}
	if after, _ := os.ReadFile(f.config); !bytes.Equal(before, after) || f.current(t) != "releases/"+filepath.Base(f.oldRelease) {
		t.Fatal("an unchanged runtime touched config.json or the current link")
	}
	status, _ := ReadStatus(f.status)
	if status.State != StateUnchanged || HealthError(status, "1.0.1") != nil {
		t.Fatalf("status: %+v", status)
	}
	entries, _ := os.ReadDir(filepath.Join(f.root, "releases"))
	if len(entries) != 1 {
		t.Fatalf("an unchanged runtime installed a release: %d entries", len(entries))
	}
}

func TestPrecheckFailureRestoresPreviousRuntime(t *testing.T) {
	f := newFixture(t)
	f.buildPackage(t, f.packagePath, "1.0.1", "1.31.1.1", nil)
	config := f.runAgent(t, "1.0.1")
	before, _ := os.ReadFile(f.config)
	_, err := Prepare(context.Background(), config, func(context.Context) error { return errors.New("nginx: [emerg] bad") })
	if Code(err) != CodePrecheck {
		t.Fatalf("error code %q (%v), want %s", Code(err), err, CodePrecheck)
	}
	if f.current(t) != "releases/"+filepath.Base(f.oldRelease) {
		t.Fatalf("current not restored: %s", f.current(t))
	}
	if after, _ := os.ReadFile(f.config); !bytes.Equal(before, after) {
		t.Fatal("config.json not restored")
	}
	status, _ := ReadStatus(f.status)
	if status.State != StateFailed || status.ErrorCode != CodePrecheck {
		t.Fatalf("status: %+v", status)
	}
	var coder interface{ HealthCode() string }
	if health := HealthError(status, "1.0.1"); !errors.As(health, &coder) || coder.HealthCode() != CodePrecheck {
		t.Fatalf("health error: %v", health)
	}
}

func TestBinaryUpgradeFailureRestoresPreviousRuntime(t *testing.T) {
	f := newFixture(t)
	f.buildPackage(t, f.packagePath, "1.0.1", "1.31.1.1", nil)
	config := f.runAgent(t, "1.0.1")
	before, _ := os.ReadFile(f.config)
	pending, err := Prepare(context.Background(), config, nil)
	if err != nil || !pending.Switched() {
		t.Fatalf("prepare: %v", err)
	}
	err = pending.Commit(context.Background(), &fakeHTTP{err: errors.New("new master did not start")})
	if Code(err) != CodeReload || f.current(t) != "releases/"+filepath.Base(f.oldRelease) {
		t.Fatalf("commit: %v current=%s", err, f.current(t))
	}
	if after, _ := os.ReadFile(f.config); !bytes.Equal(before, after) {
		t.Fatal("config.json not restored")
	}
	if status, _ := ReadStatus(f.status); status.ErrorCode != CodeReload {
		t.Fatalf("status: %+v", status)
	}
}

func TestTamperedPackageIsRejected(t *testing.T) {
	f := newFixture(t)
	f.buildPackage(t, f.packagePath, "1.0.1", "1.31.1.1", nil)
	other, _, _ := ed25519.GenerateKey(nil)
	config := f.runAgent(t, "1.0.1")
	config.Keys = map[string]ed25519.PublicKey{"test": other}
	if _, err := Prepare(context.Background(), config, nil); Code(err) != CodeSignature {
		t.Fatalf("foreign key: %v", err)
	}
	if f.current(t) != "releases/"+filepath.Base(f.oldRelease) {
		t.Fatal("rejected package switched the runtime")
	}
}

func TestPackageOfAnotherAgentIsRejected(t *testing.T) {
	f := newFixture(t)
	f.buildPackage(t, f.packagePath, "1.0.1", "1.31.1.1", nil)
	config := f.runAgent(t, "1.0.1")
	_ = os.Remove(f.agent)
	if err := os.WriteFile(f.agent, []byte("a different agent"), 0o555); err != nil {
		t.Fatal(err)
	}
	if _, err := Prepare(context.Background(), config, nil); Code(err) != CodeMismatch {
		t.Fatalf("mismatched Agent: %v", err)
	}
}

func TestRollbackAgentWithoutPackageFindsInstalledRelease(t *testing.T) {
	f := newFixture(t)
	newSHA := f.buildPackage(t, f.packagePath, "1.0.1", "1.31.1.1", nil)
	pending, err := Prepare(context.Background(), f.runAgent(t, "1.0.1"), nil)
	if err != nil {
		t.Fatal(err)
	}
	if err := pending.Commit(context.Background(), nil); err != nil {
		t.Fatal(err)
	}
	// The packaging rollback restores Agent 1.0.0, whose release (the first
	// installation) has no native.tar.gz: its installed release is used.
	if err := os.Remove(f.packagePath); err != nil {
		t.Fatal(err)
	}
	pending, err = Prepare(context.Background(), f.runAgent(t, "1.0.0"), nil)
	if err != nil || !pending.Switched() {
		t.Fatalf("rollback prepare: %v", err)
	}
	if err := pending.Commit(context.Background(), nil); err != nil {
		t.Fatal(err)
	}
	if f.current(t) != "releases/"+filepath.Base(f.oldRelease) {
		t.Fatalf("rollback current = %s", f.current(t))
	}
	if _, err := os.Stat(filepath.Join(f.root, "releases", newSHA)); err != nil {
		t.Fatalf("the newer release must stay as the previous one: %v", err)
	}
}

func TestRestartOfSameAgentIsUnchanged(t *testing.T) {
	f := newFixture(t)
	f.buildPackage(t, f.packagePath, "1.0.1", "1.31.1.1", nil)
	pending, err := Prepare(context.Background(), f.runAgent(t, "1.0.1"), nil)
	if err != nil {
		t.Fatal(err)
	}
	if err := pending.Commit(context.Background(), nil); err != nil {
		t.Fatal(err)
	}
	called := false
	pending, err = Prepare(context.Background(), f.runAgent(t, "1.0.1"), func(context.Context) error { called = true; return nil })
	if err != nil || pending.Switched() || called {
		t.Fatalf("restart: %v switched=%v", err, pending.Switched())
	}
	if status, _ := ReadStatus(f.status); status.State != StateUnchanged || HealthError(status, "1.0.1") != nil {
		t.Fatalf("status: %+v", status)
	}
}

func TestHealthErrorFromAnotherAgent(t *testing.T) {
	if err := HealthError(Status{AgentVersion: "1.0.0", State: StateSwitched}, "1.0.1"); Code(err) != CodeStatusAbsent {
		t.Fatalf("stale status accepted: %v", err)
	}
}

func TestL4UpgradeFailureMovesHTTPMasterBack(t *testing.T) {
	f := newFixture(t)
	f.buildPackage(t, f.packagePath, "1.0.1", "1.31.1.1", nil)
	pending, err := Prepare(context.Background(), f.runAgent(t, "1.0.1"), nil)
	if err != nil || !pending.Switched() {
		t.Fatalf("prepare: %v", err)
	}
	http, l4 := &fakeHTTP{}, &fakeHTTP{err: errors.New("new L4 master did not start")}
	err = pending.Commit(context.Background(), http, nil, l4)
	if Code(err) != CodeReload || f.current(t) != "releases/"+filepath.Base(f.oldRelease) {
		t.Fatalf("commit: %v current=%s", err, f.current(t))
	}
	// The HTTP master already on the new binary goes back to the previous one.
	if http.calls != 2 || l4.calls != 1 {
		t.Fatalf("upgrade calls http=%d l4=%d", http.calls, l4.calls)
	}
}

func TestAgentRolledBackAfterFailedSwitchKeepsReportingRollback(t *testing.T) {
	f := newFixture(t)
	newSHA := f.buildPackage(t, f.packagePath, "1.0.1", "1.31.1.1", nil)
	if _, err := Prepare(context.Background(), f.runAgent(t, "1.0.1"), func(context.Context) error {
		return errors.New("nginx: [emerg] unknown directive")
	}); Code(err) != CodePrecheck {
		t.Fatalf("prepare: %v", err)
	}
	// The updater rolls back to Agent 1.0.0 (its release has no package).
	if err := os.Remove(f.packagePath); err != nil {
		t.Fatal(err)
	}
	want := &Rollback{AgentVersion: "1.0.1", Release: newSHA, ErrorCode: CodePrecheck}
	for _, start := range []string{"rollback", "restart"} {
		pending, err := Prepare(context.Background(), f.runAgent(t, "1.0.0"), nil)
		if err != nil || pending.Switched() {
			t.Fatalf("%s: %v switched=%v", start, err, pending.Switched())
		}
		status, _ := ReadStatus(f.status)
		if status.State != StateUnchanged || status.Release != filepath.Base(f.oldRelease) ||
			status.RolledBack == nil || *status.RolledBack != *want || HealthError(status, "1.0.0") != nil {
			t.Fatalf("%s status: %+v rolled_back=%+v", start, status, status.RolledBack)
		}
	}
	// A later successful switch clears it.
	f.buildPackage(t, f.packagePath, "1.0.1", "1.31.1.1", nil)
	pending, err := Prepare(context.Background(), f.runAgent(t, "1.0.1"), nil)
	if err != nil || !pending.Switched() {
		t.Fatalf("switch: %v", err)
	}
	if err := pending.Commit(context.Background()); err != nil {
		t.Fatal(err)
	}
	if status, _ := ReadStatus(f.status); status.State != StateSwitched || status.RolledBack != nil {
		t.Fatalf("status after switch: %+v", status)
	}
}
