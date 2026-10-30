package rulepackvault

import (
	"bytes"
	"crypto/ecdh"
	"crypto/rand"
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"
	"errors"
	"os"
	"path/filepath"
	"strings"
	"testing"

	"github.com/cdnca/cdnca/agents/edge-agent/internal/rulepackprecheck"
	"github.com/cdnca/cdnca/libs/rulepack"
)

var packFile = filepath.Join("..", "..", "..", "..", "libs", "rulepack", "testdata", "packs", "system-sqli.json")

type sealedFixture struct {
	sealed []byte
	sha    string
	cek    []byte
	pack   *rulepack.CompiledPack
}

func newKey(t *testing.T) ([]byte, []byte) {
	t.Helper()
	key, err := ecdh.X25519().GenerateKey(rand.Reader)
	if err != nil {
		t.Fatal(err)
	}
	return key.Bytes(), key.PublicKey().Bytes()
}

func sealPack(t *testing.T) sealedFixture {
	t.Helper()
	content, err := os.ReadFile(packFile)
	if err != nil {
		t.Fatal(err)
	}
	compiled, err := rulepack.Compile(content)
	if err != nil {
		t.Fatal(err)
	}
	cek := make([]byte, rulepack.CEKSize)
	if _, err := rand.Read(cek); err != nil {
		t.Fatal(err)
	}
	sealed, err := rulepack.Seal(compiled.Canonical, cek, nil)
	if err != nil {
		t.Fatal(err)
	}
	sum := sha256.Sum256(sealed)
	return sealedFixture{sealed: sealed, sha: hex.EncodeToString(sum[:]), cek: cek, pack: compiled}
}

// wrapFor is what the control plane does for one node key.
func wrapFor(t *testing.T, fixture sealedFixture, nodePublic []byte) Wrap {
	t.Helper()
	keyID := rulepack.X25519KeyID(nodePublic)
	wrapped, err := rulepack.WrapKey(nodePublic, fixture.cek, rulepack.WrapContext{Purpose: rulepack.WrapPurposeNode,
		RecipientKeyID: keyID, PackID: fixture.pack.Pack.PackID, Version: fixture.pack.Pack.Version, SealedSHA256: fixture.sha})
	if err != nil {
		t.Fatal(err)
	}
	return Wrap{SealedSHA256: fixture.sha, PackID: fixture.pack.Pack.PackID, Version: fixture.pack.Pack.Version,
		RecipientKeyID: keyID, WrappedKey: wrapped}
}

func testVault(t *testing.T, private []byte, stateDir string, objects map[string][]byte) *Vault {
	t.Helper()
	vault, err := open(Config{PrivateKey: private, StateDir: stateDir, ModSecurityDir: filepath.Join(t.TempDir(), "modsec"),
		OwnerUID: -1, OwnerGID: -1, Objects: func(sha string) ([]byte, error) {
			if content, ok := objects[sha]; ok {
				return content, nil
			}
			return nil, os.ErrNotExist
		}})
	if err != nil {
		t.Fatal(err)
	}
	return vault
}

func TestVaultOpensInMemoryAndRecoversAfterRestart(t *testing.T) {
	fixture := sealPack(t)
	private, public := newKey(t)
	stateDir := t.TempDir()
	objects := map[string][]byte{fixture.sha: fixture.sealed}
	vault := testVault(t, private, stateDir, objects)
	if _, err := vault.OpenObject(fixture.sha); !errors.Is(err, ErrNoKey) {
		t.Fatalf("opened without a key: %v", err)
	}
	if err := vault.Replace([]Wrap{wrapFor(t, fixture, public)}); err != nil {
		t.Fatal(err)
	}
	opened, err := vault.OpenObject(fixture.sha)
	if err != nil || len(opened.Pack.Rules) != 2 || !opened.Sealed {
		t.Fatalf("open = %v", err)
	}
	// The state file holds only wrapped keys, owner-only, no plaintext.
	info, err := os.Stat(filepath.Join(stateDir, StateFile))
	if err != nil || info.Mode().Perm() != 0o600 {
		t.Fatalf("state file mode = %v, %v", info.Mode(), err)
	}
	stateBytes, _ := os.ReadFile(filepath.Join(stateDir, StateFile))
	if bytes.Contains(stateBytes, []byte("detect")) || bytes.Contains(stateBytes, []byte("wp-admin")) {
		t.Fatal("vault state carries plaintext")
	}
	// Restart: a new vault on the same state opens it again.
	restarted := testVault(t, private, stateDir, objects)
	if _, err := restarted.OpenObject(fixture.sha); err != nil {
		t.Fatalf("after restart: %v", err)
	}
	// The same state with another node key (rotation): wraps dropped.
	otherPrivate, _ := newKey(t)
	rotated := testVault(t, otherPrivate, stateDir, objects)
	if _, err := rotated.OpenObject(fixture.sha); !errors.Is(err, ErrNoKey) {
		t.Fatalf("another node key opened the pack: %v", err)
	}
}

func TestVaultRefusesOtherNodesWrapAndCopies(t *testing.T) {
	fixture := sealPack(t)
	private, _ := newKey(t)
	_, otherPublic := newKey(t)
	vault := testVault(t, private, t.TempDir(), map[string][]byte{fixture.sha: fixture.sealed})
	foreign := wrapFor(t, fixture, otherPublic)
	if err := vault.Replace([]Wrap{foreign}); !errors.Is(err, rulepack.ErrKeyRejected) {
		t.Fatalf("another node's wrap accepted: %v", err)
	}
	// A wrap relabelled with this node's key id does not open either.
	foreign.RecipientKeyID = vault.KeyID()
	if err := vault.Replace([]Wrap{foreign}); !errors.Is(err, rulepack.ErrKeyRejected) {
		t.Fatalf("relabelled wrap accepted: %v", err)
	}
}

func TestPrecheckRunsSealedMounts(t *testing.T) {
	fixture := sealPack(t)
	private, public := newKey(t)
	objects := map[string][]byte{fixture.sha: fixture.sealed}
	vault := testVault(t, private, t.TempDir(), objects)
	if err := vault.Replace([]Wrap{wrapFor(t, fixture, public)}); err != nil {
		t.Fatal(err)
	}
	// The control plane resolves the mount from the manifest only.
	manifest, err := rulepack.OpenManifest(fixture.sealed, fixture.sha)
	if err != nil {
		t.Fatal(err)
	}
	resolution := rulepack.Resolve([]rulepack.MountRequest{{Pack: manifest}}, rulepack.Target{})
	if resolution.Security == nil {
		t.Fatalf("resolution conflicts: %+v", resolution.Conflicts)
	}
	document, _ := json.Marshal(resolution.Security)
	objectsFn := func(sha string) ([]byte, error) { return objects[sha], nil }
	if _, err := rulepackprecheck.Check(document, objectsFn); err == nil {
		t.Fatal("plain precheck accepted a sealed pack")
	}
	rules, err := rulepackprecheck.CheckWith(document, objectsFn, vault.Load)
	if err != nil || len(rules) != 2 {
		t.Fatalf("sealed precheck = %d rules, %v", len(rules), err)
	}
}

func TestModSecurityFilesAreOwnerOnlyOnTmpfs(t *testing.T) {
	private, _ := newKey(t)
	vault := testVault(t, private, t.TempDir(), nil)
	path, err := vault.WriteModSecurity("dev-acme-crs.conf", []byte("SecRule ARGS \"@rx x\" \"id:1,deny\"\n"))
	if err != nil {
		t.Fatal(err)
	}
	info, err := os.Stat(path)
	if err != nil || info.Mode().Perm() != 0o600 {
		t.Fatalf("mode = %v, %v", info.Mode(), err)
	}
	if _, err := vault.WriteModSecurity("../escape", nil); !errors.Is(err, ErrInvalidConfig) {
		t.Fatalf("path escape: %v", err)
	}
	if err := vault.RemoveModSecurity(map[string]bool{}); err != nil {
		t.Fatal(err)
	}
	if _, err := os.Stat(path); !errors.Is(err, os.ErrNotExist) {
		t.Fatal("stale ModSecurity file kept")
	}
	// The production constructor requires tmpfs: a plain temp dir is refused
	// unless the host's temp dir is itself a tmpfs.
	strict, err := Open(Config{PrivateKey: private, StateDir: t.TempDir(), ModSecurityDir: t.TempDir(), OwnerUID: -1, OwnerGID: -1,
		Objects: func(string) ([]byte, error) { return nil, os.ErrNotExist }})
	if err != nil {
		t.Fatal(err)
	}
	_, err = strict.WriteModSecurity("x.conf", []byte("x"))
	if onTmpfs, _ := isTmpfs(strict.config.ModSecurityDir); onTmpfs {
		if err != nil {
			t.Fatalf("tmpfs directory refused: %v", err)
		}
	} else if !errors.Is(err, ErrNotTmpfs) {
		t.Fatalf("non-tmpfs directory accepted: %v", err)
	}
}

// A site's CC pack policy is <resolved>.<site_id>.cc.json next to the rule
// plan; RetainPlans keeps both kinds by resolved digest and drops the rest.
func TestPlanFilesAreRetainedByResolvedDigest(t *testing.T) {
	private, _ := newKey(t)
	planDir := filepath.Join(t.TempDir(), "plans")
	vault, err := open(Config{PrivateKey: private, StateDir: t.TempDir(), OwnerUID: -1, OwnerGID: -1, PlanDir: planDir, PlanGID: -1,
		Objects: func(string) ([]byte, error) { return nil, os.ErrNotExist }})
	if err != nil {
		t.Fatal(err)
	}
	kept, dropped := strings.Repeat("a", 64), strings.Repeat("b", 64)
	site := "0d130000-0000-4000-8000-000000000006"
	for _, resolved := range []string{kept, dropped} {
		if err := vault.WritePlan(resolved, []byte("{}")); err != nil {
			t.Fatal(err)
		}
		if err := vault.WriteCCPlan(resolved, site, []byte("{}")); err != nil {
			t.Fatal(err)
		}
	}
	if err := vault.WriteCCPlan(kept, "../escape", []byte("{}")); !errors.Is(err, ErrInvalidConfig) {
		t.Fatalf("invalid site ID: %v", err)
	}
	if err := vault.RetainPlans(map[string]bool{kept: true}); err != nil {
		t.Fatal(err)
	}
	entries, err := os.ReadDir(planDir)
	if err != nil {
		t.Fatal(err)
	}
	var names []string
	for _, entry := range entries {
		names = append(names, entry.Name())
	}
	want := []string{kept + "." + site + ".cc.json", kept + ".json"}
	if strings.Join(names, ",") != strings.Join(want, ",") {
		t.Fatalf("plan files = %v, want %v", names, want)
	}
	info, err := os.Stat(filepath.Join(planDir, want[0]))
	if err != nil || info.Mode().Perm() != 0o640 {
		t.Fatalf("CC plan mode = %v, %v", info, err)
	}
}
