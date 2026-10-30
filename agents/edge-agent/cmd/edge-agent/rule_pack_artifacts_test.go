package main

import (
	"crypto/ecdh"
	"crypto/rand"
	"encoding/json"
	"os"
	"path/filepath"
	"strings"
	"testing"
	"time"

	"github.com/cdnca/cdnca/agents/edge-agent/internal/gatewayclient"
	"github.com/cdnca/cdnca/agents/edge-agent/internal/objectstore"
	"github.com/cdnca/cdnca/agents/edge-agent/internal/rulepackprecheck"
	"github.com/cdnca/cdnca/agents/edge-agent/internal/rulepackvault"
	"github.com/cdnca/cdnca/libs/edgeconfig"
	"github.com/cdnca/cdnca/libs/edgeconfig/artifactset"
	"github.com/cdnca/cdnca/libs/edgeconfig/edgesite"
	"github.com/cdnca/cdnca/libs/rulepack"
)

type sealedPack struct {
	content []byte
	sha     string
	cek     []byte
	pack    *rulepack.CompiledPack
}

func sealTestPack(t *testing.T) sealedPack {
	t.Helper()
	raw, err := os.ReadFile(filepath.Join("..", "..", "..", "..", "libs", "rulepack", "testdata", "packs", "system-sqli.json"))
	if err != nil {
		t.Fatal(err)
	}
	compiled, err := rulepack.Compile(raw)
	if err != nil {
		t.Fatal(err)
	}
	cek := make([]byte, rulepack.CEKSize)
	_, _ = rand.Read(cek)
	sealed, err := rulepack.Seal(compiled.Canonical, cek, nil)
	if err != nil {
		t.Fatal(err)
	}
	return sealedPack{content: sealed, sha: artifactset.Digest(sealed), cek: cek, pack: compiled}
}

func x25519Key(t *testing.T) *ecdh.PrivateKey {
	t.Helper()
	key, err := ecdh.X25519().GenerateKey(rand.Reader)
	if err != nil {
		t.Fatal(err)
	}
	return key
}

// packItem is the set item of content (no compression, one segment) with
// the content key wrapped to recipient.
func packItem(t *testing.T, pack sealedPack, recipient *ecdh.PublicKey) artifactset.Item {
	t.Helper()
	keyID := rulepack.X25519KeyID(recipient.Bytes())
	wrapped, err := rulepack.WrapKey(recipient.Bytes(), pack.cek, rulepack.WrapContext{Purpose: rulepack.WrapPurposeNode,
		RecipientKeyID: keyID, PackID: pack.pack.Pack.PackID, Version: pack.pack.Pack.Version, SealedSHA256: pack.sha})
	if err != nil {
		t.Fatal(err)
	}
	return artifactset.Item{ArtifactID: "rule_pack/" + pack.sha, Version: pack.pack.Pack.Version, Revision: 1,
		MediaType: artifactset.MediaTypeRulePack, SHA256: pack.sha, Size: int64(len(pack.content)),
		Compression: artifactset.CompressionNone, CompressedSHA256: pack.sha, CompressedSize: int64(len(pack.content)),
		Segments: []artifactset.Segment{{SHA256: pack.sha, Size: int64(len(pack.content))}}, Encryption: artifactset.EncryptionNone,
		KeyWrap: &artifactset.KeyWrap{RecipientKeyID: keyID, WrappedKey: wrapped}}
}

func newRulePackFixture(t *testing.T, key *ecdh.PrivateKey) (*artifactSetRuntime, *objectstore.Store, *rulepackvault.Vault, string) {
	t.Helper()
	root := t.TempDir()
	objects, err := objectstore.Open(filepath.Join(root, objectStoreDir))
	if err != nil {
		t.Fatal(err)
	}
	vault, err := openRulePackVault(root, key.Bytes(), objects, filepath.Join(root, "run"), -1)
	if err != nil {
		t.Fatal(err)
	}
	runtime, err := assembleArtifactSetRuntime(root, runtimeTestNodeID, objects, nil, nil, vault)
	if err != nil {
		t.Fatal(err)
	}
	return runtime, objects, vault, root
}

// A sealed pack delivered as an artifact set item is installed in the
// object store, its key reaches the vault, and the site precheck opens it;
// a pack whose key is wrapped to another node is refused and changes
// nothing; restarting reopens it from the stored state.
func TestRulePackItemsInstallAndOpen(t *testing.T) {
	key := x25519Key(t)
	runtime, objects, vault, root := newRulePackFixture(t, key)
	pack := sealTestPack(t)

	other := packItem(t, pack, x25519Key(t).PublicKey())
	if err := runtime.PutObject(pack.sha, pack.content); err != nil {
		t.Fatal(err)
	}
	receipt, err := runtime.Apply(artifactset.Set{NodeID: runtimeTestNodeID, Revision: 1, Items: []artifactset.Item{other}},
		artifactset.Digest([]byte("wrong key")), time.Now())
	if err != nil || receipt.Result != artifactset.ResultRejected || receipt.Items[0].Reason != artifactset.ReasonInstallRejected {
		t.Fatalf("wrong key receipt = %+v, %v", receipt, err)
	}

	item := packItem(t, pack, key.PublicKey())
	receipt, err = runtime.Apply(artifactset.Set{NodeID: runtimeTestNodeID, Revision: 2, Items: []artifactset.Item{item}},
		artifactset.Digest([]byte("right key")), time.Now())
	if err != nil || receipt.Result != artifactset.ResultApplied {
		t.Fatalf("receipt = %+v, %v", receipt, err)
	}
	if _, err := objects.Collect(); err != nil || !objects.Has(pack.sha) {
		t.Fatalf("installed pack collected: %v", err)
	}
	manifest, err := rulepack.OpenManifest(pack.content, pack.sha)
	if err != nil {
		t.Fatal(err)
	}
	resolution := rulepack.Resolve([]rulepack.MountRequest{{Pack: manifest}}, rulepack.Target{})
	document, _ := json.Marshal(resolution.Security)
	plan, err := rulepackprecheck.Plan(document, vault.Object, vault.Load, false)
	if err != nil || len(plan.Segments) != 1 || len(plan.Segments[0].Rules) != len(pack.pack.Pack.Rules) {
		t.Fatalf("plan = %+v, %v", plan, err)
	}

	restarted, err := openRulePackVault(root, key.Bytes(), objects, filepath.Join(root, "run"), -1)
	if err != nil {
		t.Fatal(err)
	}
	if _, err := restarted.OpenObject(pack.sha); err != nil {
		t.Fatalf("after restart: %v", err)
	}
	stranger, err := openRulePackVault(t.TempDir(), x25519Key(t).Bytes(), objects, filepath.Join(root, "run2"), -1)
	if err != nil {
		t.Fatal(err)
	}
	if _, err := rulepackprecheck.Plan(document, stranger.Object, stranger.Load, false); err == nil {
		t.Fatal("another node key opened the sealed pack")
	}
}

// A CRS profile pack (plain) installs from the artifact set without a vault
// (no artifact encryption key); a sealed pack is then refused. The dynamic
// routing manager reads the profile a site's managed WAF names from the
// object store when the release does not carry it, and leaves out one not
// stored yet.
func TestCRSProfileItemWithoutVaultReachesDynamicRouting(t *testing.T) {
	root := t.TempDir()
	objects, err := objectstore.Open(filepath.Join(root, objectStoreDir))
	if err != nil {
		t.Fatal(err)
	}
	runtime, err := assembleArtifactSetRuntime(root, runtimeTestNodeID, objects, nil, nil, nil)
	if err != nil {
		t.Fatal(err)
	}
	content, err := os.ReadFile(filepath.Join("..", "..", "..", "..", "libs", "rulepack", "testdata", "crs-profiles", "crs-pl2.json"))
	if err != nil {
		t.Fatal(err)
	}
	sha := artifactset.Digest(content)
	_, profile, err := rulepack.LoadCRSProfile(content, sha)
	if err != nil {
		t.Fatal(err)
	}
	if err := runtime.PutObject(sha, content); err != nil {
		t.Fatal(err)
	}
	item := artifactset.Item{ArtifactID: "crs_profile/crs-pl2", Version: profile.Ref.Version, Revision: 1,
		MediaType: artifactset.MediaTypeRulePack, SHA256: sha, Size: int64(len(content)),
		Compression: artifactset.CompressionNone, CompressedSHA256: sha, CompressedSize: int64(len(content)),
		Segments: []artifactset.Segment{{SHA256: sha, Size: int64(len(content))}}, Encryption: artifactset.EncryptionNone}
	receipt, err := runtime.Apply(artifactset.Set{NodeID: runtimeTestNodeID, Revision: 1, Items: []artifactset.Item{item}},
		artifactset.Digest([]byte("profile")), time.Now())
	if err != nil || receipt.Result != artifactset.ResultApplied {
		t.Fatalf("profile receipt = %+v, %v", receipt, err)
	}

	sealed := sealTestPack(t)
	if err := runtime.PutObject(sealed.sha, sealed.content); err != nil {
		t.Fatal(err)
	}
	receipt, err = runtime.Apply(artifactset.Set{NodeID: runtimeTestNodeID, Revision: 2,
		Items: []artifactset.Item{item, packItem(t, sealed, x25519Key(t).PublicKey())}}, artifactset.Digest([]byte("sealed")), time.Now())
	if err != nil || receipt.Result != artifactset.ResultRejected || receipt.Items[1].Reason != artifactset.ReasonInstallRejected {
		t.Fatalf("sealed without vault receipt = %+v, %v", receipt, err)
	}

	manager := &dynamicRoutingManager{objects: objects, root: filepath.Join(root, "scopes")}
	if err := os.MkdirAll(manager.root, 0o700); err != nil {
		t.Fatal(err)
	}
	const scopeID = "11111111-1111-4111-8111-111111111111"
	digest, raw := dynamicTestSiteWAF(t, scopeID, "a0000000-0000-4000-8000-000000000001", profile.Ref)
	missingRef := profile.Ref
	missingRef.SHA256 = strings.Repeat("0", 64)
	missingDigest, missingRaw := dynamicTestSiteWAF(t, scopeID, "a0000000-0000-4000-8000-000000000002", missingRef)
	for site, body := range map[string][]byte{digest: raw, missingDigest: missingRaw} {
		if err := objects.Put(site, body); err != nil {
			t.Fatal(err)
		}
	}
	if err := manager.save(scopeID, dynamicRoutingScope{Current: &dynamicRoutingRelease{ConfigVersionID: "c0000000-0000-4000-8000-00000000000a",
		RootSHA256: digest, Sites: []string{digest, missingDigest}}}); err != nil {
		t.Fatal(err)
	}
	input, err := manager.input(nil, gatewayclient.DynamicRoutingRelease{})
	if err != nil {
		t.Fatal(err)
	}
	if got, ok := input.Profiles[sha]; !ok || got.Ref != profile.Ref || len(input.Profiles) != 1 {
		t.Fatalf("profiles = %+v", input.Profiles)
	}
}

// dynamicTestSiteWAF is dynamicTestSite with a managed WAF on profile.
func dynamicTestSiteWAF(t *testing.T, scopeID, siteID string, profile edgeconfig.CRSProfileRef) (string, []byte) {
	t.Helper()
	_, raw := dynamicTestSite(t, scopeID, siteID, siteID[:8]+".example.test")
	site, err := edgesite.Decode(raw)
	if err != nil {
		t.Fatal(err)
	}
	site.Security.ManagedWAF = &edgesite.ManagedWAF{PolicyID: "0d130000-0000-4000-8000-0000000000d1", PolicyVersion: 1,
		Profile: edgesite.ManagedWAFProfile{RequestBodyLimit: 1 << 20, RequestBodyNoFilesLimit: 1 << 20,
			RequestBodyLimitAction: "reject", ArgumentsLimit: 1000, JSONDepthLimit: 512, PCREMatchLimit: 100000, InspectionLimitAction: "log"},
		CRSProfile: profile, Exclusions: []int{}, AllowCIDRs: []string{}}
	encoded, err := edgesite.Encode(site)
	if err != nil {
		t.Fatal(err)
	}
	return edgesite.Digest(encoded), encoded
}
