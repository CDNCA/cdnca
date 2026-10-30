package helper

import (
	"bytes"
	"crypto/ed25519"
	"os"
	"path/filepath"
	"reflect"
	"testing"
)

// node-runtime-upgrade: a v2 bundle carries the signed native node package
// as a fifth section; staging, verification and the packaging handoff keep it
// bound to the outer digest and pass it to upgrade.sh as --native.

func stageNativeTestBundle(t *testing.T, native []byte) (StagedBundle, ed25519.PublicKey, []byte) {
	t.Helper()
	v1, publicKey := stageSignedTestRelease(t, 7, "1.2.3", "linux", "amd64", nil)
	read := func(path string) []byte {
		content, err := os.ReadFile(path)
		if err != nil {
			t.Fatal(err)
		}
		return content
	}
	bundle := EncodeReleaseBundle(read(v1.ManifestPath), read(v1.SignaturePath), read(v1.SBOMPath), read(v1.ExecutablePath), native)
	artifact := openTestArtifact(t, bundle, os.O_RDONLY)
	staged, err := StageReleaseBundle(artifact, testStagingDirectory(t), int64(len(bundle)), digestOf(bundle))
	if err != nil {
		t.Fatalf("stage v2 bundle: %v", err)
	}
	return staged, publicKey, bundle
}

func TestStageReleaseBundleV2CarriesNativeSection(t *testing.T) {
	native := append([]byte{0x1f, 0x8b}, bytes.Repeat([]byte{7}, 64)...)
	staged, publicKey, bundle := stageNativeTestBundle(t, native)
	if !bytes.HasPrefix(bundle, []byte(BundleMagicV2)) {
		t.Fatal("a bundle with a native package must use the v2 magic")
	}
	if staged.NativePath != filepath.Join(staged.Directory, NativeSectionName) || staged.NativeSize != int64(len(native)) ||
		staged.NativeSHA256 != digestOf(native) {
		t.Fatalf("native section facts: %+v", staged)
	}
	if content, err := os.ReadFile(staged.NativePath); err != nil || !bytes.Equal(content, native) {
		t.Fatalf("native section content: %v", err)
	}
	if _, err := VerifyReleaseManifest(staged, publicKey, ManifestExpectation{ReleaseSequence: 7, TargetVersion: "1.2.3", Platform: "linux", Architecture: "amd64"}); err != nil {
		t.Fatalf("verify v2 bundle: %v", err)
	}
	// The native bytes are bound to the staged facts.
	if err := os.Chmod(staged.NativePath, 0600); err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(staged.NativePath, append([]byte{0x1f, 0x8b}, bytes.Repeat([]byte{8}, 64)...), 0400); err != nil {
		t.Fatal(err)
	}
	if err := os.Chmod(staged.NativePath, 0400); err != nil {
		t.Fatal(err)
	}
	if _, err := VerifyReleaseManifest(staged, publicKey, ManifestExpectation{ReleaseSequence: 7, TargetVersion: "1.2.3", Platform: "linux", Architecture: "amd64"}); err == nil {
		t.Fatal("a changed native section was accepted")
	}
}

func TestEncodeReleaseBundleWithoutNativeStaysV1(t *testing.T) {
	bundle := EncodeReleaseBundle([]byte("m\n"), bytes.Repeat([]byte{1}, 64), []byte("{}"), []byte{0x7f})
	if !bytes.HasPrefix(bundle, []byte(BundleMagic)) || bytes.HasPrefix(bundle, []byte(BundleMagicV2)) {
		t.Fatal("a bundle without a native package must stay v1")
	}
	if !bytes.Equal(bundle, EncodeReleaseBundle([]byte("m\n"), bytes.Repeat([]byte{1}, 64), []byte("{}"), []byte{0x7f}, nil)) {
		t.Fatal("an empty native package must encode as v1")
	}
}

func TestStageReleaseBundleV1HasNoNativeSection(t *testing.T) {
	staged, _ := stageSignedTestRelease(t, 7, "1.2.3", "linux", "amd64", nil)
	if staged.NativePath != "" || staged.NativeSHA256 != "" || staged.NativeSize != 0 {
		t.Fatalf("v1 bundle reported a native section: %+v", staged)
	}
}

func TestUpgradeCommandPassesNativeSection(t *testing.T) {
	native := append([]byte{0x1f, 0x8b}, bytes.Repeat([]byte{9}, 32)...)
	staged, _, _ := stageNativeTestBundle(t, native)
	temporaryBase := t.TempDir()
	handoff, taskRoot, err := createUpgradeHandoff(staged, temporaryBase)
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { _ = cleanupUpgradeHandoff(taskRoot, temporaryBase) })
	if handoff.NativePath != filepath.Join(handoff.Directory, NativeSectionName) {
		t.Fatalf("handoff native path: %q", handoff.NativePath)
	}
	if info, err := os.Stat(handoff.NativePath); err != nil || info.Mode().Perm() != 0444 {
		t.Fatalf("handoff native mode: %v %v", info, err)
	}
	command, err := upgradeCommand(handoff)
	if err != nil {
		t.Fatal(err)
	}
	want := []string{
		"--artifact", handoff.ExecutablePath, "--sbom", handoff.SBOMPath, "--manifest", handoff.ManifestPath,
		"--signature", handoff.SignaturePath, "--public-key", PinnedReleasePublicKeyPath, "--native", handoff.NativePath,
	}
	if !reflect.DeepEqual(command.args, want) {
		t.Fatalf("upgrade command args: %v", command.args)
	}
	handoff.NativePath = "/tmp/elsewhere.tar.gz"
	if _, err := upgradeCommand(handoff); err == nil {
		t.Fatal("a non-canonical native path was accepted")
	}
}
