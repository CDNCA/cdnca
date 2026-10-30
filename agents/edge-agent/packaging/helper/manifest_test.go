package helper

import (
	"crypto/ed25519"
	"crypto/sha256"
	"crypto/x509"
	"encoding/hex"
	"encoding/pem"
	"errors"
	"fmt"
	"os"
	"path/filepath"
	"strings"
	"syscall"
	"testing"
)

func TestVerifyReleaseManifest(t *testing.T) {
	staged, publicKey := stageSignedTestRelease(t, 7, "1.2.3", "linux", "amd64", nil)
	manifest, err := VerifyReleaseManifest(staged, publicKey, ManifestExpectation{
		ReleaseSequence: 7, TargetVersion: "1.2.3", Platform: "linux", Architecture: "amd64",
	})
	if err != nil {
		t.Fatalf("verify release manifest: %v", err)
	}
	if manifest.ManifestVersion != 2 || manifest.ReleaseSequence != 7 || manifest.Version != "1.2.3" ||
		manifest.ArtifactSHA256 != staged.ExecutableSHA256 || manifest.SBOMSHA256 != staged.SBOMSHA256 ||
		manifest.ManifestSHA256 != staged.ManifestSHA256 {
		t.Fatalf("unexpected manifest: %+v", manifest)
	}
}

func TestVerifyReleaseManifestRejectsMismatches(t *testing.T) {
	tests := []struct {
		name     string
		expected ManifestExpectation
		mutate   func(*StagedBundle)
		want     error
	}{
		{name: "sequence", expected: ManifestExpectation{8, "1.2.3", "linux", "amd64"}, want: ErrReleaseMismatch},
		{name: "version", expected: ManifestExpectation{7, "1.2.4", "linux", "amd64"}, want: ErrReleaseMismatch},
		{name: "platform", expected: ManifestExpectation{7, "1.2.3", "other", "amd64"}, want: ErrReleaseMismatch},
		{name: "architecture", expected: ManifestExpectation{7, "1.2.3", "linux", "arm64"}, want: ErrReleaseMismatch},
		{name: "staged executable digest", expected: ManifestExpectation{7, "1.2.3", "linux", "amd64"}, mutate: func(value *StagedBundle) { value.ExecutableSHA256 = strings.Repeat("0", 64) }, want: ErrArtifactMismatch},
	}
	for _, test := range tests {
		t.Run(test.name, func(t *testing.T) {
			staged, publicKey := stageSignedTestRelease(t, 7, "1.2.3", "linux", "amd64", nil)
			if test.mutate != nil {
				test.mutate(&staged)
			}
			_, err := VerifyReleaseManifest(staged, publicKey, test.expected)
			if !errors.Is(err, test.want) {
				t.Fatalf("got %v, want %v", err, test.want)
			}
		})
	}
}

func TestVerifyReleaseManifestRejectsSignatureAndNonCanonicalManifest(t *testing.T) {
	t.Run("signature", func(t *testing.T) {
		staged, publicKey := stageSignedTestRelease(t, 7, "1.2.3", "linux", "amd64", nil)
		if err := os.Chmod(staged.SignaturePath, 0600); err != nil {
			t.Fatal(err)
		}
		content, err := os.ReadFile(staged.SignaturePath)
		if err != nil {
			t.Fatal(err)
		}
		content[0] ^= 1
		if err := os.WriteFile(staged.SignaturePath, content, 0400); err != nil {
			t.Fatal(err)
		}
		if err := os.Chmod(staged.SignaturePath, 0400); err != nil {
			t.Fatal(err)
		}
		_, err = VerifyReleaseManifest(staged, publicKey, ManifestExpectation{7, "1.2.3", "linux", "amd64"})
		if !errors.Is(err, ErrArtifactMismatch) {
			t.Fatalf("got %v", err)
		}
	})

	t.Run("line order", func(t *testing.T) {
		staged, publicKey := stageSignedTestRelease(t, 7, "1.2.3", "linux", "amd64", func(lines []string) {
			lines[0], lines[1] = lines[1], lines[0]
		})
		_, err := VerifyReleaseManifest(staged, publicKey, ManifestExpectation{7, "1.2.3", "linux", "amd64"})
		if !errors.Is(err, ErrInvalidManifest) {
			t.Fatalf("got %v", err)
		}
	})
}

func TestLoadPinnedReleasePublicKeyPolicy(t *testing.T) {
	seed := make([]byte, ed25519.SeedSize)
	privateKey := ed25519.NewKeyFromSeed(seed)
	publicKey := privateKey.Public().(ed25519.PublicKey)
	encoded, err := x509.MarshalPKIXPublicKey(publicKey)
	if err != nil {
		t.Fatal(err)
	}
	path := filepath.Join(t.TempDir(), "package-signing.pem")
	if err := os.WriteFile(path, pem.EncodeToMemory(&pem.Block{Type: "PUBLIC KEY", Bytes: encoded}), 0444); err != nil {
		t.Fatal(err)
	}
	info, err := os.Stat(path)
	if err != nil {
		t.Fatal(err)
	}
	stat := info.Sys().(*syscall.Stat_t)
	got, err := loadPinnedReleasePublicKey(path, int(stat.Uid), int(stat.Gid))
	if err != nil || !got.Equal(publicKey) {
		t.Fatalf("load pinned key: %v", err)
	}
	if err := os.Chmod(path, 0644); err != nil {
		t.Fatal(err)
	}
	if _, err := loadPinnedReleasePublicKey(path, int(stat.Uid), int(stat.Gid)); !errors.Is(err, ErrPinnedKeyUnsafe) {
		t.Fatalf("unsafe key mode accepted: %v", err)
	}
}

func stageSignedTestRelease(t *testing.T, sequence uint64, version, platform, architecture string, mutate func([]string)) (StagedBundle, ed25519.PublicKey) {
	t.Helper()
	executable := []byte{0x7f, 'E', 'L', 'F', 2, 1, 1, 0}
	sbom := []byte(`{"spdxVersion":"SPDX-2.3","name":"edge-agent"}`)
	executableDigest := sha256.Sum256(executable)
	sbomDigest := sha256.Sum256(sbom)
	lines := []string{
		"manifest_version=2",
		fmt.Sprintf("release_sequence=%d", sequence),
		"version=" + version,
		"artifact_path=edge-agent",
		"artifact_sha256=" + hex.EncodeToString(executableDigest[:]),
		fmt.Sprintf("artifact_size=%d", len(executable)),
		"sbom_path=edge-agent.spdx.json",
		"sbom_sha256=" + hex.EncodeToString(sbomDigest[:]),
		fmt.Sprintf("sbom_size=%d", len(sbom)),
		"os=" + platform,
		"arch=" + architecture,
		"source_repository=https://example.invalid/cdnca",
		"source_commit=" + strings.Repeat("a", 40),
		"build_time=2026-07-28T00:00:00Z",
		"minimum_control_protocol=1.0",
		"minimum_agent_protocol=1.0",
	}
	if mutate != nil {
		mutate(lines)
	}
	manifest := []byte(strings.Join(lines, "\n") + "\n")
	seed := make([]byte, ed25519.SeedSize)
	for index := range seed {
		seed[index] = byte(index)
	}
	privateKey := ed25519.NewKeyFromSeed(seed)
	publicKey := append(ed25519.PublicKey(nil), privateKey.Public().(ed25519.PublicKey)...)
	signature := ed25519.Sign(privateKey, manifest)
	bundle := testBundle(manifest, signature, sbom, executable)
	artifact := openTestArtifact(t, bundle, os.O_RDONLY)
	staged, err := StageReleaseBundle(artifact, testStagingDirectory(t), int64(len(bundle)), digestOf(bundle))
	if err != nil {
		t.Fatal(err)
	}
	return staged, publicKey
}
