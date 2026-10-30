package helper

import (
	"bytes"
	"crypto/ed25519"
	"crypto/x509"
	"encoding/base64"
	"encoding/binary"
	"encoding/json"
	"encoding/pem"
	"errors"
	"os"
	"path/filepath"
	"strconv"
	"strings"
	"testing"
)

// Frozen digest of the bundle built from releaseFixture with the fixed-seed
// key below. Any change to the manifest text, section order, framing or
// signature input changes it.
const goldenReleaseBundleSHA256 = "99f87b4d420dfacfe59defb485c7f2cf16586c7cc2cfa9130a85f0bdece7b6a7"

var releaseTestKey = ed25519.NewKeyFromSeed(bytes.Repeat([]byte{0x42}, ed25519.SeedSize))

func releaseFixture(t *testing.T, arch string) string {
	t.Helper()
	directory := filepath.Join(t.TempDir(), "release")
	if err := os.Mkdir(directory, 0o700); err != nil {
		t.Fatal(err)
	}
	executable := make([]byte, 128)
	copy(executable, []byte{0x7f, 'E', 'L', 'F', 2, 1, 1})
	binary.LittleEndian.PutUint16(executable[16:18], 2)
	binary.LittleEndian.PutUint16(executable[18:20], map[string]uint16{"amd64": 62, "arm64": 183}[arch])
	copy(executable[64:], "release bundle fixture")
	sbom := []byte(`{"SPDXID":"SPDXRef-DOCUMENT","creationInfo":{"created":"2026-07-22T00:00:00Z","creators":["Tool: fixture"]},` +
		`"dataLicense":"CC0-1.0","documentNamespace":"https://example.invalid/spdx/fixture","name":"cdnca-edge-agent-1.0.25","spdxVersion":"SPDX-2.3"}` + "\n")
	provenance, err := json.Marshal(map[string]any{
		"schema": "cdnca.edge.release-provenance/v1", "arch": arch, "version": "1.0.25",
		"source_repository": "https://example.invalid/cdnca.git", "source_commit": strings.Repeat("a", 40),
		"created":  "2026-07-22T00:00:00Z",
		"artifact": map[string]any{"path": "edge-agent", "sha256": sha256Hex(executable), "size": len(executable)},
		"sbom":     map[string]any{"path": "edge-agent.spdx.json", "sha256": sha256Hex(sbom)},
	})
	if err != nil {
		t.Fatal(err)
	}
	for name, data := range map[string][]byte{"edge-agent": executable, "edge-agent.spdx.json": sbom, "edge-agent.provenance.json": provenance} {
		if err := os.WriteFile(filepath.Join(directory, name), data, 0o444); err != nil {
			t.Fatal(err)
		}
	}
	return directory
}

func writeReleaseKey(t *testing.T, directory string, key ed25519.PublicKey) string {
	t.Helper()
	der, err := x509.MarshalPKIXPublicKey(key)
	if err != nil {
		t.Fatal(err)
	}
	path := filepath.Join(directory, "package-signing.pem")
	if err := os.WriteFile(path, pem.EncodeToMemory(&pem.Block{Type: "PUBLIC KEY", Bytes: der}), 0o444); err != nil {
		t.Fatal(err)
	}
	return path
}

// signPrepared models the external signer: it signs the exact signing-data
// bytes. encode selects the delivered signature form.
func signPrepared(t *testing.T, prepared string, key ed25519.PrivateKey, encode func([]byte) []byte) string {
	t.Helper()
	data, err := os.ReadFile(filepath.Join(prepared, SigningDataName))
	if err != nil {
		t.Fatal(err)
	}
	path := filepath.Join(filepath.Dir(prepared), "signature")
	if err := os.WriteFile(path, encode(ed25519.Sign(key, data)), 0o600); err != nil {
		t.Fatal(err)
	}
	return path
}

func raw(signature []byte) []byte { return signature }

func prepareFixture(t *testing.T) (prepared, keyPath string) {
	t.Helper()
	release := releaseFixture(t, "amd64")
	prepared = filepath.Join(t.TempDir(), "prepared")
	if _, err := PrepareReleaseBundle(PrepareOptions{ReleaseDir: release, ReleaseSequence: 25, OutputDir: prepared}); err != nil {
		t.Fatal(err)
	}
	return prepared, writeReleaseKey(t, t.TempDir(), releaseTestKey.Public().(ed25519.PublicKey))
}

func TestReleaseBundleGoldenStructureAndHelperAcceptance(t *testing.T) {
	prepared, keyPath := prepareFixture(t)
	manifest, err := os.ReadFile(filepath.Join(prepared, "manifest"))
	if err != nil {
		t.Fatal(err)
	}
	executable, _ := os.ReadFile(filepath.Join(prepared, "edge-agent"))
	sbom, _ := os.ReadFile(filepath.Join(prepared, "edge-agent.spdx.json"))
	wantManifest := "manifest_version=2\nrelease_sequence=25\nversion=1.0.25\nartifact_path=edge-agent\n" +
		"artifact_sha256=" + sha256Hex(executable) + "\nartifact_size=128\nsbom_path=edge-agent.spdx.json\n" +
		"sbom_sha256=" + sha256Hex(sbom) + "\nsbom_size=" + strconv.Itoa(len(sbom)) + "\nos=linux\narch=amd64\n" +
		"source_repository=https://example.invalid/cdnca.git\nsource_commit=" + strings.Repeat("a", 40) + "\n" +
		"build_time=2026-07-22T00:00:00Z\nminimum_control_protocol=1.0\nminimum_agent_protocol=1.0\n"
	if string(manifest) != wantManifest {
		t.Fatalf("manifest differs:\n%s", manifest)
	}
	signingData, _ := os.ReadFile(filepath.Join(prepared, SigningDataName))
	if !bytes.Equal(signingData, manifest) {
		t.Fatal("signing data must be the exact manifest bytes")
	}
	facts, err := FinalizeReleaseBundle(FinalizeOptions{
		PreparedDir: prepared, SignaturePath: signPrepared(t, prepared, releaseTestKey, raw),
		PublicKeyPath: keyPath, DownloadBaseURL: "https://auth.cdnca.com/downloads",
	})
	if err != nil {
		t.Fatal(err)
	}
	bundle, err := os.ReadFile(filepath.Join(prepared, facts.BundleFile))
	if err != nil {
		t.Fatal(err)
	}
	signature := ed25519.Sign(releaseTestKey, manifest)
	if !bytes.Equal(bundle, testBundle(manifest, signature, sbom, executable)) {
		t.Fatal("bundle is not MAGIC || u64be-framed manifest, signature, SBOM, executable")
	}
	if facts.SHA256 != goldenReleaseBundleSHA256 {
		t.Fatalf("golden release bundle SHA-256 drifted: got %s", facts.SHA256)
	}
	if facts.BundleFile != "cdnca-edge-agent-1.0.25-linux-amd64.bundle" || facts.Size != int64(len(bundle)) ||
		facts.ReleaseSequence != 25 || facts.Component != "edge-agent" ||
		facts.DownloadURL != "https://auth.cdnca.com/downloads/edge-agent/1.0.25/cdnca-edge-agent-1.0.25-linux-amd64.bundle" {
		t.Fatalf("bundle facts = %+v", facts)
	}
	sums, _ := os.ReadFile(filepath.Join(prepared, "SHA256SUMS"))
	if string(sums) != facts.SHA256+"  "+facts.BundleFile+"\n" {
		t.Fatalf("SHA256SUMS = %q", sums)
	}

	// The helper's own staging and verification accept the produced bundle.
	staged, err := StageReleaseBundle(openTestArtifact(t, bundle, os.O_RDONLY), testStagingDirectory(t), int64(len(bundle)), facts.SHA256)
	if err != nil {
		t.Fatal(err)
	}
	if _, err := VerifyReleaseManifest(staged, releaseTestKey.Public().(ed25519.PublicKey), ManifestExpectation{
		ReleaseSequence: 25, TargetVersion: "1.0.25", Platform: "linux", Architecture: "amd64",
	}); err != nil {
		t.Fatalf("helper rejected the produced bundle: %v", err)
	}
}

func TestReleaseBundleTamperIsRejectedByHelper(t *testing.T) {
	prepared, keyPath := prepareFixture(t)
	facts, err := FinalizeReleaseBundle(FinalizeOptions{
		PreparedDir: prepared, SignaturePath: signPrepared(t, prepared, releaseTestKey, raw), PublicKeyPath: keyPath,
	})
	if err != nil {
		t.Fatal(err)
	}
	bundle, _ := os.ReadFile(filepath.Join(prepared, facts.BundleFile))
	manifestLength := int(binary.BigEndian.Uint64(bundle[len(BundleMagic):]))
	offsets := map[string]int{
		"magic": 0, "manifest length": len(BundleMagic) + 7, "manifest": len(BundleMagic) + 8 + 10,
		"signature":  len(BundleMagic) + 8 + manifestLength + 8 + 5,
		"sbom":       len(BundleMagic) + 8 + manifestLength + 8 + 64 + 8 + 3,
		"executable": len(bundle) - 1,
	}
	public := releaseTestKey.Public().(ed25519.PublicKey)
	expect := ManifestExpectation{ReleaseSequence: 25, TargetVersion: "1.0.25", Platform: "linux", Architecture: "amd64"}
	verify := func(candidate []byte) error {
		staged, err := StageReleaseBundle(openTestArtifact(t, candidate, os.O_RDONLY), testStagingDirectory(t), int64(len(candidate)), sha256Hex(candidate))
		if err != nil {
			return err
		}
		_, err = VerifyReleaseManifest(staged, public, expect)
		return err
	}
	for name, offset := range offsets {
		t.Run(name, func(t *testing.T) {
			candidate := append([]byte(nil), bundle...)
			candidate[offset] ^= 0x01
			if err := verify(candidate); err == nil {
				t.Fatalf("helper accepted a bundle with a flipped %s byte", name)
			}
		})
	}
	for name, candidate := range map[string][]byte{
		"trailing byte": append(append([]byte(nil), bundle...), 0),
		"truncated":     bundle[:len(bundle)-1],
	} {
		t.Run(name, func(t *testing.T) {
			if err := verify(candidate); err == nil {
				t.Fatalf("helper accepted a %s bundle", name)
			}
		})
	}
	other := ed25519.NewKeyFromSeed(bytes.Repeat([]byte{0x24}, ed25519.SeedSize))
	t.Run("other release key", func(t *testing.T) {
		staged, err := StageReleaseBundle(openTestArtifact(t, bundle, os.O_RDONLY), testStagingDirectory(t), int64(len(bundle)), facts.SHA256)
		if err != nil {
			t.Fatal(err)
		}
		if _, err := VerifyReleaseManifest(staged, other.Public().(ed25519.PublicKey), expect); !errors.Is(err, ErrInvalidManifest) {
			t.Fatalf("other key error = %v", err)
		}
	})
}

func TestFinalizeReleaseBundleRejectsBadSignaturesAndDrift(t *testing.T) {
	other := ed25519.NewKeyFromSeed(bytes.Repeat([]byte{0x24}, ed25519.SeedSize))
	for _, test := range []struct {
		name   string
		mutate func(t *testing.T, prepared, keyPath string) FinalizeOptions
	}{
		{"wrong signing key", func(t *testing.T, prepared, keyPath string) FinalizeOptions {
			return FinalizeOptions{PreparedDir: prepared, SignaturePath: signPrepared(t, prepared, other, raw), PublicKeyPath: keyPath}
		}},
		{"short signature", func(t *testing.T, prepared, keyPath string) FinalizeOptions {
			return FinalizeOptions{PreparedDir: prepared, SignaturePath: signPrepared(t, prepared, releaseTestKey, func(s []byte) []byte { return s[:63] }), PublicKeyPath: keyPath}
		}},
		{"executable changed after prepare", func(t *testing.T, prepared, keyPath string) FinalizeOptions {
			path := filepath.Join(prepared, "edge-agent")
			_ = os.Chmod(path, 0o755)
			data, _ := os.ReadFile(path)
			data[100] ^= 1
			_ = os.WriteFile(path, data, 0o555)
			return FinalizeOptions{PreparedDir: prepared, SignaturePath: signPrepared(t, prepared, releaseTestKey, raw), PublicKeyPath: keyPath}
		}},
		{"signing data differs from manifest", func(t *testing.T, prepared, keyPath string) FinalizeOptions {
			path := filepath.Join(prepared, SigningDataName)
			_ = os.Chmod(path, 0o644)
			_ = os.WriteFile(path, []byte("manifest_version=2\n"), 0o444)
			return FinalizeOptions{PreparedDir: prepared, SignaturePath: signPrepared(t, prepared, releaseTestKey, raw), PublicKeyPath: keyPath}
		}},
		{"non-Ed25519 key", func(t *testing.T, prepared, keyPath string) FinalizeOptions {
			bad := filepath.Join(t.TempDir(), "rsa.pem")
			_ = os.WriteFile(bad, []byte("-----BEGIN PUBLIC KEY-----\nAAAA\n-----END PUBLIC KEY-----\n"), 0o444)
			return FinalizeOptions{PreparedDir: prepared, SignaturePath: signPrepared(t, prepared, releaseTestKey, raw), PublicKeyPath: bad}
		}},
		{"mutable latest URL", func(t *testing.T, prepared, keyPath string) FinalizeOptions {
			return FinalizeOptions{PreparedDir: prepared, SignaturePath: signPrepared(t, prepared, releaseTestKey, raw), PublicKeyPath: keyPath,
				DownloadBaseURL: "https://auth.cdnca.com/downloads/edge-agent/latest"}
		}},
		{"plain HTTP URL", func(t *testing.T, prepared, keyPath string) FinalizeOptions {
			return FinalizeOptions{PreparedDir: prepared, SignaturePath: signPrepared(t, prepared, releaseTestKey, raw), PublicKeyPath: keyPath,
				DownloadBaseURL: "http://auth.cdnca.com/downloads"}
		}},
	} {
		t.Run(test.name, func(t *testing.T) {
			prepared, keyPath := prepareFixture(t)
			if _, err := FinalizeReleaseBundle(test.mutate(t, prepared, keyPath)); !errors.Is(err, ErrReleaseInput) {
				t.Fatalf("finalize error = %v", err)
			}
			matches, _ := filepath.Glob(filepath.Join(prepared, "*.bundle"))
			if len(matches) != 0 {
				t.Fatalf("rejected finalize left a bundle: %v", matches)
			}
		})
	}
}

func TestFinalizeReleaseBundleAcceptsBase64AndRefusesRerun(t *testing.T) {
	prepared, keyPath := prepareFixture(t)
	options := FinalizeOptions{PreparedDir: prepared, PublicKeyPath: keyPath,
		SignaturePath: signPrepared(t, prepared, releaseTestKey, func(s []byte) []byte {
			return []byte(base64.StdEncoding.EncodeToString(s) + "\n")
		})}
	facts, err := FinalizeReleaseBundle(options)
	if err != nil || facts.SHA256 != goldenReleaseBundleSHA256 {
		t.Fatalf("base64 signature: %+v, %v", facts, err)
	}
	if _, err := FinalizeReleaseBundle(options); !errors.Is(err, ErrReleaseInput) {
		t.Fatalf("rerun overwrote outputs: %v", err)
	}
}

func TestPrepareReleaseBundleRejectsInconsistentInputs(t *testing.T) {
	for _, test := range []struct {
		name   string
		arch   string
		mutate func(t *testing.T, release string)
	}{
		{"provenance digest", "amd64", func(t *testing.T, release string) {
			rewriteProvenance(t, release, func(value map[string]any) { value["artifact"].(map[string]any)["sha256"] = strings.Repeat("0", 64) })
		}},
		{"provenance architecture", "amd64", func(t *testing.T, release string) {
			rewriteProvenance(t, release, func(value map[string]any) { value["arch"] = "arm64" })
		}},
		{"development version", "amd64", func(t *testing.T, release string) {
			rewriteProvenance(t, release, func(value map[string]any) { value["version"] = "development" })
		}},
		{"plain HTTP repository", "amd64", func(t *testing.T, release string) {
			rewriteProvenance(t, release, func(value map[string]any) { value["source_repository"] = "http://example.invalid/cdnca.git" })
		}},
		{"invalid SBOM", "amd64", func(t *testing.T, release string) {
			path := filepath.Join(release, "edge-agent.spdx.json")
			_ = os.Chmod(path, 0o644)
			_ = os.WriteFile(path, []byte(`{"spdxVersion":"SPDX-2.2"}`), 0o444)
			rewriteProvenance(t, release, func(value map[string]any) {
				data, _ := os.ReadFile(path)
				value["sbom"].(map[string]any)["sha256"] = sha256Hex(data)
			})
		}},
		{"symlinked executable", "amd64", func(t *testing.T, release string) {
			path := filepath.Join(release, "edge-agent")
			_ = os.Rename(path, path+".real")
			_ = os.Symlink(path+".real", path)
		}},
	} {
		t.Run(test.name, func(t *testing.T) {
			release := releaseFixture(t, test.arch)
			test.mutate(t, release)
			output := filepath.Join(t.TempDir(), "prepared")
			if _, err := PrepareReleaseBundle(PrepareOptions{ReleaseDir: release, ReleaseSequence: 25, OutputDir: output}); !errors.Is(err, ErrReleaseInput) {
				t.Fatalf("prepare error = %v", err)
			}
			if _, err := os.Lstat(output); !errors.Is(err, os.ErrNotExist) {
				t.Fatal("rejected prepare created output")
			}
		})
	}
	release := releaseFixture(t, "amd64")
	if _, err := PrepareReleaseBundle(PrepareOptions{ReleaseDir: release, ReleaseSequence: 0, OutputDir: filepath.Join(t.TempDir(), "zero")}); !errors.Is(err, ErrReleaseInput) {
		t.Fatalf("zero sequence: %v", err)
	}
	existing := t.TempDir()
	if _, err := PrepareReleaseBundle(PrepareOptions{ReleaseDir: release, ReleaseSequence: 1, OutputDir: existing}); !errors.Is(err, ErrReleaseInput) {
		t.Fatalf("existing output: %v", err)
	}
	arm := releaseFixture(t, "arm64")
	rewriteProvenance(t, arm, func(value map[string]any) { value["arch"] = "amd64" })
	if _, err := PrepareReleaseBundle(PrepareOptions{ReleaseDir: arm, ReleaseSequence: 1, OutputDir: filepath.Join(t.TempDir(), "arch")}); !errors.Is(err, ErrReleaseInput) {
		t.Fatalf("arm64 ELF declared amd64: %v", err)
	}
}

func rewriteProvenance(t *testing.T, release string, mutate func(map[string]any)) {
	t.Helper()
	path := filepath.Join(release, "edge-agent.provenance.json")
	data, err := os.ReadFile(path)
	if err != nil {
		t.Fatal(err)
	}
	var value map[string]any
	if err := json.Unmarshal(data, &value); err != nil {
		t.Fatal(err)
	}
	mutate(value)
	data, _ = json.Marshal(value)
	_ = os.Chmod(path, 0o644)
	if err := os.WriteFile(path, data, 0o444); err != nil {
		t.Fatal(err)
	}
}
