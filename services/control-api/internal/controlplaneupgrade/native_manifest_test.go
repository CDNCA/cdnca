package controlplaneupgrade

import (
	"archive/tar"
	"bytes"
	"crypto/sha256"
	"encoding/json"
	"fmt"
	"os"
	"path/filepath"
	"sort"
	"strings"
	"testing"
)

func TestNativeManifestVersionContract(t *testing.T) {
	for _, test := range []struct {
		version string
		valid   bool
	}{
		{"0.0.0", true},
		{"1.2.3", true},
		{"2026.10.8", true},
		{"999999999.999999999.999999999", true},
		{"0.123456789.0", true},
		{"", false},
		{"1", false},
		{"1.2", false},
		{"1.2.3.4", false},
		{"v1.2.3", false},
		{"1.2.3-rc.1", false},
		{"1.2.3-alpha", false},
		{"1.2.3+build.1", false},
		{"1.2.3-rc.1+build.1", false},
		{"1000000000.0.0", false},
		{"0.1000000000.0", false},
		{"0.0.1000000000", false},
		{"00.0.0", false},
		{"01.2.3", false},
		{"1.02.3", false},
		{"1.2.03", false},
		{"-1.2.3", false},
		{"+1.2.3", false},
		{"1.2.３", false},
		{" 1.2.3", false},
		{"1.2.3 ", false},
		{"1.2.3\n", false},
	} {
		t.Run(test.version, func(t *testing.T) {
			manifest, files := nativeManifestFixture()
			manifest.Version = test.version
			filename, artifact := nativeArchiveFixture(t, manifest, files, nil)
			artifact.Version = test.version
			_, err := ValidateNativeReleaseArchive(filename, artifact, manifest.Platform)
			if got := err == nil; got != test.valid {
				t.Errorf("archive version %q valid=%v, want %v (err=%v)", test.version, got, test.valid, err)
			}
			if got := nativeVersion(test.version); got != test.valid {
				t.Errorf("native version %q valid=%v, want %v", test.version, got, test.valid)
			}
		})
	}
}

func TestNativeManifestRequiresCompleteExactSignedArchive(t *testing.T) {
	manifest, files := nativeManifestFixture()
	file, artifact := nativeArchiveFixture(t, manifest, files, nil)
	got, err := ValidateNativeReleaseArchive(file, artifact, NativePlatform{OS: "linux", Arch: "amd64"})
	if err != nil || got.Source.Commit != manifest.Source.Commit || len(got.Files) != 4 {
		t.Fatalf("valid complete archive: %+v %v", got, err)
	}
	for _, name := range []string{"missing gateway", "extra file", "file hash", "version", "platform", "path escape", "symlink", "duplicate entry", "raw binary"} {
		t.Run(name, func(t *testing.T) {
			manifest, files := nativeManifestFixture()
			var extra []*tar.Header
			switch name {
			case "missing gateway":
				manifest.Files = manifest.Files[1:]
				delete(files, "bin/agent-gateway")
			case "extra file":
				files["unexpected"] = []byte("not listed")
			case "file hash":
				files["bin/control-api"] = []byte("tampered")
			case "version":
				manifest.Version = "9.0.0"
			case "platform":
				manifest.Platform.Arch = "arm64"
			case "path escape":
				extra = append(extra, &tar.Header{Name: "../escape", Typeflag: tar.TypeReg, Mode: 0o644})
			case "symlink":
				extra = append(extra, &tar.Header{Name: "link", Linkname: "bin/control-api", Typeflag: tar.TypeSymlink, Mode: 0o644})
			case "duplicate entry":
				extra = append(extra, &tar.Header{Name: "bin/control-api", Typeflag: tar.TypeReg, Mode: 0o755})
			}
			file, artifact := nativeArchiveFixture(t, manifest, files, extra)
			artifact.Version = "2026.10.8"
			if name == "raw binary" {
				if err := os.WriteFile(file, []byte("ELF legacy binary"), 0o600); err != nil {
					t.Fatal(err)
				}
				artifact.Digest, artifact.Size = digestBytes([]byte("ELF legacy binary")), int64(len("ELF legacy binary"))
			}
			if _, err := ValidateNativeReleaseArchive(file, artifact, NativePlatform{OS: "linux", Arch: "amd64"}); err == nil {
				t.Fatal("unsafe native archive accepted")
			}
		})
	}
}

func nativeManifestFixture() (NativeManifest, map[string][]byte) {
	files := map[string][]byte{"bin/control-api": []byte("control"), "bin/agent-gateway": []byte("gateway"),
		"static/web/index.html": []byte("<html>new</html>"), "migrations/001.up.sql": []byte("SELECT 1;")}
	manifest := NativeManifest{Schema: NativeManifestSchema, Version: "2026.10.8", BuiltAt: "2026-10-08T01:00:00Z",
		Source:   NativeSource{Commit: strings.Repeat("a", 40), Tree: strings.Repeat("b", 40), PreviousCommit: strings.Repeat("c", 40)},
		Platform: NativePlatform{OS: "linux", Arch: "amd64"}}
	for path, content := range files {
		mode := uint32(0o644)
		if strings.HasPrefix(path, "bin/") {
			mode = 0o755
		}
		manifest.Files = append(manifest.Files, NativeFile{Path: path, SHA256: fmt.Sprintf("%x", sha256.Sum256(content)), Bytes: int64(len(content)), Mode: mode})
	}
	sort.Slice(manifest.Files, func(i, j int) bool { return manifest.Files[i].Path < manifest.Files[j].Path })
	return manifest, files
}

func nativeArchiveFixture(t *testing.T, manifest NativeManifest, files map[string][]byte, extra []*tar.Header) (string, Artifact) {
	t.Helper()
	var out bytes.Buffer
	writer := tar.NewWriter(&out)
	encoded, err := json.Marshal(manifest)
	if err != nil {
		t.Fatal(err)
	}
	write := func(path string, data []byte, mode int64) {
		if err := writer.WriteHeader(&tar.Header{Name: path, Typeflag: tar.TypeReg, Mode: mode, Size: int64(len(data))}); err != nil {
			t.Fatal(err)
		}
		if _, err := writer.Write(data); err != nil {
			t.Fatal(err)
		}
	}
	write(NativeManifestFilename, encoded, 0o644)
	for path, data := range files {
		mode := int64(0o644)
		if strings.HasPrefix(path, "bin/") {
			mode = 0o755
		}
		write(path, data, mode)
	}
	for _, header := range extra {
		if err := writer.WriteHeader(header); err != nil {
			t.Fatal(err)
		}
	}
	if err := writer.Close(); err != nil {
		t.Fatal(err)
	}
	file := filepath.Join(t.TempDir(), "release.tar")
	if err := os.WriteFile(file, out.Bytes(), 0o600); err != nil {
		t.Fatal(err)
	}
	return file, Artifact{Version: "2026.10.8", Digest: digestBytes(out.Bytes()), Size: int64(out.Len()), URL: "https://release.invalid/full.tar"}
}

func TestNativeManifestInitialBaselineHasNoPredecessor(t *testing.T) {
	baseline, files := nativeManifestFixture()
	baseline.Source.PreviousCommit = ""
	filename, artifact := nativeArchiveFixture(t, baseline, files, nil)
	if _, err := ValidateNativeReleaseArchive(filename, artifact, baseline.Platform); err != nil {
		t.Fatalf("initial baseline without previous_commit rejected: %v", err)
	}
	for _, previous := range []string{"HEAD", strings.Repeat("A", 40), baseline.Source.Commit} {
		manifest, files := nativeManifestFixture()
		manifest.Source.PreviousCommit = previous
		filename, artifact := nativeArchiveFixture(t, manifest, files, nil)
		if _, err := ValidateNativeReleaseArchive(filename, artifact, manifest.Platform); err == nil {
			t.Errorf("previous_commit %q accepted", previous)
		}
	}
	// An upgrade candidate on top of the baseline must still name the running commit.
	candidate := baseline
	candidate.Version, candidate.Source = "2026.10.9", NativeSource{Commit: strings.Repeat("d", 40), Tree: strings.Repeat("e", 40)}
	if reason := nativeLineageReason(baseline, candidate); reason != "previous_commit_mismatch" {
		t.Fatalf("predecessor-less candidate reason = %q", reason)
	}
}
