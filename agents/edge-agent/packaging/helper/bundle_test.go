package helper

import (
	"bytes"
	"crypto/sha256"
	"encoding/binary"
	"encoding/hex"
	"errors"
	"os"
	"path/filepath"
	"testing"
)

const goldenBundleSHA256 = "60dc410c77a1b71b3e877e3bdb0bf0a3cd48a0bcb028fa56636912dee7ae13b2"

func TestStageReleaseBundleGoldenVector(t *testing.T) {
	sections := [][]byte{
		[]byte("manifest_version=2\n"),
		bytes.Repeat([]byte{0x5a}, 64),
		[]byte(`{"spdxVersion":"SPDX-2.3"}`),
		[]byte{0x7f, 'E', 'L', 'F', 1, 2, 3, 4},
	}
	bundle := testBundle(sections...)
	digest := sha256.Sum256(bundle)
	if got := hex.EncodeToString(digest[:]); got != goldenBundleSHA256 {
		t.Fatalf("golden bundle SHA-256 drifted: got %s", got)
	}

	artifact := openTestArtifact(t, bundle, os.O_RDONLY)
	staging := testStagingDirectory(t)
	got, err := StageReleaseBundle(artifact, staging, int64(len(bundle)), goldenBundleSHA256)
	if err != nil {
		t.Fatalf("stage bundle: %v", err)
	}
	if got.OuterSHA256 != goldenBundleSHA256 || got.ManifestSize != int64(len(sections[0])) || got.SBOMSize != int64(len(sections[2])) || got.ExecutableSize != int64(len(sections[3])) {
		t.Fatalf("unexpected staged facts: %+v", got)
	}

	paths := []string{got.ManifestPath, got.SignaturePath, got.SBOMPath, got.ExecutablePath}
	modes := []os.FileMode{0400, 0400, 0400, 0500}
	for index, path := range paths {
		content, err := os.ReadFile(path)
		if err != nil {
			t.Fatalf("read section %d: %v", index, err)
		}
		if !bytes.Equal(content, sections[index]) {
			t.Fatalf("section %d differs", index)
		}
		info, err := os.Stat(path)
		if err != nil || info.Mode().Perm() != modes[index] {
			t.Fatalf("section %d mode: %v, %v", index, info, err)
		}
	}
}

func TestStageReleaseBundleRejectsMalformedInputs(t *testing.T) {
	validSections := [][]byte{[]byte("m"), bytes.Repeat([]byte{1}, 64), []byte("s"), []byte("e")}
	validBundle := testBundle(validSections...)
	validDigest := sha256.Sum256(validBundle)

	tests := []struct {
		name   string
		bundle []byte
		size   int64
		digest string
		want   error
	}{
		{name: "bad magic", bundle: append([]byte("X"), validBundle[1:]...), size: int64(len(validBundle)), digest: hex.EncodeToString(validDigest[:]), want: ErrInvalidBundle},
		{name: "short section", bundle: validBundle[:len(validBundle)-1], size: int64(len(validBundle) - 1), digest: digestOf(validBundle[:len(validBundle)-1]), want: ErrInvalidBundle},
		{name: "trailing byte", bundle: append(append([]byte(nil), validBundle...), 0), size: int64(len(validBundle) + 1), digest: digestOf(append(append([]byte(nil), validBundle...), 0)), want: ErrInvalidBundle},
		{name: "outer digest", bundle: validBundle, size: int64(len(validBundle)), digest: string(bytes.Repeat([]byte{'0'}, 64)), want: ErrArtifactMismatch},
		{name: "outer size", bundle: validBundle, size: int64(len(validBundle) - 1), digest: hex.EncodeToString(validDigest[:]), want: ErrUnsafeArtifactFD},
	}
	for _, test := range tests {
		t.Run(test.name, func(t *testing.T) {
			artifact := openTestArtifact(t, test.bundle, os.O_RDONLY)
			staging := testStagingDirectory(t)
			_, err := StageReleaseBundle(artifact, staging, test.size, test.digest)
			if !errors.Is(err, test.want) {
				t.Fatalf("got %v, want %v", err, test.want)
			}
			entries, readErr := os.ReadDir(staging)
			if readErr != nil || len(entries) != 0 {
				t.Fatalf("failed parse left staging content: %v, %v", entries, readErr)
			}
		})
	}
}

func TestStageReleaseBundleRejectsUnsafeDescriptorAndLengths(t *testing.T) {
	sections := [][]byte{[]byte("m"), bytes.Repeat([]byte{1}, 64), []byte("s"), []byte("e")}
	bundle := testBundle(sections...)

	t.Run("writable descriptor", func(t *testing.T) {
		artifact := openTestArtifact(t, bundle, os.O_RDWR)
		_, err := StageReleaseBundle(artifact, testStagingDirectory(t), int64(len(bundle)), digestOf(bundle))
		if !errors.Is(err, ErrUnsafeArtifactFD) {
			t.Fatalf("got %v", err)
		}
	})

	t.Run("hard linked descriptor", func(t *testing.T) {
		directory := t.TempDir()
		path := filepath.Join(directory, "artifact")
		if err := os.WriteFile(path, bundle, 0600); err != nil {
			t.Fatal(err)
		}
		if err := os.Link(path, filepath.Join(directory, "second-link")); err != nil {
			t.Fatal(err)
		}
		artifact, err := os.Open(path)
		if err != nil {
			t.Fatal(err)
		}
		defer artifact.Close()
		_, err = StageReleaseBundle(artifact, testStagingDirectory(t), int64(len(bundle)), digestOf(bundle))
		if !errors.Is(err, ErrUnsafeArtifactFD) {
			t.Fatalf("got %v", err)
		}
	})

	t.Run("oversize manifest", func(t *testing.T) {
		var input bytes.Buffer
		input.WriteString(BundleMagic)
		_ = binary.Write(&input, binary.BigEndian, uint64(MaxManifestBytes+1))
		artifact := openTestArtifact(t, input.Bytes(), os.O_RDONLY)
		_, err := StageReleaseBundle(artifact, testStagingDirectory(t), int64(input.Len()), digestOf(input.Bytes()))
		if !errors.Is(err, ErrInvalidBundle) {
			t.Fatalf("got %v", err)
		}
	})
}

func testBundle(sections ...[]byte) []byte {
	var result bytes.Buffer
	result.WriteString(BundleMagic)
	for _, section := range sections {
		_ = binary.Write(&result, binary.BigEndian, uint64(len(section)))
		result.Write(section)
	}
	return result.Bytes()
}

func digestOf(value []byte) string {
	digest := sha256.Sum256(value)
	return hex.EncodeToString(digest[:])
}

func openTestArtifact(t *testing.T, content []byte, flags int) *os.File {
	t.Helper()
	path := filepath.Join(t.TempDir(), "artifact")
	if err := os.WriteFile(path, content, 0600); err != nil {
		t.Fatal(err)
	}
	file, err := os.OpenFile(path, flags, 0)
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { _ = file.Close() })
	return file
}

func testStagingDirectory(t *testing.T) string {
	t.Helper()
	path := filepath.Join(t.TempDir(), "staging")
	if err := os.Mkdir(path, 0700); err != nil {
		t.Fatal(err)
	}
	return path
}
