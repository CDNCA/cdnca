package main

import (
	"bytes"
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"
	"fmt"
	"io"
	"io/fs"
	"os"
	"path/filepath"
	"sort"
	"strings"
)

const (
	manifestSchemaVersion = "cdnca.runtime-wiring-audit-manifest/v1"
	sourceManifestKind    = "audited-source"
	toolManifestKind      = "audit-tool-source"
	manifestHashRule      = "for each C-sorted path: path + NUL + content bytes + NUL"
)

type fileManifestEntry struct {
	Path   string `json:"path"`
	SHA256 string `json:"sha256"`
}

type fileManifest struct {
	SchemaVersion       string              `json:"schema_version"`
	Kind                string              `json:"kind"`
	HashAlgorithm       string              `json:"hash_algorithm"`
	TotalHashDefinition string              `json:"total_hash_definition"`
	TotalSHA256         string              `json:"total_sha256"`
	Entries             []fileManifestEntry `json:"entries"`
}

func newFileManifest(kind string, paths []string, contents map[string][]byte) fileManifest {
	paths = append([]string(nil), paths...)
	sort.Strings(paths)
	hasher := sha256.New()
	manifest := fileManifest{
		SchemaVersion:       manifestSchemaVersion,
		Kind:                kind,
		HashAlgorithm:       "sha256",
		TotalHashDefinition: manifestHashRule,
	}
	for _, path := range paths {
		content := contents[path]
		sum := sha256.Sum256(content)
		manifest.Entries = append(manifest.Entries, fileManifestEntry{Path: path, SHA256: hex.EncodeToString(sum[:])})
		hasher.Write([]byte(path))
		hasher.Write([]byte{0})
		hasher.Write(content)
		hasher.Write([]byte{0})
	}
	manifest.TotalSHA256 = hex.EncodeToString(hasher.Sum(nil))
	return manifest
}

func encodeFileManifest(manifest fileManifest) ([]byte, error) {
	encoded, err := json.MarshalIndent(manifest, "", "  ")
	if err != nil {
		return nil, err
	}
	return append(encoded, '\n'), nil
}

func manifestBytesSHA256(content []byte) string {
	sum := sha256.Sum256(content)
	return hex.EncodeToString(sum[:])
}

func verifySourceManifest(root, manifestPath string) error {
	content, err := os.ReadFile(manifestPath)
	if err != nil {
		return fmt.Errorf("source manifest stale: read manifest: %w", err)
	}
	decoder := json.NewDecoder(bytes.NewReader(content))
	decoder.DisallowUnknownFields()
	var expected fileManifest
	if err := decoder.Decode(&expected); err != nil {
		return fmt.Errorf("source manifest stale: decode manifest: %w", err)
	}
	if err := ensureJSONEOF(decoder); err != nil {
		return fmt.Errorf("source manifest stale: decode manifest: %w", err)
	}
	if err := validateFileManifest(expected, sourceManifestKind); err != nil {
		return fmt.Errorf("source manifest stale: %w", err)
	}
	canonical, err := encodeFileManifest(expected)
	if err != nil || !bytes.Equal(content, canonical) {
		return fmt.Errorf("source manifest stale: manifest JSON is not canonical")
	}
	current, err := buildSourceIndex(root)
	if err != nil {
		return fmt.Errorf("source manifest stale: %w", err)
	}
	actual, err := encodeFileManifest(current.Manifest)
	if err != nil {
		return fmt.Errorf("source manifest stale: encode current manifest: %w", err)
	}
	if !bytes.Equal(canonical, actual) {
		return fmt.Errorf("source manifest stale: audited paths or bytes changed")
	}
	return nil
}

func ensureJSONEOF(decoder *json.Decoder) error {
	var extra any
	if err := decoder.Decode(&extra); err != io.EOF {
		if err == nil {
			return fmt.Errorf("multiple JSON values")
		}
		return err
	}
	return nil
}

func validateFileManifest(manifest fileManifest, kind string) error {
	if manifest.SchemaVersion != manifestSchemaVersion || manifest.Kind != kind ||
		manifest.HashAlgorithm != "sha256" || manifest.TotalHashDefinition != manifestHashRule ||
		!validSHA256(manifest.TotalSHA256) {
		return fmt.Errorf("invalid manifest metadata")
	}
	previous := ""
	for index, entry := range manifest.Entries {
		if !canonicalRelativePath(entry.Path) || !validSHA256(entry.SHA256) {
			return fmt.Errorf("invalid manifest entry %q", entry.Path)
		}
		if index > 0 && previous >= entry.Path {
			return fmt.Errorf("manifest paths are not unique C-sort order")
		}
		previous = entry.Path
	}
	return nil
}

func validSHA256(value string) bool {
	decoded, err := hex.DecodeString(value)
	return err == nil && len(decoded) == sha256.Size && value == strings.ToLower(value)
}

func canonicalRelativePath(value string) bool {
	if value == "" || filepath.IsAbs(value) || strings.Contains(value, `\`) || filepath.ToSlash(filepath.Clean(value)) != value {
		return false
	}
	return value != "." && value != ".." && !strings.HasPrefix(value, "../")
}

func rejectSymlinkComponents(root, candidate string) error {
	relative, err := filepath.Rel(root, candidate)
	if err != nil || filepath.IsAbs(relative) || relative == ".." || strings.HasPrefix(relative, ".."+string(filepath.Separator)) {
		return fmt.Errorf("path escapes root")
	}
	cursor := root
	for _, component := range strings.Split(relative, string(filepath.Separator)) {
		cursor = filepath.Join(cursor, component)
		info, err := os.Lstat(cursor)
		if err != nil {
			return err
		}
		if info.Mode()&os.ModeSymlink != 0 {
			return fmt.Errorf("symlink rejected: %s", filepath.ToSlash(relative))
		}
	}
	return nil
}

func buildToolSourceManifest(root string) (fileManifest, error) {
	paths := []string{}
	contents := map[string][]byte{}
	for _, directory := range []string{"tools/runtime-wiring-audit", "tests/runtime-wiring-audit"} {
		base := filepath.Join(root, filepath.FromSlash(directory))
		if err := filepath.WalkDir(base, func(path string, entry fs.DirEntry, walkErr error) error {
			if walkErr != nil {
				return walkErr
			}
			relative, err := filepath.Rel(root, path)
			if err != nil {
				return err
			}
			relative = filepath.ToSlash(relative)
			if entry.Type()&os.ModeSymlink != 0 {
				return fmt.Errorf("audit tool source symlink rejected: %s", relative)
			}
			if entry.IsDir() {
				return nil
			}
			if !entry.Type().IsRegular() {
				return fmt.Errorf("audit tool source is not regular: %s", relative)
			}
			content, err := os.ReadFile(path)
			if err != nil {
				return err
			}
			paths = append(paths, relative)
			contents[relative] = content
			return nil
		}); err != nil {
			return fileManifest{}, fmt.Errorf("walk %s: %w", directory, err)
		}
	}
	for _, relative := range []string{"scripts/runtime-wiring-audit.sh", "docs/runbooks/runtime-wiring-audit.md"} {
		path := filepath.Join(root, filepath.FromSlash(relative))
		info, err := os.Lstat(path)
		if err != nil {
			return fileManifest{}, fmt.Errorf("inspect %s: %w", relative, err)
		}
		if info.Mode()&os.ModeSymlink != 0 || !info.Mode().IsRegular() {
			return fileManifest{}, fmt.Errorf("audit tool source is not a regular non-symlink: %s", relative)
		}
		content, err := os.ReadFile(path)
		if err != nil {
			return fileManifest{}, fmt.Errorf("read %s: %w", relative, err)
		}
		paths = append(paths, relative)
		contents[relative] = content
	}
	return newFileManifest(toolManifestKind, paths, contents), nil
}
