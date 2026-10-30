package edgeconfig

import (
	"bytes"
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"path/filepath"
	"sort"
	"strings"
)

const ConfigurationBundleMediaType = "application/vnd.cdnca.edge-configuration-bundle+json;version=1"

// MaxSiteRuntimeDocumentBytes bounds the site runtime v2 document a node
// compiles (site-runtime.v2.json, one bundle file) and therefore what control
// compiles for it (edgepublish, edgedeployment, the v2 compile input CHECK of
// migration 354). The v8 root index (siteobject.MaxRootIndexBytes) shares the
// same one-document bound. ADR 0009 §8.3.
const MaxSiteRuntimeDocumentBytes = MaxConfigurationBundleFileBytes

const (
	MaxConfigurationBundleFiles        = 4096
	MaxConfigurationBundleFileBytes    = 16 << 20
	MaxConfigurationBundleContentBytes = 128 << 20
	MaxConfigurationBundleWireBytes    = 4 << 20
)

const (
	bundleDocumentVersion = 1
	releaseManifestFile   = ".release-manifest.json"
)

var (
	ErrInvalidBundle   = errors.New("invalid configuration bundle")
	ErrInvalidManifest = errors.New("invalid configuration manifest")
	ErrInvalidPath     = errors.New("invalid configuration path")
)

type FileManifest struct {
	Path   string `json:"path"`
	Size   int64  `json:"size"`
	SHA256 string `json:"sha256"`
}

type Manifest struct {
	Files []FileManifest `json:"files"`
}

type Bundle struct {
	Manifest       Manifest
	ManifestSHA256 string
	Files          map[string][]byte
}

// BundleDocument is the stable version-one wire representation.
type BundleDocument struct {
	Version        int               `json:"version"`
	Manifest       Manifest          `json:"manifest"`
	ManifestSHA256 string            `json:"manifest_sha256"`
	Files          map[string][]byte `json:"files"`
}

func newBundle(files map[string][]byte) (Bundle, error) {
	if len(files) == 0 || len(files) > MaxConfigurationBundleFiles {
		return Bundle{}, fmt.Errorf("%w: file count exceeds limit", ErrInvalidBundle)
	}
	manifestFiles := make([]FileManifest, 0, len(files))
	var total int64
	for path, content := range files {
		size := int64(len(content))
		if size > MaxConfigurationBundleFileBytes || size > MaxConfigurationBundleContentBytes-total {
			return Bundle{}, fmt.Errorf("%w: file content exceeds limit", ErrInvalidBundle)
		}
		total += size
		digest := sha256.Sum256(content)
		manifestFiles = append(manifestFiles, FileManifest{
			Path: path, Size: int64(len(content)), SHA256: hex.EncodeToString(digest[:]),
		})
	}
	sort.Slice(manifestFiles, func(i, j int) bool { return manifestFiles[i].Path < manifestFiles[j].Path })
	manifest := Manifest{Files: manifestFiles}
	digest, err := ManifestDigest(manifest)
	if err != nil {
		return Bundle{}, err
	}
	return Bundle{Manifest: manifest, ManifestSHA256: digest, Files: files}, nil
}

// NewBundle builds and validates a bundle from release files without the
// wire size bound of MarshalBundle: site runtime v8 delivers a release as
// site objects (libs/edgeconfig/siteobject), never as one wire document.
func NewBundle(files map[string][]byte) (Bundle, error) {
	bundle, err := newBundle(files)
	if err != nil {
		return Bundle{}, err
	}
	if err := ValidateBundle(bundle); err != nil {
		return Bundle{}, err
	}
	return bundle, nil
}

func ManifestDigest(manifest Manifest) (string, error) {
	normalized, err := normalizeManifest(manifest)
	if err != nil {
		return "", err
	}
	content, err := json.Marshal(normalized)
	if err != nil {
		return "", fmt.Errorf("%w: marshal manifest: %v", ErrInvalidManifest, err)
	}
	digest := sha256.Sum256(content)
	return hex.EncodeToString(digest[:]), nil
}

func NormalizeManifest(manifest Manifest) (Manifest, error) {
	return normalizeManifest(manifest)
}

func MarshalBundle(bundle Bundle) ([]byte, error) {
	manifest, err := normalizeManifest(bundle.Manifest)
	if err != nil {
		return nil, err
	}
	digest, err := ManifestDigest(manifest)
	if err != nil {
		return nil, err
	}
	if bundle.ManifestSHA256 != digest || len(bundle.Files) == 0 {
		return nil, fmt.Errorf("%w: manifest digest or files are incomplete", ErrInvalidBundle)
	}
	if err := validateBundleFiles(manifest, bundle.Files); err != nil {
		return nil, err
	}
	if err := ValidateBundle(Bundle{Manifest: manifest, ManifestSHA256: digest, Files: bundle.Files}); err != nil {
		return nil, err
	}
	content, err := json.Marshal(BundleDocument{
		Version: bundleDocumentVersion, Manifest: manifest,
		ManifestSHA256: digest, Files: bundle.Files,
	})
	if err != nil {
		return nil, fmt.Errorf("%w: marshal document: %v", ErrInvalidBundle, err)
	}
	if len(content) > MaxConfigurationBundleWireBytes {
		return nil, fmt.Errorf("%w: document exceeds wire limit", ErrInvalidBundle)
	}
	return content, nil
}

func validateBundleFiles(manifest Manifest, files map[string][]byte) error {
	if len(files) != len(manifest.Files) {
		return fmt.Errorf("%w: files are not fully described by the manifest", ErrInvalidBundle)
	}
	for _, entry := range manifest.Files {
		content, exists := files[entry.Path]
		if !exists || int64(len(content)) != entry.Size {
			return fmt.Errorf("%w: file %q does not match its manifest", ErrInvalidBundle, entry.Path)
		}
		fileDigest := sha256.Sum256(content)
		if hex.EncodeToString(fileDigest[:]) != entry.SHA256 {
			return fmt.Errorf("%w: file %q digest does not match", ErrInvalidBundle, entry.Path)
		}
	}
	return nil
}

func UnmarshalBundle(content []byte) (Bundle, error) {
	if len(content) == 0 || len(content) > MaxConfigurationBundleWireBytes {
		return Bundle{}, fmt.Errorf("%w: document size is invalid", ErrInvalidBundle)
	}
	if err := RejectDuplicateJSONKeys(content); err != nil {
		return Bundle{}, fmt.Errorf("%w: JSON is invalid: %v", ErrInvalidBundle, err)
	}
	decoder := json.NewDecoder(bytes.NewReader(content))
	decoder.DisallowUnknownFields()
	var document BundleDocument
	if err := decoder.Decode(&document); err != nil || decoder.Decode(&struct{}{}) != io.EOF {
		return Bundle{}, fmt.Errorf("%w: JSON is invalid", ErrInvalidBundle)
	}
	if document.Version != bundleDocumentVersion || len(document.Files) == 0 || document.ManifestSHA256 == "" {
		return Bundle{}, fmt.Errorf("%w: document is incomplete", ErrInvalidBundle)
	}
	manifest, err := normalizeManifest(document.Manifest)
	if err != nil {
		return Bundle{}, fmt.Errorf("%w: manifest is invalid", ErrInvalidBundle)
	}
	digest, err := ManifestDigest(manifest)
	if err != nil || digest != document.ManifestSHA256 {
		return Bundle{}, fmt.Errorf("%w: manifest digest mismatch", ErrInvalidBundle)
	}
	if err := validateBundleFiles(manifest, document.Files); err != nil {
		return Bundle{}, err
	}
	bundle := Bundle{
		Manifest: manifest, ManifestSHA256: document.ManifestSHA256, Files: document.Files,
	}
	if err := ValidateBundle(bundle); err != nil {
		return Bundle{}, err
	}
	return bundle, nil
}

// RejectDuplicateJSONKeys is exported only for the Edge compatibility shim.
func RejectDuplicateJSONKeys(content []byte) error {
	decoder := json.NewDecoder(bytes.NewReader(content))
	decoder.UseNumber()
	if err := validateJSONValue(decoder); err != nil {
		return err
	}
	if _, err := decoder.Token(); err != io.EOF {
		return fmt.Errorf("trailing JSON token")
	}
	return nil
}

func normalizeManifest(manifest Manifest) (Manifest, error) {
	if len(manifest.Files) == 0 || len(manifest.Files) > MaxConfigurationBundleFiles {
		return Manifest{}, fmt.Errorf("%w: empty manifest", ErrInvalidManifest)
	}
	files := append([]FileManifest(nil), manifest.Files...)
	sort.Slice(files, func(i, j int) bool { return files[i].Path < files[j].Path })
	seen := make(map[string]struct{}, len(files))
	var total int64
	for index := range files {
		entry := &files[index]
		if err := validateRelativePath(entry.Path); err != nil {
			return Manifest{}, err
		}
		if entry.Path == releaseManifestFile {
			return Manifest{}, fmt.Errorf("%w: reserved release path", ErrInvalidPath)
		}
		if _, exists := seen[entry.Path]; exists {
			return Manifest{}, fmt.Errorf("%w: duplicate path", ErrInvalidManifest)
		}
		seen[entry.Path] = struct{}{}
		if entry.Size < 0 || entry.Size > MaxConfigurationBundleFileBytes ||
			entry.Size > MaxConfigurationBundleContentBytes-total || !validSHA256(entry.SHA256) {
			return Manifest{}, fmt.Errorf("%w: invalid file metadata", ErrInvalidManifest)
		}
		total += entry.Size
		entry.SHA256 = strings.ToLower(entry.SHA256)
	}
	return Manifest{Files: files}, nil
}

func validateRelativePath(path string) error {
	if path == "" || filepath.IsAbs(path) || strings.ContainsRune(path, '\x00') || strings.Contains(path, `\`) {
		return fmt.Errorf("%w: unsafe relative path", ErrInvalidPath)
	}
	clean := filepath.Clean(path)
	if clean != path || clean == "." || clean == ".." || strings.HasPrefix(clean, ".."+string(filepath.Separator)) {
		return fmt.Errorf("%w: unsafe relative path", ErrInvalidPath)
	}
	for _, part := range strings.Split(path, string(filepath.Separator)) {
		if part == "" || part == "." || part == ".." {
			return fmt.Errorf("%w: unsafe relative path", ErrInvalidPath)
		}
	}
	return nil
}

func validSHA256(value string) bool {
	if len(value) != sha256.Size*2 {
		return false
	}
	decoded, err := hex.DecodeString(value)
	return err == nil && len(decoded) == sha256.Size
}

func validateJSONValue(decoder *json.Decoder) error {
	token, err := decoder.Token()
	if err != nil {
		return err
	}
	delimiter, isDelimiter := token.(json.Delim)
	if !isDelimiter {
		return nil
	}
	switch delimiter {
	case '{':
		keys := make(map[string]struct{})
		for decoder.More() {
			keyToken, err := decoder.Token()
			if err != nil {
				return err
			}
			key, ok := keyToken.(string)
			if !ok {
				return fmt.Errorf("object key is not a string")
			}
			if _, exists := keys[key]; exists {
				return fmt.Errorf("duplicate object key")
			}
			keys[key] = struct{}{}
			if err := validateJSONValue(decoder); err != nil {
				return err
			}
		}
		closing, err := decoder.Token()
		if err != nil || closing != json.Delim('}') {
			return fmt.Errorf("object is not closed")
		}
	case '[':
		for decoder.More() {
			if err := validateJSONValue(decoder); err != nil {
				return err
			}
		}
		closing, err := decoder.Token()
		if err != nil || closing != json.Delim(']') {
			return fmt.Errorf("array is not closed")
		}
	default:
		return fmt.Errorf("unexpected JSON delimiter")
	}
	return nil
}
