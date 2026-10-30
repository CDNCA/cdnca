package controlplaneupgrade

import (
	"archive/tar"
	"bytes"
	"crypto/ed25519"
	"crypto/sha256"
	"encoding/base64"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"os"
	"path"
	"regexp"
	"strings"
	"time"

	"github.com/cdnca/cdnca/libs/entitlement"
)

const (
	NativeManifestSchema       = "cdnca.native-management.release/v1"
	NativeManifestSignedSchema = "cdnca.native-management.release/v2"
	NativeManifestFilename     = "release.manifest.json"
	NativeSignatureFilename    = "release.manifest.sig"
	nativeArchiveLimit         = 1 << 30
	nativeManifestLimit        = 8 << 20
)

type NativePlatform struct {
	OS   string `json:"os"`
	Arch string `json:"arch"`
}

// PreviousCommit is empty only for the initial baseline release, which has no
// predecessor; an upgrade candidate must still name the running commit (nativeLineageReason).
type NativeSource struct {
	Commit         string `json:"commit"`
	Tree           string `json:"tree"`
	PreviousCommit string `json:"previous_commit,omitempty"`
}

type NativeFile struct {
	Path   string `json:"path"`
	SHA256 string `json:"sha256"`
	Bytes  int64  `json:"bytes"`
	Mode   uint32 `json:"mode"`
}

type NativeManifest struct {
	Schema   string         `json:"schema"`
	KeyID    string         `json:"key_id,omitempty"`
	Version  string         `json:"version"`
	BuiltAt  string         `json:"built_at"`
	Source   NativeSource   `json:"source"`
	Platform NativePlatform `json:"platform"`
	Files    []NativeFile   `json:"files"`
}

var (
	nativeGitObject     = regexp.MustCompile(`^[0-9a-f]{40}$`)
	nativeStableVersion = regexp.MustCompile(`^(0|[1-9][0-9]{0,8})\.(0|[1-9][0-9]{0,8})\.(0|[1-9][0-9]{0,8})$`)
	nativeArtifactKeyID = regexp.MustCompile(`^[A-Za-z0-9._-]{1,128}$`)
)

// ValidateNativeReleaseArchive validates a v1 tar bound by a signed Plan, not a
// legacy control-api binary. Artifact.Digest is the tar digest, never the process hash.
func ValidateNativeReleaseArchive(filename string, artifact Artifact, platform NativePlatform) (NativeManifest, error) {
	manifest, err := validateNativeReleaseArchive(filename, artifact, platform, nil)
	if err == nil && manifest.Schema != NativeManifestSchema {
		return NativeManifest{}, ErrInvalidPlan
	}
	return manifest, err
}

// ValidateSignedNativeReleaseArchive requires v2 provenance signed by an
// independently configured publisher key. Plan authorization remains separate.
func ValidateSignedNativeReleaseArchive(filename string, artifact Artifact, platform NativePlatform, keys map[string]ed25519.PublicKey) (NativeManifest, error) {
	manifest, err := validateNativeReleaseArchive(filename, artifact, platform, keys)
	if err == nil && manifest.Schema != NativeManifestSignedSchema {
		return NativeManifest{}, ErrInvalidPlan
	}
	return manifest, err
}

func validateNativeReleaseArchive(filename string, artifact Artifact, platform NativePlatform, keys map[string]ed25519.PublicKey) (NativeManifest, error) {
	if artifact.Size < 1024 || artifact.Size > nativeArchiveLimit || !digestPattern.MatchString(artifact.Digest) {
		return NativeManifest{}, ErrInvalidPlan
	}
	digest, size, err := digestRegularFile(filename, artifact.Size)
	if err != nil || size != artifact.Size || digest != artifact.Digest {
		return NativeManifest{}, ErrInvalidPlan
	}
	file, err := os.Open(filename)
	if err != nil {
		return NativeManifest{}, err
	}
	defer file.Close()
	reader := tar.NewReader(file)
	actual := make(map[string]NativeFile)
	var manifest NativeManifest
	var encoded, signature []byte
	for {
		header, err := reader.Next()
		if errors.Is(err, io.EOF) {
			break
		}
		if err != nil || len(actual) >= 65537 || !nativeRelativePath(header.Name) || header.Size < 0 ||
			header.Size > nativeArchiveLimit || header.Typeflag != tar.TypeReg ||
			(header.Mode != 0o644 && header.Mode != 0o755) || header.Linkname != "" || len(header.PAXRecords) != 0 {
			return NativeManifest{}, ErrInvalidPlan
		}
		if _, exists := actual[header.Name]; exists {
			return NativeManifest{}, ErrInvalidPlan
		}
		if header.Name == NativeManifestFilename || header.Name == NativeSignatureFilename {
			maximum := int64(nativeManifestLimit)
			if header.Name == NativeSignatureFilename {
				maximum = 128
			}
			if header.Size == 0 || header.Size > maximum || header.Mode != 0o644 {
				return NativeManifest{}, ErrInvalidPlan
			}
			body, err := io.ReadAll(reader)
			if err != nil {
				return NativeManifest{}, ErrInvalidPlan
			}
			if header.Name == NativeManifestFilename {
				encoded = body
				if decodeNativeJSON(encoded, &manifest) != nil {
					return NativeManifest{}, ErrInvalidPlan
				}
			} else {
				signature = body
			}
			actual[header.Name] = NativeFile{}
			continue
		}
		hash := sha256.New()
		copied, err := io.Copy(hash, reader)
		if err != nil || copied != header.Size {
			return NativeManifest{}, ErrInvalidPlan
		}
		actual[header.Name] = NativeFile{Path: header.Name, SHA256: fmt.Sprintf("%x", hash.Sum(nil)), Bytes: copied, Mode: uint32(header.Mode)}
	}
	metadataCount := 1
	if manifest.Schema == NativeManifestSignedSchema {
		metadataCount = 2
	}
	if !validNativeManifest(manifest, platform) || artifact.Version != manifest.Version || len(actual) != len(manifest.Files)+metadataCount {
		return NativeManifest{}, ErrInvalidPlan
	}
	var members map[string]json.RawMessage
	if json.Unmarshal(encoded, &members) != nil {
		return NativeManifest{}, ErrInvalidPlan
	}
	_, hasKeyID := members["key_id"]
	if manifest.Schema == NativeManifestSchema {
		if hasKeyID || signature != nil {
			return NativeManifest{}, ErrInvalidPlan
		}
	} else if !hasKeyID || verifyNativeManifestSignature(manifest, encoded, signature, keys) != nil {
		return NativeManifest{}, ErrInvalidPlan
	}
	for _, expected := range manifest.Files {
		if actual[expected.Path] != expected {
			return NativeManifest{}, ErrInvalidPlan
		}
	}
	// A tar stream must not hide another archive or arbitrary bytes after its EOF.
	trailing := make([]byte, 4096)
	for {
		n, err := file.Read(trailing)
		if !bytes.Equal(trailing[:n], make([]byte, n)) {
			return NativeManifest{}, ErrInvalidPlan
		}
		if errors.Is(err, io.EOF) {
			break
		}
		if err != nil {
			return NativeManifest{}, ErrInvalidPlan
		}
	}
	return manifest, nil
}

func validNativeManifest(manifest NativeManifest, platform NativePlatform) bool {
	if (manifest.Schema != NativeManifestSchema && manifest.Schema != NativeManifestSignedSchema) ||
		(manifest.Schema == NativeManifestSchema && manifest.KeyID != "") ||
		(manifest.Schema == NativeManifestSignedSchema && !nativeArtifactKeyID.MatchString(manifest.KeyID)) || !nativeVersion(manifest.Version) ||
		manifest.Platform != platform || platform.OS != "linux" || (platform.Arch != "amd64" && platform.Arch != "arm64") ||
		!nativeGitObject.MatchString(manifest.Source.Commit) || !nativeGitObject.MatchString(manifest.Source.Tree) ||
		(manifest.Source.PreviousCommit != "" && !nativeGitObject.MatchString(manifest.Source.PreviousCommit)) ||
		manifest.Source.Commit == manifest.Source.PreviousCommit ||
		len(manifest.Files) < 4 || len(manifest.Files) > 65535 {
		return false
	}
	if _, err := time.Parse(time.RFC3339, manifest.BuiltAt); err != nil {
		return false
	}
	required := map[string]bool{"bin/control-api": false, "bin/agent-gateway": false, "static/web/index.html": false}
	migration, previous := false, ""
	for _, file := range manifest.Files {
		if !nativeRelativePath(file.Path) || file.Path == NativeManifestFilename || file.Path == NativeSignatureFilename || file.Path <= previous ||
			!digestPattern.MatchString(file.SHA256) || file.Bytes < 0 || file.Bytes > nativeArchiveLimit ||
			(file.Mode != 0o644 && file.Mode != 0o755) {
			return false
		}
		if _, exists := required[file.Path]; exists {
			if file.Bytes == 0 || (strings.HasPrefix(file.Path, "bin/") && file.Mode != 0o755) {
				return false
			}
			required[file.Path] = true
		}
		migration = migration || strings.HasPrefix(file.Path, "migrations/") && strings.HasSuffix(file.Path, ".sql")
		previous = file.Path
	}
	return required["bin/control-api"] && required["bin/agent-gateway"] && required["static/web/index.html"] && migration
}

func verifyNativeManifestSignature(manifest NativeManifest, encoded, signature []byte, keys map[string]ed25519.PublicKey) error {
	key, found := keys[manifest.KeyID]
	if manifest.Schema != NativeManifestSignedSchema || !found || entitlement.ValidateEd25519PublicKey(key) != nil || len(signature) > 128 {
		return ErrInvalidPlan
	}
	signature = bytes.TrimSuffix(signature, []byte{'\n'})
	decoded, err := base64.StdEncoding.Strict().DecodeString(string(signature))
	if err != nil || len(decoded) != ed25519.SignatureSize || base64.StdEncoding.EncodeToString(decoded) != string(signature) ||
		!ed25519.Verify(key, append([]byte(NativeManifestSignedSchema+"\n"), encoded...), decoded) {
		return ErrInvalidPlan
	}
	return nil
}

func nativeVersion(value string) bool {
	return nativeStableVersion.MatchString(value)
}

func nativeRelativePath(value string) bool {
	return value != "" && len(value) <= 1024 && value != "." && path.Clean(value) == value &&
		!strings.HasPrefix(value, "/") && !strings.HasPrefix(value, "../") && value != ".." &&
		!strings.ContainsAny(value, "\\\x00\r\n")
}

func decodeNativeJSON(encoded []byte, target any) error {
	// Duplicate members are ambiguous across Go, browser and release builders.
	decoder := json.NewDecoder(bytes.NewReader(encoded))
	var readValue func() error
	readValue = func() error {
		token, err := decoder.Token()
		if err != nil {
			return err
		}
		if delimiter, ok := token.(json.Delim); ok {
			if delimiter != '{' && delimiter != '[' {
				return ErrInvalidPlan
			}
			seen := make(map[string]bool)
			for decoder.More() {
				if delimiter == '{' {
					key, err := decoder.Token()
					name, ok := key.(string)
					if err != nil || !ok || seen[name] {
						return ErrInvalidPlan
					}
					seen[name] = true
				}
				if err := readValue(); err != nil {
					return err
				}
			}
			_, err = decoder.Token()
		}
		return err
	}
	if readValue() != nil {
		return ErrInvalidPlan
	}
	decoder = json.NewDecoder(bytes.NewReader(encoded))
	decoder.DisallowUnknownFields()
	if decoder.Decode(target) != nil || !errors.Is(decoder.Decode(&struct{}{}), io.EOF) {
		return ErrInvalidPlan
	}
	return nil
}
