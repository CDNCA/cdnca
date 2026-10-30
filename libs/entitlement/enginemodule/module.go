// Package enginemodule is the format of a signed node engine module (ADR
// 0007 B3: native code nginx loads, first the OWASP CRS engine extension
// libmodsecurity + ModSecurity-nginx). The license service lists it in the
// artifact catalog as kind engine_module, the control plane puts it in node
// artifact sets, and the edge agent verifies the platform release signature
// before it installs it.
//
// A build is four files (what scripts/waf-engine-release.sh produces):
// SHA256SUMS, manifest.json, signatures.json (platform release key
// signatures over SigningDomain + manifest.json) and the payload tar.gz the
// manifest names. As a catalog entry they travel as one Bundle: an
// uncompressed deterministic tar holding exactly those four files.
//
// This package only checks structure and digests. Whether a signature is
// trusted is the node's decision (agents/edge-agent/internal/wafengine):
// neither the license service nor the control plane is trusted to vouch for
// native code.
package enginemodule

import (
	"bufio"
	"bytes"
	"crypto/ed25519"
	"crypto/sha256"
	"encoding/base64"
	"encoding/hex"
	"encoding/json"
	"errors"
	"path"
	"regexp"
	"sort"
	"strings"
)

const (
	// Component names the OWASP CRS engine extension.
	Component      = "waf-crs-module"
	ManifestSchema = "cdnca.edge.waf-crs-module/v1"
	ManifestName   = "manifest.json"
	SumsName       = "SHA256SUMS"
	ModulePath     = "modules/ngx_http_modsecurity_module.so"
	UnicodeMapPath = "unicode.mapping"

	// SignaturesName holds the platform release-key signatures (one or more
	// keys, so a release key can be rotated with an overlap). Each signs
	// SigningDomain + the exact manifest.json bytes; the domain keeps these
	// signatures apart from every other artifact the same release keys sign
	// (native node packages use "cdnca.native-node.release/v1\n").
	SignaturesName   = "signatures.json"
	SignaturesSchema = "cdnca.edge.waf-crs-module.signatures/v1"
	SigningDomain    = "cdnca.edge.waf-crs-module.manifest/v1\n"

	MaxManifestBytes   = 64 << 10
	MaxSumsBytes       = 4 << 10
	MaxSignaturesBytes = 4 << 10
	// MaxPayloadBytes keeps a bundle inside one node artifact set item
	// (libs/edgeconfig/artifactset: 8 segments of 4 MiB after zstd; the
	// payload is already gzip).
	MaxPayloadBytes = 28 << 20

	maxFiles      = 64
	maxSignatures = 8
)

var (
	ErrSumsMismatch = errors.New("waf engine artifact digest does not match SHA256SUMS")
	ErrSignature    = errors.New("waf engine manifest signature is invalid")
	ErrManifest     = errors.New("waf engine manifest is invalid or does not match this node")
	ErrPayload      = errors.New("waf engine payload does not match its manifest")

	versionPattern     = regexp.MustCompile(`^[0-9]{1,3}\.[0-9]{1,3}\.[0-9]{1,3}(-[0-9A-Za-z.-]{1,32})?$`)
	openRestyPattern   = regexp.MustCompile(`^[0-9]{1,3}\.[0-9]{1,3}\.[0-9]{1,3}\.[0-9]{1,3}$`)
	fileNamePattern    = regexp.MustCompile(`^[A-Za-z0-9][A-Za-z0-9._+-]{0,127}$`)
	payloadNamePattern = regexp.MustCompile(`^cdnca-waf-crs-module-[0-9A-Za-z.+-]{1,96}\.tar\.gz$`)
	sha256Pattern      = regexp.MustCompile(`^[0-9a-f]{64}$`)
	requiredFiles      = []string{ModulePath, UnicodeMapPath, "lib/libmodsecurity.so.3"}
)

// Manifest is the signed description of one extension build. KeyID is the
// platform release key the build was prepared for (informational: the
// signatures in signatures.json carry their own key IDs and decide trust).
type Manifest struct {
	Schema           string      `json:"schema"`
	Component        string      `json:"component"`
	Version          string      `json:"version"`
	OpenRestyVersion string      `json:"openresty_version"`
	Platform         string      `json:"platform"`
	Architecture     string      `json:"architecture"`
	KeyID            string      `json:"key_id"`
	Payload          PayloadRef  `json:"payload"`
	Files            []FileEntry `json:"files"`
}

type PayloadRef struct {
	Name   string `json:"name"`
	SHA256 string `json:"sha256"`
	Size   int64  `json:"size"`
}

type FileEntry struct {
	Path   string `json:"path"`
	SHA256 string `json:"sha256"`
	Size   int64  `json:"size"`
	Mode   uint32 `json:"mode"`
}

// SignatureDocument is signatures.json.
type SignatureDocument struct {
	Schema     string           `json:"schema"`
	Signatures []SignatureEntry `json:"signatures"`
}

type SignatureEntry struct {
	KeyID     string `json:"key_id"`
	Algorithm string `json:"algorithm"`
	Signature string `json:"signature"` // standard base64 of the 64-byte Ed25519 signature
}

// Digest is the lowercase hex SHA-256 of content.
func Digest(content []byte) string {
	sum := sha256.Sum256(content)
	return hex.EncodeToString(sum[:])
}

// ValidVersion / ValidOpenRestyVersion / ValidArchitecture check the node
// facts a manifest is matched against.
func ValidVersion(value string) bool          { return versionPattern.MatchString(value) }
func ValidOpenRestyVersion(value string) bool { return openRestyPattern.MatchString(value) }
func ValidArchitecture(value string) bool     { return value == "amd64" || value == "arm64" }

// ParseSums reads a SHA256SUMS file ("<hex>  <name>" lines).
func ParseSums(content []byte) (map[string]string, error) {
	if len(content) == 0 || len(content) > MaxSumsBytes {
		return nil, ErrSumsMismatch
	}
	sums := map[string]string{}
	scanner := bufio.NewScanner(bytes.NewReader(content))
	for scanner.Scan() {
		fields := strings.Fields(scanner.Text())
		if len(fields) != 2 || !sha256Pattern.MatchString(fields[0]) || !fileNamePattern.MatchString(strings.TrimPrefix(fields[1], "*")) {
			return nil, ErrSumsMismatch
		}
		name := strings.TrimPrefix(fields[1], "*")
		if _, exists := sums[name]; exists {
			return nil, ErrSumsMismatch
		}
		sums[name] = fields[0]
	}
	return sums, nil
}

// SigningBytes is what a platform release key signs for a manifest.
func SigningBytes(manifestBytes []byte) []byte {
	return append([]byte(SigningDomain), manifestBytes...)
}

// ParseSignatures strictly decodes signatures.json.
func ParseSignatures(content []byte) (SignatureDocument, error) {
	var document SignatureDocument
	if len(content) == 0 || len(content) > MaxSignaturesBytes {
		return document, ErrSignature
	}
	decoder := json.NewDecoder(bytes.NewReader(content))
	decoder.DisallowUnknownFields()
	if err := decoder.Decode(&document); err != nil || decoder.More() || validSignatures(document) != nil {
		return SignatureDocument{}, ErrSignature
	}
	return document, nil
}

func validSignatures(document SignatureDocument) error {
	if document.Schema != SignaturesSchema || len(document.Signatures) == 0 || len(document.Signatures) > maxSignatures {
		return ErrSignature
	}
	seen := map[string]bool{}
	for _, entry := range document.Signatures {
		if !fileNamePattern.MatchString(entry.KeyID) || seen[entry.KeyID] || entry.Algorithm != "ed25519" {
			return ErrSignature
		}
		if raw, err := base64.StdEncoding.DecodeString(entry.Signature); err != nil || len(raw) != ed25519.SignatureSize {
			return ErrSignature
		}
		seen[entry.KeyID] = true
	}
	return nil
}

// EncodeSignatures is the canonical signatures.json (sorted by key ID).
func EncodeSignatures(document SignatureDocument) ([]byte, error) {
	document.Schema = SignaturesSchema
	document.Signatures = append([]SignatureEntry(nil), document.Signatures...)
	sort.Slice(document.Signatures, func(i, j int) bool { return document.Signatures[i].KeyID < document.Signatures[j].KeyID })
	if err := validSignatures(document); err != nil {
		return nil, err
	}
	encoded, err := json.MarshalIndent(document, "", "  ")
	if err != nil {
		return nil, err
	}
	return append(encoded, '\n'), nil
}

// DecodeManifest strictly decodes and validates manifest.json (no trust).
func DecodeManifest(content []byte) (Manifest, error) {
	var manifest Manifest
	if len(content) == 0 || len(content) > MaxManifestBytes {
		return Manifest{}, ErrManifest
	}
	decoder := json.NewDecoder(bytes.NewReader(content))
	decoder.DisallowUnknownFields()
	if err := decoder.Decode(&manifest); err != nil || decoder.More() {
		return Manifest{}, ErrManifest
	}
	if err := ValidateManifest(manifest); err != nil {
		return Manifest{}, err
	}
	return manifest, nil
}

// ValidateManifest checks a manifest's shape.
func ValidateManifest(manifest Manifest) error {
	if manifest.Schema != ManifestSchema || manifest.Component != Component || !versionPattern.MatchString(manifest.Version) ||
		!openRestyPattern.MatchString(manifest.OpenRestyVersion) || manifest.Platform != "linux" ||
		!ValidArchitecture(manifest.Architecture) || !fileNamePattern.MatchString(manifest.KeyID) ||
		!payloadNamePattern.MatchString(manifest.Payload.Name) || !sha256Pattern.MatchString(manifest.Payload.SHA256) ||
		manifest.Payload.Size < 1 || manifest.Payload.Size > MaxPayloadBytes || len(manifest.Files) == 0 ||
		len(manifest.Files) > maxFiles {
		return ErrManifest
	}
	seen := map[string]bool{}
	for index, file := range manifest.Files {
		if !ValidRelativePath(file.Path) || seen[file.Path] || index > 0 && manifest.Files[index-1].Path >= file.Path ||
			!sha256Pattern.MatchString(file.SHA256) || file.Size < 1 || file.Size > manifest.Payload.Size*64 ||
			file.Mode != 0o444 && file.Mode != 0o555 {
			return ErrManifest
		}
		seen[file.Path] = true
	}
	for _, required := range requiredFiles {
		if !seen[required] {
			return ErrManifest
		}
	}
	return nil
}

// EncodeManifest is the canonical manifest encoding (the signed bytes).
func EncodeManifest(manifest Manifest) ([]byte, error) {
	if err := ValidateManifest(manifest); err != nil {
		return nil, err
	}
	encoded, err := json.MarshalIndent(manifest, "", "  ")
	if err != nil {
		return nil, err
	}
	return append(encoded, '\n'), nil
}

// ValidRelativePath reports a clean relative path of safe file names.
func ValidRelativePath(value string) bool {
	if value == "" || len(value) > 256 || path.Clean(value) != value || strings.HasPrefix(value, "/") ||
		strings.HasPrefix(value, "../") || value == ".." {
		return false
	}
	for _, part := range strings.Split(value, "/") {
		if !fileNamePattern.MatchString(part) {
			return false
		}
	}
	return true
}
