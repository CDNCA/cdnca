package helper

import (
	"bytes"
	"crypto/ed25519"
	"crypto/sha256"
	"crypto/x509"
	"encoding/base64"
	"encoding/binary"
	"encoding/hex"
	"encoding/json"
	"encoding/pem"
	"errors"
	"fmt"
	"io"
	"os"
	"path/filepath"
	"regexp"
	"strconv"
	"strings"
)

// Release bundle publication. Prepare turns release-build outputs into the
// canonical manifest v2 whose exact bytes the release key signs; Finalize
// accepts only an externally produced signature, verifies it, and assembles
// cdnca-edge-release-bundle/v1. No private key is ever read here.

const (
	PrepareSchema      = "cdnca.edge.release-bundle-prepare/v1"
	BundleFactsSchema  = "cdnca.edge.release-bundle/v1"
	SigningDataName    = "manifest.signing-data"
	bundleComponent    = "edge-agent"
	provenanceSchema   = "cdnca.edge.release-provenance/v1"
	maxProvenanceBytes = 1 << 20
)

var (
	ErrReleaseInput = errors.New("invalid release bundle input")
	semverPattern   = regexp.MustCompile(`^(0|[1-9][0-9]*)\.(0|[1-9][0-9]*)\.(0|[1-9][0-9]*)(-[0-9A-Za-z-]+(\.[0-9A-Za-z-]+)*)?$`)
	createdPattern  = regexp.MustCompile(`^[0-9]{4}-[0-9]{2}-[0-9]{2}T[0-9]{2}:[0-9]{2}:[0-9]{2}Z$`)
	baseURLPattern  = regexp.MustCompile(`^https://[a-z0-9]([a-z0-9.-]*[a-z0-9])?(:[0-9]{1,5})?(/[A-Za-z0-9._~-]+)*$`)
)

// ParseReleaseManifest applies the helper's exact canonical manifest v2 parser.
func ParseReleaseManifest(data []byte) (ReleaseManifest, error) {
	return parseReleaseManifest(data)
}

type PrepareOptions struct {
	ReleaseDir      string
	ReleaseSequence uint64
	OutputDir       string
}

type PrepareFacts struct {
	Schema           string `json:"schema"`
	Version          string `json:"version"`
	Architecture     string `json:"architecture"`
	ReleaseSequence  uint64 `json:"release_sequence"`
	ManifestSHA256   string `json:"manifest_sha256"`
	ExecutableSHA256 string `json:"executable_sha256"`
	ExecutableSize   int64  `json:"executable_size"`
	SBOMSHA256       string `json:"sbom_sha256"`
	SBOMSize         int64  `json:"sbom_size"`
	SigningData      string `json:"signing_data"`
	SignatureFormat  string `json:"signature_format"`
}

type FinalizeOptions struct {
	PreparedDir     string
	SignaturePath   string
	PublicKeyPath   string
	DownloadBaseURL string
	// NativePackagePath, when set, is the signed native node package
	// (cdnca-edge-agent.tar.gz) of the same version: the bundle becomes v2
	// and the node switches its OpenResty/Lua runtime with the Agent.
	NativePackagePath string
}

type BundleFacts struct {
	Schema          string `json:"schema"`
	Component       string `json:"component"`
	Version         string `json:"version"`
	Platform        string `json:"platform"`
	Architecture    string `json:"architecture"`
	ReleaseSequence uint64 `json:"release_sequence"`
	BundleFile      string `json:"bundle_file"`
	SHA256          string `json:"sha256"`
	Size            int64  `json:"size"`
	ManifestSHA256  string `json:"manifest_sha256"`
	ReleaseKeySPKI  string `json:"release_key_spki_sha256"`
	DownloadPath    string `json:"download_path"`
	DownloadURL     string `json:"download_url,omitempty"`
}

type provenanceDocument struct {
	Schema           string `json:"schema"`
	Arch             string `json:"arch"`
	Version          string `json:"version"`
	SourceRepository string `json:"source_repository"`
	SourceCommit     string `json:"source_commit"`
	Created          string `json:"created"`
	Artifact         struct {
		Path   string `json:"path"`
		SHA256 string `json:"sha256"`
		Size   int64  `json:"size"`
	} `json:"artifact"`
	SBOM struct {
		Path   string `json:"path"`
		SHA256 string `json:"sha256"`
	} `json:"sbom"`
}

// PrepareReleaseBundle validates release-build outputs and writes the exact
// manifest v2 signing data. It never signs.
func PrepareReleaseBundle(options PrepareOptions) (PrepareFacts, error) {
	if !cleanAbsolute(options.ReleaseDir) || !cleanAbsolute(options.OutputDir) || options.ReleaseSequence == 0 ||
		options.ReleaseSequence > 999999999999999999 {
		return PrepareFacts{}, fmt.Errorf("%w: paths must be absolute and the sequence positive", ErrReleaseInput)
	}
	if _, err := os.Lstat(options.OutputDir); !errors.Is(err, os.ErrNotExist) {
		return PrepareFacts{}, fmt.Errorf("%w: output already exists", ErrReleaseInput)
	}
	executable, err := readReleaseFile(filepath.Join(options.ReleaseDir, "edge-agent"), MaxExecutableBytes)
	if err != nil {
		return PrepareFacts{}, err
	}
	sbom, err := readReleaseFile(filepath.Join(options.ReleaseDir, "edge-agent.spdx.json"), MaxSBOMBytes)
	if err != nil {
		return PrepareFacts{}, err
	}
	provenanceBytes, err := readReleaseFile(filepath.Join(options.ReleaseDir, "edge-agent.provenance.json"), maxProvenanceBytes)
	if err != nil {
		return PrepareFacts{}, err
	}
	var provenance provenanceDocument
	if err := json.Unmarshal(provenanceBytes, &provenance); err != nil {
		return PrepareFacts{}, fmt.Errorf("%w: provenance is not JSON", ErrReleaseInput)
	}
	executableSHA, sbomSHA := sha256Hex(executable), sha256Hex(sbom)
	if provenance.Schema != provenanceSchema || (provenance.Arch != "amd64" && provenance.Arch != "arm64") ||
		provenance.Artifact.Path != "edge-agent" || provenance.Artifact.SHA256 != executableSHA ||
		provenance.Artifact.Size != int64(len(executable)) || provenance.SBOM.Path != "edge-agent.spdx.json" ||
		provenance.SBOM.SHA256 != sbomSHA || !semverPattern.MatchString(provenance.Version) ||
		!createdPattern.MatchString(provenance.Created) {
		return PrepareFacts{}, fmt.Errorf("%w: provenance does not describe the release outputs", ErrReleaseInput)
	}
	if err := validateReleaseELF(executable, provenance.Arch); err != nil {
		return PrepareFacts{}, err
	}
	if err := validateMinimalSPDX(sbom); err != nil {
		return PrepareFacts{}, err
	}
	manifest := []byte(fmt.Sprintf("manifest_version=2\nrelease_sequence=%d\nversion=%s\nartifact_path=edge-agent\n"+
		"artifact_sha256=%s\nartifact_size=%d\nsbom_path=edge-agent.spdx.json\nsbom_sha256=%s\nsbom_size=%d\n"+
		"os=linux\narch=%s\nsource_repository=%s\nsource_commit=%s\nbuild_time=%s\n"+
		"minimum_control_protocol=1.0\nminimum_agent_protocol=1.0\n",
		options.ReleaseSequence, provenance.Version, executableSHA, len(executable), sbomSHA, len(sbom),
		provenance.Arch, provenance.SourceRepository, provenance.SourceCommit, provenance.Created))
	parsed, err := parseReleaseManifest(manifest)
	if err != nil {
		return PrepareFacts{}, fmt.Errorf("%w: generated manifest rejected by the helper parser: %v", ErrReleaseInput, err)
	}
	facts := PrepareFacts{
		Schema: PrepareSchema, Version: parsed.Version, Architecture: parsed.Architecture,
		ReleaseSequence: parsed.ReleaseSequence, ManifestSHA256: sha256Hex(manifest),
		ExecutableSHA256: executableSHA, ExecutableSize: int64(len(executable)),
		SBOMSHA256: sbomSHA, SBOMSize: int64(len(sbom)), SigningData: SigningDataName,
		SignatureFormat: "ed25519-raw-64-or-base64",
	}
	encodedFacts, err := json.MarshalIndent(facts, "", "  ")
	if err != nil {
		return PrepareFacts{}, err
	}
	if err := os.Mkdir(options.OutputDir, 0o700); err != nil {
		return PrepareFacts{}, fmt.Errorf("%w: cannot create output", ErrReleaseInput)
	}
	for _, file := range []struct {
		name string
		data []byte
		mode os.FileMode
	}{
		{"edge-agent", executable, 0o555}, {"edge-agent.spdx.json", sbom, 0o444},
		{"edge-agent.provenance.json", provenanceBytes, 0o444}, {"manifest", manifest, 0o444},
		{SigningDataName, manifest, 0o444}, {"prepare.json", append(encodedFacts, '\n'), 0o444},
	} {
		if err := writeExclusive(filepath.Join(options.OutputDir, file.name), file.data, file.mode); err != nil {
			return PrepareFacts{}, err
		}
	}
	return facts, nil
}

// FinalizeReleaseBundle verifies an external Ed25519 signature over the
// prepared manifest and assembles the canonical bundle, then re-stages it
// through the helper's own parser and verifier before reporting success.
func FinalizeReleaseBundle(options FinalizeOptions) (BundleFacts, error) {
	if !cleanAbsolute(options.PreparedDir) || !cleanAbsolute(options.SignaturePath) || !cleanAbsolute(options.PublicKeyPath) {
		return BundleFacts{}, fmt.Errorf("%w: paths must be absolute", ErrReleaseInput)
	}
	if options.DownloadBaseURL != "" && (!baseURLPattern.MatchString(options.DownloadBaseURL) ||
		strings.Contains(options.DownloadBaseURL, "/latest")) {
		return BundleFacts{}, fmt.Errorf("%w: download base URL must be an https origin path without a mutable alias", ErrReleaseInput)
	}
	factsBytes, err := readReleaseFile(filepath.Join(options.PreparedDir, "prepare.json"), maxProvenanceBytes)
	if err != nil {
		return BundleFacts{}, err
	}
	var prepared PrepareFacts
	decoder := json.NewDecoder(bytes.NewReader(factsBytes))
	decoder.DisallowUnknownFields()
	if err := decoder.Decode(&prepared); err != nil || prepared.Schema != PrepareSchema {
		return BundleFacts{}, fmt.Errorf("%w: prepare facts are invalid", ErrReleaseInput)
	}
	manifest, err := readReleaseFile(filepath.Join(options.PreparedDir, "manifest"), MaxManifestBytes)
	if err != nil {
		return BundleFacts{}, err
	}
	executable, err := readReleaseFile(filepath.Join(options.PreparedDir, "edge-agent"), MaxExecutableBytes)
	if err != nil {
		return BundleFacts{}, err
	}
	sbom, err := readReleaseFile(filepath.Join(options.PreparedDir, "edge-agent.spdx.json"), MaxSBOMBytes)
	if err != nil {
		return BundleFacts{}, err
	}
	signingData, err := readReleaseFile(filepath.Join(options.PreparedDir, SigningDataName), MaxManifestBytes)
	if err != nil {
		return BundleFacts{}, err
	}
	parsed, err := parseReleaseManifest(manifest)
	if err != nil || !bytes.Equal(signingData, manifest) || sha256Hex(manifest) != prepared.ManifestSHA256 ||
		parsed.ArtifactSHA256 != sha256Hex(executable) || parsed.ArtifactSize != int64(len(executable)) ||
		parsed.SBOMSHA256 != sha256Hex(sbom) || parsed.SBOMSize != int64(len(sbom)) ||
		parsed.Version != prepared.Version || parsed.ReleaseSequence != prepared.ReleaseSequence {
		return BundleFacts{}, fmt.Errorf("%w: prepared files changed after preparation", ErrReleaseInput)
	}
	publicKey, spki, err := readEd25519PublicKey(options.PublicKeyPath)
	if err != nil {
		return BundleFacts{}, err
	}
	signature, err := readDetachedSignature(options.SignaturePath)
	if err != nil {
		return BundleFacts{}, err
	}
	if !ed25519.Verify(publicKey, manifest, signature) {
		return BundleFacts{}, fmt.Errorf("%w: signature does not verify over the manifest", ErrReleaseInput)
	}
	var native []byte
	if options.NativePackagePath != "" {
		if !cleanAbsolute(options.NativePackagePath) {
			return BundleFacts{}, fmt.Errorf("%w: paths must be absolute", ErrReleaseInput)
		}
		if native, err = readReleaseFile(options.NativePackagePath, MaxNativeBytes); err != nil {
			return BundleFacts{}, err
		}
		if len(native) < 2 || native[0] != 0x1f || native[1] != 0x8b {
			return BundleFacts{}, fmt.Errorf("%w: native package is not gzip", ErrReleaseInput)
		}
	}
	bundle := EncodeReleaseBundle(manifest, signature, sbom, executable, native)
	if int64(len(bundle)) > MaxBundleBytes {
		return BundleFacts{}, fmt.Errorf("%w: bundle exceeds the helper limit", ErrReleaseInput)
	}
	name := fmt.Sprintf("cdnca-edge-agent-%s-linux-%s.bundle", parsed.Version, parsed.Architecture)
	bundlePath := filepath.Join(options.PreparedDir, name)
	if err := writeExclusive(filepath.Join(options.PreparedDir, "manifest.sig"), signature, 0o444); err != nil {
		return BundleFacts{}, err
	}
	if err := writeExclusive(bundlePath, bundle, 0o444); err != nil {
		return BundleFacts{}, err
	}
	digest := sha256Hex(bundle)
	if err := selfCheckReleaseBundle(bundlePath, int64(len(bundle)), digest, publicKey, parsed); err != nil {
		_ = os.Remove(bundlePath)
		return BundleFacts{}, err
	}
	facts := BundleFacts{
		Schema: BundleFactsSchema, Component: bundleComponent, Version: parsed.Version, Platform: "linux",
		Architecture: parsed.Architecture, ReleaseSequence: parsed.ReleaseSequence, BundleFile: name,
		SHA256: digest, Size: int64(len(bundle)), ManifestSHA256: sha256Hex(manifest), ReleaseKeySPKI: spki,
		DownloadPath: "edge-agent/" + parsed.Version + "/" + name,
	}
	if options.DownloadBaseURL != "" {
		facts.DownloadURL = options.DownloadBaseURL + "/" + facts.DownloadPath
	}
	encoded, err := json.MarshalIndent(facts, "", "  ")
	if err != nil {
		return BundleFacts{}, err
	}
	if err := writeExclusive(filepath.Join(options.PreparedDir, "bundle.json"), append(encoded, '\n'), 0o444); err != nil {
		return BundleFacts{}, err
	}
	if err := writeExclusive(filepath.Join(options.PreparedDir, "SHA256SUMS"), []byte(digest+"  "+name+"\n"), 0o444); err != nil {
		return BundleFacts{}, err
	}
	return facts, nil
}

// EncodeReleaseBundle is MAGIC || u64be(len)||section for manifest,
// signature, SBOM and executable, with nothing else (v1); a non-empty native
// package adds it as the fifth section under the v2 magic.
func EncodeReleaseBundle(manifest, signature, sbom, executable []byte, native ...[]byte) []byte {
	var output bytes.Buffer
	sections := [][]byte{manifest, signature, sbom, executable}
	if len(native) == 1 && len(native[0]) > 0 {
		sections = append(sections, native[0])
	}
	output.WriteString(bundleMagic(len(sections) == 5))
	for _, section := range sections {
		var length [8]byte
		binary.BigEndian.PutUint64(length[:], uint64(len(section)))
		output.Write(length[:])
		output.Write(section)
	}
	return output.Bytes()
}

func selfCheckReleaseBundle(path string, size int64, digest string, publicKey ed25519.PublicKey, expected ReleaseManifest) error {
	staging, err := os.MkdirTemp("", "cdnca-release-bundle-check-")
	if err != nil {
		return err
	}
	defer os.RemoveAll(staging)
	if err := os.Chmod(staging, 0o700); err != nil {
		return err
	}
	artifact, err := os.Open(path)
	if err != nil {
		return err
	}
	defer artifact.Close()
	staged, err := StageReleaseBundle(artifact, staging, size, digest)
	if err != nil {
		return fmt.Errorf("%w: helper staging rejected the bundle: %v", ErrReleaseInput, err)
	}
	if _, err := VerifyReleaseManifest(staged, publicKey, ManifestExpectation{
		ReleaseSequence: expected.ReleaseSequence, TargetVersion: expected.Version,
		Platform: "linux", Architecture: expected.Architecture,
	}); err != nil {
		return fmt.Errorf("%w: helper verification rejected the bundle: %v", ErrReleaseInput, err)
	}
	return nil
}

func readDetachedSignature(path string) ([]byte, error) {
	data, err := readReleaseFile(path, 256)
	if err != nil {
		return nil, err
	}
	if len(data) == ed25519.SignatureSize {
		return data, nil
	}
	text := strings.TrimSuffix(string(data), "\n")
	for _, encoding := range []*base64.Encoding{base64.StdEncoding, base64.RawStdEncoding} {
		if decoded, err := encoding.DecodeString(text); err == nil && len(decoded) == ed25519.SignatureSize {
			return decoded, nil
		}
	}
	return nil, fmt.Errorf("%w: signature must be 64 raw bytes or their base64", ErrReleaseInput)
}

func readEd25519PublicKey(path string) (ed25519.PublicKey, string, error) {
	data, err := readReleaseFile(path, 4096)
	if err != nil {
		return nil, "", err
	}
	block, rest := pem.Decode(data)
	if block == nil || block.Type != "PUBLIC KEY" || len(bytes.TrimSpace(rest)) != 0 {
		return nil, "", fmt.Errorf("%w: public key must be one PEM PUBLIC KEY", ErrReleaseInput)
	}
	parsed, err := x509.ParsePKIXPublicKey(block.Bytes)
	key, ok := parsed.(ed25519.PublicKey)
	if err != nil || !ok {
		return nil, "", fmt.Errorf("%w: public key is not Ed25519", ErrReleaseInput)
	}
	return key, sha256Hex(block.Bytes), nil
}

func validateReleaseELF(executable []byte, arch string) error {
	machine := map[string]uint16{"amd64": 62, "arm64": 183}[arch]
	if len(executable) < 64 || !bytes.Equal(executable[:7], []byte{0x7f, 'E', 'L', 'F', 2, 1, 1}) ||
		(binary.LittleEndian.Uint16(executable[16:18]) != 2 && binary.LittleEndian.Uint16(executable[16:18]) != 3) ||
		binary.LittleEndian.Uint16(executable[18:20]) != machine {
		return fmt.Errorf("%w: executable is not a 64-bit little-endian %s ELF", ErrReleaseInput, arch)
	}
	return nil
}

func validateMinimalSPDX(sbom []byte) error {
	var document struct {
		SPDXVersion       string `json:"spdxVersion"`
		DataLicense       string `json:"dataLicense"`
		SPDXID            string `json:"SPDXID"`
		Name              string `json:"name"`
		DocumentNamespace string `json:"documentNamespace"`
		CreationInfo      struct {
			Created  string   `json:"created"`
			Creators []string `json:"creators"`
		} `json:"creationInfo"`
	}
	if err := json.Unmarshal(sbom, &document); err != nil || document.SPDXVersion != "SPDX-2.3" ||
		document.DataLicense != "CC0-1.0" || document.SPDXID != "SPDXRef-DOCUMENT" || document.Name == "" ||
		!(strings.HasPrefix(document.DocumentNamespace, "https://") || strings.HasPrefix(document.DocumentNamespace, "http://")) ||
		!createdPattern.MatchString(document.CreationInfo.Created) || len(document.CreationInfo.Creators) == 0 {
		return fmt.Errorf("%w: SBOM is not the minimal SPDX 2.3 document packaging accepts", ErrReleaseInput)
	}
	for _, creator := range document.CreationInfo.Creators {
		if creator == "" {
			return fmt.Errorf("%w: SBOM creator is empty", ErrReleaseInput)
		}
	}
	return nil
}

func readReleaseFile(path string, limit int64) ([]byte, error) {
	info, err := os.Lstat(path)
	if err != nil || !info.Mode().IsRegular() || info.Size() <= 0 || info.Size() > limit {
		return nil, fmt.Errorf("%w: %s must be a non-empty regular file within %s bytes", ErrReleaseInput,
			filepath.Base(path), strconv.FormatInt(limit, 10))
	}
	file, err := os.Open(path)
	if err != nil {
		return nil, fmt.Errorf("%w: cannot open %s", ErrReleaseInput, filepath.Base(path))
	}
	defer file.Close()
	data, err := io.ReadAll(io.LimitReader(file, limit+1))
	if err != nil || int64(len(data)) != info.Size() {
		return nil, fmt.Errorf("%w: %s changed while reading", ErrReleaseInput, filepath.Base(path))
	}
	return data, nil
}

func writeExclusive(path string, data []byte, mode os.FileMode) error {
	file, err := os.OpenFile(path, os.O_WRONLY|os.O_CREATE|os.O_EXCL, 0o600)
	if err != nil {
		return fmt.Errorf("%w: refusing to overwrite %s", ErrReleaseInput, filepath.Base(path))
	}
	if _, err := file.Write(data); err != nil {
		_ = file.Close()
		return err
	}
	if err := file.Sync(); err != nil {
		_ = file.Close()
		return err
	}
	if err := file.Close(); err != nil {
		return err
	}
	return os.Chmod(path, mode)
}

func cleanAbsolute(path string) bool {
	return path != "" && filepath.IsAbs(path) && filepath.Clean(path) == path && path != "/"
}

func sha256Hex(data []byte) string {
	digest := sha256.Sum256(data)
	return hex.EncodeToString(digest[:])
}
