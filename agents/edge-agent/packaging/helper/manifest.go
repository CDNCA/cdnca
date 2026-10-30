package helper

import (
	"crypto/ed25519"
	"crypto/sha256"
	"crypto/subtle"
	"crypto/x509"
	"encoding/hex"
	"encoding/pem"
	"errors"
	"fmt"
	"io"
	"os"
	"path/filepath"
	"strconv"
	"strings"
	"time"

	"golang.org/x/sys/unix"
)

const PinnedReleasePublicKeyPath = "/etc/cdnca-edge-agent/package-signing.pem"

var (
	ErrInvalidManifest = errors.New("invalid release manifest")
	ErrReleaseMismatch = errors.New("release manifest mismatch")
	ErrPinnedKeyUnsafe = errors.New("pinned release public key is unsafe")
)

type ManifestExpectation struct {
	ReleaseSequence uint64
	TargetVersion   string
	Platform        string
	Architecture    string
}

type ReleaseManifest struct {
	ManifestVersion        uint64
	ReleaseSequence        uint64
	Version                string
	ArtifactPath           string
	ArtifactSHA256         string
	ArtifactSize           int64
	SBOMPath               string
	SBOMSHA256             string
	SBOMSize               int64
	OS                     string
	Architecture           string
	SourceRepository       string
	SourceCommit           string
	BuildTime              string
	MinimumControlProtocol string
	MinimumAgentProtocol   string
	ManifestSHA256         string
}

func LoadPinnedReleasePublicKey() (ed25519.PublicKey, error) {
	return loadPinnedReleasePublicKey(PinnedReleasePublicKeyPath, 0, 0)
}

func VerifyReleaseManifest(staged StagedBundle, publicKey ed25519.PublicKey, expected ManifestExpectation) (ReleaseManifest, error) {
	if len(publicKey) != ed25519.PublicKeySize {
		return ReleaseManifest{}, fmt.Errorf("%w: key type rejected", ErrInvalidManifest)
	}
	if err := validateStagedBundlePaths(staged); err != nil {
		return ReleaseManifest{}, err
	}
	manifestBytes, err := readVerifiedStagedFile(staged.ManifestPath, staged.ManifestSize, staged.ManifestSHA256, 0400, true)
	if err != nil {
		return ReleaseManifest{}, err
	}
	signature, err := readVerifiedStagedFile(staged.SignaturePath, SignatureBytes, staged.SignatureSHA256, 0400, true)
	if err != nil {
		return ReleaseManifest{}, err
	}
	if len(signature) != ed25519.SignatureSize || !ed25519.Verify(publicKey, manifestBytes, signature) {
		return ReleaseManifest{}, fmt.Errorf("%w: signature verification failed", ErrInvalidManifest)
	}
	if _, err := readVerifiedStagedFile(staged.SBOMPath, staged.SBOMSize, staged.SBOMSHA256, 0400, false); err != nil {
		return ReleaseManifest{}, err
	}
	if _, err := readVerifiedStagedFile(staged.ExecutablePath, staged.ExecutableSize, staged.ExecutableSHA256, 0500, false); err != nil {
		return ReleaseManifest{}, err
	}
	// The native section carries its own signature (artifact trust, checked
	// by the Agent before it switches the runtime); here only its bytes are
	// bound to the staged facts the outer digest covered.
	if staged.NativePath != "" {
		if _, err := readVerifiedStagedFile(staged.NativePath, staged.NativeSize, staged.NativeSHA256, 0400, false); err != nil {
			return ReleaseManifest{}, err
		}
	}

	manifest, err := parseReleaseManifest(manifestBytes)
	if err != nil {
		return ReleaseManifest{}, err
	}
	manifest.ManifestSHA256 = staged.ManifestSHA256
	if manifest.ReleaseSequence != expected.ReleaseSequence || manifest.Version != expected.TargetVersion ||
		manifest.OS != expected.Platform || manifest.Architecture != expected.Architecture {
		return ReleaseManifest{}, fmt.Errorf("%w: signed request facts differ", ErrReleaseMismatch)
	}
	if manifest.ArtifactSHA256 != staged.ExecutableSHA256 || manifest.ArtifactSize != staged.ExecutableSize ||
		manifest.SBOMSHA256 != staged.SBOMSHA256 || manifest.SBOMSize != staged.SBOMSize {
		return ReleaseManifest{}, fmt.Errorf("%w: signed content facts differ", ErrReleaseMismatch)
	}
	return manifest, nil
}

func parseReleaseManifest(data []byte) (ReleaseManifest, error) {
	if len(data) == 0 || len(data) > int(MaxManifestBytes) || data[len(data)-1] != '\n' {
		return ReleaseManifest{}, fmt.Errorf("%w: line framing rejected", ErrInvalidManifest)
	}
	for _, value := range data {
		if value != '\n' && (value < 0x20 || value > 0x7e) {
			return ReleaseManifest{}, fmt.Errorf("%w: non-printable byte", ErrInvalidManifest)
		}
	}
	lines := strings.Split(string(data), "\n")
	if len(lines) != 17 || lines[16] != "" {
		return ReleaseManifest{}, fmt.Errorf("%w: expected 16 canonical lines", ErrInvalidManifest)
	}
	keys := [...]string{
		"manifest_version", "release_sequence", "version", "artifact_path",
		"artifact_sha256", "artifact_size", "sbom_path", "sbom_sha256",
		"sbom_size", "os", "arch", "source_repository", "source_commit",
		"build_time", "minimum_control_protocol", "minimum_agent_protocol",
	}
	values := make([]string, len(keys))
	for index, key := range keys {
		prefix := key + "="
		if !strings.HasPrefix(lines[index], prefix) {
			return ReleaseManifest{}, fmt.Errorf("%w: line %d key rejected", ErrInvalidManifest, index+1)
		}
		values[index] = strings.TrimPrefix(lines[index], prefix)
	}

	manifestVersion, err := parseCanonicalUint(values[0])
	if err != nil || manifestVersion != 2 {
		return ReleaseManifest{}, fmt.Errorf("%w: manifest version rejected", ErrInvalidManifest)
	}
	releaseSequence, err := parseCanonicalUint(values[1])
	if err != nil || releaseSequence == 0 {
		return ReleaseManifest{}, fmt.Errorf("%w: release sequence rejected", ErrInvalidManifest)
	}
	artifactSize, err := parseCanonicalSize(values[5], MaxExecutableBytes)
	if err != nil {
		return ReleaseManifest{}, fmt.Errorf("%w: executable size rejected", ErrInvalidManifest)
	}
	sbomSize, err := parseCanonicalSize(values[8], MaxSBOMBytes)
	if err != nil {
		return ReleaseManifest{}, fmt.Errorf("%w: SBOM size rejected", ErrInvalidManifest)
	}
	if !validIdentifier(values[2]) || values[3] != "edge-agent" || !validSHA256(values[4]) ||
		values[6] != "edge-agent.spdx.json" || !validSHA256(values[7]) || values[9] != "linux" ||
		(values[10] != "amd64" && values[10] != "arm64") || !validSourceRepository(values[11]) ||
		!validSourceCommit(values[12]) || !validBuildTime(values[13]) ||
		!validProtocolVersion(values[14]) || !validProtocolVersion(values[15]) {
		return ReleaseManifest{}, fmt.Errorf("%w: canonical value rejected", ErrInvalidManifest)
	}
	return ReleaseManifest{
		ManifestVersion: manifestVersion, ReleaseSequence: releaseSequence, Version: values[2],
		ArtifactPath: values[3], ArtifactSHA256: values[4], ArtifactSize: artifactSize,
		SBOMPath: values[6], SBOMSHA256: values[7], SBOMSize: sbomSize, OS: values[9], Architecture: values[10],
		SourceRepository: values[11], SourceCommit: values[12], BuildTime: values[13],
		MinimumControlProtocol: values[14], MinimumAgentProtocol: values[15],
	}, nil
}

func validateStagedBundlePaths(staged StagedBundle) error {
	if staged.Directory == "" || filepath.Clean(staged.Directory) != staged.Directory {
		return fmt.Errorf("%w: staging directory rejected", ErrInvalidBundle)
	}
	want := map[string]string{
		staged.ManifestPath: "manifest", staged.SignaturePath: "manifest.sig",
		staged.SBOMPath: "edge-agent.spdx.json", staged.ExecutablePath: "edge-agent",
	}
	expected := 4
	if staged.NativePath != "" || staged.NativeSHA256 != "" || staged.NativeSize != 0 {
		want[staged.NativePath] = NativeSectionName
		expected = 5
	}
	if len(want) != expected {
		return fmt.Errorf("%w: duplicate staged path", ErrInvalidBundle)
	}
	for path, name := range want {
		if path != filepath.Join(staged.Directory, name) {
			return fmt.Errorf("%w: staged path rejected", ErrInvalidBundle)
		}
	}
	return validateStagingDirectory(staged.Directory)
}

func readVerifiedStagedFile(path string, expectedSize int64, expectedSHA256 string, expectedMode os.FileMode, retain bool) ([]byte, error) {
	if expectedSize <= 0 || !validSHA256(expectedSHA256) {
		return nil, fmt.Errorf("%w: invalid staged facts", ErrInvalidBundle)
	}
	fd, err := unix.Open(path, unix.O_RDONLY|unix.O_NOFOLLOW|unix.O_CLOEXEC, 0)
	if err != nil {
		return nil, fmt.Errorf("%w: cannot open staged file", ErrInvalidBundle)
	}
	file := os.NewFile(uintptr(fd), path)
	defer file.Close()
	var stat unix.Stat_t
	if err := unix.Fstat(fd, &stat); err != nil || stat.Mode&unix.S_IFMT != unix.S_IFREG || stat.Nlink != 1 ||
		stat.Size != expectedSize || int(stat.Uid) != os.Geteuid() || int(stat.Gid) != os.Getegid() || os.FileMode(stat.Mode).Perm() != expectedMode.Perm() {
		return nil, fmt.Errorf("%w: staged file facts rejected", ErrInvalidBundle)
	}
	hash := sha256.New()
	var output io.Writer = hash
	var content strings.Builder
	if retain {
		content.Grow(int(expectedSize))
		output = io.MultiWriter(hash, &content)
	}
	written, err := io.Copy(output, file)
	if err != nil || written != expectedSize {
		return nil, fmt.Errorf("%w: staged file read failed", ErrInvalidBundle)
	}
	digest := hex.EncodeToString(hash.Sum(nil))
	if subtle.ConstantTimeCompare([]byte(digest), []byte(expectedSHA256)) != 1 {
		return nil, fmt.Errorf("%w: staged digest differs", ErrArtifactMismatch)
	}
	if !retain {
		return nil, nil
	}
	return []byte(content.String()), nil
}

func loadPinnedReleasePublicKey(path string, expectedUID, expectedGID int) (ed25519.PublicKey, error) {
	fd, err := unix.Open(path, unix.O_RDONLY|unix.O_NOFOLLOW|unix.O_CLOEXEC, 0)
	if err != nil {
		return nil, ErrPinnedKeyUnsafe
	}
	file := os.NewFile(uintptr(fd), path)
	defer file.Close()
	var stat unix.Stat_t
	if err := unix.Fstat(fd, &stat); err != nil || stat.Mode&unix.S_IFMT != unix.S_IFREG || stat.Nlink != 1 ||
		stat.Size <= 0 || stat.Size > 4096 || int(stat.Uid) != expectedUID || int(stat.Gid) != expectedGID || os.FileMode(stat.Mode).Perm() != 0444 {
		return nil, ErrPinnedKeyUnsafe
	}
	data, err := io.ReadAll(io.LimitReader(file, 4097))
	if err != nil || len(data) == 0 || len(data) > 4096 {
		return nil, ErrPinnedKeyUnsafe
	}
	block, rest := pem.Decode(data)
	if block == nil || block.Type != "PUBLIC KEY" || len(strings.TrimSpace(string(rest))) != 0 {
		return nil, ErrPinnedKeyUnsafe
	}
	parsed, err := x509.ParsePKIXPublicKey(block.Bytes)
	if err != nil {
		return nil, ErrPinnedKeyUnsafe
	}
	publicKey, ok := parsed.(ed25519.PublicKey)
	if !ok || len(publicKey) != ed25519.PublicKeySize {
		return nil, ErrPinnedKeyUnsafe
	}
	return append(ed25519.PublicKey(nil), publicKey...), nil
}

func parseCanonicalUint(value string) (uint64, error) {
	if value == "" || len(value) > 18 || (len(value) > 1 && value[0] == '0') {
		return 0, ErrInvalidManifest
	}
	for _, character := range value {
		if character < '0' || character > '9' {
			return 0, ErrInvalidManifest
		}
	}
	return strconv.ParseUint(value, 10, 64)
}

func parseCanonicalSize(value string, maximum int64) (int64, error) {
	parsed, err := parseCanonicalUint(value)
	if err != nil || parsed == 0 || parsed > uint64(maximum) {
		return 0, ErrInvalidManifest
	}
	return int64(parsed), nil
}

func validIdentifier(value string) bool {
	if len(value) < 1 || len(value) > 128 || !asciiLetterOrDigit(value[0]) {
		return false
	}
	for index := 1; index < len(value); index++ {
		if !asciiLetterOrDigit(value[index]) && value[index] != '.' && value[index] != '_' && value[index] != '-' {
			return false
		}
	}
	return true
}

func asciiLetterOrDigit(value byte) bool {
	return value >= 'A' && value <= 'Z' || value >= 'a' && value <= 'z' || value >= '0' && value <= '9'
}

func validSourceRepository(value string) bool {
	if len(value) == 0 || len(value) > 256 || !(strings.HasPrefix(value, "https://") || strings.HasPrefix(value, "ssh://")) {
		return false
	}
	if value == "https://" || value == "ssh://" {
		return false
	}
	for _, character := range value {
		if !((character >= 'A' && character <= 'Z') || (character >= 'a' && character <= 'z') ||
			(character >= '0' && character <= '9') || strings.ContainsRune(":/._@-", character)) {
			return false
		}
	}
	return true
}

func validSourceCommit(value string) bool {
	return (len(value) == 40 || len(value) == 64) && validSHA256Like(value)
}

func validSHA256Like(value string) bool {
	for _, character := range value {
		if !((character >= '0' && character <= '9') || (character >= 'a' && character <= 'f')) {
			return false
		}
	}
	return true
}

func validBuildTime(value string) bool {
	parsed, err := time.Parse("2006-01-02T15:04:05Z", value)
	return err == nil && parsed.UTC().Format("2006-01-02T15:04:05Z") == value
}

func validProtocolVersion(value string) bool {
	if strings.Count(value, ".") != 1 {
		return false
	}
	parts := strings.Split(value, ".")
	major, majorErr := parseCanonicalUint(parts[0])
	_, minorErr := parseCanonicalUint(parts[1])
	return majorErr == nil && minorErr == nil && major > 0
}
