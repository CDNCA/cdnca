package helper

import (
	"bytes"
	"crypto/ed25519"
	"crypto/sha256"
	"crypto/subtle"
	"encoding/binary"
	"encoding/hex"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"os"
	"path/filepath"
	"syscall"

	"github.com/cdnca/cdnca/agents/edge-agent/packaging/helper/protocol"
	"golang.org/x/sys/unix"
)

const (
	ProductionStateDirectory   = "/var/lib/cdnca-edge-agent-helper"
	ProductionReleaseRoot      = "/usr/lib/cdnca-edge-agent"
	ProductionAcceptedManifest = "/var/lib/cdnca-edge-agent-packaging/accepted-manifest"
	currentRecordSchemaVersion = 1
	maxCurrentRecordBytes      = 16 << 10
)

var ErrCurrentFacts = errors.New("installed current facts are uncertain")

type RuntimePaths struct {
	StateDirectory   string
	ReleaseRoot      string
	AcceptedManifest string
}

type InstalledFacts struct {
	Version             string
	ReleaseSequence     uint64
	ManifestSHA256      string
	ExecutableSHA256    string
	OuterArtifactSHA256 string
	AcceptedSequence    uint64
}

type currentRecord struct {
	SchemaVersion  int              `json:"schema_version"`
	ManifestSHA256 string           `json:"manifest_sha256"`
	Receipt        protocol.Receipt `json:"receipt"`
}

type CurrentStore struct {
	path string
	uid  uint32
	gid  uint32
}

func NewCurrentStore(stateDirectory string, uid, gid uint32) (*CurrentStore, error) {
	if !validAbsoluteFilePath(stateDirectory) {
		return nil, ErrCurrentFacts
	}
	if err := requireOwnedDirectory(stateDirectory, stateDirMode, uid, gid, true); err != nil {
		return nil, ErrCurrentFacts
	}
	return &CurrentStore{path: filepath.Join(stateDirectory, "current.json"), uid: uid, gid: gid}, nil
}

func (store *CurrentStore) Load() (protocol.Receipt, string, error) {
	if store == nil {
		return protocol.Receipt{}, "", ErrCurrentFacts
	}
	content, err := readOwnedCanonicalFile(store.path, journalMode, store.uid, store.gid, maxCurrentRecordBytes)
	if errors.Is(err, os.ErrNotExist) {
		return protocol.Receipt{}, "", os.ErrNotExist
	}
	if err != nil {
		return protocol.Receipt{}, "", ErrCurrentFacts
	}
	var record currentRecord
	if decodeCanonicalJSON(content, &record) != nil || !validCurrentRecord(record) {
		return protocol.Receipt{}, "", ErrCurrentFacts
	}
	return record.Receipt, record.ManifestSHA256, nil
}

func (store *CurrentStore) Save(receipt protocol.Receipt, manifestSHA256 string) error {
	if store == nil {
		return ErrCurrentFacts
	}
	record := currentRecord{SchemaVersion: currentRecordSchemaVersion, ManifestSHA256: manifestSHA256, Receipt: receipt}
	if !validCurrentRecord(record) {
		return ErrCurrentFacts
	}
	content, err := json.Marshal(record)
	if err != nil {
		return ErrCurrentFacts
	}
	_, statErr := os.Lstat(store.path)
	replace := statErr == nil
	if statErr != nil && !errors.Is(statErr, os.ErrNotExist) {
		return ErrCurrentFacts
	}
	if err := writeOwnedAtomic(store.path, journalMode, store.uid, store.gid, content, replace); err != nil {
		return ErrCurrentFacts
	}
	return nil
}

func validCurrentRecord(record currentRecord) bool {
	return record.SchemaVersion == currentRecordSchemaVersion && validHelperDigest(record.ManifestSHA256) &&
		record.Receipt.Status == "active" && protocol.ValidateResponse(protocol.Success(record.Receipt)) == nil
}

func InspectInstalled(paths RuntimePaths, publicKey ed25519.PublicKey, uid, gid uint32) (InstalledFacts, error) {
	if !validAbsoluteFilePath(paths.ReleaseRoot) || !validAbsoluteFilePath(paths.AcceptedManifest) || len(publicKey) != ed25519.PublicKeySize {
		return InstalledFacts{}, ErrCurrentFacts
	}
	currentPath := filepath.Join(paths.ReleaseRoot, "current")
	info, err := os.Lstat(currentPath)
	if err != nil || info.Mode()&os.ModeSymlink == 0 {
		return InstalledFacts{}, ErrCurrentFacts
	}
	stat, ok := info.Sys().(*syscall.Stat_t)
	if !ok || uint32(stat.Uid) != uid || uint32(stat.Gid) != gid || stat.Nlink != 1 {
		return InstalledFacts{}, ErrCurrentFacts
	}
	target, err := os.Readlink(currentPath)
	if err != nil || !filepath.IsLocal(target) || filepath.Clean(target) != target {
		return InstalledFacts{}, ErrCurrentFacts
	}
	const prefix = "versions/"
	if len(target) <= len(prefix) || target[:len(prefix)] != prefix {
		return InstalledFacts{}, ErrCurrentFacts
	}
	version := target[len(prefix):]
	if !validHelperVersion(version) || target != prefix+version {
		return InstalledFacts{}, ErrCurrentFacts
	}
	releaseDirectory := filepath.Join(paths.ReleaseRoot, target)
	if err := requireOwnedDirectory(releaseDirectory, 0o755, uid, gid, true); err != nil {
		return InstalledFacts{}, ErrCurrentFacts
	}
	manifestBytes, err := readInstalledFile(filepath.Join(releaseDirectory, "manifest"), 0o444, uid, gid, MaxManifestBytes)
	if err != nil {
		return InstalledFacts{}, err
	}
	signature, err := readInstalledFile(filepath.Join(releaseDirectory, "manifest.sig"), 0o444, uid, gid, SignatureBytes)
	if err != nil || len(signature) != ed25519.SignatureSize || !ed25519.Verify(publicKey, manifestBytes, signature) {
		return InstalledFacts{}, ErrCurrentFacts
	}
	manifest, err := parseReleaseManifest(manifestBytes)
	if err != nil || manifest.Version != version {
		return InstalledFacts{}, ErrCurrentFacts
	}
	// A release installed from a v2 bundle keeps its native section beside
	// the Agent (native.tar.gz); its outer digest covers that section too.
	nativePath := filepath.Join(releaseDirectory, NativeSectionName)
	_, nativeErr := os.Lstat(nativePath)
	if nativeErr != nil && !errors.Is(nativeErr, os.ErrNotExist) {
		return InstalledFacts{}, ErrCurrentFacts
	}
	hasNative := nativeErr == nil
	outerHash := sha256.New()
	_, _ = outerHash.Write([]byte(bundleMagic(hasNative)))
	appendCanonicalSection(outerHash, manifestBytes)
	appendCanonicalSection(outerHash, signature)
	sbomSize, sbomDigest, err := appendInstalledSection(outerHash, filepath.Join(releaseDirectory, "edge-agent.spdx.json"), 0o444, uid, gid, MaxSBOMBytes)
	if err != nil || sbomSize != manifest.SBOMSize || sbomDigest != manifest.SBOMSHA256 {
		return InstalledFacts{}, ErrCurrentFacts
	}
	executableSize, executableDigest, err := appendInstalledSection(outerHash, filepath.Join(releaseDirectory, "edge-agent"), 0o555, uid, gid, MaxExecutableBytes)
	if err != nil || executableSize != manifest.ArtifactSize || executableDigest != manifest.ArtifactSHA256 {
		return InstalledFacts{}, ErrCurrentFacts
	}
	if hasNative {
		if _, _, err := appendInstalledSection(outerHash, nativePath, 0o444, uid, gid, MaxNativeBytes); err != nil {
			return InstalledFacts{}, ErrCurrentFacts
		}
	}
	acceptedSequence := manifest.ReleaseSequence
	accepted, err := readInstalledFile(paths.AcceptedManifest, 0o600, uid, gid, MaxManifestBytes)
	if err == nil {
		acceptedManifest, parseErr := parseReleaseManifest(accepted)
		if parseErr != nil {
			return InstalledFacts{}, ErrCurrentFacts
		}
		if acceptedManifest.ReleaseSequence > acceptedSequence {
			acceptedSequence = acceptedManifest.ReleaseSequence
		}
	} else if !errors.Is(err, os.ErrNotExist) {
		return InstalledFacts{}, ErrCurrentFacts
	}
	return InstalledFacts{
		Version: version, ReleaseSequence: manifest.ReleaseSequence,
		ManifestSHA256: digestBytes(manifestBytes), ExecutableSHA256: manifest.ArtifactSHA256,
		OuterArtifactSHA256: hex.EncodeToString(outerHash.Sum(nil)),
		AcceptedSequence:    acceptedSequence,
	}, nil
}

func appendCanonicalSection(destination io.Writer, content []byte) {
	var length [8]byte
	binary.BigEndian.PutUint64(length[:], uint64(len(content)))
	_, _ = destination.Write(length[:])
	_, _ = destination.Write(content)
}

func appendInstalledSection(destination io.Writer, path string, mode os.FileMode, uid, gid uint32, maximum int64) (int64, string, error) {
	fd, err := unix.Open(path, unix.O_RDONLY|unix.O_CLOEXEC|unix.O_NOFOLLOW|unix.O_NONBLOCK, 0)
	if err != nil {
		return 0, "", ErrCurrentFacts
	}
	file := os.NewFile(uintptr(fd), filepath.Base(path))
	if file == nil {
		_ = unix.Close(fd)
		return 0, "", ErrCurrentFacts
	}
	defer file.Close()
	var stat unix.Stat_t
	if unix.Fstat(fd, &stat) != nil || stat.Mode&unix.S_IFMT != unix.S_IFREG || stat.Nlink != 1 || stat.Size <= 0 || stat.Size > maximum ||
		uint32(stat.Uid) != uid || uint32(stat.Gid) != gid || os.FileMode(stat.Mode).Perm() != mode {
		return 0, "", ErrCurrentFacts
	}
	var length [8]byte
	binary.BigEndian.PutUint64(length[:], uint64(stat.Size))
	_, _ = destination.Write(length[:])
	sectionHash := sha256.New()
	written, err := io.Copy(io.MultiWriter(destination, sectionHash), file)
	if err != nil || written != stat.Size {
		return 0, "", ErrCurrentFacts
	}
	return stat.Size, hex.EncodeToString(sectionHash.Sum(nil)), nil
}

func readInstalledFile(path string, mode os.FileMode, uid, gid uint32, maximum int64) ([]byte, error) {
	fd, err := unix.Open(path, unix.O_RDONLY|unix.O_CLOEXEC|unix.O_NOFOLLOW|unix.O_NONBLOCK, 0)
	if err != nil {
		if errors.Is(err, unix.ENOENT) {
			return nil, os.ErrNotExist
		}
		return nil, ErrCurrentFacts
	}
	file := os.NewFile(uintptr(fd), filepath.Base(path))
	if file == nil {
		_ = unix.Close(fd)
		return nil, ErrCurrentFacts
	}
	defer file.Close()
	var stat unix.Stat_t
	if unix.Fstat(fd, &stat) != nil || stat.Mode&unix.S_IFMT != unix.S_IFREG || stat.Nlink != 1 || stat.Size <= 0 || stat.Size > maximum ||
		uint32(stat.Uid) != uid || uint32(stat.Gid) != gid || os.FileMode(stat.Mode).Perm() != mode {
		return nil, ErrCurrentFacts
	}
	content, err := io.ReadAll(io.LimitReader(file, maximum+1))
	if err != nil || int64(len(content)) != stat.Size {
		return nil, ErrCurrentFacts
	}
	return content, nil
}

func digestBytes(value []byte) string {
	digest := sha256.Sum256(value)
	return hex.EncodeToString(digest[:])
}

func sameReceipt(left, right protocol.Receipt) bool {
	leftBytes, leftErr := json.Marshal(left)
	rightBytes, rightErr := json.Marshal(right)
	return leftErr == nil && rightErr == nil && subtle.ConstantTimeCompare(leftBytes, rightBytes) == 1
}

func currentTransactionID(facts InstalledFacts, sequence uint64) string {
	payload := fmt.Sprintf("%s\x00%s\x00%d", facts.ManifestSHA256, facts.Version, sequence)
	digest := sha256.Sum256([]byte(payload))
	return "current-" + hex.EncodeToString(digest[:16])
}

func verifyManifestBytesEqual(left, right []byte) bool {
	return bytes.Equal(left, right)
}
