package helper

import (
	"crypto/sha256"
	"crypto/subtle"
	"encoding/binary"
	"encoding/hex"
	"errors"
	"fmt"
	"io"
	"os"
	"path/filepath"
	"syscall"

	"golang.org/x/sys/unix"
)

const (
	BundleMagic = "cdnca-edge-release-bundle/v1\x00"
	// BundleMagicV2 adds a fifth section: the signed native node package
	// (cdnca.native-node.release/v1 tar.gz) of the same version. The Agent
	// verifies it with its artifact trust and switches /opt/cdnca-node.
	BundleMagicV2            = "cdnca-edge-release-bundle/v2\x00"
	NativeSectionName        = "native.tar.gz"
	MaxNativeBytes     int64 = 200 * 1024 * 1024
	MaxManifestBytes   int64 = 16384
	SignatureBytes     int64 = 64
	MaxSBOMBytes       int64 = 16 * 1024 * 1024
	MaxExecutableBytes int64 = 256 * 1024 * 1024
	MaxBundleBytes     int64 = 285229182
)

var (
	ErrUnsafeArtifactFD = errors.New("unsafe artifact fd")
	ErrArtifactMismatch = errors.New("artifact mismatch")
	ErrInvalidBundle    = errors.New("invalid release bundle")
)

type StagedBundle struct {
	Directory        string
	ManifestPath     string
	SignaturePath    string
	SBOMPath         string
	ExecutablePath   string
	OuterSHA256      string
	OuterSize        int64
	ManifestSHA256   string
	ManifestSize     int64
	SignatureSHA256  string
	SBOMSHA256       string
	SBOMSize         int64
	ExecutableSHA256 string
	ExecutableSize   int64
	// NativePath is empty for a v1 bundle.
	NativePath   string
	NativeSHA256 string
	NativeSize   int64
}

// bundleMagic is the magic of a bundle with or without the native section.
func bundleMagic(native bool) string {
	if native {
		return BundleMagicV2
	}
	return BundleMagic
}

type bundleSection struct {
	name string
	path string
	min  int64
	max  int64
	mode os.FileMode
}

// StageReleaseBundle revalidates an already-open artifact descriptor and
// streams its canonical sections to fixed names in a private staging directory.
func StageReleaseBundle(artifact *os.File, stagingDirectory string, expectedSize int64, expectedSHA256 string) (result StagedBundle, err error) {
	if artifact == nil {
		return result, fmt.Errorf("%w: descriptor is missing", ErrUnsafeArtifactFD)
	}
	if expectedSize <= 0 || expectedSize > MaxBundleBytes || !validSHA256(expectedSHA256) {
		return result, fmt.Errorf("%w: invalid expected artifact facts", ErrArtifactMismatch)
	}
	if err := validateArtifactFD(artifact, expectedSize); err != nil {
		return result, err
	}
	if err := validateStagingDirectory(stagingDirectory); err != nil {
		return result, err
	}
	if _, err := artifact.Seek(0, io.SeekStart); err != nil {
		return result, fmt.Errorf("%w: descriptor is not seekable", ErrUnsafeArtifactFD)
	}

	sections := []bundleSection{
		{name: "manifest", path: filepath.Join(stagingDirectory, "manifest"), min: 1, max: MaxManifestBytes, mode: 0400},
		{name: "signature", path: filepath.Join(stagingDirectory, "manifest.sig"), min: SignatureBytes, max: SignatureBytes, mode: 0400},
		{name: "sbom", path: filepath.Join(stagingDirectory, "edge-agent.spdx.json"), min: 1, max: MaxSBOMBytes, mode: 0400},
		{name: "executable", path: filepath.Join(stagingDirectory, "edge-agent"), min: 1, max: MaxExecutableBytes, mode: 0500},
	}
	created := make([]string, 0, len(sections))
	defer func() {
		if err == nil {
			return
		}
		for _, path := range created {
			_ = os.Remove(path)
		}
		_ = syncDirectory(stagingDirectory)
	}()

	outerHash := sha256.New()
	input := io.TeeReader(artifact, outerHash)
	magic := make([]byte, len(BundleMagic))
	if _, err = io.ReadFull(input, magic); err != nil || (string(magic) != BundleMagic && string(magic) != BundleMagicV2) {
		return result, fmt.Errorf("%w: bad magic", ErrInvalidBundle)
	}
	if string(magic) == BundleMagicV2 {
		sections = append(sections, bundleSection{name: "native", path: filepath.Join(stagingDirectory, NativeSectionName), min: 1, max: MaxNativeBytes, mode: 0400})
	}

	digests := make([]string, 0, len(sections))
	sizes := make([]int64, 0, len(sections))
	for _, section := range sections {
		var header [8]byte
		if _, err = io.ReadFull(input, header[:]); err != nil {
			return result, fmt.Errorf("%w: short %s length", ErrInvalidBundle, section.name)
		}
		length := binary.BigEndian.Uint64(header[:])
		if length < uint64(section.min) || length > uint64(section.max) {
			return result, fmt.Errorf("%w: %s length outside limit", ErrInvalidBundle, section.name)
		}
		digest, copyErr := writeSection(input, section.path, int64(length), section.mode)
		if copyErr != nil {
			return result, fmt.Errorf("%w: %s section: %v", ErrInvalidBundle, section.name, copyErr)
		}
		created = append(created, section.path)
		digests = append(digests, digest)
		sizes = append(sizes, int64(length))
	}

	var trailing [1]byte
	n, readErr := input.Read(trailing[:])
	if n != 0 || readErr != io.EOF {
		return result, fmt.Errorf("%w: trailing bytes", ErrInvalidBundle)
	}
	if err = syncDirectory(stagingDirectory); err != nil {
		return result, fmt.Errorf("%w: cannot sync staging directory", ErrInvalidBundle)
	}
	outerDigest := hex.EncodeToString(outerHash.Sum(nil))
	if subtle.ConstantTimeCompare([]byte(outerDigest), []byte(expectedSHA256)) != 1 {
		return result, fmt.Errorf("%w: outer digest differs", ErrArtifactMismatch)
	}

	result = StagedBundle{
		Directory: stagingDirectory, ManifestPath: sections[0].path,
		SignaturePath: sections[1].path, SBOMPath: sections[2].path,
		ExecutablePath: sections[3].path, OuterSHA256: outerDigest, OuterSize: expectedSize,
		ManifestSHA256: digests[0], ManifestSize: sizes[0], SignatureSHA256: digests[1],
		SBOMSHA256: digests[2], SBOMSize: sizes[2], ExecutableSHA256: digests[3], ExecutableSize: sizes[3],
	}
	if len(sections) == 5 {
		result.NativePath, result.NativeSHA256, result.NativeSize = sections[4].path, digests[4], sizes[4]
	}
	return result, nil
}

func validateArtifactFD(artifact *os.File, expectedSize int64) error {
	var stat unix.Stat_t
	if err := unix.Fstat(int(artifact.Fd()), &stat); err != nil {
		return fmt.Errorf("%w: cannot stat descriptor", ErrUnsafeArtifactFD)
	}
	if stat.Mode&unix.S_IFMT != unix.S_IFREG || stat.Nlink != 1 || stat.Size != expectedSize {
		return fmt.Errorf("%w: descriptor facts rejected", ErrUnsafeArtifactFD)
	}
	flags, err := unix.FcntlInt(artifact.Fd(), unix.F_GETFL, 0)
	if err != nil || flags&unix.O_ACCMODE != unix.O_RDONLY {
		return fmt.Errorf("%w: descriptor is writable", ErrUnsafeArtifactFD)
	}
	return nil
}

func validateStagingDirectory(path string) error {
	info, err := os.Lstat(path)
	if err != nil || !info.IsDir() || info.Mode()&os.ModeSymlink != 0 || info.Mode().Perm() != 0700 {
		return fmt.Errorf("%w: staging directory policy rejected", ErrInvalidBundle)
	}
	stat, ok := info.Sys().(*syscall.Stat_t)
	if !ok || int(stat.Uid) != os.Geteuid() || int(stat.Gid) != os.Getegid() {
		return fmt.Errorf("%w: staging directory owner rejected", ErrInvalidBundle)
	}
	return nil
}

func writeSection(input io.Reader, path string, size int64, mode os.FileMode) (digest string, err error) {
	fd, err := unix.Open(path, unix.O_WRONLY|unix.O_CREAT|unix.O_EXCL|unix.O_NOFOLLOW|unix.O_CLOEXEC, uint32(mode.Perm()))
	if err != nil {
		return "", err
	}
	file := os.NewFile(uintptr(fd), path)
	remove := true
	defer func() {
		_ = file.Close()
		if remove {
			_ = os.Remove(path)
		}
	}()

	hash := sha256.New()
	written, err := io.CopyN(io.MultiWriter(file, hash), input, size)
	if err != nil || written != size {
		return "", io.ErrUnexpectedEOF
	}
	if err := file.Chmod(mode); err != nil {
		return "", err
	}
	if err := file.Sync(); err != nil {
		return "", err
	}
	if err := file.Close(); err != nil {
		return "", err
	}
	remove = false
	return hex.EncodeToString(hash.Sum(nil)), nil
}

func syncDirectory(path string) error {
	directory, err := os.Open(path)
	if err != nil {
		return err
	}
	defer directory.Close()
	return directory.Sync()
}

func validSHA256(value string) bool {
	if len(value) != sha256.Size*2 {
		return false
	}
	for _, character := range value {
		if !((character >= '0' && character <= '9') || (character >= 'a' && character <= 'f')) {
			return false
		}
	}
	return true
}
