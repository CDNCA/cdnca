//go:build linux || darwin

package diskguard

import (
	"bytes"
	"crypto/rand"
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"os"
	"path/filepath"
	"strings"
	"time"

	"golang.org/x/sys/unix"
)

const quarantinePrefix = ".cdnca-diskguard-quarantine-"
const quarantineRootName = quarantinePrefix + "private"
const quarantineIntentSuffix = ".intent.json"

const directoryReadBatchSize = 256

var errScanEntryLimit = errors.New("disk guard scan entry limit exceeded")

type fileIdentity struct {
	device uint64
	inode  uint64
	links  uint64
}

type openDirectory struct {
	fd       int
	path     string
	identity fileIdentity
	owner    uint32
	mode     uint32
}

type fileMetadata struct {
	identity       fileIdentity
	regular        bool
	size           int64
	allocatedBytes uint64
	modified       fileTimestamp
}

type fileTimestamp struct {
	seconds     int64
	nanoseconds int64
}

type filesystemUsage struct {
	totalBytes     uint64
	availableBytes uint64
}

type quarantineIntent struct {
	SchemaVersion         string `json:"schema_version"`
	ConfigID              string `json:"config_id"`
	ConfigRevision        uint64 `json:"config_revision"`
	DirectoryID           string `json:"directory_id"`
	DirectoryDevice       uint64 `json:"directory_device"`
	DirectoryInode        uint64 `json:"directory_inode"`
	PrivateRootDevice     uint64 `json:"private_root_device"`
	PrivateRootInode      uint64 `json:"private_root_inode"`
	NamespaceName         string `json:"namespace_name"`
	NamespaceDevice       uint64 `json:"namespace_device"`
	NamespaceInode        uint64 `json:"namespace_inode"`
	CandidateName         string `json:"candidate_name"`
	CandidateDevice       uint64 `json:"candidate_device"`
	CandidateInode        uint64 `json:"candidate_inode"`
	CandidateLinks        uint64 `json:"candidate_links"`
	CandidateSize         int64  `json:"candidate_size"`
	CandidateAllocated    uint64 `json:"candidate_allocated_bytes"`
	CandidateMtimeSeconds int64  `json:"candidate_mtime_seconds"`
	CandidateMtimeNanos   int64  `json:"candidate_mtime_nanoseconds"`
	Renamed               bool   `json:"renamed"`
}

func secureOpenDirectory(directoryPath string) (*openDirectory, error) {
	if !safeAbsolutePath(directoryPath) {
		return nil, ErrInvalidConfig
	}
	fd, err := unix.Open("/", unix.O_RDONLY|unix.O_DIRECTORY|unix.O_CLOEXEC, 0)
	if err != nil {
		return nil, err
	}
	parts := strings.Split(strings.TrimPrefix(directoryPath, "/"), "/")
	for _, part := range parts {
		if part == "" {
			continue
		}
		next, openErr := unix.Openat(fd, part, unix.O_RDONLY|unix.O_DIRECTORY|unix.O_CLOEXEC|unix.O_NOFOLLOW, 0)
		_ = unix.Close(fd)
		if openErr != nil {
			return nil, openErr
		}
		fd = next
	}
	var stat unix.Stat_t
	if err := unix.Fstat(fd, &stat); err != nil {
		_ = unix.Close(fd)
		return nil, err
	}
	return &openDirectory{
		fd: fd, path: directoryPath, identity: identityFromStat(stat), owner: stat.Uid, mode: uint32(stat.Mode),
	}, nil
}

func (directory *openDirectory) writableOnlyByOwner() bool {
	return directory.owner == uint32(os.Geteuid()) &&
		directory.mode&0o700 == 0o700 && directory.mode&0o022 == 0
}

func (directory *openDirectory) close() {
	_ = unix.Close(directory.fd)
}

func (directory *openDirectory) unchanged() bool {
	current, err := secureOpenDirectory(directory.path)
	if err != nil {
		return false
	}
	defer current.close()
	return current.identity.sameFile(directory.identity) && current.writableOnlyByOwner()
}

func (directory *openDirectory) names(maxEntries int) ([]string, error) {
	if maxEntries < 0 {
		return nil, errScanEntryLimit
	}
	duplicated, err := unix.Dup(directory.fd)
	if err != nil {
		return nil, err
	}
	file := os.NewFile(uintptr(duplicated), directory.path)
	if file == nil {
		_ = unix.Close(duplicated)
		return nil, errors.New("create directory file")
	}
	defer file.Close()
	names := make([]string, 0, min(maxEntries, directoryReadBatchSize))
	for {
		batchSize := min(directoryReadBatchSize, maxEntries-len(names)+1)
		entries, readErr := file.ReadDir(batchSize)
		for _, entry := range entries {
			names = append(names, entry.Name())
			if len(names) > maxEntries {
				return nil, errScanEntryLimit
			}
		}
		if errors.Is(readErr, io.EOF) {
			return names, nil
		}
		if readErr != nil {
			return nil, readErr
		}
	}
}

func (directory *openDirectory) metadata(name string) (fileMetadata, error) {
	if !safeBaseName(name) {
		return fileMetadata{}, ErrEvaluation
	}
	var stat unix.Stat_t
	if err := unix.Fstatat(directory.fd, name, &stat, unix.AT_SYMLINK_NOFOLLOW); err != nil {
		return fileMetadata{}, err
	}
	return metadataFromStat(stat), nil
}

func (directory *openDirectory) openRegular(name string) (int, fileMetadata, error) {
	before, err := directory.metadata(name)
	if err != nil {
		return -1, fileMetadata{}, err
	}
	if !before.regular || before.identity.links != 1 {
		return -1, fileMetadata{}, ErrEvaluation
	}
	fd, err := unix.Openat(directory.fd, name, unix.O_RDONLY|unix.O_CLOEXEC|unix.O_NOFOLLOW|unix.O_NONBLOCK, 0)
	if err != nil {
		return -1, fileMetadata{}, err
	}
	opened, err := metadataForFD(fd)
	if err != nil {
		_ = unix.Close(fd)
		return -1, fileMetadata{}, err
	}
	if !opened.regular || opened.identity.links != 1 || !opened.sameCandidate(before) {
		_ = unix.Close(fd)
		return -1, fileMetadata{}, ErrEvaluation
	}
	return fd, opened, nil
}

func (directory *openDirectory) usage() (filesystemUsage, error) {
	var stat unix.Statfs_t
	if err := unix.Fstatfs(directory.fd, &stat); err != nil {
		return filesystemUsage{}, err
	}
	if stat.Bsize <= 0 || stat.Blocks == 0 {
		return filesystemUsage{}, ErrEvaluation
	}
	blockSize := uint64(stat.Bsize)
	return filesystemUsage{
		totalBytes:     multiplySaturated(uint64(stat.Blocks), blockSize),
		availableBytes: multiplySaturated(uint64(stat.Bavail), blockSize),
	}, nil
}

func metadataForFD(fd int) (fileMetadata, error) {
	var stat unix.Stat_t
	if err := unix.Fstat(fd, &stat); err != nil {
		return fileMetadata{}, err
	}
	return metadataFromStat(stat), nil
}

func activationJournalPath(directoryPath, candidateName string) string {
	return filepath.Join(directoryPath, quarantineRootName, quarantineIntentName(candidateName))
}

func quarantineIntentName(candidateName string) string {
	digest := sha256.Sum256([]byte(candidateName))
	return quarantinePrefix + "intent-" + hex.EncodeToString(digest[:]) + quarantineIntentSuffix
}

func writeQuarantineIntent(root *openDirectory, intent quarantineIntent) error {
	if root == nil || !root.writableOnlyByOwner() || root.identity.device == 0 {
		return ErrEvaluation
	}
	payload, err := json.Marshal(intent)
	if err != nil || len(payload) > 64<<10 {
		return ErrEvaluation
	}
	name := quarantineIntentName(intent.CandidateName)
	temporary, err := randomIntentTempName()
	if err != nil {
		return err
	}
	fd, err := unix.Openat(root.fd, temporary, unix.O_WRONLY|unix.O_CREAT|unix.O_EXCL|unix.O_CLOEXEC|unix.O_NOFOLLOW, 0o600)
	if err != nil {
		return err
	}
	file := os.NewFile(uintptr(fd), filepath.Join(root.path, temporary))
	if file == nil {
		_ = unix.Close(fd)
		return ErrEvaluation
	}
	removeTemporary := true
	defer func() {
		_ = file.Close()
		if removeTemporary {
			_ = unix.Unlinkat(root.fd, temporary, 0)
		}
	}()
	if _, err := file.Write(payload); err != nil {
		return err
	}
	if err := file.Sync(); err != nil {
		return err
	}
	if err := file.Close(); err != nil {
		return err
	}
	if err := unix.Renameat(root.fd, temporary, root.fd, name); err != nil {
		return err
	}
	removeTemporary = false
	return unix.Fsync(root.fd)
}

func readQuarantineIntent(root *openDirectory, name string) (quarantineIntent, error) {
	var intent quarantineIntent
	if root == nil || !safeBaseName(name) || name != quarantineIntentNameForMarker(name) {
		return intent, ErrEvaluation
	}
	var stat unix.Stat_t
	if err := unix.Fstatat(root.fd, name, &stat, unix.AT_SYMLINK_NOFOLLOW); err != nil {
		return intent, err
	}
	identity := identityFromStat(stat)
	if identity.links != 1 || identity.device != root.identity.device || stat.Mode&unix.S_IFMT != unix.S_IFREG ||
		stat.Mode&0o777 != 0o600 || stat.Uid != uint32(os.Geteuid()) {
		return intent, ErrEvaluation
	}
	fd, err := unix.Openat(root.fd, name, unix.O_RDONLY|unix.O_CLOEXEC|unix.O_NOFOLLOW, 0)
	if err != nil {
		return intent, err
	}
	file := os.NewFile(uintptr(fd), filepath.Join(root.path, name))
	if file == nil {
		_ = unix.Close(fd)
		return intent, ErrEvaluation
	}
	defer file.Close()
	contents, err := io.ReadAll(io.LimitReader(file, 64<<10+1))
	if err != nil || len(contents) > 64<<10 {
		return intent, ErrEvaluation
	}
	decoder := json.NewDecoder(bytes.NewReader(contents))
	decoder.DisallowUnknownFields()
	if err := decoder.Decode(&intent); err != nil {
		return intent, err
	}
	var extra any
	if err := decoder.Decode(&extra); err != io.EOF {
		return intent, ErrEvaluation
	}
	return intent, nil
}

func quarantineIntentNameForMarker(name string) string {
	if !strings.HasPrefix(name, quarantinePrefix+"intent-") || !strings.HasSuffix(name, quarantineIntentSuffix) {
		return ""
	}
	return name
}

func clearQuarantineIntent(root *openDirectory, candidateName string) error {
	if root == nil {
		return ErrEvaluation
	}
	name := quarantineIntentName(candidateName)
	var stat unix.Stat_t
	if err := unix.Fstatat(root.fd, name, &stat, unix.AT_SYMLINK_NOFOLLOW); errors.Is(err, unix.ENOENT) {
		return nil
	} else if err != nil {
		return err
	}
	identity := identityFromStat(stat)
	if identity.links != 1 || identity.device != root.identity.device || stat.Mode&unix.S_IFMT != unix.S_IFREG ||
		stat.Mode&0o777 != 0o600 || stat.Uid != uint32(os.Geteuid()) {
		return ErrEvaluation
	}
	if err := unix.Unlinkat(root.fd, name, 0); err != nil && !errors.Is(err, unix.ENOENT) {
		return err
	}
	return unix.Fsync(root.fd)
}

func randomIntentTempName() (string, error) {
	value := make([]byte, 16)
	if _, err := rand.Read(value); err != nil {
		return "", err
	}
	return quarantinePrefix + "intent-tmp-" + hex.EncodeToString(value), nil
}

func syncDirectory(fd int) error {
	if fd < 0 {
		return ErrEvaluation
	}
	return unix.Fsync(fd)
}

func identityFromStat(stat unix.Stat_t) fileIdentity {
	return fileIdentity{device: uint64(stat.Dev), inode: uint64(stat.Ino), links: uint64(stat.Nlink)}
}

func metadataFromStat(stat unix.Stat_t) fileMetadata {
	allocated := uint64(0)
	if stat.Blocks > 0 {
		allocated = multiplySaturated(uint64(stat.Blocks), 512)
	}
	return fileMetadata{
		identity:       identityFromStat(stat),
		regular:        stat.Mode&unix.S_IFMT == unix.S_IFREG,
		size:           stat.Size,
		allocatedBytes: allocated,
		modified:       statMtime(stat),
	}
}

func (metadata fileMetadata) sameCandidate(other fileMetadata) bool {
	return metadata.identity.sameFile(other.identity) && metadata.identity.links == other.identity.links &&
		metadata.regular == other.regular && metadata.size == other.size &&
		metadata.allocatedBytes == other.allocatedBytes && metadata.modified == other.modified
}

func (timestamp fileTimestamp) valid() bool {
	return timestamp.nanoseconds >= 0 && timestamp.nanoseconds < int64(time.Second)
}

func (timestamp fileTimestamp) compare(other fileTimestamp) int {
	if timestamp.seconds < other.seconds {
		return -1
	}
	if timestamp.seconds > other.seconds {
		return 1
	}
	if timestamp.nanoseconds < other.nanoseconds {
		return -1
	}
	if timestamp.nanoseconds > other.nanoseconds {
		return 1
	}
	return 0
}

func (identity fileIdentity) sameFile(other fileIdentity) bool {
	return identity.device == other.device && identity.inode == other.inode
}

func multiplySaturated(left, right uint64) uint64 {
	if right != 0 && left > ^uint64(0)/right {
		return ^uint64(0)
	}
	return left * right
}

func acquireFileLock(lockPath string) (func(), error) {
	parent, err := secureOpenDirectory(filepath.Dir(lockPath))
	if err != nil {
		return nil, fmt.Errorf("%w: %v", ErrEvaluation, err)
	}
	defer parent.close()
	if !parent.writableOnlyByOwner() || !parent.unchanged() {
		return nil, ErrEvaluation
	}
	name := filepath.Base(lockPath)
	fd, err := unix.Openat(parent.fd, name, unix.O_RDWR|unix.O_CREAT|unix.O_CLOEXEC|unix.O_NOFOLLOW, 0o600)
	if err != nil {
		return nil, fmt.Errorf("%w: %v", ErrEvaluation, err)
	}
	var stat unix.Stat_t
	statErr := unix.Fstat(fd, &stat)
	identity := identityFromStat(stat)
	if statErr != nil || identity.links != 1 || stat.Mode&unix.S_IFMT != unix.S_IFREG || stat.Mode&0o077 != 0 {
		_ = unix.Close(fd)
		return nil, ErrEvaluation
	}
	if stat.Mode&0o600 != 0o600 || stat.Uid != uint32(os.Geteuid()) {
		_ = unix.Close(fd)
		return nil, ErrEvaluation
	}
	if !lockNameMatches(parent, name, identity) {
		_ = unix.Close(fd)
		return nil, ErrEvaluation
	}
	if err := unix.Flock(fd, unix.LOCK_EX|unix.LOCK_NB); err != nil {
		_ = unix.Close(fd)
		if errors.Is(err, unix.EWOULDBLOCK) || errors.Is(err, unix.EAGAIN) {
			return nil, ErrAlreadyRunning
		}
		return nil, fmt.Errorf("%w: %v", ErrEvaluation, err)
	}
	if !lockNameMatches(parent, name, identity) {
		_ = unix.Flock(fd, unix.LOCK_UN)
		_ = unix.Close(fd)
		return nil, ErrEvaluation
	}
	return func() {
		_ = unix.Flock(fd, unix.LOCK_UN)
		_ = unix.Close(fd)
	}, nil
}

func validateLockPath(lockPath string) error {
	parent, err := secureOpenDirectory(filepath.Dir(lockPath))
	if err != nil {
		return err
	}
	defer parent.close()
	var stat unix.Stat_t
	err = unix.Fstatat(parent.fd, filepath.Base(lockPath), &stat, unix.AT_SYMLINK_NOFOLLOW)
	if errors.Is(err, unix.ENOENT) {
		return nil
	}
	if err != nil {
		return err
	}
	identity := identityFromStat(stat)
	if identity.links != 1 || stat.Mode&unix.S_IFMT != unix.S_IFREG || stat.Mode&0o077 != 0 ||
		stat.Mode&0o600 != 0o600 || stat.Uid != uint32(os.Geteuid()) || !parent.unchanged() {
		return ErrEvaluation
	}
	return nil
}

func lockNameMatches(parent *openDirectory, name string, expected fileIdentity) bool {
	var stat unix.Stat_t
	if err := unix.Fstatat(parent.fd, name, &stat, unix.AT_SYMLINK_NOFOLLOW); err != nil {
		return false
	}
	identity := identityFromStat(stat)
	return parent.unchanged() && identity.links == 1 && identity.sameFile(expected) &&
		stat.Mode&unix.S_IFMT == unix.S_IFREG && stat.Mode&0o077 == 0 &&
		stat.Mode&0o600 == 0o600 && stat.Uid == uint32(os.Geteuid())
}

func randomQuarantineName() (string, error) {
	value := make([]byte, 16)
	if _, err := rand.Read(value); err != nil {
		return "", err
	}
	return quarantinePrefix + hex.EncodeToString(value), nil
}

func openPrivateQuarantineRoot(directory *openDirectory) (*openDirectory, error) {
	err := unix.Mkdirat(directory.fd, quarantineRootName, 0o700)
	if err != nil && !errors.Is(err, unix.EEXIST) {
		return nil, err
	}
	fd, err := unix.Openat(directory.fd, quarantineRootName, unix.O_RDONLY|unix.O_DIRECTORY|unix.O_CLOEXEC|unix.O_NOFOLLOW, 0)
	if err != nil {
		return nil, err
	}
	var stat unix.Stat_t
	if err := unix.Fstat(fd, &stat); err != nil {
		_ = unix.Close(fd)
		return nil, err
	}
	private := &openDirectory{
		fd: fd, path: filepath.Join(directory.path, quarantineRootName), identity: identityFromStat(stat),
		owner: stat.Uid, mode: uint32(stat.Mode),
	}
	if !private.writableOnlyByOwner() || private.identity.device != directory.identity.device ||
		!privateQuarantineMatches(directory, quarantineRootName, private) {
		private.close()
		return nil, ErrEvaluation
	}
	if err := syncDirectory(directory.fd); err != nil {
		private.close()
		return nil, err
	}
	return private, nil
}

func openExistingPrivateQuarantineRoot(directory *openDirectory) (*openDirectory, bool, error) {
	if directory == nil {
		return nil, false, ErrEvaluation
	}
	var stat unix.Stat_t
	if err := unix.Fstatat(directory.fd, quarantineRootName, &stat, unix.AT_SYMLINK_NOFOLLOW); errors.Is(err, unix.ENOENT) {
		return nil, false, nil
	} else if err != nil {
		return nil, false, err
	}
	root, err := openPrivateQuarantineRoot(directory)
	return root, err == nil, err
}

func createPrivateQuarantine(directory *openDirectory) (*openDirectory, string, error) {
	for attempt := 0; attempt < 4; attempt++ {
		name, err := randomQuarantineName()
		if err != nil {
			return nil, "", err
		}
		if err := unix.Mkdirat(directory.fd, name, 0o700); err != nil {
			if errors.Is(err, unix.EEXIST) {
				continue
			}
			return nil, "", err
		}
		fd, err := unix.Openat(directory.fd, name, unix.O_RDONLY|unix.O_DIRECTORY|unix.O_CLOEXEC|unix.O_NOFOLLOW, 0)
		if err != nil {
			return nil, "", err
		}
		var stat unix.Stat_t
		if err := unix.Fstat(fd, &stat); err != nil {
			_ = unix.Close(fd)
			return nil, "", err
		}
		private := &openDirectory{
			fd: fd, path: filepath.Join(directory.path, name), identity: identityFromStat(stat),
			owner: stat.Uid, mode: uint32(stat.Mode),
		}
		if !private.writableOnlyByOwner() || private.identity.device != directory.identity.device ||
			!privateQuarantineMatches(directory, name, private) {
			private.close()
			return nil, "", ErrEvaluation
		}
		if err := syncDirectory(directory.fd); err != nil {
			private.close()
			return nil, "", err
		}
		return private, name, nil
	}
	return nil, "", ErrEvaluation
}

func openPrivateQuarantine(directory *openDirectory, name string, expected fileIdentity) (*openDirectory, error) {
	if directory == nil || !safeBaseName(name) || !strings.HasPrefix(name, quarantinePrefix) ||
		name == quarantineRootName || expected.device != directory.identity.device {
		return nil, ErrEvaluation
	}
	fd, err := unix.Openat(directory.fd, name, unix.O_RDONLY|unix.O_DIRECTORY|unix.O_CLOEXEC|unix.O_NOFOLLOW, 0)
	if err != nil {
		return nil, err
	}
	var stat unix.Stat_t
	if err := unix.Fstat(fd, &stat); err != nil {
		_ = unix.Close(fd)
		return nil, err
	}
	private := &openDirectory{
		fd: fd, path: filepath.Join(directory.path, name), identity: identityFromStat(stat),
		owner: stat.Uid, mode: uint32(stat.Mode),
	}
	if !private.identity.sameFile(expected) || !private.writableOnlyByOwner() ||
		!privateQuarantineMatches(directory, name, private) {
		private.close()
		return nil, ErrEvaluation
	}
	return private, nil
}

func privateQuarantineMatches(parent *openDirectory, name string, private *openDirectory) bool {
	var stat unix.Stat_t
	if err := unix.Fstatat(parent.fd, name, &stat, unix.AT_SYMLINK_NOFOLLOW); err != nil {
		return false
	}
	identity := identityFromStat(stat)
	return parent.unchanged() && identity.sameFile(private.identity) && identity.device == parent.identity.device &&
		stat.Mode&unix.S_IFMT == unix.S_IFDIR && stat.Uid == uint32(os.Geteuid()) && stat.Mode&0o777 == 0o700
}

func removePrivateQuarantine(parent *openDirectory, name string, expected fileIdentity) {
	var stat unix.Stat_t
	if err := unix.Fstatat(parent.fd, name, &stat, unix.AT_SYMLINK_NOFOLLOW); err != nil {
		return
	}
	if identityFromStat(stat).sameFile(expected) && stat.Mode&unix.S_IFMT == unix.S_IFDIR {
		_ = unix.Unlinkat(parent.fd, name, unix.AT_REMOVEDIR)
	}
}

func removePrivateQuarantineDurable(parent *openDirectory, name string, expected fileIdentity) error {
	private, err := openPrivateQuarantine(parent, name, expected)
	if errors.Is(err, unix.ENOENT) {
		return nil
	}
	if err != nil {
		return err
	}
	names, err := private.names(0)
	private.close()
	if err != nil || len(names) != 0 {
		return ErrEvaluation
	}
	if err := unix.Unlinkat(parent.fd, name, unix.AT_REMOVEDIR); err != nil && !errors.Is(err, unix.ENOENT) {
		return err
	}
	return syncDirectory(parent.fd)
}

func restoreQuarantine(quarantine *openDirectory, name string, directory *openDirectory, original string) {
	if err := unix.Linkat(quarantine.fd, name, directory.fd, original, 0); err == nil {
		if err := unix.Unlinkat(quarantine.fd, name, 0); err == nil {
			_ = syncDirectory(quarantine.fd)
			_ = syncDirectory(directory.fd)
		}
	}
}

func unlinkQuarantined(directory *openDirectory, name string, fd int, expected fileMetadata) error {
	named, err := directory.metadata(name)
	opened, fdErr := metadataForFD(fd)
	if err != nil || fdErr != nil || !named.regular || named.identity.links != 1 ||
		!named.sameCandidate(expected) || !opened.sameCandidate(expected) ||
		named.identity.device != directory.identity.device {
		return ErrEvaluation
	}
	if err := unix.Unlinkat(directory.fd, name, 0); err != nil {
		return err
	}
	return syncDirectory(directory.fd)
}
