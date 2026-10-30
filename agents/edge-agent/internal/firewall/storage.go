package firewall

import (
	"context"
	"crypto/rand"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"os"
	"path/filepath"
	"reflect"
	"runtime"
	"strings"
	"time"

	"github.com/google/uuid"
	"golang.org/x/sys/unix"
)

const (
	stateSchemaVersion = 1
	maxStateFileSize   = 16 << 20
)

type activeRecord struct {
	SchemaVersion int             `json:"schema_version"`
	Digest        string          `json:"digest"`
	AppliedAt     time.Time       `json:"applied_at"`
	Version       FirewallVersion `json:"version"`
	Scopes        []scopeRecord   `json:"scopes,omitempty"`
}

type scopeRecord struct {
	TenantID       string    `json:"tenant_id"`
	SiteID         string    `json:"site_id"`
	PolicyKind     string    `json:"policy_kind,omitempty"`
	PolicyID       string    `json:"policy_id,omitempty"`
	PolicyVersion  uint64    `json:"policy_version"`
	TaskRevision   uint64    `json:"task_revision"`
	IdempotencyKey string    `json:"idempotency_key"`
	CommandDigest  string    `json:"command_digest"`
	Entries        []Entry   `json:"entries"`
	AppliedAt      time.Time `json:"applied_at"`
}

type versionRecord struct {
	SchemaVersion int             `json:"schema_version"`
	Digest        string          `json:"digest"`
	Version       FirewallVersion `json:"version"`
}

type taskRecord struct {
	SchemaVersion int    `json:"schema_version"`
	Digest        string `json:"digest"`
	Result        Result `json:"result"`
}

type inflightRecord struct {
	SchemaVersion int             `json:"schema_version"`
	Digest        string          `json:"digest"`
	Command       FirewallVersion `json:"command"`
	Candidate     activeRecord    `json:"candidate"`
	Previous      *activeRecord   `json:"previous,omitempty"`
	StartedAt     time.Time       `json:"started_at"`
}

type diskStore struct {
	versionsDir  string
	tasksDir     string
	tmpDir       string
	inflightPath string
	rootFD       int
	versionsFD   int
	tasksFD      int
	tmpFD        int
}

func newDiskStore(configuredRoot string) (*diskStore, error) {
	if configuredRoot == "" || !filepath.IsAbs(configuredRoot) || filepath.Clean(configuredRoot) != configuredRoot || configuredRoot == string(filepath.Separator) {
		return nil, ErrInvalidPath
	}
	rootFD, err := openOrCreateStateRoot(configuredRoot)
	if err != nil {
		return nil, err
	}
	store := &diskStore{
		versionsDir: filepath.Join(configuredRoot, "versions"), tasksDir: filepath.Join(configuredRoot, "tasks"),
		tmpDir: filepath.Join(configuredRoot, "tmp"),
		rootFD: rootFD, versionsFD: -1, tasksFD: -1, tmpFD: -1,
	}
	store.inflightPath = filepath.Join(configuredRoot, "inflight.json")
	complete := false
	defer func() {
		if !complete {
			store.close()
		}
	}()
	for _, directory := range []struct {
		name   string
		target *int
	}{{"versions", &store.versionsFD}, {"tasks", &store.tasksFD}, {"tmp", &store.tmpFD}} {
		fd, openErr := openOrCreatePrivateDirectory(store.rootFD, directory.name)
		if openErr != nil {
			return nil, openErr
		}
		*directory.target = fd
	}
	unlock, err := store.lock(context.Background())
	if err != nil {
		return nil, err
	}
	defer unlock()
	if err := store.cleanupTemporaryFiles(); err != nil {
		return nil, err
	}
	complete = true
	runtime.SetFinalizer(store, (*diskStore).close)
	return store, nil
}

func openOrCreateStateRoot(path string) (int, error) {
	fd, err := unix.Open(string(filepath.Separator), unix.O_RDONLY|unix.O_DIRECTORY|unix.O_CLOEXEC, 0)
	if err != nil {
		return -1, fmt.Errorf("open firewall state root ancestor: %w", err)
	}
	parts := strings.Split(strings.TrimPrefix(path, string(filepath.Separator)), string(filepath.Separator))
	for _, part := range parts {
		next, openErr := unix.Openat(fd, part, unix.O_RDONLY|unix.O_DIRECTORY|unix.O_CLOEXEC|unix.O_NOFOLLOW, 0)
		if errors.Is(openErr, unix.ENOENT) {
			if mkdirErr := unix.Mkdirat(fd, part, 0o700); mkdirErr != nil && !errors.Is(mkdirErr, unix.EEXIST) {
				_ = unix.Close(fd)
				return -1, fmt.Errorf("create firewall state root: %w", mkdirErr)
			}
			next, openErr = unix.Openat(fd, part, unix.O_RDONLY|unix.O_DIRECTORY|unix.O_CLOEXEC|unix.O_NOFOLLOW, 0)
		}
		_ = unix.Close(fd)
		if openErr != nil {
			return -1, fmt.Errorf("%w: open firewall state root component", ErrInvalidPath)
		}
		fd = next
	}
	if err := validatePrivateDirectory(fd); err != nil {
		_ = unix.Close(fd)
		return -1, err
	}
	return fd, nil
}

func openOrCreatePrivateDirectory(parentFD int, name string) (int, error) {
	if err := unix.Mkdirat(parentFD, name, 0o700); err != nil && !errors.Is(err, unix.EEXIST) {
		return -1, fmt.Errorf("create firewall state directory: %w", err)
	}
	fd, err := unix.Openat(parentFD, name, unix.O_RDONLY|unix.O_DIRECTORY|unix.O_CLOEXEC|unix.O_NOFOLLOW, 0)
	if err != nil {
		return -1, ErrInvalidPath
	}
	if err := validatePrivateDirectory(fd); err != nil {
		_ = unix.Close(fd)
		return -1, err
	}
	return fd, nil
}

func validatePrivateDirectory(fd int) error {
	var stat unix.Stat_t
	if err := unix.Fstat(fd, &stat); err != nil {
		return fmt.Errorf("inspect firewall state directory: %w", err)
	}
	if stat.Mode&unix.S_IFMT != unix.S_IFDIR || stat.Mode&0o077 != 0 {
		return ErrInvalidPath
	}
	return nil
}

func (s *diskStore) close() {
	for _, fd := range []int{s.tmpFD, s.tasksFD, s.versionsFD, s.rootFD} {
		if fd >= 0 {
			_ = unix.Close(fd)
		}
	}
	s.rootFD, s.versionsFD, s.tasksFD, s.tmpFD = -1, -1, -1, -1
}

func validStateName(name string) bool {
	return name != "" && name != "." && name != ".." && filepath.Base(name) == name
}

func randomStateName(prefix, suffix string) (string, error) {
	var value [16]byte
	if _, err := rand.Read(value[:]); err != nil {
		return "", err
	}
	return fmt.Sprintf("%s%x%s", prefix, value, suffix), nil
}

func duplicateDirectory(fd int, path string) (*os.File, error) {
	duplicate, err := unix.Openat(fd, ".", unix.O_RDONLY|unix.O_DIRECTORY|unix.O_CLOEXEC, 0)
	if err != nil {
		return nil, err
	}
	file := os.NewFile(uintptr(duplicate), path)
	if file == nil {
		_ = unix.Close(duplicate)
		return nil, ErrInvalidPath
	}
	return file, nil
}

func descriptorDirectoryPath(fd int) (string, error) {
	var stat unix.Stat_t
	if err := unix.Fstat(fd, &stat); err != nil {
		return "", err
	}
	var path string
	switch runtime.GOOS {
	case "linux":
		path = fmt.Sprintf("/proc/%d/fd/%d", os.Getpid(), fd)
	case "darwin":
		path = fmt.Sprintf("/.vol/%d/%d", uint64(stat.Dev), uint64(stat.Ino))
	default:
		return "", ErrInvalidPath
	}
	var resolved unix.Stat_t
	if err := unix.Stat(path, &resolved); err != nil || stat.Dev != resolved.Dev || stat.Ino != resolved.Ino {
		return "", ErrInvalidPath
	}
	return path, nil
}

func regularFileAt(directoryFD int, name string) (unix.Stat_t, error) {
	var stat unix.Stat_t
	if !validStateName(name) {
		return stat, ErrInvalidPath
	}
	if err := unix.Fstatat(directoryFD, name, &stat, unix.AT_SYMLINK_NOFOLLOW); err != nil {
		return stat, err
	}
	if stat.Mode&unix.S_IFMT != unix.S_IFREG {
		return stat, ErrInvalidPath
	}
	return stat, nil
}

func (s *diskStore) cleanupTemporaryFiles() error {
	directory, err := duplicateDirectory(s.tmpFD, s.tmpDir)
	if err != nil {
		return fmt.Errorf("read firewall temporary directory: %w", err)
	}
	defer directory.Close()
	entries, err := directory.ReadDir(-1)
	if err != nil {
		return fmt.Errorf("read firewall temporary directory: %w", err)
	}
	for _, entry := range entries {
		if _, err := regularFileAt(s.tmpFD, entry.Name()); err != nil {
			return ErrInvalidPath
		}
		if err := unix.Unlinkat(s.tmpFD, entry.Name(), 0); err != nil {
			return fmt.Errorf("remove abandoned firewall temporary file: %w", err)
		}
	}
	return unix.Fsync(s.tmpFD)
}

func (s *diskStore) lock(ctx context.Context) (func(), error) {
	fd, err := unix.Openat(s.rootFD, "apply.lock", unix.O_CREAT|unix.O_RDWR|unix.O_CLOEXEC|unix.O_NOFOLLOW, 0o600)
	if err != nil {
		return nil, fmt.Errorf("open firewall apply lock: %w", err)
	}
	var stat unix.Stat_t
	if err := unix.Fstat(fd, &stat); err != nil || stat.Mode&unix.S_IFMT != unix.S_IFREG || stat.Mode&0o077 != 0 {
		_ = unix.Close(fd)
		return nil, ErrInvalidPath
	}
	ticker := time.NewTicker(10 * time.Millisecond)
	defer ticker.Stop()
	for {
		err = unix.Flock(fd, unix.LOCK_EX|unix.LOCK_NB)
		if err == nil {
			return func() {
				_ = unix.Flock(fd, unix.LOCK_UN)
				_ = unix.Close(fd)
			}, nil
		}
		if !errors.Is(err, unix.EWOULDBLOCK) && !errors.Is(err, unix.EAGAIN) {
			_ = unix.Close(fd)
			return nil, fmt.Errorf("lock firewall apply state: %w", err)
		}
		select {
		case <-ctx.Done():
			_ = unix.Close(fd)
			return nil, ctx.Err()
		case <-ticker.C:
		}
	}
}

func (s *diskStore) writeBatch(_ string, batch []byte) (string, error) {
	directoryPath, err := descriptorDirectoryPath(s.tmpFD)
	if err != nil {
		return "", fmt.Errorf("resolve firewall transaction directory: %w", err)
	}
	name, err := randomStateName(".firewall-batch-", ".nft")
	if err != nil {
		return "", fmt.Errorf("name firewall transaction: %w", err)
	}
	fd, err := unix.Openat(s.tmpFD, name, unix.O_WRONLY|unix.O_CREAT|unix.O_EXCL|unix.O_CLOEXEC|unix.O_NOFOLLOW, 0o600)
	if err != nil {
		return "", fmt.Errorf("create firewall transaction: %w", err)
	}
	file := os.NewFile(uintptr(fd), filepath.Join(directoryPath, name))
	if file == nil {
		_ = unix.Close(fd)
		_ = unix.Unlinkat(s.tmpFD, name, 0)
		return "", ErrInvalidPath
	}
	path := filepath.Join(directoryPath, name)
	ok := false
	defer func() {
		_ = file.Close()
		if !ok {
			_ = unix.Unlinkat(s.tmpFD, name, 0)
		}
	}()
	if _, err := file.Write(batch); err != nil {
		return "", fmt.Errorf("write firewall transaction: %w", err)
	}
	if err := file.Sync(); err != nil {
		return "", fmt.Errorf("sync firewall transaction: %w", err)
	}
	if err := file.Close(); err != nil {
		return "", fmt.Errorf("close firewall transaction: %w", err)
	}
	if err := unix.Fsync(s.tmpFD); err != nil {
		return "", fmt.Errorf("sync firewall transaction directory: %w", err)
	}
	ok = true
	return path, nil
}

func (s *diskStore) versionName(versionID string) string {
	return versionID + ".json"
}

func (s *diskStore) taskName(taskID string) string {
	return taskID + ".json"
}

func (s *diskStore) loadVersion(versionID string) (*versionRecord, error) {
	value := &versionRecord{}
	exists, err := readJSONAt(s.versionsFD, s.versionName(versionID), value)
	if err != nil || !exists {
		return nil, err
	}
	if value.SchemaVersion != stateSchemaVersion || value.Version.VersionID != versionID || value.Digest == "" {
		return nil, ErrCorruptState
	}
	return value, nil
}

func (s *diskStore) saveVersion(compiled CompiledVersion) error {
	existing, err := s.loadVersion(compiled.Version.VersionID)
	if err != nil {
		return err
	}
	if existing != nil {
		if existing.Digest != compiled.Digest {
			return ErrConflict
		}
		return nil
	}
	return writeJSONAtomicAt(s.versionsFD, s.versionName(compiled.Version.VersionID), versionRecord{
		SchemaVersion: stateSchemaVersion, Digest: compiled.Digest, Version: compiled.Version,
	})
}

func (s *diskStore) loadTask(taskID string) (*taskRecord, error) {
	value := &taskRecord{}
	exists, err := readJSONAt(s.tasksFD, s.taskName(taskID), value)
	if err != nil || !exists {
		return nil, err
	}
	if value.SchemaVersion != stateSchemaVersion || value.Result.TaskID != taskID || value.Digest == "" {
		return nil, ErrCorruptState
	}
	return value, nil
}

func (s *diskStore) saveTask(taskID, digest string, result Result) error {
	existing, err := s.loadTask(taskID)
	if err != nil {
		return err
	}
	if existing != nil {
		if existing.Digest == digest && reflect.DeepEqual(existing.Result, result) {
			return nil
		}
		if existing.Digest != digest || existing.Result.State != StateRollbackFailed || result.State == StateRollbackFailed {
			return ErrConflict
		}
	}
	return writeJSONAtomicAt(s.tasksFD, s.taskName(taskID), taskRecord{SchemaVersion: stateSchemaVersion, Digest: digest, Result: result})
}

func (s *diskStore) loadTaskByIdempotency(idempotencyKey string) (*taskRecord, error) {
	if idempotencyKey == "" {
		return nil, nil
	}
	directory, err := duplicateDirectory(s.tasksFD, s.tasksDir)
	if err != nil {
		return nil, fmt.Errorf("read firewall tasks: %w", err)
	}
	defer directory.Close()
	entries, err := directory.ReadDir(-1)
	if err != nil {
		return nil, fmt.Errorf("read firewall tasks: %w", err)
	}
	var found *taskRecord
	for _, entry := range entries {
		if entry.IsDir() || filepath.Ext(entry.Name()) != ".json" {
			return nil, ErrCorruptState
		}
		value := &taskRecord{}
		exists, err := readJSONAt(s.tasksFD, entry.Name(), value)
		if err != nil || !exists {
			return nil, err
		}
		if value.SchemaVersion != stateSchemaVersion || value.Digest == "" || value.Result.TaskID == "" {
			return nil, ErrCorruptState
		}
		if value.Result.IdempotencyKey != idempotencyKey {
			continue
		}
		if found != nil {
			return nil, ErrCorruptState
		}
		found = value
	}
	return found, nil
}

func (s *diskStore) loadActive() (*activeRecord, error) {
	value := &activeRecord{}
	exists, err := readJSONAt(s.rootFD, "active.json", value)
	if err != nil || !exists {
		return nil, err
	}
	if value.SchemaVersion != stateSchemaVersion || value.Digest == "" || value.Version.VersionID == "" || value.AppliedAt.IsZero() {
		return nil, ErrCorruptState
	}
	for index := range value.Scopes {
		if value.Scopes[index].PolicyKind == "" && value.Scopes[index].PolicyID == "" {
			if !canonicalUUID(value.Scopes[index].SiteID) {
				return nil, ErrCorruptState
			}
			value.Scopes[index].PolicyKind = "legacy_acl"
			value.Scopes[index].PolicyID = uuid.NewSHA1(uuid.MustParse(value.Scopes[index].SiteID), []byte("cdnca.firewall.legacy_acl")).String()
		}
		if !validPolicyIdentity(value.Scopes[index].PolicyKind, value.Scopes[index].PolicyID) {
			return nil, ErrCorruptState
		}
	}
	return value, nil
}

func (s *diskStore) saveActive(value activeRecord) error {
	return writeJSONAtomicAt(s.rootFD, "active.json", value)
}

func (s *diskStore) loadInflight() (*inflightRecord, error) {
	value := &inflightRecord{}
	exists, err := readJSONAt(s.rootFD, "inflight.json", value)
	if err != nil || !exists {
		return nil, err
	}
	if value.SchemaVersion != stateSchemaVersion || value.Digest == "" || value.Command.TaskID == "" ||
		value.Command.VersionID == "" || value.Candidate.Digest == "" || value.Candidate.Version.VersionID == "" ||
		value.Candidate.Version.TaskID != value.Command.TaskID || !validDigest(value.Digest) ||
		!validDigest(value.Candidate.Digest) || value.StartedAt.IsZero() {
		return nil, ErrCorruptState
	}
	legacyIdentity := value.Command.PolicyKind == "" && value.Command.PolicyID == "" && canonicalUUID(value.Command.SiteID)
	upgradeLegacyScopedVersion(&value.Command)
	upgradeLegacyScopedVersion(&value.Candidate.Version)
	if value.Previous != nil {
		upgradeLegacyActiveRecord(value.Previous)
	}
	normalized, digest, normalizeErr := normalize(value.Command)
	if normalizeErr != nil || digest != value.Digest && !legacyIdentity || !reflect.DeepEqual(normalized, value.Command) {
		return nil, ErrCorruptState
	}
	if legacyIdentity {
		value.Digest = digest
	}
	compiled, compileErr := Compile(value.Candidate.Version)
	if compileErr != nil || compiled.Digest != value.Candidate.Digest || !reflect.DeepEqual(compiled.Version, value.Candidate.Version) {
		return nil, ErrCorruptState
	}
	if value.Previous != nil {
		if value.Previous.Version.VersionID == "" || value.Previous.Version.TaskID == "" || !validDigest(value.Previous.Digest) {
			return nil, ErrCorruptState
		}
		previous, previousErr := Compile(value.Previous.Version)
		if previousErr != nil || previous.Digest != value.Previous.Digest || !reflect.DeepEqual(previous.Version, value.Previous.Version) {
			return nil, ErrCorruptState
		}
	}
	return value, nil
}

func upgradeLegacyScopedVersion(version *FirewallVersion) {
	if version == nil || version.TenantID == "" || version.SiteID == "" || version.PolicyKind != "" || version.PolicyID != "" || !canonicalUUID(version.SiteID) {
		return
	}
	version.PolicyKind = "legacy_acl"
	version.PolicyID = uuid.NewSHA1(uuid.MustParse(version.SiteID), []byte("cdnca.firewall.legacy_acl")).String()
}

func upgradeLegacyActiveRecord(value *activeRecord) {
	if value == nil {
		return
	}
	for index := range value.Scopes {
		if value.Scopes[index].PolicyKind == "" && value.Scopes[index].PolicyID == "" && canonicalUUID(value.Scopes[index].SiteID) {
			value.Scopes[index].PolicyKind = "legacy_acl"
			value.Scopes[index].PolicyID = uuid.NewSHA1(uuid.MustParse(value.Scopes[index].SiteID), []byte("cdnca.firewall.legacy_acl")).String()
		}
	}
}

func (s *diskStore) saveInflight(value inflightRecord) error {
	existing, err := s.loadInflight()
	if err != nil {
		return err
	}
	if existing != nil && !reflect.DeepEqual(existing, &value) {
		return ErrConflict
	}
	return writeJSONAtomicAt(s.rootFD, "inflight.json", value)
}

func (s *diskStore) clearInflight() error {
	if err := unix.Unlinkat(s.rootFD, "inflight.json", 0); err != nil && !errors.Is(err, unix.ENOENT) {
		return fmt.Errorf("remove firewall in-flight journal: %w", err)
	}
	return unix.Fsync(s.rootFD)
}

func readJSONAt(directoryFD int, name string, target any) (bool, error) {
	if !validStateName(name) {
		return false, ErrInvalidPath
	}
	fd, err := unix.Openat(directoryFD, name, unix.O_RDONLY|unix.O_CLOEXEC|unix.O_NOFOLLOW, 0)
	if errors.Is(err, unix.ENOENT) {
		return false, nil
	}
	if err != nil {
		return false, fmt.Errorf("open firewall state: %w", err)
	}
	file := os.NewFile(uintptr(fd), name)
	if file == nil {
		_ = unix.Close(fd)
		return false, ErrInvalidPath
	}
	defer file.Close()
	info, err := file.Stat()
	if err != nil || !info.Mode().IsRegular() || info.Mode().Perm()&0o077 != 0 || info.Mode().Perm()&0o400 == 0 ||
		info.Size() < 2 || info.Size() > maxStateFileSize {
		return false, ErrCorruptState
	}
	decoder := json.NewDecoder(io.LimitReader(file, maxStateFileSize+1))
	decoder.DisallowUnknownFields()
	if err := decoder.Decode(target); err != nil {
		return false, ErrCorruptState
	}
	if err := decoder.Decode(&struct{}{}); !errors.Is(err, io.EOF) {
		return false, ErrCorruptState
	}
	return true, nil
}

func writeJSONAtomicAt(directoryFD int, name string, value any) error {
	if !validStateName(name) {
		return ErrInvalidPath
	}
	encoded, err := json.Marshal(value)
	if err != nil {
		return ErrCorruptState
	}
	temporary, err := randomStateName(".firewall-state-", ".tmp")
	if err != nil {
		return fmt.Errorf("name firewall state: %w", err)
	}
	fd, err := unix.Openat(directoryFD, temporary, unix.O_WRONLY|unix.O_CREAT|unix.O_EXCL|unix.O_CLOEXEC|unix.O_NOFOLLOW, 0o600)
	if err != nil {
		return fmt.Errorf("create firewall state: %w", err)
	}
	file := os.NewFile(uintptr(fd), temporary)
	if file == nil {
		_ = unix.Close(fd)
		_ = unix.Unlinkat(directoryFD, temporary, 0)
		return ErrInvalidPath
	}
	defer func() {
		_ = file.Close()
		_ = unix.Unlinkat(directoryFD, temporary, 0)
	}()
	if _, err := file.Write(encoded); err != nil {
		return fmt.Errorf("write firewall state: %w", err)
	}
	if err := file.Sync(); err != nil {
		return fmt.Errorf("sync firewall state: %w", err)
	}
	if err := file.Close(); err != nil {
		return fmt.Errorf("close firewall state: %w", err)
	}
	if err := unix.Renameat(directoryFD, temporary, directoryFD, name); err != nil {
		return fmt.Errorf("activate firewall state: %w", err)
	}
	return unix.Fsync(directoryFD)
}
