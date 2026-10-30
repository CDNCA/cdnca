package l4runtime

import (
	"bytes"
	"context"
	"encoding/hex"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"net/netip"
	"os"
	"path/filepath"
	"strings"
	"syscall"
	"time"
)

const stateSchemaVersion = 1

const (
	activationJournalSchemaVersion = 1
	activationOperationApply       = "apply"
	activationOperationRollback    = "rollback"
)

type storedRuntimeV2 struct {
	Config      ConfigV2            `json:"config"`
	AddressSets map[string][]string `json:"address_sets"`
}

type activeRecord struct {
	SchemaVersion int       `json:"schema_version"`
	VersionID     string    `json:"version_id"`
	Digest        string    `json:"digest"`
	VersionDir    string    `json:"version_dir"`
	AppliedAt     time.Time `json:"applied_at"`
}

type activationJournal struct {
	SchemaVersion int           `json:"schema_version"`
	Operation     string        `json:"operation"`
	Candidate     activeRecord  `json:"candidate"`
	Previous      *activeRecord `json:"previous,omitempty"`
	CreatedAt     time.Time     `json:"created_at"`
}

type diskStore struct {
	root                  string
	versionsDir           string
	temporaryDir          string
	stateDir              string
	runDir                string
	currentPath           string
	activePath            string
	activationJournalPath string
	lockPath              string
}

func newDiskStore(configuredRoot string) (*diskStore, error) {
	if configuredRoot == "" || !filepath.IsAbs(configuredRoot) || filepath.Clean(configuredRoot) != configuredRoot || configuredRoot == string(filepath.Separator) {
		return nil, ErrInvalidPath
	}
	if info, err := os.Lstat(configuredRoot); err == nil && info.Mode()&os.ModeSymlink != 0 {
		return nil, ErrInvalidPath
	} else if err != nil && !errors.Is(err, os.ErrNotExist) {
		return nil, fmt.Errorf("inspect L4 state root: %w", err)
	}
	if err := os.MkdirAll(configuredRoot, 0o700); err != nil {
		return nil, fmt.Errorf("create L4 state root: %w", err)
	}
	realRoot, err := filepath.EvalSymlinks(configuredRoot)
	if err != nil || realRoot == string(filepath.Separator) {
		return nil, ErrInvalidPath
	}
	if err := ensurePrivateDirectory(realRoot); err != nil {
		return nil, err
	}
	store := &diskStore{
		root: realRoot, versionsDir: filepath.Join(realRoot, "versions"), temporaryDir: filepath.Join(realRoot, "tmp"),
		stateDir: filepath.Join(realRoot, "state"), runDir: filepath.Join(realRoot, "run"),
		currentPath: filepath.Join(realRoot, "current"), activePath: filepath.Join(realRoot, "state", "active.json"),
		activationJournalPath: filepath.Join(realRoot, "state", "activation-journal.json"),
		lockPath:              filepath.Join(realRoot, "state", "apply.lock"),
	}
	for _, directory := range []string{store.versionsDir, store.temporaryDir, store.stateDir, store.runDir} {
		if err := ensurePrivateDirectory(directory); err != nil {
			return nil, err
		}
	}
	unlock, err := store.lock(context.Background())
	if err != nil {
		return nil, err
	}
	defer unlock()
	if err := store.cleanupTemporary(); err != nil {
		return nil, err
	}
	journal, err := store.loadActivationJournal()
	if err != nil {
		return nil, err
	}
	if journal == nil {
		if err := store.reconcileCurrent(); err != nil {
			return nil, err
		}
	}
	return store, nil
}

func ensurePrivateDirectory(path string) error {
	info, err := os.Lstat(path)
	if errors.Is(err, os.ErrNotExist) {
		if err := os.Mkdir(path, 0o700); err != nil {
			return fmt.Errorf("create L4 state directory: %w", err)
		}
		return nil
	}
	if err != nil || info.Mode()&os.ModeSymlink != 0 || !info.IsDir() || info.Mode().Perm()&0o077 != 0 {
		return ErrInvalidPath
	}
	return nil
}

func (s *diskStore) lock(ctx context.Context) (func(), error) {
	file, err := os.OpenFile(s.lockPath, os.O_CREATE|os.O_RDWR|syscall.O_NOFOLLOW, 0o600)
	if err != nil {
		return nil, fmt.Errorf("open L4 apply lock: %w", err)
	}
	info, err := file.Stat()
	if err != nil || !info.Mode().IsRegular() || info.Mode().Perm()&0o077 != 0 {
		_ = file.Close()
		return nil, ErrInvalidPath
	}
	ticker := time.NewTicker(10 * time.Millisecond)
	defer ticker.Stop()
	for {
		err = syscall.Flock(int(file.Fd()), syscall.LOCK_EX|syscall.LOCK_NB)
		if err == nil {
			return func() {
				_ = syscall.Flock(int(file.Fd()), syscall.LOCK_UN)
				_ = file.Close()
			}, nil
		}
		if !errors.Is(err, syscall.EWOULDBLOCK) && !errors.Is(err, syscall.EAGAIN) {
			_ = file.Close()
			return nil, fmt.Errorf("lock L4 apply state: %w", err)
		}
		select {
		case <-ctx.Done():
			_ = file.Close()
			return nil, ctx.Err()
		case <-ticker.C:
		}
	}
}

func (s *diskStore) stage(compiled CompiledConfig) (string, error) {
	path, err := os.MkdirTemp(s.temporaryDir, compiled.Config.VersionID+"-")
	if err != nil {
		return "", fmt.Errorf("create L4 staging directory: %w", err)
	}
	if err := os.Chmod(path, 0o700); err != nil {
		_ = os.RemoveAll(path)
		return "", fmt.Errorf("protect L4 staging directory: %w", err)
	}
	if err := writeFileSynced(filepath.Join(path, "config.json"), compiled.CanonicalJSON); err != nil {
		_ = os.RemoveAll(path)
		return "", err
	}
	if err := writeFileSynced(filepath.Join(path, "nginx.conf"), compiled.NginxConfig); err != nil {
		_ = os.RemoveAll(path)
		return "", err
	}
	if err := syncDirectory(path); err != nil {
		_ = os.RemoveAll(path)
		return "", err
	}
	return path, nil
}

func (s *diskStore) stageV2(compiled CompiledConfigV2) (string, error) {
	path, err := os.MkdirTemp(s.temporaryDir, compiled.Config.VersionID+"-")
	if err != nil {
		return "", fmt.Errorf("create L4 v2 staging directory: %w", err)
	}
	if err := os.Chmod(path, 0o700); err != nil {
		_ = os.RemoveAll(path)
		return "", fmt.Errorf("protect L4 v2 staging directory: %w", err)
	}
	runtimeJSON, err := encodeStoredRuntimeV2(compiled)
	if err == nil {
		err = writeFileSynced(filepath.Join(path, "runtime.json"), runtimeJSON)
	}
	if err == nil {
		err = writeFileSynced(filepath.Join(path, "config.json"), compiled.GeoJSON)
	}
	if err == nil {
		err = writeFileSynced(filepath.Join(path, "nginx.conf"), compiled.NginxConfig)
	}
	if err == nil {
		err = syncDirectory(path)
	}
	if err != nil {
		_ = os.RemoveAll(path)
		return "", err
	}
	return path, nil
}

func encodeStoredRuntimeV2(compiled CompiledConfigV2) ([]byte, error) {
	document := storedRuntimeV2{Config: compiled.Config, AddressSets: make(map[string][]string, len(compiled.ResolvedAddressSets))}
	for streamID, addresses := range compiled.ResolvedAddressSets {
		for _, address := range addresses {
			document.AddressSets[streamID] = append(document.AddressSets[streamID], address.String())
		}
	}
	content, err := json.Marshal(document)
	if err != nil {
		return nil, ErrInvalidConfig
	}
	return append(content, '\n'), nil
}

func decodeStoredRuntimeV2(content []byte) (CompiledConfigV2, error) {
	var document storedRuntimeV2
	decoder := json.NewDecoder(bytes.NewReader(content))
	decoder.DisallowUnknownFields()
	if err := decoder.Decode(&document); err != nil || ensureJSONEOF(decoder) != nil {
		return CompiledConfigV2{}, ErrCorruptState
	}
	addressSets := make(map[string][]netip.Addr, len(document.AddressSets))
	for streamID, values := range document.AddressSets {
		for _, value := range values {
			address, err := netip.ParseAddr(value)
			if err != nil {
				return CompiledConfigV2{}, ErrCorruptState
			}
			addressSets[streamID] = append(addressSets[streamID], address)
		}
	}
	compiled, err := CompileV2(document.Config, addressSets)
	if err != nil {
		return CompiledConfigV2{}, ErrCorruptState
	}
	return compiled, nil
}

func writeFileSynced(path string, content []byte) error {
	file, err := os.OpenFile(path, os.O_CREATE|os.O_EXCL|os.O_WRONLY, 0o600)
	if err != nil {
		return fmt.Errorf("create L4 configuration file: %w", err)
	}
	ok := false
	defer func() {
		_ = file.Close()
		if !ok {
			_ = os.Remove(path)
		}
	}()
	if _, err := file.Write(content); err != nil {
		return fmt.Errorf("write L4 configuration file: %w", err)
	}
	if err := file.Sync(); err != nil {
		return fmt.Errorf("sync L4 configuration file: %w", err)
	}
	if err := file.Close(); err != nil {
		return fmt.Errorf("close L4 configuration file: %w", err)
	}
	ok = true
	return nil
}

func (s *diskStore) commitStage(stagePath string, compiled CompiledConfig) (string, error) {
	versionDir := compiled.Config.VersionID + "-" + compiled.Digest
	destination := filepath.Join(s.versionsDir, versionDir)
	entries, err := os.ReadDir(s.versionsDir)
	if err != nil {
		return "", fmt.Errorf("read L4 versions: %w", err)
	}
	for _, entry := range entries {
		existingVersionID, _, valid := parseVersionDirectoryName(entry.Name())
		if !valid || !entry.IsDir() {
			return "", ErrCorruptState
		}
		if existingVersionID == compiled.Config.VersionID && entry.Name() != versionDir {
			return "", ErrConflict
		}
	}
	if info, err := os.Lstat(destination); err == nil {
		if info.Mode()&os.ModeSymlink != 0 || !info.IsDir() {
			return "", ErrCorruptState
		}
		if err := verifyVersionDirectory(destination, compiled); err != nil {
			return "", err
		}
		return versionDir, nil
	} else if !errors.Is(err, os.ErrNotExist) {
		return "", fmt.Errorf("inspect L4 version directory: %w", err)
	}
	for _, name := range []string{"config.json", "nginx.conf"} {
		if err := os.Chmod(filepath.Join(stagePath, name), 0o400); err != nil {
			return "", fmt.Errorf("seal L4 version file: %w", err)
		}
	}
	if err := os.Rename(stagePath, destination); err != nil {
		return "", fmt.Errorf("commit L4 version: %w", err)
	}
	if err := os.Chmod(destination, 0o500); err != nil {
		_ = makeRemovable(destination)
		_ = os.RemoveAll(destination)
		return "", fmt.Errorf("seal L4 version directory: %w", err)
	}
	if err := syncDirectory(s.versionsDir); err != nil {
		return "", err
	}
	return versionDir, nil
}

func (s *diskStore) commitStageV2(stagePath string, compiled CompiledConfigV2) (string, error) {
	versionDir := compiled.Config.VersionID + "-" + compiled.Digest
	destination := filepath.Join(s.versionsDir, versionDir)
	entries, err := os.ReadDir(s.versionsDir)
	if err != nil {
		return "", fmt.Errorf("read L4 versions: %w", err)
	}
	for _, entry := range entries {
		existingVersionID, _, valid := parseVersionDirectoryName(entry.Name())
		if !valid || !entry.IsDir() {
			return "", ErrCorruptState
		}
		if existingVersionID == compiled.Config.VersionID && entry.Name() != versionDir {
			return "", ErrConflict
		}
	}
	if info, err := os.Lstat(destination); err == nil {
		if info.Mode()&os.ModeSymlink != 0 || !info.IsDir() {
			return "", ErrCorruptState
		}
		if err := verifyVersionDirectoryV2(destination, compiled); err != nil {
			return "", err
		}
		return versionDir, nil
	} else if !errors.Is(err, os.ErrNotExist) {
		return "", fmt.Errorf("inspect L4 v2 version directory: %w", err)
	}
	for _, name := range []string{"runtime.json", "config.json", "nginx.conf"} {
		if err := os.Chmod(filepath.Join(stagePath, name), 0o400); err != nil {
			return "", fmt.Errorf("seal L4 v2 version file: %w", err)
		}
	}
	if err := os.Rename(stagePath, destination); err != nil {
		return "", fmt.Errorf("commit L4 v2 version: %w", err)
	}
	if err := os.Chmod(destination, 0o500); err != nil {
		_ = makeRemovable(destination)
		_ = os.RemoveAll(destination)
		return "", fmt.Errorf("seal L4 v2 version directory: %w", err)
	}
	if err := syncDirectory(s.versionsDir); err != nil {
		return "", err
	}
	return versionDir, nil
}

func verifyVersionDirectory(path string, compiled CompiledConfig) error {
	directoryInfo, err := os.Lstat(path)
	if err != nil || directoryInfo.Mode()&os.ModeSymlink != 0 || !directoryInfo.IsDir() || directoryInfo.Mode().Perm() != 0o500 {
		return ErrCorruptState
	}
	for name, expected := range map[string][]byte{"config.json": compiled.CanonicalJSON, "nginx.conf": compiled.NginxConfig} {
		filePath := filepath.Join(path, name)
		info, err := os.Lstat(filePath)
		if err != nil || !info.Mode().IsRegular() || info.Mode().Perm() != 0o400 {
			return ErrCorruptState
		}
		actual, err := readRegularFile(filePath)
		if err != nil || string(actual) != string(expected) {
			return ErrConflict
		}
	}
	return nil
}

func verifyVersionDirectoryV2(path string, compiled CompiledConfigV2) error {
	directoryInfo, err := os.Lstat(path)
	if err != nil || directoryInfo.Mode()&os.ModeSymlink != 0 || !directoryInfo.IsDir() || directoryInfo.Mode().Perm() != 0o500 {
		return ErrCorruptState
	}
	runtimeJSON, err := encodeStoredRuntimeV2(compiled)
	if err != nil {
		return err
	}
	for name, expected := range map[string][]byte{"runtime.json": runtimeJSON, "config.json": compiled.GeoJSON, "nginx.conf": compiled.NginxConfig} {
		filePath := filepath.Join(path, name)
		info, err := os.Lstat(filePath)
		if err != nil || !info.Mode().IsRegular() || info.Mode().Perm() != 0o400 {
			return ErrCorruptState
		}
		actual, err := readRegularFile(filePath)
		if err != nil || !bytes.Equal(actual, expected) {
			return ErrConflict
		}
	}
	return nil
}

func (s *diskStore) switchCurrent(versionDir string) error {
	if !validVersionDirectoryName(versionDir) {
		return ErrCorruptState
	}
	destination := filepath.Join(s.versionsDir, versionDir)
	if info, err := os.Lstat(destination); err != nil || info.Mode()&os.ModeSymlink != 0 || !info.IsDir() {
		return ErrCorruptState
	}
	temporary := s.currentPath + ".new"
	if err := os.Remove(temporary); err != nil && !errors.Is(err, os.ErrNotExist) {
		return fmt.Errorf("remove stale L4 pointer: %w", err)
	}
	if err := os.Symlink(filepath.Join("versions", versionDir), temporary); err != nil {
		return fmt.Errorf("create L4 current pointer: %w", err)
	}
	if err := os.Rename(temporary, s.currentPath); err != nil {
		_ = os.Remove(temporary)
		return fmt.Errorf("activate L4 current pointer: %w", err)
	}
	return syncDirectory(s.root)
}

func (s *diskStore) clearCurrent() error {
	info, err := os.Lstat(s.currentPath)
	if errors.Is(err, os.ErrNotExist) {
		return nil
	}
	if err != nil || info.Mode()&os.ModeSymlink == 0 {
		return ErrCorruptState
	}
	if err := os.Remove(s.currentPath); err != nil {
		return fmt.Errorf("remove L4 current pointer: %w", err)
	}
	return syncDirectory(s.root)
}

func (s *diskStore) loadActive() (*activeRecord, error) {
	content, err := readRegularFile(s.activePath)
	if errors.Is(err, os.ErrNotExist) {
		return nil, nil
	}
	if err != nil {
		return nil, err
	}
	var active activeRecord
	if err := json.Unmarshal(content, &active); err != nil {
		return nil, ErrCorruptState
	}
	if err := s.validateActiveRecord(active); err != nil {
		return nil, err
	}
	return &active, nil
}

func (s *diskStore) validateActiveRecord(active activeRecord) error {
	if active.SchemaVersion != stateSchemaVersion || !identifierPattern.MatchString(active.VersionID) ||
		!validDigest(active.Digest) || active.VersionDir != active.VersionID+"-"+active.Digest || active.AppliedAt.IsZero() {
		return ErrCorruptState
	}
	versionPath := filepath.Join(s.versionsDir, active.VersionDir)
	if runtimeJSON, runtimeErr := readRegularFile(filepath.Join(versionPath, "runtime.json")); runtimeErr == nil {
		compiledV2, err := decodeStoredRuntimeV2(runtimeJSON)
		if err != nil || compiledV2.Config.VersionID != active.VersionID || compiledV2.Digest != active.Digest ||
			verifyVersionDirectoryV2(versionPath, compiledV2) != nil {
			return ErrCorruptState
		}
		return nil
	} else if !errors.Is(runtimeErr, os.ErrNotExist) {
		return ErrCorruptState
	}
	configJSON, err := readRegularFile(filepath.Join(versionPath, "config.json"))
	if err != nil {
		return ErrCorruptState
	}
	var config Config
	if err := json.Unmarshal(configJSON, &config); err != nil {
		return ErrCorruptState
	}
	compiled, err := Compile(config)
	if err != nil || compiled.Digest != active.Digest || verifyVersionDirectory(versionPath, compiled) != nil {
		return ErrCorruptState
	}
	return nil
}

func (s *diskStore) loadVersion(versionID, digest string) (CompiledConfig, string, error) {
	if !identifierPattern.MatchString(versionID) || !validDigest(digest) {
		return CompiledConfig{}, "", ErrInvalidConfig
	}
	versionDir := versionID + "-" + digest
	versionPath := filepath.Join(s.versionsDir, versionDir)
	if runtimeJSON, runtimeErr := readRegularFile(filepath.Join(versionPath, "runtime.json")); runtimeErr == nil {
		compiledV2, err := decodeStoredRuntimeV2(runtimeJSON)
		if err != nil || compiledV2.Config.VersionID != versionID || compiledV2.Digest != digest ||
			verifyVersionDirectoryV2(versionPath, compiledV2) != nil {
			return CompiledConfig{}, "", ErrCorruptState
		}
		return compatibleCompiledV2(compiledV2), versionDir, nil
	} else if !errors.Is(runtimeErr, os.ErrNotExist) {
		return CompiledConfig{}, "", ErrCorruptState
	}
	configJSON, err := readRegularFile(filepath.Join(versionPath, "config.json"))
	if err != nil {
		return CompiledConfig{}, "", fmt.Errorf("read L4 rollback version: %w", err)
	}
	var config Config
	if err := json.Unmarshal(configJSON, &config); err != nil {
		return CompiledConfig{}, "", ErrCorruptState
	}
	compiled, err := Compile(config)
	if err != nil || compiled.Config.VersionID != versionID || compiled.Digest != digest {
		return CompiledConfig{}, "", ErrCorruptState
	}
	if err := verifyVersionDirectory(versionPath, compiled); err != nil {
		return CompiledConfig{}, "", err
	}
	return compiled, versionDir, nil
}

func (s *diskStore) saveActive(active activeRecord) error {
	content, err := json.Marshal(active)
	if err != nil {
		return ErrCorruptState
	}
	return writeAtomic(s.stateDir, s.activePath, append(content, '\n'))
}

func (s *diskStore) restoreActive(active *activeRecord) error {
	if active != nil {
		return s.saveActive(*active)
	}
	info, err := os.Lstat(s.activePath)
	if errors.Is(err, os.ErrNotExist) {
		return nil
	}
	if err != nil || !info.Mode().IsRegular() {
		return ErrCorruptState
	}
	if err := os.Remove(s.activePath); err != nil {
		return fmt.Errorf("remove unconfirmed L4 active state: %w", err)
	}
	return syncDirectory(s.stateDir)
}

func (s *diskStore) saveActivationJournal(journal activationJournal) error {
	content, err := json.Marshal(journal)
	if err != nil {
		return ErrCorruptState
	}
	return writeAtomic(s.stateDir, s.activationJournalPath, append(content, '\n'))
}

func (s *diskStore) loadActivationJournal() (*activationJournal, error) {
	content, err := readRegularFile(s.activationJournalPath)
	if errors.Is(err, os.ErrNotExist) {
		return nil, nil
	}
	if err != nil {
		return nil, err
	}
	decoder := json.NewDecoder(bytes.NewReader(content))
	decoder.DisallowUnknownFields()
	var journal activationJournal
	if err := decoder.Decode(&journal); err != nil {
		return nil, ErrCorruptState
	}
	if err := decoder.Decode(&struct{}{}); !errors.Is(err, io.EOF) {
		return nil, ErrCorruptState
	}
	if journal.SchemaVersion != activationJournalSchemaVersion || journal.CreatedAt.IsZero() ||
		(journal.Operation != activationOperationApply && journal.Operation != activationOperationRollback) {
		return nil, ErrCorruptState
	}
	if err := s.validateActiveRecord(journal.Candidate); err != nil {
		return nil, err
	}
	if journal.Previous != nil {
		if err := s.validateActiveRecord(*journal.Previous); err != nil || sameActiveRecord(journal.Previous, &journal.Candidate) {
			return nil, ErrCorruptState
		}
	}
	return &journal, nil
}

func (s *diskStore) clearActivationJournal() error {
	info, err := os.Lstat(s.activationJournalPath)
	if errors.Is(err, os.ErrNotExist) {
		return nil
	}
	if err != nil || !info.Mode().IsRegular() {
		return ErrCorruptState
	}
	if err := os.Remove(s.activationJournalPath); err != nil {
		return fmt.Errorf("remove L4 activation journal: %w", err)
	}
	return syncDirectory(s.stateDir)
}

func sameActiveRecord(left, right *activeRecord) bool {
	if left == nil || right == nil {
		return left == nil && right == nil
	}
	return left.SchemaVersion == right.SchemaVersion &&
		left.VersionID == right.VersionID && left.Digest == right.Digest && left.VersionDir == right.VersionDir &&
		left.AppliedAt.Equal(right.AppliedAt)
}

func (s *diskStore) reconcileCurrent() error {
	active, err := s.loadActive()
	if err != nil {
		return err
	}
	if active == nil {
		return s.clearCurrent()
	}
	current, err := s.currentVersionDir()
	if err != nil {
		return err
	}
	if current == active.VersionDir {
		return nil
	}
	return s.switchCurrent(active.VersionDir)
}

func (s *diskStore) currentVersionDir() (string, error) {
	target, err := os.Readlink(s.currentPath)
	if errors.Is(err, os.ErrNotExist) {
		return "", nil
	}
	if err != nil {
		return "", ErrCorruptState
	}
	if filepath.Dir(target) != "versions" || filepath.Base(target) == "." || filepath.Clean(target) != target {
		return "", ErrCorruptState
	}
	versionDir := filepath.Base(target)
	if !validVersionDirectoryName(versionDir) {
		return "", ErrCorruptState
	}
	return versionDir, nil
}

func (s *diskStore) cleanupTemporary() error {
	entries, err := os.ReadDir(s.temporaryDir)
	if err != nil {
		return fmt.Errorf("read L4 temporary directory: %w", err)
	}
	for _, entry := range entries {
		path := filepath.Join(s.temporaryDir, entry.Name())
		info, err := os.Lstat(path)
		if err != nil || info.Mode()&os.ModeSymlink != 0 || !info.IsDir() {
			return ErrInvalidPath
		}
		if err := makeRemovable(path); err != nil {
			return err
		}
		if err := os.RemoveAll(path); err != nil {
			return fmt.Errorf("remove abandoned L4 staging directory: %w", err)
		}
	}
	return syncDirectory(s.temporaryDir)
}

func readRegularFile(path string) ([]byte, error) {
	file, err := os.OpenFile(path, os.O_RDONLY|syscall.O_NOFOLLOW, 0)
	if err != nil {
		return nil, err
	}
	defer file.Close()
	info, err := file.Stat()
	if err != nil || !info.Mode().IsRegular() || info.Size() > maximumStateFileBytes {
		return nil, ErrCorruptState
	}
	content, err := io.ReadAll(io.LimitReader(file, maximumStateFileBytes+1))
	if err != nil || len(content) > maximumStateFileBytes {
		return nil, ErrCorruptState
	}
	return content, nil
}

func validVersionDirectoryName(value string) bool {
	_, _, valid := parseVersionDirectoryName(value)
	return valid
}

func parseVersionDirectoryName(value string) (string, string, bool) {
	separator := strings.LastIndexByte(value, '-')
	if separator <= 0 || !identifierPattern.MatchString(value[:separator]) || !validDigest(value[separator+1:]) {
		return "", "", false
	}
	return value[:separator], value[separator+1:], true
}

func validDigest(value string) bool {
	if len(value) != 64 {
		return false
	}
	decoded, err := hex.DecodeString(value)
	return err == nil && len(decoded) == 32 && strings.ToLower(value) == value
}

func makeRemovable(path string) error {
	if err := os.Chmod(path, 0o700); err != nil {
		return fmt.Errorf("make L4 staging directory removable: %w", err)
	}
	return nil
}

func writeAtomic(directory, destination string, content []byte) error {
	file, err := os.CreateTemp(directory, ".l4-state-")
	if err != nil {
		return fmt.Errorf("create L4 state file: %w", err)
	}
	temporary := file.Name()
	ok := false
	defer func() {
		_ = file.Close()
		if !ok {
			_ = os.Remove(temporary)
		}
	}()
	if err := file.Chmod(0o600); err != nil {
		return err
	}
	if _, err := file.Write(content); err != nil {
		return err
	}
	if err := file.Sync(); err != nil {
		return err
	}
	if err := file.Close(); err != nil {
		return err
	}
	if err := os.Rename(temporary, destination); err != nil {
		return err
	}
	if err := syncDirectory(directory); err != nil {
		return err
	}
	ok = true
	return nil
}

func syncDirectory(path string) error {
	directory, err := os.Open(path)
	if err != nil {
		return fmt.Errorf("open L4 state directory: %w", err)
	}
	defer directory.Close()
	if err := directory.Sync(); err != nil {
		return fmt.Errorf("sync L4 state directory: %w", err)
	}
	return nil
}
