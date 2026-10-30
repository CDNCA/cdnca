package http3runtime

import (
	"bytes"
	"context"
	"crypto/hmac"
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
	"syscall"
	"time"
)

const quicHostKeyBytes = 80

var errCandidateAsset = errors.New("invalid HTTP/3 candidate asset")

const (
	activationJournalSchemaVersion = 1
	activationStagePrepared        = "prepared"
	activationStageConfirmed       = "confirmed"
)

type activeRecord struct {
	SchemaVersion int       `json:"schema_version"`
	VersionID     string    `json:"version_id"`
	Digest        string    `json:"digest"`
	VersionDir    string    `json:"version_dir"`
	AppliedAt     time.Time `json:"applied_at"`
}

type activationJournal struct {
	SchemaVersion int           `json:"schema_version"`
	Stage         string        `json:"stage"`
	Candidate     activeRecord  `json:"candidate"`
	Previous      *activeRecord `json:"previous,omitempty"`
	Evidence      string        `json:"evidence,omitempty"`
	CreatedAt     time.Time     `json:"created_at"`
	MAC           string        `json:"mac"`
}

type activationJournalPayload struct {
	SchemaVersion int           `json:"schema_version"`
	Stage         string        `json:"stage"`
	Candidate     activeRecord  `json:"candidate"`
	Previous      *activeRecord `json:"previous,omitempty"`
	Evidence      string        `json:"evidence,omitempty"`
	CreatedAt     time.Time     `json:"created_at"`
}

type diskStore struct {
	root, versionsDir, temporaryDir, stateDir, runDir        string
	currentPath, activePath, activationJournalPath, lockPath string
	quicHostKeyPath                                          string
}

func newDiskStore(configuredRoot string) (*diskStore, error) {
	if !safeAbsolutePath(configuredRoot) {
		return nil, ErrInvalidPath
	}
	if info, err := os.Lstat(configuredRoot); err == nil && info.Mode()&os.ModeSymlink != 0 {
		return nil, ErrInvalidPath
	} else if err != nil && !errors.Is(err, os.ErrNotExist) {
		return nil, err
	}
	if err := os.MkdirAll(configuredRoot, 0o700); err != nil {
		return nil, fmt.Errorf("create HTTP/3 state root: %w", err)
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
		quicHostKeyPath:       filepath.Join(realRoot, "state", releaseQUICHostKeyFile),
	}
	for _, directory := range []string{
		store.versionsDir,
		store.temporaryDir,
		store.stateDir,
		store.runDir,
		filepath.Join(store.runDir, "nginx-temp"),
	} {
		if err := ensurePrivateDirectory(directory); err != nil {
			return nil, err
		}
	}
	unlock, err := store.lock(context.Background())
	if err != nil {
		return nil, err
	}
	defer unlock()
	if err := store.ensureQUICHostKey(); err != nil {
		return nil, err
	}
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

func (s *diskStore) ensureQUICHostKey() error {
	key, err := readRegularFileWithMode(s.quicHostKeyPath, quicHostKeyBytes, 0o600)
	if err == nil {
		if len(key) != quicHostKeyBytes {
			return ErrCorruptState
		}
		return nil
	}
	if !errors.Is(err, os.ErrNotExist) {
		return ErrCorruptState
	}
	key = make([]byte, quicHostKeyBytes)
	if _, err := rand.Read(key); err != nil {
		return fmt.Errorf("generate QUIC host key: %w", err)
	}
	if err := writeFileSynced(s.quicHostKeyPath, key, 0o600); err != nil {
		return err
	}
	return syncDirectory(s.stateDir)
}

func (s *diskStore) loadQUICHostKey() ([]byte, error) {
	key, err := readRegularFileWithMode(s.quicHostKeyPath, quicHostKeyBytes, 0o600)
	if err != nil || len(key) != quicHostKeyBytes {
		return nil, ErrCorruptState
	}
	return key, nil
}

func ensurePrivateDirectory(path string) error {
	info, err := os.Lstat(path)
	if errors.Is(err, os.ErrNotExist) {
		if err := os.Mkdir(path, 0o700); err != nil {
			return err
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
		return nil, err
	}
	ticker := time.NewTicker(10 * time.Millisecond)
	defer ticker.Stop()
	for {
		if err = syscall.Flock(int(file.Fd()), syscall.LOCK_EX|syscall.LOCK_NB); err == nil {
			return func() {
				_ = syscall.Flock(int(file.Fd()), syscall.LOCK_UN)
				_ = file.Close()
			}, nil
		}
		if !errors.Is(err, syscall.EWOULDBLOCK) && !errors.Is(err, syscall.EAGAIN) {
			_ = file.Close()
			return nil, err
		}
		select {
		case <-ctx.Done():
			_ = file.Close()
			return nil, ctx.Err()
		case <-ticker.C:
		}
	}
}

func (s *diskStore) stage(compiled CompiledPolicy) (string, error) {
	path, err := os.MkdirTemp(s.temporaryDir, compiled.Policy.VersionID+"-")
	if err != nil {
		return "", err
	}
	if err := os.Chmod(path, 0o700); err != nil {
		_ = os.RemoveAll(path)
		return "", err
	}
	certificate, err := readVerifiedSource(compiled.Policy.TLS.CertificateFile, compiled.Policy.TLS.CertificateSHA256)
	if err != nil {
		_ = os.RemoveAll(path)
		return "", err
	}
	privateKey, err := readVerifiedSource(compiled.Policy.TLS.PrivateKeyFile, compiled.Policy.TLS.PrivateKeySHA256)
	if err != nil {
		_ = os.RemoveAll(path)
		return "", err
	}
	quicHostKey, err := s.loadQUICHostKey()
	if err != nil {
		_ = os.RemoveAll(path)
		return "", err
	}
	tlsPath := filepath.Join(path, releaseTLSDirectory)
	if err := os.Mkdir(tlsPath, 0o700); err != nil {
		_ = os.RemoveAll(path)
		return "", err
	}
	files := []struct {
		path    string
		content []byte
	}{
		{filepath.Join(path, "policy.json"), compiled.CanonicalJSON},
		{filepath.Join(path, "nginx.conf"), compiled.NginxConfig},
		{filepath.Join(path, releaseQUICHostKeyFile), quicHostKey},
		{filepath.Join(tlsPath, releaseCertificateFile), certificate},
		{filepath.Join(tlsPath, releasePrivateKeyFile), privateKey},
	}
	for _, file := range files {
		if err := writeFileSynced(file.path, file.content, 0o600); err != nil {
			_ = os.RemoveAll(path)
			return "", err
		}
	}
	if err := syncDirectory(tlsPath); err != nil {
		_ = os.RemoveAll(path)
		return "", err
	}
	if err := syncDirectory(path); err != nil {
		_ = os.RemoveAll(path)
		return "", err
	}
	return path, nil
}

func (s *diskStore) commitStage(stagePath string, compiled CompiledPolicy) (string, error) {
	quicHostKey, err := s.loadQUICHostKey()
	if err != nil {
		return "", err
	}
	versionDir := compiled.Policy.VersionID + "-" + compiled.Digest
	destination := filepath.Join(s.versionsDir, versionDir)
	entries, err := os.ReadDir(s.versionsDir)
	if err != nil {
		return "", err
	}
	for _, entry := range entries {
		versionID, _, valid := parseVersionDirectoryName(entry.Name())
		if !valid || !entry.IsDir() {
			return "", ErrCorruptState
		}
		if versionID == compiled.Policy.VersionID && entry.Name() != versionDir {
			return "", ErrConflict
		}
	}
	if info, err := os.Lstat(destination); err == nil {
		if info.Mode()&os.ModeSymlink != 0 || !info.IsDir() || verifyVersionDirectory(destination, compiled, quicHostKey) != nil {
			return "", ErrConflict
		}
		if err := errors.Join(removeReleaseTree(stagePath), syncDirectory(s.temporaryDir)); err != nil {
			return "", err
		}
		return versionDir, nil
	} else if !errors.Is(err, os.ErrNotExist) {
		return "", err
	}
	complete := false
	cleanupPath := stagePath
	defer func() {
		if !complete {
			_ = removeReleaseTree(cleanupPath)
		}
	}()
	if err := verifyReleaseDirectory(stagePath, compiled, quicHostKey, 0o700, 0o700, 0o600); err != nil {
		return "", err
	}
	for _, name := range []string{"policy.json", "nginx.conf", releaseQUICHostKeyFile, filepath.Join(releaseTLSDirectory, releaseCertificateFile), filepath.Join(releaseTLSDirectory, releasePrivateKeyFile)} {
		if err := os.Chmod(filepath.Join(stagePath, name), 0o400); err != nil {
			return "", err
		}
	}
	if err := os.Chmod(filepath.Join(stagePath, releaseTLSDirectory), 0o500); err != nil {
		return "", err
	}
	if err := os.Rename(stagePath, destination); err != nil {
		return "", err
	}
	cleanupPath = destination
	if err := os.Chmod(destination, 0o500); err != nil {
		return "", err
	}
	if err := verifyVersionDirectory(destination, compiled, quicHostKey); err != nil {
		return "", err
	}
	if err := syncDirectory(s.versionsDir); err != nil {
		return "", err
	}
	complete = true
	return versionDir, nil
}

func verifyVersionDirectory(path string, compiled CompiledPolicy, quicHostKey []byte) error {
	return verifyReleaseDirectory(path, compiled, quicHostKey, 0o500, 0o500, 0o400)
}

func verifyReleaseDirectory(path string, compiled CompiledPolicy, quicHostKey []byte, rootMode, tlsMode, fileMode os.FileMode) error {
	info, err := os.Lstat(path)
	if err != nil || info.Mode()&os.ModeSymlink != 0 || !info.IsDir() || info.Mode().Perm() != rootMode ||
		!exactDirectoryEntries(path, []string{"nginx.conf", "policy.json", releaseQUICHostKeyFile, releaseTLSDirectory}) {
		return ErrCorruptState
	}
	tlsPath := filepath.Join(path, releaseTLSDirectory)
	tlsInfo, err := os.Lstat(tlsPath)
	if err != nil || tlsInfo.Mode()&os.ModeSymlink != 0 || !tlsInfo.IsDir() || tlsInfo.Mode().Perm() != tlsMode ||
		!exactDirectoryEntries(tlsPath, []string{releaseCertificateFile, releasePrivateKeyFile}) {
		return ErrCorruptState
	}
	for name, expected := range map[string][]byte{"policy.json": compiled.CanonicalJSON, "nginx.conf": compiled.NginxConfig} {
		actual, err := readRegularFileWithMode(filepath.Join(path, name), maxPolicyBytes, fileMode)
		if err != nil || string(actual) != string(expected) {
			return ErrCorruptState
		}
	}
	actualHostKey, err := readRegularFileWithMode(filepath.Join(path, releaseQUICHostKeyFile), quicHostKeyBytes, fileMode)
	if err != nil || len(quicHostKey) != quicHostKeyBytes || !bytes.Equal(actualHostKey, quicHostKey) {
		return ErrCorruptState
	}
	for name, expectedDigest := range map[string]string{
		releaseCertificateFile: compiled.Policy.TLS.CertificateSHA256,
		releasePrivateKeyFile:  compiled.Policy.TLS.PrivateKeySHA256,
	} {
		actual, err := readRegularFileWithMode(filepath.Join(tlsPath, name), maxCertificateBytes, fileMode)
		if err != nil || digestBytes(actual) != expectedDigest {
			return ErrCorruptState
		}
	}
	return nil
}

func readVerifiedSource(path, expectedDigest string) ([]byte, error) {
	content, err := readRegularFile(path, maxCertificateBytes)
	if err != nil {
		return nil, fmt.Errorf("%w: %v", errCandidateAsset, err)
	}
	if digestBytes(content) != expectedDigest {
		return nil, errCandidateAsset
	}
	return content, nil
}

func digestBytes(content []byte) string {
	digest := sha256.Sum256(content)
	return hex.EncodeToString(digest[:])
}

func exactDirectoryEntries(path string, expected []string) bool {
	entries, err := os.ReadDir(path)
	if err != nil || len(entries) != len(expected) {
		return false
	}
	for index, name := range expected {
		if entries[index].Name() != name {
			return false
		}
	}
	return true
}

func readRegularFileWithMode(path string, limit int64, mode os.FileMode) ([]byte, error) {
	file, err := os.OpenFile(path, os.O_RDONLY|syscall.O_NOFOLLOW, 0)
	if err != nil {
		return nil, err
	}
	defer file.Close()
	info, err := file.Stat()
	if err != nil || !info.Mode().IsRegular() || info.Mode().Perm() != mode || info.Size() > limit {
		return nil, ErrCorruptState
	}
	pathInfo, err := os.Lstat(path)
	if err != nil || pathInfo.Mode()&os.ModeSymlink != 0 || !os.SameFile(info, pathInfo) {
		return nil, ErrCorruptState
	}
	content, err := io.ReadAll(io.LimitReader(file, limit+1))
	if err != nil || int64(len(content)) > limit {
		return nil, ErrCorruptState
	}
	info, err = file.Stat()
	if err != nil || info.Mode().Perm() != mode || info.Size() != int64(len(content)) {
		return nil, ErrCorruptState
	}
	return content, nil
}

func removeReleaseTree(path string) error {
	var result error
	for _, directory := range []string{filepath.Join(path, releaseTLSDirectory), path} {
		info, err := os.Lstat(directory)
		if err != nil {
			if !errors.Is(err, os.ErrNotExist) {
				result = errors.Join(result, err)
			}
			continue
		}
		if info.Mode()&os.ModeSymlink == 0 && info.IsDir() {
			result = errors.Join(result, os.Chmod(directory, 0o700))
		}
	}
	return errors.Join(result, os.RemoveAll(path))
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
		return err
	}
	if err := os.Symlink(filepath.Join("versions", versionDir), temporary); err != nil {
		return err
	}
	if err := os.Rename(temporary, s.currentPath); err != nil {
		_ = os.Remove(temporary)
		return err
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
		return err
	}
	return syncDirectory(s.root)
}

func (s *diskStore) loadActive() (*activeRecord, error) {
	content, err := readRegularFile(s.activePath, maxPolicyBytes)
	if errors.Is(err, os.ErrNotExist) {
		return nil, nil
	}
	if err != nil {
		return nil, err
	}
	var active activeRecord
	if err := json.Unmarshal(content, &active); err != nil || active.SchemaVersion != stateSchemaVersion ||
		!identifierPattern.MatchString(active.VersionID) || !validDigest(active.Digest) ||
		active.VersionDir != active.VersionID+"-"+active.Digest || active.AppliedAt.IsZero() {
		return nil, ErrCorruptState
	}
	policyBytes, err := readRegularFile(filepath.Join(s.versionsDir, active.VersionDir, "policy.json"), maxPolicyBytes)
	if err != nil {
		return nil, ErrCorruptState
	}
	var policy Policy
	if err := json.Unmarshal(policyBytes, &policy); err != nil {
		return nil, ErrCorruptState
	}
	compiled, err := Compile(policy)
	quicHostKey, keyErr := s.loadQUICHostKey()
	if err != nil || keyErr != nil || compiled.Digest != active.Digest || verifyVersionDirectory(filepath.Join(s.versionsDir, active.VersionDir), compiled, quicHostKey) != nil {
		return nil, ErrCorruptState
	}
	return &active, nil
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
	if err := os.Remove(s.activePath); err != nil && !errors.Is(err, os.ErrNotExist) {
		return err
	}
	return syncDirectory(s.stateDir)
}

func (s *diskStore) saveActivationJournal(journal activationJournal) error {
	journal.MAC = ""
	mac, err := s.activationJournalMAC(journal)
	if err != nil {
		return err
	}
	journal.MAC = mac
	content, err := json.Marshal(journal)
	if err != nil {
		return ErrCorruptState
	}
	return writeAtomic(s.stateDir, s.activationJournalPath, append(content, '\n'))
}

func (s *diskStore) loadActivationJournal() (*activationJournal, error) {
	content, err := readRegularFileWithMode(s.activationJournalPath, maxPolicyBytes, 0o600)
	if errors.Is(err, os.ErrNotExist) {
		return nil, nil
	}
	if err != nil {
		return nil, ErrCorruptState
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
		(journal.Stage != activationStagePrepared && journal.Stage != activationStageConfirmed) ||
		(journal.Stage == activationStagePrepared && journal.Evidence != "") ||
		(journal.Stage == activationStageConfirmed && !validDigest(journal.Evidence)) || !validDigest(journal.MAC) {
		return nil, ErrCorruptState
	}
	expectedMAC, err := s.activationJournalMAC(journal)
	if err != nil || !hmac.Equal([]byte(expectedMAC), []byte(journal.MAC)) {
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

func (s *diskStore) activationJournalMAC(journal activationJournal) (string, error) {
	payload, err := json.Marshal(activationJournalPayload{
		SchemaVersion: journal.SchemaVersion,
		Stage:         journal.Stage,
		Candidate:     journal.Candidate,
		Previous:      journal.Previous,
		Evidence:      journal.Evidence,
		CreatedAt:     journal.CreatedAt,
	})
	if err != nil {
		return "", ErrCorruptState
	}
	key, err := s.loadQUICHostKey()
	if err != nil {
		return "", err
	}
	mac := hmac.New(sha256.New, key)
	_, _ = mac.Write(payload)
	return hex.EncodeToString(mac.Sum(nil)), nil
}

func (s *diskStore) clearActivationJournal() error {
	info, err := os.Lstat(s.activationJournalPath)
	if errors.Is(err, os.ErrNotExist) {
		return nil
	}
	if err != nil || !info.Mode().IsRegular() || info.Mode().Perm() != 0o600 {
		return ErrCorruptState
	}
	if err := os.Remove(s.activationJournalPath); err != nil {
		return err
	}
	return syncDirectory(s.stateDir)
}

func (s *diskStore) validateActiveRecord(active activeRecord) error {
	if active.SchemaVersion != stateSchemaVersion || !identifierPattern.MatchString(active.VersionID) ||
		!validDigest(active.Digest) || active.VersionDir != active.VersionID+"-"+active.Digest || active.AppliedAt.IsZero() {
		return ErrCorruptState
	}
	policyBytes, err := readRegularFile(filepath.Join(s.versionsDir, active.VersionDir, "policy.json"), maxPolicyBytes)
	if err != nil {
		return ErrCorruptState
	}
	var policy Policy
	if err := json.Unmarshal(policyBytes, &policy); err != nil {
		return ErrCorruptState
	}
	compiled, err := Compile(policy)
	quicHostKey, keyErr := s.loadQUICHostKey()
	if err != nil || keyErr != nil || compiled.Digest != active.Digest || verifyVersionDirectory(filepath.Join(s.versionsDir, active.VersionDir), compiled, quicHostKey) != nil {
		return ErrCorruptState
	}
	return nil
}

func sameActiveRecord(left, right *activeRecord) bool {
	if left == nil || right == nil {
		return left == nil && right == nil
	}
	return left.SchemaVersion == right.SchemaVersion && left.VersionID == right.VersionID &&
		left.Digest == right.Digest && left.VersionDir == right.VersionDir && left.AppliedAt.Equal(right.AppliedAt)
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
	if err != nil || filepath.Dir(target) != "versions" || filepath.Clean(target) != target {
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
		return err
	}
	for _, entry := range entries {
		path := filepath.Join(s.temporaryDir, entry.Name())
		info, err := os.Lstat(path)
		if err != nil || info.Mode()&os.ModeSymlink != 0 || !info.IsDir() {
			return ErrInvalidPath
		}
		if err := os.RemoveAll(path); err != nil {
			return err
		}
	}
	return syncDirectory(s.temporaryDir)
}

func readRegularFile(path string, limit int64) ([]byte, error) {
	file, err := os.OpenFile(path, os.O_RDONLY|syscall.O_NOFOLLOW, 0)
	if err != nil {
		return nil, err
	}
	defer file.Close()
	info, err := file.Stat()
	if err != nil || !info.Mode().IsRegular() || info.Size() > limit {
		return nil, ErrCorruptState
	}
	content, err := io.ReadAll(io.LimitReader(file, limit+1))
	if err != nil || int64(len(content)) > limit {
		return nil, ErrCorruptState
	}
	return content, nil
}

func parseVersionDirectoryName(value string) (string, string, bool) {
	separator := strings.LastIndexByte(value, '-')
	if separator <= 0 || !identifierPattern.MatchString(value[:separator]) || !validDigest(value[separator+1:]) {
		return "", "", false
	}
	return value[:separator], value[separator+1:], true
}

func validVersionDirectoryName(value string) bool {
	_, _, valid := parseVersionDirectoryName(value)
	return valid
}

func writeFileSynced(path string, content []byte, mode os.FileMode) error {
	file, err := os.OpenFile(path, os.O_CREATE|os.O_EXCL|os.O_WRONLY, mode)
	if err != nil {
		return err
	}
	ok := false
	defer func() {
		_ = file.Close()
		if !ok {
			_ = os.Remove(path)
		}
	}()
	if _, err := file.Write(content); err != nil {
		return err
	}
	if err := file.Sync(); err != nil {
		return err
	}
	if err := file.Close(); err != nil {
		return err
	}
	ok = true
	return nil
}

func writeAtomic(directory, destination string, content []byte) error {
	file, err := os.CreateTemp(directory, ".http3-state-")
	if err != nil {
		return err
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
		return err
	}
	defer directory.Close()
	return directory.Sync()
}
