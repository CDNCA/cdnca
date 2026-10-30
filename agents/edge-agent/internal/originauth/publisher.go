package originauth

import (
	"bytes"
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"os"
	"path/filepath"
	"strconv"
	"strings"
	"sync"
	"syscall"
)

type Publication struct {
	PolicyVersion uint64
	SHA256        [sha256.Size]byte
	CurrentPath   string
}

type Publisher struct {
	root string
	mu   sync.Mutex
}

func NewPublisher(root string) (*Publisher, error) {
	if !filepath.IsAbs(root) || filepath.Clean(root) != root || root == string(filepath.Separator) {
		return nil, reject("PUBLISH_ROOT_INVALID")
	}
	if info, err := os.Lstat(root); err == nil {
		stat, ok := infoSys(info)
		if !ok || !info.IsDir() || info.Mode()&os.ModeSymlink != 0 || info.Mode().Perm() != 0o700 || stat.Uid != uint32(os.Geteuid()) {
			return nil, reject("PUBLISH_ROOT_UNSAFE")
		}
	} else if !errors.Is(err, os.ErrNotExist) {
		return nil, reject("PUBLISH_ROOT_UNAVAILABLE")
	}
	return &Publisher{root: root}, nil
}

func (p *Publisher) PublishJSON(raw []byte) (Publication, error) {
	canonical, policy, err := CompileJSON(raw)
	if err != nil {
		return Publication{}, err
	}
	p.mu.Lock()
	defer p.mu.Unlock()
	if err := os.MkdirAll(p.root, 0o700); err != nil {
		return Publication{}, reject("PUBLISH_WRITE_FAILED")
	}
	if err := requirePrivateDirectory(p.root); err != nil {
		return Publication{}, err
	}
	unlock, err := p.lock()
	if err != nil {
		return Publication{}, err
	}
	defer unlock()
	versions := filepath.Join(p.root, "versions")
	if err := os.MkdirAll(versions, 0o700); err != nil {
		return Publication{}, reject("PUBLISH_WRITE_FAILED")
	}
	if err := requirePrivateDirectory(versions); err != nil {
		return Publication{}, err
	}
	latest, err := latestVersion(versions)
	if err != nil {
		return Publication{}, err
	}
	path := filepath.Join(versions, versionFilename(policy.PolicyVersion))
	current := filepath.Join(p.root, "current.json")
	fallback := filepath.Join(p.root, "fallback.json")
	if policy.PolicyVersion < latest {
		return Publication{}, reject("POLICY_VERSION_REGRESSED")
	}
	if policy.PolicyVersion == latest && latest != 0 {
		existing, err := readPrivateRegular(path)
		if err != nil || !bytes.Equal(existing, canonical) {
			return Publication{}, reject("POLICY_VERSION_CONFLICT")
		}
	}
	currentCanonical, currentPolicy, currentErr := readValidatedPublication(current, versions)
	if currentErr == nil {
		if currentPolicy.PolicyVersion > policy.PolicyVersion {
			return Publication{}, reject("POLICY_VERSION_REGRESSED")
		}
		if currentPolicy.PolicyVersion == policy.PolicyVersion && !bytes.Equal(currentCanonical, canonical) {
			return Publication{}, reject("POLICY_VERSION_CONFLICT")
		}
		if err := writeAtomic(fallback, currentCanonical); err != nil {
			return Publication{}, err
		}
	} else if latest != 0 {
		_, _, fallbackErr := readValidatedPublication(fallback, versions)
		currentMissing := pathMissing(current)
		fallbackMissing := pathMissing(fallback)
		initialRetry := currentMissing && fallbackMissing && policy.PolicyVersion == latest
		if policy.PolicyVersion != latest || fallbackErr != nil && !initialRetry {
			return Publication{}, reject("PUBLISH_CURRENT_INVALID")
		}
	} else if !pathMissing(current) {
		return Publication{}, reject("PUBLISH_CURRENT_INVALID")
	}
	if policy.PolicyVersion > latest {
		if err := writeImmutable(path, canonical); err != nil {
			return Publication{}, err
		}
	}
	if latest == 0 || currentErr != nil && pathMissing(fallback) {
		if err := writeAtomic(fallback, canonical); err != nil {
			return Publication{}, err
		}
	}
	if err := writeAtomic(current, canonical); err != nil {
		return Publication{}, err
	}
	return Publication{PolicyVersion: policy.PolicyVersion, SHA256: sha256.Sum256(canonical), CurrentPath: current}, nil
}

func (p *Publisher) lock() (func(), error) {
	file, err := os.OpenFile(filepath.Join(p.root, ".publish.lock"), os.O_CREATE|os.O_RDWR|syscall.O_NOFOLLOW, 0o600)
	if err != nil {
		return nil, reject("PUBLISH_LOCK_FAILED")
	}
	info, err := file.Stat()
	stat, ok := infoSys(info)
	if err != nil || !ok || !info.Mode().IsRegular() || info.Mode().Perm() != 0o600 || stat.Nlink != 1 || stat.Uid != uint32(os.Geteuid()) {
		_ = file.Close()
		return nil, reject("PUBLISH_ROOT_UNSAFE")
	}
	if err := syscall.Flock(int(file.Fd()), syscall.LOCK_EX); err != nil {
		_ = file.Close()
		return nil, reject("PUBLISH_LOCK_FAILED")
	}
	return func() {
		_ = syscall.Flock(int(file.Fd()), syscall.LOCK_UN)
		_ = file.Close()
	}, nil
}

func latestVersion(directory string) (uint64, error) {
	entries, err := os.ReadDir(directory)
	if err != nil {
		return 0, reject("PUBLISH_READ_FAILED")
	}
	var latest uint64
	for _, entry := range entries {
		if !strings.HasSuffix(entry.Name(), ".json") {
			continue
		}
		stem := strings.TrimSuffix(entry.Name(), ".json")
		if len(stem) != 20 {
			continue
		}
		version, err := strconv.ParseUint(stem, 10, 64)
		if err != nil {
			continue
		}
		info, err := entry.Info()
		stat, ok := infoSys(info)
		if err != nil || !ok || !info.Mode().IsRegular() || info.Mode().Perm() != 0o600 || stat.Nlink != 1 || stat.Uid != uint32(os.Geteuid()) {
			return 0, reject("PUBLISH_ROOT_UNSAFE")
		}
		if version > latest {
			latest = version
		}
	}
	return latest, nil
}

func versionFilename(version uint64) string { return fmt.Sprintf("%020d.json", version) }

func requirePrivateDirectory(path string) error {
	info, err := os.Lstat(path)
	stat, ok := infoSys(info)
	if err != nil || !ok || !info.IsDir() || info.Mode()&os.ModeSymlink != 0 ||
		info.Mode().Perm() != 0o700 || stat.Uid != uint32(os.Geteuid()) {
		return reject("PUBLISH_ROOT_UNSAFE")
	}
	return nil
}

func readPrivateRegular(path string) ([]byte, error) {
	file, err := os.OpenFile(path, os.O_RDONLY|syscall.O_NOFOLLOW, 0)
	if err != nil {
		return nil, err
	}
	defer file.Close()
	info, err := file.Stat()
	stat, ok := infoSys(info)
	if err != nil || !ok || !info.Mode().IsRegular() || info.Mode().Perm() != 0o600 || stat.Nlink != 1 || stat.Uid != uint32(os.Geteuid()) {
		return nil, reject("PUBLISH_ROOT_UNSAFE")
	}
	return io.ReadAll(io.LimitReader(file, MaxPolicyBytes+1))
}

func readValidatedPublication(path, versions string) ([]byte, *CompiledPolicy, error) {
	raw, err := readPrivateRegular(path)
	if err != nil {
		return nil, nil, err
	}
	decoder := json.NewDecoder(bytes.NewReader(raw))
	decoder.DisallowUnknownFields()
	var policy CompiledPolicy
	if err := decoder.Decode(&policy); err != nil || requireEOF(decoder) != nil ||
		policy.SchemaVersion != SchemaVersion || policy.PolicyVersion == 0 || len(policy.Rules) == 0 {
		return nil, nil, reject("PUBLISH_CURRENT_INVALID")
	}
	canonical, err := json.Marshal(&policy)
	if err != nil {
		return nil, nil, reject("PUBLISH_CURRENT_INVALID")
	}
	canonical = append(canonical, '\n')
	if !bytes.Equal(raw, canonical) {
		return nil, nil, reject("PUBLISH_CURRENT_INVALID")
	}
	version, err := readPrivateRegular(filepath.Join(versions, versionFilename(policy.PolicyVersion)))
	if err != nil || !bytes.Equal(version, canonical) {
		return nil, nil, reject("PUBLISH_CURRENT_INVALID")
	}
	for _, rule := range policy.Rules {
		if !credentialBindingValid(rule.Provider, rule.CurrentKey) ||
			rule.PreviousKey != nil && !credentialBindingValid(rule.Provider, *rule.PreviousKey) {
			return nil, nil, reject("PUBLISH_CURRENT_INVALID")
		}
	}
	return canonical, &policy, nil
}

func credentialBindingValid(provider string, key CompiledKey) bool {
	raw, err := readSecretFile(key.SecretFile)
	if err != nil {
		return false
	}
	defer clear(raw)
	digest := sha256.Sum256(raw)
	if !constantTimeHexEqual(hex.EncodeToString(digest[:]), key.SHA256) {
		return false
	}
	credential, err := decodeCredential(raw, provider)
	clearCredential(&credential)
	return err == nil
}

func pathMissing(path string) bool {
	_, err := os.Lstat(path)
	return errors.Is(err, os.ErrNotExist)
}

func writeImmutable(path string, content []byte) error {
	file, err := os.OpenFile(path, os.O_WRONLY|os.O_CREATE|os.O_EXCL, 0o600)
	if err != nil {
		return reject("PUBLISH_WRITE_FAILED")
	}
	remove := true
	defer func() {
		_ = file.Close()
		if remove {
			_ = os.Remove(path)
		}
	}()
	if _, err := file.Write(content); err != nil {
		return reject("PUBLISH_WRITE_FAILED")
	}
	if err := file.Sync(); err != nil {
		return reject("PUBLISH_WRITE_FAILED")
	}
	if err := file.Close(); err != nil {
		return reject("PUBLISH_WRITE_FAILED")
	}
	remove = false
	return syncDirectory(filepath.Dir(path))
}

func writeAtomic(path string, content []byte) error {
	temporary, err := os.CreateTemp(filepath.Dir(path), ".current-*.json")
	if err != nil {
		return reject("PUBLISH_WRITE_FAILED")
	}
	temporaryPath := temporary.Name()
	defer func() {
		_ = temporary.Close()
		_ = os.Remove(temporaryPath)
	}()
	if err := temporary.Chmod(0o600); err != nil {
		return reject("PUBLISH_WRITE_FAILED")
	}
	if _, err := temporary.Write(content); err != nil {
		return reject("PUBLISH_WRITE_FAILED")
	}
	if err := temporary.Sync(); err != nil {
		return reject("PUBLISH_WRITE_FAILED")
	}
	if err := temporary.Close(); err != nil {
		return reject("PUBLISH_WRITE_FAILED")
	}
	if err := os.Rename(temporaryPath, path); err != nil {
		return reject("PUBLISH_WRITE_FAILED")
	}
	return syncDirectory(filepath.Dir(path))
}

func syncDirectory(path string) error {
	directory, err := os.Open(path)
	if err != nil {
		return reject("PUBLISH_WRITE_FAILED")
	}
	defer directory.Close()
	if err := directory.Sync(); err != nil && !errors.Is(err, os.ErrInvalid) {
		return reject("PUBLISH_WRITE_FAILED")
	}
	return nil
}
