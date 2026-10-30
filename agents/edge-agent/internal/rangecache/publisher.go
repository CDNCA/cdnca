package rangecache

import (
	"bytes"
	"context"
	"crypto/sha256"
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
	"time"
)

const (
	policyFilename = "policy.json"
	configFilename = "nginx.conf"
	rollbackLimit  = 10 * time.Second
	maxConfigBytes = 2 << 20
)

type Publisher struct {
	mu      sync.Mutex
	root    string
	paths   RuntimePaths
	runtime Runtime
}

func NewPublisher(root string, paths RuntimePaths, runtime Runtime) (*Publisher, error) {
	if runtime == nil {
		return nil, invalid("runtime is required")
	}
	if !safeRoot(root) {
		return nil, invalid("publisher root must be a clean absolute non-root path")
	}
	if err := validateRuntimePaths(paths); err != nil {
		return nil, err
	}
	if info, err := os.Lstat(root); err == nil && (!info.IsDir() || info.Mode()&os.ModeSymlink != 0) {
		return nil, invalid("publisher root must be a real directory")
	} else if err != nil && !errors.Is(err, os.ErrNotExist) {
		return nil, fmt.Errorf("inspect range cache publisher root: %w", err)
	}
	return &Publisher{root: root, paths: paths, runtime: runtime}, nil
}

func (publisher *Publisher) ApplyJSON(ctx context.Context, raw []byte) (Publication, error) {
	if err := ctx.Err(); err != nil {
		return Publication{}, err
	}
	artifact, err := CompileJSON(raw, publisher.paths)
	if err != nil {
		return Publication{}, err
	}

	publisher.mu.Lock()
	defer publisher.mu.Unlock()
	if err := publisher.ensureState(); err != nil {
		return Publication{}, err
	}
	unlock, err := publisher.lock()
	if err != nil {
		return Publication{}, err
	}
	defer unlock()

	versions := filepath.Join(publisher.root, "versions")
	latest, err := latestReleaseVersion(versions)
	if err != nil {
		return Publication{}, err
	}
	if artifact.PolicyVersion < latest {
		return Publication{}, invalid("policy_version %d is older than published version %d", artifact.PolicyVersion, latest)
	}
	release := filepath.Join(versions, versionDirectory(artifact.PolicyVersion))
	if artifact.PolicyVersion == latest && latest != 0 {
		if err := validateRelease(release, artifact); err != nil {
			return Publication{}, err
		}
	} else {
		release, err = publisher.stageRelease(ctx, artifact)
		if err != nil {
			return Publication{}, err
		}
	}
	config := filepath.Join(release, configFilename)
	if err := publisher.runtime.Precheck(ctx, config); err != nil {
		if ctxErr := ctx.Err(); ctxErr != nil {
			return Publication{}, ctxErr
		}
		return Publication{}, ErrPrecheck
	}

	previous, err := publisher.readPointer("current")
	if err != nil {
		return Publication{}, err
	}
	target := filepath.Join("versions", versionDirectory(artifact.PolicyVersion))
	if previous == target {
		if err := publisher.runtime.Healthy(ctx, filepath.Join(publisher.root, "current", configFilename)); err != nil {
			if ctxErr := ctx.Err(); ctxErr != nil {
				return Publication{}, ctxErr
			}
			return Publication{}, ErrHealth
		}
		if err := publisher.setPointer("lkg", target); err != nil {
			return Publication{}, err
		}
		return Publication{PolicyVersion: artifact.PolicyVersion, Digest: artifact.Digest}, nil
	}
	previousDigest, err := publisher.pointerDigest(previous)
	if err != nil {
		return Publication{}, err
	}
	if err := publisher.setPointer("current", target); err != nil {
		return Publication{}, err
	}
	currentConfig := filepath.Join(publisher.root, "current", configFilename)
	if err := publisher.runtime.Reload(ctx, currentConfig); err != nil {
		if rollbackErr := publisher.restore(previous); rollbackErr != nil {
			return Publication{}, ErrRollback
		}
		if ctxErr := ctx.Err(); ctxErr != nil {
			return Publication{}, ctxErr
		}
		return Publication{}, ErrReload
	}
	if err := publisher.runtime.Healthy(ctx, currentConfig); err != nil {
		if rollbackErr := publisher.restore(previous); rollbackErr != nil {
			return Publication{}, ErrRollback
		}
		if ctxErr := ctx.Err(); ctxErr != nil {
			return Publication{}, ctxErr
		}
		return Publication{}, ErrHealth
	}
	if err := publisher.setPointer("lkg", target); err != nil {
		if rollbackErr := publisher.restore(previous); rollbackErr != nil {
			return Publication{}, ErrRollback
		}
		return Publication{}, fmt.Errorf("persist range cache LKG: %w", err)
	}
	return Publication{
		PolicyVersion: artifact.PolicyVersion, Digest: artifact.Digest,
		Previous: previousDigest, Changed: true,
	}, nil
}

func (publisher *Publisher) CurrentConfig() (string, error) {
	publisher.mu.Lock()
	defer publisher.mu.Unlock()
	target, err := publisher.readPointer("current")
	if err != nil {
		return "", err
	}
	if target == "" {
		return "", os.ErrNotExist
	}
	if _, err := readRelease(filepath.Join(publisher.root, target)); err != nil {
		return "", err
	}
	return filepath.Join(publisher.root, "current", configFilename), nil
}

func (publisher *Publisher) LKGConfig() (string, error) {
	publisher.mu.Lock()
	defer publisher.mu.Unlock()
	target, err := publisher.readPointer("lkg")
	if err != nil {
		return "", err
	}
	if target == "" {
		return "", os.ErrNotExist
	}
	if _, err := readRelease(filepath.Join(publisher.root, target)); err != nil {
		return "", err
	}
	return filepath.Join(publisher.root, "lkg", configFilename), nil
}

func (publisher *Publisher) stageRelease(ctx context.Context, artifact Artifact) (string, error) {
	stagingRoot := filepath.Join(publisher.root, "staging")
	temporary, err := os.MkdirTemp(stagingRoot, ".range-")
	if err != nil {
		return "", fmt.Errorf("create range cache staging release: %w", err)
	}
	committed := false
	defer func() {
		if !committed {
			_ = os.RemoveAll(temporary)
		}
	}()
	if err := writeExclusive(filepath.Join(temporary, policyFilename), artifact.CanonicalPolicy); err != nil {
		return "", err
	}
	config := filepath.Join(temporary, configFilename)
	if err := writeExclusive(config, artifact.Nginx); err != nil {
		return "", err
	}
	if err := syncDirectory(temporary); err != nil {
		return "", err
	}
	if err := publisher.runtime.Precheck(ctx, config); err != nil {
		if ctxErr := ctx.Err(); ctxErr != nil {
			return "", ctxErr
		}
		return "", ErrPrecheck
	}
	versions := filepath.Join(publisher.root, "versions")
	release := filepath.Join(versions, versionDirectory(artifact.PolicyVersion))
	if err := os.Rename(temporary, release); err != nil {
		return "", fmt.Errorf("commit range cache release: %w", err)
	}
	committed = true
	if err := os.Chmod(release, 0o500); err != nil {
		return "", fmt.Errorf("seal range cache release: %w", err)
	}
	if err := validateRelease(release, artifact); err != nil {
		return "", err
	}
	if err := syncDirectory(versions); err != nil {
		return "", err
	}
	return release, nil
}

func (publisher *Publisher) ensureState() error {
	for _, path := range []string{publisher.root, publisher.paths.StateRoot} {
		if err := os.MkdirAll(path, 0o700); err != nil {
			return fmt.Errorf("create range cache state directory: %w", err)
		}
		if err := requirePrivateDirectory(path); err != nil {
			return err
		}
	}
	for _, path := range []string{
		filepath.Join(publisher.root, "versions"), filepath.Join(publisher.root, "staging"),
		filepath.Join(publisher.paths.StateRoot, "cache"), filepath.Join(publisher.paths.StateRoot, "proxy_temp"),
	} {
		if err := os.Mkdir(path, 0o700); err != nil && !errors.Is(err, os.ErrExist) {
			return fmt.Errorf("create range cache state directory: %w", err)
		}
		if err := requirePrivateDirectory(path); err != nil {
			return err
		}
	}
	return nil
}

func (publisher *Publisher) lock() (func(), error) {
	path := filepath.Join(publisher.root, ".publish.lock")
	file, err := os.OpenFile(path, os.O_CREATE|os.O_RDWR|syscall.O_NOFOLLOW, 0o600)
	if err != nil {
		return nil, fmt.Errorf("open range cache publication lock: %w", err)
	}
	info, err := file.Stat()
	if err != nil || !info.Mode().IsRegular() || info.Mode().Perm() != 0o600 {
		_ = file.Close()
		return nil, invalid("publication lock is not a private regular file")
	}
	if err := syscall.Flock(int(file.Fd()), syscall.LOCK_EX); err != nil {
		_ = file.Close()
		return nil, fmt.Errorf("lock range cache publication: %w", err)
	}
	return func() {
		_ = syscall.Flock(int(file.Fd()), syscall.LOCK_UN)
		_ = file.Close()
	}, nil
}

func (publisher *Publisher) restore(previous string) error {
	if previous == "" {
		ctx, cancel := context.WithTimeout(context.Background(), rollbackLimit)
		defer cancel()
		config := filepath.Join(publisher.root, "current", configFilename)
		if err := publisher.runtime.Stop(ctx, config); err != nil {
			return ErrRollback
		}
		if err := os.Remove(filepath.Join(publisher.root, "current")); err != nil && !errors.Is(err, os.ErrNotExist) {
			return err
		}
		return syncDirectory(publisher.root)
	}
	if _, err := readRelease(filepath.Join(publisher.root, previous)); err != nil {
		return err
	}
	if err := publisher.setPointer("current", previous); err != nil {
		return err
	}
	ctx, cancel := context.WithTimeout(context.Background(), rollbackLimit)
	defer cancel()
	config := filepath.Join(publisher.root, "current", configFilename)
	if err := publisher.runtime.Reload(ctx, config); err != nil {
		return ErrRollback
	}
	if err := publisher.runtime.Healthy(ctx, config); err != nil {
		return ErrRollback
	}
	return nil
}

func (publisher *Publisher) readPointer(name string) (string, error) {
	if name != "current" && name != "lkg" {
		return "", invalid("unsupported pointer name")
	}
	target, err := os.Readlink(filepath.Join(publisher.root, name))
	if errors.Is(err, os.ErrNotExist) {
		return "", nil
	}
	if err != nil {
		return "", err
	}
	if !validPointer(target) {
		return "", invalid("unsafe %s pointer", name)
	}
	return target, nil
}

func (publisher *Publisher) setPointer(name, target string) error {
	if (name != "current" && name != "lkg") || !validPointer(target) {
		return invalid("unsafe range cache pointer")
	}
	temporary := filepath.Join(publisher.root, "."+name+"-"+filepath.Base(target)+".tmp")
	if err := os.Remove(temporary); err != nil && !errors.Is(err, os.ErrNotExist) {
		return err
	}
	if err := os.Symlink(target, temporary); err != nil {
		return err
	}
	if err := os.Rename(temporary, filepath.Join(publisher.root, name)); err != nil {
		_ = os.Remove(temporary)
		return err
	}
	return syncDirectory(publisher.root)
}

func (publisher *Publisher) pointerDigest(target string) ([sha256.Size]byte, error) {
	if target == "" {
		return [sha256.Size]byte{}, nil
	}
	artifact, err := readRelease(filepath.Join(publisher.root, target))
	return artifact.Digest, err
}

func latestReleaseVersion(directory string) (uint64, error) {
	entries, err := os.ReadDir(directory)
	if err != nil {
		return 0, fmt.Errorf("read range cache releases: %w", err)
	}
	var latest uint64
	for _, entry := range entries {
		if len(entry.Name()) != 20 {
			continue
		}
		version, err := strconv.ParseUint(entry.Name(), 10, 64)
		if err != nil {
			continue
		}
		if _, err := readRelease(filepath.Join(directory, entry.Name())); err != nil {
			return 0, err
		}
		if version > latest {
			latest = version
		}
	}
	return latest, nil
}

func validateRelease(path string, expected Artifact) error {
	actual, err := readRelease(path)
	if err != nil {
		return err
	}
	if actual.PolicyVersion != expected.PolicyVersion || actual.Digest != expected.Digest ||
		!bytes.Equal(actual.CanonicalPolicy, expected.CanonicalPolicy) || !bytes.Equal(actual.Nginx, expected.Nginx) {
		return invalid("policy_version %d already has different content", expected.PolicyVersion)
	}
	return nil
}

func readRelease(path string) (Artifact, error) {
	info, err := os.Lstat(path)
	if err != nil {
		return Artifact{}, err
	}
	if !info.IsDir() || info.Mode()&os.ModeSymlink != 0 || info.Mode().Perm() != 0o500 {
		return Artifact{}, invalid("range cache release is not sealed")
	}
	entries, err := os.ReadDir(path)
	if err != nil || len(entries) != 2 {
		return Artifact{}, invalid("range cache release must contain exactly two files")
	}
	policy, err := readPrivateRegular(filepath.Join(path, policyFilename), MaxPolicyBytes)
	if err != nil {
		return Artifact{}, err
	}
	nginx, err := readPrivateRegular(filepath.Join(path, configFilename), maxConfigBytes)
	if err != nil {
		return Artifact{}, err
	}
	var compiled Policy
	if err := jsonUnmarshalStrict(policy, &compiled); err != nil {
		return Artifact{}, err
	}
	digestInput := append(append(make([]byte, 0, len(policy)+len(nginx)), policy...), nginx...)
	return Artifact{
		PolicyVersion: compiled.PolicyVersion, CanonicalPolicy: policy, Nginx: nginx,
		Digest: sha256.Sum256(digestInput),
	}, nil
}

func readPrivateRegular(path string, limit int) ([]byte, error) {
	file, err := os.OpenFile(path, os.O_RDONLY|syscall.O_NOFOLLOW, 0)
	if err != nil {
		return nil, err
	}
	defer file.Close()
	info, err := file.Stat()
	if err != nil {
		return nil, err
	}
	stat, ok := info.Sys().(*syscall.Stat_t)
	if !ok || !info.Mode().IsRegular() || info.Mode().Perm() != 0o400 || stat.Nlink != 1 {
		return nil, invalid("range cache release file is unsafe")
	}
	content, err := io.ReadAll(io.LimitReader(file, int64(limit)+1))
	if err != nil {
		return nil, err
	}
	if len(content) > limit {
		return nil, invalid("range cache release file exceeds %d bytes", limit)
	}
	return content, nil
}

func writeExclusive(path string, content []byte) error {
	file, err := os.OpenFile(path, os.O_WRONLY|os.O_CREATE|os.O_EXCL, 0o400)
	if err != nil {
		return fmt.Errorf("create range cache release file: %w", err)
	}
	remove := true
	defer func() {
		_ = file.Close()
		if remove {
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
	remove = false
	return nil
}

func requirePrivateDirectory(path string) error {
	info, err := os.Lstat(path)
	if err != nil {
		return err
	}
	if !info.IsDir() || info.Mode()&os.ModeSymlink != 0 || info.Mode().Perm() != 0o700 {
		return invalid("state directory %q must be real and owner-only", path)
	}
	return nil
}

func syncDirectory(path string) error {
	directory, err := os.Open(path)
	if err != nil {
		return err
	}
	defer directory.Close()
	if err := directory.Sync(); err != nil && !errors.Is(err, os.ErrInvalid) {
		return err
	}
	return nil
}

func versionDirectory(version uint64) string { return fmt.Sprintf("%020d", version) }

func validPointer(target string) bool {
	if filepath.IsAbs(target) || filepath.Clean(target) != target || strings.Contains(target, "..") {
		return false
	}
	parts := strings.Split(target, string(filepath.Separator))
	if len(parts) != 2 || parts[0] != "versions" || len(parts[1]) != 20 {
		return false
	}
	_, err := strconv.ParseUint(parts[1], 10, 64)
	return err == nil
}

func safeRoot(path string) bool {
	return filepath.IsAbs(path) && filepath.Clean(path) == path && path != string(filepath.Separator) && !strings.ContainsAny(path, "\x00\r\n")
}

func jsonUnmarshalStrict(raw []byte, destination any) error {
	decoder := json.NewDecoder(bytes.NewReader(raw))
	decoder.DisallowUnknownFields()
	if err := decoder.Decode(destination); err != nil {
		return invalid("decode stored policy: %v", err)
	}
	return requireJSONEOF(decoder)
}
