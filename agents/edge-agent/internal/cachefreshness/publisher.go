package cachefreshness

import (
	"bytes"
	"context"
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
	"time"
)

const (
	policyFilename         = "policy.json"
	configFilename         = "nginx.conf"
	digestFilename         = "sha256"
	historicalHeadFilename = "historical-head"
	maxConfigBytes         = 1 << 20
	rollbackLimit          = 10 * time.Second
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
		return nil, fmt.Errorf("inspect cache freshness publisher root: %w", err)
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

	if err := publisher.cleanStaging(); err != nil {
		return Publication{}, err
	}
	historicalHead, err := publisher.readHistoricalHead()
	if err != nil {
		return Publication{}, err
	}
	latest, err := publisher.latestReleaseVersion(historicalHead)
	if err != nil {
		return Publication{}, err
	}
	if latest > historicalHead {
		if err := publisher.writeHistoricalHead(latest); err != nil {
			return Publication{}, err
		}
		historicalHead = latest
	}
	if err := publisher.validateReleaseScope(latest, artifact); err != nil {
		return Publication{}, err
	}
	if artifact.PolicyVersion < historicalHead {
		return Publication{}, invalid("policy_version %d is older than historical head %d", artifact.PolicyVersion, historicalHead)
	}
	target := filepath.Join("versions", versionDirectory(artifact.PolicyVersion))
	release := filepath.Join(publisher.root, target)
	_, releaseErr := os.Lstat(release)
	switch {
	case releaseErr == nil:
		if err := publisher.validateRelease(release, artifact); err != nil {
			return Publication{}, err
		}
	case errors.Is(releaseErr, os.ErrNotExist):
		if historicalHead != 0 && artifact.PolicyVersion <= historicalHead {
			return Publication{}, invalid("policy_version %d has already been published but its release is unavailable", artifact.PolicyVersion)
		}
		if err := publisher.stageRelease(ctx, release, artifact); err != nil {
			return Publication{}, err
		}
	default:
		return Publication{}, releaseErr
	}
	if artifact.PolicyVersion > historicalHead {
		if err := publisher.writeHistoricalHead(artifact.PolicyVersion); err != nil {
			return Publication{}, err
		}
	}

	previous, err := publisher.readPointer("current")
	if err != nil {
		return Publication{}, err
	}
	if previous == target {
		lkg, err := publisher.readPointer("lkg")
		if err != nil {
			return Publication{}, err
		}
		if lkg != target {
			previousDigest, err := publisher.pointerDigest(lkg)
			if err != nil {
				return Publication{}, err
			}
			config := filepath.Join(publisher.root, "current", configFilename)
			if err := publisher.runtime.Precheck(ctx, config); err != nil {
				if restoreErr := publisher.restore(lkg); restoreErr != nil {
					return Publication{}, ErrRollback
				}
				if ctxErr := ctx.Err(); ctxErr != nil {
					return Publication{}, ctxErr
				}
				return Publication{}, ErrPrecheck
			}
			if err := publisher.runtime.Activate(ctx, config, artifact.PolicyVersion); err != nil {
				if restoreErr := publisher.restore(lkg); restoreErr != nil {
					return Publication{}, ErrRollback
				}
				if ctxErr := ctx.Err(); ctxErr != nil {
					return Publication{}, ctxErr
				}
				return Publication{}, ErrActivate
			}
			if err := publisher.runtime.Healthy(ctx, artifact.PolicyVersion); err != nil {
				if restoreErr := publisher.restore(lkg); restoreErr != nil {
					return Publication{}, ErrRollback
				}
				if ctxErr := ctx.Err(); ctxErr != nil {
					return Publication{}, ctxErr
				}
				return Publication{}, ErrHealth
			}
			if err := publisher.setPointer("lkg", target); err != nil {
				if restoreErr := publisher.restore(lkg); restoreErr != nil {
					return Publication{}, ErrRollback
				}
				return Publication{}, fmt.Errorf("persist cache freshness LKG: %w", err)
			}
			return Publication{
				PolicyVersion: artifact.PolicyVersion,
				Digest:        artifact.Digest,
				Previous:      previousDigest,
				Changed:       true,
			}, nil
		}
		if err := publisher.runtime.Healthy(ctx, artifact.PolicyVersion); err != nil {
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
	config := filepath.Join(publisher.root, "current", configFilename)
	if err := publisher.runtime.Activate(ctx, config, artifact.PolicyVersion); err != nil {
		if restoreErr := publisher.restore(previous); restoreErr != nil {
			return Publication{}, ErrRollback
		}
		if ctxErr := ctx.Err(); ctxErr != nil {
			return Publication{}, ctxErr
		}
		return Publication{}, ErrActivate
	}
	if err := publisher.runtime.Healthy(ctx, artifact.PolicyVersion); err != nil {
		if restoreErr := publisher.restore(previous); restoreErr != nil {
			return Publication{}, ErrRollback
		}
		if ctxErr := ctx.Err(); ctxErr != nil {
			return Publication{}, ctxErr
		}
		return Publication{}, ErrHealth
	}
	if err := publisher.setPointer("lkg", target); err != nil {
		if restoreErr := publisher.restore(previous); restoreErr != nil {
			return Publication{}, ErrRollback
		}
		return Publication{}, fmt.Errorf("persist cache freshness LKG: %w", err)
	}
	return Publication{
		PolicyVersion: artifact.PolicyVersion,
		Digest:        artifact.Digest,
		Previous:      previousDigest,
		Changed:       true,
	}, nil
}

func (publisher *Publisher) validateReleaseScope(latest uint64, candidate Artifact) error {
	if latest == 0 {
		return nil
	}
	bound, err := publisher.readReleaseTarget(filepath.Join("versions", versionDirectory(latest)))
	if err != nil {
		return err
	}
	boundScope, err := artifactScope(bound)
	if err != nil {
		return err
	}
	candidateScope, err := artifactScope(candidate)
	if err != nil {
		return err
	}
	if boundScope != candidateScope {
		return invalid("cache freshness publisher scope is bound to tenant_id %q and site_id %q", boundScope.TenantID, boundScope.SiteID)
	}
	return nil
}

type publicationScope struct {
	TenantID string `json:"tenant_id"`
	SiteID   string `json:"site_id"`
}

func artifactScope(artifact Artifact) (publicationScope, error) {
	var scope publicationScope
	if err := json.Unmarshal(artifact.CanonicalPolicy, &scope); err != nil {
		return publicationScope{}, invalid("decode canonical cache freshness publication scope: %v", err)
	}
	if scope.TenantID == "" || scope.SiteID == "" {
		return publicationScope{}, invalid("canonical cache freshness publication scope is incomplete")
	}
	return scope, nil
}

func (publisher *Publisher) stageRelease(ctx context.Context, release string, artifact Artifact) error {
	staging, err := os.MkdirTemp(filepath.Join(publisher.root, "staging"), ".cache-freshness-")
	if err != nil {
		return fmt.Errorf("create cache freshness staging release: %w", err)
	}
	committed := false
	defer func() {
		if !committed {
			_ = os.RemoveAll(staging)
		}
	}()
	for name, content := range map[string][]byte{
		policyFilename: artifact.CanonicalPolicy,
		configFilename: artifact.Nginx,
		digestFilename: []byte(fmt.Sprintf("%x\n", artifact.Digest)),
	} {
		if err := writeExclusive(filepath.Join(staging, name), content); err != nil {
			return err
		}
	}
	if err := syncDirectory(staging); err != nil {
		return err
	}
	if err := publisher.runtime.Precheck(ctx, filepath.Join(staging, configFilename)); err != nil {
		if ctxErr := ctx.Err(); ctxErr != nil {
			return ctxErr
		}
		return ErrPrecheck
	}
	if err := publisher.validateReleaseContents(staging, artifact, 0o700); err != nil {
		return err
	}
	if err := os.Rename(staging, release); err != nil {
		return fmt.Errorf("commit cache freshness release: %w", err)
	}
	committed = true
	if err := os.Chmod(release, 0o500); err != nil {
		return fmt.Errorf("seal cache freshness release: %w", err)
	}
	if err := syncDirectory(filepath.Dir(release)); err != nil {
		return err
	}
	return publisher.validateRelease(release, artifact)
}

func (publisher *Publisher) restore(previous string) error {
	ctx, cancel := context.WithTimeout(context.Background(), rollbackLimit)
	defer cancel()
	if previous == "" {
		if err := publisher.runtime.Stop(ctx); err != nil {
			return ErrRollback
		}
		if err := os.Remove(filepath.Join(publisher.root, "current")); err != nil && !errors.Is(err, os.ErrNotExist) {
			return err
		}
		return syncDirectory(publisher.root)
	}
	artifact, err := publisher.readReleaseTarget(previous)
	if err != nil {
		return ErrRollback
	}
	if err := publisher.runtime.Precheck(ctx, filepath.Join(publisher.root, previous, configFilename)); err != nil {
		return ErrRollback
	}
	if err := publisher.setPointer("current", previous); err != nil {
		return err
	}
	if err := publisher.runtime.Activate(ctx, filepath.Join(publisher.root, "current", configFilename), artifact.PolicyVersion); err != nil {
		return ErrRollback
	}
	if err := publisher.runtime.Healthy(ctx, artifact.PolicyVersion); err != nil {
		return ErrRollback
	}
	return nil
}

func (publisher *Publisher) ensureState() error {
	for _, path := range []string{publisher.root, publisher.paths.StateRoot} {
		if err := os.MkdirAll(path, 0o700); err != nil {
			return fmt.Errorf("create cache freshness state directory: %w", err)
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
			return fmt.Errorf("create cache freshness state directory: %w", err)
		}
		if err := requirePrivateDirectory(path); err != nil {
			return err
		}
	}
	return nil
}

func (publisher *Publisher) lock() (func(), error) {
	file, err := os.OpenFile(filepath.Join(publisher.root, ".publish.lock"), os.O_CREATE|os.O_RDWR|syscall.O_NOFOLLOW, 0o600)
	if err != nil {
		return nil, fmt.Errorf("open cache freshness publication lock: %w", err)
	}
	info, err := file.Stat()
	if err != nil {
		_ = file.Close()
		return nil, err
	}
	stat, ok := info.Sys().(*syscall.Stat_t)
	if !ok || !info.Mode().IsRegular() || info.Mode().Perm() != 0o600 || stat.Nlink != 1 {
		_ = file.Close()
		return nil, invalid("publication lock is not a private single-linked regular file")
	}
	if err := syscall.Flock(int(file.Fd()), syscall.LOCK_EX); err != nil {
		_ = file.Close()
		return nil, fmt.Errorf("lock cache freshness publication: %w", err)
	}
	return func() {
		_ = syscall.Flock(int(file.Fd()), syscall.LOCK_UN)
		_ = file.Close()
	}, nil
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
	if name != "current" && name != "lkg" || !validPointer(target) {
		return invalid("unsafe publication pointer")
	}
	temporary := filepath.Join(publisher.root, "."+name+".next")
	_ = os.Remove(temporary)
	if err := os.Symlink(target, temporary); err != nil {
		return fmt.Errorf("create cache freshness %s pointer: %w", name, err)
	}
	if err := os.Rename(temporary, filepath.Join(publisher.root, name)); err != nil {
		_ = os.Remove(temporary)
		return fmt.Errorf("activate cache freshness %s pointer: %w", name, err)
	}
	return syncDirectory(publisher.root)
}

func (publisher *Publisher) pointerDigest(target string) ([sha256.Size]byte, error) {
	if target == "" {
		return [sha256.Size]byte{}, nil
	}
	content, err := readSealedFile(filepath.Join(publisher.root, target, digestFilename), sha256.Size*2+1, 0o400)
	if err != nil {
		return [sha256.Size]byte{}, err
	}
	decoded, err := hex.DecodeString(strings.TrimSpace(string(content)))
	if err != nil || len(decoded) != sha256.Size {
		return [sha256.Size]byte{}, invalid("release digest is invalid")
	}
	var digest [sha256.Size]byte
	copy(digest[:], decoded)
	return digest, nil
}

func (publisher *Publisher) validateRelease(release string, artifact Artifact) error {
	return publisher.validateReleaseContents(release, artifact, 0o500)
}

func (publisher *Publisher) validateReleaseContents(release string, artifact Artifact, directoryMode os.FileMode) error {
	actual, err := publisher.readReleaseWithMode(release, directoryMode)
	if err != nil {
		return err
	}
	if actual.PolicyVersion != artifact.PolicyVersion || actual.Digest != artifact.Digest ||
		!bytes.Equal(actual.CanonicalPolicy, artifact.CanonicalPolicy) || !bytes.Equal(actual.Nginx, artifact.Nginx) {
		return invalid("policy_version %d conflicts with existing release", artifact.PolicyVersion)
	}
	return nil
}

func (publisher *Publisher) readReleaseWithMode(release string, directoryMode os.FileMode) (Artifact, error) {
	releaseInfo, err := os.Lstat(release)
	if err != nil {
		return Artifact{}, err
	}
	if !releaseInfo.IsDir() || releaseInfo.Mode()&os.ModeSymlink != 0 || releaseInfo.Mode().Perm() != directoryMode {
		return Artifact{}, invalid("cache freshness release must be a real directory with mode %04o", directoryMode)
	}
	return publisher.readReleaseFiles(release)
}

func (publisher *Publisher) readReleaseTarget(target string) (Artifact, error) {
	version, err := versionFromTarget(target)
	if err != nil {
		return Artifact{}, err
	}
	artifact, err := publisher.readRelease(filepath.Join(publisher.root, target))
	if err != nil {
		return Artifact{}, err
	}
	if artifact.PolicyVersion != version {
		return Artifact{}, invalid("release directory version does not match canonical policy")
	}
	return artifact, nil
}

func (publisher *Publisher) readRelease(release string) (Artifact, error) {
	releaseInfo, err := os.Lstat(release)
	if err != nil {
		return Artifact{}, err
	}
	if !releaseInfo.IsDir() || releaseInfo.Mode()&os.ModeSymlink != 0 || releaseInfo.Mode().Perm() != 0o500 {
		return Artifact{}, invalid("cache freshness release must be a sealed real directory")
	}
	return publisher.readReleaseFiles(release)
}

func (publisher *Publisher) readReleaseFiles(release string) (Artifact, error) {
	entries, err := os.ReadDir(release)
	if err != nil {
		return Artifact{}, err
	}
	if len(entries) != 3 {
		return Artifact{}, invalid("cache freshness release contains unexpected entries")
	}
	expectedFiles := map[string]struct{}{policyFilename: {}, configFilename: {}, digestFilename: {}}
	for _, entry := range entries {
		if _, exists := expectedFiles[entry.Name()]; !exists {
			return Artifact{}, invalid("cache freshness release contains unexpected entry %q", entry.Name())
		}
	}
	policy, err := readSealedFile(filepath.Join(release, policyFilename), MaxPolicyBytes, 0o400)
	if err != nil {
		return Artifact{}, err
	}
	nginx, err := readSealedFile(filepath.Join(release, configFilename), maxConfigBytes, 0o400)
	if err != nil {
		return Artifact{}, err
	}
	digestFile, err := readSealedFile(filepath.Join(release, digestFilename), sha256.Size*2+1, 0o400)
	if err != nil {
		return Artifact{}, err
	}
	compiled, err := CompileJSON(policy, publisher.paths)
	if err != nil {
		return Artifact{}, err
	}
	if !bytes.Equal(policy, compiled.CanonicalPolicy) || !bytes.Equal(nginx, compiled.Nginx) ||
		!bytes.Equal(digestFile, []byte(fmt.Sprintf("%x\n", compiled.Digest))) {
		return Artifact{}, invalid("cache freshness release does not match its canonical policy")
	}
	return compiled, nil
}

func (publisher *Publisher) latestReleaseVersion(historicalHead uint64) (uint64, error) {
	entries, err := os.ReadDir(filepath.Join(publisher.root, "versions"))
	if err != nil {
		return 0, err
	}
	var latest uint64
	for _, entry := range entries {
		if !entry.IsDir() || len(entry.Name()) != 20 {
			continue
		}
		version, parseErr := strconv.ParseUint(entry.Name(), 10, 64)
		if parseErr != nil || version == 0 || version > MaxPolicyVersion || versionDirectory(version) != entry.Name() {
			continue
		}
		target := filepath.Join("versions", entry.Name())
		artifact, err := publisher.readReleaseTarget(target)
		if err != nil && version > historicalHead {
			artifact, err = publisher.recoverUnsealedRelease(target, version)
		}
		if err == nil && artifact.PolicyVersion > latest {
			latest = artifact.PolicyVersion
		}
	}
	return latest, nil
}

func (publisher *Publisher) recoverUnsealedRelease(target string, version uint64) (Artifact, error) {
	release := filepath.Join(publisher.root, target)
	artifact, err := publisher.readReleaseWithMode(release, 0o700)
	if err != nil {
		return Artifact{}, err
	}
	if artifact.PolicyVersion != version {
		return Artifact{}, invalid("unsealed release directory version does not match canonical policy")
	}
	if err := os.Chmod(release, 0o500); err != nil {
		return Artifact{}, fmt.Errorf("recover sealed cache freshness release: %w", err)
	}
	if err := syncDirectory(filepath.Dir(release)); err != nil {
		return Artifact{}, err
	}
	return publisher.readReleaseTarget(target)
}

func (publisher *Publisher) cleanStaging() error {
	staging := filepath.Join(publisher.root, "staging")
	entries, err := os.ReadDir(staging)
	if err != nil {
		return err
	}
	for _, entry := range entries {
		if !strings.HasPrefix(entry.Name(), ".cache-freshness-") {
			continue
		}
		path := filepath.Join(staging, entry.Name())
		if entry.IsDir() {
			_ = filepath.WalkDir(path, func(current string, item os.DirEntry, walkErr error) error {
				if walkErr == nil && item != nil && item.IsDir() {
					_ = os.Chmod(current, 0o700)
				}
				return walkErr
			})
		}
		if err := os.RemoveAll(path); err != nil {
			return fmt.Errorf("clean cache freshness staging residue: %w", err)
		}
	}
	return syncDirectory(staging)
}

func (publisher *Publisher) readHistoricalHead() (uint64, error) {
	content, err := readSealedFile(filepath.Join(publisher.root, historicalHeadFilename), 21, 0o600)
	if errors.Is(err, os.ErrNotExist) {
		return 0, nil
	}
	if err != nil {
		return 0, err
	}
	if len(content) != 21 || content[20] != '\n' {
		return 0, invalid("cache freshness historical head is invalid")
	}
	version, err := strconv.ParseUint(string(content[:20]), 10, 64)
	if err != nil || version == 0 || version > MaxPolicyVersion || versionDirectory(version) != string(content[:20]) {
		return 0, invalid("cache freshness historical head is invalid")
	}
	return version, nil
}

func (publisher *Publisher) writeHistoricalHead(version uint64) error {
	if version == 0 || version > MaxPolicyVersion {
		return invalid("cache freshness historical head version is invalid")
	}
	temporary := filepath.Join(publisher.root, ".historical-head.next")
	if err := os.Remove(temporary); err != nil && !errors.Is(err, os.ErrNotExist) {
		return err
	}
	if err := writeExclusiveMode(temporary, []byte(versionDirectory(version)+"\n"), 0o600); err != nil {
		return fmt.Errorf("write cache freshness historical head: %w", err)
	}
	if err := os.Rename(temporary, filepath.Join(publisher.root, historicalHeadFilename)); err != nil {
		_ = os.Remove(temporary)
		return fmt.Errorf("commit cache freshness historical head: %w", err)
	}
	return syncDirectory(publisher.root)
}

func versionDirectory(version uint64) string { return fmt.Sprintf("%020d", version) }

func versionFromTarget(target string) (uint64, error) {
	if !validPointer(target) {
		return 0, invalid("unsafe release pointer")
	}
	version, err := strconv.ParseUint(filepath.Base(target), 10, 64)
	if err != nil || version == 0 {
		return 0, invalid("release pointer version is invalid")
	}
	return version, nil
}

func validPointer(target string) bool {
	if filepath.Dir(target) != "versions" || len(filepath.Base(target)) != 20 {
		return false
	}
	version, err := strconv.ParseUint(filepath.Base(target), 10, 64)
	return err == nil && version > 0 && version <= MaxPolicyVersion
}

func safeRoot(path string) bool {
	return filepath.IsAbs(path) && filepath.Clean(path) == path && path != string(filepath.Separator) && !strings.ContainsAny(path, "\x00\r\n")
}

func writeExclusive(path string, content []byte) error {
	return writeExclusiveMode(path, content, 0o400)
}

func writeExclusiveMode(path string, content []byte, mode os.FileMode) error {
	file, err := os.OpenFile(path, os.O_CREATE|os.O_EXCL|os.O_WRONLY|syscall.O_NOFOLLOW, mode)
	if err != nil {
		return err
	}
	if _, err := file.Write(content); err != nil {
		_ = file.Close()
		return err
	}
	if err := file.Sync(); err != nil {
		_ = file.Close()
		return err
	}
	return file.Close()
}

func readSealedFile(path string, limit int, mode os.FileMode) ([]byte, error) {
	file, err := os.OpenFile(path, os.O_RDONLY|syscall.O_NOFOLLOW, 0)
	if err != nil {
		if !errors.Is(err, os.ErrNotExist) {
			return nil, invalid("open sealed cache freshness file %q: %v", filepath.Base(path), err)
		}
		return nil, err
	}
	defer file.Close()
	info, err := file.Stat()
	if err != nil {
		return nil, err
	}
	stat, ok := info.Sys().(*syscall.Stat_t)
	if !ok || !info.Mode().IsRegular() || info.Mode().Perm() != mode || stat.Nlink != 1 {
		return nil, invalid("cache freshness release file %q must be sealed, regular, and single-linked", filepath.Base(path))
	}
	content, err := io.ReadAll(io.LimitReader(file, int64(limit)+1))
	if err != nil {
		return nil, err
	}
	if len(content) > limit {
		return nil, invalid("cache freshness release file %q exceeds its size limit", filepath.Base(path))
	}
	return content, nil
}

func requirePrivateDirectory(path string) error {
	info, err := os.Lstat(path)
	if err != nil {
		return err
	}
	if !info.IsDir() || info.Mode()&os.ModeSymlink != 0 || info.Mode().Perm()&0o077 != 0 {
		return invalid("state directory %q must be a private real directory", path)
	}
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
