package originroute

import (
	"bytes"
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"os"
	"path/filepath"
	"regexp"
	"sort"
	"sync"
	"syscall"
	"time"
)

var digestPattern = regexp.MustCompile(`^[0-9a-f]{64}$`)

const (
	publicationJournalName   = "apply-journal.json"
	publicationJournalSchema = 1
	publicationJournalLimit  = 1024
	publisherLockName        = ".apply.lock"
	publisherRecoveryTimeout = 10 * time.Second
)

type publicationJournal struct {
	Schema          int    `json:"schema"`
	CandidateDigest string `json:"candidate_digest"`
	PreviousDigest  string `json:"previous_digest"`
}

type Runtime interface {
	Precheck(context.Context, string) error
	Reload(context.Context, string) error
	Healthy(context.Context, string) error
	Stop(context.Context) error
}

type Publisher struct {
	mu        sync.Mutex
	stateRoot string
	luaRoot   string
	addresses AddressInspector
	runtime   Runtime
}

func NewPublisher(stateRoot, luaRoot string, addresses AddressInspector, runtime Runtime) (*Publisher, error) {
	if !safeAbsolutePath(stateRoot) || !safeAbsolutePath(luaRoot) || addresses == nil || runtime == nil {
		return nil, invalid("publisher roots, address inspector, and runtime are required")
	}
	publisher := &Publisher{stateRoot: stateRoot, luaRoot: luaRoot, addresses: addresses, runtime: runtime}
	if err := publisher.ensureState(); err != nil {
		return nil, err
	}
	ctx, cancel := context.WithTimeout(context.Background(), publisherRecoveryTimeout)
	defer cancel()
	unlock, err := publisher.lock(ctx)
	if err != nil {
		return nil, err
	}
	defer unlock()
	if err := publisher.reconcile(); err != nil {
		return nil, err
	}
	return publisher, nil
}

func (publisher *Publisher) Apply(ctx context.Context, raw []byte) (ApplyResult, error) {
	policy, err := Parse(raw)
	if err != nil {
		return ApplyResult{}, err
	}
	if err := ValidateLocalBindings(ctx, policy, publisher.addresses); err != nil {
		return ApplyResult{}, err
	}
	artifact, err := Compile(policy, publisher.stateRoot, publisher.luaRoot)
	if err != nil {
		return ApplyResult{}, err
	}

	publisher.mu.Lock()
	defer publisher.mu.Unlock()
	if err := publisher.ensureState(); err != nil {
		return ApplyResult{}, err
	}
	unlock, err := publisher.lock(ctx)
	if err != nil {
		return ApplyResult{}, err
	}
	defer unlock()
	if err := publisher.reconcile(); err != nil {
		return ApplyResult{}, err
	}
	previous, err := publisher.pointer("current")
	if err != nil {
		return ApplyResult{}, err
	}
	if previous != "" {
		current, err := publisher.readRelease(previous)
		if err != nil {
			return ApplyResult{}, fmt.Errorf("validate current origin route release: %w", err)
		}
		if artifact.Revision < current.Revision ||
			(artifact.Revision == current.Revision && artifact.Digest != current.Digest) {
			return ApplyResult{}, ErrConflict
		}
		if artifact.Digest == current.Digest {
			if err := publisher.runtime.Healthy(ctx, artifact.VersionID); err != nil {
				return ApplyResult{}, fmt.Errorf("%w: %v", ErrHealth, err)
			}
			return ApplyResult{
				VersionID: artifact.VersionID, Digest: artifact.Digest,
				PreviousDigest: previous, Changed: false,
			}, nil
		}
	}
	release, err := publisher.ensureRelease(artifact)
	if err != nil {
		return ApplyResult{}, err
	}
	if err := publisher.runtime.Precheck(ctx, release); err != nil {
		return ApplyResult{}, fmt.Errorf("%w: %v", ErrPrecheck, err)
	}
	journal := publicationJournal{
		Schema: publicationJournalSchema, CandidateDigest: artifact.Digest, PreviousDigest: previous,
	}
	if err := publisher.writeJournal(journal); err != nil {
		return ApplyResult{}, err
	}
	if err := publisher.setPointer("current", artifact.Digest); err != nil {
		if clearErr := publisher.clearJournal(); clearErr != nil {
			return ApplyResult{}, fmt.Errorf("set current=%v clear journal=%v", err, clearErr)
		}
		return ApplyResult{}, err
	}
	if err := publisher.runtime.Reload(ctx, release); err != nil {
		if restoreErr := publisher.restoreLKG(); restoreErr != nil {
			return ApplyResult{}, fmt.Errorf("%w: reload=%v restore=%v", ErrRollback, err, restoreErr)
		}
		if clearErr := publisher.clearJournal(); clearErr != nil {
			return ApplyResult{}, fmt.Errorf("%w: reload=%v clear journal=%v", ErrRollback, err, clearErr)
		}
		return ApplyResult{}, fmt.Errorf("%w: %v", ErrReload, err)
	}
	if err := publisher.runtime.Healthy(ctx, artifact.VersionID); err != nil {
		if restoreErr := publisher.restoreLKG(); restoreErr != nil {
			return ApplyResult{}, fmt.Errorf("%w: health=%v restore=%v", ErrRollback, err, restoreErr)
		}
		if clearErr := publisher.clearJournal(); clearErr != nil {
			return ApplyResult{}, fmt.Errorf("%w: health=%v clear journal=%v", ErrRollback, err, clearErr)
		}
		return ApplyResult{}, fmt.Errorf("%w: %v", ErrHealth, err)
	}
	if err := publisher.setPointer("lkg", artifact.Digest); err != nil {
		if restoreErr := publisher.restoreLKG(); restoreErr != nil {
			return ApplyResult{}, fmt.Errorf("%w: lkg=%v restore=%v", ErrRollback, err, restoreErr)
		}
		return ApplyResult{}, err
	}
	if err := publisher.clearJournal(); err != nil {
		return ApplyResult{}, err
	}
	return ApplyResult{
		VersionID: artifact.VersionID, Digest: artifact.Digest,
		PreviousDigest: previous, Changed: true,
	}, nil
}

func (publisher *Publisher) restoreLKG() error {
	previous, err := publisher.pointer("lkg")
	if err != nil {
		return err
	}
	return publisher.restore(previous)
}

func (publisher *Publisher) restore(previous string) error {
	ctx, cancel := context.WithTimeout(context.Background(), 10*time.Second)
	defer cancel()
	if previous == "" {
		if err := publisher.runtime.Stop(ctx); err != nil {
			return err
		}
		return publisher.removePointer("current")
	}
	release, err := publisher.readRelease(previous)
	if err != nil {
		return err
	}
	if err := publisher.setPointer("current", previous); err != nil {
		return err
	}
	path := filepath.Join(publisher.stateRoot, "versions", previous)
	if err := publisher.runtime.Reload(ctx, path); err != nil {
		return err
	}
	return publisher.runtime.Healthy(ctx, release.VersionID)
}

func (publisher *Publisher) lock(ctx context.Context) (func(), error) {
	path := filepath.Join(publisher.stateRoot, publisherLockName)
	file, err := os.OpenFile(path, os.O_CREATE|os.O_RDWR|syscall.O_NOFOLLOW, 0o600)
	if err != nil {
		return nil, fmt.Errorf("open origin route publication lock: %w", err)
	}
	info, statErr := file.Stat()
	stat, hasStat := infoSysStat(info)
	if statErr != nil || info == nil || !info.Mode().IsRegular() || info.Mode().Perm() != 0o600 ||
		!hasStat || stat.Nlink != 1 {
		_ = file.Close()
		return nil, invalid("origin route publication lock must be a single-link regular 0600 file")
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
			return nil, fmt.Errorf("lock origin route publication: %w", err)
		}
		select {
		case <-ctx.Done():
			_ = file.Close()
			return nil, ctx.Err()
		case <-ticker.C:
		}
	}
}

func infoSysStat(info os.FileInfo) (*syscall.Stat_t, bool) {
	if info == nil {
		return nil, false
	}
	stat, ok := info.Sys().(*syscall.Stat_t)
	return stat, ok
}

func (publisher *Publisher) reconcile() error {
	journal, err := publisher.readJournal()
	if err != nil {
		return err
	}
	current, err := publisher.pointer("current")
	if err != nil {
		return err
	}
	lkg, err := publisher.pointer("lkg")
	if err != nil {
		return err
	}
	if lkg != "" {
		if _, err := publisher.readRelease(lkg); err != nil {
			return fmt.Errorf("validate origin route LKG: %w", err)
		}
	}
	if journal != nil {
		if journal.PreviousDigest != lkg && journal.CandidateDigest != lkg {
			return fmt.Errorf("origin route publication journal is inconsistent with LKG")
		}
		if _, err := publisher.readRelease(journal.CandidateDigest); err != nil {
			return fmt.Errorf("validate journal candidate: %w", err)
		}
	}
	if current == lkg {
		if journal == nil {
			return nil
		}
	} else if journal == nil {
		candidate := current
		if candidate == "" {
			candidate = lkg
		}
		journal = &publicationJournal{
			Schema: publicationJournalSchema, CandidateDigest: candidate, PreviousDigest: lkg,
		}
		if err := publisher.writeJournal(*journal); err != nil {
			return fmt.Errorf("journal unexpected current origin route release: %w", err)
		}
	}
	if err := publisher.restore(lkg); err != nil {
		return fmt.Errorf("%w: reconcile current to LKG: %v", ErrRollback, err)
	}
	return publisher.clearJournal()
}

func (publisher *Publisher) readJournal() (*publicationJournal, error) {
	path := filepath.Join(publisher.stateRoot, publicationJournalName)
	file, err := os.OpenFile(path, os.O_RDONLY|syscall.O_NOFOLLOW, 0)
	if errors.Is(err, os.ErrNotExist) {
		return nil, nil
	}
	if err != nil {
		return nil, err
	}
	defer file.Close()
	info, statErr := file.Stat()
	stat, hasStat := infoSysStat(info)
	if statErr != nil || info == nil || !info.Mode().IsRegular() || info.Mode().Perm() != 0o600 ||
		info.Size() > publicationJournalLimit || !hasStat || stat.Nlink != 1 {
		return nil, fmt.Errorf("origin route publication journal is unsafe")
	}
	decoder := json.NewDecoder(io.LimitReader(file, publicationJournalLimit+1))
	decoder.DisallowUnknownFields()
	var journal publicationJournal
	if err := decoder.Decode(&journal); err != nil {
		return nil, fmt.Errorf("decode origin route publication journal: %w", err)
	}
	if err := decoder.Decode(&struct{}{}); err != io.EOF {
		return nil, fmt.Errorf("origin route publication journal must contain one JSON value")
	}
	if journal.Schema != publicationJournalSchema || !digestPattern.MatchString(journal.CandidateDigest) ||
		(journal.PreviousDigest != "" && !digestPattern.MatchString(journal.PreviousDigest)) {
		return nil, fmt.Errorf("origin route publication journal is invalid")
	}
	return &journal, nil
}

func (publisher *Publisher) writeJournal(journal publicationJournal) error {
	content, err := json.Marshal(journal)
	if err != nil {
		return err
	}
	content = append(content, '\n')
	temporary, err := os.CreateTemp(publisher.stateRoot, ".apply-journal-")
	if err != nil {
		return err
	}
	temporaryPath := temporary.Name()
	defer os.Remove(temporaryPath)
	if err := temporary.Chmod(0o600); err == nil {
		_, err = temporary.Write(content)
	}
	if err == nil {
		err = temporary.Sync()
	}
	closeErr := temporary.Close()
	if err != nil {
		return err
	}
	if closeErr != nil {
		return closeErr
	}
	if err := os.Rename(temporaryPath, filepath.Join(publisher.stateRoot, publicationJournalName)); err != nil {
		return err
	}
	return syncDirectory(publisher.stateRoot)
}

func (publisher *Publisher) clearJournal() error {
	err := os.Remove(filepath.Join(publisher.stateRoot, publicationJournalName))
	if errors.Is(err, os.ErrNotExist) {
		return nil
	}
	if err != nil {
		return err
	}
	return syncDirectory(publisher.stateRoot)
}

func (publisher *Publisher) ensureState() error {
	if err := ensurePrivateDirectory(publisher.stateRoot); err != nil {
		return err
	}
	for _, name := range []string{"versions", "staging", "shared"} {
		if err := ensurePrivateDirectory(filepath.Join(publisher.stateRoot, name)); err != nil {
			return err
		}
	}
	for _, name := range []string{"client-body-temp", "proxy-temp", "fastcgi-temp", "uwsgi-temp", "scgi-temp"} {
		if err := ensurePrivateDirectory(filepath.Join(publisher.stateRoot, "shared", name)); err != nil {
			return err
		}
	}
	return nil
}

func ensurePrivateDirectory(path string) error {
	if err := os.MkdirAll(path, 0o700); err != nil {
		return err
	}
	info, err := os.Lstat(path)
	if err != nil {
		return err
	}
	if !info.IsDir() || info.Mode()&os.ModeSymlink != 0 || info.Mode().Perm() != 0o700 {
		return fmt.Errorf("unsafe origin route state directory %s", path)
	}
	return nil
}

func (publisher *Publisher) ensureRelease(artifact Artifact) (string, error) {
	target := filepath.Join(publisher.stateRoot, "versions", artifact.Digest)
	if _, err := os.Lstat(target); err == nil {
		release, err := publisher.readRelease(artifact.Digest)
		if err != nil || release.Digest != artifact.Digest {
			return "", fmt.Errorf("existing origin route release is invalid")
		}
		return target, nil
	} else if !errors.Is(err, os.ErrNotExist) {
		return "", err
	}
	staging, err := os.MkdirTemp(filepath.Join(publisher.stateRoot, "staging"), ".originroute-")
	if err != nil {
		return "", err
	}
	defer func() { _ = os.RemoveAll(staging) }()
	if err := os.Chmod(staging, 0o700); err != nil {
		return "", err
	}
	for name, content := range map[string][]byte{"policy.json": artifact.Policy, "nginx.conf": artifact.Nginx} {
		if err := writeDurableFile(filepath.Join(staging, name), content); err != nil {
			return "", err
		}
	}
	if err := syncDirectory(staging); err != nil {
		return "", err
	}
	if err := os.Rename(staging, target); err != nil {
		if _, statErr := os.Lstat(target); statErr != nil {
			return "", err
		}
	}
	if err := os.Chmod(target, 0o500); err != nil {
		return "", err
	}
	if err := syncDirectory(filepath.Join(publisher.stateRoot, "versions")); err != nil {
		return "", err
	}
	if _, err := publisher.readRelease(artifact.Digest); err != nil {
		return "", err
	}
	return target, nil
}

func writeDurableFile(path string, content []byte) error {
	file, err := os.OpenFile(path, os.O_WRONLY|os.O_CREATE|os.O_EXCL, 0o400)
	if err != nil {
		return err
	}
	if _, err = file.Write(content); err == nil {
		err = file.Sync()
	}
	closeErr := file.Close()
	if err != nil {
		return err
	}
	return closeErr
}

func syncDirectory(path string) error {
	directory, err := os.Open(path)
	if err != nil {
		return err
	}
	defer directory.Close()
	return directory.Sync()
}

func (publisher *Publisher) readRelease(digest string) (Artifact, error) {
	if !digestPattern.MatchString(digest) {
		return Artifact{}, fmt.Errorf("invalid release digest")
	}
	path := filepath.Join(publisher.stateRoot, "versions", digest)
	info, err := os.Lstat(path)
	if err != nil || !info.IsDir() || info.Mode()&os.ModeSymlink != 0 || info.Mode().Perm() != 0o500 {
		return Artifact{}, fmt.Errorf("unsafe release directory")
	}
	entries, err := os.ReadDir(path)
	if err != nil {
		return Artifact{}, err
	}
	names := make([]string, len(entries))
	for index, entry := range entries {
		names[index] = entry.Name()
	}
	sort.Strings(names)
	if len(names) != 2 || names[0] != "nginx.conf" || names[1] != "policy.json" {
		return Artifact{}, fmt.Errorf("release file set is invalid: %v", names)
	}
	policyBytes, err := readRegularFile(filepath.Join(path, "policy.json"))
	if err != nil {
		return Artifact{}, err
	}
	nginx, err := readRegularFile(filepath.Join(path, "nginx.conf"))
	if err != nil {
		return Artifact{}, err
	}
	policy, err := Parse(policyBytes)
	if err != nil {
		return Artifact{}, err
	}
	expected, err := Compile(policy, publisher.stateRoot, publisher.luaRoot)
	if err != nil || expected.Digest != digest || !bytes.Equal(expected.Nginx, nginx) || !bytes.Equal(expected.Policy, policyBytes) {
		return Artifact{}, fmt.Errorf("release digest or content is invalid")
	}
	return expected, nil
}

func readRegularFile(path string) ([]byte, error) {
	info, err := os.Lstat(path)
	if err != nil {
		return nil, invalid("release file must be a single-link regular 0400 file")
	}
	stat, hasStat := info.Sys().(*syscall.Stat_t)
	if !info.Mode().IsRegular() || info.Mode().Perm() != 0o400 || !hasStat || stat.Nlink != 1 {
		return nil, invalid("release file must be a single-link regular 0400 file")
	}
	file, err := os.Open(path)
	if err != nil {
		return nil, err
	}
	defer file.Close()
	return io.ReadAll(io.LimitReader(file, maxPolicyBytes+1))
}

func (publisher *Publisher) pointer(name string) (string, error) {
	path := filepath.Join(publisher.stateRoot, name)
	info, err := os.Lstat(path)
	if errors.Is(err, os.ErrNotExist) {
		return "", nil
	}
	if err != nil || info.Mode()&os.ModeSymlink == 0 {
		return "", fmt.Errorf("unsafe %s pointer", name)
	}
	target, err := os.Readlink(path)
	if err != nil || filepath.Dir(target) != "versions" || !digestPattern.MatchString(filepath.Base(target)) {
		return "", fmt.Errorf("unsafe %s pointer target", name)
	}
	return filepath.Base(target), nil
}

func (publisher *Publisher) setPointer(name, digest string) error {
	if !digestPattern.MatchString(digest) {
		return fmt.Errorf("invalid pointer digest")
	}
	temporary, err := os.CreateTemp(publisher.stateRoot, "."+name+"-")
	if err != nil {
		return err
	}
	temporaryPath := temporary.Name()
	if err := temporary.Close(); err != nil {
		return err
	}
	if err := os.Remove(temporaryPath); err != nil {
		return err
	}
	defer os.Remove(temporaryPath)
	if err := os.Symlink(filepath.Join("versions", digest), temporaryPath); err != nil {
		return err
	}
	if err := os.Rename(temporaryPath, filepath.Join(publisher.stateRoot, name)); err != nil {
		return err
	}
	return syncDirectory(publisher.stateRoot)
}

func (publisher *Publisher) removePointer(name string) error {
	err := os.Remove(filepath.Join(publisher.stateRoot, name))
	if errors.Is(err, os.ErrNotExist) {
		return nil
	}
	if err != nil {
		return err
	}
	return syncDirectory(publisher.stateRoot)
}
