package certstore

import (
	"context"
	"crypto/sha256"
	"encoding/hex"
	"errors"
	"fmt"
	"os"
	"path/filepath"
	"slices"
	"sync"
	"time"
)

type Manager struct {
	mu      sync.Mutex
	config  RuntimeConfig
	store   *diskStore
	runtime Runtime
	now     func() time.Time
	cache   *indexCache
}

func NewManager(config RuntimeConfig, runtime Runtime) (*Manager, error) {
	return newManager(config, runtime, time.Now)
}

func newManager(config RuntimeConfig, runtime Runtime, now func() time.Time) (*Manager, error) {
	if err := validateRuntimeConfig(config); err != nil {
		return nil, err
	}
	if runtime == nil || now == nil {
		return nil, invalid("runtime and clock are required")
	}
	store, err := newDiskStore(config.StateRoot)
	if err != nil {
		return nil, err
	}
	return &Manager{config: config, store: store, runtime: runtime, now: now, cache: newIndexCache()}, nil
}

func (manager *Manager) ApplyJSON(ctx context.Context, raw []byte) (Result, error) {
	artifact, err := CompileJSON(raw, manager.config, manager.now())
	if err != nil {
		return Result{}, err
	}
	return manager.apply(ctx, artifact)
}

func (manager *Manager) Apply(ctx context.Context, bundle Bundle) (Result, error) {
	artifact, err := Compile(bundle, manager.config, manager.now())
	if err != nil {
		return Result{}, err
	}
	return manager.apply(ctx, artifact)
}

func (manager *Manager) ApplyWithActivation(ctx context.Context, bundle Bundle, activation ActivationMetadata) (Result, error) {
	artifact, err := CompileWithActivation(bundle, manager.config, manager.now(), activation)
	if err != nil {
		return Result{}, err
	}
	return manager.apply(ctx, artifact)
}

func (manager *Manager) apply(ctx context.Context, artifact Artifact) (Result, error) {
	manager.mu.Lock()
	defer manager.mu.Unlock()
	if err := ctx.Err(); err != nil {
		return Result{}, err
	}
	unlock, err := manager.store.lock(ctx)
	if err != nil {
		return Result{}, err
	}
	defer unlock()
	if err := manager.settlePendingIndex(); err != nil {
		return Result{}, err
	}

	previousTarget, err := manager.store.readPointer("current")
	if err != nil {
		return Result{}, err
	}
	previousLKG, err := manager.store.readPointer("lkg")
	if err != nil {
		return Result{}, err
	}
	previousStatus, err := manager.store.readStatus()
	if err != nil {
		return Result{}, err
	}
	var previousArtifact Artifact
	if previousTarget != "" {
		previousArtifact, err = manager.loadArtifact(previousTarget)
		if err != nil {
			return Result{}, err
		}
	}
	if err := validateCommandReplay(previousArtifact.Activation, artifact.Activation, previousTarget != ""); err != nil {
		return failedResult(artifact, previousArtifact, "STALE_CERTIFICATE_VERSION", true), err
	}
	journal, err := manager.planIndex(artifact)
	if errors.Is(err, ErrStaleActivation) {
		return failedResult(artifact, previousArtifact, "STALE_CERTIFICATE_VERSION", true), err
	}
	if errors.Is(err, ErrConflict) || errors.Is(err, ErrInvalidBundle) {
		return failedResult(artifact, previousArtifact, "CERTIFICATE_VERSION_CONFLICT", true), err
	}
	if err != nil {
		return Result{}, err
	}
	target := filepath.Join("versions", artifact.VersionID+"-"+artifact.Digest)
	if previousTarget == target {
		return resultFromStatus(artifact, previousStatus, false), nil
	}

	stage, err := manager.store.stage(artifact)
	if err != nil {
		return Result{}, err
	}
	stageExists := true
	defer func() {
		if stageExists {
			_ = os.RemoveAll(stage)
		}
	}()
	if err := manager.runtime.Precheck(ctx, stage); err != nil {
		return failedResult(artifact, previousArtifact, "PRECHECK_FAILED", true), sanitized(ctx, ErrPrecheck)
	}
	target, err = manager.store.commit(stage, artifact)
	if err != nil {
		return Result{}, err
	}
	stageExists = false
	// The index change is bound to the release before current names it.
	if len(journal.Sites) != 0 {
		if err := manager.store.writeIndexJournal(journal); err != nil {
			return Result{}, err
		}
	}
	rollback := func() error {
		return errors.Join(manager.restore(previousTarget, previousLKG, previousStatus, previousArtifact), manager.settleIndexFor(previousTarget))
	}
	if err := manager.store.setPointer("current", target); err != nil {
		if rollbackErr := rollback(); rollbackErr != nil {
			return Result{}, ErrRollback
		}
		return Result{}, err
	}
	if err := manager.runtime.Activate(ctx, manager.store.current); err != nil {
		if rollbackErr := rollback(); rollbackErr != nil {
			return failedResult(artifact, previousArtifact, "ROLLBACK_FAILED", false), ErrRollback
		}
		return failedResult(artifact, previousArtifact, "ACTIVATION_FAILED", true), sanitized(ctx, ErrActivation)
	}
	if err := manager.runtime.Healthy(ctx, artifact.HealthTargets); err != nil {
		if rollbackErr := rollback(); rollbackErr != nil {
			return failedResult(artifact, previousArtifact, "ROLLBACK_FAILED", false), ErrRollback
		}
		return failedResult(artifact, previousArtifact, "HEALTH_FAILED", true), sanitized(ctx, ErrHealth)
	}
	if err := manager.store.setPointer("lkg", target); err != nil {
		if rollbackErr := rollback(); rollbackErr != nil {
			return Result{}, ErrRollback
		}
		return Result{}, err
	}
	status := statusFromArtifact(artifact, manager.now())
	if err := manager.store.writeStatus(status); err != nil {
		if rollbackErr := rollback(); rollbackErr != nil {
			return Result{}, ErrRollback
		}
		return Result{}, err
	}
	// The release is active and healthy: apply its index change. If this is
	// interrupted, the next apply or Recover finishes it (settlePendingIndex).
	if err := manager.settleIndexFor(target); err != nil {
		return Result{}, err
	}
	// Keep the release this one replaced as a rollback anchor (bounded).
	manager.store.pruneReleases(target, previousTarget)
	return resultFromStatus(artifact, status, true), nil
}

func (manager *Manager) Recover(ctx context.Context) (Result, error) {
	manager.mu.Lock()
	defer manager.mu.Unlock()
	unlock, err := manager.store.lock(ctx)
	if err != nil {
		return Result{}, err
	}
	defer unlock()
	current, err := manager.store.readPointer("current")
	if err != nil {
		return Result{}, err
	}
	lkg, err := manager.store.readPointer("lkg")
	if err != nil {
		return Result{}, err
	}
	status, err := manager.store.readStatus()
	if err != nil {
		return Result{}, err
	}
	originalStatus := status
	var originalArtifact Artifact
	var originalErr error
	if current != "" {
		originalArtifact, originalErr = manager.loadArtifact(current)
	}
	if current == "" && lkg == "" {
		if !emptyStatus(status) {
			return Result{}, fmt.Errorf("%w: status exists without a certificate pointer", ErrUnsafeState)
		}
		pristine, err := manager.store.pristine()
		if err != nil {
			return Result{}, err
		}
		if !pristine {
			return Result{}, fmt.Errorf("%w: certificate state is incomplete", ErrUnsafeState)
		}
		return Result{}, nil
	}
	var originalHealth []HealthTarget
	if originalErr == nil {
		originalHealth = cloneHealthTargets(originalArtifact.HealthTargets)
	} else {
		if lkg == "" || lkg == current || !status.Active || current != statusTarget(status) {
			return Result{}, errors.Join(originalErr, ErrUnsafeState)
		}
		originalHealth, err = decodeStatusHealthTargets(status.HealthTargets)
		if err != nil || len(originalHealth) == 0 {
			return Result{}, errors.Join(originalErr, ErrUnsafeState)
		}
		if err := manager.runtime.Precheck(ctx, filepath.Join(manager.store.root, current)); err != nil {
			return Result{}, errors.Join(originalErr, sanitized(ctx, ErrPrecheck))
		}
	}
	restoreOriginal := func() error {
		return manager.restoreState(current, lkg, originalStatus, originalHealth)
	}

	candidates := []string{current}
	if originalErr != nil {
		candidates = candidates[:0]
	}
	if lkg != "" && lkg != current {
		candidates = append(candidates, lkg)
	}
	var lastErr error
	for _, target := range candidates {
		if target == "" {
			continue
		}
		artifact, err := manager.loadArtifact(target)
		if err != nil {
			lastErr = err
			continue
		}
		release := filepath.Join(manager.store.root, target)
		if err := manager.runtime.Precheck(ctx, release); err != nil {
			if ctxErr := ctx.Err(); ctxErr != nil {
				return Result{}, ctxErr
			}
			if errors.Is(err, context.Canceled) || errors.Is(err, context.DeadlineExceeded) {
				return Result{}, err
			}
			lastErr = ErrPrecheck
			continue
		}
		if err := manager.store.setPointer("current", target); err != nil {
			if rollbackErr := restoreOriginal(); rollbackErr != nil {
				return Result{}, errors.Join(originalErr, ErrRollback)
			}
			return Result{}, errors.Join(originalErr, err)
		}
		if err := manager.runtime.Activate(ctx, manager.store.current); err != nil {
			if rollbackErr := restoreOriginal(); rollbackErr != nil {
				return Result{}, errors.Join(originalErr, ErrRollback)
			}
			if ctxErr := ctx.Err(); ctxErr != nil {
				return Result{}, errors.Join(originalErr, ctxErr)
			}
			if errors.Is(err, context.Canceled) || errors.Is(err, context.DeadlineExceeded) {
				return Result{}, errors.Join(originalErr, err)
			}
			lastErr = ErrActivation
			continue
		}
		if err := manager.runtime.Healthy(ctx, artifact.HealthTargets); err != nil {
			if rollbackErr := restoreOriginal(); rollbackErr != nil {
				return Result{}, errors.Join(originalErr, ErrRollback)
			}
			if ctxErr := ctx.Err(); ctxErr != nil {
				return Result{}, errors.Join(originalErr, ctxErr)
			}
			if errors.Is(err, context.Canceled) || errors.Is(err, context.DeadlineExceeded) {
				return Result{}, errors.Join(originalErr, err)
			}
			lastErr = ErrHealth
			continue
		}
		if err := manager.store.setPointer("lkg", target); err != nil {
			if rollbackErr := restoreOriginal(); rollbackErr != nil {
				return Result{}, errors.Join(originalErr, ErrRollback)
			}
			return Result{}, errors.Join(originalErr, err)
		}
		if !status.Active || status.VersionID != artifact.VersionID || status.Digest != artifact.Digest ||
			!sameActivationMetadata(status.Activation, artifact.Activation) || !sameStatusHealthTargets(status.HealthTargets, artifact.HealthTargets) {
			status = statusFromArtifact(artifact, manager.now())
			if err := manager.store.writeStatus(status); err != nil {
				if rollbackErr := restoreOriginal(); rollbackErr != nil {
					return Result{}, errors.Join(originalErr, ErrRollback)
				}
				return Result{}, errors.Join(originalErr, err)
			}
		}
		// target stays active: apply its pending index change, or discard
		// the change of a release that did not become active.
		if err := manager.settleIndexFor(target); err != nil {
			return Result{}, errors.Join(originalErr, err)
		}
		manager.store.pruneReleases(target, current, lkg)
		return resultFromStatus(artifact, status, false), nil
	}
	if lastErr == nil {
		lastErr = ErrHealth
	}
	return Result{}, errors.Join(originalErr, lastErr)
}

func (manager *Manager) Status(ctx context.Context) (Status, error) {
	manager.mu.Lock()
	defer manager.mu.Unlock()
	unlock, err := manager.store.lock(ctx)
	if err != nil {
		return Status{}, err
	}
	defer unlock()
	return manager.store.readStatus()
}

func (manager *Manager) CertificateVersionReferences(ctx context.Context) (CertificateVersionReferences, error) {
	manager.mu.Lock()
	defer manager.mu.Unlock()
	if err := ctx.Err(); err != nil {
		return CertificateVersionReferences{}, err
	}
	unlock, err := manager.store.lock(ctx)
	if err != nil {
		return CertificateVersionReferences{}, err
	}
	defer unlock()
	return manager.store.readCertificateVersionReferences()
}

func (manager *Manager) loadArtifact(target string) (Artifact, error) {
	bundle, activation, err := manager.store.readBundle(target)
	if err != nil {
		return Artifact{}, err
	}
	// A stored release was validated when it was activated and its digest is
	// checked below; it stays loadable after a certificate in it expires.
	artifact, err := compile(bundle, manager.config, manager.now(), activation, false)
	if err != nil {
		return Artifact{}, err
	}
	if target != filepath.Join("versions", artifact.VersionID+"-"+artifact.Digest) {
		return Artifact{}, fmt.Errorf("%w: release digest does not match its content", ErrUnsafeState)
	}
	if err := validateReleaseFiles(filepath.Join(manager.store.root, target), artifact); err != nil {
		return Artifact{}, err
	}
	return artifact, nil
}

func readImmutableCertificateFile(path string, maximum int64) ([]byte, error) {
	content, err := validatePrivateFile(path, maximum)
	if err != nil {
		return nil, err
	}
	info, err := os.Lstat(path)
	if err != nil || !info.Mode().IsRegular() || info.Mode().Perm() != 0o400 || info.Mode()&os.ModeSymlink != 0 {
		clearBytesInPlace(content)
		return nil, fmt.Errorf("%w: certificate material is not immutable", ErrUnsafeState)
	}
	return content, nil
}

func clearBytesInPlace(value []byte) {
	for index := range value {
		value[index] = 0
	}
}

func (manager *Manager) restore(previousTarget, previousLKG string, previousStatus Status, previousArtifact Artifact) error {
	return manager.restoreState(previousTarget, previousLKG, previousStatus, previousArtifact.HealthTargets)
}

func (manager *Manager) restoreState(target, lkg string, status Status, health []HealthTarget) error {
	if err := manager.setPointer("current", target); err != nil {
		return err
	}
	runtimeErr := manager.restoreRuntime(target, health)
	factsErr := manager.restoreFacts(lkg, status)
	return errors.Join(runtimeErr, factsErr)
}

func (manager *Manager) restoreRuntime(target string, health []HealthTarget) error {
	ctx, cancel := context.WithTimeout(context.Background(), 10*time.Second)
	defer cancel()
	if target == "" {
		return manager.runtime.Stop(ctx, manager.store.current)
	}
	current, err := manager.store.readPointer("current")
	if err != nil || current != target {
		return fmt.Errorf("%w: current pointer does not match the rollback target", ErrUnsafeState)
	}
	release := filepath.Join(manager.store.root, target)
	if err := manager.runtime.Precheck(ctx, release); err != nil {
		return err
	}
	if err := manager.runtime.Activate(ctx, manager.store.current); err != nil {
		return err
	}
	return manager.runtime.Healthy(ctx, health)
}

func (manager *Manager) restoreFacts(lkg string, status Status) error {
	lkgErr := manager.setPointer("lkg", lkg)
	var statusErr error
	if status.SchemaVersion == "" {
		statusErr = manager.store.removeStatus()
	} else {
		statusErr = manager.store.writeStatus(status)
	}
	return errors.Join(lkgErr, statusErr)
}

func (manager *Manager) setPointer(name, target string) error {
	if target == "" {
		return manager.store.clearPointer(name)
	}
	return manager.store.setPointer(name, target)
}

func statusFromArtifact(artifact Artifact, now time.Time) Status {
	return Status{
		Active: true, VersionID: artifact.VersionID, Digest: artifact.Digest,
		Activation: cloneActivation(artifact.Activation), HealthTargets: encodeStatusHealthTargets(artifact.HealthTargets), AppliedAt: now.UTC(),
	}
}

func statusTarget(status Status) string {
	if !status.Active || !validIdentifier(status.VersionID, MaxVersionIDBytes) || !validDigest(status.Digest) {
		return ""
	}
	return filepath.Join("versions", status.VersionID+"-"+status.Digest)
}

func encodeStatusHealthTargets(targets []HealthTarget) []StatusHealthTarget {
	encoded := make([]StatusHealthTarget, len(targets))
	for index, target := range targets {
		encoded[index] = StatusHealthTarget{ServerName: target.ServerName, LeafSHA256: hex.EncodeToString(target.LeafSHA256[:])}
	}
	return encoded
}

func decodeStatusHealthTargets(targets []StatusHealthTarget) ([]HealthTarget, error) {
	decoded := make([]HealthTarget, len(targets))
	seen := make(map[string]struct{}, len(targets))
	for index, target := range targets {
		normalized, err := normalizeDomain(target.ServerName, false)
		if err != nil || normalized != target.ServerName || len(target.LeafSHA256) != sha256.Size*2 {
			return nil, fmt.Errorf("%w: status health target is invalid", ErrUnsafeState)
		}
		digest, err := hex.DecodeString(target.LeafSHA256)
		if err != nil || hex.EncodeToString(digest) != target.LeafSHA256 {
			return nil, fmt.Errorf("%w: status health digest is invalid", ErrUnsafeState)
		}
		if _, exists := seen[target.ServerName]; exists {
			return nil, fmt.Errorf("%w: duplicate status health target", ErrUnsafeState)
		}
		seen[target.ServerName] = struct{}{}
		decoded[index].ServerName = target.ServerName
		copy(decoded[index].LeafSHA256[:], digest)
	}
	return decoded, nil
}

func sameStatusHealthTargets(status []StatusHealthTarget, artifact []HealthTarget) bool {
	decoded, err := decodeStatusHealthTargets(status)
	return err == nil && sameHealthTargets(decoded, artifact)
}

func sameHealthTargets(left, right []HealthTarget) bool {
	if len(left) != len(right) {
		return false
	}
	for index := range left {
		if left[index] != right[index] {
			return false
		}
	}
	return true
}

func cloneHealthTargets(targets []HealthTarget) []HealthTarget {
	return append([]HealthTarget(nil), targets...)
}

func validDigest(value string) bool {
	if len(value) != sha256.Size*2 {
		return false
	}
	decoded, err := hex.DecodeString(value)
	return err == nil && hex.EncodeToString(decoded) == value
}

func emptyStatus(status Status) bool {
	return status.SchemaVersion == "" && !status.Active && status.VersionID == "" && status.Digest == "" &&
		status.Activation == nil && len(status.HealthTargets) == 0 && status.AppliedAt.IsZero()
}

func resultFromStatus(artifact Artifact, status Status, changed bool) Result {
	return Result{
		VersionID: artifact.VersionID, Digest: artifact.Digest,
		ActiveVersionID: status.VersionID, ActiveDigest: status.Digest,
		Changed: changed, RunningVersionUnchanged: !changed, AppliedAt: status.AppliedAt,
	}
}

func failedResult(candidate Artifact, previous Artifact, code string, unchanged bool) Result {
	result := Result{VersionID: candidate.VersionID, Digest: candidate.Digest, ErrorCode: code, RunningVersionUnchanged: unchanged}
	if previous.VersionID != "" {
		result.ActiveVersionID = previous.VersionID
		result.ActiveDigest = previous.Digest
	}
	return result
}

func sanitized(ctx context.Context, fallback error) error {
	if err := ctx.Err(); err != nil {
		return err
	}
	return fallback
}

func IsRejectedCandidate(err error) bool {
	return errors.Is(err, ErrInvalidBundle) || errors.Is(err, ErrConflict) || errors.Is(err, ErrPrecheck)
}

func cloneActivation(value *ActivationMetadata) *ActivationMetadata {
	if value == nil {
		return nil
	}
	result := *value
	result.Certificates = make([]CertificateRevision, len(value.Certificates))
	copy(result.Certificates, value.Certificates)
	result.RemovedSites = append([]RemovedSite(nil), value.RemovedSites...)
	if len(result.RemovedSites) == 0 {
		result.RemovedSites = nil
	}
	return &result
}

func sameActivationMetadata(left, right *ActivationMetadata) bool {
	if left == nil || right == nil {
		return left == nil && right == nil
	}
	return sameActivationCommand(left, right) && sameCertificateRevisions(left.Certificates, right.Certificates) &&
		slices.Equal(left.RemovedSites, right.RemovedSites)
}
