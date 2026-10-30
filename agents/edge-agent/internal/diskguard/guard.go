package diskguard

import (
	"context"
	"errors"
	"fmt"
	"math/bits"
	"os"
	"path/filepath"
	"sort"
	"strings"
	"sync"
	"sync/atomic"
	"time"

	"golang.org/x/sys/unix"
)

const defaultMaxScanEntries = 100000

type usageProvider interface {
	usage(*openDirectory) (filesystemUsage, error)
}

type nativeUsageProvider struct{}

func (nativeUsageProvider) usage(directory *openDirectory) (filesystemUsage, error) {
	return directory.usage()
}

type testHooks struct {
	beforeQuarantine func(*openDirectory, candidate)
	afterQuarantine  func(*openDirectory, candidate, string)
}

type Guard struct {
	config         Config
	sink           EventSink
	now            func() time.Time
	usage          usageProvider
	hooks          testHooks
	maxScanEntries int

	roundMu    sync.Mutex
	pressure   map[uint64]bool
	snapshotMu sync.RWMutex
	snapshot   Metrics

	evaluations  atomic.Uint64
	failures     atomic.Uint64
	deleted      atomic.Uint64
	deletedBytes atomic.Uint64
}

type directoryPlan struct {
	config     ManagedDirectory
	directory  *openDirectory
	usage      filesystemUsage
	used       uint16
	pressure   bool
	candidates []candidate
}

type candidate struct {
	directoryIndex int
	directoryID    string
	name           string
	kind           DirectoryKind
	priority       int
	modified       fileTimestamp
	allocatedBytes uint64
	identity       fileIdentity
	size           int64
}

type evaluationFailure struct {
	reason FailureReason
	cause  error
}

func (failure *evaluationFailure) Error() string {
	return fmt.Sprintf("%v: %v", ErrEvaluation, failure.cause)
}

func (failure *evaluationFailure) Unwrap() []error {
	return []error{ErrEvaluation, failure.cause}
}

func newEvaluationFailure(reason FailureReason, format string, arguments ...any) error {
	return &evaluationFailure{reason: reason, cause: fmt.Errorf(format, arguments...)}
}

func New(config Config, options Options) (*Guard, error) {
	if err := validateConfig(config); err != nil {
		return nil, err
	}
	if options.MaxScanEntries < 0 || options.MaxScanEntries > defaultMaxScanEntries {
		return nil, ErrInvalidConfig
	}
	if err := preflightRuntimePaths(config); err != nil {
		return nil, err
	}
	maxScanEntries := options.MaxScanEntries
	if maxScanEntries == 0 {
		maxScanEntries = defaultMaxScanEntries
	}
	guard := &Guard{
		config: cloneConfig(config), sink: options.EventSink, now: time.Now,
		usage: nativeUsageProvider{}, pressure: make(map[uint64]bool), maxScanEntries: maxScanEntries,
	}
	guard.snapshot = Metrics{
		SchemaVersion: SchemaVersion, ObservedAt: guard.now().UTC(), ConfigID: config.ConfigID,
		ConfigRevision: config.Revision, DryRun: config.DryRun,
	}
	return guard, nil
}

func preflightRuntimePaths(config Config) error {
	paths := make([]string, 0, len(config.Directories)+1)
	paths = append(paths, filepath.Dir(config.LockPath))
	for _, directory := range config.Directories {
		paths = append(paths, directory.Path)
	}
	seen := make(map[string]*openDirectory, len(paths))
	managed := make([]*openDirectory, 0, len(config.Directories))
	managedAncestors := make([][]fileIdentity, 0, len(config.Directories))
	defer func() {
		for _, directory := range seen {
			directory.close()
		}
	}()
	for _, path := range paths {
		if _, exists := seen[path]; exists {
			continue
		}
		directory, err := secureOpenDirectory(path)
		if err != nil || !directory.unchanged() || !directory.writableOnlyByOwner() {
			if directory != nil {
				directory.close()
			}
			return ErrInvalidConfig
		}
		seen[path] = directory
	}
	for _, configDirectory := range config.Directories {
		managed = append(managed, seen[configDirectory.Path])
		physicalAncestors, err := secureAncestorIdentities(configDirectory.Path)
		if err != nil {
			return ErrInvalidConfig
		}
		managedAncestors = append(managedAncestors, physicalAncestors)
	}
	for _, protectedPath := range config.ProtectedPaths {
		resolved, physicalAncestors, endpointExists, err := resolveProtectedPath(protectedPath)
		if err != nil || !safeAbsolutePath(resolved) {
			return ErrInvalidConfig
		}
		for index, managedDirectory := range managed {
			physicalOverlap := containsIdentity(physicalAncestors, managedAncestors[index][0])
			if endpointExists {
				physicalOverlap = physicalPathsOverlap(managedAncestors[index], physicalAncestors)
			}
			if physicalOverlap ||
				pathsOverlap(resolved, managedDirectory.path) {
				return ErrInvalidConfig
			}
		}
	}
	if err := validateLockPath(config.LockPath); err != nil {
		return ErrInvalidConfig
	}
	return nil
}

func resolveProtectedPath(protectedPath string) (string, []fileIdentity, bool, error) {
	existing := protectedPath
	suffix := ""
	for {
		resolved, err := filepath.EvalSymlinks(existing)
		if err == nil {
			identities, identityErr := secureAncestorIdentities(resolved)
			if identityErr != nil {
				return "", nil, false, identityErr
			}
			endpointExists := suffix == ""
			if suffix != "" {
				resolved = filepath.Join(resolved, suffix)
			}
			return filepath.Clean(resolved), identities, endpointExists, nil
		}
		if !errors.Is(err, os.ErrNotExist) || existing == "/" {
			return "", nil, false, err
		}
		if _, lstatErr := os.Lstat(existing); lstatErr == nil {
			return "", nil, false, err
		} else if !errors.Is(lstatErr, os.ErrNotExist) {
			return "", nil, false, lstatErr
		}
		base := filepath.Base(existing)
		if suffix == "" {
			suffix = base
		} else {
			suffix = filepath.Join(base, suffix)
		}
		existing = filepath.Dir(existing)
	}
}

func secureAncestorIdentities(path string) ([]fileIdentity, error) {
	identities := make([]fileIdentity, 0, 8)
	for current := path; ; current = filepath.Dir(current) {
		directory, err := secureOpenDirectory(current)
		if err != nil {
			return nil, err
		}
		identities = append(identities, directory.identity)
		directory.close()
		if current == "/" {
			return identities, nil
		}
	}
}

func physicalPathsOverlap(left, right []fileIdentity) bool {
	if len(left) == 0 || len(right) == 0 {
		return false
	}
	return containsIdentity(right, left[0]) || containsIdentity(left, right[0])
}

func containsIdentity(identities []fileIdentity, target fileIdentity) bool {
	for _, identity := range identities {
		if identity.sameFile(target) {
			return true
		}
	}
	return false
}

func cloneConfig(config Config) Config {
	cloned := config
	cloned.Directories = make([]ManagedDirectory, len(config.Directories))
	cloned.ProtectedPaths = append([]string(nil), config.ProtectedPaths...)
	for index, directory := range config.Directories {
		cloned.Directories[index] = directory
		cloned.Directories[index].Patterns = append([]string(nil), directory.Patterns...)
		cloned.Directories[index].ActiveNames = append([]string(nil), directory.ActiveNames...)
	}
	return cloned
}

func (guard *Guard) Evaluate(ctx context.Context) (Report, error) {
	if !guard.roundMu.TryLock() {
		report := guard.newReport()
		guard.fail(ctx, &report, FailureLockHeld)
		return report, ErrAlreadyRunning
	}
	defer guard.roundMu.Unlock()
	unlock, err := acquireFileLock(guard.config.LockPath)
	if err != nil {
		report := guard.newReport()
		reason := FailureLockUnsafe
		if errors.Is(err, ErrAlreadyRunning) {
			reason = FailureLockHeld
		}
		guard.fail(ctx, &report, reason)
		return report, err
	}
	defer unlock()
	return guard.evaluateLocked(ctx)
}

func (guard *Guard) Run(ctx context.Context) error {
	if !guard.roundMu.TryLock() {
		return ErrAlreadyRunning
	}
	defer guard.roundMu.Unlock()
	unlock, err := acquireFileLock(guard.config.LockPath)
	if err != nil {
		report := guard.newReport()
		reason := FailureLockUnsafe
		if errors.Is(err, ErrAlreadyRunning) {
			reason = FailureLockHeld
		}
		guard.fail(ctx, &report, reason)
		return err
	}
	defer unlock()

	ticker := time.NewTicker(guard.config.EvaluationPeriod)
	defer ticker.Stop()
	for {
		select {
		case <-ctx.Done():
			return nil
		default:
		}
		_, _ = guard.evaluateLocked(ctx)
		select {
		case <-ctx.Done():
			return nil
		case <-ticker.C:
		}
	}
}

func (guard *Guard) evaluateLocked(ctx context.Context) (report Report, returnErr error) {
	report = guard.newReport()
	defer func() { guard.storeSnapshot(report.Metrics) }()
	guard.record(ctx, &report, Event{Code: EventEvaluationStarted})
	if err := ctx.Err(); err != nil {
		guard.fail(ctx, &report, FailureCancelled)
		return report, newEvaluationFailure(FailureCancelled, "%w", err)
	}
	if err := guard.recoverQuarantines(ctx); err != nil {
		guard.fail(ctx, &report, failureReason(err))
		return report, err
	}

	plans, nextPressure, err := guard.preflight(ctx, &report)
	if err != nil {
		guard.fail(ctx, &report, failureReason(err))
		return report, err
	}
	defer closePlans(plans)
	guard.pressure = nextPressure

	allCandidates := make([]candidate, 0)
	for index := range plans {
		report.Metrics.Directories = append(report.Metrics.Directories, DirectoryMetric{
			DirectoryID:     plans[index].config.ID,
			UsedBasisPoints: plans[index].used,
			Pressure:        plans[index].pressure,
		})
		if plans[index].pressure {
			allCandidates = append(allCandidates, plans[index].candidates...)
		}
	}
	sort.Slice(allCandidates, func(left, right int) bool {
		if allCandidates[left].priority != allCandidates[right].priority {
			return allCandidates[left].priority < allCandidates[right].priority
		}
		if compared := allCandidates[left].modified.compare(allCandidates[right].modified); compared != 0 {
			return compared < 0
		}
		if allCandidates[left].directoryID != allCandidates[right].directoryID {
			return allCandidates[left].directoryID < allCandidates[right].directoryID
		}
		return allCandidates[left].name < allCandidates[right].name
	})
	report.Metrics.RoundCandidateFiles = len(allCandidates)
	budgetFiles := 0
	budgetBytes := uint64(0)

	for _, item := range allCandidates {
		if err := ctx.Err(); err != nil {
			guard.fail(ctx, &report, FailureCancelled)
			return report, newEvaluationFailure(FailureCancelled, "%w", err)
		}
		plan := &plans[item.directoryIndex]
		if !plan.pressure {
			continue
		}
		if budgetFiles >= guard.config.MaxDeletedFiles ||
			item.allocatedBytes > guard.config.MaxAllocatedBytes-budgetBytes {
			report.Metrics.RoundBudgetSkipped++
			continue
		}
		budgetFiles++
		budgetBytes += item.allocatedBytes
		if guard.config.DryRun {
			report.Metrics.RoundWouldDeleteFiles++
			report.Metrics.RoundWouldDeleteBytes += item.allocatedBytes
			guard.record(ctx, &report, eventForCandidate(EventCandidateWouldDelete, plan, item, true))
			continue
		}
		if err := guard.deleteCandidate(plan, item); err != nil {
			guard.fail(ctx, &report, failureReason(err))
			return report, err
		}
		report.Metrics.RoundDeletedFiles++
		report.Metrics.RoundDeletedBytes += item.allocatedBytes
		guard.deleted.Add(1)
		guard.deletedBytes.Add(item.allocatedBytes)
		guard.record(ctx, &report, eventForCandidate(EventCandidateDeleted, plan, item, false))

		usage, err := guard.usage.usage(plan.directory)
		if err != nil {
			guard.fail(ctx, &report, FailureUsageUnavailable)
			return report, newEvaluationFailure(FailureUsageUnavailable, "refresh usage: %w", err)
		}
		plan.usage = usage
		plan.used = usedBasisPoints(usage)
		for index := range plans {
			if plans[index].directory.identity.device == plan.directory.identity.device {
				plans[index].used = plan.used
			}
		}
		if plan.used <= guard.config.LowWatermark {
			for index := range plans {
				if plans[index].directory.identity.device != plan.directory.identity.device {
					continue
				}
				plans[index].pressure = false
				guard.pressure[plan.directory.identity.device] = false
				guard.record(ctx, &report, Event{
					Code: EventPressureRecovered, DirectoryID: plans[index].config.ID,
					UsedBasisPoints: plan.used,
				})
			}
		}
	}

	for index := range report.Metrics.Directories {
		for planIndex := range plans {
			if report.Metrics.Directories[index].DirectoryID == plans[planIndex].config.ID {
				report.Metrics.Directories[index].UsedBasisPoints = plans[planIndex].used
				report.Metrics.Directories[index].Pressure = plans[planIndex].pressure
			}
		}
	}
	report.Metrics.Healthy = true
	report.Metrics.DeletedFilesTotal = guard.deleted.Load()
	report.Metrics.DeletedBytesTotal = guard.deletedBytes.Load()
	guard.record(ctx, &report, Event{Code: EventEvaluationCompleted})
	return report, nil
}

func (guard *Guard) Snapshot() Metrics {
	guard.snapshotMu.RLock()
	defer guard.snapshotMu.RUnlock()
	return cloneMetrics(guard.snapshot)
}

func (guard *Guard) storeSnapshot(metrics Metrics) {
	guard.snapshotMu.Lock()
	guard.snapshot = cloneMetrics(metrics)
	guard.snapshotMu.Unlock()
}

func cloneMetrics(metrics Metrics) Metrics {
	cloned := metrics
	cloned.Directories = append([]DirectoryMetric(nil), metrics.Directories...)
	return cloned
}

func (guard *Guard) preflight(ctx context.Context, report *Report) ([]directoryPlan, map[uint64]bool, error) {
	nextPressure := make(map[uint64]bool, len(guard.pressure))
	for device, pressure := range guard.pressure {
		nextPressure[device] = pressure
	}
	plans := make([]directoryPlan, 0, len(guard.config.Directories))
	remainingScanEntries := guard.maxScanEntries
	for _, config := range guard.config.Directories {
		if err := ctx.Err(); err != nil {
			closePlans(plans)
			return nil, nextPressure, newEvaluationFailure(FailureCancelled, "%w", err)
		}
		directory, err := secureOpenDirectory(config.Path)
		if err != nil || !directory.unchanged() {
			if directory != nil {
				directory.close()
			}
			closePlans(plans)
			return nil, nextPressure, newEvaluationFailure(FailureDirectoryUnsafe, "unsafe managed directory")
		}
		usage, err := guard.usage.usage(directory)
		if err != nil {
			directory.close()
			closePlans(plans)
			return nil, nextPressure, newEvaluationFailure(FailureUsageUnavailable, "usage unavailable: %w", err)
		}
		used := usedBasisPoints(usage)
		wasPressure := nextPressure[directory.identity.device]
		pressure := wasPressure
		switch {
		case used >= guard.config.HighWatermark:
			pressure = true
		case used <= guard.config.LowWatermark:
			pressure = false
		}
		nextPressure[directory.identity.device] = pressure
		plan := directoryPlan{config: config, directory: directory, usage: usage, used: used, pressure: pressure}
		var scannedEntries int
		plan.candidates, scannedEntries, err = guard.scanDirectory(ctx, len(plans), &plan, report, remainingScanEntries)
		if err != nil {
			directory.close()
			closePlans(plans)
			return nil, nextPressure, err
		}
		remainingScanEntries -= scannedEntries
		plans = append(plans, plan)
		if pressure && !wasPressure {
			guard.record(ctx, report, Event{Code: EventPressureEntered, DirectoryID: config.ID, UsedBasisPoints: used})
		}
		if !pressure && wasPressure {
			guard.record(ctx, report, Event{Code: EventPressureRecovered, DirectoryID: config.ID, UsedBasisPoints: used})
		}
	}
	return plans, nextPressure, nil
}

func (guard *Guard) scanDirectory(ctx context.Context, directoryIndex int, plan *directoryPlan, report *Report, maxEntries int) ([]candidate, int, error) {
	names, err := plan.directory.names(maxEntries)
	if err != nil {
		return nil, 0, newEvaluationFailure(FailureScanFailed, "scan managed directory: %w", err)
	}
	now := guard.now()
	activeNames := make(map[string]struct{}, len(plan.config.ActiveNames))
	for _, name := range plan.config.ActiveNames {
		activeNames[name] = struct{}{}
	}
	candidates := make([]candidate, 0)
	for _, name := range names {
		if err := ctx.Err(); err != nil {
			return nil, 0, newEvaluationFailure(FailureCancelled, "%w", err)
		}
		if !safeBaseName(name) || !matchesPattern(plan.config.Patterns, name) {
			continue
		}
		if filepath.Join(plan.config.Path, name) == guard.config.LockPath {
			report.Metrics.RoundProtectedFiles++
			continue
		}
		if protectedName(name, activeNames) {
			report.Metrics.RoundProtectedFiles++
			continue
		}
		if plan.config.Kind == DirectoryRotatedLogs && !rotatedLogName(name) {
			report.Metrics.RoundUnsafeFiles++
			continue
		}
		metadata, err := plan.directory.metadata(name)
		if err != nil {
			return nil, 0, newEvaluationFailure(FailureScanFailed, "inspect candidate: %w", err)
		}
		if !metadata.regular || metadata.identity.links != 1 || metadata.identity.device != plan.directory.identity.device {
			report.Metrics.RoundUnsafeFiles++
			continue
		}
		fd, opened, err := plan.directory.openRegular(name)
		if err != nil {
			return nil, 0, newEvaluationFailure(FailureScanFailed, "open candidate during preflight: %w", err)
		}
		_ = unix.Close(fd)
		if !opened.sameCandidate(metadata) || opened.identity.device != plan.directory.identity.device {
			return nil, 0, newEvaluationFailure(FailureCandidateChanged, "candidate changed during preflight")
		}
		if !candidateOldEnough(metadata.modified, now, plan.config.MinimumAge) {
			continue
		}
		priority := 2
		if plan.config.Kind == DirectoryRotatedLogs && compressedLogName(name) {
			priority = 0
		} else if plan.config.Kind == DirectoryCacheTemp {
			priority = 1
		}
		candidates = append(candidates, candidate{
			directoryIndex: directoryIndex, directoryID: plan.config.ID, name: name, kind: plan.config.Kind,
			priority: priority, modified: metadata.modified, allocatedBytes: metadata.allocatedBytes,
			identity: metadata.identity, size: metadata.size,
		})
	}
	if plan.config.MinimumRemain >= len(candidates) {
		return nil, len(names), nil
	}
	sort.Slice(candidates, func(left, right int) bool {
		if compared := candidates[left].modified.compare(candidates[right].modified); compared != 0 {
			return compared > 0
		}
		return candidates[left].name > candidates[right].name
	})
	return candidates[plan.config.MinimumRemain:], len(names), nil
}

func (guard *Guard) deleteCandidate(plan *directoryPlan, item candidate) error {
	fd, metadata, err := plan.directory.openRegular(item.name)
	if err != nil {
		return newEvaluationFailure(FailureCandidateChanged, "candidate changed: %w", err)
	}
	defer unix.Close(fd)
	if !item.matches(metadata) || metadata.identity.device != plan.directory.identity.device ||
		!plan.directory.unchanged() {
		return newEvaluationFailure(FailureCandidateChanged, "candidate changed")
	}
	current, err := plan.directory.metadata(item.name)
	if err != nil || !current.sameCandidate(metadata) || !item.matches(current) || !plan.directory.unchanged() {
		return newEvaluationFailure(FailureCandidateChanged, "candidate changed")
	}
	quarantineRoot, err := openPrivateQuarantineRoot(plan.directory)
	if err != nil {
		return newEvaluationFailure(FailureDeleteFailed, "open private quarantine root: %w", err)
	}
	defer quarantineRoot.close()
	quarantine, namespace, err := createPrivateQuarantine(quarantineRoot)
	if err != nil {
		return newEvaluationFailure(FailureDeleteFailed, "create private quarantine: %w", err)
	}
	quarantineIdentity := quarantine.identity
	defer quarantine.close()
	intent := guard.newQuarantineIntent(plan, item, metadata, quarantineRoot, quarantine, namespace)
	if err := writeQuarantineIntent(quarantineRoot, intent); err != nil {
		removePrivateQuarantine(quarantineRoot, namespace, quarantineIdentity)
		return newEvaluationFailure(FailureDeleteFailed, "write quarantine intent: %v", err)
	}
	if err := syncDirectory(plan.directory.fd); err != nil {
		return newEvaluationFailure(FailureDeleteFailed, "sync quarantine intent: %w", err)
	}
	if guard.hooks.beforeQuarantine != nil {
		guard.hooks.beforeQuarantine(plan.directory, item)
	}
	current, nameErr := plan.directory.metadata(item.name)
	opened, fdErr := metadataForFD(fd)
	if nameErr != nil || fdErr != nil || !current.sameCandidate(metadata) || !opened.sameCandidate(metadata) ||
		!item.matches(current) || !plan.directory.unchanged() {
		_ = clearQuarantineIntent(quarantineRoot, item.name)
		_ = removePrivateQuarantineDurable(quarantineRoot, namespace, quarantineIdentity)
		return newEvaluationFailure(FailureCandidateChanged, "candidate changed after scan")
	}
	if err := unix.Renameat(plan.directory.fd, item.name, quarantine.fd, item.name); err != nil {
		_ = clearQuarantineIntent(quarantineRoot, item.name)
		_ = removePrivateQuarantineDurable(quarantineRoot, namespace, quarantineIdentity)
		return newEvaluationFailure(FailureDeleteFailed, "quarantine candidate: %w", err)
	}
	if err := syncDirectory(plan.directory.fd); err != nil {
		return newEvaluationFailure(FailureDeleteFailed, "sync managed directory after quarantine: %w", err)
	}
	if err := syncDirectory(quarantine.fd); err != nil {
		return newEvaluationFailure(FailureDeleteFailed, "sync quarantine after rename: %w", err)
	}
	intent.Renamed = true
	if err := writeQuarantineIntent(quarantineRoot, intent); err != nil {
		return newEvaluationFailure(FailureDeleteFailed, "commit quarantine intent: %w", err)
	}
	if guard.hooks.afterQuarantine != nil {
		guard.hooks.afterQuarantine(quarantine, item, item.name)
	}
	quarantined, nameErr := quarantine.metadata(item.name)
	opened, fdErr = metadataForFD(fd)
	if nameErr != nil || fdErr != nil || !quarantined.sameCandidate(metadata) || !opened.sameCandidate(metadata) ||
		!item.matches(quarantined) {
		restoreQuarantine(quarantine, item.name, plan.directory, item.name)
		return newEvaluationFailure(FailureCandidateChanged, "quarantined candidate changed (stat=%v regular=%t links=%d same=%t)",
			nameErr, quarantined.regular, quarantined.identity.links, quarantined.sameCandidate(metadata))
	}
	if !plan.directory.unchanged() ||
		!privateQuarantineMatches(plan.directory, quarantineRootName, quarantineRoot) ||
		!privateQuarantineMatches(quarantineRoot, namespace, quarantine) {
		restoreQuarantine(quarantine, item.name, plan.directory, item.name)
		return newEvaluationFailure(FailureCandidateChanged, "managed directory replaced")
	}
	if err := unlinkQuarantined(quarantine, item.name, fd, metadata); err != nil {
		restoreQuarantine(quarantine, item.name, plan.directory, item.name)
		return newEvaluationFailure(FailureDeleteFailed, "unlink candidate: %w", err)
	}
	if err := clearQuarantineIntent(quarantineRoot, item.name); err != nil {
		return newEvaluationFailure(FailureDeleteFailed, "clear quarantine intent: %w", err)
	}
	if err := removePrivateQuarantineDurable(quarantineRoot, namespace, quarantineIdentity); err != nil {
		return newEvaluationFailure(FailureDeleteFailed, "remove quarantine namespace: %w", err)
	}
	return nil
}

func (guard *Guard) newQuarantineIntent(plan *directoryPlan, item candidate, metadata fileMetadata,
	root, namespace *openDirectory, namespaceName string) quarantineIntent {
	return quarantineIntent{
		SchemaVersion: ConfigSchemaVersion, ConfigID: guard.config.ConfigID, ConfigRevision: guard.config.Revision,
		DirectoryID: plan.config.ID, DirectoryDevice: plan.directory.identity.device,
		DirectoryInode: plan.directory.identity.inode, PrivateRootDevice: root.identity.device,
		PrivateRootInode: root.identity.inode, NamespaceName: namespaceName,
		NamespaceDevice: namespace.identity.device, NamespaceInode: namespace.identity.inode,
		CandidateName: item.name, CandidateDevice: metadata.identity.device, CandidateInode: metadata.identity.inode,
		CandidateLinks: metadata.identity.links, CandidateSize: metadata.size,
		CandidateAllocated: metadata.allocatedBytes, CandidateMtimeSeconds: metadata.modified.seconds,
		CandidateMtimeNanos: metadata.modified.nanoseconds,
	}
}

func (guard *Guard) recoverQuarantines(ctx context.Context) error {
	remaining := guard.maxScanEntries
	for _, configured := range guard.config.Directories {
		if err := ctx.Err(); err != nil {
			return newEvaluationFailure(FailureCancelled, "%w", err)
		}
		directory, err := secureOpenDirectory(configured.Path)
		if err != nil || !directory.unchanged() {
			if directory != nil {
				directory.close()
			}
			return newEvaluationFailure(FailureDirectoryUnsafe, "open managed directory for quarantine recovery")
		}
		err = guard.recoverDirectoryQuarantines(ctx, configured, directory, &remaining)
		directory.close()
		if err != nil {
			return err
		}
	}
	return nil
}

func (guard *Guard) recoverDirectoryQuarantines(ctx context.Context, configured ManagedDirectory,
	directory *openDirectory, remaining *int) error {
	root, exists, err := openExistingPrivateQuarantineRoot(directory)
	if err != nil {
		return newEvaluationFailure(FailureDeleteFailed, "open quarantine root for recovery: %w", err)
	}
	if !exists {
		return nil
	}
	defer root.close()
	names, err := root.names(*remaining)
	if err != nil {
		return newEvaluationFailure(FailureDeleteFailed, "scan quarantine root: %w", err)
	}
	*remaining -= len(names)
	for _, name := range names {
		if err := ctx.Err(); err != nil {
			return newEvaluationFailure(FailureCancelled, "%w", err)
		}
		switch {
		case quarantineIntentNameForMarker(name) != "":
			intent, err := readQuarantineIntent(root, name)
			if err != nil {
				return newEvaluationFailure(FailureDeleteFailed, "read quarantine intent: %w", err)
			}
			if name != quarantineIntentName(intent.CandidateName) ||
				!guard.quarantineScopeMatches(configured, directory, root, intent) {
				return newEvaluationFailure(FailureCandidateChanged, "quarantine intent scope changed")
			}
			if err := guard.recoverQuarantineIntent(directory, root, intent); err != nil {
				return err
			}
		case strings.HasPrefix(name, quarantinePrefix+"intent-tmp-"):
			metadata, metadataErr := root.metadata(name)
			if metadataErr != nil || !metadata.regular || metadata.identity.links != 1 ||
				metadata.identity.device != root.identity.device {
				return newEvaluationFailure(FailureDeleteFailed, "unsafe quarantine intent temporary")
			}
			return newEvaluationFailure(FailureDeleteFailed, "incomplete quarantine intent retained")
		case strings.HasPrefix(name, quarantinePrefix) && name != quarantineRootName:
			metadata, metadataErr := root.metadata(name)
			if errors.Is(metadataErr, unix.ENOENT) {
				continue
			}
			if metadataErr != nil {
				return newEvaluationFailure(FailureDeleteFailed, "inspect quarantine namespace: %w", metadataErr)
			}
			namespace, openErr := openPrivateQuarantine(root, name, metadata.identity)
			if openErr != nil {
				return newEvaluationFailure(FailureDeleteFailed, "unsafe quarantine namespace: %w", openErr)
			}
			namespace.close()
		default:
			return newEvaluationFailure(FailureDeleteFailed, "unknown quarantine root entry")
		}
	}
	return nil
}

func (guard *Guard) quarantineScopeMatches(configured ManagedDirectory, directory, root *openDirectory,
	intent quarantineIntent) bool {
	modified := fileTimestamp{seconds: intent.CandidateMtimeSeconds, nanoseconds: intent.CandidateMtimeNanos}
	return intent.SchemaVersion == ConfigSchemaVersion && intent.ConfigID == guard.config.ConfigID &&
		intent.ConfigRevision == guard.config.Revision && intent.DirectoryID == configured.ID &&
		intent.DirectoryDevice == directory.identity.device && intent.DirectoryInode == directory.identity.inode &&
		intent.PrivateRootDevice == root.identity.device && intent.PrivateRootInode == root.identity.inode &&
		intent.NamespaceDevice == root.identity.device && intent.CandidateDevice == directory.identity.device &&
		intent.CandidateLinks == 1 && intent.CandidateSize >= 0 && modified.valid() &&
		safeBaseName(intent.CandidateName) && safeBaseName(intent.NamespaceName) &&
		strings.HasPrefix(intent.NamespaceName, quarantinePrefix) && intent.NamespaceName != quarantineRootName
}

func (guard *Guard) recoverQuarantineIntent(directory, root *openDirectory, intent quarantineIntent) error {
	expected := fileMetadata{
		identity: fileIdentity{device: intent.CandidateDevice, inode: intent.CandidateInode, links: intent.CandidateLinks},
		regular:  true, size: intent.CandidateSize, allocatedBytes: intent.CandidateAllocated,
		modified: fileTimestamp{seconds: intent.CandidateMtimeSeconds, nanoseconds: intent.CandidateMtimeNanos},
	}
	namespaceIdentity := fileIdentity{device: intent.NamespaceDevice, inode: intent.NamespaceInode}
	namespace, err := openPrivateQuarantine(root, intent.NamespaceName, namespaceIdentity)
	if errors.Is(err, unix.ENOENT) {
		return recoverMissingQuarantine(directory, root, intent, expected)
	}
	if err != nil {
		return newEvaluationFailure(FailureCandidateChanged, "quarantine namespace changed: %w", err)
	}
	defer namespace.close()
	names, err := namespace.names(1)
	if err != nil || (len(names) == 1 && names[0] != intent.CandidateName) {
		return newEvaluationFailure(FailureCandidateChanged, "quarantine namespace contents changed")
	}
	if len(names) == 0 {
		if err := recoverMissingQuarantine(directory, root, intent, expected); err != nil {
			return err
		}
		if err := removePrivateQuarantineDurable(root, intent.NamespaceName, namespaceIdentity); err != nil {
			return newEvaluationFailure(FailureDeleteFailed, "remove empty quarantine namespace: %w", err)
		}
		return nil
	}
	quarantined, err := namespace.metadata(intent.CandidateName)
	if err != nil || !quarantined.sameCandidate(expected) || quarantined.identity.links != 1 ||
		quarantined.identity.device != directory.identity.device {
		return newEvaluationFailure(FailureCandidateChanged, "quarantined candidate changed")
	}
	if original, err := directory.metadata(intent.CandidateName); err == nil {
		return newEvaluationFailure(FailureCandidateChanged, "original candidate unexpectedly exists (same=%t)", original.sameCandidate(expected))
	} else if !errors.Is(err, unix.ENOENT) {
		return newEvaluationFailure(FailureDeleteFailed, "inspect original candidate: %w", err)
	}
	fd, opened, err := namespace.openRegular(intent.CandidateName)
	if err != nil {
		return newEvaluationFailure(FailureCandidateChanged, "open quarantined candidate: %w", err)
	}
	defer unix.Close(fd)
	if !opened.sameCandidate(expected) {
		return newEvaluationFailure(FailureCandidateChanged, "opened quarantined candidate changed")
	}
	if err := unlinkQuarantined(namespace, intent.CandidateName, fd, expected); err != nil {
		return newEvaluationFailure(FailureDeleteFailed, "recover quarantined candidate: %w", err)
	}
	if err := clearQuarantineIntent(root, intent.CandidateName); err != nil {
		return newEvaluationFailure(FailureDeleteFailed, "clear recovered quarantine intent: %w", err)
	}
	if err := removePrivateQuarantineDurable(root, intent.NamespaceName, namespaceIdentity); err != nil {
		return newEvaluationFailure(FailureDeleteFailed, "remove recovered quarantine namespace: %w", err)
	}
	return nil
}

func recoverMissingQuarantine(directory, root *openDirectory, intent quarantineIntent, expected fileMetadata) error {
	if original, err := directory.metadata(intent.CandidateName); err == nil {
		if !original.sameCandidate(expected) {
			return newEvaluationFailure(FailureCandidateChanged, "original candidate changed while intent pending")
		}
	} else if !errors.Is(err, unix.ENOENT) {
		return newEvaluationFailure(FailureDeleteFailed, "inspect pending original candidate: %w", err)
	}
	if err := clearQuarantineIntent(root, intent.CandidateName); err != nil {
		return newEvaluationFailure(FailureDeleteFailed, "clear pending quarantine intent: %w", err)
	}
	return nil
}

func (item candidate) matches(metadata fileMetadata) bool {
	return metadata.identity.sameFile(item.identity) && metadata.identity.links == item.identity.links &&
		metadata.size == item.size && metadata.allocatedBytes == item.allocatedBytes &&
		metadata.modified == item.modified
}

func candidateOldEnough(modified fileTimestamp, now time.Time, minimumAge time.Duration) bool {
	if !modified.valid() {
		return false
	}
	boundary := now.Add(-minimumAge)
	return modified.compare(fileTimestamp{
		seconds: boundary.Unix(), nanoseconds: int64(boundary.Nanosecond()),
	}) <= 0
}

func usedBasisPoints(usage filesystemUsage) uint16 {
	if usage.totalBytes == 0 || usage.availableBytes >= usage.totalBytes {
		return 0
	}
	used := usage.totalBytes - usage.availableBytes
	high, low := bits.Mul64(used, 10000)
	quotient, remainder := bits.Div64(high, low, usage.totalBytes)
	if remainder != 0 {
		quotient++
	}
	if quotient > 10000 {
		quotient = 10000
	}
	return uint16(quotient)
}

func closePlans(plans []directoryPlan) {
	for index := range plans {
		plans[index].directory.close()
	}
}

func eventForCandidate(code EventCode, plan *directoryPlan, item candidate, dryRun bool) Event {
	return Event{
		Code: code, DirectoryID: plan.config.ID, FileName: item.name, Category: item.kind,
		UsedBasisPoints: plan.used, AllocatedBytes: item.allocatedBytes, DryRun: dryRun,
	}
}

func (guard *Guard) newReport() Report {
	now := guard.now().UTC()
	return Report{Metrics: Metrics{
		SchemaVersion: SchemaVersion, ObservedAt: now, ConfigID: guard.config.ConfigID,
		ConfigRevision: guard.config.Revision, DryRun: guard.config.DryRun,
		EvaluationsTotal: guard.evaluations.Add(1), EvaluationFailures: guard.failures.Load(),
		DeletedFilesTotal: guard.deleted.Load(), DeletedBytesTotal: guard.deletedBytes.Load(),
		Directories: make([]DirectoryMetric, 0, len(guard.config.Directories)),
	}}
}

func (guard *Guard) record(ctx context.Context, report *Report, event Event) {
	event.SchemaVersion = SchemaVersion
	event.OccurredAt = guard.now().UTC()
	event.ConfigID = guard.config.ConfigID
	event.ConfigRevision = guard.config.Revision
	event.DryRun = event.DryRun || guard.config.DryRun
	report.Events = append(report.Events, event)
	if guard.sink != nil {
		guard.sink.RecordDiskGuardEvent(ctx, event)
	}
}

func (guard *Guard) fail(ctx context.Context, report *Report, reason FailureReason) {
	report.Metrics.Healthy = false
	report.Metrics.FailureReason = reason
	report.Metrics.EvaluationFailures = guard.failures.Add(1)
	report.Metrics.DeletedFilesTotal = guard.deleted.Load()
	report.Metrics.DeletedBytesTotal = guard.deletedBytes.Load()
	guard.record(ctx, report, Event{Code: EventEvaluationFailed, FailureReason: reason})
	guard.storeSnapshot(report.Metrics)
}

func failureReason(err error) FailureReason {
	var failure *evaluationFailure
	if errors.As(err, &failure) {
		return failure.reason
	}
	if errors.Is(err, context.Canceled) || errors.Is(err, context.DeadlineExceeded) {
		return FailureCancelled
	}
	if errors.Is(err, ErrAlreadyRunning) {
		return FailureLockHeld
	}
	return FailureDirectoryUnsafe
}
