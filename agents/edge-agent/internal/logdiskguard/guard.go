package logdiskguard

import (
	"bufio"
	"bytes"
	"context"
	"crypto/sha256"
	"encoding/binary"
	"encoding/json"
	"errors"
	"fmt"
	"hash/crc32"
	"io"
	"os"
	"path/filepath"
	"regexp"
	"sort"
	"strconv"
	"sync"
	"sync/atomic"
	"time"

	"golang.org/x/sys/unix"
)

const (
	spoolSchemaVersion = 1
	segmentHeaderBytes = 24
	recordHeaderBytes  = 40
	maximumFrameBytes  = 1 << 20
)

var (
	segmentMagic      = [8]byte{'C', 'D', 'N', 'E', 'V', 'T', '1', 0}
	segmentPattern    = regexp.MustCompile(`^segment-([0-9]{20})\.(seg|open)$`)
	temporaryPattern  = regexp.MustCompile(`^(access|security)-([0-9]{20})\.tmp$`)
	quarantinePattern = regexp.MustCompile(`^(segment-[0-9]{20}\.seg)\.([0-9]{20})\.([0-9]{20})\.q$`)
	identifierPattern = regexp.MustCompile(`^[a-zA-Z0-9][a-zA-Z0-9._-]{0,127}$`)
	segmentCRCTable   = crc32.MakeTable(crc32.Castagnoli)
)

type Guard struct {
	config Config
	now    func() time.Time
	usage  func(string) (Usage, error)
	sink   EventSink
	hooks  testHooks

	roundMu    sync.Mutex
	snapshotMu sync.RWMutex
	snapshot   Metrics
	pressure   bool

	evaluations  atomic.Uint64
	failures     atomic.Uint64
	deleted      atomic.Uint64
	deletedBytes atomic.Uint64
	recovered    atomic.Uint64
}

type ackState struct {
	SchemaVersion uint16 `json:"schema_version"`
	Sequence      uint64 `json:"sequence"`
	EventID       string `json:"event_id,omitempty"`
}

type storedEnvelope struct {
	SchemaVersion uint16 `json:"schema_version"`
	Type          string `json:"type"`
	Sequence      uint64 `json:"sequence"`
}

type candidateKind uint8

const (
	candidateSegment candidateKind = iota
	candidateTemporary
)

type candidate struct {
	kind      candidateKind
	name      string
	start     uint64
	maximum   uint64
	identity  fileIdentity
	size      uint64
	allocated uint64
	modified  time.Time
}

func segmentName(start uint64, suffix string) string {
	return fmt.Sprintf("segment-%020d.%s", start, suffix)
}

func ValidateConfig(config Config) error {
	if !config.Enabled {
		return nil
	}
	if config.SchemaVersion != ConfigSchemaVersion || !identifierPattern.MatchString(config.ConfigID) || config.Revision == 0 ||
		!safeAbsolutePath(config.SpoolRoot) || !safeAbsolutePath(config.StateRoot) || !safeAbsolutePath(config.LockPath) ||
		filepath.Dir(config.LockPath) != config.StateRoot || pathsOverlap(config.SpoolRoot, config.StateRoot) ||
		config.LowWatermark < 5000 || config.LowWatermark > 9500 || config.HighWatermark < 6000 || config.HighWatermark > 9900 ||
		config.LowWatermark >= config.HighWatermark || config.HighWatermark-config.LowWatermark < 100 ||
		config.MinimumFreeBytes < 1<<20 || config.MinimumFreeBytes > 1<<50 ||
		config.MinimumAge < time.Hour || config.MinimumAge > 90*24*time.Hour ||
		config.EvaluationPeriod < 5*time.Second || config.EvaluationPeriod > time.Hour ||
		config.MaxRoundDuration < 10*time.Millisecond || config.MaxRoundDuration > time.Minute ||
		config.MaxDeletedFiles < 1 || config.MaxDeletedFiles > 10000 ||
		config.MaxDeletedBytes < 1<<20 || config.MaxDeletedBytes > 16<<30 {
		return ErrInvalidConfig
	}
	return nil
}

func pathsOverlap(left, right string) bool {
	for _, pair := range [][2]string{{left, right}, {right, left}} {
		relative, err := filepath.Rel(pair[0], pair[1])
		if err == nil && relative != ".." && !bytes.HasPrefix([]byte(relative), []byte(".."+string(filepath.Separator))) {
			return true
		}
	}
	return false
}

func New(config Config, options Options) (*Guard, error) {
	if !config.Enabled {
		return nil, nil
	}
	if err := ValidateConfig(config); err != nil {
		return nil, err
	}
	if options.Now == nil {
		options.Now = time.Now
	}
	if options.Usage == nil {
		options.Usage = nativeUsage
	}
	if err := ensurePrivateDirectory(config.StateRoot); err != nil {
		return nil, err
	}
	if err := ensurePrivateDirectory(filepath.Join(config.StateRoot, "quarantine")); err != nil {
		return nil, err
	}
	spool, err := secureOpenDirectory(config.SpoolRoot)
	if err != nil {
		return nil, err
	}
	segments, err := secureOpenDirectory(filepath.Join(config.SpoolRoot, "segments"))
	if err != nil {
		spool.close()
		return nil, err
	}
	state, err := secureOpenDirectory(filepath.Join(config.SpoolRoot, "state"))
	if err != nil {
		segments.close()
		spool.close()
		return nil, err
	}
	guardState, err := secureOpenDirectory(config.StateRoot)
	if err != nil {
		state.close()
		segments.close()
		spool.close()
		return nil, err
	}
	quarantine, err := secureOpenDirectory(filepath.Join(config.StateRoot, "quarantine"))
	if err != nil || spool.identity.device != segments.identity.device || spool.identity.device != state.identity.device || spool.identity.device != quarantine.identity.device {
		if quarantine != nil {
			quarantine.close()
		}
		guardState.close()
		state.close()
		segments.close()
		spool.close()
		return nil, ErrUnsafePath
	}
	quarantine.close()
	guardState.close()
	state.close()
	segments.close()
	spool.close()

	guard := &Guard{config: config, now: options.Now, usage: options.Usage, sink: options.EventSink, hooks: options.hooks}
	guard.snapshot = guard.baseMetrics(ReasonHealthy)
	return guard, nil
}

func (guard *Guard) Run(ctx context.Context) error {
	ticker := time.NewTicker(guard.config.EvaluationPeriod)
	defer ticker.Stop()
	for {
		_, _ = guard.Evaluate(ctx)
		select {
		case <-ctx.Done():
			return nil
		case <-ticker.C:
		}
	}
}

func (guard *Guard) Evaluate(ctx context.Context) (Report, error) {
	if !guard.roundMu.TryLock() {
		report := guard.newReport(ReasonLockHeld)
		guard.fail(ctx, &report, ReasonLockHeld)
		return report, ErrAlreadyRunning
	}
	defer guard.roundMu.Unlock()
	start := guard.now()
	report := guard.newReport(ReasonHealthy)
	guard.evaluations.Add(1)

	guardState, err := secureOpenDirectory(guard.config.StateRoot)
	if err != nil {
		guard.fail(ctx, &report, ReasonUnsafePath)
		return report, err
	}
	defer guardState.close()
	unlockGuard, err := acquirePrivateLock(guardState, filepath.Base(guard.config.LockPath), true)
	if err != nil {
		reason := reasonForError(err)
		guard.fail(ctx, &report, reason)
		return report, err
	}
	defer unlockGuard()

	if err := ctx.Err(); err != nil {
		guard.fail(ctx, &report, ReasonCancelled)
		return report, err
	}
	usage, err := guard.usage(guard.config.SpoolRoot)
	if err != nil || usage.TotalBytes == 0 || usage.AvailableBytes > usage.TotalBytes {
		guard.fail(ctx, &report, ReasonUsageUnavailable)
		if err == nil {
			err = ErrUnsafePath
		}
		return report, err
	}
	used := uint16(((usage.TotalBytes - usage.AvailableBytes) * 10000) / usage.TotalBytes)
	report.Metrics.UsedBasisPoints = used
	report.Metrics.AvailableBytes = usage.AvailableBytes
	minimumFreePressure := usage.AvailableBytes < guard.config.MinimumFreeBytes
	highPressure := used >= guard.config.HighWatermark
	if guard.pressure && used > guard.config.LowWatermark {
		highPressure = true
	}
	guard.pressure = highPressure || minimumFreePressure
	report.Metrics.Pressure = guard.pressure
	if !guard.pressure {
		guard.complete(ctx, &report, ReasonHealthy)
		return report, nil
	}
	pressureReason := ReasonPressureHighWatermark
	if minimumFreePressure {
		pressureReason = ReasonPressureMinimumFree
	}
	guard.record(ctx, &report, pressureReason, "")

	spoolState, err := secureOpenDirectory(filepath.Join(guard.config.SpoolRoot, "state"))
	if err != nil {
		guard.fail(ctx, &report, ReasonUnsafePath)
		return report, err
	}
	defer spoolState.close()
	unlockSpool, err := acquirePrivateLock(spoolState, "spool.lock", false)
	if err != nil {
		reason := reasonForError(err)
		guard.fail(ctx, &report, reason)
		return report, err
	}
	defer unlockSpool()

	ack, err := readAck(spoolState)
	if err != nil {
		guard.fail(ctx, &report, reasonForError(err))
		return report, err
	}
	quarantine, err := secureOpenDirectory(filepath.Join(guard.config.StateRoot, "quarantine"))
	if err != nil {
		guard.fail(ctx, &report, ReasonUnsafePath)
		return report, err
	}
	defer quarantine.close()
	segments, err := secureOpenDirectory(filepath.Join(guard.config.SpoolRoot, "segments"))
	if err != nil {
		guard.fail(ctx, &report, ReasonUnsafePath)
		return report, err
	}
	defer segments.close()
	if err := guard.recoverQuarantine(ctx, &report, segments, quarantine, ack.Sequence); err != nil {
		guard.fail(ctx, &report, reasonForError(err))
		return report, err
	}

	candidates, protected, err := guard.scanCandidates(segments, ack.Sequence, start)
	if err != nil {
		guard.fail(ctx, &report, reasonForError(err))
		return report, err
	}
	temporary, exists, err := secureOpenOptionalDirectory(filepath.Join(guard.config.SpoolRoot, "tmp"))
	if err != nil {
		guard.fail(ctx, &report, ReasonUnsafePath)
		return report, err
	}
	if exists {
		defer temporary.close()
		tempCandidates, tempProtected, scanErr := guard.scanTemporary(temporary, start)
		if scanErr != nil {
			guard.fail(ctx, &report, reasonForError(scanErr))
			return report, scanErr
		}
		candidates = append(candidates, tempCandidates...)
		protected += tempProtected
	}
	sort.Slice(candidates, func(left, right int) bool {
		if candidates[left].kind != candidates[right].kind {
			return candidates[left].kind < candidates[right].kind
		}
		if !candidates[left].modified.Equal(candidates[right].modified) {
			return candidates[left].modified.Before(candidates[right].modified)
		}
		return candidates[left].name < candidates[right].name
	})
	report.Metrics.RoundCandidateFiles = len(candidates)
	report.Metrics.RoundProtectedFiles = protected
	budgetExhausted := false
	budgetFiles := 0
	budgetBytes := uint64(0)
	for index, item := range candidates {
		if err := ctx.Err(); err != nil {
			guard.fail(ctx, &report, ReasonCancelled)
			return report, err
		}
		if guard.now().Sub(start) > guard.config.MaxRoundDuration || budgetFiles >= guard.config.MaxDeletedFiles ||
			budgetBytes+item.allocated > guard.config.MaxDeletedBytes {
			report.Metrics.RoundBudgetSkipped += len(candidates) - index
			budgetExhausted = true
			break
		}
		if guard.config.DryRun {
			report.Metrics.RoundWouldDeleteFiles++
			budgetFiles++
			budgetBytes += item.allocated
			continue
		}
		if err := guard.deleteCandidate(item, segments, temporary, quarantine); err != nil {
			guard.fail(ctx, &report, ReasonDeleteFailed)
			return report, err
		}
		report.Metrics.RoundDeletedFiles++
		report.Metrics.RoundDeletedBytes += item.allocated
		budgetFiles++
		budgetBytes += item.allocated
		guard.deleted.Add(1)
		guard.deletedBytes.Add(item.allocated)
		guard.record(ctx, &report, ReasonCleanupCompleted, item.name)
	}
	if budgetExhausted {
		guard.complete(ctx, &report, ReasonBudgetExhausted)
	} else {
		guard.complete(ctx, &report, ReasonCleanupCompleted)
	}
	return report, nil
}

func readAck(state *openDirectory) (ackState, error) {
	file, err := openRegularAt(state, "ack.json", unix.O_RDONLY)
	if err != nil {
		if _, statErr := os.Lstat(filepath.Join(state.path, "ack.json")); errors.Is(statErr, os.ErrNotExist) {
			return ackState{SchemaVersion: spoolSchemaVersion}, nil
		}
		return ackState{}, err
	}
	defer file.close()
	if file.size <= 0 || file.size > 64<<10 {
		return ackState{}, ErrCorruptState
	}
	duplicate, err := unix.Dup(file.fd)
	if err != nil {
		return ackState{}, ErrUnsafePath
	}
	handle := os.NewFile(uintptr(duplicate), "ack.json")
	defer handle.Close()
	decoder := json.NewDecoder(io.LimitReader(handle, 64<<10))
	decoder.DisallowUnknownFields()
	var ack ackState
	if err := decoder.Decode(&ack); err != nil || decoder.Decode(&struct{}{}) != io.EOF || ack.SchemaVersion != spoolSchemaVersion {
		return ackState{}, ErrCorruptState
	}
	return ack, nil
}

func (guard *Guard) scanCandidates(segments *openDirectory, ack uint64, now time.Time) ([]candidate, int, error) {
	entries, err := readDirectoryNames(segments)
	if err != nil {
		return nil, 0, ErrUnsafePath
	}
	candidates := make([]candidate, 0)
	protected := 0
	for _, name := range entries {
		matches := segmentPattern.FindStringSubmatch(name)
		if len(matches) != 3 {
			return nil, 0, ErrCorruptState
		}
		start, parseErr := strconv.ParseUint(matches[1], 10, 64)
		if parseErr != nil || start == 0 {
			return nil, 0, ErrCorruptState
		}
		file, openErr := openRegularAt(segments, name, unix.O_RDONLY)
		if openErr != nil {
			return nil, 0, openErr
		}
		if matches[2] == "open" {
			file.close()
			protected++
			continue
		}
		maximum, reproducible, parseErr := parseSegment(file, start)
		if parseErr != nil {
			file.close()
			return nil, 0, parseErr
		}
		item := candidate{kind: candidateSegment, name: name, start: start, maximum: maximum, identity: file.identity,
			size: uint64(file.size), allocated: allocatedOrSize(file), modified: file.modified}
		file.close()
		if !reproducible || maximum > ack || now.Sub(item.modified) < guard.config.MinimumAge {
			protected++
			continue
		}
		candidates = append(candidates, item)
	}
	return candidates, protected, nil
}

func (guard *Guard) scanTemporary(directory *openDirectory, now time.Time) ([]candidate, int, error) {
	entries, err := readDirectoryNames(directory)
	if err != nil {
		return nil, 0, ErrUnsafePath
	}
	candidates := make([]candidate, 0)
	protected := 0
	for _, name := range entries {
		if !temporaryPattern.MatchString(name) {
			protected++
			continue
		}
		file, openErr := openRegularAt(directory, name, unix.O_RDONLY)
		if openErr != nil {
			return nil, 0, openErr
		}
		item := candidate{kind: candidateTemporary, name: name, identity: file.identity, size: uint64(file.size), allocated: allocatedOrSize(file), modified: file.modified}
		file.close()
		if now.Sub(item.modified) < guard.config.MinimumAge {
			protected++
			continue
		}
		candidates = append(candidates, item)
	}
	return candidates, protected, nil
}

func allocatedOrSize(file *openFile) uint64 {
	if file.allocated != 0 {
		return file.allocated
	}
	if file.size > 0 {
		return uint64(file.size)
	}
	return 1
}

func parseSegment(file *openFile, expectedStart uint64) (uint64, bool, error) {
	if _, err := unix.Seek(file.fd, 0, io.SeekStart); err != nil {
		return 0, false, ErrCorruptState
	}
	duplicate, err := unix.Dup(file.fd)
	if err != nil {
		return 0, false, ErrUnsafePath
	}
	handle := os.NewFile(uintptr(duplicate), "segment")
	defer handle.Close()
	reader := bufio.NewReader(handle)
	header := make([]byte, segmentHeaderBytes)
	if _, err := io.ReadFull(reader, header); err != nil || !bytes.Equal(header[:8], segmentMagic[:]) ||
		binary.BigEndian.Uint16(header[8:10]) != spoolSchemaVersion || binary.BigEndian.Uint64(header[16:24]) != expectedStart {
		return 0, false, ErrCorruptState
	}
	expected := expectedStart
	maximum := uint64(0)
	reproducible := true
	for {
		frameHeader := make([]byte, recordHeaderBytes)
		read, err := io.ReadFull(reader, frameHeader)
		if errors.Is(err, io.EOF) && read == 0 {
			break
		}
		if err != nil {
			return 0, false, ErrCorruptState
		}
		length := binary.BigEndian.Uint32(frameHeader[0:4])
		if length == 0 || length > maximumFrameBytes {
			return 0, false, ErrCorruptState
		}
		payload := make([]byte, int(length))
		if _, err := io.ReadFull(reader, payload); err != nil || crc32.Checksum(payload, segmentCRCTable) != binary.BigEndian.Uint32(frameHeader[4:8]) {
			return 0, false, ErrCorruptState
		}
		digest := sha256.Sum256(payload)
		if !bytes.Equal(digest[:], frameHeader[8:40]) {
			return 0, false, ErrCorruptState
		}
		decoder := json.NewDecoder(bytes.NewReader(payload))
		var envelope storedEnvelope
		if err := decoder.Decode(&envelope); err != nil || decoder.Decode(&struct{}{}) != io.EOF || envelope.SchemaVersion != spoolSchemaVersion || envelope.Sequence != expected {
			return 0, false, ErrCorruptState
		}
		if envelope.Type != "access.v1" && envelope.Type != "security.v1" {
			reproducible = false
		}
		maximum = envelope.Sequence
		expected++
	}
	if maximum == 0 {
		return 0, false, ErrCorruptState
	}
	return maximum, reproducible, nil
}

func readDirectoryNames(directory *openDirectory) ([]string, error) {
	handle, err := duplicateDirectoryFile(directory)
	if err != nil {
		return nil, err
	}
	defer handle.Close()
	entries, err := handle.ReadDir(-1)
	if err != nil {
		return nil, err
	}
	names := make([]string, 0, len(entries))
	for _, entry := range entries {
		names = append(names, entry.Name())
	}
	sort.Strings(names)
	return names, nil
}

func (guard *Guard) deleteCandidate(item candidate, segments, temporary, quarantine *openDirectory) error {
	if item.kind == candidateTemporary {
		if temporary == nil {
			return ErrUnsafePath
		}
		file, err := openRegularAt(temporary, item.name, unix.O_RDONLY)
		if err != nil {
			return err
		}
		defer file.close()
		if !file.identity.same(item.identity) || uint64(file.size) != item.size {
			return ErrUnsafePath
		}
		if err := verifyNameIdentity(temporary, item.name, item.identity, file.size); err != nil {
			return err
		}
		if err := unix.Unlinkat(temporary.fd, item.name, 0); err != nil {
			return fmt.Errorf("delete temporary file: %w", err)
		}
		return syncDirectory(temporary)
	}
	file, err := openRegularAt(segments, item.name, unix.O_RDONLY)
	if err != nil {
		return err
	}
	defer file.close()
	if !file.identity.same(item.identity) || uint64(file.size) != item.size {
		return ErrUnsafePath
	}
	if err := verifyNameIdentity(segments, item.name, item.identity, file.size); err != nil {
		return err
	}
	quarantineName := fmt.Sprintf("%s.%020d.%020d.q", item.name, item.maximum, item.identity.inode)
	if err := unix.Renameat(segments.fd, item.name, quarantine.fd, quarantineName); err != nil {
		return fmt.Errorf("quarantine segment: %w", err)
	}
	if err := syncDirectory(segments); err != nil {
		return err
	}
	if err := syncDirectory(quarantine); err != nil {
		return err
	}
	quarantined, err := openRegularAt(quarantine, quarantineName, unix.O_RDONLY)
	if err != nil {
		return err
	}
	unchanged := quarantined.identity.same(item.identity) && uint64(quarantined.size) == item.size
	quarantined.close()
	if !unchanged {
		return ErrUnsafePath
	}
	if guard.hooks.afterQuarantine != nil {
		if err := guard.hooks.afterQuarantine(); err != nil {
			return err
		}
	}
	if err := unix.Unlinkat(quarantine.fd, quarantineName, 0); err != nil {
		return fmt.Errorf("delete quarantined segment: %w", err)
	}
	return syncDirectory(quarantine)
}

func (guard *Guard) recoverQuarantine(ctx context.Context, report *Report, segments, quarantine *openDirectory, ack uint64) error {
	entries, err := readDirectoryNames(quarantine)
	if err != nil {
		return ErrUnsafePath
	}
	for _, name := range entries {
		if err := ctx.Err(); err != nil {
			return err
		}
		matches := quarantinePattern.FindStringSubmatch(name)
		if len(matches) != 4 {
			return ErrCorruptState
		}
		maximum, maxErr := strconv.ParseUint(matches[2], 10, 64)
		inode, inodeErr := strconv.ParseUint(matches[3], 10, 64)
		if maxErr != nil || inodeErr != nil || maximum == 0 || inode == 0 {
			return ErrCorruptState
		}
		startMatches := segmentPattern.FindStringSubmatch(matches[1])
		start, startErr := strconv.ParseUint(startMatches[1], 10, 64)
		if startErr != nil || start == 0 {
			return ErrCorruptState
		}
		file, openErr := openRegularAt(quarantine, name, unix.O_RDONLY)
		if openErr != nil {
			return openErr
		}
		parsedMax, reproducible, parseErr := parseSegment(file, start)
		identity := file.identity
		file.close()
		if parseErr != nil || !reproducible || parsedMax != maximum || identity.inode != inode {
			return ErrCorruptState
		}
		if maximum <= ack {
			if err := unix.Unlinkat(quarantine.fd, name, 0); err != nil {
				return err
			}
		} else {
			exists, err := nameExists(segments, matches[1])
			if err != nil || exists {
				return ErrCorruptState
			}
			if err := unix.Renameat(quarantine.fd, name, segments.fd, matches[1]); err != nil {
				return err
			}
		}
		report.Metrics.RoundRecoveredFiles++
		guard.recovered.Add(1)
	}
	if len(entries) != 0 {
		if err := syncDirectory(quarantine); err != nil {
			return err
		}
		if err := syncDirectory(segments); err != nil {
			return err
		}
	}
	return nil
}

func reasonForError(err error) ReasonCode {
	switch {
	case errors.Is(err, context.Canceled), errors.Is(err, context.DeadlineExceeded):
		return ReasonCancelled
	case errors.Is(err, ErrAlreadyRunning):
		return ReasonLockHeld
	case errors.Is(err, ErrCorruptState):
		return ReasonCorruptState
	case errors.Is(err, ErrUnsafePath):
		return ReasonUnsafePath
	default:
		return ReasonDeleteFailed
	}
}

func (guard *Guard) baseMetrics(reason ReasonCode) Metrics {
	return Metrics{SchemaVersion: SchemaVersion, ObservedAt: guard.now().UTC(), ConfigID: guard.config.ConfigID,
		ConfigRevision: guard.config.Revision, ReasonCode: reason, DryRun: guard.config.DryRun}
}

func (guard *Guard) newReport(reason ReasonCode) Report {
	metrics := guard.baseMetrics(reason)
	metrics.EvaluationsTotal = guard.evaluations.Load()
	metrics.EvaluationFailures = guard.failures.Load()
	metrics.DeletedFilesTotal = guard.deleted.Load()
	metrics.DeletedBytesTotal = guard.deletedBytes.Load()
	metrics.RecoveredFilesTotal = guard.recovered.Load()
	return Report{Metrics: metrics}
}

func (guard *Guard) record(ctx context.Context, report *Report, reason ReasonCode, name string) {
	event := Event{SchemaVersion: SchemaVersion, OccurredAt: guard.now().UTC(), ConfigID: guard.config.ConfigID,
		ConfigRevision: guard.config.Revision, ReasonCode: reason, UsedBasisPoints: report.Metrics.UsedBasisPoints,
		AvailableBytes: report.Metrics.AvailableBytes, FileName: name, DryRun: guard.config.DryRun}
	report.Events = append(report.Events, event)
	if guard.sink != nil {
		guard.sink.RecordLogDiskGuardEvent(ctx, event)
	}
}

func (guard *Guard) complete(ctx context.Context, report *Report, reason ReasonCode) {
	report.Metrics.ReasonCode = reason
	report.Metrics.Healthy = !report.Metrics.Pressure && (reason == ReasonHealthy || reason == ReasonCleanupCompleted)
	report.Metrics.EvaluationsTotal = guard.evaluations.Load()
	report.Metrics.EvaluationFailures = guard.failures.Load()
	report.Metrics.DeletedFilesTotal = guard.deleted.Load()
	report.Metrics.DeletedBytesTotal = guard.deletedBytes.Load()
	report.Metrics.RecoveredFilesTotal = guard.recovered.Load()
	guard.record(ctx, report, reason, "")
	guard.store(report.Metrics)
}

func (guard *Guard) fail(ctx context.Context, report *Report, reason ReasonCode) {
	guard.failures.Add(1)
	report.Metrics.ReasonCode = reason
	report.Metrics.Healthy = false
	report.Metrics.EvaluationsTotal = guard.evaluations.Load()
	report.Metrics.EvaluationFailures = guard.failures.Load()
	report.Metrics.DeletedFilesTotal = guard.deleted.Load()
	report.Metrics.DeletedBytesTotal = guard.deletedBytes.Load()
	report.Metrics.RecoveredFilesTotal = guard.recovered.Load()
	guard.record(ctx, report, reason, "")
	guard.store(report.Metrics)
}

func (guard *Guard) store(metrics Metrics) {
	metrics.ObservedAt = guard.now().UTC()
	guard.snapshotMu.Lock()
	guard.snapshot = metrics
	guard.snapshotMu.Unlock()
}

func (guard *Guard) Snapshot() Metrics {
	guard.snapshotMu.RLock()
	defer guard.snapshotMu.RUnlock()
	return guard.snapshot
}
