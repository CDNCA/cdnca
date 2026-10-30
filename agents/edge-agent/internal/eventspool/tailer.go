package eventspool

import (
	"bufio"
	"context"
	"crypto/sha256"
	"encoding/hex"
	"errors"
	"fmt"
	"io"
	"os"
	"path/filepath"
	"sort"
	"strconv"
	"strings"
	"syscall"
	"time"
)

const (
	fingerprintBytes      int64 = 64
	maxRetiredTailSources       = 128
	digestReadBufferBytes       = 128 << 10
)

type retiredTailSource struct {
	Device uint64 `json:"device"`
	Inode  uint64 `json:"inode"`
	Size   int64  `json:"size"`
	Digest string `json:"sha256"`
}

type tailCheckpoint struct {
	SchemaVersion  uint16              `json:"schema_version"`
	SourcePath     string              `json:"source_path"`
	Device         uint64              `json:"device"`
	Inode          uint64              `json:"inode"`
	Generation     uint64              `json:"generation"`
	Offset         int64               `json:"offset"`
	Fingerprint    string              `json:"fingerprint,omitempty"`
	RetiredSources []retiredTailSource `json:"retired_sources,omitempty"`
}

type sourceIdentity struct {
	device uint64
	inode  uint64
	size   int64
}

type sourceFileState struct {
	identity     sourceIdentity
	mode         os.FileMode
	nlink        uint64
	modifiedSec  int64
	modifiedNSec int64
	changedSec   int64
	changedNSec  int64
}

type rotatedSource struct {
	identity sourceIdentity
	digest   string
}

type Tailer struct {
	config             TailConfig
	stateDevice        uint64
	checkpointPath     string
	lockPath           string
	quarantineDir      string
	quarantineLockPath string
	hashHook           func(*os.File, int64)
}

func NewTailer(config TailConfig) (*Tailer, error) {
	if config.Now == nil {
		config.Now = time.Now
	}
	if config.SourcePath == "" || !filepath.IsAbs(config.SourcePath) || filepath.Clean(config.SourcePath) != config.SourcePath ||
		config.StateDir == "" || !filepath.IsAbs(config.StateDir) || filepath.Clean(config.StateDir) != config.StateDir ||
		!validUUID(config.Identity.EnrollmentNodeID) ||
		config.Resolve == nil && (!validUUID(config.Identity.TenantID) || !validUUID(config.Identity.SiteID) ||
			!validRequired(config.Identity.ConfigVersionID, 128)) ||
		config.Resolve != nil && config.EventType != "" ||
		config.MaxLineBytes < 256 || config.MaxLineBytes > 1<<20 || config.MaxBatchEvents < 1 || config.MaxBatchEvents > 10000 ||
		config.MaxQuarantineBytes < 64<<10 || config.MaxQuarantineBytes > 1<<30 || config.Now == nil {
		return nil, ErrInvalidConfig
	}
	if config.EventType != "" && config.EventType != EventL4Session {
		return nil, ErrInvalidConfig
	}
	if config.EventType == EventL4Session && (!validUUID(config.Identity.ConfigVersionID) || !validUUID(config.Identity.StreamID) ||
		!validUUID(config.Identity.ListenerID) || config.Identity.ConfigRevision == 0) {
		return nil, ErrInvalidConfig
	}
	config.Identity.EnrollmentNodeID = strings.ToLower(config.Identity.EnrollmentNodeID)
	config.Identity.TenantID = strings.ToLower(config.Identity.TenantID)
	config.Identity.SiteID = strings.ToLower(config.Identity.SiteID)
	if err := rejectSymlinkComponents(config.SourcePath); err != nil {
		return nil, err
	}
	realSourceDir, err := filepath.EvalSymlinks(filepath.Dir(config.SourcePath))
	if err != nil {
		return nil, ErrUnsafePath
	}
	config.SourcePath = filepath.Join(realSourceDir, filepath.Base(config.SourcePath))
	if err := rejectSymlinkComponents(config.StateDir); err != nil {
		return nil, err
	}
	if err := os.MkdirAll(config.StateDir, 0o700); err != nil {
		return nil, fmt.Errorf("create event tail state: %w", err)
	}
	if err := rejectSymlinkComponents(config.StateDir); err != nil {
		return nil, err
	}
	realStateDir, err := filepath.EvalSymlinks(config.StateDir)
	if err != nil {
		return nil, ErrUnsafePath
	}
	config.StateDir = realStateDir
	info, err := os.Lstat(realStateDir)
	stat, ok := infoSys(info)
	if err != nil || !ok || !info.IsDir() || info.Mode().Perm()&0o077 != 0 {
		return nil, ErrUnsafePath
	}
	digest := sha256.Sum256([]byte(config.SourcePath))
	stem := hex.EncodeToString(digest[:16])
	tailer := &Tailer{
		config:             config,
		stateDevice:        uint64(stat.Dev),
		checkpointPath:     filepath.Join(config.StateDir, "tail-"+stem+".json"),
		lockPath:           filepath.Join(config.StateDir, "tail-"+stem+".lock"),
		quarantineDir:      filepath.Join(config.StateDir, "quarantine"),
		quarantineLockPath: filepath.Join(config.StateDir, "quarantine.lock"),
	}
	if err := ensureOwnerDirectory(tailer.quarantineDir, tailer.stateDevice); err != nil {
		return nil, err
	}
	return tailer, nil
}

func (t *Tailer) TailOnce(ctx context.Context, sink BatchSink) (TailResult, error) {
	if sink == nil {
		return TailResult{}, ErrInvalidConfig
	}
	unlock, err := lockPrivateFile(ctx, t.lockPath, t.stateDevice)
	if err != nil {
		return TailResult{}, err
	}
	defer unlock()
	checkpoint, exists, err := t.loadCheckpoint()
	if err != nil {
		return TailResult{}, err
	}
	active, activeIdentity, err := openSource(t.config.SourcePath)
	if err != nil {
		return TailResult{}, err
	}
	defer active.Close()
	var result TailResult
	if !exists {
		_, _, candidates, scanErr := t.findSource(0, 0, nil, &result)
		if scanErr != nil {
			return result, scanErr
		}
		if len(candidates) > 0 {
			result.Issues = append(result.Issues, Issue{Code: "TAIL_ROTATION_AMBIGUOUS"})
			return result, ErrTailRotationAmbiguous
		}
		checkpoint = tailCheckpoint{
			SchemaVersion: SchemaVersion, SourcePath: t.config.SourcePath,
			Device: activeIdentity.device, Inode: activeIdentity.inode, Generation: 1,
		}
	}

	if checkpoint.Device != activeIdentity.device || checkpoint.Inode != activeIdentity.inode {
		hashedBefore := result.RotationFilesHashed
		rotated, identity, candidates, findErr := t.findSource(checkpoint.Device, checkpoint.Inode, checkpoint.RetiredSources, &result)
		if result.RotationFilesHashed > hashedBefore {
			result.Issues = append(result.Issues, Issue{Code: "TAIL_RETIRED_DIGEST_SCAN", Generation: checkpoint.Generation, Offset: checkpoint.Offset})
		}
		if findErr != nil {
			if errors.Is(findErr, ErrTailRotationAmbiguous) {
				result.Issues = append(result.Issues, Issue{Code: "TAIL_ROTATION_AMBIGUOUS", Generation: checkpoint.Generation, Offset: checkpoint.Offset})
			}
			return result, findErr
		}
		if rotated == nil {
			return result, ErrTailGap
		}
		defer rotated.Close()
		retained, ambiguous := classifyRotatedSources(candidates, checkpoint, activeIdentity)
		partial, processErr := t.processSource(ctx, rotated, identity, &checkpoint, sink, &result)
		info, statErr := rotated.Stat()
		if processErr != nil {
			return result, processErr
		}
		stat, statOK := infoSys(info)
		if statErr != nil || !statOK || !info.Mode().IsRegular() || info.Mode().Perm() != 0o600 || stat.Nlink != 1 ||
			uint64(stat.Dev) != identity.device || uint64(stat.Ino) != identity.inode {
			return result, ErrUnsafePath
		}
		if partial {
			result.Issues = append(result.Issues, Issue{Code: "TAIL_ROTATED_PARTIAL", Generation: checkpoint.Generation, Offset: checkpoint.Offset})
			return result, ErrTailRotatedPartial
		}
		if info.Size() != checkpoint.Offset || ambiguous || len(retained) >= maxRetiredTailSources {
			result.Issues = append(result.Issues, Issue{Code: "TAIL_ROTATION_AMBIGUOUS", Generation: checkpoint.Generation, Offset: checkpoint.Offset})
			return result, ErrTailRotationAmbiguous
		}
		digest, hashedBytes, hashErr := t.fullSourceDigest(rotated, identity)
		result.RotationFilesHashed++
		result.RotationBytesHashed += hashedBytes
		if hashErr != nil {
			if errors.Is(hashErr, ErrTailRotationAmbiguous) {
				result.Issues = append(result.Issues, Issue{Code: "TAIL_ROTATION_AMBIGUOUS", Generation: checkpoint.Generation, Offset: checkpoint.Offset})
			}
			return result, hashErr
		}
		checkpoint.RetiredSources = append(retained, retiredTailSource{
			Device: checkpoint.Device, Inode: checkpoint.Inode, Size: checkpoint.Offset, Digest: digest,
		})
		checkpoint.Device = activeIdentity.device
		checkpoint.Inode = activeIdentity.inode
		checkpoint.Generation++
		checkpoint.Offset = 0
		checkpoint.Fingerprint = ""
		if err := t.saveCheckpoint(checkpoint); err != nil {
			return result, err
		}
	} else if checkpoint.Offset > activeIdentity.size || !fingerprintMatches(active, checkpoint) {
		result.Issues = append(result.Issues, Issue{Code: "TAIL_COPYTRUNCATE", Generation: checkpoint.Generation, Offset: checkpoint.Offset})
		checkpoint.Generation++
		checkpoint.Offset = 0
		checkpoint.Fingerprint = ""
		if err := t.saveCheckpoint(checkpoint); err != nil {
			return result, err
		}
	}
	_, err = t.processSource(ctx, active, activeIdentity, &checkpoint, sink, &result)
	return result, err
}

func (t *Tailer) processSource(ctx context.Context, file *os.File, identity sourceIdentity, checkpoint *tailCheckpoint, sink BatchSink, result *TailResult) (bool, error) {
	if _, err := file.Seek(checkpoint.Offset, io.SeekStart); err != nil {
		return false, fmt.Errorf("seek edge event log: %w", err)
	}
	reader := bufio.NewReaderSize(file, t.config.MaxLineBytes+2)
	envelopes := make([]Envelope, 0, t.config.MaxBatchEvents)
	completedSinceSave := 0
	flush := func() error {
		if len(envelopes) > 0 {
			if t.config.Resolve != nil {
				// A shared source interleaves sites; publications group
				// consecutive records of one site, so keep each site's
				// records together (file order within a site). Event IDs
				// are per line and the checkpoint covers the whole batch.
				sortBySiteDimension(envelopes)
			}
			results, err := sink.AppendBatch(ctx, envelopes)
			if err != nil {
				return err
			}
			if len(results) != len(envelopes) {
				return ErrCorruptState
			}
			for _, appendResult := range results {
				switch {
				case appendResult.Sampled:
					result.SampledEvents++
				case appendResult.Expired:
					result.ExpiredEvents++
				case appendResult.Duplicate:
					result.DuplicateEvents++
				default:
					result.AppendedEvents++
				}
			}
			envelopes = envelopes[:0]
		}
		fingerprint, err := fingerprintAt(file, checkpoint.Offset)
		if err != nil {
			return err
		}
		checkpoint.Fingerprint = fingerprint
		if err := t.saveCheckpoint(*checkpoint); err != nil {
			return err
		}
		completedSinceSave = 0
		return nil
	}

	for {
		if err := ctx.Err(); err != nil {
			return false, err
		}
		lineOffset := checkpoint.Offset
		line, consumed, complete, tooLong, err := readCompletedLine(reader, t.config.MaxLineBytes)
		if err != nil {
			return false, err
		}
		if !complete {
			if completedSinceSave > 0 || len(envelopes) > 0 {
				if err := flush(); err != nil {
					return true, err
				}
			}
			return consumed > 0, nil
		}
		checkpoint.Offset += consumed
		result.CompletedLines++
		completedSinceSave++
		if tooLong {
			if err := t.quarantineLine("TAIL_LINE_TOO_LARGE", identity, checkpoint.Generation, lineOffset, consumed, nil); err != nil {
				return false, err
			}
			result.QuarantinedLines++
			result.Issues = append(result.Issues, Issue{Code: "TAIL_LINE_TOO_LARGE", Generation: checkpoint.Generation, Offset: lineOffset})
		} else {
			envelope, parseErr := t.parseSourceLine(line)
			if errors.Is(parseErr, ErrLineNotReady) {
				// Not this time: the line is read again from its start.
				checkpoint.Offset = lineOffset
				result.CompletedLines--
				completedSinceSave--
				if completedSinceSave > 0 || len(envelopes) > 0 {
					if err := flush(); err != nil {
						return true, err
					}
				}
				result.Issues = append(result.Issues, Issue{Code: "TAIL_LINE_NOT_READY", Generation: checkpoint.Generation, Offset: lineOffset})
				return true, nil
			}
			if errors.Is(parseErr, ErrLineSkipped) {
				result.SkippedLines++
			} else if errors.Is(parseErr, ErrLineUnattributable) {
				if err := t.quarantineLine("TAIL_ATTRIBUTION_MISSING", identity, checkpoint.Generation, lineOffset, consumed, line); err != nil {
					return false, err
				}
				result.QuarantinedLines++
				result.Issues = append(result.Issues, Issue{Code: "TAIL_ATTRIBUTION_MISSING", Generation: checkpoint.Generation, Offset: lineOffset})
			} else if parseErr != nil {
				if err := t.quarantineLine("TAIL_INVALID_JSON", identity, checkpoint.Generation, lineOffset, consumed, line); err != nil {
					return false, err
				}
				result.QuarantinedLines++
				result.Issues = append(result.Issues, Issue{Code: "TAIL_INVALID_JSON", Generation: checkpoint.Generation, Offset: lineOffset})
			} else {
				envelope.EventID = deterministicEventID(identity, checkpoint.Generation, lineOffset, t.config.Identity.EnrollmentNodeID, line)
				if envelope.Type == EventSecurity && envelope.Count > 0 {
					envelope.EventID = aggregateEventID(t.config.SourcePath, t.config.Identity.EnrollmentNodeID, line)
				}
				envelopes = append(envelopes, envelope)
			}
		}
		if len(envelopes) == t.config.MaxBatchEvents || completedSinceSave == t.config.MaxBatchEvents {
			if err := flush(); err != nil {
				return false, err
			}
		}
	}
}

// ErrLineUnattributable: a Resolve result for a valid line that can no
// longer be bound (its attribution history is gone). The tail quarantines it
// as TAIL_ATTRIBUTION_MISSING, apart from invalid lines (TF-E04).
var ErrLineUnattributable = errors.New("event log line attribution history is missing")

func (t *Tailer) parseSourceLine(line []byte) (Envelope, error) {
	if t.config.Resolve != nil {
		resolved, err := t.config.Resolve(line)
		if err != nil {
			if errors.Is(err, ErrLineNotReady) || errors.Is(err, ErrLineSkipped) || errors.Is(err, ErrLineUnattributable) {
				return Envelope{}, err
			}
			return Envelope{}, ErrInvalidEvent
		}
		identity := resolved.Identity
		identity.EnrollmentNodeID = t.config.Identity.EnrollmentNodeID
		if !validUUID(identity.TenantID) || !validUUID(identity.SiteID) || !validRequired(identity.ConfigVersionID, 128) {
			return Envelope{}, ErrInvalidEvent
		}
		identity.TenantID, identity.SiteID = strings.ToLower(identity.TenantID), strings.ToLower(identity.SiteID)
		return ParseSourceLineBound(resolved.Line, resolved.CapturePolicy, identity)
	}
	if t.config.EventType == EventL4Session {
		return ParseL4SourceLineBound(line, t.config.Identity)
	}
	return ParseSourceLineBound(line, t.config.CapturePolicy, t.config.Identity)
}

func sortBySiteDimension(envelopes []Envelope) {
	key := func(envelope Envelope) string {
		return strings.Join([]string{string(envelope.Type), envelope.TenantID, envelope.SiteID, envelope.ConfigVersionID,
			envelope.CapturePolicyDigest, strconv.FormatUint(envelope.CapturePolicyRevision, 10), envelope.Host,
			strconv.Itoa(int(envelope.ListenPort))}, "\x00")
	}
	sort.SliceStable(envelopes, func(i, j int) bool { return key(envelopes[i]) < key(envelopes[j]) })
}

func readCompletedLine(reader *bufio.Reader, maximum int) ([]byte, int64, bool, bool, error) {
	var consumed int64
	var line []byte
	tooLong := false
	for {
		fragment, err := reader.ReadSlice('\n')
		consumed += int64(len(fragment))
		if !tooLong && len(line)+len(fragment) <= maximum+1 {
			line = append(line, fragment...)
		} else {
			tooLong = true
			line = nil
		}
		switch {
		case err == nil:
			if !tooLong {
				line = line[:len(line)-1]
				tooLong = len(line) > maximum
			}
			return line, consumed, true, tooLong, nil
		case errors.Is(err, bufio.ErrBufferFull):
			continue
		case errors.Is(err, io.EOF):
			return nil, consumed, false, tooLong, nil
		default:
			return nil, consumed, false, tooLong, fmt.Errorf("read edge event log: %w", err)
		}
	}
}

func deterministicEventID(identity sourceIdentity, generation uint64, offset int64, nodeID string, line []byte) string {
	hash := sha256.New()
	_, _ = fmt.Fprintf(hash, "%d:%d:%d:%d:%s:", identity.device, identity.inode, generation, offset, nodeID)
	lineDigest := sha256.Sum256(line)
	_, _ = hash.Write(lineDigest[:])
	return "evt_" + hex.EncodeToString(hash.Sum(nil))
}

func (t *Tailer) loadCheckpoint() (tailCheckpoint, bool, error) {
	var checkpoint tailCheckpoint
	exists, err := readStateJSON(t.checkpointPath, &checkpoint, t.stateDevice)
	if err != nil || !exists {
		return checkpoint, exists, err
	}
	if checkpoint.SchemaVersion != SchemaVersion || checkpoint.SourcePath != t.config.SourcePath || checkpoint.Device == 0 || checkpoint.Inode == 0 ||
		checkpoint.Generation == 0 || checkpoint.Offset < 0 || !validCheckpointFingerprint(checkpoint.Offset, checkpoint.Fingerprint) ||
		len(checkpoint.RetiredSources) > maxRetiredTailSources {
		return tailCheckpoint{}, false, ErrCorruptState
	}
	seen := make(map[[2]uint64]struct{}, len(checkpoint.RetiredSources))
	for _, retired := range checkpoint.RetiredSources {
		key := [2]uint64{retired.Device, retired.Inode}
		_, duplicate := seen[key]
		if retired.Device == 0 || retired.Inode == 0 || retired.Size < 0 || !canonicalSHA256(retired.Digest) ||
			(retired.Device == checkpoint.Device && retired.Inode == checkpoint.Inode) || duplicate {
			return tailCheckpoint{}, false, ErrCorruptState
		}
		seen[key] = struct{}{}
	}
	return checkpoint, true, nil
}

// SourcePath is the log file the tailer reads (its real path).
func (t *Tailer) SourcePath() string { return t.config.SourcePath }

// Position is the durable cursor (generation, offset) for diagnostics; a
// source never read has none (0, 0).
func (t *Tailer) Position() (uint64, int64) {
	checkpoint, exists, err := t.loadCheckpoint()
	if err != nil || !exists {
		return 0, 0
	}
	return checkpoint.Generation, checkpoint.Offset
}

func (t *Tailer) saveCheckpoint(checkpoint tailCheckpoint) error {
	return writeStateJSON(t.config.StateDir, t.checkpointPath, checkpoint)
}

func fingerprintMatches(file *os.File, checkpoint tailCheckpoint) bool {
	if checkpoint.Offset == 0 {
		return checkpoint.Fingerprint == ""
	}
	fingerprint, err := fingerprintAt(file, checkpoint.Offset)
	return err == nil && fingerprint == checkpoint.Fingerprint
}

func fingerprintAt(file *os.File, offset int64) (string, error) {
	if offset == 0 {
		return "", nil
	}
	start := offset - fingerprintBytes
	if start < 0 {
		start = 0
	}
	buffer := make([]byte, offset-start)
	if _, err := file.ReadAt(buffer, start); err != nil {
		return "", fmt.Errorf("fingerprint edge event log: %w", err)
	}
	digest := sha256.Sum256(buffer)
	return hex.EncodeToString(digest[:]), nil
}

func validCheckpointFingerprint(offset int64, fingerprint string) bool {
	if offset == 0 {
		return fingerprint == ""
	}
	return canonicalSHA256(fingerprint)
}

func canonicalSHA256(value string) bool {
	if len(value) != sha256.Size*2 || value != strings.ToLower(value) {
		return false
	}
	_, err := hex.DecodeString(value)
	return err == nil
}

func openSource(path string) (*os.File, sourceIdentity, error) {
	if err := rejectSymlinkComponents(path); err != nil {
		return nil, sourceIdentity{}, err
	}
	file, err := os.OpenFile(path, os.O_RDONLY|syscall.O_NOFOLLOW, 0)
	if err != nil {
		return nil, sourceIdentity{}, fmt.Errorf("open edge event log: %w", err)
	}
	info, statErr := file.Stat()
	stat, ok := infoSys(info)
	if statErr != nil || !ok || !info.Mode().IsRegular() || info.Mode().Perm() != 0o600 || stat.Nlink != 1 {
		_ = file.Close()
		return nil, sourceIdentity{}, ErrUnsafePath
	}
	return file, sourceIdentity{device: uint64(stat.Dev), inode: uint64(stat.Ino), size: info.Size()}, nil
}

func (t *Tailer) findSource(device, inode uint64, retiredSources []retiredTailSource, result *TailResult) (*os.File, sourceIdentity, []rotatedSource, error) {
	directory := filepath.Dir(t.config.SourcePath)
	entries, err := os.ReadDir(directory)
	if err != nil {
		return nil, sourceIdentity{}, nil, fmt.Errorf("scan rotated event logs: %w", err)
	}
	prefix := filepath.Base(t.config.SourcePath) + "."
	var found *os.File
	var foundIdentity sourceIdentity
	var candidates []rotatedSource
	for _, entry := range entries {
		if !strings.HasPrefix(entry.Name(), prefix) {
			continue
		}
		if len(candidates) >= maxRetiredTailSources+2 {
			if found != nil {
				_ = found.Close()
			}
			return nil, sourceIdentity{}, nil, ErrTailRotationAmbiguous
		}
		info, infoErr := entry.Info()
		stat, statOK := infoSys(info)
		if infoErr != nil || !statOK || !info.Mode().IsRegular() || info.Mode().Perm() != 0o600 || stat.Nlink != 1 || entry.Type()&os.ModeSymlink != 0 {
			if found != nil {
				_ = found.Close()
			}
			return nil, sourceIdentity{}, nil, ErrUnsafePath
		}
		path := filepath.Join(directory, entry.Name())
		file, identity, openErr := openSource(path)
		if openErr != nil {
			if found != nil {
				_ = found.Close()
			}
			return nil, sourceIdentity{}, nil, openErr
		}
		candidate := rotatedSource{identity: identity}
		for _, retired := range retiredSources {
			if retiredIdentityMatches(candidate, retired) {
				digest, hashedBytes, hashErr := t.fullSourceDigest(file, identity)
				result.RotationFilesHashed++
				result.RotationBytesHashed += hashedBytes
				if hashErr != nil {
					_ = file.Close()
					if found != nil {
						_ = found.Close()
					}
					return nil, sourceIdentity{}, nil, hashErr
				}
				candidate.digest = digest
				break
			}
		}
		candidates = append(candidates, candidate)
		if identity.device == device && identity.inode == inode {
			if found != nil {
				_ = file.Close()
				_ = found.Close()
				return nil, sourceIdentity{}, nil, ErrUnsafePath
			}
			found = file
			foundIdentity = identity
			continue
		}
		_ = file.Close()
	}
	return found, foundIdentity, candidates, nil
}

func (t *Tailer) fullSourceDigest(file *os.File, expected sourceIdentity) (string, int64, error) {
	before, err := checkedOpenSourceState(file)
	if err != nil {
		return "", 0, err
	}
	if !sameSource(before.identity, expected) || before.identity.size != expected.size {
		return "", 0, ErrTailRotationAmbiguous
	}
	hash := sha256.New()
	reader := io.NewSectionReader(file, 0, before.identity.size)
	buffer := make([]byte, digestReadBufferBytes)
	var read int64
	var readErr error
	hookCalled := false
	for {
		count, err := reader.Read(buffer)
		if count > 0 {
			_, _ = hash.Write(buffer[:count])
			read += int64(count)
			if !hookCalled && t.hashHook != nil {
				t.hashHook(file, read)
				hookCalled = true
			}
		}
		if errors.Is(err, io.EOF) {
			break
		}
		if err != nil {
			readErr = err
			break
		}
	}
	after, statErr := checkedOpenSourceState(file)
	if statErr != nil {
		return "", read, statErr
	}
	if read != before.identity.size || !sameSourceFileState(before, after) {
		return "", read, ErrTailRotationAmbiguous
	}
	if readErr != nil {
		return "", read, fmt.Errorf("hash rotated event log: %w", readErr)
	}
	return hex.EncodeToString(hash.Sum(nil)), read, nil
}

func checkedOpenSourceState(file *os.File) (sourceFileState, error) {
	info, err := file.Stat()
	stat, ok := infoSys(info)
	if err != nil || !ok || !info.Mode().IsRegular() || info.Mode().Perm() != 0o600 || stat.Nlink != 1 {
		return sourceFileState{}, ErrUnsafePath
	}
	changedSec, changedNSec := statChangeTime(stat)
	modified := info.ModTime()
	return sourceFileState{
		identity: sourceIdentity{device: uint64(stat.Dev), inode: uint64(stat.Ino), size: info.Size()},
		mode:     info.Mode(), nlink: uint64(stat.Nlink),
		modifiedSec: modified.Unix(), modifiedNSec: int64(modified.Nanosecond()),
		changedSec: changedSec, changedNSec: changedNSec,
	}, nil
}

func sameSourceFileState(left, right sourceFileState) bool {
	return sameSource(left.identity, right.identity) && left.identity.size == right.identity.size &&
		left.mode == right.mode && left.nlink == right.nlink &&
		left.modifiedSec == right.modifiedSec && left.modifiedNSec == right.modifiedNSec &&
		left.changedSec == right.changedSec && left.changedNSec == right.changedNSec
}

func classifyRotatedSources(candidates []rotatedSource, checkpoint tailCheckpoint, active sourceIdentity) ([]retiredTailSource, bool) {
	retained := make([]retiredTailSource, 0, len(checkpoint.RetiredSources))
	for _, retired := range checkpoint.RetiredSources {
		for _, candidate := range candidates {
			if retiredSourceMatches(candidate, retired) {
				retained = append(retained, retired)
				break
			}
		}
	}
	for _, candidate := range candidates {
		if sameSource(candidate.identity, sourceIdentity{device: checkpoint.Device, inode: checkpoint.Inode}) || sameSource(candidate.identity, active) {
			continue
		}
		known := false
		for _, retired := range retained {
			if retiredSourceMatches(candidate, retired) {
				known = true
				break
			}
		}
		if !known {
			return retained, true
		}
	}
	return retained, false
}

func retiredSourceMatches(candidate rotatedSource, retired retiredTailSource) bool {
	return retiredIdentityMatches(candidate, retired) && candidate.digest == retired.Digest
}

func retiredIdentityMatches(candidate rotatedSource, retired retiredTailSource) bool {
	return candidate.identity.device == retired.Device && candidate.identity.inode == retired.Inode && candidate.identity.size == retired.Size
}

func sameSource(left, right sourceIdentity) bool {
	return left.device == right.device && left.inode == right.inode
}

func lockPrivateFile(ctx context.Context, path string, device uint64) (func(), error) {
	file, err := os.OpenFile(path, os.O_CREATE|os.O_RDWR|syscall.O_NOFOLLOW, 0o600)
	if err != nil {
		return nil, err
	}
	info, statErr := file.Stat()
	stat, ok := infoSys(info)
	if statErr != nil || !ok || !info.Mode().IsRegular() || info.Mode().Perm() != 0o600 || stat.Nlink != 1 || uint64(stat.Dev) != device {
		_ = file.Close()
		return nil, ErrUnsafePath
	}
	for {
		if err := syscall.Flock(int(file.Fd()), syscall.LOCK_EX|syscall.LOCK_NB); err == nil {
			return func() {
				_ = syscall.Flock(int(file.Fd()), syscall.LOCK_UN)
				_ = file.Close()
			}, nil
		} else if !errors.Is(err, syscall.EWOULDBLOCK) && !errors.Is(err, syscall.EAGAIN) {
			_ = file.Close()
			return nil, err
		}
		select {
		case <-ctx.Done():
			_ = file.Close()
			return nil, ctx.Err()
		case <-time.After(10 * time.Millisecond):
		}
	}
}
