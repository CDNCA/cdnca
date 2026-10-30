package eventspool

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
	"sort"
	"strings"
	"sync"
	"syscall"
	"time"

	agentv1 "github.com/cdnca/cdnca/proto/gen/go/agent/v1"
	"google.golang.org/protobuf/proto"
)

type ackState struct {
	SchemaVersion uint16 `json:"schema_version"`
	Sequence      uint64 `json:"sequence"`
	EventID       string `json:"event_id,omitempty"`
}

type alertState struct {
	SchemaVersion uint16 `json:"schema_version"`
	Code          string `json:"code"`
	// ExpiredEvents counts events skipped because they were already older
	// than the hard age limit when offered (each offer counts, replays too).
	ExpiredEvents uint64 `json:"expired_events,omitempty"`
}

type eventIdentity struct {
	digest   [sha256.Size]byte
	sequence uint64
}

type preparedRecord struct {
	frame  []byte
	record Record
}

const maxConnectionsQueueEntries = 256

type connectionsIdentityState struct {
	EventID         string `json:"event_id"`
	IdentityDigest  []byte `json:"identity_digest"`
	CanonicalDigest []byte `json:"canonical_digest"`
	SourceWatermark uint64 `json:"source_watermark"`
}

type connectionsQueueEntry struct {
	Sequence        uint64 `json:"sequence"`
	MessageID       string `json:"message_id"`
	EventID         string `json:"event_id"`
	TenantID        string `json:"tenant_id"`
	InstallationID  string `json:"installation_id"`
	SourceWatermark uint64 `json:"source_watermark"`
	IdentityDigest  []byte `json:"identity_digest"`
	Payload         []byte `json:"payload"`
}

type connectionsState struct {
	SchemaVersion       uint16                     `json:"schema_version"`
	NextSequence        uint64                     `json:"next_sequence"`
	LastSourceWatermark uint64                     `json:"last_source_watermark"`
	Identities          []connectionsIdentityState `json:"identities"`
	Entries             []connectionsQueueEntry    `json:"entries"`
}

type Spool struct {
	mu              sync.Mutex
	config          Config
	root            string
	segmentsDir     string
	stateDir        string
	lockPath        string
	publishPath     string
	ackPath         string
	alertPath       string
	connectionsPath string
	device          uint64
	ack             ackState
	pending         []Record
	eventIDs        map[string]eventIdentity
	tenantBytes     map[string]int64
	metas           []segmentMeta
	nextSequence    uint64
	segmentBytes    int64
	peakBytes       int64
	lastAlertCode   string
	expiredEvents   uint64
	testWriteError  func() error
}

func New(config Config) (*Spool, error) {
	if config.Now == nil {
		config.Now = time.Now
	}
	if err := validateSpoolConfig(config); err != nil {
		return nil, err
	}
	root, device, err := prepareRoot(config.Root)
	if err != nil {
		return nil, err
	}
	spool := &Spool{
		config:          config,
		root:            root,
		segmentsDir:     filepath.Join(root, "segments"),
		stateDir:        filepath.Join(root, "state"),
		lockPath:        filepath.Join(root, "state", "spool.lock"),
		publishPath:     filepath.Join(root, "state", "publish.lock"),
		ackPath:         filepath.Join(root, "state", "ack.json"),
		alertPath:       filepath.Join(root, "state", "alert.json"),
		connectionsPath: filepath.Join(root, "state", "connections.json"),
		device:          device,
	}
	for _, directory := range []string{spool.segmentsDir, spool.stateDir} {
		if err := ensureOwnerDirectory(directory, device); err != nil {
			return nil, err
		}
	}
	spool.mu.Lock()
	defer spool.mu.Unlock()
	unlock, err := spool.lock(context.Background())
	if err != nil {
		return nil, err
	}
	defer unlock()
	if err := spool.loadAckLocked(); err != nil {
		return nil, err
	}
	if _, err := spool.loadConnectionsStateLocked(); err != nil {
		return nil, err
	}
	spool.loadAlertLocked()
	if err := spool.rebuildLocked(true); err != nil {
		return nil, err
	}
	return spool, nil
}

func (s *Spool) loadConnectionsStateLocked() (connectionsState, error) {
	state := connectionsState{SchemaVersion: SchemaVersion, NextSequence: 1}
	exists, err := readStateJSON(s.connectionsPath, &state, s.device)
	if err != nil {
		return connectionsState{}, err
	}
	if !exists {
		return state, nil
	}
	if state.SchemaVersion != SchemaVersion || state.NextSequence == 0 || len(state.Entries) > maxConnectionsQueueEntries {
		return connectionsState{}, ErrCorruptState
	}
	identities := make(map[string]connectionsIdentityState, len(state.Identities))
	for _, identity := range state.Identities {
		if !idPattern.MatchString(identity.EventID) || len(identity.IdentityDigest) != sha256.Size ||
			len(identity.CanonicalDigest) != sha256.Size || identity.SourceWatermark == 0 {
			return connectionsState{}, ErrCorruptState
		}
		if _, exists := identities[identity.EventID]; exists {
			return connectionsState{}, ErrCorruptState
		}
		identities[identity.EventID] = identity
		if identity.SourceWatermark > state.LastSourceWatermark {
			return connectionsState{}, ErrCorruptState
		}
	}
	seenSequences := make(map[uint64]struct{}, len(state.Entries))
	for _, entry := range state.Entries {
		if entry.Sequence == 0 || entry.Sequence >= state.NextSequence || entry.MessageID == "" ||
			!idPattern.MatchString(entry.EventID) || !validUUID(entry.TenantID) || !validUUID(entry.InstallationID) ||
			entry.SourceWatermark == 0 || len(entry.IdentityDigest) != sha256.Size || len(entry.Payload) == 0 ||
			len(entry.Payload) > maxConnectionsEnvelopeBytes {
			return connectionsState{}, ErrCorruptState
		}
		if _, exists := seenSequences[entry.Sequence]; exists {
			return connectionsState{}, ErrCorruptState
		}
		seenSequences[entry.Sequence] = struct{}{}
		var envelope agentv1.ConnectionsMetricEnvelopeV1
		if proto.Unmarshal(entry.Payload, &envelope) != nil || validateConnectionsEnvelope(&envelope) != nil ||
			envelope.GetEvent().GetEventId() != entry.EventID || envelope.GetTenantId() != entry.TenantID ||
			envelope.GetInstallationId() != entry.InstallationID || envelope.GetSourceWatermark() != entry.SourceWatermark {
			return connectionsState{}, ErrCorruptState
		}
		identityDigest := connectionsIdentityDigest(&envelope)
		if !bytes.Equal(entry.IdentityDigest, identityDigest[:]) || entry.MessageID != connectionsMessageID(identityDigest) {
			return connectionsState{}, ErrCorruptState
		}
		known, exists := identities[entry.EventID]
		if !exists || !bytes.Equal(known.IdentityDigest, identityDigest[:]) ||
			!bytes.Equal(known.CanonicalDigest, envelope.GetCanonicalEventSha256()) || known.SourceWatermark != entry.SourceWatermark {
			return connectionsState{}, ErrCorruptState
		}
	}
	return state, nil
}

func (s *Spool) persistConnectionsStateLocked(state connectionsState) error {
	if state.SchemaVersion == 0 {
		state.SchemaVersion = SchemaVersion
	}
	if state.NextSequence == 0 || len(state.Entries) > maxConnectionsQueueEntries {
		return ErrCorruptState
	}
	encoded, err := json.Marshal(state)
	if err != nil || len(encoded)+1 > 64<<10 {
		return ErrBackpressure
	}
	return writeStateJSON(s.stateDir, s.connectionsPath, state)
}

func validateSpoolConfig(config Config) error {
	if config.Root == "" || !filepath.IsAbs(config.Root) || filepath.Clean(config.Root) != config.Root || config.Root == string(filepath.Separator) ||
		config.MaxEventBytes < 256 || config.MaxEventBytes > 1<<20 ||
		config.MaxSegmentBytes < int64(config.MaxEventBytes+recordHeaderSize+segmentHeaderSize) || config.MaxSegmentBytes > 1<<30 ||
		config.SoftLimitBytes < config.MaxSegmentBytes || config.SoftLimitBytes >= config.HardLimitBytes || config.HardLimitBytes > 1<<40 ||
		config.MaxTenantBytes < config.MaxSegmentBytes || config.MaxTenantBytes > config.HardLimitBytes ||
		config.MaxBatchEvents < 1 || config.MaxBatchEvents > 10000 ||
		config.SoftAgeLimit <= 0 || config.SoftAgeLimit >= config.HardAgeLimit || config.HardAgeLimit > 29*24*time.Hour || config.Now == nil {
		return ErrInvalidConfig
	}
	switch config.PressureMode {
	case PressureBackpressure:
		if config.AccessSampleEvery != 0 || config.SecuritySampleEvery != 0 {
			return ErrInvalidConfig
		}
	case PressureSample:
		if config.AccessSampleEvery == 0 || config.SecuritySampleEvery == 0 || config.AccessSampleEvery > 1_000_000 || config.SecuritySampleEvery > 1_000_000 {
			return ErrInvalidConfig
		}
	default:
		return ErrInvalidConfig
	}
	return nil
}

func prepareRoot(configured string) (string, uint64, error) {
	if err := rejectSymlinkComponents(configured); err != nil {
		return "", 0, err
	}
	if err := os.MkdirAll(configured, 0o700); err != nil {
		return "", 0, fmt.Errorf("create event spool root: %w", err)
	}
	if err := rejectSymlinkComponents(configured); err != nil {
		return "", 0, err
	}
	realRoot, err := filepath.EvalSymlinks(configured)
	if err != nil || realRoot == string(filepath.Separator) {
		return "", 0, ErrUnsafePath
	}
	info, err := os.Lstat(realRoot)
	stat, ok := infoSys(info)
	if err != nil || !ok || !info.IsDir() || info.Mode().Perm()&0o077 != 0 {
		return "", 0, ErrUnsafePath
	}
	return realRoot, uint64(stat.Dev), nil
}

func rejectSymlinkComponents(path string) error {
	if !filepath.IsAbs(path) || filepath.Clean(path) != path {
		return ErrUnsafePath
	}
	current := string(filepath.Separator)
	for _, component := range strings.Split(strings.TrimPrefix(path, string(filepath.Separator)), string(filepath.Separator)) {
		if component == "" {
			continue
		}
		current = filepath.Join(current, component)
		info, err := os.Lstat(current)
		if errors.Is(err, os.ErrNotExist) {
			return nil
		}
		if err != nil || info.Mode()&os.ModeSymlink != 0 {
			return ErrUnsafePath
		}
	}
	return nil
}

func ensureOwnerDirectory(path string, device uint64) error {
	if err := os.Mkdir(path, 0o700); err != nil && !errors.Is(err, os.ErrExist) {
		return fmt.Errorf("create event spool directory: %w", err)
	}
	info, err := os.Lstat(path)
	stat, ok := infoSys(info)
	if err != nil || !ok || !info.IsDir() || info.Mode()&os.ModeSymlink != 0 || info.Mode().Perm()&0o077 != 0 || uint64(stat.Dev) != device {
		return ErrUnsafePath
	}
	return nil
}

func infoSys(info os.FileInfo) (*syscall.Stat_t, bool) {
	if info == nil {
		return nil, false
	}
	stat, ok := info.Sys().(*syscall.Stat_t)
	return stat, ok
}

func (s *Spool) lock(ctx context.Context) (func(), error) {
	file, err := os.OpenFile(s.lockPath, os.O_CREATE|os.O_RDWR|syscall.O_NOFOLLOW, 0o600)
	if err != nil {
		return nil, fmt.Errorf("open event spool lock: %w", err)
	}
	info, statErr := file.Stat()
	stat, ok := infoSys(info)
	if statErr != nil || !ok || !info.Mode().IsRegular() || info.Mode().Perm() != 0o600 || stat.Nlink != 1 || uint64(stat.Dev) != s.device {
		_ = file.Close()
		return nil, ErrUnsafePath
	}
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
			return nil, fmt.Errorf("lock event spool: %w", err)
		}
		select {
		case <-ctx.Done():
			_ = file.Close()
			return nil, ctx.Err()
		case <-time.After(10 * time.Millisecond):
		}
	}
}

func (s *Spool) AppendBatch(ctx context.Context, envelopes []Envelope) ([]AppendResult, error) {
	if len(envelopes) == 0 || len(envelopes) > s.config.MaxBatchEvents {
		return nil, ErrInvalidEvent
	}
	s.mu.Lock()
	defer s.mu.Unlock()
	unlock, err := s.lock(ctx)
	if err != nil {
		return nil, err
	}
	defer unlock()
	if err := s.loadAckLocked(); err != nil {
		return nil, err
	}
	if err := s.rebuildLocked(true); err != nil {
		return nil, err
	}

	results := make([]AppendResult, len(envelopes))
	batchIDs := make(map[string]eventIdentity, len(envelopes))
	batchTenantBytes := make(map[string]int64)
	total := s.segmentBytes
	virtualOpenSize := int64(0)
	virtualOpenRecords := 0
	if open := s.openSegmentLocked(); open != nil {
		virtualOpenSize = open.size
		virtualOpenRecords = open.records
	}
	next := s.nextSequence
	now := s.config.Now().UTC()
	// Age pressure is a property of the stored backlog only: an incoming
	// event that is itself old (a node replaying logs after a long outage)
	// must not push back once the backlog has drained, or the tailer stays
	// on that line forever.
	backlogAge := time.Duration(0)
	if oldest := s.oldestOccurredAtLocked(); !oldest.IsZero() && now.After(oldest) {
		backlogAge = now.Sub(oldest)
	}
	if backlogAge >= s.config.HardAgeLimit {
		s.recordAlertLocked("SPOOL_AGE_HARD_WATERMARK")
		return nil, ErrAgeLimit
	}
	expired := uint64(0)
	prepared := make([]preparedRecord, 0, len(envelopes))
	for index := range envelopes {
		envelope := envelopes[index]
		if err := validateEnvelope(envelope, identityPending); err != nil {
			return nil, err
		}
		digest := contentDigest(envelope)
		if existing, found := s.eventIDs[envelope.EventID]; found {
			if existing.digest != digest {
				return nil, ErrConflict
			}
			results[index] = AppendResult{EventID: envelope.EventID, Sequence: existing.sequence, Duplicate: true}
			continue
		}
		if existing, found := batchIDs[envelope.EventID]; found {
			if existing.digest != digest {
				return nil, ErrConflict
			}
			results[index] = AppendResult{EventID: envelope.EventID, Sequence: existing.sequence, Duplicate: true}
			continue
		}
		if envelope.OccurredAt.After(now.Add(5 * time.Minute)) {
			return nil, ErrInvalidEvent
		}
		if now.Sub(envelope.OccurredAt) >= s.config.HardAgeLimit {
			// Too old to keep: skip it (counted) instead of failing the
			// batch, which would stop the source at this line for good.
			results[index] = AppendResult{EventID: envelope.EventID, Expired: true}
			expired++
			continue
		}

		envelope.Sequence = next
		payload, err := encodeEnvelope(envelope)
		if err != nil || len(payload) > s.config.MaxEventBytes {
			return nil, ErrInvalidEvent
		}
		frame := encodeFrame(payload)
		frameBytes := int64(len(frame))
		headerBytes := int64(0)
		if virtualOpenSize == 0 || (virtualOpenRecords > 0 && virtualOpenSize+frameBytes > s.config.MaxSegmentBytes) {
			headerBytes = segmentHeaderSize
		}
		projected := total + headerBytes + frameBytes
		if projected > s.config.HardLimitBytes {
			s.recordAlertLocked("SPOOL_HARD_WATERMARK")
			return nil, ErrHardLimit
		}
		if s.tenantBytes[envelope.TenantID]+batchTenantBytes[envelope.TenantID]+frameBytes > s.config.MaxTenantBytes {
			s.recordAlertLocked("SPOOL_TENANT_LIMIT")
			return nil, ErrTenantLimit
		}
		if projected > s.config.SoftLimitBytes || backlogAge >= s.config.SoftAgeLimit {
			if s.config.PressureMode == PressureBackpressure {
				return nil, ErrBackpressure
			}
			if shouldSampleOut(envelope, s.config) {
				results[index] = AppendResult{EventID: envelope.EventID, Sampled: true}
				continue
			}
		}
		identity := eventIdentity{digest: digest, sequence: next}
		batchIDs[envelope.EventID] = identity
		batchTenantBytes[envelope.TenantID] += frameBytes
		results[index] = AppendResult{EventID: envelope.EventID, Sequence: next}
		prepared = append(prepared, preparedRecord{frame: frame, record: Record{
			Sequence: next, EventID: envelope.EventID, TenantID: envelope.TenantID,
			NodeID: envelope.NodeID, Type: envelope.Type, OccurredAt: envelope.OccurredAt,
			Payload: payload, Size: frameBytes, digest: digest, envelope: envelope,
		}})
		total += frameBytes
		if headerBytes > 0 {
			total += headerBytes
			virtualOpenSize = segmentHeaderSize
			virtualOpenRecords = 0
		}
		virtualOpenSize += frameBytes
		virtualOpenRecords++
		next++
	}
	if expired > 0 {
		s.expiredEvents += expired
		s.recordAlertLocked("SPOOL_EVENT_EXPIRED")
	}
	if len(prepared) == 0 {
		return results, nil
	}
	if err := s.appendPreparedLocked(prepared); err != nil {
		s.recordAlertLocked(safeErrorCode(err))
		_ = s.rebuildLocked(true)
		return nil, fmt.Errorf("append event spool batch: %w", err)
	}
	if err := s.rebuildLocked(false); err != nil {
		return nil, err
	}
	return results, nil
}

// AppendConnections durably stages one finalized, authority-backed gauge. The
// staged record is not removed until FlushConnections observes a compatible
// publisher acknowledgement.
func (s *Spool) AppendConnections(ctx context.Context, envelope *agentv1.ConnectionsMetricEnvelopeV1) (ConnectionsAppendResult, error) {
	if ctx == nil || envelope == nil {
		return ConnectionsAppendResult{}, ErrInvalidConnections
	}
	if err := validateConnectionsEnvelope(envelope); err != nil {
		return ConnectionsAppendResult{}, err
	}
	s.mu.Lock()
	defer s.mu.Unlock()
	unlock, err := s.lock(ctx)
	if err != nil {
		return ConnectionsAppendResult{}, err
	}
	defer unlock()
	state, err := s.loadConnectionsStateLocked()
	if err != nil {
		return ConnectionsAppendResult{}, err
	}
	identityDigest := connectionsIdentityDigest(envelope)
	for _, identity := range state.Identities {
		if identity.EventID != envelope.GetEvent().GetEventId() {
			continue
		}
		if bytes.Equal(identity.IdentityDigest, identityDigest[:]) &&
			bytes.Equal(identity.CanonicalDigest, envelope.GetCanonicalEventSha256()) {
			return ConnectionsAppendResult{EventID: identity.EventID, SourceWatermark: identity.SourceWatermark, Duplicate: true}, nil
		}
		return ConnectionsAppendResult{}, ErrConnectionsConflict
	}
	if envelope.GetSourceWatermark() <= state.LastSourceWatermark {
		return ConnectionsAppendResult{}, ErrConnectionsWatermark
	}
	if len(state.Entries) >= maxConnectionsQueueEntries {
		return ConnectionsAppendResult{}, ErrBackpressure
	}
	payload, err := proto.MarshalOptions{Deterministic: true}.Marshal(envelope)
	if err != nil || len(payload) == 0 || len(payload) > maxConnectionsEnvelopeBytes {
		return ConnectionsAppendResult{}, ErrInvalidConnections
	}
	entry := connectionsQueueEntry{
		Sequence: state.NextSequence, MessageID: connectionsMessageID(identityDigest),
		EventID: envelope.GetEvent().GetEventId(), TenantID: envelope.GetTenantId(),
		InstallationID: envelope.GetInstallationId(), SourceWatermark: envelope.GetSourceWatermark(),
		IdentityDigest: append([]byte(nil), identityDigest[:]...), Payload: append([]byte(nil), payload...),
	}
	state.NextSequence++
	state.LastSourceWatermark = envelope.GetSourceWatermark()
	state.Identities = append(state.Identities, connectionsIdentityState{
		EventID: entry.EventID, IdentityDigest: append([]byte(nil), identityDigest[:]...),
		CanonicalDigest: append([]byte(nil), envelope.GetCanonicalEventSha256()...), SourceWatermark: entry.SourceWatermark,
	})
	state.Entries = append(state.Entries, entry)
	if err := s.persistConnectionsStateLocked(state); err != nil {
		return ConnectionsAppendResult{}, err
	}
	return ConnectionsAppendResult{EventID: entry.EventID, SourceWatermark: entry.SourceWatermark}, nil
}

// FlushConnections publishes staged connection metrics and removes only the
// prefix covered by a valid publisher acknowledgement.
func (s *Spool) FlushConnections(ctx context.Context, publisher Publisher, maximum int) (ConnectionsPublishResult, error) {
	if ctx == nil || publisher == nil || maximum < 1 || maximum > maxConnectionsQueueEntries {
		return ConnectionsPublishResult{}, ErrInvalidConfig
	}
	unlockPublish, err := lockPrivateFile(ctx, s.publishPath, s.device)
	if err != nil {
		return ConnectionsPublishResult{}, err
	}
	defer unlockPublish()
	s.mu.Lock()
	state, err := s.loadConnectionsStateLocked()
	s.mu.Unlock()
	if err != nil {
		return ConnectionsPublishResult{}, err
	}
	if len(state.Entries) == 0 {
		return ConnectionsPublishResult{}, nil
	}
	if maximum > len(state.Entries) {
		maximum = len(state.Entries)
	}
	entries := append([]connectionsQueueEntry(nil), state.Entries[:maximum]...)
	publications := make([]Publication, len(entries))
	for index := range entries {
		publications[index] = connectionsPublication(entries[index])
	}
	ack, publishErr := publisher.Publish(ctx, publications)
	if ack.Acknowledged < 0 || ack.Acknowledged > len(publications) ||
		(publishErr == nil && ack.Acknowledged != len(publications)) {
		return ConnectionsPublishResult{Attempts: 1}, ErrInvalidAck
	}
	if ack.Acknowledged == 0 {
		return ConnectionsPublishResult{Attempts: 1}, publishErr
	}
	s.mu.Lock()
	defer s.mu.Unlock()
	unlock, err := s.lock(ctx)
	if err != nil {
		return ConnectionsPublishResult{Attempts: 1}, err
	}
	defer unlock()
	latest, err := s.loadConnectionsStateLocked()
	if err != nil {
		return ConnectionsPublishResult{Attempts: 1}, err
	}
	if len(latest.Entries) < ack.Acknowledged {
		return ConnectionsPublishResult{Attempts: 1}, ErrCorruptState
	}
	for index := 0; index < ack.Acknowledged; index++ {
		current, expected := latest.Entries[index], entries[index]
		if current.Sequence != expected.Sequence || current.MessageID != expected.MessageID ||
			current.EventID != expected.EventID || !bytes.Equal(current.Payload, expected.Payload) {
			return ConnectionsPublishResult{Attempts: 1}, ErrCorruptState
		}
	}
	latest.Entries = append([]connectionsQueueEntry(nil), latest.Entries[ack.Acknowledged:]...)
	// Keep every pending identity and a bounded recent replay window. Older
	// observations still cannot re-enter because the durable watermark fences them.
	pendingIdentities := make(map[string]struct{}, len(latest.Entries))
	for _, entry := range latest.Entries {
		pendingIdentities[entry.EventID] = struct{}{}
	}
	retained := make([]connectionsIdentityState, 0, min(len(latest.Identities), len(latest.Entries)+64))
	for index, identity := range latest.Identities {
		_, pending := pendingIdentities[identity.EventID]
		if pending || index >= len(latest.Identities)-64 {
			retained = append(retained, identity)
		}
	}
	latest.Identities = retained
	if err := s.persistConnectionsStateLocked(latest); err != nil {
		return ConnectionsPublishResult{Attempts: 1}, err
	}
	last := entries[ack.Acknowledged-1]
	result := ConnectionsPublishResult{
		Published: ack.Acknowledged, PublishedMessages: ack.Acknowledged,
		LastSourceWatermark: last.SourceWatermark, Attempts: 1,
	}
	return result, publishErr
}

func shouldSampleOut(envelope Envelope, config Config) bool {
	if envelope.Type == EventAccessWindow || envelope.Type == EventSubscriptionMinute || envelope.Type == EventL4Checkpoint {
		return false // billed usage, never sampled
	}
	every := config.AccessSampleEvery
	if envelope.Type == EventSecurity {
		every = config.SecuritySampleEvery
	}
	if every <= 1 {
		return false
	}
	digest := sha256.Sum256([]byte(envelope.EventID))
	value := uint32(digest[0])<<24 | uint32(digest[1])<<16 | uint32(digest[2])<<8 | uint32(digest[3])
	return value%every != 0
}

func (s *Spool) appendPreparedLocked(values []preparedRecord) error {
	var current *os.File
	var currentMeta *segmentMeta
	closeCurrent := func() error {
		if current == nil {
			return nil
		}
		if err := current.Sync(); err != nil {
			_ = current.Close()
			current = nil
			return err
		}
		err := current.Close()
		current = nil
		return err
	}
	defer func() { _ = closeCurrent() }()

	for _, value := range values {
		if currentMeta == nil {
			currentMeta = s.openSegmentLocked()
		}
		if currentMeta != nil && currentMeta.records > 0 && currentMeta.size+int64(len(value.frame)) > s.config.MaxSegmentBytes {
			if err := closeCurrent(); err != nil {
				return err
			}
			if err := s.sealOpenSegmentLocked(*currentMeta); err != nil {
				return err
			}
			currentMeta = nil
		}
		if currentMeta == nil {
			created, err := s.createOpenSegmentLocked(value.record.Sequence)
			if err != nil {
				return err
			}
			currentMeta = &created
		}
		if current == nil {
			file, err := s.openSegmentAppendLocked(currentMeta.path)
			if err != nil {
				return err
			}
			current = file
		}
		if s.testWriteError != nil {
			if err := s.testWriteError(); err != nil {
				return err
			}
		}
		if _, err := current.Write(value.frame); err != nil {
			return err
		}
		currentMeta.size += int64(len(value.frame))
		currentMeta.max = value.record.Sequence
		currentMeta.records++
	}
	return closeCurrent()
}

func (s *Spool) openSegmentLocked() *segmentMeta {
	for index := range s.metas {
		if s.metas[index].open {
			return &s.metas[index]
		}
	}
	return nil
}

func (s *Spool) createOpenSegmentLocked(start uint64) (segmentMeta, error) {
	path := filepath.Join(s.segmentsDir, segmentName(start, "open"))
	file, err := os.OpenFile(path, os.O_CREATE|os.O_EXCL|os.O_WRONLY|syscall.O_NOFOLLOW, 0o600)
	if err != nil {
		return segmentMeta{}, err
	}
	ok := false
	defer func() {
		_ = file.Close()
		if !ok {
			_ = os.Remove(path)
		}
	}()
	if _, err := file.Write(encodeSegmentHeader(start)); err != nil {
		return segmentMeta{}, err
	}
	if err := file.Sync(); err != nil {
		return segmentMeta{}, err
	}
	if err := file.Close(); err != nil {
		return segmentMeta{}, err
	}
	if err := syncDirectory(s.segmentsDir); err != nil {
		return segmentMeta{}, err
	}
	ok = true
	meta := segmentMeta{path: path, name: filepath.Base(path), start: start, size: segmentHeaderSize, open: true}
	s.metas = append(s.metas, meta)
	return meta, nil
}

func (s *Spool) openSegmentAppendLocked(path string) (*os.File, error) {
	file, err := os.OpenFile(path, os.O_WRONLY|os.O_APPEND|syscall.O_NOFOLLOW, 0)
	if err != nil {
		return nil, err
	}
	info, statErr := file.Stat()
	stat, ok := infoSys(info)
	if statErr != nil || !ok || !info.Mode().IsRegular() || info.Mode().Perm() != 0o600 || stat.Nlink != 1 || uint64(stat.Dev) != s.device {
		_ = file.Close()
		return nil, ErrUnsafePath
	}
	return file, nil
}

func (s *Spool) sealOpenSegmentLocked(meta segmentMeta) error {
	if !meta.open || meta.records == 0 {
		return ErrCorruptState
	}
	destination := strings.TrimSuffix(meta.path, ".open") + ".seg"
	if err := os.Rename(meta.path, destination); err != nil {
		return err
	}
	return syncDirectory(s.segmentsDir)
}

func (s *Spool) rebuildLocked(cleanup bool) error {
	records, metas, total, err := s.scanSegmentsLocked(true)
	if err != nil {
		return err
	}
	if cleanup {
		removed := false
		kept := metas[:0]
		for _, meta := range metas {
			if meta.records > 0 && meta.max <= s.ack.Sequence {
				if err := os.Remove(meta.path); err != nil {
					return fmt.Errorf("remove acknowledged event segment: %w", err)
				}
				total -= meta.size
				removed = true
				continue
			}
			kept = append(kept, meta)
		}
		metas = kept
		if removed {
			if err := syncDirectory(s.segmentsDir); err != nil {
				return err
			}
		}
	}
	s.pending = s.pending[:0]
	s.eventIDs = make(map[string]eventIdentity)
	s.tenantBytes = make(map[string]int64)
	maxSequence := s.ack.Sequence
	for _, record := range records {
		if record.Sequence > maxSequence {
			maxSequence = record.Sequence
		}
		if record.Sequence <= s.ack.Sequence {
			continue
		}
		identity := eventIdentity{digest: record.digest, sequence: record.Sequence}
		if existing, duplicate := s.eventIDs[record.EventID]; duplicate && existing != identity {
			return ErrCorruptState
		}
		s.eventIDs[record.EventID] = identity
		s.tenantBytes[record.TenantID] += record.Size
		s.pending = append(s.pending, record)
	}
	s.metas = metas
	s.segmentBytes = total
	if total > s.peakBytes {
		s.peakBytes = total
	}
	s.nextSequence = maxSequence + 1
	return nil
}

func (s *Spool) loadAckLocked() error {
	var ack ackState
	exists, err := readStateJSON(s.ackPath, &ack, s.device)
	if err != nil {
		return err
	}
	if !exists {
		s.ack = ackState{SchemaVersion: SchemaVersion}
		return nil
	}
	if ack.SchemaVersion != SchemaVersion || (ack.Sequence == 0) != (ack.EventID == "") || (ack.Sequence > 0 && !idPattern.MatchString(ack.EventID)) {
		return ErrCorruptState
	}
	s.ack = ack
	return nil
}

func (s *Spool) loadAlertLocked() {
	var alert alertState
	if exists, err := readStateJSON(s.alertPath, &alert, s.device); err == nil && exists && alert.SchemaVersion == SchemaVersion {
		s.lastAlertCode = alert.Code
		s.expiredEvents = alert.ExpiredEvents
	}
}

func (s *Spool) recordAlertLocked(code string) {
	s.lastAlertCode = code
	_ = writeStateJSON(s.stateDir, s.alertPath, alertState{SchemaVersion: SchemaVersion, Code: code, ExpiredEvents: s.expiredEvents})
}

func (s *Spool) Ack(sequence uint64, eventID string) error {
	s.mu.Lock()
	defer s.mu.Unlock()
	unlock, err := s.lock(context.Background())
	if err != nil {
		return err
	}
	defer unlock()
	if err := s.loadAckLocked(); err != nil {
		return err
	}
	if sequence < s.ack.Sequence {
		return nil
	}
	if sequence == s.ack.Sequence {
		if eventID != s.ack.EventID {
			return ErrConflict
		}
		return nil
	}
	if sequence != s.ack.Sequence+1 {
		return ErrAckOrder
	}
	return s.ackThroughLocked(sequence, eventID)
}

func (s *Spool) ackThroughLocked(sequence uint64, eventID string) error {
	if err := s.rebuildLocked(false); err != nil {
		return err
	}
	if sequence <= s.ack.Sequence {
		if sequence == s.ack.Sequence && eventID != s.ack.EventID {
			return ErrConflict
		}
		return nil
	}
	index := sort.Search(len(s.pending), func(index int) bool { return s.pending[index].Sequence >= sequence })
	if index == len(s.pending) || s.pending[index].Sequence != sequence || s.pending[index].EventID != eventID || len(s.pending) == 0 || s.pending[0].Sequence != s.ack.Sequence+1 {
		return ErrAckOrder
	}
	ack := ackState{SchemaVersion: SchemaVersion, Sequence: sequence, EventID: eventID}
	if err := writeStateJSON(s.stateDir, s.ackPath, ack); err != nil {
		return err
	}
	s.ack = ack
	removed := false
	keptMetas := s.metas[:0]
	for _, meta := range s.metas {
		if meta.records > 0 && meta.max <= sequence {
			if err := os.Remove(meta.path); err != nil {
				return fmt.Errorf("remove acknowledged event segment: %w", err)
			}
			s.segmentBytes -= meta.size
			removed = true
			continue
		}
		keptMetas = append(keptMetas, meta)
	}
	s.metas = keptMetas
	if removed {
		if err := syncDirectory(s.segmentsDir); err != nil {
			return err
		}
	}
	pending := s.pending[:0]
	s.eventIDs = make(map[string]eventIdentity)
	s.tenantBytes = make(map[string]int64)
	for _, record := range s.pending {
		if record.Sequence <= sequence {
			continue
		}
		s.eventIDs[record.EventID] = eventIdentity{digest: record.digest, sequence: record.Sequence}
		s.tenantBytes[record.TenantID] += record.Size
		pending = append(pending, record)
	}
	s.pending = pending
	return nil
}

func (s *Spool) nextBatch(ctx context.Context, maximum int) ([]Record, error) {
	if maximum < 1 || maximum > s.config.MaxBatchEvents {
		return nil, ErrInvalidConfig
	}
	s.mu.Lock()
	defer s.mu.Unlock()
	unlock, err := s.lock(ctx)
	if err != nil {
		return nil, err
	}
	defer unlock()
	if err := s.loadAckLocked(); err != nil {
		return nil, err
	}
	if err := s.rebuildLocked(true); err != nil {
		return nil, err
	}
	if len(s.pending) < maximum {
		maximum = len(s.pending)
	}
	result := make([]Record, maximum)
	for index := range result {
		result[index] = s.pending[index]
		result[index].Payload = append([]byte(nil), s.pending[index].Payload...)
	}
	return result, nil
}

func (s *Spool) Flush(ctx context.Context, publisher Publisher, maximum int) (PublishResult, error) {
	if publisher == nil {
		return PublishResult{}, ErrInvalidConfig
	}
	unlockPublish, err := lockPrivateFile(ctx, s.publishPath, s.device)
	if err != nil {
		return PublishResult{}, err
	}
	defer unlockPublish()
	records, err := s.nextBatch(ctx, maximum)
	if err != nil || len(records) == 0 {
		return PublishResult{}, err
	}
	publications, err := buildPublications(records)
	if err != nil {
		return PublishResult{}, err
	}
	ack, publishErr := publisher.Publish(ctx, publications)
	if ack.Acknowledged < 0 || ack.Acknowledged > len(publications) || (publishErr == nil && ack.Acknowledged != len(publications)) {
		return PublishResult{}, ErrInvalidAck
	}
	if ack.Acknowledged == 0 {
		return PublishResult{}, publishErr
	}
	last := publications[ack.Acknowledged-1]
	publishedEvents := 0
	for _, publication := range publications[:ack.Acknowledged] {
		publishedEvents += publication.EventCount
	}
	s.mu.Lock()
	defer s.mu.Unlock()
	unlock, err := s.lock(ctx)
	if err != nil {
		return PublishResult{}, err
	}
	defer unlock()
	if err := s.loadAckLocked(); err != nil {
		return PublishResult{}, err
	}
	if err := s.ackThroughLocked(last.LastSequence, last.LastEventID); err != nil {
		return PublishResult{}, err
	}
	return PublishResult{
		Published: publishedEvents, PublishedMessages: ack.Acknowledged, LastSequence: last.LastSequence,
	}, publishErr
}

func (s *Spool) Drain(ctx context.Context, publisher Publisher, maximum int, retry RetryConfig) (PublishResult, error) {
	if publisher == nil || maximum < 1 || maximum > s.config.MaxBatchEvents || retry.InitialBackoff <= 0 ||
		retry.MaximumBackoff < retry.InitialBackoff || retry.MaximumAttempts < 1 {
		return PublishResult{}, ErrInvalidConfig
	}
	if retry.Sleep == nil {
		retry.Sleep = sleepContext
	}
	var total PublishResult
	backoff := retry.InitialBackoff
	consecutiveFailures := 0
	for {
		result, err := s.Flush(ctx, publisher, maximum)
		if err == nil && result.Published == 0 {
			return total, nil
		}
		total.Attempts++
		total.Published += result.Published
		total.PublishedMessages += result.PublishedMessages
		if result.LastSequence > total.LastSequence {
			total.LastSequence = result.LastSequence
		}
		if err == nil {
			consecutiveFailures = 0
			backoff = retry.InitialBackoff
			continue
		}
		consecutiveFailures++
		if consecutiveFailures >= retry.MaximumAttempts {
			return total, err
		}
		if sleepErr := retry.Sleep(ctx, backoff); sleepErr != nil {
			return total, sleepErr
		}
		if backoff < retry.MaximumBackoff {
			backoff *= 2
			if backoff > retry.MaximumBackoff {
				backoff = retry.MaximumBackoff
			}
		}
	}
}

func sleepContext(ctx context.Context, delay time.Duration) error {
	timer := time.NewTimer(delay)
	defer timer.Stop()
	select {
	case <-ctx.Done():
		return ctx.Err()
	case <-timer.C:
		return nil
	}
}

func (s *Spool) Stats() (Stats, error) {
	s.mu.Lock()
	defer s.mu.Unlock()
	unlock, err := s.lock(context.Background())
	if err != nil {
		return Stats{}, err
	}
	defer unlock()
	if err := s.loadAckLocked(); err != nil {
		return Stats{}, err
	}
	if err := s.rebuildLocked(true); err != nil {
		return Stats{}, err
	}
	tenantBytes := make(map[string]int64, len(s.tenantBytes))
	for tenant, value := range s.tenantBytes {
		tenantBytes[tenant] = value
	}
	oldest := s.oldestOccurredAtLocked()
	age := s.config.Now().UTC().Sub(oldest)
	if oldest.IsZero() || age < 0 {
		age = 0
	}
	pressure := "normal"
	if age >= s.config.HardAgeLimit {
		pressure = "hard"
	} else if age >= s.config.SoftAgeLimit {
		pressure = "soft"
	}
	return Stats{
		NextSequence: s.nextSequence, AckedSequence: s.ack.Sequence, PendingEvents: len(s.pending),
		SegmentBytes: s.segmentBytes, PeakBytes: s.peakBytes, TenantBytes: tenantBytes, LastAlertCode: s.lastAlertCode,
		OldestOccurredAt: oldest, OldestAgeSeconds: uint64(age / time.Second), AgePressure: pressure,
		ExpiredEvents: s.expiredEvents,
	}, nil
}

func (s *Spool) oldestOccurredAtLocked() time.Time {
	var oldest time.Time
	for _, record := range s.pending {
		if oldest.IsZero() || record.OccurredAt.Before(oldest) {
			oldest = record.OccurredAt
		}
	}
	return oldest
}

func readStateJSON(path string, target any, device uint64) (bool, error) {
	file, err := os.OpenFile(path, os.O_RDONLY|syscall.O_NOFOLLOW, 0)
	if errors.Is(err, os.ErrNotExist) {
		return false, nil
	}
	if err != nil {
		return false, ErrCorruptState
	}
	defer file.Close()
	info, statErr := file.Stat()
	stat, ok := infoSys(info)
	if statErr != nil || !ok || !info.Mode().IsRegular() || info.Mode().Perm() != 0o600 || stat.Nlink != 1 || uint64(stat.Dev) != device || info.Size() > 64<<10 {
		return false, ErrUnsafePath
	}
	decoder := json.NewDecoder(io.LimitReader(file, 64<<10))
	decoder.DisallowUnknownFields()
	if err := decoder.Decode(target); err != nil || decoder.Decode(&struct{}{}) != io.EOF {
		return false, ErrCorruptState
	}
	return true, nil
}

func writeStateJSON(directory, destination string, value any) error {
	encoded, err := json.Marshal(value)
	if err != nil {
		return ErrCorruptState
	}
	file, err := os.CreateTemp(directory, ".event-state-")
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
	if _, err := file.Write(append(encoded, '\n')); err != nil {
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
