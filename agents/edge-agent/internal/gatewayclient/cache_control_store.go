package gatewayclient

import (
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"os"
	"path/filepath"
	"sort"
	"sync"
	"syscall"
	"time"

	agentv1 "github.com/cdnca/cdnca/proto/gen/go/agent/v1"
	"google.golang.org/protobuf/proto"
)

const (
	cacheControlDurableRecordVersion = 2
	cacheControlCompletionVersion    = 1
	cacheControlCompletionSuffix     = ".completed"
	cacheControlCompletionRetention  = 24 * time.Hour
)

type cacheControlDurableRecord struct {
	Version       int      `json:"version"`
	RecordKey     string   `json:"record_key"`
	EventID       string   `json:"event_id"`
	TaskID        string   `json:"task_id"`
	LeaseID       string   `json:"lease_id"`
	Attempt       uint32   `json:"attempt"`
	CommandDigest string   `json:"command_digest"`
	Command       []byte   `json:"command"`
	ExecutionDone bool     `json:"execution_done"`
	AckedThrough  uint64   `json:"acked_through"`
	AckedEventID  string   `json:"acked_event_id,omitempty"`
	Statuses      [][]byte `json:"statuses"`
}

type cacheControlCompletion struct {
	Version            int       `json:"version"`
	RecordKey          string    `json:"record_key"`
	EventID            string    `json:"event_id"`
	TaskID             string    `json:"task_id"`
	LeaseID            string    `json:"lease_id"`
	Attempt            uint32    `json:"attempt"`
	CommandDigest      string    `json:"command_digest"`
	ExpiresAt          time.Time `json:"expires_at"`
	TerminalStatus     []byte    `json:"terminal_status"`
	TransitionSequence uint64    `json:"transition_sequence"`
	StatusEventID      string    `json:"status_event_id"`
}

type cacheControlDurableStore struct {
	mu              sync.Mutex
	directory       string
	maxCommandBytes int
	maxStatusBytes  int
	now             func() time.Time
}

func newCacheControlDurableStore(directory string, maxCommandBytes, maxStatusBytes int) (*cacheControlDurableStore, error) {
	if err := validateSecureDirectory(directory, true); err != nil {
		return nil, err
	}
	return &cacheControlDurableStore{
		directory: directory, maxCommandBytes: maxCommandBytes, maxStatusBytes: maxStatusBytes, now: time.Now,
	}, nil
}

func cacheControlRecordKey(taskID string) string {
	digest := sha256.Sum256([]byte(taskID))
	return hex.EncodeToString(digest[:])
}

func (s *cacheControlDurableStore) completedCommand(command *agentv1.CacheControlCommand) (*cacheControlDurableRecord, bool, error) {
	commandBytes, err := (proto.MarshalOptions{Deterministic: true}).Marshal(command)
	if err != nil || len(commandBytes) == 0 || len(commandBytes) > s.maxCommandBytes {
		return nil, false, fmt.Errorf("%w: cache command cannot be persisted", ErrInvalidMessage)
	}
	key := cacheControlRecordKey(command.GetTaskId())
	s.mu.Lock()
	defer s.mu.Unlock()
	if err := s.compactCompletionsLocked(s.now().UTC()); err != nil {
		return nil, false, err
	}
	completion, err := s.loadCompletionLocked(key)
	if err != nil || completion == nil {
		return nil, false, err
	}
	if completion.EventID != command.GetEvent().GetEventId() || completion.TaskID != command.GetTaskId() ||
		completion.LeaseID != command.GetLeaseId() || completion.Attempt != command.GetAttempt() ||
		completion.CommandDigest != commandDigest(commandBytes) {
		return nil, false, ErrCommandConflict
	}
	return cacheControlCompletionRecord(completion, commandBytes), true, nil
}

func (s *cacheControlDurableStore) putCommand(command *agentv1.CacheControlCommand, firstStatus *agentv1.CacheControlStatus) (*cacheControlDurableRecord, bool, error) {
	commandBytes, err := (proto.MarshalOptions{Deterministic: true}).Marshal(command)
	if err != nil || len(commandBytes) == 0 || len(commandBytes) > s.maxCommandBytes {
		return nil, false, fmt.Errorf("%w: cache command cannot be persisted", ErrInvalidMessage)
	}
	statusBytes, err := marshalCacheControlStatus(firstStatus, s.maxStatusBytes)
	if err != nil {
		return nil, false, err
	}
	key := cacheControlRecordKey(command.GetTaskId())
	s.mu.Lock()
	defer s.mu.Unlock()
	if err := s.compactCompletionsLocked(s.now().UTC()); err != nil {
		return nil, false, err
	}
	record, err := s.loadLocked(key)
	if err != nil {
		return nil, false, err
	}
	digest := commandDigest(commandBytes)
	if record != nil {
		if record.EventID != command.GetEvent().GetEventId() || record.TaskID != command.GetTaskId() ||
			record.LeaseID != command.GetLeaseId() || record.Attempt != command.GetAttempt() ||
			record.CommandDigest != digest || !proto.Equal(cacheControlCommandFromBytes(record.Command), command) {
			return nil, false, ErrCommandConflict
		}
		return cloneCacheControlRecord(record), false, nil
	}
	completion, err := s.loadCompletionLocked(key)
	if err != nil {
		return nil, false, err
	}
	if completion != nil {
		if completion.EventID != command.GetEvent().GetEventId() || completion.TaskID != command.GetTaskId() ||
			completion.LeaseID != command.GetLeaseId() || completion.Attempt != command.GetAttempt() ||
			completion.CommandDigest != digest {
			return nil, false, ErrCommandConflict
		}
		return cacheControlCompletionRecord(completion, commandBytes), false, nil
	}
	record = &cacheControlDurableRecord{
		Version: cacheControlDurableRecordVersion, RecordKey: key, EventID: command.GetEvent().GetEventId(),
		TaskID: command.GetTaskId(), LeaseID: command.GetLeaseId(), Attempt: command.GetAttempt(),
		CommandDigest: digest, Command: commandBytes, Statuses: [][]byte{statusBytes},
	}
	if err := s.saveLocked(record); err != nil {
		return nil, false, err
	}
	return cloneCacheControlRecord(record), true, nil
}

func (s *cacheControlDurableStore) appendStatuses(key string, statuses []*agentv1.CacheControlStatus, executionDone bool) error {
	s.mu.Lock()
	defer s.mu.Unlock()
	record, err := s.loadLocked(key)
	if err != nil {
		return err
	}
	if record == nil {
		return fmt.Errorf("durable cache control record is missing")
	}
	existing := make(map[string]struct{}, len(record.Statuses))
	lastSequence := record.AckedThrough
	for _, encoded := range record.Statuses {
		status := new(agentv1.CacheControlStatus)
		if proto.Unmarshal(encoded, status) == nil && status.Event != nil {
			existing[status.Event.EventId] = struct{}{}
			lastSequence = status.TransitionSequence
		}
	}
	for _, status := range statuses {
		if status == nil || status.Event == nil || !cacheControlStatusSequenceValid(status) {
			return fmt.Errorf("%w: invalid cache control status", ErrInvalidMessage)
		}
		if _, exists := existing[status.Event.EventId]; exists {
			continue
		}
		if status.TransitionSequence <= lastSequence {
			return fmt.Errorf("%w: cache control status sequence regressed", ErrInvalidMessage)
		}
		encoded, err := marshalCacheControlStatus(status, s.maxStatusBytes)
		if err != nil {
			return err
		}
		record.Statuses = append(record.Statuses, encoded)
		existing[status.Event.EventId] = struct{}{}
		lastSequence = status.TransitionSequence
	}
	if executionDone {
		record.ExecutionDone = true
	}
	return s.saveLocked(record)
}

func (s *cacheControlDurableStore) acknowledge(ack *agentv1.CacheControlStatusAck) error {
	if ack == nil || cacheControlMessageHasUnknown(ack.ProtoReflect()) || !canonicalUUID(ack.StatusEventId) ||
		!safeIdentifier(ack.TaskId) || !canonicalUUID(ack.LeaseId) || ack.Attempt == 0 || ack.TransitionSequence == 0 ||
		ack.PersistedTime == nil || ack.PersistedTime.CheckValid() != nil {
		return fmt.Errorf("%w: invalid cache control status acknowledgement", ErrInvalidMessage)
	}
	key := cacheControlRecordKey(ack.TaskId)
	s.mu.Lock()
	defer s.mu.Unlock()
	record, err := s.loadLocked(key)
	if err != nil {
		return err
	}
	if record == nil {
		completion, completionErr := s.loadCompletionLocked(key)
		if completionErr != nil {
			return completionErr
		}
		if completion != nil && completion.StatusEventID == ack.StatusEventId &&
			completion.TaskID == ack.TaskId && completion.LeaseID == ack.LeaseId && completion.Attempt == ack.Attempt &&
			completion.TransitionSequence == ack.TransitionSequence {
			return nil
		}
		return fmt.Errorf("%w: cache control acknowledgement has no durable record", ErrInvalidMessage)
	}
	if ack.TransitionSequence <= record.AckedThrough {
		if ack.TransitionSequence == record.AckedThrough && ack.StatusEventId == record.AckedEventID {
			return nil
		}
		return fmt.Errorf("%w: cache control acknowledgement regressed", ErrInvalidMessage)
	}
	matched := -1
	terminal := false
	for index, encoded := range record.Statuses {
		status := new(agentv1.CacheControlStatus)
		if proto.Unmarshal(encoded, status) != nil {
			return fmt.Errorf("cache control journal status is corrupt")
		}
		if status.TransitionSequence == ack.TransitionSequence && status.Event.GetEventId() == ack.StatusEventId {
			matched = index
			terminal = cacheControlTerminalState(status.State)
			break
		}
	}
	if matched < 0 {
		return fmt.Errorf("%w: cache control acknowledgement does not match an unacknowledged status", ErrInvalidMessage)
	}
	if terminal {
		if !record.ExecutionDone || matched != len(record.Statuses)-1 {
			return fmt.Errorf("%w: terminal cache control acknowledgement is incomplete", ErrInvalidMessage)
		}
		command := cacheControlCommandFromBytes(record.Command)
		if command == nil || command.DeadlineTime == nil || command.DeadlineTime.CheckValid() != nil {
			return fmt.Errorf("cache control journal command deadline is corrupt")
		}
		retainFrom := command.DeadlineTime.AsTime().UTC()
		if now := s.now().UTC(); now.After(retainFrom) {
			retainFrom = now
		}
		completion := &cacheControlCompletion{
			Version: cacheControlCompletionVersion, RecordKey: key, EventID: record.EventID,
			TaskID: record.TaskID, LeaseID: record.LeaseID, Attempt: record.Attempt, CommandDigest: record.CommandDigest,
			ExpiresAt: retainFrom.Add(cacheControlCompletionRetention), TerminalStatus: append([]byte(nil), record.Statuses[matched]...),
			TransitionSequence: ack.TransitionSequence, StatusEventID: ack.StatusEventId,
		}
		if err := s.saveCompletionLocked(completion); err != nil {
			return err
		}
		return s.deleteLocked(key)
	}
	record.Version = cacheControlDurableRecordVersion
	record.AckedThrough = ack.TransitionSequence
	record.AckedEventID = ack.StatusEventId
	record.Statuses = append([][]byte(nil), record.Statuses[matched+1:]...)
	return s.saveLocked(record)
}

func (s *cacheControlDurableStore) records() ([]*cacheControlDurableRecord, error) {
	s.mu.Lock()
	defer s.mu.Unlock()
	if err := s.compactCompletionsLocked(s.now().UTC()); err != nil {
		return nil, err
	}
	entries, err := os.ReadDir(s.directory)
	if err != nil {
		return nil, err
	}
	var records []*cacheControlDurableRecord
	for _, entry := range entries {
		if entry.IsDir() || filepath.Ext(entry.Name()) != ".json" {
			continue
		}
		key := entry.Name()[:len(entry.Name())-len(".json")]
		if len(key) != sha256.Size*2 {
			return nil, fmt.Errorf("unexpected cache control journal file")
		}
		record, err := s.loadLocked(key)
		if err != nil {
			return nil, err
		}
		records = append(records, cloneCacheControlRecord(record))
	}
	sort.Slice(records, func(i, j int) bool {
		if records[i].TaskID == records[j].TaskID {
			return records[i].Attempt < records[j].Attempt
		}
		return records[i].TaskID < records[j].TaskID
	})
	return records, nil
}

func (s *cacheControlDurableStore) loadCompletionLocked(key string) (*cacheControlCompletion, error) {
	file, err := os.OpenFile(filepath.Join(s.directory, key+cacheControlCompletionSuffix), os.O_RDONLY|syscall.O_NOFOLLOW, 0)
	if errors.Is(err, os.ErrNotExist) {
		return nil, nil
	}
	if err != nil {
		return nil, err
	}
	defer file.Close()
	info, err := file.Stat()
	if err != nil || !info.Mode().IsRegular() || info.Mode().Perm()&0o077 != 0 || info.Size() > int64(2*s.maxStatusBytes+4096) {
		return nil, fmt.Errorf("cache control completion file is invalid")
	}
	decoder := json.NewDecoder(io.LimitReader(file, info.Size()+1))
	decoder.DisallowUnknownFields()
	var completion cacheControlCompletion
	if err := decoder.Decode(&completion); err != nil || decoder.Decode(&struct{}{}) != io.EOF {
		return nil, fmt.Errorf("decode cache control completion")
	}
	if err := s.validateCompletion(&completion, key); err != nil {
		return nil, err
	}
	return &completion, nil
}

func (s *cacheControlDurableStore) validateCompletion(completion *cacheControlCompletion, key string) error {
	if completion == nil || completion.Version != cacheControlCompletionVersion || completion.RecordKey != key ||
		completion.RecordKey != cacheControlRecordKey(completion.TaskID) ||
		!canonicalUUID(completion.EventID) || !safeIdentifier(completion.TaskID) || !canonicalUUID(completion.LeaseID) ||
		completion.Attempt == 0 || len(completion.CommandDigest) != sha256.Size*2 || completion.ExpiresAt.IsZero() ||
		completion.TransitionSequence == 0 || !canonicalUUID(completion.StatusEventID) ||
		len(completion.TerminalStatus) == 0 || len(completion.TerminalStatus) > s.maxStatusBytes {
		return fmt.Errorf("cache control completion is corrupt")
	}
	if _, err := hex.DecodeString(completion.CommandDigest); err != nil {
		return fmt.Errorf("cache control completion digest is corrupt")
	}
	status := new(agentv1.CacheControlStatus)
	if proto.Unmarshal(completion.TerminalStatus, status) != nil || cacheControlMessageHasUnknown(status.ProtoReflect()) ||
		status.Event == nil || status.Event.EventId != completion.StatusEventID || status.TaskId != completion.TaskID ||
		status.LeaseId != completion.LeaseID || status.Attempt != completion.Attempt ||
		status.TransitionSequence != completion.TransitionSequence || !cacheControlTerminalState(status.State) ||
		!cacheControlStatusSequenceValid(status) {
		return fmt.Errorf("cache control completion status is corrupt")
	}
	return nil
}

func (s *cacheControlDurableStore) saveCompletionLocked(completion *cacheControlCompletion) error {
	if err := s.validateCompletion(completion, completion.RecordKey); err != nil {
		return err
	}
	current, err := s.loadCompletionLocked(completion.RecordKey)
	if err != nil {
		return err
	}
	if current != nil && (current.EventID != completion.EventID || current.CommandDigest != completion.CommandDigest ||
		current.StatusEventID != completion.StatusEventID || current.TransitionSequence != completion.TransitionSequence) {
		return ErrCommandConflict
	}
	encoded, err := json.Marshal(completion)
	if err != nil {
		return err
	}
	return s.writeLocked(".cache-control-completion-", completion.RecordKey+cacheControlCompletionSuffix, encoded)
}

func (s *cacheControlDurableStore) compactCompletionsLocked(now time.Time) error {
	entries, err := os.ReadDir(s.directory)
	if err != nil {
		return err
	}
	removed := false
	for _, entry := range entries {
		if entry.IsDir() || filepath.Ext(entry.Name()) != cacheControlCompletionSuffix {
			continue
		}
		key := entry.Name()[:len(entry.Name())-len(cacheControlCompletionSuffix)]
		if len(key) != sha256.Size*2 {
			return fmt.Errorf("unexpected cache control completion file")
		}
		completion, err := s.loadCompletionLocked(key)
		if err != nil {
			return err
		}
		if completion != nil && !now.Before(completion.ExpiresAt) {
			if err := os.Remove(filepath.Join(s.directory, entry.Name())); err != nil {
				return err
			}
			removed = true
		}
	}
	if removed {
		return s.syncDirectoryLocked()
	}
	return nil
}

func cacheControlCompletionRecord(completion *cacheControlCompletion, command []byte) *cacheControlDurableRecord {
	return &cacheControlDurableRecord{
		Version: cacheControlDurableRecordVersion, RecordKey: completion.RecordKey, EventID: completion.EventID,
		TaskID: completion.TaskID, LeaseID: completion.LeaseID, Attempt: completion.Attempt,
		CommandDigest: completion.CommandDigest, Command: append([]byte(nil), command...), ExecutionDone: true,
		AckedThrough: completion.TransitionSequence, AckedEventID: completion.StatusEventID,
		Statuses: [][]byte{append([]byte(nil), completion.TerminalStatus...)},
	}
}

// recordOrCompletion is the journal record of a task, or its compacted
// completion (terminal status only, no command) once the Gateway
// acknowledged the terminal status; nil when the node never held the task.
func (s *cacheControlDurableStore) recordOrCompletion(key string) (*cacheControlDurableRecord, error) {
	s.mu.Lock()
	defer s.mu.Unlock()
	record, err := s.loadLocked(key)
	if err != nil || record != nil {
		return cloneCacheControlRecord(record), err
	}
	completion, err := s.loadCompletionLocked(key)
	if err != nil || completion == nil {
		return nil, err
	}
	return cacheControlCompletionRecord(completion, nil), nil
}

func (s *cacheControlDurableStore) record(key string) (*cacheControlDurableRecord, error) {
	s.mu.Lock()
	defer s.mu.Unlock()
	record, err := s.loadLocked(key)
	return cloneCacheControlRecord(record), err
}

func (s *cacheControlDurableStore) loadLocked(key string) (*cacheControlDurableRecord, error) {
	file, err := os.OpenFile(filepath.Join(s.directory, key+".json"), os.O_RDONLY|syscall.O_NOFOLLOW, 0)
	if errors.Is(err, os.ErrNotExist) {
		return nil, nil
	}
	if err != nil {
		return nil, err
	}
	defer file.Close()
	info, err := file.Stat()
	if err != nil || !info.Mode().IsRegular() || info.Mode().Perm()&0o077 != 0 || info.Size() > int64(2*s.maxCommandBytes+8*s.maxStatusBytes) {
		return nil, fmt.Errorf("cache control journal file is invalid")
	}
	decoder := json.NewDecoder(io.LimitReader(file, info.Size()+1))
	decoder.DisallowUnknownFields()
	var record cacheControlDurableRecord
	if err := decoder.Decode(&record); err != nil || decoder.Decode(&struct{}{}) != io.EOF {
		return nil, fmt.Errorf("decode cache control journal")
	}
	if record.Version == 1 {
		record.Version = cacheControlDurableRecordVersion
	}
	if err := s.validateRecord(&record, key); err != nil {
		return nil, err
	}
	return &record, nil
}

func (s *cacheControlDurableStore) validateRecord(record *cacheControlDurableRecord, key string) error {
	if record == nil || record.Version != cacheControlDurableRecordVersion || record.RecordKey != key ||
		record.RecordKey != cacheControlRecordKey(record.TaskID) || record.EventID == "" ||
		len(record.Command) == 0 || len(record.Command) > s.maxCommandBytes || record.CommandDigest != commandDigest(record.Command) ||
		record.AckedThrough > 2 || record.AckedThrough == 0 && record.AckedEventID != "" || record.AckedThrough > 0 && !canonicalUUID(record.AckedEventID) ||
		len(record.Statuses) == 0 && record.AckedThrough == 0 {
		return fmt.Errorf("cache control journal record is corrupt")
	}
	command := cacheControlCommandFromBytes(record.Command)
	if command == nil || command.Event == nil || command.Event.EventId != record.EventID || command.TaskId != record.TaskID ||
		command.LeaseId != record.LeaseID || command.Attempt != record.Attempt {
		return fmt.Errorf("cache control journal command is corrupt")
	}
	lastSequence := record.AckedThrough
	for index, encoded := range record.Statuses {
		status := new(agentv1.CacheControlStatus)
		if len(encoded) == 0 || len(encoded) > s.maxStatusBytes || proto.Unmarshal(encoded, status) != nil || status.Event == nil ||
			cacheControlMessageHasUnknown(status.ProtoReflect()) ||
			status.TaskId != record.TaskID || status.LeaseId != record.LeaseID || status.Attempt != record.Attempt ||
			status.TransitionSequence <= lastSequence || !cacheControlStatusSequenceValid(status) {
			return fmt.Errorf("cache control journal status is corrupt")
		}
		if index == 0 && record.AckedThrough == 0 && (status.State != agentv1.CacheControlState_CACHE_CONTROL_STATE_DELIVERED || status.TransitionSequence != 1) {
			return fmt.Errorf("cache control journal initial status is corrupt")
		}
		lastSequence = status.TransitionSequence
	}
	terminal := false
	if len(record.Statuses) > 0 {
		last := new(agentv1.CacheControlStatus)
		_ = proto.Unmarshal(record.Statuses[len(record.Statuses)-1], last)
		terminal = cacheControlTerminalState(last.State)
	}
	if record.ExecutionDone != terminal {
		return fmt.Errorf("cache control journal terminal state is corrupt")
	}
	return nil
}

func (s *cacheControlDurableStore) deleteLocked(key string) error {
	if err := os.Remove(filepath.Join(s.directory, key+".json")); err != nil {
		return err
	}
	return s.syncDirectoryLocked()
}

func (s *cacheControlDurableStore) syncDirectoryLocked() error {
	directory, err := os.Open(s.directory)
	if err != nil {
		return err
	}
	defer directory.Close()
	return directory.Sync()
}

func (s *cacheControlDurableStore) saveLocked(record *cacheControlDurableRecord) error {
	if err := s.validateRecord(record, record.RecordKey); err != nil {
		return err
	}
	encoded, err := json.Marshal(record)
	if err != nil {
		return err
	}
	return s.writeLocked(".cache-control-record-", record.RecordKey+".json", encoded)
}

func (s *cacheControlDurableStore) writeLocked(prefix, name string, encoded []byte) error {
	temporary, err := os.CreateTemp(s.directory, prefix)
	if err != nil {
		return err
	}
	temporaryPath := temporary.Name()
	defer os.Remove(temporaryPath)
	if err := temporary.Chmod(0o600); err != nil {
		_ = temporary.Close()
		return err
	}
	if _, err := temporary.Write(encoded); err != nil {
		_ = temporary.Close()
		return err
	}
	if err := temporary.Sync(); err != nil {
		_ = temporary.Close()
		return err
	}
	if err := temporary.Close(); err != nil {
		return err
	}
	if err := os.Rename(temporaryPath, filepath.Join(s.directory, name)); err != nil {
		return err
	}
	return s.syncDirectoryLocked()
}

func marshalCacheControlStatus(status *agentv1.CacheControlStatus, limit int) ([]byte, error) {
	encoded, err := (proto.MarshalOptions{Deterministic: true}).Marshal(status)
	if err != nil || len(encoded) == 0 || len(encoded) > limit {
		return nil, fmt.Errorf("%w: cache control status cannot be persisted", ErrInvalidMessage)
	}
	return encoded, nil
}

func cacheControlCommandFromBytes(encoded []byte) *agentv1.CacheControlCommand {
	command := new(agentv1.CacheControlCommand)
	if proto.Unmarshal(encoded, command) != nil || cacheControlMessageHasUnknown(command.ProtoReflect()) {
		return nil
	}
	return command
}

func cacheControlStatusesFromRecord(record *cacheControlDurableRecord) ([]*agentv1.CacheControlStatus, error) {
	statuses := make([]*agentv1.CacheControlStatus, 0, len(record.Statuses))
	for _, encoded := range record.Statuses {
		status := new(agentv1.CacheControlStatus)
		if err := proto.Unmarshal(encoded, status); err != nil {
			return nil, err
		}
		if cacheControlMessageHasUnknown(status.ProtoReflect()) {
			return nil, fmt.Errorf("%w: cache control status contains unknown fields", ErrInvalidMessage)
		}
		statuses = append(statuses, status)
	}
	return statuses, nil
}

func cloneCacheControlRecord(record *cacheControlDurableRecord) *cacheControlDurableRecord {
	if record == nil {
		return nil
	}
	copyRecord := *record
	copyRecord.Command = append([]byte(nil), record.Command...)
	copyRecord.Statuses = make([][]byte, len(record.Statuses))
	for index := range record.Statuses {
		copyRecord.Statuses[index] = append([]byte(nil), record.Statuses[index]...)
	}
	return &copyRecord
}

func cacheControlTerminalState(state agentv1.CacheControlState) bool {
	return state == agentv1.CacheControlState_CACHE_CONTROL_STATE_SUCCEEDED ||
		state == agentv1.CacheControlState_CACHE_CONTROL_STATE_PARTIAL_FAILED ||
		state == agentv1.CacheControlState_CACHE_CONTROL_STATE_FAILED ||
		state == agentv1.CacheControlState_CACHE_CONTROL_STATE_CANCELLED
}

func cacheControlStatusSequenceValid(status *agentv1.CacheControlStatus) bool {
	if status == nil {
		return false
	}
	switch status.State {
	case agentv1.CacheControlState_CACHE_CONTROL_STATE_DELIVERED:
		return status.TransitionSequence == 1
	case agentv1.CacheControlState_CACHE_CONTROL_STATE_RUNNING:
		return status.TransitionSequence == 2
	case agentv1.CacheControlState_CACHE_CONTROL_STATE_SUCCEEDED,
		agentv1.CacheControlState_CACHE_CONTROL_STATE_PARTIAL_FAILED,
		agentv1.CacheControlState_CACHE_CONTROL_STATE_FAILED,
		agentv1.CacheControlState_CACHE_CONTROL_STATE_CANCELLED:
		return status.TransitionSequence == 3
	default:
		return false
	}
}
