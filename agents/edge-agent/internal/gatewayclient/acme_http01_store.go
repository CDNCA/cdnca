package gatewayclient

import (
	"crypto/sha256"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"os"
	"path/filepath"
	"sort"
	"sync"
	"syscall"

	agentv1 "github.com/cdnca/cdnca/proto/gen/go/agent/v1"
	"google.golang.org/protobuf/proto"
)

const overlayDurableRecordVersion = 1

type overlayDurableRecord struct {
	Version          int      `json:"version"`
	RecordKey        string   `json:"record_key"`
	EventID          string   `json:"event_id"`
	DeploymentID     string   `json:"overlay_deployment_id"`
	Attempt          uint32   `json:"attempt"`
	OverlayVersionID string   `json:"overlay_version_id"`
	OverlayRevision  uint64   `json:"overlay_revision"`
	CommandDigest    string   `json:"command_digest"`
	Command          []byte   `json:"command"`
	ArtifactOffset   uint64   `json:"artifact_offset"`
	ExecutionDone    bool     `json:"execution_done"`
	Statuses         [][]byte `json:"statuses"`
}

type overlayDurableStore struct {
	mu              sync.Mutex
	directory       string
	artifacts       string
	maxCommandBytes int
	maxStatusBytes  int
}

func newOverlayDurableStore(directory string, maxCommandBytes, maxStatusBytes int) (*overlayDurableStore, error) {
	if err := validateSecureDirectory(directory, true); err != nil {
		return nil, err
	}
	artifacts := filepath.Join(directory, "artifacts")
	if err := validateSecureDirectory(artifacts, true); err != nil {
		return nil, err
	}
	return &overlayDurableStore{directory: directory, artifacts: artifacts, maxCommandBytes: maxCommandBytes, maxStatusBytes: maxStatusBytes}, nil
}

func (s *overlayDurableStore) putCommand(command *agentv1.AcmeHTTP01OverlayCommand, firstStatus *agentv1.AcmeHTTP01OverlayStatus) (*overlayDurableRecord, bool, error) {
	commandBytes, err := (proto.MarshalOptions{Deterministic: true}).Marshal(command)
	if err != nil || len(commandBytes) == 0 || len(commandBytes) > s.maxCommandBytes {
		return nil, false, fmt.Errorf("%w: overlay command cannot be persisted", ErrInvalidMessage)
	}
	statusBytes, err := marshalOverlayStatus(firstStatus, s.maxStatusBytes)
	if err != nil {
		return nil, false, err
	}
	key := recordKey(command.OverlayDeploymentId, command.Attempt)
	s.mu.Lock()
	defer s.mu.Unlock()
	record, err := s.loadLocked(key)
	if err != nil {
		return nil, false, err
	}
	digest := commandDigest(commandBytes)
	if record != nil {
		if record.EventID != command.Event.EventId || record.DeploymentID != command.OverlayDeploymentId ||
			record.Attempt != command.Attempt || record.OverlayVersionID != command.OverlayVersionId ||
			record.OverlayRevision != command.OverlayRevision || record.CommandDigest != digest ||
			!proto.Equal(overlayCommandFromBytes(record.Command), command) {
			return nil, false, ErrCommandConflict
		}
		return cloneOverlayRecord(record), false, nil
	}
	record = &overlayDurableRecord{
		Version: overlayDurableRecordVersion, RecordKey: key, EventID: command.Event.EventId,
		DeploymentID: command.OverlayDeploymentId, Attempt: command.Attempt,
		OverlayVersionID: command.OverlayVersionId, OverlayRevision: command.OverlayRevision,
		CommandDigest: digest, Command: commandBytes, Statuses: [][]byte{statusBytes},
	}
	if err := s.saveLocked(record); err != nil {
		return nil, false, err
	}
	return cloneOverlayRecord(record), true, nil
}

func (s *overlayDurableStore) appendStatuses(key string, statuses []*agentv1.AcmeHTTP01OverlayStatus, executionDone bool) error {
	s.mu.Lock()
	defer s.mu.Unlock()
	record, err := s.loadLocked(key)
	if err != nil {
		return err
	}
	if record == nil {
		return fmt.Errorf("durable overlay record is missing")
	}
	existing := make(map[string]struct{}, len(record.Statuses))
	for _, encoded := range record.Statuses {
		status := new(agentv1.AcmeHTTP01OverlayStatus)
		if proto.Unmarshal(encoded, status) == nil && status.Event != nil {
			existing[status.Event.EventId] = struct{}{}
		}
	}
	for _, status := range statuses {
		if status == nil || status.Event == nil {
			return fmt.Errorf("%w: invalid overlay status", ErrInvalidMessage)
		}
		if _, exists := existing[status.Event.EventId]; exists {
			continue
		}
		encoded, err := marshalOverlayStatus(status, s.maxStatusBytes)
		if err != nil {
			return err
		}
		record.Statuses = append(record.Statuses, encoded)
		existing[status.Event.EventId] = struct{}{}
	}
	if executionDone {
		record.ExecutionDone = true
	}
	return s.saveLocked(record)
}

func (s *overlayDurableStore) setArtifactOffset(key string, offset uint64) error {
	s.mu.Lock()
	defer s.mu.Unlock()
	record, err := s.loadLocked(key)
	if err != nil {
		return err
	}
	if record == nil || offset < record.ArtifactOffset {
		return fmt.Errorf("invalid overlay artifact offset transition")
	}
	record.ArtifactOffset = offset
	return s.saveLocked(record)
}

func (s *overlayDurableStore) records() ([]*overlayDurableRecord, error) {
	s.mu.Lock()
	defer s.mu.Unlock()
	entries, err := os.ReadDir(s.directory)
	if err != nil {
		return nil, err
	}
	var records []*overlayDurableRecord
	for _, entry := range entries {
		if entry.IsDir() || filepath.Ext(entry.Name()) != ".json" {
			continue
		}
		key := entry.Name()[:len(entry.Name())-len(".json")]
		if len(key) != sha256.Size*2 {
			return nil, fmt.Errorf("unexpected overlay journal file")
		}
		record, err := s.loadLocked(key)
		if err != nil {
			return nil, err
		}
		records = append(records, cloneOverlayRecord(record))
	}
	sort.Slice(records, func(i, j int) bool {
		if records[i].DeploymentID == records[j].DeploymentID {
			return records[i].Attempt < records[j].Attempt
		}
		return records[i].DeploymentID < records[j].DeploymentID
	})
	return records, nil
}

func (s *overlayDurableStore) record(key string) (*overlayDurableRecord, error) {
	s.mu.Lock()
	defer s.mu.Unlock()
	record, err := s.loadLocked(key)
	return cloneOverlayRecord(record), err
}

func (s *overlayDurableStore) artifactPath(key string) string {
	return filepath.Join(s.artifacts, key+".part")
}

func (s *overlayDurableStore) openArtifact(key string, offset uint64) (*os.File, error) {
	file, err := os.OpenFile(s.artifactPath(key), os.O_CREATE|os.O_RDWR|syscall.O_NOFOLLOW, 0o600)
	if err != nil {
		return nil, err
	}
	info, err := file.Stat()
	if err != nil || !info.Mode().IsRegular() || info.Mode().Perm()&0o077 != 0 || uint64(info.Size()) < offset {
		_ = file.Close()
		return nil, fmt.Errorf("overlay artifact part is invalid")
	}
	if err := file.Truncate(int64(offset)); err != nil {
		_ = file.Close()
		return nil, err
	}
	if _, err := file.Seek(int64(offset), io.SeekStart); err != nil {
		_ = file.Close()
		return nil, err
	}
	return file, nil
}

func (s *overlayDurableStore) readArtifact(key string, expectedSize uint64) ([]byte, error) {
	file, err := os.OpenFile(s.artifactPath(key), os.O_RDONLY|syscall.O_NOFOLLOW, 0)
	if err != nil {
		return nil, err
	}
	defer file.Close()
	info, err := file.Stat()
	if err != nil || !info.Mode().IsRegular() || info.Mode().Perm()&0o077 != 0 || info.Size() < 0 || uint64(info.Size()) != expectedSize {
		return nil, fmt.Errorf("completed overlay artifact is invalid")
	}
	content, err := io.ReadAll(io.LimitReader(file, int64(expectedSize)+1))
	if err != nil || uint64(len(content)) != expectedSize {
		return nil, fmt.Errorf("read completed overlay artifact")
	}
	return content, nil
}

func (s *overlayDurableStore) loadLocked(key string) (*overlayDurableRecord, error) {
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
		return nil, fmt.Errorf("overlay journal file is invalid")
	}
	decoder := json.NewDecoder(io.LimitReader(file, info.Size()+1))
	decoder.DisallowUnknownFields()
	var record overlayDurableRecord
	if err := decoder.Decode(&record); err != nil || decoder.Decode(&struct{}{}) != io.EOF {
		return nil, fmt.Errorf("decode overlay journal")
	}
	if err := s.validateRecord(&record, key); err != nil {
		return nil, err
	}
	return &record, nil
}

func (s *overlayDurableStore) validateRecord(record *overlayDurableRecord, key string) error {
	if record == nil || record.Version != overlayDurableRecordVersion || record.RecordKey != key ||
		record.RecordKey != recordKey(record.DeploymentID, record.Attempt) || record.EventID == "" ||
		record.OverlayVersionID == "" || record.OverlayRevision == 0 || len(record.Command) == 0 ||
		len(record.Command) > s.maxCommandBytes || record.CommandDigest != commandDigest(record.Command) || len(record.Statuses) == 0 {
		return fmt.Errorf("overlay journal record is corrupt")
	}
	command := overlayCommandFromBytes(record.Command)
	if command == nil || command.Event == nil || command.Event.EventId != record.EventID ||
		command.OverlayDeploymentId != record.DeploymentID || command.Attempt != record.Attempt ||
		command.OverlayVersionId != record.OverlayVersionID || command.OverlayRevision != record.OverlayRevision {
		return fmt.Errorf("overlay journal command is corrupt")
	}
	for _, encoded := range record.Statuses {
		status := new(agentv1.AcmeHTTP01OverlayStatus)
		if len(encoded) == 0 || len(encoded) > s.maxStatusBytes || proto.Unmarshal(encoded, status) != nil || status.Event == nil ||
			status.OverlayDeploymentId != record.DeploymentID || status.Attempt != record.Attempt ||
			status.OverlayVersionId != record.OverlayVersionID || status.OverlayRevision != record.OverlayRevision {
			return fmt.Errorf("overlay journal status is corrupt")
		}
	}
	return nil
}

func (s *overlayDurableStore) saveLocked(record *overlayDurableRecord) error {
	if err := s.validateRecord(record, record.RecordKey); err != nil {
		return err
	}
	encoded, err := json.Marshal(record)
	if err != nil {
		return err
	}
	temporary, err := os.CreateTemp(s.directory, ".overlay-record-")
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
	if err := os.Rename(temporaryPath, filepath.Join(s.directory, record.RecordKey+".json")); err != nil {
		return err
	}
	directory, err := os.Open(s.directory)
	if err != nil {
		return err
	}
	defer directory.Close()
	return directory.Sync()
}

func marshalOverlayStatus(status *agentv1.AcmeHTTP01OverlayStatus, limit int) ([]byte, error) {
	encoded, err := (proto.MarshalOptions{Deterministic: true}).Marshal(status)
	if err != nil || len(encoded) == 0 || len(encoded) > limit {
		return nil, fmt.Errorf("%w: overlay status cannot be persisted", ErrInvalidMessage)
	}
	return encoded, nil
}

func overlayCommandFromBytes(encoded []byte) *agentv1.AcmeHTTP01OverlayCommand {
	command := new(agentv1.AcmeHTTP01OverlayCommand)
	if proto.Unmarshal(encoded, command) != nil {
		return nil
	}
	return command
}

func overlayStatusesFromRecord(record *overlayDurableRecord) ([]*agentv1.AcmeHTTP01OverlayStatus, error) {
	statuses := make([]*agentv1.AcmeHTTP01OverlayStatus, 0, len(record.Statuses))
	for _, encoded := range record.Statuses {
		status := new(agentv1.AcmeHTTP01OverlayStatus)
		if err := proto.Unmarshal(encoded, status); err != nil {
			return nil, err
		}
		statuses = append(statuses, status)
	}
	return statuses, nil
}

func cloneOverlayRecord(record *overlayDurableRecord) *overlayDurableRecord {
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
