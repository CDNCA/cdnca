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

	agentv1 "github.com/cdnca/cdnca/proto/gen/go/agent/v1"
	"google.golang.org/protobuf/proto"
)

const durableRecordVersion = 1

type durableRecord struct {
	Version         int      `json:"version"`
	RecordKey       string   `json:"record_key"`
	EventID         string   `json:"event_id"`
	DeploymentID    string   `json:"deployment_id"`
	Attempt         uint32   `json:"attempt"`
	ConfigVersionID string   `json:"config_version_id"`
	CommandDigest   string   `json:"command_digest"`
	Command         []byte   `json:"command"`
	ArtifactOffset  uint64   `json:"artifact_offset"`
	ExecutionDone   bool     `json:"execution_done"`
	Statuses        [][]byte `json:"statuses"`
}

type durableStore struct {
	mu              sync.Mutex
	directory       string
	artifacts       string
	maxCommandBytes int
	maxStatusBytes  int
}

func newDurableStore(directory string, maxCommandBytes, maxStatusBytes int) (*durableStore, error) {
	if err := validateSecureDirectory(directory, true); err != nil {
		return nil, err
	}
	artifacts := filepath.Join(directory, "artifacts")
	if err := validateSecureDirectory(artifacts, true); err != nil {
		return nil, err
	}
	return &durableStore{directory: directory, artifacts: artifacts, maxCommandBytes: maxCommandBytes, maxStatusBytes: maxStatusBytes}, nil
}

func recordKey(deploymentID string, attempt uint32) string {
	sum := sha256.Sum256([]byte(fmt.Sprintf("%s\x00%d", deploymentID, attempt)))
	return hex.EncodeToString(sum[:])
}

func commandDigest(commandBytes []byte) string {
	sum := sha256.Sum256(commandBytes)
	return hex.EncodeToString(sum[:])
}

func (s *durableStore) putCommand(command *agentv1.DeploymentCommand, firstStatus *agentv1.DeploymentStatus) (*durableRecord, bool, error) {
	commandBytes, err := (proto.MarshalOptions{Deterministic: true}).Marshal(command)
	if err != nil || len(commandBytes) == 0 || len(commandBytes) > s.maxCommandBytes {
		return nil, false, fmt.Errorf("%w: command cannot be persisted", ErrInvalidMessage)
	}
	statusBytes, err := marshalStatus(firstStatus, s.maxStatusBytes)
	if err != nil {
		return nil, false, err
	}
	key := recordKey(command.DeploymentId, command.Attempt)
	s.mu.Lock()
	defer s.mu.Unlock()
	record, err := s.loadLocked(key)
	if err != nil {
		return nil, false, err
	}
	digest := commandDigest(commandBytes)
	if record != nil {
		if record.EventID != command.Event.EventId || record.DeploymentID != command.DeploymentId || record.Attempt != command.Attempt || record.ConfigVersionID != command.ConfigVersionId || record.CommandDigest != digest || !proto.Equal(commandFromBytes(record.Command), command) {
			return nil, false, ErrCommandConflict
		}
		return cloneRecord(record), false, nil
	}
	record = &durableRecord{
		Version:         durableRecordVersion,
		RecordKey:       key,
		EventID:         command.Event.EventId,
		DeploymentID:    command.DeploymentId,
		Attempt:         command.Attempt,
		ConfigVersionID: command.ConfigVersionId,
		CommandDigest:   digest,
		Command:         commandBytes,
		Statuses:        [][]byte{statusBytes},
	}
	if err := s.saveLocked(record); err != nil {
		return nil, false, err
	}
	return cloneRecord(record), true, nil
}

func (s *durableStore) appendStatuses(key string, statuses []*agentv1.DeploymentStatus, executionDone bool) error {
	s.mu.Lock()
	defer s.mu.Unlock()
	record, err := s.loadLocked(key)
	if err != nil {
		return err
	}
	if record == nil {
		return fmt.Errorf("durable deployment record is missing")
	}
	existing := make(map[string]struct{}, len(record.Statuses))
	scoped := false
	for _, encoded := range record.Statuses {
		status := new(agentv1.DeploymentStatus)
		if proto.Unmarshal(encoded, status) == nil && status.Event != nil {
			existing[status.Event.EventId] = struct{}{}
			scoped = scoped || status.State == agentv1.NodeDeploymentState_NODE_DEPLOYMENT_STATE_AGENT_QUEUED
		}
	}
	command := commandFromBytes(record.Command)
	if scoped && command != nil {
		// A record queued on a multi-tenant session reports every later
		// journal transition after AGENT_QUEUED and STARTED, bound to its scope.
		rewritten := make([]*agentv1.DeploymentStatus, len(statuses))
		for index, status := range statuses {
			rewritten[index] = status
			if status != nil && status.Event != nil && status.ConfigurationScopeId == nil {
				rewritten[index] = scopeExecutionStatuses(command, []*agentv1.DeploymentStatus{status})[0]
			}
		}
		statuses = rewritten
	}
	for _, status := range statuses {
		if status == nil || status.Event == nil {
			return fmt.Errorf("%w: invalid deployment status", ErrInvalidMessage)
		}
		if _, exists := existing[status.Event.EventId]; exists {
			continue
		}
		encoded, err := marshalStatus(status, s.maxStatusBytes)
		if err != nil {
			return err
		}
		record.Statuses = append(record.Statuses, encoded)
		existing[status.Event.EventId] = struct{}{}
	}
	if executionDone {
		record.ExecutionDone = true
	}
	if err := s.saveLocked(record); err != nil {
		return err
	}
	// A node-side artifact (segment/set) travels in the platform scope, which a
	// node never claims as a configuration scope: it has no apply result.
	if scoped && executionDone && command != nil && command.ConfigurationScopeId != nil && len(record.Statuses) > 0 &&
		!isArtifactSetCommand(command) {
		final := new(agentv1.DeploymentStatus)
		if proto.Unmarshal(record.Statuses[len(record.Statuses)-1], final) == nil {
			if result, terminal := scopeApplyResultFor(final); terminal {
				return s.saveScopeApplyResultLocked(command.GetConfigurationScopeId(), result)
			}
		}
	}
	return nil
}

func (s *durableStore) setArtifactOffset(key string, offset uint64) error {
	s.mu.Lock()
	defer s.mu.Unlock()
	record, err := s.loadLocked(key)
	if err != nil {
		return err
	}
	if record == nil || offset < record.ArtifactOffset {
		return fmt.Errorf("invalid artifact offset transition")
	}
	record.ArtifactOffset = offset
	return s.saveLocked(record)
}

// journalSiblingStateFile names daemon state the Agent keeps in the journal root next to
// the deployment records: learned gateway endpoints (cmd/edge-agent daemon.go,
// endpoint_failover.go). Every other non-record .json there stays an error.
const learnedGatewayEndpointsFile = "gateway-endpoints.json"

func journalSiblingStateFile(name string) bool {
	return name == learnedGatewayEndpointsFile
}

func (s *durableStore) records() ([]*durableRecord, error) {
	s.mu.Lock()
	defer s.mu.Unlock()
	entries, err := os.ReadDir(s.directory)
	if err != nil {
		return nil, err
	}
	var records []*durableRecord
	for _, entry := range entries {
		if entry.IsDir() || filepath.Ext(entry.Name()) != ".json" {
			continue
		}
		if journalSiblingStateFile(entry.Name()) {
			continue
		}
		key := entry.Name()[:len(entry.Name())-len(".json")]
		if len(key) != sha256.Size*2 {
			return nil, fmt.Errorf("unexpected gateway journal file")
		}
		record, err := s.loadLocked(key)
		if err != nil {
			return nil, err
		}
		records = append(records, cloneRecord(record))
	}
	sort.Slice(records, func(i, j int) bool {
		if records[i].DeploymentID == records[j].DeploymentID {
			return records[i].Attempt < records[j].Attempt
		}
		return records[i].DeploymentID < records[j].DeploymentID
	})
	return records, nil
}

func (s *durableStore) record(key string) (*durableRecord, error) {
	s.mu.Lock()
	defer s.mu.Unlock()
	record, err := s.loadLocked(key)
	return cloneRecord(record), err
}

func (s *durableStore) artifactPath(key string) string {
	return filepath.Join(s.artifacts, key+".part")
}

func (s *durableStore) readArtifact(key string, expectedSize uint64) ([]byte, error) {
	file, err := os.OpenFile(s.artifactPath(key), os.O_RDONLY|syscall.O_NOFOLLOW, 0)
	if err != nil {
		return nil, fmt.Errorf("open completed artifact: %w", err)
	}
	defer file.Close()
	info, err := file.Stat()
	if err != nil || !info.Mode().IsRegular() || info.Mode().Perm()&0o077 != 0 || info.Size() < 0 || uint64(info.Size()) != expectedSize {
		return nil, fmt.Errorf("completed artifact file is invalid")
	}
	content, err := io.ReadAll(io.LimitReader(file, int64(expectedSize)+1))
	if err != nil || uint64(len(content)) != expectedSize {
		return nil, fmt.Errorf("read completed artifact")
	}
	return content, nil
}

func (s *durableStore) openArtifact(key string, offset uint64) (*os.File, error) {
	path := s.artifactPath(key)
	file, err := os.OpenFile(path, os.O_CREATE|os.O_RDWR|syscall.O_NOFOLLOW, 0o600)
	if err != nil {
		return nil, fmt.Errorf("open artifact part: %w", err)
	}
	info, err := file.Stat()
	if err != nil || !info.Mode().IsRegular() || info.Mode().Perm()&0o077 != 0 {
		file.Close()
		return nil, fmt.Errorf("artifact part is not an owner-only regular file")
	}
	if uint64(info.Size()) < offset {
		file.Close()
		return nil, fmt.Errorf("artifact part is shorter than its verified offset")
	}
	if err := file.Truncate(int64(offset)); err != nil {
		file.Close()
		return nil, fmt.Errorf("truncate artifact part: %w", err)
	}
	if _, err := file.Seek(int64(offset), io.SeekStart); err != nil {
		file.Close()
		return nil, fmt.Errorf("seek artifact part: %w", err)
	}
	return file, nil
}

func (s *durableStore) loadLocked(key string) (*durableRecord, error) {
	path := filepath.Join(s.directory, key+".json")
	file, err := os.OpenFile(path, os.O_RDONLY|syscall.O_NOFOLLOW, 0)
	if errors.Is(err, os.ErrNotExist) {
		return nil, nil
	}
	if err != nil {
		return nil, fmt.Errorf("open gateway journal: %w", err)
	}
	defer file.Close()
	info, err := file.Stat()
	if err != nil || !info.Mode().IsRegular() || info.Mode().Perm()&0o077 != 0 || info.Size() > int64(2*s.maxCommandBytes+8*s.maxStatusBytes) {
		return nil, fmt.Errorf("gateway journal file is invalid")
	}
	decoder := json.NewDecoder(io.LimitReader(file, info.Size()+1))
	decoder.DisallowUnknownFields()
	var record durableRecord
	if err := decoder.Decode(&record); err != nil || decoder.Decode(&struct{}{}) != io.EOF {
		return nil, fmt.Errorf("decode gateway journal")
	}
	if err := s.validateRecord(&record, key); err != nil {
		return nil, err
	}
	return &record, nil
}

func (s *durableStore) validateRecord(record *durableRecord, key string) error {
	if record == nil || record.Version != durableRecordVersion || record.RecordKey != key || record.RecordKey != recordKey(record.DeploymentID, record.Attempt) || record.EventID == "" || record.ConfigVersionID == "" || len(record.Command) == 0 || len(record.Command) > s.maxCommandBytes || record.CommandDigest != commandDigest(record.Command) || len(record.Statuses) == 0 {
		return fmt.Errorf("gateway journal record is corrupt")
	}
	command := commandFromBytes(record.Command)
	if command == nil || command.Event == nil || command.Event.EventId != record.EventID || command.DeploymentId != record.DeploymentID || command.Attempt != record.Attempt || command.ConfigVersionId != record.ConfigVersionID {
		return fmt.Errorf("gateway journal command is corrupt")
	}
	for _, encoded := range record.Statuses {
		status := new(agentv1.DeploymentStatus)
		if len(encoded) == 0 || len(encoded) > s.maxStatusBytes || proto.Unmarshal(encoded, status) != nil || status.Event == nil || status.DeploymentId != record.DeploymentID || status.Attempt != record.Attempt || status.ConfigVersionId != record.ConfigVersionID {
			return fmt.Errorf("gateway journal status is corrupt")
		}
	}
	return nil
}

func (s *durableStore) saveLocked(record *durableRecord) error {
	if err := s.validateRecord(record, record.RecordKey); err != nil {
		return err
	}
	encoded, err := json.Marshal(record)
	if err != nil {
		return fmt.Errorf("encode gateway journal: %w", err)
	}
	temporary, err := os.CreateTemp(s.directory, ".record-*")
	if err != nil {
		return fmt.Errorf("create gateway journal temporary: %w", err)
	}
	temporaryPath := temporary.Name()
	defer os.Remove(temporaryPath)
	if err := temporary.Chmod(0o600); err != nil {
		temporary.Close()
		return err
	}
	if _, err := temporary.Write(encoded); err != nil {
		temporary.Close()
		return err
	}
	if err := temporary.Sync(); err != nil {
		temporary.Close()
		return err
	}
	if err := temporary.Close(); err != nil {
		return err
	}
	if err := os.Rename(temporaryPath, filepath.Join(s.directory, record.RecordKey+".json")); err != nil {
		return fmt.Errorf("replace gateway journal: %w", err)
	}
	directory, err := os.Open(s.directory)
	if err != nil {
		return err
	}
	defer directory.Close()
	return directory.Sync()
}

func marshalStatus(status *agentv1.DeploymentStatus, limit int) ([]byte, error) {
	encoded, err := (proto.MarshalOptions{Deterministic: true}).Marshal(status)
	if err != nil || len(encoded) == 0 || len(encoded) > limit {
		return nil, fmt.Errorf("%w: status cannot be persisted", ErrInvalidMessage)
	}
	return encoded, nil
}

func commandFromBytes(encoded []byte) *agentv1.DeploymentCommand {
	command := new(agentv1.DeploymentCommand)
	if proto.Unmarshal(encoded, command) != nil {
		return nil
	}
	return command
}

func statusesFromRecord(record *durableRecord) ([]*agentv1.DeploymentStatus, error) {
	statuses := make([]*agentv1.DeploymentStatus, 0, len(record.Statuses))
	for _, encoded := range record.Statuses {
		status := new(agentv1.DeploymentStatus)
		if err := proto.Unmarshal(encoded, status); err != nil {
			return nil, err
		}
		statuses = append(statuses, status)
	}
	return statuses, nil
}

func cloneRecord(record *durableRecord) *durableRecord {
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
