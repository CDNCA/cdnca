package gatewayclient

import (
	"encoding/json"
	"fmt"
	"io"
	"log/slog"
	"os"
	"path/filepath"
	"sort"
	"strings"
	"syscall"
	"time"

	agentv1 "github.com/cdnca/cdnca/proto/gen/go/agent/v1"
	commonv1 "github.com/cdnca/cdnca/proto/gen/go/common/v1"
)

// A journal record moved to <journal>/quarantine leaves a tombstone behind: the
// command's identity (deployment id, attempt, command digest), marked finished
// with an unknown outcome. When the Gateway redelivers that command the Agent
// does not run it a second time; it answers a terminal FAILED status whose
// summary starts with journalQuarantinedReason, and the controller treats that
// as a failed deployment that an operator or an automatic republish redoes
// under a new attempt or deployment.
//
// Tombstones are written only when a record is quarantined (journal scan at
// session start) and read once per arriving deployment command. Neither is on
// a request path: no data-plane or per-request code touches them.
const (
	journalQuarantinedReason  = "journal_quarantined"
	journalTombstoneDirectory = "tombstones"
	journalTombstoneVersion   = 1
	// Retention and count bound the directory: a tombstone older than the
	// retention is ignored and removed, and past the cap the oldest go first.
	journalTombstoneRetention = 30 * 24 * time.Hour
	journalTombstoneLimit     = 1024
	journalTombstoneMaxBytes  = 4096
)

type journalTombstone struct {
	Version       int    `json:"version"`
	RecordKey     string `json:"record_key"`
	DeploymentID  string `json:"deployment_id"`
	Attempt       uint32 `json:"attempt"`
	CommandDigest string `json:"command_digest"`
	QuarantinedAt int64  `json:"quarantined_at_unix"`
}

var journalTombstoneClock = time.Now

func (s *durableStore) tombstoneDirectory() string {
	return filepath.Join(s.directory, journalTombstoneDirectory)
}

// writeTombstoneLocked records the quarantined command's identity, then drops
// tombstones past retention or the cap. Callers hold s.mu.
func (s *durableStore) writeTombstoneLocked(record *durableRecord) error {
	directory := s.tombstoneDirectory()
	if err := os.MkdirAll(directory, 0o700); err != nil {
		return fmt.Errorf("create gateway journal tombstones: %w", err)
	}
	encoded, err := json.Marshal(journalTombstone{
		Version: journalTombstoneVersion, RecordKey: record.RecordKey, DeploymentID: record.DeploymentID,
		Attempt: record.Attempt, CommandDigest: record.CommandDigest, QuarantinedAt: journalTombstoneClock().Unix(),
	})
	if err != nil {
		return err
	}
	temporary, err := os.CreateTemp(directory, ".tomb-*")
	if err != nil {
		return fmt.Errorf("create gateway journal tombstone: %w", err)
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
	if err := os.Rename(temporaryPath, filepath.Join(directory, record.RecordKey+".json")); err != nil {
		return fmt.Errorf("write gateway journal tombstone: %w", err)
	}
	s.pruneTombstonesLocked()
	return nil
}

func (s *durableStore) readTombstoneLocked(key string) *journalTombstone {
	file, err := os.OpenFile(filepath.Join(s.tombstoneDirectory(), key+".json"), os.O_RDONLY|syscall.O_NOFOLLOW, 0)
	if err != nil {
		return nil
	}
	defer file.Close()
	info, err := file.Stat()
	if err != nil || !info.Mode().IsRegular() || info.Mode().Perm()&0o077 != 0 || info.Size() > journalTombstoneMaxBytes {
		return nil
	}
	decoder := json.NewDecoder(io.LimitReader(file, info.Size()+1))
	decoder.DisallowUnknownFields()
	var tombstone journalTombstone
	if decoder.Decode(&tombstone) != nil || decoder.Decode(&struct{}{}) != io.EOF {
		return nil
	}
	if tombstone.Version != journalTombstoneVersion || tombstone.RecordKey != key || tombstone.RecordKey != recordKey(tombstone.DeploymentID, tombstone.Attempt) {
		return nil
	}
	if journalTombstoneClock().Sub(time.Unix(tombstone.QuarantinedAt, 0)) > journalTombstoneRetention {
		return nil
	}
	return &tombstone
}

func (s *durableStore) removeTombstoneLocked(key string) {
	_ = os.Remove(filepath.Join(s.tombstoneDirectory(), key+".json"))
}

func (s *durableStore) pruneTombstonesLocked() {
	entries, err := os.ReadDir(s.tombstoneDirectory())
	if err != nil {
		return
	}
	type kept struct {
		name string
		at   int64
	}
	var live []kept
	for _, entry := range entries {
		name := entry.Name()
		if entry.IsDir() || !strings.HasSuffix(name, ".json") {
			continue
		}
		tombstone := s.readTombstoneLocked(strings.TrimSuffix(name, ".json"))
		if tombstone == nil {
			// Expired, unreadable or foreign: nothing refers to it any more.
			_ = os.Remove(filepath.Join(s.tombstoneDirectory(), name))
			continue
		}
		live = append(live, kept{name: name, at: tombstone.QuarantinedAt})
	}
	if len(live) <= journalTombstoneLimit {
		return
	}
	sort.Slice(live, func(i, j int) bool { return live[i].at < live[j].at })
	for _, item := range live[:len(live)-journalTombstoneLimit] {
		_ = os.Remove(filepath.Join(s.tombstoneDirectory(), item.name))
	}
}

func journalQuarantinedStatus(command *agentv1.DeploymentCommand, sequence uint64, at time.Time) *agentv1.DeploymentStatus {
	status := failedStatus(command, sequence, at, commonv1.ErrorCode_ERROR_CODE_FAILED_PRECONDITION,
		journalQuarantinedReason+": this command's journal record was quarantined; its outcome is unknown and it was not run again", false)
	if command.ConfigurationScopeId != nil {
		status = withCommandScope(command, status)
	}
	return status
}

// tombstonedRecordLocked builds the finished record a redelivered, quarantined
// command gets: its first status plus a terminal FAILED, with execution done.
// It returns nil when the command has no live tombstone.
func (s *durableStore) tombstonedRecordLocked(key string, command *agentv1.DeploymentCommand, commandBytes []byte, firstStatusBytes []byte, firstStatus *agentv1.DeploymentStatus, at time.Time) (*durableRecord, error) {
	tombstone := s.readTombstoneLocked(key)
	if tombstone == nil {
		return nil, nil
	}
	if tombstone.CommandDigest != commandDigest(commandBytes) {
		return nil, ErrCommandConflict
	}
	statuses := [][]byte{firstStatusBytes}
	sequence := uint64(2)
	if firstStatus.ConfigurationScopeId != nil {
		// A multi-tenant session reports AGENT_QUEUED before its terminal status.
		queued, err := marshalStatus(scopedQueuedStatus(command, at), s.maxStatusBytes)
		if err != nil {
			return nil, err
		}
		statuses = append(statuses, queued)
		sequence = scopedStartedSequence
	}
	failed, err := marshalStatus(journalQuarantinedStatus(command, sequence, at), s.maxStatusBytes)
	if err != nil {
		return nil, err
	}
	return &durableRecord{
		Version: durableRecordVersion, RecordKey: key, EventID: command.Event.EventId,
		DeploymentID: command.DeploymentId, Attempt: command.Attempt, ConfigVersionID: command.ConfigVersionId,
		CommandDigest: commandDigest(commandBytes), Command: commandBytes,
		ExecutionDone: true, Statuses: append(statuses, failed),
	}, nil
}

// finishTombstonedLocked saves the record and, for a scoped command, its apply
// result exactly as appendStatuses does for a command that ran and failed. The
// record now carries the identity, so the tombstone is dropped.
func (s *durableStore) finishTombstonedLocked(record *durableRecord, command *agentv1.DeploymentCommand) error {
	if err := s.saveLocked(record); err != nil {
		return err
	}
	slog.Error("gateway journal: redelivered command was quarantined earlier, reported FAILED without running it",
		"deployment_id", record.DeploymentID, "attempt", record.Attempt, "reason", journalQuarantinedReason)
	if command.ConfigurationScopeId != nil && !isArtifactSetCommand(command) {
		if statuses, err := statusesFromRecord(record); err == nil && len(statuses) > 0 {
			if result, terminal := scopeApplyResultFor(statuses[len(statuses)-1]); terminal {
				if err := s.saveScopeApplyResultLocked(command.GetConfigurationScopeId(), result); err != nil {
					return err
				}
			}
		}
	}
	s.removeTombstoneLocked(record.RecordKey)
	return nil
}
