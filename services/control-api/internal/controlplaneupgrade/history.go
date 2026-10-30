package controlplaneupgrade

import (
	"bytes"
	"encoding/json"
	"errors"
	"io"
	"os"
	"path/filepath"
	"reflect"
	"regexp"
	"time"
)

// HistorySchema journals each checkpoint the runner reaches so operators can
// read an upgrade log. It is evidence only: state.json stays the single
// recovery authority and readers of state.json never see this file.
const HistorySchema = "cdnca.control-plane-upgrade-history/v1"

var planErrorCode = regexp.MustCompile(`^[a-z][a-z0-9_]{0,95}$`)

const (
	historyFilename   = "history.json"
	maxHistoryEntries = 64
)

type HistoryEntry struct {
	Phase     Phase  `json:"phase"`
	ErrorCode string `json:"error_code,omitempty"`
	At        int64  `json:"at"`
	// Migration snapshots the database migration evidence (applied set,
	// backup, timings, restore) at this checkpoint of a migrating plan.
	Migration *MigrationRecord `json:"migration,omitempty"`
}

type History struct {
	Schema   string         `json:"schema"`
	PlanID   string         `json:"plan_id"`
	Sequence uint64         `json:"sequence"`
	Entries  []HistoryEntry `json:"entries"`
}

func validHistory(history History) bool {
	if history.Schema != HistorySchema || history.PlanID == "" || history.Sequence == 0 ||
		len(history.Entries) == 0 || len(history.Entries) > maxHistoryEntries {
		return false
	}
	previous := int64(0)
	for _, entry := range history.Entries {
		if !validPhase(entry.Phase) || entry.At <= 0 || entry.At < previous ||
			(entry.ErrorCode != "" && !planErrorCode.MatchString(entry.ErrorCode)) || !validMigrationRecord(entry.Migration) {
			return false
		}
		previous = entry.At
	}
	return true
}

func decodeHistory(encoded []byte) (History, error) {
	decoder := json.NewDecoder(bytes.NewReader(encoded))
	decoder.DisallowUnknownFields()
	var history History
	if decoder.Decode(&history) != nil || !errors.Is(decoder.Decode(&struct{}{}), io.EOF) || !validHistory(history) {
		return History{}, ErrCorruptState
	}
	return history, nil
}

// LoadHistory returns the journal of the most recent plan, if one exists.
func (store *FileStore) LoadHistory() (History, error) {
	encoded, err := os.ReadFile(filepath.Join(store.root, historyFilename))
	if errors.Is(err, os.ErrNotExist) {
		return History{}, ErrStateNotFound
	}
	if err != nil || len(encoded) == 0 || len(encoded) > 64*1024 {
		return History{}, ErrCorruptState
	}
	return decodeHistory(encoded)
}

// appendHistory records state as the newest checkpoint. A new plan starts a
// new journal; an unchanged checkpoint is not repeated.
func (store *FileStore) appendHistory(state State, at time.Time) error {
	history, err := store.LoadHistory()
	if err != nil || history.PlanID != state.PlanID || history.Sequence != state.Sequence {
		history = History{Schema: HistorySchema, PlanID: state.PlanID, Sequence: state.Sequence}
	}
	entry := HistoryEntry{Phase: state.Phase, ErrorCode: state.ErrorCode, At: at.UTC().Unix(), Migration: state.Migration.clone()}
	if count := len(history.Entries); count > 0 {
		last := history.Entries[count-1]
		if last.Phase == entry.Phase && last.ErrorCode == entry.ErrorCode && reflect.DeepEqual(last.Migration, entry.Migration) {
			return nil
		}
		if entry.At < last.At {
			entry.At = last.At
		}
	}
	history.Entries = append(history.Entries, entry)
	if len(history.Entries) > maxHistoryEntries {
		history.Entries = history.Entries[len(history.Entries)-maxHistoryEntries:]
	}
	encoded, err := json.Marshal(history)
	// Migration snapshots make entries larger; keep the newest ones readable.
	for err == nil && len(encoded) > 64*1024 && len(history.Entries) > 1 {
		history.Entries = history.Entries[1:]
		encoded, err = json.Marshal(history)
	}
	if err != nil {
		return err
	}
	temporary, err := os.CreateTemp(store.root, ".history-*.tmp")
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
	if err := temporary.Close(); err != nil {
		return err
	}
	return os.Rename(temporaryPath, filepath.Join(store.root, historyFilename))
}
