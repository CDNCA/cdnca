package l4runtime

import (
	"bytes"
	"encoding/json"
	"errors"
	"os"
	"path/filepath"
)

// the degraded forwards of each V2 version directory (stream
// ID -> l4-isolate reason code of its last resolution / probe), kept next to
// the LKG state (state/) so a restarted agent reports the same forwards.
// Recovered forwards are dropped; versions that can no longer serve are pruned.
const streamStateSchemaVersion = 1

type streamState struct {
	SchemaVersion int                          `json:"schema_version"`
	Versions      map[string]map[string]string `json:"versions"`
}

func (s *diskStore) streamStatePath() string { return filepath.Join(s.stateDir, "l4-streams.json") }

func (s *diskStore) loadStreamState() (streamState, error) {
	state := streamState{SchemaVersion: streamStateSchemaVersion, Versions: map[string]map[string]string{}}
	content, err := readRegularFile(s.streamStatePath())
	if errors.Is(err, os.ErrNotExist) {
		return state, nil
	}
	if err != nil {
		return state, err
	}
	decoder := json.NewDecoder(bytes.NewReader(content))
	decoder.DisallowUnknownFields()
	var stored streamState
	if err := decoder.Decode(&stored); err != nil || ensureJSONEOF(decoder) != nil || stored.SchemaVersion != streamStateSchemaVersion {
		return state, ErrCorruptState
	}
	for versionDir, degraded := range stored.Versions {
		if !validVersionDirectoryName(versionDir) {
			return state, ErrCorruptState
		}
		for streamID, reason := range degraded {
			if streamID == "" || !degradedReasons[reason] {
				return state, ErrCorruptState
			}
		}
		state.Versions[versionDir] = degraded
	}
	return state, nil
}

// streamReasons are the stored degraded forwards of versionDir (none when
// the file is missing or unreadable: reporting never blocks serving).
func (s *diskStore) streamReasons(versionDir string) map[string]string {
	state, err := s.loadStreamState()
	if err != nil {
		return nil
	}
	return state.Versions[versionDir]
}

// recordStreamReasons stores the degraded forwards of versionDir and drops
// every version other than it, the active one and the one a pending release
// would restore. Caller holds the store lock.
func (s *diskStore) recordStreamReasons(versionDir string, reasons map[string]string) error {
	state, err := s.loadStreamState()
	if err != nil {
		state = streamState{SchemaVersion: streamStateSchemaVersion, Versions: map[string]map[string]string{}}
	}
	degraded := map[string]string{}
	for streamID, reason := range reasons {
		if degradedReasons[reason] {
			degraded[streamID] = reason
		}
	}
	state.Versions[versionDir] = degraded
	keep := map[string]bool{versionDir: true}
	if active, err := s.loadActive(); err != nil {
		return err
	} else if active != nil {
		keep[active.VersionDir] = true
	}
	if pending, err := s.loadReleaseJournal(); err != nil {
		return err
	} else if pending != nil && pending.Previous != nil {
		keep[pending.Previous.VersionDir] = true
	}
	kept := streamState{SchemaVersion: streamStateSchemaVersion, Versions: map[string]map[string]string{}}
	for dir, value := range state.Versions {
		if keep[dir] && len(value) != 0 {
			kept.Versions[dir] = value
		}
	}
	if len(kept.Versions) == 0 {
		if err := os.Remove(s.streamStatePath()); errors.Is(err, os.ErrNotExist) {
			return nil
		} else if err != nil {
			return err
		}
		return syncDirectory(s.stateDir)
	}
	content, err := json.Marshal(kept)
	if err != nil {
		return ErrCorruptState
	}
	return writeAtomic(s.stateDir, s.streamStatePath(), append(content, '\n'))
}
