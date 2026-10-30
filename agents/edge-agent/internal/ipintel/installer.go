// Package ipintel installs the IP intelligence library on an edge node. It
// is the installer of the artifact set media type
// artifactset.MediaTypeIPIntel (ADR 0007 section 4.3): the set executor has
// already checked the item's digest chain against the control plane signed
// set; Prepare opens the library (layout, order, data digest and metadata,
// libs/entitlement/ipintel Open), checks that it is the library the set item
// names (revision and build ID) and stages it, Commit switches the file
// OpenResty maps with one rename and keeps the previous library (LKG).
//
// On-disk contract for the node lookup (G3-c), all below Root (inside
// deployment_root, readable by the native OpenResty unit):
//
//	current.ipi         active artifact (format v2, CDNIPI01), replaced by rename
//	previous.ipi        the library current.ipi replaced (LKG)
//	state.json          {revision, artifact_sha256, source_release, ...} of current.ipi
//
// A reader opens current.ipi once and mmaps it read-only; a later rename does
// not affect an existing mapping, so workers reopen when the header of
// current.ipi changes (checked on a timer, never per request). A missing
// current.ipi means no library: carrier / IDC / ASN / region rules do not
// match.
package ipintel

import (
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"
	"errors"
	"fmt"
	"os"
	"path/filepath"
	"strconv"
	"sync"
	"time"

	format "github.com/cdnca/cdnca/libs/entitlement/ipintel"
)

const (
	CurrentFile  = "current.ipi"
	PreviousFile = "previous.ipi"
	StateFile    = "state.json"
	StateSchema  = "cdnca.edge.ip-intel-state/v1"
)

var (
	ErrInvalidConfig = errors.New("invalid ip intel installer configuration")
	// ErrRejected: the content is not a valid, newer library; the active
	// library is unchanged.
	ErrRejected = errors.New("ip intel library rejected")
)

// State is what the node reports as its loaded library.
type State struct {
	Schema string `json:"schema"`
	// ArtifactID is the set item the library came from: ipintel/base (license)
	// or ipintel/local (control-plane module.ipintel.dnspup). Revisions are
	// ordered within one artifact only. Empty in states written before it
	// was recorded (treated as ipintel/base).
	ArtifactID        string `json:"artifact_id,omitempty"`
	Revision          uint64 `json:"revision"`
	BuildID           string `json:"build_id"`
	ArtifactSHA256    string `json:"artifact_sha256"`
	ArtifactBytes     int64  `json:"artifact_bytes"`
	CapabilityVersion int    `json:"capability_version"`
	SourceRelease     string `json:"source_release"`
	DataUpdatedAt     int64  `json:"data_updated_at"`
	PreviousRevision  uint64 `json:"previous_revision,omitempty"`
	InstalledAt       int64  `json:"installed_at"`
}

type Installer struct {
	root string
	mu   sync.Mutex
}

// New prepares root (absolute, created owner-writable, world-readable so the
// OpenResty unit can map the library).
func New(root string) (*Installer, error) {
	if !filepath.IsAbs(root) || filepath.Clean(root) != root {
		return nil, ErrInvalidConfig
	}
	if err := os.MkdirAll(root, 0o755); err != nil {
		return nil, fmt.Errorf("create ip intel root: %w", err)
	}
	return &Installer{root: root}, nil
}

// Root is the directory holding current.ipi.
func (installer *Installer) Root() string { return installer.root }

// Current returns the loaded library's state (nil: none). The state file is
// trusted only when current.ipi still has its digest.
func (installer *Installer) Current() (*State, error) {
	installer.mu.Lock()
	defer installer.mu.Unlock()
	return installer.current()
}

func (installer *Installer) current() (*State, error) {
	encoded, err := os.ReadFile(installer.path(StateFile))
	if errors.Is(err, os.ErrNotExist) {
		return nil, nil
	}
	if err != nil {
		return nil, err
	}
	var state State
	if err := json.Unmarshal(encoded, &state); err != nil || state.Schema != StateSchema || state.Revision == 0 {
		return nil, fmt.Errorf("%w: ip intel state is corrupt", ErrRejected)
	}
	data, err := os.ReadFile(installer.path(CurrentFile))
	if errors.Is(err, os.ErrNotExist) {
		return nil, nil
	}
	if err != nil {
		return nil, err
	}
	digest := sha256.Sum256(data)
	if hex.EncodeToString(digest[:]) != state.ArtifactSHA256 {
		return nil, fmt.Errorf("%w: current ip intel library does not match its state", ErrRejected)
	}
	return &state, nil
}

// Staged is a verified library waiting for Commit or Abort.
type Staged struct {
	installer *Installer
	state     State
	previous  *State
	path      string
}

// State is the library state Commit activates.
func (staged *Staged) State() State { return staged.state }

// Expected is the library a set item names: the catalog entry's revision
// and version (the library build ID).
type Expected struct {
	ArtifactID string
	Revision   uint64
	BuildID    string
}

// DefaultArtifactID is the artifact of a state without one.
const DefaultArtifactID = "ipintel/base"

func artifactOf(state *State) string {
	if state.ArtifactID == "" {
		return DefaultArtifactID
	}
	return state.ArtifactID
}

// Prepare verifies content as the complete library expected names, newer
// than the active one of the same artifact, and stages it. A library of the
// other artifact (base ↔ local: the control plane picked the one with newer
// data) replaces the active one whatever its revision. The same library
// again is a no-op stage.
func (installer *Installer) Prepare(content []byte, expected Expected, now time.Time) (*Staged, error) {
	table, err := format.Open(content)
	if err != nil {
		return nil, errors.Join(ErrRejected, err)
	}
	metadata := table.Metadata
	dataUpdatedAt, err := time.Parse(time.RFC3339, metadata.DataUpdatedAt)
	if err != nil || metadata.Revision == 0 {
		return nil, fmt.Errorf("%w: library metadata", ErrRejected)
	}
	if metadata.Revision != expected.Revision || metadata.BuildID != expected.BuildID {
		return nil, fmt.Errorf("%w: library is revision %d build %q, the set item names revision %d build %q",
			ErrRejected, metadata.Revision, metadata.BuildID, expected.Revision, expected.BuildID)
	}
	digest := sha256.Sum256(content)
	artifactID := expected.ArtifactID
	if artifactID == "" {
		artifactID = DefaultArtifactID
	}
	state := State{Schema: StateSchema, ArtifactID: artifactID, Revision: metadata.Revision, BuildID: metadata.BuildID, ArtifactSHA256: hex.EncodeToString(digest[:]),
		ArtifactBytes: int64(len(content)), CapabilityVersion: metadata.CapabilityVersion,
		SourceRelease: metadata.SourceRelease, DataUpdatedAt: dataUpdatedAt.Unix(), InstalledAt: now.UTC().Unix()}
	installer.mu.Lock()
	defer installer.mu.Unlock()
	current, err := installer.current()
	if err != nil && !errors.Is(err, ErrRejected) {
		return nil, err
	}
	staged := &Staged{installer: installer, state: state, previous: current}
	if current != nil {
		switch {
		case state.Revision == current.Revision && state.ArtifactSHA256 == current.ArtifactSHA256 && artifactID == artifactOf(current):
			staged.state = *current
			return staged, nil
		case artifactID == artifactOf(current) && state.Revision <= current.Revision:
			return nil, fmt.Errorf("%w: revision %d is not newer than %d", ErrRejected, state.Revision, current.Revision)
		}
		state.PreviousRevision = current.Revision
		staged.state = state
	}
	staged.path = installer.path(".incoming-" + strconv.FormatUint(state.Revision, 10) + ".ipi")
	if err := writeSynced(staged.path, content, 0o644); err != nil {
		_ = os.Remove(staged.path)
		return nil, err
	}
	return staged, nil
}

// Abort drops a staged library.
func (staged *Staged) Abort() {
	if staged.path != "" {
		_ = os.Remove(staged.path)
	}
}

// Commit activates the staged library. undo puts back the library that was
// active before (or none).
func (staged *Staged) Commit() (undo func() error, err error) {
	if staged.path == "" {
		return func() error { return nil }, nil
	}
	installer := staged.installer
	installer.mu.Lock()
	defer installer.mu.Unlock()
	current, err := installer.current()
	if err != nil && !errors.Is(err, ErrRejected) {
		staged.Abort()
		return nil, err
	}
	if !sameState(current, staged.previous) {
		staged.Abort()
		return nil, fmt.Errorf("%w: the active library changed while staging", ErrRejected)
	}
	currentPath, previousPath := installer.path(CurrentFile), installer.path(PreviousFile)
	_ = os.Remove(previousPath)
	if current != nil {
		if err := os.Link(currentPath, previousPath); err != nil {
			staged.Abort()
			return nil, fmt.Errorf("keep previous ip intel library: %w", err)
		}
	}
	if err := os.Rename(staged.path, currentPath); err != nil {
		staged.Abort()
		return nil, fmt.Errorf("activate ip intel library: %w", err)
	}
	if err := installer.writeState(&staged.state); err != nil {
		return nil, err
	}
	previous := staged.previous
	return func() error {
		installer.mu.Lock()
		defer installer.mu.Unlock()
		if previous == nil {
			_ = os.Remove(currentPath)
			return installer.writeState(nil)
		}
		if err := os.Rename(previousPath, currentPath); err != nil {
			return fmt.Errorf("restore previous ip intel library: %w", err)
		}
		return installer.writeState(previous)
	}, nil
}

// Remove uninstalls the active library (it is kept as previous.ipi).
func (installer *Installer) Remove() error {
	installer.mu.Lock()
	defer installer.mu.Unlock()
	currentPath := installer.path(CurrentFile)
	if _, err := os.Stat(currentPath); err == nil {
		if err := os.Rename(currentPath, installer.path(PreviousFile)); err != nil {
			return fmt.Errorf("remove ip intel library: %w", err)
		}
	} else if !errors.Is(err, os.ErrNotExist) {
		return err
	}
	return installer.writeState(nil)
}

func (installer *Installer) writeState(state *State) error {
	statePath := installer.path(StateFile)
	if state == nil {
		if err := os.Remove(statePath); err != nil && !errors.Is(err, os.ErrNotExist) {
			return err
		}
		return syncDir(installer.root)
	}
	encoded, _ := json.Marshal(state)
	temporary := installer.path(".state.json.tmp")
	if err := writeSynced(temporary, encoded, 0o644); err != nil {
		return err
	}
	if err := os.Rename(temporary, statePath); err != nil {
		return err
	}
	return syncDir(installer.root)
}

func (installer *Installer) path(name string) string { return filepath.Join(installer.root, name) }

func sameState(left, right *State) bool {
	if left == nil || right == nil {
		return left == nil && right == nil
	}
	return artifactOf(left) == artifactOf(right) && left.Revision == right.Revision && left.ArtifactSHA256 == right.ArtifactSHA256
}

func writeSynced(path string, data []byte, mode os.FileMode) error {
	file, err := os.OpenFile(path, os.O_CREATE|os.O_TRUNC|os.O_WRONLY, mode)
	if err != nil {
		return err
	}
	if _, err := file.Write(data); err != nil {
		file.Close()
		return err
	}
	if err := file.Sync(); err != nil {
		file.Close()
		return err
	}
	return file.Close()
}

func syncDir(path string) error {
	directory, err := os.Open(path)
	if err != nil {
		return err
	}
	defer directory.Close()
	return directory.Sync()
}
