// Package nodeartifacts executes node artifact sets on the edge node
// (libs/edgeconfig/artifactset, ADR 0007 section 4.3). Segment objects are
// already in the object store (written by segment deployments); Apply
// rebuilds every item of a verified set from its segments, prechecks it with
// the installer of its media type, then switches the whole set: commits every
// item (undoing the committed ones if one fails), uninstalls the media types
// the set no longer holds and records the set as the active one (LKG). A set
// that cannot be applied leaves the active set untouched; the receipt says
// why, per item.
package nodeartifacts

import (
	"bytes"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"os"
	"path/filepath"
	"sort"
	"sync"
	"time"

	"github.com/cdnca/cdnca/agents/edge-agent/internal/objectstore"
	"github.com/cdnca/cdnca/libs/edgeconfig/artifactset"
	"github.com/klauspost/compress/zstd"
)

const (
	StateFile   = "active.json"
	StateSchema = "cdnca.edge.artifact-set-state/v1"
)

var (
	ErrInvalidConfig = errors.New("invalid node artifact set configuration")
	// ErrStaleSet: the set is older than (or conflicts with) the active one.
	ErrStaleSet = errors.New("node artifact set is not newer than the active set")
	// ErrWrongNode: the set names another node.
	ErrWrongNode = errors.New("node artifact set is for another node")
)

// Staged is an item an installer has verified and is ready to activate.
type Staged interface {
	// Commit activates the item; undo puts back what was active before.
	Commit() (undo func() error, err error)
	Abort()
}

// Installer installs the items of one media type. At most one item per
// media type is active. A Prepare error rejects the item (and the set); an
// *artifactset.InstallError names the receipt reason.
type Installer interface {
	Prepare(item artifactset.Item, content []byte, now time.Time) (Staged, error)
	// Remove uninstalls the media type's active item.
	Remove() error
}

// MultiInstaller is an installer whose media type may have several items in
// one set (rule packs: one per mounted pack). Each item is prepared and
// committed on its own; Remove runs when the set holds none of them.
type MultiInstaller interface {
	Installer
	MultipleItems()
}

type Config struct {
	NodeID     string
	StateDir   string
	Objects    *objectstore.Store
	Installers map[string]Installer
}

// State is the active (last applied) set.
type State struct {
	Schema    string             `json:"schema"`
	NodeID    string             `json:"node_id"`
	Revision  uint64             `json:"revision"`
	SetSHA256 string             `json:"set_sha256"`
	Items     []artifactset.Item `json:"items"`
	AppliedAt time.Time          `json:"applied_at"`
}

type Executor struct {
	config Config
	mu     sync.Mutex
	active *State
}

func New(config Config) (*Executor, error) {
	if config.NodeID == "" || !filepath.IsAbs(config.StateDir) || filepath.Clean(config.StateDir) != config.StateDir ||
		config.Objects == nil || len(config.Installers) == 0 {
		return nil, ErrInvalidConfig
	}
	for mediaType, installer := range config.Installers {
		if !artifactset.SupportedMediaType(mediaType) || installer == nil {
			return nil, fmt.Errorf("%w: installer for %q", ErrInvalidConfig, mediaType)
		}
	}
	if err := os.MkdirAll(config.StateDir, 0o700); err != nil {
		return nil, fmt.Errorf("create node artifact set state: %w", err)
	}
	executor := &Executor{config: config}
	active, err := executor.load()
	if err != nil {
		return nil, err
	}
	executor.active = active
	return executor, nil
}

// Active returns a copy of the active set (nil: none applied).
func (executor *Executor) Active() *State {
	executor.mu.Lock()
	defer executor.mu.Unlock()
	if executor.active == nil {
		return nil
	}
	state := *executor.active
	state.Items = append([]artifactset.Item(nil), executor.active.Items...)
	return &state
}

// HasItem reports whether the active set holds an item of mediaType.
func (executor *Executor) HasItem(mediaType string) bool {
	executor.mu.Lock()
	defer executor.mu.Unlock()
	if executor.active == nil {
		return false
	}
	for _, item := range executor.active.Items {
		if item.MediaType == mediaType {
			return true
		}
	}
	return false
}

type prepared struct {
	item   artifactset.Item
	staged Staged
}

// Apply applies a set already verified against the edge publication key;
// setSHA256 is the digest of its signed bytes. The returned receipt is
// complete and valid; an error means no receipt can describe the outcome
// (stale set, wrong node, local I/O failure).
func (executor *Executor) Apply(set artifactset.Set, setSHA256 string, now time.Time) (artifactset.Receipt, error) {
	if set.NodeID != executor.config.NodeID {
		return artifactset.Receipt{}, ErrWrongNode
	}
	if !artifactset.ValidDigest(setSHA256) {
		return artifactset.Receipt{}, fmt.Errorf("%w: set digest", ErrInvalidConfig)
	}
	executor.mu.Lock()
	defer executor.mu.Unlock()
	receipt := artifactset.Receipt{NodeID: set.NodeID, Revision: set.Revision, SetSHA256: setSHA256,
		ReportedAt: now, Items: make([]artifactset.ItemResult, len(set.Items))}
	if active := executor.active; active != nil {
		switch {
		case active.Revision == set.Revision && active.SetSHA256 == setSHA256:
			return executor.appliedReceipt(receipt, set), nil
		case set.Revision <= active.Revision:
			return artifactset.Receipt{}, fmt.Errorf("%w: revision %d, active %d", ErrStaleSet, set.Revision, active.Revision)
		}
	}
	for index, item := range set.Items {
		receipt.Items[index] = artifactset.ItemResult{ArtifactID: item.ArtifactID, Version: item.Version, SHA256: item.SHA256}
	}
	staged := make([]prepared, 0, len(set.Items))
	abort := func() {
		for _, entry := range staged {
			entry.staged.Abort()
		}
	}
	failed, pending := false, false
	seen := map[string]bool{}
	for index, item := range set.Items {
		result, reason, entry := executor.prepare(item, seen[item.MediaType], now)
		seen[item.MediaType] = true
		receipt.Items[index].Result, receipt.Items[index].Reason = result, reason
		switch result {
		case artifactset.ResultRejected:
			failed = true
		case artifactset.ResultPending:
			pending = true
		default:
			staged = append(staged, entry)
		}
	}
	if failed || pending {
		abort()
		return executor.unswitchedReceipt(receipt, failed), nil
	}
	undos := make([]func() error, 0, len(staged))
	rollback := func() {
		for index := len(undos) - 1; index >= 0; index-- {
			_ = undos[index]()
		}
	}
	for position, entry := range staged {
		undo, err := entry.staged.Commit()
		if err != nil {
			for _, rest := range staged[position+1:] {
				rest.staged.Abort()
			}
			rollback()
			markItem(&receipt, entry.item.ArtifactID, artifactset.ResultRejected, artifactset.ReasonActivationFailed)
			return executor.unswitchedReceipt(receipt, true), nil
		}
		undos = append(undos, undo)
	}
	for mediaType, installer := range executor.config.Installers {
		if seen[mediaType] || !executor.activeHas(mediaType) {
			continue
		}
		if err := installer.Remove(); err != nil {
			rollback()
			for index := range receipt.Items {
				receipt.Items[index].Result, receipt.Items[index].Reason = artifactset.ResultRejected, artifactset.ReasonActivationFailed
			}
			if len(receipt.Items) == 0 {
				return artifactset.Receipt{}, fmt.Errorf("uninstall %s: %w", mediaType, err)
			}
			return executor.unswitchedReceipt(receipt, true), nil
		}
	}
	state := &State{Schema: StateSchema, NodeID: set.NodeID, Revision: set.Revision, SetSHA256: setSHA256,
		Items: append([]artifactset.Item{}, set.Items...), AppliedAt: now.UTC().Truncate(time.Second)}
	if err := executor.store(state); err != nil {
		rollback()
		return artifactset.Receipt{}, err
	}
	executor.active = state
	return executor.appliedReceipt(receipt, set), nil
}

// prepare rebuilds one item from its segments and stages it.
func (executor *Executor) prepare(item artifactset.Item, duplicateMediaType bool, now time.Time) (string, string, prepared) {
	installer, found := executor.config.Installers[item.MediaType]
	if !found {
		return artifactset.ResultRejected, artifactset.ReasonUnsupportedMediaType, prepared{}
	}
	if _, multiple := installer.(MultiInstaller); duplicateMediaType && !multiple {
		return artifactset.ResultRejected, artifactset.ReasonInstallRejected, prepared{}
	}
	segments := make([][]byte, 0, len(item.Segments))
	for _, segment := range item.Segments {
		data, err := executor.config.Objects.Get(segment.SHA256)
		switch {
		case errors.Is(err, objectstore.ErrNotFound):
			return artifactset.ResultPending, artifactset.ReasonObjectMissing, prepared{}
		case err != nil:
			return artifactset.ResultRejected, artifactset.ReasonSegmentMismatch, prepared{}
		}
		segments = append(segments, data)
	}
	compressed, err := item.Join(segments)
	if err != nil {
		return artifactset.ResultRejected, artifactset.ReasonSegmentMismatch, prepared{}
	}
	content := compressed
	if item.Compression == artifactset.CompressionZstd {
		content, err = decompress(compressed, item.Size)
		if err != nil {
			return artifactset.ResultRejected, artifactset.ReasonDecompressFailed, prepared{}
		}
	}
	if !item.CheckContent(content) {
		return artifactset.ResultRejected, artifactset.ReasonContentMismatch, prepared{}
	}
	staged, err := installer.Prepare(item, content, now)
	if err != nil {
		return artifactset.ResultRejected, artifactset.RejectReason(err), prepared{}
	}
	return artifactset.ResultApplied, "", prepared{item: item, staged: staged}
}

// unswitchedReceipt finishes a receipt for a set that was not applied:
// items that were fine are reported as not switched because of the others.
func (executor *Executor) unswitchedReceipt(receipt artifactset.Receipt, rejected bool) artifactset.Receipt {
	receipt.Result = artifactset.ResultPending
	if rejected {
		receipt.Result = artifactset.ResultRejected
	}
	for index := range receipt.Items {
		if receipt.Items[index].Result == artifactset.ResultApplied {
			receipt.Items[index].Result = receipt.Result
			receipt.Items[index].Reason = artifactset.ReasonSetRejected
		}
	}
	if executor.active != nil {
		receipt.ActiveRevision, receipt.ActiveSetSHA256 = executor.active.Revision, executor.active.SetSHA256
	}
	return receipt
}

func (executor *Executor) appliedReceipt(receipt artifactset.Receipt, set artifactset.Set) artifactset.Receipt {
	receipt.Result, receipt.ActiveRevision, receipt.ActiveSetSHA256 = artifactset.ResultApplied, set.Revision, receipt.SetSHA256
	receipt.Items = make([]artifactset.ItemResult, len(set.Items))
	for index, item := range set.Items {
		receipt.Items[index] = artifactset.ItemResult{ArtifactID: item.ArtifactID, Version: item.Version, SHA256: item.SHA256,
			Result: artifactset.ResultApplied}
	}
	return receipt
}

func (executor *Executor) activeHas(mediaType string) bool {
	if executor.active == nil {
		return false
	}
	for _, item := range executor.active.Items {
		if item.MediaType == mediaType {
			return true
		}
	}
	return false
}

func markItem(receipt *artifactset.Receipt, artifactID, result, reason string) {
	for index := range receipt.Items {
		if receipt.Items[index].ArtifactID == artifactID {
			receipt.Items[index].Result, receipt.Items[index].Reason = result, reason
		}
	}
}

func decompress(compressed []byte, size int64) ([]byte, error) {
	decoder, err := zstd.NewReader(nil, zstd.WithDecoderMaxMemory(uint64(artifactset.MaxItemBytes)))
	if err != nil {
		return nil, err
	}
	defer decoder.Close()
	if err := decoder.Reset(bytes.NewReader(compressed)); err != nil {
		return nil, err
	}
	content, err := io.ReadAll(io.LimitReader(decoder, size+1))
	if err != nil {
		return nil, err
	}
	return content, nil
}

func (executor *Executor) path() string { return filepath.Join(executor.config.StateDir, StateFile) }

func (executor *Executor) load() (*State, error) {
	encoded, err := os.ReadFile(executor.path())
	if errors.Is(err, os.ErrNotExist) {
		return nil, nil
	}
	if err != nil {
		return nil, fmt.Errorf("read node artifact set state: %w", err)
	}
	var state State
	if err := json.Unmarshal(encoded, &state); err != nil || state.Schema != StateSchema ||
		state.NodeID != executor.config.NodeID || state.Revision == 0 || !artifactset.ValidDigest(state.SetSHA256) {
		return nil, fmt.Errorf("%w: node artifact set state is corrupt", ErrInvalidConfig)
	}
	sort.Slice(state.Items, func(left, right int) bool { return state.Items[left].ArtifactID < state.Items[right].ArtifactID })
	return &state, nil
}

func (executor *Executor) store(state *State) error {
	encoded, err := json.Marshal(state)
	if err != nil {
		return err
	}
	temporary := executor.path() + ".tmp"
	file, err := os.OpenFile(temporary, os.O_CREATE|os.O_TRUNC|os.O_WRONLY, 0o600)
	if err != nil {
		return fmt.Errorf("write node artifact set state: %w", err)
	}
	_, writeErr := file.Write(encoded)
	if writeErr == nil {
		writeErr = file.Sync()
	}
	if closeErr := file.Close(); writeErr == nil {
		writeErr = closeErr
	}
	if writeErr == nil {
		writeErr = os.Rename(temporary, executor.path())
	}
	if writeErr != nil {
		_ = os.Remove(temporary)
		return fmt.Errorf("write node artifact set state: %w", writeErr)
	}
	directory, err := os.Open(executor.config.StateDir)
	if err != nil {
		return err
	}
	defer directory.Close()
	return directory.Sync()
}
