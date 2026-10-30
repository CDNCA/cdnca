package updater

import (
	"bytes"
	"context"
	"crypto/sha256"
	"encoding/base64"
	"encoding/hex"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"os"
	"path/filepath"
	"sort"
	"strconv"
	"strings"
	"sync"
	"syscall"
	"time"

	"github.com/google/uuid"
	"golang.org/x/sys/unix"
)

const (
	EdgeUpgradeCommandSchema  = "cdnca.edge.upgrade.command/v1"
	EdgeUpgradeStatusSchemaV1 = "cdnca.edge.upgrade.status/v1"
	EdgeUpgradeStatusSchemaV2 = "cdnca.edge.upgrade.status/v2"
	EdgeUpgradeStatusSchema   = EdgeUpgradeStatusSchemaV1

	upgradeWireStateVersion = 1
	maxUpgradeWireBytes     = 256 * 1024
)

var (
	ErrInvalidUpgradeCommand    = errors.New("invalid edge upgrade command")
	ErrUpgradeCommandConflict   = errors.New("edge upgrade command conflicts with durable state")
	ErrUpgradeCommandNotFound   = errors.New("edge upgrade command not found")
	ErrUpgradeCommandNotClaimed = errors.New("edge upgrade command has not been durably claimed")
	ErrInvalidUpgradeStatus     = errors.New("invalid edge upgrade status")
	ErrUpgradeStatusConflict    = errors.New("edge upgrade status conflicts with durable state")
	ErrUpgradeStatusAckMismatch = errors.New("edge upgrade status acknowledgement digest mismatch")
)

type EdgeUpgradeCommand struct {
	Schema                string `json:"schema"`
	CommandID             string `json:"command_id"`
	PlanID                string `json:"plan_id"`
	PlanRevision          uint64 `json:"plan_revision"`
	BatchID               string `json:"batch_id"`
	InstallationID        string `json:"installation_id"`
	NodeID                string `json:"node_id"`
	Action                string `json:"action"`
	SignedExecution       []byte `json:"signed_execution"`
	SignedExecutionSHA256 string `json:"signed_execution_sha256"`
}

type EdgeUpgradeState string

const (
	EdgeUpgradeStateAccepted    EdgeUpgradeState = "accepted"
	EdgeUpgradeStateClaimed     EdgeUpgradeState = "claimed"
	EdgeUpgradeStateInstalling  EdgeUpgradeState = "installing"
	EdgeUpgradeStateHealthy     EdgeUpgradeState = "healthy"
	EdgeUpgradeStateFailed      EdgeUpgradeState = "failed"
	EdgeUpgradeStateRollingBack EdgeUpgradeState = "rolling_back"
	EdgeUpgradeStateRolledBack  EdgeUpgradeState = "rolled_back"
	EdgeUpgradeStateUncertain   EdgeUpgradeState = "uncertain"
)

type EdgeUpgradeStatus struct {
	Schema                 string               `json:"schema"`
	StatusID               string               `json:"status_id"`
	StatusRevision         uint64               `json:"status_revision"`
	CommandID              string               `json:"command_id"`
	PlanID                 string               `json:"plan_id"`
	PlanRevision           uint64               `json:"plan_revision"`
	InstallationID         string               `json:"installation_id"`
	NodeID                 string               `json:"node_id"`
	CommandSHA256          string               `json:"command_sha256"`
	State                  EdgeUpgradeState     `json:"state"`
	CurrentVersion         string               `json:"current_version"`
	PreviousVersion        string               `json:"previous_version"`
	InstallerTransactionID string               `json:"installer_transaction_id"`
	ErrorCode              string               `json:"error_code"`
	AlertRequired          bool                 `json:"alert_required"`
	ObservedAt             time.Time            `json:"observed_at"`
	ActiveEvidence         *ActiveProbeEvidence `json:"active_evidence,omitempty"`
}

type edgeUpgradeStatusWireV1 struct {
	Schema                 string           `json:"schema"`
	StatusID               string           `json:"status_id"`
	StatusRevision         uint64           `json:"status_revision"`
	CommandID              string           `json:"command_id"`
	PlanID                 string           `json:"plan_id"`
	PlanRevision           uint64           `json:"plan_revision"`
	InstallationID         string           `json:"installation_id"`
	NodeID                 string           `json:"node_id"`
	CommandSHA256          string           `json:"command_sha256"`
	State                  EdgeUpgradeState `json:"state"`
	CurrentVersion         string           `json:"current_version"`
	PreviousVersion        string           `json:"previous_version"`
	InstallerTransactionID string           `json:"installer_transaction_id"`
	ErrorCode              string           `json:"error_code"`
	AlertRequired          bool             `json:"alert_required"`
	ObservedAt             time.Time        `json:"observed_at"`
}

type edgeUpgradeStatusWireV2 struct {
	edgeUpgradeStatusWireV1
	ActiveEvidence *ActiveProbeEvidence `json:"active_evidence"`
}

func (status EdgeUpgradeStatus) MarshalJSON() ([]byte, error) {
	wire := edgeUpgradeStatusWireV1{
		Schema: status.Schema, StatusID: status.StatusID, StatusRevision: status.StatusRevision,
		CommandID: status.CommandID, PlanID: status.PlanID, PlanRevision: status.PlanRevision,
		InstallationID: status.InstallationID, NodeID: status.NodeID, CommandSHA256: status.CommandSHA256,
		State: status.State, CurrentVersion: status.CurrentVersion, PreviousVersion: status.PreviousVersion,
		InstallerTransactionID: status.InstallerTransactionID, ErrorCode: status.ErrorCode,
		AlertRequired: status.AlertRequired, ObservedAt: status.ObservedAt,
	}
	if status.Schema == EdgeUpgradeStatusSchemaV2 {
		return json.Marshal(edgeUpgradeStatusWireV2{edgeUpgradeStatusWireV1: wire,
			ActiveEvidence: status.ActiveEvidence})
	}
	return json.Marshal(wire)
}

type AcceptedUpgradeCommand struct {
	Command   EdgeUpgradeCommand
	Encoded   []byte
	SHA256    string
	Duplicate bool
}

type ClaimedUpgradeCommand struct {
	AcceptedUpgradeCommand
	Plan Plan
}

type QueuedUpgradeStatus struct {
	Status    EdgeUpgradeStatus
	Encoded   []byte
	SHA256    string
	Duplicate bool
}

type UpgradeStatusAcknowledgement struct {
	StatusID          string
	CommandID         string
	StatusRevision    uint64
	StatusSHA256      string
	PersistedAt       time.Time
	PublishedStream   string
	PublishedSequence uint64
	Encoded           []byte
	SHA256            string
}

type DurableUpgradeStore struct {
	disk      *diskStore
	fs        *anchoredUpgradeFS
	wireDir   string
	inboxDir  string
	claimsDir string
	outboxDir string
	ackedDir  string
}

type anchoredUpgradeBinding struct {
	parent    *os.File
	name      string
	file      *os.File
	directory bool
}

type anchoredUpgradeFS struct {
	mu       sync.Mutex
	rootPath string
	root     *os.File
	state    *os.File
	staging  *os.File
	verified *os.File
	lockFile *os.File
	wire     *os.File
	inbox    *os.File
	claims   *os.File
	outbox   *os.File
	acked    *os.File
	bindings []anchoredUpgradeBinding
}

func newAnchoredUpgradeFS(disk *diskStore, withWire bool) (_ *anchoredUpgradeFS, resultErr error) {
	if disk == nil {
		return nil, ErrUnsafePath
	}
	fs := &anchoredUpgradeFS{rootPath: disk.root}
	defer func() {
		if resultErr != nil {
			fs.close()
		}
	}()
	var err error
	fs.root, err = openAnchoredDirectory(disk.root)
	if err != nil {
		return nil, err
	}
	if fs.state, err = fs.bindDirectory(fs.root, "state"); err != nil {
		return nil, err
	}
	if fs.staging, err = fs.bindDirectory(fs.root, "staging"); err != nil {
		return nil, err
	}
	if fs.verified, err = fs.bindDirectory(fs.staging, "verified"); err != nil {
		return nil, err
	}
	if fs.lockFile, err = fs.bindLock(fs.state, "upgrade.lock"); err != nil {
		return nil, err
	}
	if withWire {
		if fs.wire, err = fs.bindDirectory(fs.state, "upgrade-wire-v1"); err != nil {
			return nil, err
		}
		if fs.inbox, err = fs.bindDirectory(fs.wire, "inbox"); err != nil {
			return nil, err
		}
		if fs.claims, err = fs.bindDirectory(fs.wire, "claims"); err != nil {
			return nil, err
		}
		if fs.outbox, err = fs.bindDirectory(fs.wire, "outbox"); err != nil {
			return nil, err
		}
		if fs.acked, err = fs.bindDirectory(fs.wire, "acked"); err != nil {
			return nil, err
		}
	}
	if err := fs.validateBindings(); err != nil {
		return nil, err
	}
	return fs, nil
}

func openAnchoredDirectory(path string) (*os.File, error) {
	fd, err := unix.Open(path, unix.O_RDONLY|unix.O_DIRECTORY|unix.O_CLOEXEC|unix.O_NOFOLLOW, 0)
	if err != nil {
		return nil, fmt.Errorf("%w: open updater directory: %v", ErrUnsafePath, err)
	}
	file := os.NewFile(uintptr(fd), path)
	if err := validateAnchoredDirectory(file); err != nil {
		_ = file.Close()
		return nil, err
	}
	return file, nil
}

func openAnchoredDirectoryAt(parent *os.File, name string) (*os.File, error) {
	if parent == nil || filepath.Base(name) != name || name == "." || name == ".." {
		return nil, ErrUnsafePath
	}
	fd, err := unix.Openat(int(parent.Fd()), name, unix.O_RDONLY|unix.O_DIRECTORY|unix.O_CLOEXEC|unix.O_NOFOLLOW, 0)
	if err != nil {
		return nil, fmt.Errorf("%w: open updater directory: %v", ErrUnsafePath, err)
	}
	file := os.NewFile(uintptr(fd), name)
	if err := validateAnchoredDirectory(file); err != nil {
		_ = file.Close()
		return nil, err
	}
	return file, nil
}

func validateAnchoredDirectory(file *os.File) error {
	if file == nil {
		return ErrUnsafePath
	}
	info, err := file.Stat()
	if err != nil || !info.IsDir() || info.Mode().Perm()&0o022 != 0 {
		return fmt.Errorf("%w: untrusted updater directory", ErrUnsafePath)
	}
	return nil
}

func (fs *anchoredUpgradeFS) bindDirectory(parent *os.File, name string) (*os.File, error) {
	file, err := openAnchoredDirectoryAt(parent, name)
	if err != nil {
		return nil, err
	}
	fs.bindings = append(fs.bindings, anchoredUpgradeBinding{parent: parent, name: name, file: file, directory: true})
	return file, nil
}

func (fs *anchoredUpgradeFS) bindLock(parent *os.File, name string) (*os.File, error) {
	fd, err := unix.Openat(int(parent.Fd()), name, unix.O_RDWR|unix.O_CREAT|unix.O_CLOEXEC|unix.O_NOFOLLOW, 0o600)
	if err != nil {
		return nil, fmt.Errorf("%w: open updater lock: %v", ErrUnsafePath, err)
	}
	file := os.NewFile(uintptr(fd), name)
	if err := validateAnchoredRegular(file, -1, false); err != nil {
		_ = file.Close()
		return nil, err
	}
	fs.bindings = append(fs.bindings, anchoredUpgradeBinding{parent: parent, name: name, file: file})
	return file, nil
}

func (fs *anchoredUpgradeFS) close() {
	seen := make(map[*os.File]struct{})
	for _, file := range []*os.File{fs.acked, fs.outbox, fs.claims, fs.inbox, fs.wire, fs.lockFile, fs.verified, fs.staging, fs.state, fs.root} {
		if file != nil {
			if _, found := seen[file]; !found {
				_ = file.Close()
				seen[file] = struct{}{}
			}
		}
	}
}

func (fs *anchoredUpgradeFS) validateBindings() error {
	rootInfo, err := fs.root.Stat()
	pathInfo, pathErr := os.Lstat(fs.rootPath)
	if err != nil || pathErr != nil || pathInfo.Mode()&os.ModeSymlink != 0 || !pathInfo.IsDir() || !os.SameFile(rootInfo, pathInfo) {
		return fmt.Errorf("%w: updater root changed", ErrUnsafePath)
	}
	for _, binding := range fs.bindings {
		flags := unix.O_RDONLY | unix.O_CLOEXEC | unix.O_NOFOLLOW
		if binding.directory {
			flags |= unix.O_DIRECTORY
		}
		fd, openErr := unix.Openat(int(binding.parent.Fd()), binding.name, flags, 0)
		if openErr != nil {
			return fmt.Errorf("%w: updater binding changed", ErrUnsafePath)
		}
		candidate := os.NewFile(uintptr(fd), binding.name)
		candidateInfo, candidateErr := candidate.Stat()
		boundInfo, boundErr := binding.file.Stat()
		_ = candidate.Close()
		if candidateErr != nil || boundErr != nil || !os.SameFile(candidateInfo, boundInfo) {
			return fmt.Errorf("%w: updater binding changed", ErrUnsafePath)
		}
		if binding.directory {
			if !candidateInfo.IsDir() || candidateInfo.Mode().Perm()&0o022 != 0 {
				return fmt.Errorf("%w: untrusted updater directory", ErrUnsafePath)
			}
		} else if !candidateInfo.Mode().IsRegular() {
			return fmt.Errorf("%w: updater lock changed", ErrUnsafePath)
		}
		if !binding.directory {
			if count, ok := regularLinkCount(candidateInfo.Sys()); !ok || count != 1 {
				return fmt.Errorf("%w: updater lock link count", ErrUnsafePath)
			}
		}
	}
	return nil
}

func (fs *anchoredUpgradeFS) ready() bool {
	if fs == nil {
		return false
	}
	fs.mu.Lock()
	defer fs.mu.Unlock()
	return fs.validateBindings() == nil
}

func (fs *anchoredUpgradeFS) lock(ctx context.Context) (func(), error) {
	if fs == nil || ctx == nil {
		return nil, ErrUnsafePath
	}
	fs.mu.Lock()
	if err := ctx.Err(); err != nil {
		fs.mu.Unlock()
		return nil, err
	}
	if err := fs.validateBindings(); err != nil {
		fs.mu.Unlock()
		return nil, err
	}
	ticker := time.NewTicker(10 * time.Millisecond)
	defer ticker.Stop()
	for {
		if err := syscall.Flock(int(fs.lockFile.Fd()), syscall.LOCK_EX|syscall.LOCK_NB); err == nil {
			return func() {
				_ = syscall.Flock(int(fs.lockFile.Fd()), syscall.LOCK_UN)
				fs.mu.Unlock()
			}, nil
		} else if !errors.Is(err, syscall.EWOULDBLOCK) && !errors.Is(err, syscall.EAGAIN) {
			fs.mu.Unlock()
			return nil, fmt.Errorf("lock updater state: %w", err)
		}
		select {
		case <-ctx.Done():
			fs.mu.Unlock()
			return nil, ctx.Err()
		case <-ticker.C:
		}
	}
}

func validateAnchoredRegular(file *os.File, maximum int64, nonempty bool) error {
	if file == nil {
		return ErrCorruptState
	}
	info, err := file.Stat()
	if err != nil || !info.Mode().IsRegular() || maximum >= 0 && info.Size() > maximum || nonempty && info.Size() <= 0 {
		return ErrCorruptState
	}
	if count, ok := regularLinkCount(info.Sys()); !ok || count != 1 {
		return ErrCorruptState
	}
	return nil
}

func (fs *anchoredUpgradeFS) readBytesAt(directory *os.File, name string, maximum int64) ([]byte, bool, error) {
	if directory == nil || filepath.Base(name) != name || strings.HasPrefix(name, ".") {
		return nil, false, ErrCorruptState
	}
	fd, err := unix.Openat(int(directory.Fd()), name, unix.O_RDONLY|unix.O_CLOEXEC|unix.O_NOFOLLOW, 0)
	if errors.Is(err, unix.ENOENT) {
		return nil, false, nil
	}
	if err != nil {
		return nil, false, ErrCorruptState
	}
	file := os.NewFile(uintptr(fd), name)
	defer file.Close()
	if err := validateAnchoredRegular(file, maximum, true); err != nil {
		return nil, false, err
	}
	info, _ := file.Stat()
	encoded, err := io.ReadAll(io.LimitReader(file, maximum+1))
	if err != nil || int64(len(encoded)) != info.Size() {
		return nil, false, ErrCorruptState
	}
	return encoded, true, nil
}

func (fs *anchoredUpgradeFS) readJSONAt(directory *os.File, name string, destination any) (bool, error) {
	encoded, found, err := fs.readBytesAt(directory, name, maxStateFileSize)
	if err != nil || !found {
		return found, err
	}
	decoder := json.NewDecoder(bytes.NewReader(encoded))
	decoder.DisallowUnknownFields()
	if err := decoder.Decode(destination); err != nil {
		return false, ErrCorruptState
	}
	var extra any
	if err := decoder.Decode(&extra); !errors.Is(err, io.EOF) {
		return false, ErrCorruptState
	}
	return true, nil
}

func (fs *anchoredUpgradeFS) writeBytesAt(directory *os.File, name string, encoded []byte, maximum int) error {
	if directory == nil || filepath.Base(name) != name || strings.HasPrefix(name, ".") || len(encoded) == 0 || len(encoded) > maximum {
		return ErrCorruptState
	}
	temporary := ".anchor-" + randomSuffix()
	fd, err := unix.Openat(int(directory.Fd()), temporary, unix.O_WRONLY|unix.O_CREAT|unix.O_EXCL|unix.O_CLOEXEC|unix.O_NOFOLLOW, 0o600)
	if err != nil {
		return fmt.Errorf("create anchored updater state: %w", err)
	}
	file := os.NewFile(uintptr(fd), temporary)
	ok := false
	defer func() {
		_ = file.Close()
		if !ok {
			_ = unix.Unlinkat(int(directory.Fd()), temporary, 0)
		}
	}()
	if _, err := file.Write(encoded); err != nil {
		return fmt.Errorf("write anchored updater state: %w", err)
	}
	if err := file.Sync(); err != nil {
		return fmt.Errorf("sync anchored updater state: %w", err)
	}
	if err := file.Close(); err != nil {
		return fmt.Errorf("close anchored updater state: %w", err)
	}
	if err := unix.Renameat(int(directory.Fd()), temporary, int(directory.Fd()), name); err != nil {
		return fmt.Errorf("publish anchored updater state: %w", err)
	}
	ok = true
	return directory.Sync()
}

func (fs *anchoredUpgradeFS) writeJSONAt(directory *os.File, name string, value any) error {
	encoded, err := json.Marshal(value)
	if err != nil {
		return ErrCorruptState
	}
	return fs.writeBytesAt(directory, name, encoded, maxStateFileSize)
}

func (fs *anchoredUpgradeFS) jsonNamesAt(directory *os.File) ([]string, error) {
	if directory == nil {
		return nil, ErrCorruptState
	}
	fd, err := unix.Openat(int(directory.Fd()), ".", unix.O_RDONLY|unix.O_DIRECTORY|unix.O_CLOEXEC, 0)
	if err != nil {
		return nil, err
	}
	copy := os.NewFile(uintptr(fd), directory.Name())
	entries, err := copy.ReadDir(-1)
	_ = copy.Close()
	if err != nil {
		return nil, err
	}
	names := make([]string, 0, len(entries))
	for _, entry := range entries {
		if strings.HasPrefix(entry.Name(), ".") {
			continue
		}
		id := strings.TrimSuffix(entry.Name(), ".json")
		if id == entry.Name() || !validUpgradeExecutionUUID(id) {
			return nil, ErrCorruptState
		}
		fd, openErr := unix.Openat(int(directory.Fd()), entry.Name(), unix.O_RDONLY|unix.O_CLOEXEC|unix.O_NOFOLLOW, 0)
		if openErr != nil {
			return nil, ErrCorruptState
		}
		file := os.NewFile(uintptr(fd), entry.Name())
		validErr := validateAnchoredRegular(file, maxStateFileSize, true)
		_ = file.Close()
		if validErr != nil {
			return nil, ErrCorruptState
		}
		names = append(names, entry.Name())
	}
	sort.Strings(names)
	return names, nil
}

func (fs *anchoredUpgradeFS) loadTransaction() (*transaction, error) {
	var value transaction
	found, err := fs.readJSONAt(fs.state, "transaction.json", &value)
	if err != nil || !found {
		return nil, err
	}
	if value.Version != stateVersion || value.Digest == "" || value.Plan.PlanID == "" ||
		!safeIDPattern.MatchString(value.InstallerTransactionID) ||
		(value.PreparedInstall != nil && !preparedInstallMatchesTransaction(*value.PreparedInstall, &value)) ||
		value.ActivationAttempts < 0 || value.ActivationAttempts > maxInstallerActivationAttempts ||
		value.ActivationAttempts != 0 && value.PreparedInstall == nil ||
		(value.Phase != phaseDownload && value.Phase != phaseInstall && value.Phase != phaseObserve &&
			value.Phase != phaseRollback && value.Phase != phaseDone) {
		return nil, ErrCorruptState
	}
	digest, digestErr := planDigest(value.Plan)
	if digestErr != nil || value.Digest != digest {
		return nil, ErrCorruptState
	}
	return &value, nil
}

func (fs *anchoredUpgradeFS) saveTransaction(value *transaction) error {
	if value == nil {
		return ErrCorruptState
	}
	return fs.writeJSONAt(fs.state, "transaction.json", value)
}

func (fs *anchoredUpgradeFS) removeTreeAt(parent *os.File, name string) error {
	var stat unix.Stat_t
	if err := unix.Fstatat(int(parent.Fd()), name, &stat, unix.AT_SYMLINK_NOFOLLOW); errors.Is(err, unix.ENOENT) {
		return nil
	} else if err != nil || stat.Mode&unix.S_IFMT != unix.S_IFDIR {
		return ErrUnsafePath
	}
	directory, err := openAnchoredDirectoryAt(parent, name)
	if err != nil {
		return err
	}
	entries, err := directory.ReadDir(-1)
	if err != nil {
		_ = directory.Close()
		return err
	}
	for _, entry := range entries {
		var child unix.Stat_t
		if err := unix.Fstatat(int(directory.Fd()), entry.Name(), &child, unix.AT_SYMLINK_NOFOLLOW); err != nil {
			_ = directory.Close()
			return err
		}
		switch child.Mode & unix.S_IFMT {
		case unix.S_IFDIR:
			if err := fs.removeTreeAt(directory, entry.Name()); err != nil {
				_ = directory.Close()
				return err
			}
		case unix.S_IFREG:
			if child.Nlink != 1 {
				_ = directory.Close()
				return ErrUnsafePath
			}
			if err := unix.Unlinkat(int(directory.Fd()), entry.Name(), 0); err != nil {
				_ = directory.Close()
				return err
			}
		default:
			_ = directory.Close()
			return ErrUnsafePath
		}
	}
	if err := directory.Close(); err != nil {
		return err
	}
	if err := unix.Unlinkat(int(parent.Fd()), name, unix.AT_REMOVEDIR); err != nil {
		return err
	}
	return parent.Sync()
}

func (fs *anchoredUpgradeFS) prepareStaging(planID string) (*os.File, string, error) {
	if !safeIDPattern.MatchString(planID) {
		return nil, "", ErrUnsafePath
	}
	name := "pending-" + planID
	if err := fs.removeTreeAt(fs.staging, name); err != nil {
		return nil, "", err
	}
	if err := unix.Mkdirat(int(fs.staging.Fd()), name, 0o700); err != nil {
		return nil, "", fmt.Errorf("create artifact staging directory: %w", err)
	}
	if err := fs.staging.Sync(); err != nil {
		return nil, "", err
	}
	directory, err := openAnchoredDirectoryAt(fs.staging, name)
	if err != nil {
		return nil, "", err
	}
	fd, err := unix.Openat(int(directory.Fd()), "artifact", unix.O_WRONLY|unix.O_CREAT|unix.O_EXCL|unix.O_CLOEXEC|unix.O_NOFOLLOW, 0o600)
	_ = directory.Close()
	if err != nil {
		return nil, "", fmt.Errorf("create staged artifact: %w", err)
	}
	return os.NewFile(uintptr(fd), "artifact"), filepath.Join(fs.rootPath, "staging", name, "artifact"), nil
}

func (fs *anchoredUpgradeFS) openArtifactAt(directory *os.File, expectedSize int64) (*os.File, error) {
	fd, err := unix.Openat(int(directory.Fd()), "artifact", unix.O_RDONLY|unix.O_CLOEXEC|unix.O_NOFOLLOW, 0)
	if err != nil {
		return nil, ErrArtifactIntegrity
	}
	file := os.NewFile(uintptr(fd), "artifact")
	if err := validateAnchoredRegular(file, expectedSize, expectedSize > 0); err != nil {
		_ = file.Close()
		return nil, ErrArtifactIntegrity
	}
	info, _ := file.Stat()
	if info.Size() != expectedSize {
		_ = file.Close()
		return nil, ErrArtifactIntegrity
	}
	return file, nil
}

func (fs *anchoredUpgradeFS) verifiedArtifact(digest string, expectedSize int64) (string, error) {
	file, path, err := fs.openVerified(digest, expectedSize)
	if file != nil {
		_ = file.Close()
	}
	return path, err
}

func (fs *anchoredUpgradeFS) openVerified(digest string, expectedSize int64) (*os.File, string, error) {
	if !validDigest(digest) {
		return nil, "", ErrUnsafePath
	}
	directory, err := openAnchoredDirectoryAt(fs.verified, digest)
	if err != nil {
		return nil, "", ErrUnsafePath
	}
	defer directory.Close()
	file, err := fs.openArtifactAt(directory, expectedSize)
	if err != nil {
		return nil, "", err
	}
	hash := sha256.New()
	size, err := io.Copy(hash, file)
	if err != nil || size != expectedSize || hex.EncodeToString(hash.Sum(nil)) != digest {
		_ = file.Close()
		return nil, "", ErrArtifactIntegrity
	}
	if _, err := file.Seek(0, io.SeekStart); err != nil {
		_ = file.Close()
		return nil, "", ErrArtifactIntegrity
	}
	return file, filepath.Join(fs.rootPath, "staging", "verified", digest, "artifact"), nil
}

func (fs *anchoredUpgradeFS) commitStaging(planID, path, digest string, expectedSize int64) (string, error) {
	name := "pending-" + planID
	if !safeIDPattern.MatchString(planID) || !validDigest(digest) ||
		path != filepath.Join(fs.rootPath, "staging", name, "artifact") {
		return "", ErrUnsafePath
	}
	pending, err := openAnchoredDirectoryAt(fs.staging, name)
	if err != nil {
		return "", err
	}
	artifact, err := fs.openArtifactAt(pending, expectedSize)
	if err != nil {
		_ = pending.Close()
		return "", err
	}
	if err := artifact.Chmod(0o400); err != nil {
		_ = artifact.Close()
		_ = pending.Close()
		return "", fmt.Errorf("protect staged artifact: %w", err)
	}
	if err := artifact.Sync(); err != nil {
		_ = artifact.Close()
		_ = pending.Close()
		return "", err
	}
	_ = artifact.Close()
	if err := pending.Sync(); err != nil {
		_ = pending.Close()
		return "", err
	}
	_ = pending.Close()
	if existing, openErr := openAnchoredDirectoryAt(fs.verified, digest); openErr == nil {
		_ = existing.Close()
		verified, verifyErr := fs.verifiedArtifact(digest, expectedSize)
		if verifyErr != nil {
			return "", verifyErr
		}
		if err := fs.removeTreeAt(fs.staging, name); err != nil {
			return "", err
		}
		return verified, nil
	}
	if err := unix.Renameat(int(fs.staging.Fd()), name, int(fs.verified.Fd()), digest); err != nil {
		return "", fmt.Errorf("publish verified artifact: %w", err)
	}
	if err := fs.staging.Sync(); err != nil {
		return "", err
	}
	if err := fs.verified.Sync(); err != nil {
		return "", err
	}
	return fs.verifiedArtifact(digest, expectedSize)
}

func (fs *anchoredUpgradeFS) availableDiskBytes() (uint64, error) {
	var status unix.Statfs_t
	if err := unix.Fstatfs(int(fs.root.Fd()), &status); err != nil {
		return 0, fmt.Errorf("inspect updater disk capacity: %w", err)
	}
	return uint64(status.Bavail) * uint64(status.Bsize), nil
}

type UpgradeRuntimeConfig struct {
	// DownloadPolicy, when set, adopts the control-signed download policy of
	// each verified execution before it is accepted (fix-btenv3).
	DownloadPolicy *PolicyDownloader
	Store          *DurableUpgradeStore
	Manager        upgradeManager
	Options        UpgradeExecutionConsumerOptions
	Now            func() time.Time
}

type UpgradeRuntime struct {
	store    *DurableUpgradeStore
	manager  upgradeManager
	options  UpgradeExecutionConsumerOptions
	now      func() time.Time
	download *PolicyDownloader
}

type upgradeManager interface {
	prepare(context.Context, Plan) (preparedUpgrade, error)
	beginInstall(context.Context, string) (bool, error)
	processPrepared(context.Context, Plan, string) (Result, error)
	pendingTransaction(context.Context) (Plan, string, bool, error)
}

func NewUpgradeRuntime(config UpgradeRuntimeConfig) (*UpgradeRuntime, error) {
	if config.Store == nil || config.Manager == nil || config.Options.ExpectedInstallationID == "" ||
		config.Options.ExpectedNodeID == "" || len(config.Options.ControlKeys) == 0 || len(config.Options.EdgeKeys) == 0 ||
		config.Store.fs == nil || !config.Store.fs.ready() {
		return nil, ErrInvalidUpgradeCommand
	}
	if config.Now == nil {
		config.Now = time.Now
	}
	config.Options.RequireV2 = true
	return &UpgradeRuntime{store: config.Store, manager: config.Manager, options: config.Options, now: config.Now,
		download: config.DownloadPolicy}, nil
}

func (r *UpgradeRuntime) Ready() bool {
	return r != nil && r.store != nil && r.manager != nil && r.store.fs != nil && r.store.fs.ready()
}

func (r *UpgradeRuntime) AcceptCommand(ctx context.Context, encoded []byte) error {
	if !r.Ready() || ctx == nil {
		return ErrInvalidUpgradeCommand
	}
	frozen := append([]byte(nil), encoded...)
	command, err := decodeEdgeUpgradeCommand(frozen)
	if err != nil {
		return err
	}
	options, err := r.verificationOptions(command)
	if err != nil {
		return err
	}
	options.Now = r.now().UTC()
	envelope, _, err := verifyUpgradeExecution(command.SignedExecution, options)
	if err != nil {
		return err
	}
	// The control plane's current endpoint, authenticated by the control
	// signature just verified; the download below uses it.
	if _, err := r.download.Adopt(envelope.Execution.DownloadPolicy, envelope.Execution.DownloadURL,
		envelope.Execution.IssuedAt); err != nil {
		return err
	}
	accepted, err := r.store.AcceptCommand(ctx, frozen)
	if err != nil {
		return err
	}
	if err := r.ensureAcceptedStatus(ctx, accepted); err != nil {
		return err
	}
	return nil
}

func (r *UpgradeRuntime) Recover(ctx context.Context) error {
	if !r.Ready() || ctx == nil {
		return ErrInvalidUpgradeCommand
	}
	commands, err := r.store.PendingCommands(ctx)
	if err != nil {
		return err
	}
	for _, command := range commands {
		if err := r.ensureAcceptedStatus(ctx, command); err != nil {
			return err
		}
		acknowledged, err := r.store.acceptedStatusAcknowledged(ctx, command.Command.CommandID)
		if err != nil {
			return err
		}
		if !acknowledged {
			continue
		}
		last, found, err := r.store.LastStatus(ctx, command.Command.CommandID)
		if err != nil {
			return err
		}
		if found && terminalUpgradeState(last.State) {
			continue
		}
		if err := r.processCommand(ctx, command); err != nil {
			return err
		}
	}
	return nil
}

func (r *UpgradeRuntime) PendingStatuses(ctx context.Context) ([]QueuedUpgradeStatus, error) {
	if !r.Ready() || ctx == nil {
		return nil, ErrInvalidUpgradeStatus
	}
	return r.store.PendingStatuses(ctx)
}

func (r *UpgradeRuntime) AcknowledgeStatus(ctx context.Context, statusID, commandID, digest string) (bool, error) {
	if !r.Ready() || ctx == nil || !validUpgradeExecutionUUID(commandID) {
		return false, ErrUpgradeStatusAckMismatch
	}
	return r.store.acknowledgeStatus(ctx, statusID, commandID, digest)
}

// AcknowledgeStatusWithPublication persists a status acknowledgement only when
// the caller supplies the verified Gateway publication identity and exact ack wire.
func (r *UpgradeRuntime) AcknowledgeStatusWithPublication(ctx context.Context, acknowledgement UpgradeStatusAcknowledgement) (bool, error) {
	if !r.Ready() || ctx == nil {
		return false, ErrUpgradeStatusAckMismatch
	}
	return r.store.AcknowledgeStatusWithPublication(ctx, acknowledgement)
}

func (r *UpgradeRuntime) InstallerProtocolVersion() int {
	if r == nil {
		return 0
	}
	if manager, ok := r.manager.(*Manager); ok {
		return manager.installerProtocolVersion()
	}
	return 0
}

func (r *UpgradeRuntime) StatusAcknowledgementReceiptsEnabled() bool {
	return r != nil && r.Ready()
}

func (r *UpgradeRuntime) PendingStatusAcknowledgements(ctx context.Context) ([]UpgradeStatusAcknowledgement, error) {
	if !r.Ready() || ctx == nil {
		return nil, ErrUpgradeStatusAckMismatch
	}
	return r.store.PendingStatusAcknowledgements(ctx)
}

func (r *UpgradeRuntime) PersistStatusAcknowledgement(ctx context.Context, acknowledgement UpgradeStatusAcknowledgement) (bool, error) {
	if !r.Ready() || ctx == nil {
		return false, ErrUpgradeStatusAckMismatch
	}
	return r.store.PersistStatusAcknowledgement(ctx, acknowledgement)
}

func (r *UpgradeRuntime) ConfirmStatusAcknowledgement(ctx context.Context, acknowledgement UpgradeStatusAcknowledgement) (bool, error) {
	if !r.Ready() || ctx == nil {
		return false, ErrUpgradeStatusAckMismatch
	}
	return r.store.ConfirmStatusAcknowledgement(ctx, acknowledgement)
}

func (r *UpgradeRuntime) ensureAcceptedStatus(ctx context.Context, command AcceptedUpgradeCommand) error {
	_, found, err := r.store.LastStatus(ctx, command.Command.CommandID)
	if err != nil {
		return err
	}
	if found {
		return nil
	}
	return r.emitStatus(ctx, command, EdgeUpgradeStateAccepted, Result{}, "")
}

func (r *UpgradeRuntime) processCommand(ctx context.Context, command AcceptedUpgradeCommand) error {
	last, found, err := r.store.LastStatus(ctx, command.Command.CommandID)
	if err != nil {
		return err
	}
	if found && terminalUpgradeState(last.State) {
		return nil
	}
	options, err := r.verificationOptions(command.Command)
	if err != nil {
		return err
	}
	options.Now = r.now().UTC()
	claimed, err := r.store.ResumeClaimedCommand(ctx, command.Command.CommandID, options)
	if errors.Is(err, ErrUpgradeCommandNotClaimed) {
		claimed, err = r.store.ClaimCommand(ctx, command.Command.CommandID, options)
	}
	if err != nil {
		return err
	}
	if !found || last.State == EdgeUpgradeStateAccepted {
		if err := r.emitStatus(ctx, command, EdgeUpgradeStateClaimed, Result{}, ""); err != nil {
			return err
		}
		last.State = EdgeUpgradeStateClaimed
	}
	prepared, prepareErr := r.manager.prepare(ctx, claimed.Plan)
	if prepareErr != nil {
		return prepareErr
	}
	if prepared.Complete {
		if last.State == EdgeUpgradeStateClaimed {
			return ErrUpgradeStatusConflict
		}
		result := normalizeUpgradeResult(command.Command.Action, prepared.Result)
		for _, state := range upgradeResultStates(command.Command.Action, result,
			last.State == EdgeUpgradeStateUncertain || last.State == EdgeUpgradeStateRollingBack) {
			if err := r.emitStatus(ctx, command, state, result, result.ErrorCode); err != nil {
				return err
			}
		}
		return nil
	}
	if last.State == EdgeUpgradeStateClaimed {
		durable, beginErr := r.manager.beginInstall(ctx, prepared.InstallerTransactionID)
		if beginErr != nil && !errors.Is(beginErr, ErrInstallerLegacyActivated) {
			return beginErr
		}
		if beginErr == nil && !durable {
			return ErrInstallerUncertain
		}
		if !errors.Is(beginErr, ErrInstallerLegacyActivated) {
			if err := r.emitStatus(ctx, command, EdgeUpgradeStateInstalling,
				Result{InstallerTransactionID: prepared.InstallerTransactionID}, ""); err != nil {
				return err
			}
		}
	}
	result, processErr := r.manager.processPrepared(ctx, claimed.Plan, prepared.InstallerTransactionID)
	if processErr != nil && result.State == "" {
		_, transactionID, _, pendingErr := r.manager.pendingTransaction(ctx)
		if pendingErr != nil {
			return pendingErr
		}
		result.InstallerTransactionID = transactionID
		result.AlertRequired = true
		if err := r.emitStatus(ctx, command, EdgeUpgradeStateUncertain, result, upgradeErrorCode(processErr)); err != nil {
			return err
		}
		return processErr
	}
	result = normalizeUpgradeResult(command.Command.Action, result)
	for _, state := range upgradeResultStates(command.Command.Action, result,
		last.State == EdgeUpgradeStateUncertain || last.State == EdgeUpgradeStateRollingBack) {
		if err := r.emitStatus(ctx, command, state, result, result.ErrorCode); err != nil {
			return err
		}
	}
	return processErr
}

func (r *UpgradeRuntime) verificationOptions(command EdgeUpgradeCommand) (UpgradeExecutionConsumerOptions, error) {
	envelope, err := decodeUpgradeExecution(command.SignedExecution)
	if err != nil {
		return UpgradeExecutionConsumerOptions{}, err
	}
	options := r.options
	options.ExpectedCommandID = command.CommandID
	options.ExpectedNonce = envelope.Execution.Nonce
	options.ExpectedCurrentVersion = envelope.Execution.CurrentVersion
	options.ExpectedTargetVersion = envelope.Execution.TargetVersion
	options.ExpectedPlanID = command.PlanID
	options.ExpectedPlanRevision = command.PlanRevision
	options.ExpectedBatchID = command.BatchID
	return options, nil
}

func (r *UpgradeRuntime) emitStatus(ctx context.Context, command AcceptedUpgradeCommand, state EdgeUpgradeState,
	result Result, errorCode string) error {
	last, found, err := r.store.LastStatus(ctx, command.Command.CommandID)
	if err != nil {
		return err
	}
	revision := uint64(1)
	if found {
		revision = last.StatusRevision + 1
	}
	statusID, err := upgradeStatusID(command.Command.CommandID, revision)
	if err != nil {
		return err
	}
	var activeEvidence *ActiveProbeEvidence
	if state == EdgeUpgradeStateHealthy || state == EdgeUpgradeStateRolledBack {
		activeEvidence = cloneActiveProbeEvidence(result.ActiveEvidence)
	}
	status := EdgeUpgradeStatus{
		Schema: EdgeUpgradeStatusSchemaV2, StatusID: statusID, StatusRevision: revision,
		CommandID: command.Command.CommandID, PlanID: command.Command.PlanID, PlanRevision: command.Command.PlanRevision,
		InstallationID: command.Command.InstallationID, NodeID: command.Command.NodeID, CommandSHA256: command.SHA256,
		State: state, CurrentVersion: result.CurrentVersion, PreviousVersion: result.PreviousVersion,
		InstallerTransactionID: result.InstallerTransactionID, ErrorCode: errorCode,
		AlertRequired: result.AlertRequired, ObservedAt: r.now().UTC().Truncate(time.Microsecond),
		ActiveEvidence: activeEvidence,
	}
	if found && sameUpgradeStatusFacts(last, status) {
		return nil
	}
	encoded, err := json.Marshal(status)
	if err != nil {
		return err
	}
	if found && last.State == EdgeUpgradeStateUncertain {
		_, err = r.store.ReconcileStatus(ctx, encoded)
	} else {
		_, err = r.store.EnqueueStatus(ctx, encoded)
	}
	return err
}

func (s *DurableUpgradeStore) LastStatus(ctx context.Context, commandID string) (EdgeUpgradeStatus, bool, error) {
	if !validUpgradeExecutionUUID(commandID) {
		return EdgeUpgradeStatus{}, false, ErrInvalidUpgradeStatus
	}
	unlock, err := s.lock(ctx)
	if err != nil {
		return EdgeUpgradeStatus{}, false, err
	}
	defer unlock()
	history, err := s.statusHistoryLocked(commandID)
	if err != nil || len(history) == 0 {
		return EdgeUpgradeStatus{}, false, err
	}
	encoded, found, err := s.fs.readBytesAt(s.fs.outbox, statusFileName(history[len(history)-1].StatusID), maxUpgradeWireBytes)
	if err != nil || !found {
		return EdgeUpgradeStatus{}, false, ErrCorruptState
	}
	status, err := decodeEdgeUpgradeStatus(encoded)
	if err != nil {
		return EdgeUpgradeStatus{}, false, ErrCorruptState
	}
	return status, true, nil
}

func upgradeStatusID(commandID string, revision uint64) (string, error) {
	command, err := uuid.Parse(commandID)
	if err != nil || command == uuid.Nil || revision == 0 {
		return "", ErrInvalidUpgradeStatus
	}
	return uuid.NewSHA1(command, []byte(strconv.FormatUint(revision, 10))).String(), nil
}

func upgradeResultStates(action string, result Result, reconciling bool) []EdgeUpgradeState {
	if result.State == StateFailed && result.ErrorCode == "ROLLBACK_FAILED" {
		return []EdgeUpgradeState{EdgeUpgradeStateUncertain}
	}
	switch result.State {
	case StateSucceeded:
		switch action {
		case string(ActionUpgrade):
			return []EdgeUpgradeState{EdgeUpgradeStateHealthy}
		case string(ActionRollback):
			return []EdgeUpgradeState{EdgeUpgradeStateRolledBack}
		default:
			return nil
		}
	case StateRolledBack:
		if action == string(ActionRollback) {
			return []EdgeUpgradeState{EdgeUpgradeStateFailed}
		}
		if action == string(ActionUpgrade) && reconciling {
			return []EdgeUpgradeState{EdgeUpgradeStateRolledBack}
		}
		return []EdgeUpgradeState{EdgeUpgradeStateRollingBack, EdgeUpgradeStateRolledBack}
	case StateFailed:
		return []EdgeUpgradeState{EdgeUpgradeStateFailed}
	default:
		return nil
	}
}

func normalizeUpgradeResult(action string, result Result) Result {
	if action == string(ActionRollback) && result.State == StateRolledBack {
		result.AlertRequired = true
	}
	return result
}

func sameUpgradeStatusFacts(left, right EdgeUpgradeStatus) bool {
	return left.State == right.State && left.CurrentVersion == right.CurrentVersion &&
		left.PreviousVersion == right.PreviousVersion &&
		left.InstallerTransactionID == right.InstallerTransactionID &&
		left.ErrorCode == right.ErrorCode && left.AlertRequired == right.AlertRequired &&
		sameActiveProbeEvidence(left.ActiveEvidence, right.ActiveEvidence)
}

func sameActiveProbeEvidence(left, right *ActiveProbeEvidence) bool {
	return left == nil && right == nil || left != nil && right != nil && *left == *right
}

func terminalUpgradeState(state EdgeUpgradeState) bool {
	return state == EdgeUpgradeStateHealthy || state == EdgeUpgradeStateFailed || state == EdgeUpgradeStateRolledBack
}

func upgradeErrorCode(err error) string {
	switch {
	case errors.Is(err, ErrInstallerUncertain):
		return "INSTALLER_UNCERTAIN"
	case errors.Is(err, ErrDownload):
		return "DOWNLOAD_FAILED"
	case errors.Is(err, ErrArtifactIntegrity):
		return "ARTIFACT_INTEGRITY_FAILED"
	case errors.Is(err, ErrInsufficientDisk):
		return "INSUFFICIENT_DISK"
	case errors.Is(err, ErrExpired):
		return "PLAN_EXPIRED"
	case errors.Is(err, ErrStateIncompatible):
		return stateIncompatibleCode
	default:
		return "UPGRADE_FAILED"
	}
}

type durableUpgradeClaim struct {
	Version                 int       `json:"version"`
	CommandSHA256           string    `json:"command_sha256"`
	SignedExecutionSHA256   string    `json:"signed_execution_sha256"`
	Schema                  string    `json:"schema"`
	InstallationID          string    `json:"installation_id"`
	NodeID                  string    `json:"node_id"`
	CommandID               string    `json:"command_id"`
	Nonce                   string    `json:"nonce"`
	GrantDigest             string    `json:"grant_digest"`
	PlanID                  string    `json:"plan_id"`
	PlanRevision            uint64    `json:"plan_revision"`
	BatchID                 string    `json:"batch_id"`
	ArtifactBundleID        string    `json:"artifact_bundle_id"`
	ArtifactBundleSHA256    string    `json:"artifact_bundle_sha256"`
	CommandIssuanceNotAfter int64     `json:"command_issuance_not_after"`
	ExecutionSequence       uint64    `json:"execution_sequence,omitempty"`
	ReleaseSequence         uint64    `json:"release_sequence,omitempty"`
	Component               string    `json:"component,omitempty"`
	ExpiresAt               time.Time `json:"expires_at"`
}

type durableStatusAck struct {
	Version                int              `json:"version"`
	StatusID               string           `json:"status_id"`
	SHA256                 string           `json:"sha256"`
	CommandID              string           `json:"command_id"`
	StatusRevision         uint64           `json:"status_revision"`
	State                  EdgeUpgradeState `json:"state"`
	InstallerTransactionID string           `json:"installer_transaction_id"`
	PersistedAt            time.Time        `json:"persisted_at,omitempty"`
	PublishedStream        string           `json:"published_stream,omitempty"`
	PublishedSequence      uint64           `json:"published_sequence,omitempty"`
	Encoded                []byte           `json:"encoded,omitempty"`
	AckSHA256              string           `json:"ack_sha256,omitempty"`
	ReceiptRequired        bool             `json:"receipt_required,omitempty"`
	ReceiptConfirmed       bool             `json:"receipt_confirmed,omitempty"`
	CurrentVersion         string           `json:"-"`
	PreviousVersion        string           `json:"-"`
	ErrorCode              string           `json:"-"`
	AlertRequired          bool             `json:"-"`
}

func NewDurableUpgradeStore(root string) (*DurableUpgradeStore, error) {
	disk, err := newDiskStore(root)
	if err != nil {
		return nil, err
	}
	store := &DurableUpgradeStore{
		disk: disk, wireDir: filepath.Join(disk.stateDir, "upgrade-wire-v1"),
	}
	store.inboxDir = filepath.Join(store.wireDir, "inbox")
	store.claimsDir = filepath.Join(store.wireDir, "claims")
	store.outboxDir = filepath.Join(store.wireDir, "outbox")
	store.ackedDir = filepath.Join(store.wireDir, "acked")
	for _, directory := range []string{store.wireDir, store.inboxDir, store.claimsDir, store.outboxDir, store.ackedDir} {
		if err := ensureTrustedDirectory(directory); err != nil {
			return nil, err
		}
		if err := syncDirectory(filepath.Dir(directory)); err != nil {
			return nil, err
		}
	}
	store.fs, err = newAnchoredUpgradeFS(disk, true)
	if err != nil {
		return nil, err
	}
	return store, nil
}

func (s *DurableUpgradeStore) lock(ctx context.Context) (func(), error) {
	return s.fs.lock(ctx)
}

func (s *DurableUpgradeStore) AcceptCommand(ctx context.Context, encoded []byte) (AcceptedUpgradeCommand, error) {
	command, err := decodeEdgeUpgradeCommand(encoded)
	if err != nil {
		return AcceptedUpgradeCommand{}, err
	}
	unlock, err := s.lock(ctx)
	if err != nil {
		return AcceptedUpgradeCommand{}, err
	}
	defer unlock()
	return s.acceptCommandLocked(encoded, command)
}

func (s *DurableUpgradeStore) acceptCommandLocked(encoded []byte, command EdgeUpgradeCommand) (AcceptedUpgradeCommand, error) {
	result := acceptedUpgradeCommand(command, encoded)
	name := commandFileName(command.CommandID)
	existing, found, err := s.fs.readBytesAt(s.fs.inbox, name, maxUpgradeWireBytes)
	if err != nil {
		return AcceptedUpgradeCommand{}, err
	}
	if found {
		if !bytes.Equal(existing, encoded) {
			return AcceptedUpgradeCommand{}, ErrUpgradeCommandConflict
		}
		result.Duplicate = true
		return result, nil
	}
	if err := s.fs.writeBytesAt(s.fs.inbox, name, encoded, maxUpgradeWireBytes); err != nil {
		return AcceptedUpgradeCommand{}, err
	}
	return result, nil
}

func (s *DurableUpgradeStore) PendingCommands(ctx context.Context) ([]AcceptedUpgradeCommand, error) {
	unlock, err := s.lock(ctx)
	if err != nil {
		return nil, err
	}
	defer unlock()
	return s.commandsLocked(s.fs.inbox)
}

func (s *DurableUpgradeStore) ClaimCommand(ctx context.Context, commandID string,
	options UpgradeExecutionConsumerOptions) (ClaimedUpgradeCommand, error) {
	if !validUpgradeExecutionUUID(commandID) {
		return ClaimedUpgradeCommand{}, ErrInvalidUpgradeCommand
	}
	unlock, err := s.lock(ctx)
	if err != nil {
		return ClaimedUpgradeCommand{}, err
	}
	defer unlock()
	accepted, found, err := s.loadCommandLocked(commandID)
	if err != nil {
		return ClaimedUpgradeCommand{}, err
	}
	if !found {
		return ClaimedUpgradeCommand{}, ErrUpgradeCommandNotFound
	}
	if options.ExpectedCommandID != accepted.Command.CommandID ||
		options.ExpectedInstallationID != accepted.Command.InstallationID || options.ExpectedNodeID != accepted.Command.NodeID {
		return ClaimedUpgradeCommand{}, ErrUpgradeExecutionTargetMismatch
	}
	replay := durableClaimWriter{store: s, command: accepted}
	plan, err := VerifyAndConsumeUpgradeExecution(ctx, accepted.Command.SignedExecution, options, replay)
	if err != nil {
		return ClaimedUpgradeCommand{}, err
	}
	return ClaimedUpgradeCommand{AcceptedUpgradeCommand: accepted, Plan: plan}, nil
}

func (s *DurableUpgradeStore) ResumeClaimedCommand(ctx context.Context, commandID string,
	options UpgradeExecutionConsumerOptions) (ClaimedUpgradeCommand, error) {
	if !validUpgradeExecutionUUID(commandID) {
		return ClaimedUpgradeCommand{}, ErrInvalidUpgradeCommand
	}
	unlock, err := s.lock(ctx)
	if err != nil {
		return ClaimedUpgradeCommand{}, err
	}
	defer unlock()
	accepted, found, err := s.loadCommandLocked(commandID)
	if err != nil {
		return ClaimedUpgradeCommand{}, err
	}
	if !found {
		return ClaimedUpgradeCommand{}, ErrUpgradeCommandNotFound
	}
	var claim durableUpgradeClaim
	claimed, err := s.fs.readJSONAt(s.fs.claims, claimFileName(commandID), &claim)
	if err != nil {
		return ClaimedUpgradeCommand{}, err
	}
	if !claimed {
		return ClaimedUpgradeCommand{}, ErrUpgradeCommandNotClaimed
	}
	if !validDurableClaim(claim) || claim.CommandSHA256 != accepted.SHA256 ||
		claim.SignedExecutionSHA256 != accepted.Command.SignedExecutionSHA256 ||
		!durableClaimMatchesCommand(claim, accepted) {
		return ClaimedUpgradeCommand{}, ErrUpgradeCommandConflict
	}
	if options.ExpectedCommandID != accepted.Command.CommandID ||
		options.ExpectedInstallationID != accepted.Command.InstallationID || options.ExpectedNodeID != accepted.Command.NodeID {
		return ClaimedUpgradeCommand{}, ErrUpgradeExecutionTargetMismatch
	}
	replay := durableClaimReader{command: accepted, claim: claim}
	plan, err := VerifyAndConsumeUpgradeExecution(ctx, accepted.Command.SignedExecution, options, replay)
	if err != nil {
		return ClaimedUpgradeCommand{}, err
	}
	return ClaimedUpgradeCommand{AcceptedUpgradeCommand: accepted, Plan: plan}, nil
}

func (s *DurableUpgradeStore) ClaimedCommands(ctx context.Context) ([]AcceptedUpgradeCommand, error) {
	unlock, err := s.lock(ctx)
	if err != nil {
		return nil, err
	}
	defer unlock()
	names, err := s.fs.jsonNamesAt(s.fs.claims)
	if err != nil {
		return nil, err
	}
	result := make([]AcceptedUpgradeCommand, 0, len(names))
	for _, name := range names {
		var claim durableUpgradeClaim
		found, err := s.fs.readJSONAt(s.fs.claims, name, &claim)
		if err != nil || !found || !validDurableClaim(claim) || strings.TrimSuffix(name, ".json") != claim.CommandID {
			return nil, ErrCorruptState
		}
		command, found, err := s.loadCommandLocked(claim.CommandID)
		if err != nil || !found || command.SHA256 != claim.CommandSHA256 ||
			command.Command.SignedExecutionSHA256 != claim.SignedExecutionSHA256 ||
			!durableClaimMatchesCommand(claim, command) {
			return nil, ErrCorruptState
		}
		result = append(result, command)
	}
	return result, nil
}

type durableClaimWriter struct {
	store   *DurableUpgradeStore
	command AcceptedUpgradeCommand
}

func (w durableClaimWriter) ConsumeUpgradeExecution(_ context.Context, claim UpgradeExecutionReplayClaim) (bool, error) {
	envelope, err := decodeUpgradeExecution(w.command.Command.SignedExecution)
	if err != nil || claim != upgradeExecutionReplayClaim(envelope.Execution) ||
		claim.CommandID != w.command.Command.CommandID || claim.PlanID != w.command.Command.PlanID ||
		claim.PlanRevision != w.command.Command.PlanRevision || claim.BatchID != w.command.Command.BatchID ||
		claim.InstallationID != w.command.Command.InstallationID || claim.NodeID != w.command.Command.NodeID {
		return false, ErrUpgradeCommandConflict
	}
	record := durableUpgradeClaim{
		Version: upgradeWireStateVersion, CommandSHA256: w.command.SHA256,
		SignedExecutionSHA256: w.command.Command.SignedExecutionSHA256,
		Schema:                claim.Schema, InstallationID: claim.InstallationID, NodeID: claim.NodeID, CommandID: claim.CommandID,
		Nonce: claim.Nonce, GrantDigest: claim.GrantDigest, PlanID: claim.PlanID, PlanRevision: claim.PlanRevision,
		BatchID: claim.BatchID, ArtifactBundleID: claim.ArtifactBundleID,
		ArtifactBundleSHA256: claim.ArtifactBundleSHA256, CommandIssuanceNotAfter: claim.CommandIssuanceNotAfter,
		ExpiresAt: claim.ExpiresAt.UTC(),
	}
	if claim.Schema == upgradeExecutionV3Schema {
		record.ExecutionSequence = claim.ExecutionSequence
		record.ReleaseSequence = claim.ReleaseSequence
		record.Component = claim.Component
	}
	var existing durableUpgradeClaim
	name := claimFileName(claim.CommandID)
	found, err := w.store.fs.readJSONAt(w.store.fs.claims, name, &existing)
	if err != nil {
		return false, err
	}
	if found {
		if !sameDurableClaim(existing, record) {
			return false, ErrUpgradeCommandConflict
		}
		return false, nil
	}
	if err := w.store.fs.writeJSONAt(w.store.fs.claims, name, record); err != nil {
		return false, err
	}
	return true, nil
}

type durableClaimReader struct {
	command AcceptedUpgradeCommand
	claim   durableUpgradeClaim
}

func (r durableClaimReader) ConsumeUpgradeExecution(ctx context.Context, claim UpgradeExecutionReplayClaim) (bool, error) {
	if err := ctx.Err(); err != nil {
		return false, err
	}
	record := durableUpgradeClaim{
		Version: upgradeWireStateVersion, CommandSHA256: r.command.SHA256,
		SignedExecutionSHA256: r.command.Command.SignedExecutionSHA256,
		Schema:                claim.Schema, InstallationID: claim.InstallationID, NodeID: claim.NodeID, CommandID: claim.CommandID,
		Nonce: claim.Nonce, GrantDigest: claim.GrantDigest, PlanID: claim.PlanID, PlanRevision: claim.PlanRevision,
		BatchID: claim.BatchID, ArtifactBundleID: claim.ArtifactBundleID,
		ArtifactBundleSHA256: claim.ArtifactBundleSHA256, CommandIssuanceNotAfter: claim.CommandIssuanceNotAfter,
		ExpiresAt: claim.ExpiresAt.UTC(),
	}
	if claim.Schema == upgradeExecutionV3Schema {
		record.ExecutionSequence = claim.ExecutionSequence
		record.ReleaseSequence = claim.ReleaseSequence
		record.Component = claim.Component
	}
	if !sameDurableClaim(r.claim, record) || !durableClaimMatchesCommand(r.claim, r.command) {
		return false, ErrUpgradeCommandConflict
	}
	return true, nil
}

func (s *DurableUpgradeStore) EnqueueStatus(ctx context.Context, encoded []byte) (QueuedUpgradeStatus, error) {
	return s.enqueueStatus(ctx, encoded, false)
}

func (s *DurableUpgradeStore) ReconcileStatus(ctx context.Context, encoded []byte) (QueuedUpgradeStatus, error) {
	return s.enqueueStatus(ctx, encoded, true)
}

func (s *DurableUpgradeStore) enqueueStatus(ctx context.Context, encoded []byte, reconcile bool) (QueuedUpgradeStatus, error) {
	status, err := decodeEdgeUpgradeStatus(encoded)
	if err != nil {
		return QueuedUpgradeStatus{}, err
	}
	unlock, err := s.lock(ctx)
	if err != nil {
		return QueuedUpgradeStatus{}, err
	}
	defer unlock()
	if err := s.validateStatusBindingLocked(status); err != nil {
		return QueuedUpgradeStatus{}, err
	}
	if err := s.validateStatusAcksLocked(); err != nil {
		return QueuedUpgradeStatus{}, err
	}
	result := queuedUpgradeStatus(status, encoded)
	ack, found, err := s.loadStatusAckLocked(status.StatusID)
	if err != nil {
		return QueuedUpgradeStatus{}, err
	}
	if found {
		if !statusAckMatchesStatus(ack, status, result.SHA256) {
			return QueuedUpgradeStatus{}, ErrUpgradeStatusConflict
		}
		ledger, ledgerFound, err := s.fs.readBytesAt(s.fs.outbox, statusFileName(status.StatusID), maxUpgradeWireBytes)
		if err != nil || !ledgerFound {
			return QueuedUpgradeStatus{}, ErrCorruptState
		}
		if !bytes.Equal(ledger, encoded) {
			return QueuedUpgradeStatus{}, ErrUpgradeStatusConflict
		}
		result.Duplicate = true
		return result, nil
	}
	name := statusFileName(status.StatusID)
	existing, found, err := s.fs.readBytesAt(s.fs.outbox, name, maxUpgradeWireBytes)
	if err != nil {
		return QueuedUpgradeStatus{}, err
	}
	if found {
		if !bytes.Equal(existing, encoded) {
			return QueuedUpgradeStatus{}, ErrUpgradeStatusConflict
		}
		result.Duplicate = true
		return result, nil
	}
	if err := s.validateStatusProgressionLocked(status, reconcile); err != nil {
		return QueuedUpgradeStatus{}, err
	}
	statuses, _, err := s.statusSnapshotLocked()
	if err != nil {
		return QueuedUpgradeStatus{}, err
	}
	if _, err := s.statusHistoryFromSnapshotLocked(status.CommandID, append(statuses, result)); err != nil {
		return QueuedUpgradeStatus{}, fmt.Errorf("%w: candidate history: %v", ErrUpgradeStatusConflict, err)
	}
	if err := s.fs.writeBytesAt(s.fs.outbox, name, encoded, maxUpgradeWireBytes); err != nil {
		return QueuedUpgradeStatus{}, err
	}
	return result, nil
}

func (s *DurableUpgradeStore) PendingStatuses(ctx context.Context) ([]QueuedUpgradeStatus, error) {
	unlock, err := s.lock(ctx)
	if err != nil {
		return nil, err
	}
	defer unlock()
	statuses, acknowledgements, err := s.statusSnapshotLocked()
	if err != nil {
		return nil, err
	}
	commandIDs := make(map[string]struct{})
	for _, queued := range statuses {
		commandIDs[queued.Status.CommandID] = struct{}{}
	}
	for commandID := range commandIDs {
		if _, err := s.statusHistoryFromSnapshotLocked(commandID, statuses); err != nil {
			return nil, err
		}
	}
	result := make([]QueuedUpgradeStatus, 0, len(statuses))
	for _, queued := range statuses {
		if _, acknowledged := acknowledgements[queued.Status.StatusID]; acknowledged {
			continue
		}
		result = append(result, queued)
	}
	sort.Slice(result, func(left, right int) bool {
		if result[left].Status.CommandID != result[right].Status.CommandID {
			return result[left].Status.CommandID < result[right].Status.CommandID
		}
		if result[left].Status.StatusRevision != result[right].Status.StatusRevision {
			return result[left].Status.StatusRevision < result[right].Status.StatusRevision
		}
		return result[left].Status.StatusID < result[right].Status.StatusID
	})
	return result, nil
}

func (s *DurableUpgradeStore) acceptedStatusAcknowledged(ctx context.Context, commandID string) (bool, error) {
	if !validUpgradeExecutionUUID(commandID) {
		return false, ErrUpgradeStatusAckMismatch
	}
	unlock, err := s.lock(ctx)
	if err != nil {
		return false, err
	}
	defer unlock()
	history, err := s.statusHistoryLocked(commandID)
	if err != nil {
		return false, err
	}
	if len(history) == 0 || history[0].State != EdgeUpgradeStateAccepted {
		return false, ErrCorruptState
	}
	ack, found, err := s.loadStatusAckLocked(history[0].StatusID)
	if err != nil || !found {
		return false, err
	}
	return sameDurableStatusAck(ack, history[0]), nil
}

func (s *DurableUpgradeStore) AcknowledgeStatus(ctx context.Context, statusID, digest string) (bool, error) {
	if !validUpgradeExecutionUUID(statusID) || !validDigest(digest) {
		return false, ErrUpgradeStatusAckMismatch
	}
	return s.acknowledgeStatus(ctx, statusID, "", digest)
}

// AcknowledgeStatusWithPublication is the only status acknowledgement write
// path that accepts a publication identity. It deliberately reuses the exact
// receipt validation and durable replay semantics.
func (s *DurableUpgradeStore) AcknowledgeStatusWithPublication(ctx context.Context, acknowledgement UpgradeStatusAcknowledgement) (bool, error) {
	if !validUpgradeStatusAcknowledgement(acknowledgement) {
		return false, ErrUpgradeStatusAckMismatch
	}
	return s.acknowledgeStatusWithPublication(ctx, acknowledgement.StatusID, acknowledgement.CommandID,
		acknowledgement.StatusSHA256, acknowledgement.PublishedStream, acknowledgement.PublishedSequence)
}

func (s *DurableUpgradeStore) acknowledgeStatus(ctx context.Context, statusID, commandID, digest string) (bool, error) {
	return s.acknowledgeStatusWithPublication(ctx, statusID, commandID, digest, "", 0)
}

func (s *DurableUpgradeStore) acknowledgeStatusWithPublication(ctx context.Context, statusID, commandID, digest, stream string, sequence uint64) (bool, error) {
	if !validUpgradeExecutionUUID(statusID) || !validDigest(digest) {
		return false, ErrUpgradeStatusAckMismatch
	}
	if commandID != "" && !validUpgradeExecutionUUID(commandID) {
		return false, ErrUpgradeStatusAckMismatch
	}
	if !validStatusPublication(stream, sequence) {
		return false, ErrUpgradeStatusAckMismatch
	}
	unlock, err := s.lock(ctx)
	if err != nil {
		return false, err
	}
	defer unlock()
	ack, found, err := s.loadStatusAckLocked(statusID)
	if err != nil {
		return false, err
	}
	if found {
		if ack.SHA256 != digest || commandID != "" && ack.CommandID != commandID {
			return false, ErrUpgradeStatusAckMismatch
		}
		if stream != "" && (ack.PublishedStream != stream || ack.PublishedSequence != sequence) {
			return false, ErrUpgradeStatusAckMismatch
		}
		encoded, ledgerFound, err := s.fs.readBytesAt(s.fs.outbox, statusFileName(statusID), maxUpgradeWireBytes)
		if err != nil || !ledgerFound {
			return false, ErrCorruptState
		}
		status, err := decodeEdgeUpgradeStatus(encoded)
		if err != nil || status.StatusID != statusID || s.validateStatusBindingLocked(status) != nil ||
			!statusAckMatchesStatus(ack, status, digest) {
			return false, ErrCorruptState
		}
		return true, nil
	}
	encoded, found, err := s.fs.readBytesAt(s.fs.outbox, statusFileName(statusID), maxUpgradeWireBytes)
	if err != nil {
		return false, err
	}
	if !found {
		return false, nil
	}
	if sha256String(encoded) != digest {
		return false, ErrUpgradeStatusAckMismatch
	}
	status, err := decodeEdgeUpgradeStatus(encoded)
	if err != nil || status.StatusID != statusID || s.validateStatusBindingLocked(status) != nil ||
		commandID != "" && status.CommandID != commandID {
		return false, ErrCorruptState
	}
	ack = durableStatusAck{
		Version: upgradeWireStateVersion, StatusID: statusID, SHA256: digest,
		CommandID: status.CommandID, StatusRevision: status.StatusRevision, State: status.State,
		InstallerTransactionID: status.InstallerTransactionID, PublishedStream: stream, PublishedSequence: sequence,
	}
	if err := s.fs.writeJSONAt(s.fs.acked, ackFileName(statusID), ack); err != nil {
		return false, err
	}
	return true, nil
}

func (s *DurableUpgradeStore) PersistStatusAcknowledgement(ctx context.Context, acknowledgement UpgradeStatusAcknowledgement) (bool, error) {
	if !validUpgradeStatusAcknowledgement(acknowledgement) {
		return false, ErrUpgradeStatusAckMismatch
	}
	unlock, err := s.lock(ctx)
	if err != nil {
		return false, err
	}
	defer unlock()
	encoded, found, err := s.fs.readBytesAt(s.fs.outbox, statusFileName(acknowledgement.StatusID), maxUpgradeWireBytes)
	if err != nil {
		return false, err
	}
	if !found || sha256String(encoded) != acknowledgement.StatusSHA256 {
		return false, ErrUpgradeStatusAckMismatch
	}
	status, err := decodeEdgeUpgradeStatus(encoded)
	if err != nil || status.StatusID != acknowledgement.StatusID || status.CommandID != acknowledgement.CommandID ||
		status.StatusRevision != acknowledgement.StatusRevision || s.validateStatusBindingLocked(status) != nil {
		return false, ErrUpgradeStatusAckMismatch
	}
	existing, exists, err := s.loadStatusAckLocked(status.StatusID)
	if err != nil {
		return false, err
	}
	want := durableStatusAck{
		Version: upgradeWireStateVersion, StatusID: status.StatusID, SHA256: acknowledgement.StatusSHA256,
		CommandID: status.CommandID, StatusRevision: status.StatusRevision, State: status.State,
		InstallerTransactionID: status.InstallerTransactionID,
		PersistedAt:            acknowledgement.PersistedAt.UTC(), PublishedStream: acknowledgement.PublishedStream,
		PublishedSequence: acknowledgement.PublishedSequence, Encoded: append([]byte(nil), acknowledgement.Encoded...),
		AckSHA256: acknowledgement.SHA256, ReceiptRequired: true,
	}
	if exists {
		if existing.ReceiptRequired {
			if !sameUpgradeStatusAcknowledgement(upgradeStatusAcknowledgementFromDurable(existing), acknowledgement) {
				return false, ErrUpgradeStatusAckMismatch
			}
			return status.State == EdgeUpgradeStateAccepted, nil
		}
		if !statusAckMatchesStatus(existing, status, acknowledgement.StatusSHA256) {
			return false, ErrUpgradeStatusAckMismatch
		}
	}
	if err := s.fs.writeJSONAt(s.fs.acked, ackFileName(status.StatusID), want); err != nil {
		return false, err
	}
	return status.State == EdgeUpgradeStateAccepted, nil
}

func (s *DurableUpgradeStore) PendingStatusAcknowledgements(ctx context.Context) ([]UpgradeStatusAcknowledgement, error) {
	unlock, err := s.lock(ctx)
	if err != nil {
		return nil, err
	}
	defer unlock()
	_, acknowledgements, err := s.statusSnapshotLocked()
	if err != nil {
		return nil, err
	}
	result := make([]UpgradeStatusAcknowledgement, 0)
	for _, acknowledgement := range acknowledgements {
		if acknowledgement.ReceiptRequired && !acknowledgement.ReceiptConfirmed {
			result = append(result, upgradeStatusAcknowledgementFromDurable(acknowledgement))
		}
	}
	sort.Slice(result, func(left, right int) bool {
		if result[left].CommandID != result[right].CommandID {
			return result[left].CommandID < result[right].CommandID
		}
		return result[left].StatusRevision < result[right].StatusRevision
	})
	return result, nil
}

func (s *DurableUpgradeStore) ConfirmStatusAcknowledgement(ctx context.Context, acknowledgement UpgradeStatusAcknowledgement) (bool, error) {
	if !validUpgradeStatusAcknowledgement(acknowledgement) {
		return false, ErrUpgradeStatusAckMismatch
	}
	unlock, err := s.lock(ctx)
	if err != nil {
		return false, err
	}
	defer unlock()
	stored, found, err := s.loadStatusAckLocked(acknowledgement.StatusID)
	if err != nil {
		return false, err
	}
	if !found || !stored.ReceiptRequired ||
		!sameUpgradeStatusAcknowledgement(upgradeStatusAcknowledgementFromDurable(stored), acknowledgement) {
		return false, ErrUpgradeStatusAckMismatch
	}
	if stored.ReceiptConfirmed {
		return true, nil
	}
	stored.ReceiptConfirmed = true
	if err := s.fs.writeJSONAt(s.fs.acked, ackFileName(stored.StatusID), stored); err != nil {
		return false, err
	}
	return true, nil
}

func (s *DurableUpgradeStore) validateStatusBindingLocked(status EdgeUpgradeStatus) error {
	command, found, err := s.loadCommandLocked(status.CommandID)
	if err != nil {
		return err
	}
	if !found || status.CommandSHA256 != command.SHA256 || status.PlanID != command.Command.PlanID ||
		status.PlanRevision != command.Command.PlanRevision || status.InstallationID != command.Command.InstallationID ||
		status.NodeID != command.Command.NodeID {
		return ErrInvalidUpgradeStatus
	}
	if status.State == EdgeUpgradeStateAccepted {
		return nil
	}
	var claim durableUpgradeClaim
	claimed, err := s.fs.readJSONAt(s.fs.claims, claimFileName(status.CommandID), &claim)
	if err != nil {
		return err
	}
	if !claimed || !validDurableClaim(claim) || claim.CommandSHA256 != command.SHA256 ||
		!durableClaimMatchesCommand(claim, command) {
		return ErrInvalidUpgradeStatus
	}
	envelope, err := decodeUpgradeExecution(command.Command.SignedExecution)
	if err != nil {
		return ErrInvalidUpgradeStatus
	}
	current := envelope.Execution.CurrentVersion
	target := envelope.Execution.TargetVersion
	hasTransaction := status.InstallerTransactionID != ""
	matches := func(wantCurrent, wantPrevious string) bool {
		return status.CurrentVersion == wantCurrent && status.PreviousVersion == wantPrevious
	}
	switch status.State {
	case EdgeUpgradeStateClaimed, EdgeUpgradeStateInstalling:
		return nil
	case EdgeUpgradeStateHealthy:
		if command.Command.Action == string(ActionUpgrade) && hasTransaction && matches(target, current) &&
			status.ErrorCode == "" && !status.AlertRequired {
			return nil
		}
	case EdgeUpgradeStateRollingBack:
		if command.Command.Action == string(ActionUpgrade) && hasTransaction && matches(current, target) &&
			status.ErrorCode != "" && !status.AlertRequired {
			return nil
		}
	case EdgeUpgradeStateRolledBack:
		if command.Command.Action == string(ActionRollback) && hasTransaction && matches(target, current) &&
			status.ErrorCode == "" && !status.AlertRequired {
			return nil
		}
		if command.Command.Action == string(ActionUpgrade) && hasTransaction && matches(current, target) &&
			status.ErrorCode != "" && !status.AlertRequired {
			return nil
		}
	case EdgeUpgradeStateFailed:
		if hasTransaction && status.ErrorCode != "" && status.AlertRequired &&
			(matches(current, "") || matches(target, current) ||
				command.Command.Action == string(ActionRollback) && matches(current, target)) {
			return nil
		}
	case EdgeUpgradeStateUncertain:
		if hasTransaction && status.ErrorCode != "" && status.AlertRequired &&
			(matches("", "") || matches(target, current)) {
			return nil
		}
	}
	return ErrInvalidUpgradeStatus
}

func (s *DurableUpgradeStore) validateStatusProgressionLocked(status EdgeUpgradeStatus, reconcile bool) error {
	history, err := s.statusHistoryLocked(status.CommandID)
	if err != nil {
		return err
	}
	if len(history) == 0 {
		if reconcile || status.StatusRevision != 1 ||
			(status.State != EdgeUpgradeStateAccepted && status.State != EdgeUpgradeStateClaimed) {
			return fmt.Errorf("%w: initial progression", ErrUpgradeStatusConflict)
		}
		return nil
	}
	previous := history[len(history)-1]
	if status.StatusRevision != previous.StatusRevision+1 {
		return fmt.Errorf("%w: revision progression", ErrUpgradeStatusConflict)
	}
	command, found, err := s.loadCommandLocked(status.CommandID)
	if err != nil {
		return err
	}
	if !found {
		return fmt.Errorf("%w: missing command", ErrUpgradeStatusConflict)
	}
	if previous.InstallerTransactionID != "" && status.InstallerTransactionID != previous.InstallerTransactionID {
		return fmt.Errorf("%w: transaction progression", ErrUpgradeStatusConflict)
	}
	if reconcile {
		if previous.State != EdgeUpgradeStateUncertain || previous.InstallerTransactionID == "" ||
			status.InstallerTransactionID != previous.InstallerTransactionID ||
			!validReconciledUpgradeStateForAction(command.Command.Action, status.State) {
			return fmt.Errorf("%w: invalid reconciliation", ErrUpgradeStatusConflict)
		}
		return nil
	}
	if previous.State == EdgeUpgradeStateUncertain {
		return fmt.Errorf("%w: reconciliation required", ErrUpgradeStatusConflict)
	}
	if !found || !validUpgradeStateTransitionForAction(command.Command.Action, previous.State, status.State) {
		return fmt.Errorf("%w: invalid transition", ErrUpgradeStatusConflict)
	}
	return nil
}

func (s *DurableUpgradeStore) statusHistoryLocked(commandID string) ([]durableStatusAck, error) {
	statuses, _, err := s.statusSnapshotLocked()
	if err != nil {
		return nil, err
	}
	return s.statusHistoryFromSnapshotLocked(commandID, statuses)
}

func (s *DurableUpgradeStore) statusHistoryFromSnapshotLocked(commandID string,
	statuses []QueuedUpgradeStatus) ([]durableStatusAck, error) {
	byStatusID := make(map[string]durableStatusAck)
	byRevision := make(map[uint64]durableStatusAck)
	appendStatus := func(status durableStatusAck) error {
		if existing, found := byStatusID[status.StatusID]; found {
			if !sameDurableStatusAck(existing, status) {
				return ErrCorruptState
			}
			return nil
		}
		if existing, found := byRevision[status.StatusRevision]; found && !sameDurableStatusAck(existing, status) {
			return ErrCorruptState
		}
		byStatusID[status.StatusID] = status
		byRevision[status.StatusRevision] = status
		return nil
	}

	for _, queued := range statuses {
		status := queued.Status
		if status.CommandID != commandID {
			continue
		}
		if err := appendStatus(durableStatusAck{
			Version: upgradeWireStateVersion, StatusID: status.StatusID, SHA256: queued.SHA256,
			CommandID: status.CommandID, StatusRevision: status.StatusRevision, State: status.State,
			InstallerTransactionID: status.InstallerTransactionID, CurrentVersion: status.CurrentVersion,
			PreviousVersion: status.PreviousVersion, ErrorCode: status.ErrorCode, AlertRequired: status.AlertRequired,
		}); err != nil {
			return nil, err
		}
	}

	history := make([]durableStatusAck, 0, len(byRevision))
	for _, status := range byRevision {
		history = append(history, status)
	}
	sort.Slice(history, func(left, right int) bool {
		return history[left].StatusRevision < history[right].StatusRevision
	})
	action := ""
	if len(history) > 1 {
		command, found, err := s.loadCommandLocked(commandID)
		if err != nil || !found {
			return nil, ErrCorruptState
		}
		action = command.Command.Action
	}
	installerTransactionID := ""
	rollbackCause := ""
	for index, status := range history {
		if status.StatusRevision != uint64(index+1) ||
			(index == 0 && status.State != EdgeUpgradeStateAccepted && status.State != EdgeUpgradeStateClaimed) {
			return nil, ErrCorruptState
		}
		if index == 0 {
			continue
		}
		previous := history[index-1]
		if status.State == EdgeUpgradeStateInstalling {
			installerTransactionID = status.InstallerTransactionID
		} else if installerTransactionID != "" && status.InstallerTransactionID != installerTransactionID {
			return nil, ErrCorruptState
		}
		valid := validUpgradeStateTransitionForAction(action, previous.State, status.State)
		if previous.State == EdgeUpgradeStateUncertain {
			valid = previous.InstallerTransactionID != "" && status.InstallerTransactionID == previous.InstallerTransactionID &&
				validReconciledUpgradeStateForAction(action, status.State)
		}
		if status.State == EdgeUpgradeStateRollingBack {
			rollbackCause = status.ErrorCode
		}
		if (status.State == EdgeUpgradeStateRolledBack || status.State == EdgeUpgradeStateFailed) &&
			action == string(ActionUpgrade) &&
			rollbackCause != "" && status.ErrorCode != rollbackCause {
			valid = false
		}
		if !valid {
			return nil, ErrCorruptState
		}
	}
	return history, nil
}

func (s *DurableUpgradeStore) validateStatusAcksLocked() error {
	_, _, err := s.statusSnapshotLocked()
	return err
}

func (s *DurableUpgradeStore) statusSnapshotLocked() ([]QueuedUpgradeStatus, map[string]durableStatusAck, error) {
	statusNames, err := s.fs.jsonNamesAt(s.fs.outbox)
	if err != nil {
		return nil, nil, err
	}
	statuses := make([]QueuedUpgradeStatus, 0, len(statusNames))
	byStatusID := make(map[string]QueuedUpgradeStatus, len(statusNames))
	for _, name := range statusNames {
		encoded, found, err := s.fs.readBytesAt(s.fs.outbox, name, maxUpgradeWireBytes)
		if err != nil || !found {
			return nil, nil, ErrCorruptState
		}
		status, err := decodeEdgeUpgradeStatus(encoded)
		if err != nil || strings.TrimSuffix(name, ".json") != status.StatusID || s.validateStatusBindingLocked(status) != nil {
			return nil, nil, ErrCorruptState
		}
		queued := queuedUpgradeStatus(status, encoded)
		statuses = append(statuses, queued)
		byStatusID[status.StatusID] = queued
	}

	names, err := s.fs.jsonNamesAt(s.fs.acked)
	if err != nil {
		return nil, nil, err
	}
	acknowledgements := make(map[string]durableStatusAck, len(names))
	for _, name := range names {
		statusID := strings.TrimSuffix(name, ".json")
		ack, found, err := s.loadStatusAckLocked(statusID)
		queued, ledgerFound := byStatusID[statusID]
		if err != nil || !found || statusID != ack.StatusID || !ledgerFound ||
			!statusAckMatchesStatus(ack, queued.Status, queued.SHA256) {
			return nil, nil, ErrCorruptState
		}
		acknowledgements[statusID] = ack
	}
	return statuses, acknowledgements, nil
}

func (s *DurableUpgradeStore) commandsLocked(directory *os.File) ([]AcceptedUpgradeCommand, error) {
	names, err := s.fs.jsonNamesAt(directory)
	if err != nil {
		return nil, err
	}
	result := make([]AcceptedUpgradeCommand, 0, len(names))
	for _, name := range names {
		encoded, found, err := s.fs.readBytesAt(directory, name, maxUpgradeWireBytes)
		if err != nil || !found {
			return nil, ErrCorruptState
		}
		command, err := decodeEdgeUpgradeCommand(encoded)
		if err != nil || strings.TrimSuffix(name, ".json") != command.CommandID {
			return nil, ErrCorruptState
		}
		result = append(result, acceptedUpgradeCommand(command, encoded))
	}
	return result, nil
}

func (s *DurableUpgradeStore) loadCommandLocked(commandID string) (AcceptedUpgradeCommand, bool, error) {
	encoded, found, err := s.fs.readBytesAt(s.fs.inbox, commandFileName(commandID), maxUpgradeWireBytes)
	if err != nil || !found {
		return AcceptedUpgradeCommand{}, found, err
	}
	command, err := decodeEdgeUpgradeCommand(encoded)
	if err != nil || command.CommandID != commandID {
		return AcceptedUpgradeCommand{}, false, ErrCorruptState
	}
	return acceptedUpgradeCommand(command, encoded), true, nil
}

func (s *DurableUpgradeStore) loadStatusAckLocked(statusID string) (durableStatusAck, bool, error) {
	var ack durableStatusAck
	found, err := s.fs.readJSONAt(s.fs.acked, ackFileName(statusID), &ack)
	if err != nil || !found {
		return ack, found, err
	}
	if ack.Version != upgradeWireStateVersion || ack.StatusID != statusID || !validDigest(ack.SHA256) ||
		!validUpgradeExecutionUUID(ack.CommandID) || ack.StatusRevision == 0 || !validEdgeUpgradeState(ack.State) ||
		(ack.InstallerTransactionID != "" && !safeIDPattern.MatchString(ack.InstallerTransactionID)) {
		return durableStatusAck{}, false, ErrCorruptState
	}
	if ack.ReceiptRequired {
		if !validUpgradeStatusAcknowledgement(upgradeStatusAcknowledgementFromDurable(ack)) {
			return durableStatusAck{}, false, ErrCorruptState
		}
	} else if ack.ReceiptConfirmed || !ack.PersistedAt.IsZero() || len(ack.Encoded) != 0 || ack.AckSHA256 != "" ||
		!validStatusPublication(ack.PublishedStream, ack.PublishedSequence) {
		return durableStatusAck{}, false, ErrCorruptState
	}
	return ack, true, nil
}

func validStatusPublication(stream string, sequence uint64) bool {
	return stream == "" && sequence == 0 || stream == "AGENT_DEPLOYMENT_STATUS" && sequence > 0
}

func validUpgradeStatusAcknowledgement(acknowledgement UpgradeStatusAcknowledgement) bool {
	return validUpgradeExecutionUUID(acknowledgement.StatusID) &&
		validUpgradeExecutionUUID(acknowledgement.CommandID) && acknowledgement.StatusRevision > 0 &&
		validDigest(acknowledgement.StatusSHA256) && !acknowledgement.PersistedAt.IsZero() &&
		acknowledgement.PublishedStream == "AGENT_DEPLOYMENT_STATUS" && acknowledgement.PublishedSequence > 0 &&
		len(acknowledgement.Encoded) > 0 && len(acknowledgement.Encoded) <= maxUpgradeWireBytes &&
		validDigest(acknowledgement.SHA256) && sha256String(acknowledgement.Encoded) == acknowledgement.SHA256
}

func sameUpgradeStatusAcknowledgement(left, right UpgradeStatusAcknowledgement) bool {
	return left.StatusID == right.StatusID && left.CommandID == right.CommandID &&
		left.StatusRevision == right.StatusRevision && left.StatusSHA256 == right.StatusSHA256 &&
		left.PersistedAt.Equal(right.PersistedAt) && left.PublishedStream == right.PublishedStream &&
		left.PublishedSequence == right.PublishedSequence && left.SHA256 == right.SHA256 &&
		bytes.Equal(left.Encoded, right.Encoded)
}

func upgradeStatusAcknowledgementFromDurable(acknowledgement durableStatusAck) UpgradeStatusAcknowledgement {
	return UpgradeStatusAcknowledgement{
		StatusID: acknowledgement.StatusID, CommandID: acknowledgement.CommandID,
		StatusRevision: acknowledgement.StatusRevision, StatusSHA256: acknowledgement.SHA256,
		PersistedAt: acknowledgement.PersistedAt, PublishedStream: acknowledgement.PublishedStream,
		PublishedSequence: acknowledgement.PublishedSequence, Encoded: append([]byte(nil), acknowledgement.Encoded...),
		SHA256: acknowledgement.AckSHA256,
	}
}

func (s *DurableUpgradeStore) commandPath(commandID string) string {
	return filepath.Join(s.inboxDir, commandID+".json")
}

func (s *DurableUpgradeStore) claimPath(commandID string) string {
	return filepath.Join(s.claimsDir, commandID+".json")
}

func (s *DurableUpgradeStore) statusPath(statusID string) string {
	return filepath.Join(s.outboxDir, statusID+".json")
}

func (s *DurableUpgradeStore) ackPath(statusID string) string {
	return filepath.Join(s.ackedDir, statusID+".json")
}

func commandFileName(commandID string) string { return commandID + ".json" }
func claimFileName(commandID string) string   { return commandID + ".json" }
func statusFileName(statusID string) string   { return statusID + ".json" }
func ackFileName(statusID string) string      { return statusID + ".json" }

func decodeEdgeUpgradeCommand(encoded []byte) (EdgeUpgradeCommand, error) {
	var command EdgeUpgradeCommand
	if err := decodeCanonicalUpgradeWire(encoded, &command); err != nil ||
		command.Schema != EdgeUpgradeCommandSchema || !validUpgradeExecutionUUID(command.CommandID) ||
		!validUpgradeExecutionUUID(command.PlanID) || command.PlanRevision == 0 || !safeIDPattern.MatchString(command.BatchID) ||
		!validUpgradeExecutionUUID(command.InstallationID) || !validUpgradeExecutionUUID(command.NodeID) ||
		(command.Action != string(ActionUpgrade) && command.Action != string(ActionRollback)) ||
		len(command.SignedExecution) == 0 || len(command.SignedExecution) > maxUpgradeExecutionBytes ||
		!validDigest(command.SignedExecutionSHA256) || sha256String(command.SignedExecution) != command.SignedExecutionSHA256 {
		return EdgeUpgradeCommand{}, ErrInvalidUpgradeCommand
	}
	envelope, err := decodeUpgradeExecution(command.SignedExecution)
	if err != nil || (envelope.Execution.Schema != upgradeExecutionV2Schema && envelope.Execution.Schema != upgradeExecutionV3Schema) ||
		envelope.Execution.CommandID != command.CommandID || envelope.Execution.PlanID != command.PlanID ||
		envelope.Execution.PlanRevision != command.PlanRevision || envelope.Execution.BatchID != command.BatchID ||
		envelope.Execution.InstallationID != command.InstallationID || envelope.Execution.NodeID != command.NodeID ||
		envelope.Execution.Operation != command.Action {
		return EdgeUpgradeCommand{}, ErrInvalidUpgradeCommand
	}
	return command, nil
}

func decodeEdgeUpgradeStatus(encoded []byte) (EdgeUpgradeStatus, error) {
	var status EdgeUpgradeStatus
	if err := decodeCanonicalUpgradeWire(encoded, &status); err != nil ||
		(status.Schema != EdgeUpgradeStatusSchemaV1 && status.Schema != EdgeUpgradeStatusSchemaV2) ||
		!validUpgradeExecutionUUID(status.StatusID) || status.StatusRevision == 0 ||
		!validUpgradeExecutionUUID(status.CommandID) || !validUpgradeExecutionUUID(status.PlanID) || status.PlanRevision == 0 ||
		!validUpgradeExecutionUUID(status.InstallationID) || !validUpgradeExecutionUUID(status.NodeID) ||
		!validDigest(status.CommandSHA256) || !validEdgeUpgradeState(status.State) || !validUpgradeStatusFields(status) ||
		status.ObservedAt.IsZero() {
		return EdgeUpgradeStatus{}, ErrInvalidUpgradeStatus
	}
	_, offset := status.ObservedAt.Zone()
	if offset != 0 || (status.CurrentVersion != "" && invalidVersion(status.CurrentVersion)) ||
		(status.PreviousVersion != "" && invalidVersion(status.PreviousVersion)) ||
		(status.InstallerTransactionID != "" && !safeIDPattern.MatchString(status.InstallerTransactionID)) ||
		(status.ErrorCode != "" && !safeIDPattern.MatchString(status.ErrorCode)) {
		return EdgeUpgradeStatus{}, ErrInvalidUpgradeStatus
	}
	expectedStatusID, err := upgradeStatusID(status.CommandID, status.StatusRevision)
	if err != nil || status.StatusID != expectedStatusID {
		return EdgeUpgradeStatus{}, ErrInvalidUpgradeStatus
	}
	if status.Schema == EdgeUpgradeStatusSchemaV1 {
		if status.ActiveEvidence != nil {
			return EdgeUpgradeStatus{}, ErrInvalidUpgradeStatus
		}
	} else if status.State == EdgeUpgradeStateHealthy || status.State == EdgeUpgradeStateRolledBack {
		if validateActiveProbeEvidence(status.InstallerTransactionID, status.ActiveEvidence) != nil ||
			status.ActiveEvidence.ProbeObservedAt.After(status.ObservedAt) {
			return EdgeUpgradeStatus{}, ErrInvalidUpgradeStatus
		}
	} else if status.ActiveEvidence != nil {
		return EdgeUpgradeStatus{}, ErrInvalidUpgradeStatus
	}
	return status, nil
}

func durableStatusPathMatches(path, statusID string) bool {
	return strings.TrimSuffix(filepath.Base(path), ".json") == statusID
}

func validUpgradeStatusFields(status EdgeUpgradeStatus) bool {
	switch status.State {
	case EdgeUpgradeStateAccepted, EdgeUpgradeStateClaimed:
		return status.CurrentVersion == "" && status.PreviousVersion == "" && status.InstallerTransactionID == "" &&
			status.ErrorCode == "" && !status.AlertRequired
	case EdgeUpgradeStateInstalling:
		return status.CurrentVersion == "" && status.PreviousVersion == "" && status.InstallerTransactionID != "" &&
			status.ErrorCode == "" && !status.AlertRequired
	default:
		return true
	}
}

func decodeCanonicalUpgradeWire(encoded []byte, destination any) error {
	if len(encoded) == 0 || len(encoded) > maxUpgradeWireBytes {
		return ErrCorruptState
	}
	decoder := json.NewDecoder(bytes.NewReader(encoded))
	decoder.DisallowUnknownFields()
	if err := decoder.Decode(destination); err != nil {
		return err
	}
	var extra any
	if err := decoder.Decode(&extra); !errors.Is(err, io.EOF) {
		return ErrCorruptState
	}
	canonical, err := json.Marshal(destination)
	if err != nil || !bytes.Equal(canonical, encoded) {
		return ErrCorruptState
	}
	return nil
}

func validEdgeUpgradeState(state EdgeUpgradeState) bool {
	switch state {
	case EdgeUpgradeStateAccepted, EdgeUpgradeStateClaimed, EdgeUpgradeStateInstalling, EdgeUpgradeStateHealthy,
		EdgeUpgradeStateFailed, EdgeUpgradeStateRollingBack, EdgeUpgradeStateRolledBack, EdgeUpgradeStateUncertain:
		return true
	default:
		return false
	}
}

func validUpgradeStateTransition(previous, next EdgeUpgradeState) bool {
	switch previous {
	case EdgeUpgradeStateAccepted:
		return next == EdgeUpgradeStateClaimed
	case EdgeUpgradeStateClaimed:
		return next == EdgeUpgradeStateInstalling
	case EdgeUpgradeStateInstalling:
		return next == EdgeUpgradeStateHealthy || next == EdgeUpgradeStateFailed ||
			next == EdgeUpgradeStateRollingBack || next == EdgeUpgradeStateUncertain
	case EdgeUpgradeStateRollingBack:
		return next == EdgeUpgradeStateRolledBack || next == EdgeUpgradeStateFailed || next == EdgeUpgradeStateUncertain
	default:
		return false
	}
}

func validUpgradeStateTransitionForAction(action string, previous, next EdgeUpgradeState) bool {
	if action == string(ActionUpgrade) {
		return validUpgradeStateTransition(previous, next)
	}
	if action != string(ActionRollback) {
		return false
	}
	switch previous {
	case EdgeUpgradeStateAccepted:
		return next == EdgeUpgradeStateClaimed
	case EdgeUpgradeStateClaimed:
		return next == EdgeUpgradeStateInstalling
	case EdgeUpgradeStateInstalling:
		return next == EdgeUpgradeStateRolledBack || next == EdgeUpgradeStateFailed || next == EdgeUpgradeStateUncertain
	default:
		return false
	}
}

func validReconciledUpgradeState(state EdgeUpgradeState) bool {
	return state == EdgeUpgradeStateUncertain || state == EdgeUpgradeStateHealthy ||
		state == EdgeUpgradeStateFailed || state == EdgeUpgradeStateRolledBack
}

func validReconciledUpgradeStateForAction(action string, state EdgeUpgradeState) bool {
	return validReconciledUpgradeState(state) &&
		(action == string(ActionUpgrade) || state != EdgeUpgradeStateHealthy)
}

func sameDurableStatusAck(left, right durableStatusAck) bool {
	return left.Version == right.Version && left.StatusID == right.StatusID && left.SHA256 == right.SHA256 &&
		left.CommandID == right.CommandID && left.StatusRevision == right.StatusRevision && left.State == right.State &&
		left.InstallerTransactionID == right.InstallerTransactionID
}

func statusAckMatchesStatus(ack durableStatusAck, status EdgeUpgradeStatus, digest string) bool {
	return ack.StatusID == status.StatusID && ack.SHA256 == digest && ack.CommandID == status.CommandID &&
		ack.StatusRevision == status.StatusRevision && ack.State == status.State &&
		ack.InstallerTransactionID == status.InstallerTransactionID
}

func validDurableClaim(claim durableUpgradeClaim) bool {
	grantDigest, err := base64.RawURLEncoding.DecodeString(claim.GrantDigest)
	bundleDigest, bundleErr := base64.RawURLEncoding.DecodeString(claim.ArtifactBundleSHA256)
	validSequenceFacts := claim.Schema == upgradeExecutionV2Schema && claim.ExecutionSequence == 0 &&
		claim.ReleaseSequence == 0 && claim.Component == ""
	if claim.Schema == upgradeExecutionV3Schema {
		validSequenceFacts = claim.ExecutionSequence > 0 && claim.ReleaseSequence > 0 &&
			upgradeExecutionCodePattern.MatchString(claim.Component)
	}
	return claim.Version == upgradeWireStateVersion && validDigest(claim.CommandSHA256) &&
		validDigest(claim.SignedExecutionSHA256) && validSequenceFacts &&
		validUpgradeExecutionUUID(claim.InstallationID) &&
		validUpgradeExecutionUUID(claim.NodeID) && validUpgradeExecutionUUID(claim.CommandID) &&
		validUpgradeExecutionUUID(claim.Nonce) && err == nil && len(grantDigest) == sha256.Size &&
		validUpgradeExecutionUUID(claim.PlanID) && claim.PlanRevision > 0 && claim.PlanRevision <= maxUpgradePlanRevision &&
		validUpgradeExecutionUUID(claim.BatchID) && validUpgradeExecutionUUID(claim.ArtifactBundleID) &&
		bundleErr == nil && len(bundleDigest) == sha256.Size && claim.CommandIssuanceNotAfter > 0 &&
		!claim.ExpiresAt.IsZero() && claim.ExpiresAt.Unix() <= claim.CommandIssuanceNotAfter
}

func durableClaimMatchesCommand(claim durableUpgradeClaim, command AcceptedUpgradeCommand) bool {
	envelope, err := decodeUpgradeExecution(command.Command.SignedExecution)
	sequenceFactsMatch := err == nil && envelope.Execution.Schema == upgradeExecutionV2Schema &&
		claim.ExecutionSequence == 0 && claim.ReleaseSequence == 0 && claim.Component == ""
	if err == nil && envelope.Execution.Schema == upgradeExecutionV3Schema {
		sequenceFactsMatch = claim.ExecutionSequence == envelope.Execution.ExecutionSequence &&
			claim.ReleaseSequence == envelope.Execution.ReleaseSequence && claim.Component == envelope.Execution.Component
	}
	return err == nil && claim.CommandID == command.Command.CommandID &&
		sequenceFactsMatch &&
		claim.Schema == envelope.Execution.Schema && claim.PlanID == command.Command.PlanID &&
		claim.PlanRevision == command.Command.PlanRevision && claim.BatchID == command.Command.BatchID &&
		claim.InstallationID == command.Command.InstallationID && claim.NodeID == command.Command.NodeID &&
		claim.Nonce == envelope.Execution.Nonce && claim.GrantDigest == envelope.Execution.GrantDigest &&
		claim.ArtifactBundleID == envelope.Execution.ArtifactBundleID &&
		claim.ArtifactBundleSHA256 == envelope.Execution.ArtifactBundleSHA256 &&
		claim.CommandIssuanceNotAfter == envelope.Execution.CommandIssuanceNotAfter &&
		claim.ExpiresAt.Equal(time.Unix(envelope.Execution.ExpiresAt, 0).UTC())
}

func sameDurableClaim(left, right durableUpgradeClaim) bool {
	return left.Version == right.Version && left.CommandSHA256 == right.CommandSHA256 &&
		left.SignedExecutionSHA256 == right.SignedExecutionSHA256 && left.Schema == right.Schema &&
		left.InstallationID == right.InstallationID &&
		left.NodeID == right.NodeID && left.CommandID == right.CommandID && left.Nonce == right.Nonce &&
		left.GrantDigest == right.GrantDigest && left.PlanID == right.PlanID && left.PlanRevision == right.PlanRevision &&
		left.BatchID == right.BatchID && left.ArtifactBundleID == right.ArtifactBundleID &&
		left.ArtifactBundleSHA256 == right.ArtifactBundleSHA256 &&
		left.ExecutionSequence == right.ExecutionSequence && left.ReleaseSequence == right.ReleaseSequence &&
		left.Component == right.Component &&
		left.CommandIssuanceNotAfter == right.CommandIssuanceNotAfter && left.ExpiresAt.Equal(right.ExpiresAt)
}

func invalidVersion(value string) bool {
	_, err := parseVersion(value)
	return err != nil
}

func acceptedUpgradeCommand(command EdgeUpgradeCommand, encoded []byte) AcceptedUpgradeCommand {
	return AcceptedUpgradeCommand{Command: command, Encoded: append([]byte(nil), encoded...), SHA256: sha256String(encoded)}
}

func queuedUpgradeStatus(status EdgeUpgradeStatus, encoded []byte) QueuedUpgradeStatus {
	return QueuedUpgradeStatus{Status: status, Encoded: append([]byte(nil), encoded...), SHA256: sha256String(encoded)}
}

func sha256String(value []byte) string {
	digest := sha256.Sum256(value)
	return hex.EncodeToString(digest[:])
}

func durableJSONPaths(directory string) ([]string, error) {
	entries, err := os.ReadDir(directory)
	if err != nil {
		return nil, err
	}
	paths := make([]string, 0, len(entries))
	for _, entry := range entries {
		if strings.HasPrefix(entry.Name(), ".") {
			continue
		}
		name := strings.TrimSuffix(entry.Name(), ".json")
		if entry.IsDir() || name == entry.Name() || !validUpgradeExecutionUUID(name) {
			return nil, ErrCorruptState
		}
		paths = append(paths, filepath.Join(directory, entry.Name()))
	}
	sort.Strings(paths)
	return paths, nil
}

func readDurableBytes(path string, maximum int64) ([]byte, bool, error) {
	file, err := os.Open(path)
	if errors.Is(err, os.ErrNotExist) {
		return nil, false, nil
	}
	if err != nil {
		return nil, false, err
	}
	defer file.Close()
	info, statErr := file.Stat()
	pathInfo, pathErr := os.Lstat(path)
	if statErr != nil || pathErr != nil || pathInfo.Mode()&os.ModeSymlink != 0 || !info.Mode().IsRegular() ||
		!os.SameFile(info, pathInfo) || info.Size() <= 0 || info.Size() > maximum {
		return nil, false, ErrCorruptState
	}
	if count, ok := regularLinkCount(info.Sys()); !ok || count != 1 {
		return nil, false, ErrCorruptState
	}
	encoded, err := io.ReadAll(io.LimitReader(file, maximum+1))
	if err != nil || int64(len(encoded)) != info.Size() {
		return nil, false, ErrCorruptState
	}
	return encoded, true, nil
}

func writeDurableBytes(path string, encoded []byte) error {
	if len(encoded) == 0 || len(encoded) > maxUpgradeWireBytes {
		return ErrCorruptState
	}
	directory := filepath.Dir(path)
	temporary := filepath.Join(directory, ".wire-"+randomSuffix())
	file, err := os.OpenFile(temporary, os.O_CREATE|os.O_EXCL|os.O_WRONLY, 0o600)
	if err != nil {
		return fmt.Errorf("create durable upgrade wire: %w", err)
	}
	ok := false
	defer func() {
		_ = file.Close()
		if !ok {
			_ = os.Remove(temporary)
		}
	}()
	if _, err := file.Write(encoded); err != nil {
		return fmt.Errorf("write durable upgrade wire: %w", err)
	}
	if err := file.Sync(); err != nil {
		return fmt.Errorf("sync durable upgrade wire: %w", err)
	}
	if err := file.Close(); err != nil {
		return fmt.Errorf("close durable upgrade wire: %w", err)
	}
	if err := os.Rename(temporary, path); err != nil {
		return fmt.Errorf("publish durable upgrade wire: %w", err)
	}
	ok = true
	return syncDirectory(directory)
}
