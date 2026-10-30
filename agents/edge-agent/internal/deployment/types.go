package deployment

import (
	"crypto/sha256"
	"encoding/hex"
	"errors"
	"fmt"
	"path/filepath"
	"strings"
	"time"

	"github.com/cdnca/cdnca/libs/edgeconfig"
)

type State string

const (
	StateQueued         State = "queued"
	StateDelivered      State = "delivered"
	StateStaged         State = "staged"
	StatePrechecked     State = "prechecked"
	StateActivated      State = "activated"
	StateHealthy        State = "healthy"
	StateFailed         State = "failed"
	StateReverting      State = "reverting"
	StateReverted       State = "reverted"
	StateRollbackFailed State = "rollback_failed"
)

type Action string

const (
	ActionApply    Action = "apply"
	ActionRollback Action = "rollback"
)

var (
	ErrConflict        = errors.New("deployment command conflicts with recorded attempt")
	ErrStaleAttempt    = errors.New("deployment attempt is stale")
	ErrInvalidCommand  = errors.New("invalid deployment command")
	ErrInvalidPath     = errors.New("invalid path")
	ErrDigestMismatch  = errors.New("digest mismatch")
	ErrCorruptState    = errors.New("corrupt deployment state")
	ErrDrainNotReady   = errors.New("deployment drain is not ready")
	ErrDrainInProgress = errors.New("deployment old workers are draining")
	ErrDrainDeadline   = errors.New("deployment drain deadline exceeded")
)

type ProcessIdentity struct {
	PID              int    `json:"pid"`
	ParentPID        int    `json:"parent_pid"`
	Role             string `json:"role"`
	StartTicks       uint64 `json:"start_ticks"`
	ExecutableDevice uint64 `json:"executable_device"`
	ExecutableInode  uint64 `json:"executable_inode"`
	OwnerUID         uint32 `json:"owner_uid"`
	BootID           string `json:"boot_id"`
}

type RuntimeGeneration struct {
	Master  ProcessIdentity   `json:"master"`
	Workers []ProcessIdentity `json:"workers"`
}

type DrainPhase string

const (
	DrainPhaseHealthGate  DrainPhase = "health-gate"
	DrainPhaseDrainingOld DrainPhase = "draining-old"
	DrainPhaseCompleted   DrainPhase = "completed"
	DrainPhaseFailed      DrainPhase = "failed"
)

type DrainRequest struct {
	DeploymentID    string
	Revision        uint64
	Digest          string
	OldVersionID    string
	NewVersionID    string
	MaxDrain        time.Duration
	CommandDeadline time.Time
}

type DrainResult struct {
	DeploymentID        string
	Revision            uint64
	Digest              string
	Phase               DrainPhase
	StartedAt           time.Time
	Deadline            time.Time
	RemainingOldWorkers int
	Transitions         []DrainTransition
}

type DrainTransition struct {
	Sequence  uint64     `json:"sequence"`
	Phase     DrainPhase `json:"phase"`
	At        time.Time  `json:"at"`
	ErrorCode string     `json:"error_code,omitempty"`
}

type Limits struct {
	MaxFiles     int
	MaxFileSize  int64
	MaxTotalSize int64
}

type Config struct {
	Limits          Limits
	PrecheckTimeout time.Duration
	ReloadTimeout   time.Duration
	HealthTimeout   time.Duration
	HealthInterval  time.Duration
	RetainReleases  int
}

func DefaultConfig() Config {
	return Config{
		Limits: Limits{
			MaxFiles:     4096,
			MaxFileSize:  16 << 20,
			MaxTotalSize: 128 << 20,
		},
		PrecheckTimeout: 15 * time.Second,
		ReloadTimeout:   15 * time.Second,
		HealthTimeout:   30 * time.Second,
		HealthInterval:  500 * time.Millisecond,
		RetainReleases:  5,
	}
}

type FileManifest = edgeconfig.FileManifest
type Manifest = edgeconfig.Manifest
type Bundle = edgeconfig.Bundle

type Command struct {
	DeploymentID      string
	Attempt           uint32
	Action            Action
	ConfigVersionID   string
	PreviousVersionID string
	Bundle            Bundle
	// ScopeID routes the command on a multi-scope node. The single-scope
	// Manager ignores it; it is not part of the command digest.
	ScopeID string
}

type Transition struct {
	Sequence               uint64    `json:"sequence"`
	State                  State     `json:"state"`
	At                     time.Time `json:"at"`
	RunningConfigUnchanged bool      `json:"running_config_unchanged,omitempty"`
	ErrorCode              string    `json:"error_code,omitempty"`
	Summary                string    `json:"summary,omitempty"`
	// MaintenanceFailure: the terminal (healthy / reverted) transition of a
	// configuration that was activated but whose bookkeeping afterwards
	// (state save, retention) failed; reported as a failed check, never as
	// running_config_unchanged (PJ-E02).
	MaintenanceFailure string `json:"maintenance_failure,omitempty"`
}

type Result struct {
	DeploymentID           string
	Attempt                uint32
	Action                 Action
	ConfigVersionID        string
	State                  State
	Sequence               uint64
	Transitions            []Transition
	RunningConfigUnchanged bool
	ErrorCode              string
	Summary                string
}

type Pointers struct {
	Current        string `json:"current,omitempty"`
	CurrentDigest  string `json:"current_digest,omitempty"`
	Previous       string `json:"previous,omitempty"`
	PreviousDigest string `json:"previous_digest,omitempty"`
}

func (c Config) validate() error {
	if c.Limits.MaxFiles <= 0 || c.Limits.MaxFileSize <= 0 || c.Limits.MaxTotalSize <= 0 {
		return fmt.Errorf("%w: bundle limits must be positive", ErrInvalidCommand)
	}
	if c.Limits.MaxFileSize > c.Limits.MaxTotalSize {
		return fmt.Errorf("%w: per-file limit exceeds total limit", ErrInvalidCommand)
	}
	if c.PrecheckTimeout <= 0 || c.ReloadTimeout <= 0 || c.HealthTimeout <= 0 || c.HealthInterval <= 0 {
		return fmt.Errorf("%w: operation timeouts must be positive", ErrInvalidCommand)
	}
	if c.RetainReleases < 2 {
		return fmt.Errorf("%w: at least current and rollback releases must be retained", ErrInvalidCommand)
	}
	return nil
}

func validateBundleLimits(manifest Manifest, files map[string][]byte, limits Limits) error {
	if len(manifest.Files) > limits.MaxFiles || len(files) > limits.MaxFiles {
		return fmt.Errorf("%w: bundle contains too many files", ErrInvalidCommand)
	}
	var total int64
	for _, entry := range manifest.Files {
		if entry.Size > limits.MaxFileSize || entry.Size > limits.MaxTotalSize-total {
			return fmt.Errorf("%w: bundle size limit exceeded", ErrInvalidCommand)
		}
		total += entry.Size
	}
	total = 0
	for _, content := range files {
		size := int64(len(content))
		if size > limits.MaxFileSize || size > limits.MaxTotalSize-total {
			return fmt.Errorf("%w: bundle content size limit exceeded", ErrInvalidCommand)
		}
		total += size
	}
	return nil
}

func ManifestDigest(manifest Manifest) (string, error) {
	digest, err := edgeconfig.ManifestDigest(manifest)
	if err == nil {
		return digest, nil
	}
	return "", mapManifestError(err)
}

func normalizeManifest(manifest Manifest) (Manifest, error) {
	normalized, err := edgeconfig.NormalizeManifest(manifest)
	if err == nil {
		return normalized, nil
	}
	return Manifest{}, mapManifestError(err)
}

func mapManifestError(err error) error {
	if errors.Is(err, edgeconfig.ErrInvalidPath) {
		return fmt.Errorf("%w: %v", ErrInvalidPath, err)
	}
	return fmt.Errorf("%w: %v", ErrInvalidCommand, err)
}

func validateRelativePath(path string) error {
	if path == "" || filepath.IsAbs(path) || strings.ContainsRune(path, '\x00') || strings.Contains(path, `\`) {
		return fmt.Errorf("%w: unsafe relative path", ErrInvalidPath)
	}
	clean := filepath.Clean(path)
	if clean != path || clean == "." || clean == ".." || strings.HasPrefix(clean, ".."+string(filepath.Separator)) {
		return fmt.Errorf("%w: unsafe relative path", ErrInvalidPath)
	}
	for _, part := range strings.Split(path, string(filepath.Separator)) {
		if part == "" || part == "." || part == ".." {
			return fmt.Errorf("%w: unsafe relative path", ErrInvalidPath)
		}
	}
	return nil
}

func validateID(value, name string) error {
	if value == "" || value == "." || value == ".." || filepath.Base(value) != value || strings.ContainsAny(value, `/\\`) || strings.ContainsRune(value, '\x00') {
		return fmt.Errorf("%w: unsafe %s", ErrInvalidPath, name)
	}
	if len(value) > 255 {
		return fmt.Errorf("%w: %s is too long", ErrInvalidCommand, name)
	}
	for _, char := range value {
		if (char < 'a' || char > 'z') && (char < 'A' || char > 'Z') && (char < '0' || char > '9') && char != '.' && char != '_' && char != '-' {
			return fmt.Errorf("%w: unsafe %s", ErrInvalidPath, name)
		}
	}
	return nil
}

func validSHA256(value string) bool {
	if len(value) != sha256.Size*2 {
		return false
	}
	decoded, err := hex.DecodeString(value)
	return err == nil && len(decoded) == sha256.Size
}
