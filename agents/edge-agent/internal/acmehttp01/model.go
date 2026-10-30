package acmehttp01

import (
	"bytes"
	"context"
	"crypto/sha256"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"regexp"
	"sort"
	"strings"
	"time"

	"github.com/cdnca/cdnca/libs/edgeconfig"
	"github.com/google/uuid"
)

const (
	ArtifactMediaType     = "application/vnd.cdnca.acme-http01-overlay.v1+json"
	ArtifactSchemaVersion = "cdnca.edge.acme-http01-overlay/v1"
	RouteMarker           = edgeconfig.ACMEHTTP01RouteMarker
	ChallengePathPrefix   = edgeconfig.ACMEHTTP01ChallengePathPrefix
	MaxEntries            = 4096
	MaxArtifactBytes      = 8 << 20
	MaxChallengeLifetime  = 24 * time.Hour

	// Command purposes (ADR-0003). A cleanup_only snapshot names its purpose
	// in the signed bytes and carries no token; an apply snapshot names none.
	PurposeApply       = "apply"
	PurposeCleanupOnly = "cleanup_only"
)

var (
	ErrInvalidSnapshot  = errors.New("invalid ACME HTTP-01 overlay snapshot")
	ErrExpired          = errors.New("ACME HTTP-01 overlay is expired")
	ErrConflict         = errors.New("ACME HTTP-01 overlay conflicts with immutable state")
	ErrStaleAttempt     = errors.New("ACME HTTP-01 overlay attempt is stale")
	ErrRouteUnavailable = errors.New("ACME HTTP-01 route is unavailable")
	ErrPrecheckFailed   = errors.New("ACME HTTP-01 overlay precheck failed")
	ErrActivationFailed = errors.New("ACME HTTP-01 overlay activation failed")
	ErrHealthFailed     = errors.New("ACME HTTP-01 overlay health check failed")
	ErrRollbackFailed   = errors.New("ACME HTTP-01 overlay rollback failed")
	ErrInvalidStateRoot = errors.New("invalid ACME HTTP-01 overlay state root")
	ErrCorruptState     = errors.New("corrupt ACME HTTP-01 overlay state")
	tokenPattern        = regexp.MustCompile(`^[A-Za-z0-9_-]{22,256}$`)
	thumbprintPattern   = regexp.MustCompile(`^[A-Za-z0-9_-]{43}$`)
	hostLabelPattern    = regexp.MustCompile(`^[a-z0-9](?:[a-z0-9-]{0,61}[a-z0-9])?$`)
)

type Entry struct {
	Host      string    `json:"host"`
	Token     string    `json:"token"`
	Value     string    `json:"value"`
	ExpiresAt time.Time `json:"expires_at"`
}

type Snapshot struct {
	SchemaVersion    string    `json:"schema_version"`
	OverlayVersionID string    `json:"overlay_version_id"`
	OverlayRevision  uint64    `json:"overlay_revision"`
	Purpose          string    `json:"purpose,omitempty"`
	GeneratedAt      time.Time `json:"generated_at"`
	Entries          []Entry   `json:"entries"`
}

type HealthPolicy struct {
	ActivationTimeout            time.Duration
	ObservationWindow            time.Duration
	RequiredConsecutiveSuccesses uint32
}

type Command struct {
	DeploymentID      string
	Attempt           uint32
	OverlayVersionID  string
	OverlayRevision   uint64
	Purpose           string // PurposeApply or PurposeCleanupOnly; equals the snapshot's signed purpose
	PreviousVersionID *string
	PreviousRevision  *uint64
	ArtifactSHA256    [sha256.Size]byte
	CommandSHA256     [sha256.Size]byte
	Snapshot          Snapshot
	Health            HealthPolicy
	Deadline          time.Time
}

type State string

const (
	StateStaged         State = "staged"
	StatePrechecked     State = "prechecked"
	StateActivated      State = "activated"
	StateHealthy        State = "healthy"
	StateFailed         State = "failed"
	StateReverting      State = "reverting"
	StateReverted       State = "reverted"
	StateRollbackFailed State = "rollback_failed"
)

type Transition struct {
	Sequence        uint64
	State           State
	At              time.Time
	ResultCode      string
	Summary         string
	ActiveUnchanged bool
}

type Pointer struct {
	VersionID string `json:"version_id,omitempty"`
	Revision  uint64 `json:"revision,omitempty"`
	SHA256    string `json:"sha256,omitempty"`
}

type Result struct {
	DeploymentID string
	Attempt      uint32
	VersionID    string
	Revision     uint64
	State        State
	Transitions  []Transition
	Active       Pointer
}

type Consumer interface {
	Apply(context.Context, Command) (Result, error)
	Ready() bool
	Current() (Pointer, error)
}

func DecodeSnapshot(content []byte, now time.Time) (Snapshot, error) {
	snapshot, err := DecodeSnapshotStructure(content)
	if err != nil {
		return Snapshot{}, err
	}
	if err := ValidateSnapshot(snapshot, now); err != nil {
		return Snapshot{}, err
	}
	return snapshot, nil
}

func DecodeSnapshotStructure(content []byte) (Snapshot, error) {
	if len(content) == 0 || len(content) > MaxArtifactBytes {
		return Snapshot{}, ErrInvalidSnapshot
	}
	decoder := json.NewDecoder(bytes.NewReader(content))
	decoder.DisallowUnknownFields()
	var snapshot Snapshot
	if err := decoder.Decode(&snapshot); err != nil || decoder.Decode(&struct{}{}) != io.EOF {
		return Snapshot{}, ErrInvalidSnapshot
	}
	if err := validateSnapshotStructure(snapshot); err != nil {
		return Snapshot{}, err
	}
	return snapshot, nil
}

func ValidateSnapshot(snapshot Snapshot, now time.Time) error {
	if err := validateSnapshotStructure(snapshot); err != nil || snapshot.GeneratedAt.After(now.Add(5*time.Minute)) {
		return ErrInvalidSnapshot
	}
	for _, entry := range snapshot.Entries {
		if !entry.ExpiresAt.After(now) {
			return ErrExpired
		}
		if entry.ExpiresAt.After(now.Add(MaxChallengeLifetime)) {
			return ErrInvalidSnapshot
		}
	}
	return nil
}

func validateSnapshotStructure(snapshot Snapshot) error {
	if snapshot.SchemaVersion != ArtifactSchemaVersion || !canonicalUUID(snapshot.OverlayVersionID) ||
		snapshot.OverlayRevision == 0 || snapshot.GeneratedAt.IsZero() || len(snapshot.Entries) > MaxEntries ||
		snapshot.Purpose != "" && (snapshot.Purpose != PurposeCleanupOnly || len(snapshot.Entries) != 0) {
		return ErrInvalidSnapshot
	}
	seen := make(map[string]struct{}, len(snapshot.Entries))
	for index, entry := range snapshot.Entries {
		if !validHost(entry.Host) || !tokenPattern.MatchString(entry.Token) ||
			!validChallengeValue(entry.Token, entry.Value) || entry.ExpiresAt.IsZero() {
			return ErrInvalidSnapshot
		}
		key := entry.Host + "\x00" + entry.Token
		if _, exists := seen[key]; exists {
			return ErrInvalidSnapshot
		}
		seen[key] = struct{}{}
		if index > 0 && compareEntry(snapshot.Entries[index-1], entry) >= 0 {
			return ErrInvalidSnapshot
		}
	}
	return nil
}

func CanonicalSnapshot(snapshot Snapshot) ([]byte, error) {
	copySnapshot := snapshot
	copySnapshot.Entries = append([]Entry(nil), snapshot.Entries...)
	sort.Slice(copySnapshot.Entries, func(i, j int) bool {
		return compareEntry(copySnapshot.Entries[i], copySnapshot.Entries[j]) < 0
	})
	encoded, err := json.Marshal(copySnapshot)
	if err != nil {
		return nil, fmt.Errorf("marshal ACME HTTP-01 snapshot: %w", err)
	}
	return encoded, nil
}

func validateCommand(command Command, now time.Time) error {
	if err := validateCommandStructure(command); err != nil {
		return err
	}
	if !command.Deadline.After(now) {
		return ErrExpired
	}
	return ValidateSnapshot(command.Snapshot, now)
}

func validateCommandStructure(command Command) error {
	if !canonicalUUID(command.DeploymentID) || command.Attempt == 0 ||
		!canonicalUUID(command.OverlayVersionID) || command.OverlayRevision == 0 ||
		command.Snapshot.OverlayVersionID != command.OverlayVersionID ||
		command.Snapshot.OverlayRevision != command.OverlayRevision || command.Deadline.IsZero() ||
		!(command.Purpose == PurposeApply && command.Snapshot.Purpose == "" ||
			command.Purpose == PurposeCleanupOnly && command.Snapshot.Purpose == PurposeCleanupOnly) ||
		command.Health.ActivationTimeout <= 0 ||
		command.Health.ObservationWindow < 0 || command.Health.RequiredConsecutiveSuccesses == 0 {
		return ErrInvalidSnapshot
	}
	if (command.PreviousVersionID == nil) != (command.PreviousRevision == nil) {
		return ErrInvalidSnapshot
	}
	if command.PreviousVersionID != nil && (!canonicalUUID(*command.PreviousVersionID) || *command.PreviousRevision == 0 || *command.PreviousRevision >= command.OverlayRevision) {
		return ErrInvalidSnapshot
	}
	return validateSnapshotStructure(command.Snapshot)
}

func validHost(host string) bool {
	if host == "" || len(host) > 253 || host != strings.ToLower(host) || strings.HasSuffix(host, ".") || strings.Contains(host, "..") {
		return false
	}
	labels := strings.Split(host, ".")
	if len(labels) < 2 {
		return false
	}
	for _, label := range labels {
		if !hostLabelPattern.MatchString(label) {
			return false
		}
	}
	return true
}

func validChallengeValue(token, value string) bool {
	if len(value) != len(token)+1+43 || !strings.HasPrefix(value, token+".") {
		return false
	}
	return thumbprintPattern.MatchString(value[len(token)+1:])
}

func compareEntry(left, right Entry) int {
	if left.Host < right.Host {
		return -1
	}
	if left.Host > right.Host {
		return 1
	}
	return strings.Compare(left.Token, right.Token)
}

func canonicalUUID(value string) bool {
	parsed, err := uuid.Parse(value)
	return err == nil && parsed.String() == value
}
