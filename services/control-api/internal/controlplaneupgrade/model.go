package controlplaneupgrade

import (
	"crypto/sha256"
	"encoding/hex"
	"errors"
	"path/filepath"
	"regexp"
)

const StateSchema = "cdnca.control-plane-upgrade-state/v1"

type Target string

const (
	TargetKubernetes       Target = "kubernetes"
	TargetSystemd          Target = "systemd"
	TargetNativeStandalone Target = "native-standalone"
)

type Phase string

const (
	PhaseVerified    Phase = "verified"
	PhaseExpanded    Phase = "expanded"
	PhasePreflighted Phase = "preflighted"
	PhaseDrained     Phase = "drained"
	// The three database phases only occur when a native candidate appends
	// migrations; other plans go straight from drained to activated.
	PhaseControlStopped   Phase = "control_stopped"
	PhaseDatabaseBackedUp Phase = "database_backed_up"
	PhaseDatabaseMigrated Phase = "database_migrated"
	PhaseActivated        Phase = "activated"
	PhaseHealthy          Phase = "healthy"
	PhaseContracted       Phase = "contracted"
	PhaseCompleted        Phase = "completed"
	PhaseRollingBack      Phase = "rolling_back"
	PhaseRolledBack       Phase = "rolled_back"
	PhaseFailed           Phase = "failed"
)

type Result string

const (
	ResultApplied    Result = "applied"
	ResultRolledBack Result = "rolled_back"
	ResultFailed     Result = "failed"
)

var (
	ErrInvalidConfig  = errors.New("invalid control-plane upgrade configuration")
	ErrInvalidPlan    = errors.New("invalid control-plane upgrade plan")
	ErrTargetMismatch = errors.New("control-plane upgrade target mismatch")
	ErrStalePlan      = errors.New("stale control-plane upgrade plan")
	ErrPlanConflict   = errors.New("control-plane upgrade plan conflict")
	ErrPlanInProgress = errors.New("another control-plane upgrade is in progress")
	ErrCorruptState   = errors.New("corrupt control-plane upgrade state")
	ErrStateNotFound  = errors.New("control-plane upgrade state not found")
	ErrRolledBack     = errors.New("control-plane upgrade rolled back")
	// ErrCandidateRejected marks a signed candidate that can never apply to the
	// current release (lineage, version or file compatibility). Retrying the
	// same plan cannot succeed, so the runner records a terminal failure.
	ErrCandidateRejected = errors.New("control-plane upgrade candidate rejected")
	// ErrArtifactUnavailable is a transient download failure; it never carries
	// the (possibly credential-bearing) artifact URL.
	ErrArtifactUnavailable = errors.New("control-plane upgrade artifact unavailable")
	// ErrBackupSpaceInsufficient keeps a migration plan before Drain until the
	// backup directory has room for a complete database dump.
	ErrBackupSpaceInsufficient = errors.New("control-plane database backup space insufficient")
)

// stepError gives a step failure a stable receipt/journal code instead of the
// step's default one. It never carries operator text into the receipt.
type stepError struct {
	code string
	err  error
}

func (failure *stepError) Error() string { return failure.err.Error() }
func (failure *stepError) Unwrap() error { return failure.err }

func withStepCode(code string, err error) error {
	if err == nil {
		return nil
	}
	return &stepError{code: code, err: err}
}

func stepCode(err error, fallback string) string {
	var coded *stepError
	if errors.As(err, &coded) && planErrorCode.MatchString(coded.code) {
		return coded.code
	}
	return fallback
}

var digestPattern = regexp.MustCompile(`^[0-9a-f]{64}$`)

type Artifact struct {
	ID       string `json:"id"`
	Version  string `json:"version"`
	Digest   string `json:"sha256"`
	URL      string `json:"url"`
	Size     int64  `json:"size"`
	Sequence uint64 `json:"sequence"`
}

type Plan struct {
	ID              string   `json:"id"`
	BundleID        string   `json:"bundle_id"`
	BundleSHA256    string   `json:"bundle_sha256"`
	InstallationID  string   `json:"installation_id"`
	Component       string   `json:"component"`
	CurrentVersion  string   `json:"current_version"`
	TargetVersion   string   `json:"target_version"`
	ProtocolVersion int      `json:"protocol_version"`
	Sequence        uint64   `json:"sequence"`
	Target          Artifact `json:"target"`
	Rollback        Artifact `json:"rollback"`
}

type Facts struct {
	InstallationID  string
	CurrentVersion  string
	CurrentDigest   string
	ProtocolVersion int
}

type Receipt struct {
	ID             string `json:"id"`
	PlanID         string `json:"plan_id"`
	BundleSHA256   string `json:"bundle_sha256"`
	Sequence       uint64 `json:"sequence"`
	Target         Target `json:"target"`
	CurrentVersion string `json:"current_version"`
	TargetVersion  string `json:"target_version"`
	Result         Result `json:"result"`
	ErrorCode      string `json:"error_code,omitempty"`
	CompletedAt    int64  `json:"completed_at"`
	// Migration is present only for plans that appended database migrations.
	Migration *MigrationRecord `json:"migration,omitempty"`
	Replayed  bool             `json:"-"`
}

type State struct {
	Schema         string   `json:"schema"`
	PlanID         string   `json:"plan_id"`
	BundleSHA256   string   `json:"bundle_sha256"`
	Sequence       uint64   `json:"sequence"`
	Phase          Phase    `json:"phase"`
	PreviousDigest string   `json:"previous_digest,omitempty"`
	TargetDigest   string   `json:"target_digest,omitempty"`
	ErrorCode      string   `json:"error_code,omitempty"`
	Receipt        *Receipt `json:"receipt,omitempty"`
	// Migration is the durable recovery record of a migrating plan: once
	// BackupPath is set, every rollback restores it before the old release.
	Migration *MigrationRecord `json:"migration,omitempty"`
}

// MigrationRecord is the evidence of one append-only database migration.
// Applied lists the appended migration identifiers in version order.
type MigrationRecord struct {
	Applied       []string `json:"applied"`
	Migrated      bool     `json:"migrated,omitempty"`
	BackupPath    string   `json:"backup_path,omitempty"`
	BackupBytes   int64    `json:"backup_bytes,omitempty"`
	BackupSHA256  string   `json:"backup_sha256,omitempty"`
	BackupMillis  int64    `json:"backup_ms,omitempty"`
	MigrateMillis int64    `json:"migrate_ms,omitempty"`
	Restored      bool     `json:"restored,omitempty"`
	RestoreMillis int64    `json:"restore_ms,omitempty"`
	// RolesError records why the superuser-only roles could not be ensured
	// before migrating; the migration still runs and features needing them
	// fail closed (FX01 retention cleanup).
	RolesError string `json:"roles_error,omitempty"`
}

const maxMigrationsPerPlan = 64

var migrationIdentifier = regexp.MustCompile(`^([0-9]{3})_[a-z0-9]+(?:_[a-z0-9]+)*$`)

func (record *MigrationRecord) clone() *MigrationRecord {
	if record == nil {
		return nil
	}
	copied := *record
	copied.Applied = append([]string(nil), record.Applied...)
	return &copied
}

func validMigrationRecord(record *MigrationRecord) bool {
	if record == nil {
		return true
	}
	if len(record.Applied) == 0 || len(record.Applied) > maxMigrationsPerPlan {
		return false
	}
	for index, name := range record.Applied {
		if len(name) > 96 || !migrationIdentifier.MatchString(name) || (index > 0 && name[:3] <= record.Applied[index-1][:3]) {
			return false
		}
	}
	if record.BackupPath == "" {
		return record.BackupBytes == 0 && record.BackupSHA256 == "" && !record.Migrated && !record.Restored && record.RestoreMillis == 0
	}
	return len(record.BackupPath) <= 1024 && filepath.IsAbs(record.BackupPath) && filepath.Clean(record.BackupPath) == record.BackupPath &&
		record.BackupBytes > 0 && digestPattern.MatchString(record.BackupSHA256) &&
		record.BackupMillis >= 0 && record.MigrateMillis >= 0 && record.RestoreMillis >= 0
}

func digestBytes(value []byte) string {
	digest := sha256.Sum256(value)
	return hex.EncodeToString(digest[:])
}

func validPhase(phase Phase) bool {
	switch phase {
	case PhaseVerified, PhaseExpanded, PhasePreflighted, PhaseDrained, PhaseControlStopped, PhaseDatabaseBackedUp,
		PhaseDatabaseMigrated, PhaseActivated, PhaseHealthy, PhaseContracted, PhaseCompleted, PhaseRollingBack,
		PhaseRolledBack, PhaseFailed:
		return true
	default:
		return false
	}
}
