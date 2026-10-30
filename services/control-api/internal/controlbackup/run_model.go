package controlbackup

import (
	"encoding/json"
	"errors"
	"time"
)

const (
	BackupRunStartSchema    = "cdnca.control-backup-run-start/v1"
	BackupRunTerminalSchema = "cdnca.control-backup-run-terminal/v1"
	SignedBackupRunSchema   = "cdnca.control-backup-run.signed/v1"
	BackupRunSucceeded      = "succeeded"
	BackupRunFailed         = "failed"
)

var (
	ErrBackupRunInvalid   = errors.New("backup_run_invalid")
	ErrBackupRunIntegrity = errors.New("backup_run_integrity_failed")
	ErrBackupRunConflict  = errors.New("backup_run_idempotency_conflict")
	ErrBackupRunUnknown   = errors.New("backup_outcome_unknown")
	ErrBackupRunStore     = errors.New("backup_run_store_failed")
	ErrBackupRunLegacy    = errors.New("backup_run_legacy_untracked")
)

// BackupRunStart is persisted before acquiring the write freeze. Scope is bound
// by the importing control installation, never by the signed file's author.
type BackupRunStart struct {
	Schema          string    `json:"schema"`
	BackupID        string    `json:"backup_id"`
	InstallationID  string    `json:"installation_id"`
	SourceClusterID string    `json:"source_cluster_id"`
	PlanSHA256      string    `json:"plan_sha256"`
	StartedAt       time.Time `json:"started_at"`
}

// BackupRunTerminal exists only after Run has returned with a confirmed release.
// The optional success fields preserve the existing CLI's replayable output.
type BackupRunTerminal struct {
	Schema             string     `json:"schema"`
	BackupID           string     `json:"backup_id"`
	StartSHA256        string     `json:"start_sha256"`
	CompletedAt        time.Time  `json:"completed_at"`
	State              string     `json:"state"`
	ResultCode         string     `json:"result_code"`
	ManifestSHA256     string     `json:"manifest_sha256,omitempty"`
	RecoveryPointAt    *time.Time `json:"recovery_point_at,omitempty"`
	ObservedRPOSeconds *int64     `json:"observed_rpo_seconds,omitempty"`
}

type SignedBackupRunFact struct {
	Schema        string          `json:"schema"`
	Payload       json.RawMessage `json:"payload"`
	PayloadSHA256 string          `json:"payload_sha256"`
	SigningKeyID  string          `json:"signing_key_id"`
	Signature     string          `json:"signature"`
}

// Installation/source are required. Importers may omit backup/plan bindings;
// the execution store requires all four before it reads any previous result.
type BackupRunExpectation struct {
	InstallationID  string
	SourceClusterID string
	BackupID        string
	PlanSHA256      string
}

type VerifiedBackupRun struct {
	Start          BackupRunStart
	Terminal       *BackupRunTerminal
	SignedStart    SignedBackupRunFact
	SignedTerminal *SignedBackupRunFact
}

// BackupRunError never exposes driver errors in its text. Unknown means that
// freeze acquisition or release could not be confirmed and forbids a terminal.
type BackupRunError struct {
	Code           string
	OutcomeUnknown bool
	Err            error
}

func (failure *BackupRunError) Error() string { return failure.Code }
func (failure *BackupRunError) Unwrap() error { return failure.Err }
