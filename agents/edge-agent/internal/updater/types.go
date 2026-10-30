package updater

import (
	"context"
	"crypto/ed25519"
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"
	"errors"
	"io"
	"os"
	"runtime"
	"strings"
	"time"
)

type Action string

const (
	ActionUpgrade  Action = "upgrade"
	ActionRollback Action = "rollback"
)

type State string

const (
	StateSucceeded  State = "succeeded"
	StateRolledBack State = "rolled_back"
	StateFailed     State = "failed"
)

var (
	ErrInvalidPlan       = errors.New("invalid upgrade plan")
	ErrInvalidSignature  = errors.New("invalid upgrade plan signature")
	ErrUnknownKey        = errors.New("unknown upgrade signing key")
	ErrExpired           = errors.New("upgrade plan expired")
	ErrReplay            = errors.New("upgrade plan replay rejected")
	ErrDowngrade         = errors.New("upgrade plan would downgrade the agent")
	ErrIncompatible      = errors.New("upgrade plan is incompatible with this agent")
	ErrUnsafePath        = errors.New("unsafe updater path")
	ErrArtifactTooLarge  = errors.New("upgrade artifact exceeds its size limit")
	ErrArtifactIntegrity = errors.New("upgrade artifact integrity check failed")
	ErrInsufficientDisk  = errors.New("insufficient disk space for upgrade")
	// ErrStateIncompatible: Config.BeforeActivating refused the target
	// version (local state it cannot read); reported as L4_STATE_INCOMPATIBLE.
	ErrStateIncompatible  = errors.New("node state cannot be read by the target agent version")
	ErrDownloadPolicy     = errors.New("artifact URL is not allowed by download policy")
	ErrDownload           = errors.New("artifact download failed")
	ErrActivation         = errors.New("upgraded agent failed to start")
	ErrHealth             = errors.New("upgraded agent failed health verification")
	ErrRollback           = errors.New("automatic rollback failed")
	ErrCorruptState       = errors.New("corrupt updater state")
	ErrInvalidReceipt     = errors.New("invalid installer receipt")
	ErrInstaller          = errors.New("installer operation failed")
	ErrInstallerUnknown   = errors.New("installer transaction is unknown")
	ErrInstallerUncertain = errors.New("installer state is uncertain")
	ErrRolloutIneligible  = errors.New("node is outside the signed rollout cohort")
)

type Artifact struct {
	URL    string `json:"url"`
	SHA256 string `json:"sha256"`
	Size   int64  `json:"size"`
}

type Compatibility struct {
	MinAgentVersion string `json:"min_agent_version"`
	MaxAgentVersion string `json:"max_agent_version"`
}

type HealthPolicy struct {
	Command                      []string      `json:"command,omitempty"`
	ActivationTimeout            time.Duration `json:"activation_timeout"`
	ObservationWindow            time.Duration `json:"observation_window"`
	Interval                     time.Duration `json:"interval"`
	ProbeTimeout                 time.Duration `json:"probe_timeout"`
	RequiredConsecutiveSuccesses int           `json:"required_consecutive_successes"`
}

type RollbackPolicy struct {
	Automatic bool `json:"automatic"`
}

type RolloutPolicy struct {
	Percentage uint8  `json:"percentage"`
	CohortSalt string `json:"cohort_salt"`
}

type Signature struct {
	KeyID string `json:"key_id"`
	Value string `json:"value"`
}

type Plan struct {
	Domain                  string         `json:"domain,omitempty"`
	SchemaVersion           int            `json:"schema_version"`
	PlanID                  string         `json:"plan_id"`
	Revision                uint64         `json:"revision"`
	BatchID                 string         `json:"batch_id,omitempty"`
	ArtifactBundleID        string         `json:"artifact_bundle_id,omitempty"`
	ArtifactBundleSHA256    string         `json:"artifact_bundle_sha256,omitempty"`
	CommandIssuanceNotAfter int64          `json:"command_issuance_not_after,omitempty"`
	ExecutionSequence       uint64         `json:"execution_sequence,omitempty"`
	ReleaseSequence         uint64         `json:"release_sequence"`
	IssuedAt                time.Time      `json:"issued_at"`
	ExpiresAt               time.Time      `json:"expires_at"`
	Action                  Action         `json:"action"`
	CurrentVersion          string         `json:"current_version"`
	TargetVersion           string         `json:"target_version"`
	Platform                string         `json:"platform"`
	Architecture            string         `json:"architecture"`
	Artifact                Artifact       `json:"artifact"`
	Compatibility           Compatibility  `json:"compatibility"`
	Health                  HealthPolicy   `json:"health"`
	Rollout                 RolloutPolicy  `json:"rollout"`
	Rollback                RollbackPolicy `json:"rollback"`
	Signature               Signature      `json:"signature"`
}

type Result struct {
	PlanID                 string               `json:"plan_id"`
	Revision               uint64               `json:"revision"`
	ExecutionSequence      uint64               `json:"execution_sequence,omitempty"`
	ReleaseSequence        uint64               `json:"release_sequence"`
	State                  State                `json:"state"`
	CurrentVersion         string               `json:"current_version"`
	PreviousVersion        string               `json:"previous_version,omitempty"`
	InstallerTransactionID string               `json:"installer_transaction_id"`
	ErrorCode              string               `json:"error_code,omitempty"`
	AlertRequired          bool                 `json:"alert_required,omitempty"`
	ActiveEvidence         *ActiveProbeEvidence `json:"active_evidence,omitempty"`
	Duplicate              bool                 `json:"-"`
}

const ActiveProbeEvidenceSchema = "cdnca.edge.upgrade.active-probe/v1"

type ActiveProbeEvidence struct {
	Schema                      string    `json:"schema"`
	ActiveArtifactSHA256        string    `json:"active_artifact_sha256"`
	ActiveConfigSHA256          string    `json:"active_config_sha256"`
	LastKnownGoodArtifactSHA256 string    `json:"last_known_good_artifact_sha256"`
	LastKnownGoodConfigSHA256   string    `json:"last_known_good_config_sha256"`
	ProbeObservedAt             time.Time `json:"probe_observed_at"`
	ProbeDeadline               time.Time `json:"probe_deadline"`
	EvidenceSHA256              string    `json:"evidence_sha256"`
}

type ConfigProbeEvidence struct {
	ActiveConfigSHA256        string
	LastKnownGoodConfigSHA256 string
}

type evidenceProbe interface {
	Evidence(context.Context, ActivationReceipt, []string) (ConfigProbeEvidence, error)
}

func activeProbeEvidenceDigest(installerTransactionID string, evidence ActiveProbeEvidence) string {
	canonical, _ := json.Marshal(struct {
		Schema                      string    `json:"schema"`
		ActiveArtifactSHA256        string    `json:"active_artifact_sha256"`
		ActiveConfigSHA256          string    `json:"active_config_sha256"`
		LastKnownGoodArtifactSHA256 string    `json:"last_known_good_artifact_sha256"`
		LastKnownGoodConfigSHA256   string    `json:"last_known_good_config_sha256"`
		InstallerTransactionID      string    `json:"installer_transaction_id"`
		ProbeObservedAt             time.Time `json:"probe_observed_at"`
		ProbeDeadline               time.Time `json:"probe_deadline"`
	}{
		Schema: evidence.Schema, ActiveArtifactSHA256: evidence.ActiveArtifactSHA256,
		ActiveConfigSHA256:          evidence.ActiveConfigSHA256,
		LastKnownGoodArtifactSHA256: evidence.LastKnownGoodArtifactSHA256,
		LastKnownGoodConfigSHA256:   evidence.LastKnownGoodConfigSHA256,
		InstallerTransactionID:      installerTransactionID,
		ProbeObservedAt:             evidence.ProbeObservedAt.UTC(), ProbeDeadline: evidence.ProbeDeadline.UTC(),
	})
	digest := sha256.Sum256(canonical)
	return hex.EncodeToString(digest[:])
}

func validateActiveProbeEvidence(installerTransactionID string, evidence *ActiveProbeEvidence) error {
	if evidence == nil || evidence.Schema != ActiveProbeEvidenceSchema ||
		!validActiveProbeDigest(evidence.ActiveArtifactSHA256) ||
		!validActiveProbeDigest(evidence.ActiveConfigSHA256) ||
		!validActiveProbeDigest(evidence.LastKnownGoodArtifactSHA256) ||
		!validActiveProbeDigest(evidence.LastKnownGoodConfigSHA256) ||
		!safeIDPattern.MatchString(installerTransactionID) || evidence.ProbeObservedAt.IsZero() ||
		evidence.ProbeDeadline.IsZero() || evidence.ProbeObservedAt.After(evidence.ProbeDeadline) ||
		activeProbeEvidenceDigest(installerTransactionID, *evidence) != evidence.EvidenceSHA256 {
		return ErrInvalidReceipt
	}
	_, observedOffset := evidence.ProbeObservedAt.Zone()
	_, deadlineOffset := evidence.ProbeDeadline.Zone()
	if observedOffset != 0 || deadlineOffset != 0 {
		return ErrInvalidReceipt
	}
	return nil
}

func validActiveProbeDigest(value string) bool {
	decoded, err := hex.DecodeString(value)
	return err == nil && len(decoded) == sha256.Size && value == strings.ToLower(value)
}

func cloneActiveProbeEvidence(evidence *ActiveProbeEvidence) *ActiveProbeEvidence {
	if evidence == nil {
		return nil
	}
	clone := *evidence
	return &clone
}

type Clock interface {
	Now() time.Time
	Sleep(context.Context, time.Duration) error
}

type realClock struct{}

func (realClock) Now() time.Time { return time.Now() }

func (realClock) Sleep(ctx context.Context, duration time.Duration) error {
	timer := time.NewTimer(duration)
	defer timer.Stop()
	select {
	case <-ctx.Done():
		return ctx.Err()
	case <-timer.C:
		return nil
	}
}

type DownloadRequest struct {
	URL      string
	MaxBytes int64
}

type Downloader interface {
	Download(context.Context, DownloadRequest, io.Writer) error
}

type ReceiptStatus string

const (
	ReceiptStatusActive     ReceiptStatus = "active"
	ReceiptStatusRolledBack ReceiptStatus = "rolled_back"
)

type ActivationReceipt struct {
	SchemaVersion          int           `json:"schema_version"`
	InstallerTransactionID string        `json:"installer_transaction_id"`
	ExecutionSequence      uint64        `json:"execution_sequence,omitempty"`
	ReleaseSequence        uint64        `json:"release_sequence"`
	ArtifactSHA256         string        `json:"artifact_sha256"`
	CurrentVersion         string        `json:"current_version"`
	PreviousVersion        string        `json:"previous_version,omitempty"`
	Status                 ReceiptStatus `json:"status"`
	IssuedAt               time.Time     `json:"issued_at"`
	Signature              Signature     `json:"signature"`
}

type InstallRequest struct {
	InstallerTransactionID string
	ExecutionSequence      uint64
	ReleaseSequence        uint64
	Action                 Action
	CurrentVersion         string
	TargetVersion          string
	Platform               string
	Architecture           string
	ArtifactSHA256         string
	ArtifactSize           int64
	StagedPath             string
	Artifact               *os.File
	CurrentReceipt         ActivationReceipt
}

const (
	InstallerProtocolV2            = 2
	InstallerProtocolV3            = 3
	maxInstallerActivationAttempts = 2
)

type PreparedInstall struct {
	SchemaVersion          int    `json:"schema_version"`
	InstallerTransactionID string `json:"installer_transaction_id"`
	InstallPayloadSHA256   string `json:"install_payload_sha256"`
	ExecutionSequence      uint64 `json:"execution_sequence,omitempty"`
	ReleaseSequence        uint64 `json:"release_sequence"`
	ArtifactSHA256         string `json:"artifact_sha256"`
	ManifestSHA256         string `json:"manifest_sha256"`
	ExecutableSHA256       string `json:"executable_sha256"`
	SBOMSHA256             string `json:"sbom_sha256"`
	PreviousVersion        string `json:"previous_version"`
	TargetVersion          string `json:"target_version"`
}

type InstallerTransactionPhase string

const (
	InstallerTransactionUnknown    InstallerTransactionPhase = "unknown"
	InstallerTransactionPrepared   InstallerTransactionPhase = "prepared"
	InstallerTransactionInstalling InstallerTransactionPhase = "installing"
	InstallerTransactionAborted    InstallerTransactionPhase = "aborted"
	InstallerTransactionActive     InstallerTransactionPhase = "active"
	InstallerTransactionRolledBack InstallerTransactionPhase = "rolled_back"
)

type InstallerTransaction struct {
	InstallerTransactionID string
	Phase                  InstallerTransactionPhase
	Prepared               PreparedInstall
	Receipt                ActivationReceipt
}

type RollbackRequest struct {
	InstallerTransactionID string
	ReleaseSequence        uint64
	ArtifactSHA256         string
	ExpectedCurrentVersion string
	RollbackVersion        string
	ActiveReceipt          ActivationReceipt
	PreviousReceipt        ActivationReceipt
}

type Installer interface {
	Current(context.Context) (ActivationReceipt, error)
	Install(context.Context, InstallRequest) (ActivationReceipt, error)
	Query(context.Context, string) (ActivationReceipt, error)
	Rollback(context.Context, RollbackRequest) (ActivationReceipt, error)
}

type InstallerV2 interface {
	ProtocolVersion() int
	Prepare(context.Context, InstallRequest) (PreparedInstall, error)
	Inspect(context.Context, string) (InstallerTransaction, error)
	MarkInstalling(context.Context, PreparedInstall) (InstallerTransaction, error)
	Activate(context.Context, PreparedInstall) (ActivationReceipt, error)
	Abort(context.Context, PreparedInstall) (InstallerTransaction, error)
}

type Probe interface {
	Check(context.Context, ActivationReceipt, []string) error
}

type Config struct {
	Root             string
	Platform         string
	Architecture     string
	AgentVersion     string
	NodeID           string
	Keys             map[string]ed25519.PublicKey
	ReceiptKeys      map[string]ed25519.PublicKey
	Downloader       Downloader
	Installer        Installer
	Probe            Probe
	Clock            Clock
	MaxArtifactBytes int64
	DiskReserveBytes int64
	// BeforeActivating, when set, runs before the installer is asked to make
	// version the active agent (an upgrade or downgrade plan, and the
	// automatic rollback to the previous version). It prepares local state
	// that version must read; an error refuses the activation (the plan
	// fails with L4_STATE_INCOMPATIBLE, a rollback keeps the running version).
	// It must be idempotent: it runs again on retries and recovery.
	BeforeActivating func(ctx context.Context, version string) error
}

func DefaultConfig(root, agentVersion string, keys, receiptKeys map[string]ed25519.PublicKey, downloader Downloader, installer Installer, probe Probe) Config {
	return Config{
		Root: root, Platform: runtime.GOOS, Architecture: runtime.GOARCH,
		AgentVersion: agentVersion, Keys: keys, ReceiptKeys: receiptKeys, Downloader: downloader, Installer: installer, Probe: probe,
		Clock: realClock{}, MaxArtifactBytes: 285229182, DiskReserveBytes: 64 << 20,
	}
}
