package securityreleaseruntime

import (
	"context"
	"crypto/ed25519"
	"crypto/sha256"
	"encoding/hex"
	"errors"
	"fmt"
	"regexp"
	"strconv"
	"strings"
	"time"

	"github.com/cdnca/cdnca/agents/edge-agent/internal/securityrelease"
	"github.com/google/uuid"
)

const (
	RecordSchema                = "cdnca.edge.security-release-runtime/v1"
	SignedUpdaterAdapterVersion = 1
	maxSignedCommandBytes       = 1 << 20
)

var (
	ErrInvalidConfig         = errors.New("invalid security release runtime configuration")
	ErrManifestRejected      = errors.New("security release manifest rejected")
	ErrFactsUnavailable      = errors.New("security release runtime facts unavailable")
	ErrStaleSequence         = errors.New("security release sequence is stale")
	ErrSequenceConflict      = errors.New("security release sequence conflicts with durable state")
	ErrSignedCommandRequired = errors.New("signed updater command is required")
	ErrSignedCommandConflict = errors.New("signed updater command conflicts with durable state")
	ErrUpdaterUnavailable    = errors.New("signed updater adapter is unavailable")
	ErrUpdaterExecution      = errors.New("signed updater execution failed")
	ErrReceiptMismatch       = errors.New("signed updater receipt conflicts with durable state")
	ErrCorruptState          = errors.New("security release runtime state is corrupt")
)

type State string

const (
	StatePending    State = "pending"
	StateHeld       State = "held"
	StateActive     State = "active"
	StateRolledBack State = "rolled_back"
)

type RuntimeFacts struct {
	NodeID             string
	AgentVersion       string
	RuntimeVersion     string
	RuntimeImageDigest string
}

type RuntimeFactsSource interface {
	Current(context.Context) (RuntimeFacts, error)
}

type ExecutionRequest struct {
	Version               uint32
	ExecutionID           string
	NodeID                string
	ReleaseID             string
	ReleaseSequence       uint64
	ManifestSHA256        string
	Action                securityrelease.Action
	CurrentRuntimeVersion string
	TargetRuntimeVersion  string
	LKGRuntimeVersion     string
	LKGImageDigest        string
	SignedCommand         []byte
	SignedCommandSHA256   string
}

type ExecutionReceipt struct {
	Version                uint32
	ExecutionID            string
	NodeID                 string
	ReleaseID              string
	ReleaseSequence        uint64
	ManifestSHA256         string
	Action                 securityrelease.Action
	InstallerTransactionID string
	PreviousRuntimeVersion string
	ResultRuntimeVersion   string
	LKGRuntimeVersion      string
	LKGImageDigest         string
	ActiveReceiptSHA256    string
	RollbackReceiptSHA256  string
}

// SignedUpdaterAdapter executes an already signed updater command. Implementations
// must use ExecutionID as their idempotency key and return the same receipt on replay.
type SignedUpdaterAdapter interface {
	Version() uint32
	Execute(context.Context, ExecutionRequest) (ExecutionReceipt, error)
}

type Record struct {
	Schema                 string                     `json:"schema"`
	NodeID                 string                     `json:"node_id"`
	ReleaseID              string                     `json:"release_id"`
	ReleaseSequence        uint64                     `json:"release_sequence"`
	ManifestSHA256         string                     `json:"manifest_sha256"`
	DecisionAction         securityrelease.Action     `json:"decision_action"`
	DecisionReason         securityrelease.ReasonCode `json:"decision_reason"`
	CurrentRuntimeVersion  string                     `json:"current_runtime_version"`
	TargetRuntimeVersion   string                     `json:"target_runtime_version"`
	RolloutPhase           securityrelease.Phase      `json:"rollout_phase"`
	ExecutionID            string                     `json:"execution_id"`
	SignedCommandSHA256    string                     `json:"signed_command_sha256,omitempty"`
	InstallerTransactionID string                     `json:"installer_transaction_id,omitempty"`
	ActiveReceiptSHA256    string                     `json:"active_receipt_sha256,omitempty"`
	RollbackReceiptSHA256  string                     `json:"rollback_receipt_sha256,omitempty"`
	LKGRuntimeVersion      string                     `json:"lkg_runtime_version"`
	LKGImageDigest         string                     `json:"lkg_image_digest"`
	State                  State                      `json:"state"`
	RecordedAt             time.Time                  `json:"recorded_at"`
	CompletedAt            time.Time                  `json:"completed_at,omitempty"`
}

type Config struct {
	Root         string
	NodeID       string
	ManifestKeys map[string]ed25519.PublicKey
	Facts        RuntimeFactsSource
	Updater      SignedUpdaterAdapter
	Clock        func() time.Time
}

type Runtime struct {
	nodeID  string
	keys    map[string]ed25519.PublicKey
	facts   RuntimeFactsSource
	updater SignedUpdaterAdapter
	now     func() time.Time
	store   *diskStore
}

func NewRuntime(config Config) (*Runtime, error) {
	parsed, err := uuid.Parse(config.NodeID)
	if err != nil || parsed == uuid.Nil || parsed.String() != config.NodeID || config.Facts == nil || len(config.ManifestKeys) == 0 {
		return nil, ErrInvalidConfig
	}
	keys := make(map[string]ed25519.PublicKey, len(config.ManifestKeys))
	for keyID, key := range config.ManifestKeys {
		if !safeToken(keyID) || len(key) != ed25519.PublicKeySize {
			return nil, ErrInvalidConfig
		}
		keys[keyID] = append(ed25519.PublicKey(nil), key...)
	}
	if config.Clock == nil {
		config.Clock = time.Now
	}
	store, err := newDiskStore(config.Root)
	if err != nil {
		return nil, err
	}
	return &Runtime{
		nodeID: config.NodeID, keys: keys, facts: config.Facts,
		updater: config.Updater, now: config.Clock, store: store,
	}, nil
}

func (runtime *Runtime) Current(ctx context.Context) (Record, bool, error) {
	if runtime == nil || runtime.store == nil || ctx == nil {
		return Record{}, false, ErrInvalidConfig
	}
	var record Record
	var found bool
	err := runtime.store.withLock(ctx, func() error {
		loaded, err := runtime.store.loadLocked()
		if err != nil || loaded == nil {
			return err
		}
		record, found = *loaded, true
		return nil
	})
	return record, found, err
}

func (runtime *Runtime) Apply(ctx context.Context, encodedManifest, signedCommand []byte) (Record, error) {
	if runtime == nil || runtime.store == nil || runtime.facts == nil || runtime.now == nil || ctx == nil {
		return Record{}, ErrInvalidConfig
	}
	manifestDigest := sha256.Sum256(encodedManifest)
	manifestSHA256 := hex.EncodeToString(manifestDigest[:])
	var result Record
	err := runtime.store.withLock(ctx, func() error {
		current, err := runtime.store.loadLocked()
		if err != nil {
			return err
		}
		if current != nil && current.ManifestSHA256 == manifestSHA256 {
			result = *current
			if current.State != StatePending {
				return nil
			}
			return runtime.executePending(ctx, current, signedCommand, &result)
		}

		manifest, err := securityrelease.Verify(encodedManifest, runtime.keys, runtime.now().UTC())
		if err != nil {
			return fmt.Errorf("%w: %v", ErrManifestRejected, err)
		}
		if current != nil {
			switch {
			case manifest.ReleaseSequence < current.ReleaseSequence:
				result = *current
				return ErrStaleSequence
			case manifest.ReleaseSequence == current.ReleaseSequence:
				result = *current
				return ErrSequenceConflict
			case current.State == StatePending:
				result = *current
				return ErrSequenceConflict
			}
		}
		facts, err := runtime.facts.Current(ctx)
		if err != nil || !validRuntimeFacts(facts, runtime.nodeID) {
			return fmt.Errorf("%w: %v", ErrFactsUnavailable, err)
		}
		decision := securityrelease.Decide(manifest, securityrelease.NodeFacts{
			NodeID: facts.NodeID, AgentVersion: facts.AgentVersion, RuntimeVersion: facts.RuntimeVersion,
		})
		candidate := recordForDecision(manifest, manifestSHA256, facts, decision, runtime.now().UTC())
		result = candidate
		if decision.Action == securityrelease.ActionHold {
			candidate.State = StateHeld
			candidate.CompletedAt = candidate.RecordedAt
			if err := runtime.store.saveLocked(&candidate); err != nil {
				return err
			}
			result = candidate
			return nil
		}
		candidate.State = StatePending
		if err := runtime.store.saveLocked(&candidate); err != nil {
			return err
		}
		result = candidate
		return runtime.executePending(ctx, &candidate, signedCommand, &result)
	})
	return result, err
}

func (runtime *Runtime) executePending(ctx context.Context, pending *Record, signedCommand []byte, result *Record) error {
	if pending == nil || pending.State != StatePending || result == nil {
		return ErrCorruptState
	}
	if len(signedCommand) == 0 {
		return ErrSignedCommandRequired
	}
	if len(signedCommand) > maxSignedCommandBytes {
		return ErrSignedCommandConflict
	}
	commandDigest := sha256.Sum256(signedCommand)
	commandSHA256 := hex.EncodeToString(commandDigest[:])
	if pending.SignedCommandSHA256 != "" && pending.SignedCommandSHA256 != commandSHA256 {
		return ErrSignedCommandConflict
	}
	if pending.SignedCommandSHA256 == "" {
		pending.SignedCommandSHA256 = commandSHA256
		if err := runtime.store.saveLocked(pending); err != nil {
			return err
		}
		*result = *pending
	}
	if runtime.updater == nil || runtime.updater.Version() != SignedUpdaterAdapterVersion {
		return ErrUpdaterUnavailable
	}
	request := executionRequest(*pending, signedCommand)
	receipt, err := runtime.updater.Execute(ctx, request)
	if err != nil {
		return fmt.Errorf("%w: %v", ErrUpdaterExecution, err)
	}
	if !validExecutionReceipt(receipt, request) {
		return ErrReceiptMismatch
	}
	completed := *pending
	completed.InstallerTransactionID = receipt.InstallerTransactionID
	completed.ActiveReceiptSHA256 = receipt.ActiveReceiptSHA256
	completed.RollbackReceiptSHA256 = receipt.RollbackReceiptSHA256
	completed.CompletedAt = runtime.now().UTC().Truncate(time.Microsecond)
	if pending.DecisionAction == securityrelease.ActionRollback {
		completed.State = StateRolledBack
	} else {
		completed.State = StateActive
	}
	if err := runtime.store.saveLocked(&completed); err != nil {
		return err
	}
	*result = completed
	return nil
}

func recordForDecision(manifest securityrelease.Manifest, manifestSHA256 string, facts RuntimeFacts,
	decision securityrelease.Decision, recordedAt time.Time,
) Record {
	lkgVersion, lkgImage := facts.RuntimeVersion, facts.RuntimeImageDigest
	target := manifest.TargetRuntimeVersion
	if manifest.Rollout.Phase == securityrelease.PhaseRollback {
		lkgVersion, lkgImage = manifest.Rollout.LastKnownGoodVersion, manifest.Rollout.LastKnownGoodImageDigest
		target = lkgVersion
	}
	record := Record{
		Schema: RecordSchema, NodeID: facts.NodeID, ReleaseID: manifest.ReleaseID,
		ReleaseSequence: manifest.ReleaseSequence, ManifestSHA256: manifestSHA256,
		DecisionAction: decision.Action, DecisionReason: decision.Reason,
		CurrentRuntimeVersion: facts.RuntimeVersion, TargetRuntimeVersion: target,
		RolloutPhase: manifest.Rollout.Phase, LKGRuntimeVersion: lkgVersion, LKGImageDigest: lkgImage,
		RecordedAt: recordedAt.UTC().Truncate(time.Microsecond),
	}
	record.ExecutionID = executionID(record)
	return record
}

func executionID(record Record) string {
	value := strings.Join([]string{
		RecordSchema, record.NodeID, record.ReleaseID, strconv.FormatUint(record.ReleaseSequence, 10),
		record.ManifestSHA256, string(record.DecisionAction),
	}, "\x00")
	digest := sha256.Sum256([]byte(value))
	return hex.EncodeToString(digest[:])
}

func executionRequest(record Record, signedCommand []byte) ExecutionRequest {
	return ExecutionRequest{
		Version: SignedUpdaterAdapterVersion, ExecutionID: record.ExecutionID, NodeID: record.NodeID,
		ReleaseID: record.ReleaseID, ReleaseSequence: record.ReleaseSequence, ManifestSHA256: record.ManifestSHA256,
		Action: record.DecisionAction, CurrentRuntimeVersion: record.CurrentRuntimeVersion,
		TargetRuntimeVersion: record.TargetRuntimeVersion, LKGRuntimeVersion: record.LKGRuntimeVersion,
		LKGImageDigest: record.LKGImageDigest, SignedCommand: append([]byte(nil), signedCommand...),
		SignedCommandSHA256: record.SignedCommandSHA256,
	}
}

func validExecutionReceipt(receipt ExecutionReceipt, request ExecutionRequest) bool {
	if receipt.Version != SignedUpdaterAdapterVersion || receipt.ExecutionID != request.ExecutionID ||
		receipt.NodeID != request.NodeID || receipt.ReleaseID != request.ReleaseID ||
		receipt.ReleaseSequence != request.ReleaseSequence || receipt.ManifestSHA256 != request.ManifestSHA256 ||
		receipt.Action != request.Action || !safeToken(receipt.InstallerTransactionID) ||
		receipt.PreviousRuntimeVersion != request.CurrentRuntimeVersion ||
		receipt.ResultRuntimeVersion != request.TargetRuntimeVersion ||
		receipt.LKGRuntimeVersion != request.LKGRuntimeVersion || receipt.LKGImageDigest != request.LKGImageDigest {
		return false
	}
	if request.Action == securityrelease.ActionDeploy {
		return validDigest(receipt.ActiveReceiptSHA256) && receipt.RollbackReceiptSHA256 == ""
	}
	return request.Action == securityrelease.ActionRollback && receipt.ActiveReceiptSHA256 == "" &&
		validDigest(receipt.RollbackReceiptSHA256)
}

func validRuntimeFacts(facts RuntimeFacts, nodeID string) bool {
	return facts.NodeID == nodeID && validUUID(facts.NodeID) && validVersion(facts.AgentVersion, 3) &&
		validVersion(facts.RuntimeVersion, 4) && validImageDigest(facts.RuntimeImageDigest)
}

func validRecord(record Record) bool {
	if record.Schema != RecordSchema || !validUUID(record.NodeID) || !validUUID(record.ReleaseID) ||
		record.ReleaseSequence == 0 || !validDigest(record.ManifestSHA256) || !validAction(record.DecisionAction) ||
		!validReason(record.DecisionReason) || !validVersion(record.CurrentRuntimeVersion, 4) ||
		!validVersion(record.TargetRuntimeVersion, 4) || !validPhase(record.RolloutPhase) ||
		!validDigest(record.ExecutionID) || record.ExecutionID != executionID(record) ||
		!validVersion(record.LKGRuntimeVersion, 4) || !validImageDigest(record.LKGImageDigest) ||
		record.RecordedAt.IsZero() || !record.RecordedAt.Equal(record.RecordedAt.UTC()) {
		return false
	}
	switch record.State {
	case StateHeld:
		return record.DecisionAction == securityrelease.ActionHold && record.SignedCommandSHA256 == "" &&
			record.InstallerTransactionID == "" && record.ActiveReceiptSHA256 == "" &&
			record.RollbackReceiptSHA256 == "" && !record.CompletedAt.IsZero()
	case StatePending:
		return record.DecisionAction != securityrelease.ActionHold &&
			(record.SignedCommandSHA256 == "" || validDigest(record.SignedCommandSHA256)) &&
			record.InstallerTransactionID == "" && record.ActiveReceiptSHA256 == "" &&
			record.RollbackReceiptSHA256 == "" && record.CompletedAt.IsZero()
	case StateActive:
		return record.DecisionAction == securityrelease.ActionDeploy && validDigest(record.SignedCommandSHA256) &&
			safeToken(record.InstallerTransactionID) && validDigest(record.ActiveReceiptSHA256) &&
			record.RollbackReceiptSHA256 == "" && !record.CompletedAt.IsZero()
	case StateRolledBack:
		return record.DecisionAction == securityrelease.ActionRollback && validDigest(record.SignedCommandSHA256) &&
			safeToken(record.InstallerTransactionID) && record.ActiveReceiptSHA256 == "" &&
			validDigest(record.RollbackReceiptSHA256) && !record.CompletedAt.IsZero()
	default:
		return false
	}
}

var tokenPattern = regexp.MustCompile(`^[A-Za-z0-9][A-Za-z0-9._:-]{0,255}$`)

func safeToken(value string) bool { return tokenPattern.MatchString(value) }

func validUUID(value string) bool {
	parsed, err := uuid.Parse(value)
	return err == nil && parsed != uuid.Nil && parsed.String() == value
}

func validDigest(value string) bool {
	decoded, err := hex.DecodeString(value)
	return err == nil && len(decoded) == sha256.Size && value == strings.ToLower(value)
}

func validImageDigest(value string) bool {
	return strings.HasPrefix(value, "sha256:") && validDigest(strings.TrimPrefix(value, "sha256:"))
}

func validVersion(value string, parts int) bool {
	values := strings.Split(value, ".")
	if len(values) != parts {
		return false
	}
	for _, part := range values {
		if part == "" || len(part) > 1 && part[0] == '0' {
			return false
		}
		if _, err := strconv.ParseUint(part, 10, 64); err != nil {
			return false
		}
	}
	return true
}

func validAction(action securityrelease.Action) bool {
	return action == securityrelease.ActionDeploy || action == securityrelease.ActionHold ||
		action == securityrelease.ActionRollback
}

func validPhase(phase securityrelease.Phase) bool {
	return phase == securityrelease.PhaseCanary || phase == securityrelease.PhaseExpansion ||
		phase == securityrelease.PhasePaused || phase == securityrelease.PhaseRollback
}

func validReason(reason securityrelease.ReasonCode) bool {
	switch reason {
	case securityrelease.ReasonCanaryEligible, securityrelease.ReasonCanaryNotSelected,
		securityrelease.ReasonExpansionEligible, securityrelease.ReasonExpansionNotSelected,
		securityrelease.ReasonPaused, securityrelease.ReasonRollbackRequired,
		securityrelease.ReasonAgentIncompatible, securityrelease.ReasonRuntimeMismatch,
		securityrelease.ReasonAlreadyActive:
		return true
	default:
		return false
	}
}
