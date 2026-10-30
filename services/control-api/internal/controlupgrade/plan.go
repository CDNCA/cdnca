package controlupgrade

import (
	"bytes"
	"crypto/sha256"
	"encoding/base64"
	"encoding/hex"
	"encoding/json"
	"errors"
	"fmt"
	"regexp"
	"strings"
	"time"

	"github.com/google/uuid"
	"golang.org/x/mod/semver"
)

var (
	ErrInvalidPlan             = errors.New("invalid control upgrade rollout plan")
	ErrPlanBlocked             = errors.New("control upgrade rollout plan is blocked")
	ErrInvalidPlanTransition   = errors.New("invalid control upgrade rollout transition")
	ErrInvalidPlanCommand      = errors.New("invalid control upgrade rollout command")
	ErrInvalidPlanEvent        = errors.New("invalid control upgrade rollout event")
	ErrPlanIdempotencyConflict = errors.New("control upgrade rollout idempotency conflict")
	ErrStalePlanRevision       = errors.New("stale control upgrade rollout revision")
	ErrPlanNodeNotActive       = errors.New("control upgrade rollout node is not active")
	ErrStaleStatusEvidence     = errors.New("control upgrade rollout status evidence is stale")
)

var planReasonPattern = regexp.MustCompile(`^[a-z][a-z0-9_]{0,95}$`)

const (
	RolloutPlanSchemaVersionV2 uint16 = 2
	RolloutPlanSchemaVersion   uint16 = 3
)

const maxRolloutRevision = uint64(1<<63 - 1)

type PlanState string

const (
	PlanQueued      PlanState = "queued"
	PlanCanary      PlanState = "canary"
	PlanRunning     PlanState = "running"
	PlanPaused      PlanState = "paused"
	PlanRollingBack PlanState = "rolling_back"
	PlanCompleted   PlanState = "completed"
	PlanFailed      PlanState = "failed"
)

type PlanAction string

const (
	PlanStart       PlanAction = "start"
	PlanPauseAction PlanAction = "pause"
	PlanResume      PlanAction = "resume"
	PlanRollback    PlanAction = "rollback"
)

type PlanNodeState string

const (
	NodePending    PlanNodeState = "pending"
	NodeDispatched PlanNodeState = "dispatched"
	NodeHealthy    PlanNodeState = "healthy"
	NodeFailed     PlanNodeState = "failed"
	NodeRolledBack PlanNodeState = "rolled_back"
)

type PlanCompletion string

const (
	CompletionNone       PlanCompletion = ""
	CompletionUpgraded   PlanCompletion = "upgraded"
	CompletionRolledBack PlanCompletion = "rolled_back"
)

type PlanBlockerCode string

const (
	BlockerIrreversibleMigration PlanBlockerCode = "irreversible_migration"
	BlockerRollbackUnavailable   PlanBlockerCode = "rollback_unavailable"
	BlockerAgentIncompatible     PlanBlockerCode = "agent_incompatible"
	BlockerProtocolIncompatible  PlanBlockerCode = "protocol_incompatible"
)

type PlanTarget struct {
	NodeID          string
	AgentVersion    string
	ProtocolVersion uint32
}

type PlanGroup struct {
	ID        string
	Canary    bool
	BatchSize int
	Targets   []PlanTarget
}

type PlanSafety struct {
	MinAgentVersion       string
	MaxAgentVersion       string
	ProtocolMin           uint32
	ProtocolMax           uint32
	RollbackAvailable     bool
	IrreversibleMigration bool
}

type RolloutPlanInput struct {
	ID                        string
	ParentGrantID             string
	GrantDigest               string
	ParentGrantExpiresAt      int64
	ArtifactBundleID          string
	ArtifactBundleSHA256      string
	CommandIssuanceNotAfter   int64
	ReleaseSequence           uint64
	Component                 string
	ArtifactID                string
	SHA256Digest              string
	ArtifactSizeBytes         int64
	RollbackGrantDigest       string
	RollbackReleaseSequence   uint64
	RollbackArtifactID        string
	RollbackSHA256Digest      string
	RollbackArtifactSizeBytes int64
	CurrentVersion            string
	TargetVersion             string
	AutomaticRollback         bool
	ForwardProfile            CommandProfile
	RollbackProfile           CommandProfile
	Safety                    PlanSafety
	Groups                    []PlanGroup
}

type PlanBatch struct {
	ID      string
	GroupID string
	Canary  bool
	NodeIDs []string
}

type PlanBlocker struct {
	Code   PlanBlockerCode
	NodeID string
}

type PlanCommand struct {
	ID               string
	Action           PlanAction
	ExpectedRevision uint64
	Reason           string
}

type PlanHealthEvent struct {
	ID                     string
	NodeID                 string
	Success                bool
	Code                   string
	DispatchRevision       uint64
	InstallerTransactionID string
	ActiveEvidence         *ActiveProbeEvidence
}

const (
	EdgeUpgradeStatusSchemaV1 = "cdnca.edge.upgrade.status/v1"
	EdgeUpgradeStatusSchemaV2 = "cdnca.edge.upgrade.status/v2"
	ActiveProbeEvidenceSchema = "cdnca.edge.upgrade.active-probe/v1"
)

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

func validActiveProbeEvidence(installerTransactionID string, evidence *ActiveProbeEvidence) bool {
	if evidence == nil || evidence.Schema != ActiveProbeEvidenceSchema ||
		!validActiveProbeDigest(evidence.ActiveArtifactSHA256) ||
		!validActiveProbeDigest(evidence.ActiveConfigSHA256) ||
		!validActiveProbeDigest(evidence.LastKnownGoodArtifactSHA256) ||
		!validActiveProbeDigest(evidence.LastKnownGoodConfigSHA256) ||
		!rolloutSafeIDPattern.MatchString(installerTransactionID) || evidence.ProbeObservedAt.IsZero() ||
		evidence.ProbeDeadline.IsZero() || evidence.ProbeObservedAt.After(evidence.ProbeDeadline) ||
		activeProbeEvidenceDigest(installerTransactionID, *evidence) != evidence.EvidenceSHA256 {
		return false
	}
	_, observedOffset := evidence.ProbeObservedAt.Zone()
	_, deadlineOffset := evidence.ProbeDeadline.Zone()
	return observedOffset == 0 && deadlineOffset == 0
}

func validActiveProbeDigest(value string) bool {
	decoded, err := hex.DecodeString(value)
	return err == nil && len(decoded) == sha256.Size && value == strings.ToLower(value) || validPlanDigest(value)
}

func activeProbeArtifactMatches(planDigest, evidenceDigest string) bool {
	if planDigest == evidenceDigest {
		return true
	}
	decoded, err := base64.RawURLEncoding.DecodeString(planDigest)
	return err == nil && len(decoded) == sha256.Size && hex.EncodeToString(decoded) == evidenceDigest
}

func cloneControlActiveProbeEvidence(evidence *ActiveProbeEvidence) *ActiveProbeEvidence {
	if evidence == nil {
		return nil
	}
	clone := *evidence
	return &clone
}

func samePlanHealth(left, right PlanHealthEvent) bool {
	return left.ID == right.ID && left.NodeID == right.NodeID && left.Success == right.Success &&
		left.Code == right.Code && left.DispatchRevision == right.DispatchRevision &&
		left.InstallerTransactionID == right.InstallerTransactionID &&
		(left.ActiveEvidence == nil && right.ActiveEvidence == nil ||
			left.ActiveEvidence != nil && right.ActiveEvidence != nil && *left.ActiveEvidence == *right.ActiveEvidence)
}

type PlanEvent struct {
	ID       string
	Revision uint64
	From     PlanState
	To       PlanState
	Action   string
	Reason   string
	BatchID  string
	NodeID   string
}

type PlanCommandReceipt struct {
	Command PlanCommand
	Event   PlanEvent
}

type PlanHealthReceipt struct {
	Health PlanHealthEvent
	Event  PlanEvent
}

type RolloutPlan struct {
	SchemaVersion             uint16
	ID                        string
	ParentGrantID             string
	GrantDigest               string
	ParentGrantExpiresAt      int64
	ArtifactBundleID          string
	ArtifactBundleSHA256      string
	CommandIssuanceNotAfter   int64
	ReleaseSequence           uint64
	Component                 string
	ArtifactID                string
	SHA256Digest              string
	ArtifactSizeBytes         int64
	RollbackGrantDigest       string
	RollbackReleaseSequence   uint64
	RollbackArtifactID        string
	RollbackSHA256Digest      string
	RollbackArtifactSizeBytes int64
	CurrentVersion            string
	TargetVersion             string
	AutomaticRollback         bool
	ForwardProfile            CommandProfile
	RollbackProfile           CommandProfile
	Safety                    PlanSafety
	State                     PlanState
	ResumeState               PlanState
	Completion                PlanCompletion
	Revision                  uint64
	ActiveBatch               int
	Batches                   []PlanBatch
	RollbackBatches           []PlanBatch
	Targets                   map[string]PlanTarget
	NodeStates                map[string]PlanNodeState
	NodeDispatchRevisions     map[string]uint64
	Blockers                  []PlanBlocker
	CommandReceipts           []PlanCommandReceipt
	HealthReceipts            []PlanHealthReceipt
}

type PlanApplyResult struct {
	Plan     RolloutPlan
	Event    PlanEvent
	Replayed bool
}

func NewRolloutPlan(input RolloutPlanInput) (RolloutPlan, error) {
	if !validCanonicalPlanUUID(input.ID) || !validCanonicalPlanUUID(input.ParentGrantID) ||
		!validPlanDigest(input.GrantDigest) || input.ParentGrantExpiresAt <= 0 ||
		!validCanonicalPlanUUID(input.ArtifactBundleID) || !validPlanDigest(input.ArtifactBundleSHA256) ||
		input.CommandIssuanceNotAfter <= 0 ||
		input.ReleaseSequence == 0 || !codePattern.MatchString(input.Component) ||
		!validCanonicalPlanUUID(input.ArtifactID) || !validPlanDigest(input.SHA256Digest) || input.ArtifactSizeBytes <= 0 ||
		!validCanonicalVersion(input.CurrentVersion) ||
		!validCanonicalVersion(input.TargetVersion) ||
		semver.Compare("v"+input.CurrentVersion, "v"+input.TargetVersion) >= 0 ||
		input.Safety.RollbackAvailable && (input.RollbackGrantDigest != input.GrantDigest ||
			input.RollbackReleaseSequence == 0 || input.RollbackReleaseSequence > input.ReleaseSequence ||
			!validCanonicalPlanUUID(input.RollbackArtifactID) ||
			!validPlanDigest(input.RollbackSHA256Digest) || input.RollbackArtifactSizeBytes <= 0) ||
		!validCommandProfile(input.ForwardProfile) || !validCommandProfile(input.RollbackProfile) ||
		!input.AutomaticRollback ||
		!validCanonicalVersion(input.Safety.MinAgentVersion) ||
		!validCanonicalVersion(input.Safety.MaxAgentVersion) ||
		semver.Compare("v"+input.Safety.MinAgentVersion, "v"+input.Safety.MaxAgentVersion) > 0 ||
		input.Safety.ProtocolMin == 0 || input.Safety.ProtocolMax < input.Safety.ProtocolMin ||
		len(input.Groups) == 0 {
		return RolloutPlan{}, ErrInvalidPlan
	}

	schemaVersion := RolloutPlanSchemaVersionV2
	if input.RollbackReleaseSequence != input.ReleaseSequence {
		schemaVersion = RolloutPlanSchemaVersion
	}
	plan := RolloutPlan{
		SchemaVersion: schemaVersion,
		ID:            input.ID, ParentGrantID: input.ParentGrantID, GrantDigest: input.GrantDigest,
		ParentGrantExpiresAt: input.ParentGrantExpiresAt, ReleaseSequence: input.ReleaseSequence,
		ArtifactBundleID: input.ArtifactBundleID, ArtifactBundleSHA256: input.ArtifactBundleSHA256,
		CommandIssuanceNotAfter: input.CommandIssuanceNotAfter,
		Component:               input.Component, ArtifactID: input.ArtifactID, SHA256Digest: input.SHA256Digest,
		ArtifactSizeBytes:   input.ArtifactSizeBytes,
		RollbackGrantDigest: input.RollbackGrantDigest, RollbackReleaseSequence: input.RollbackReleaseSequence,
		RollbackArtifactID: input.RollbackArtifactID, RollbackSHA256Digest: input.RollbackSHA256Digest,
		RollbackArtifactSizeBytes: input.RollbackArtifactSizeBytes,
		CurrentVersion:            input.CurrentVersion, TargetVersion: input.TargetVersion,
		AutomaticRollback: input.AutomaticRollback,
		ForwardProfile:    cloneCommandProfile(input.ForwardProfile), RollbackProfile: cloneCommandProfile(input.RollbackProfile),
		Safety: input.Safety, State: PlanQueued, Revision: 1, ActiveBatch: -1,
		Targets: make(map[string]PlanTarget), NodeStates: make(map[string]PlanNodeState),
		NodeDispatchRevisions: make(map[string]uint64),
	}

	canaries := 0
	seenGroups := make(map[string]bool, len(input.Groups))
	for _, canary := range []bool{true, false} {
		for _, group := range input.Groups {
			if group.Canary != canary {
				continue
			}
			if group.Canary {
				canaries++
				if len(group.Targets) > 2 {
					return RolloutPlan{}, ErrInvalidPlan
				}
			}
			if !codePattern.MatchString(group.ID) || len(group.Targets) == 0 ||
				group.BatchSize <= 0 || group.BatchSize > len(group.Targets) || seenGroups[group.ID] {
				return RolloutPlan{}, ErrInvalidPlan
			}
			seenGroups[group.ID] = true
			// ProtocolVersion is the gateway session major (1 on every shipped agent), not the
			// execution schema: v3 execution support is carried by the agent itself.
			for _, target := range group.Targets {
				if !validCanonicalPlanUUID(target.NodeID) || !validCanonicalVersion(target.AgentVersion) ||
					target.ProtocolVersion == 0 {
					return RolloutPlan{}, ErrInvalidPlan
				}
				if _, exists := plan.NodeStates[target.NodeID]; exists {
					return RolloutPlan{}, ErrInvalidPlan
				}
				plan.Targets[target.NodeID] = target
				plan.NodeStates[target.NodeID] = NodePending
				plan.NodeDispatchRevisions[target.NodeID] = 0
			}
			for start := 0; start < len(group.Targets); start += group.BatchSize {
				end := min(start+group.BatchSize, len(group.Targets))
				nodes := make([]string, end-start)
				for index, target := range group.Targets[start:end] {
					nodes[index] = target.NodeID
				}
				plan.Batches = append(plan.Batches, PlanBatch{
					ID:      derivedPlanID(plan.ID, "batch", fmt.Sprintf("%s:%04d", group.ID, start/group.BatchSize+1)),
					GroupID: group.ID, Canary: group.Canary, NodeIDs: nodes,
				})
			}
		}
	}
	if canaries != 1 {
		return RolloutPlan{}, ErrInvalidPlan
	}
	plan.Blockers = expectedPlanBlockers(plan)
	return plan, nil
}

func ApplyPlanCommand(current RolloutPlan, command PlanCommand) (PlanApplyResult, error) {
	if !validCanonicalPlanUUID(command.ID) || command.ExpectedRevision == 0 ||
		command.ExpectedRevision > maxRolloutRevision ||
		!planReasonPattern.MatchString(command.Reason) || !validPlanAction(command.Action) {
		return PlanApplyResult{}, ErrInvalidPlanCommand
	}
	if !validRolloutPlan(current) {
		return PlanApplyResult{}, ErrInvalidPlan
	}
	for _, receipt := range current.CommandReceipts {
		if receipt.Command.ID != command.ID {
			continue
		}
		if receipt.Command != command {
			return PlanApplyResult{}, ErrPlanIdempotencyConflict
		}
		return PlanApplyResult{Plan: cloneRolloutPlan(current), Event: receipt.Event, Replayed: true}, nil
	}
	if command.ExpectedRevision != current.Revision {
		return PlanApplyResult{}, ErrStalePlanRevision
	}

	plan := cloneRolloutPlan(current)
	event, err := applyPlanCommandTransition(&plan, command)
	if err != nil {
		return PlanApplyResult{}, err
	}
	plan.CommandReceipts = append(plan.CommandReceipts, PlanCommandReceipt{Command: command, Event: event})
	return PlanApplyResult{Plan: plan, Event: event}, nil
}

func applyPlanCommandTransition(plan *RolloutPlan, command PlanCommand) (PlanEvent, error) {
	from := plan.State
	switch command.Action {
	case PlanStart:
		if plan.State != PlanQueued {
			return PlanEvent{}, ErrInvalidPlanTransition
		}
		if len(plan.Blockers) != 0 {
			return PlanEvent{}, ErrPlanBlocked
		}
		beginForwardBatch(plan, 0)
	case PlanPauseAction:
		if plan.State != PlanCanary && plan.State != PlanRunning {
			return PlanEvent{}, ErrInvalidPlanTransition
		}
		plan.ResumeState = plan.State
		plan.State = PlanPaused
	case PlanResume:
		if plan.State != PlanPaused || plan.ResumeState != PlanCanary && plan.ResumeState != PlanRunning {
			return PlanEvent{}, ErrInvalidPlanTransition
		}
		plan.State = plan.ResumeState
		plan.ResumeState = ""
		for _, nodeID := range plan.Batches[plan.ActiveBatch].NodeIDs {
			if plan.NodeStates[nodeID] == NodeFailed {
				plan.NodeStates[nodeID] = NodeDispatched
				plan.NodeDispatchRevisions[nodeID] = plan.Revision + 1
			}
		}
		advanceForwardIfComplete(plan)
	case PlanRollback:
		if err := beginRollback(plan); err != nil {
			return PlanEvent{}, err
		}
	}
	if !CanPlanTransition(from, plan.State) {
		return PlanEvent{}, ErrInvalidPlanTransition
	}
	event := commitPlanEvent(plan, PlanEvent{
		From: from, To: plan.State, Action: string(command.Action), Reason: command.Reason,
		BatchID: activePlanBatchID(*plan),
	})
	return event, nil
}

func ApplyPlanHealth(current RolloutPlan, health PlanHealthEvent) (PlanApplyResult, error) {
	if !validCanonicalPlanUUID(health.ID) || !validCanonicalPlanUUID(health.NodeID) ||
		health.DispatchRevision == 0 || health.DispatchRevision > maxRolloutRevision ||
		health.Success && health.Code != "" ||
		!health.Success && !planReasonPattern.MatchString(health.Code) ||
		health.Success && !validActiveProbeEvidence(health.InstallerTransactionID, health.ActiveEvidence) ||
		!health.Success && health.ActiveEvidence != nil {
		return PlanApplyResult{}, ErrInvalidPlanEvent
	}
	if !validRolloutPlan(current) {
		return PlanApplyResult{}, ErrInvalidPlan
	}
	if health.Success {
		activeArtifact, lastKnownGoodArtifact := current.SHA256Digest, current.RollbackSHA256Digest
		if current.State == PlanRollingBack {
			activeArtifact, lastKnownGoodArtifact = lastKnownGoodArtifact, activeArtifact
		}
		if !activeProbeArtifactMatches(activeArtifact, health.ActiveEvidence.ActiveArtifactSHA256) ||
			!activeProbeArtifactMatches(lastKnownGoodArtifact,
				health.ActiveEvidence.LastKnownGoodArtifactSHA256) {
			return PlanApplyResult{}, ErrInvalidPlanEvent
		}
	}
	for _, receipt := range current.HealthReceipts {
		if receipt.Health.ID != health.ID {
			continue
		}
		if !samePlanHealth(receipt.Health, health) {
			return PlanApplyResult{}, ErrPlanIdempotencyConflict
		}
		return PlanApplyResult{Plan: cloneRolloutPlan(current), Event: receipt.Event, Replayed: true}, nil
	}
	plan := cloneRolloutPlan(current)
	event, err := applyPlanHealthTransition(&plan, health)
	if err != nil {
		return PlanApplyResult{}, err
	}
	plan.HealthReceipts = append(plan.HealthReceipts, PlanHealthReceipt{Health: health, Event: event})
	return PlanApplyResult{Plan: plan, Event: event}, nil
}

func applyPlanHealthTransition(plan *RolloutPlan, health PlanHealthEvent) (PlanEvent, error) {
	if plan.State != PlanCanary && plan.State != PlanRunning && plan.State != PlanPaused &&
		plan.State != PlanRollingBack {
		return PlanEvent{}, ErrInvalidPlanTransition
	}
	from := plan.State
	batch := activePlanBatch(*plan)
	if !containsNode(batch.NodeIDs, health.NodeID) || plan.NodeStates[health.NodeID] != NodeDispatched {
		return PlanEvent{}, ErrPlanNodeNotActive
	}
	if health.DispatchRevision != plan.NodeDispatchRevisions[health.NodeID] {
		return PlanEvent{}, ErrStalePlanRevision
	}
	event := PlanEvent{From: from, NodeID: health.NodeID, BatchID: batch.ID}
	if !health.Success {
		event.Reason = health.Code
		if health.Code == "unknown_outcome" {
			event.Action = "outcome_uncertain"
			if from != PlanRollingBack {
				if from != PlanPaused {
					plan.ResumeState = from
				}
				plan.State = PlanPaused
			}
		} else if from == PlanRollingBack {
			plan.NodeStates[health.NodeID] = NodeFailed
			event.Action = "health_failed"
			plan.State = PlanFailed
		} else {
			if from != PlanPaused {
				plan.ResumeState = from
			}
			plan.State = PlanPaused
			plan.NodeStates[health.NodeID] = NodeFailed
			event.Action = "health_failed"
		}
	} else {
		event.Action, event.Reason = "health_succeeded", "healthy"
		if from == PlanRollingBack {
			plan.NodeStates[health.NodeID] = NodeRolledBack
			advanceRollbackIfComplete(plan)
		} else {
			plan.NodeStates[health.NodeID] = NodeHealthy
			if from != PlanPaused {
				advanceForwardIfComplete(plan)
			}
		}
	}
	if !CanPlanTransition(from, plan.State) {
		return PlanEvent{}, ErrInvalidPlanTransition
	}
	event.To = plan.State
	event = commitPlanEvent(plan, event)
	if shouldBeginAutomaticRollback(*plan) {
		command := PlanCommand{
			ID:               derivedPlanID(plan.ID, "command", "automatic_rollback:"+event.ID),
			Action:           PlanRollback,
			ExpectedRevision: plan.Revision,
			Reason:           "automatic_policy_requested",
		}
		rollbackEvent, err := applyPlanCommandTransition(plan, command)
		if err != nil {
			return PlanEvent{}, err
		}
		plan.CommandReceipts = append(plan.CommandReceipts, PlanCommandReceipt{
			Command: command,
			Event:   rollbackEvent,
		})
	}
	return event, nil
}

func shouldBeginAutomaticRollback(plan RolloutPlan) bool {
	if !plan.AutomaticRollback || plan.State != PlanPaused {
		return false
	}
	hasDefinitiveFailure := false
	for _, state := range plan.NodeStates {
		if state == NodeDispatched {
			return false
		}
		if state == NodeFailed {
			hasDefinitiveFailure = true
		}
	}
	return hasDefinitiveFailure
}

func CanPlanTransition(from, to PlanState) bool {
	switch from {
	case PlanQueued:
		return to == PlanCanary
	case PlanCanary:
		return to == PlanCanary || to == PlanRunning || to == PlanPaused ||
			to == PlanRollingBack || to == PlanCompleted
	case PlanRunning:
		return to == PlanRunning || to == PlanPaused || to == PlanRollingBack || to == PlanCompleted
	case PlanPaused:
		return to == PlanCanary || to == PlanRunning || to == PlanPaused || to == PlanRollingBack
	case PlanRollingBack:
		return to == PlanRollingBack || to == PlanCompleted || to == PlanFailed
	case PlanCompleted:
		return to == PlanRollingBack
	default:
		return false
	}
}

func beginForwardBatch(plan *RolloutPlan, index int) {
	plan.ActiveBatch = index
	batch := plan.Batches[index]
	if batch.Canary {
		plan.State = PlanCanary
	} else {
		plan.State = PlanRunning
	}
	for _, nodeID := range batch.NodeIDs {
		plan.NodeStates[nodeID] = NodeDispatched
		plan.NodeDispatchRevisions[nodeID] = plan.Revision + 1
	}
}

func advanceForwardIfComplete(plan *RolloutPlan) {
	if !batchNodesHaveState(plan.NodeStates, plan.Batches[plan.ActiveBatch].NodeIDs, NodeHealthy) {
		return
	}
	next := plan.ActiveBatch + 1
	if next == len(plan.Batches) {
		plan.State = PlanCompleted
		plan.Completion = CompletionUpgraded
		plan.ActiveBatch = -1
		return
	}
	beginForwardBatch(plan, next)
}

func beginRollback(plan *RolloutPlan) error {
	if plan.Safety.IrreversibleMigration || !plan.Safety.RollbackAvailable {
		return ErrPlanBlocked
	}
	if plan.State != PlanCanary && plan.State != PlanRunning && plan.State != PlanPaused &&
		(plan.State != PlanCompleted || plan.Completion != CompletionUpgraded) {
		return ErrInvalidPlanTransition
	}
	for _, state := range plan.NodeStates {
		if state == NodeDispatched {
			return ErrPlanBlocked
		}
	}
	plan.RollbackBatches = expectedRollbackBatches(*plan)
	if len(plan.RollbackBatches) == 0 {
		return ErrInvalidPlanTransition
	}
	plan.State = PlanRollingBack
	plan.ResumeState = ""
	plan.Completion = CompletionNone
	plan.ActiveBatch = 0
	for _, nodeID := range plan.RollbackBatches[0].NodeIDs {
		plan.NodeStates[nodeID] = NodeDispatched
		plan.NodeDispatchRevisions[nodeID] = plan.Revision + 1
	}
	return nil
}

func advanceRollbackIfComplete(plan *RolloutPlan) {
	if !batchNodesHaveState(plan.NodeStates, plan.RollbackBatches[plan.ActiveBatch].NodeIDs, NodeRolledBack) {
		return
	}
	next := plan.ActiveBatch + 1
	if next == len(plan.RollbackBatches) {
		plan.State = PlanCompleted
		plan.Completion = CompletionRolledBack
		plan.ActiveBatch = -1
		return
	}
	plan.ActiveBatch = next
	for _, nodeID := range plan.RollbackBatches[next].NodeIDs {
		plan.NodeStates[nodeID] = NodeDispatched
		plan.NodeDispatchRevisions[nodeID] = plan.Revision + 1
	}
}

func commitPlanEvent(plan *RolloutPlan, event PlanEvent) PlanEvent {
	plan.Revision++
	event.ID = derivedPlanID(plan.ID, "event", fmt.Sprintf("%d", plan.Revision))
	event.Revision = plan.Revision
	return event
}

func activePlanBatch(plan RolloutPlan) PlanBatch {
	if plan.State == PlanRollingBack {
		return plan.RollbackBatches[plan.ActiveBatch]
	}
	return plan.Batches[plan.ActiveBatch]
}

func activePlanBatchID(plan RolloutPlan) string {
	if plan.ActiveBatch < 0 {
		return ""
	}
	return activePlanBatch(plan).ID
}

func batchNodesHaveState(states map[string]PlanNodeState, nodes []string, state PlanNodeState) bool {
	for _, nodeID := range nodes {
		if states[nodeID] != state {
			return false
		}
	}
	return true
}

func containsNode(nodes []string, nodeID string) bool {
	for _, candidate := range nodes {
		if candidate == nodeID {
			return true
		}
	}
	return false
}

func validCanonicalPlanUUID(value string) bool {
	parsed, err := uuid.Parse(value)
	return err == nil && parsed != uuid.Nil && parsed.String() == value
}

func validPlanDigest(value string) bool {
	decoded, err := base64.RawURLEncoding.DecodeString(value)
	return err == nil && len(decoded) == sha256.Size && base64.RawURLEncoding.EncodeToString(decoded) == value
}

func validPlanAction(action PlanAction) bool {
	return action == PlanStart || action == PlanPauseAction || action == PlanResume || action == PlanRollback
}

func derivedPlanID(planID, kind, value string) string {
	return uuid.NewSHA1(uuid.MustParse(planID), []byte(kind+":"+value)).String()
}

func validRolloutPlan(plan RolloutPlan) bool {
	if (plan.SchemaVersion != RolloutPlanSchemaVersionV2 && plan.SchemaVersion != RolloutPlanSchemaVersion) ||
		!validCanonicalPlanUUID(plan.ID) ||
		!validCanonicalPlanUUID(plan.ParentGrantID) || !validPlanDigest(plan.GrantDigest) ||
		plan.ParentGrantExpiresAt <= 0 ||
		!validCanonicalPlanUUID(plan.ArtifactBundleID) || !validPlanDigest(plan.ArtifactBundleSHA256) ||
		plan.CommandIssuanceNotAfter <= 0 ||
		plan.ReleaseSequence == 0 || !codePattern.MatchString(plan.Component) ||
		!validCanonicalPlanUUID(plan.ArtifactID) || !validPlanDigest(plan.SHA256Digest) ||
		plan.ArtifactSizeBytes <= 0 ||
		!validCanonicalVersion(plan.CurrentVersion) ||
		!validCanonicalVersion(plan.TargetVersion) ||
		semver.Compare("v"+plan.CurrentVersion, "v"+plan.TargetVersion) >= 0 ||
		plan.Safety.RollbackAvailable && (plan.RollbackGrantDigest != plan.GrantDigest ||
			plan.RollbackReleaseSequence == 0 || plan.RollbackReleaseSequence > plan.ReleaseSequence ||
			!validCanonicalPlanUUID(plan.RollbackArtifactID) ||
			!validPlanDigest(plan.RollbackSHA256Digest) || plan.RollbackArtifactSizeBytes <= 0) ||
		!validCommandProfile(plan.ForwardProfile) || !validCommandProfile(plan.RollbackProfile) ||
		!plan.AutomaticRollback || plan.Revision == 0 || plan.Revision > maxRolloutRevision ||
		len(plan.Batches) == 0 ||
		!validCanonicalVersion(plan.Safety.MinAgentVersion) || !validCanonicalVersion(plan.Safety.MaxAgentVersion) ||
		semver.Compare("v"+plan.Safety.MinAgentVersion, "v"+plan.Safety.MaxAgentVersion) > 0 ||
		plan.Safety.ProtocolMin == 0 || plan.Safety.ProtocolMax < plan.Safety.ProtocolMin ||
		len(plan.Targets) == 0 || len(plan.Targets) != len(plan.NodeStates) ||
		len(plan.Targets) != len(plan.NodeDispatchRevisions) {
		return false
	}
	if (plan.SchemaVersion == RolloutPlanSchemaVersionV2) !=
		(plan.RollbackReleaseSequence == plan.ReleaseSequence) {
		return false
	}
	seen := make(map[string]bool, len(plan.Targets))
	seenNonCanary := false
	canaryGroup := ""
	groupBatch := make(map[string]int)
	groupCanary := make(map[string]bool)
	for _, batch := range plan.Batches {
		if !codePattern.MatchString(batch.GroupID) || len(batch.NodeIDs) == 0 {
			return false
		}
		groupBatch[batch.GroupID]++
		if batch.ID != derivedPlanID(plan.ID, "batch", fmt.Sprintf("%s:%04d", batch.GroupID, groupBatch[batch.GroupID])) {
			return false
		}
		if prior, exists := groupCanary[batch.GroupID]; exists && prior != batch.Canary {
			return false
		}
		groupCanary[batch.GroupID] = batch.Canary
		if batch.Canary {
			if seenNonCanary || canaryGroup != "" && canaryGroup != batch.GroupID {
				return false
			}
			canaryGroup = batch.GroupID
		} else {
			seenNonCanary = true
		}
		for _, nodeID := range batch.NodeIDs {
			target, exists := plan.Targets[nodeID]
			dispatchRevision, hasDispatchRevision := plan.NodeDispatchRevisions[nodeID]
			if !exists || seen[nodeID] || target.NodeID != nodeID || !validCanonicalPlanUUID(nodeID) ||
				!validCanonicalVersion(target.AgentVersion) ||
				target.ProtocolVersion == 0 ||
				!validPlanNodeState(plan.NodeStates[nodeID]) ||
				!hasDispatchRevision || dispatchRevision > plan.Revision ||
				(plan.NodeStates[nodeID] == NodePending) != (dispatchRevision == 0) {
				return false
			}
			seen[nodeID] = true
		}
	}
	if canaryGroup == "" || len(seen) != len(plan.Targets) ||
		!samePlanBlockers(plan.Blockers, expectedPlanBlockers(plan)) || !validPlanReceipts(plan) {
		return false
	}
	switch plan.State {
	case PlanQueued:
		return plan.ActiveBatch == -1 && plan.ResumeState == "" && plan.Completion == CompletionNone &&
			len(plan.RollbackBatches) == 0 &&
			allPlanNodesState(plan.NodeStates, NodePending)
	case PlanCanary:
		return plan.ResumeState == "" && plan.Completion == CompletionNone &&
			validForwardProgress(plan, true, false)
	case PlanRunning:
		return plan.ResumeState == "" && plan.Completion == CompletionNone &&
			validForwardProgress(plan, false, false)
	case PlanPaused:
		return plan.Completion == CompletionNone &&
			(plan.ResumeState == PlanCanary && validForwardProgress(plan, true, true) ||
				plan.ResumeState == PlanRunning && validForwardProgress(plan, false, true))
	case PlanRollingBack:
		return plan.ResumeState == "" && plan.Completion == CompletionNone && validRollbackProgress(plan, false)
	case PlanCompleted:
		return plan.ActiveBatch == -1 && plan.ResumeState == "" &&
			(plan.Completion == CompletionUpgraded && len(plan.RollbackBatches) == 0 &&
				allPlanNodesState(plan.NodeStates, NodeHealthy) ||
				plan.Completion == CompletionRolledBack && validRolledBackCompletion(plan))
	case PlanFailed:
		return plan.ResumeState == "" && plan.Completion == CompletionNone && validRollbackProgress(plan, true)
	default:
		return false
	}
}

func validPlanReceipts(plan RolloutPlan) bool {
	if plan.Revision != 1+uint64(len(plan.CommandReceipts)+len(plan.HealthReceipts)) {
		return false
	}
	type replayReceipt struct {
		event   PlanEvent
		command *PlanCommand
		health  *PlanHealthEvent
	}
	receipts := make(map[uint64]replayReceipt, plan.Revision-1)
	causations := make(map[string]bool, plan.Revision-1)
	validEvent := func(event PlanEvent, causationID string) bool {
		if !validCanonicalPlanUUID(causationID) || causations[causationID] ||
			event.Revision < 2 || event.Revision > plan.Revision || receipts[event.Revision].event.Revision != 0 ||
			event.ID != derivedPlanID(plan.ID, "event", fmt.Sprintf("%d", event.Revision)) ||
			!CanPlanTransition(event.From, event.To) {
			return false
		}
		causations[causationID] = true
		return true
	}
	for index := range plan.CommandReceipts {
		receipt := &plan.CommandReceipts[index]
		command, event := receipt.Command, receipt.Event
		if command.ExpectedRevision == 0 || command.ExpectedRevision > maxRolloutRevision ||
			!validPlanAction(command.Action) ||
			!planReasonPattern.MatchString(command.Reason) || !validEvent(event, command.ID) {
			return false
		}
		receipts[event.Revision] = replayReceipt{event: event, command: &receipt.Command}
	}
	for index := range plan.HealthReceipts {
		receipt := &plan.HealthReceipts[index]
		health, event := receipt.Health, receipt.Event
		if health.DispatchRevision == 0 || health.DispatchRevision > maxRolloutRevision ||
			health.Success && health.Code != "" ||
			!health.Success && !planReasonPattern.MatchString(health.Code) ||
			!validCanonicalPlanUUID(health.NodeID) || !validEvent(event, health.ID) {
			return false
		}
		receipts[event.Revision] = replayReceipt{event: event, health: &receipt.Health}
	}
	replayed := initialRolloutPlan(plan)
	for revision := uint64(2); revision <= plan.Revision; revision++ {
		receipt, exists := receipts[revision]
		if !exists {
			return false
		}
		var generated PlanEvent
		var err error
		switch {
		case receipt.command != nil:
			if replayed.Revision == receipt.event.Revision {
				if len(replayed.CommandReceipts) == 0 {
					return false
				}
				automatic := replayed.CommandReceipts[len(replayed.CommandReceipts)-1]
				if automatic.Command != *receipt.command || automatic.Event != receipt.event {
					return false
				}
				generated = automatic.Event
			} else {
				if receipt.command.ExpectedRevision != replayed.Revision {
					return false
				}
				generated, err = applyPlanCommandTransition(&replayed, *receipt.command)
			}
		case receipt.health != nil:
			generated, err = applyPlanHealthTransition(&replayed, *receipt.health)
		default:
			return false
		}
		if err != nil || generated != receipt.event {
			return false
		}
	}
	return len(receipts) == int(plan.Revision-1) && sameRolloutMutableState(replayed, plan)
}

func initialRolloutPlan(plan RolloutPlan) RolloutPlan {
	initial := cloneRolloutPlan(plan)
	initial.State = PlanQueued
	initial.ResumeState = ""
	initial.Completion = CompletionNone
	initial.Revision = 1
	initial.ActiveBatch = -1
	initial.RollbackBatches = nil
	initial.CommandReceipts = nil
	initial.HealthReceipts = nil
	for nodeID := range initial.NodeStates {
		initial.NodeStates[nodeID] = NodePending
		initial.NodeDispatchRevisions[nodeID] = 0
	}
	return initial
}

func sameRolloutMutableState(left, right RolloutPlan) bool {
	if left.State != right.State || left.ResumeState != right.ResumeState || left.Completion != right.Completion ||
		left.Revision != right.Revision || left.ActiveBatch != right.ActiveBatch ||
		!samePlanBatches(left.RollbackBatches, right.RollbackBatches) ||
		len(left.NodeStates) != len(right.NodeStates) ||
		len(left.NodeDispatchRevisions) != len(right.NodeDispatchRevisions) {
		return false
	}
	for nodeID, state := range left.NodeStates {
		if right.NodeStates[nodeID] != state ||
			right.NodeDispatchRevisions[nodeID] != left.NodeDispatchRevisions[nodeID] {
			return false
		}
	}
	return true
}

func expectedPlanBlockers(plan RolloutPlan) []PlanBlocker {
	var blockers []PlanBlocker
	if plan.Safety.IrreversibleMigration {
		blockers = append(blockers, PlanBlocker{Code: BlockerIrreversibleMigration})
	}
	if !plan.Safety.RollbackAvailable {
		blockers = append(blockers, PlanBlocker{Code: BlockerRollbackUnavailable})
	}
	for _, batch := range plan.Batches {
		for _, nodeID := range batch.NodeIDs {
			target := plan.Targets[nodeID]
			if semver.Compare("v"+target.AgentVersion, "v"+plan.Safety.MinAgentVersion) < 0 ||
				semver.Compare("v"+target.AgentVersion, "v"+plan.Safety.MaxAgentVersion) > 0 {
				blockers = append(blockers, PlanBlocker{Code: BlockerAgentIncompatible, NodeID: nodeID})
			}
			if target.ProtocolVersion < plan.Safety.ProtocolMin || target.ProtocolVersion > plan.Safety.ProtocolMax {
				blockers = append(blockers, PlanBlocker{Code: BlockerProtocolIncompatible, NodeID: nodeID})
			}
		}
	}
	return blockers
}

func samePlanBlockers(left, right []PlanBlocker) bool {
	if len(left) != len(right) {
		return false
	}
	for index := range left {
		if left[index] != right[index] {
			return false
		}
	}
	return true
}

func expectedRollbackBatches(plan RolloutPlan) []PlanBatch {
	var batches []PlanBatch
	for index := len(plan.Batches) - 1; index >= 0; index-- {
		var nodes []string
		for _, nodeID := range plan.Batches[index].NodeIDs {
			if plan.NodeStates[nodeID] != NodePending {
				nodes = append(nodes, nodeID)
			}
		}
		if len(nodes) != 0 {
			batches = append(batches, PlanBatch{
				ID:      derivedPlanID(plan.ID, "rollback", fmt.Sprintf("%04d", len(batches)+1)),
				GroupID: plan.Batches[index].GroupID, NodeIDs: nodes,
			})
		}
	}
	return batches
}

func samePlanBatches(left, right []PlanBatch) bool {
	if len(left) != len(right) {
		return false
	}
	for index := range left {
		if left[index].ID != right[index].ID || left[index].GroupID != right[index].GroupID ||
			left[index].Canary != right[index].Canary || !sameStrings(left[index].NodeIDs, right[index].NodeIDs) {
			return false
		}
	}
	return true
}

func sameStrings(left, right []string) bool {
	if len(left) != len(right) {
		return false
	}
	for index := range left {
		if left[index] != right[index] {
			return false
		}
	}
	return true
}

func validForwardBatch(plan RolloutPlan) bool {
	return plan.ActiveBatch >= 0 && plan.ActiveBatch < len(plan.Batches)
}

func validForwardProgress(plan RolloutPlan, canary, paused bool) bool {
	if len(plan.RollbackBatches) != 0 || !validForwardBatch(plan) || plan.Batches[plan.ActiveBatch].Canary != canary {
		return false
	}
	for index, batch := range plan.Batches {
		switch {
		case index < plan.ActiveBatch:
			if !batchNodesHaveState(plan.NodeStates, batch.NodeIDs, NodeHealthy) {
				return false
			}
		case index > plan.ActiveBatch:
			if !batchNodesHaveState(plan.NodeStates, batch.NodeIDs, NodePending) {
				return false
			}
		case paused:
			if !batchNodesOnlyHaveStates(plan.NodeStates, batch.NodeIDs, NodeHealthy, NodeDispatched, NodeFailed) {
				return false
			}
		default:
			if !batchNodesOnlyHaveStates(plan.NodeStates, batch.NodeIDs, NodeHealthy, NodeDispatched) ||
				!batchNodesContainState(plan.NodeStates, batch.NodeIDs, NodeDispatched) {
				return false
			}
		}
	}
	return true
}

func validRollbackProgress(plan RolloutPlan, failed bool) bool {
	if plan.ActiveBatch < 0 || plan.ActiveBatch >= len(plan.RollbackBatches) ||
		!samePlanBatches(plan.RollbackBatches, expectedRollbackBatches(plan)) {
		return false
	}
	for index, batch := range plan.RollbackBatches {
		switch {
		case index < plan.ActiveBatch:
			if !batchNodesHaveState(plan.NodeStates, batch.NodeIDs, NodeRolledBack) {
				return false
			}
		case index > plan.ActiveBatch:
			if !batchNodesOnlyHaveStates(plan.NodeStates, batch.NodeIDs, NodeHealthy, NodeDispatched, NodeFailed) {
				return false
			}
		case failed:
			if !batchNodesOnlyHaveStates(plan.NodeStates, batch.NodeIDs, NodeDispatched, NodeRolledBack, NodeFailed) ||
				!batchNodesContainState(plan.NodeStates, batch.NodeIDs, NodeFailed) {
				return false
			}
		default:
			if !batchNodesOnlyHaveStates(plan.NodeStates, batch.NodeIDs, NodeDispatched, NodeRolledBack) ||
				!batchNodesContainState(plan.NodeStates, batch.NodeIDs, NodeDispatched) {
				return false
			}
		}
	}
	return true
}

func validRolledBackCompletion(plan RolloutPlan) bool {
	if len(plan.RollbackBatches) == 0 || !samePlanBatches(plan.RollbackBatches, expectedRollbackBatches(plan)) {
		return false
	}
	rolledBack := make(map[string]bool)
	for _, batch := range plan.RollbackBatches {
		if !batchNodesHaveState(plan.NodeStates, batch.NodeIDs, NodeRolledBack) {
			return false
		}
		for _, nodeID := range batch.NodeIDs {
			rolledBack[nodeID] = true
		}
	}
	for nodeID, state := range plan.NodeStates {
		if !rolledBack[nodeID] && state != NodePending {
			return false
		}
	}
	return true
}

func validPlanNodeState(state PlanNodeState) bool {
	return state == NodePending || state == NodeDispatched || state == NodeHealthy ||
		state == NodeFailed || state == NodeRolledBack
}

func allPlanNodesState(states map[string]PlanNodeState, state PlanNodeState) bool {
	for _, current := range states {
		if current != state {
			return false
		}
	}
	return true
}

func batchNodesOnlyHaveStates(states map[string]PlanNodeState, nodes []string, allowed ...PlanNodeState) bool {
	for _, nodeID := range nodes {
		if !containsPlanNodeState(allowed, states[nodeID]) {
			return false
		}
	}
	return true
}

func batchNodesContainState(states map[string]PlanNodeState, nodes []string, expected ...PlanNodeState) bool {
	for _, nodeID := range nodes {
		if containsPlanNodeState(expected, states[nodeID]) {
			return true
		}
	}
	return false
}

func containsPlanNodeState(states []PlanNodeState, state PlanNodeState) bool {
	for _, candidate := range states {
		if candidate == state {
			return true
		}
	}
	return false
}

func cloneRolloutPlan(plan RolloutPlan) RolloutPlan {
	clone := plan
	clone.ForwardProfile = cloneCommandProfile(plan.ForwardProfile)
	clone.RollbackProfile = cloneCommandProfile(plan.RollbackProfile)
	clone.Batches = clonePlanBatches(plan.Batches)
	clone.RollbackBatches = clonePlanBatches(plan.RollbackBatches)
	clone.Targets = make(map[string]PlanTarget, len(plan.Targets))
	for nodeID, target := range plan.Targets {
		clone.Targets[nodeID] = target
	}
	clone.NodeStates = make(map[string]PlanNodeState, len(plan.NodeStates))
	for nodeID, state := range plan.NodeStates {
		clone.NodeStates[nodeID] = state
	}
	clone.NodeDispatchRevisions = make(map[string]uint64, len(plan.NodeDispatchRevisions))
	for nodeID, revision := range plan.NodeDispatchRevisions {
		clone.NodeDispatchRevisions[nodeID] = revision
	}
	clone.Blockers = append([]PlanBlocker(nil), plan.Blockers...)
	clone.CommandReceipts = append([]PlanCommandReceipt(nil), plan.CommandReceipts...)
	clone.HealthReceipts = append([]PlanHealthReceipt(nil), plan.HealthReceipts...)
	for index := range clone.HealthReceipts {
		clone.HealthReceipts[index].Health.ActiveEvidence =
			cloneControlActiveProbeEvidence(plan.HealthReceipts[index].Health.ActiveEvidence)
	}
	return clone
}

func cloneCommandProfile(profile CommandProfile) CommandProfile {
	clone := profile
	clone.Health.Command = append([]string(nil), profile.Health.Command...)
	return clone
}

func validCommandProfile(profile CommandProfile) bool {
	if !codePattern.MatchString(profile.Platform) || !codePattern.MatchString(profile.Architecture) ||
		!validCanonicalVersion(profile.Compatibility.MinAgentVersion) ||
		!validCanonicalVersion(profile.Compatibility.MaxAgentVersion) ||
		semver.Compare("v"+profile.Compatibility.MinAgentVersion, "v"+profile.Compatibility.MaxAgentVersion) > 0 ||
		len(profile.Health.Command) != 2 || profile.Health.Command[0] != "{artifact}" ||
		profile.Health.Command[1] != "--version" || profile.Health.ActivationTimeoutNanoseconds <= 0 ||
		profile.Health.ObservationWindowNanoseconds <= 0 || profile.Health.IntervalNanoseconds <= 0 ||
		profile.Health.ProbeTimeoutNanoseconds <= 0 || profile.Health.RequiredConsecutiveSuccesses <= 0 ||
		profile.Health.IntervalNanoseconds > profile.Health.ActivationTimeoutNanoseconds ||
		profile.Health.ProbeTimeoutNanoseconds > profile.Health.ActivationTimeoutNanoseconds ||
		profile.Rollout.Percentage == 0 || profile.Rollout.Percentage > 100 || !profile.Rollback.Automatic {
		return false
	}
	for _, argument := range profile.Health.Command {
		if argument == "" || len(argument) > 4096 || bytes.IndexByte([]byte(argument), 0) >= 0 {
			return false
		}
	}
	return true
}

func clonePlanBatches(batches []PlanBatch) []PlanBatch {
	clone := make([]PlanBatch, len(batches))
	for index, batch := range batches {
		clone[index] = batch
		clone[index].NodeIDs = append([]string(nil), batch.NodeIDs...)
	}
	return clone
}
