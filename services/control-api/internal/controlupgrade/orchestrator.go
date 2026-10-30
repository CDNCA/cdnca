package controlupgrade

import (
	"bytes"
	"context"
	"encoding/base64"
	"encoding/hex"
	"encoding/json"
	"log/slog"
	"reflect"
	"strings"
	"time"

	"github.com/cdnca/cdnca/libs/entitlement"
	"github.com/google/uuid"
)

type RolloutProfilePolicy struct {
	ActivationTimeout            time.Duration
	ObservationWindow            time.Duration
	HealthInterval               time.Duration
	ProbeTimeout                 time.Duration
	RequiredConsecutiveSuccesses int
}

type RolloutRuntimeConfig struct {
	License          *LicenseClient
	LicenseKeys      *entitlement.KeyRing
	CommandGrantKeys *entitlement.KeyRing
	// SignerRevocation, when set, rejects parent grants, artifact bundles and
	// command grants whose authentic signer is revoked for release artifacts.
	SignerRevocation   SignerRevocationChecker
	ControlSigner      entitlement.Signer
	EdgeSigner         entitlement.Signer
	InstallationID     uuid.UUID
	CommandIssuanceTTL time.Duration
	ExecutionTTL       time.Duration
	Profiles           RolloutProfilePolicy
	// Artifacts caches the signed forward/rollback artifacts on the control
	// plane; executions then point nodes at the cache, never at the license origin.
	Artifacts *ArtifactCache
	// DownloadPolicy, when set, signs the current download endpoint for the
	// cached artifact URL into each execution (nil result: none).
	DownloadPolicy func(ctx context.Context, downloadURL string) *entitlement.UpgradeDownloadPolicy
	Clock          func() time.Time
}

type RolloutRuntime struct {
	config            RolloutRuntimeConfig
	createPreparation rolloutCreatePreparationStore
}

type rolloutCreatePreparationStore interface {
	PrepareCreateRollout(context.Context, Actor, RolloutIdentity, CreateRolloutRequest,
		[32]byte) (CreateRolloutIntent, RolloutWriteResult, error)
	LoadRolloutTargetCohort(context.Context, Actor, []string) (RolloutTargetCohort, error)
}

func NewRolloutRuntime(config RolloutRuntimeConfig) (*RolloutRuntime, error) {
	if config.Clock == nil {
		config.Clock = time.Now
	}
	if config.License == nil || config.LicenseKeys == nil || config.CommandGrantKeys == nil || config.Artifacts == nil ||
		config.ControlSigner == nil || config.EdgeSigner == nil || config.InstallationID == uuid.Nil ||
		config.CommandIssuanceTTL <= 0 || config.CommandIssuanceTTL > 7*24*time.Hour ||
		config.ExecutionTTL <= 0 || config.ExecutionTTL > config.CommandIssuanceTTL ||
		!validRolloutProfilePolicy(config.Profiles) ||
		entitlement.ValidateKeyID(config.ControlSigner.KeyID()) != nil ||
		entitlement.ValidateKeyID(config.EdgeSigner.KeyID()) != nil ||
		config.ControlSigner.KeyID() == config.EdgeSigner.KeyID() {
		return nil, ErrInvalidInput
	}
	return &RolloutRuntime{config: config}, nil
}

func validRolloutProfilePolicy(policy RolloutProfilePolicy) bool {
	return policy.ActivationTimeout > 0 && policy.ActivationTimeout <= 30*time.Minute &&
		policy.ObservationWindow > 0 && policy.ObservationWindow <= 30*time.Minute &&
		policy.HealthInterval > 0 && policy.HealthInterval <= policy.ObservationWindow &&
		policy.HealthInterval <= policy.ActivationTimeout && policy.ProbeTimeout > 0 &&
		policy.ProbeTimeout <= policy.ActivationTimeout && policy.RequiredConsecutiveSuccesses >= 1 &&
		policy.RequiredConsecutiveSuccesses <= 100
}

func (s *Service) ConfigureRolloutRuntime(runtime *RolloutRuntime) error {
	if s == nil || s.store == nil || runtime == nil {
		return ErrInvalidInput
	}
	s.rollout = runtime
	return nil
}

func (s *Service) ListRollouts(ctx context.Context, actor Actor,
	request ListRolloutsRequest) (ListRolloutsResponse, error) {
	if s == nil || s.store == nil {
		return ListRolloutsResponse{}, ErrRuntimeUnavailable
	}
	return s.store.ListRollouts(ctx, actor, request)
}

func (s *Service) GetRollout(ctx context.Context, actor Actor, planID string) (RolloutDetail, error) {
	if s == nil || s.store == nil {
		return RolloutDetail{}, ErrRuntimeUnavailable
	}
	return s.store.GetRollout(ctx, actor, planID)
}

func (s *Service) CreateRollout(ctx context.Context, actor Actor,
	request CreateRolloutRequest) (RolloutWriteResult, error) {
	if s == nil || s.store == nil || s.rollout == nil {
		return RolloutWriteResult{}, ErrRuntimeUnavailable
	}
	if validateCreateRolloutRequest(request) != nil {
		return RolloutWriteResult{}, ErrInvalidInput
	}
	config := s.rollout.config
	identity := RolloutIdentity{ActorScopeID: actor.ScopeID.String(), ActorUserID: actor.UserID.String(),
		InstallationID: config.InstallationID.String()}
	digest, _, err := rolloutRequestDigest(actor, config.InstallationID, "create", "", request.CreateRolloutBody)
	if err != nil {
		return RolloutWriteResult{}, err
	}
	preparation := s.rollout.createPreparation
	if preparation == nil {
		preparation = s.store
	}
	intent, replay, err := preparation.PrepareCreateRollout(ctx, actor, identity, request, digest)
	if err != nil || replay.Replayed {
		return replay, err
	}
	cohort, err := preparation.LoadRolloutTargetCohort(ctx, actor, request.NodeIDs)
	if err != nil {
		return RolloutWriteResult{}, err
	}

	binding := intent.Binding
	var parent entitlement.UpgradeGrant
	var bundle entitlement.UpgradePlanArtifactBundle
	if intent.State == createIntentAcquired {
		parent, bundle, err = verifyRolloutArtifacts(config, intent.PlanID, binding)
	} else {
		binding, parent, bundle, err = issueRolloutArtifacts(ctx, config, intent, cohort, request)
	}
	if err != nil {
		return RolloutWriteResult{}, err
	}
	// Cache both artifacts before the plan becomes durable so every later
	// command can be served by the control plane alone.
	if err := config.Artifacts.ensureManifest(ctx, bundle.Forward.Manifest); err != nil {
		return RolloutWriteResult{}, err
	}
	if err := config.Artifacts.ensureManifest(ctx, bundle.Rollback.Manifest); err != nil {
		return RolloutWriteResult{}, err
	}
	profiles := rolloutProfiles(cohort, bundle.Version, config.Profiles)
	binding.ForwardProfileBytes, _ = json.Marshal(profiles.forward)
	binding.RollbackProfileBytes, _ = json.Marshal(profiles.rollback)
	binding.ForwardProfileSHA256 = encodedRolloutDigest(binding.ForwardProfileBytes)
	binding.RollbackProfileSHA256 = encodedRolloutDigest(binding.RollbackProfileBytes)
	if err := s.store.AcquireCreateRollout(ctx, actor, intent, binding); err != nil {
		return RolloutWriteResult{}, err
	}
	confirmed, err := s.store.LoadRolloutTargetCohort(ctx, actor, request.NodeIDs)
	if err != nil || !reflect.DeepEqual(confirmed, cohort) {
		if err == nil {
			err = ErrCohortIncompatible
		}
		return RolloutWriteResult{}, err
	}
	plan, err := newRolloutPlanFromArtifacts(intent.PlanID, parent, bundle, binding, cohort, request, profiles)
	if err != nil {
		return RolloutWriteResult{}, err
	}
	snapshot, err := encodeRolloutValue(plan)
	if err != nil {
		return RolloutWriteResult{}, ErrInvalidPlan
	}
	result, err := s.store.FinalizeCreateRollout(ctx, actor, identity, request, digest, intent, cohort,
		plan, binding, snapshot, encodedRolloutDigest(snapshot))
	if err == nil {
		// Best effort: a new plan is when older versions stop being needed.
		// Failure only leaves extra files; it never affects the plan.
		if removed, pruneErr := config.Artifacts.PruneUnreferenced(ctx, s.store.pool); pruneErr != nil {
			slog.Warn("control upgrade artifact cache prune failed", "error", pruneErr)
		} else if removed > 0 {
			slog.Info("control upgrade artifact cache pruned", "removed", removed)
		}
	}
	return result, err
}

type derivedRolloutProfiles struct {
	forward  CommandProfile
	rollback CommandProfile
}

func rolloutProfiles(cohort RolloutTargetCohort, targetVersion string,
	policy RolloutProfilePolicy) derivedRolloutProfiles {
	health := entitlement.UpgradeExecutionHealthPolicy{Command: []string{"{artifact}", "--version"},
		ActivationTimeoutNanoseconds: int64(policy.ActivationTimeout),
		ObservationWindowNanoseconds: int64(policy.ObservationWindow), IntervalNanoseconds: int64(policy.HealthInterval),
		ProbeTimeoutNanoseconds:      int64(policy.ProbeTimeout),
		RequiredConsecutiveSuccesses: policy.RequiredConsecutiveSuccesses}
	base := CommandProfile{Platform: cohort.Platform, Architecture: cohort.Architecture, Health: health,
		Rollout:  entitlement.UpgradeExecutionRolloutPolicy{Percentage: 100},
		Rollback: entitlement.UpgradeExecutionRollbackPolicy{Automatic: true}}
	forward := cloneCommandProfile(base)
	forward.Compatibility = entitlement.UpgradeExecutionCompatibility{MinAgentVersion: cohort.CurrentVersion,
		MaxAgentVersion: cohort.CurrentVersion}
	rollback := cloneCommandProfile(base)
	rollback.Compatibility = entitlement.UpgradeExecutionCompatibility{MinAgentVersion: targetVersion,
		MaxAgentVersion: targetVersion}
	return derivedRolloutProfiles{forward: forward, rollback: rollback}
}

func issueRolloutArtifacts(ctx context.Context, config RolloutRuntimeConfig, intent CreateRolloutIntent,
	cohort RolloutTargetCohort, request CreateRolloutRequest) (PlanGrantBinding, entitlement.UpgradeGrant,
	entitlement.UpgradePlanArtifactBundle, error) {
	parentResult, err := config.License.IssueParentGrant(ctx, ParentGrantRequest{
		IdempotencyKey: "parent." + strings.ReplaceAll(intent.ID, "-", ""), RequestID: request.RequestID,
		Component: "edge-agent", CurrentVersion: cohort.CurrentVersion, ProtocolVersion: int(cohort.ProtocolVersion)})
	if err != nil {
		return PlanGrantBinding{}, entitlement.UpgradeGrant{}, entitlement.UpgradePlanArtifactBundle{}, err
	}
	parent, err := VerifyGrantWithRevocation(parentResult.Encoded, config.LicenseKeys, entitlement.UpgradeGrantVerifyOptions{
		Now: config.Clock().UTC(), ExpectedAudience: entitlement.UpgradeGrantAudience,
		ExpectedInstallationID: config.InstallationID.String()}, config.SignerRevocation)
	if err != nil || parentResult.ID.String() != parent.GrantID || parent.Component != "edge-agent" ||
		parent.CurrentVersion != cohort.CurrentVersion || parent.ProtocolVersion != int(cohort.ProtocolVersion) {
		return PlanGrantBinding{}, entitlement.UpgradeGrant{}, entitlement.UpgradePlanArtifactBundle{}, ErrGrantInvalid
	}
	parentDigest, err := entitlement.CanonicalUpgradeGrantDigest(parentResult.Encoded)
	if err != nil {
		return PlanGrantBinding{}, entitlement.UpgradeGrant{}, entitlement.UpgradePlanArtifactBundle{}, ErrGrantInvalid
	}
	deadline := config.Clock().UTC().Add(config.CommandIssuanceTTL).Unix()
	bundleResult, err := config.License.IssuePlanArtifactBundle(ctx, PlanArtifactBundleRequest{
		IdempotencyKey: "bundle." + strings.ReplaceAll(intent.ID, "-", ""), RequestID: request.RequestID,
		PlanID: intent.PlanID, InitialPlanRevision: 1, ParentUpgradeGrant: parentResult.Encoded,
		CommandIssuanceNotAfter: deadline})
	if err != nil {
		return PlanGrantBinding{}, entitlement.UpgradeGrant{}, entitlement.UpgradePlanArtifactBundle{}, err
	}
	signedBundle, err := entitlement.DecodeUpgradePlanArtifactBundle(bundleResult.Encoded)
	if err != nil {
		return PlanGrantBinding{}, entitlement.UpgradeGrant{}, entitlement.UpgradePlanArtifactBundle{}, ErrGrantInvalid
	}
	bundle, err := config.LicenseKeys.VerifyUpgradePlanArtifactBundle(signedBundle,
		entitlement.UpgradePlanArtifactBundleVerifyOptions{Now: config.Clock().UTC(),
			ExpectedAudience:       entitlement.UpgradePlanArtifactBundleAudience,
			ExpectedInstallationID: config.InstallationID.String(), ExpectedPlanID: intent.PlanID,
			ExpectedInitialPlanRevision: 1})
	if err == nil {
		err = checkReleaseSigners(config.SignerRevocation, signedBundle.KeyID,
			signedBundle.Bundle.Forward.SignatureKeyID, signedBundle.Bundle.Rollback.SignatureKeyID)
	}
	if err != nil || bundleResult.ID.String() != bundle.BundleID || bundleResult.CommandIssuanceNotAfter != deadline ||
		bundle.ParentGrantID != parent.GrantID || bundle.ParentGrantSHA256 != parentDigest {
		return PlanGrantBinding{}, entitlement.UpgradeGrant{}, entitlement.UpgradePlanArtifactBundle{}, ErrGrantInvalid
	}
	binding := PlanGrantBinding{ParentGrantBytes: bytes.Clone(parentResult.Encoded), ParentGrantSHA256: parentDigest,
		ArtifactBundleBytes:  bytes.Clone(bundleResult.Encoded),
		ArtifactBundleSHA256: base64.RawURLEncoding.EncodeToString(bundleResult.Digest[:])}
	return binding, parent, bundle, nil
}

func verifyRolloutArtifacts(config RolloutRuntimeConfig, planID string,
	binding PlanGrantBinding) (entitlement.UpgradeGrant, entitlement.UpgradePlanArtifactBundle, error) {
	parent, err := VerifyGrantWithRevocation(binding.ParentGrantBytes, config.LicenseKeys, entitlement.UpgradeGrantVerifyOptions{
		Now: config.Clock().UTC(), ExpectedAudience: entitlement.UpgradeGrantAudience,
		ExpectedInstallationID: config.InstallationID.String()}, config.SignerRevocation)
	if err != nil {
		return entitlement.UpgradeGrant{}, entitlement.UpgradePlanArtifactBundle{}, ErrGrantInvalid
	}
	signed, err := entitlement.DecodeUpgradePlanArtifactBundle(binding.ArtifactBundleBytes)
	if err != nil {
		return entitlement.UpgradeGrant{}, entitlement.UpgradePlanArtifactBundle{}, ErrGrantInvalid
	}
	bundle, err := config.LicenseKeys.VerifyUpgradePlanArtifactBundle(signed,
		entitlement.UpgradePlanArtifactBundleVerifyOptions{Now: config.Clock().UTC(),
			ExpectedAudience:       entitlement.UpgradePlanArtifactBundleAudience,
			ExpectedInstallationID: config.InstallationID.String(), ExpectedPlanID: planID,
			ExpectedInitialPlanRevision: 1})
	if err == nil {
		err = checkReleaseSigners(config.SignerRevocation, signed.KeyID,
			signed.Bundle.Forward.SignatureKeyID, signed.Bundle.Rollback.SignatureKeyID)
	}
	if err != nil || bundle.ParentGrantID != parent.GrantID || bundle.ParentGrantSHA256 != binding.ParentGrantSHA256 {
		return entitlement.UpgradeGrant{}, entitlement.UpgradePlanArtifactBundle{}, ErrGrantInvalid
	}
	return parent, bundle, nil
}

func newRolloutPlanFromArtifacts(planID string, parent entitlement.UpgradeGrant,
	bundle entitlement.UpgradePlanArtifactBundle, binding PlanGrantBinding, cohort RolloutTargetCohort,
	request CreateRolloutRequest, profiles derivedRolloutProfiles) (RolloutPlan, error) {
	canaries := make(map[string]bool, len(request.CanaryNodeIDs))
	for _, nodeID := range request.CanaryNodeIDs {
		canaries[nodeID] = true
	}
	groups := []PlanGroup{{ID: "canary", Canary: true, BatchSize: min(request.BatchSize, len(canaries))}}
	for _, target := range cohort.Targets {
		if canaries[target.NodeID] {
			groups[0].Targets = append(groups[0].Targets, target)
		}
	}
	nonCanaries := len(cohort.Targets) - len(canaries)
	if nonCanaries > 0 {
		group := PlanGroup{ID: "wave", BatchSize: min(request.BatchSize, nonCanaries)}
		for _, target := range cohort.Targets {
			if !canaries[target.NodeID] {
				group.Targets = append(group.Targets, target)
			}
		}
		groups = append(groups, group)
	}
	forward, rollback := bundle.Forward.Manifest, bundle.Rollback.Manifest
	forwardReleaseSequence, rollbackReleaseSequence := bundle.ChannelRevision, bundle.ChannelRevision
	if bundle.Schema == entitlement.UpgradePlanArtifactBundleV2Schema {
		forwardReleaseSequence = forward.ReleaseSequence
		rollbackReleaseSequence = rollback.ReleaseSequence
	}
	return NewRolloutPlan(RolloutPlanInput{ID: planID, ParentGrantID: parent.GrantID,
		GrantDigest: binding.ParentGrantSHA256, ParentGrantExpiresAt: parent.ExpiresAt,
		ArtifactBundleID: bundle.BundleID, ArtifactBundleSHA256: binding.ArtifactBundleSHA256,
		CommandIssuanceNotAfter: bundle.CommandIssuanceNotAfter, ReleaseSequence: forwardReleaseSequence,
		Component: bundle.Component, ArtifactID: forward.ArtifactID, SHA256Digest: forward.SHA256Digest,
		ArtifactSizeBytes: forward.ArtifactSizeBytes, RollbackGrantDigest: binding.ParentGrantSHA256,
		RollbackReleaseSequence: rollbackReleaseSequence, RollbackArtifactID: rollback.ArtifactID,
		RollbackSHA256Digest: rollback.SHA256Digest, RollbackArtifactSizeBytes: rollback.ArtifactSizeBytes,
		CurrentVersion: bundle.CurrentVersion, TargetVersion: bundle.Version, AutomaticRollback: true,
		ForwardProfile: profiles.forward, RollbackProfile: profiles.rollback,
		Safety: PlanSafety{MinAgentVersion: profiles.forward.Compatibility.MinAgentVersion,
			MaxAgentVersion: profiles.forward.Compatibility.MaxAgentVersion,
			ProtocolMin:     uint32(max(forward.ProtocolMin, rollback.ProtocolMin)),
			ProtocolMax:     uint32(min(forward.ProtocolMax, rollback.ProtocolMax)), RollbackAvailable: true}, Groups: groups})
}

func (s *Service) ApplyRolloutAction(ctx context.Context, actor Actor,
	request RolloutActionRequest) (RolloutWriteResult, error) {
	if s == nil || s.store == nil || s.rollout == nil {
		return RolloutWriteResult{}, ErrRuntimeUnavailable
	}
	prepared, replay, err := s.store.PrepareRolloutAction(ctx, actor, request)
	if err != nil || replay.Replayed {
		return replay, err
	}
	commands := make([]RolloutNodeCommand, 0, len(prepared.Dispatches))
	outbox := make([]RolloutOutboxMessage, 0, len(prepared.Dispatches))
	for _, dispatch := range prepared.Dispatches {
		command, message, err := s.issueRolloutDispatch(ctx, prepared.Request.RequestID,
			prepared.Plan, prepared.Binding, dispatch)
		if err != nil {
			return RolloutWriteResult{}, err
		}
		commands = append(commands, command)
		outbox = append(outbox, message)
	}
	return s.store.FinalizeRolloutAction(ctx, prepared, commands, outbox)
}

func (s *Service) ResolveStatusIdentity(ctx context.Context, commandID string) (RolloutIdentity, error) {
	if s == nil || s.store == nil {
		return RolloutIdentity{}, ErrRuntimeUnavailable
	}
	return s.store.ResolveStatusIdentity(ctx, commandID)
}

func (s *Service) RejectStatus(ctx context.Context, rejection RolloutStatusRejection) error {
	if s == nil || s.store == nil {
		return ErrRuntimeUnavailable
	}
	return s.store.RejectStatus(ctx, rejection)
}

func (s *Service) RecordStatus(ctx context.Context, identity RolloutIdentity,
	receipt RolloutStatusReceipt) (bool, error) {
	if s == nil || s.store == nil {
		return false, ErrRuntimeUnavailable
	}
	if !terminalRolloutStatus(receipt.State) {
		return s.store.RecordStatus(ctx, identity, receipt)
	}
	prepared, replayed, err := s.store.PrepareRolloutStatus(ctx, identity, receipt)
	if err != nil || replayed {
		return replayed, err
	}
	if s.rollout == nil {
		return false, ErrRuntimeUnavailable
	}
	commands := make([]RolloutNodeCommand, 0, len(prepared.Dispatches))
	outbox := make([]RolloutOutboxMessage, 0, len(prepared.Dispatches))
	requestID := "status." + strings.ReplaceAll(receipt.StatusID, "-", "")
	for _, dispatch := range prepared.Dispatches {
		command, message, err := s.issueRolloutDispatch(ctx, requestID, prepared.Plan,
			prepared.Binding, dispatch)
		if err != nil {
			return false, err
		}
		commands = append(commands, command)
		outbox = append(outbox, message)
	}
	return s.store.FinalizeRolloutStatus(ctx, prepared, commands, outbox)
}

func (s *Service) issueRolloutDispatch(ctx context.Context, requestID string, plan RolloutPlan,
	binding PlanGrantBinding, dispatch RolloutDispatchIntent) (RolloutNodeCommand, RolloutOutboxMessage, error) {
	config := s.rollout.config
	operation := "forward"
	action := entitlement.UpgradeOperation
	if dispatch.Action == entitlement.RollbackOperation {
		operation, action = "rollback", entitlement.RollbackOperation
	}
	result, err := config.License.IssueCommandGrant(ctx, CommandGrantRequest{
		IdempotencyKey: "command." + strings.ReplaceAll(dispatch.CommandID, "-", ""),
		RequestID:      requestID, PlanID: dispatch.PlanID, PlanRevision: dispatch.PlanRevision,
		BatchID: dispatch.BatchID, CommandID: dispatch.CommandID, NodeID: dispatch.NodeID, Operation: operation,
		ArtifactBundle: binding.ArtifactBundleBytes, ForwardProfile: plan.ForwardProfile,
		RollbackProfile: plan.RollbackProfile})
	if err != nil {
		return RolloutNodeCommand{}, RolloutOutboxMessage{}, err
	}
	now := config.Clock().UTC()
	options := entitlement.UpgradeCommandGrantVerifyOptions{Now: now,
		ExpectedAudience:       entitlement.UpgradeCommandGrantAudience,
		ExpectedInstallationID: dispatch.InstallationID, ExpectedNodeID: dispatch.NodeID,
		ExpectedCommandID: dispatch.CommandID, ExpectedPlanID: dispatch.PlanID,
		ExpectedPlanRevision: dispatch.PlanRevision, ExpectedBatchID: dispatch.BatchID}
	signedGrant, err := entitlement.DecodeUpgradeCommandGrant(result.Encoded)
	if err != nil {
		return RolloutNodeCommand{}, RolloutOutboxMessage{}, ErrGrantInvalid
	}
	grant, err := config.CommandGrantKeys.VerifyUpgradeCommandGrant(signedGrant, options)
	if err == nil {
		err = checkReleaseSigners(config.SignerRevocation, signedGrant.KeyID)
	}
	expectedReleaseSequence := plan.ReleaseSequence
	if action == entitlement.RollbackOperation {
		expectedReleaseSequence = plan.RollbackReleaseSequence
	}
	if err != nil || result.ID.String() != grant.CommandID ||
		(grant.Schema != entitlement.UpgradeCommandGrantV2Schema && grant.Schema != entitlement.UpgradeCommandGrantV3Schema) ||
		(plan.SchemaVersion == RolloutPlanSchemaVersion && (grant.Schema != entitlement.UpgradeCommandGrantV3Schema ||
			grant.ExecutionSequence == 0 || grant.ReleaseSequence != expectedReleaseSequence)) ||
		grant.Operation != action || grant.ArtifactBundleID != plan.ArtifactBundleID ||
		grant.ArtifactBundleSHA256 != plan.ArtifactBundleSHA256 ||
		grant.CommandIssuanceNotAfter != plan.CommandIssuanceNotAfter ||
		grant.ExpiresAt-grant.IssuedAt > int64(config.ExecutionTTL/time.Second) {
		return RolloutNodeCommand{}, RolloutOutboxMessage{}, ErrGrantInvalid
	}
	downloadURL, err := config.Artifacts.Ensure(ctx, grant.DownloadURL, grant.SHA256Digest, grant.ArtifactSizeBytes)
	if err != nil {
		return RolloutNodeCommand{}, RolloutOutboxMessage{}, err
	}
	var policy *entitlement.UpgradeDownloadPolicy
	if config.DownloadPolicy != nil {
		policy = config.DownloadPolicy(ctx, downloadURL)
	}
	execution, err := IssueCachedCommandExecution(ctx, result.Encoded, config.CommandGrantKeys, options,
		config.ControlSigner, config.EdgeSigner, downloadURL, policy)
	if err != nil {
		return RolloutNodeCommand{}, RolloutOutboxMessage{}, ErrExecutionInvalid
	}
	command := RolloutNodeCommand{ID: dispatch.CommandID, PlanID: dispatch.PlanID,
		PlanRevision: dispatch.PlanRevision, BatchID: dispatch.BatchID, NodeID: dispatch.NodeID,
		InstallationID: dispatch.InstallationID, Action: action, CommandGrantBytes: bytes.Clone(result.Encoded),
		CommandGrantSHA256:    base64.RawURLEncoding.EncodeToString(result.Digest[:]),
		CommandGrantExpiresAt: time.Unix(result.ExpiresAt, 0).UTC(), SignedExecutionBytes: execution,
		SignedExecutionSHA256: hex.EncodeToString(sha256Bytes(execution))}
	if grant.Schema == entitlement.UpgradeCommandGrantV3Schema {
		command.CommandSchema = grant.Schema
		command.ExecutionSequence = grant.ExecutionSequence
		command.ReleaseSequence = grant.ReleaseSequence
		command.Component = grant.Component
	}
	payload, err := json.Marshal(rolloutCommandPayload{Schema: "cdnca.edge.upgrade.command/v1",
		CommandID: command.ID, PlanID: command.PlanID, PlanRevision: command.PlanRevision,
		BatchID: command.BatchID, InstallationID: command.InstallationID, NodeID: command.NodeID,
		Action: command.Action, SignedExecution: command.SignedExecutionBytes,
		SignedExecutionSHA256: command.SignedExecutionSHA256})
	if err != nil {
		return RolloutNodeCommand{}, RolloutOutboxMessage{}, ErrExecutionInvalid
	}
	message := RolloutOutboxMessage{ID: command.ID, PlanID: command.PlanID,
		PlanRevision: command.PlanRevision, Topic: upgradeCommandSubjectPrefix + "." + command.NodeID,
		MessageKey: command.ID, PayloadBytes: payload, PayloadSHA256: rolloutWireDigest(payload), AvailableAt: now}
	return command, message, nil
}
