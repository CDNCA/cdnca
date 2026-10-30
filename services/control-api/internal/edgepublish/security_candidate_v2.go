package edgepublish

import (
	"bytes"
	"context"
	"encoding/json"
	"fmt"
	"slices"
	"sort"
	"time"

	agentv1 "github.com/cdnca/cdnca/proto/gen/go/agent/v1"
	"github.com/cdnca/cdnca/services/control-api/internal/edgedeployment"
	"github.com/google/uuid"
	"github.com/jackc/pgx/v5"
)

// persistSiteRuntimeV2SecurityCandidateTx is PersistSecurityCandidateTx for
// a site runtime v2 scope (docs/architecture/security-activation-v2.md): the
// v2 document is compiled with the candidate binding in place of the site's
// active one, and delivered as site objects (site runtime v8): one signed
// root and a key envelope for every target node (canary and expand) now,
// since a releasable config takes no more artifacts. Each node's envelope is
// bound to a pre-assigned deployment and event (attempt 1) and recorded in
// security_policy_activation_node_artifacts_333 with the root's digest (what
// the node reports running), from which the activation builds each phase's
// rollout. The candidate's identity digest is the root's.
func (s *Service) persistSiteRuntimeV2SecurityCandidateTx(
	ctx context.Context,
	tx pgx.Tx,
	request SecurityCandidateRequest,
	override *securityBindingFact,
) (SecurityCandidateResult, error) {
	now := s.config.Clock().UTC().Truncate(time.Microsecond)
	soldLimits, err := loadSoldPackageLimits(ctx, tx, request.ConfigurationScopeID)
	if err != nil {
		return SecurityCandidateResult{}, err
	}
	if !override.detach && len(soldPackageSecurityBindings([]securityBindingFact{*override}, soldLimits[override.siteID])) == 0 {
		return SecurityCandidateResult{}, ErrUnsupportedSecurityPolicy
	}
	target := TargetSnapshot{NodeIDs: canonicalUUIDs(request.TargetNodeIDs)}
	if len(target.NodeIDs) != len(request.TargetNodeIDs) || slices.Contains(target.NodeIDs, uuid.Nil) {
		return SecurityCandidateResult{}, ErrInvalidInput
	}
	snapshotBytes, snapshotDigest, bundle, _, capabilities, telemetrySubscriptions, err :=
		s.compileSiteRuntimeV2FactsWith(ctx, tx, request.ConfigurationScopeID, request.ConfigVersionID,
			request.SourceRevision, target, now, nil, nil, override)
	if err != nil {
		return SecurityCandidateResult{}, err
	}
	if _, found := telemetrySubscriptions[request.SiteID]; !found {
		return SecurityCandidateResult{}, ErrNotFound
	}
	if err := validateL4AdditionalListenerTargets(ctx, tx, request.ConfigurationScopeID, target.NodeIDs, capabilities, now); err != nil {
		return SecurityCandidateResult{}, err
	}
	if err := validateCrossScopeComposition(ctx, tx, request.ConfigurationScopeID, target.NodeIDs, snapshotBytes); err != nil {
		return SecurityCandidateResult{}, err
	}
	challengeTargets, err := siteRuntimeV2ChallengePolicyTargets(snapshotBytes)
	if err != nil {
		return SecurityCandidateResult{}, err
	}
	if err := validateChallengePolicyTargets(ctx, tx, request.ConfigurationScopeID, target.NodeIDs, challengeTargets); err != nil {
		return SecurityCandidateResult{}, err
	}
	recipients, err := lockConfigurationArtifactRecipients(ctx, tx, request.ConfigurationScopeID, target.NodeIDs, now)
	if err != nil {
		return SecurityCandidateResult{}, err
	}
	release, err := s.buildSiteObjectRelease(ctx, tx, request.ConfigurationScopeID, request.ConfigVersionID, bundle,
		recipients, capabilities, now)
	if err != nil {
		return SecurityCandidateResult{}, err
	}
	persisted, err := s.deployments.PersistReleasableConfigTx(ctx, tx, request.ConfigVersionID,
		edgedeployment.PersistConfigRequest{
			ConfigurationScopeID: request.ConfigurationScopeID, CanonicalSnapshot: snapshotBytes,
			GeneratorName: s.config.GeneratorName, GeneratorVersion: s.config.GeneratorVersion,
			IdempotencyKey: "securityactivation.config." + request.IdempotencyKey,
			Artifacts:      release.artifacts,
		})
	if err != nil {
		return SecurityCandidateResult{}, err
	}
	if persisted.ConfigVersion.ID != request.ConfigVersionID {
		return SecurityCandidateResult{}, fmt.Errorf("%w: persisted security candidate config mismatch", ErrPersistence)
	}
	if err := release.persist(ctx, tx, now); err != nil {
		return SecurityCandidateResult{}, err
	}
	// Every node runs the shared signed root (site runtime v8): the
	// candidate's identity and each node's expected digest are its digest.
	plaintextDigest := release.rootSHA256
	if err := persistSiteIPv6RolloutTargets(ctx, tx, request.ConfigurationScopeID, request.ConfigVersionID,
		request.SourceRevision, snapshotBytes, now); err != nil {
		return SecurityCandidateResult{}, err
	}
	// Telemetry from a node running the candidate is accepted for its sites.
	if err := persistTelemetrySiteBindings(ctx, tx, request.ConfigVersionID, telemetrySubscriptions); err != nil {
		return SecurityCandidateResult{}, err
	}
	encodedCapabilities, err := encodeSecurityCandidateCapabilities(capabilities)
	if err != nil {
		return SecurityCandidateResult{}, err
	}
	if _, err := tx.Exec(ctx, `INSERT INTO security_policy_activation_config_facts(
		tenant_scope_id,config_version_id,artifact_sha256,policy_kind,required_capabilities,created_at)
		VALUES($1,$2,$3,$4,$5,$6)`, request.ConfigurationScopeID, request.ConfigVersionID,
		plaintextDigest[:], request.Policy.Kind, encodedCapabilities, now); err != nil {
		return SecurityCandidateResult{}, fmt.Errorf("%w: persist security activation config fact", ErrPersistence)
	}
	for _, binding := range release.bindings {
		if _, err := tx.Exec(ctx, `INSERT INTO security_policy_activation_node_artifacts_333(
			tenant_scope_id,config_version_id,node_id,deployment_id,event_id,artifact_id,artifact_sha256,
			recipient_key_id,created_at) VALUES($1,$2,$3,$4,$5,$6,$7,$8,$9)`,
			request.ConfigurationScopeID, request.ConfigVersionID, binding.NodeID, binding.DeploymentID,
			binding.EventID, binding.ArtifactID, release.rootSHA256[:], binding.RecipientKeyID, now); err != nil {
			return SecurityCandidateResult{}, fmt.Errorf("%w: persist security activation node artifact", ErrPersistence)
		}
	}
	return SecurityCandidateResult{
		ConfigVersionID: request.ConfigVersionID, CanonicalSnapshotSHA256: snapshotDigest,
		ArtifactSHA256: plaintextDigest, RequiredCapabilities: cloneSecurityCapabilities(capabilities),
		SiteRuntimeV2: true,
	}, nil
}

// encodeSecurityCandidateCapabilities is the config fact's
// required_capabilities: name-ordered, each once, non-empty.
func encodeSecurityCandidateCapabilities(capabilities []*agentv1.Capability) ([]byte, error) {
	capabilityFacts := make([]struct {
		Name       int32  `json:"name"`
		APIVersion uint32 `json:"api_version"`
	}, len(capabilities))
	for index, capability := range capabilities {
		if capability == nil || capability.Name == agentv1.CapabilityName_CAPABILITY_NAME_UNSPECIFIED ||
			capability.ApiVersion == 0 || index > 0 && capabilities[index-1].Name >= capability.Name {
			return nil, ErrUnsupportedSecurityPolicy
		}
		capabilityFacts[index].Name = int32(capability.Name)
		capabilityFacts[index].APIVersion = capability.ApiVersion
	}
	encoded, err := json.Marshal(capabilityFacts)
	if err != nil || len(capabilityFacts) == 0 {
		return nil, ErrUnsupportedSecurityPolicy
	}
	return encoded, nil
}

func canonicalUUIDs(values []uuid.UUID) []uuid.UUID {
	result := slices.Clone(values)
	sort.Slice(result, func(i, j int) bool { return bytes.Compare(result[i][:], result[j][:]) < 0 })
	return slices.Compact(result)
}
