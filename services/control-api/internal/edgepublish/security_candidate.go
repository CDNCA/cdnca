package edgepublish

import (
	"context"
	"crypto/sha256"
	"slices"

	agentv1 "github.com/cdnca/cdnca/proto/gen/go/agent/v1"
	"github.com/cdnca/cdnca/services/control-api/internal/securitypolicy"
	"github.com/google/uuid"
	"github.com/jackc/pgx/v5"
)

type SecurityCandidateRequest struct {
	ConfigurationScopeID uuid.UUID
	SiteID               uuid.UUID
	SourceRevision       int64
	ConfigVersionID      uuid.UUID
	PublicationID        uuid.UUID
	BindingID            uuid.UUID
	BindingRevision      int64
	Policy               securitypolicy.Policy
	RuntimeSHA256        [sha256.Size]byte
	IdempotencyKey       string
	// SiteRuntimeSchema: v2 (or empty, ResolveSiteRuntimeSchema) compiles
	// the site runtime v2 document and encrypts it for each of TargetNodeIDs
	// (every node the activation will reach, canary and expand).
	SiteRuntimeSchema string
	TargetNodeIDs     []uuid.UUID
	// Detach (sec-rebind): the candidate withdraws the site's binding of
	// Policy.Kind instead of replacing it; the site enforces no rule of it.
	Detach bool
}

type SecurityCandidateResult struct {
	ConfigVersionID         uuid.UUID
	CanonicalSnapshotSHA256 [sha256.Size]byte
	ArtifactSHA256          [sha256.Size]byte
	RequiredCapabilities    []*agentv1.Capability
	// SiteRuntimeV2: ArtifactSHA256 is the plaintext bundle's digest; each
	// node's artifact is in security_policy_activation_node_artifacts_333.
	SiteRuntimeV2 bool
}

// PersistSecurityCandidateTx builds an immutable candidate without advancing
// the active edge source revision. The caller owns the scope lock and promotion
// CAS that eventually makes this candidate active.
func (s *Service) PersistSecurityCandidateTx(
	ctx context.Context,
	tx pgx.Tx,
	request SecurityCandidateRequest,
) (SecurityCandidateResult, error) {
	if s == nil || tx == nil || request.ConfigurationScopeID == uuid.Nil || request.SiteID == uuid.Nil ||
		request.SourceRevision < 2 || request.ConfigVersionID == uuid.Nil || request.PublicationID == uuid.Nil || request.BindingID == uuid.Nil ||
		request.BindingRevision < 1 || request.Policy.ID == uuid.Nil || request.Policy.ScopeID != request.ConfigurationScopeID ||
		request.Policy.Revision < 1 || request.RuntimeSHA256 == ([sha256.Size]byte{}) ||
		!publishKeyPattern.MatchString(request.IdempotencyKey) {
		return SecurityCandidateResult{}, ErrInvalidInput
	}
	request.SiteRuntimeSchema = ResolveSiteRuntimeSchema(request.SiteRuntimeSchema)
	if request.SiteRuntimeSchema != siteRuntimeV2Schema ||
		len(request.TargetNodeIDs) == 0 || len(request.TargetNodeIDs) > maxPublicationTargets {
		return SecurityCandidateResult{}, ErrInvalidInput
	}
	if compiled, err := securitypolicy.CompileRuntimeSnapshot(request.Policy, request.SiteID); err != nil || compiled.SHA256 != request.RuntimeSHA256 {
		return SecurityCandidateResult{}, ErrUnsupportedSecurityPolicy
	}
	override := securityBindingFact{
		siteID: request.SiteID, bindingID: request.BindingID, bindingRevision: request.BindingRevision,
		publicationID: request.PublicationID, runtimeSHA256: request.RuntimeSHA256, policy: request.Policy,
		detach: request.Detach,
	}
	if err := checkPackageRuntime(ctx, tx, request.ConfigurationScopeID, s.config.Clock().UTC(), &override); err != nil {
		return SecurityCandidateResult{}, err
	}
	return s.persistSiteRuntimeV2SecurityCandidateTx(ctx, tx, request, &override)
}

// replaceSecurityBinding puts a candidate's binding in place of the site's
// active binding of the same policy kind (or adds it); a detach candidate
// removes the site's binding of the kind.
func replaceSecurityBinding(securityBindings map[uuid.UUID][]securityBindingFact, override securityBindingFact) {
	bindings := securityBindings[override.siteID]
	if override.detach {
		bindings = slices.DeleteFunc(slices.Clone(bindings), func(binding securityBindingFact) bool {
			return binding.policy.Kind == override.policy.Kind
		})
		if len(bindings) == 0 {
			delete(securityBindings, override.siteID)
			return
		}
		securityBindings[override.siteID] = bindings
		return
	}
	replaced := false
	for index := range bindings {
		if bindings[index].policy.Kind == override.policy.Kind {
			bindings[index], replaced = override, true
		}
	}
	if !replaced {
		bindings = append(bindings, override)
	}
	securityBindings[override.siteID] = bindings
}

const (
	securityPolicyProvenanceSchema   = "cdnca.edge.security-policy/v1"
	securityPolicyProvenanceSchemaV2 = "cdnca.edge.security-policy/v2"
)

type securityPolicyProvenance struct {
	SchemaVersion         string    `json:"schema_version"`
	ConfigVersionID       string    `json:"config_version_id,omitempty"`
	ConfigEntrySHA256     []string  `json:"config_entry_sha256,omitempty"`
	TenantScopeID         uuid.UUID `json:"tenant_scope_id"`
	SiteID                uuid.UUID `json:"site_id"`
	BindingID             uuid.UUID `json:"binding_id"`
	BindingRevision       int64     `json:"binding_revision"`
	PublicationID         uuid.UUID `json:"publication_id"`
	PolicyID              uuid.UUID `json:"policy_id"`
	Kind                  string    `json:"kind"`
	PolicyVersion         int64     `json:"policy_version"`
	RuntimeSnapshotSHA256 string    `json:"runtime_snapshot_sha256"`
	CompiledPolicySHA256  string    `json:"compiled_policy_sha256,omitempty"`
}

func cloneSecurityCapabilities(values []*agentv1.Capability) []*agentv1.Capability {
	result := make([]*agentv1.Capability, len(values))
	for index, value := range values {
		if value != nil {
			result[index] = &agentv1.Capability{Name: value.GetName(), ApiVersion: value.GetApiVersion()}
		}
	}
	return result
}
