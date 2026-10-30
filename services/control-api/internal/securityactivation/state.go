package securityactivation

import (
	"bytes"
	"crypto/sha256"
	"encoding/json"
	"errors"
	"io"
	"net/netip"
	"sort"
	"strings"

	agentv1 "github.com/cdnca/cdnca/proto/gen/go/agent/v1"
	"github.com/cdnca/cdnca/services/control-api/internal/securitypolicy"
	"github.com/google/uuid"
	"google.golang.org/protobuf/proto"
)

func normalizeCIDRRecoveryIntent(input *CIDRRecoveryIntent) (*CIDRRecoveryIntent, error) {
	if input == nil {
		return nil, nil
	}
	if input.Operation != RecoveryOperationCIDRUnlock ||
		input.ReasonCode != RecoveryReasonFalsePositiveConfirmed ||
		len(input.CIDRs) == 0 || len(input.CIDRs) > 64 {
		return nil, ErrInvalidInput
	}
	result := &CIDRRecoveryIntent{
		Operation:  input.Operation,
		ReasonCode: input.ReasonCode,
		CIDRs:      make([]string, len(input.CIDRs)),
	}
	seen := make(map[string]struct{}, len(input.CIDRs))
	for index, raw := range input.CIDRs {
		prefix, err := netip.ParsePrefix(strings.TrimSpace(raw))
		if err != nil || prefix.Bits() == 0 || prefix.Addr().Is4In6() || prefix.Addr().IsMulticast() {
			return nil, ErrInvalidInput
		}
		canonical := prefix.Masked().String()
		if _, duplicate := seen[canonical]; duplicate {
			return nil, ErrInvalidInput
		}
		seen[canonical] = struct{}{}
		result.CIDRs[index] = canonical
	}
	sort.Strings(result.CIDRs)
	return result, nil
}

func validateCIDRRecoveryPolicy(active, candidate securitypolicy.Policy, intent *CIDRRecoveryIntent) error {
	if intent == nil || active.ID == uuid.Nil || active.ScopeID == uuid.Nil ||
		active.Kind != securitypolicy.KindACL || !active.Enabled ||
		active.DefaultAction != securitypolicy.ActionAllow || candidate.Revision != active.Revision+1 {
		return ErrConflict
	}

	expected, err := cloneCIDRRecoveryPolicy(active)
	if err != nil {
		return ErrConflict
	}
	expected.Revision = candidate.Revision
	expected.UpdatedAt = candidate.UpdatedAt
	targets := make(map[string]bool, len(intent.CIDRs))
	for _, cidr := range intent.CIDRs {
		targets[cidr] = false
	}
	rules := make([]securitypolicy.Rule, 0, len(expected.Rules))
	for _, rule := range expected.Rules {
		dropRule := false
		if rule.Enabled && rule.Action == securitypolicy.ActionBlock {
			for conditionIndex := range rule.Conditions {
				condition := &rule.Conditions[conditionIndex]
				if condition.Field != "client_ip" || condition.Operator != "ip_in_cidr" {
					continue
				}
				values := make([]string, 0, len(condition.Values))
				for _, value := range condition.Values {
					prefix, parseErr := netip.ParsePrefix(value)
					if parseErr != nil {
						return ErrConflict
					}
					canonical := prefix.Masked().String()
					if _, requested := targets[canonical]; requested {
						targets[canonical] = true
						continue
					}
					values = append(values, value)
				}
				if len(values) == 0 {
					dropRule = true
					break
				}
				condition.Values = values
			}
		}
		if !dropRule {
			rules = append(rules, rule)
		}
	}
	for _, found := range targets {
		if !found {
			return ErrConflict
		}
	}
	expected.Rules = rules
	want, err := json.Marshal(expected)
	if err != nil {
		return ErrConflict
	}
	got, err := json.Marshal(candidate)
	if err != nil || !bytes.Equal(got, want) {
		return ErrConflict
	}
	return nil
}

func cloneCIDRRecoveryPolicy(input securitypolicy.Policy) (securitypolicy.Policy, error) {
	encoded, err := json.Marshal(input)
	if err != nil {
		return securitypolicy.Policy{}, err
	}
	var result securitypolicy.Policy
	if err := json.Unmarshal(encoded, &result); err != nil {
		return securitypolicy.Policy{}, err
	}
	return result, nil
}

func cidrRecoveryAuditPayload(intent *CIDRRecoveryIntent, resultReason string) map[string]any {
	if intent == nil {
		return nil
	}
	return map[string]any{
		"operation":          intent.Operation,
		"reason_code":        intent.ReasonCode,
		"cidrs":              append([]string(nil), intent.CIDRs...),
		"result_reason_code": resultReason,
	}
}

// phaseFacts counts a phase's nodes by their latest receipt. superseded:
// nodes that ignored the candidate as an old release (they already run a
// newer revision; fix-cfgflow3). That is not a failure, but the candidate
// can no longer be promoted (promotion requires every target to run it and
// the scope's source revision to be the candidate's), so it is cancelled.
type phaseFacts struct {
	total, healthy, failed, cancelled, superseded int
}

type reconcileAction string

const (
	actionNone    reconcileAction = ""
	actionWait    reconcileAction = "wait"
	actionExpand  reconcileAction = "expand"
	actionPromote reconcileAction = "promote"
	actionRecover reconcileAction = "recover"
	actionFail    reconcileAction = "fail"
	actionCancel  reconcileAction = "cancel"
	actionExpire  reconcileAction = "expire"
)

func decideReconcile(status CandidateStatus, expired bool, canary, expand phaseFacts) reconcileAction {
	if status == StatusFailed || status == StatusCancelled || status == StatusExpired || status == StatusPromoted {
		return actionNone
	}
	if expired {
		return actionExpire
	}
	invalid := func(facts phaseFacts) bool {
		return facts.total < 0 || facts.healthy < 0 || facts.failed < 0 || facts.cancelled < 0 || facts.superseded < 0 ||
			facts.healthy+facts.failed+facts.cancelled+facts.superseded > facts.total
	}
	if invalid(canary) || invalid(expand) {
		return actionFail
	}
	if canary.failed > 0 || expand.failed > 0 {
		return actionFail
	}
	if canary.cancelled > 0 || expand.cancelled > 0 || canary.superseded > 0 || expand.superseded > 0 {
		return actionCancel
	}
	switch status {
	case StatusClaimed:
		return actionWait
	case StatusCanary:
		if canary.total > 0 && canary.healthy == canary.total {
			if expand.total == 0 {
				return actionPromote
			}
			return actionExpand
		}
		return actionWait
	case StatusExpanding:
		if canary.total > 0 && canary.healthy == canary.total &&
			expand.total > 0 && expand.healthy == expand.total {
			return actionPromote
		}
		return actionWait
	case StatusHealthy:
		return actionPromote
	default:
		return actionFail
	}
}

func validatePhaseIdentity(candidate Candidate, identity PhaseIdentity) error {
	if identity.CandidateID != candidate.ID || identity.RolloutID == uuid.Nil ||
		(identity.Phase != "canary" && identity.Phase != "expand") ||
		identity.ConfigVersionID != candidate.CandidateConfigVersionID ||
		identity.ArtifactSHA256 != candidate.CandidateArtifactSHA256 ||
		identity.TargetSnapshotSHA256 != candidate.TargetSnapshotSHA256 {
		return ErrConflict
	}
	return nil
}

// aggregateReceiptFacts counts the phase's latest receipts. nodeArtifacts is
// nil for site runtime v1 (every node runs the candidate artifact) and, for
// v2, each node's own HPKE artifact digest (migration 333).
func aggregateReceiptFacts(candidate Candidate, targetNodeIDs []uuid.UUID, receipts []ReceiptFact,
	nodeArtifacts map[uuid.UUID][sha256.Size]byte) (phaseFacts, error) {
	targets := make(map[uuid.UUID]struct{}, len(targetNodeIDs))
	for _, nodeID := range targetNodeIDs {
		if nodeID == uuid.Nil {
			return phaseFacts{}, ErrInvalidInput
		}
		if _, duplicate := targets[nodeID]; duplicate {
			return phaseFacts{}, ErrInvalidInput
		}
		targets[nodeID] = struct{}{}
	}
	latest := make(map[uuid.UUID]ReceiptFact, len(targets))
	deployments := make(map[uuid.UUID]uuid.UUID, len(targets))
	for _, fact := range receipts {
		if _, ok := targets[fact.NodeID]; !ok || fact.RolloutID == uuid.Nil || fact.DeploymentID == uuid.Nil ||
			(fact.Phase != "canary" && fact.Phase != "expand") || fact.Action != "apply" ||
			fact.Attempt < 1 || fact.TransitionSequence < 1 {
			return phaseFacts{}, ErrConflict
		}
		if deploymentID, found := deployments[fact.NodeID]; found && deploymentID != fact.DeploymentID {
			return phaseFacts{}, ErrConflict
		}
		deployments[fact.NodeID] = fact.DeploymentID
		current, found := latest[fact.NodeID]
		if found && (fact.Attempt < current.Attempt ||
			fact.Attempt == current.Attempt && fact.TransitionSequence < current.TransitionSequence) {
			continue
		}
		if found && fact.Attempt == current.Attempt && fact.TransitionSequence == current.TransitionSequence {
			if fact != current {
				return phaseFacts{}, ErrConflict
			}
			continue
		}
		latest[fact.NodeID] = fact
	}
	result := phaseFacts{total: len(targets)}
	for _, fact := range latest {
		switch fact.State {
		case "healthy":
			expected, found := candidate.CandidateArtifactSHA256, true
			if nodeArtifacts != nil {
				expected, found = nodeArtifacts[fact.NodeID]
			}
			if !found || fact.ConfigVersionID != candidate.CandidateConfigVersionID || fact.ArtifactSHA256 != expected {
				return phaseFacts{}, ErrConflict
			}
			result.healthy++
		case "failed", "reverted", "rollback_failed":
			if fact.State == "failed" && fact.Superseded {
				result.superseded++
				continue
			}
			result.failed++
		case "cancelled":
			result.cancelled++
		}
	}
	return result, nil
}

func partitionTargets(raw []uuid.UUID, canarySize int) ([]uuid.UUID, []uuid.UUID, error) {
	if canarySize < 1 || canarySize > len(raw) {
		return nil, nil, ErrInvalidInput
	}
	nodes := append([]uuid.UUID(nil), raw...)
	sort.Slice(nodes, func(left, right int) bool {
		return bytes.Compare(nodes[left][:], nodes[right][:]) < 0
	})
	for index, nodeID := range nodes {
		if nodeID == uuid.Nil || index > 0 && nodeID == nodes[index-1] {
			return nil, nil, ErrInvalidInput
		}
	}
	return append([]uuid.UUID(nil), nodes[:canarySize]...), append([]uuid.UUID(nil), nodes[canarySize:]...), nil
}

func canonicalUUIDList(values []uuid.UUID) string {
	copyOfValues := append([]uuid.UUID(nil), values...)
	sort.Slice(copyOfValues, func(left, right int) bool {
		return bytes.Compare(copyOfValues[left][:], copyOfValues[right][:]) < 0
	})
	encoded, _ := json.Marshal(copyOfValues)
	return string(encoded)
}

func canonicalTargetSnapshot(scopeID, siteID uuid.UUID, raw []uuid.UUID) ([sha256.Size]byte, []uuid.UUID, error) {
	if scopeID == uuid.Nil || siteID == uuid.Nil || len(raw) == 0 {
		return [sha256.Size]byte{}, nil, ErrInvalidInput
	}
	nodes, _, err := partitionTargets(raw, len(raw))
	if err != nil {
		return [sha256.Size]byte{}, nil, err
	}
	document := struct {
		SchemaVersion string      `json:"schema_version"`
		TenantScopeID uuid.UUID   `json:"tenant_scope_id"`
		SiteID        uuid.UUID   `json:"site_id"`
		NodeIDs       []uuid.UUID `json:"node_ids"`
	}{"cdnca.security-activation-targets/v1", scopeID, siteID, nodes}
	encoded, err := json.Marshal(document)
	if err != nil {
		return [sha256.Size]byte{}, nil, err
	}
	return sha256.Sum256(encoded), nodes, nil
}

func cloneRollbackPolicy(old securitypolicy.Policy, newRevision int64) (securitypolicy.Policy, error) {
	if old.ID == uuid.Nil || old.ScopeID == uuid.Nil || old.Revision < 1 || newRevision <= old.Revision {
		return securitypolicy.Policy{}, ErrInvalidInput
	}
	result := old
	result.Revision = newRevision
	result.Rules = make([]securitypolicy.Rule, len(old.Rules))
	for index, rule := range old.Rules {
		result.Rules[index] = rule
		result.Rules[index].Conditions = make([]securitypolicy.Condition, len(rule.Conditions))
		for conditionIndex, condition := range rule.Conditions {
			result.Rules[index].Conditions[conditionIndex] = condition
			result.Rules[index].Conditions[conditionIndex].Values = append([]string(nil), condition.Values...)
		}
		if rule.ActionConfig.RateLimit != nil {
			copyOfRateLimit := *rule.ActionConfig.RateLimit
			if copyOfRateLimit.Adaptive != nil {
				copyOfAdaptive := *copyOfRateLimit.Adaptive
				copyOfRateLimit.Adaptive = &copyOfAdaptive
			}
			result.Rules[index].ActionConfig.RateLimit = &copyOfRateLimit
		}
		if rule.ActionConfig.Challenge != nil {
			copyOfChallenge := *rule.ActionConfig.Challenge
			result.Rules[index].ActionConfig.Challenge = &copyOfChallenge
		}
	}
	return result, nil
}

func cloneCapabilities(values []*agentv1.Capability) []*agentv1.Capability {
	result := make([]*agentv1.Capability, 0, len(values))
	for _, value := range values {
		if value != nil {
			result = append(result, proto.Clone(value).(*agentv1.Capability))
		}
	}
	return result
}

type capabilityIdentity struct {
	Name       int32  `json:"name"`
	APIVersion uint32 `json:"api_version"`
}

func canonicalCapabilities(values []*agentv1.Capability) ([]*agentv1.Capability, []byte, error) {
	result := cloneCapabilities(values)
	if len(result) > 32 {
		return nil, nil, ErrInvalidInput
	}
	sort.Slice(result, func(left, right int) bool { return result[left].Name < result[right].Name })
	identities := make([]capabilityIdentity, len(result))
	for index, value := range result {
		if value.Name == agentv1.CapabilityName_CAPABILITY_NAME_UNSPECIFIED || value.ApiVersion == 0 {
			return nil, nil, ErrInvalidInput
		}
		if _, known := agentv1.CapabilityName_name[int32(value.Name)]; !known ||
			index > 0 && result[index-1].Name == value.Name {
			return nil, nil, ErrInvalidInput
		}
		identities[index] = capabilityIdentity{Name: int32(value.Name), APIVersion: value.ApiVersion}
	}
	encoded, err := json.Marshal(identities)
	if err != nil {
		return nil, nil, err
	}
	return result, encoded, nil
}

func decodeCapabilities(encoded []byte) ([]*agentv1.Capability, error) {
	var identities []capabilityIdentity
	decoder := json.NewDecoder(bytes.NewReader(encoded))
	decoder.DisallowUnknownFields()
	if err := decoder.Decode(&identities); err != nil {
		return nil, ErrConflict
	}
	if err := decoder.Decode(&struct{}{}); !errors.Is(err, io.EOF) {
		return nil, ErrConflict
	}
	values := make([]*agentv1.Capability, len(identities))
	for index, identity := range identities {
		values[index] = &agentv1.Capability{Name: agentv1.CapabilityName(identity.Name), ApiVersion: identity.APIVersion}
	}
	result, _, err := canonicalCapabilities(values)
	if err != nil {
		return nil, errors.Join(ErrConflict, err)
	}
	return result, nil
}
