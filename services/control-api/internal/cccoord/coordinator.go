package cccoord

import (
	"context"
	"errors"
	"fmt"
	"net/netip"
	"strconv"
	"time"

	"github.com/cdnca/cdnca/services/control-api/internal/securityactivation"
	"github.com/cdnca/cdnca/services/control-api/internal/securitypolicy"
	"github.com/google/uuid"
)

type actionRepository interface {
	Claim(context.Context, string, int) ([]Action, error)
	Retry(context.Context, Action, error) error
	SettlePublished(context.Context, Action, PublicationResult) error
	PendingActivations(context.Context, int) ([]Activation, error)
	SettleActivation(context.Context, Activation, ActivationState) error
}

type actionPublisher interface {
	Publish(context.Context, Action) (PublicationResult, error)
	ActivationState(context.Context, Activation) (ActivationState, error)
}

type Coordinator struct {
	repository actionRepository
	publisher  actionPublisher
	owner      string
	config     Config
}

type RunResult struct {
	Claimed          int
	Published        int
	Retryable        int
	ActivationActive int
	ActivationFailed int
}

func NewCoordinator(repository actionRepository, publisher actionPublisher, owner string, config Config) (*Coordinator, error) {
	if repository == nil || publisher == nil || !identityPattern.MatchString(owner) || config.validate() != nil {
		return nil, ErrInvalidInput
	}
	return &Coordinator{repository: repository, publisher: publisher, owner: owner, config: config}, nil
}

func (coordinator *Coordinator) RunOnce(ctx context.Context) (RunResult, error) {
	if coordinator == nil || ctx == nil {
		return RunResult{}, ErrInvalidInput
	}
	result := RunResult{}
	actions, err := coordinator.repository.Claim(ctx, coordinator.owner, coordinator.config.MaxClaims)
	if err != nil {
		return result, err
	}
	result.Claimed = len(actions)
	for _, action := range actions {
		operationCtx, cancel := context.WithTimeout(ctx, coordinator.config.OperationTimeout)
		publication, publishErr := coordinator.publisher.Publish(operationCtx, action)
		cancel()
		if publishErr != nil {
			if err := coordinator.repository.Retry(ctx, action, publishErr); err != nil {
				return result, errors.Join(publishErr, err)
			}
			result.Retryable++
			continue
		}
		if err := coordinator.repository.SettlePublished(ctx, action, publication); err != nil {
			return result, err
		}
		result.Published++
	}
	activations, err := coordinator.repository.PendingActivations(ctx, coordinator.config.MaxClaims)
	if err != nil {
		return result, err
	}
	for _, activation := range activations {
		operationCtx, cancel := context.WithTimeout(ctx, coordinator.config.OperationTimeout)
		state, stateErr := coordinator.publisher.ActivationState(operationCtx, activation)
		cancel()
		if stateErr != nil {
			continue
		}
		if state == ActivationPending {
			continue
		}
		if err := coordinator.repository.SettleActivation(ctx, activation, state); err != nil {
			return result, err
		}
		if state == ActivationActive {
			result.ActivationActive++
		} else {
			result.ActivationFailed++
		}
	}
	return result, nil
}

type policyPort interface {
	Get(context.Context, securitypolicy.Actor, uuid.UUID) (securitypolicy.Policy, error)
	Update(context.Context, securitypolicy.Actor, securitypolicy.UpdateRequest) (securitypolicy.WriteResult, error)
}

type activationPort interface {
	Status(context.Context, securitypolicy.Actor, uuid.UUID, string) (securityactivation.StatusResult, error)
	Start(context.Context, securitypolicy.Actor, securityactivation.StartInput) (securityactivation.StartResult, error)
}

type policyVersionReader interface {
	PolicyVersion(context.Context, uuid.UUID, int64) (securitypolicy.Policy, error)
}

type PolicyPublisher struct {
	policies    policyPort
	activations activationPort
	versions    policyVersionReader
	clock       func() time.Time
}

func NewPolicyPublisher(
	policies policyPort,
	activations activationPort,
	versions policyVersionReader,
	clock func() time.Time,
) (*PolicyPublisher, error) {
	if policies == nil || activations == nil || versions == nil || clock == nil {
		return nil, ErrInvalidInput
	}
	return &PolicyPublisher{policies: policies, activations: activations, versions: versions, clock: clock}, nil
}

func (publisher *PolicyPublisher) Publish(ctx context.Context, action Action) (PublicationResult, error) {
	if publisher == nil || ctx == nil || !validAction(action) {
		return PublicationResult{}, ErrInvalidInput
	}
	actor := actorForAction(action.ActorUserID, action.ActorScopeID, action.TenantScopeID)
	status, err := publisher.activations.Status(ctx, actor, action.SiteID, securitypolicy.KindCC)
	if err != nil {
		return PublicationResult{}, err
	}
	if status.Binding == nil || status.Binding.PolicyID != action.SourcePolicyID ||
		status.Binding.ActivePolicyVersion != action.ExpectedVersion {
		return PublicationResult{}, ErrGenerationConflict
	}
	head, err := publisher.policies.Get(ctx, actor, action.SourcePolicyID)
	if err != nil {
		return PublicationResult{}, err
	}
	base, err := publisher.versions.PolicyVersion(ctx, action.SourcePolicyID, action.ExpectedVersion)
	if err != nil || base.ScopeID != action.TenantScopeID || base.Kind != securitypolicy.KindCC ||
		head.ScopeID != action.TenantScopeID || head.Kind != securitypolicy.KindCC {
		return PublicationResult{}, ErrScopeMismatch
	}
	fields, err := policyFieldsForAction(base, action)
	if err != nil {
		return PublicationResult{}, err
	}
	key := "cccoord." + action.Operation + "." + action.ID.String()
	updated, err := publisher.policies.Update(ctx, actor, securitypolicy.UpdateRequest{
		ID: action.SourcePolicyID, ExpectedRevision: action.ExpectedVersion, Fields: fields,
		IdempotencyKey: key, RequestID: action.ID.String(),
	})
	if err != nil {
		return PublicationResult{}, err
	}
	if updated.Policy.Revision <= action.ExpectedVersion || updated.Policy.Kind != securitypolicy.KindCC {
		return PublicationResult{}, ErrGenerationConflict
	}
	now := publisher.clock().UTC().Truncate(time.Microsecond)
	expiresAt := action.ExpiresAt
	if !expiresAt.After(now.Add(time.Minute)) {
		expiresAt = now.Add(15 * time.Minute)
	}
	started, err := publisher.activations.Start(ctx, actor, securityactivation.StartInput{
		TenantScopeID: action.TenantScopeID, SiteID: action.SiteID, PolicyID: action.SourcePolicyID,
		PolicyVersion: updated.Policy.Revision, ExpectedBindingRevision: status.Binding.BindingRevision,
		ExpectedActivePolicyVersion: action.ExpectedVersion, TargetNodeIDs: action.TargetNodeIDs,
		CanarySize: 1, IdempotencyKey: key, RequestID: action.ID.String(),
		CorrelationID: action.StateID.String(), Traceparent: "", ExpiresAt: expiresAt,
	})
	if err != nil {
		return PublicationResult{}, err
	}
	if started.Candidate.LastBundleID == uuid.Nil || started.Candidate.ID == uuid.Nil ||
		started.Candidate.LastClaimedPolicyVersion != updated.Policy.Revision ||
		started.Candidate.ExpectedActivePolicyVersion != action.ExpectedVersion {
		return PublicationResult{}, ErrGenerationConflict
	}
	return PublicationResult{
		PublicationID: started.Candidate.LastBundleID,
		CandidateID:   started.Candidate.ID,
		PolicyVersion: updated.Policy.Revision,
	}, nil
}

func (publisher *PolicyPublisher) ActivationState(ctx context.Context, activation Activation) (ActivationState, error) {
	if publisher == nil || ctx == nil || activation.TenantScopeID == uuid.Nil || activation.SiteID == uuid.Nil ||
		activation.PolicyID == uuid.Nil || activation.PublicationID == uuid.Nil || activation.PolicyVersion < 1 ||
		activation.ActorScopeID != activation.TenantScopeID || activation.ActorUserID == uuid.Nil {
		return ActivationFailed, ErrInvalidInput
	}
	actor := actorForAction(activation.ActorUserID, activation.ActorScopeID, activation.TenantScopeID)
	status, err := publisher.activations.Status(ctx, actor, activation.SiteID, securitypolicy.KindCC)
	if err != nil {
		return ActivationPending, err
	}
	if status.Binding == nil || status.Binding.PolicyID != activation.PolicyID {
		return ActivationFailed, ErrScopeMismatch
	}
	if status.Binding.ActivePolicyVersion == activation.PolicyVersion {
		return ActivationActive, nil
	}
	if status.LatestCandidate == nil || status.LatestCandidate.LastBundleID != activation.PublicationID {
		return ActivationPending, nil
	}
	switch status.LatestCandidate.Status {
	case securityactivation.StatusFailed, securityactivation.StatusCancelled, securityactivation.StatusExpired:
		return ActivationFailed, nil
	default:
		return ActivationPending, nil
	}
}

func policyFieldsForAction(base securitypolicy.Policy, action Action) (securitypolicy.PolicyFields, error) {
	rules := append([]securitypolicy.Rule(nil), base.Rules...)
	name := generatedRuleName(action.StateID)
	index := -1
	for candidate := range rules {
		if rules[candidate].Name == name {
			if index >= 0 {
				return securitypolicy.PolicyFields{}, ErrGenerationConflict
			}
			index = candidate
		}
	}
	switch action.Operation {
	case ActionBlock:
		if index >= 0 || len(rules) >= 100 {
			return securitypolicy.PolicyFields{}, ErrCapacity
		}
		rules = append(rules, securitypolicy.Rule{
			Name: name, Priority: 1, Enabled: true,
			Conditions: []securitypolicy.Condition{
				{Field: "client_ip", Operator: "ip_in_cidr", Values: []string{action.ClientCIDR}},
				{Field: "host", Operator: "equals", Values: []string{action.Host}},
				{Field: "path", Operator: "equals", Values: []string{action.Path}},
				{Field: "method", Operator: "equals", Values: []string{action.Method}},
				{Field: "port", Operator: "number_eq", Values: []string{strconv.Itoa(int(action.ListenerPort))}},
			},
			Action: securitypolicy.ActionBlock, Flow: securitypolicy.FlowStop,
		})
	case ActionRelease:
		if index < 0 || !sameGeneratedRule(rules[index], action) {
			return securitypolicy.PolicyFields{}, ErrGenerationConflict
		}
		rules = append(rules[:index:index], rules[index+1:]...)
	default:
		return securitypolicy.PolicyFields{}, ErrInvalidInput
	}
	return securitypolicy.PolicyFields{
		Kind: base.Kind, Name: base.Name, Description: base.Description, Enabled: base.Enabled,
		DefaultAction: base.DefaultAction, Rules: rules,
	}, nil
}

func sameGeneratedRule(rule securitypolicy.Rule, action Action) bool {
	want := map[string]string{
		"client_ip\x00ip_in_cidr": action.ClientCIDR,
		"host\x00equals":          action.Host,
		"path\x00equals":          action.Path,
		"method\x00equals":        action.Method,
		"port\x00number_eq":       strconv.Itoa(int(action.ListenerPort)),
	}
	if !rule.Enabled || rule.Action != securitypolicy.ActionBlock || rule.Flow != securitypolicy.FlowStop ||
		rule.ActionConfig.RateLimit != nil || rule.ActionConfig.Challenge != nil || len(rule.Conditions) != len(want) {
		return false
	}
	for _, condition := range rule.Conditions {
		value, ok := want[condition.Field+"\x00"+condition.Operator]
		if !ok || condition.Key != "" || len(condition.Values) != 1 || condition.Values[0] != value {
			return false
		}
	}
	return true
}

func validAction(action Action) bool {
	if action.ID == uuid.Nil || action.TenantScopeID == uuid.Nil || action.SiteID == uuid.Nil ||
		action.StateID == uuid.Nil || action.SourcePolicyID == uuid.Nil || action.RuleID == uuid.Nil ||
		action.Generation < 1 || action.ExpectedVersion < 1 || action.ActorScopeID == uuid.Nil ||
		action.ActorUserID == uuid.Nil || len(action.TargetNodeIDs) < 2 || action.RequestClass != RequestClassStandard ||
		!validHost(action.Host) || !validPath(action.Path) || !validMethod(action.Method) || action.ListenerPort == 0 ||
		(action.Protocol != "http" && action.Protocol != "https") {
		return false
	}
	prefix, err := netipParsePrefix(action.ClientCIDR)
	return err == nil && prefix == action.ClientCIDR
}

func netipParsePrefix(value string) (string, error) {
	prefix, err := netip.ParsePrefix(value)
	if err != nil || prefix != prefix.Masked() || prefix.Bits() == 0 {
		return "", ErrInvalidInput
	}
	return prefix.String(), nil
}

func generatedRuleName(stateID uuid.UUID) string { return fmt.Sprintf("cccoord-%s", stateID) }

func actorForAction(userID, actorScopeID, tenantScopeID uuid.UUID) securitypolicy.Actor {
	kind := "platform"
	if actorScopeID == tenantScopeID {
		kind = "tenant"
	}
	return securitypolicy.Actor{UserID: userID, ScopeID: actorScopeID, ScopeKind: kind}
}
