package cccoord

import (
	"context"
	"errors"
	"reflect"
	"testing"
	"time"

	"github.com/cdnca/cdnca/services/control-api/internal/securityactivation"
	"github.com/cdnca/cdnca/services/control-api/internal/securitypolicy"
	"github.com/google/uuid"
)

func TestPolicyFieldsForActionAddsAndRemovesOnlyExactGeneratedRule(t *testing.T) {
	action := testAction()
	base := securitypolicy.Policy{
		ID: action.SourcePolicyID, ScopeID: action.TenantScopeID, Kind: securitypolicy.KindCC,
		Name: "site cc", Enabled: true, DefaultAction: securitypolicy.ActionAllow, Revision: 7,
		Rules: []securitypolicy.Rule{{
			ID: uuid.New(), Name: "baseline", Priority: 100, Enabled: true,
			Conditions: []securitypolicy.Condition{{Field: "path", Operator: "prefix", Values: []string{"/api"}}},
			Action:     securitypolicy.ActionRateLimit, Flow: securitypolicy.FlowStop,
			ActionConfig: securitypolicy.ActionConfig{RateLimit: &securitypolicy.RateLimitConfig{
				WindowSeconds: 1, MaxRequests: 10, Algorithm: "fixed_window", ResponseAction: "reject",
			}},
		}},
	}
	blocked, err := policyFieldsForAction(base, action)
	if err != nil || len(blocked.Rules) != 2 || !reflect.DeepEqual(blocked.Rules[0], base.Rules[0]) {
		t.Fatalf("block fields = (%+v, %v)", blocked, err)
	}
	generated := blocked.Rules[1]
	if generated.Name != generatedRuleName(action.StateID) || !sameGeneratedRule(generated, action) {
		t.Fatalf("generated rule = %+v", generated)
	}
	generated.ID = uuid.New()
	active := base
	active.Rules = append([]securitypolicy.Rule{base.Rules[0]}, generated)
	action.Operation = ActionRelease
	released, err := policyFieldsForAction(active, action)
	if err != nil || len(released.Rules) != 1 || !reflect.DeepEqual(released.Rules[0], base.Rules[0]) {
		t.Fatalf("release fields = (%+v, %v)", released, err)
	}
	tampered := active
	tampered.Rules = append([]securitypolicy.Rule(nil), active.Rules...)
	tampered.Rules[1].Conditions = append([]securitypolicy.Condition(nil), tampered.Rules[1].Conditions...)
	tampered.Rules[1].Conditions[0].Values = []string{"198.51.100.0/24"}
	if _, err := policyFieldsForAction(tampered, action); !errors.Is(err, ErrGenerationConflict) {
		t.Fatalf("tampered release error = %v", err)
	}
}

func TestPolicyPublisherRequiresExistingUniqueCCBindingBeforeActivation(t *testing.T) {
	action := testAction()
	base := securitypolicy.Policy{
		ID: action.SourcePolicyID, ScopeID: action.TenantScopeID, Kind: securitypolicy.KindCC,
		Name: "site cc", Enabled: true, DefaultAction: securitypolicy.ActionAllow, Revision: action.ExpectedVersion,
		Rules: []securitypolicy.Rule{{
			ID: uuid.New(), Name: "baseline", Priority: 100, Enabled: true,
			Conditions: []securitypolicy.Condition{{Field: "path", Operator: "prefix", Values: []string{"/"}}},
			Action:     securitypolicy.ActionRateLimit, Flow: securitypolicy.FlowStop,
			ActionConfig: securitypolicy.ActionConfig{RateLimit: &securitypolicy.RateLimitConfig{
				WindowSeconds: 1, MaxRequests: 10, Algorithm: "fixed_window", ResponseAction: "reject",
			}},
		}},
	}
	policy := &policyPortStub{head: base}
	activation := &activationPortStub{binding: securityactivation.Binding{
		ID: uuid.New(), PolicyID: action.SourcePolicyID, BindingRevision: 4,
		ActivePolicyVersion: action.ExpectedVersion, LastClaimedPolicyVersion: action.ExpectedVersion,
	}}
	reader := policyVersionStub{policy: base}
	publisher, err := NewPolicyPublisher(policy, activation, reader, func() time.Time {
		return time.Date(2026, 8, 7, 12, 0, 0, 0, time.UTC)
	})
	if err != nil {
		t.Fatal(err)
	}
	result, err := publisher.Publish(context.Background(), action)
	if err != nil || result.PolicyVersion != action.ExpectedVersion+1 || result.PublicationID == uuid.Nil ||
		policy.updates != 1 || activation.starts != 1 || activation.lastStart.PolicyID != action.SourcePolicyID ||
		activation.lastStart.ExpectedBindingRevision != 4 ||
		activation.lastStart.ExpectedActivePolicyVersion != action.ExpectedVersion ||
		!reflect.DeepEqual(activation.lastStart.TargetNodeIDs, action.TargetNodeIDs) {
		t.Fatalf("Publish() = (%+v, %v), update=%d start=%+v", result, err, policy.updates, activation.lastStart)
	}
	replayed, err := publisher.Publish(context.Background(), action)
	if err != nil || replayed.PolicyVersion != result.PolicyVersion || policy.updates != 1 || activation.starts != 2 {
		t.Fatalf("replayed Publish() = (%+v, %v), update=%d starts=%d", replayed, err, policy.updates, activation.starts)
	}
	activation.binding.PolicyID = uuid.New()
	if _, err := publisher.Publish(context.Background(), action); !errors.Is(err, ErrGenerationConflict) || policy.updates != 1 {
		t.Fatalf("wrong binding error = %v updates=%d", err, policy.updates)
	}
}

func testAction() Action {
	tenant, site, state := uuid.New(), uuid.New(), uuid.New()
	return Action{
		ID: uuid.New(), TenantScopeID: tenant, SiteID: site, StateID: state,
		SourcePolicyID: uuid.New(), RuleID: uuid.New(), ClientCIDR: "203.0.113.9/32",
		Host: "edge.example.test", Path: "/login", Method: "POST", ListenerPort: 443,
		Protocol: "https", RequestClass: RequestClassStandard, Operation: ActionBlock,
		ReasonCode: ReasonThresholdReached, Generation: 2, ExpectedVersion: 7,
		TargetNodeIDs: []uuid.UUID{uuid.New(), uuid.New()}, ExpiresAt: time.Now().Add(time.Hour),
		ActorScopeID: tenant, ActorUserID: uuid.New(),
	}
}

type policyPortStub struct {
	head        securitypolicy.Policy
	updates     int
	lastRequest *securitypolicy.UpdateRequest
	lastResult  securitypolicy.WriteResult
}

func (stub *policyPortStub) Get(context.Context, securitypolicy.Actor, uuid.UUID) (securitypolicy.Policy, error) {
	return stub.head, nil
}

func (stub *policyPortStub) Update(_ context.Context, _ securitypolicy.Actor, request securitypolicy.UpdateRequest) (securitypolicy.WriteResult, error) {
	if stub.lastRequest != nil && request.IdempotencyKey == stub.lastRequest.IdempotencyKey {
		if !reflect.DeepEqual(request, *stub.lastRequest) {
			return securitypolicy.WriteResult{}, securitypolicy.ErrIdempotencyConflict
		}
		replayed := stub.lastResult
		replayed.Replayed = true
		return replayed, nil
	}
	if request.ExpectedRevision != stub.head.Revision {
		return securitypolicy.WriteResult{}, securitypolicy.ErrRevisionConflict
	}
	stub.updates++
	updated := stub.head
	updated.Revision++
	updated.Rules = request.Fields.Rules
	stub.head = updated
	requestCopy := request
	stub.lastRequest = &requestCopy
	stub.lastResult = securitypolicy.WriteResult{Policy: updated}
	return stub.lastResult, nil
}

type policyVersionStub struct{ policy securitypolicy.Policy }

func (stub policyVersionStub) PolicyVersion(context.Context, uuid.UUID, int64) (securitypolicy.Policy, error) {
	return stub.policy, nil
}

type activationPortStub struct {
	binding   securityactivation.Binding
	starts    int
	lastStart securityactivation.StartInput
}

func (stub *activationPortStub) Status(context.Context, securitypolicy.Actor, uuid.UUID, string) (securityactivation.StatusResult, error) {
	return securityactivation.StatusResult{Binding: &stub.binding}, nil
}

func (stub *activationPortStub) Start(_ context.Context, _ securitypolicy.Actor, input securityactivation.StartInput) (securityactivation.StartResult, error) {
	stub.starts++
	stub.lastStart = input
	return securityactivation.StartResult{Candidate: securityactivation.Candidate{
		ID: uuid.New(), LastBundleID: uuid.New(), LastClaimedPolicyVersion: input.PolicyVersion,
		ExpectedActivePolicyVersion: input.ExpectedActivePolicyVersion,
	}}, nil
}
