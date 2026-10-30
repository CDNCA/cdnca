package analyticslog

import (
	"context"
	"errors"
	"strings"
	"testing"
	"time"

	"github.com/cdnca/cdnca/services/control-api/internal/edgedeployment"
	"github.com/cdnca/cdnca/services/control-api/internal/securityactivation"
	"github.com/cdnca/cdnca/services/control-api/internal/securitypolicy"
	"github.com/google/uuid"
)

func TestBlockStatePaginationContractIncludesTotalAndPromotionTime(t *testing.T) {
	if !validBlockListRequest(BlockListRequest{Limit: 50, Offset: MaxBlockOffset}) ||
		validBlockListRequest(BlockListRequest{Limit: 50, Offset: MaxBlockOffset + 1}) {
		t.Fatal("block offset bounds are not enforced")
	}
	for _, query := range []string{"SELECT audit.id", "candidate.promoted_at", "ORDER BY audit.occurred_at DESC"} {
		if !strings.Contains(blockHistoryQuery, query) {
			t.Fatalf("block history query missing %q", query)
		}
	}
	for _, query := range []string{"jsonb_array_length", "WHEN $4<>'' THEN 1"} {
		if !strings.Contains(blockHistoryCountQuery, query) {
			t.Fatalf("block history count query missing %q", query)
		}
	}
}

type blockStateStoreStub struct {
	preparation BlockUnlockPreparation
	err         error
}

func (store blockStateStoreStub) ListCurrent(context.Context, uuid.UUID, BlockListRequest) (CurrentBlockPage, error) {
	return CurrentBlockPage{}, nil
}

func (store blockStateStoreStub) ListHistory(context.Context, uuid.UUID, BlockListRequest) (BlockHistoryPage, error) {
	return BlockHistoryPage{}, nil
}

func (store blockStateStoreStub) CountCurrent(context.Context, uuid.UUID) (SiteBlacklistCountPage, error) {
	return SiteBlacklistCountPage{}, nil
}

func (store blockStateStoreStub) PrepareUnlock(context.Context, uuid.UUID, uuid.UUID) (BlockUnlockPreparation, error) {
	return store.preparation, store.err
}

type policyUpdaterStub struct {
	request securitypolicy.UpdateRequest
	result  securitypolicy.WriteResult
	err     error
}

func (stub *policyUpdaterStub) Update(_ context.Context, _ securitypolicy.Actor, request securitypolicy.UpdateRequest) (securitypolicy.WriteResult, error) {
	stub.request = request
	return stub.result, stub.err
}

type activationStarterStub struct {
	input  securityactivation.StartInput
	result securityactivation.StartResult
	err    error
}

type typedNilBlockActivation struct{}

func (*typedNilBlockActivation) Start(context.Context, securitypolicy.Actor,
	securityactivation.StartInput,
) (securityactivation.StartResult, error) {
	return securityactivation.StartResult{}, nil
}

func (stub *activationStarterStub) Start(_ context.Context, _ securitypolicy.Actor, input securityactivation.StartInput) (securityactivation.StartResult, error) {
	stub.input = input
	return stub.result, stub.err
}

func TestBlockUnlockBuildsExactSuccessorAndRealActivation(t *testing.T) {
	now := time.Date(2026, 8, 7, 12, 0, 0, 0, time.UTC)
	tenantScopeID, actorScopeID, userID := uuid.New(), uuid.New(), uuid.New()
	siteID, policyID, ruleA, ruleB := uuid.New(), uuid.New(), uuid.New(), uuid.New()
	nodeA, nodeB := uuid.New(), uuid.New()
	blockID := blockIdentity(siteID, policyID, "192.0.2.10/32")
	policy := securitypolicy.Policy{
		ID: policyID, ScopeID: tenantScopeID, Kind: securitypolicy.KindACL,
		Name: "site ACL", Enabled: true, DefaultAction: securitypolicy.ActionAllow, Revision: 7,
		Rules: []securitypolicy.Rule{
			{ID: ruleA, Name: "false positive", Priority: 10, Enabled: true, Action: securitypolicy.ActionBlock,
				Flow: securitypolicy.FlowStop, Conditions: []securitypolicy.Condition{{Field: "client_ip", Operator: "ip_in_cidr", Values: []string{"192.0.2.10/32"}}}},
			{ID: ruleB, Name: "preserved", Priority: 20, Enabled: true, Action: securitypolicy.ActionBlock,
				Flow: securitypolicy.FlowStop, Conditions: []securitypolicy.Condition{{Field: "client_ip", Operator: "ip_in_cidr", Values: []string{"198.51.100.0/24"}}}},
		},
	}
	updater := &policyUpdaterStub{result: securitypolicy.WriteResult{Policy: securitypolicy.Policy{ID: policyID, Revision: 8}}}
	starter := &activationStarterStub{result: securityactivation.StartResult{
		Candidate:  securityactivation.Candidate{ID: uuid.New(), Status: securityactivation.StatusClaimed},
		ReasonCode: securityactivation.RecoveryResultClaimed,
	}}
	service, err := NewBlockStateService(blockStateStoreStub{preparation: BlockUnlockPreparation{
		Block:  CurrentBlock{ID: blockID, SiteID: siteID, PolicyID: policyID, CIDR: "192.0.2.10/32"},
		Policy: policy, BindingRevision: 4, ActivePolicyVersion: 7, LatestPolicyVersion: 7,
		TargetNodeIDs: []uuid.UUID{nodeA, nodeB},
	}}, updater, starter, func() time.Time { return now })
	if err != nil {
		t.Fatal(err)
	}
	result, err := service.Unlock(context.Background(), BlockActor{
		UserID: userID, ActorScopeID: actorScopeID, TargetScopeID: tenantScopeID, ScopeKind: "platform",
	}, blockID, securityactivation.RecoveryReasonFalsePositiveConfirmed, "unlock-key", "request-1")
	if err != nil {
		t.Fatalf("Unlock: %v", err)
	}
	if result.CandidateID != starter.result.Candidate.ID || result.Progress != string(securityactivation.StatusClaimed) {
		t.Fatalf("unlock result = %+v", result)
	}
	if updater.request.ExpectedRevision != 7 || len(updater.request.Fields.Rules) != 1 ||
		updater.request.Fields.Rules[0].ID != ruleB {
		t.Fatalf("policy successor = %+v", updater.request)
	}
	if starter.input.PolicyVersion != 8 || starter.input.ExpectedActivePolicyVersion != 7 ||
		starter.input.ExpectedBindingRevision != 4 || len(starter.input.TargetNodeIDs) != 2 ||
		starter.input.Recovery == nil || starter.input.Recovery.ReasonCode != securityactivation.RecoveryReasonFalsePositiveConfirmed ||
		len(starter.input.Recovery.CIDRs) != 1 || starter.input.Recovery.CIDRs[0] != "192.0.2.10/32" {
		t.Fatalf("activation input = %+v", starter.input)
	}
}

func TestBlockUnlockFailsClosedBeforePolicyWrite(t *testing.T) {
	blockID := uuid.New()
	for _, test := range []struct {
		name string
		prep BlockUnlockPreparation
		err  error
	}{
		{name: "unrelated prepared revision", prep: BlockUnlockPreparation{Block: CurrentBlock{ID: blockID}, ActivePolicyVersion: 7, LatestPolicyVersion: 8}},
		{name: "store unavailable", err: ErrStorageUnavailable},
	} {
		t.Run(test.name, func(t *testing.T) {
			updater := new(policyUpdaterStub)
			service, err := NewBlockStateService(blockStateStoreStub{preparation: test.prep, err: test.err}, updater,
				new(activationStarterStub), time.Now)
			if err != nil {
				t.Fatal(err)
			}
			_, got := service.Unlock(context.Background(), BlockActor{
				UserID: uuid.New(), ActorScopeID: uuid.New(), TargetScopeID: uuid.New(), ScopeKind: "tenant",
			}, blockID, securityactivation.RecoveryReasonFalsePositiveConfirmed, "unlock-key", "request-1")
			if test.err != nil && !errors.Is(got, test.err) || test.err == nil && !errors.Is(got, ErrBlockStateConflict) {
				t.Fatalf("Unlock error = %v", got)
			}
			if updater.request.ID != uuid.Nil {
				t.Fatal("policy write happened before the fail-closed fence")
			}
		})
	}
}

func TestBlockBindingUnlockableUsesOnlyOpenActivationAsFence(t *testing.T) {
	candidateID := uuid.New()
	status := func(value securityactivation.CandidateStatus) *string {
		encoded := string(value)
		return &encoded
	}
	for _, test := range []struct {
		name string
		row  currentBindingRow
		want bool
	}{
		{name: "no candidate", row: currentBindingRow{activeVersion: 7, latestVersion: 7}, want: true},
		{name: "claimed candidate", row: currentBindingRow{activeVersion: 7, latestVersion: 7, candidateID: &candidateID, candidateStatus: status(securityactivation.StatusClaimed)}},
		{name: "healthy candidate", row: currentBindingRow{activeVersion: 7, latestVersion: 7, candidateID: &candidateID, candidateStatus: status(securityactivation.StatusHealthy)}},
		{name: "promoted candidate", row: currentBindingRow{activeVersion: 7, latestVersion: 7, candidateID: &candidateID, candidateStatus: status(securityactivation.StatusPromoted)}, want: true},
		{name: "failed newer policy", row: currentBindingRow{activeVersion: 7, latestVersion: 8, candidateID: &candidateID, candidateStatus: status(securityactivation.StatusFailed)}},
	} {
		t.Run(test.name, func(t *testing.T) {
			if got := blockBindingUnlockable(test.row); got != test.want {
				t.Fatalf("blockBindingUnlockable()=%v want=%v row=%+v", got, test.want, test.row)
			}
		})
	}
}

func TestBlockStateServiceRejectsTypedNilDependencies(t *testing.T) {
	var activation *typedNilBlockActivation
	if _, err := NewBlockStateService(new(blockHandlerStoreStub), new(policyUpdaterStub), activation, time.Now); !errors.Is(err, ErrInvalidConfiguration) {
		t.Fatalf("typed nil activation error=%v", err)
	}
}

// fix-cfgflow3: nodes that ignored an unlock as an old release are counted
// apart (superseded_nodes), not as failed, in both block views.
func TestBlockEdgeProgressCountsIgnoredOldReleaseApart(t *testing.T) {
	for _, want := range []string{
		"AND NOT " + edgedeployment.SupersededDeploymentSQL + ")::int AS failed_nodes",
		"count(*) FILTER (WHERE " + edgedeployment.SupersededDeploymentSQL + ")::int AS superseded_nodes",
	} {
		if !strings.Contains(blockEdgeProgressSQL, want) {
			t.Fatalf("block edge progress query missing %q", want)
		}
	}
	for name, query := range map[string]string{"history": blockHistoryQuery, "current": currentBindingsQuery} {
		if !strings.Contains(query, blockEdgeProgressSQL) || !strings.Contains(query, "COALESCE(progress.superseded_nodes,0)") {
			t.Fatalf("%s query does not use the shared edge progress", name)
		}
	}
}
