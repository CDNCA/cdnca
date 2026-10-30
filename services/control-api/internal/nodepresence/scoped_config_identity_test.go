package nodepresence

import (
	"testing"
	"time"

	agentv1 "github.com/cdnca/cdnca/proto/gen/go/agent/v1"
	commonv1 "github.com/cdnca/cdnca/proto/gen/go/common/v1"
	"github.com/google/uuid"
)

func TestHeartbeatScopedConfigIdentityContract(t *testing.T) {
	now := time.Date(2026, 10, 15, 10, 0, 0, 0, time.UTC)
	nodeID := uuid.New()
	subject := "cdnca.agent.heartbeats." + nodeID.String()
	scopeA, scopeB := uuid.NewString(), uuid.NewString()
	currentA, previousA, firstB := uuid.NewString(), uuid.NewString(), uuid.NewString()
	scope := func(id, current, previous string, fill byte) *agentv1.ScopedConfigIdentity {
		entry := &agentv1.ScopedConfigIdentity{ConfigurationScopeId: id}
		if current != "" {
			entry.CurrentConfigVersionId, entry.CurrentConfigIdentity = &current, activeIdentity(current, fill)
		}
		if previous != "" {
			entry.PreviousConfigVersionId, entry.PreviousConfigIdentity = &previous, activeIdentity(previous, fill+1)
		}
		return entry
	}
	// Scope B failed its first apply, so it reports only the result.
	failedFirst := func() *agentv1.ScopedConfigIdentity {
		return &agentv1.ScopedConfigIdentity{ConfigurationScopeId: scopeB, LastApplyResult: &agentv1.ScopedApplyResult{
			DeploymentId: uuid.NewString(), Attempt: 1, ConfigVersionId: firstB,
			State: agentv1.NodeDeploymentState_NODE_DEPLOYMENT_STATE_FAILED, ErrorCode: commonv1.ErrorCode_ERROR_CODE_RATE_LIMITED,
		}}
	}
	several := validPresenceHeartbeat(1, 1, now)
	several.ActiveConfigIdentityCapability = activeIdentityCapability()
	several.ScopedConfigIdentities = []*agentv1.ScopedConfigIdentity{scope(scopeA, currentA, previousA, 1), failedFirst()}
	envelope, err := newTestValidator(t, now).Decode(subject, marshalHeartbeat(t, several))
	if err != nil {
		t.Fatalf("several scopes rejected: %v", err)
	}
	normalized, err := normalizeScopedConfigIdentities(envelope.Heartbeat)
	if err != nil || len(normalized) != 2 || normalized[1].ApplyState != "failed" || normalized[1].ApplyErrorCode != "RATE_LIMITED" ||
		normalized[0].Previous == nil || *normalized[0].PreviousID != uuid.MustParse(previousA) {
		t.Fatalf("normalized scoped identities = %+v, %v", normalized, err)
	}

	single := validPresenceHeartbeat(1, 2, now)
	single.ActiveConfigIdentityCapability = activeIdentityCapability()
	single.ScopedConfigIdentities = []*agentv1.ScopedConfigIdentity{scope(scopeA, currentA, "", 1)}
	single.CurrentConfigVersionId, single.CurrentConfigIdentity = &currentA, activeIdentity(currentA, 1)
	if _, err := newTestValidator(t, now).Decode(subject, marshalHeartbeat(t, single)); err != nil {
		t.Fatalf("single scope mirrored by legacy fields rejected: %v", err)
	}

	for name, mutate := range map[string]func(*agentv1.Heartbeat){
		"duplicate scope": func(value *agentv1.Heartbeat) {
			value.ScopedConfigIdentities[1] = scope(scopeA, firstB, "", 3)
		},
		"nil scope": func(value *agentv1.Heartbeat) {
			value.ScopedConfigIdentities[0].ConfigurationScopeId = uuid.Nil.String()
		},
		"non-canonical": func(value *agentv1.Heartbeat) {
			value.ScopedConfigIdentities[0].ConfigurationScopeId = "A" + scopeA[1:]
		},
		"empty entry":        func(value *agentv1.Heartbeat) { value.ScopedConfigIdentities[1].LastApplyResult = nil },
		"without capability": func(value *agentv1.Heartbeat) { value.ActiveConfigIdentityCapability = nil },
		"previous without current": func(value *agentv1.Heartbeat) {
			entry := value.ScopedConfigIdentities[0]
			entry.CurrentConfigVersionId, entry.CurrentConfigIdentity = nil, nil
		},
		"previous equals current": func(value *agentv1.Heartbeat) {
			entry := value.ScopedConfigIdentities[0]
			entry.PreviousConfigVersionId, entry.PreviousConfigIdentity = &currentA, activeIdentity(currentA, 5)
		},
		"failure without error": func(value *agentv1.Heartbeat) {
			value.ScopedConfigIdentities[1].LastApplyResult.ErrorCode = commonv1.ErrorCode_ERROR_CODE_UNSPECIFIED
		},
		"success with error": func(value *agentv1.Heartbeat) {
			value.ScopedConfigIdentities[1].LastApplyResult.State = agentv1.NodeDeploymentState_NODE_DEPLOYMENT_STATE_HEALTHY
		},
		"in-flight apply result": func(value *agentv1.Heartbeat) {
			value.ScopedConfigIdentities[1].LastApplyResult.State = agentv1.NodeDeploymentState_NODE_DEPLOYMENT_STATE_STARTED
		},
		"legacy fields with several scopes": func(value *agentv1.Heartbeat) {
			value.CurrentConfigVersionId, value.CurrentConfigIdentity = &currentA, activeIdentity(currentA, 1)
		},
	} {
		t.Run(name, func(t *testing.T) {
			if _, err := newTestValidator(t, now).Decode(subject, marshalHeartbeat(t, cloneHeartbeat(several, mutate))); err == nil {
				t.Fatal("validator accepted invalid scoped config identities")
			}
		})
	}
	if _, err := newTestValidator(t, now).Decode(subject, marshalHeartbeat(t, cloneHeartbeat(single, func(value *agentv1.Heartbeat) {
		value.CurrentConfigIdentity = activeIdentity(currentA, 9)
	}))); err == nil {
		t.Fatal("validator accepted legacy fields that do not mirror the single scope")
	}
}
