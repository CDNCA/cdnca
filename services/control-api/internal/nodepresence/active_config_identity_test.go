package nodepresence

import (
	"strings"
	"testing"
	"time"

	agentv1 "github.com/cdnca/cdnca/proto/gen/go/agent/v1"
	"github.com/google/uuid"
)

func TestHeartbeatActiveConfigIdentityContract(t *testing.T) {
	now := time.Date(2026, 8, 2, 10, 0, 0, 0, time.UTC)
	nodeID := uuid.New()
	subject := "cdnca.agent.heartbeats." + nodeID.String()
	configID, previousID, loadedID := uuid.NewString(), uuid.NewString(), uuid.NewString()
	valid := validPresenceHeartbeat(1, 1, now)
	valid.CurrentConfigVersionId = &configID
	valid.PreviousConfigVersionId = &previousID
	valid.Runtime.LoadedConfigVersionId = &loadedID
	valid.ActiveConfigIdentityCapability = activeIdentityCapability()
	valid.CurrentConfigIdentity = activeIdentity(configID, 1)
	valid.PreviousConfigIdentity = activeIdentity(previousID, 2)
	valid.Runtime.LoadedConfigIdentity = activeIdentity(loadedID, 3)
	valid.ActiveDeployments = []*agentv1.ActiveDeployment{{
		DeploymentId: uuid.NewString(), Attempt: 1, ConfigVersionId: configID,
		State:                        agentv1.NodeDeploymentState_NODE_DEPLOYMENT_STATE_HEALTHY,
		ObservedActiveConfigIdentity: activeIdentity(configID, 1),
	}}
	if _, err := newTestValidator(t, now).Decode(subject, marshalHeartbeat(t, valid)); err != nil {
		t.Fatalf("valid v1 identity rejected: %v", err)
	}

	tests := []struct {
		name   string
		mutate func(*agentv1.Heartbeat)
	}{
		{name: "identity without capability", mutate: func(value *agentv1.Heartbeat) { value.ActiveConfigIdentityCapability = nil }},
		{name: "wrong capability", mutate: func(value *agentv1.Heartbeat) {
			value.ActiveConfigIdentityCapability.Name = agentv1.CapabilityName_CAPABILITY_NAME_ATOMIC_RELEASE
		}},
		{name: "wrong API version", mutate: func(value *agentv1.Heartbeat) { value.ActiveConfigIdentityCapability.ApiVersion = 2 }},
		{name: "unknown schema", mutate: func(value *agentv1.Heartbeat) {
			value.CurrentConfigIdentity.Schema = agentv1.ActiveConfigIdentitySchema_ACTIVE_CONFIG_IDENTITY_SCHEMA_UNSPECIFIED
		}},
		{name: "short digest", mutate: func(value *agentv1.Heartbeat) { value.CurrentConfigIdentity.ArtifactSha256 = make([]byte, 31) }},
		{name: "companion mismatch", mutate: func(value *agentv1.Heartbeat) { value.CurrentConfigIdentity.ConfigVersionId = uuid.NewString() }},
		{name: "missing companion", mutate: func(value *agentv1.Heartbeat) { value.CurrentConfigVersionId = nil }},
		{name: "loaded mismatch", mutate: func(value *agentv1.Heartbeat) { value.Runtime.LoadedConfigIdentity.ConfigVersionId = uuid.NewString() }},
		{name: "deployment mismatch", mutate: func(value *agentv1.Heartbeat) {
			value.ActiveDeployments[0].ObservedActiveConfigIdentity.ConfigVersionId = uuid.NewString()
		}},
	}
	for _, test := range tests {
		t.Run(test.name, func(t *testing.T) {
			candidate := cloneHeartbeat(valid, test.mutate)
			if _, err := newTestValidator(t, now).Decode(subject, marshalHeartbeat(t, candidate)); err == nil {
				t.Fatal("validator accepted invalid active config identity")
			}
		})
	}

	legacy := validPresenceHeartbeat(1, 2, now)
	legacy.CurrentConfigVersionId = &configID
	if _, err := newTestValidator(t, now).Decode(subject, marshalHeartbeat(t, legacy)); err != nil {
		t.Fatalf("legacy UUID-only heartbeat rejected: %v", err)
	}
}

func TestHeartbeatObservedActiveConfigIdentityRequiresTerminalState(t *testing.T) {
	now := time.Date(2026, 8, 2, 10, 0, 0, 0, time.UTC)
	nodeID, configID := uuid.New(), uuid.NewString()
	subject := "cdnca.agent.heartbeats." + nodeID.String()
	states := []agentv1.NodeDeploymentState{
		agentv1.NodeDeploymentState_NODE_DEPLOYMENT_STATE_QUEUED,
		agentv1.NodeDeploymentState_NODE_DEPLOYMENT_STATE_DELIVERED,
		agentv1.NodeDeploymentState_NODE_DEPLOYMENT_STATE_STAGED,
		agentv1.NodeDeploymentState_NODE_DEPLOYMENT_STATE_PRECHECKED,
		agentv1.NodeDeploymentState_NODE_DEPLOYMENT_STATE_ACTIVATED,
		agentv1.NodeDeploymentState_NODE_DEPLOYMENT_STATE_HEALTHY,
		agentv1.NodeDeploymentState_NODE_DEPLOYMENT_STATE_FAILED,
		agentv1.NodeDeploymentState_NODE_DEPLOYMENT_STATE_REVERTING,
		agentv1.NodeDeploymentState_NODE_DEPLOYMENT_STATE_REVERTED,
		agentv1.NodeDeploymentState_NODE_DEPLOYMENT_STATE_ROLLBACK_FAILED,
	}
	for _, state := range states {
		t.Run(state.String(), func(t *testing.T) {
			heartbeat := validPresenceHeartbeat(1, 1, now)
			heartbeat.ActiveConfigIdentityCapability = activeIdentityCapability()
			heartbeat.ActiveDeployments = []*agentv1.ActiveDeployment{{
				DeploymentId: uuid.NewString(), Attempt: 1, ConfigVersionId: configID, State: state,
				ObservedActiveConfigIdentity: activeIdentity(configID, 1),
			}}
			_, err := newTestValidator(t, now).Decode(subject, marshalHeartbeat(t, heartbeat))
			accepted := state == agentv1.NodeDeploymentState_NODE_DEPLOYMENT_STATE_HEALTHY ||
				state == agentv1.NodeDeploymentState_NODE_DEPLOYMENT_STATE_REVERTED
			if accepted != (err == nil) {
				t.Fatalf("observed identity state %s accepted=%t, error=%v", state, err == nil, err)
			}
		})
	}
}

func TestCanonicalUUIDPolicySupportsRFC9562UUIDv7(t *testing.T) {
	v7 := uuid.Must(uuid.NewV7())
	if _, err := canonicalUUID(v7.String()); err != nil {
		t.Fatalf("canonical UUIDv7 rejected: %v", err)
	}

	badVariant := v7
	badVariant[8] = badVariant[8]&0x3f | 0xc0
	reservedVersion := v7
	reservedVersion[6] = reservedVersion[6]&0x0f | 0x90
	invalid := []struct {
		name  string
		value string
	}{
		{name: "uppercase", value: strings.ToUpper(v7.String())},
		{name: "nil", value: uuid.Nil.String()},
		{name: "non RFC variant", value: badVariant.String()},
		{name: "reserved version", value: reservedVersion.String()},
		{name: "whitespace", value: " " + v7.String()},
		{name: "partial", value: v7.String()[:35]},
		{name: "malformed layout", value: strings.ReplaceAll(v7.String(), "-", "")},
	}
	for _, test := range invalid {
		t.Run(test.name, func(t *testing.T) {
			if _, err := canonicalUUID(test.value); err == nil {
				t.Fatalf("canonical UUID policy accepted %q", test.value)
			}
		})
	}
}

func activeIdentityCapability() *agentv1.Capability {
	return &agentv1.Capability{
		Name:       agentv1.CapabilityName_CAPABILITY_NAME_ACTIVE_CONFIG_IDENTITY,
		ApiVersion: 1,
	}
}

func activeIdentity(configID string, fill byte) *agentv1.ActiveConfigIdentity {
	return &agentv1.ActiveConfigIdentity{
		Schema:          agentv1.ActiveConfigIdentitySchema_ACTIVE_CONFIG_IDENTITY_SCHEMA_V1,
		ConfigVersionId: configID, ArtifactSha256: bytesOf(fill, 32),
	}
}

func bytesOf(value byte, count int) []byte {
	result := make([]byte, count)
	for index := range result {
		result[index] = value
	}
	return result
}
