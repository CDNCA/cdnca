package edgestatus

import (
	"testing"
	"time"

	agentv1 "github.com/cdnca/cdnca/proto/gen/go/agent/v1"
	"github.com/google/uuid"
	"google.golang.org/protobuf/proto"
)

func TestDeploymentStatusActiveConfigIdentityContract(t *testing.T) {
	now := time.Date(2026, 8, 2, 11, 0, 0, 0, time.UTC)
	nodeID := uuid.New()
	subject := DefaultSubjectPrefix + "." + nodeID.String()
	valid := validStatus(now, agentv1.NodeDeploymentState_NODE_DEPLOYMENT_STATE_HEALTHY, 5)
	valid.ActiveConfigIdentityCapability = statusIdentityCapability()
	valid.ActiveConfigIdentity = statusIdentity(valid.ConfigVersionId, 7)
	if _, err := testValidator(t, now).Decode(subject, marshalStatus(t, valid)); err != nil {
		t.Fatalf("valid terminal identity rejected: %v", err)
	}

	tests := []struct {
		name   string
		mutate func(*agentv1.DeploymentStatus)
	}{
		{name: "identity without capability", mutate: func(value *agentv1.DeploymentStatus) { value.ActiveConfigIdentityCapability = nil }},
		{name: "wrong capability", mutate: func(value *agentv1.DeploymentStatus) {
			value.ActiveConfigIdentityCapability.Name = agentv1.CapabilityName_CAPABILITY_NAME_ATOMIC_RELEASE
		}},
		{name: "wrong API version", mutate: func(value *agentv1.DeploymentStatus) { value.ActiveConfigIdentityCapability.ApiVersion = 2 }},
		{name: "wrong schema", mutate: func(value *agentv1.DeploymentStatus) { value.ActiveConfigIdentity.Schema = 0 }},
		{name: "short digest", mutate: func(value *agentv1.DeploymentStatus) { value.ActiveConfigIdentity.ArtifactSha256 = make([]byte, 31) }},
		{name: "wrong config companion", mutate: func(value *agentv1.DeploymentStatus) { value.ActiveConfigIdentity.ConfigVersionId = uuid.NewString() }},
		{name: "identity on nonterminal", mutate: func(value *agentv1.DeploymentStatus) {
			value.State = agentv1.NodeDeploymentState_NODE_DEPLOYMENT_STATE_ACTIVATED
		}},
	}
	for _, test := range tests {
		t.Run(test.name, func(t *testing.T) {
			candidate := proto.Clone(valid).(*agentv1.DeploymentStatus)
			test.mutate(candidate)
			if _, err := testValidator(t, now).Decode(subject, marshalStatus(t, candidate)); err == nil {
				t.Fatal("validator accepted invalid active config identity")
			}
		})
	}

	certificate := proto.Clone(valid).(*agentv1.DeploymentStatus)
	certificate.ActiveConfigIdentity = nil
	if _, err := testValidator(t, now).Decode(subject, marshalStatus(t, certificate)); err != nil {
		t.Fatalf("certificate terminal status without config identity rejected: %v", err)
	}

	legacy := validStatus(now, agentv1.NodeDeploymentState_NODE_DEPLOYMENT_STATE_HEALTHY, 5)
	if _, err := testValidator(t, now).Decode(subject, marshalStatus(t, legacy)); err != nil {
		t.Fatalf("legacy terminal UUID-only status rejected: %v", err)
	}
}

func statusIdentityCapability() *agentv1.Capability {
	return &agentv1.Capability{
		Name:       agentv1.CapabilityName_CAPABILITY_NAME_ACTIVE_CONFIG_IDENTITY,
		ApiVersion: 1,
	}
}

func statusIdentity(configID string, fill byte) *agentv1.ActiveConfigIdentity {
	digest := make([]byte, 32)
	for index := range digest {
		digest[index] = fill
	}
	return &agentv1.ActiveConfigIdentity{
		Schema:          agentv1.ActiveConfigIdentitySchema_ACTIVE_CONFIG_IDENTITY_SCHEMA_V1,
		ConfigVersionId: configID, ArtifactSha256: digest,
	}
}
