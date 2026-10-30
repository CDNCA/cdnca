package certificatepublish

import (
	"context"
	"reflect"
	"testing"
	"time"

	agentv1 "github.com/cdnca/cdnca/proto/gen/go/agent/v1"
	"github.com/cdnca/cdnca/services/control-api/internal/edgedeployment"
	"github.com/google/uuid"
	"google.golang.org/protobuf/proto"
	"google.golang.org/protobuf/types/known/timestamppb"
)

type retryResultDeploymentStore30 struct {
	publicationTestDeploymentStore
	result edgedeployment.SecretReplacementResult
}

func (s *retryResultDeploymentStore30) ReplaceSecretRollout(
	context.Context,
	edgedeployment.SecretReplacementRequest,
	edgedeployment.SecretReplacementSource,
) (edgedeployment.SecretReplacementResult, error) {
	return s.result, nil
}

func TestRetryPublicationRejectsMismatchedSuccessfulResult30(t *testing.T) {
	tenantScopeID := uuid.New()
	nodeIDs := []uuid.UUID{uuid.New(), uuid.New()}
	request := RetryPublicationRequest{
		PublicationRequest: PublicationRequest{TenantScopeID: tenantScopeID, NodeIDs: nodeIDs},
		OriginalRolloutID:  uuid.New(),
		ExpectedRevision:   7,
	}
	tests := []struct {
		name   string
		mutate func(*edgedeployment.SecretReplacementResult)
	}{
		{name: "zero result", mutate: func(value *edgedeployment.SecretReplacementResult) { *value = edgedeployment.SecretReplacementResult{} }},
		{name: "original rollout", mutate: func(value *edgedeployment.SecretReplacementResult) { value.OriginalRolloutID = uuid.New() }},
		{name: "original revision", mutate: func(value *edgedeployment.SecretReplacementResult) { value.OriginalRevision++ }},
		{name: "tenant scope", mutate: func(value *edgedeployment.SecretReplacementResult) { value.Rollout.ConfigurationScopeID = uuid.New() }},
		{name: "rollout action", mutate: func(value *edgedeployment.SecretReplacementResult) {
			value.Rollout.Action = agentv1.DeploymentAction_DEPLOYMENT_ACTION_ROLLBACK
		}},
		{name: "rollout revision", mutate: func(value *edgedeployment.SecretReplacementResult) { value.Rollout.Revision = 0 }},
		{name: "rollout attempts", mutate: func(value *edgedeployment.SecretReplacementResult) { value.Rollout.MaxAttempts = 2 }},
		{name: "created time", mutate: func(value *edgedeployment.SecretReplacementResult) { value.Rollout.CreatedAt = time.Time{} }},
		{name: "queued before created", mutate: func(value *edgedeployment.SecretReplacementResult) {
			value.Rollout.QueuedAt = value.Rollout.CreatedAt.Add(-time.Second)
		}},
		{name: "node", mutate: func(value *edgedeployment.SecretReplacementResult) { value.Rollout.Deployments[0].NodeID = uuid.New() }},
		{name: "duplicate node", mutate: func(value *edgedeployment.SecretReplacementResult) {
			value.Rollout.Deployments[1].NodeID = value.Rollout.Deployments[0].NodeID
		}},
		{name: "deployment ID", mutate: func(value *edgedeployment.SecretReplacementResult) {
			value.Rollout.Deployments[0].Command.DeploymentId = uuid.NewString()
		}},
		{name: "attempt", mutate: func(value *edgedeployment.SecretReplacementResult) { value.Rollout.Deployments[0].Command.Attempt = 2 }},
		{name: "config version", mutate: func(value *edgedeployment.SecretReplacementResult) {
			value.Rollout.Deployments[0].Command.ConfigVersionId = uuid.NewString()
		}},
		{name: "artifact kind", mutate: func(value *edgedeployment.SecretReplacementResult) {
			value.Rollout.Deployments[0].Command.Artifacts[0].Kind = agentv1.ArtifactKind_ARTIFACT_KIND_CONFIGURATION
		}},
		{name: "artifact digest", mutate: func(value *edgedeployment.SecretReplacementResult) {
			value.Rollout.Deployments[0].Command.Artifacts[0].Sha256 = make([]byte, 31)
		}},
		{name: "deadline", mutate: func(value *edgedeployment.SecretReplacementResult) {
			value.Rollout.Deployments[0].Command.DeadlineTime = nil
		}},
	}
	for _, test := range tests {
		t.Run(test.name, func(t *testing.T) {
			result := validRetryPublicationResult30(request)
			test.mutate(&result)
			service := &PublicationService{deployments: &retryResultDeploymentStore30{result: result}}
			if actual, err := service.RetryPublication(t.Context(), request); err == nil ||
				!reflect.DeepEqual(actual, edgedeployment.SecretReplacementResult{}) {
				t.Fatalf("mismatched successful result = (%+v, %v)", actual, err)
			}
		})
	}
}

func TestRetryPublicationAcceptsExactlyBoundSuccessfulResult30(t *testing.T) {
	request := RetryPublicationRequest{
		PublicationRequest: PublicationRequest{TenantScopeID: uuid.New(), NodeIDs: []uuid.UUID{uuid.New(), uuid.New()}},
		OriginalRolloutID:  uuid.New(),
		ExpectedRevision:   11,
	}
	want := validRetryPublicationResult30(request)
	service := &PublicationService{deployments: &retryResultDeploymentStore30{result: want}}
	actual, err := service.RetryPublication(t.Context(), request)
	if err != nil || actual.OriginalRolloutID != want.OriginalRolloutID || actual.OriginalRevision != want.OriginalRevision ||
		actual.Rollout.ID != want.Rollout.ID || len(actual.Rollout.Deployments) != len(want.Rollout.Deployments) {
		t.Fatalf("valid successful result = (%+v, %v)", actual, err)
	}
}

func validRetryPublicationResult30(request RetryPublicationRequest) edgedeployment.SecretReplacementResult {
	createdAt := time.Date(2026, 8, 7, 10, 0, 0, 0, time.UTC)
	configID := uuid.New()
	rollout := edgedeployment.Rollout{
		ID: uuid.New(), ConfigurationScopeID: request.TenantScopeID, ConfigVersionID: configID,
		Action:    agentv1.DeploymentAction_DEPLOYMENT_ACTION_APPLY,
		CreatedAt: createdAt, QueuedAt: createdAt, Revision: 1, MaxAttempts: 1,
		Deployments: make([]edgedeployment.Deployment, len(request.NodeIDs)),
	}
	for index, nodeID := range request.NodeIDs {
		deploymentID := uuid.New()
		deployment := edgedeployment.Deployment{
			ID: deploymentID, NodeID: nodeID, Subject: "cdnca.agent.commands." + nodeID.String(),
			Command: &agentv1.DeploymentCommand{
				DeploymentId: deploymentID.String(), Attempt: 1, ConfigVersionId: configID.String(),
				Action: agentv1.DeploymentAction_DEPLOYMENT_ACTION_APPLY,
				Artifacts: []*agentv1.ArtifactDescriptor{{
					Kind: agentv1.ArtifactKind_ARTIFACT_KIND_NODE_SECRET_BUNDLE, Sha256: make([]byte, 32),
				}},
				DeadlineTime: timestamppb.New(createdAt.Add(time.Hour)),
			},
		}
		deployment.CommandBytes, _ = proto.MarshalOptions{Deterministic: true}.Marshal(deployment.Command)
		rollout.Deployments[index] = deployment
	}
	return edgedeployment.SecretReplacementResult{
		OriginalRolloutID: request.OriginalRolloutID, OriginalRevision: request.ExpectedRevision + 1,
		Rollout: rollout,
	}
}
