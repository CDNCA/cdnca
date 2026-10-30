package gateway

import (
	"testing"

	agentv1 "github.com/cdnca/cdnca/proto/gen/go/agent/v1"
	"github.com/google/uuid"
)

func TestSITE13GatewayRoutesOnlyStrictErrorPageDescriptor(t *testing.T) {
	gateway := newCommandGateway(t, defaultFakeControl(), &fakeCommandBus{}, nil)
	valid := validDeploymentCommand()
	valid.ConfigVersionId = uuid.NewString()
	setDeploymentConfigurationScope(t, valid, uuid.NewString())
	valid.Artifacts[0].MediaType = ErrorPageArtifactMediaType
	if err := gateway.validateDeploymentCommand(valid, "", true); err != nil {
		t.Fatal(err)
	}
	for name, mutate := range map[string]func(*agentv1.ArtifactDescriptor){
		"signature": func(value *agentv1.ArtifactDescriptor) { value.Signature = value.Signature[:63] },
		"kind": func(value *agentv1.ArtifactDescriptor) {
			value.Kind = agentv1.ArtifactKind_ARTIFACT_KIND_NODE_SECRET_BUNDLE
		},
		"compression": func(value *agentv1.ArtifactDescriptor) {
			value.Compression = agentv1.ArtifactCompression_ARTIFACT_COMPRESSION_ZSTD
		},
	} {
		t.Run(name, func(t *testing.T) {
			candidate := validDeploymentCommand()
			candidate.ConfigVersionId = uuid.NewString()
			setDeploymentConfigurationScope(t, candidate, uuid.NewString())
			candidate.Artifacts[0].MediaType = ErrorPageArtifactMediaType
			mutate(candidate.Artifacts[0])
			if err := gateway.validateDeploymentCommand(candidate, "", true); err == nil {
				t.Fatal("invalid error page descriptor accepted")
			}
		})
	}
}
