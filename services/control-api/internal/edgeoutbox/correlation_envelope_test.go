package edgeoutbox

import (
	"bytes"
	"crypto/sha256"
	"strings"
	"testing"

	agentv1 "github.com/cdnca/cdnca/proto/gen/go/agent/v1"
	"github.com/google/uuid"
	"google.golang.org/protobuf/proto"
)

func TestValidateClaimRejectsCorrelationEnvelopeMisbinding(t *testing.T) {
	tests := []struct {
		name   string
		mutate func(*agentv1.DeploymentCommand)
	}{
		{name: "rollout", mutate: func(value *agentv1.DeploymentCommand) { value.RolloutId = uuid.NewString() }},
		{name: "config version", mutate: func(value *agentv1.DeploymentCommand) { value.ConfigVersionId = uuid.NewString() }},
	}
	for _, test := range tests {
		t.Run(test.name, func(t *testing.T) {
			command := validClaim(t)
			decoded := new(agentv1.DeploymentCommand)
			if err := proto.Unmarshal(command.payload, decoded); err != nil {
				t.Fatal(err)
			}
			test.mutate(decoded)
			resealClaim(t, &command, decoded)
			_, failed := validateClaim(command, DefaultConfig().MaxPayloadBytes)
			if failed.code != "deployment_command_identity_mismatch" || failed.retryable {
				t.Fatalf("correlation failure = %+v", failed)
			}
			failureText := failed.safeText(DefaultConfig().MaxErrorBytes)
			for _, forbidden := range []string{
				decoded.GetRolloutId(), decoded.GetConfigVersionId(), decoded.GetEvent().GetRequestId(),
				decoded.GetEvent().GetCorrelationId(), decoded.GetEvent().GetTraceparent(), decoded.GetEvent().GetTaskId(),
			} {
				if forbidden != "" && strings.Contains(failureText, forbidden) {
					t.Fatalf("failure text leaks correlation value %q: %q", forbidden, failureText)
				}
			}
		})
	}
}

func TestValidateClaimRejectsInvalidCorrelationMetadata(t *testing.T) {
	tests := []struct {
		name   string
		mutate func(*agentv1.DeploymentCommand)
	}{
		{name: "malformed traceparent", mutate: func(value *agentv1.DeploymentCommand) {
			value.Event.Traceparent = "not-a-traceparent"
		}},
		{name: "zero trace ID", mutate: func(value *agentv1.DeploymentCommand) {
			value.Event.Traceparent = "00-00000000000000000000000000000000-2222222222222222-01"
		}},
		{name: "invalid task", mutate: func(value *agentv1.DeploymentCommand) {
			taskID := "task with spaces"
			value.Event.TaskId = &taskID
		}},
	}
	for _, test := range tests {
		t.Run(test.name, func(t *testing.T) {
			command := validClaim(t)
			decoded := new(agentv1.DeploymentCommand)
			if err := proto.Unmarshal(command.payload, decoded); err != nil {
				t.Fatal(err)
			}
			test.mutate(decoded)
			resealClaim(t, &command, decoded)
			if _, failed := validateClaim(command, DefaultConfig().MaxPayloadBytes); failed.code != "deployment_command_metadata_invalid" {
				t.Fatalf("metadata failure = %+v", failed)
			}
		})
	}
}

func TestValidateClaimAllowsLegacyEmptyCorrelationOptionals(t *testing.T) {
	command := validClaim(t)
	decoded := new(agentv1.DeploymentCommand)
	if err := proto.Unmarshal(command.payload, decoded); err != nil {
		t.Fatal(err)
	}
	decoded.Event.Traceparent = ""
	decoded.Event.TaskId = nil
	resealClaim(t, &command, decoded)
	if _, failed := validateClaim(command, DefaultConfig().MaxPayloadBytes); failed.code != "" {
		t.Fatalf("legacy optionals rejected = %+v", failed)
	}
}

func resealClaim(t *testing.T, command *claimedCommand, decoded *agentv1.DeploymentCommand) {
	t.Helper()
	payload := deterministicCommand(t, decoded)
	digest := sha256.Sum256(payload)
	command.payload = bytes.Clone(payload)
	command.payloadSHA256 = bytes.Clone(digest[:])
	command.commandBytes = bytes.Clone(payload)
	command.commandSHA256 = bytes.Clone(digest[:])
}
