package edgestatus

import (
	"bytes"
	"crypto/sha256"
	"math"
	"strings"
	"testing"
	"time"

	agentv1 "github.com/cdnca/cdnca/proto/gen/go/agent/v1"
	commonv1 "github.com/cdnca/cdnca/proto/gen/go/common/v1"
	"github.com/google/uuid"
	"google.golang.org/protobuf/encoding/protowire"
	"google.golang.org/protobuf/proto"
	"google.golang.org/protobuf/types/known/durationpb"
	"google.golang.org/protobuf/types/known/timestamppb"
)

func TestValidatorDecodesCanonicalDeploymentStatus(t *testing.T) {
	now := time.Date(2026, 7, 22, 10, 0, 0, 0, time.UTC)
	validator := testValidator(t, now)
	nodeID := uuid.New()
	status := validStatus(now, agentv1.NodeDeploymentState_NODE_DEPLOYMENT_STATE_DELIVERED, 1)
	payload := marshalStatus(t, status)

	for _, subject := range []string{
		DefaultSubjectPrefix + "." + nodeID.String(),
		DefaultSubjectPrefix + ".generic-v2." + nodeID.String() + "." + status.Event.EventId,
	} {
		envelope, err := validator.Decode(subject, payload)
		if err != nil {
			t.Fatal(err)
		}
		if envelope.NodeID != nodeID || envelope.DeploymentID.String() != status.DeploymentId ||
			envelope.ConfigID.String() != status.ConfigVersionId || envelope.EventID.String() != status.Event.EventId ||
			envelope.RequestID.String() != status.Event.RequestId {
			t.Fatalf("decoded envelope identities = %+v", envelope)
		}
		digest := sha256.Sum256(payload)
		if envelope.Digest != digest || !bytes.Equal(envelope.Payload, payload) {
			t.Fatal("validator did not preserve canonical status digest")
		}
	}
}

func TestValidatorRejectsEventSubjectIdentityConflicts(t *testing.T) {
	now := time.Date(2026, 7, 22, 10, 0, 0, 0, time.UTC)
	nodeID := uuid.NewString()
	status := validStatus(now, agentv1.NodeDeploymentState_NODE_DEPLOYMENT_STATE_DELIVERED, 1)
	payload := marshalStatus(t, status)

	for name, subject := range map[string]string{
		"wrong event":          DefaultSubjectPrefix + ".generic-v2." + nodeID + "." + uuid.NewString(),
		"noncanonical event":   DefaultSubjectPrefix + ".generic-v2." + nodeID + "." + strings.ToUpper(status.Event.EventId),
		"extra token":          DefaultSubjectPrefix + ".generic-v2." + nodeID + "." + status.Event.EventId + ".extra",
		"missing namespace":    DefaultSubjectPrefix + "." + nodeID + "." + status.Event.EventId,
		"upgrade namespace":    DefaultSubjectPrefix + ".upgrade." + nodeID,
		"upgrade v2 namespace": DefaultSubjectPrefix + ".upgrade-v2." + status.Event.EventId,
		"cache namespace":      DefaultSubjectPrefix + ".cache." + nodeID,
		"overlay namespace":    DefaultSubjectPrefix + ".acme-http01." + nodeID,
	} {
		t.Run(name, func(t *testing.T) {
			if _, err := testValidator(t, now).Decode(subject, payload); err == nil {
				t.Fatal("validator accepted subject/payload identity conflict")
			}
		})
	}
}

func TestValidatorRejectsMalformedAndUnknownDeploymentStatus(t *testing.T) {
	now := time.Date(2026, 7, 22, 10, 0, 0, 0, time.UTC)
	nodeID := uuid.New()
	subject := DefaultSubjectPrefix + "." + nodeID.String()
	tests := []struct {
		name   string
		mutate func(*agentv1.DeploymentStatus)
	}{
		{name: "missing event", mutate: func(value *agentv1.DeploymentStatus) { value.Event = nil }},
		{name: "noncanonical deployment", mutate: func(value *agentv1.DeploymentStatus) { value.DeploymentId = "BAD" }},
		{name: "noncanonical config", mutate: func(value *agentv1.DeploymentStatus) { value.ConfigVersionId = "BAD" }},
		{name: "noncanonical event", mutate: func(value *agentv1.DeploymentStatus) { value.Event.EventId = "BAD" }},
		{name: "noncanonical request", mutate: func(value *agentv1.DeploymentStatus) { value.Event.RequestId = "BAD" }},
		{name: "future time", mutate: func(value *agentv1.DeploymentStatus) {
			value.Event.OccurredTime = timestamppb.New(now.Add(6 * time.Minute))
		}},
		{name: "unknown state", mutate: func(value *agentv1.DeploymentStatus) { value.State = 99 }},
		{name: "unspecified state", mutate: func(value *agentv1.DeploymentStatus) {
			value.State = agentv1.NodeDeploymentState_NODE_DEPLOYMENT_STATE_UNSPECIFIED
		}},
		{name: "zero attempt", mutate: func(value *agentv1.DeploymentStatus) { value.Attempt = 0 }},
		{name: "large attempt", mutate: func(value *agentv1.DeploymentStatus) { value.Attempt = math.MaxUint32 }},
		{name: "zero sequence", mutate: func(value *agentv1.DeploymentStatus) { value.TransitionSequence = 0 }},
		{name: "large sequence", mutate: func(value *agentv1.DeploymentStatus) { value.TransitionSequence = math.MaxUint64 }},
		{name: "failed changed runtime", mutate: func(value *agentv1.DeploymentStatus) {
			value.State = agentv1.NodeDeploymentState_NODE_DEPLOYMENT_STATE_FAILED
			value.Error = validProtocolError()
		}},
		{name: "failed missing error", mutate: func(value *agentv1.DeploymentStatus) {
			value.State = agentv1.NodeDeploymentState_NODE_DEPLOYMENT_STATE_FAILED
			value.RunningConfigUnchanged = true
		}},
		{name: "error on success", mutate: func(value *agentv1.DeploymentStatus) { value.Error = validProtocolError() }},
		{name: "duplicate checks", mutate: func(value *agentv1.DeploymentStatus) {
			value.Checks = []*agentv1.CheckResult{{Name: "syntax"}, {Name: "syntax"}}
		}},
		{name: "negative check duration", mutate: func(value *agentv1.DeploymentStatus) {
			value.Checks = []*agentv1.CheckResult{{Name: "syntax", LatencyDuration: durationpb.New(-time.Second)}}
		}},
		{name: "bad correlation", mutate: func(value *agentv1.DeploymentStatus) { value.Event.CorrelationId = "not-a-uuid" }},
		{name: "bad task", mutate: func(value *agentv1.DeploymentStatus) { bad := " bad"; value.Event.TaskId = &bad }},
	}
	for _, test := range tests {
		t.Run(test.name, func(t *testing.T) {
			value := validStatus(now, agentv1.NodeDeploymentState_NODE_DEPLOYMENT_STATE_DELIVERED, 1)
			test.mutate(value)
			if _, err := testValidator(t, now).Decode(subject, marshalStatus(t, value)); err == nil {
				t.Fatal("validator accepted invalid deployment status")
			}
		})
	}

	valid := marshalStatus(t, validStatus(now, agentv1.NodeDeploymentState_NODE_DEPLOYMENT_STATE_DELIVERED, 1))
	unknown := protowire.AppendTag(valid, 100, protowire.VarintType)
	unknown = protowire.AppendVarint(unknown, 1)
	if _, err := testValidator(t, now).Decode(subject, unknown); err == nil {
		t.Fatal("validator accepted unknown protobuf field")
	}
	if _, err := testValidator(t, now).Decode(DefaultSubjectPrefix+".generic-v2."+nodeID.String()+".extra.extra", valid); err == nil {
		t.Fatal("validator accepted subject with extra token")
	}
	if _, err := testValidator(t, now).Decode(DefaultSubjectPrefix+"."+string(bytes.ToUpper([]byte(nodeID.String()))), valid); err == nil {
		t.Fatal("validator accepted noncanonical subject UUID")
	}
}

func TestValidatorRejectsOversizedPayload(t *testing.T) {
	config := DefaultValidatorConfig()
	config.MaxStatusBytes = 1
	validator, err := NewValidator(config)
	if err != nil {
		t.Fatal(err)
	}
	if _, err := validator.Decode(DefaultSubjectPrefix+"."+uuid.NewString(), []byte{1, 2}); err == nil {
		t.Fatal("validator accepted oversized payload")
	}
}

func testValidator(t *testing.T, now time.Time) *Validator {
	t.Helper()
	validator, err := NewValidator(DefaultValidatorConfig())
	if err != nil {
		t.Fatal(err)
	}
	validator.now = func() time.Time { return now }
	return validator
}

func validStatus(now time.Time, state agentv1.NodeDeploymentState, sequence uint64) *agentv1.DeploymentStatus {
	causationID := uuid.NewString()
	return &agentv1.DeploymentStatus{
		Event: &commonv1.EventMetadata{
			EventId: uuid.NewString(), RequestId: uuid.NewString(), OccurredTime: timestamppb.New(now),
			CausationId: &causationID, CorrelationId: uuid.NewString(),
		},
		DeploymentId: uuid.NewString(), Attempt: 1, ConfigVersionId: uuid.NewString(),
		State: state, TransitionSequence: sequence,
	}
}

func validProtocolError() *commonv1.ProtocolError {
	return &commonv1.ProtocolError{Code: commonv1.ErrorCode_ERROR_CODE_UNAVAILABLE, Message: "operation failed"}
}

func marshalStatus(t *testing.T, value *agentv1.DeploymentStatus) []byte {
	t.Helper()
	payload, err := proto.MarshalOptions{Deterministic: true}.Marshal(value)
	if err != nil {
		t.Fatal(err)
	}
	return payload
}
