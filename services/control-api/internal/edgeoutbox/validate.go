package edgeoutbox

import (
	"bytes"
	"crypto/sha256"
	"math"
	"regexp"
	"strings"

	agentv1 "github.com/cdnca/cdnca/proto/gen/go/agent/v1"
	"github.com/google/uuid"
	"google.golang.org/protobuf/proto"
)

var taskIDPattern = regexp.MustCompile(`^[A-Za-z0-9][A-Za-z0-9._:-]{0,127}$`)

func validateClaim(command claimedCommand, maxPayloadBytes int) (string, failure) {
	if command.outboxID == uuid.Nil || command.deploymentID == uuid.Nil || command.nodeID == uuid.Nil ||
		command.commandEventID == uuid.Nil || command.deploymentNodeID == uuid.Nil ||
		command.rolloutID == uuid.Nil || command.configVersionID == uuid.Nil ||
		command.deploymentAttempt <= 0 || command.deploymentAttempt > math.MaxUint32 {
		return "", integrityFailure("database_identity_invalid")
	}
	expectedSubject := CommandSubjectPrefix + "." + command.nodeID.String()
	if command.subject != expectedSubject || command.deploymentNodeID != command.nodeID {
		return "", integrityFailure("subject_identity_mismatch")
	}
	if len(command.payload) == 0 || len(command.payload) > maxPayloadBytes ||
		len(command.payloadSHA256) != sha256.Size || len(command.commandSHA256) != sha256.Size {
		return "", integrityFailure("payload_bounds_invalid")
	}
	payloadDigest := sha256.Sum256(command.payload)
	storedCommandDigest := sha256.Sum256(command.commandBytes)
	if !bytes.Equal(payloadDigest[:], command.payloadSHA256) ||
		!bytes.Equal(command.payloadSHA256, command.commandSHA256) ||
		!bytes.Equal(storedCommandDigest[:], command.commandSHA256) ||
		!bytes.Equal(command.payload, command.commandBytes) {
		return "", integrityFailure("payload_digest_mismatch")
	}
	decoded := new(agentv1.DeploymentCommand)
	if err := (proto.UnmarshalOptions{DiscardUnknown: false}).Unmarshal(command.payload, decoded); err != nil {
		return "", integrityFailure("deployment_command_invalid")
	}
	deterministic, err := proto.MarshalOptions{Deterministic: true}.Marshal(decoded)
	if err != nil || !bytes.Equal(deterministic, command.payload) {
		return "", integrityFailure("deployment_command_not_deterministic")
	}
	if decoded.Event == nil || decoded.Event.EventId != command.commandEventID.String() ||
		decoded.DeploymentId != command.deploymentID.String() ||
		decoded.Attempt != uint32(command.deploymentAttempt) ||
		decoded.RolloutId != command.rolloutID.String() ||
		decoded.ConfigVersionId != command.configVersionID.String() ||
		!canonicalUUID(decoded.Event.RequestId) || !canonicalUUID(decoded.Event.CorrelationId) {
		return "", integrityFailure("deployment_command_identity_mismatch")
	}
	if decoded.Event.OccurredTime == nil || decoded.Event.OccurredTime.CheckValid() != nil ||
		decoded.DeadlineTime == nil || decoded.DeadlineTime.CheckValid() != nil ||
		decoded.Action == agentv1.DeploymentAction_DEPLOYMENT_ACTION_UNSPECIFIED ||
		!validTraceparent(decoded.Event.Traceparent) ||
		(decoded.Event.TaskId != nil && !taskIDPattern.MatchString(decoded.Event.GetTaskId())) {
		return "", integrityFailure("deployment_command_metadata_invalid")
	}
	if decoded.PreviousConfigVersionId != nil && !canonicalUUID(decoded.GetPreviousConfigVersionId()) {
		return "", integrityFailure("deployment_command_identity_mismatch")
	}
	return command.commandEventID.String(), failure{}
}

func canonicalUUID(value string) bool {
	parsed, err := uuid.Parse(value)
	return err == nil && parsed.String() == value
}

func validTraceparent(value string) bool {
	if value == "" {
		return true
	}
	if len(value) != 55 || strings.TrimSpace(value) != value ||
		value[:3] != "00-" || value[35] != '-' || value[52] != '-' {
		return false
	}
	traceID, spanID, flags := value[3:35], value[36:52], value[53:55]
	return lowerHex(traceID) && lowerHex(spanID) && lowerHex(flags) &&
		traceID != strings.Repeat("0", 32) && spanID != strings.Repeat("0", 16)
}

func lowerHex(value string) bool {
	for _, character := range value {
		if character < '0' || character > '9' {
			if character < 'a' || character > 'f' {
				return false
			}
		}
	}
	return true
}

func integrityFailure(code string) failure {
	return failure{class: "integrity", code: code, retryable: false}
}
