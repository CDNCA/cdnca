package edgestatus

import (
	"context"
	"crypto/sha256"
	"errors"
	"testing"
	"time"

	agentv1 "github.com/cdnca/cdnca/proto/gen/go/agent/v1"
	commonv1 "github.com/cdnca/cdnca/proto/gen/go/common/v1"
	"github.com/google/uuid"
	"google.golang.org/protobuf/proto"
	"google.golang.org/protobuf/types/known/timestamppb"
)

// Reproduction: node 85 (clock +25.5 ms off) sent STARTED tens of
// milliseconds after a command stamped by the controller; a status time before
// the command time was a binding conflict with no allowance for two hosts'
// clocks. Within CrossHostClockSkew either way it binds; far before it does not.
func TestCommandBindingAllowsCrossHostClockSkew(t *testing.T) {
	commandTime := time.Now().UTC().Truncate(time.Microsecond)
	deploymentID, configID, scopeID := uuid.New(), uuid.New(), uuid.New()
	command := &agentv1.DeploymentCommand{
		Event: &commonv1.EventMetadata{EventId: uuid.NewString(), RequestId: uuid.NewString(),
			OccurredTime: timestamppb.New(commandTime), CorrelationId: uuid.NewString()},
		DeploymentId: deploymentID.String(), Attempt: 1, ConfigVersionId: configID.String(),
		Action: agentv1.DeploymentAction_DEPLOYMENT_ACTION_APPLY, ConfigurationScopeId: proto.String(scopeID.String()),
	}
	commandBytes, err := proto.MarshalOptions{Deterministic: true}.Marshal(command)
	if err != nil {
		t.Fatal(err)
	}
	digest := sha256.Sum256(commandBytes)
	deployment := lockedDeployment{action: "apply", scopeID: scopeID, commandBytes: commandBytes, commandDigest: digest[:]}
	envelopeAt := func(at time.Time) Envelope {
		causation := command.Event.EventId
		return Envelope{DeploymentID: deploymentID, ConfigID: configID, Status: &agentv1.DeploymentStatus{
			Event: &commonv1.EventMetadata{EventId: uuid.NewString(), RequestId: command.Event.RequestId,
				OccurredTime: timestamppb.New(at), CausationId: &causation, CorrelationId: command.Event.CorrelationId},
			DeploymentId: deploymentID.String(), Attempt: 1, ConfigVersionId: configID.String(),
			State: agentv1.NodeDeploymentState_NODE_DEPLOYMENT_STATE_STARTED, TransitionSequence: 3,
			ConfigurationScopeId: proto.String(scopeID.String()),
		}}
	}
	for name, offset := range map[string]time.Duration{
		"node 30ms behind": -30 * time.Millisecond, "node 30ms ahead": 30 * time.Millisecond,
		"node 4s behind": -4 * time.Second,
	} {
		if err := verifyCommandBinding(deployment, envelopeAt(commandTime.Add(offset))); err != nil {
			t.Errorf("%s: %v, want bound", name, err)
		}
	}
	if err := verifyCommandBinding(deployment, envelopeAt(commandTime.Add(-CrossHostClockSkew-time.Millisecond))); !errors.Is(err, ErrBindingConflict) {
		t.Errorf("status beyond the skew before its command: %v, want ErrBindingConflict", err)
	}
}

type finalizingProjector struct {
	fakeProjector
	ended       bool
	finalizeErr error
	finalized   []error
}

func (p *finalizingProjector) FinalizeRefused(_ context.Context, _ Envelope, cause error) (bool, error) {
	p.finalized = append(p.finalized, cause)
	return p.ended, p.finalizeErr
}

// A permanently refused status was dropped and its deployment left
// running. The processor now ends the deployment before dropping the message;
// a transient finalize failure is redelivered a bounded number of times.
func TestProcessorFinalizesRefusedStatusBeforeTerm(t *testing.T) {
	now := time.Now().UTC()
	payload := marshalStatus(t, validStatus(now, agentv1.NodeDeploymentState_NODE_DEPLOYMENT_STATE_DELIVERED, 1))
	subject := DefaultSubjectPrefix + "." + uuid.NewString()
	for _, test := range []struct {
		name        string
		projectErr  error
		finalizeErr error
		delivered   uint64
		want        string
		finalized   int
	}{
		{name: "binding conflict ends deployment", projectErr: ErrBindingConflict, want: DispositionTerm, finalized: 1},
		{name: "invalid transition ends deployment", projectErr: ErrInvalidTransition, want: DispositionTerm, finalized: 1},
		{name: "finalize failure is redelivered", projectErr: ErrBindingConflict, finalizeErr: errors.New("db down"),
			delivered: 1, want: DispositionNak, finalized: 1},
		{name: "finalize failure gives up at the bound", projectErr: ErrBindingConflict, finalizeErr: errors.New("db down"),
			delivered: refusalFinalizeDeliveries, want: DispositionTerm, finalized: 1},
		{name: "transient projection error does not finalize", projectErr: errors.New("db down"), want: DispositionNak},
	} {
		t.Run(test.name, func(t *testing.T) {
			projector := &finalizingProjector{fakeProjector: fakeProjector{err: test.projectErr}, ended: true, finalizeErr: test.finalizeErr}
			processor, err := NewProcessor(testValidator(t, now), projector, time.Millisecond, time.Second)
			if err != nil {
				t.Fatal(err)
			}
			delivery := &fakeDelivery{subject: subject, data: payload, delivered: test.delivered}
			disposition, err := processor.Process(context.Background(), delivery)
			if err != nil || disposition != test.want || len(projector.finalized) != test.finalized {
				t.Fatalf("Process() = (%q, %v) finalized %d, want %q finalized %d", disposition, err,
					len(projector.finalized), test.want, test.finalized)
			}
			if test.finalized == 1 && !errors.Is(projector.finalized[0], test.projectErr) {
				t.Fatalf("finalized with %v, want %v", projector.finalized[0], test.projectErr)
			}
		})
	}
}

func TestRefusalReasonOnlyForStrandingErrors(t *testing.T) {
	for err, want := range map[error]string{ErrBindingConflict: RefusalBindingConflict, ErrInvalidTransition: RefusalInvalidTransition} {
		if got, ok := refusalReason(err); !ok || got != want {
			t.Errorf("refusalReason(%v) = %q, %v", err, got, ok)
		}
	}
	for _, err := range []error{ErrInvalidStatus, ErrPayloadConflict, ErrDeploymentMissing, ErrProjectionConflict} {
		if _, ok := refusalReason(err); ok {
			t.Errorf("refusalReason(%v) ends the deployment", err)
		}
	}
	for _, state := range []string{"activated", "reverting", "healthy", "failed"} {
		if refusalEndsDeployment(state) {
			t.Errorf("refusal ends a %s deployment", state)
		}
	}
}
