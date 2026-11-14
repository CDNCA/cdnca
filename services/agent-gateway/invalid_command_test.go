package gateway

import (
	"context"
	"errors"
	"strings"
	"sync/atomic"
	"testing"
	"time"

	agentv1 "github.com/cdnca/cdnca/proto/gen/go/agent/v1"
	commonv1 "github.com/cdnca/cdnca/proto/gen/go/common/v1"
	"google.golang.org/grpc/codes"
	"google.golang.org/grpc/status"
)

type terminableFakeDelivery struct {
	*fakeCommandDelivery
	terms atomic.Int32
}

func (d *terminableFakeDelivery) Term(context.Context) error { d.terms.Add(1); return nil }

func wrongRecipientCommand() *agentv1.DeploymentCommand {
	command := validEncryptedDeploymentCommand(agentv1.ArtifactKind_ARTIFACT_KIND_CONFIGURATION)
	retired := "x25519:" + strings.Repeat("7", 64)
	command.Artifacts[0].RecipientKeyId = &retired
	return command
}

func serveInvalidCommandSession(t *testing.T, gateway *Gateway, stream *capturingBidiStream) (chan error, context.CancelFunc) {
	t.Helper()
	lease, err := NewMemorySessionCoordinator().Acquire(context.Background(), testNodeID)
	if err != nil {
		t.Fatal(err)
	}
	ctx, cancel := context.WithCancel(context.Background())
	stream.ctx = ctx
	done := make(chan error, 1)
	go func() {
		done <- gateway.serveSession(
			stream, make(chan connectReceive), lease, newMessageReplayWindow(defaultMessageReplayWindow), 1,
			nodeIdentity{NodeID: testNodeID, SerialNumber: "10"}, "", versionRange(1, 0),
			&commonv1.ProtocolVersion{Major: 1}, testArtifactRecipientKeyID, time.Now().Add(time.Hour), true, false,
		)
	}()
	return done, cancel
}

// A durable command whose recipient_key_id is not the session key must be
// terminated and reported as failed without ending the session, so the next
// command on the same subject still reaches the node.
func TestInvalidDurableCommandIsTerminatedAndReportedFailed(t *testing.T) {
	bus := &fakeCommandBus{subscription: newFakeCommandSubscription()}
	gateway := newCommandGateway(t, defaultFakeControl(), bus, nil)
	invalid := wrongRecipientCommand()
	badDelivery := &terminableFakeDelivery{fakeCommandDelivery: &fakeCommandDelivery{command: invalid}}
	good := validEncryptedDeploymentCommand(agentv1.ArtifactKind_ARTIFACT_KIND_CONFIGURATION)
	goodDelivery := &fakeCommandDelivery{command: good}
	bus.subscription.deliveries <- badDelivery
	bus.subscription.deliveries <- goodDelivery

	stream := &capturingBidiStream{sent: make(chan *agentv1.ConnectResponse, 2)}
	done, cancel := serveInvalidCommandSession(t, gateway, stream)
	select {
	case response := <-stream.sent:
		if response.GetDeploymentCommand().GetDeploymentId() != good.DeploymentId {
			t.Fatalf("forwarded deployment %q, want the valid command %q", response.GetDeploymentCommand().GetDeploymentId(), good.DeploymentId)
		}
	case <-time.After(2 * time.Second):
		t.Fatal("valid command after the invalid one was not forwarded")
	}
	cancel()
	select {
	case err := <-done:
		if status.Code(err) != codes.Canceled {
			t.Fatalf("serveSession() code = %v, want Canceled (session must not be dropped by the invalid command)", status.Code(err))
		}
	case <-time.After(time.Second):
		t.Fatal("serveSession() did not stop")
	}
	if badDelivery.terms.Load() != 1 || badDelivery.naks.Load() != 0 || badDelivery.acks.Load() != 0 {
		t.Fatalf("invalid delivery terms=%d naks=%d acks=%d, want 1/0/0", badDelivery.terms.Load(), badDelivery.naks.Load(), badDelivery.acks.Load())
	}
	bus.mu.Lock()
	defer bus.mu.Unlock()
	if len(bus.published) != 2 {
		t.Fatalf("published %d statuses, want delivered and failed", len(bus.published))
	}
	delivered, failed := bus.published[0], bus.published[1]
	if delivered.State != agentv1.NodeDeploymentState_NODE_DEPLOYMENT_STATE_DELIVERED || delivered.TransitionSequence != 1 ||
		failed.State != agentv1.NodeDeploymentState_NODE_DEPLOYMENT_STATE_FAILED || failed.TransitionSequence != 2 {
		t.Fatalf("statuses = %v / %v", delivered.State, failed.State)
	}
	for _, published := range bus.published {
		if published.DeploymentId != invalid.DeploymentId || published.Attempt != invalid.Attempt || published.ConfigVersionId != invalid.ConfigVersionId {
			t.Fatalf("status identity does not match the rejected command: %v", published)
		}
	}
	if !failed.RunningConfigUnchanged || failed.Error == nil || !strings.Contains(failed.Error.Message, "recipient does not match") {
		t.Fatalf("failed status error = %v", failed.Error)
	}
}

// When the failure cannot be recorded the message is not terminated: it is
// negatively acknowledged and the session ends, so nothing is lost silently.
func TestInvalidDurableCommandStatusPublishFailureKeepsMessage(t *testing.T) {
	bus := &fakeCommandBus{subscription: newFakeCommandSubscription(), publishErr: errors.New("status stream unavailable")}
	gateway := newCommandGateway(t, defaultFakeControl(), bus, nil)
	delivery := &terminableFakeDelivery{fakeCommandDelivery: &fakeCommandDelivery{command: wrongRecipientCommand()}}
	bus.subscription.deliveries <- delivery
	stream := &capturingBidiStream{sent: make(chan *agentv1.ConnectResponse, 1)}
	done, cancel := serveInvalidCommandSession(t, gateway, stream)
	defer cancel()
	select {
	case err := <-done:
		if status.Code(err) != codes.Unavailable {
			t.Fatalf("serveSession() code = %v, want Unavailable", status.Code(err))
		}
	case <-time.After(2 * time.Second):
		t.Fatal("serveSession() did not stop")
	}
	if delivery.terms.Load() != 0 || delivery.naks.Load() != 1 {
		t.Fatalf("delivery terms=%d naks=%d, want 0/1", delivery.terms.Load(), delivery.naks.Load())
	}
}

// A delivery that cannot be terminated keeps the previous behavior.
func TestInvalidDurableCommandWithoutTermKeepsLegacyRejection(t *testing.T) {
	bus := &fakeCommandBus{subscription: newFakeCommandSubscription()}
	gateway := newCommandGateway(t, defaultFakeControl(), bus, nil)
	delivery := &fakeCommandDelivery{command: wrongRecipientCommand()}
	bus.subscription.deliveries <- delivery
	stream := &capturingBidiStream{sent: make(chan *agentv1.ConnectResponse, 1)}
	done, cancel := serveInvalidCommandSession(t, gateway, stream)
	defer cancel()
	select {
	case err := <-done:
		if status.Code(err) != codes.InvalidArgument {
			t.Fatalf("serveSession() code = %v, want InvalidArgument", status.Code(err))
		}
	case <-time.After(2 * time.Second):
		t.Fatal("serveSession() did not stop")
	}
	if delivery.naks.Load() != 1 {
		t.Fatalf("naks=%d, want 1", delivery.naks.Load())
	}
}
