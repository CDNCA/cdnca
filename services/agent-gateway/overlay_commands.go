package gateway

import (
	"context"
	"fmt"
	"time"

	agentv1 "github.com/cdnca/cdnca/proto/gen/go/agent/v1"
	commonv1 "github.com/cdnca/cdnca/proto/gen/go/common/v1"
	"github.com/google/uuid"
	"google.golang.org/protobuf/types/known/timestamppb"
)

type OverlayCommandBus interface {
	SubscribeOverlay(context.Context, string) (OverlayCommandSubscription, error)
	PublishOverlayStatus(context.Context, string, *agentv1.AcmeHTTP01OverlayStatus) error
}

type OverlayCommandSubscription interface {
	Next(context.Context) (OverlayCommandDelivery, error)
	Close() error
}

type OverlayCommandDelivery interface {
	Command() *agentv1.AcmeHTTP01OverlayCommand
	Ack(context.Context) error
	Nak(context.Context) error
}

type overlayDeploymentKey struct {
	deploymentID string
	attempt      uint32
	versionID    string
}

type pendingOverlayCommand struct {
	command    *agentv1.AcmeHTTP01OverlayCommand
	deliveries []OverlayCommandDelivery
}

type pendingOverlayCommandSet map[overlayDeploymentKey]*pendingOverlayCommand

func (p pendingOverlayCommandSet) deliveryCount() int {
	count := 0
	for _, command := range p {
		count += len(command.deliveries)
	}
	return count
}

type overlayCommandReceive struct {
	delivery OverlayCommandDelivery
	err      error
}

type sessionOverlayCommandSource struct {
	ctx          context.Context
	cancel       context.CancelFunc
	subscription OverlayCommandSubscription
	next         <-chan overlayCommandReceive
}

func newSessionOverlayCommandSource(ctx context.Context, bus OverlayCommandBus, nodeID string) (*sessionOverlayCommandSource, error) {
	sourceContext, cancel := context.WithCancel(ctx)
	subscription, err := bus.SubscribeOverlay(sourceContext, nodeID)
	if err != nil {
		cancel()
		return nil, err
	}
	return &sessionOverlayCommandSource{ctx: sourceContext, cancel: cancel, subscription: subscription}, nil
}

func (s *sessionOverlayCommandSource) arm() {
	if s.next != nil {
		return
	}
	next := make(chan overlayCommandReceive, 1)
	s.next = next
	go func() {
		delivery, err := s.subscription.Next(s.ctx)
		next <- overlayCommandReceive{delivery: delivery, err: err}
	}()
}

func stopSessionOverlayCommands(source *sessionOverlayCommandSource, pending pendingOverlayCommandSet, timeout time.Duration) {
	for key, command := range pending {
		for _, delivery := range command.deliveries {
			nakOverlayCommand(delivery, timeout)
		}
		delete(pending, key)
	}
	if source == nil {
		return
	}
	source.cancel()
	_ = source.subscription.Close()
	if source.next != nil {
		timer := time.NewTimer(timeout)
		defer timer.Stop()
		select {
		case result := <-source.next:
			nakOverlayCommand(result.delivery, timeout)
		case <-timer.C:
		}
	}
}

func nakOverlayCommand(delivery OverlayCommandDelivery, timeout time.Duration) {
	if delivery == nil {
		return
	}
	ctx, cancel := context.WithTimeout(context.Background(), timeout)
	defer cancel()
	_ = delivery.Nak(ctx)
}

func overlayCommandKey(command *agentv1.AcmeHTTP01OverlayCommand) overlayDeploymentKey {
	return overlayDeploymentKey{
		deploymentID: command.GetOverlayDeploymentId(),
		attempt:      command.GetAttempt(),
		versionID:    command.GetOverlayVersionId(),
	}
}

func overlayStatusKey(status *agentv1.AcmeHTTP01OverlayStatus) overlayDeploymentKey {
	return overlayDeploymentKey{
		deploymentID: status.GetOverlayDeploymentId(),
		attempt:      status.GetAttempt(),
		versionID:    status.GetOverlayVersionId(),
	}
}

func unsupportedACMEHTTP01OverlayStatus(command *agentv1.AcmeHTTP01OverlayCommand, now time.Time) *agentv1.AcmeHTTP01OverlayStatus {
	return refusedACMEHTTP01OverlayStatus(command, now,
		uuid.NewSHA1(uuid.NameSpaceOID, []byte("acme-http01-unsupported/"+command.OverlayDeploymentId)),
		"overlay capability is unavailable")
}

// applyRefusedACMEHTTP01OverlayStatus answers an APPLY overlay for a node
// whose session does not allow deployments (ADR-0003: only CLEANUP_ONLY is
// relayed to it). The event identity follows the command's, so a later
// attempt of the same generation is answered again.
func applyRefusedACMEHTTP01OverlayStatus(command *agentv1.AcmeHTTP01OverlayCommand, now time.Time) *agentv1.AcmeHTTP01OverlayStatus {
	return refusedACMEHTTP01OverlayStatus(command, now,
		uuid.NewSHA1(uuid.NameSpaceOID, []byte("acme-http01-apply-refused/"+command.Event.EventId)),
		"overlay apply is not authorized while deployments are not allowed")
}

func refusedACMEHTTP01OverlayStatus(command *agentv1.AcmeHTTP01OverlayCommand, now time.Time, eventID uuid.UUID, message string) *agentv1.AcmeHTTP01OverlayStatus {
	causationID := command.Event.EventId
	return &agentv1.AcmeHTTP01OverlayStatus{
		Event: &commonv1.EventMetadata{
			EventId:   eventID.String(),
			RequestId: command.Event.RequestId, OccurredTime: timestamppb.New(now.UTC()),
			Traceparent: command.Event.Traceparent, CausationId: &causationID,
			CorrelationId: command.Event.CorrelationId, TaskId: command.Event.TaskId,
		},
		OverlayDeploymentId: command.OverlayDeploymentId, Attempt: command.Attempt,
		OverlayVersionId: command.OverlayVersionId, OverlayRevision: command.OverlayRevision,
		State:              agentv1.AcmeHTTP01OverlayState_ACME_HTTP01_OVERLAY_STATE_FAILED,
		TransitionSequence: 1, ActiveOverlayUnchanged: true,
		ResultCode:        agentv1.AcmeHTTP01OverlayResultCode_ACME_HTTP01_OVERLAY_RESULT_CODE_UNSUPPORTED,
		ActivationSummary: message,
		Error: &commonv1.ProtocolError{
			Code: commonv1.ErrorCode_ERROR_CODE_FAILED_PRECONDITION, Message: message,
		},
	}
}

// ConfigureOverlayMessaging relays ACME HTTP-01 overlay commands (FX05①) to
// nodes that declare ACME_HTTP01_OVERLAY v1 and their statuses back.
func (g *Gateway) ConfigureOverlayMessaging(overlays OverlayCommandBus) error {
	if g == nil || isNilInterface(overlays) {
		return fmt.Errorf("overlay command bus is required")
	}
	if g.overlays != nil {
		return fmt.Errorf("overlay command bus is already configured")
	}
	g.overlays = overlays
	return nil
}
