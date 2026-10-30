package notification

import (
	"context"
	"errors"
	"testing"

	"github.com/google/uuid"
)

type dispatchTestMemberSender struct {
	calls []DeliveryAttempt
}

func (s *dispatchTestMemberSender) Send(_ context.Context, delivery DeliveryAttempt) SendResult {
	s.calls = append(s.calls, delivery)
	return SendResult{}
}

type dispatchTestAnonymousDispatcher struct {
	result AnonymousDispatchResult
	script []AnonymousDispatchResult
	calls  []AnonymousDeliveryAttempt
}

func (d *dispatchTestAnonymousDispatcher) Dispatch(
	_ context.Context,
	delivery AnonymousDeliveryAttempt,
) AnonymousDispatchResult {
	d.calls = append(d.calls, delivery)
	if len(d.script) > 0 {
		result := d.script[0]
		d.script = d.script[1:]
		return result
	}
	return d.result
}

func TestDispatchEnqueueValidationRejectsNilReferenceAndMemberRecovery(t *testing.T) {
	request := DispatchEnqueueRequest{
		ScopeID: uuid.New(), SourceEventID: "recovery-request-1",
		AnonymousDispatchReference: uuid.New(), AuditRequestID: "audit-recovery-request-1",
	}
	if err := validateDispatchEnqueueRequest(request); err != nil {
		t.Fatalf("valid dispatch request: %v", err)
	}
	request.AnonymousDispatchReference = uuid.Nil
	if err := validateDispatchEnqueueRequest(request); !errors.Is(err, ErrInvalidDispatch) {
		t.Fatalf("nil reference error = %v", err)
	}
	member := EnqueueRequest{
		ScopeID: uuid.New(), RecipientID: uuid.New(), SourceEventID: "recovery-request-1",
		EventType: EventTypeAccountRecovery, Policy: DeliverySystemRequired,
		AuditRequestID: "audit-recovery-request-1",
	}
	if err := validateEnqueueRequest(member); !errors.Is(err, ErrInvalidEnqueue) {
		t.Fatalf("member recovery error = %v", err)
	}
}

func TestWorkerRoutesMemberAndAnonymousAttemptsToDisjointInterfaces(t *testing.T) {
	memberSender := &dispatchTestMemberSender{}
	dispatcher := &dispatchTestAnonymousDispatcher{
		result: AnonymousDispatchResult{Disposition: AnonymousDispatchNoopACK},
	}
	worker := &Worker{sender: memberSender, anonymousDispatcher: dispatcher}
	base := claimedDelivery{
		OutboxID: uuid.New(), ScopeID: uuid.New(), EventID: uuid.New(),
		EventType: "node.offline", SourceEventID: "node-event-1",
		Channel: ChannelSMS, Template: TemplateRef{ID: "test", Version: 1, Channel: ChannelSMS},
	}
	memberID := uuid.New()
	base.Recipient = memberRecipient{userID: memberID}
	if failure, noop := worker.dispatch(context.Background(), base); failure != nil || noop {
		t.Fatalf("member dispatch = (%v, %v)", failure, noop)
	}
	if len(memberSender.calls) != 1 || memberSender.calls[0].RecipientID != memberID || len(dispatcher.calls) != 0 {
		t.Fatalf("member route calls = member:%+v anonymous:%+v", memberSender.calls, dispatcher.calls)
	}

	reference := uuid.New()
	base.EventType = EventTypeAccountRecovery
	base.SourceEventID = "recovery-request-1"
	base.Recipient = anonymousRecipient{reference: reference}
	if failure, noop := worker.dispatch(context.Background(), base); failure != nil || !noop {
		t.Fatalf("anonymous dispatch = (%v, %v)", failure, noop)
	}
	if len(memberSender.calls) != 1 || len(dispatcher.calls) != 1 {
		t.Fatalf("anonymous route calls = member:%d anonymous:%d", len(memberSender.calls), len(dispatcher.calls))
	}
	got := dispatcher.calls[0]
	if got.AnonymousDispatchReference != reference || got.EventType != EventTypeAccountRecovery ||
		got.SourceEventID != base.SourceEventID {
		t.Fatalf("anonymous attempt = %+v", got)
	}
}

func TestWorkerNeverFallsBackToMemberSenderForAnonymousFailure(t *testing.T) {
	memberSender := &dispatchTestMemberSender{}
	delivery := claimedDelivery{
		OutboxID: uuid.New(), ScopeID: uuid.New(), EventID: uuid.New(),
		Recipient: anonymousRecipient{reference: uuid.New()},
		EventType: EventTypeAccountRecovery, SourceEventID: "recovery-request-2",
	}
	worker := &Worker{sender: memberSender}
	failure, noop := worker.dispatch(context.Background(), delivery)
	if failure == nil || failure.Class != FailureTemporary || failure.Code != "dispatch_unavailable" || noop {
		t.Fatalf("missing dispatcher result = (%+v, %v)", failure, noop)
	}
	if len(memberSender.calls) != 0 {
		t.Fatalf("member sender received anonymous attempt: %+v", memberSender.calls)
	}

	invalid := &dispatchTestAnonymousDispatcher{}
	worker.anonymousDispatcher = invalid
	failure, noop = worker.dispatch(context.Background(), delivery)
	if failure == nil || failure.Class != FailurePermanent || failure.Code != "dispatch_contract_invalid" || noop {
		t.Fatalf("invalid dispatcher result = (%+v, %v)", failure, noop)
	}
	if len(memberSender.calls) != 0 {
		t.Fatalf("member sender received invalid anonymous attempt: %+v", memberSender.calls)
	}
}
