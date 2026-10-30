package notification

import (
	"context"
	"strings"
	"testing"
	"time"

	"github.com/google/uuid"
)

func TestDispatchObservationOnlyKeepsRecognizedMaskedContacts(t *testing.T) {
	started := time.Date(2026, 9, 28, 10, 0, 0, 123456789, time.FixedZone("test", 8*60*60))
	for _, test := range []struct {
		channel       Channel
		contact, want string
	}{
		{ChannelEmail, "member@example.test", "m***@example.test"},
		{ChannelEmail, "m@example.test", "***@example.test"},
		{ChannelEmail, "+tag@example.test", "***@example.test"},
		{ChannelSMS, "+8613800001234", "***1234"},
		{ChannelSMS, "13800001234", "***1234"},
		{ChannelEmail, "Member <member@example.test>", ""},
		{ChannelEmail, "\"secret\"@example.test", ""},
		{ChannelEmail, "用户@example.test", ""},
		{ChannelEmail, "member@例子.测试", ""},
		{ChannelEmail, "member@example.test\x00", ""},
		{ChannelEmail, "member@localhost", ""},
		{ChannelEmail, "member@example.test\nsecret", ""},
		{ChannelSMS, "1234", ""},
		{ChannelSMS, "+86 13800001234", ""},
		{ChannelSMS, "0001234567", ""},
		{ChannelEmail, strings.Repeat("m", 321) + "@example.test", ""},
		{Channel("unknown"), "member@example.test", ""},
	} {
		t.Run(string(test.channel)+test.contact, func(t *testing.T) {
			observation := NewDispatchObservation(test.channel, test.contact, started)
			if observation == nil || observation.recipientAddressMasked != test.want ||
				!observation.providerCallStartedAt.Equal(started.Truncate(time.Microsecond)) || observation.providerCallStartedAt.Location() != time.UTC {
				t.Fatalf("observation=%+v want=%q", observation, test.want)
			}
		})
	}
	if NewDispatchObservation(ChannelEmail, "member@example.test", time.Time{}) != nil {
		t.Fatal("missing provider call time must stay unavailable")
	}
}

func TestAnonymousWorkerPreservesProviderObservationExceptNoop(t *testing.T) {
	observation := NewDispatchObservation(ChannelEmail, "member@example.test", time.Now())
	for _, result := range []AnonymousDispatchResult{
		{Disposition: AnonymousDispatchAccepted, Provider: "test", ProviderDeliveryID: "id", Observation: observation},
		{Disposition: AnonymousDispatchDelivered, Observation: observation},
		{Disposition: AnonymousDispatchUnknown, Provider: "test", Observation: observation},
		{Failure: &Failure{Class: FailureTemporary, Code: "provider_unavailable"}, Observation: observation},
		{Failure: &Failure{Class: FailurePermanent, Code: "provider_rejected"}, Observation: observation},
		{Disposition: AnonymousDispatchNoopACK, Observation: observation},
	} {
		worker := &Worker{anonymousDispatcher: &dispatchTestAnonymousDispatcher{result: result}}
		got, noop := worker.dispatchResult(context.Background(), claimedDelivery{Recipient: anonymousRecipient{reference: uuid.New()}})
		if result.Disposition == AnonymousDispatchNoopACK {
			if !noop || got.Observation != nil {
				t.Fatalf("no-op invented a provider call: %+v", got)
			}
		} else if got.Observation != observation {
			t.Fatalf("observation lost for %+v", result)
		}
	}
}
