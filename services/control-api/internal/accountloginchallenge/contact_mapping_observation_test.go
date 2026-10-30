package accountloginchallenge

import (
	"testing"
	"time"

	"github.com/cdnca/cdnca/services/control-api/internal/notification"
)

func TestMapSendResultPreservesProviderObservation(t *testing.T) {
	observation := notification.NewDispatchObservation(notification.ChannelSMS, "+8613800001234", time.Date(2026, 9, 28, 10, 0, 0, 0, time.UTC))
	for _, result := range []notification.SendResult{
		{Disposition: notification.SendAccepted, Observation: observation},
		{Disposition: notification.SendDelivered, Observation: observation},
		{Disposition: notification.SendUnknown, Observation: observation},
		{Failure: &notification.Failure{Class: notification.FailureTemporary, Code: "provider_unavailable"}, Observation: observation},
	} {
		if got := mapSendResult(result); got.Observation != observation {
			t.Fatalf("mapped result=%+v lost observation", got)
		}
	}
}
