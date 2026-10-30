package notificationcontrol

import (
	"errors"
	"strings"
	"testing"
	"time"

	"github.com/google/uuid"
)

func TestNormalizeDeliveryHistoryQuery(t *testing.T) {
	now := time.Date(2026, 9, 28, 8, 0, 0, 123000000, time.UTC)
	id := "11111111-1111-4111-8111-abcdef123456"
	query, err := normalizeDeliveryHistoryQuery(DeliveryHistoryQuery{
		ScopeID: id, UserID: id, MessageID: id, Channel: "email", State: "retry_wait", Result: "failure",
		EventType: "announcement.published", From: "2026-09-28T15:00:00+08:00", To: now.Format(time.RFC3339Nano), Limit: "300", Cursor: id + ":2",
	})
	if err != nil || query.ScopeID.String() != id || query.UserID.String() != id || query.MessageID.String() != id ||
		query.UserDisplayID != nil || query.Limit != 300 || query.CursorOutboxID.String() != id || query.CursorSequence != 2 ||
		!query.From.Equal(time.Date(2026, 9, 28, 7, 0, 0, 0, time.UTC)) || !query.To.Equal(now) || query.Result != "failure" {
		t.Fatalf("normalized=%+v err=%v", query, err)
	}
	defaults, err := normalizeDeliveryHistoryQuery(DeliveryHistoryQuery{UserID: "9223372036854775807"})
	if err != nil || defaults.UserDisplayID == nil || *defaults.UserDisplayID != 9223372036854775807 || defaults.UserID != nil ||
		defaults.Limit != 50 || defaults.To != nil || defaults.From != nil {
		t.Fatalf("defaults=%+v err=%v", defaults, err)
	}
	for name, input := range map[string]DeliveryHistoryQuery{
		"invalid query": {Invalid: true}, "nil scope": {ScopeID: uuid.Nil.String()}, "uppercase scope": {ScopeID: strings.ToUpper(id)},
		"message": {MessageID: "bad"}, "user": {UserID: "bad"}, "zero user": {UserID: "0"}, "negative user": {UserID: "-1"},
		"user leading zero": {UserID: "01"}, "user plus": {UserID: "+1"}, "user overflow": {UserID: "9223372036854775808"},
		"channel": {Channel: "push"}, "state": {State: "success"}, "result": {Result: "unknown"}, "event type": {EventType: "bad type"},
		"from": {From: "today"}, "to": {To: "2026-09-28"}, "reversed": {From: now.Add(time.Second).Format(time.RFC3339Nano), To: now.Format(time.RFC3339Nano)},
		"equal":      {From: now.Format(time.RFC3339Nano), To: now.Format(time.RFC3339Nano)},
		"window":     {From: now.Add(-31*24*time.Hour - time.Nanosecond).Format(time.RFC3339Nano), To: now.Format(time.RFC3339Nano)},
		"limit zero": {Limit: "0"}, "limit overflow": {Limit: "301"}, "limit leading zero": {Limit: "01"},
		"cursor UUID": {Cursor: id}, "cursor scope": {Cursor: "bad:1"}, "cursor nil": {Cursor: uuid.Nil.String() + ":1"},
		"cursor sequence": {Cursor: id + ":0"}, "cursor leading zero": {Cursor: id + ":01"},
		"cursor overflow": {Cursor: id + ":2147483648"}, "cursor suffix": {Cursor: id + ":1:2"},
	} {
		t.Run(name, func(t *testing.T) {
			if _, err := normalizeDeliveryHistoryQuery(input); !errors.Is(err, ErrInvalidInput) {
				t.Fatalf("query=%+v err=%v", input, err)
			}
		})
	}
}
