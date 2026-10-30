package notificationcontrol

import (
	"testing"

	"github.com/google/uuid"
)

func TestNormalizeDeliveryLogQuery(t *testing.T) {
	scopeID := uuid.New()
	cursor := uuid.New()
	query, err := normalizeDeliveryLogQuery(DeliveryLogQuery{
		ScopeID: scopeID.String(), Channel: ChannelEmail, State: "retry_wait", Limit: "25", Cursor: cursor.String(),
	})
	if err != nil {
		t.Fatal(err)
	}
	if query.ScopeID == nil || *query.ScopeID != scopeID || query.Cursor == nil || *query.Cursor != cursor ||
		query.Channel != ChannelEmail || query.State != "retry_wait" || query.Limit != 25 {
		t.Fatalf("normalized query=%+v", query)
	}

	defaults, err := normalizeDeliveryLogQuery(DeliveryLogQuery{})
	if err != nil || defaults.Limit != 50 || defaults.ScopeID != nil || defaults.Cursor != nil {
		t.Fatalf("defaults=%+v err=%v", defaults, err)
	}

	for name, value := range map[string]DeliveryLogQuery{
		"scope":   {ScopeID: "not-a-uuid"},
		"channel": {Channel: "push"},
		"state":   {State: "private-provider-state"},
		"limit":   {Limit: "0"},
		"large":   {Limit: "101"},
		"cursor":  {Cursor: "not-a-uuid"},
	} {
		if _, err := normalizeDeliveryLogQuery(value); err == nil {
			t.Fatalf("%s query unexpectedly valid", name)
		}
	}
}
