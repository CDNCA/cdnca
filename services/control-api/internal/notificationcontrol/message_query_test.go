package notificationcontrol

import (
	"errors"
	"testing"
)

func TestNormalizeMessageQuery(t *testing.T) {
	valid := MessageQuery{
		ScopeID: "22222222-2222-4222-8222-222222222222",
		Type:    "package.monitor.traffic.triggered",
		UserID:  "33333333-3333-4333-8333-333333333333",
		Limit:   "300",
		Cursor:  "44444444-4444-4444-8444-444444444444",
	}
	query, err := normalizeMessageQuery(valid)
	if err != nil || query.Limit != 300 || query.ScopeID == nil || query.UserID == nil || query.Cursor == nil {
		t.Fatalf("normalized query=%+v err=%v", query, err)
	}
	defaults, err := normalizeMessageQuery(MessageQuery{})
	if err != nil || defaults.Limit != defaultMessageQueryLimit {
		t.Fatalf("defaults=%+v err=%v", defaults, err)
	}
	for name, candidate := range map[string]MessageQuery{
		"invalid scope":  {ScopeID: "scope"},
		"invalid type":   {Type: "Package Expiring"},
		"invalid user":   {UserID: "user"},
		"invalid limit":  {Limit: "301"},
		"invalid cursor": {Cursor: "cursor"},
		"control ID":     {PackageID: "bad\nvalue"},
	} {
		t.Run(name, func(t *testing.T) {
			if _, err := normalizeMessageQuery(candidate); !errors.Is(err, ErrInvalidInput) {
				t.Fatalf("err=%v", err)
			}
		})
	}
}
