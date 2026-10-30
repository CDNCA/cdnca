package marketsupply

import (
	"strings"
	"testing"

	"github.com/cdnca/cdnca/libs/marketproto/secdigest"
	"github.com/google/uuid"
)

func TestDigestSlug(t *testing.T) {
	for in, want := range map[string]string{"SQLi": "sqli", "942100": "942100", "cc:rule-1": "cc:rule-1", "": "",
		"has space": "", "-lead": "", strings.Repeat("a", 65): ""} {
		if got := digestSlug(in); got != want {
			t.Errorf("digestSlug(%q) = %q, want %q", in, got, want)
		}
	}
}

func TestKeepValidLogsAndActionsDropOnlyBadRows(t *testing.T) {
	const window = 1800000000
	at := int64(window*1000 + 1)
	logs := keepValidLogs([]secdigest.Log{
		{AtMS: at, ClientIP: "203.0.113.7", Host: "www.example.com", Path: "/login", Action: "block", Detector: "SQLI"},
		{AtMS: at, ClientIP: "203.0.113.7", Host: "www.example.com", Path: "login", Action: "block"}, // not origin-form
		{AtMS: at, ClientIP: "2001:DB8::1", Host: "www.example.com", Path: "/", Action: "block"},     // not canonical
	})
	if len(logs) != 1 || logs[0].Detector != "sqli" {
		t.Fatalf("logs %+v", logs)
	}
	actions := keepValidActions([]secdigest.Action{
		{At: window, Source: "autodefense", Level: 3, Kind: "cidr", Target: "203.0.113.0/24", Reason: strings.Repeat("r", 600)},
		{At: window, Source: "autodefense", Level: 3, Kind: "cidr", Target: "203.0.113.9/24"}, // not masked
	}, window)
	if len(actions) != 1 || len(actions[0].Reason) != 512 {
		t.Fatalf("actions %+v", actions)
	}
}

func TestSubscribersAreCopies(t *testing.T) {
	s := &Service{}
	member := uuid.New()
	s.RememberSubscriber("k", member)
	s.RememberSubscriber("ignored", uuid.Nil)
	got := s.Subscribers()
	got["k"] = uuid.New()
	if again, ok := s.Subscriber("k"); !ok || again != member || len(s.Subscribers()) != 1 {
		t.Fatalf("subscriber %s %v %v", again, ok, s.Subscribers())
	}
}
