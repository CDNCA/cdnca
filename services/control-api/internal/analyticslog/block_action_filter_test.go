package analyticslog

import (
	"net/http/httptest"
	"net/netip"
	"testing"
	"time"
)

// The security log lists block and challenge
// events (an aggregated CC challenge line included); action narrows it.
// Observed (log) and temporary_ban hits are listed too.
func TestBlockEventActionFilter(t *testing.T) {
	ip := netip.MustParseAddr("192.0.2.1")
	for _, item := range []struct {
		action, filter string
		want           bool
	}{
		{"block", "", true}, {"challenge", "", true}, {"temporary_ban", "", true}, {"log", "", true}, {"allow", "", false},
		{"block", "block", true}, {"challenge", "block", false}, {"challenge", "challenge", true}, {"block", "challenge", false},
	} {
		if got := blockEventRowMatches(blockEventRow{Action: item.action}, ip, Filter{Action: item.filter}); got != item.want {
			t.Errorf("action %q filter %q = %v", item.action, item.filter, got)
		}
	}
	from, to := time.Now().UTC().Add(-time.Hour).Format(time.RFC3339), time.Now().UTC().Format(time.RFC3339)
	route := handlerRoute{audience: AudienceTenant, kind: routeBlockEvent}
	for action, ok := range map[string]bool{"block": true, "challenge": true, "log": true, "temporary_ban": true, "allow": false} {
		request := httptest.NewRequest("GET", "/v1/analytics/logs/block-events?from="+from+"&to="+to+"&action="+action, nil)
		query, err := parseQuery(request, route)
		if (err == nil) != ok || ok && query.Filter.Action != action {
			t.Errorf("action=%s: %v %+v", action, err, query.Filter.Action)
		}
	}
	access := httptest.NewRequest("GET", "/v1/analytics/logs/access?from="+from+"&to="+to+"&action=block", nil)
	if _, err := parseQuery(access, handlerRoute{audience: AudienceTenant, kind: routeAccess}); err == nil {
		t.Error("access log accepted action")
	}
	if values := filterParameters(scope{tenantID: "t"}, Filter{Action: "challenge"}, 10); values.Get("param_has_action") != "1" ||
		values.Get("param_action") != "challenge" {
		t.Errorf("parameters %v", values)
	}
}
