package marketsubscribe

import (
	"encoding/json"
	"errors"
	"strings"
	"testing"
	"time"

	"github.com/cdnca/cdnca/libs/marketproto/siteconf"
)

func nodeStatusReply(t *testing.T, nodes any) siteconf.Reply {
	t.Helper()
	raw, err := json.Marshal(map[string]any{"enabled": true, "nodes": nodes})
	if err != nil {
		t.Fatal(err)
	}
	return siteconf.Reply{OK: true, Status: raw}
}

// fix-mktsiteconf7 §1: what the subscriber saves after one supply.site_status
// of an applied leaf (clock injected; backoff and limit of ReconcilePolicy).
func TestNodeCheckDecision(t *testing.T) {
	now := time.Date(2026, 10, 28, 15, 0, 0, 0, time.UTC)
	policy := DefaultReconcilePolicy()
	base := nodeCheck{revision: 4}

	t.Run("in effect settles", func(t *testing.T) {
		got := nodeCheckDecision(base, nodeStatusReply(t, map[string]string{"state": "effective"}), nil, now, policy)
		if got.state != NodeEffective || got.attempts != 0 || got.reason != "" || !got.next.IsZero() || got.notify {
			t.Fatalf("decision = %+v", got)
		}
	})
	t.Run("leaf failure settles with its reason and notifies", func(t *testing.T) {
		got := nodeCheckDecision(base, nodeStatusReply(t, map[string]string{"state": "failed", "reason": "security_failed",
			"detail": "waf:candidate_rejected"}), nil, now, policy)
		if got.state != NodeFailed || got.reason != "security_failed" || got.detail != "waf:candidate_rejected" || !got.notify {
			t.Fatalf("decision = %+v", got)
		}
	})
	t.Run("still on its way backs off", func(t *testing.T) {
		got := nodeCheckDecision(base, nodeStatusReply(t, map[string]string{"state": "delivering", "reason": "site_syncing"}), nil, now, policy)
		if got.state != NodeDelivering || got.attempts != 1 || got.reason != "site_syncing" || !got.next.Equal(now.Add(policy.Backoff)) {
			t.Fatalf("decision = %+v", got)
		}
		check := base
		check.attempts = 3
		got = nodeCheckDecision(check, nodeStatusReply(t, map[string]string{"state": "delivering"}), nil, now, policy)
		if want := now.Add(8 * policy.Backoff); got.attempts != 4 || !got.next.Equal(want) {
			t.Fatalf("decision = %+v, want next %s", got, want)
		}
	})
	t.Run("never in effect within the limit fails as a timeout", func(t *testing.T) {
		check := base
		check.attempts = policy.MaxAttempts - 1
		got := nodeCheckDecision(check, nodeStatusReply(t, map[string]string{"state": "delivering", "reason": "security_activating",
			"detail": "cc"}), nil, now, policy)
		if got.state != NodeFailed || got.reason != NodeReasonTimeout || got.detail != "security_activating:cc" || !got.notify ||
			got.attempts != policy.MaxAttempts {
			t.Fatalf("decision = %+v", got)
		}
	})
	t.Run("leaf unreachable backs off, then fails", func(t *testing.T) {
		got := nodeCheckDecision(base, siteconf.Reply{}, errors.New("relay timeout"), now, policy)
		if got.state != NodeDelivering || got.reason != NodeReasonStatusUnavailable || got.attempts != 1 {
			t.Fatalf("decision = %+v", got)
		}
		check := base
		check.attempts = policy.MaxAttempts - 1
		got = nodeCheckDecision(check, siteconf.Reply{Error: "grant inactive"}, nil, now, policy)
		if got.state != NodeFailed || got.reason != NodeReasonStatusUnavailable || got.detail != "grant inactive" || !got.notify {
			t.Fatalf("decision = %+v", got)
		}
	})
	t.Run("a reply without node delivery is not an answer", func(t *testing.T) {
		got := nodeCheckDecision(base, siteconf.Reply{OK: true, Status: json.RawMessage(`{"enabled":true}`)}, nil, now, policy)
		if got.state != NodeDelivering || got.reason != NodeReasonStatusUnavailable {
			t.Fatalf("decision = %+v", got)
		}
	})
	t.Run("leaf text is bounded and codes are checked", func(t *testing.T) {
		got := nodeCheckDecision(base, nodeStatusReply(t, map[string]string{"state": "failed", "reason": "Bad Code!",
			"detail": strings.Repeat("x", 900)}), nil, now, policy)
		if got.state != NodeFailed || got.reason != NodeReasonUnknown || len(got.detail) != 500 {
			t.Fatalf("decision = %+v (detail %d)", got, len(got.detail))
		}
		got = nodeCheckDecision(base, nodeStatusReply(t, map[string]string{"state": "weird"}), nil, now, policy)
		if got.state != NodeDelivering || got.reason != NodeReasonStatusUnavailable {
			t.Fatalf("unknown state decision = %+v", got)
		}
	})
}
