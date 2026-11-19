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

// A check's source names the site,
// the supply, the leaf, its node pool (up to 128 bytes) and the revision, so
// it can pass the notification store's 128-byte audit request ID (and the
// 256-byte source event ID). The IDs derived from it stay within both and
// are the same for the same source (a retry dedups as before); a short
// source is kept as is.
func TestNoticeIDsStayWithinTheStoreLimits(t *testing.T) {
	short := "market-nodes/a/b/c/p1/1"
	if event, audit := noticeIDs(short); event != short || audit != short {
		t.Fatalf("short source = %q %q", event, audit)
	}
	pool := strings.Repeat("p", 128)
	long := "market-nodes/0f4b6a2e-6a59-4d39-9d6b-1c0a3c2d4e5f/7c9e6679-7425-40de-944b-e07fc1f90ae7/" +
		"1b4e28ba-2fa1-11d2-883f-0016d3cca427/" + pool + "/9223372036854775807"
	event, audit := noticeIDs(long)
	if len(event) > 256 || len(audit) > 128 || !strings.HasPrefix(audit, "market-nodes/") || audit == long {
		t.Fatalf("long source = %q (%d) %q (%d)", event, len(event), audit, len(audit))
	}
	if again, auditAgain := noticeIDs(long); again != event || auditAgain != audit {
		t.Fatal("the same source must derive the same IDs")
	}
	if _, other := noticeIDs(long[:len(long)-1] + "6"); other == audit {
		t.Fatal("another revision must derive another audit request ID")
	}
	// Within 256 the source event ID is kept (dedup unchanged), only the audit ID is digested.
	mid := "market-receipt/" + strings.Repeat("x", 150)
	if event, audit := noticeIDs(mid); event != mid || len(audit) > 128 || audit == mid {
		t.Fatalf("mid source = %q %q", event, audit)
	}
}
