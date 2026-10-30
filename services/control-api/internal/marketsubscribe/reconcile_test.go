package marketsubscribe

import (
	"errors"
	"testing"
	"time"

	"github.com/cdnca/cdnca/libs/marketproto/siteconf"
	"github.com/google/uuid"
)

// fix-cfgflow2 §2: what the receipt reconciler does with one committing leaf.
func TestReconcileDecision(t *testing.T) {
	now := time.Date(2026, 10, 27, 12, 0, 0, 0, time.UTC)
	leafSite := uuid.New()
	policy := DefaultReconcilePolicy()
	base := pendingReceipt{revision: 7, digest: "d7", attempts: 0}

	t.Run("confirmed reply completes the receipt", func(t *testing.T) {
		got := reconcileDecision(base, siteconf.Reply{OK: true, LeafSiteID: &leafSite, Digest: "d7"}, nil, now, policy)
		if got.state != "applied" || got.leafSite == nil || *got.leafSite != leafSite {
			t.Fatalf("decision = %+v", got)
		}
	})
	t.Run("reply without a digest is confirmed by its site", func(t *testing.T) {
		got := reconcileDecision(base, siteconf.Reply{OK: true, LeafSiteID: &leafSite}, nil, now, policy)
		if got.state != "applied" {
			t.Fatalf("decision = %+v", got)
		}
	})
	t.Run("transport error backs off", func(t *testing.T) {
		got := reconcileDecision(base, siteconf.Reply{}, errors.New("relay timeout"), now, policy)
		if got.state != "committing" || got.attempts != 1 || !got.next.Equal(now.Add(policy.Backoff)) || got.reason == "" {
			t.Fatalf("decision = %+v", got)
		}
	})
	t.Run("backoff doubles and is capped", func(t *testing.T) {
		pending := base
		pending.attempts = 3
		got := reconcileDecision(pending, siteconf.Reply{}, errors.New("relay timeout"), now, policy)
		if want := now.Add(8 * policy.Backoff); got.attempts != 4 || !got.next.Equal(want) {
			t.Fatalf("decision = %+v, want next %s", got, want)
		}
		pending.attempts = 20
		policy := policy
		policy.MaxAttempts = 100
		got = reconcileDecision(pending, siteconf.Reply{}, errors.New("relay timeout"), now, policy)
		if !got.next.Equal(now.Add(policy.MaxBackoff)) {
			t.Fatalf("capped next = %s", got.next)
		}
	})
	t.Run("too many failures give up with a reason", func(t *testing.T) {
		pending := base
		pending.attempts = policy.MaxAttempts - 1
		got := reconcileDecision(pending, siteconf.Reply{OK: false, Error: "grant inactive"}, nil, now, policy)
		if got.state != "inconsistent" || got.reason != "grant inactive" || !got.notify {
			t.Fatalf("decision = %+v", got)
		}
	})
	t.Run("leaf normalized differently gives up at once", func(t *testing.T) {
		got := reconcileDecision(base, siteconf.Reply{OK: true, LeafSiteID: &leafSite, Digest: "other"}, nil, now, policy)
		if got.state != "inconsistent" || !got.notify {
			t.Fatalf("decision = %+v", got)
		}
	})
}

func TestReconcilePolicyValidates(t *testing.T) {
	if err := DefaultReconcilePolicy().validate(); err != nil {
		t.Fatal(err)
	}
	bad := DefaultReconcilePolicy()
	bad.MaxAttempts = 0
	if err := bad.validate(); err == nil {
		t.Fatal("zero attempts accepted")
	}
}
