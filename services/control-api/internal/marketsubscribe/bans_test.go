package marketsubscribe

import (
	"encoding/json"
	"errors"
	"testing"
	"time"

	"github.com/cdnca/cdnca/libs/marketproto/bansync"
	"github.com/cdnca/cdnca/libs/marketproto/siteconf"
	"github.com/cdnca/cdnca/services/control-api/internal/marketclient"
	"github.com/google/uuid"
)

func TestBanDecision(t *testing.T) {
	now := time.Unix(1_800_000_000, 0).UTC()
	a, b, over := uuid.New(), uuid.New(), uuid.New()
	job := banJob{revision: 10, attempt: 2, snapshot: banSnapshot{
		bans:    []bansync.Ban{{Ref: a}, {Ref: b}},
		refused: []bansync.Refusal{{Ref: over, Code: bansync.RefuseSiteLimit}}}}
	ok := func(status bansync.Status) siteconf.Reply {
		raw, _ := json.Marshal(status)
		return siteconf.Reply{OK: true, Status: raw}
	}

	out := banDecision(job, ok(bansync.Status{Revision: 10, Refused: []bansync.Refusal{
		{Ref: b, Code: bansync.RefuseTenantLimit}, {Ref: uuid.New(), Code: "not_sent"}, {Ref: b, Code: "twice"}},
		Nodes: bansync.Nodes{State: bansync.NodesApplied, Total: 2, Applied: 2}}), nil, now)
	if out.state != banAccepted || !out.answered || len(out.accepted) != 1 || out.accepted[0] != a || len(out.refused) != 2 ||
		out.refused[0].Ref != over || out.refused[1].Ref != b || out.refused[1].Code != bansync.RefuseTenantLimit ||
		!out.next.Equal(now.Add(banRefresh)) {
		t.Fatalf("accepted = %+v", out)
	}
	out = banDecision(job, ok(bansync.Status{Revision: 10, Refused: []bansync.Refusal{{Ref: a, Code: "Bad Code!"}},
		Nodes: bansync.Nodes{State: "weird", Reason: "<script>"}}), nil, now)
	if out.refused[1].Code != BanReasonUnknown || out.nodes.State != bansync.NodesDelivering || out.nodes.Reason != BanReasonUnknown ||
		!out.next.Equal(now.Add(probeBackoff(2))) {
		t.Fatalf("sanitized = %+v", out)
	}
	if out = banDecision(job, ok(bansync.Status{Revision: 99}), nil, now); out.newer != 99 || out.state != banSent || out.answered {
		t.Fatalf("leaf runs newer = %+v", out)
	}
	for name, c := range map[string]struct {
		reply         siteconf.Reply
		err           error
		state, reason string
		answered      bool
	}{
		"old leaf":     {siteconf.Reply{Error: "market supply: operation not supported"}, nil, banUnsupported, "peer_unsupported", false},
		"rate limited": {siteconf.Reply{Error: bansync.ErrCodeRateLimited}, nil, banRejected, bansync.ErrCodeRateLimited, false},
		"paused":       {siteconf.Reply{Error: bansync.ErrCodePaused}, nil, banRejected, bansync.ErrCodePaused, true},
		"ended":        {siteconf.Reply{Error: bansync.ErrCodeEnded}, nil, banRejected, bansync.ErrCodeEnded, true},
		"no site":      {siteconf.Reply{Error: bansync.ErrCodeSiteNotFound}, nil, banRejected, bansync.ErrCodeSiteNotFound, false},
		"other":        {siteconf.Reply{Error: "market supply: grant not synced"}, nil, banRejected, BanReasonLeafError, false},
		"bad status":   {siteconf.Reply{OK: true, Status: json.RawMessage(`[`)}, nil, banRejected, BanReasonLeafError, false},
		"old market":   {siteconf.Reply{}, &marketclient.RejectedError{Status: 403, Code: "forbidden"}, banRejected, BanReasonRelayRefused, false},
		"market busy":  {siteconf.Reply{}, &marketclient.RejectedError{Status: 429}, banSent, BanReasonTimeout, false},
		"no answer":    {siteconf.Reply{}, errors.New("leaf did not reply in time"), banSent, BanReasonTimeout, false},
	} {
		got := banDecision(job, c.reply, c.err, now)
		if got.state != c.state || got.reason != c.reason || got.answered != c.answered || !got.next.After(now) {
			t.Errorf("%s: %+v", name, got)
		}
		if c.answered && (len(got.accepted) != 0 || got.nodes.State != bansync.NodesNone) {
			t.Errorf("%s: lifted bans still accepted: %+v", name, got)
		}
	}
}

func TestProbeBackoffAndReason(t *testing.T) {
	for attempt, want := range map[int]time.Duration{1: 3 * time.Second, 2: 6 * time.Second, 5: 48 * time.Second, 6: time.Minute, 20: time.Minute} {
		if got := probeBackoff(attempt); got != want {
			t.Errorf("probeBackoff(%d) = %v, want %v", attempt, got, want)
		}
	}
	long := ""
	for range bansync.MaxReason + 10 {
		long += "封"
	}
	if got := banReason("a\tb\n" + long); len([]rune(got)) != bansync.MaxReason || got[:3] != "a b" {
		t.Fatalf("banReason = %q", got)
	}
}
