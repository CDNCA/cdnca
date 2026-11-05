package marketsupply

import (
	"encoding/json"
	"testing"
	"time"

	"github.com/cdnca/cdnca/libs/marketproto/envelope"
	"github.com/cdnca/cdnca/libs/marketproto/grant"
	"github.com/cdnca/cdnca/libs/marketproto/siteconf"
	"github.com/cdnca/cdnca/libs/marketproto/spec"
	"github.com/cdnca/cdnca/services/control-api/internal/securityactivation"
	"github.com/cdnca/cdnca/services/control-api/internal/securitypolicy"
	"github.com/cdnca/cdnca/services/control-api/internal/site"
	"github.com/google/uuid"
)

// After a restart the relay ran the subscriber's whole history
// again, and an old commit rewrote the leaf site and turned its CC policy
// off. A commit older than what the leaf runs, or one it already applied,
// writes nothing and answers with the revision that runs; newer ones and
// rollbacks over the failed revision are applied as before.
func TestLeafSkipsStaleAndReplayedCommits(t *testing.T) {
	pool := marketSupplyPool(t)
	ctx := t.Context()
	platform := platformScope(t, pool)
	now := time.Now().UTC()
	svc := newTestService(t, pool, func() time.Time { return now })
	svc.cfg.CNAMEDomain = "cdn.leaf.example.net"
	fake := &fakeSites{sites: map[uuid.UUID]site.Site{}}
	svc.WithSites(fake, nil)
	svc.WithSecurity(securitypolicy.NewService(securitypolicy.NewStoreWithClock(pool, time.Now)),
		&recordingActivations{kinds: map[uuid.UUID]string{}, status: map[string]securityactivation.CandidateStatus{},
			active: map[string]int64{}, started: make(chan struct{}, 8)})
	actor, err := svc.ensureActor(ctx)
	if err != nil {
		t.Fatal(err)
	}
	poolID := insertLineGroup(t, pool, platform, actor.userID)
	g := grant.Grant{Schema: grant.SchemaV2, GrantID: uuid.New(), LeafMemberID: uuid.New(),
		SubscriptionPath: []uuid.UUID{uuid.New()}, NodePoolRef: poolID.String(),
		Limits:         spec.LimitSet{{Metric: spec.MetricDomains, Cap: 2, Action: spec.ActionRejectNew}},
		LoadThresholds: spec.DefaultLoadFloor, Tags: spec.Tags{CCProtection: spec.CCNone, Tenancy: spec.TenancyShared},
		Allocation: spec.Allocation{HTTPPorts: 1},
		IssuedAt:   now.Add(-time.Hour).Unix(), NotBefore: now.Add(-time.Hour).Unix(), NotAfter: now.Add(24 * time.Hour).Unix()}
	mustSync(t, svc, g)
	tenant, err := svc.ensureTenant(ctx, actor, Key(g))
	if err != nil {
		t.Fatal(err)
	}

	withCC := siteconf.Config{Schema: siteconf.SchemaV1, Domains: []string{"stale.example.cn"}, HTTPPorts: []int{80},
		Origins: []siteconf.Origin{{Host: "203.0.113.20", Port: 80}}}
	withCC.CC, _ = json.Marshal(siteCC{DefaultAction: securitypolicy.ActionAllow, Rules: []securitypolicy.Rule{bucketRule()}})
	moved := withCC
	moved.Origins = []siteconf.Origin{{Host: "203.0.113.21", Port: 80}}
	bare := moved
	bare.CC = nil
	for _, cfg := range []*siteconf.Config{&withCC, &moved, &bare} {
		if err := cfg.Normalize(); err != nil {
			t.Fatal(err)
		}
	}
	siteID := uuid.New()
	var leafSite *uuid.UUID
	commit := func(seq, revision, rollbackOf int64, cfg siteconf.Config) siteconf.Reply {
		t.Helper()
		raw, _ := json.Marshal(siteconf.CommitRequest{SiteID: siteID, LeafSiteID: leafSite, Revision: revision,
			Digest: cfg.Digest(), Config: cfg, RollbackOf: rollbackOf})
		reply, err := svc.Handle(WithRelaySeq(ctx, seq), envelope.Header{MessageID: uuid.New(), GrantID: g.GrantID,
			Operation: siteconf.OpCommit, Domains: cfg.Domains}, raw)
		if err != nil {
			t.Fatalf("commit seq %d revision %d: %v", seq, revision, err)
		}
		return reply
	}
	ccState := func() (bool, int64) {
		t.Helper()
		var enabled bool
		var revision int64
		if err := pool.QueryRow(ctx, `SELECT enabled, revision FROM security_policies WHERE scope_id=$1 AND name=$2
			AND kind='cc' AND deleted_at IS NULL`, tenant.scopeID, leafPolicyName(securitypolicy.KindCC, *leafSite)).
			Scan(&enabled, &revision); err != nil {
			t.Fatal(err)
		}
		return enabled, revision
	}
	writes := func() int { return len(fake.creates) + fake.updates }

	r := commit(10, 1, 0, withCC)
	if !r.OK || r.LeafSiteID == nil || r.AppliedRevision != 1 {
		t.Fatalf("revision 1 = %+v", r)
	}
	leafSite = r.LeafSiteID
	if r := commit(11, 2, 0, moved); !r.OK || r.AppliedRevision != 2 || fake.updates != 1 {
		t.Fatalf("revision 2 = %+v updates=%d", r, fake.updates)
	}
	if enabled, revision := ccState(); !enabled || revision != 1 {
		t.Fatalf("cc after revision 2 enabled=%v revision=%d", enabled, revision)
	}

	// Replays of both, then a reconciler resending revision 1 after 2 applied:
	// no site write, the CC policy untouched, revision 2 reported.
	before := writes()
	for _, replay := range []struct {
		seq, revision int64
		cfg           siteconf.Config
	}{{10, 1, withCC}, {11, 2, moved}, {12, 1, bare}} {
		if r := commit(replay.seq, replay.revision, 0, replay.cfg); !r.OK || r.AppliedRevision != 2 ||
			r.LeafSiteID == nil || *r.LeafSiteID != *leafSite || r.Digest != "" {
			t.Fatalf("stale commit seq %d revision %d = %+v", replay.seq, replay.revision, r)
		}
	}
	if writes() != before {
		t.Fatalf("stale commits wrote the site: %d -> %d", before, writes())
	}
	if enabled, revision := ccState(); !enabled || revision != 1 {
		t.Fatalf("stale commit changed the cc policy: enabled=%v revision=%d", enabled, revision)
	}
	// Without a relay sequence (a direct call) the revision order still holds.
	if r := commit(0, 1, 0, bare); !r.OK || r.AppliedRevision != 2 || writes() != before {
		t.Fatalf("stale commit without sequence = %+v", r)
	}

	// Revision 3 (no cc) applies and turns the policy off; it then fails on
	// another leaf and the subscriber rolls back to 2: applied over 3.
	if r := commit(13, 3, 0, bare); !r.OK || r.AppliedRevision != 3 {
		t.Fatalf("revision 3 = %+v", r)
	}
	if enabled, _ := ccState(); enabled {
		t.Fatal("revision 3 left the cc policy on")
	}
	if r := commit(14, 2, 3, moved); !r.OK || r.AppliedRevision != 2 {
		t.Fatalf("rollback of 3 = %+v", r)
	}
	if enabled, revision := ccState(); !enabled || revision != 3 {
		t.Fatalf("rollback did not restore cc: enabled=%v revision=%d", enabled, revision)
	}
	// Replaying 3 after its rollback must not apply it again.
	before = writes()
	if r := commit(13, 3, 0, bare); !r.OK || r.AppliedRevision != 2 || writes() != before {
		t.Fatalf("replayed 3 after its rollback = %+v", r)
	}
	if enabled, _ := ccState(); !enabled {
		t.Fatal("replayed revision 3 turned cc off again")
	}
	// A rollback of an older failure (sent before 3) is stale too.
	if r := commit(15, 1, 2, withCC); !r.OK || r.AppliedRevision != 2 || writes() != before {
		t.Fatalf("stale rollback = %+v", r)
	}
	// Sending 3 again later (a new apply of the same revision) is applied.
	if r := commit(16, 3, 0, bare); !r.OK || r.AppliedRevision != 3 || writes() == before {
		t.Fatalf("revision 3 sent again = %+v", r)
	}

	var applied, high, seq int64
	if err := pool.QueryRow(ctx, `SELECT applied_revision, high_revision, relay_seq FROM market_supply_site_revisions
		WHERE tenant_scope_id=$1 AND site_id=$2`, tenant.scopeID, siteID).Scan(&applied, &high, &seq); err != nil ||
		applied != 3 || high != 3 || seq != 16 {
		t.Fatalf("recorded applied/high/seq = %d/%d/%d %v", applied, high, seq, err)
	}

	// Status and prepare report what runs; a delete sent before the last
	// applied commit is a replay and leaves the site; a newer one deletes it.
	ref := func(seq int64, op string) siteconf.Reply {
		t.Helper()
		raw, _ := json.Marshal(siteconf.SiteRef{SiteID: siteID, LeafSiteID: *leafSite})
		reply, err := svc.Handle(WithRelaySeq(ctx, seq), envelope.Header{MessageID: uuid.New(), GrantID: g.GrantID,
			Operation: op}, raw)
		if err != nil {
			t.Fatal(err)
		}
		return reply
	}
	if r := ref(17, siteconf.OpStatus); !r.OK || r.AppliedRevision != 3 {
		t.Fatalf("status = %+v", r)
	}
	if r := ref(9, siteconf.OpDelete); !r.OK || r.AppliedRevision != 3 {
		t.Fatalf("replayed delete = %+v", r)
	}
	if _, ok := fake.sites[*leafSite]; !ok {
		t.Fatal("replayed delete removed the site")
	}
	if r := ref(18, siteconf.OpDelete); !r.OK || r.AppliedRevision != 0 {
		t.Fatalf("delete = %+v", r)
	}
	if _, ok := fake.sites[*leafSite]; ok {
		t.Fatal("delete kept the site")
	}
	// The first create replayed after the delete does not bring the site back.
	creates := len(fake.creates)
	leafSite = nil
	if r := commit(10, 1, 0, withCC); !r.OK || r.AppliedRevision != 0 || r.LeafSiteID != nil || len(fake.creates) != creates {
		t.Fatalf("create replayed after delete = %+v creates %d -> %d", r, creates, len(fake.creates))
	}
}
