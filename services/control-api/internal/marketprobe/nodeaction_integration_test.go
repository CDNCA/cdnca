//go:build integration

package marketprobe

import (
	"context"
	"errors"
	"io"
	"log/slog"
	"testing"
	"time"

	"github.com/cdnca/cdnca/services/control-api/internal/database/databasetest"
	"github.com/cdnca/cdnca/services/control-api/internal/marketclient"
	"github.com/google/uuid"
)

// ADR 0012 §19.3 (ML-23): queued actions are claimed into one report; a lost
// answer resends the same report ID (the market drops the replay), an answer
// marks them reported; site rows carry their key's grant; rows older than a
// day are pruned unsent; nothing is sent before the member registered.
func TestReportNodeActionsClaimsAndRetries(t *testing.T) {
	pool := databasetest.MigratedPool(t, nil)
	ctx := t.Context()
	now := time.Date(2026, 10, 22, 4, 0, 0, 0, time.UTC)
	node, site, grantID := uuid.New(), uuid.New(), uuid.New()
	key := "0123456789abcdef01234567"
	insert := func(at time.Time, source, kind string, level int, marketKey *string, siteID *uuid.UUID, created time.Time) {
		t.Helper()
		if _, err := pool.Exec(ctx, `INSERT INTO market_node_action_queue(node_id,node_pool_ref,occurred_at,source,kind,level,count,
			market_key,site_id,created_at) VALUES($1,'pool-a',$2,$3,$4,$5,1,$6,$7,$8)`, node, at, source, kind, level, marketKey, siteID,
			created); err != nil {
			t.Fatal(err)
		}
	}
	insert(now.Add(-time.Minute), "ddos", "rate_ban", 4, nil, nil, now)
	insert(now.Add(-time.Minute), "ddos", "rate_ban", 4, nil, nil, now) // merges with the first
	insert(now.Add(-30*time.Second), "autodefense", "kernel_ban", 4, &key, &site, now)
	insert(now.Add(-26*time.Hour), "xdp", "fallback", 4, nil, nil, now.Add(-25*time.Hour)) // too old: pruned

	market := &fakeMarket{}
	member := marketclient.Identity{}
	s := New(pool, market, nil, Config{Now: func() time.Time { return now }, Identity: func() marketclient.Identity { return member },
		Grants: staticGrants{key: grantID}}, slog.New(slog.NewTextHandler(io.Discard, nil)))
	if sent, err := s.ReportNodeActions(ctx); err != nil || sent != 0 || len(market.actions) != 0 {
		t.Fatalf("unregistered member sends nothing: %d %v", sent, err)
	}
	member.MemberID = uuid.New()
	market.actionErr = errors.New("answer lost")
	if _, err := s.ReportNodeActions(ctx); err == nil || len(market.actions) != 1 {
		t.Fatalf("first attempt fails: %v %d", err, len(market.actions))
	}
	first := market.actions[0]
	if len(first.Items) != 2 || first.Items[0].Count != 2 || !first.Items[1].SiteAttributable() || *first.Items[1].GrantID != grantID ||
		*first.Items[1].LeafSiteID != site {
		t.Fatalf("report items: %+v", first.Items)
	}
	market.actionErr = nil
	if sent, err := s.ReportNodeActions(context.Background()); err != nil || sent != 2 || len(market.actions) != 2 ||
		market.actions[1].ReportID != first.ReportID {
		t.Fatalf("retry resends the same report: %d %v %+v", sent, err, market.actions)
	}
	var pending, total int
	if err := pool.QueryRow(ctx, `SELECT count(*) FILTER (WHERE reported_at IS NULL), count(*) FROM market_node_action_queue`).
		Scan(&pending, &total); err != nil || pending != 0 || total != 3 {
		t.Fatalf("pending=%d total=%d (old row pruned) %v", pending, total, err)
	}
	if sent, err := s.ReportNodeActions(ctx); err != nil || sent != 0 || len(market.actions) != 2 {
		t.Fatalf("nothing left: %d %v", sent, err)
	}
}
