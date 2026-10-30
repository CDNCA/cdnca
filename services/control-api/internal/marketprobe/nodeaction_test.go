package marketprobe

import (
	"testing"
	"time"

	"github.com/cdnca/cdnca/libs/marketproto/nodeaction"
	"github.com/google/uuid"
)

type staticGrants map[string]uuid.UUID

func (g staticGrants) GrantForKey(key string) (uuid.UUID, bool) {
	id, ok := g[key]
	return id, ok
}

// Identical actions merge by count; a site row takes its key's current grant
// and, without one, is reported without a site (still a node action, never
// counted for the site); a future second is clamped to now.
func TestMergeNodeActions(t *testing.T) {
	now := time.Unix(1_800_000_000, 0)
	node, site, other, grantID := uuid.New(), uuid.New(), uuid.New(), uuid.New()
	known, unknown := "aaaaaaaaaaaaaaaaaaaaaaaa", "bbbbbbbbbbbbbbbbbbbbbbbb"
	ban := nodeaction.Item{NodePoolRef: "p", NodeID: node, At: now.Unix() - 5, Source: "ddos", Kind: "rate_ban", Level: 4, Count: 2}
	kernel := nodeaction.Item{NodePoolRef: "p", NodeID: node, At: now.Unix() - 5, Source: "autodefense", Kind: "kernel_ban", Level: 4,
		Count: 1, LeafSiteID: &site}
	orphan := kernel
	orphan.LeafSiteID = &other
	future := ban
	future.At = now.Unix() + 30
	s := &Service{cfg: Config{Grants: staticGrants{known: grantID}}}
	items := s.mergeNodeActions([]queuedAction{{item: ban}, {item: ban}, {item: kernel, marketKey: &known}, {item: kernel, marketKey: &known},
		{item: orphan, marketKey: &unknown}, {item: future}}, now)
	if len(items) != 4 {
		t.Fatalf("items: %+v", items)
	}
	if items[0].Count != 4 || items[0].GrantID != nil {
		t.Fatalf("ddos merged: %+v", items[0])
	}
	if !items[1].SiteAttributable() || *items[1].GrantID != grantID || items[1].Count != 2 {
		t.Fatalf("site action with its grant: %+v", items[1])
	}
	if items[2].SiteAttributable() || items[2].LeafSiteID != nil {
		t.Fatalf("no grant: reported without a site: %+v", items[2])
	}
	if items[3].At != now.Unix() {
		t.Fatalf("future clamped: %+v", items[3])
	}
	if err := (nodeaction.Report{Schema: nodeaction.SchemaV1, ReportID: uuid.New(), LeafMemberID: uuid.New(), CreatedAt: now.Unix(),
		Items: items}).Validate(); err != nil {
		t.Fatalf("merged items form a valid report: %v", err)
	}
}
