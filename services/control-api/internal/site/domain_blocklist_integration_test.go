package site

import (
	"context"
	"errors"
	"testing"

	"github.com/cdnca/cdnca/services/control-api/internal/domainblocklist"
	"github.com/cdnca/cdnca/services/control-api/internal/domaintrust"
	"github.com/google/uuid"
)

func TestDomainBlocklistRootAndExactMatching(t *testing.T) {
	f := newTrustFixture(t)
	ctx := context.Background()
	blocklist, err := domainblocklist.NewService(f.pool, f.clock)
	if err != nil {
		t.Fatal(err)
	}
	admin := domainblocklist.Actor{UserID: f.admin.userID, ScopeID: f.admin.scopeID, ScopeKind: "platform"}
	existing, err := f.createSite(f.b, f.b, "shop.root-block.test")
	if err != nil {
		t.Fatal(err)
	}
	root, err := blocklist.Create(ctx, admin, domainblocklist.Input{Pattern: "Root-Block.test", MatchType: "root",
		Reason: "phishing report"}, "bl-1", "bl-1")
	if err != nil || root.Pattern != "root-block.test" {
		t.Fatalf("create root = %+v, %v", root, err)
	}
	if _, err := blocklist.Create(ctx, admin, domainblocklist.Input{Pattern: "only.exact-block.test", MatchType: "exact"},
		"bl-2", "bl-2"); err != nil {
		t.Fatal(err)
	}
	if _, err := blocklist.Create(ctx, admin, domainblocklist.Input{Pattern: "root-block.test"}, "bl-3", "bl-3"); !errors.Is(err, domainblocklist.ErrConflict) {
		t.Fatalf("duplicate pattern = %v", err)
	}
	if _, err := blocklist.Create(ctx, domainblocklist.Actor{UserID: f.a.userID, ScopeID: f.a.scopeID, ScopeKind: "tenant"},
		domainblocklist.Input{Pattern: "x.test"}, "bl-4", "bl-4"); !errors.Is(err, domainblocklist.ErrPermissionDenied) {
		t.Fatalf("tenant create = %v", err)
	}
	for _, domain := range []string{"root-block.test", "a.b.root-block.test", "*.root-block.test", "only.exact-block.test"} {
		var detail *domaintrust.DomainError
		if _, err := f.createSite(f.a, f.a, domain); !errors.As(err, &detail) || !errors.Is(err, domaintrust.ErrDomainBlocked) ||
			detail.Domain != domain {
			t.Fatalf("blocked %s = %v", domain, err)
		}
	}
	// Platform administrators are blocked too.
	if _, err := f.createSite(f.admin, f.a, "admin.root-block.test"); !errors.Is(err, domaintrust.ErrDomainBlocked) {
		t.Fatalf("admin blocked = %v", err)
	}
	for _, domain := range []string{"other.exact-block.test", "exact-block.test", "notroot-block.test"} {
		if _, err := f.createSite(f.a, f.a, domain); err != nil {
			t.Fatalf("allowed %s: %v", domain, err)
		}
	}
	// Adding a blocked alias through update is refused; the existing site stays editable otherwise.
	current, err := f.sites.Get(ctx, f.b.siteActor(), existing.Site.ID)
	if err != nil {
		t.Fatal(err)
	}
	fields := SiteFields{Domains: append(current.Domains, "only.exact-block.test"), HTTPPorts: []string{"80"},
		Origins: []string{"192.0.2.1"}, Enabled: true, Status: StatusActive}
	if _, err := f.sites.Update(ctx, f.b.siteActor(), UpdateRequest{ID: current.ID, ExpectedRevision: current.Revision,
		Fields: fields, IdempotencyKey: "upd-bl", RequestID: "upd-bl"}); !errors.Is(err, domaintrust.ErrDomainBlocked) {
		t.Fatalf("update add blocked alias = %v", err)
	}
	fields.Domains = current.Domains
	if _, err := f.sites.Update(ctx, f.b.siteActor(), UpdateRequest{ID: current.ID, ExpectedRevision: current.Revision,
		Fields: fields, IdempotencyKey: "upd-ok", RequestID: "upd-ok"}); err != nil {
		t.Fatalf("existing hit stays editable: %v", err)
	}
	hits, err := blocklist.Hits(ctx, admin, root.ID)
	if err != nil || len(hits) != 1 || hits[0].SiteID != existing.Site.ID || hits[0].Domain != "shop.root-block.test" {
		t.Fatalf("hits = %+v, %v", hits, err)
	}
	if all, err := blocklist.Hits(ctx, admin, uuid.Nil); err != nil || len(all) != 1 {
		t.Fatalf("all hits = %+v, %v", all, err)
	}

	imported, err := blocklist.Import(ctx, admin, []domainblocklist.Input{
		{Pattern: "import-a.test"}, {Pattern: "root-block.test", MatchType: "exact", Reason: "narrowed"},
		{Pattern: "import-a.test"},
	}, "imp-1", "imp-1")
	if err != nil || imported.Created != 1 || imported.Updated != 1 {
		t.Fatalf("import = %+v, %v", imported, err)
	}
	if replay, err := blocklist.Import(ctx, admin, []domainblocklist.Input{
		{Pattern: "import-a.test"}, {Pattern: "root-block.test", MatchType: "exact", Reason: "narrowed"},
	}, "imp-1", "imp-1"); err != nil || !replay.Replayed {
		t.Fatalf("import replay = %+v, %v", replay, err)
	}
	if _, err := f.createSite(f.a, f.a, "sub.root-block.test"); err != nil {
		t.Fatalf("root narrowed to exact still blocks subdomain: %v", err)
	}
	entries, err := blocklist.List(ctx, admin, "block", 0)
	if err != nil || len(entries) != 2 {
		t.Fatalf("list = %+v, %v", entries, err)
	}
	for _, entry := range entries {
		if err := blocklist.Delete(ctx, admin, entry.ID, entry.Revision, "del-"+entry.ID.String()[:8], "del"); err != nil {
			t.Fatal(err)
		}
	}
	if _, err := f.createSite(f.a, f.a, "only.exact-block.test"); err != nil {
		t.Fatalf("after delete: %v", err)
	}
}
