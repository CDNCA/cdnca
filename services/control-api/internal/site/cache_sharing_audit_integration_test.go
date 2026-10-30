//go:build integration

package site

import (
	"context"
	"encoding/json"
	"testing"

	"github.com/cdnca/cdnca/services/control-api/internal/audit"
	"github.com/cdnca/cdnca/services/control-api/internal/audit/audittest"
)

// 所有域名共用缓存 is off on a new site; turning it on or
// off writes site.cache_sharing.update with the actor, source IP, site and the
// before -> after value; an update that leaves it alone writes none.
func TestSiteCacheSharingChangeIsAudited(t *testing.T) {
	f := newTrustFixture(t)
	created, err := f.createSite(f.a, f.a, "cache-share.example.test", "alias.cache-share.example.test")
	if err != nil {
		t.Fatal(err)
	}
	if created.Site.CacheSharedAcrossDomains {
		t.Fatal("a new site shares its cache across domains")
	}
	revision := created.Site.Revision
	update := func(shared *bool) Site {
		t.Helper()
		key := f.key("update")
		result, err := f.sites.Update(context.Background(), f.a.siteActor(), UpdateRequest{
			ID: created.Site.ID, ExpectedRevision: revision, IdempotencyKey: key, RequestID: key, SourceIP: "198.51.100.7",
			Fields: SiteFields{Domains: []string{"cache-share.example.test", "alias.cache-share.example.test"},
				HTTPPorts: []string{"80"}, Origins: []string{"192.0.2.1"}, Enabled: true,
				Status: StatusActive, CacheSharedAcrossDomains: shared},
		})
		if err != nil {
			t.Fatalf("update shared=%v: %v", shared, err)
		}
		revision = result.Site.Revision
		return result.Site
	}
	events := func() []map[string]any {
		t.Helper()
		rows, err := f.pool.Query(context.Background(), `SELECT actor_user_id::text,scope_id::text,resource_type,resource_id,result,payload,changes
			FROM audit_events WHERE action='site.cache_sharing.update' ORDER BY stream_position`)
		if err != nil {
			t.Fatal(err)
		}
		defer rows.Close()
		var result []map[string]any
		for rows.Next() {
			var actor, scope, resourceType, resourceID, outcome string
			var raw, changes []byte
			if err := rows.Scan(&actor, &scope, &resourceType, &resourceID, &outcome, &raw, &changes); err != nil {
				t.Fatal(err)
			}
			payload := map[string]any{}
			if err := json.Unmarshal(raw, &payload); err != nil {
				t.Fatal(err)
			}
			// The changes column, kept beside the payload for the assertions.
			payload["changes"] = audittest.DecodeChanges(t, changes)
			if actor != f.a.userID.String() || scope != f.a.scopeID.String() || resourceType != "site" ||
				resourceID != created.Site.ID.String() || outcome != "success" {
				t.Fatalf("event envelope = %s %s %s %s %s", actor, scope, resourceType, resourceID, outcome)
			}
			result = append(result, payload)
		}
		return result
	}
	if got := update(boolPointer(true)); !got.CacheSharedAcrossDomains {
		t.Fatal("turning sharing on did not stick")
	}
	if got := update(nil); !got.CacheSharedAcrossDomains {
		t.Fatal("an update without the option changed it")
	}
	update(boolPointer(true))
	if got := update(boolPointer(false)); got.CacheSharedAcrossDomains {
		t.Fatal("turning sharing off did not stick")
	}
	recorded := events()
	if len(recorded) != 2 {
		t.Fatalf("cache sharing audit events = %d, want 2 (on, off): %v", len(recorded), recorded)
	}
	for index, want := range []struct{ from, to bool }{{false, true}, {true, false}} {
		payload := recorded[index]
		changes, _ := payload["changes"].([]audit.Change)
		change, _ := audittest.Find(changes, "cache_shared_across_domains")
		if payload["ip"] != "198.51.100.7" || payload["site_domain"] != created.Site.Domain ||
			change.Before != want.from || change.After != want.to {
			t.Fatalf("event %d payload = %v", index, payload)
		}
	}
}

func boolPointer(value bool) *bool { return &value }
