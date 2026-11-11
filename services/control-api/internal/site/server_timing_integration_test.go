//go:build integration

package site

import (
	"context"
	"testing"

	"github.com/cdnca/cdnca/services/control-api/internal/audit"
	"github.com/cdnca/cdnca/services/control-api/internal/audit/audittest"
)

// Migration 651: Server-Timing 响应头 is off on a new
// site; turning it on or off writes site.server_timing.update with the
// before -> after value and advances the scope's source revision; an update
// without the field keeps it and writes no event.
func TestSiteServerTimingWriteAuditAndRevision(t *testing.T) {
	f := newTrustFixture(t)
	created, err := f.createSite(f.a, f.a, "server-timing.example.test")
	if err != nil {
		t.Fatal(err)
	}
	if created.Site.ServerTiming {
		t.Fatal("a new site answers Server-Timing")
	}
	revision := created.Site.Revision
	sourceRevision := func() int64 {
		t.Helper()
		var value int64
		if err := f.pool.QueryRow(context.Background(), `SELECT source_revision FROM edge_configuration_scopes WHERE scope_id=$1`,
			f.a.scopeID).Scan(&value); err != nil {
			t.Fatal(err)
		}
		return value
	}
	update := func(enabled *bool) Site {
		t.Helper()
		key := f.key("update")
		result, err := f.sites.Update(context.Background(), f.a.siteActor(), UpdateRequest{
			ID: created.Site.ID, ExpectedRevision: revision, IdempotencyKey: key, RequestID: key, SourceIP: "198.51.100.9",
			Fields: SiteFields{Domains: []string{"server-timing.example.test"},
				HTTPPorts: []string{"80"}, Origins: []string{"192.0.2.1"}, Enabled: true,
				Status: StatusActive, ServerTiming: enabled},
		})
		if err != nil {
			t.Fatalf("update server_timing=%v: %v", enabled, err)
		}
		revision = result.Site.Revision
		return result.Site
	}
	before := sourceRevision()
	if got := update(boolPointer(true)); !got.ServerTiming {
		t.Fatal("turning Server-Timing on did not stick")
	}
	if after := sourceRevision(); after <= before {
		t.Fatalf("source revision %d -> %d: the switch must advance it", before, after)
	}
	if got := update(nil); !got.ServerTiming {
		t.Fatal("an update without server_timing changed it")
	}
	if got := update(boolPointer(false)); got.ServerTiming {
		t.Fatal("turning Server-Timing off did not stick")
	}
	var stored bool
	if err := f.pool.QueryRow(context.Background(), `SELECT server_timing FROM sites WHERE id=$1`, created.Site.ID).Scan(&stored); err != nil || stored {
		t.Fatalf("stored server_timing = %v (%v)", stored, err)
	}
	rows, err := f.pool.Query(context.Background(), `SELECT resource_id,result,changes FROM audit_events
		WHERE action='site.server_timing.update' ORDER BY stream_position`)
	if err != nil {
		t.Fatal(err)
	}
	defer rows.Close()
	var recorded [][]audit.Change
	for rows.Next() {
		var resourceID, outcome string
		var changes []byte
		if err := rows.Scan(&resourceID, &outcome, &changes); err != nil {
			t.Fatal(err)
		}
		if resourceID != created.Site.ID.String() || outcome != "success" {
			t.Fatalf("event envelope = %s %s", resourceID, outcome)
		}
		recorded = append(recorded, audittest.DecodeChanges(t, changes))
	}
	if len(recorded) != 2 {
		t.Fatalf("server timing audit events = %d, want 2 (on, off)", len(recorded))
	}
	for index, want := range []struct{ from, to bool }{{false, true}, {true, false}} {
		change, _ := audittest.Find(recorded[index], "server_timing")
		if change.Before != want.from || change.After != want.to {
			t.Fatalf("event %d change = %+v", index, change)
		}
	}
}
