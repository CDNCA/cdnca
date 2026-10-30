//go:build integration

package node

import (
	"slices"
	"testing"

	"github.com/cdnca/cdnca/services/control-api/internal/database/databasetest"
	"github.com/google/uuid"
)

// fix-nodeipgeo: the resolver writes the automatic IP 归属 of new and
// existing nodes, re-resolves on an address or library change, never
// overwrites manual fields, is idempotent, and an update's
// ip_location_manual marks and restores fields.
func TestNodeIPLocationResolverPostgres(t *testing.T) {
	pool := databasetest.MigratedPool(t, nil)
	ctx := t.Context()
	var platform, user uuid.UUID
	// The migrated template holds no scopes; create the platform scope.
	platform = uuid.New()
	if _, err := pool.Exec(ctx, `INSERT INTO access_scopes(id,kind) VALUES($1,'platform')`, platform); err != nil {
		t.Fatal(err)
	}
	user = uuid.New()
	if _, err := pool.Exec(ctx, `INSERT INTO users(id,username,display_name,password_hash) VALUES($1,$2,'ipgeo','unused')`, user, "ipgeo-"+user.String()[:8]); err != nil {
		t.Fatal(err)
	}
	nodeID := uuid.New()
	if _, err := pool.Exec(ctx, `INSERT INTO nodes(id,display_id,scope_id,name,ipv4,created_by_user_id)
		VALUES($1,9001,$2,'ipgeo','192.0.2.10',$3)`, nodeID, platform, user); err != nil {
		t.Fatal(err)
	}
	library := &IPLocationLibrary{Revision: 1, Version: "v1"}
	source := &fakeIPLocationSource{library: library, answers: map[string]*NodeIPLocation{
		"192.0.2.10": &shanghai, "198.51.100.1": &tokyo,
	}}
	resolver := NewIPLocationResolver(pool, source, nil)
	run := func(want int) {
		t.Helper()
		written, err := resolver.RunOnce(ctx)
		if err != nil || written != want {
			t.Fatalf("RunOnce() = %d, %v; want %d", written, err, want)
		}
	}
	store := NewStore(pool)
	view := func() IPLocationView {
		t.Helper()
		got, err := store.IPLocation(ctx, platform, nodeID)
		if err != nil {
			t.Fatal(err)
		}
		return got
	}

	run(1)
	got := view()
	if got.Effective != shanghai || got.Resolution == nil || got.Resolution.Outcome != IPLocationResolved ||
		got.Resolution.Address != "192.0.2.10" || got.Resolution.LibraryVersion != "v1" {
		t.Fatalf("resolved view = %#v %#v", got, got.Resolution)
	}
	run(0) // idempotent

	// manual city survives a re-resolution; 恢复自动 brings it back
	current, err := store.Get(ctx, platform, nodeID)
	if err != nil {
		t.Fatal(err)
	}
	settings := current.ManagementSettings
	settings.IPLocation.City = "杭州"
	settings.IPLocationManual = []string{"city"}
	_, err = store.Update(ctx, Actor{UserID: user, ScopeID: platform}, UpdateRequest{
		ID: nodeID, ExpectedRevision: current.Revision, Fields: UpdateFields{ManagementSettings: &settings},
		IdempotencyKey: uuid.NewString(), RequestID: "ipgeo-manual",
	}, [32]byte{1})
	if err != nil {
		t.Fatal(err)
	}
	ipv4 := "198.51.100.1"
	if _, err := pool.Exec(ctx, `UPDATE nodes SET ipv4=$2 WHERE id=$1`, nodeID, ipv4); err != nil {
		t.Fatal(err)
	}
	run(1)
	got = view()
	if got.Effective.City != "杭州" || got.Effective.CountryCode != "JP" || !slices.Equal(got.Manual, []string{"city"}) {
		t.Fatalf("after address change = %#v", got)
	}

	library.Revision = 2 // a new library re-resolves every node
	run(1)
	if got := view(); got.Resolution.LibraryRevision != 2 {
		t.Fatalf("library revision = %d", got.Resolution.LibraryRevision)
	}

	current, err = store.Get(ctx, platform, nodeID)
	if err != nil {
		t.Fatal(err)
	}
	settings = current.ManagementSettings
	settings.IPLocationManual = []string{}
	if _, err := store.Update(ctx, Actor{UserID: user, ScopeID: platform}, UpdateRequest{
		ID: nodeID, ExpectedRevision: current.Revision, Fields: UpdateFields{ManagementSettings: &settings},
		IdempotencyKey: uuid.NewString(), RequestID: "ipgeo-restore",
	}, [32]byte{2}); err != nil {
		t.Fatal(err)
	}
	if got := view(); got.Effective != tokyo || len(got.Manual) != 0 {
		t.Fatalf("restored = %#v", got)
	}

	source.answers = nil // not in the library: "unresolved", values cleared
	library.Revision = 3
	run(1)
	if got := view(); got.Resolution.Outcome != IPLocationUnresolved || got.Effective != (NodeIPLocation{}) {
		t.Fatalf("unresolved = %#v", got)
	}
}
