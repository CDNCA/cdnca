//go:build integration

package acmehttp01

import (
	"fmt"
	"strings"
	"testing"

	"github.com/cdnca/cdnca/services/control-api/internal/node"
	"github.com/google/uuid"
	"github.com/jackc/pgx/v5"
)

// keepEndpoints moves the fixture's line group to a new current revision that
// lists only the kept nodes (the others left the line group).
func (f *nodeFixture) keepEndpoints(t *testing.T, kept ...uuid.UUID) {
	t.Helper()
	seedTx(t, f.pool, func(exec func(string, ...any)) {
		exec(`UPDATE node_line_groups SET current_revision=current_revision+1,updated_at=now() WHERE id=$1`, f.group)
		for index, item := range kept {
			exec(`INSERT INTO node_line_endpoints(id,node_id,tenant_scope_id,line_group_id,config_revision,address,
				address_family,port,region,carrier,priority,weight,enabled)
				SELECT gen_random_uuid(),$1,group_row.tenant_scope_id,group_row.id,group_row.current_revision,$3::inet,4,80,
				       'cn','BGP',0,1,true
				FROM node_line_groups group_row WHERE group_row.id=$2`, item, f.group, fmt.Sprintf("198.51.100.%d", index+1))
		}
	})
}

// purge deletes the node through the administrator path (node.Store, ADR 0006).
func (f *nodeFixture) purge(t *testing.T, target uuid.UUID) error {
	t.Helper()
	var platform uuid.UUID
	var revision int64
	if err := f.pool.QueryRow(t.Context(), `SELECT scope_id,revision FROM nodes WHERE id=$1`, target).Scan(&platform, &revision); err != nil {
		t.Fatal(err)
	}
	retired := node.StateRetired
	_, err := node.NewStore(f.pool).Update(t.Context(), node.Actor{UserID: f.user, ScopeID: platform}, node.UpdateRequest{
		ID: target, ExpectedRevision: revision, Fields: node.UpdateFields{AdminState: &retired},
		IdempotencyKey: "purge-" + target.String(), RequestID: uuid.NewString(),
	}, [32]byte{1})
	return err
}

// nodeRows lists every table that references nodes (directly or through
// node-owned rows) and still holds a row naming node.
func (f *nodeFixture) nodeRows(t *testing.T, target uuid.UUID) []string {
	t.Helper()
	rows, err := f.pool.Query(t.Context(), `
		WITH RECURSIVE closure(relation) AS (
			SELECT conrelid FROM pg_constraint WHERE contype='f' AND confrelid=(current_schema()||'.nodes')::regclass
			UNION
			SELECT c.conrelid FROM pg_constraint c JOIN closure ON c.confrelid=closure.relation WHERE c.contype='f'
		)
		SELECT DISTINCT relation::regclass::text FROM closure
		JOIN pg_attribute attribute ON attribute.attrelid=closure.relation
		WHERE attribute.attname='node_id' AND NOT attribute.attisdropped`)
	if err != nil {
		t.Fatal(err)
	}
	tables, err := pgx.CollectRows(rows, pgx.RowTo[string])
	if err != nil {
		t.Fatal(err)
	}
	var left []string
	for _, table := range tables {
		var count int
		if err := f.pool.QueryRow(t.Context(), `SELECT count(*) FROM `+pgx.Identifier{table}.Sanitize()+
			` WHERE node_id=$1`, target).Scan(&count); err != nil {
			t.Fatal(err)
		}
		if count != 0 {
			left = append(left, table)
		}
	}
	return left
}

// A purged node's HTTP-01 generations, deliveries, challenge targets, epoch
// memberships, debts and coverage go with it (the node no longer exists, its
// tokens mean nothing). The site's frozen epoch keeps its member count and
// digest through a tombstone, so the surviving member still confirms the
// challenge, the epoch still closes, and no other node's facts change.
func TestNodeHTTP01NodePurgeRemovesHTTP01Facts(t *testing.T) {
	f := newNodeFixture(t, true, true, true)
	n0, n1, n2 := f.nodes[0], f.nodes[1], f.nodes[2]
	a := f.challenge(t, "a.example.test")
	if err := f.store.PublishChallenge(t.Context(), a); err != nil {
		t.Fatal(err)
	}
	f.healthyAll(t)
	// n1 leaves the line group and is released with a debt; n2 leaves too but
	// is purged before any reconcile releases it.
	f.keepEndpoints(t, n0, n2)
	f.reconcile(t)
	f.deliver(t)
	if got := f.debtEvents(t, "a.example.test", n1); len(got) == 0 {
		t.Fatal("n1 owes no debt before its purge")
	}
	f.keepEndpoints(t, n0)
	var before int
	if err := f.pool.QueryRow(t.Context(), `SELECT count(*) FROM acme_http01_node_overlay_generations WHERE node_id=$1`,
		n0).Scan(&before); err != nil {
		t.Fatal(err)
	}
	for _, purged := range []uuid.UUID{n1, n2} {
		if err := f.purge(t, purged); err != nil {
			t.Fatalf("purge %s: %v", purged, err)
		}
		if left := f.nodeRows(t, purged); len(left) != 0 {
			t.Fatalf("rows left after purging %s: %s", purged, strings.Join(left, ","))
		}
	}
	var tombstones int
	if err := f.pool.QueryRow(t.Context(), `SELECT count(*) FROM acme_http01_site_overlay_epoch_purged_members
		WHERE node_id=ANY($1::uuid[])`, []uuid.UUID{n1, n2}).Scan(&tombstones); err != nil || tombstones != 2 {
		t.Fatalf("epoch tombstones %d %v", tombstones, err)
	}
	var after int
	if err := f.pool.QueryRow(t.Context(), `SELECT count(*) FROM acme_http01_node_overlay_generations WHERE node_id=$1`,
		n0).Scan(&after); err != nil || after != before {
		t.Fatalf("surviving node generations %d -> %d %v", before, after, err)
	}
	status := f.status(t, a)
	if len(status.Confirmed) != 1 || status.Confirmed[0] != n0 || len(status.Pending)+len(status.Failed)+len(status.Released) != 0 {
		t.Fatalf("challenge status after purge %+v", status)
	}
	// Reconcile and a second site still work on the epoch with tombstones,
	// and the final empty cleanup closes it.
	f.reconcile(t)
	if err := f.store.WithdrawChallenge(t.Context(), a); err != nil {
		t.Fatal(err)
	}
	var open bool
	if err := f.pool.QueryRow(t.Context(), `SELECT open_epoch_id IS NOT NULL FROM acme_http01_site_overlay_states
		WHERE site_id=$1`, f.sites["a.example.test"]).Scan(&open); err != nil || open {
		t.Fatalf("epoch still open after the final cleanup: %v %v", open, err)
	}
	b := f.challenge(t, "b.example.test")
	if err := f.store.PublishChallenge(t.Context(), b); err != nil {
		t.Fatal(err)
	}
	if got := f.status(t, b); len(got.Pending) != 1 || got.Pending[0] != n0 {
		t.Fatalf("new challenge after purge %+v", got)
	}
}

// Only the purge path may delete HTTP-01 facts: without the purge marker,
// with the marker of another node, or without deleting the node itself the
// delete is refused.
func TestNodeHTTP01FactsSurviveOutsidePurge(t *testing.T) {
	f := newNodeFixture(t, true, true)
	n1 := f.nodes[1]
	a := f.challenge(t, "a.example.test")
	if err := f.store.PublishChallenge(t.Context(), a); err != nil {
		t.Fatal(err)
	}
	f.healthyAll(t)
	run := func(marker uuid.UUID, statements ...string) error {
		return pgx.BeginFunc(t.Context(), f.pool, func(tx pgx.Tx) error {
			if marker != uuid.Nil {
				if _, err := tx.Exec(t.Context(), `SELECT set_config('cdnca.node_purge', $1, true)`, marker.String()); err != nil {
					return err
				}
			}
			for _, statement := range statements {
				if _, err := tx.Exec(t.Context(), statement, n1); err != nil {
					return err
				}
			}
			return nil
		})
	}
	wantCode(t, "delete without marker", run(uuid.Nil, `DELETE FROM acme_http01_node_overlay_deliveries WHERE node_id=$1`), "P3376")
	wantCode(t, "delete with the marker, node kept", run(n1, `DELETE FROM acme_http01_node_challenge_targets WHERE node_id=$1`), "P3462")
	wantCode(t, "purge function without marker", run(uuid.Nil, `SELECT acme_http01_purge_node_346($1)`), "P3463")
	wantCode(t, "purge function, marker of another node", run(f.nodes[0], `SELECT acme_http01_purge_node_346($1)`), "P3463")
	wantCode(t, "purge function, node kept", run(n1, `SELECT acme_http01_purge_node_346($1)`), "P3462")
	wantCode(t, "tombstone outside a purge", run(uuid.Nil, `INSERT INTO acme_http01_site_overlay_epoch_purged_members(epoch_id,node_id,purged_at)
		SELECT epoch_id,node_id,now() FROM acme_http01_site_overlay_epoch_members WHERE node_id=$1`), "P3461")
	var deliveries int
	if err := f.pool.QueryRow(t.Context(), `SELECT count(*) FROM acme_http01_node_overlay_deliveries WHERE node_id=$1`,
		n1).Scan(&deliveries); err != nil || deliveries == 0 {
		t.Fatalf("n1 deliveries %d %v", deliveries, err)
	}
}
