//go:build integration

package acmehttp01

import (
	"slices"
	"testing"

	"github.com/jackc/pgx/v5"
)

// HTTP-01 申请受理时，域名必须是本作用域在用站点且线路组有服务节点
// （与 PublishChallenge 的 ErrNoTarget / ErrInvalidChallenge 同一判定）；解析指向别处只提示。
func TestOrderReadinessMatchesPublishGate(t *testing.T) {
	f := newNodeFixture(t, true)
	check := func(domains ...string) (string, []string) {
		t.Helper()
		var notServing string
		var elsewhere []string
		if err := pgx.BeginFunc(t.Context(), f.pool, func(tx pgx.Tx) error {
			var err error
			notServing, elsewhere, err = OrderReadiness(t.Context(), tx, f.scope, domains)
			return err
		}); err != nil {
			t.Fatal(err)
		}
		return notServing, elsewhere
	}
	if notServing, elsewhere := check("a.example.test", "b.example.test"); notServing != "" || len(elsewhere) != 0 {
		t.Fatalf("served sites: notServing=%q elsewhere=%v", notServing, elsewhere)
	}
	if notServing, _ := check("a.example.test", "c.example.test"); notServing != "c.example.test" {
		t.Fatalf("unknown domain: notServing=%q", notServing)
	}
	seedTx(t, f.pool, func(exec func(string, ...any)) {
		exec(`INSERT INTO site_dns_resolution_checks(site_id,scope_id,ok,detail,cname,domains,results,next_check_at,
			checked_at,created_at,updated_at) VALUES($1,$2,false,'dns_points_elsewhere','x.cname.test',ARRAY['b.example.test'],
			'[{"domain":"b.example.test","code":"dns_points_elsewhere","observed":["203.0.113.9"]}]',now(),now(),now(),now())`,
			f.sites["b.example.test"], f.scope)
	})
	if notServing, elsewhere := check("a.example.test", "b.example.test"); notServing != "" || !slices.Equal(elsewhere, []string{"b.example.test"}) {
		t.Fatalf("dns elsewhere: notServing=%q elsewhere=%v", notServing, elsewhere)
	}
	seedTx(t, f.pool, func(exec func(string, ...any)) {
		exec(`UPDATE node_line_endpoints SET enabled=false WHERE line_group_id=$1`, f.group)
	})
	if notServing, _ := check("a.example.test"); notServing != "a.example.test" {
		t.Fatalf("no serving node: notServing=%q", notServing)
	}
}
