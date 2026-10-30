//go:build integration

package entitlementusage

import (
	"testing"
	"time"

	"github.com/cdnca/cdnca/libs/entitlement"
	"github.com/cdnca/cdnca/services/control-api/internal/database/databasetest"
	"github.com/cdnca/cdnca/services/control-api/internal/entitlementsync"
	"github.com/google/uuid"
	"github.com/jackc/pgx/v5"
)

// fix-usagereport：在迁移到头的真实库上采集 13 码（每条 SQL 都对真实表结构执行）；
// sites.count 只计未删除网站（停用也计），月流量取本 UTC 自然月，发布渠道取平台策略当前允许数。
func TestCollectAllThirteenCodesPostgreSQL(t *testing.T) {
	pool := databasetest.MigratedPool(t, nil)
	ctx := t.Context()
	now := time.Date(2026, 10, 27, 10, 30, 15, 0, time.UTC)
	tenant, scope, user := uuid.New(), uuid.New(), uuid.New()
	for _, statement := range []struct {
		query string
		args  []any
	}{
		{`INSERT INTO tenants(id,display_name) VALUES($1,'usage')`, []any{tenant}},
		{`INSERT INTO access_scopes(id,kind,tenant_id) VALUES($1,'tenant',$2)`, []any{scope, tenant}},
		{`INSERT INTO users(id,username,display_name,password_hash,created_at,updated_at) VALUES($1,$2,'u','hash',$3,$3)`, []any{user, "usage-" + user.String(), now}},
		{`INSERT INTO memberships(scope_id,user_id,created_at) VALUES($1,$2,$3)`, []any{scope, user, now}},
	} {
		if _, err := pool.Exec(ctx, statement.query, statement.args...); err != nil {
			t.Fatal(err)
		}
	}
	for index, state := range []string{"active", "disabled", "deleted"} {
		site := uuid.New()
		var deletedAt any
		if state == "deleted" {
			deletedAt = now
		}
		err := pgx.BeginFunc(ctx, pool, func(tx pgx.Tx) error {
			if _, err := tx.Exec(ctx, `INSERT INTO sites(id,display_id,scope_id,owner_user_id,domain,http_ports,https_ports,
				origins,origin_hosts,cname,https_enabled,enabled,status,is_default,revision,created_by_user_id,
				updated_by_user_id,created_at,updated_at,deleted_at)
				VALUES($1,$2,$3,$4,$5,ARRAY['80'],ARRAY[]::text[],ARRAY['192.0.2.1:80'],ARRAY['192.0.2.1'],'',false,$6,
				CASE WHEN $6 THEN 'active' ELSE 'disabled' END,false,1,$4,$4,$7,$7,$8)`, site, index+1, scope, user, state+".usage.example.test",
				state == "active", now, deletedAt); err != nil {
				return err
			}
			if _, err := tx.Exec(ctx, `INSERT INTO site_origin_pools(site_id,updated_at) VALUES($1,$2)`, site, now); err != nil {
				return err
			}
			_, err := tx.Exec(ctx, `INSERT INTO site_origins(site_id,position,host,port,weight,enabled)
				VALUES($1,1,'192.0.2.1',80,1,true)`, site)
			return err
		})
		if err != nil {
			t.Fatal(err)
		}
	}
	traffic := &fakeTraffic{value: 123_456}
	observedAt, values, err := Collector{Pool: pool, Traffic: traffic, ReleaseChannels: func() int { return 3 },
		Now: func() time.Time { return now.Add(400 * time.Millisecond) }}.Collect(ctx)
	if err != nil {
		t.Fatal(err)
	}
	if !observedAt.Equal(now) || !traffic.from.Equal(time.Date(2026, 10, 1, 0, 0, 0, 0, time.UTC)) || !traffic.to.Equal(now) {
		t.Fatalf("observed=%v window=[%v,%v)", observedAt, traffic.from, traffic.to)
	}
	if len(values) != 13 {
		t.Fatalf("values=%v", values)
	}
	got := map[string]int64{}
	for index, value := range values {
		if value.Code != entitlementsync.UsageReportCodes[index] {
			t.Fatalf("order=%v", values)
		}
		got[value.Code] = value.Used
	}
	want := map[string]int64{
		entitlement.QuotaSitesCount: 2, entitlement.QuotaMonthlyTrafficBytes: 123_456, entitlement.QuotaReleaseChannelsCount: 3,
	}
	for code, used := range got {
		if used != want[code] {
			t.Errorf("%s=%d want %d", code, used, want[code])
		}
	}
}
