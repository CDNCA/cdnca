//go:build integration

package migrations_test

import (
	"testing"
	"time"

	"github.com/google/uuid"
)

// 661: up/down/up restores 660 object for object; the
// backfill turns a month of stored samples into hour buckets (usage adds the
// counter steps, a counter that went down counts as a reset, a gap over five
// minutes is flagged) and the down drops the table.
func TestNodeTrafficHourly661UpDownUp(t *testing.T) {
	pool := migrationPoolAt(t, 660)
	ctx := t.Context()
	scope, user, node := uuid.New(), uuid.New(), uuid.New()
	for _, statement := range []struct {
		sql  string
		args []any
	}{
		{`INSERT INTO access_scopes(id,kind) VALUES($1,'platform')`, []any{scope}},
		{`INSERT INTO users(id,username,display_name,password_hash) VALUES($1,'hourly661','H','test-only')`, []any{user}},
		{`INSERT INTO nodes(id,scope_id,name,admin_state,created_by_user_id,display_id) VALUES($1,$2,'n661','active',$3,661)`, []any{node, scope, user}},
	} {
		if _, err := pool.Exec(ctx, statement.sql, statement.args...); err != nil {
			t.Fatal(err)
		}
	}
	// 同一小时内：0s(100,100) 10s(200,150) 20s(50,60 重置) 30s+10min(70,80 缺口)；下一小时 0s(90,100 重置)。
	hour := time.Now().UTC().Truncate(time.Hour).Add(-time.Hour)
	points := []struct {
		offset time.Duration
		rx, tx int
	}{{0, 100, 100}, {10 * time.Second, 200, 150}, {20 * time.Second, 50, 60}, {10*time.Minute + 20*time.Second, 70, 80}, {time.Hour, 90, 100}}
	for index, point := range points {
		if _, err := pool.Exec(ctx, `
			INSERT INTO node_metric_samples(event_id,request_id,node_id,schema_version,config_revision,publication_sequence,observed_at,
				record_kind,metrics_known,cpu_percent,memory_used_bytes,memory_total_bytes,active_connections,rx_bandwidth_bps,tx_bandwidth_bps,
				telemetry_json,total_rx_bytes,total_tx_bytes,puback_stream,puback_sequence,consumer_durable,consumer_sequence,num_delivered,wire_sha256)
			VALUES(gen_random_uuid(),gen_random_uuid(),$1::uuid,1,0,$2::bigint,$3,'host_metric',true,1,1,2,0,0,0,
				jsonb_build_object('schema_version',1,
					'network_selection',jsonb_build_object('source','default_route','interfaces',jsonb_build_array('eth0')),
					'network_interfaces',jsonb_build_array(jsonb_build_object('name','eth0','rx_bytes',$4::bigint,'tx_bytes',$5::bigint,'rx_bandwidth_bps',0,'tx_bandwidth_bps',0)),
					'total_rx_bytes',$4::bigint,'total_tx_bytes',$5::bigint),
				$4,$5,'NODE_MONITORING_STATUS',$2::bigint,'control_api_node_metrics',$2::bigint,1,decode(md5($2::bigint::text)||md5($1::uuid::text),'hex'))`,
			node, index+1, hour.Add(point.offset), point.rx, point.tx); err != nil {
			t.Fatalf("sample %d: %v", index, err)
		}
	}
	migrationUpDownUp(t, pool, 661)
	type bucket struct {
		samples, resets int
		usage           string
		gap             bool
	}
	got := map[time.Time]bucket{}
	rows, err := pool.Query(ctx, `SELECT hour_start,samples,usage_bytes::text,counter_resets,has_gap FROM node_traffic_hourly WHERE node_id=$1`, node)
	if err != nil {
		t.Fatal(err)
	}
	for rows.Next() {
		var at time.Time
		var item bucket
		if err := rows.Scan(&at, &item.samples, &item.usage, &item.resets, &item.gap); err != nil {
			t.Fatal(err)
		}
		got[at.UTC()] = item
	}
	rows.Close()
	// 第一小时：(200-100)+(150-100)=150，(50 重置取当前 50)+(60)=110，(70-50)+(80-60)=40 → 300，缺口。第二小时单点。
	want := map[time.Time]bucket{hour: {4, 1, "300", true}, hour.Add(time.Hour): {1, 0, "0", false}}
	if len(got) != len(want) || got[hour] != want[hour] || got[hour.Add(time.Hour)] != want[hour.Add(time.Hour)] {
		t.Fatalf("backfilled buckets = %+v, want %+v", got, want)
	}
	if _, err := pool.Exec(ctx, `DELETE FROM nodes WHERE id=$1`, node); err == nil {
		// 节点被删时汇总随之级联删除（样本表 RESTRICT 阻止时不会走到这里）。
		var left int
		_ = pool.QueryRow(ctx, `SELECT count(*) FROM node_traffic_hourly WHERE node_id=$1`, node).Scan(&left)
		if left != 0 {
			t.Fatalf("hour buckets survived node delete: %d", left)
		}
	}
}
