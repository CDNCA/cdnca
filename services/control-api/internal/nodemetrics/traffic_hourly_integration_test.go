//go:build integration

package nodemetrics

import (
	"crypto/sha256"
	"encoding/binary"
	"fmt"
	"math/rand"
	"reflect"
	"strings"
	"testing"
	"time"

	"github.com/cdnca/cdnca/services/control-api/internal/database/databasetest"
	controlmigrations "github.com/cdnca/cdnca/services/control-api/migrations"
	"github.com/google/uuid"
	"github.com/jackc/pgx/v5/pgxpool"
)

// 小时桶算法必须与逐样本扫描逐字段相同：同一批样本（含计数器重置、缺口、乱序、
// 同一时刻、两块网卡）经 Put 入库后，两种算法给出同一个 MonthlyTraffic。
func TestHourlyTrafficMatchesRawScan(t *testing.T) {
	pool := databasetest.MigratedPool(t, nil)
	scope, nodeIDs, now := seedHourlyFixture(t, pool)
	reader := &PostgresReader{pool: pool}
	checkHourlyAgainstScan(t, reader, scope, nodeIDs, now)
}

// 迁移 661 的回填 SQL 与入库路径给出逐行相同的小时汇总表。
func TestHourlyTrafficBackfillMatchesIngest(t *testing.T) {
	pool := databasetest.MigratedPool(t, nil)
	ctx := t.Context()
	scope, nodeIDs, now := seedHourlyFixture(t, pool)
	const dump = `SELECT node_id::text||'|'||hour_start::text||'|'||samples||'|'||first_observed_at::text||'|'||first_rx||'|'||first_tx||
		'|'||last_observed_at::text||'|'||last_rx||'|'||last_tx||'|'||usage_bytes||'|'||counter_resets||'|'||has_gap
		FROM node_traffic_hourly ORDER BY node_id,hour_start`
	collect := func() []string {
		rows, err := pool.Query(ctx, dump)
		if err != nil {
			t.Fatal(err)
		}
		defer rows.Close()
		var lines []string
		for rows.Next() {
			var line string
			if err := rows.Scan(&line); err != nil {
				t.Fatal(err)
			}
			lines = append(lines, line)
		}
		return lines
	}
	ingest := collect()
	script, err := controlmigrations.FS.ReadFile("661_node_traffic_hourly.up.sql")
	if err != nil {
		t.Fatal(err)
	}
	backfill := string(script[strings.Index(string(script), "DO $migration_661_backfill$"):])
	if _, err := pool.Exec(ctx, "TRUNCATE node_traffic_hourly"); err != nil {
		t.Fatal(err)
	}
	if _, err := pool.Exec(ctx, backfill); err != nil {
		t.Fatal(err)
	}
	filled := collect()
	if len(ingest) < 100 || !reflect.DeepEqual(ingest, filled) {
		t.Fatalf("backfill differs from ingest: ingest=%d rows backfill=%d rows", len(ingest), len(filled))
	}
	checkHourlyAgainstScan(t, &PostgresReader{pool: pool}, scope, nodeIDs, now)
}

func seedHourlyFixture(t *testing.T, pool *pgxpool.Pool) (uuid.UUID, []uuid.UUID, time.Time) {
	t.Helper()
	ctx := t.Context()
	scope, user := uuid.New(), uuid.New()
	for _, statement := range []string{
		`INSERT INTO access_scopes(id,kind) VALUES($1,'platform')`,
	} {
		if _, err := pool.Exec(ctx, statement, scope); err != nil {
			t.Fatal(err)
		}
	}
	if _, err := pool.Exec(ctx, `INSERT INTO users(id,username,display_name,password_hash) VALUES($1,'hourly','Hourly','test-only')`, user); err != nil {
		t.Fatal(err)
	}
	store, _ := NewPostgresStore(pool)
	now := time.Now().UTC().Truncate(time.Second)
	monthStart := time.Date(now.Year(), now.Month(), 1, 0, 0, 0, 0, time.UTC).Add(-8 * time.Hour)
	if monthStart.After(now) {
		monthStart = monthStart.AddDate(0, -1, 0)
	}
	random := rand.New(rand.NewSource(20261113))
	var sequence uint64
	nodeIDs := make([]uuid.UUID, 0, 8)
	for node := 0; node < 8; node++ {
		id := uuid.New()
		nodeIDs = append(nodeIDs, id)
		if _, err := pool.Exec(ctx, `INSERT INTO nodes(id,scope_id,name,admin_state,created_by_user_id,display_id) VALUES($1,$2,$3,'active',$4,$5)`,
			id, scope, fmt.Sprintf("hourly-%d", node), user, 900+node); err != nil {
			t.Fatal(err)
		}
		span := now.Sub(monthStart)
		var rx, tx uint64
		at := monthStart.Add(time.Duration(random.Int63n(int64(time.Hour))))
		for at.Before(now.Add(-time.Minute)) {
			switch random.Intn(40) {
			case 0: // 计数器归零（重启）
				rx, tx = uint64(random.Intn(1000)), uint64(random.Intn(1000))
			case 1: // 只有一个方向归零
				rx = uint64(random.Intn(50))
			default:
				rx += uint64(random.Intn(1 << 20))
				tx += uint64(random.Intn(1 << 20))
			}
			sequence++
			observed := at
			switch random.Intn(12) {
			case 0: // 乱序：比序号晚到的旧样本
				observed = at.Add(-time.Duration(random.Int63n(int64(3 * time.Hour))))
			case 1: // 与上一个样本同一时刻
				observed = at.Add(-time.Duration(random.Intn(3)) * 10 * time.Second)
			}
			if observed.Before(monthStart.Add(-30 * time.Minute)) {
				observed = monthStart.Add(-30 * time.Minute)
			}
			if err := putCounterSample(t, store, id, sequence, observed.Truncate(time.Microsecond), rx, tx); err != nil {
				t.Fatal(err)
			}
			step := 10 * time.Second
			if random.Intn(60) == 0 {
				step = time.Duration(6+random.Intn(90)) * time.Minute // 缺口
			} else if random.Intn(15) == 0 {
				step = time.Duration(random.Int63n(int64(3 * time.Hour / 50)))
			}
			if span > 20*24*time.Hour {
				step *= 40 // 样本稀疏些，控制测试时长
			}
			at = at.Add(step)
		}
	}
	return scope, nodeIDs, now
}

func checkHourlyAgainstScan(t *testing.T, reader *PostgresReader, scope uuid.UUID, nodeIDs []uuid.UUID, now time.Time) {
	t.Helper()
	ctx := t.Context()
	got, err := reader.monthlyTraffic(ctx, scope, nodeIDs, now)
	if err != nil {
		t.Fatal(err)
	}
	periods := map[uuid.UUID]trafficPeriod{}
	want := map[uuid.UUID]MonthlyTraffic{}
	local := now.In(time.FixedZone("x", 8*3600))
	for _, id := range nodeIDs {
		start := time.Date(local.Year(), local.Month(), 1, 0, 0, 0, 0, time.FixedZone("x", 8*3600)).UTC()
		end := time.Date(local.Year(), local.Month()+1, 1, 0, 0, 0, 0, time.FixedZone("x", 8*3600)).UTC()
		periods[id] = trafficPeriod{start: start, end: end}
		item := got[id]
		item.UsageBytes, item.CounterResets, item.Samples, item.SourceFinalizedThrough, item.State = 0, 0, 0, nil, "insufficient_data"
		want[id] = item
	}
	if err := reader.scanTraffic(ctx, scope, nodeIDs, periods, want, now.Add(-40*24*time.Hour), now); err != nil {
		t.Fatal(err)
	}
	for _, id := range nodeIDs {
		if !reflect.DeepEqual(got[id], want[id]) {
			t.Errorf("node %s: hourly=%+v scan=%+v", id, got[id], want[id])
		}
		if want[id].Samples < 100 || want[id].CounterResets == 0 {
			t.Errorf("node %s: fixture too weak: %+v", id, want[id])
		}
	}
}

func putCounterSample(t *testing.T, store *PostgresStore, node uuid.UUID, sequence uint64, observed time.Time, rx, tx uint64) error {
	t.Helper()
	// 两块网卡，选中的合计为 rx/tx。
	telemetry := &Telemetry{SchemaVersion: 1,
		NetworkSelection: &NetworkSelection{Source: "default_route", Interfaces: []string{"eth0", "eth1"}},
		NetworkInterfaces: []NetworkInterface{
			{Name: "eth0", RXBytes: rx / 2, TXBytes: tx / 2}, {Name: "eth1", RXBytes: rx - rx/2, TXBytes: tx - tx/2},
			{Name: "lo", RXBytes: 5, TXBytes: 5}},
		TotalRXBytes: rx, TotalTXBytes: tx}
	var hash [32]byte
	binary.BigEndian.PutUint64(hash[:], sequence)
	sample := Sample{EventID: uuid.NewString(), RequestID: uuid.NewString(), NodeID: node.String(), SchemaVersion: 1,
		Kind: RecordHostMetric, PublicationSequence: sequence, ObservedAt: observed, Known: true,
		CPUPercent: 1, MemoryUsedBytes: 1, MemoryTotalBytes: 2, Telemetry: telemetry,
		PubAckStream: NodeMonitoringStatusStream, PubAckSequence: sequence, ConsumerDurable: DefaultConsumerDurable,
		ConsumerSequence: sequence, NumDelivered: 1, WireSHA256: sha256.Sum256(hash[:])}
	_, err := store.Put(t.Context(), sample)
	return err
}

// 热更时迁移先于二进制：旧二进制在空档里写入的原始样本没有进小时桶。启动时的
// RepairRecentTraffic 从原始样本重算最近 3 小时的桶，结果必须与整月扫描相同，且可重复执行。
func TestRepairRecentTrafficMatchesRawScan(t *testing.T) {
	pool := databasetest.MigratedPool(t, nil)
	ctx := t.Context()
	scope, user, node := uuid.New(), uuid.New(), uuid.New()
	if _, err := pool.Exec(ctx, `INSERT INTO access_scopes(id,kind) VALUES($1,'platform')`, scope); err != nil {
		t.Fatal(err)
	}
	if _, err := pool.Exec(ctx, `INSERT INTO users(id,username,display_name,password_hash) VALUES($1,'repair','R','test-only')`, user); err != nil {
		t.Fatal(err)
	}
	if _, err := pool.Exec(ctx, `INSERT INTO nodes(id,scope_id,name,admin_state,created_by_user_id,display_id) VALUES($1,$2,'repair',  'active',$3,990)`, node, scope, user); err != nil {
		t.Fatal(err)
	}
	store, _ := NewPostgresStore(pool)
	now := time.Now().UTC().Truncate(time.Second)
	begin := now.Add(-150 * time.Minute)
	// 新二进制写过的第一个样本：桶里已有它。
	var sequence uint64 = 1
	if err := putCounterSample(t, store, node, sequence, begin.Truncate(time.Microsecond), 1000, 2000); err != nil {
		t.Fatal(err)
	}
	// 其后的样本由旧路径写入：直接插原始行，不维护桶。含一次重置和一个缺口。
	rx, tx := uint64(1000), uint64(2000)
	at := begin
	for at.Before(now.Add(-time.Minute)) {
		at = at.Add(10 * time.Second)
		if at.Sub(begin) > 70*time.Minute && at.Sub(begin) < 80*time.Minute {
			continue // 缺口
		}
		rx, tx = rx+700, tx+900
		if at.Sub(begin) >= 100*time.Minute && at.Sub(begin) < 100*time.Minute+10*time.Second {
			rx, tx = 40, 50 // 重启归零
		}
		sequence++
		var hash [32]byte
		binary.BigEndian.PutUint64(hash[:], sequence)
		if _, err := pool.Exec(ctx, `
			INSERT INTO node_metric_samples(event_id,request_id,node_id,schema_version,config_revision,publication_sequence,observed_at,
				record_kind,metrics_known,cpu_percent,memory_used_bytes,memory_total_bytes,active_connections,rx_bandwidth_bps,tx_bandwidth_bps,
				telemetry_json,total_rx_bytes,total_tx_bytes,puback_stream,puback_sequence,consumer_durable,consumer_sequence,num_delivered,wire_sha256)
			VALUES(gen_random_uuid(),gen_random_uuid(),$1::uuid,1,0,$2::bigint,$3,'host_metric',true,1,1,2,0,0,0,
				jsonb_build_object('schema_version',1,
					'network_selection',jsonb_build_object('source','default_route','interfaces',jsonb_build_array('eth0')),
					'network_interfaces',jsonb_build_array(jsonb_build_object('name','eth0','rx_bytes',$4::bigint,'tx_bytes',$5::bigint,'rx_bandwidth_bps',0,'tx_bandwidth_bps',0)),
					'total_rx_bytes',$4::bigint,'total_tx_bytes',$5::bigint),
				$4,$5,'NODE_MONITORING_STATUS',$2::bigint,'control_api_node_metrics',$2::bigint,1,$6)`,
			node, sequence, at.Truncate(time.Microsecond), rx, tx, hash[:]); err != nil {
			t.Fatal(err)
		}
	}
	reader := &PostgresReader{pool: pool}
	compare := func(label string) MonthlyTraffic {
		t.Helper()
		got, err := reader.monthlyTraffic(ctx, scope, []uuid.UUID{node}, now)
		if err != nil {
			t.Fatal(err)
		}
		loc := time.FixedZone("x", 8*3600)
		local := now.In(loc)
		periods := map[uuid.UUID]trafficPeriod{node: {
			start: time.Date(local.Year(), local.Month(), 1, 0, 0, 0, 0, loc).UTC(),
			end:   time.Date(local.Year(), local.Month()+1, 1, 0, 0, 0, 0, loc).UTC()}}
		want := map[uuid.UUID]MonthlyTraffic{node: {State: "insufficient_data", PeriodKey: got[node].PeriodKey,
			PeriodStart: got[node].PeriodStart, PeriodEnd: got[node].PeriodEnd, Timezone: got[node].Timezone}}
		if err := reader.scanTraffic(ctx, scope, []uuid.UUID{node}, periods, want, now.Add(-40*24*time.Hour), now); err != nil {
			t.Fatal(err)
		}
		if label == "after repair" && !reflect.DeepEqual(got[node], want[node]) {
			t.Fatalf("%s: buckets=%+v scan=%+v", label, got[node], want[node])
		}
		if label == "before repair" && reflect.DeepEqual(got[node], want[node]) {
			t.Fatalf("fixture too weak: old-path samples already in the buckets: %+v", got[node])
		}
		return want[node]
	}
	compare("before repair")
	if err := store.RepairRecentTraffic(ctx, now); err != nil {
		t.Fatal(err)
	}
	scanned := compare("after repair")
	if scanned.CounterResets == 0 || scanned.Samples < 500 || scanned.State != "incomplete" {
		t.Fatalf("fixture too weak: %+v", scanned)
	}
	if err := store.RepairRecentTraffic(ctx, now); err != nil { // 幂等
		t.Fatal(err)
	}
	compare("after repair")
}
