package marketprobe

import (
	"context"
	"os"
	"reflect"
	"testing"
	"time"

	"github.com/cdnca/cdnca/libs/marketproto/nodeload"
	agentv1 "github.com/cdnca/cdnca/proto/gen/go/agent/v1"
	"github.com/cdnca/cdnca/services/control-api/internal/marketclient"
	"github.com/google/uuid"
	"github.com/jackc/pgx/v5"
	"github.com/jackc/pgx/v5/pgconn"
	"github.com/jackc/pgx/v5/pgxpool"
)

// TestSyncInventoryReportsServingProbeReadyNodes runs the inventory query on a
// migrated schema (MARKET_PROBE_TEST_DATABASE_URL, with search_path set). Rows
// are seeded with replication-role triggers off: only the read side is tested.
func TestSyncInventoryReportsServingProbeReadyNodes(t *testing.T) {
	url := os.Getenv("MARKET_PROBE_TEST_DATABASE_URL")
	if url == "" {
		t.Skip("MARKET_PROBE_TEST_DATABASE_URL is not set")
	}
	ctx, cancel := context.WithTimeout(context.Background(), time.Minute)
	defer cancel()
	pool, err := pgxpool.New(ctx, url)
	if err != nil {
		t.Fatal(err)
	}
	defer pool.Close()
	capable := capabilities(t, agentv1.CapabilityName_CAPABILITY_NAME_MARKET_PROBE)
	legacy := capabilities(t, agentv1.CapabilityName_CAPABILITY_NAME_NODE_MONITORING)
	platform, user := uuid.New(), uuid.New()
	group, other := uuid.New(), uuid.New()
	ready, held, disabled, old, stale, newer := uuid.New(), uuid.New(), uuid.New(), uuid.New(), uuid.New(), uuid.New()
	probeOnly := uuid.New() // probe-capable and serving, but not join_market
	err = pgx.BeginFunc(ctx, pool, func(tx pgx.Tx) error {
		exec := func(sql string, args ...any) error {
			_, err := tx.Exec(ctx, sql, args...)
			return err
		}
		for _, step := range []func() error{
			func() error { return exec(`SET LOCAL session_replication_role = replica`) },
			func() error {
				return exec(`INSERT INTO access_scopes(id,kind) SELECT $1,'platform'
					WHERE NOT EXISTS (SELECT 1 FROM access_scopes WHERE kind='platform')`, platform)
			},
			func() error {
				return tx.QueryRow(ctx, `SELECT id FROM access_scopes WHERE kind='platform'`).Scan(&platform)
			},
			func() error {
				return exec(`INSERT INTO users(id,username,display_name,password_hash,created_at,updated_at)
					VALUES($1,$2,'probe test','x',now(),now())`, user, "probe-"+user.String()[:8])
			},
		} {
			if err := step(); err != nil {
				return err
			}
		}
		for _, node := range []struct {
			id    uuid.UUID
			state string
		}{{ready, "active"}, {held, "active"}, {disabled, "disabled"}, {old, "active"}, {stale, "active"}, {newer, "active"},
			{probeOnly, "active"}} {
			if err := exec(`INSERT INTO nodes(id,scope_id,name,admin_state,created_by_user_id,display_id)
				VALUES($1,$2,$3,$4,$5,(SELECT COALESCE(max(display_id),0)+1 FROM nodes))`,
				node.id, platform, "probe-"+node.id.String()[:8], node.state, user); err != nil {
				return err
			}
		}
		for _, g := range []struct {
			id       uuid.UUID
			revision int64
		}{{group, 2}, {other, 1}} {
			if err := exec(`INSERT INTO node_line_groups(id,tenant_scope_id,name,current_revision,created_by_user_id,
				updated_by_user_id,created_at,updated_at,display_id,resolved_value,ipv4_resolved_value)
				VALUES($1,$2,$3,$4,$5,$5,now(),now(),(SELECT COALESCE(max(display_id),0)+1 FROM node_line_groups),
				'lg-'||replace($1::uuid::text,'-',''),'lg4-'||replace($1::uuid::text,'-',''))`,
				g.id, platform, "probe-"+g.id.String()[:8], g.revision, user); err != nil {
				return err
			}
		}
		for _, e := range []struct {
			node     uuid.UUID
			group    uuid.UUID
			revision int64
			address  string
			region   string
			carrier  string
		}{
			{ready, group, 2, "2606:4700::1111", "广东", "电信"},
			{ready, group, 2, "8.8.8.8", "广东", "电信"},
			{held, group, 2, "8.8.4.4", "cn", "联通"},
			{disabled, group, 2, "9.9.9.9", "cn", "移动"},
			{old, group, 2, "1.1.1.1", "cn", "BGP"},
			{stale, group, 1, "1.0.0.1", "cn", "BGP"}, // previous revision only
			{newer, other, 1, "149.112.112.112", "cn", "BGP"},
			{probeOnly, group, 2, "8.8.8.9", "广东", "电信"},
		} {
			if err := exec(`INSERT INTO node_line_endpoints(id,node_id,tenant_scope_id,line_group_id,config_revision,address,
				address_family,port,region,carrier,priority,weight,enabled)
				VALUES($1,$2,$3,$4,$5,$6::inet,family($6::inet),80,$7,$8,0,1,true)`,
				uuid.New(), e.node, platform, e.group, e.revision, e.address, e.region, e.carrier); err != nil {
				return err
			}
		}
		// Unheld IPv4 nodes in the group keep "held" from being protected by fail-open.
		if err := exec(`INSERT INTO node_serving_holds(node_id,source,held,reason_code,revision,held_since,protected_groups,
			detail,changed_at,updated_at) VALUES($1,'availability_monitor',true,'test',1,now(),0,'{}',now(),now())`, held); err != nil {
			return err
		}
		for _, n := range []struct {
			node  uuid.UUID
			epoch int64
			caps  []byte
		}{{ready, 1, legacy}, {ready, 2, capable}, {held, 1, capable}, {disabled, 1, capable}, {old, 1, legacy},
			{stale, 1, capable}, {newer, 1, capable}, {probeOnly, 1, capable}} {
			if err := exec(`INSERT INTO node_session_capabilities(node_id,session_epoch,certificate_id,certificate_sha256,
				artifact_key_id,selected_protocol_major,selected_protocol_minor,capabilities_snapshot,capabilities_sha256,
				facts_snapshot,facts_sha256,gateway_workload_identity,gateway_instance_id,registered_at)
				VALUES($1,$2,$3,$4,'k',1,0,$5,$4,'\x00',$4,'gw','gw-1',now())`,
				n.node, n.epoch, uuid.New(), make([]byte, 32), n.caps); err != nil {
				return err
			}
		}
		for _, n := range []struct {
			node uuid.UUID
			role *string
		}{{ready, ptr("join_market")}, {held, ptr("join_market")}, {disabled, ptr("join_market")}, {old, ptr("join_market")},
			{stale, ptr("join_market")}, {newer, ptr("join_market")}, {probeOnly, ptr("probe_only")}} {
			if err := setRole(ctx, tx, n.node, n.role, true); err != nil {
				return err
			}
		}
		return nil
	})
	if err != nil {
		t.Fatal(err)
	}
	type component = struct {
		Kind        string `json:"kind"`
		NodePoolRef string `json:"node_pool_ref"`
	}
	market := &fakeMarket{offers: []marketclient.OwnOffer{{Status: "listed",
		Components: []component{{Kind: "own_pool", NodePoolRef: group.String()}}}}}
	s := New(pool, market, nil, Config{}, quiet())
	if err := s.SyncInventory(ctx); err != nil {
		t.Fatal(err)
	}
	got := market.reports[group.String()]
	if len(got) != 1 || !reflect.DeepEqual(got[0], marketclient.PoolNode{NodeID: ready.String(), IP: "8.8.8.8", Region: "cn", Carrier: "telecom"}) {
		t.Fatalf("reported %+v", got)
	}
	// ADR 0012 §24: the pool's online available count (ML-18 guard count:
	// active, online, not isolated, not held), whatever the market inventory.
	if online := market.online[group.String()]; online == nil || *online != 3 {
		t.Fatalf("online available %v, want 3 (ready, old, probe-only)", online)
	}
	if _, err := pool.Exec(ctx, `UPDATE node_presence SET status='offline', offline_since=now(), online_since=NULL WHERE node_id=$1`, old); err != nil {
		t.Fatal(err)
	}
	if err := s.SyncInventory(ctx); err != nil {
		t.Fatal(err)
	}
	if online := market.online[group.String()]; online == nil || *online != 2 {
		t.Fatalf("online available after one node went offline %v, want 2", online)
	}
	if _, reported := market.reports[other.String()]; reported {
		t.Fatal("a pool no offer uses was reported")
	}
	if !s.known[ready.String()] || len(s.known) != 1 {
		t.Fatalf("known %v", s.known)
	}
	// The role follows the latest heartbeat: probe-only leaves the offer's
	// inventory, join_market enters it.
	for _, change := range []struct {
		node uuid.UUID
		role string
	}{{ready, "probe_only"}, {probeOnly, "join_market"}} {
		if err := setRole(ctx, pool, change.node, ptr(change.role), false); err != nil {
			t.Fatal(err)
		}
	}
	if err := s.SyncInventory(ctx); err != nil {
		t.Fatal(err)
	}
	got = market.reports[group.String()]
	if len(got) != 1 || !reflect.DeepEqual(got[0], marketclient.PoolNode{NodeID: probeOnly.String(), IP: "8.8.8.9", Region: "cn", Carrier: "telecom"}) {
		t.Fatalf("after role change reported %+v", got)
	}

	// ADR 0012 §6.1: the closed minute's mean CPU and memory of each reported
	// node, from host and probe samples with known metrics only.
	member := uuid.New()
	s.cfg.Identity = func() marketclient.Identity { return marketclient.Identity{MemberID: member} }
	minute := time.Now().UTC().Truncate(time.Minute)
	err = pgx.BeginFunc(ctx, pool, func(tx pgx.Tx) error {
		if _, err := tx.Exec(ctx, `SET LOCAL session_replication_role = replica`); err != nil {
			return err
		}
		for i, sample := range []struct {
			node  uuid.UUID
			at    time.Duration // before the minute end
			kind  string
			known bool
			cpu   float64
			used  int64
		}{
			{probeOnly, 50 * time.Second, "host_metric", true, 70, 600},
			{probeOnly, 10 * time.Second, "host_metric", true, 90, 800},
			{probeOnly, 0, "legacy_metric", false, 0, 0},             // metrics unknown
			{probeOnly, 70 * time.Second, "host_metric", true, 1, 1}, // previous minute
			{ready, 20 * time.Second, "host_metric", true, 99, 999},  // not in the inventory any more
		} {
			var cpu, used, total any
			if sample.known {
				cpu, used, total = sample.cpu, sample.used, int64(1000)
			}
			if _, err := tx.Exec(ctx, `INSERT INTO node_metric_samples(event_id,request_id,node_id,schema_version,config_revision,
				publication_sequence,observed_at,metrics_known,cpu_percent,memory_used_bytes,memory_total_bytes,active_connections,
				rx_bandwidth_bps,tx_bandwidth_bps,puback_stream,puback_sequence,consumer_durable,consumer_sequence,num_delivered,
				wire_sha256,record_kind)
				VALUES($1,$2,$3,1,CASE WHEN $11='host_metric' THEN 0 ELSE 1 END,$4,$5,$6,$7,$8,$9,CASE WHEN $6 THEN 0 END,CASE WHEN $6 THEN 0 END,CASE WHEN $6 THEN 0 END,
				'NODE_MONITORING_STATUS',$4,'control_api_node_metrics',$4,1,$10,$11)`,
				uuid.New(), uuid.New(), sample.node, int64(1_000_000+i)+time.Now().UnixNano()%1_000_000_000, minute.Add(-sample.at),
				sample.known, cpu, used, total, make([]byte, 32), sample.kind); err != nil {
				return err
			}
		}
		return nil
	})
	if err != nil {
		t.Fatal(err)
	}
	sent, err := s.ReportLoad(ctx, minute)
	if err != nil || sent != 1 || len(market.loads) != 1 {
		t.Fatalf("load report: sent %d err %v loads %+v", sent, err, market.loads)
	}
	report := market.loads[0]
	item := report.Items[0]
	if report.Schema != nodeload.SchemaV1 || report.LeafMemberID != member || report.Validate() != nil ||
		item.NodePoolRef != group.String() || item.NodeID != probeOnly || item.ObservedAt != minute.Unix() ||
		item.CPUPercent != 80 || item.MemoryPercent != 70 || item.SampleCount != 2 {
		t.Fatalf("load report %+v", report)
	}
	if _, err := s.ReportLoad(ctx, minute); err != nil || market.loads[1].ReportID != report.ReportID {
		t.Fatalf("a retried minute keeps its report ID: %v", err)
	}
}

func ptr(value string) *string { return &value }

type execer interface {
	Exec(ctx context.Context, sql string, args ...any) (pgconn.CommandTag, error)
}

// setRole seeds (insert) or changes (update) node_presence.market_probe_role.
func setRole(ctx context.Context, db execer, node uuid.UUID, role *string, insert bool) error {
	if !insert {
		_, err := db.Exec(ctx, `UPDATE node_presence SET market_probe_role=$2 WHERE node_id=$1`, node, role)
		return err
	}
	_, err := db.Exec(ctx, `INSERT INTO node_presence(
		node_id,status,session_epoch,heartbeat_sequence,event_id,request_id,payload_digest,occurred_at,projected_at,
		last_seen_at,confirmed_session_epoch,confirmed_heartbeat_sequence,confirmed_event_id,confirmed_request_id,
		confirmed_payload_digest,online_since,openresty_state,firewall_state,
		filesystem_total_bytes,filesystem_available_bytes,cache_used_bytes,market_probe_role,updated_at)
		VALUES($1,'online',1,1,$2,$3,$4,now(),now(),now(),1,1,$2,$3,$4,now(),'running','running',100,50,0,$5,now())`,
		node, uuid.New(), uuid.New(), make([]byte, 32), role)
	return err
}
