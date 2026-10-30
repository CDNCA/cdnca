//go:build integration

package sched302table

import (
	"context"
	"crypto/ed25519"
	"crypto/rand"
	"os"
	"strings"
	"sync"
	"testing"
	"time"

	"github.com/cdnca/cdnca/libs/edgeconfig/sched302"
	agentv1 "github.com/cdnca/cdnca/proto/gen/go/agent/v1"
	"github.com/cdnca/cdnca/services/control-api/internal/database"
	"github.com/cdnca/cdnca/services/control-api/internal/database/databasetest"
	"github.com/google/uuid"
	"github.com/jackc/pgx/v5"
	"github.com/jackc/pgx/v5/pgxpool"
)

type testSigner struct{ key ed25519.PrivateKey }

func (signer testSigner) KeyID() string { return "artifact-key" }
func (signer testSigner) Sign(_ context.Context, payload []byte) ([]byte, error) {
	return ed25519.Sign(signer.key, payload), nil
}

type recordingPublisher struct {
	mu     sync.Mutex
	tables map[string][]*agentv1.Sched302Table
}

func (publisher *recordingPublisher) Publish(_ context.Context, nodeID string, table *agentv1.Sched302Table) error {
	publisher.mu.Lock()
	defer publisher.mu.Unlock()
	publisher.tables[nodeID] = append(publisher.tables[nodeID], table)
	return nil
}

func (publisher *recordingPublisher) last(t *testing.T, nodeID uuid.UUID) (sched302.Table, int) {
	t.Helper()
	publisher.mu.Lock()
	defer publisher.mu.Unlock()
	tables := publisher.tables[nodeID.String()]
	if len(tables) == 0 {
		t.Fatalf("no table pushed to %s", nodeID)
	}
	decoded, err := sched302.Decode(tables[len(tables)-1].TableJson)
	if err != nil {
		t.Fatal(err)
	}
	return decoded, len(tables)
}

type harness struct {
	t       *testing.T
	ctx     context.Context
	pool    *pgxpool.Pool
	scopeID uuid.UUID
	userID  uuid.UUID
	display int
}

func newHarness(t *testing.T) *harness {
	databaseURL := strings.TrimSpace(os.Getenv("TEST_DATABASE_URL"))
	if databaseURL == "" {
		t.Skip("TEST_DATABASE_URL is not set")
	}
	ctx := t.Context()
	admin, err := pgxpool.New(ctx, databaseURL)
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(admin.Close)
	schema := "sched302_" + strings.ReplaceAll(uuid.NewString(), "-", "")
	identifier := pgx.Identifier{schema}.Sanitize()
	if _, err := admin.Exec(ctx, "CREATE SCHEMA "+identifier); err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() {
		cleanup, done := databasetest.CleanupContext()
		defer done()
		_, _ = admin.Exec(cleanup, "DROP SCHEMA "+identifier+" CASCADE")
	})
	config, err := pgxpool.ParseConfig(databaseURL)
	if err != nil {
		t.Fatal(err)
	}
	config.ConnConfig.RuntimeParams["search_path"] = schema
	pool, err := pgxpool.NewWithConfig(ctx, config)
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(pool.Close)
	if err := database.Migrate(ctx, pool, "up"); err != nil {
		t.Fatal(err)
	}
	value := &harness{t: t, ctx: ctx, pool: pool, scopeID: uuid.New(), userID: uuid.New()}
	value.exec(`INSERT INTO access_scopes(id,kind) VALUES($1,'platform')`, value.scopeID)
	value.exec(`INSERT INTO users(id,username,display_name,password_hash) VALUES($1,'s302-owner','owner','test-only')`, value.userID)
	value.exec(`INSERT INTO memberships(scope_id,user_id) VALUES($1,$2)`, value.scopeID, value.userID)
	return value
}

func (h *harness) exec(query string, args ...any) {
	h.t.Helper()
	if _, err := h.pool.Exec(h.ctx, query, args...); err != nil {
		h.t.Fatal(err)
	}
}

// seeded runs statements with triggers and foreign keys off: the writers of
// these facts (site service, presence projector, metrics) are not under test.
func (h *harness) seeded(statements ...func(pgx.Tx) error) {
	h.t.Helper()
	if err := pgx.BeginFunc(h.ctx, h.pool, func(tx pgx.Tx) error {
		if _, err := tx.Exec(h.ctx, `SET LOCAL session_replication_role = replica`); err != nil {
			return err
		}
		for _, statement := range statements {
			if err := statement(tx); err != nil {
				return err
			}
		}
		return nil
	}); err != nil {
		h.t.Fatal(err)
	}
}

func (h *harness) node(online bool, hostname string, cpu float64) uuid.UUID {
	h.t.Helper()
	id := uuid.New()
	h.display++
	h.exec(`INSERT INTO nodes(id,scope_id,name,admin_state,created_by_user_id,display_id)
		VALUES($1,$2,$3,'active',$4,$5)`, id, h.scopeID, id.String(), h.userID, h.display)
	if hostname != "" {
		h.exec(`UPDATE nodes SET management_settings=management_settings||jsonb_build_object('schedule302_hostname',$2::text)
			WHERE id=$1`, id, hostname)
	}
	status := "offline"
	if online {
		status = "online"
	}
	h.seeded(func(tx pgx.Tx) error {
		eventID, requestID := uuid.New(), uuid.New()
		_, err := tx.Exec(h.ctx, `INSERT INTO node_presence(
			node_id,status,session_epoch,heartbeat_sequence,event_id,request_id,payload_digest,occurred_at,projected_at,
			last_seen_at,confirmed_session_epoch,confirmed_heartbeat_sequence,confirmed_event_id,confirmed_request_id,
			confirmed_payload_digest,online_since,offline_since,openresty_state,firewall_state,
			filesystem_total_bytes,filesystem_available_bytes,cache_used_bytes,updated_at)
			VALUES($1,$2,1,1,$3,$4,$5,now(),now(),now(),1,1,$3,$4,$5,
			CASE WHEN $2='online' THEN now() END,CASE WHEN $2='offline' THEN now() END,'running','running',100,50,0,now())`,
			id, status, eventID, requestID, make([]byte, 32))
		return err
	})
	if cpu >= 0 {
		h.seeded(func(tx pgx.Tx) error {
			_, err := tx.Exec(h.ctx, `INSERT INTO node_metric_samples(event_id,request_id,node_id,schema_version,config_revision,
				publication_sequence,observed_at,metrics_known,cpu_percent,memory_used_bytes,memory_total_bytes,active_connections,
				rx_bandwidth_bps,tx_bandwidth_bps,puback_stream,puback_sequence,consumer_durable,consumer_sequence,num_delivered,
				wire_sha256,record_kind)
				VALUES($1,$2,$3,1,0,1,now(),true,$4,1,2,0,0,0,'NODE_MONITORING_STATUS',1,'control_api_node_metrics',1,1,$5,'host_metric')`,
				uuid.New(), uuid.New(), id, cpu, make([]byte, 32))
			return err
		})
	}
	return id
}

type endpoint struct {
	node            uuid.UUID
	address         string
	region, carrier string
}

func (h *harness) lineGroup(endpoints []endpoint) uuid.UUID {
	h.t.Helper()
	groupID := uuid.New()
	if err := pgx.BeginFunc(h.ctx, h.pool, func(tx pgx.Tx) error {
		if _, err := tx.Exec(h.ctx, `INSERT INTO node_line_groups(id,tenant_scope_id,name,current_revision,created_by_user_id,
			updated_by_user_id,created_at,updated_at) VALUES($1,$2,'s302-group',1,$3,$3,now(),now())`, groupID, h.scopeID, h.userID); err != nil {
			return err
		}
		if _, err := tx.Exec(h.ctx, `INSERT INTO node_line_group_revisions(line_group_id,tenant_scope_id,revision,name,
			resolved_value,probe_interval_ms,probe_timeout_ms,failure_threshold,recovery_threshold,failure_debounce_ms,
			recovery_debounce_ms,endpoint_count,configuration_digest,created_by_user_id,created_at)
			VALUES($1,$2,1,'s302-group','lg-'||replace($1::uuid::text,'-',''),10000,3000,2,1,0,0,$3,$4,$5,now()-interval '1 hour')`,
			groupID, h.scopeID, len(endpoints), make([]byte, 32), h.userID); err != nil {
			return err
		}
		for _, point := range endpoints {
			if _, err := tx.Exec(h.ctx, `INSERT INTO node_line_endpoints(id,node_id,tenant_scope_id,line_group_id,
				config_revision,address,address_family,port,region,carrier,priority,weight,enabled)
				VALUES($1,$2,$3,$4,1,$5,4,80,$6,$7,0,10,true)`, uuid.New(), point.node, h.scopeID, groupID,
				point.address, point.region, point.carrier); err != nil {
				return err
			}
		}
		if _, err := tx.Exec(h.ctx, `INSERT INTO node_line_endpoint_health(tenant_scope_id,line_group_id,config_revision,
			endpoint_id,status,consecutive_successes,consecutive_failures,last_sequence,last_changed_at,row_revision,created_at,updated_at)
			SELECT $1,$2,1,id,'unknown',0,0,0,now()-interval '1 hour',1,now()-interval '1 hour',now()-interval '1 hour'
			FROM node_line_endpoints WHERE tenant_scope_id=$1 AND line_group_id=$2`, h.scopeID, groupID); err != nil {
			return err
		}
		_, err := tx.Exec(h.ctx, `UPDATE node_line_group_revisions SET sealed_at=now()-interval '1 hour'
			WHERE tenant_scope_id=$1 AND line_group_id=$2 AND revision=1`, h.scopeID, groupID)
		return err
	}); err != nil {
		h.t.Fatal(err)
	}
	return groupID
}

func (h *harness) site(groupID uuid.UUID, domain, target string) uuid.UUID {
	h.t.Helper()
	siteID := uuid.New()
	h.seeded(func(tx pgx.Tx) error {
		h.display++
		if _, err := tx.Exec(h.ctx, `INSERT INTO sites(id,scope_id,owner_user_id,domain,origins,origin_hosts,http_ports,
			enabled,node_group_id,created_by_user_id,updated_by_user_id,display_id) VALUES($1,$2,$3,$4,'{192.0.2.1}','{192.0.2.1}','{80}',
			true,$5,$3,$3,$6)`, siteID, h.scopeID, h.userID, domain, groupID, h.display); err != nil {
			return err
		}
		_, err := tx.Exec(h.ctx, `INSERT INTO site_schedule302_settings(scope_id,site_id,target,keep_path,keep_query,
			signature_ttl_seconds,https_to_http,extensions,path_prefixes,min_size_bytes,sign_key,updated_by_user_id,updated_at)
			VALUES($1,$2,$3,true,true,60,false,'{}','{}',0,$4,$5,now())`, h.scopeID, siteID, target, make([]byte, 32), h.userID)
		return err
	})
	return siteID
}

// TestScheduleTablesFollowNodeHealth: tables per serving node with
// availability from the DNS scheduling facts (holds, presence) and load from
// node metrics; an unchanged table is not resent, a change is pushed on the
// next tick, a node leaving every scheduled site gets an empty table once.
func TestScheduleTablesFollowNodeHealth(t *testing.T) {
	h := newHarness(t)
	telecom := h.node(true, "", 42.4)
	unicom := h.node(true, "edge-u.cdnca.com", -1)
	offline := h.node(false, "", -1)
	group := h.lineGroup([]endpoint{
		{telecom, "198.51.100.1", "广东", "中国电信"},
		{unicom, "198.51.100.2", "北京", "联通"},
		{offline, "198.51.100.3", "", "BGP"},
	})
	siteID := h.site(group, "dl.example.test", sched302.TargetAddress)
	publicKey, privateKey, _ := ed25519.GenerateKey(rand.Reader)
	publisher := &recordingPublisher{tables: map[string][]*agentv1.Sched302Table{}}
	clock := time.Now()
	worker, err := NewWorker(h.pool, testSigner{privateKey}, publisher, func() time.Time { return clock }, nil)
	if err != nil {
		t.Fatal(err)
	}
	if err := worker.Tick(h.ctx); err != nil {
		t.Fatal(err)
	}
	table, pushes := publisher.last(t, telecom)
	if pushes != 1 || table.Revision != 1 || len(table.Sites) != 1 || table.Sites[0].SiteID != siteID.String() {
		t.Fatalf("telecom table %+v (%d pushes)", table, pushes)
	}
	byNode := map[string]sched302.Candidate{}
	for _, candidate := range table.Sites[0].Candidates {
		byNode[candidate.NodeID] = candidate
	}
	if c := byNode[telecom.String()]; !c.Available || c.Carrier != "telecom" || c.Province != 440000 || c.Load != 42 || c.Host != "198.51.100.1" {
		t.Fatalf("telecom candidate %+v", c)
	}
	if c := byNode[unicom.String()]; !c.Available || c.Carrier != "unicom" || c.Province != 110000 || c.Load != 0 {
		t.Fatalf("unicom candidate %+v", c)
	}
	if c := byNode[offline.String()]; c.Available || c.Carrier != "bgp" {
		t.Fatalf("offline node candidate %+v", c)
	}
	publisher.mu.Lock()
	carrier := publisher.tables[telecom.String()][0]
	publisher.mu.Unlock()
	if !ed25519.Verify(publicKey, carrier.TableJson, carrier.Signature) || carrier.SigningKeyId != "artifact-key" {
		t.Fatal("table signature does not verify")
	}

	// Unchanged: not resent.
	clock = clock.Add(time.Second)
	if err := worker.Tick(h.ctx); err != nil {
		t.Fatal(err)
	}
	if _, pushes := publisher.last(t, telecom); pushes != 1 {
		t.Fatalf("unchanged table resent: %d", pushes)
	}

	// The telecom node is held (availability monitoring): unavailable at once.
	h.exec(`INSERT INTO node_serving_holds(node_id,source,held,reason_code,revision,held_since,changed_at,updated_at)
		VALUES($1,'availability_monitor',true,'probe_failed',1,now(),now(),now())`, telecom)
	clock = clock.Add(time.Second)
	if err := worker.Tick(h.ctx); err != nil {
		t.Fatal(err)
	}
	table, pushes = publisher.last(t, unicom)
	if table.Revision != 2 {
		t.Fatalf("hold did not push a new table: revision %d (%d pushes)", table.Revision, pushes)
	}
	for _, candidate := range table.Sites[0].Candidates {
		if candidate.NodeID == telecom.String() && candidate.Available {
			t.Fatal("held node still available")
		}
	}

	// Refresh within the hold even when nothing changed.
	clock = clock.Add(time.Duration(sched302.HoldSeconds) * time.Second / 2)
	if err := worker.Tick(h.ctx); err != nil {
		t.Fatal(err)
	}
	if table, _ := publisher.last(t, unicom); table.Revision != 3 || table.GeneratedAt != clock.Unix() {
		t.Fatalf("no refresh: %+v", table)
	}

	// Scheduling off: every node gets one empty table, then nothing.
	h.exec(`DELETE FROM site_schedule302_settings WHERE site_id=$1`, siteID)
	clock = clock.Add(time.Second)
	if err := worker.Tick(h.ctx); err != nil {
		t.Fatal(err)
	}
	table, pushes = publisher.last(t, unicom)
	if len(table.Sites) != 0 {
		t.Fatalf("leaving node table %+v", table)
	}
	clock = clock.Add(time.Second)
	if err := worker.Tick(h.ctx); err != nil {
		t.Fatal(err)
	}
	if _, again := publisher.last(t, unicom); again != pushes {
		t.Fatalf("empty table resent: %d -> %d", pushes, again)
	}
}

// target=hostname: only nodes with a direct hostname are candidates.
func TestScheduleTablesHostnameTarget(t *testing.T) {
	h := newHarness(t)
	named := h.node(true, "edge-a.cdnca.com", -1)
	bare := h.node(true, "", -1)
	group := h.lineGroup([]endpoint{{named, "198.51.100.1", "", ""}, {bare, "198.51.100.2", "", ""}})
	h.site(group, "dl.example.test", sched302.TargetHostname)
	_, privateKey, _ := ed25519.GenerateKey(rand.Reader)
	publisher := &recordingPublisher{tables: map[string][]*agentv1.Sched302Table{}}
	worker, err := NewWorker(h.pool, testSigner{privateKey}, publisher, time.Now, nil)
	if err != nil {
		t.Fatal(err)
	}
	if err := worker.Tick(h.ctx); err != nil {
		t.Fatal(err)
	}
	table, _ := publisher.last(t, bare)
	if candidates := table.Sites[0].Candidates; len(candidates) != 1 || candidates[0].Host != "edge-a.cdnca.com" {
		t.Fatalf("hostname candidates %+v", candidates)
	}
}
