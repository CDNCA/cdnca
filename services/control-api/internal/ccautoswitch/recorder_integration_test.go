//go:build integration

package ccautoswitch_test

import (
	"context"
	"encoding/json"
	"fmt"
	"os"
	"strings"
	"sync/atomic"
	"testing"
	"time"

	agentv1 "github.com/cdnca/cdnca/proto/gen/go/agent/v1"
	commonv1 "github.com/cdnca/cdnca/proto/gen/go/common/v1"
	"github.com/cdnca/cdnca/services/control-api/internal/ccautoswitch"
	"github.com/cdnca/cdnca/services/control-api/internal/database"
	"github.com/cdnca/cdnca/services/control-api/internal/database/databasetest"
	"github.com/cdnca/cdnca/services/control-api/internal/nodemetrics"
	"github.com/cdnca/cdnca/services/control-api/internal/notification"
	"github.com/google/uuid"
	"github.com/jackc/pgx/v5"
	"github.com/jackc/pgx/v5/pgxpool"
	"google.golang.org/protobuf/proto"
	"google.golang.org/protobuf/types/known/timestamppb"
)

type delivery struct {
	subject string
	data    []byte
	meta    nodemetrics.DeliveryMetadata
	acked   int
	termed  int
	naked   int
}

func (d *delivery) Subject() string                          { return d.subject }
func (d *delivery) Data() []byte                             { return d.data }
func (d *delivery) Metadata() nodemetrics.DeliveryMetadata   { return d.meta }
func (d *delivery) Ack(context.Context) error                { d.acked++; return nil }
func (d *delivery) Nak(context.Context, time.Duration) error { d.naked++; return nil }
func (d *delivery) Term(context.Context) error               { d.termed++; return nil }

type harness struct {
	t         *testing.T
	pool      *pgxpool.Pool
	recorder  *ccautoswitch.Recorder
	processor *nodemetrics.Processor
	sequence  atomic.Uint64
}

func newHarness(t *testing.T) *harness {
	t.Helper()
	if strings.TrimSpace(os.Getenv("TEST_DATABASE_URL")) == "" {
		t.Skip("TEST_DATABASE_URL is not set")
	}
	pool := databasetest.ClonedMigratedPool(t, nil)
	if pool == nil {
		var err error
		if pool, err = pgxpool.New(t.Context(), os.Getenv("TEST_DATABASE_URL")); err != nil {
			t.Fatal(err)
		}
		t.Cleanup(pool.Close)
		if err := database.Migrate(t.Context(), pool, "up"); err != nil {
			t.Fatal(err)
		}
	}
	notifications, err := notification.NewStore(pool)
	if err != nil {
		t.Fatal(err)
	}
	if err := notifications.SetChannelSwitches(t.Context(), notification.ChannelSwitches{SMS: true, Email: true}); err != nil {
		t.Fatal(err)
	}
	recorder, err := ccautoswitch.NewRecorder(pool, notifications)
	if err != nil {
		t.Fatal(err)
	}
	processor, err := nodemetrics.NewProcessor(nodemetrics.NewDecoder(nodemetrics.DefaultDecoderConfig()),
		failingStore{t}, time.Second, 5*time.Second)
	if err != nil {
		t.Fatal(err)
	}
	processor.WithCCAutoSwitchRecorder(recorder)
	return &harness{t: t, pool: pool, recorder: recorder, processor: processor}
}

// failingStore proves CC auto switch reports never reach node_metric_samples.
type failingStore struct{ t *testing.T }

func (store failingStore) Put(context.Context, nodemetrics.Sample) (bool, error) {
	store.t.Error("CC auto switch report reached the node metric sample store")
	return false, nil
}

func (h *harness) exec(query string, args ...any) {
	h.t.Helper()
	if _, err := h.pool.Exec(h.t.Context(), query, args...); err != nil {
		h.t.Fatalf("%s: %v", strings.Join(strings.Fields(query)[:3], " "), err)
	}
}

// tenant seeds a tenant scope with an active owner member and one site.
func (h *harness) tenant(name string) (scope, owner, site uuid.UUID, domain string) {
	h.t.Helper()
	tenant := uuid.New()
	scope, owner, site = uuid.New(), uuid.New(), uuid.New()
	domain = name + "-" + site.String()[:8] + ".example.com"
	h.exec(`INSERT INTO tenants(id,display_name,status,created_at,updated_at) VALUES($1,$2,'active',now(),now())`, tenant, name)
	h.exec(`INSERT INTO access_scopes(id,kind,tenant_id,created_at) VALUES($1,'tenant',$2,now())`, scope, tenant)
	h.exec(`INSERT INTO users(id,username,display_name,password_hash,status,created_at,updated_at)
		VALUES($1,$2,$3,'not-used','active',now(),now())`, owner, "cc-"+strings.ReplaceAll(owner.String(), "-", "")[:20], name)
	h.exec(`INSERT INTO memberships(scope_id,user_id,status,created_at) VALUES($1,$2,'active',now())`, scope, owner)
	// The origin pool constraint triggers are deferred to commit.
	if err := pgx.BeginFunc(h.t.Context(), h.pool, func(tx pgx.Tx) error {
		if _, err := tx.Exec(h.t.Context(), `INSERT INTO sites(id,scope_id,owner_user_id,domain,origins,origin_hosts,
			created_by_user_id,updated_by_user_id,display_id)
			VALUES($1,$2,$3,$4,ARRAY['origin.example.test:80'],ARRAY['origin.example.test'],$3,$3,1)`,
			site, scope, owner, domain); err != nil {
			return err
		}
		if _, err := tx.Exec(h.t.Context(), `INSERT INTO site_origin_pools(site_id) VALUES($1)`, site); err != nil {
			return err
		}
		_, err := tx.Exec(h.t.Context(), `INSERT INTO site_origins(site_id,position,host,port) VALUES($1,1,'origin.example.test',80)`, site)
		return err
	}); err != nil {
		h.t.Fatal(err)
	}
	return scope, owner, site, domain
}

// node seeds an active platform node carrying the given configuration scopes.
func (h *harness) node(platform, creator uuid.UUID, carried ...uuid.UUID) uuid.UUID {
	h.t.Helper()
	id := uuid.New()
	h.exec(`WITH allocated AS (
			INSERT INTO node_display_id_sequences(scope_id,next_value,updated_at) VALUES($2,2,now())
			ON CONFLICT(scope_id) DO UPDATE SET next_value=node_display_id_sequences.next_value+1, updated_at=now()
			RETURNING next_value-1 AS display_id)
		INSERT INTO nodes(id,display_id,scope_id,name,admin_state,created_by_user_id)
		SELECT $1,allocated.display_id,$2,$3,'active',$4 FROM allocated`, id, platform, "cc-node-"+id.String()[:8], creator)
	for _, scope := range carried {
		h.exec(`INSERT INTO node_config_state(node_id,configuration_scope_id,updated_at) VALUES($1,$2,now())`, id, scope)
	}
	return id
}

// report runs one CC_AUTO_SWITCH report through the node metrics processor,
// encoded exactly as the agent and gateway send it.
func (h *harness) report(node, scope, site uuid.UUID, engaged time.Time) *delivery {
	h.t.Helper()
	engaged = engaged.UTC().Truncate(time.Second)
	payload, err := json.Marshal(map[string]any{
		"schema_version": 1, "node_id": node.String(), "tenant_scope_id": scope.String(), "site_id": site.String(),
		"policy_id": uuid.NewString(), "policy_version": 2, "engaged_at": engaged,
		"trigger_qps": 1500, "trigger_5xx": 3, "qps_total": 1000, "qps_5xx": 0, "recover_seconds": 300,
	})
	if err != nil {
		h.t.Fatal(err)
	}
	sequence := h.sequence.Add(1)
	report := &agentv1.NodeMonitoringReport{
		Event: &commonv1.EventMetadata{
			EventId:   uuid.NewSHA1(node, []byte("cc-auto-switch/"+site.String()+"/"+engaged.Format(time.RFC3339))).String(),
			RequestId: uuid.NewString(), OccurredTime: timestamppb.New(engaged),
		},
		Schema: agentv1.NodeMonitoringSchema_NODE_MONITORING_SCHEMA_V1, NodeId: node.String(), PublicationSequence: sequence,
		Kind: agentv1.NodeMonitoringRecordKind_NODE_MONITORING_RECORD_KIND_CC_AUTO_SWITCH, PayloadJson: payload,
	}
	data, err := proto.MarshalOptions{Deterministic: true}.Marshal(report)
	if err != nil {
		h.t.Fatal(err)
	}
	item := &delivery{subject: nodemetrics.DefaultSubjectPrefix + "." + node.String(), data: data,
		meta: nodemetrics.DeliveryMetadata{Stream: nodemetrics.NodeMonitoringStatusStream, Durable: nodemetrics.DefaultConsumerDurable,
			StreamSequence: sequence, ConsumerSequence: sequence, NumDelivered: 1}}
	return h.process(item)
}

func (h *harness) process(item *delivery) *delivery {
	h.t.Helper()
	disposition, err := h.processor.Process(h.t.Context(), item)
	if err != nil || disposition != nodemetrics.DispositionAck || item.acked != 1 {
		h.t.Fatalf("Process() = (%s, %v), delivery acked=%d termed=%d naked=%d", disposition, err, item.acked, item.termed, item.naked)
	}
	return item
}

type notice struct {
	source, channel, body string
}

func (h *harness) notices(scope, owner uuid.UUID) []notice {
	h.t.Helper()
	rows, err := h.pool.Query(h.t.Context(), `SELECT event.source_event_id, outbox.channel, outbox.body
		FROM notification_events event JOIN notification_outbox outbox ON outbox.event_id=event.id
		WHERE event.scope_id=$1 AND event.recipient_user_id=$2 AND event.event_type=$3
		ORDER BY event.source_event_id, outbox.channel`, scope, owner, ccautoswitch.EventType)
	if err != nil {
		h.t.Fatal(err)
	}
	defer rows.Close()
	var result []notice
	for rows.Next() {
		var item notice
		if err := rows.Scan(&item.source, &item.channel, &item.body); err != nil {
			h.t.Fatal(err)
		}
		result = append(result, item)
	}
	if err := rows.Err(); err != nil {
		h.t.Fatal(err)
	}
	return result
}

func (h *harness) samples() int {
	h.t.Helper()
	var count int
	if err := h.pool.QueryRow(h.t.Context(), `SELECT count(*) FROM node_metric_samples`).Scan(&count); err != nil {
		h.t.Fatal(err)
	}
	return count
}

// 上报 → 多节点 5 分钟窗口去重 → 给站点 owner 入队；窗口外再次切换重新通知。
func TestCCAutoSwitchNotifiesOwnerOncePerWindowAcrossNodes(t *testing.T) {
	h := newHarness(t)
	platform := uuid.New()
	h.exec(`INSERT INTO access_scopes(id,kind,created_at) VALUES($1,'platform',now())`, platform)
	scope, owner, site, domain := h.tenant("cc-owner")
	first, second := h.node(platform, owner, scope), h.node(platform, owner, platform, scope)
	samplesBefore := h.samples()

	start := time.Now().Add(-20 * time.Minute)
	// fix-notifsub: never-chosen defaults are now both channels; the member
	// picks email only here so the later SMS opt-in is observable.
	h.exec(`INSERT INTO notification_subscriptions(scope_id,user_id,event_type,sms_enabled,email_enabled,revision,created_at,updated_at)
		VALUES($1,$2,$3,false,true,1,now(),now())`, scope, owner, ccautoswitch.EventType)
	h.report(first, scope, site, start)
	h.report(second, scope, site, start.Add(2*time.Second))
	// The same engagement redelivered (agent restart re-observes it).
	h.report(first, scope, site, start)
	h.report(second, scope, site, start.Add(4*time.Minute+59*time.Second))
	got := h.notices(scope, owner)
	source := "cc-auto-switch/" + site.String() + "/1"
	if len(got) != 1 || got[0].source != source || got[0].channel != "email" || !strings.Contains(got[0].body, domain) ||
		!strings.Contains(got[0].body, "1500") || !strings.Contains(got[0].body, "阈值 1000") {
		t.Fatalf("first window notices=%+v (email only by the member's choice)", got)
	}
	if stats := h.recorder.Stats(); stats.Notified != 1 || stats.Deduplicated != 3 || stats.Rejected != 0 {
		t.Fatalf("first window stats=%+v", stats)
	}

	// Past the window: notified again under the next sequence.
	h.report(second, scope, site, start.Add(5*time.Minute))
	h.report(first, scope, site, start.Add(5*time.Minute+30*time.Second))
	got = h.notices(scope, owner)
	if len(got) != 2 || got[1].source != "cc-auto-switch/"+site.String()+"/2" {
		t.Fatalf("second window notices=%+v", got)
	}
	// A late engagement from the first window does not reopen it.
	h.report(first, scope, site, start.Add(time.Minute))
	if got := h.notices(scope, owner); len(got) != 2 {
		t.Fatalf("late engagement notified: %+v", got)
	}
	var sequence int64
	var started time.Time
	if err := h.pool.QueryRow(t.Context(), `SELECT sequence, window_started_at FROM cc_auto_switch_notification_windows
		WHERE site_id=$1`, site).Scan(&sequence, &started); err != nil || sequence != 2 ||
		!started.Equal(start.Add(5*time.Minute).Truncate(time.Second)) {
		t.Fatalf("window sequence=%d started=%s err=%v", sequence, started, err)
	}

	// Subscribing to SMS takes effect for the next window.
	h.exec(`UPDATE notification_subscriptions SET sms_enabled=true,revision=2,updated_at=now()
		WHERE scope_id=$1 AND user_id=$2 AND event_type=$3`, scope, owner, ccautoswitch.EventType)
	h.report(first, scope, site, start.Add(11*time.Minute))
	got = h.notices(scope, owner)
	if len(got) != 4 || got[2].channel != "email" || got[3].channel != "sms" || !strings.Contains(got[3].body, domain) {
		t.Fatalf("third window notices=%+v", got)
	}
	// Too old to be useful (a node cut off from the gateway for hours).
	h.report(first, scope, site, time.Now().Add(-2*time.Hour))
	if stats := h.recorder.Stats(); stats.Notified != 3 || stats.Stale != 1 {
		t.Fatalf("final stats=%+v", stats)
	}
	if h.samples() != samplesBefore {
		t.Fatal("CC auto switch reports were written to node_metric_samples")
	}
	// Each notification window is one security.incident_detected fact in the
	// same transaction (migration 369), with no client address in it.
	rows, err := h.pool.Query(t.Context(), `SELECT subject_sequence,payload->>'incident_sequence',payload::text
		FROM domain_event_outbox_368 WHERE event_type='io.cdnca.security.v1.incident_detected' AND tenant_scope_id=$1
		ORDER BY subject_sequence`, scope)
	if err != nil {
		t.Fatal(err)
	}
	var windows []string
	for rows.Next() {
		var sequence int64
		var window, payload string
		if err := rows.Scan(&sequence, &window, &payload); err != nil {
			t.Fatal(err)
		}
		if strings.Contains(payload, "client") || !strings.Contains(payload, `"site_id": "`+site.String()+`"`) {
			t.Fatalf("incident payload %s", payload)
		}
		windows = append(windows, fmt.Sprintf("%d:%s", sequence, window))
	}
	if rows.Err() != nil || strings.Join(windows, ",") != "1:1,2:2,3:3" {
		t.Fatalf("incident facts = %v, %v", windows, rows.Err())
	}
}

// 归属不符丢弃：站点不在上报的 scope、节点不承载该 scope、站点已删除，都只计数不通知。
func TestCCAutoSwitchDropsEngagementsOutsideOwnership(t *testing.T) {
	h := newHarness(t)
	platform := uuid.New()
	h.exec(`INSERT INTO access_scopes(id,kind,created_at) VALUES($1,'platform',now())`, platform)
	scope, owner, site, _ := h.tenant("cc-victim")
	otherScope, otherOwner, otherSite, _ := h.tenant("cc-other")
	serving := h.node(platform, owner, scope)
	foreign := h.node(platform, owner, otherScope)
	bare := h.node(platform, owner, platform)
	engaged := time.Now().Add(-time.Minute)

	h.report(serving, otherScope, site, engaged) // site claimed under another tenant's scope
	h.report(foreign, scope, site, engaged)      // node does not carry the site's scope
	h.report(bare, scope, site, engaged)         // platform-only node
	h.report(serving, scope, otherSite, engaged) // other tenant's site under this scope
	h.exec(`UPDATE sites SET deleted_at=now() WHERE id=$1`, otherSite)
	h.report(foreign, otherScope, otherSite, engaged) // deleted site
	if stats := h.recorder.Stats(); stats.Rejected != 5 || stats.Notified != 0 {
		t.Fatalf("stats=%+v", stats)
	}
	if got := h.notices(scope, owner); len(got) != 0 {
		t.Fatalf("victim notified: %+v", got)
	}
	if got := h.notices(otherScope, otherOwner); len(got) != 0 {
		t.Fatalf("other tenant notified: %+v", got)
	}
	var windows int
	if err := h.pool.QueryRow(t.Context(), `SELECT count(*) FROM cc_auto_switch_notification_windows
		WHERE site_id IN ($1,$2)`, site, otherSite).Scan(&windows); err != nil || windows != 0 {
		t.Fatalf("rejected engagements opened windows=%d err=%v", windows, err)
	}
	// The legitimate engagement is still notified afterwards.
	h.report(serving, scope, site, engaged)
	if got := h.notices(scope, owner); len(got) != 1 {
		t.Fatalf("legitimate engagement notices=%+v", got)
	}
}

// 事件被管理员关闭：窗口照常推进，不入队。
func TestCCAutoSwitchRespectsDisabledEventPolicy(t *testing.T) {
	h := newHarness(t)
	platform := uuid.New()
	h.exec(`INSERT INTO access_scopes(id,kind,created_at) VALUES($1,'platform',now())`, platform)
	scope, owner, site, _ := h.tenant("cc-quiet")
	node := h.node(platform, owner, scope)
	h.exec(`UPDATE notification_event_policies SET enabled=false WHERE event_type=$1`, ccautoswitch.EventType)
	t.Cleanup(func() {
		_, _ = h.pool.Exec(context.Background(), `UPDATE notification_event_policies SET enabled=true WHERE event_type=$1`, ccautoswitch.EventType)
	})
	h.report(node, scope, site, time.Now().Add(-time.Minute))
	var outbox int
	if err := h.pool.QueryRow(t.Context(), `SELECT count(*) FROM notification_events event
		JOIN notification_outbox outbox ON outbox.event_id=event.id WHERE event.scope_id=$1`, scope).Scan(&outbox); err != nil || outbox != 0 {
		t.Fatalf("disabled event delivered outbox=%d err=%v", outbox, err)
	}
}
