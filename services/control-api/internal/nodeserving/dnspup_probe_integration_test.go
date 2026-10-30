package nodeserving

import (
	"bytes"
	"context"
	"crypto/sha256"
	"fmt"
	"net/http/httptest"
	"strings"
	"sync"
	"testing"
	"time"

	"github.com/cdnca/cdnca/services/control-api/internal/dnsacme"
	"github.com/cdnca/cdnca/services/control-api/internal/dnspupprobe"
	"github.com/cdnca/cdnca/services/control-api/internal/dnspupprobe/dnspuptest"
	"github.com/cdnca/cdnca/services/control-api/internal/nodednspupprobe"
	"github.com/cdnca/cdnca/services/control-api/internal/notification"
	"github.com/google/uuid"
	"github.com/jackc/pgx/v5"
)

type grantedFeatures struct{}

func (grantedFeatures) ReadValidFeatures(context.Context, pgx.Tx) (map[string]bool, error) {
	return map[string]bool{dnspupprobe.Feature: true}, nil
}

// dnspupHarness wires the official plugin (fake dnspup), the node probe
// runner and the availability monitor on one migrated schema.
type dnspupHarness struct {
	*servingHarness
	fake    *dnspuptest.Server
	runner  *nodednspupprobe.Runner
	worker  *Worker
	clock   time.Time
	mu      sync.Mutex
	failing map[string]bool // target IP → every checkpoint fails
}

func newDNSPupHarness(t *testing.T) *dnspupHarness {
	h := &dnspupHarness{servingHarness: newServingHarness(t), failing: map[string]bool{},
		clock: time.Now().UTC().Truncate(time.Second)}
	var server *httptest.Server
	h.fake, server = dnspuptest.New()
	t.Cleanup(server.Close)
	h.fake.PollsUntilDone = -1 // jobs complete on create: no 2 s poll
	h.fake.MonthlyLimit = 100_000
	h.fake.Checkpoints = []dnspuptest.Checkpoint{
		{ID: "t1", Region: "广东", ISP: "电信", Status: "online"}, {ID: "t2", Region: "上海", ISP: "电信", Status: "online"},
		{ID: "u1", Region: "北京", ISP: "联通", Status: "online"}, {ID: "m1", Region: "浙江", ISP: "移动", Status: "online"},
	}
	isp := map[string]string{"t1": "电信", "t2": "电信", "u1": "联通", "m1": "移动"}
	h.fake.Answer = func(request dnspuptest.ProbeRequest) []dnspuptest.Result {
		h.mu.Lock()
		failing := h.failing[request.Target]
		h.mu.Unlock()
		var out []dnspuptest.Result
		for _, id := range request.NodeIDs {
			status := "ok"
			if failing {
				status = "timeout"
			}
			out = append(out, dnspuptest.Result{NodeID: id, Region: "广东", ISP: isp[id], Status: status, LatencyMS: 12})
		}
		return out
	}
	cipher, err := dnsacme.NewAESGCMCredentialCipher("probe-node-test-kek", bytes.Repeat([]byte{0x4d}, 32))
	if err != nil {
		t.Fatal(err)
	}
	alerts, err := notification.NewStore(h.pool)
	if err != nil {
		t.Fatal(err)
	}
	now := func() time.Time { h.mu.Lock(); defer h.mu.Unlock(); return h.clock }
	service, err := dnspupprobe.New(dnspupprobe.Config{Pool: h.pool, Cipher: cipher, Features: grantedFeatures{},
		Alerts: alerts, Now: now})
	if err != nil {
		t.Fatal(err)
	}
	// Enable the plugin with the fake's key pair (the settings API path).
	session := h.Session(dnspupprobe.PermissionManage)
	secret := h.fake.Secret
	if _, err := service.UpdateSettings(h.ctx, dnspupprobe.Actor{UserID: h.userID, ScopeID: h.scopeID, SessionID: session},
		"enable-1", dnspupprobe.SettingsInput{Enabled: true, BaseURL: server.URL, APIKey: h.fake.APIKey, APISecret: &secret}); err != nil {
		t.Fatal(err)
	}
	h.runner, err = nodednspupprobe.NewRunner(nodednspupprobe.Config{Pool: h.pool, Sources: service.Runtime,
		Alerts: alerts, Now: now})
	if err != nil {
		t.Fatal(err)
	}
	h.exec(`UPDATE notification_channel_settings SET sms_enabled=true,email_enabled=true WHERE singleton`)
	h.exec(`INSERT INTO role_permissions(role_id,permission_name)
		SELECT role_id,permission FROM role_assignments, unnest(ARRAY['nodes.manage','system.probe_dnspup.manage']) permission
		WHERE scope_id=$1 AND user_id=$2 ON CONFLICT DO NOTHING`, h.scopeID, h.userID)
	h.worker, err = NewWorker(h.store, time.Second, nil, NewMonitorEvaluator(h.store))
	if err != nil {
		t.Fatal(err)
	}
	return h
}

func (h *dnspupHarness) fail(address string, on bool) {
	h.mu.Lock()
	h.failing[address] = on
	h.mu.Unlock()
}

// tick advances the clock one 5-minute round and runs the dnspup round.
func (h *dnspupHarness) tick(t *testing.T) {
	t.Helper()
	h.mu.Lock()
	h.clock = h.clock.Add(5 * time.Minute)
	h.mu.Unlock()
	if err := h.runner.RunOnce(h.ctx); err != nil {
		t.Fatal(err)
	}
}

func (h *dnspupHarness) evaluate(t *testing.T) {
	t.Helper()
	if err := h.worker.RunOnce(h.ctx); err != nil {
		t.Fatal(err)
	}
}

func (h *dnspupHarness) count(t *testing.T, query string, args ...any) int {
	t.Helper()
	var value int
	if err := h.pool.QueryRow(h.ctx, query, args...).Scan(&value); err != nil {
		t.Fatal(err)
	}
	return value
}

// 本机探测与 dnspup 多数检测点都失败才停调度（连续 3 次）；
// 仅 dnspup 失败只告警；本机失败但 dnspup 可达不停调度。
func TestDNSPupNodeProbeNeedsBothSourcesToPause(t *testing.T) {
	h := newDNSPupHarness(t)
	both, dnspupOnly, localOnly := h.addNode(), h.addNode(), h.addNode()
	h.lineGroup(map[uuid.UUID]string{both: "198.51.100.1", dnspupOnly: "198.51.100.2", localOnly: "198.51.100.3"})
	h.activate("pause")
	h.fail("198.51.100.1", true)
	h.fail("198.51.100.2", true)
	for range 3 {
		h.tick(t)
	}
	// 默认三网各 3 点；fake 电信只有 2 个检测点、联通/移动各 1 个 → 每轮 4 个检测点。
	if got := h.count(t, `SELECT count(*) FROM node_dnspup_probe_results WHERE node_id=$1 AND failed
		AND failed_checks=4 AND total_checks=4 AND jsonb_array_length(checkpoints)=4`, both); got != 3 {
		t.Fatalf("failed log rows of node both = %d", got)
	}
	if got := h.count(t, `SELECT count(*) FROM node_dnspup_probe_states WHERE failing`); got != 2 {
		t.Fatalf("failing dnspup verdicts = %d, want 2", got)
	}
	h.report(both, false, false, time.Second)
	h.report(dnspupOnly, true, true, time.Second)
	h.report(localOnly, false, false, time.Second)
	h.evaluate(t)
	if held, reason, _ := h.hold(both); !held || reason != ReasonProbeUnhealthy {
		t.Fatalf("both failed: held=%v reason=%q", held, reason)
	}
	if held, _, _ := h.hold(dnspupOnly); held {
		t.Fatal("dnspup failing alone paused the node")
	}
	if held, _, _ := h.hold(localOnly); held {
		t.Fatal("local failing while dnspup reaches the node paused it")
	}
	// dnspup 单独失败要告警（node.dnspup.unreachable 给 nodes.manage）。
	if got := h.count(t, `SELECT count(*) FROM notification_events WHERE event_type='node.dnspup.unreachable'`); got != 2 {
		t.Fatalf("dnspup unreachable alerts = %d", got)
	}
	if got := h.count(t, `SELECT count(*) FROM audit_events WHERE action='node.dnspup_probe.verdict' AND resource_id=$1`, dnspupOnly.String()); got != 1 {
		t.Fatalf("verdict audits = %d", got)
	}
	// dnspup 恢复后即释放（本机仍失败也不再停调度）。
	h.fail("198.51.100.1", false)
	h.tick(t)
	h.report(both, false, false, time.Second)
	h.evaluate(t)
	if held, reason, _ := h.hold(both); held || reason != ReasonDNSPupReachable {
		t.Fatalf("dnspup recovered: held=%v reason=%q", held, reason)
	}
	if got := h.count(t, `SELECT count(*) FROM notification_events WHERE event_type='node.dnspup.recovered'`); got != 1 {
		t.Fatalf("dnspup recovered alerts = %d", got)
	}
}

// 额度：低于预警线降频并通知；用完停止 dnspup 拨测、回落本机探测，不因缺数据判离线。
func TestDNSPupNodeProbeBudgetDegradesAndFallsBack(t *testing.T) {
	h := newDNSPupHarness(t)
	node := h.addNode()
	h.lineGroup(map[uuid.UUID]string{node: "198.51.100.9"})
	h.activate("pause")
	h.fake.Do(func(fake *dnspuptest.Server) { fake.MonthlyLimit, fake.MonthlyUsed = 1000, 500 })
	h.tick(t)
	if _, budget, err := nodednspupprobe.ReadSettings(h.ctx, h.pool); err != nil || budget != nodednspupprobe.BudgetLow {
		t.Fatalf("budget=%q err=%v", budget, err)
	}
	if got := h.count(t, `SELECT count(*) FROM notification_events WHERE event_type='probe.dnspup.balance_low'`); got != 1 {
		t.Fatalf("balance low alerts = %d (outbox=%d)", got, h.count(t, `SELECT count(*) FROM notification_outbox`))
	}
	creates := 0
	h.fake.Do(func(fake *dnspuptest.Server) { creates = fake.Creates })
	h.tick(t) // 5 分钟 < 降频后的 15 分钟：不拨测
	h.fake.Do(func(fake *dnspuptest.Server) {
		if fake.Creates != creates {
			t.Errorf("probed again after 5 min at low balance: %d → %d", creates, fake.Creates)
		}
	})
	h.tick(t)
	h.tick(t) // 第 15 分钟到期
	h.fake.Do(func(fake *dnspuptest.Server) {
		if fake.Creates != creates+1 {
			t.Errorf("low balance round not probed at 15 min: %d → %d", creates, fake.Creates)
		}
	})

	// 用完：停止拨测、通知、本机探测单独判定。
	h.fail("198.51.100.9", true)
	h.fake.Do(func(fake *dnspuptest.Server) { fake.MonthlyUsed = fake.MonthlyLimit })
	h.mu.Lock()
	h.clock = h.clock.Add(time.Hour) // 旧判定已过期
	h.mu.Unlock()
	if err := h.runner.RunOnce(h.ctx); err != nil {
		t.Fatal(err)
	}
	if _, budget, _ := nodednspupprobe.ReadSettings(h.ctx, h.pool); budget != nodednspupprobe.BudgetExhausted {
		t.Fatalf("budget=%q", budget)
	}
	if got := h.count(t, `SELECT count(*) FROM notification_events WHERE event_type='probe.dnspup.balance_exhausted'`); got != 1 {
		t.Fatalf("balance exhausted alerts = %d", got)
	}
	h.fake.Do(func(fake *dnspuptest.Server) {
		if fake.Creates != creates+1 {
			t.Errorf("probed with no balance left: %d", fake.Creates)
		}
	})
	// fresh_until 用数据库时钟判断：把状态置为过期，回落本机。
	h.exec(`UPDATE node_dnspup_probe_states SET fresh_until=clock_timestamp()-interval '1 second'`)
	h.report(node, true, true, time.Second)
	h.evaluate(t)
	if held, _, _ := h.hold(node); held {
		t.Fatal("no dnspup data held a locally healthy node")
	}
	h.report(node, false, false, time.Second)
	h.evaluate(t)
	if held, reason, _ := h.hold(node); !held || reason != ReasonProbeUnhealthy {
		t.Fatalf("local probe alone: held=%v reason=%q", held, reason)
	}
	if got := h.count(t, `SELECT count(*) FROM audit_events WHERE action='system.probe_dnspup.node_budget'`); got != 2 {
		t.Fatalf("budget audits = %d", got)
	}
}

// 设置写入要审计，非法值拒绝，无权限拒绝。
func TestDNSPupNodeProbeSettingsAreAudited(t *testing.T) {
	h := newDNSPupHarness(t)
	store, err := nodednspupprobe.NewStore(h.pool, grantedFeatures{}, time.Now)
	if err != nil {
		t.Fatal(err)
	}
	admin := dnspupprobe.Actor{UserID: h.userID, ScopeID: h.scopeID, SessionID: h.Session(dnspupprobe.PermissionManage), IP: "203.0.113.9"}
	value := nodednspupprobe.DefaultSettings()
	value.IntervalSeconds, value.Groups = 60, []string{"mobile", "telecom"}
	status, err := store.Update(h.ctx, admin, "node-settings-1", value)
	if err != nil || status.IntervalSeconds != 60 || strings.Join(status.Groups, ",") != "telecom,mobile" || !status.PluginActive ||
		status.Estimate.RoundsPerDay != 1440 || status.BalanceUnit != "request" {
		t.Fatalf("update = %+v err=%v", status, err)
	}
	if replay, err := store.Update(h.ctx, admin, "node-settings-1", value); err != nil || replay.Revision != status.Revision {
		t.Fatalf("replay = %+v err=%v", replay, err)
	}
	value.IntervalSeconds = 120
	if _, err := store.Update(h.ctx, admin, "node-settings-2", value); err != nodednspupprobe.ErrInvalidSettings {
		t.Fatalf("invalid interval err=%v", err)
	}
	if got := h.count(t, `SELECT count(*) FROM audit_events WHERE action='system.probe_dnspup.node_settings' AND result='success'
		AND changes @> '[{"field":"interval_seconds"}]' AND source_ip='203.0.113.9'`); got != 1 {
		t.Fatalf("success audits = %d", got)
	}
	if got := h.count(t, `SELECT count(*) FROM audit_events WHERE action='system.probe_dnspup.node_settings' AND result='failure'`); got != 1 {
		t.Fatalf("failure audits = %d", got)
	}
	// 无 system.probe_dnspup.manage / platform.admin 的平台成员不能修改。
	viewer := h.member()
	if _, err := store.Update(h.ctx, viewer, "node-settings-3", nodednspupprobe.DefaultSettings()); err != nodednspupprobe.ErrPermissionDenied {
		t.Fatalf("viewer update err=%v", err)
	}
}

// Session adds an auth session for the harness owner (platform.admin).
func (h *dnspupHarness) Session(...string) uuid.UUID {
	return h.session(h.userID)
}

func (h *dnspupHarness) session(user uuid.UUID) uuid.UUID {
	id := uuid.New()
	refresh := sha256.Sum256(id[:])
	h.exec(`INSERT INTO auth_sessions(id,family_id,user_id,scope_id,refresh_token_hash,created_at,expires_at)
		VALUES($1,$1,$2,$3,$4,now()-interval '1 hour',now()+interval '30 days')`, id, user, h.scopeID, refresh[:])
	return id
}

// member is a platform member without any role.
func (h *dnspupHarness) member() dnspupprobe.Actor {
	user := uuid.New()
	h.exec(`INSERT INTO users(id,username,display_name,password_hash) VALUES($1,$2,'member','test-only')`, user,
		fmt.Sprintf("member-%s", strings.ReplaceAll(user.String(), "-", "")[:12]))
	h.exec(`INSERT INTO memberships(scope_id,user_id) VALUES($1,$2)`, h.scopeID, user)
	return dnspupprobe.Actor{UserID: user, ScopeID: h.scopeID, SessionID: h.session(user)}
}
