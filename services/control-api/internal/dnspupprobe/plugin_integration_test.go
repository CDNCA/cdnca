package dnspupprobe

import (
	"crypto/sha256"
	"errors"
	"strings"
	"testing"
	"time"

	"github.com/cdnca/cdnca/services/control-api/internal/dnspupprobe/dnspuptest"
	"github.com/google/uuid"
)

// seedPluginKey creates a tenant, an enabled plugin installation and an API
// key bound to it (bound=false: a plain key of the same tenant).
func (f *serviceFixture) seedPluginKey(t *testing.T, bound bool) PluginActor {
	t.Helper()
	tenant, scope, user := uuid.New(), uuid.New(), uuid.New()
	mustExecTest(t, f.pool, `INSERT INTO tenants(id,display_name,created_at,updated_at) VALUES($1,'pp',$2,$2)`, tenant, f.now)
	mustExecTest(t, f.pool, `INSERT INTO access_scopes(id,kind,tenant_id,created_at) VALUES($1,'tenant',$2,$3)`, scope, tenant, f.now)
	mustExecTest(t, f.pool, `INSERT INTO users(id,username,display_name,password_hash,status,created_at,updated_at)
		VALUES($1,$2,$2,'not-used','active',$3,$3)`, user, "ppk-"+strings.ReplaceAll(user.String(), "-", "")[:20], f.now)
	mustExecTest(t, f.pool, `INSERT INTO memberships(scope_id,user_id,status,created_at) VALUES($1,$2,'active',$3)`, scope, user, f.now)
	authorization, installation := uuid.New(), uuid.New()
	digest := sha256.Sum256([]byte("io.cdnca.cf-optimize"))
	mustExecTest(t, f.pool, `INSERT INTO plugin_installation_heads(tenant_scope_id,authorization_id,installation_id,
		verification_id,plugin_id,plugin_version,manifest_sha256,configuration_schema_sha256,manifest_scopes,approved_scopes,
		sensitive_scopes,status,revision,identity_generation,created_at,updated_at,entrypoint_type)
		VALUES($1,$2,$3,$4,'io.cdnca.cf-optimize','1.0.0',$5,$5,ARRAY['probes.dnspup.request'],ARRAY['probes.dnspup.request'],
		ARRAY[]::text[],'enabled',1,1,clock_timestamp(),clock_timestamp(),'external_https')`,
		scope, authorization, installation, uuid.New(), digest[:])
	key := uuid.New()
	prefix := "cfk_" + strings.ReplaceAll(key.String(), "-", "")[:22]
	if bound {
		mustExecTest(t, f.pool, `INSERT INTO api_keys(id,key_id,key_prefix,scope_id,tenant_id,user_id,name,scopes,secret_digest,
			pepper_version,status,activated_at,created_by_user_id,plugin_installation_authorization_id,plugin_installation_id,plugin_id)
			VALUES($1,$2,$2||'.',$3,$4,$5,'pp',ARRAY['probes.dnspup.request'],$6,'legacy-v1','active',now(),$5,$7,$8,
			'io.cdnca.cf-optimize')`, key, prefix, scope, tenant, user, digest[:], authorization, installation)
	} else {
		mustExecTest(t, f.pool, `INSERT INTO api_keys(id,key_id,key_prefix,scope_id,tenant_id,user_id,name,scopes,secret_digest,
			pepper_version,status,activated_at,created_by_user_id)
			VALUES($1,$2,$2||'.',$3,$4,$5,'pp',ARRAY['probes.dnspup.request'],$6,'legacy-v1','active',now(),$5)`,
			key, prefix, scope, tenant, user, digest[:])
	}
	return PluginActor{ScopeID: scope, UserID: user, KeyID: key, Permissions: []string{PermissionPluginRequest}}
}

func (f *serviceFixture) enable(t *testing.T) {
	t.Helper()
	if _, err := f.service.UpdateSettings(t.Context(), f.admin, "enable-"+uuid.NewString()[:8], f.input(true, ptr(f.fake.Secret))); err != nil {
		t.Fatal(err)
	}
}

func TestPluginProbeRequestsLimitsIsolationAndMetering(t *testing.T) {
	f := newServiceFixture(t)
	ctx := t.Context()
	plugin := f.seedPluginKey(t, true)
	// Not configured yet: a clear reason, nothing created.
	if status, err := f.service.PluginStatus(ctx, plugin); err != nil || status.Available || status.Reason != ReasonNotConfigured {
		t.Fatalf("status before configuration %+v %v", status, err)
	}
	if _, err := f.service.CreatePluginRequest(ctx, plugin, "r0", ProbeInput{Type: "tcping", Target: "203.0.113.5", Port: 443}); !errors.Is(err, ErrNotConfigured) {
		t.Fatalf("create before configuration: %v", err)
	}
	f.features.grant(false)
	if status, _ := f.service.PluginStatus(ctx, plugin); status.Reason != ReasonNotInstalled {
		t.Fatalf("status without module: %+v", status)
	}
	f.features.grant(true)
	f.enable(t)
	f.fake.Do(func(fake *dnspuptest.Server) {
		fake.AllowedTools = []string{"tcping", "http", "dns", "mtr"}
		fake.Checkpoints = []dnspuptest.Checkpoint{{ID: "gd-ct", Region: "广东", ISP: "电信", Status: "online"},
			{ID: "gd-cm", Region: "广东", ISP: "移动", Status: "online"}, {ID: "hk-1", Region: "香港", ISP: "HKBN"}}
		fake.Answer = func(request dnspuptest.ProbeRequest) []dnspuptest.Result {
			return []dnspuptest.Result{{NodeID: "gd-ct", Region: "广东", ISP: "电信", Status: "ok", AvgLatency: 31},
				{NodeID: "gd-cm", Region: "广东", ISP: "移动", Status: "timeout", ErrorCode: "tcp_connect_timeout"}}
		}
	})
	mustExecTest(t, f.pool, `UPDATE probe_dnspup_settings SET plugin_per_minute=2`)
	input := ProbeInput{Type: "tcping", Target: "203.0.113.5", Port: 443,
		Selection: Selection{Areas: []string{AreaMainland}, PointsPerGroup: 1}}
	created, err := f.service.CreatePluginRequest(ctx, plugin, "r1", input)
	if err != nil || created.Status != "pending" {
		t.Fatalf("create %+v %v", created, err)
	}
	if body := f.fake.Bodies[len(f.fake.Bodies)-1]; body.Type != "tcping" || len(body.NodeIDs) != 2 || body.Port != 443 {
		t.Fatalf("dnspup body = %+v (mainland, one per carrier: gd-cm + gd-ct)", body)
	}
	if again, err := f.service.CreatePluginRequest(ctx, plugin, "r1", input); err != nil || again.ID != created.ID {
		t.Fatalf("replay %+v %v", again, err)
	}
	if _, err := f.service.CreatePluginRequest(ctx, plugin, "r1", ProbeInput{Type: "ping", Target: "203.0.113.5"}); !errors.Is(err, ErrIdempotency) {
		t.Fatalf("idempotency conflict: %v", err)
	}
	// Results: poll at most every 2 s; running first, then completed.
	var view ProbeRequestView
	for range 3 {
		f.now = f.now.Add(3 * time.Second)
		if view, err = f.service.GetPluginRequest(ctx, plugin, created.ID); err != nil {
			t.Fatal(err)
		}
	}
	if view.Status != "completed" || len(view.Results) != 2 {
		t.Fatalf("view %+v", view)
	}
	for _, result := range view.Results {
		if result.ID == "gd-cm" && (result.OK || result.Failure != FailureTimeout || result.Line != CarrierMobile) ||
			result.ID == "gd-ct" && (!result.OK || result.Latency != 31 || result.Province != "广东") {
			t.Fatalf("result %+v", result)
		}
	}
	// Results go back to the caller only.
	other := f.seedPluginKey(t, true)
	if _, err := f.service.GetPluginRequest(ctx, other, created.ID); !errors.Is(err, ErrRequestNotFound) {
		t.Fatalf("other installation read: %v", err)
	}
	if _, err := f.service.PluginStatus(ctx, f.seedPluginKey(t, false)); !errors.Is(err, ErrPluginIdentity) {
		t.Fatalf("unbound key: %v", err)
	}
	if _, err := f.service.PluginStatus(ctx, PluginActor{ScopeID: plugin.ScopeID, KeyID: plugin.KeyID}); !errors.Is(err, ErrPermissionDenied) {
		t.Fatalf("no permission: %v", err)
	}
	// Per-minute limit (2): the second new request passes, the third is refused.
	if _, err := f.service.CreatePluginRequest(ctx, plugin, "r2", ProbeInput{Type: "https", Target: "https://www.example.com/",
		Selection: Selection{PointsPerGroup: 1}}); err != nil {
		t.Fatal(err)
	}
	if _, err := f.service.CreatePluginRequest(ctx, plugin, "r3", ProbeInput{Type: "ping", Target: "203.0.113.6"}); !errors.Is(err, ErrPluginRateLimited) {
		t.Fatalf("rate limit: %v", err)
	}
	if got := f.count(t, `SELECT requests FROM probe_dnspup_plugin_usage WHERE tenant_scope_id=$1`, plugin.ScopeID); got != 2 {
		t.Fatalf("tenant usage = %d", got)
	}
	if got := f.count(t, `SELECT requests FROM probe_dnspup_usage WHERE purpose='plugin'`); got != 2 {
		t.Fatalf("plugin purpose usage = %d", got)
	}
	// Tenant monthly limit and the purpose cap both stop it.
	f.now = f.now.Add(2 * time.Minute)
	mustExecTest(t, f.pool, `UPDATE probe_dnspup_settings SET plugin_tenant_monthly=2`)
	if _, err := f.service.CreatePluginRequest(ctx, plugin, "r4", ProbeInput{Type: "ping", Target: "203.0.113.6"}); !errors.Is(err, ErrPluginQuota) {
		t.Fatalf("tenant monthly: %v", err)
	}
	mustExecTest(t, f.pool, `UPDATE probe_dnspup_settings SET plugin_tenant_monthly=0`)
	mustExecTest(t, f.pool, `UPDATE probe_dnspup_purposes SET monthly_cap=2 WHERE purpose='plugin'`)
	if status, _ := f.service.PluginStatus(ctx, plugin); status.Available || status.Reason != "probe_dnspup_quota_exceeded" {
		t.Fatalf("purpose cap status %+v", status)
	}
	// Invalid targets never reach dnspup.
	creates := f.fake.Creates
	for _, bad := range []ProbeInput{{Type: "tcping", Target: "10.0.0.1", Port: 80}, {Type: "http", Target: "ftp://a.example"},
		{Type: "mtr", Target: "203.0.113.5"}, {Type: "dns", Target: "1.2.3.4"}} {
		if _, err := f.service.CreatePluginRequest(ctx, plugin, "bad-"+uuid.NewString()[:8], bad); !errors.Is(err, ErrInvalidInput) {
			t.Errorf("bad input %+v: %v", bad, err)
		}
	}
	if f.fake.Creates != creates {
		t.Fatalf("invalid inputs created dnspup jobs")
	}
}

func TestPurposeGatesMeteringObservationsAndDiagnose(t *testing.T) {
	f := newServiceFixture(t)
	ctx := t.Context()
	f.enable(t)
	f.fake.Do(func(fake *dnspuptest.Server) {
		fake.AllowedTools = []string{"tcping", "mtr"}
		fake.Answer = func(dnspuptest.ProbeRequest) []dnspuptest.Result {
			return []dnspuptest.Result{{NodeID: "gd-ct", Region: "广东", ISP: "电信", Status: "ok", AvgLatency: 12},
				{NodeID: "bj-cu", Region: "北京", ISP: "联通", Status: "bad", ErrorCode: "tcp_connect_refused"}}
		}
		fake.AnswerTraces = func(dnspuptest.ProbeRequest) []map[string]any {
			return []map[string]any{{"nodeId": "gd-ct", "status": "ok", "trace": map[string]any{"hops": []any{}}}}
		}
	})
	runtime := f.service.Runtime(ctx)
	if runtime.Probe == nil || runtime.Stopped(ConsumerEdge) {
		t.Fatalf("runtime %+v", runtime.Gates)
	}
	results, err := runtime.Probe(ctx, ConsumerEdge, "site", "edge.example.net|443", runtime.RoundFor(ConsumerEdge, f.now, time.Minute),
		ProbeRequest{Type: "tcping", Target: "edge.example.net", Port: 443})
	if err != nil || len(results) != 2 {
		t.Fatalf("edge probe %v %v", results, err)
	}
	if got := f.count(t, `SELECT requests FROM probe_dnspup_usage WHERE purpose='edge_health'`); got != 1 {
		t.Fatalf("edge usage = %d", got)
	}
	matrix, err := f.service.ReadMatrix(ctx, f.admin, SubjectEdge, "edge.example.net", "1h")
	if err != nil || len(matrix.Cells) != 2 || len(matrix.Series) != 1 {
		t.Fatalf("matrix %+v %v", matrix, err)
	}
	for _, cell := range matrix.Cells {
		if cell.Area == "北京" && (cell.Carrier != CarrierUnicom || cell.Availability != 0 || cell.TopFailure != FailureRefused) ||
			cell.Area == "广东" && (cell.Availability != 1 || cell.AvgLatencyMS != 12) {
			t.Fatalf("cell %+v", cell)
		}
	}
	if _, err := f.service.ReadMatrix(ctx, f.viewer, SubjectEdge, "edge.example.net", "1h"); !errors.Is(err, ErrPermissionDenied) {
		t.Fatalf("viewer matrix: %v", err)
	}
	// A purpose at its cap stops; availability purposes cannot be disabled.
	enabled, capped, zero := true, int64(1), 0
	view, err := f.service.UpdatePurposes(ctx, f.admin, "p1", []PurposeInput{{Purpose: PurposeEdgeHealth, Enabled: &enabled,
		MonthlyCap: &capped, IntervalSeconds: &zero}})
	if err != nil {
		t.Fatal(err)
	}
	for _, item := range view.Purposes {
		if item.Purpose == PurposeEdgeHealth && (!item.Gate.Stopped || item.Gate.Reason != "monthly_cap" || item.UsedThisMonth != 1) {
			t.Fatalf("capped edge %+v", item)
		}
	}
	disabled := false
	if _, err := f.service.UpdatePurposes(ctx, f.admin, "p2", []PurposeInput{{Purpose: PurposeNodeAvailability, Enabled: &disabled,
		MonthlyCap: &capped, IntervalSeconds: &zero}}); !errors.Is(err, ErrInvalidInput) {
		t.Fatalf("disable availability: %v", err)
	}
	runtime = f.service.Runtime(ctx)
	if _, err := runtime.Probe(ctx, ConsumerEdge, "site", "other|443", 9, ProbeRequest{Type: "tcping", Target: "other.example.net",
		Port: 443}); !errors.Is(err, ErrBudgetStopped) {
		t.Fatalf("capped edge probe: %v", err)
	}
	// A slowed purpose stretches its round.
	interval := 600
	if _, err := f.service.UpdatePurposes(ctx, f.admin, "p3", []PurposeInput{{Purpose: PurposeOriginFailover, Enabled: &enabled,
		MonthlyCap: new(int64), IntervalSeconds: &interval}}); err != nil {
		t.Fatal(err)
	}
	if got := f.service.Runtime(ctx).IntervalFor(ConsumerOrigin, 15*time.Second); got != 10*time.Minute {
		t.Fatalf("origin interval = %s", got)
	}
	// Diagnose: mtr from at most 2 checkpoints, metered as diagnose, audited.
	if _, err := f.service.CreateDiagnose(ctx, f.admin, "d0", DiagnoseInput{Target: "203.0.113.9",
		Checkpoints: []string{"a", "b", "c"}}); !errors.Is(err, ErrInvalidInput) {
		t.Fatalf("3 checkpoints: %v", err)
	}
	diagnosis, err := f.service.CreateDiagnose(ctx, f.admin, "d1", DiagnoseInput{Target: "203.0.113.9", Checkpoints: []string{"gd-ct"}})
	if err != nil || diagnosis.Type != "mtr" {
		t.Fatalf("diagnose %+v %v", diagnosis, err)
	}
	if body := f.fake.Bodies[len(f.fake.Bodies)-1]; body.Type != "mtr" || body.Count != 100 || len(body.NodeIDs) != 1 {
		t.Fatalf("mtr body %+v", body)
	}
	for range 3 {
		f.now = f.now.Add(3 * time.Second)
		if diagnosis, err = f.service.GetDiagnose(ctx, f.admin, diagnosis.ID); err != nil {
			t.Fatal(err)
		}
	}
	if diagnosis.Status != "completed" || !strings.Contains(string(diagnosis.Traces), "hops") {
		t.Fatalf("diagnosis %+v", diagnosis)
	}
	if got := f.count(t, `SELECT requests FROM probe_dnspup_usage WHERE purpose='diagnose'`); got != 1 {
		t.Fatalf("diagnose usage = %d", got)
	}
	if got := f.count(t, `SELECT count(*) FROM audit_events WHERE action IN ($1,$2)`, ActionPurposes, ActionDiagnose); got < 3 {
		t.Fatalf("audit rows = %d", got)
	}
}
