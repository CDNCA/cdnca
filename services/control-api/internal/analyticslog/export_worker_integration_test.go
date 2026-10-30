//go:build integration

package analyticslog

import (
	"context"
	"errors"
	"strings"
	"testing"
	"time"

	"github.com/cdnca/cdnca/services/control-api/internal/database/databasetest"
	"github.com/google/uuid"
	"github.com/jackc/pgx/v5/pgxpool"
)

type exportWorkerFixture struct {
	pool     *pgxpool.Pool
	tenantID uuid.UUID
	actor    Actor
}

func newExportWorkerFixture(t *testing.T) exportWorkerFixture {
	t.Helper()
	pool := databasetest.MigratedPool(t, nil)
	tenantID, scopeID, userID, sessionID := uuid.New(), uuid.New(), uuid.New(), uuid.New()
	for _, statement := range []struct {
		sql  string
		args []any
	}{
		{`INSERT INTO tenants(id,display_name) VALUES($1,'export worker tenant')`, []any{tenantID}},
		{`INSERT INTO access_scopes(id,kind,tenant_id) VALUES($1,'tenant',$2)`, []any{scopeID, tenantID}},
		{`INSERT INTO users(id,username,display_name,password_hash) VALUES($1,$2,$2,'test-only-hash')`,
			[]any{userID, "export-worker-" + userID.String()[:8]}},
		{`INSERT INTO memberships(scope_id,user_id) VALUES($1,$2)`, []any{scopeID, userID}},
	} {
		if _, err := pool.Exec(t.Context(), statement.sql, statement.args...); err != nil {
			t.Fatal(err)
		}
	}
	return exportWorkerFixture{pool: pool, tenantID: tenantID, actor: Actor{
		ScopeKind: "tenant", TenantID: tenantID.String(), ActorID: userID.String(),
		ScopeID: scopeID.String(), SessionID: sessionID.String(), Permissions: []string{ReadPermission},
	}}
}

func exportWorkerStore(snapshot time.Time) *obs05PagedStore {
	return &obs05PagedStore{pages: []AccessPage{{
		Items: []AccessLog{{
			EventID: "event-a", OccurredAt: snapshot.Add(-time.Minute), SiteID: siteA, NodeID: nodeA,
			Host: "example.test", URIPath: "/index", Method: "GET", Protocol: "HTTP/2",
			StatusCode: 200, CountryCode: "CN", Carrier: "carrier", UpstreamResult: "success",
		}},
		SnapshotAt: snapshot,
	}}}
}

// TF-C01：后台 worker（runWorker 用 context.Background）完成导出时，完成审计
// 必须带上创建请求持久化的 request_id，否则 audit_events_request_id_check 让
// 整个完成事务回滚，导出与统一任务永远停在 running。TF-C02：有效授权的
// Consume 在真实 PG 上不能因 SQL 保留字别名失败，且只能消费一次。
func TestExportNaturalWorkerCompletesAndDownloadsOnceWithPostgres17(t *testing.T) {
	fixture := newExportWorkerFixture(t)
	now := time.Now().UTC().Truncate(time.Second)
	manager, err := NewExportManager(fixture.pool, exportWorkerStore(now), func() time.Time { return now })
	if err != nil {
		t.Fatal(err)
	}
	ctx := WithRequestID(t.Context(), "req-export-worker-1")
	created, replayed, err := manager.Create(ctx, fixture.actor, QueryRequest{
		Audience: AudienceTenant, Limit: MaxLimit,
		Filter: Filter{From: now.Add(-time.Hour), To: now},
	}, "export-worker-key-1")
	if err != nil || replayed {
		t.Fatalf("Create() = (%#v, %v, %v)", created, replayed, err)
	}

	// Create 已 kick 真实 runWorker；不在测试上下文里补 requestID。
	deadline := time.Now().Add(30 * time.Second)
	var job AccessExport
	for {
		job, err = manager.Get(t.Context(), fixture.actor, AudienceTenant, "", created.ID)
		if err != nil {
			t.Fatalf("Get() error = %v", err)
		}
		if job.Status == ExportCompleted || job.Status == ExportFailed || time.Now().After(deadline) {
			break
		}
		time.Sleep(50 * time.Millisecond)
	}
	if job.Status != ExportCompleted || !job.Downloadable || job.RowCount == nil || *job.RowCount != 1 {
		t.Fatalf("export after natural worker = %#v, want completed downloadable 1 row", job)
	}
	// LOG-02：Get/List 带回冻结的原查询条件（真实 jsonb 列往返）。
	if job.Filter == nil || job.Filter.From != now.Add(-time.Hour).UTC().Format(time.RFC3339Nano) ||
		job.Filter.To != now.UTC().Format(time.RFC3339Nano) {
		t.Fatalf("export filter summary = %#v", job.Filter)
	}
	var jobState, completeRequestID string
	if err := fixture.pool.QueryRow(t.Context(), `SELECT state FROM background_jobs WHERE id=$1`,
		created.ID).Scan(&jobState); err != nil || jobState != "succeeded" {
		t.Fatalf("background job state = %q, %v; want succeeded", jobState, err)
	}
	if err := fixture.pool.QueryRow(t.Context(), `SELECT request_id FROM audit_events
		WHERE action='analytics_log.export.complete' AND resource_id=$1`, created.ID).Scan(&completeRequestID); err != nil ||
		completeRequestID != "req-export-worker-1" {
		t.Fatalf("complete audit request_id = %q, %v; want creating request id", completeRequestID, err)
	}

	grant, err := manager.Grant(ctx, fixture.actor, AudienceTenant, "", created.ID)
	if err != nil {
		t.Fatalf("Grant() error = %v", err)
	}
	download, err := manager.Consume(ctx, fixture.actor, AudienceTenant, "", created.ID, grant.Token)
	if err != nil {
		t.Fatalf("Consume() error = %v", err)
	}
	if !strings.Contains(string(download.Content), "example.test") || download.SHA256 != job.SHA256 {
		t.Fatalf("download = %q sha=%s, want artifact sha=%s", download.Content, download.SHA256, job.SHA256)
	}
	if _, err := manager.Consume(ctx, fixture.actor, AudienceTenant, "", created.ID, grant.Token); !errors.Is(err, ErrExpired) {
		t.Fatalf("second Consume() error = %v, want ErrExpired", err)
	}
	otherSession := fixture.actor
	otherSession.SessionID = uuid.NewString()
	second, err := manager.Grant(ctx, fixture.actor, AudienceTenant, "", created.ID)
	if err != nil {
		t.Fatalf("second Grant() error = %v", err)
	}
	if _, err := manager.Consume(ctx, otherSession, AudienceTenant, "", created.ID, second.Token); err == nil {
		t.Fatal("Consume() with another session succeeded")
	}
	var consumed, downloads int
	if err := fixture.pool.QueryRow(t.Context(), `SELECT
		(SELECT count(*) FROM analytics_log_export_grants_v1 WHERE export_id=$1 AND consumed_at IS NOT NULL),
		(SELECT count(*) FROM audit_events WHERE action='analytics_log.export.download' AND resource_id=$1::text)`,
		created.ID).Scan(&consumed, &downloads); err != nil || consumed != 1 || downloads != 1 {
		t.Fatalf("consumed grants=%d downloads=%d err=%v, want 1/1", consumed, downloads, err)
	}
}

// 每个任务用自己的请求编号：同一轮 worker 先后处理两条任务，不能把第一条
// 的 request_id 复用给第二条。
func TestExportWorkerUsesEachJobsOwnRequestIDWithPostgres17(t *testing.T) {
	fixture := newExportWorkerFixture(t)
	now := time.Now().UTC().Truncate(time.Second)
	store := exportWorkerStore(now)
	store.pages = append(store.pages, exportWorkerStore(now).pages...)
	manager, err := NewExportManager(fixture.pool, store, func() time.Time { return now })
	if err != nil {
		t.Fatal(err)
	}
	// 先占住 worker，避免 Create 的 kick 抢先处理。
	manager.workerMu.Lock()
	manager.workerRunning = true
	manager.workerMu.Unlock()
	ids := make([]string, 0, 2)
	for index, requestID := range []string{"req-export-a", "req-export-b"} {
		created, _, err := manager.Create(WithRequestID(t.Context(), requestID), fixture.actor, QueryRequest{
			Audience: AudienceTenant, Limit: MaxLimit,
			Filter: Filter{From: now.Add(-time.Hour), To: now.Add(-time.Duration(index) * time.Second)},
		}, "export-worker-key-"+requestID)
		if err != nil {
			t.Fatal(err)
		}
		ids = append(ids, created.ID)
	}
	workerCtx, cancel := context.WithTimeout(context.Background(), exportWorkerTimeout)
	defer cancel()
	for range ids {
		if processed, err := manager.processOne(workerCtx); err != nil || !processed {
			t.Fatalf("processOne() = (%v, %v)", processed, err)
		}
	}
	for index, id := range ids {
		var requestID string
		if err := fixture.pool.QueryRow(t.Context(), `SELECT request_id FROM audit_events
			WHERE action='analytics_log.export.complete' AND resource_id=$1`, id).Scan(&requestID); err != nil {
			t.Fatal(err)
		}
		if want := []string{"req-export-a", "req-export-b"}[index]; requestID != want {
			t.Fatalf("export %d complete audit request_id = %q, want %q", index, requestID, want)
		}
	}
}
