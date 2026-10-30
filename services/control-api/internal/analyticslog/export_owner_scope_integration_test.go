//go:build integration

package analyticslog

import (
	"context"
	"errors"
	"testing"
	"time"

	"github.com/google/uuid"
)

// LOG-01：导出申请归属"账号 + 查询范围"，与登录会话无关；下载授权仍只发给
// 当前会话。
func TestExportOwnerScopeSurvivesReloginWithPostgres17(t *testing.T) {
	fixture := newExportWorkerFixture(t)
	now := time.Now().UTC().Truncate(time.Second)
	manager, err := NewExportManager(fixture.pool, exportWorkerStore(now), func() time.Time { return now })
	if err != nil {
		t.Fatal(err)
	}
	// 先占住 worker，测试里手动推进。
	manager.workerMu.Lock()
	manager.workerRunning = true
	manager.workerMu.Unlock()
	ctx := WithRequestID(t.Context(), "req-export-owner-1")
	request := QueryRequest{Audience: AudienceTenant, Limit: 1, Filter: Filter{From: now.Add(-time.Hour), To: now, Host: "example.test"}}

	first, replayed, err := manager.Create(ctx, fixture.actor, request, "export-owner-key-0001")
	if err != nil || replayed {
		t.Fatalf("Create() = (%#v, %v, %v)", first, replayed, err)
	}
	// 重复点击（新幂等键）不新建。
	again, replayed, err := manager.Create(ctx, fixture.actor, request, "export-owner-key-0002")
	if err != nil || !replayed || again.ID != first.ID {
		t.Fatalf("second Create() = (%s, %v, %v), want replay of %s", again.ID, replayed, err, first.ID)
	}

	relogin := fixture.actor
	relogin.SessionID = uuid.NewString()
	// 重新登录：申请记录与按范围找回都能看到原申请，再次申请复用原申请。
	jobs, err := manager.List(ctx, relogin, AudienceTenant, "")
	if err != nil || len(jobs) != 1 || jobs[0].ID != first.ID {
		t.Fatalf("List() after relogin = (%#v, %v)", jobs, err)
	}
	found, err := manager.FindByScope(ctx, relogin, request)
	if err != nil || len(found) != 1 || found[0].ID != first.ID {
		t.Fatalf("FindByScope() after relogin = (%#v, %v)", found, err)
	}
	if _, err := manager.Get(ctx, relogin, AudienceTenant, "", first.ID); err != nil {
		t.Fatalf("Get() after relogin error = %v", err)
	}
	reused, replayed, err := manager.Create(ctx, relogin, request, "export-owner-key-0003")
	if err != nil || !replayed || reused.ID != first.ID {
		t.Fatalf("Create() after relogin = (%s, %v, %v)", reused.ID, replayed, err)
	}
	// 已落库的幂等键（首次申请）换了范围：冲突，不偷偷建新申请；复用时不落新键。
	otherScope := request
	otherScope.Filter.Host = "other.example.test"
	if _, _, err := manager.Create(ctx, relogin, otherScope, "export-owner-key-0001"); !errors.Is(err, ErrConflict) {
		t.Fatalf("Create() with reused key for another scope error = %v, want ErrConflict", err)
	}

	// 别的账号（同租户另一成员）看不到、拿不到授权。
	otherUser := uuid.New()
	if _, err := fixture.pool.Exec(t.Context(), `INSERT INTO users(id,username,display_name,password_hash) VALUES($1,$2,$2,'test-only-hash')`,
		otherUser, "export-owner-"+otherUser.String()[:8]); err != nil {
		t.Fatal(err)
	}
	if _, err := fixture.pool.Exec(t.Context(), `INSERT INTO memberships(scope_id,user_id) VALUES($1,$2)`, fixture.actor.ScopeID, otherUser); err != nil {
		t.Fatal(err)
	}
	stranger := fixture.actor
	stranger.ActorID, stranger.SessionID = otherUser.String(), uuid.NewString()
	if jobs, err := manager.List(ctx, stranger, AudienceTenant, ""); err != nil || len(jobs) != 0 {
		t.Fatalf("stranger List() = (%d, %v), want empty", len(jobs), err)
	}
	if found, err := manager.FindByScope(ctx, stranger, request); err != nil || len(found) != 0 {
		t.Fatalf("stranger FindByScope() = (%d, %v), want empty", len(found), err)
	}
	if _, err := manager.Get(ctx, stranger, AudienceTenant, "", first.ID); !errors.Is(err, ErrNotFound) {
		t.Fatalf("stranger Get() error = %v, want ErrNotFound", err)
	}
	// 别的账号同范围申请是自己的一份。
	own, _, err := manager.Create(ctx, stranger, request, "export-owner-key-0004")
	if err != nil || own.ID == first.ID {
		t.Fatalf("stranger Create() = (%s, %v), want its own export", own.ID, err)
	}

	workerCtx, cancel := context.WithTimeout(context.Background(), exportWorkerTimeout)
	defer cancel()
	if processed, err := manager.processOne(workerCtx); err != nil || !processed {
		t.Fatalf("processOne() = (%v, %v)", processed, err)
	}
	if _, err := manager.Grant(ctx, stranger, AudienceTenant, "", first.ID); !errors.Is(err, ErrNotFound) {
		t.Fatalf("stranger Grant() error = %v, want ErrNotFound", err)
	}
	// 旧会话拿到的令牌在新会话用不了；新会话重新获取授权后可下载。
	oldGrant, err := manager.Grant(ctx, fixture.actor, AudienceTenant, "", first.ID)
	if err != nil {
		t.Fatalf("old session Grant() error = %v", err)
	}
	if _, err := manager.Consume(ctx, relogin, AudienceTenant, "", first.ID, oldGrant.Token); !errors.Is(err, ErrExpired) {
		t.Fatalf("Consume() old session token in new session error = %v, want ErrExpired", err)
	}
	newGrant, err := manager.Grant(ctx, relogin, AudienceTenant, "", first.ID)
	if err != nil {
		t.Fatalf("new session Grant() error = %v", err)
	}
	if _, err := manager.Consume(ctx, relogin, AudienceTenant, "", first.ID, newGrant.Token); err != nil {
		t.Fatalf("new session Consume() error = %v", err)
	}
	var grantSession uuid.UUID
	if err := fixture.pool.QueryRow(t.Context(), `SELECT session_id FROM analytics_log_export_grants_v1
		WHERE export_id=$1 AND consumed_at IS NOT NULL`, first.ID).Scan(&grantSession); err != nil ||
		grantSession.String() != relogin.SessionID {
		t.Fatalf("consumed grant session = %s, %v; want current session %s", grantSession, err, relogin.SessionID)
	}
	var rows int
	if err := fixture.pool.QueryRow(t.Context(), `SELECT count(*) FROM analytics_log_exports_v1 WHERE actor_user_id=$1`,
		fixture.actor.ActorID).Scan(&rows); err != nil || rows != 1 {
		t.Fatalf("owner export rows = %d, %v; want 1", rows, err)
	}
}

// 失败的申请再次申请：原申请原地重试（同一编号、同一幂等键），不另建一份；
// 产物过期后才建新一代。
func TestExportOwnerScopeRetriesFailedInPlaceWithPostgres17(t *testing.T) {
	fixture := newExportWorkerFixture(t)
	now := time.Now().UTC().Truncate(time.Second)
	clock := now
	store := &obs05PagedStore{pages: []AccessPage{{SnapshotAt: time.Time{}, Items: []AccessLog{{EventID: "x"}}}}}
	store.pages = append(store.pages, exportWorkerStore(now).pages...)
	manager, err := NewExportManager(fixture.pool, store, func() time.Time { return clock })
	if err != nil {
		t.Fatal(err)
	}
	manager.workerMu.Lock()
	manager.workerRunning = true
	manager.workerMu.Unlock()
	ctx := WithRequestID(t.Context(), "req-export-retry-1")
	request := QueryRequest{Audience: AudienceTenant, Limit: 1, Filter: Filter{From: now.Add(-time.Hour), To: now}}
	created, _, err := manager.Create(ctx, fixture.actor, request, "export-retry-key-0001")
	if err != nil {
		t.Fatal(err)
	}
	workerCtx, cancel := context.WithTimeout(context.Background(), exportWorkerTimeout)
	defer cancel()
	if processed, err := manager.processOne(workerCtx); err != nil || !processed {
		t.Fatalf("first processOne() = (%v, %v)", processed, err)
	}
	failed, err := manager.Get(ctx, fixture.actor, AudienceTenant, "", created.ID)
	if err != nil || failed.Status != ExportFailed {
		t.Fatalf("export after invalid page = (%#v, %v), want failed", failed, err)
	}
	relogin := fixture.actor
	relogin.SessionID = uuid.NewString()
	retried, replayed, err := manager.Create(ctx, relogin, request, "export-retry-key-0002")
	if err != nil || replayed || retried.ID != created.ID || retried.Status != ExportPending {
		t.Fatalf("retry Create() = (%#v, %v, %v), want same export pending", retried, replayed, err)
	}
	if processed, err := manager.processOne(workerCtx); err != nil || !processed {
		t.Fatalf("retry processOne() = (%v, %v)", processed, err)
	}
	done, err := manager.Get(ctx, relogin, AudienceTenant, "", created.ID)
	if err != nil || done.Status != ExportCompleted {
		t.Fatalf("retried export = (%#v, %v), want completed", done, err)
	}
	var key, jobState string
	var attempt, retries int
	if err := fixture.pool.QueryRow(t.Context(), `SELECT request.idempotency_key,job.state,job.attempt,
		(SELECT count(*) FROM audit_events WHERE action='analytics_log.export.retry' AND resource_id=request.id::text)
		FROM analytics_log_exports_v1 request JOIN background_jobs job ON job.id=request.id WHERE request.id=$1`,
		created.ID).Scan(&key, &jobState, &attempt, &retries); err != nil {
		t.Fatal(err)
	}
	if key != "export-retry-key-0001" || jobState != "succeeded" || attempt != 2 || retries != 1 {
		t.Fatalf("retried export key=%q job=%s attempt=%d retry audits=%d", key, jobState, attempt, retries)
	}
	// 产物过期后同范围再申请：新一代。
	clock = now.Add(exportArtifactTTL + time.Second)
	next, replayed, err := manager.Create(ctx, relogin, request, "export-retry-key-0003")
	if err != nil || replayed || next.ID == created.ID {
		t.Fatalf("Create() after expiry = (%s, %v, %v), want a new generation", next.ID, replayed, err)
	}
	var generation int
	if err := fixture.pool.QueryRow(t.Context(), `SELECT scope_generation FROM analytics_log_exports_v1 WHERE id=$1`,
		next.ID).Scan(&generation); err != nil || generation != 2 {
		t.Fatalf("new export generation = %d, %v; want 2", generation, err)
	}
}
