//go:build integration

package analyticslog

import (
	"context"
	"errors"
	"testing"
	"time"

	"github.com/google/uuid"
)

// /
// 下载次数与最近下载来自只增的下载记录，Cleanup 删掉已消费授权（5 分钟）和到期制品（1 小时）后
// 仍回读原值；制品清理后到期时间仍在、不可下载。失败或重复的授权不计数，别的账号的下载不串。
// 时钟放在 3 小时前：授权/制品删除护栏按数据库真实时间判断“未到期”。
func TestExportDownloadHistorySurvivesCleanupWithPostgres17(t *testing.T) {
	fixture := newExportWorkerFixture(t)
	base := time.Now().UTC().Add(-3 * time.Hour).Truncate(time.Second)
	clock := base
	store := exportWorkerStore(base)
	manager, err := NewExportManager(fixture.pool, store, func() time.Time { return clock })
	if err != nil {
		t.Fatal(err)
	}
	manager.workerMu.Lock()
	manager.workerRunning = true
	manager.workerMu.Unlock()
	ctx := WithRequestID(t.Context(), "req-export-history-1")
	request := QueryRequest{Audience: AudienceTenant, Limit: 1, Filter: Filter{From: base.Add(-time.Hour), To: base}}
	created, _, err := manager.Create(ctx, fixture.actor, request, "export-history-key-0001")
	if err != nil {
		t.Fatal(err)
	}
	workerCtx, cancel := context.WithTimeout(context.Background(), exportWorkerTimeout)
	defer cancel()
	if processed, err := manager.processOne(workerCtx); err != nil || !processed {
		t.Fatalf("processOne() = (%v, %v)", processed, err)
	}
	completed, err := manager.Get(ctx, fixture.actor, AudienceTenant, "", created.ID)
	wantExpiry := base.Add(exportArtifactTTL)
	if err != nil || !completed.Downloadable || completed.ExpiresAt == nil || !completed.ExpiresAt.Equal(wantExpiry) {
		t.Fatalf("completed export = (%#v, %v), want downloadable until %s", completed, err, wantExpiry)
	}

	// 一次成功下载。
	clock = base.Add(time.Minute)
	downloadedAt := clock
	grant, err := manager.Grant(ctx, fixture.actor, AudienceTenant, "", created.ID)
	if err != nil {
		t.Fatalf("Grant() error = %v", err)
	}
	if _, err := manager.Consume(ctx, fixture.actor, AudienceTenant, "", created.ID, grant.Token); err != nil {
		t.Fatalf("Consume() error = %v", err)
	}
	// 重复消费、非法令牌、过期授权都不计数。
	if _, err := manager.Consume(ctx, fixture.actor, AudienceTenant, "", created.ID, grant.Token); !errors.Is(err, ErrExpired) {
		t.Fatalf("replayed Consume() error = %v, want ErrExpired", err)
	}
	if _, err := manager.Consume(ctx, fixture.actor, AudienceTenant, "", created.ID, "not-a-token"); !errors.Is(err, ErrExpired) {
		t.Fatalf("invalid token Consume() error = %v, want ErrExpired", err)
	}
	stale, err := manager.Grant(ctx, fixture.actor, AudienceTenant, "", created.ID)
	if err != nil {
		t.Fatalf("second Grant() error = %v", err)
	}
	clock = base.Add(time.Minute + exportGrantTTL + time.Second)
	if _, err := manager.Consume(ctx, fixture.actor, AudienceTenant, "", created.ID, stale.Token); !errors.Is(err, ErrExpired) {
		t.Fatalf("expired grant Consume() error = %v, want ErrExpired", err)
	}

	assertHistory := func(stage string, downloadable bool) {
		t.Helper()
		records, err := manager.List(ctx, fixture.actor, AudienceTenant, "")
		if err != nil || len(records) != 1 {
			t.Fatalf("%s List() = (%#v, %v)", stage, records, err)
		}
		got := records[0]
		if got.DownloadCount != 1 || got.LastDownloadedAt == nil || !got.LastDownloadedAt.Equal(downloadedAt) ||
			got.LastDownloadedBy == nil || got.LastDownloadedBy.ID != fixture.actor.ActorID {
			t.Fatalf("%s download history = count %d at %v by %#v, want 1 at %s by actor",
				stage, got.DownloadCount, got.LastDownloadedAt, got.LastDownloadedBy, downloadedAt)
		}
		if got.Status != ExportCompleted || got.Downloadable != downloadable || got.ExpiresAt == nil || !got.ExpiresAt.Equal(wantExpiry) {
			t.Fatalf("%s export = status %s downloadable %v expires %v, want completed %v %s",
				stage, got.Status, got.Downloadable, got.ExpiresAt, downloadable, wantExpiry)
		}
	}
	// 授权过期后真正运行 Cleanup：授权行没了，计数仍为 1，文件仍可下载。
	clock = base.Add(10 * time.Minute)
	if err := manager.Cleanup(ctx); err != nil {
		t.Fatalf("Cleanup() after grant expiry error = %v", err)
	}
	var grants int
	if err := fixture.pool.QueryRow(ctx, `SELECT count(*) FROM analytics_log_export_grants_v1 WHERE export_id=$1`,
		created.ID).Scan(&grants); err != nil || grants != 0 {
		t.Fatalf("grants after Cleanup = %d, %v; want 0", grants, err)
	}
	assertHistory("after grant cleanup", true)

	// 别的账号（同租户成员）自己的导出与下载不串进来。
	otherUser := uuid.New()
	if _, err := fixture.pool.Exec(ctx, `INSERT INTO users(id,username,display_name,password_hash) VALUES($1,$2,$2,'test-only-hash')`,
		otherUser, "export-history-"+otherUser.String()[:8]); err != nil {
		t.Fatal(err)
	}
	if _, err := fixture.pool.Exec(ctx, `INSERT INTO memberships(scope_id,user_id) VALUES($1,$2)`, fixture.actor.ScopeID, otherUser); err != nil {
		t.Fatal(err)
	}
	stranger := fixture.actor
	stranger.ActorID, stranger.SessionID = otherUser.String(), uuid.NewString()
	own, _, err := manager.Create(ctx, stranger, request, "export-history-key-0002")
	if err != nil || own.ID == created.ID {
		t.Fatalf("stranger Create() = (%s, %v), want its own export", own.ID, err)
	}
	// the stranger's export reads its own page from the store
	store.pages = append(store.pages, exportWorkerStore(base).pages...)
	if processed, err := manager.processOne(workerCtx); err != nil || !processed {
		t.Fatalf("stranger processOne() = (%v, %v)", processed, err)
	}
	for range 2 {
		ownGrant, err := manager.Grant(ctx, stranger, AudienceTenant, "", own.ID)
		if err != nil {
			t.Fatalf("stranger Grant() error = %v", err)
		}
		if _, err := manager.Consume(ctx, stranger, AudienceTenant, "", own.ID, ownGrant.Token); err != nil {
			t.Fatalf("stranger Consume() error = %v", err)
		}
	}
	if theirs, err := manager.List(ctx, stranger, AudienceTenant, ""); err != nil || len(theirs) != 1 || theirs[0].DownloadCount != 2 {
		t.Fatalf("stranger List() = (%#v, %v), want own export downloaded twice", theirs, err)
	}
	assertHistory("after another account downloads", true)

	// 制品到期并被清理：历史保留、到期时间不变、不可下载、不能再签发授权。
	clock = base.Add(exportArtifactTTL + time.Minute)
	if err := manager.Cleanup(ctx); err != nil {
		t.Fatalf("Cleanup() after artifact expiry error = %v", err)
	}
	var artifacts int
	if err := fixture.pool.QueryRow(ctx, `SELECT count(*) FROM analytics_log_export_artifacts_v1 WHERE export_id=$1`,
		created.ID).Scan(&artifacts); err != nil || artifacts != 0 {
		t.Fatalf("artifacts after Cleanup = %d, %v; want 0", artifacts, err)
	}
	assertHistory("after artifact cleanup", false)
	if _, err := manager.Grant(ctx, fixture.actor, AudienceTenant, "", created.ID); !errors.Is(err, ErrNotFound) {
		t.Fatalf("Grant() after artifact cleanup error = %v, want ErrNotFound", err)
	}
	if late, err := manager.Get(ctx, fixture.actor, AudienceTenant, "", created.ID); err != nil || late.Downloadable ||
		late.ExpiresAt == nil || !late.ExpiresAt.Equal(wantExpiry) || late.DownloadCount != 1 {
		t.Fatalf("Get() after artifact cleanup = (%#v, %v)", late, err)
	}
}
