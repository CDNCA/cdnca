package migrations_test

import (
	"context"
	"errors"
	"fmt"
	"os"
	"strings"
	"sync"
	"testing"
	"time"

	"github.com/cdnca/cdnca/services/control-api/internal/announcement"
	controlmigrations "github.com/cdnca/cdnca/services/control-api/migrations"
	"github.com/google/uuid"
	"github.com/jackc/pgx/v5"
	"github.com/jackc/pgx/v5/pgconn"
	"github.com/jackc/pgx/v5/pgxpool"
)

func TestAnnouncements043EmptyRoundTrip(t *testing.T) {
	pool, cleanup := new043Pool(t)
	defer cleanup()
	apply043Through(t, pool)
	apply043Down(t, pool)
	apply043Up(t, pool)
	var watermark int64
	if err := pool.QueryRow(t.Context(), `SELECT COALESCE(max(current_watermark),0) FROM announcement_state_watermarks`).Scan(&watermark); err != nil {
		t.Fatal(err)
	}
	if watermark != 0 {
		t.Fatalf("round-trip watermark = %d, want 0", watermark)
	}
}

func TestAnnouncements043DownFailsClosedForEveryFactFamily(t *testing.T) {
	for _, tc := range []struct {
		name string
		seed func(*testing.T, *pgxpool.Pool, migrationFixture)
	}{
		{name: "draft", seed: seed043Draft},
		{name: "published-and-inbox", seed: seed043Published},
		{name: "write-request", seed: seed043WriteRequest},
	} {
		t.Run(tc.name, func(t *testing.T) {
			pool, cleanup := new043Pool(t)
			defer cleanup()
			apply043Through(t, pool)
			fixture := seed043Base(t, pool)
			tc.seed(t, pool, fixture)
			before := count043Facts(t, pool)
			err := apply043DownErr(pool)
			var pgErr *pgconn.PgError
			if !errors.As(err, &pgErr) || pgErr.Code != "P0001" {
				t.Fatalf("down error = %v, want SQLSTATE P0001", err)
			}
			if got := count043Facts(t, pool); got != before {
				t.Fatalf("facts after rejected down = %d, want %d", got, before)
			}
		})
	}
}

func TestAnnouncements043MarkdownSQLMatchesGoCorpus(t *testing.T) {
	pool, cleanup := new043Pool(t)
	defer cleanup()
	apply043Through(t, pool)
	fixture := seed043Base(t, pool)
	seed043Draft(t, pool, fixture)
	cases := []struct {
		name    string
		content announcement.Content
		valid   bool
	}{
		{name: "plain", content: announcement.Content{Title: "标题", Body: "正文"}, valid: true},
		{name: "layout", content: announcement.Content{Title: "标题", Body: "第一行\n\t第二行"}, valid: true},
		{name: "internal nbsp", content: announcement.Content{Title: "标题", Body: "正文\u00a0内容"}, valid: true},
		{name: "leading ascii space", content: announcement.Content{Title: "标题", Body: " 正文"}},
		{name: "leading nbsp", content: announcement.Content{Title: "标题", Body: "\u00a0正文"}},
		{name: "trailing ideographic space", content: announcement.Content{Title: "标题", Body: "正文\u3000"}},
		{name: "carriage return", content: announcement.Content{Title: "标题", Body: "正文\r注入"}},
		{name: "next line control", content: announcement.Content{Title: "标题", Body: "正文\u0085注入"}},
		{name: "zero width space", content: announcement.Content{Title: "标题", Body: "正文\u200b注入"}},
		{name: "soft hyphen", content: announcement.Content{Title: "标题", Body: "正文\u00ad注入"}},
		{name: "bidi isolate", content: announcement.Content{Title: "标题", Body: "正文\u2066注入"}},
		{name: "title control", content: announcement.Content{Title: "标题\n注入", Body: "正文"}},
		{name: "title format", content: announcement.Content{Title: "标\u200b题", Body: "正文"}},
		{name: "reference link", content: announcement.Content{Title: "标题", Body: "[伪链接][标签]"}},
		{name: "protocol relative", content: announcement.Content{Title: "标题", Body: "协议相对资源 //example.invalid/a"}},
		{name: "bare www host", content: announcement.Content{Title: "标题", Body: "www.example.invalid/resource"}},
	}
	for index, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			goValid := announcement.ValidateContent(tc.content) == nil
			_, err := pool.Exec(t.Context(), `UPDATE announcement_versions
				SET title=$3,body=$4,revision=revision+1,state_changed_at=$5
				WHERE tenant_scope_id=$1 AND announcement_id=$2 AND version=1`,
				fixture.scopeID, fixture.announcementID, tc.content.Title, tc.content.Body,
				time.Date(2026, 7, 23, 1, 2, 0, index+1, time.UTC))
			sqlValid := err == nil
			if goValid != tc.valid || sqlValid != tc.valid || goValid != sqlValid {
				t.Fatalf("validity Go/SQL/want = %t/%t/%t, SQL error=%v", goValid, sqlValid, tc.valid, err)
			}
		})
	}
}

func TestAnnouncements043WatermarkAllocatorRejectsTamperingAndIsTransactional(t *testing.T) {
	pool, cleanup := new043Pool(t)
	defer cleanup()
	apply043Through(t, pool)
	fixture := seed043Base(t, pool)
	seed043Draft(t, pool, fixture)

	for _, statement := range []string{
		`UPDATE announcement_state_watermarks SET current_watermark=0 WHERE tenant_scope_id=$1`,
		`UPDATE announcement_state_watermarks SET current_watermark=current_watermark+1 WHERE tenant_scope_id=$1`,
		`UPDATE announcement_state_watermarks SET current_watermark=current_watermark+2 WHERE tenant_scope_id=$1`,
		`DELETE FROM announcement_state_watermarks WHERE tenant_scope_id=$1`,
		`SELECT next_announcement_state_watermark($1)`,
	} {
		if _, err := pool.Exec(t.Context(), statement, fixture.scopeID); err == nil {
			t.Fatalf("watermark tampering unexpectedly succeeded: %s", statement)
		}
	}
	if _, err := pool.Exec(t.Context(), `TRUNCATE announcement_state_watermarks`); err == nil {
		t.Fatal("watermark truncate unexpectedly succeeded")
	}
	if _, err := pool.Exec(t.Context(), `GRANT EXECUTE ON FUNCTION next_announcement_state_watermark(uuid) TO PUBLIC`); err != nil {
		t.Fatal(err)
	}
	if _, err := pool.Exec(t.Context(), `SELECT next_announcement_state_watermark($1)`, fixture.scopeID); err == nil {
		t.Fatal("granting allocator execute bypassed the controlled-call guard")
	}

	second := fixture
	second.announcementID = uuid.New()
	seed043Draft(t, pool, second)
	baseline := current043Watermark(t, pool, fixture.scopeID)
	start := make(chan struct{})
	errorsByWriter := make(chan error, 2)
	var writers sync.WaitGroup
	for index, id := range []uuid.UUID{fixture.announcementID, second.announcementID} {
		writers.Add(1)
		go func(index int, announcementID uuid.UUID) {
			defer writers.Done()
			<-start
			_, err := pool.Exec(t.Context(), `UPDATE announcement_versions
				SET body=$3,revision=revision+1,state_changed_at=$4
				WHERE tenant_scope_id=$1 AND announcement_id=$2 AND version=1`, fixture.scopeID,
				announcementID, fmt.Sprintf("并发-%d", index), time.Date(2026, 7, 23, 1, 3, index, 0, time.UTC))
			errorsByWriter <- err
		}(index, id)
	}
	close(start)
	writers.Wait()
	close(errorsByWriter)
	for err := range errorsByWriter {
		if err != nil {
			t.Fatalf("controlled concurrent allocation: %v", err)
		}
	}
	if current := current043Watermark(t, pool, fixture.scopeID); current != baseline+2 {
		t.Fatalf("concurrent watermark = %d, want %d", current, baseline+2)
	}
	var count int
	var minimum, maximum int64
	if err := pool.QueryRow(t.Context(), `SELECT count(*),min(watermark),max(watermark)
		FROM announcement_state_facts WHERE tenant_scope_id=$1 AND watermark>$2`, fixture.scopeID, baseline).
		Scan(&count, &minimum, &maximum); err != nil {
		t.Fatal(err)
	}
	if count != 2 || minimum != baseline+1 || maximum != baseline+2 {
		t.Fatalf("concurrent facts count/min/max = %d/%d/%d", count, minimum, maximum)
	}

	baseline = current043Watermark(t, pool, fixture.scopeID)
	tx, err := pool.Begin(t.Context())
	if err != nil {
		t.Fatal(err)
	}
	if _, err := tx.Exec(t.Context(), `UPDATE announcement_versions
		SET body='回滚',revision=revision+1,state_changed_at=$3
		WHERE tenant_scope_id=$1 AND announcement_id=$2 AND version=1`, fixture.scopeID,
		fixture.announcementID, time.Date(2026, 7, 23, 1, 4, 0, 0, time.UTC)); err != nil {
		_ = tx.Rollback(t.Context())
		t.Fatal(err)
	}
	if current043WatermarkQuery(t, tx, fixture.scopeID) != baseline+1 {
		_ = tx.Rollback(t.Context())
		t.Fatal("allocator did not advance inside the transaction")
	}
	if err := tx.Rollback(t.Context()); err != nil {
		t.Fatal(err)
	}
	if current := current043Watermark(t, pool, fixture.scopeID); current != baseline {
		t.Fatalf("rolled-back watermark = %d, want %d", current, baseline)
	}
	if _, err := pool.Exec(t.Context(), `UPDATE announcement_versions
		SET body='回滚后复用',revision=revision+1,state_changed_at=$3
		WHERE tenant_scope_id=$1 AND announcement_id=$2 AND version=1`, fixture.scopeID,
		fixture.announcementID, time.Date(2026, 7, 23, 1, 5, 0, 0, time.UTC)); err != nil {
		t.Fatal(err)
	}
	if current := current043Watermark(t, pool, fixture.scopeID); current != baseline+1 {
		t.Fatalf("post-rollback watermark = %d, want %d", current, baseline+1)
	}
}

func TestAnnouncements043PublishedPointerRequiresPublishedTarget(t *testing.T) {
	pool, cleanup := new043Pool(t)
	defer cleanup()
	apply043Through(t, pool)
	fixture := seed043Base(t, pool)
	seed043Published(t, pool, fixture)
	now := time.Date(2026, 7, 23, 1, 2, 0, 0, time.UTC)
	tx, err := pool.Begin(t.Context())
	if err != nil {
		t.Fatal(err)
	}
	defer tx.Rollback(t.Context())
	if _, err := tx.Exec(t.Context(), `INSERT INTO announcement_versions(
		 tenant_scope_id,announcement_id,version,revision,status,title,body,audience_mode,withdrawal_visibility,created_by_user_id,created_at,state_changed_at
	) VALUES($1,$2,2,1,'draft','Second','正文','all','retain',$3,$4,$4)`, fixture.scopeID, fixture.announcementID, fixture.userID, now); err != nil {
		t.Fatal(err)
	}
	if _, err := tx.Exec(t.Context(), `UPDATE announcements SET head_version=2,updated_at=$3 WHERE tenant_scope_id=$1 AND id=$2`, fixture.scopeID, fixture.announcementID, now); err != nil {
		t.Fatal(err)
	}
	if err := tx.Commit(t.Context()); err != nil {
		t.Fatal(err)
	}
	if _, err := pool.Exec(t.Context(), `UPDATE announcements SET current_published_version=2 WHERE tenant_scope_id=$1 AND id=$2`, fixture.scopeID, fixture.announcementID); err == nil {
		t.Fatal("draft pointer update unexpectedly succeeded")
	}
	if _, err := pool.Exec(t.Context(), `UPDATE announcements SET current_published_version=NULL WHERE tenant_scope_id=$1 AND id=$2`, fixture.scopeID, fixture.announcementID); err == nil {
		t.Fatal("clearing a live published pointer unexpectedly succeeded")
	}
	withdrawnAt := now.Add(time.Minute)
	if _, err := pool.Exec(t.Context(), `UPDATE announcement_versions
		SET status='withdrawn',withdrawn_at=$3,revision=revision+1,state_changed_at=$3
		WHERE tenant_scope_id=$1 AND announcement_id=$2 AND version=1`, fixture.scopeID, fixture.announcementID, withdrawnAt); err == nil {
		t.Fatal("status-only withdrawal unexpectedly succeeded")
	}
}

type watermarkQuerier interface {
	QueryRow(context.Context, string, ...any) pgx.Row
}

func current043Watermark(t *testing.T, pool *pgxpool.Pool, scopeID uuid.UUID) int64 {
	t.Helper()
	return current043WatermarkQuery(t, pool, scopeID)
}

func current043WatermarkQuery(t *testing.T, queryer watermarkQuerier, scopeID uuid.UUID) int64 {
	t.Helper()
	var current int64
	if err := queryer.QueryRow(t.Context(), `SELECT current_watermark FROM announcement_state_watermarks WHERE tenant_scope_id=$1`, scopeID).Scan(&current); err != nil {
		t.Fatal(err)
	}
	return current
}

type migrationFixture struct {
	tenantID, scopeID, userID, announcementID, eventID uuid.UUID
}

func seed043Base(t *testing.T, pool *pgxpool.Pool) migrationFixture {
	t.Helper()
	f := migrationFixture{tenantID: uuid.New(), scopeID: uuid.New(), userID: uuid.New(), announcementID: uuid.New(), eventID: uuid.New()}
	if _, err := pool.Exec(t.Context(), `INSERT INTO tenants(id,display_name) VALUES($1,'migration-043')`, f.tenantID); err != nil {
		t.Fatal(err)
	}
	if _, err := pool.Exec(t.Context(), `INSERT INTO access_scopes(id,kind,tenant_id) VALUES($1,'tenant',$2)`, f.scopeID, f.tenantID); err != nil {
		t.Fatal(err)
	}
	if _, err := pool.Exec(t.Context(), `INSERT INTO users(id,username,display_name,password_hash) VALUES($1,'migration043','migration043','hash')`, f.userID); err != nil {
		t.Fatal(err)
	}
	if _, err := pool.Exec(t.Context(), `INSERT INTO memberships(scope_id,user_id) VALUES($1,$2)`, f.scopeID, f.userID); err != nil {
		t.Fatal(err)
	}
	return f
}

func seed043Draft(t *testing.T, pool *pgxpool.Pool, f migrationFixture) {
	now := time.Date(2026, 7, 23, 1, 0, 0, 0, time.UTC)
	tx, err := pool.Begin(t.Context())
	if err != nil {
		t.Fatal(err)
	}
	defer tx.Rollback(t.Context())
	if _, err := tx.Exec(t.Context(), `INSERT INTO announcements(id,tenant_scope_id,created_by_user_id,created_at,updated_at) VALUES($1,$2,$3,$4,$4)`, f.announcementID, f.scopeID, f.userID, now); err != nil {
		t.Fatal(err)
	}
	if _, err := tx.Exec(t.Context(), `INSERT INTO announcement_versions(
		 tenant_scope_id,announcement_id,version,revision,status,title,body,audience_mode,withdrawal_visibility,created_by_user_id,created_at,state_changed_at
	) VALUES($1,$2,1,1,'draft','Draft','正文','all','retain',$3,$4,$4)`, f.scopeID, f.announcementID, f.userID, now); err != nil {
		t.Fatal(err)
	}
	if err := tx.Commit(t.Context()); err != nil {
		t.Fatal(err)
	}
}

func seed043Published(t *testing.T, pool *pgxpool.Pool, f migrationFixture) {
	seed043Draft(t, pool, f)
	now := time.Date(2026, 7, 23, 1, 1, 0, 0, time.UTC)
	if _, err := pool.Exec(t.Context(), `INSERT INTO announcement_recipient_snapshots(tenant_scope_id,announcement_id,announcement_version,user_id,resolved_at) VALUES($1,$2,1,$3,$4)`, f.scopeID, f.announcementID, f.userID, now); err != nil {
		t.Fatal(err)
	}
	if _, err := pool.Exec(t.Context(), `INSERT INTO announcement_inbox_events(id,tenant_scope_id,announcement_id,announcement_version,recipient_user_id,title,body,published_at,created_at) VALUES($1,$2,$3,1,$4,'Draft','正文',$5,$5)`, f.eventID, f.scopeID, f.announcementID, f.userID, now); err != nil {
		t.Fatal(err)
	}
	if _, err := pool.Exec(t.Context(), `INSERT INTO announcement_inbox_states(tenant_scope_id,event_id,user_id,updated_at) VALUES($1,$2,$3,$4)`, f.scopeID, f.eventID, f.userID, now); err != nil {
		t.Fatal(err)
	}
	tx, err := pool.Begin(t.Context())
	if err != nil {
		t.Fatal(err)
	}
	defer tx.Rollback(t.Context())
	if _, err := tx.Exec(t.Context(), `UPDATE announcement_versions SET status='published',sealed_at=$3,published_at=$3,revision=2,state_changed_at=$3 WHERE tenant_scope_id=$1 AND announcement_id=$2 AND version=1 AND revision=1`, f.scopeID, f.announcementID, now); err != nil {
		t.Fatal(err)
	}
	if _, err := tx.Exec(t.Context(), `UPDATE announcements SET current_published_version=1,updated_at=$3 WHERE tenant_scope_id=$1 AND id=$2`, f.scopeID, f.announcementID, now); err != nil {
		t.Fatal(err)
	}
	if err := tx.Commit(t.Context()); err != nil {
		t.Fatal(err)
	}
}

func seed043WriteRequest(t *testing.T, pool *pgxpool.Pool, f migrationFixture) {
	now := time.Date(2026, 7, 23, 1, 0, 0, 0, time.UTC)
	digest := strings.Repeat("aa", 32)
	if _, err := pool.Exec(t.Context(), `INSERT INTO announcement_write_requests(id,tenant_scope_id,actor_user_id,operation,idempotency_key,request_digest,created_at) VALUES($1,$2,$3,'announcement.create','migration043-key',decode($4,'hex'),$5)`, uuid.New(), f.scopeID, f.userID, digest, now); err != nil {
		t.Fatal(err)
	}
}

func count043Facts(t *testing.T, pool *pgxpool.Pool) int {
	t.Helper()
	var count int
	if err := pool.QueryRow(t.Context(), `SELECT (SELECT count(*) FROM announcements)+(SELECT count(*) FROM announcement_versions)+(SELECT count(*) FROM announcement_state_facts)+(SELECT count(*) FROM announcement_write_requests)`).Scan(&count); err != nil {
		t.Fatal(err)
	}
	return count
}

func new043Pool(t *testing.T) (*pgxpool.Pool, func()) {
	t.Helper()
	databaseURL := strings.TrimSpace(os.Getenv("TEST_DATABASE_URL"))
	if databaseURL == "" {
		t.Skip("TEST_DATABASE_URL is not set")
	}
	admin, err := pgxpool.New(t.Context(), databaseURL)
	if err != nil {
		t.Fatal(err)
	}
	schema := "migration_043_" + strings.ReplaceAll(uuid.NewString(), "-", "")
	if _, err := admin.Exec(t.Context(), `CREATE SCHEMA `+schema); err != nil {
		admin.Close()
		t.Fatal(err)
	}
	admin.Close()
	config, err := pgxpool.ParseConfig(databaseURL)
	if err != nil {
		t.Fatal(err)
	}
	config.ConnConfig.RuntimeParams["search_path"] = schema
	pool, err := pgxpool.NewWithConfig(t.Context(), config)
	if err != nil {
		t.Fatal(err)
	}
	return pool, func() {
		pool.Close()
		cleanup, err := pgxpool.New(context.Background(), databaseURL)
		if err == nil {
			_, _ = cleanup.Exec(context.Background(), `DROP SCHEMA `+schema+` CASCADE`)
			cleanup.Close()
		}
	}
}

func apply043Through(t *testing.T, pool *pgxpool.Pool) {
	t.Helper()
	for version := 1; version <= 43; version++ {
		name := fmt.Sprintf("%03d_", version)
		entries, err := controlmigrations.FS.ReadDir(".")
		if err != nil {
			t.Fatal(err)
		}
		for _, entry := range entries {
			if strings.HasPrefix(entry.Name(), name) && strings.HasSuffix(entry.Name(), ".up.sql") {
				script, err := controlmigrations.FS.ReadFile(entry.Name())
				if err != nil {
					t.Fatal(err)
				}
				if _, err := pool.Exec(t.Context(), string(script)); err != nil {
					t.Fatalf("apply %s: %v", entry.Name(), err)
				}
			}
		}
	}
}

func apply043Up(t *testing.T, pool *pgxpool.Pool) {
	t.Helper()
	script, err := controlmigrations.FS.ReadFile("043_announcements.up.sql")
	if err != nil {
		t.Fatal(err)
	}
	if _, err := pool.Exec(t.Context(), string(script)); err != nil {
		t.Fatal(err)
	}
}

func apply043Down(t *testing.T, pool *pgxpool.Pool) {
	t.Helper()
	if err := apply043DownErr(pool); err != nil {
		t.Fatal(err)
	}
}

func apply043DownErr(pool *pgxpool.Pool) error {
	script, err := controlmigrations.FS.ReadFile("043_announcements.down.sql")
	if err != nil {
		return err
	}
	_, err = pool.Exec(context.Background(), string(script))
	return err
}
