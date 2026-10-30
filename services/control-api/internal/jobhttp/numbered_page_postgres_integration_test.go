//go:build integration

package jobhttp

import (
	"context"
	"sync"
	"testing"
	"time"

	"github.com/cdnca/cdnca/services/control-api/internal/jobstate"
	"github.com/google/uuid"
	"github.com/jackc/pgx/v5"
	"github.com/jackc/pgx/v5/pgxpool"
)

func TestPostgresNumberedPagesCountScopeAndFilterConsistency(t *testing.T) {
	pool := openJobHTTPTestDatabase(t)
	now := fixtureNow.Add(-10 * time.Minute)
	store, err := jobstate.NewStore(pool, func() time.Time { return now })
	if err != nil {
		t.Fatal(err)
	}
	tenantA, scopeA := seedJobHTTPTenant(t, pool, "Numbered page tenant A")
	tenantB, _ := seedJobHTTPTenant(t, pool, "Numbered page tenant B")
	var ids []uuid.UUID
	for range 5 {
		now = now.Add(time.Second)
		job := createIntegrationJob(t, store, tenantA, "cache.operation", "resource/a", uuid.Nil)
		ids = append(ids, job.ID)
	}
	createIntegrationJob(t, store, tenantB, "cache.operation", "resource/a", uuid.Nil)
	createIntegrationJob(t, store, tenantA, "analytics.log_export", "resource/b", uuid.Nil)
	reader, _ := NewPostgresReader(pool)
	service, _ := NewService(reader, fixtureServiceConfig())
	request := fixtureListRequest(AudienceTenant)
	request.Page, request.Limit, request.Kind, request.Resource = 2, 2, "cache.operation", "resource/a"
	request.States = []State{StateQueued}
	page, err := service.List(t.Context(), tenantPrincipal(scopeA), request)
	if err != nil || *page.Page.Total != 5 || *page.Page.TotalPages != 3 || len(page.Data) != 2 ||
		page.Data[0].TaskID != ids[2] || page.Data[1].TaskID != ids[1] {
		t.Fatalf("tenant numbered page=%+v err=%v", page, err)
	}
	request.Page = 3
	page, err = service.List(t.Context(), tenantPrincipal(scopeA), request)
	if err != nil || len(page.Data) != 1 || page.Data[0].TaskID != ids[0] || *page.Page.Total != 5 {
		t.Fatalf("last page=%+v err=%v", page, err)
	}
	request.Page = 4
	page, err = service.List(t.Context(), tenantPrincipal(scopeA), request)
	if err != nil || len(page.Data) != 0 || *page.Page.Total != 5 || page.Page.Number != 4 {
		t.Fatalf("past end=%+v err=%v", page, err)
	}
	request.Page, request.TaskID = 1, &ids[0]
	page, err = service.List(t.Context(), tenantPrincipal(scopeA), request)
	if err != nil || *page.Page.Total != 1 || len(page.Data) != 1 || page.Data[0].TaskID != ids[0] {
		t.Fatalf("exact task filter=%+v err=%v", page, err)
	}
	request.TaskID, request.Audience, request.TenantID = nil, AudiencePlatform, &tenantB
	page, err = service.List(t.Context(), platformPrincipal(uuid.New()), request)
	if err != nil || *page.Page.Total != 1 || len(page.Data) != 1 || page.Data[0].TenantID != tenantB {
		t.Fatalf("platform tenant filter=%+v err=%v", page, err)
	}
	request.States = []State{StateSucceeded}
	page, err = service.List(t.Context(), platformPrincipal(uuid.New()), request)
	if err != nil || *page.Page.Total != 0 || *page.Page.TotalPages != 0 || len(page.Data) != 0 {
		t.Fatalf("empty state filter=%+v err=%v", page, err)
	}
}

type numberedPageQueryTracer struct {
	once       sync.Once
	beforePage func()
}

func (tracer *numberedPageQueryTracer) TraceQueryStart(ctx context.Context, _ *pgx.Conn, data pgx.TraceQueryStartData) context.Context {
	if data.SQL == platformNumberedSQL {
		tracer.once.Do(tracer.beforePage)
	}
	return ctx
}

func (*numberedPageQueryTracer) TraceQueryEnd(context.Context, *pgx.Conn, pgx.TraceQueryEndData) {}

func TestPostgresNumberedPageSameSnapshotDuringConcurrentInsertAndStatusChange(t *testing.T) {
	pool := openJobHTTPTestDatabase(t)
	store, err := jobstate.NewStore(pool, func() time.Time { return fixtureNow })
	if err != nil {
		t.Fatal(err)
	}
	tenantID, _ := seedJobHTTPTenant(t, pool, "Numbered concurrency tenant")
	first := createIntegrationJob(t, store, tenantID, "cache.operation", "resource/a", uuid.Nil)
	second := createIntegrationJob(t, store, tenantID, "cache.operation", "resource/a", uuid.Nil)
	tracer := &numberedPageQueryTracer{beforePage: func() {
		createIntegrationJob(t, store, tenantID, "cache.operation", "resource/a", uuid.Nil)
		if _, err := store.Cancel(t.Context(), tenantID, second.ID); err != nil {
			t.Fatal(err)
		}
	}}
	config := pool.Config()
	config.ConnConfig.Tracer = tracer
	traced, err := pgxpool.NewWithConfig(t.Context(), config)
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(traced.Close)
	reader, _ := NewPostgresReader(traced)
	service, _ := NewService(reader, fixtureServiceConfig())
	request := fixtureListRequest(AudiencePlatform)
	request.Page, request.Limit, request.States = 1, 10, []State{StateQueued}
	page, err := service.List(t.Context(), platformPrincipal(uuid.New()), request)
	if err != nil || *page.Page.Total != 2 || len(page.Data) != 2 {
		t.Fatalf("snapshot=%+v err=%v", page, err)
	}
	seen := map[uuid.UUID]bool{}
	for _, job := range page.Data {
		seen[job.TaskID] = true
		if job.Status != StateQueued {
			t.Fatalf("count/rows used different snapshots: %+v", job)
		}
	}
	if !seen[first.ID] || !seen[second.ID] {
		t.Fatalf("concurrent insertion displaced a snapshot row: %v", seen)
	}
	fresh, err := service.List(t.Context(), platformPrincipal(uuid.New()), request)
	if err != nil || *fresh.Page.Total != 2 || len(fresh.Data) != 2 {
		t.Fatalf("fresh=%+v err=%v", fresh, err)
	}
	for _, job := range fresh.Data {
		if job.TaskID == second.ID {
			t.Fatal("new request did not observe committed state change")
		}
	}
}

func TestPostgresCompletionMetadataSameTenantAndUnknownFallback(t *testing.T) {
	pool := openJobHTTPTestDatabase(t)
	store, _ := jobstate.NewStore(pool, func() time.Time { return fixtureNow })
	tenantA, scopeA := seedJobHTTPTenant(t, pool, "Completion tenant A")
	tenantB, _ := seedJobHTTPTenant(t, pool, "Completion tenant B")
	parent := createIntegrationJob(t, store, tenantA, "dns.cname.allocation", "allocation/a", uuid.Nil)
	child := createIntegrationJob(t, store, tenantA, "dns_reconcile", "site/a", uuid.Nil)
	foreign := createIntegrationJob(t, store, tenantB, "dns_reconcile", "site/b", uuid.Nil)
	reader, _ := NewPostgresReader(pool)
	service, _ := NewService(reader, fixtureServiceConfig())
	request := fixtureListRequest(AudienceTenant)
	request.Page, request.TaskID = 1, &parent.ID
	page, err := service.List(t.Context(), tenantPrincipal(scopeA), request)
	if err != nil || (*page.TaskMetadata)[0].Dependencies.State != "unknown" {
		t.Fatalf("missing optional relation must remain unknown: %+v err=%v", page, err)
	}
	// A focused projection fixture exercises the reader SQL, not migration 126's
	// CNAME producer, DNS mutation or worker completion semantics.
	if _, err := pool.Exec(t.Context(), `CREATE TABLE cname_allocation_targets (
		tenant_id uuid NOT NULL, job_id uuid NOT NULL, child_task_id uuid, PRIMARY KEY(tenant_id,job_id))`); err != nil {
		t.Fatal(err)
	}
	if _, err := pool.Exec(t.Context(), `INSERT INTO cname_allocation_targets VALUES($1,$2,$3)`, tenantA, parent.ID, child.ID); err != nil {
		t.Fatal(err)
	}
	page, err = service.List(t.Context(), tenantPrincipal(scopeA), request)
	if err != nil || (*page.TaskMetadata)[0].Dependencies.State != "unknown" {
		t.Fatalf("missing DNS relation must remain unknown: %+v err=%v", page, err)
	}
	if _, err := pool.Exec(t.Context(), `CREATE TABLE dns_reconcile_tasks (
		tenant_id uuid NOT NULL, job_id uuid PRIMARY KEY, FOREIGN KEY(tenant_id,job_id) REFERENCES background_jobs(tenant_id,id))`); err != nil {
		t.Fatal(err)
	}
	page, err = service.List(t.Context(), tenantPrincipal(scopeA), request)
	if err != nil || (*page.TaskMetadata)[0].Dependencies.State != "unknown" {
		t.Fatalf("kind without a DNS producer fact must remain unknown: %+v err=%v", page, err)
	}
	if _, err := pool.Exec(t.Context(), `INSERT INTO dns_reconcile_tasks VALUES($1,$2),($3,$4)`, tenantA, child.ID, tenantB, foreign.ID); err != nil {
		t.Fatal(err)
	}
	page, err = service.List(t.Context(), tenantPrincipal(scopeA), request)
	if err != nil {
		t.Fatal(err)
	}
	metadata := (*page.TaskMetadata)[0]
	if metadata.Dependencies.State != "observed" || len(metadata.Dependencies.Items) != 1 ||
		metadata.Dependencies.Items[0].TaskID != child.ID || metadata.Dependencies.Items[0].Relation != "completion" ||
		metadata.Dependencies.Items[0].Status != StateQueued || metadata.Priority.Policy != "ready_fifo" {
		t.Fatalf("metadata=%+v", metadata)
	}
	if _, err := pool.Exec(t.Context(), `UPDATE cname_allocation_targets SET child_task_id=$3 WHERE tenant_id=$1 AND job_id=$2`, tenantA, parent.ID, foreign.ID); err != nil {
		t.Fatal(err)
	}
	page, err = service.List(t.Context(), tenantPrincipal(scopeA), request)
	if err != nil || (*page.TaskMetadata)[0].Dependencies.State != "unknown" || len((*page.TaskMetadata)[0].Dependencies.Items) != 0 {
		t.Fatalf("foreign child leaked: %+v err=%v", page, err)
	}
}
