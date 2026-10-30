//go:build integration

package jobhttp

import (
	"context"
	"errors"
	"fmt"
	"io/fs"
	"os"
	"regexp"
	"slices"
	"strings"
	"testing"
	"time"

	"github.com/cdnca/cdnca/services/control-api/internal/jobstate"
	controlmigrations "github.com/cdnca/cdnca/services/control-api/migrations"
	"github.com/google/uuid"
	"github.com/jackc/pgx/v5"
	"github.com/jackc/pgx/v5/pgxpool"
)

func TestPostgresReaderIsolationPaginationAndMonotonicProjection(t *testing.T) {
	pool := openJobHTTPTestDatabase(t)
	now := fixtureNow.Add(-10 * time.Minute)
	store, err := jobstate.NewStore(pool, func() time.Time { return now })
	if err != nil {
		t.Fatal(err)
	}
	tenantA, scopeA := seedJobHTTPTenant(t, pool, "Job HTTP Tenant A")
	tenantB, scopeB := seedJobHTTPTenant(t, pool, "Job HTTP Tenant B")
	platformScope := uuid.New()
	if _, err := pool.Exec(t.Context(), `INSERT INTO access_scopes(id,kind) VALUES($1,'platform')`, platformScope); err != nil {
		t.Fatal(err)
	}
	nodeID := uuid.New()
	jobA := createIntegrationJob(t, store, tenantA, "cache.purge", "site/site-a", nodeID)
	claimOne := claimIntegrationJob(t, store, tenantA, "cache.purge", "worker-a-1")
	now = now.Add(time.Second)
	reportIntegrationResult(t, store, claimOne, "node-a", jobstate.ItemSucceeded, "", 1)
	now = now.Add(time.Second)
	reportIntegrationResult(t, store, claimOne, "item-b", jobstate.ItemFailed, "origin_timeout", 1)
	now = now.Add(time.Second)
	if _, err := store.Retry(t.Context(), tenantA, jobA.ID); err != nil {
		t.Fatal(err)
	}
	now = now.Add(5 * time.Second)
	claimTwo := claimIntegrationJob(t, store, tenantA, "cache.purge", "worker-a-2")
	now = now.Add(time.Second)
	reportIntegrationResult(t, store, claimTwo, "item-b", jobstate.ItemSucceeded, "", 2)
	stale, err := store.Report(t.Context(), jobstate.ReportInput{
		TenantID: tenantA, JobID: jobA.ID, WorkerID: claimOne.WorkerID, LeaseID: claimOne.LeaseID,
		Report: jobstate.Report{ItemID: "item-b", State: jobstate.ItemFailed, Code: "stale_failure", Attempt: 1, Sequence: 2},
	})
	if err != nil || stale.Applied || stale.Job.State != jobstate.StateSucceeded {
		t.Fatalf("stale report = %+v, err=%v", stale, err)
	}

	now = now.Add(time.Minute)
	jobAQueued := createIntegrationJob(t, store, tenantA, "dns.repair", "site/site-a", uuid.Nil)
	now = now.Add(time.Minute)
	jobB := createIntegrationJob(t, store, tenantB, "edge.publish", "site/site-b", uuid.Nil)

	reader, err := NewPostgresReader(pool)
	if err != nil {
		t.Fatal(err)
	}
	service, err := NewService(reader, fixtureServiceConfig())
	if err != nil {
		t.Fatal(err)
	}
	platform := platformPrincipal(platformScope)
	request := ListRequest{
		Audience: AudiencePlatform, From: fixtureNow.Add(-time.Hour), To: fixtureNow.Add(time.Hour), Limit: 1,
	}
	var ids []uuid.UUID
	for {
		page, err := service.List(t.Context(), platform, request)
		if err != nil {
			t.Fatal(err)
		}
		for _, job := range page.Data {
			ids = append(ids, job.TaskID)
		}
		if page.Page.NextCursor == "" {
			break
		}
		request.Cursor = page.Page.NextCursor
	}
	wantIDs := []uuid.UUID{jobB.ID, jobAQueued.ID, jobA.ID}
	if !slices.Equal(ids, wantIDs) {
		t.Fatalf("platform task IDs = %v, want %v", ids, wantIDs)
	}

	tenantRequest := request
	tenantRequest.Audience = AudienceTenant
	tenantRequest.Cursor = ""
	tenantRequest.Limit = 10
	tenantPage, err := service.List(t.Context(), tenantPrincipal(scopeA), tenantRequest)
	if err != nil {
		t.Fatal(err)
	}
	if len(tenantPage.Data) != 2 || tenantPage.Data[0].TenantID != tenantA || tenantPage.Data[1].TenantID != tenantA {
		t.Fatalf("tenant page = %+v", tenantPage)
	}
	if _, err := service.Get(t.Context(), tenantPrincipal(scopeB), AudienceTenant, jobA.ID); !errors.Is(err, ErrNotFound) {
		t.Fatalf("foreign detail error = %v", err)
	}
	stored, err := service.Get(t.Context(), tenantPrincipal(scopeA), AudienceTenant, jobA.ID)
	if err != nil || stored.Status != StateSucceeded || stored.Attempt != 2 {
		t.Fatalf("stored job = %+v, err=%v", stored, err)
	}

	attempts, err := service.Attempts(t.Context(), tenantPrincipal(scopeA), ChildPageRequest{
		Audience: AudienceTenant, TaskID: jobA.ID, Limit: 10,
	})
	if err != nil || len(attempts.Data) != 2 || attempts.Data[0].Number != 2 || attempts.Data[1].Number != 1 {
		t.Fatalf("attempts = %+v, err=%v", attempts, err)
	}
	results, err := service.Results(t.Context(), tenantPrincipal(scopeA), ChildPageRequest{
		Audience: AudienceTenant, TaskID: jobA.ID, Limit: 10,
	})
	if err != nil || len(results.Data) != 2 || results.Data[0].NodeID == nil ||
		results.Data[0].Status != ResultSucceeded || results.Data[1].Attempt != 2 {
		t.Fatalf("results = %+v, err=%v", results, err)
	}
	// item-b failed once in attempt 1 and settled in attempt 2; node-a settled in attempt 1.
	if results.Data[0].FailureCount != 0 || results.Data[1].FailureCount != 1 ||
		results.Data[0].StartedAt == nil || results.Data[1].StartedAt == nil ||
		!results.Data[1].StartedAt.Equal(attempts.Data[0].StartedAt) ||
		!results.Data[0].StartedAt.Equal(attempts.Data[1].StartedAt) {
		t.Fatalf("item start/failure facts = %+v attempts=%+v", results.Data, attempts.Data)
	}
	pending, err := service.Results(t.Context(), tenantPrincipal(scopeA), ChildPageRequest{
		Audience: AudienceTenant, TaskID: jobAQueued.ID, Limit: 10,
	})
	if err != nil || len(pending.Data) != 2 || pending.Data[0].StartedAt != nil || pending.Data[0].FailureCount != 0 {
		t.Fatalf("pending results = %+v, err=%v", pending, err)
	}

	byNode := tenantRequest
	byNode.Resource = strings.ToUpper(nodeID.String())
	nodePage, err := service.List(t.Context(), tenantPrincipal(scopeA), byNode)
	if err != nil || len(nodePage.Data) != 1 || nodePage.Data[0].TaskID != jobA.ID {
		t.Fatalf("node resource page = %+v, err=%v", nodePage, err)
	}
	byNode.Resource = "site/site-a"
	subjectPage, err := service.List(t.Context(), tenantPrincipal(scopeA), byNode)
	if err != nil || len(subjectPage.Data) != 2 {
		t.Fatalf("subject resource page = %+v, err=%v", subjectPage, err)
	}
	byNode.Resource, byNode.Page = nodeID.String(), 1
	numbered, err := service.List(t.Context(), tenantPrincipal(scopeA), byNode)
	if err != nil || numbered.Page.Total == nil || *numbered.Page.Total != 1 || numbered.Data[0].TaskID != jobA.ID {
		t.Fatalf("numbered node resource page = %+v, err=%v", numbered, err)
	}
	if foreign, err := service.List(t.Context(), tenantPrincipal(scopeB), byNode); err != nil || *foreign.Page.Total != 0 {
		t.Fatalf("foreign tenant matched node resource = %+v, err=%v", foreign, err)
	}
}

func createIntegrationJob(
	t *testing.T,
	store *jobstate.Store,
	tenantID uuid.UUID,
	kind, subject string,
	nodeID uuid.UUID,
) jobstate.StoredJob {
	t.Helper()
	items := []jobstate.CreateItem{{ItemID: "node-a"}, {ItemID: "item-b"}}
	if nodeID != uuid.Nil {
		items[0].NodeID = &nodeID
	}
	result, err := store.Create(t.Context(), jobstate.CreateInput{
		TenantID: tenantID, Kind: kind, Subject: subject, IdempotencyKey: "job-" + uuid.NewString(),
		Payload: []byte(`{"private":"not-queryable"}`), Items: items, MaxAttempts: 2,
		RequestID: "job-http-integration", TraceID: "trace-job-http-integration",
	})
	if err != nil {
		t.Fatal(err)
	}
	return result.Job
}

func claimIntegrationJob(t *testing.T, store *jobstate.Store, tenantID uuid.UUID, kind, worker string) jobstate.Claim {
	t.Helper()
	claims, err := store.Claim(t.Context(), jobstate.ClaimInput{
		TenantID: tenantID, Kind: kind, WorkerID: worker, Limit: 1, LeaseDuration: 30 * time.Second,
	})
	if err != nil || len(claims) != 1 {
		t.Fatalf("claims = %+v, err=%v", claims, err)
	}
	return claims[0]
}

func reportIntegrationResult(
	t *testing.T,
	store *jobstate.Store,
	claim jobstate.Claim,
	itemID string,
	state jobstate.ItemState,
	code string,
	sequence uint64,
) {
	t.Helper()
	result, err := store.Report(t.Context(), jobstate.ReportInput{
		TenantID: claim.Job.TenantID, JobID: claim.Job.ID, WorkerID: claim.WorkerID, LeaseID: claim.LeaseID,
		Report: jobstate.Report{ItemID: itemID, State: state, Code: code, Attempt: claim.Job.Attempt, Sequence: sequence},
	})
	if err != nil || !result.Applied {
		t.Fatalf("report = %+v, err=%v", result, err)
	}
}

func seedJobHTTPTenant(t *testing.T, pool *pgxpool.Pool, name string) (uuid.UUID, uuid.UUID) {
	t.Helper()
	tenantID, scopeID := uuid.New(), uuid.New()
	if _, err := pool.Exec(t.Context(), `INSERT INTO tenants(id,display_name) VALUES($1,$2)`, tenantID, name); err != nil {
		t.Fatal(err)
	}
	if _, err := pool.Exec(t.Context(), `INSERT INTO access_scopes(id,kind,tenant_id) VALUES($1,'tenant',$2)`, scopeID, tenantID); err != nil {
		t.Fatal(err)
	}
	return tenantID, scopeID
}

func openJobHTTPTestDatabase(t *testing.T) *pgxpool.Pool {
	t.Helper()
	databaseURL := os.Getenv("TEST_DATABASE_URL")
	if databaseURL == "" {
		t.Skip("TEST_DATABASE_URL is not set")
	}
	admin, err := pgxpool.New(t.Context(), databaseURL)
	if err != nil {
		t.Fatal(err)
	}
	if err := admin.Ping(t.Context()); err != nil {
		admin.Close()
		t.Fatal(err)
	}
	schema := "jobhttp_test_" + strings.ReplaceAll(uuid.NewString(), "-", "")
	if !regexp.MustCompile(`^jobhttp_test_[a-f0-9]{32}$`).MatchString(schema) {
		admin.Close()
		t.Fatalf("unsafe schema %q", schema)
	}
	identifier := pgx.Identifier{schema}.Sanitize()
	if _, err := admin.Exec(t.Context(), "CREATE SCHEMA "+identifier); err != nil {
		admin.Close()
		t.Fatal(err)
	}
	config, err := pgxpool.ParseConfig(databaseURL)
	if err != nil {
		admin.Close()
		t.Fatal(err)
	}
	config.ConnConfig.RuntimeParams["search_path"] = schema
	pool, err := pgxpool.NewWithConfig(t.Context(), config)
	if err != nil {
		admin.Close()
		t.Fatal(err)
	}
	t.Cleanup(func() {
		pool.Close()
		if _, err := admin.Exec(context.Background(), "DROP SCHEMA "+identifier+" CASCADE"); err != nil {
			t.Errorf("drop jobhttp schema: %v", err)
		}
		admin.Close()
	})
	migrateJobHTTPThrough27(t, pool)
	return pool
}

func migrateJobHTTPThrough27(t *testing.T, pool *pgxpool.Pool) {
	t.Helper()
	if _, err := pool.Exec(t.Context(), `
		CREATE TABLE schema_migrations (
			version bigint PRIMARY KEY,
			applied_at timestamptz NOT NULL DEFAULT now()
		)`); err != nil {
		t.Fatal(err)
	}
	for version := int64(1); version <= 27; version++ {
		matches, err := fs.Glob(controlmigrations.FS, fmt.Sprintf("%03d_*.up.sql", version))
		if err != nil || len(matches) != 1 {
			t.Fatalf("migration %03d matches=%v err=%v", version, matches, err)
		}
		script, err := fs.ReadFile(controlmigrations.FS, matches[0])
		if err != nil {
			t.Fatal(err)
		}
		if err := pgx.BeginFunc(t.Context(), pool, func(tx pgx.Tx) error {
			if _, err := tx.Exec(t.Context(), string(script)); err != nil {
				return err
			}
			_, err := tx.Exec(t.Context(), `INSERT INTO schema_migrations(version) VALUES($1)`, version)
			return err
		}); err != nil {
			t.Fatalf("apply migration %03d: %v", version, err)
		}
	}
}
