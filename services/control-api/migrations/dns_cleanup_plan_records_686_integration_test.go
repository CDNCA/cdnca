//go:build integration

package migrations_test

import (
	"testing"
	"time"

	"github.com/cdnca/cdnca/services/control-api/internal/jobstate"
	"github.com/google/uuid"
)

// TestDNSCleanupPlanRecords686: after 686 a
// cleanup item can carry its full record; the row must name an existing item
// and hold a canonical owner and an A/AAAA/CNAME type. Down drops the table
// and leaves the jobs.
func TestDNSCleanupPlanRecords686(t *testing.T) {
	const version = 686
	pool := migrationPoolAt(t, version-1)
	ctx := t.Context()
	if err := migrateVersionIsolated(ctx, pool, "up", version); err != nil {
		t.Fatalf("up %d: %v", version, err)
	}
	tenantID := uuid.New()
	mustExec(t, pool, `INSERT INTO tenants(id,display_name) VALUES($1,'DNS 686')`, tenantID)
	jobs, err := jobstate.NewStore(pool, time.Now)
	if err != nil {
		t.Fatal(err)
	}
	item, spare := "删除记录 old.cdn.example.com A 198.51.100.7 #zone/rec-1", "删除记录 new.cdn.example.com A 198.51.100.8 #zone/rec-2"
	created, err := jobs.Create(ctx, jobstate.CreateInput{TenantID: tenantID, Kind: "dns.cleanup.v1", Subject: "DNS清除",
		IdempotencyKey: "dns-686-" + tenantID.String(), Items: []jobstate.CreateItem{{ItemID: item}, {ItemID: spare}}, MaxAttempts: 1,
		RequestID: "request-686"})
	if err != nil {
		t.Fatal(err)
	}
	insert := `INSERT INTO dns_cleanup_plan_records(tenant_id,job_id,item_id,zone_id,provider_record_id,owner_name,
		record_type,record_value) VALUES($1,$2,$3,$4,'rec-1',$5,$6,'198.51.100.7')`
	mustExec(t, pool, insert, tenantID, created.Job.ID, item, uuid.New(), "old.cdn.example.com.", "A")
	for name, args := range map[string][]any{
		"upper-case owner":    {tenantID, created.Job.ID, spare, uuid.New(), "New.cdn.example.com.", "A"},
		"owner without dot":   {tenantID, created.Job.ID, spare, uuid.New(), "new.cdn.example.com", "A"},
		"TXT record":          {tenantID, created.Job.ID, spare, uuid.New(), "new.cdn.example.com.", "TXT"},
		"item of no job":      {tenantID, uuid.New(), spare, uuid.New(), "new.cdn.example.com.", "A"},
		"second row for item": {tenantID, created.Job.ID, item, uuid.New(), "old.cdn.example.com.", "A"},
		"item not in the job": {tenantID, created.Job.ID, "删除记录 other", uuid.New(), "old.cdn.example.com.", "A"},
	} {
		if _, err := pool.Exec(ctx, insert, args...); err == nil {
			t.Errorf("%s was accepted", name)
		}
	}
	if err := migrateVersionIsolated(ctx, pool, "down", version); err != nil {
		t.Fatalf("down %d: %v", version, err)
	}
	var table bool
	var items int
	if err := pool.QueryRow(ctx, `SELECT to_regclass(current_schema() || '.dns_cleanup_plan_records') IS NOT NULL,
		(SELECT count(*) FROM background_job_items WHERE job_id=$1)`, created.Job.ID).Scan(&table, &items); err != nil {
		t.Fatal(err)
	}
	if table || items != 2 {
		t.Fatalf("after down: table=%v items=%d", table, items)
	}
	if err := migrateVersionIsolated(ctx, pool, "up", version); err != nil {
		t.Fatalf("second up %d: %v", version, err)
	}
}
