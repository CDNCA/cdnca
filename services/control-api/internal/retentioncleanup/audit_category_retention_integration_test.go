//go:build integration

package retentioncleanup

import (
	"context"
	"errors"
	"testing"
	"time"

	"github.com/cdnca/cdnca/services/control-api/internal/audit"
	"github.com/cdnca/cdnca/services/control-api/internal/systemcleanup"
	"github.com/google/uuid"
	"github.com/jackc/pgx/v5"
)

// unified-log: each audit row expires by its own category's retention. A
// long-retention row (finance) no longer blocks the cleanup of shorter-lived
// rows after it, it stays readable until its own retention, and the archive
// copies of deleted rows are purged so the log does not keep growing.
func TestWorkerExpiresAuditRowsByCategory(t *testing.T) {
	pool := retentionTestPool(t)
	ctx := context.Background()
	grantCleanupRole(t, pool)
	tenantID, scopeID, platformScope := uuid.New(), uuid.New(), uuid.New()
	for _, statement := range []struct {
		sql  string
		args []any
	}{
		{`INSERT INTO access_scopes(id,kind) VALUES($1,'platform')`, []any{platformScope}},
		{`INSERT INTO tenants(id,display_name) VALUES($1,'Category retention')`, []any{tenantID}},
		{`INSERT INTO access_scopes(id,kind,tenant_id) VALUES($1,'tenant',$2)`, []any{scopeID, tenantID}},
	} {
		if _, err := pool.Exec(ctx, statement.sql, statement.args...); err != nil {
			t.Fatalf("seed: %v", err)
		}
	}
	setRetention := func(days map[string]int) {
		t.Helper()
		if err := SaveAuditRetention(ctx, pool, platformScope, days); err != nil {
			t.Fatalf("save retention: %v", err)
		}
	}
	setRetention(map[string]int{"auth": 10, "site": 10, "finance": 1095})

	now := time.Now().UTC()
	events := []struct {
		age              time.Duration
		action, resource string
	}{
		{30 * 24 * time.Hour, "billing.adjustment.create", "order-a"}, // 1 finance, within 1095 days: kept
		{20 * 24 * time.Hour, "auth.login", "user-a"},                 // 2 expired, superseded by 3: deleted
		{19 * 24 * time.Hour, "auth.login", "user-a"},                 // 3 expired, superseded by 4: deleted
		{18 * 24 * time.Hour, "auth.login", "user-a"},                 // 4 expired, newest of its group: kept
		{17 * 24 * time.Hour, "site.update", "site-a"},                // 5 expired, superseded by 6: deleted
		{16 * 24 * time.Hour, "site.update", "site-a"},                // 6 expired, newest: kept
		{24 * time.Hour, "site.update", "site-b"},                     // 7 within retention
		{12 * time.Hour, "auth.login", "user-b"},                      // 8 head
	}
	for _, event := range events {
		clock := now.Add(-event.age)
		log := audit.NewWithClock(pool, func() time.Time { return clock })
		if err := pgx.BeginFunc(ctx, pool, func(tx pgx.Tx) error {
			return log.Append(ctx, tx, audit.Event{ScopeID: scopeID, Action: event.action, ResourceType: "test",
				ResourceID: event.resource, RequestID: "category-" + uuid.NewString(), Result: "success",
				Payload: map[string]any{}})
		}); err != nil {
			t.Fatalf("append %s: %v", event.action, err)
		}
	}
	worker, err := NewWorker(pool, audit.New(pool), Config{BatchSize: 3, BatchPause: time.Millisecond})
	if err != nil {
		t.Fatal(err)
	}
	positions := func(table string) []int64 {
		t.Helper()
		rows, err := pool.Query(ctx, `SELECT stream_position FROM `+table+` WHERE scope_id=$1 ORDER BY 1`, scopeID)
		if err != nil {
			t.Fatal(err)
		}
		got, err := pgx.CollectRows(rows, pgx.RowTo[int64])
		if err != nil {
			t.Fatal(err)
		}
		return got
	}
	if result := worker.archiveAudit(ctx); result.Err != nil {
		t.Fatalf("archive: %+v", result)
	}
	if got := positions("audit_events"); !equalPositions(got, []int64{1, 4, 6, 7, 8}) {
		t.Fatalf("remaining = %v, want [1 4 6 7 8] (finance row must not block the rest)", got)
	}
	var through int64
	if err := pool.QueryRow(ctx, `SELECT through_position FROM audit_chain_checkpoints WHERE scope_id=$1`, scopeID).Scan(&through); err != nil || through != 6 {
		t.Fatalf("checkpoint = %d (%v), want 6", through, err)
	}
	// Archive copies of deleted rows are gone; kept rows and the checkpoint row remain.
	if got := positions("audit_event_archive"); !equalPositions(got, []int64{1, 4, 6}) {
		t.Fatalf("archive = %v, want [1 4 6]", got)
	}
	if err := audit.New(pool).VerifyScope(ctx, scopeID); err != nil {
		t.Fatalf("verify: %v", err)
	}

	// A newer row of the same finance group (9, appended late with an older
	// timestamp, so it is not archivable yet) unpins row 1; shortening finance
	// retention to 20 days then deletes row 1 even though no new row is
	// archived in this run. Pinned rows 4 and 6 stay.
	clock := now.Add(-15 * 24 * time.Hour)
	log := audit.NewWithClock(pool, func() time.Time { return clock })
	if err := pgx.BeginFunc(ctx, pool, func(tx pgx.Tx) error {
		return log.Append(ctx, tx, audit.Event{ScopeID: scopeID, Action: "billing.adjustment.create", ResourceType: "test",
			ResourceID: "order-a", RequestID: "category-" + uuid.NewString(), Result: "success", Payload: map[string]any{}})
	}); err != nil {
		t.Fatal(err)
	}
	setRetention(map[string]int{"auth": 10, "site": 10, "finance": 20})
	if result := worker.archiveAudit(ctx); result.Err != nil {
		t.Fatalf("second archive: %+v", result)
	}
	if got := positions("audit_events"); !equalPositions(got, []int64{4, 6, 7, 8, 9}) {
		t.Fatalf("remaining after finance retention change = %v, want [4 6 7 8 9]", got)
	}
	if err := audit.New(pool).VerifyScope(ctx, scopeID); err != nil {
		t.Fatalf("verify after second run: %v", err)
	}
	// Nobody but the cleanup role may purge the archive, and never the checkpoint row.
	if _, err := pool.Exec(ctx, `DELETE FROM audit_event_archive WHERE scope_id=$1`, scopeID); !hasCode(err, "P3312") {
		t.Fatalf("plain archive delete err = %v", err)
	}
	if err := pgx.BeginFunc(ctx, pool, func(tx pgx.Tx) error {
		if _, err := tx.Exec(ctx, "SET LOCAL ROLE "+Role); err != nil {
			return err
		}
		_, err := tx.Exec(ctx, `DELETE FROM audit_event_archive WHERE scope_id=$1 AND stream_position=4`, scopeID)
		return err
	}); !hasCode(err, "P3614") {
		t.Fatalf("cleanup delete of an archive row still in audit_events err = %v, want P3614", err)
	}
}

// Retention settings: defaults from the catalog, 0 = forever, range checked.
func TestAuditRetentionSettings(t *testing.T) {
	pool := retentionTestPool(t)
	ctx := context.Background()
	platformScope := uuid.New()
	if _, err := pool.Exec(ctx, `INSERT INTO access_scopes(id,kind) VALUES($1,'platform')`, platformScope); err != nil {
		t.Fatal(err)
	}
	got, err := LoadAuditRetention(ctx, pool)
	if err != nil {
		t.Fatal(err)
	}
	for _, info := range audit.Categories() {
		if got[string(info.Category)] != info.RetentionDays {
			t.Errorf("default %s = %d, want %d", info.Category, got[string(info.Category)], info.RetentionDays)
		}
	}
	if err := SaveAuditRetention(ctx, pool, platformScope, map[string]int{"auth": 0, "finance": 3650}); err != nil {
		t.Fatal(err)
	}
	got, err = LoadAuditRetention(ctx, pool)
	if err != nil || got["auth"] != 0 || got["finance"] != 3650 || got["site"] != 180 {
		t.Fatalf("after save = %v (%v)", got, err)
	}
	for _, bad := range []map[string]int{{"auth": -1}, {"auth": 3651}, {"bogus": 10}} {
		if err := SaveAuditRetention(ctx, pool, platformScope, bad); err == nil {
			t.Errorf("SaveAuditRetention(%v) accepted", bad)
		}
	}
}

// The console path: systemcleanup.Service.Save stores per-category retention
// the cleanup worker reads, and audits each changed category.
func TestConsoleSavedAuditRetentionDrivesCleanup(t *testing.T) {
	pool := retentionTestPool(t)
	ctx := context.Background()
	scopeID, userID, roleID := uuid.New(), uuid.New(), uuid.New()
	for _, statement := range []struct {
		sql  string
		args []any
	}{
		{`INSERT INTO access_scopes(id,kind) VALUES($1,'platform')`, []any{scopeID}},
		{`INSERT INTO users(id,username,display_name,password_hash) VALUES($1,'retention-admin','Admin','unused')`, []any{userID}},
		{`INSERT INTO memberships(scope_id,user_id) VALUES($1,$2)`, []any{scopeID, userID}},
		{`INSERT INTO roles(id,scope_id,name,description,system_role) VALUES($1,$2,'retention-admin','test',true)`, []any{roleID, scopeID}},
		{`INSERT INTO role_assignments(scope_id,user_id,role_id) VALUES($1,$2,$3)`, []any{scopeID, userID, roleID}},
		{`INSERT INTO role_permissions(role_id,permission_name) VALUES($1,'system_configuration.manage'),($1,'system_configuration.read')`, []any{roleID}},
	} {
		if _, err := pool.Exec(ctx, statement.sql, statement.args...); err != nil {
			t.Fatal(err)
		}
	}
	service, err := systemcleanup.NewService(pool, audit.New(pool), time.Now)
	if err != nil {
		t.Fatal(err)
	}
	actor := systemcleanup.Actor{UserID: userID, ScopeID: scopeID, ScopeKind: "platform"}
	value := systemcleanup.DefaultSettings()
	value.AuditRetentionDays = map[string]int{"auth": 7} // partial: the rest keep their defaults
	saved, err := service.Save(ctx, actor, systemcleanup.SaveRequest{Value: value, IdempotencyKey: "retention-1", RequestID: "retention-1"})
	if err != nil || saved.Value.AuditRetentionDays["auth"] != 7 || saved.Value.AuditRetentionDays["finance"] != 1095 {
		t.Fatalf("save = %+v (%v)", saved, err)
	}
	got, err := LoadAuditRetention(ctx, pool)
	if err != nil || got["auth"] != 7 || got["site"] != 180 {
		t.Fatalf("worker retention = %v (%v)", got, err)
	}
	read, err := service.Get(ctx, actor)
	if err != nil || len(read.Value.AuditRetentionDays) != len(audit.Categories()) || read.Value.AuditRetentionDays["auth"] != 7 {
		t.Fatalf("get = %+v (%v)", read, err)
	}
	var category, changes string
	if err := pool.QueryRow(ctx, `SELECT category, changes::text FROM audit_events
		WHERE action='system_cleanup_settings.update' AND scope_id=$1`, scopeID).Scan(&category, &changes); err != nil {
		t.Fatal(err)
	}
	if category != "system" || changes != `[{"after": 7, "field": "audit_retention_days.auth", "before": 90}]` {
		t.Fatalf("audit category=%s changes=%s", category, changes)
	}
	bad := systemcleanup.DefaultSettings()
	bad.AuditRetentionDays = map[string]int{"login_records": 30}
	if _, err := service.Save(ctx, actor, systemcleanup.SaveRequest{ExpectedRevision: 1, Value: bad,
		IdempotencyKey: "retention-2", RequestID: "retention-2"}); !errors.Is(err, systemcleanup.ErrInvalidInput) {
		t.Fatalf("unknown category accepted: %v", err)
	}
}

func equalPositions(got, want []int64) bool {
	if len(got) != len(want) {
		return false
	}
	for index := range got {
		if got[index] != want[index] {
			return false
		}
	}
	return true
}
