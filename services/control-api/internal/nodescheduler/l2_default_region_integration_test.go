//go:build integration

package nodescheduler

import (
	"bytes"
	"errors"
	"strings"
	"testing"
	"time"

	"github.com/cdnca/cdnca/services/control-api/internal/apikeycredential"
	"github.com/cdnca/cdnca/services/control-api/internal/database/databasetest"
	"github.com/cdnca/cdnca/services/control-api/internal/iamlock"
	"github.com/cdnca/cdnca/services/control-api/internal/iamlock/protocol"
	"github.com/cdnca/cdnca/services/control-api/internal/identity"
	"github.com/cdnca/cdnca/services/control-api/internal/sessioncredential"
	"github.com/cdnca/cdnca/services/control-api/migrations"
	"github.com/google/uuid"
	"github.com/jackc/pgx/v5"
	"github.com/jackc/pgx/v5/pgconn"
)

func TestL2DefaultRegionCRUDIsolationIdempotency(t *testing.T) {
	fixture := newIntegrationFixture(t)
	ctx := t.Context()
	request := L2ConfigWriteRequest{
		Name: "default L2", Region: "", Mode: L2ModeCache, LoadMethod: L2LoadRoundRobin,
		IdempotencyKey: "default-create", RequestID: "default-create-request",
	}
	created, err := fixture.service.PutL2Config(ctx, fixture.actor, request)
	if err != nil || created.Config.Region != "" || created.Config.Revision != 1 || created.Replayed {
		t.Fatalf("create default config=%#v err=%v", created, err)
	}
	read, err := fixture.service.GetL2Config(ctx, fixture.actor, created.Config.ID)
	if err != nil || read.Region != "" || read.ID != created.Config.ID || read.TenantScopeID != fixture.actor.ScopeID {
		t.Fatalf("read default config=%#v err=%v", read, err)
	}
	replay, err := fixture.service.PutL2Config(ctx, fixture.actor, request)
	// pgx can use time.Local for UTC hosts, while the JSON receipt uses UTC.
	// Compare the same instants without depending on Location pointer identity.
	createdConfig, replayConfig := created.Config, replay.Config
	createdConfig.CreatedAt, createdConfig.UpdatedAt = createdConfig.CreatedAt.UTC(), createdConfig.UpdatedAt.UTC()
	replayConfig.CreatedAt, replayConfig.UpdatedAt = replayConfig.CreatedAt.UTC(), replayConfig.UpdatedAt.UTC()
	if err != nil || !replay.Replayed || replayConfig != createdConfig {
		t.Fatalf("default replay=%#v err=%v", replay, err)
	}
	changed := request
	changed.Region = "华东"
	if _, err := fixture.service.PutL2Config(ctx, fixture.actor, changed); !errors.Is(err, ErrIdempotencyConflict) {
		t.Fatalf("changed region replay error=%v", err)
	}
	for index, region := range []string{"华东", ""} {
		update := request
		update.ConfigID, update.ExpectedRevision, update.Region = created.Config.ID, int64(index+1), region
		update.IdempotencyKey, update.RequestID = "default-update-"+string(rune('a'+index)), "default-update-request-"+string(rune('a'+index))
		written, err := fixture.service.PutL2Config(ctx, fixture.actor, update)
		if err != nil || written.Config.Region != region || written.Config.Revision != int64(index+2) {
			t.Fatalf("update region=%q result=%#v err=%v", region, written, err)
		}
		read, err = fixture.service.GetL2Config(ctx, fixture.actor, created.Config.ID)
		if err != nil || read.Region != region || read.Revision != written.Config.Revision {
			t.Fatalf("read updated region=%#v err=%v", read, err)
		}
		update.IdempotencyKey += "-stale"
		if _, err := fixture.service.PutL2Config(ctx, fixture.actor, update); !errors.Is(err, ErrRevisionConflict) {
			t.Fatalf("stale revision error=%v", err)
		}
	}
	viewer := seedTenantViewer(t, fixture.pool, fixture.actor.ScopeID, "default-viewer")
	if listed, err := fixture.service.ListL2Configs(ctx, viewer); err != nil || len(listed) != 1 || listed[0].Region != "" {
		t.Fatalf("viewer read default=%#v err=%v", listed, err)
	}
	if _, err := fixture.service.PutL2Config(ctx, viewer, request); !errors.Is(err, ErrPermissionDenied) {
		t.Fatalf("viewer default write error=%v", err)
	}
	other := seedTenantActor(t, fixture.pool, "default-other")
	if _, err := fixture.service.GetL2Config(ctx, other, created.Config.ID); !errors.Is(err, ErrNotFound) {
		t.Fatalf("cross-scope default read error=%v", err)
	}
	for _, testCase := range []struct {
		name  string
		actor Actor
		id    uuid.UUID
	}{
		{name: "missing", actor: fixture.actor, id: uuid.New()},
		{name: "cross-scope", actor: other, id: created.Config.ID},
	} {
		update := request
		update.ConfigID, update.ExpectedRevision = testCase.id, 3
		update.IdempotencyKey, update.RequestID = testCase.name, testCase.name+"-request"
		if _, err := fixture.service.PutL2Config(ctx, testCase.actor, update); !errors.Is(err, ErrNotFound) {
			t.Fatalf("%s update error=%v, want not found", testCase.name, err)
		}
	}
	read, err = fixture.service.GetL2Config(ctx, fixture.actor, created.Config.ID)
	if err != nil || read.Region != "" || read.Name != request.Name || read.Revision != 3 {
		t.Fatalf("failed CAS mutated config=%#v err=%v", read, err)
	}
	var receipts, audits int
	if err := fixture.pool.QueryRow(ctx, `SELECT count(*) FROM l2_topology_write_requests`).Scan(&receipts); err != nil {
		t.Fatal(err)
	}
	if err := fixture.pool.QueryRow(ctx, `SELECT count(*) FROM audit_events WHERE resource_id=$1`, created.Config.ID.String()).Scan(&audits); err != nil {
		t.Fatal(err)
	}
	if receipts != 3 || audits != 3 {
		t.Fatalf("default write receipts=%d audits=%d, want 3/3", receipts, audits)
	}
	deletedRequest := request
	deletedRequest.Name, deletedRequest.IdempotencyKey, deletedRequest.RequestID = "deleted default", "deleted-create", "deleted-create-request"
	deleted, err := fixture.service.PutL2Config(ctx, fixture.actor, deletedRequest)
	if err != nil {
		t.Fatal(err)
	}
	if _, err := fixture.service.DeleteL2Config(ctx, fixture.actor, deleted.Config.ID, 1, "default-delete", "default-delete-request"); err != nil {
		t.Fatal(err)
	}
	deletedRequest.ConfigID, deletedRequest.ExpectedRevision = deleted.Config.ID, 1
	deletedRequest.IdempotencyKey, deletedRequest.RequestID = "deleted-update", "deleted-update-request"
	if _, err := fixture.service.PutL2Config(ctx, fixture.actor, deletedRequest); !errors.Is(err, ErrNotFound) {
		t.Fatalf("soft-deleted update error=%v, want not found", err)
	}
	if err := fixture.pool.QueryRow(ctx, `SELECT count(*) FROM l2_topology_write_requests`).Scan(&receipts); err != nil {
		t.Fatal(err)
	}
	if err := fixture.pool.QueryRow(ctx, `SELECT count(*) FROM audit_events WHERE scope_id=$1`, fixture.actor.ScopeID).Scan(&audits); err != nil {
		t.Fatal(err)
	}
	if receipts != 5 || audits != 5 {
		t.Fatalf("failed writes leaked receipts/audit: got %d/%d, want 5/5", receipts, audits)
	}

	t.Run("platform session own scope and revoked replay", func(t *testing.T) {
		now := time.Now().UTC().Truncate(time.Microsecond)
		tokens, err := identity.NewTokenManager(strings.Repeat("d", 32), time.Hour)
		if err != nil {
			t.Fatal(err)
		}
		sessions, err := sessioncredential.NewVerifier(tokens, func() time.Time { return now })
		if err != nil {
			t.Fatal(err)
		}
		apiKeys, err := apikeycredential.NewVerifier(bytes.Repeat([]byte{0x42}, 32), func() time.Time { return now })
		if err != nil {
			t.Fatal(err)
		}
		authorizer, err := iamlock.NewAuthorizer(sessions, apiKeys)
		if err != nil {
			t.Fatal(err)
		}
		service, err := NewIAMService(fixture.pool, func() time.Time { return now }, authorizer, nil)
		if err != nil {
			t.Fatal(err)
		}
		actor := seedPlatformIAMSession(t, fixture, tokens, now)
		if _, err := service.PutL2Config(ctx, actor, request); !errors.Is(err, ErrPlatformWriteDenied) {
			t.Fatalf("platform cross-scope default write error=%v", err)
		}
		actor.TargetScopeID = actor.ScopeID
		created, err := service.PutL2Config(ctx, actor, request)
		if err != nil || created.Config.Region != "" || created.Config.TenantScopeID != actor.ScopeID {
			t.Fatalf("platform own default create error=%v", err)
		}
		read, err := service.GetL2Config(ctx, actor, created.Config.ID)
		if err != nil || read.Region != "" || read.ID != created.Config.ID {
			t.Fatalf("platform own default read error=%v", err)
		}
		if replay, err := service.PutL2Config(ctx, actor, request); err != nil || !replay.Replayed || replay.Config.ID != created.Config.ID {
			t.Fatalf("platform own default replay error=%v", err)
		}
		if err := pgx.BeginFunc(ctx, fixture.pool, func(tx pgx.Tx) error {
			if _, err := protocol.BeginAuthorityMutation(ctx, tx, protocol.OperationSessionRevoke, []uuid.UUID{actor.ScopeID}); err != nil {
				return err
			}
			_, err := tx.Exec(ctx, `UPDATE auth_sessions SET revoked_at=$3,revocation_reason='test'
				WHERE user_id=$1 AND scope_id=$2`, actor.UserID, actor.ScopeID, now)
			return err
		}); err != nil {
			t.Fatal(err)
		}
		if _, err := service.PutL2Config(ctx, actor, request); !errors.Is(err, ErrCredentialInvalid) {
			t.Fatalf("revoked session must reject default replay: %v", err)
		}
	})
}

func TestL2DefaultRegionMigration270RoundTripAndGuards(t *testing.T) {
	// Migration 268's down is a deliberate one-way gate (P2682) and later
	// migrations sit on top of 270; pin the schema head to 270 for this test.
	pool := openNodeSchedulingDatabaseThrough(t, 270)
	ctx := t.Context()
	actor := seedTenantActor(t, pool, "default-migration")
	defaultID := uuid.New()
	insert := func(id uuid.UUID, region string) error {
		_, err := pool.Exec(ctx, `INSERT INTO l2_topology_configs
			(id,tenant_scope_id,name,region,mode,load_method,created_by_user_id,updated_by_user_id,created_at,updated_at)
			VALUES($1,$2,$1::uuid::text,$3,'cache','rr',$4,$4,now(),now())`, id, actor.ScopeID, region, actor.UserID)
		return err
	}
	// This real SQL write fails under migration 269's original nonempty-region CHECK.
	if err := insert(defaultID, ""); err != nil {
		t.Fatalf("database rejects explicit default region: %v", err)
	}
	var count, head int
	if err := pool.QueryRow(ctx, `SELECT count(*),max(version) FROM schema_migrations WHERE integrity_state='verified'`).Scan(&count, &head); err != nil || count != 270 || head != 270 {
		t.Fatalf("verified migrations count=%d head=%d err=%v, want 270/270", count, head, err)
	}
	for _, region := range []string{" ", "\t", "华\n东", strings.Repeat("区", 65)} {
		assertConstraintError(t, insert(uuid.New(), region), "l2_topology_configs_region_270_check")
	}
	if err := insert(uuid.New(), strings.Repeat("区", 64)); err != nil {
		t.Fatalf("64 code-point region: %v", err)
	}
	down, err := migrations.FS.ReadFile("270_l2_topology_default_region.down.sql")
	if err != nil {
		t.Fatal(err)
	}
	err = pgx.BeginFunc(ctx, pool, func(tx pgx.Tx) error {
		if _, err := tx.Exec(ctx, `UPDATE schema_migrations SET migration_id='270_wrong' WHERE version=270`); err != nil {
			return err
		}
		_, err := tx.Exec(ctx, string(down))
		return err
	})
	var wrongHead *pgconn.PgError
	if !errors.As(err, &wrongHead) || wrongHead.Code != "P2701" {
		t.Fatalf("down with wrong release head=%v, want P2701", err)
	}
	for _, softDeleted := range []bool{false, true} {
		if softDeleted {
			if _, err := pool.Exec(ctx, `UPDATE l2_topology_configs SET deleted_at=now(),deleted_by_user_id=$2 WHERE id=$1`, defaultID, actor.UserID); err != nil {
				t.Fatal(err)
			}
		}
		err := databasetest.MigrateThrough(ctx, pool, "down", 270)
		var pgError *pgconn.PgError
		if !errors.As(err, &pgError) || pgError.Code != "P2702" {
			t.Fatalf("down with default soft_deleted=%t err=%v, want P2702", softDeleted, err)
		}
		var region string
		if err := pool.QueryRow(ctx, `SELECT region FROM l2_topology_configs WHERE id=$1`, defaultID).Scan(&region); err != nil || region != "" {
			t.Fatalf("failed down changed default fact: region=%q err=%v", region, err)
		}
	}

	// A separate fresh schema proves reversible down/up without rewriting default facts.
	empty := openNodeSchedulingDatabaseThrough(t, 270)
	namedActor := seedTenantActor(t, empty, "named-migration")
	namedID := uuid.New()
	if _, err := empty.Exec(ctx, `INSERT INTO l2_topology_configs
		(id,tenant_scope_id,name,region,mode,load_method,created_by_user_id,updated_by_user_id,created_at,updated_at)
		VALUES($1,$2,'named','华东','cache','rr',$3,$3,now(),now())`, namedID, namedActor.ScopeID, namedActor.UserID); err != nil {
		t.Fatal(err)
	}
	if err := databasetest.MigrateThrough(ctx, empty, "down", 270); err != nil {
		t.Fatalf("down without default facts: %v", err)
	}
	_, err = empty.Exec(ctx, `UPDATE l2_topology_configs SET region='' WHERE id=$1`, namedID)
	assertConstraintError(t, err, "l2_topology_configs_region_check")
	up, err := migrations.FS.ReadFile("270_l2_topology_default_region.up.sql")
	if err != nil {
		t.Fatal(err)
	}
	err = pgx.BeginFunc(ctx, empty, func(tx pgx.Tx) error {
		if _, err := tx.Exec(ctx, `UPDATE schema_migrations SET checksum_sha256=repeat('0',64) WHERE version=269`); err != nil {
			return err
		}
		_, err := tx.Exec(ctx, string(up))
		return err
	})
	var pgError *pgconn.PgError
	if !errors.As(err, &pgError) || pgError.Code != "P2700" {
		t.Fatalf("up with wrong predecessor hash=%v, want P2700", err)
	}
	if err := databasetest.MigrateThrough(ctx, empty, "up", 270); err != nil {
		t.Fatalf("reapply 270: %v", err)
	}
	var region string
	if err := empty.QueryRow(ctx, `SELECT region FROM l2_topology_configs WHERE id=$1`, namedID).Scan(&region); err != nil || region != "华东" {
		t.Fatalf("round trip changed named region=%q err=%v", region, err)
	}
	if _, err := empty.Exec(ctx, `UPDATE l2_topology_configs SET region='' WHERE id=$1`, namedID); err != nil {
		t.Fatalf("default after reapply: %v", err)
	}
}
