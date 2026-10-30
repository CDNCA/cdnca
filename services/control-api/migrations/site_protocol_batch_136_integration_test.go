//go:build integration

package migrations_test

import (
	"errors"
	"os"
	"strings"
	"testing"

	"github.com/google/uuid"
	"github.com/jackc/pgx/v5"
	"github.com/jackc/pgx/v5/pgconn"
)

func TestSiteProtocolBatch136MigrationContract(t *testing.T) {
	up := readSiteProtocol136(t, "136_site_protocol_batch.up.sql")
	down := readSiteProtocol136(t, "136_site_protocol_batch.down.sql")
	for _, fragment := range []string{
		"migration 136 requires the exact verified 135 release head",
		"version = 135 AND migration_id = '135_user_groups'",
		"checksum_sha256 = 'cac03de016d85a2e4fbaf225b987e72cd72ecec406d3520adbc168b32097c121'",
		"down_checksum_sha256 = '33cb1ca76ea840e4f83842775435d0ebc3dace58b38d0a9a10706a46ba669c78'",
		"CREATE TABLE site_protocol_batches", "CREATE TABLE site_protocol_states",
		"CREATE TABLE site_protocol_batch_items", "CREATE TABLE site_protocol_jobs",
		"CREATE TABLE site_protocol_node_results", "CREATE TABLE site_protocol_write_requests",
		"CREATE TABLE site_protocol_outbox", "CREATE TABLE site_protocol_audit_events",
		"UNIQUE(actor_scope_id,actor_user_id,operation,idempotency_key)",
		"BEFORE UPDATE OR DELETE", "BEFORE TRUNCATE",
	} {
		if !strings.Contains(up, fragment) {
			t.Errorf("136 up missing %q", fragment)
		}
	}
	if guard, mutation := strings.Index(up, "migration 136 requires the exact verified 135 release head"), strings.Index(up, "INSERT INTO permissions"); guard < 0 || mutation < 0 || guard > mutation {
		t.Fatal("136 predecessor guard must run before the first mutation")
	}
	for _, fragment := range []string{
		"migration 136 rollback requires the exact verified 136 head",
		"version = 136 AND migration_id = '136_site_protocol_batch'",
		"checksum_sha256 = 'f73cf9d49c0da51b31186cadfa57bb68438041fe5af2289d66d85a8f19b38ccb'",
		"checksum_sha256 = 'cac03de016d85a2e4fbaf225b987e72cd72ecec406d3520adbc168b32097c121'",
		"down_checksum_sha256 = '33cb1ca76ea840e4f83842775435d0ebc3dace58b38d0a9a10706a46ba669c78'",
		"migration 136 rollback would discard site protocol facts",
		"DROP TABLE site_protocol_outbox", "DROP TABLE site_protocol_batches",
	} {
		if !strings.Contains(down, fragment) {
			t.Errorf("136 down missing %q", fragment)
		}
	}
	for _, stale := range []string{
		"1d513fd8f458f785c33b5d0f691b760d1d2bf9a83d186a7ad1239bad25c79c94",
		"b576bcc0425f0e5695459ca8427929ab38b4de06053dc8a77bd4792ed392e75c",
		"c6a10532d1747ae2342cd606ba82f673bef7d14f8a0d85d97260ddd40d640383",
	} {
		if strings.Contains(up, stale) || strings.Contains(down, stale) {
			t.Errorf("136 migration retained stale checksum %q", stale)
		}
	}
}

func TestSiteProtocolBatch136EmptyRoundTrip(t *testing.T) {
	pool := packageCommerceRBAC079Pool(t, 135)
	if err := migrateVersionIsolated(t.Context(), pool, "up", 136); err != nil {
		t.Fatalf("apply 136: %v", err)
	}
	if err := migrateVersionIsolated(t.Context(), pool, "down", 136); err != nil {
		t.Fatalf("rollback 136: %v", err)
	}
}

func TestSiteProtocolBatch136ScopeReceiptAndRollbackGuards(t *testing.T) {
	pool := packageCommerceRBAC079Pool(t, 135)
	if err := migrateVersionIsolated(t.Context(), pool, "up", 136); err != nil {
		t.Fatalf("apply 136: %v", err)
	}
	// 136 的作用域触发器在 site_protocol_batches 上读 NEW.site_id（42703），319 修复了函数体；
	// 这里装上 319 的函数体，校验 136 的作用域/回执/回滚守卫本身。
	if _, err := pool.Exec(t.Context(), siteProtocolScopeFunction319(t)); err != nil {
		t.Fatalf("install 319 scope function: %v", err)
	}
	platformScopeID, actorID := uuid.New(), uuid.New()
	tenantID, tenantScopeID, siteID := uuid.New(), uuid.New(), uuid.New()
	if _, err := pool.Exec(t.Context(), `
		INSERT INTO tenants(id,display_name,status,revision,created_at,updated_at)
		VALUES($3,'Protocol Tenant','active',1,now(),now());
		INSERT INTO access_scopes(id,kind,created_at) VALUES($1,'platform',now());
		INSERT INTO access_scopes(id,kind,tenant_id,created_at) VALUES($4,'tenant',$3,now());
		INSERT INTO users(id,username,display_name,password_hash,status,revision,created_at,updated_at)
		VALUES($2,'protocol-admin','Protocol Admin','hash','active',1,now(),now());
		INSERT INTO memberships(scope_id,user_id,status,created_at)
		VALUES($1,$2,'active',now()),($4,$2,'active',now());
		INSERT INTO sites(id,scope_id,owner_user_id,domain,origins,origin_hosts,created_by_user_id,updated_by_user_id)
		VALUES($5,$4,$2,'protocol.example.test',ARRAY['192.0.2.1:443'],ARRAY['protocol.example.test'],$2,$2);
		INSERT INTO site_origin_pools(site_id) VALUES($5);
		INSERT INTO site_origins(site_id,position,host,port) VALUES($5,1,'192.0.2.1',443)`,
		pgx.QueryExecModeSimpleProtocol, platformScopeID, actorID, tenantID, tenantScopeID, siteID); err != nil {
		t.Fatal(err)
	}
	_, err := pool.Exec(t.Context(), `INSERT INTO site_protocol_batches(
		id,tenant_scope_id,actor_user_id,action,http3_enabled,state,revision,request_sha256,request_id,trace_id,created_at,updated_at
	) VALUES($1,$2,$3,'apply',true,'queued',1,$4,'request-1','trace-1',now(),now())`, uuid.New(), platformScopeID, actorID, make([]byte, 32))
	assertSiteProtocol136Code(t, err, "P1361")
	if _, err := pool.Exec(t.Context(), `INSERT INTO site_protocol_batches(
		id,tenant_scope_id,actor_user_id,action,http3_enabled,state,revision,request_sha256,request_id,trace_id,created_at,updated_at
	) VALUES($1,$2,$3,'apply',true,'queued',1,$4,'request-2','trace-2',now(),now())`,
		uuid.New(), tenantScopeID, actorID, make([]byte, 32)); err != nil {
		t.Fatal(err)
	}
	assertSiteProtocol136Code(t, migrateVersionIsolated(t.Context(), pool, "down", 136), "P1366")
}

func assertSiteProtocol136Code(t *testing.T, err error, code string) {
	t.Helper()
	var pgErr *pgconn.PgError
	if !errors.As(err, &pgErr) || pgErr.Code != code {
		t.Fatalf("error=%v, want PostgreSQL code %s", err, code)
	}
}

func siteProtocolScopeFunction319(t *testing.T) string {
	t.Helper()
	up := readSiteProtocol136(t, "319_site_protocol_scope_fields.up.sql")
	const start, end = "CREATE OR REPLACE FUNCTION validate_site_protocol_scope_136()", "$function$;"
	begin := strings.Index(up, start)
	if begin < 0 {
		t.Fatal("319 scope function is missing")
	}
	length := strings.Index(up[begin:], end)
	if length < 0 {
		t.Fatal("319 scope function is unterminated")
	}
	return up[begin : begin+length+len(end)]
}

func readSiteProtocol136(t *testing.T, name string) string {
	t.Helper()
	content, err := os.ReadFile(name)
	if err != nil {
		t.Fatal(err)
	}
	return string(content)
}
