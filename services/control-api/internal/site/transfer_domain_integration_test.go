package site

import (
	"context"
	"errors"
	"os"
	"strings"
	"testing"
	"time"

	"github.com/cdnca/cdnca/services/control-api/internal/database"
	"github.com/cdnca/cdnca/services/control-api/internal/domaintrust"
	"github.com/google/uuid"
	"github.com/jackc/pgx/v5"
	"github.com/jackc/pgx/v5/pgxpool"
)

// fix-decide1027b 第 4 项：原租户已验证网站域名的 apex 时，过户把该 apex 的验证转给
// 目标租户（原租户 revoked、目标租户 verified，两边各记 domain_ownership.admin_transfer），
// 新站不再被 domain_verified_by_other 拒；原租户其他网站仍在用该 apex 时拒绝过户。
func TestSiteTransferMovesVerifiedApex(t *testing.T) {
	dsn := os.Getenv("TEST_DATABASE_URL")
	if dsn == "" {
		t.Skip("TEST_DATABASE_URL required")
	}
	admin, err := pgxpool.New(t.Context(), dsn)
	if err != nil {
		t.Fatal(err)
	}
	defer admin.Close()
	schema := "site_transfer_apex_" + strings.ReplaceAll(uuid.NewString(), "-", "")
	if _, err := admin.Exec(t.Context(), "CREATE SCHEMA "+pgx.Identifier{schema}.Sanitize()); err != nil {
		t.Fatal(err)
	}
	defer admin.Exec(context.Background(), "DROP SCHEMA "+pgx.Identifier{schema}.Sanitize()+" CASCADE")
	config, err := pgxpool.ParseConfig(dsn)
	if err != nil {
		t.Fatal(err)
	}
	config.ConnConfig.RuntimeParams["search_path"] = schema
	pool, err := pgxpool.NewWithConfig(t.Context(), config)
	if err != nil {
		t.Fatal(err)
	}
	defer pool.Close()
	if err := database.Migrate(t.Context(), pool, "up"); err != nil {
		t.Fatal(err)
	}
	now := time.Now().UTC().Truncate(time.Second)
	manager := addonSiteInsertPlatformActor(t, pool, "apex-admin")
	addonSiteAssignSubscriptionRole(t, pool, manager.ScopeID, manager.UserID, "platform-site-admin", "platform.admin", "sites.manage")
	from := addonSiteInsertSubscriptionTenant(t, pool, "Apex from", "apex-from")
	addonSiteAssignSubscriptionRole(t, pool, from.scopeID, from.userID, "site-owner", "sites.manage")
	to := addonSiteInsertSubscriptionTenant(t, pool, "Apex to", "apex-to")
	addonSiteAssignSubscriptionRole(t, pool, to.scopeID, to.userID, "site-owner", "sites.manage")
	store := NewStoreWithClock(pool, func() time.Time { return now }, nil)
	store.guard = installAddonSiteEntitlement(t, pool, now, time.Hour)
	service := NewService(store)
	platform := Actor{UserID: manager.UserID, ScopeID: manager.ScopeID, ScopeKind: "platform", SessionID: manager.SessionID}

	verify := func(apex string) {
		t.Helper()
		if _, err := pool.Exec(t.Context(), `INSERT INTO domain_ownerships(id,scope_id,apex,method,token,status,verified_at,
			created_by_user_id,created_at,updated_at) VALUES($1,$2,$3,'dns_txt',$4,'verified',$5,$6,$5,$5)`,
			uuid.New(), from.scopeID, apex, strings.Repeat("ab", 24), now.Add(-time.Hour), from.userID); err != nil {
			t.Fatal(err)
		}
	}
	create := func(key string, domains ...string) Site {
		t.Helper()
		created, err := service.Create(t.Context(), platform, CreateRequest{TargetScopeID: from.scopeID, OwnerUserID: from.userID,
			Fields: SiteFields{Domains: domains, HTTPPorts: []string{"80"}, Origins: []string{"192.0.2.9:80"},
				Enabled: false, Status: StatusDisabled},
			IdempotencyKey: key, RequestID: key})
		if err != nil {
			t.Fatalf("create %v: %v", domains, err)
		}
		return created.Site
	}
	status := func(scopeID uuid.UUID, apex string) string {
		t.Helper()
		var value string
		err := pool.QueryRow(t.Context(), `SELECT status FROM domain_ownerships WHERE scope_id=$1 AND apex=$2`, scopeID, apex).Scan(&value)
		if errors.Is(err, pgx.ErrNoRows) {
			return ""
		}
		if err != nil {
			t.Fatal(err)
		}
		return value
	}

	verify("move.example")
	moving := create("apex-create", "www.move.example", "*.move.example")
	moved, err := service.Transfer(t.Context(), platform, TransferRequest{ID: moving.ID, ExpectedRevision: moving.Revision,
		TargetUserID: to.userID, IdempotencyKey: "apex-transfer", RequestID: "apex-transfer"})
	if err != nil {
		t.Fatalf("transfer of a site under a verified apex: %v", err)
	}
	if moved.Site.ScopeID != to.scopeID {
		t.Fatalf("moved scope = %s", moved.Site.ScopeID)
	}
	if got := status(from.scopeID, "move.example"); got != "revoked" {
		t.Fatalf("old tenant ownership = %q, want revoked", got)
	}
	if got := status(to.scopeID, "move.example"); got != "verified" {
		t.Fatalf("target tenant ownership = %q, want verified", got)
	}
	var audited int
	if err := pool.QueryRow(t.Context(), `SELECT count(*) FROM audit_events WHERE action='domain_ownership.admin_transfer'
		AND actor_user_id=$1 AND scope_id=ANY($2::uuid[]) AND payload->>'apex'='move.example'`,
		manager.UserID, []uuid.UUID{from.scopeID, to.scopeID}).Scan(&audited); err != nil || audited != 2 {
		t.Fatalf("admin_transfer audit = %d, %v", audited, err)
	}
	// 目标用户在该 apex 下可直接再建站（验证已归他）
	if _, err := service.Create(t.Context(), Actor{UserID: to.userID, ScopeID: to.scopeID, ScopeKind: "tenant"}, CreateRequest{
		TargetScopeID: to.scopeID, Fields: SiteFields{Domains: []string{"move.example"}, HTTPPorts: []string{"80"},
			Origins: []string{"192.0.2.9:80"}, Enabled: false, Status: StatusDisabled},
		IdempotencyKey: "apex-target-create", RequestID: "apex-target-create"}); err != nil {
		t.Fatalf("target creates under the moved apex: %v", err)
	}

	// 原用户还有其他网站在用已验证 apex：拒绝，验证不动
	verify("shared.example")
	first := create("shared-1", "a.shared.example")
	create("shared-2", "b.shared.example")
	_, err = service.Transfer(t.Context(), platform, TransferRequest{ID: first.ID, ExpectedRevision: first.Revision,
		TargetUserID: to.userID, IdempotencyKey: "shared-transfer", RequestID: "shared-transfer"})
	var detail *domaintrust.DomainError
	if !errors.Is(err, ErrTransferApexInUse) || !errors.As(err, &detail) || detail.Apex != "shared.example" ||
		detail.Domain != "b.shared.example" {
		t.Fatalf("transfer with the apex still in use: %v", err)
	}
	if got := status(from.scopeID, "shared.example"); got != "verified" {
		t.Fatalf("refused transfer changed the ownership: %q", got)
	}
	var deleted *time.Time
	if err := pool.QueryRow(t.Context(), `SELECT deleted_at FROM sites WHERE id=$1`, first.ID).Scan(&deleted); err != nil || deleted != nil {
		t.Fatalf("refused transfer deleted the site: %v %v", deleted, err)
	}
}
