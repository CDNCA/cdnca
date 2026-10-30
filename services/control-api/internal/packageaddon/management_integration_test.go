package packageaddon_test

import (
	"bytes"
	"context"
	"crypto/sha256"
	"encoding/json"
	"errors"
	"fmt"
	"io/fs"
	"net/http"
	"net/http/httptest"
	"os"
	"strconv"
	"strings"
	"sync"
	"testing"
	"time"

	"github.com/cdnca/cdnca/services/control-api/internal/audit"
	"github.com/cdnca/cdnca/services/control-api/internal/database"
	"github.com/cdnca/cdnca/services/control-api/internal/database/databasetest"
	"github.com/cdnca/cdnca/services/control-api/internal/httpapi"
	"github.com/cdnca/cdnca/services/control-api/internal/identity"
	"github.com/cdnca/cdnca/services/control-api/internal/packageaddon"
	"github.com/cdnca/cdnca/services/control-api/internal/packageperiod"
	"github.com/cdnca/cdnca/services/control-api/internal/packagesubscription"
	controlmigrations "github.com/cdnca/cdnca/services/control-api/migrations"
	"github.com/google/uuid"
	"github.com/jackc/pgx/v5"
	"github.com/jackc/pgx/v5/pgxpool"
)

type tenantFixture struct{ scopeID, userID, sessionID uuid.UUID }

func TestAddonAdminAllocationAtomicNoDebitAndEffectiveQuota(t *testing.T) {
	dsn := os.Getenv("TEST_DATABASE_URL")
	if dsn == "" {
		t.Skip("TEST_DATABASE_URL required")
	}
	if !strings.Contains(dsn, "package_admin_test") {
		t.Fatal("requires task-owned package_admin_test database")
	}
	admin, err := pgxpool.New(t.Context(), dsn)
	if err != nil {
		t.Fatal(err)
	}
	defer admin.Close()
	schema := "package_addon_test_" + strings.ReplaceAll(uuid.NewString(), "-", "")
	if _, err = admin.Exec(t.Context(), "CREATE SCHEMA "+pgx.Identifier{schema}.Sanitize()); err != nil {
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
	if err = database.Migrate(t.Context(), pool, "up"); err != nil {
		t.Fatal(err)
	}
	now := time.Date(2026, 9, 25, 0, 0, 0, 0, time.UTC)
	actor := insertPlatformActor(t, pool, "addon-platform")
	assignSubscriptionRole(t, pool, actor.ScopeID, actor.UserID, "addon-manager", "billing.adjustments.manage", "packages.manage", "sites.manage", "streams.manage")
	tenant := insertSubscriptionTenant(t, pool, "Addon Tenant", "addon-tenant")
	base := insertPackageProductVersion(t, pool, actor, 1, 10, 1000)
	service := packagesubscription.NewService(packagesubscription.NewStoreWithClock(pool, func() time.Time { return now }))
	factor, _ := packageperiod.NewTrafficFactor(1, 1)
	month := packageperiod.DurationMonth
	opened, err := service.Open(t.Context(), actor, packagesubscription.OpenRequest{TenantScopeID: tenant.scopeID, OwnerUserID: tenant.userID, ProductID: base, ProductRevision: 1, SiteLimit: 10, NodeLimit: 1, Terms: packageperiod.Terms{Duration: &month}, TimeZone: "Asia/Shanghai", CyclePolicy: packageperiod.CyclePolicy{Kind: packageperiod.CycleMonthly}, TrafficFactor: factor, IdempotencyKey: "addon-subscription", RequestID: "addon-subscription"})
	if err != nil {
		t.Fatal(err)
	}
	store := packageaddon.Store{Pool: pool, Now: func() time.Time { return now }}
	who := packageaddon.Actor{UserID: actor.UserID, ScopeID: actor.ScopeID, SessionID: actor.SessionID}
	fields := packageaddon.ProductFields{Name: "Domain extension", Kind: "domains", Quantity: 2, MonthlyPriceMinor: 123, ProductIDs: []uuid.UUID{base}, Enabled: true}
	created, err := store.Write(t.Context(), who, packageaddon.Command{Action: "product.create", Product: &fields}, "addon-product", "addon-product")
	if err != nil {
		t.Fatal(err)
	}

	if _, err = pool.Exec(t.Context(), `UPDATE users SET email='addon@example.test',phone='+8613812345678' WHERE id=$1`, tenant.userID); err != nil {
		t.Fatal(err)
	}
	options, err := store.Subscriptions(t.Context(), 1, 100, "addon@example.test", created.ID)
	if err != nil || options.Total != 1 {
		t.Fatalf("email filter=%#v %v", options, err)
	}
	options, err = store.Subscriptions(t.Context(), 1, 100, "13812345678", created.ID)
	if err != nil || options.Total != 1 {
		t.Fatalf("phone filter=%#v %v", options, err)
	}
	options, err = store.Subscriptions(t.Context(), 1, 100, tenant.userID.String(), created.ID)
	if err != nil || options.Total != 1 || options.Items[0].OwnerUserID != tenant.userID || options.Items[0].ID != opened.Subscription.ID {
		t.Fatalf("eligible=%#v %v", options, err)
	}
	products, err := store.Products(t.Context(), 1, 10)
	if err != nil || products.Total != 1 || products.Items[0].ID != created.ID {
		t.Fatalf("products=%#v %v", products, err)
	}
	command := packageaddon.Command{Action: "assignment.create", AddonID: created.ID, OwnerUserID: tenant.userID, SubscriptionID: opened.Subscription.ID, Amount: 3}
	assigned, err := store.Write(t.Context(), who, command, "addon-assign", "addon-assign")
	if err != nil {
		t.Fatal(err)
	}

	options, err = store.Subscriptions(t.Context(), 1, 100, tenant.userID.String(), created.ID)
	if err != nil || options.Total != 0 {
		t.Fatalf("assigned must not remain eligible: %#v %v", options, err)
	}
	assignments, err := store.Assignments(t.Context(), 1, 10, "addon@example.test", created.ID)
	if err != nil || assignments.Total != 1 {
		t.Fatalf("assignment email filter=%#v %v", assignments, err)
	}
	assignments, err = store.Assignments(t.Context(), 1, 10, tenant.userID.String(), created.ID)
	if err != nil || assignments.Total != 1 || assignments.Items[0].Snapshot.Quantity != 2 {
		t.Fatalf("assignments=%#v %v", assignments, err)
	}
	filtered, err := store.Assignments(t.Context(), 1, 10, "nonmatching", created.ID)
	if err != nil || filtered.Total != 0 {
		t.Fatalf("filter=%#v %v", filtered, err)
	}
	wrongOwner := command
	wrongOwner.OwnerUserID = actor.UserID
	if _, err = store.Write(t.Context(), who, wrongOwner, "wrong-owner", "wrong-owner"); !errors.Is(err, packageaddon.ErrInvalid) {
		t.Fatalf("owner=%v", err)
	}
	replay, err := store.Write(t.Context(), who, command, "addon-assign", "addon-replay")
	if err != nil || replay != assigned || assigned.ChargedMinor != 0 {
		t.Fatalf("replay %#v %v", replay, err)
	}
	bad := command
	bad.Amount = 4
	if _, err = store.Write(t.Context(), who, bad, "addon-assign", "addon-conflict"); !errors.Is(err, packageaddon.ErrConflict) {
		t.Fatalf("idempotency error=%v", err)
	}
	if _, err = store.Write(t.Context(), who, command, "addon-duplicate", "addon-duplicate"); !errors.Is(err, packageaddon.ErrDuplicate) {
		t.Fatalf("duplicate error=%v", err)
	}
	var orders, receipts, audits int
	if err = pool.QueryRow(t.Context(), `SELECT (SELECT count(*) FROM package_orders),(SELECT count(*) FROM package_addon_write_receipts),(SELECT count(*) FROM audit_events WHERE action LIKE 'package.addon.%')`).Scan(&orders, &receipts, &audits); err != nil {
		t.Fatal(err)
	}
	if orders != 0 || receipts != 2 || audits != 2 {
		t.Fatalf("orders/receipts/audits=%d/%d/%d", orders, receipts, audits)
	}
	got, err := service.Get(t.Context(), actor, tenant.scopeID, opened.Subscription.ID)
	if err != nil || got.Quotas.Domains != 16 {
		t.Fatalf("effective=%#v err=%v", got.Quotas, err)
	}
	var recurring int64
	if err = pgx.BeginFunc(t.Context(), pool, func(tx pgx.Tx) error {
		var e error
		recurring, e = packageaddon.RenewalAddition(t.Context(), tx, opened.Subscription.ID, "quarter")
		return e
	}); err != nil || recurring != 1107 {
		t.Fatalf("quarter addition=%d err=%v", recurring, err)
	}
	fields.Enabled = false
	if _, err = store.Write(t.Context(), who, packageaddon.Command{Action: "product.update", ID: created.ID, ExpectedRevision: 1, Product: &fields}, "addon-off", "addon-off"); err != nil {
		t.Fatal(err)
	}
	got, err = service.Get(t.Context(), actor, tenant.scopeID, opened.Subscription.ID)
	if err != nil || got.Quotas.Domains != 16 {
		t.Fatal("disabling catalog revoked existing rights", err)
	}
	// Both concurrent revisions target the same row; exactly one may commit.
	var wg sync.WaitGroup
	results := make(chan error, 2)
	for i := 0; i < 2; i++ {
		wg.Add(1)
		go func(i int) {
			defer wg.Done()
			_, e := store.Write(t.Context(), who, packageaddon.Command{Action: "assignment.update", ID: assigned.ID, ExpectedRevision: 1, Amount: 4}, fmt.Sprintf("addon-race-%d", i), fmt.Sprintf("addon-race-%d", i))
			results <- e
		}(i)
	}
	wg.Wait()
	close(results)
	success, conflict := 0, 0
	for e := range results {
		if e == nil {
			success++
		} else if errors.Is(e, packageaddon.ErrConflict) {
			conflict++
		} else {
			t.Fatal(e)
		}
	}
	if success != 1 || conflict != 1 {
		t.Fatalf("race=%d/%d", success, conflict)
	}
	if _, err = store.Write(t.Context(), who, packageaddon.Command{Action: "assignment.delete", ID: assigned.ID, ExpectedRevision: 2}, "addon-revoke", "addon-revoke"); err != nil {
		t.Fatal(err)
	}
	got, err = service.Get(t.Context(), actor, tenant.scopeID, opened.Subscription.ID)
	if err != nil || got.Quotas.Domains != 10 {
		t.Fatal("revoke did not restore base", err)
	}
	if _, err = pool.Exec(t.Context(), `UPDATE package_addon_write_receipts SET response='{}'`); err == nil {
		t.Fatal("receipt changed")
	}
	if _, err = pool.Exec(t.Context(), `UPDATE package_addon_products SET name='unaudited',revision=revision+1 WHERE id=$1`, created.ID); err == nil {
		t.Fatal("unaudited write committed")
	}
	waf := fields
	waf.Name = "WAF"
	waf.Kind = "waf"
	waf.Quantity = 1
	waf.Enabled = true
	w, err := store.Write(t.Context(), who, packageaddon.Command{Action: "product.create", Product: &waf}, "waf-create", "waf-create")
	if err != nil {
		t.Fatal(err)
	}
	command.AddonID = w.ID
	command.Amount = 1
	if _, err = store.Write(t.Context(), who, command, "waf-assign", "waf-assign"); err != nil {
		t.Fatal(err)
	}
	if _, err = store.Write(t.Context(), who, command, "waf-duplicate", "waf-duplicate"); !errors.Is(err, packageaddon.ErrDuplicate) {
		t.Fatalf("WAF duplicate=%v", err)
	}
	missing := who
	missing.SessionID = uuid.New()
	if _, err = store.Write(t.Context(), missing, command, "forbidden", "forbidden"); !errors.Is(err, packageaddon.ErrForbidden) {
		t.Fatalf("invalid session=%v", err)
	}

	// A deferred audit failure must roll back the product and receipt together.
	if _, err = pool.Exec(t.Context(), `CREATE FUNCTION reject_addon_test_audit() RETURNS trigger LANGUAGE plpgsql AS $$ BEGIN IF NEW.action='package.addon.product.create' THEN RAISE EXCEPTION 'injected audit failure'; END IF; RETURN NEW; END $$; CREATE TRIGGER reject_addon_test_audit BEFORE INSERT ON audit_events FOR EACH ROW EXECUTE FUNCTION reject_addon_test_audit()`); err != nil {
		t.Fatal(err)
	}
	failed := fields
	failed.Name = "must roll back"
	if _, err = store.Write(t.Context(), who, packageaddon.Command{Action: "product.create", Product: &failed}, "audit-failure", "audit-failure"); err == nil {
		t.Fatal("audit failure committed")
	}
	var rollbackRows int
	if err = pool.QueryRow(t.Context(), `SELECT (SELECT count(*) FROM package_addon_products WHERE name='must roll back')+(SELECT count(*) FROM package_addon_write_receipts WHERE idempotency_key='audit-failure')`).Scan(&rollbackRows); err != nil || rollbackRows != 0 {
		t.Fatalf("rollback rows=%d %v", rollbackRows, err)
	}
	if _, err = pool.Exec(t.Context(), `DROP TRIGGER reject_addon_test_audit ON audit_events; DROP FUNCTION reject_addon_test_audit()`); err != nil {
		t.Fatal(err)
	}
	tenantActor := packageaddon.Actor{UserID: tenant.userID, ScopeID: tenant.scopeID, SessionID: tenant.sessionID}
	if _, err = store.Write(t.Context(), tenantActor, packageaddon.Command{Action: "product.create", Product: &failed}, "tenant-denied", "tenant-denied"); !errors.Is(err, packageaddon.ErrForbidden) {
		t.Fatalf("tenant=%v", err)
	}
	// An invalid session cannot use an already completed receipt.
	if _, err = store.Write(t.Context(), missing, packageaddon.Command{Action: "product.create", Product: &fields}, "addon-product", "receipt-session"); !errors.Is(err, packageaddon.ErrForbidden) {
		t.Fatalf("replay auth=%v", err)
	}
	assertAddonDownRetainsFacts(t)

	tokens, err := identity.NewTokenManager(uuid.NewString()+uuid.NewString(), time.Hour)
	if err != nil {
		t.Fatal(err)
	}
	identityService, err := identity.NewService(identity.NewStore(pool), tokens, time.Hour)
	if err != nil {
		t.Fatal(err)
	}
	token, _, err := tokens.Mint(actor.UserID, actor.ScopeID, actor.SessionID)
	if err != nil {
		t.Fatal(err)
	}
	tenantToken, _, err := tokens.Mint(tenant.userID, tenant.scopeID, tenant.sessionID)
	if err != nil {
		t.Fatal(err)
	}
	handler := httpapi.New(pool, identityService, httpapi.Config{APIKeyPepper: []byte("addon-test-only-key-at-least-32-bytes"), Now: func() time.Time { return now }}).Handler()
	request := func(method, path, token string, body any) *httptest.ResponseRecorder {
		raw, _ := json.Marshal(body)
		r := httptest.NewRequest(method, path, bytes.NewReader(raw))
		r.Header.Set("Authorization", "Bearer "+token)
		r.Header.Set("Idempotency-Key", "http-create")
		r.Header.Set("X-Request-ID", "http-create")
		w := httptest.NewRecorder()
		handler.ServeHTTP(w, r)
		return w
	}
	for _, path := range []string{"/v1/admin/package-addons", "/v1/admin/package-addons/assignments", "/v1/admin/package-addons/subscriptions", "/v1/admin/package-addons/bindings"} {
		if w := request(http.MethodGet, path, token, nil); w.Code != 200 {
			t.Fatalf("HTTP %s status=%d %s", path, w.Code, w.Body.String())
		}
		if w := request(http.MethodGet, path, tenantToken, nil); w.Code != 403 {
			t.Fatalf("tenant HTTP %s status=%d", path, w.Code)
		}
	}
	if w := request(http.MethodGet, "/v1/admin/package-addons?limit=0", token, nil); w.Code != 400 || !strings.Contains(w.Body.String(), "package_addon_invalid") {
		t.Fatalf("bad HTTP=%d %s", w.Code, w.Body.String())
	}
	httpFields := fields
	httpFields.Name = "HTTP product"
	httpCommand := packageaddon.Command{Action: "product.create", Product: &httpFields}
	httpResponse := request(http.MethodPost, "/v1/admin/package-addons/commands", token, httpCommand)
	if httpResponse.Code != 200 {
		t.Fatalf("HTTP create=%d %s", httpResponse.Code, httpResponse.Body.String())
	}
	replayHTTP := request(http.MethodPost, "/v1/admin/package-addons/commands", token, httpCommand)
	if replayHTTP.Code != 200 || replayHTTP.Body.String() != httpResponse.Body.String() {
		t.Fatalf("HTTP replay=%d %s", replayHTTP.Code, replayHTTP.Body.String())
	}
	now = opened.Subscription.Period.EndsAt.Add(time.Second)
	command.AddonID = created.ID
	if _, err = store.Write(t.Context(), who, command, "expired", "expired"); !errors.Is(err, packageaddon.ErrInvalid) {
		t.Fatalf("expired=%v", err)
	}
}
// assertAddonDownRetainsFacts checks 263's own down guard. database.Migrate
// "down" rolls back only the current head, which is no longer 263, so the
// guard runs on a schema migrated through 263 with an (uncommitted) addon
// product: the down script must refuse instead of dropping the facts.
func assertAddonDownRetainsFacts(t *testing.T) {
	t.Helper()
	pool := databasetest.MigratedThroughPool(t, "package_addon_263", 263)
	matches, err := fs.Glob(controlmigrations.FS, "263_*.down.sql")
	if err != nil || len(matches) != 1 {
		t.Fatalf("resolve 263 down: %v %v", matches, err)
	}
	down, err := fs.ReadFile(controlmigrations.FS, matches[0])
	if err != nil {
		t.Fatal(err)
	}
	err = pgx.BeginFunc(t.Context(), pool, func(tx pgx.Tx) error {
		if _, err := tx.Exec(t.Context(), `INSERT INTO package_addon_products(id,name,kind,quantity,monthly_price_minor,created_at,updated_at)
			VALUES($1,'retained','domains',1,0,now(),now())`, uuid.New()); err != nil {
			t.Fatalf("seed addon product: %v", err)
		}
		_, err := tx.Exec(t.Context(), string(down))
		return err
	})
	if err == nil || !strings.Contains(err.Error(), "retain addon facts") {
		t.Fatalf("263 down with addon facts error = %v", err)
	}
}

func insertPlatformActor(t *testing.T, pool *pgxpool.Pool, username string) packagesubscription.Actor {
	t.Helper()
	scopeID, userID := uuid.New(), uuid.New()
	if _, err := pool.Exec(context.Background(), `INSERT INTO access_scopes (id, kind) VALUES ($1, 'platform')`, scopeID); err != nil {
		t.Fatal(err)
	}
	insertSubscriptionUser(t, pool, scopeID, userID, username)
	assignSubscriptionRole(t, pool, scopeID, userID, "platform_owner",
		"package_subscriptions.read", "package_subscriptions.manage")
	return packagesubscription.Actor{UserID: userID, ScopeID: scopeID, SessionID: insertSubscriptionSession(t, pool, scopeID, userID), ScopeKind: packagesubscription.ScopePlatform}
}

func insertSubscriptionTenant(t *testing.T, pool *pgxpool.Pool, name, username string) tenantFixture {
	t.Helper()
	tenantID, scopeID, userID := uuid.New(), uuid.New(), uuid.New()
	if _, err := pool.Exec(context.Background(), `INSERT INTO tenants (id, display_name) VALUES ($1,$2)`, tenantID, name); err != nil {
		t.Fatal(err)
	}
	if _, err := pool.Exec(context.Background(), `INSERT INTO access_scopes (id, kind, tenant_id) VALUES ($1,'tenant',$2)`, scopeID, tenantID); err != nil {
		t.Fatal(err)
	}
	insertSubscriptionUser(t, pool, scopeID, userID, username)
	assignSubscriptionRole(t, pool, scopeID, userID, "tenant_viewer", "package_subscriptions.read")
	return tenantFixture{scopeID: scopeID, userID: userID, sessionID: insertSubscriptionSession(t, pool, scopeID, userID)}
}

func insertSubscriptionUser(t *testing.T, pool *pgxpool.Pool, scopeID, userID uuid.UUID, username string) {
	t.Helper()
	if _, err := pool.Exec(context.Background(), `
		INSERT INTO users (id, username, display_name, password_hash) VALUES ($1,$2,$3,'test-password-hash')`,
		userID, username, username); err != nil {
		t.Fatal(err)
	}
	if _, err := pool.Exec(context.Background(), `INSERT INTO memberships (scope_id, user_id) VALUES ($1,$2)`, scopeID, userID); err != nil {
		t.Fatal(err)
	}
}

func assignSubscriptionRole(t *testing.T, pool *pgxpool.Pool, scopeID, userID uuid.UUID,
	roleName string, permissions ...string,
) {
	t.Helper()
	roleID := uuid.New()
	if _, err := pool.Exec(t.Context(), `
		INSERT INTO roles (id,scope_id,name,description,system_role)
		VALUES ($1,$2,$3,'Package subscription test role',true)`, roleID, scopeID, roleName); err != nil {
		t.Fatal(err)
	}
	for _, permission := range permissions {
		if roleName == "tenant_viewer" && permission == "package_subscriptions.read" {
			continue
		}
		if _, err := pool.Exec(t.Context(), `
			INSERT INTO role_permissions (role_id,permission_name) VALUES ($1,$2)
			ON CONFLICT DO NOTHING`, roleID, permission); err != nil {
			t.Fatal(err)
		}
	}
	if _, err := pool.Exec(t.Context(), `
		INSERT INTO role_assignments (scope_id,user_id,role_id) VALUES ($1,$2,$3)`, scopeID, userID, roleID); err != nil {
		t.Fatal(err)
	}
}

func insertSubscriptionSession(t *testing.T, pool *pgxpool.Pool, scopeID, userID uuid.UUID) uuid.UUID {
	t.Helper()
	sessionID := uuid.New()
	digest := sha256.Sum256(sessionID[:])
	if _, err := pool.Exec(t.Context(), `
		INSERT INTO auth_sessions (
			id,family_id,user_id,scope_id,refresh_token_hash,created_at,expires_at
		) VALUES ($1,$2,$3,$4,$5,$6,$7)`, sessionID, uuid.New(), userID, scopeID, digest[:],
		time.Date(2020, time.January, 1, 0, 0, 0, 0, time.UTC),
		time.Date(2035, time.January, 1, 0, 0, 0, 0, time.UTC)); err != nil {
		t.Fatal(err)
	}
	return sessionID
}

func insertPackageProductVersion(t *testing.T, pool *pgxpool.Pool, actor packagesubscription.Actor,
	revision, domains, traffic int64,
) uuid.UUID {
	t.Helper()
	productID := uuid.New()
	now := time.Date(2026, time.July, 22, 0, 0, 0, 0, time.UTC)
	spec := []byte(`{"name":"Business","limits":{"domains":` + strconv.FormatInt(domains, 10) +
		`,"monthly_traffic_bytes":` + strconv.FormatInt(traffic, 10) +
		`},"prices":{"currency":"CNY","monthly_minor":1000,"quarterly_minor":2800,"yearly_minor":10000}}`)
	err := pgx.BeginFunc(t.Context(), pool, func(tx pgx.Tx) error {
		if _, err := tx.Exec(t.Context(), `SELECT iam_global_lock_shared_v1()`); err != nil {
			return err
		}
		if _, err := tx.Exec(t.Context(), `SELECT iam_scope_locks_v1(ARRAY[$1::uuid])`, actor.ScopeID); err != nil {
			return err
		}
		if _, err := tx.Exec(t.Context(), `
			INSERT INTO package_products (
				id,name,enabled,sort_order,spec,revision,created_by_user_id,updated_by_user_id,created_at,updated_at
			) VALUES ($1,'Business',true,100,$2,$3,$4,$4,$5,$5)`, productID, spec, revision, actor.UserID, now); err != nil {
			return err
		}
		if _, err := tx.Exec(t.Context(), `
			INSERT INTO package_product_versions (
				product_id,revision,name,enabled,sort_order,spec,deleted,created_by_user_id,created_at
			) VALUES ($1,$2,'Business',true,100,$3,false,$4,$5)`, productID, revision, spec, actor.UserID, now); err != nil {
			return err
		}
		return audit.NewWithClock(pool, func() time.Time { return now }).Append(t.Context(), tx, audit.Event{
			ScopeID: actor.ScopeID, ActorUserID: &actor.UserID,
			Action: "package.product.create", ResourceType: "package_product", ResourceID: productID.String(),
			RequestID: "package-subscription-product-create-" + productID.String(), Result: "success",
			Payload: map[string]any{"revision": revision, "enabled": true},
		})
	})
	if err != nil {
		t.Fatal(err)
	}
	return productID
}
