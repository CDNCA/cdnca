package site

import (
	"context"
	"crypto/ed25519"
	"crypto/sha256"
	"encoding/base64"
	"errors"
	"fmt"
	"os"
	"strconv"
	"strings"
	"sync"
	"testing"
	"time"

	"github.com/cdnca/cdnca/libs/entitlement"
	"github.com/cdnca/cdnca/services/control-api/internal/audit"
	"github.com/cdnca/cdnca/services/control-api/internal/database"
	"github.com/cdnca/cdnca/services/control-api/internal/entitlementguard"
	"github.com/cdnca/cdnca/services/control-api/internal/packageaddon"
	"github.com/cdnca/cdnca/services/control-api/internal/packageperiod"
	"github.com/cdnca/cdnca/services/control-api/internal/packagesubscription"
	"github.com/google/uuid"
	"github.com/jackc/pgx/v5"
	"github.com/jackc/pgx/v5/pgxpool"
)

type addonSiteTenantFixture struct{ scopeID, userID, sessionID uuid.UUID }

func TestAddonSiteAdmissionPostgres(t *testing.T) {
	dsn := os.Getenv("TEST_DATABASE_URL")
	if dsn == "" {
		t.Skip("TEST_DATABASE_URL required")
	}
	admin, err := pgxpool.New(t.Context(), dsn)
	if err != nil {
		t.Fatal(err)
	}
	defer admin.Close()
	schema := "addon_site_" + strings.ReplaceAll(uuid.NewString(), "-", "")
	if _, err = admin.Exec(t.Context(), "CREATE SCHEMA "+pgx.Identifier{schema}.Sanitize()); err != nil {
		t.Fatal(err)
	}
	defer admin.Exec(context.Background(), "DROP SCHEMA "+pgx.Identifier{schema}.Sanitize()+" CASCADE")
	cfg, err := pgxpool.ParseConfig(dsn)
	if err != nil {
		t.Fatal(err)
	}
	cfg.ConnConfig.RuntimeParams["search_path"] = schema
	pool, err := pgxpool.NewWithConfig(t.Context(), cfg)
	if err != nil {
		t.Fatal(err)
	}
	defer pool.Close()
	if err = database.Migrate(t.Context(), pool, "up"); err != nil {
		t.Fatal(err)
	}
	now := time.Now().UTC().Truncate(time.Second)
	manager := addonSiteInsertPlatformActor(t, pool, "addon-site-admin")
	addonSiteAssignSubscriptionRole(t, pool, manager.ScopeID, manager.UserID, "addon-site-manager", "billing.adjustments.manage", "packages.manage", "sites.manage")
	tenant := addonSiteInsertSubscriptionTenant(t, pool, "Addon site tenant", "addon-site-user")
	addonSiteAssignSubscriptionRole(t, pool, tenant.scopeID, tenant.userID, "addon-site-owner", "sites.manage", "dns.manage")
	product := addonSiteInsertPackageProductVersion(t, pool, manager, 1, 10, 1000)
	subscriptions := packagesubscription.NewService(packagesubscription.NewStoreWithClock(pool, func() time.Time { return now }))
	factor, _ := packageperiod.NewTrafficFactor(1, 1)
	month := packageperiod.DurationMonth
	opened, err := subscriptions.Open(t.Context(), manager, packagesubscription.OpenRequest{TenantScopeID: tenant.scopeID, OwnerUserID: tenant.userID, ProductID: product, ProductRevision: 1, SiteLimit: 10, NodeLimit: 1, Terms: packageperiod.Terms{Duration: &month}, TimeZone: "Asia/Shanghai", CyclePolicy: packageperiod.CyclePolicy{Kind: packageperiod.CycleMonthly}, TrafficFactor: factor, IdempotencyKey: "site-sub", RequestID: "site-sub"})
	if err != nil {
		t.Fatal(err)
	}
	store := NewStoreWithClock(pool, func() time.Time { return now }, nil)
	store.guard = installAddonSiteEntitlement(t, pool, now, time.Hour)
	service := NewService(store)
	actor := Actor{UserID: tenant.userID, ScopeID: tenant.scopeID, ScopeKind: "tenant"}
	subscriptionID := opened.Subscription.ID
	fields := func(domain string, ports ...string) SiteFields {
		return SiteFields{Domains: []string{domain}, HTTPPorts: ports, Origins: []string{"192.0.2.1"}, Enabled: false, Status: StatusDisabled, PackageSubscriptionID: &subscriptionID}
	}
	create := func(key string, f SiteFields) (WriteResult, error) {
		return service.Create(t.Context(), actor, CreateRequest{TargetScopeID: tenant.scopeID, OwnerUserID: tenant.userID, Fields: f, IdempotencyKey: key, RequestID: key})
	}
	first, err := create("first", fields("a.example.co.uk", "80", "8080"))
	if err != nil {
		t.Fatal(err)
	}
	if _, err = create("port-denied", fields("b.example.co.uk", "8081")); !errors.Is(err, packageaddon.ErrQuotaExceeded) {
		t.Fatalf("disabled port quota=%v", err)
	}
	if _, err = create("root-denied", fields("a.other.co.uk", "80")); !errors.Is(err, packageaddon.ErrQuotaExceeded) {
		t.Fatalf("root quota=%v", err)
	}
	sameRoot := fields("b.example.co.uk", "80")
	sameRoot.Domains = append(sameRoot.Domains, "c.example.co.uk")
	if _, err = create("same-root", sameRoot); err != nil {
		t.Fatal(err)
	}
	update := fields("a.example.co.uk", "80", "8080", "8081")
	update.PackageSubscriptionID = nil
	if _, err = service.Update(t.Context(), actor, UpdateRequest{ID: first.Site.ID, ExpectedRevision: first.Site.Revision, Fields: update, IdempotencyKey: "omit-binding", RequestID: "omit-binding"}); !errors.Is(err, packageaddon.ErrQuotaExceeded) {
		t.Fatalf("omitting binding bypassed quota=%v", err)
	}
	addons := packageaddon.Store{Pool: pool, Now: func() time.Time { return now }}
	adminActor := packageaddon.Actor{UserID: manager.UserID, ScopeID: manager.ScopeID, SessionID: manager.SessionID}
	add := func(kind string) {
		t.Helper()
		key := "addon-" + kind
		p, err := addons.Write(t.Context(), adminActor, packageaddon.Command{Action: "product.create", Product: &packageaddon.ProductFields{Name: key, Kind: kind, Quantity: 1, MonthlyPriceMinor: 10, Enabled: true}}, key, key)
		if err != nil {
			t.Fatal(err)
		}
		_, err = addons.Write(t.Context(), adminActor, packageaddon.Command{Action: "assignment.create", AddonID: p.ID, OwnerUserID: tenant.userID, SubscriptionID: subscriptionID, Amount: 1}, key+"-assign", key+"-assign")
		if err != nil {
			t.Fatal(err)
		}
	}
	add("root_domains")
	add("http_ports")
	var wg sync.WaitGroup
	results := make(chan error, 2)
	for i := 0; i < 2; i++ {
		wg.Add(1)
		go func(i int) {
			defer wg.Done()
			_, err := create(fmt.Sprintf("race-%d", i), fields(fmt.Sprintf("site%d.new.co.uk", i), "8081"))
			results <- err
		}(i)
	}
	wg.Wait()
	close(results)
	success, denied := 0, 0
	for err := range results {
		if err == nil {
			success++
		} else if errors.Is(err, packageaddon.ErrQuotaExceeded) {
			denied++
		} else {
			t.Fatal(err)
		}
	}
	if success != 1 || denied != 1 {
		t.Fatalf("concurrent last slot: success=%d denied=%d", success, denied)
	}
	// Reduce a pre-existing over-quota configuration and keep its subscription.
	if _, err = pool.Exec(t.Context(), `UPDATE sites SET http_ports=ARRAY['80','8080','8082'] WHERE id=$1`, first.Site.ID); err != nil {
		t.Fatal(err)
	}
	update = fields("a.example.co.uk", "80", "8080")
	update.PackageSubscriptionID = nil
	err = pgx.BeginFunc(t.Context(), pool, func(tx pgx.Tx) error {
		ownerID, e := preservePackageBinding(t.Context(), tx, tenant.scopeID, first.Site.ID, &update)
		if e != nil {
			return e
		}
		if e = checkPackageSiteChange(t.Context(), tx, tenant.scopeID, ownerID, first.Site.ID, update, now); e != nil {
			return e
		}
		_, e = tx.Exec(t.Context(), `UPDATE sites SET http_ports=ARRAY['80','8080'] WHERE id=$1`, first.Site.ID)
		return e
	})
	if err != nil {
		t.Fatal(err)
	}
	if update.PackageSubscriptionID == nil || *update.PackageSubscriptionID != subscriptionID {
		t.Fatal("ordinary update cleared binding")
	}
	var usage packageaddon.SiteUsageCounts
	err = pgx.BeginFunc(t.Context(), pool, func(tx pgx.Tx) error {
		var e error
		usage, e = packageaddon.SiteUsage(t.Context(), tx, tenant.scopeID, subscriptionID)
		return e
	})
	if err != nil || usage.RootDomains != 2 || usage.HTTPPorts != 2 || usage.Domains != 4 {
		t.Fatalf("usage=%+v err=%v", usage, err)
	}

	// PJ-C01: single and batch writes share the package admission. Enabling
	// needs an active subscription; disabling without expansion does not.
	revision := func() int64 {
		t.Helper()
		var r int64
		if err := pool.QueryRow(t.Context(), `SELECT revision FROM sites WHERE id=$1`, first.Site.ID).Scan(&r); err != nil {
			t.Fatal(err)
		}
		return r
	}
	batch := func(svc *Service, key, action string) BatchActionItemResult {
		t.Helper()
		result, err := svc.BatchAction(t.Context(), actor, BatchActionRequest{Action: action,
			Items: []BatchActionItem{{ID: first.Site.ID, ExpectedRevision: revision()}}, IdempotencyKey: key, RequestID: key})
		if err != nil {
			t.Fatal(err)
		}
		return result.Items[0]
	}
	if item := batch(service, "batch-enable-active", BatchActionEnable); item.Status != "updated" {
		t.Fatalf("batch enable on active subscription=%+v", item)
	}
	expiredStore := NewStoreWithClock(pool, func() time.Time { return now.AddDate(0, 2, 0) }, nil)
	expiredStore.guard = store.guard
	expired := NewService(expiredStore)
	disable := fields("a.example.co.uk", "80", "8080")
	disable.PackageSubscriptionID = nil
	if _, err = expired.Update(t.Context(), actor, UpdateRequest{ID: first.Site.ID, ExpectedRevision: revision(), Fields: disable, IdempotencyKey: "expired-disable", RequestID: "expired-disable"}); err != nil {
		t.Fatalf("disable on expired subscription=%v", err)
	}
	grow := fields("a.example.co.uk", "80", "8080", "8081")
	grow.PackageSubscriptionID = nil
	if _, err = expired.Update(t.Context(), actor, UpdateRequest{ID: first.Site.ID, ExpectedRevision: revision(), Fields: grow, IdempotencyKey: "expired-grow", RequestID: "expired-grow"}); !errors.Is(err, packageaddon.ErrSubscriptionInactive) {
		t.Fatalf("disabled expansion on expired subscription=%v", err)
	}
	enable := fields("a.example.co.uk", "80", "8080")
	enable.PackageSubscriptionID, enable.Enabled, enable.Status = nil, true, StatusActive
	if _, err = expired.Update(t.Context(), actor, UpdateRequest{ID: first.Site.ID, ExpectedRevision: revision(), Fields: enable, IdempotencyKey: "expired-enable", RequestID: "expired-enable"}); !errors.Is(err, packageaddon.ErrSubscriptionInactive) {
		t.Fatalf("single enable on expired subscription=%v", err)
	}
	item := batch(expired, "batch-enable-expired", BatchActionEnable)
	if item.Status != "failed" || item.Error == nil || item.Error.Code != "package_subscription_inactive" {
		t.Fatalf("batch enable on expired subscription=%+v", item)
	}
	var enabled bool
	if err := pool.QueryRow(t.Context(), `SELECT enabled FROM sites WHERE id=$1`, first.Site.ID).Scan(&enabled); err != nil || enabled {
		t.Fatalf("expired batch enable wrote enabled=%v err=%v", enabled, err)
	}
	if item := batch(expired, "batch-disable-expired", BatchActionDisable); item.Status != "updated" {
		t.Fatalf("batch disable on expired subscription=%+v", item)
	}
}
func addonSiteInsertPlatformActor(t *testing.T, pool *pgxpool.Pool, username string) packagesubscription.Actor {
	t.Helper()
	scopeID, userID := uuid.New(), uuid.New()
	if _, err := pool.Exec(context.Background(), `INSERT INTO access_scopes (id, kind) VALUES ($1, 'platform')`, scopeID); err != nil {
		t.Fatal(err)
	}
	addonSiteInsertSubscriptionUser(t, pool, scopeID, userID, username)
	addonSiteAssignSubscriptionRole(t, pool, scopeID, userID, "platform_owner",
		"package_subscriptions.read", "package_subscriptions.manage")
	return packagesubscription.Actor{UserID: userID, ScopeID: scopeID, SessionID: addonSiteInsertSubscriptionSession(t, pool, scopeID, userID), ScopeKind: packagesubscription.ScopePlatform}
}

func addonSiteInsertSubscriptionTenant(t *testing.T, pool *pgxpool.Pool, name, username string) addonSiteTenantFixture {
	t.Helper()
	tenantID, scopeID, userID := uuid.New(), uuid.New(), uuid.New()
	if _, err := pool.Exec(context.Background(), `INSERT INTO tenants (id, display_name) VALUES ($1,$2)`, tenantID, name); err != nil {
		t.Fatal(err)
	}
	if _, err := pool.Exec(context.Background(), `INSERT INTO access_scopes (id, kind, tenant_id) VALUES ($1,'tenant',$2)`, scopeID, tenantID); err != nil {
		t.Fatal(err)
	}
	addonSiteInsertSubscriptionUser(t, pool, scopeID, userID, username)
	addonSiteAssignSubscriptionRole(t, pool, scopeID, userID, "tenant_viewer", "package_subscriptions.read")
	return addonSiteTenantFixture{scopeID: scopeID, userID: userID, sessionID: addonSiteInsertSubscriptionSession(t, pool, scopeID, userID)}
}

func addonSiteInsertSubscriptionUser(t *testing.T, pool *pgxpool.Pool, scopeID, userID uuid.UUID, username string) {
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

func addonSiteAssignSubscriptionRole(t *testing.T, pool *pgxpool.Pool, scopeID, userID uuid.UUID,
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

func addonSiteInsertSubscriptionSession(t *testing.T, pool *pgxpool.Pool, scopeID, userID uuid.UUID) uuid.UUID {
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

func addonSiteInsertPackageProductVersion(t *testing.T, pool *pgxpool.Pool, actor packagesubscription.Actor,
	revision, domains, traffic int64,
) uuid.UUID {
	t.Helper()
	return addonSiteInsertPackageProductVersionCNAME(t, pool, actor, revision, domains, traffic, "cdn.example.com", "")
}

// addonSiteInsertPackageProductVersionCNAME is addonSiteInsertPackageProductVersion
// with the product's per-site CNAME domain and hostname.
func addonSiteInsertPackageProductVersionCNAME(t *testing.T, pool *pgxpool.Pool, actor packagesubscription.Actor,
	revision, domains, traffic int64, cnameDomain, cnameHostname string,
) uuid.UUID {
	t.Helper()
	return addonSiteInsertPackageProductVersionCNAMEMode(t, pool, actor, revision, domains, traffic, "per_site", cnameDomain, cnameHostname)
}

// addonSiteInsertPackageProductVersionCNAMEMode also takes the CNAME mode
// (per_site or shared).
func addonSiteInsertPackageProductVersionCNAMEMode(t *testing.T, pool *pgxpool.Pool, actor packagesubscription.Actor,
	revision, domains, traffic int64, cnameMode, cnameDomain, cnameHostname string,
) uuid.UUID {
	t.Helper()
	productID := uuid.New()
	now := time.Date(2026, time.July, 22, 0, 0, 0, 0, time.UTC)
	name := "Business"
	if cnameDomain != "cdn.example.com" {
		name = "Business " + cnameDomain
	}
	if cnameMode != "per_site" {
		name += " " + cnameMode
	}
	spec := []byte(`{"name":"` + name + `","limits":{"domains":` + strconv.FormatInt(domains, 10) +
		`,"root_domains":1,"http_ports":1,"monthly_traffic_bytes":` + strconv.FormatInt(traffic, 10) +
		`},"cname":{"mode":"` + cnameMode + `","domain":"` + cnameDomain + `","hostname":"` + cnameHostname +
		`"},"prices":{"currency":"CNY","monthly_minor":1000,"quarterly_minor":2800,"yearly_minor":10000}}`)
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
			) VALUES ($1,$6,true,100,$2,$3,$4,$4,$5,$5)`, productID, spec, revision, actor.UserID, now, name); err != nil {
			return err
		}
		if _, err := tx.Exec(t.Context(), `
			INSERT INTO package_product_versions (
				product_id,revision,name,enabled,sort_order,spec,deleted,created_by_user_id,created_at
			) VALUES ($1,$2,$6,true,100,$3,false,$4,$5)`, productID, revision, spec, actor.UserID, now, name); err != nil {
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

type addonSiteEntitlementSigner struct {
	id      string
	private ed25519.PrivateKey
}

func (s addonSiteEntitlementSigner) KeyID() string { return s.id }
func (s addonSiteEntitlementSigner) Sign(_ context.Context, payload []byte) ([]byte, error) {
	return ed25519.Sign(s.private, payload), nil
}

func installAddonSiteEntitlement(t *testing.T, pool *pgxpool.Pool, now time.Time, leaseWindow time.Duration) *entitlementguard.Guard {
	t.Helper()
	public, private, err := ed25519.GenerateKey(nil)
	if err != nil {
		t.Fatal(err)
	}
	until := now.Add(24 * time.Hour)
	signer := addonSiteEntitlementSigner{id: "plugin-control-test-key", private: private}
	trust, err := entitlementguard.NewTrustStore([]entitlementguard.VerificationKey{{KeyID: signer.id, PublicKey: public, NotBefore: now.Add(-24 * time.Hour), SignUntil: &until, VerifyUntil: &until}})
	if err != nil {
		t.Fatal(err)
	}
	keyFingerprint := sha256.Sum256(public)
	keysetPayload := []byte(fmt.Sprintf(
		`{"schema":"cdnca.signing-keyset/v2","active_key_id":%q,"keys":[`+
			`{"key_id":%q,"algorithm":"Ed25519","public_key":%q,"fingerprint":%q,`+
			`"status":"active","not_before":%q,"sign_until":%q,"verify_until":%q}],"rotations":[]}`,
		signer.id, signer.id, base64.RawURLEncoding.EncodeToString(public),
		base64.RawURLEncoding.EncodeToString(keyFingerprint[:]), now.Add(-24*time.Hour).Format(time.RFC3339Nano),
		until.Format(time.RFC3339Nano), until.Format(time.RFC3339Nano)))
	keysetDigest := sha256.Sum256(keysetPayload)
	if _, err = pool.Exec(t.Context(), `INSERT INTO entitlement_signing_keyset_lkg(
		singleton,schema_version,etag,active_key_id,chain_depth,payload,payload_sha256,accepted_at,updated_at
	) VALUES(true,'cdnca.signing-keyset/v2',$1,$2,1,$3,$4,$5,$5)`,
		`"`+base64.RawURLEncoding.EncodeToString(keysetDigest[:])+`"`, signer.id,
		keysetPayload, keysetDigest[:], now); err != nil {
		t.Fatal(err)
	}
	if _, err = pool.Exec(t.Context(), `INSERT INTO entitlement_signing_keyset_current_keys(
		key_id,public_key,status,not_before,sign_until,verify_until,keyset_payload_sha256,accepted_at
	) VALUES($1,$2,'active',$3,$4,$4,$5,$6)`, signer.id, public, now.Add(-24*time.Hour),
		until, keysetDigest[:], now); err != nil {
		t.Fatal(err)
	}
	const customer = "11111111-1111-4111-8111-111111111111"
	const installation = "22222222-2222-4222-8222-222222222222"
	const license = "33333333-3333-4333-8333-333333333333"
	issuedAt := now.Add(-time.Minute)
	revocation, err := entitlement.SignRevocationSet(t.Context(), entitlement.RevocationSet{Schema: entitlement.RevocationSetSchemaV2, Audience: entitlement.RevocationSetAudience, CustomerID: customer, InstallationID: installation, LicenseID: license, Revision: 1, IssuedAt: issuedAt.Unix(), ExpiresAt: issuedAt.Add(entitlement.RevocationSetWindow).Unix(), RevokedSerials: []uint64{}}, signer, entitlement.RevocationKeyWindow{NotBefore: now.Add(-time.Hour), SignUntil: &until, VerifyUntil: &until})
	if err != nil {
		t.Fatal(err)
	}
	artifact, err := revocation.Encode()
	if err != nil {
		t.Fatal(err)
	}
	if _, err = entitlementguard.NewRevocationService(pool, trust).Accept(t.Context(), artifact, now); err != nil {
		t.Fatal(err)
	}
	lease := entitlement.Lease{Schema: entitlement.SchemaV1, Audience: entitlement.ControlAudience, CustomerID: customer, InstallationID: installation, LicenseID: license, Serial: 1, NotBefore: now.Add(-time.Hour).Unix(), ExpiresAt: now.Add(leaseWindow).Unix(), GraceUntil: now.Add(leaseWindow + time.Hour).Unix(), Version: entitlement.VersionRange{Channel: "stable", Min: "0.1.0", Max: "1.0.0"}, Features: []entitlement.Feature{{Code: entitlementguard.FeatureSitesManage}}, Quotas: []entitlement.Quota{{Code: entitlementguard.QuotaDomainsCount, Limit: 100}}}
	signed, err := entitlement.Sign(t.Context(), lease, signer)
	if err != nil {
		t.Fatal(err)
	}
	if _, err = entitlementguard.NewService(pool, trust).Install(t.Context(), entitlementguard.InstallBundle{InstallationID: installation, SignedLease: signed}, now); err != nil {
		t.Fatal(err)
	}
	return entitlementguard.NewGuard(pool, func() time.Time { return now }, trust)
}
