package l4forward

import (
	"context"
	"crypto/sha256"
	"errors"
	"fmt"
	"os"
	"strings"
	"sync"
	"testing"
	"time"

	"github.com/cdnca/cdnca/services/control-api/internal/audit"
	"github.com/cdnca/cdnca/services/control-api/internal/database"
	"github.com/cdnca/cdnca/services/control-api/internal/packageaddon"
	"github.com/cdnca/cdnca/services/control-api/internal/packageperiod"
	"github.com/cdnca/cdnca/services/control-api/internal/packagesubscription"
	"github.com/google/uuid"
	"github.com/jackc/pgx/v5"
	"github.com/jackc/pgx/v5/pgxpool"
)

func TestStreamAddonRuntimeQuota(t *testing.T) {
	fixture := newStreamAddonFixture(t)
	pool, service, actor := fixture.pool, NewService(NewStore(fixture.pool)), fixture.actor
	create := func(subscription uuid.UUID, port uint16, extras []AdditionalListener) CreateRequest {
		key := uuid.NewString()
		return CreateRequest{Fields: Fields{PackageSubscriptionID: new(subscription),
			Name: key, Protocol: ProtocolTCP, ListenAddress: "*", ListenPort: port,
			AdditionalListeners: &extras, UpstreamAddress: "192.0.2.10", UpstreamPort: 8080,
			ConnectTimeoutMS: 1000, ResponseTimeoutMS: 30000, MaxConnectionsPerClient: 100, Enabled: true},
			IdempotencyKey: key, RequestID: key}
	}
	update := func(item Forward, fields Fields) UpdateRequest {
		key := uuid.NewString()
		return UpdateRequest{ID: item.ID, ExpectedRevision: item.Revision, Fields: fields, IdempotencyKey: key, RequestID: key}
	}
	t.Run("frozen addon includes primary and UDP extras", func(t *testing.T) {
		subscription := fixture.subscription(t, actor.UserID, 0)
		request := create(subscription, 27101, []AdditionalListener{{ID: uuid.New(), Protocol: ProtocolUDP, Address: "*", Port: 27101}})
		if _, err := service.Create(t.Context(), actor, request); !errors.Is(err, packageaddon.ErrQuotaExceeded) {
			t.Fatalf("zero base admission: %v", err)
		}
		addon, _ := fixture.assign(t, subscription, 2, 1)
		created, err := service.Create(t.Context(), actor, request)
		if err != nil {
			t.Fatal(err)
		}
		if len(created.Forward.PublishIntent.RuntimeSpec.AdditionalListeners) != 1 {
			t.Fatal("admitted listener did not retain its runtime spec")
		}
		var queued int
		if err := pool.QueryRow(t.Context(), `SELECT count(*) FROM edge_automatic_publication_requests
			WHERE publish_intent_id=$1 AND source_resource_id=$2`, created.Forward.PublishIntent.ID, created.Forward.ID).Scan(&queued); err != nil || queued != 1 {
			t.Fatalf("automatic publication request count=%d error=%v", queued, err)
		}
		replayed, err := service.Create(t.Context(), actor, request)
		if err != nil || !replayed.Replayed || replayed.Forward.ID != created.Forward.ID {
			t.Fatalf("replay=%#v error=%v", replayed, err)
		}
		fields := packageaddon.ProductFields{Name: "changed " + addon.String(), Kind: "stream_ports", Quantity: 100, MonthlyPriceMinor: 100, Enabled: false}
		if _, err = fixture.addons.Write(t.Context(), fixture.admin, packageaddon.Command{Action: "product.update", ID: addon, ExpectedRevision: 1, Product: &fields}, uuid.NewString(), uuid.NewString()); err != nil {
			t.Fatal(err)
		}
		if _, err = service.Create(t.Context(), actor, create(subscription, 27102, nil)); !errors.Is(err, packageaddon.ErrQuotaExceeded) {
			t.Fatalf("catalog edit changed allocated frozen quota: %v", err)
		}
		disabled := request.Fields
		disabled.Enabled = false
		changed, err := service.Update(t.Context(), actor, update(created.Forward, disabled))
		if err != nil {
			t.Fatal(err)
		}
		if _, err = service.Create(t.Context(), actor, create(subscription, 27103, nil)); !errors.Is(err, packageaddon.ErrQuotaExceeded) {
			t.Fatalf("disabled listeners escaped quota: %v", err)
		}
		// Omitting extras retains and charges them when changing another field.
		enabled := request.Fields
		enabled.AdditionalListeners = nil
		changed, err = service.Update(t.Context(), actor, update(changed.Forward, enabled))
		if err != nil || len(changed.Forward.AdditionalListeners) != 1 {
			t.Fatalf("retained extras=%#v error=%v", changed, err)
		}
		more := append(append([]AdditionalListener{}, created.Forward.AdditionalListeners...), AdditionalListener{ID: uuid.New(), Protocol: ProtocolTCP, Address: "*", Port: 27104})
		enabled.AdditionalListeners = &more
		if _, err = service.Update(t.Context(), actor, update(changed.Forward, enabled)); !errors.Is(err, packageaddon.ErrQuotaExceeded) {
			t.Fatalf("extra expansion=%v", err)
		}
		// Reducing listeners releases only the removed socket.
		empty := []AdditionalListener{}
		enabled.AdditionalListeners = &empty
		changed, err = service.Update(t.Context(), actor, update(changed.Forward, enabled))
		if err != nil {
			t.Fatal(err)
		}
		if _, err = service.Create(t.Context(), actor, create(subscription, 27105, nil)); err != nil {
			t.Fatalf("retired extra did not release quota: %v", err)
		}
		key := uuid.NewString()
		if _, err = service.Delete(t.Context(), actor, DeleteRequest{ID: changed.Forward.ID, ExpectedRevision: changed.Forward.Revision, IdempotencyKey: key, RequestID: key}); err != nil {
			t.Fatal(err)
		}
		if _, err = service.Create(t.Context(), actor, create(subscription, 27106, nil)); err != nil {
			t.Fatalf("deleted forward did not release quota: %v", err)
		}
	})
	t.Run("last socket has one concurrent winner", func(t *testing.T) {
		subscription := fixture.subscription(t, actor.UserID, 1)
		start := make(chan struct{})
		results := make(chan error, 2)
		var workers sync.WaitGroup
		for i := 0; i < 2; i++ {
			request := create(subscription, uint16(27201+i), nil)
			workers.Add(1)
			go func() {
				defer workers.Done()
				<-start
				_, err := service.Create(t.Context(), actor, request)
				results <- err
			}()
		}
		close(start)
		workers.Wait()
		close(results)
		admitted, rejected := 0, 0
		for err := range results {
			switch {
			case err == nil:
				admitted++
			case errors.Is(err, packageaddon.ErrQuotaExceeded):
				rejected++
			default:
				t.Fatal(err)
			}
		}
		if admitted != 1 || rejected != 1 {
			t.Fatalf("admitted/rejected=%d/%d", admitted, rejected)
		}
	})
	t.Run("owner isolation and move checks", func(t *testing.T) {
		otherUser := fixture.member(t)
		foreign := fixture.subscription(t, otherUser, 10)
		if _, err := service.Create(t.Context(), actor, create(foreign, 27301, nil)); !errors.Is(err, ErrPermissionDenied) {
			t.Fatalf("foreign owner create=%v", err)
		}
		unlimited := fixture.subscription(t, actor.UserID, -1)
		request := create(unlimited, 27302, []AdditionalListener{{ID: uuid.New(), Protocol: ProtocolUDP, Address: "*", Port: 27302}})
		created, err := service.Create(t.Context(), actor, request)
		if err != nil {
			t.Fatal(err)
		}
		fields := request.Fields
		fields.PackageSubscriptionID = new(foreign)
		if _, err := service.Update(t.Context(), actor, update(created.Forward, fields)); !errors.Is(err, ErrPermissionDenied) {
			t.Fatalf("foreign owner move=%v", err)
		}
		limited := fixture.subscription(t, actor.UserID, 1)
		fields.PackageSubscriptionID = new(limited)
		fields.Enabled = false
		if _, err := service.Update(t.Context(), actor, update(created.Forward, fields)); !errors.Is(err, packageaddon.ErrQuotaExceeded) {
			t.Fatalf("disabled move bypass=%v", err)
		}
		empty := []AdditionalListener{}
		fields.AdditionalListeners = &empty
		changed, err := service.Update(t.Context(), actor, update(created.Forward, fields))
		if err != nil {
			t.Fatal(err)
		}
		fields.Enabled = true
		if _, err := service.Update(t.Context(), actor, update(changed.Forward, fields)); err != nil {
			t.Fatalf("valid re-enable=%v", err)
		}
		stranger := actor
		stranger.ScopeID = uuid.New()
		if _, err := service.Create(t.Context(), stranger, create(unlimited, 27303, nil)); !errors.Is(err, ErrPermissionDenied) && !errors.Is(err, ErrInvalidInput) {
			t.Fatalf("foreign scope=%v", err)
		}
	})
	t.Run("inactive subscription and late failure cannot reserve quota", func(t *testing.T) {
		subscription := fixture.subscription(t, actor.UserID, 1)
		request := create(subscription, 27501, nil)
		var expiry time.Time
		if err := pool.QueryRow(t.Context(), `SELECT ends_at FROM package_subscriptions WHERE id=$1`, subscription).Scan(&expiry); err != nil {
			t.Fatal(err)
		}
		expiredService := NewService(NewStoreWithClock(pool, func() time.Time { return expiry }))
		if _, err := expiredService.Create(t.Context(), actor, request); !errors.Is(err, packageaddon.ErrSubscriptionInactive) {
			t.Fatalf("expiry boundary admission=%v", err)
		}
		if _, err := pool.Exec(t.Context(), `CREATE FUNCTION reject_stream_addon_audit() RETURNS trigger LANGUAGE plpgsql AS $$
		BEGIN IF NEW.action='stream.create' THEN RAISE EXCEPTION 'injected stream audit failure'; END IF; RETURN NEW; END $$;
		CREATE TRIGGER reject_stream_addon_audit BEFORE INSERT ON audit_events FOR EACH ROW EXECUTE FUNCTION reject_stream_addon_audit()`); err != nil {
			t.Fatal(err)
		}
		if _, err := service.Create(t.Context(), actor, request); err == nil {
			t.Fatal("late audit failure was committed")
		}
		if _, err := pool.Exec(t.Context(), `DROP TRIGGER reject_stream_addon_audit ON audit_events; DROP FUNCTION reject_stream_addon_audit()`); err != nil {
			t.Fatal(err)
		}
		if _, err := service.Create(t.Context(), actor, request); err != nil {
			t.Fatalf("failed attempt consumed quota or receipt: %v", err)
		}
	})
	t.Run("old over-allocation can shrink but cannot grow or reactivate", func(t *testing.T) {
		subscription := fixture.subscription(t, actor.UserID, 0)
		_, assignment := fixture.assign(t, subscription, 1, 3)
		request := create(subscription, 27401, []AdditionalListener{
			{ID: uuid.New(), Protocol: ProtocolTCP, Address: "*", Port: 27402},
			{ID: uuid.New(), Protocol: ProtocolUDP, Address: "*", Port: 27403},
		})
		created, err := service.Create(t.Context(), actor, request)
		if err != nil {
			t.Fatal(err)
		}
		// Seed a historical over-allocation with immutable audit, as might exist
		// before quota admission was introduced. Production addon writes guard it.
		err = pgx.BeginFunc(t.Context(), pool, func(tx pgx.Tx) error {
			if _, err := tx.Exec(t.Context(), `UPDATE package_addon_assignments SET amount=1,revision=2,updated_at=clock_timestamp() WHERE id=$1`, assignment); err != nil {
				return err
			}
			return audit.New(pool).Append(t.Context(), tx, audit.Event{ScopeID: fixture.admin.ScopeID, ActorUserID: &fixture.admin.UserID,
				Action: "package.addon.assignment.update", ResourceType: "package_addon", ResourceID: assignment.String(), RequestID: uuid.NewString(), Result: "success", Payload: map[string]any{"revision": 2}})
		})
		if err != nil {
			t.Fatal(err)
		}
		fields := request.Fields
		fields.Enabled = false
		changed, err := service.Update(t.Context(), actor, update(created.Forward, fields))
		if err != nil {
			t.Fatalf("over quota disable=%v", err)
		}
		fields.Enabled = true
		if _, err := service.Update(t.Context(), actor, update(changed.Forward, fields)); !errors.Is(err, packageaddon.ErrQuotaExceeded) {
			t.Fatalf("over quota re-enable=%v", err)
		}
		extra := request.Fields.AdditionalListeners
		fewer := (*extra)[:1]
		fields.AdditionalListeners = &fewer
		fields.Enabled = false
		changed, err = service.Update(t.Context(), actor, update(changed.Forward, fields))
		if err != nil {
			t.Fatalf("strict shrink must work while still over quota: %v", err)
		}
		key := uuid.NewString()
		if _, err := service.Delete(t.Context(), actor, DeleteRequest{ID: changed.Forward.ID, ExpectedRevision: changed.Forward.Revision, IdempotencyKey: key, RequestID: key}); err != nil {
			t.Fatalf("over quota delete=%v", err)
		}
	})
	var incomplete int
	if err := pool.QueryRow(t.Context(), `SELECT count(*) FROM l4_write_requests WHERE completed_at IS NULL`).Scan(&incomplete); err != nil || incomplete != 0 {
		t.Fatalf("failed quota mutations left receipts: %d %v", incomplete, err)
	}
}

type streamAddonFixture struct {
	pool   *pgxpool.Pool
	actor  Actor
	admin  packageaddon.Actor
	addons packageaddon.Store
	siteID uuid.UUID
}

func newStreamAddonFixture(t *testing.T) streamAddonFixture {
	t.Helper()
	dsn := os.Getenv("TEST_DATABASE_URL")
	if dsn == "" {
		t.Skip("TEST_DATABASE_URL required")
	}
	// 用随机 schema 隔离（下方 CREATE SCHEMA），不需要专用库名。
	adminPool, err := pgxpool.New(t.Context(), dsn)
	if err != nil {
		t.Fatal(err)
	}
	schema := "stream_addon_" + strings.ReplaceAll(uuid.NewString(), "-", "")
	if _, err = adminPool.Exec(t.Context(), "CREATE SCHEMA "+pgx.Identifier{schema}.Sanitize()); err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() {
		_, err := adminPool.Exec(context.Background(), "DROP SCHEMA "+pgx.Identifier{schema}.Sanitize()+" CASCADE")
		if err != nil {
			t.Error(err)
		}
		adminPool.Close()
	})
	config, err := pgxpool.ParseConfig(dsn)
	if err != nil {
		t.Fatal(err)
	}
	config.ConnConfig.RuntimeParams["search_path"] = schema
	pool, err := pgxpool.NewWithConfig(t.Context(), config)
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(pool.Close)
	if err = database.Migrate(t.Context(), pool, "up"); err != nil {
		t.Fatal(err)
	}
	f := streamAddonFixture{pool: pool, actor: Actor{ScopeID: uuid.New(), UserID: uuid.New(), ScopeKind: "tenant"}, admin: packageaddon.Actor{ScopeID: uuid.New(), UserID: uuid.New(), SessionID: uuid.New()}, siteID: uuid.New()}
	f.addons = packageaddon.Store{Pool: pool}
	tenantID := uuid.New()
	for _, q := range []struct {
		sql  string
		args []any
	}{
		{`INSERT INTO access_scopes(id,kind) VALUES($1,'platform')`, []any{f.admin.ScopeID}},
		{`INSERT INTO tenants(id,display_name) VALUES($1,'stream addon test')`, []any{tenantID}},
		{`INSERT INTO access_scopes(id,kind,tenant_id) VALUES($1,'tenant',$2)`, []any{f.actor.ScopeID, tenantID}},
	} {
		if _, err := pool.Exec(t.Context(), q.sql, q.args...); err != nil {
			t.Fatal(err)
		}
	}
	for _, a := range []Actor{{UserID: f.admin.UserID, ScopeID: f.admin.ScopeID, ScopeKind: "platform"}, f.actor} {
		roleID := uuid.New()
		for _, q := range []struct {
			sql  string
			args []any
		}{
			{`INSERT INTO users(id,username,display_name,password_hash) VALUES($1,$2,'stream addon','test-hash')`, []any{a.UserID, "stream-" + a.UserID.String()}},
			{`INSERT INTO memberships(scope_id,user_id) VALUES($1,$2)`, []any{a.ScopeID, a.UserID}},
			{`INSERT INTO roles(id,scope_id,name,description,system_role) VALUES($1,$2,'stream-addon','test',true)`, []any{roleID, a.ScopeID}},
			{`INSERT INTO role_assignments(scope_id,user_id,role_id) VALUES($1,$2,$3)`, []any{a.ScopeID, a.UserID, roleID}},
		} {
			if _, err := pool.Exec(t.Context(), q.sql, q.args...); err != nil {
				t.Fatal(err)
			}
		}
		permissions := []string{"streams.manage"}
		if a.ScopeKind == "platform" {
			permissions = append(permissions, "billing.adjustments.manage", "packages.manage", "package_subscriptions.manage", "package_subscriptions.read")
		}
		for _, p := range permissions {
			if _, err := pool.Exec(t.Context(), `INSERT INTO role_permissions(role_id,permission_name) VALUES($1,$2) ON CONFLICT DO NOTHING`, roleID, p); err != nil {
				t.Fatal(err)
			}
		}
	}
	digest := sha256.Sum256(f.admin.SessionID[:])
	if _, err = pool.Exec(t.Context(), `INSERT INTO auth_sessions(id,family_id,user_id,scope_id,refresh_token_hash,created_at,expires_at) VALUES($1,$2,$3,$4,$5,clock_timestamp(),clock_timestamp()+interval '1 hour')`, f.admin.SessionID, uuid.New(), f.admin.UserID, f.admin.ScopeID, digest[:]); err != nil {
		t.Fatal(err)
	}
	err = pgx.BeginFunc(t.Context(), pool, func(tx pgx.Tx) error {
		if _, err := tx.Exec(t.Context(), `INSERT INTO sites(id,display_id,scope_id,owner_user_id,domain,http_ports,origins,origin_hosts,created_by_user_id,updated_by_user_id) VALUES($1,1,$2,$3,'stream-addon.example',ARRAY['80'],ARRAY['192.0.2.10'],ARRAY['192.0.2.10'],$3,$3)`, f.siteID, f.actor.ScopeID, f.actor.UserID); err != nil {
			return err
		}
		if _, err := tx.Exec(t.Context(), `INSERT INTO site_origin_pools(site_id) VALUES($1)`, f.siteID); err != nil {
			return err
		}
		_, err := tx.Exec(t.Context(), `INSERT INTO site_origins(site_id,position,host,port) VALUES($1,1,'192.0.2.10',80)`, f.siteID)
		return err
	})
	if err != nil {
		t.Fatal(err)
	}
	if _, err = pool.Exec(t.Context(), `INSERT INTO edge_automatic_publication_policy_facts(target_scope_id,revision,mode,node_ids,activation_timeout_ms,observation_window_ms,required_consecutive_successes,max_attempts,deadline_window_seconds,actor_scope_id,actor_user_id,reason,created_at) VALUES($1,1,'automatic',ARRAY[$2::uuid],30000,15000,2,3,600,$1,$3,'stream addon',clock_timestamp())`, f.actor.ScopeID, uuid.New(), f.actor.UserID); err != nil {
		t.Fatal(err)
	}
	return f
}

func (f streamAddonFixture) member(t *testing.T) uuid.UUID {
	t.Helper()
	id := uuid.New()
	if _, err := f.pool.Exec(t.Context(), `INSERT INTO users(id,username,display_name,password_hash) VALUES($1,$2,'other owner','test-hash')`, id, "other-"+id.String()); err != nil {
		t.Fatal(err)
	}
	if _, err := f.pool.Exec(t.Context(), `INSERT INTO memberships(scope_id,user_id) VALUES($1,$2)`, f.actor.ScopeID, id); err != nil {
		t.Fatal(err)
	}
	return id
}

func (f streamAddonFixture) subscription(t *testing.T, owner uuid.UUID, ports int64) uuid.UUID {
	t.Helper()
	return f.subscriptionOnLine(t, owner, ports, uuid.Nil)
}

// subscriptionOnLine opens a subscription whose package snapshot names
// nodeGroup as its line group (uuid.Nil: none).
func (f streamAddonFixture) subscriptionOnLine(t *testing.T, owner uuid.UUID, ports int64, nodeGroup uuid.UUID) uuid.UUID {
	t.Helper()
	product := uuid.New()
	line := ""
	if nodeGroup != uuid.Nil {
		line = fmt.Sprintf(`,"node_group_id":%q`, nodeGroup)
	}
	spec := fmt.Sprintf(`{"name":"Stream","limits":{"domains":100,"monthly_traffic_bytes":1000000,"stream_ports":%d},"prices":{"currency":"CNY","monthly_minor":1000,"quarterly_minor":2800,"yearly_minor":10000}%s}`, ports, line)
	err := pgx.BeginFunc(t.Context(), f.pool, func(tx pgx.Tx) error {
		if _, err := tx.Exec(t.Context(), `SELECT iam_global_lock_shared_v1();`); err != nil {
			return err
		}
		if _, err := tx.Exec(t.Context(), `SELECT iam_scope_locks_v1(ARRAY[$1::uuid])`, f.admin.ScopeID); err != nil {
			return err
		}
		if _, err := tx.Exec(t.Context(), `INSERT INTO package_products(id,name,enabled,sort_order,spec,revision,created_by_user_id,updated_by_user_id,created_at,updated_at) VALUES($1,$2,true,1,$3,1,$4,$4,clock_timestamp(),clock_timestamp())`, product, product.String(), spec, f.admin.UserID); err != nil {
			return err
		}
		if _, err := tx.Exec(t.Context(), `INSERT INTO package_product_versions(product_id,revision,name,enabled,sort_order,spec,deleted,created_by_user_id,created_at) VALUES($1,1,$2,true,1,$3,false,$4,clock_timestamp())`, product, product.String(), spec, f.admin.UserID); err != nil {
			return err
		}
		return audit.New(f.pool).Append(t.Context(), tx, audit.Event{ScopeID: f.admin.ScopeID, ActorUserID: &f.admin.UserID, Action: "package.product.create", ResourceType: "package_product", ResourceID: product.String(), RequestID: uuid.NewString(), Result: "success", Payload: map[string]any{"revision": 1, "enabled": true}})
	})
	if err != nil {
		t.Fatal(err)
	}
	factor, _ := packageperiod.NewTrafficFactor(1, 1)
	month := packageperiod.DurationMonth
	result, err := packagesubscription.NewService(packagesubscription.NewStore(f.pool)).Open(t.Context(), packagesubscription.Actor{UserID: f.admin.UserID, ScopeID: f.admin.ScopeID, SessionID: f.admin.SessionID, ScopeKind: packagesubscription.ScopePlatform}, packagesubscription.OpenRequest{TenantScopeID: f.actor.ScopeID, OwnerUserID: owner, ProductID: product, ProductRevision: 1, SiteLimit: 100, NodeLimit: 1, Terms: packageperiod.Terms{Duration: &month}, TimeZone: "UTC", CyclePolicy: packageperiod.CyclePolicy{Kind: packageperiod.CycleMonthly}, TrafficFactor: factor, IdempotencyKey: uuid.NewString(), RequestID: uuid.NewString()})
	if err != nil {
		t.Fatal(err)
	}
	return result.Subscription.ID
}

func (f streamAddonFixture) assign(t *testing.T, subscription uuid.UUID, quantity, amount int64) (uuid.UUID, uuid.UUID) {
	t.Helper()
	fields := packageaddon.ProductFields{Name: uuid.NewString(), Kind: "stream_ports", Quantity: quantity, MonthlyPriceMinor: 100, Enabled: true}
	product, err := f.addons.Write(t.Context(), f.admin, packageaddon.Command{Action: "product.create", Product: &fields}, uuid.NewString(), uuid.NewString())
	if err != nil {
		t.Fatal(err)
	}
	assigned, err := f.addons.Write(t.Context(), f.admin, packageaddon.Command{Action: "assignment.create", AddonID: product.ID, OwnerUserID: f.actor.UserID, SubscriptionID: subscription, Amount: amount}, uuid.NewString(), uuid.NewString())
	if err != nil {
		t.Fatal(err)
	}
	return product.ID, assigned.ID
}
