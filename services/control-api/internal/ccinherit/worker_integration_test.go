package ccinherit

import (
	"context"
	"crypto/sha256"
	"encoding/json"
	"log/slog"
	"os"
	"strings"
	"sync"
	"testing"
	"time"

	"github.com/cdnca/cdnca/libs/entitlement/rulecatalog"
	"github.com/cdnca/cdnca/services/control-api/internal/audit"
	"github.com/cdnca/cdnca/services/control-api/internal/database"
	"github.com/cdnca/cdnca/services/control-api/internal/database/databasetest"
	"github.com/cdnca/cdnca/services/control-api/internal/securityactivation"
	"github.com/cdnca/cdnca/services/control-api/internal/securitypolicy"
	"github.com/google/uuid"
	"github.com/jackc/pgx/v5"
	"github.com/jackc/pgx/v5/pgxpool"
)

var testNow = time.Date(2026, 10, 17, 2, 0, 0, 0, time.UTC)

type recordingStarter struct {
	mu     sync.Mutex
	actors []securitypolicy.Actor
	inputs []securityactivation.StartInput
}

func (starter *recordingStarter) Start(_ context.Context, actor securitypolicy.Actor,
	input securityactivation.StartInput) (securityactivation.StartResult, error) {
	starter.mu.Lock()
	defer starter.mu.Unlock()
	starter.actors, starter.inputs = append(starter.actors, actor), append(starter.inputs, input)
	return securityactivation.StartResult{}, nil
}

type fixture struct {
	pool                            *pgxpool.Pool
	scopeID, tenantID, userID, node uuid.UUID
	configID                        uuid.UUID
	configRevision                  int64
}

func migratedPool(t *testing.T) *pgxpool.Pool {
	t.Helper()
	url := os.Getenv("TEST_DATABASE_URL")
	if url == "" {
		t.Skip("TEST_DATABASE_URL is not set")
	}
	if pool := databasetest.ClonedMigratedPool(t, nil); pool != nil {
		return pool
	}
	ctx := context.Background()
	admin, err := pgxpool.New(ctx, url)
	if err != nil {
		t.Fatal(err)
	}
	schema := "ccinherit_test_" + strings.ReplaceAll(uuid.NewString(), "-", "")
	if _, err := admin.Exec(ctx, "CREATE SCHEMA "+pgx.Identifier{schema}.Sanitize()); err != nil {
		t.Fatal(err)
	}
	config, err := pgxpool.ParseConfig(url)
	if err != nil {
		t.Fatal(err)
	}
	config.ConnConfig.RuntimeParams["search_path"] = schema
	pool, err := pgxpool.NewWithConfig(ctx, config)
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() {
		pool.Close()
		cleanup, cancel := databasetest.CleanupContext()
		defer cancel()
		_, _ = admin.Exec(cleanup, "DROP SCHEMA "+pgx.Identifier{schema}.Sanitize()+" CASCADE")
		admin.Close()
	})
	if err := database.Migrate(ctx, pool, "up"); err != nil {
		t.Fatal(err)
	}
	return pool
}

func exec(t *testing.T, pool *pgxpool.Pool, sql string, args ...any) {
	t.Helper()
	if _, err := pool.Exec(t.Context(), sql, args...); err != nil {
		t.Fatalf("%v\n%s", err, sql)
	}
}

func newFixture(t *testing.T) fixture {
	t.Helper()
	pool := migratedPool(t)
	value := fixture{pool: pool, scopeID: uuid.New(), tenantID: uuid.New(), userID: uuid.New(), node: uuid.New(),
		configID: uuid.New()}
	platformScope := uuid.New()
	exec(t, pool, `INSERT INTO access_scopes(id,kind) VALUES($1,'platform')`, platformScope)
	exec(t, pool, `INSERT INTO tenants(id,display_name) VALUES($1,'inherit tenant')`, value.tenantID)
	exec(t, pool, `INSERT INTO access_scopes(id,kind,tenant_id) VALUES($1,'tenant',$2)`, value.scopeID, value.tenantID)
	exec(t, pool, `INSERT INTO users(id,username,display_name,password_hash) VALUES($1,'inherit-owner','inherit owner','hash')`, value.userID)
	exec(t, pool, `INSERT INTO memberships(scope_id,user_id) VALUES($1,$2)`, value.scopeID, value.userID)
	exec(t, pool, `INSERT INTO nodes(id,display_id,scope_id,name,admin_state,created_by_user_id) VALUES($1,1,$2,'inherit-node','active',$3)`,
		value.node, value.scopeID, value.userID)
	// A package with the custom CC feature (CC policies of the owner).
	productID, subscriptionID := uuid.New(), uuid.New()
	spec := `{"limits":{"domains":10,"root_domains":10,"http_ports":10,"stream_ports":10,"custom_cc":true},"protection":{"waf":false}}`
	if err := pgx.BeginFunc(t.Context(), pool, func(tx pgx.Tx) error {
		statements := []struct {
			sql  string
			args []any
		}{
			{`SELECT iam_global_lock_shared_v1()`, nil},
			{`SELECT iam_scope_locks_v1(ARRAY[$1::uuid])`, []any{platformScope}},
			{`INSERT INTO package_products(id,name,spec,created_by_user_id,updated_by_user_id,created_at,updated_at) VALUES($1,$2,$3,$4,$4,$5,$5)`,
				[]any{productID, productID.String(), spec, value.userID, testNow}},
			{`INSERT INTO package_product_versions(product_id,revision,name,enabled,sort_order,spec,created_by_user_id,created_at) VALUES($1,1,$2,true,100,$3,$4,$5)`,
				[]any{productID, productID.String(), spec, value.userID, testNow}},
		}
		for _, statement := range statements {
			if _, err := tx.Exec(t.Context(), statement.sql, statement.args...); err != nil {
				return err
			}
		}
		if err := audit.New(pool).Append(t.Context(), tx, audit.Event{ScopeID: platformScope, ActorUserID: &value.userID,
			Action: "package.product.create", ResourceType: "package_product", ResourceID: productID.String(),
			RequestID: productID.String(), Result: "success", Payload: map[string]any{"revision": 1, "enabled": true}}); err != nil {
			return err
		}
		for _, statement := range []struct {
			sql  string
			args []any
		}{
			{`INSERT INTO package_subscriptions(id,tenant_scope_id,product_id,product_revision,product_snapshot,site_limit,domain_limit,node_limit,traffic_limit_bytes,starts_at,ends_at,timezone,cycle_kind,tcp_factor_numerator,tcp_factor_denominator,created_by_user_id,updated_by_user_id,created_at,updated_at)
				SELECT $1,$2,product_id,revision,jsonb_build_object('id',product_id::text,'revision',revision,'name',name,'spec',spec),10,10,10,1000000,$4,$5,'UTC','monthly',1,1,$3,$3,$4,$4 FROM package_product_versions WHERE product_id=$6`,
				[]any{subscriptionID, value.scopeID, value.userID, testNow.Add(-time.Hour), testNow.Add(24 * time.Hour), productID}},
			{`INSERT INTO package_subscription_entitlement_versions(subscription_id,revision,tenant_scope_id,effective_at,product_id,product_revision,product_snapshot,site_limit,domain_limit,node_limit,traffic_limit_bytes,timezone,cycle_kind,tcp_factor_numerator,tcp_factor_denominator,currency,entitlement_status,operation,created_by_user_id,created_at)
				SELECT id,1,tenant_scope_id,starts_at,product_id,product_revision,product_snapshot,site_limit,domain_limit,node_limit,traffic_limit_bytes,timezone,cycle_kind,tcp_factor_numerator,tcp_factor_denominator,'CNY','active','migration_backfill',created_by_user_id,created_at FROM package_subscriptions WHERE id=$1`,
				[]any{subscriptionID}},
			{`INSERT INTO package_monitor_subscription_owners(subscription_id,state_revision,tenant_scope_id,owner_user_id,source_kind,created_at) VALUES($1,1,$2,$3,'subscription_state',$4)`,
				[]any{subscriptionID, value.scopeID, value.userID, testNow}},
		} {
			if _, err := tx.Exec(t.Context(), statement.sql, statement.args...); err != nil {
				return err
			}
		}
		return nil
	}); err != nil {
		t.Fatal(err)
	}
	// The system rule catalog, as a signed delivery writes it.
	if err := pgx.BeginFunc(t.Context(), pool, func(tx pgx.Tx) error {
		if _, err := tx.Exec(t.Context(), `SELECT set_config('cdnca.security_rule_catalog_apply','on',true)`); err != nil {
			return err
		}
		delivery := uuid.New()
		for _, item := range rulecatalog.CurrentSeed() {
			body, err := json.Marshal(item.Body)
			if err != nil {
				return err
			}
			if _, err := tx.Exec(t.Context(), `INSERT INTO security_system_rules(system_key,kind,legacy_id,name,description,sort,hidden,
				revision,body,status,delivery_id,first_seen_at,updated_at) VALUES($1,$2,$3,$4,$5,$6,$7,$8,$9,'active',$10,$11,$11)`,
				item.SystemKey, item.Kind, item.LegacyID, item.Name, item.Description, item.Sort, item.Hidden, item.Revision,
				body, delivery, testNow); err != nil {
				return err
			}
		}
		return nil
	}); err != nil {
		t.Fatal(err)
	}
	return value
}

// setGlobal writes the tenant's global CC config and its outbox row, as
// openrestysecurity.Store does.
func (value *fixture) setGlobal(t *testing.T, document string, at time.Time) {
	t.Helper()
	value.configRevision++
	digest := sha256.Sum256([]byte(document))
	if value.configRevision == 1 {
		exec(t, value.pool, `INSERT INTO openresty_security_configs(id,tenant_scope_id,scope_type,scope_id,document,document_sha256,revision,created_at,updated_at)
			VALUES($1,$2,'global','0',$3,$4,1,$5,$5)`, value.configID, value.scopeID, document, digest[:], at)
	} else {
		exec(t, value.pool, `UPDATE openresty_security_configs SET document=$2,document_sha256=$3,revision=$4,updated_at=$5 WHERE id=$1`,
			value.configID, document, digest[:], value.configRevision, at)
	}
	exec(t, value.pool, `INSERT INTO openresty_security_config_revisions(tenant_scope_id,config_id,revision,scope_type,scope_id,operation,
		document,document_sha256,key_configured,actor_scope_id,actor_user_id,request_id,created_at)
		VALUES($1,$2,$3,'global','0','global.patch',$4,$5,false,$1,$6,'inherit-test',$7)`,
		value.scopeID, value.configID, value.configRevision, document, digest[:], value.userID, at)
	exec(t, value.pool, `INSERT INTO openresty_security_publication_outbox(id,tenant_scope_id,config_id,revision,scope_type,scope_id,operation,
		document,document_sha256,state,available_at,created_at,updated_at)
		VALUES($1,$2,$3,$4,'global','0','global.patch',$5,$6,'pending',$7,$7,$7)`,
		uuid.New(), value.scopeID, value.configID, value.configRevision, document, digest[:], at)
}

// bind makes site run policy at revision (published by the owner to the
// fixture node): the binding and the publication the worker reads.
func (value fixture) bind(t *testing.T, policy securitypolicy.Policy, revision int64, domain string) (uuid.UUID, uuid.UUID) {
	t.Helper()
	siteID, bindingID, bundleID := uuid.New(), uuid.New(), uuid.New()
	if err := pgx.BeginFunc(t.Context(), value.pool, func(tx pgx.Tx) error {
		if _, err := tx.Exec(t.Context(), "SET CONSTRAINTS ALL DEFERRED"); err != nil {
			return err
		}
		if _, err := tx.Exec(t.Context(), `INSERT INTO sites(id,display_id,scope_id,owner_user_id,domain,origins,origin_hosts,created_by_user_id,updated_by_user_id)
			VALUES($1,(SELECT COALESCE(max(display_id),0)+1 FROM sites),$2,$3,$4,ARRAY['192.0.2.10:80'],ARRAY['192.0.2.10'],$3,$3)`,
			siteID, value.scopeID, value.userID, domain); err != nil {
			return err
		}
		if _, err := tx.Exec(t.Context(), `INSERT INTO site_origin_pools(site_id) VALUES($1)`, siteID); err != nil {
			return err
		}
		_, err := tx.Exec(t.Context(), `INSERT INTO site_origins(site_id,position,host,port) VALUES($1,1,'192.0.2.10',80)`, siteID)
		return err
	}); err != nil {
		t.Fatal(err)
	}
	exec(t, value.pool, `INSERT INTO security_policy_site_bindings(id,tenant_scope_id,site_id,policy_id,policy_kind,active_policy_version,
		last_claimed_policy_version,last_bundle_id,revision,created_at,updated_at) VALUES($1,$2,$3,$4,'cc',NULL,NULL,NULL,0,$5,$5)`,
		bindingID, value.scopeID, siteID, policy.ID, testNow)
	var document []byte
	if err := value.pool.QueryRow(t.Context(), `SELECT document FROM security_policy_versions WHERE policy_id=$1 AND revision=$2`,
		policy.ID, revision).Scan(&document); err != nil {
		t.Fatal(err)
	}
	var version securitypolicy.Policy
	if err := json.Unmarshal(document, &version); err != nil {
		t.Fatal(err)
	}
	runtime, err := securitypolicy.CompileRuntimeSnapshot(version, siteID)
	if err != nil {
		t.Fatal(err)
	}
	digest := sha256.Sum256(document)
	exec(t, value.pool, `INSERT INTO security_policy_publications(id,binding_id,tenant_scope_id,site_id,policy_id,policy_kind,policy_version,
		expected_binding_revision,binding_revision,expected_active_version,rollout_id,idempotency_key,request_digest,plan_request_digest,
		canonical_payload,canonical_payload_sha256,runtime_snapshot_sha256,bundle_bytes,bundle_sha256,signing_key_id,issued_at,expires_at,
		actor_scope_id,actor_user_id,request_id,created_at)
		VALUES($1,$2,$3,$4,$5,'cc',$6,0,1,0,$7,$8,$9,$9,$10,$9,$11,$10,$9,'fixture-key',$12,$13,$3,$14,$8,$12)`,
		bundleID, bindingID, value.scopeID, siteID, policy.ID, revision, uuid.New(), "inherit-"+bundleID.String(),
		digest[:], document, runtime.SHA256[:], testNow, testNow.Add(time.Hour), value.userID)
	exec(t, value.pool, `UPDATE security_policy_site_bindings SET active_policy_version=$2,last_claimed_policy_version=$2,last_bundle_id=$3,
		revision=1,updated_at=$4 WHERE id=$1`, bindingID, revision, bundleID, testNow)
	// One open claim per node and tenant: earlier publications completed.
	exec(t, value.pool, `UPDATE security_policy_publication_targets SET released_at=$2,release_reason='completed'
		WHERE node_id=$1 AND released_at IS NULL`, value.node, testNow)
	exec(t, value.pool, `INSERT INTO security_policy_publication_targets(publication_id,tenant_scope_id,binding_id,node_id,claimed_at,expires_at)
		VALUES($1,$2,$3,$4,$5,$6)`, bundleID, value.scopeID, bindingID, value.node, testNow, testNow.Add(time.Hour))
	return siteID, bundleID
}

func ccPolicyFields(name string, settings *securitypolicy.CCSettings) securitypolicy.PolicyFields {
	return securitypolicy.PolicyFields{Kind: securitypolicy.KindCC, Name: name, Enabled: true,
		DefaultAction: securitypolicy.ActionAllow, CCSettings: settings,
		Rules: []securitypolicy.Rule{{Name: "relaxed", Priority: 10, Enabled: true,
			Conditions: []securitypolicy.Condition{{Field: "path", Operator: "prefix", Values: []string{"/"}}},
			Action:     securitypolicy.ActionRateLimit, Flow: securitypolicy.FlowStop,
			ActionConfig: securitypolicy.ActionConfig{RateLimit: &securitypolicy.RateLimitConfig{Algorithm: "fixed_window",
				WindowSeconds: 5, MaxRequests: 300, ResponseAction: "temporary_ban", BanSeconds: 360}}}}}
}

func systemSettings() *securitypolicy.CCSettings {
	return &securitypolicy.CCSettings{BanSeconds: &securitypolicy.CCDuration{Mode: securitypolicy.CCSettingSystem},
		AutoSwitch: &securitypolicy.CCAutoSwitch{Mode: securitypolicy.CCSettingSystem, RuleGroups: []string{}, Rules: []securitypolicy.Rule{}}}
}

// TestWorkerFollowsGlobalCCConfig: turning the global auto switch on (and
// changing the blacklist time) re-resolves every system-mode policy of the
// tenant: a new revision, an activation of each site that ran the previous
// revision (as its publisher), none for a site pinned to an older revision
// or for a custom-mode policy; a second pass changes nothing.
func TestWorkerFollowsGlobalCCConfig(t *testing.T) {
	value := newFixture(t)
	value.setGlobal(t, `{"block_time":3600,"auto_switch":{"enable":false,"qps_50x":0,"qps_total":0,"rule":"","seconds":0}}`, testNow)
	clock := func() time.Time { return testNow }
	service := securitypolicy.NewService(securitypolicy.NewStoreWithClock(value.pool, clock))
	store := securitypolicy.NewStoreWithClock(value.pool, clock)
	owner := securitypolicy.Actor{UserID: value.userID, ScopeID: value.scopeID, ScopeKind: "tenant"}
	create := func(name string, settings *securitypolicy.CCSettings) securitypolicy.Policy {
		result, err := service.Create(t.Context(), owner, securitypolicy.CreateRequest{TargetScopeID: value.scopeID,
			OwnerUserID: value.userID, Fields: ccPolicyFields(name, settings), IdempotencyKey: "create-" + name, RequestID: "create-" + name})
		if err != nil {
			t.Fatalf("create %s: %v", name, err)
		}
		return result.Policy
	}
	inheriting := create("inheriting", systemSettings())
	if inheriting.CCSettings.AutoSwitch.Active() || inheriting.CCSettings.BanSeconds.Seconds != 3600 {
		t.Fatalf("initial resolution = %+v", inheriting.CCSettings)
	}
	custom := create("custom", &securitypolicy.CCSettings{BanSeconds: &securitypolicy.CCDuration{Mode: securitypolicy.CCSettingCustom, Seconds: 600}})
	_, _ = value.bind(t, custom, custom.Revision, "custom.example")

	starter := &recordingStarter{}
	worker, err := NewWorker(value.pool, store, service, starter, time.Second, clock, slog.New(slog.NewTextHandler(os.Stderr, nil)))
	if err != nil {
		t.Fatal(err)
	}
	if err := worker.Reconcile(t.Context()); err != nil {
		t.Fatalf("first pass: %v", err)
	}
	if len(starter.inputs) != 0 {
		t.Fatalf("unchanged config activated %+v", starter.inputs)
	}

	// One site runs the latest revision, another stays pinned to the first.
	edited, err := service.Update(t.Context(), owner, securitypolicy.UpdateRequest{ID: inheriting.ID, ExpectedRevision: inheriting.Revision,
		Fields: ccPolicyFields("inheriting", systemSettings()), IdempotencyKey: "edit", RequestID: "edit"})
	if err != nil {
		t.Fatal(err)
	}
	pinned, _ := value.bind(t, inheriting, inheriting.Revision, "pinned.example")
	current, _ := value.bind(t, inheriting, edited.Policy.Revision, "current.example")

	value.setGlobal(t, `{"block_time":900,"auto_switch":{"enable":true,"qps_50x":20,"qps_total":300,"rule":"10003","seconds":120}}`, testNow.Add(time.Minute))
	if err := worker.Reconcile(t.Context()); err != nil {
		t.Fatalf("second pass: %v", err)
	}
	after, err := service.Get(t.Context(), owner, inheriting.ID)
	if err != nil {
		t.Fatal(err)
	}
	settings := after.CCSettings
	if after.Revision != edited.Policy.Revision+1 || settings.BanSeconds.Seconds != 900 || !settings.AutoSwitch.Active() ||
		settings.AutoSwitch.QPSTotal != 300 || settings.AutoSwitch.QPS5xx != 20 || settings.AutoSwitch.RecoverSeconds != 120 ||
		settings.AutoSwitch.RuleGroups[0] != "cc_rule:10003" {
		t.Fatalf("re-resolved policy revision %d settings %+v", after.Revision, settings)
	}
	unchanged, err := service.Get(t.Context(), owner, custom.ID)
	if err != nil || unchanged.Revision != custom.Revision {
		t.Fatalf("custom policy rewritten: %+v %v", unchanged, err)
	}
	if len(starter.inputs) != 1 {
		t.Fatalf("activations = %+v", starter.inputs)
	}
	input := starter.inputs[0]
	if input.SiteID != current || input.SiteID == pinned || input.PolicyID != inheriting.ID || input.PolicyVersion != after.Revision ||
		input.ExpectedActivePolicyVersion != edited.Policy.Revision || len(input.TargetNodeIDs) != 1 || input.TargetNodeIDs[0] != value.node ||
		starter.actors[0] != owner {
		t.Fatalf("activation %+v by %+v", input, starter.actors[0])
	}
	if _, err := securitypolicy.CompileRuntimeSnapshot(after, current); err != nil {
		t.Fatalf("re-resolved policy does not compile: %v", err)
	}

	// Nothing changed since: no new revision, no activation.
	worker.swept = false
	if err := worker.Reconcile(t.Context()); err != nil {
		t.Fatalf("third pass: %v", err)
	}
	again, err := service.Get(t.Context(), owner, inheriting.ID)
	if err != nil || again.Revision != after.Revision || len(starter.inputs) != 1 {
		t.Fatalf("idempotent pass wrote revision %d, activations %d (%v)", again.Revision, len(starter.inputs), err)
	}
}

// fix-fwregion: the platform's firewall page configs are the auto switch
// layers. A platform region override re-resolves the inheriting policy with
// an override for the region's platform node and republishes the site;
// deleting it falls back to global and republishes again; the tenant's own
// node never gets an override.
func TestWorkerFollowsPlatformAutoSwitchOverrides(t *testing.T) {
	value := newFixture(t)
	// The license default (tenant document) until the platform sets one.
	value.setGlobal(t, `{"auto_switch":{"enable":true,"qps_50x":0,"qps_total":300,"rule":"10003","seconds":120}}`, testNow)
	var platformScope uuid.UUID
	if err := value.pool.QueryRow(t.Context(), `SELECT id FROM access_scopes WHERE kind='platform' ORDER BY id LIMIT 1`).
		Scan(&platformScope); err != nil {
		t.Fatal(err)
	}
	platformNode := uuid.New()
	exec(t, value.pool, `INSERT INTO nodes(id,display_id,scope_id,name,region,admin_state,created_by_user_id) VALUES($1,2,$2,'edge-east','east','active',$3)`,
		platformNode, platformScope, value.userID)
	clock := func() time.Time { return testNow }
	store := securitypolicy.NewStoreWithClock(value.pool, clock)
	service := securitypolicy.NewService(store)
	owner := securitypolicy.Actor{UserID: value.userID, ScopeID: value.scopeID, ScopeKind: "tenant"}
	created, err := service.Create(t.Context(), owner, securitypolicy.CreateRequest{TargetScopeID: value.scopeID,
		OwnerUserID: value.userID, Fields: ccPolicyFields("layers", systemSettings()), IdempotencyKey: "create-layers", RequestID: "create-layers"})
	if err != nil {
		t.Fatal(err)
	}
	if !created.Policy.CCSettings.AutoSwitch.Active() || created.Policy.CCSettings.AutoSwitch.QPSTotal != 300 ||
		len(created.Policy.CCSettings.AutoSwitch.Overrides) != 0 {
		t.Fatalf("license default not followed: %+v", created.Policy.CCSettings.AutoSwitch)
	}
	site, _ := value.bind(t, created.Policy, created.Policy.Revision, "layers.example")
	starter := &recordingStarter{}
	worker, err := NewWorker(value.pool, store, service, starter, time.Second, clock, slog.New(slog.NewTextHandler(os.Stderr, nil)))
	if err != nil {
		t.Fatal(err)
	}
	if err := worker.Reconcile(t.Context()); err != nil || len(starter.inputs) != 0 {
		t.Fatalf("first pass: %v %+v", err, starter.inputs)
	}

	overrideID := uuid.New()
	setPlatform := func(scopeType, scopeID, document string, at time.Time, deleted bool) {
		digest := sha256.Sum256([]byte(document))
		id := overrideID
		if scopeType == "global" {
			id = uuid.NewSHA1(uuid.NameSpaceOID, []byte(platformScope.String()+":global"))
		}
		exec(t, value.pool, `INSERT INTO openresty_security_configs(id,tenant_scope_id,scope_type,scope_id,document,document_sha256,revision,created_at,updated_at)
			VALUES($1,$2,$3,$4,$5,$6,1,$7,$7) ON CONFLICT (id) DO UPDATE SET document=EXCLUDED.document,document_sha256=EXCLUDED.document_sha256,
			revision=openresty_security_configs.revision+1,updated_at=EXCLUDED.updated_at`, id, platformScope, scopeType, scopeID, document, digest[:], at)
		if deleted {
			exec(t, value.pool, `UPDATE openresty_security_configs SET deleted_at=$2 WHERE id=$1`, id, at)
		}
		exec(t, value.pool, `INSERT INTO openresty_security_publication_outbox(id,tenant_scope_id,config_id,revision,scope_type,scope_id,operation,
			document,document_sha256,state,available_at,created_at,updated_at)
			VALUES($1,$2,$3,1,$4,$5,'override.patch',$6,$7,'pending',$8,$8,$8)`, uuid.New(), platformScope, id, scopeType, scopeID, document, digest[:], at)
	}
	setPlatform("region", "east", `{"auto_switch":{"enable":true,"qps_50x":0,"qps_total":50,"rule":"10003","seconds":300}}`, testNow.Add(time.Minute), false)
	if err := worker.Reconcile(t.Context()); err != nil {
		t.Fatalf("override pass: %v", err)
	}
	after, err := service.Get(t.Context(), owner, created.Policy.ID)
	if err != nil {
		t.Fatal(err)
	}
	overrides := after.CCSettings.AutoSwitch.Overrides
	if len(overrides) != 1 || len(overrides[0].Nodes) != 1 || overrides[0].Nodes[0] != platformNode || overrides[0].QPSTotal != 50 ||
		after.CCSettings.AutoSwitch.QPSTotal != 300 {
		t.Fatalf("region override not resolved: %+v", after.CCSettings.AutoSwitch)
	}
	for _, override := range overrides {
		for _, node := range override.Nodes {
			if node == value.node {
				t.Fatal("tenant node got a platform override")
			}
		}
	}
	if len(starter.inputs) != 1 || starter.inputs[0].SiteID != site || starter.inputs[0].PolicyVersion != after.Revision {
		t.Fatalf("override not republished: %+v", starter.inputs)
	}

	setPlatform("region", "east", `{"auto_switch":{"enable":true,"qps_50x":0,"qps_total":50,"rule":"10003","seconds":300}}`, testNow.Add(2*time.Minute), true)
	if err := worker.Reconcile(t.Context()); err != nil {
		t.Fatalf("delete pass: %v", err)
	}
	fallback, err := service.Get(t.Context(), owner, created.Policy.ID)
	if err != nil || len(fallback.CCSettings.AutoSwitch.Overrides) != 0 || fallback.Revision != after.Revision+1 {
		t.Fatalf("deleted override did not fall back: %+v %v", fallback.CCSettings.AutoSwitch, err)
	}
	if len(starter.inputs) != 2 {
		t.Fatalf("fallback not republished: %+v", starter.inputs)
	}
}
