//go:build integration

package main

// Control half of tests/market-supplier-e2e/run.sh (ADR 0012 ML-30 E1): the three-level resale chain over the market
// process of tests/market-limits-e2e (TestMarketLimitsMarketProcess, member API + relay + operator API over mTLS).
// Three controllers, each with its own migrated schema, signed lease and production marketruntime (grant, relay and
// hold loops, notices into its notification center):
//
//	A supplier_a  leaf: lists its line group (production marketsupply with the real site service);
//	B reseller_b  buys A's offer with a direct top-up and resells it (upstream component);
//	C root_c      buys B's offer and puts its site on it through the relay (production marketsubscribe.Apply).
//
// Then: §18.2 visibility (A sees C only as a downstream number via B, B sees C), the site lands on A's line group in
// a market tenant, an attack digest of A's site (production SecurityDigests over stand-in ClickHouse readers) reaches
// C bound to C's own site while B only gets market.downstream.attacked, and A's stop complaint on that downstream
// number is seen through by the operator (root C, the chain), held on the root subscription, applied by A's hold
// loop to C's share only, and every party on the path is told; the release restores it.

import (
	"bytes"
	"context"
	"crypto/ed25519"
	"crypto/tls"
	"encoding/json"
	"fmt"
	"io"
	"log/slog"
	"net/http"
	"os"
	"path/filepath"
	"strings"
	"sync"
	"testing"
	"time"

	"github.com/cdnca/cdnca/libs/entitlement"
	"github.com/cdnca/cdnca/libs/marketproto/secdigest"
	"github.com/cdnca/cdnca/libs/marketproto/siteconf"
	"github.com/cdnca/cdnca/services/control-api/internal/analyticslog"
	"github.com/cdnca/cdnca/services/control-api/internal/identity"
	"github.com/cdnca/cdnca/services/control-api/internal/marketclient"
	"github.com/cdnca/cdnca/services/control-api/internal/marketruntime"
	"github.com/cdnca/cdnca/services/control-api/internal/marketsubscribe"
	"github.com/cdnca/cdnca/services/control-api/internal/marketsupply"
	"github.com/cdnca/cdnca/services/control-api/internal/notification"
	"github.com/cdnca/cdnca/services/control-api/internal/packagesubscription"
	"github.com/cdnca/cdnca/services/control-api/internal/securityanalytics"
	"github.com/cdnca/cdnca/services/control-api/internal/site"
	"github.com/google/uuid"
	"github.com/jackc/pgx/v5"
	"github.com/jackc/pgx/v5/pgxpool"
)

// supplierController is one controller of the chain: its schema, runtime and (for C) subscriber service.
type supplierController struct {
	name      string
	pool      *pgxpool.Pool
	runtime   *marketruntime.Runtime
	supply    *marketsupply.Service
	subscribe *marketsubscribe.Service
}

type marketSupplierFlow struct {
	*marketLimitsFlow // member/control/state/target/buy helpers; pool and poolRef are A's
	ctl               map[string]*supplierController
	attacks           *supplierAttacks
	digests           *supplierDigests
	operatorHTTP      *http.Client
}

func TestMarketSupplierControlProcess(t *testing.T) {
	directory := os.Getenv("MARKET_LIMITS_E2E_DIR")
	databaseURL := strings.TrimSpace(os.Getenv("TEST_DATABASE_URL"))
	if directory == "" || databaseURL == "" {
		t.Skip("MARKET_LIMITS_E2E_DIR and TEST_DATABASE_URL are required; run tests/market-supplier-e2e/run.sh")
	}
	flow := startMarketSupplier(t, directory, databaseURL)
	defer flow.done()
	flow.run()
}

// supplierAttacks stands in for A's ClickHouse readers (analyticslog attack summaries and the autodefense site
// security window) under the production marketsupply.SecurityDigests. Until armed it fails, so the digest loop keeps
// its cursor; once armed the first window it asks for carries one attack on the armed site.
type supplierAttacks struct {
	mu                 sync.Mutex
	armed              bool
	tenant, site, host string
	window             int64
}

func (a *supplierAttacks) arm(tenant, site uuid.UUID, host string) {
	a.mu.Lock()
	defer a.mu.Unlock()
	a.armed, a.tenant, a.site, a.host = true, tenant.String(), site.String(), host
}

func (a *supplierAttacks) served() int64 {
	a.mu.Lock()
	defer a.mu.Unlock()
	return a.window
}

func (a *supplierAttacks) ListAttackSummaries(_ context.Context, from, _ time.Time, _ uint64, _ uint16,
) ([]analyticslog.AttackSiteSummary, error) {
	a.mu.Lock()
	defer a.mu.Unlock()
	if !a.armed {
		return nil, fmt.Errorf("e2e: attack source not armed yet")
	}
	if a.window == 0 {
		a.window = from.Unix()
	}
	if from.Unix() != a.window {
		return nil, nil
	}
	return []analyticslog.AttackSiteSummary{{TenantID: a.tenant, SiteID: a.site, Host: a.host, Events: 3, Blocked: 3,
		Clients: 1, TopDetector: "sqli", TopClientIP: "203.0.113.9", FirstEventAt: from.Add(time.Second),
		LastEventAt: from.Add(3 * time.Second)}}, nil
}

func (a *supplierAttacks) SiteSecurityWindow(_ context.Context, _, _ uuid.UUID, from, _ time.Time, _ int,
) ([]secdigest.Log, int64, []secdigest.Action, error) {
	a.mu.Lock()
	host := a.host
	a.mu.Unlock()
	logs := []secdigest.Log{{AtMS: from.Add(time.Second).UnixMilli(), ClientIP: "203.0.113.9", Host: host, Path: "/login",
		Action: "block", Detector: "sqli", RuleID: "942100"}}
	actions := []secdigest.Action{{At: from.Unix() + 5, Source: "waf", Level: 2, Kind: "ip", Target: "203.0.113.9", Reason: "sqli"}}
	return logs, int64(len(logs)), actions, nil
}

// supplierDigests stands in for C's ClickHouse writer (securityanalytics.ClickHouse.WriteMarketSecurity).
type supplierDigests struct {
	mu  sync.Mutex
	got []securityanalytics.MarketSecurity
}

func (d *supplierDigests) WriteMarketSecurity(_ context.Context, m securityanalytics.MarketSecurity) error {
	d.mu.Lock()
	defer d.mu.Unlock()
	d.got = append(d.got, m)
	return nil
}

func (d *supplierDigests) all() []securityanalytics.MarketSecurity {
	d.mu.Lock()
	defer d.mu.Unlock()
	return append([]securityanalytics.MarketSecurity(nil), d.got...)
}

func startMarketSupplier(t *testing.T, directory, databaseURL string) *marketSupplierFlow {
	t.Helper()
	var h marketLimitsHandoff
	waitJSONFile(t, filepath.Join(directory, "market.json"), &h)
	t.Setenv(marketruntime.MarketCAFileEnv, h.CAFile)
	roots, err := marketruntime.RootCAs()
	if err != nil {
		t.Fatal(err)
	}
	license := marketLimitsLicense{id: h.LicenseKeyID, key: ed25519.NewKeyFromSeed(h.LicenseSeed)}
	base := &marketLimitsFlow{t: t, h: h, clients: map[string]*marketclient.Client{}, members: map[string]uuid.UUID{},
		http: &http.Client{Timeout: time.Minute}}
	operator, err := tls.LoadX509KeyPair(h.Operator.CertFile, h.Operator.KeyFile)
	if err != nil {
		t.Fatal(err)
	}
	flow := &marketSupplierFlow{marketLimitsFlow: base, ctl: map[string]*supplierController{},
		attacks: &supplierAttacks{}, digests: &supplierDigests{},
		operatorHTTP: &http.Client{Timeout: time.Minute, Transport: &http.Transport{TLSClientConfig: &tls.Config{
			MinVersion: tls.VersionTLS13, RootCAs: roots, Certificates: []tls.Certificate{operator}}}}}
	runCtx, stop := context.WithCancel(t.Context())
	t.Cleanup(stop)
	features := map[string][]string{
		"supplier_a": {entitlement.FeatureMarketSell},
		"reseller_b": {entitlement.FeatureMarketSell, entitlement.FeatureMarketResell},
		"root_c":     nil,
	}
	for _, name := range []string{"supplier_a", "reseller_b", "root_c"} {
		c := h.Controllers[name]
		client, err := marketclient.New(marketclient.Config{BaseURL: h.URL, RootCAs: roots,
			ClientCertificate: marketruntime.ClientCertificate(c.CertFile, c.KeyFile),
			MarketKeys:        map[string]ed25519.PublicKey{h.KeyID: h.PublicKey}})
		if err != nil {
			t.Fatal(err)
		}
		base.clients[name] = client
		pool, _, _ := controlE2EDatabase(t, databaseURL)
		trust := marketLimitsInstallLease(t, pool, license, c.InstallationID, features[name]...)
		supplierNoticeRecipient(t, pool)
		tokens, err := identity.NewTokenManager(strings.Repeat("k", 32), time.Hour)
		if err != nil {
			t.Fatal(err)
		}
		ids, err := identity.NewService(identity.NewStore(pool), tokens, 24*time.Hour)
		if err != nil {
			t.Fatal(err)
		}
		// Every controller runs the production supply side (the grant loop syncs it, empty for B and C).
		supply := marketsupply.New(pool, ids, packagesubscription.NewService(packagesubscription.NewStore(pool)),
			marketsupply.Config{CNAMEDomain: "cdn." + strings.ReplaceAll(name, "_", "-") + ".example.net", TimeZone: "UTC"})
		supply.WithSites(site.NewService(site.NewStoreWithClock(pool, time.Now, trust)), nil)
		runtime := marketruntime.New(marketruntime.Config{DisplayName: strings.ToUpper(name[len(name)-1:]),
			CertFile: c.CertFile, KeyFile: c.KeyFile, StateDir: filepath.Join(directory, name+"-state"),
			GrantEvery: 2 * time.Second, CallTimeout: time.Minute}, pool, client, supply,
			slog.Default().With("component", "market", "controller", name))
		notices, err := notification.NewStore(pool)
		if err != nil {
			t.Fatal(err)
		}
		runtime.WithNotices(notices).WithHolds(client, supply, 2*time.Second)
		ctl := &supplierController{name: name, pool: pool, runtime: runtime, supply: supply}
		switch name {
		case "supplier_a":
			runtime.WithSecDigest(supply.WithSecurityReaders(flow.attacks, flow.attacks), nil)
			base.pool = pool
			base.leaf = runtime
			base.poolRef, base.nodeID = marketLimitsLineGroup(t, pool)
		case "root_c":
			ctl.subscribe = marketsubscribe.New(pool, client, runtime).WithDigests(client, flow.digests)
			runtime.WithSubscriptions(ctl.subscribe).WithSecDigest(nil, ctl.subscribe)
		}
		flow.ctl[name] = ctl
		go func() { _ = runtime.Run(runCtx) }()
	}
	for name, ctl := range flow.ctl {
		flow.waitFor(name+" registered", 2*time.Minute, func() bool { return ctl.runtime.Identity().MemberID != uuid.Nil })
		base.members[name] = ctl.runtime.Identity().MemberID
	}
	if err := base.clients["supplier_a"].ReportPoolNodes(t.Context(), base.poolRef, []marketclient.PoolNode{{
		NodeID: base.nodeID.String(), IP: "45.10.10.1", Region: "us", Carrier: "bgp"}}, nil); err != nil {
		t.Fatal(err)
	}
	flow.control("POST", "/admit", nil, nil)
	return flow
}

// supplierNoticeRecipient seeds the platform scope (if missing) and one console user holding both market notice
// permissions (marketplace.purchase for buyer notices, marketplace.sell for seller notices, marketruntime/notices.go).
func supplierNoticeRecipient(t *testing.T, pool *pgxpool.Pool) {
	t.Helper()
	user, role := uuid.New(), uuid.New()
	err := pgx.BeginFunc(t.Context(), pool, func(tx pgx.Tx) error {
		for _, statement := range []struct {
			query string
			args  []any
		}{
			{`INSERT INTO access_scopes (id, kind) SELECT $1,'platform' WHERE NOT EXISTS (SELECT 1 FROM access_scopes WHERE kind='platform')`, []any{uuid.New()}},
			{`INSERT INTO users(id,username,display_name,password_hash) VALUES($1,'market-supplier-console','控制台','unused')`, []any{user}},
			{`INSERT INTO memberships(scope_id,user_id) SELECT id,$1 FROM access_scopes WHERE kind='platform'`, []any{user}},
			{`INSERT INTO roles(id,scope_id,name,system_role) SELECT $1,id,'platform_owner',true FROM access_scopes WHERE kind='platform'`, []any{role}},
			{`INSERT INTO role_permissions(role_id,permission_name) VALUES($1,'marketplace.purchase'),($1,'marketplace.sell')`, []any{role}},
			{`INSERT INTO role_assignments(scope_id,user_id,role_id) SELECT id,$1,$2 FROM access_scopes WHERE kind='platform'`, []any{user, role}},
		} {
			if _, err := tx.Exec(t.Context(), statement.query, statement.args...); err != nil {
				return fmt.Errorf("%.70s: %w", statement.query, err)
			}
		}
		return nil
	})
	if err != nil {
		t.Fatal(err)
	}
}

// listAs creates and publishes one daily offer of seller over components.
func (flow *marketSupplierFlow) listAs(seller, name string, daily int64, components ...map[string]any) uuid.UUID {
	flow.t.Helper()
	offer := map[string]any{"name": name, "billing_model": "daily_bundle", "components": components,
		"allocation": map[string]any{"http_ports": 2}, "compliance": map[string]any{"require_icp": false},
		"pricing": map[string]any{"currency": "CNY", "daily_minor": daily, "min_days": 1, "max_days": 30}}
	var created marketLimitsOffer
	if status := flow.member(seller, "POST", "/v1/offers", "", offer, &created); status != http.StatusCreated {
		flow.t.Fatalf("%s creates offer %s: %d", seller, name, status)
	}
	if status := flow.member(seller, "POST", "/v1/offers/"+created.ID.String()+"/publish", "", nil, nil); status != http.StatusOK {
		flow.t.Fatalf("%s publishes offer %s: %d", seller, name, status)
	}
	return created.ID
}

func (flow *marketSupplierFlow) creditFrom(seller, buyer string, amount int64, key string) {
	flow.control("POST", "/credit", map[string]any{"Seller": seller, "Buyer": buyer, "Amount": amount, "Key": key}, nil)
}

// operator calls the market operator API (/admin/v1/*) with the operator certificate.
func (flow *marketSupplierFlow) operator(method, path, key string, body, out any) int {
	flow.t.Helper()
	var reader io.Reader
	if body != nil {
		raw, _ := json.Marshal(body)
		reader = bytes.NewReader(raw)
	}
	request, _ := http.NewRequestWithContext(flow.t.Context(), method, flow.h.AdminURL+path, reader)
	request.Header.Set("Content-Type", "application/json")
	if key != "" {
		request.Header.Set("Idempotency-Key", key)
	}
	response, err := flow.operatorHTTP.Do(request)
	if err != nil {
		flow.t.Fatalf("operator %s %s: %v", method, path, err)
	}
	defer response.Body.Close()
	raw, _ := io.ReadAll(response.Body)
	if response.StatusCode >= 300 {
		flow.t.Logf("operator %s %s: %d %s", method, path, response.StatusCode, raw)
	} else if out != nil {
		if err := json.Unmarshal(raw, out); err != nil {
			flow.t.Fatalf("operator %s: %s", path, raw)
		}
	}
	return response.StatusCode
}

type supplierNotice struct {
	Kind   string            `json:"kind"`
	Values map[string]string `json:"values"`
}

// notices returns the market notices queued to one member, of one kind.
func (flow *marketSupplierFlow) notices(member, kind string) []supplierNotice {
	flow.t.Helper()
	var all []supplierNotice
	flow.control("GET", "/notices?member="+member, nil, &all)
	var out []supplierNotice
	for _, n := range all {
		if n.Kind == kind {
			out = append(out, n)
		}
	}
	return out
}

// events counts the notification center events of kind in one controller (the relayed notice landed there).
func (flow *marketSupplierFlow) events(name, kind string) int {
	flow.t.Helper()
	var n int
	if err := flow.ctl[name].pool.QueryRow(flow.t.Context(), `SELECT count(*) FROM notification_events WHERE event_type=$1`,
		kind).Scan(&n); err != nil {
		flow.t.Fatal(err)
	}
	return n
}

// leafLocal is A's local package subscription of one grant path (market_supply_limits row keyed by HoldKey).
func (flow *marketSupplierFlow) leafLocal(path []uuid.UUID) uuid.UUID {
	flow.t.Helper()
	key := marketsupply.HoldKey(path, flow.poolRef)
	var local uuid.UUID
	flow.waitFor("A synced grant "+key, time.Minute, func() bool {
		return flow.pool.QueryRow(flow.t.Context(), `SELECT package_subscription_id FROM market_supply_limits
			WHERE market_key=$1`, key).Scan(&local) == nil
	})
	return local
}

// seedRootSite creates C's own tenant site (the console's site, before it is put on a market supply).
func seedRootSite(t *testing.T, pool *pgxpool.Pool, domain string) uuid.UUID {
	t.Helper()
	tenant, user, siteID := uuid.New(), uuid.New(), uuid.New()
	err := pgx.BeginFunc(t.Context(), pool, func(tx pgx.Tx) error {
		for _, statement := range []struct {
			query string
			args  []any
		}{
			{`INSERT INTO tenants(id,display_name) VALUES($1,'C 的租户')`, []any{tenant}},
			{`INSERT INTO access_scopes(id,kind,tenant_id) VALUES($1,'tenant',$1)`, []any{tenant}},
			{`INSERT INTO users(id,username,display_name,password_hash) VALUES($1,'root-c-owner','C','unused')`, []any{user}},
			{`INSERT INTO memberships(scope_id,user_id) VALUES($1,$2)`, []any{tenant, user}},
			{`INSERT INTO sites(id,scope_id,owner_user_id,domain,origins,origin_hosts,created_by_user_id,updated_by_user_id,display_id)
			  VALUES($1,$2,$3,$4,ARRAY['198.51.100.10:80'],ARRAY['198.51.100.10'],$3,$3,1)`, []any{siteID, tenant, user, domain}},
			{`INSERT INTO site_origin_pools(site_id) VALUES($1)`, []any{siteID}},
			{`INSERT INTO site_origins(site_id,position,host,port) VALUES($1,1,'198.51.100.10',80)`, []any{siteID}},
		} {
			if _, err := tx.Exec(t.Context(), statement.query, statement.args...); err != nil {
				return fmt.Errorf("%.70s: %w", statement.query, err)
			}
		}
		return nil
	})
	if err != nil {
		t.Fatal(err)
	}
	return siteID
}

// containsAny reports whether raw mentions any of the secrets.
func containsAny(raw []byte, secrets ...string) string {
	for _, s := range secrets {
		if s != "" && bytes.Contains(raw, []byte(s)) {
			return s
		}
	}
	return ""
}

func (flow *marketSupplierFlow) run() {
	t := flow.t
	a, b, c := flow.members["supplier_a"], flow.members["reseller_b"], flow.members["root_c"]

	// ① A lists its line group; B buys it with a direct top-up and resells it; C buys B's resale.
	oa := flow.listAs("supplier_a", "A 线路组", 100, map[string]any{"kind": "own_pool", "node_pool_ref": flow.poolRef})
	if status := flow.member("reseller_b", "POST", "/v1/subscriptions", "", map[string]any{"offer_id": oa, "days": 10,
		"idempotency_key": "b-unfunded"}, nil); status != http.StatusPaymentRequired {
		t.Fatalf("B buys before the direct top-up: %d, want 402", status)
	}
	flow.creditFrom("supplier_a", "reseller_b", 5_000, "ab-topup")
	s1 := flow.buy("reseller_b", oa, 10, "b-buys-a")
	ob := flow.listAs("reseller_b", "B 转售", 150, map[string]any{"kind": "upstream", "subscription_id": s1})
	flow.creditFrom("reseller_b", "root_c", 5_000, "bc-topup")
	s2 := flow.buy("root_c", ob, 3, "c-buys-b")
	var balance struct {
		BalanceMinor int64 `json:"balance_minor"`
	}
	flow.member("reseller_b", "GET", fmt.Sprintf("/v1/ledger/balance?buyer_id=%s&seller_id=%s&currency=CNY", b, a), "", nil, &balance)
	if balance.BalanceMinor != 5_000-10*100 {
		t.Fatalf("B's balance with A after 10 days at 100: %d", balance.BalanceMinor)
	}
	flow.member("root_c", "GET", fmt.Sprintf("/v1/ledger/balance?buyer_id=%s&seller_id=%s&currency=CNY", c, b), "", nil, &balance)
	if balance.BalanceMinor != 5_000-3*150 {
		t.Fatalf("C's balance with B after 3 days at 150: %d", balance.BalanceMinor)
	}
	// A serves C's root through B's subscription: grant path [s2, s1]; A only learns a downstream number.
	chain := []uuid.UUID{s2, s1}
	localC, localB := flow.leafLocal(chain), flow.leafLocal([]uuid.UUID{s1})
	grants, _, err := flow.clients["supplier_a"].Grants(t.Context(), a)
	if err != nil {
		t.Fatal(err)
	}
	var downstream string
	for _, g := range grants {
		if len(g.SubscriptionPath) == 2 && g.SubscriptionPath[0] == s2 {
			downstream = g.DownstreamRef
		}
	}
	if !strings.HasPrefix(downstream, "d-") {
		t.Fatalf("A's grant for C carries no downstream number: %+v", grants)
	}
	flow.expectServing("root_c", s2, "C bought B's resale")
	t.Logf("PASS ① A listed %s; B paid by direct top-up (balance 4000) and resells as %s; C bought it (balance 4550); A synced"+
		" path [C,B] as local %s (downstream %s) next to B's own %s", oa, ob, localC, downstream, localB)

	// ② §18.2 visibility: A sees B as its direct subscriber and C only as a downstream number via B; B sees C.
	type subscribers struct {
		Items []struct {
			Relation      string     `json:"relation"`
			BuyerID       *uuid.UUID `json:"buyer_id"`
			BuyerName     *string    `json:"buyer_name"`
			DownstreamRef string     `json:"downstream_ref"`
			ViaName       *string    `json:"via_name"`
		} `json:"items"`
	}
	var ofA, ofB subscribers
	flow.member("supplier_a", "GET", "/v1/seller/subscribers?offer_id="+oa.String(), "", nil, &ofA)
	flow.member("reseller_b", "GET", "/v1/seller/subscribers?offer_id="+ob.String(), "", nil, &ofB)
	relations := map[string]int{}
	for _, row := range ofA.Items {
		relations[row.Relation]++
		switch row.Relation {
		case "direct":
			if row.BuyerID == nil || *row.BuyerID != b {
				t.Fatalf("A's direct row is not B: %+v", row)
			}
		case "downstream":
			if row.BuyerID != nil || row.BuyerName != nil || row.DownstreamRef != downstream || row.ViaName == nil || *row.ViaName != "B" {
				t.Fatalf("A's downstream row: %+v (want only %s via B)", row, downstream)
			}
		}
	}
	if relations["direct"] != 1 || relations["downstream"] != 1 {
		t.Fatalf("A's subscribers: %+v", ofA.Items)
	}
	if len(ofB.Items) != 1 || ofB.Items[0].Relation != "direct" || ofB.Items[0].BuyerID == nil || *ofB.Items[0].BuyerID != c {
		t.Fatalf("B's subscribers: %+v", ofB.Items)
	}
	t.Log("PASS ② visibility a: A sees B direct and C only as " + downstream + " via B; B sees C direct")

	// ③ C puts its own site on the supply: the production subscriber service relays prepare/commit to A, which
	// creates the site on its line group in a market tenant.
	cc := flow.ctl["root_c"]
	domain := "www.root-c.example.com"
	siteC := seedRootSite(t, cc.pool, domain)
	var supplyID uuid.UUID
	flow.waitFor("C synced its supply target", time.Minute, func() bool {
		return cc.pool.QueryRow(t.Context(), `SELECT id FROM site_supplies WHERE market_subscription_id=$1
			AND jsonb_array_length(leaves)=1`, s2).Scan(&supplyID) == nil
	})
	if err := cc.subscribe.Bind(t.Context(), siteC, supplyID, "primary", 0); err != nil {
		t.Fatal(err)
	}
	result, err := cc.subscribe.Apply(t.Context(), siteC, 1, siteconf.Config{Schema: siteconf.SchemaV1, Domains: []string{domain},
		HTTPPorts: []int{80}, Origins: []siteconf.Origin{{Host: "198.51.100.10", Port: 80}}})
	if err != nil || !result.Applied || len(result.Leaves) != 1 || result.Leaves[0].Leaf.LeafMemberID != a {
		t.Fatalf("C applies its site through the relay: %+v %v", result, err)
	}
	var leafSite, leafTenant uuid.UUID
	var leafGroup *uuid.UUID
	var tenantUser string
	if err := flow.pool.QueryRow(t.Context(), `SELECT site.id, scope.tenant_id, site.node_group_id, account.username FROM sites site
		JOIN access_scopes scope ON scope.id=site.scope_id AND scope.kind='tenant'
		JOIN memberships membership ON membership.scope_id=scope.id
		JOIN users account ON account.id=membership.user_id AND account.username LIKE 'mkt-%'
		WHERE site.domain=$1 AND site.deleted_at IS NULL`, domain).Scan(&leafSite, &leafTenant, &leafGroup, &tenantUser); err != nil {
		t.Fatalf("C's site on A: %v", err)
	}
	if leafGroup == nil || leafGroup.String() != flow.poolRef || tenantUser != "mkt-"+marketsupply.HoldKey(chain, flow.poolRef) {
		t.Fatalf("C's site on A: group %v tenant %s (pool %s)", leafGroup, tenantUser, flow.poolRef)
	}
	t.Logf("PASS ③ C's site %s committed through the relay to A: leaf site %s on A's line group in tenant %s", domain, leafSite, tenantUser)

	// ④ attack digest of A's market site: sealed to C, bound to C's site; B only learns that its subscriber was attacked.
	flow.attacks.arm(leafTenant, leafSite, domain)
	flow.waitFor("C received A's attack digest", 3*time.Minute, func() bool { return len(flow.digests.all()) > 0 })
	got := flow.digests.all()[0]
	if got.SiteID != siteC || got.SupplyID != supplyID || got.LeafMemberID != a || got.Digest.LeafSiteID != leafSite ||
		got.Digest.Summary.Blocked != 3 || len(got.Digest.Logs) != 1 || got.Digest.Logs[0].Path != "/login" || len(got.Digest.Actions) != 1 {
		t.Fatalf("C's stored digest: %+v", got)
	}
	var attacked []supplierNotice
	flow.waitFor("B told of the downstream attack", time.Minute, func() bool {
		attacked = flow.notices("reseller_b", "market.downstream.attacked")
		return len(attacked) == 1 && flow.events("reseller_b", "market.downstream.attacked") >= 1
	})
	raw, _ := json.Marshal(attacked)
	if attacked[0].Values["subscription"] != s2.String() || containsAny(raw, "203.0.113.9", "/login", leafSite.String(), "942100") != "" {
		t.Fatalf("B's notice: %s", raw)
	}
	if n := flow.notices("supplier_a", "market.downstream.attacked"); len(n) != 0 {
		t.Fatalf("the leaf is not told of its own site: %+v", n)
	}
	t.Logf("PASS ④ digest of window %d reached C on site %s (supply %s, 3 blocked, 1 log, 1 action); B got only"+
		" market.downstream.attacked for %s (in its notification center); A none", flow.attacks.served(), siteC, supplyID, s2)

	flow.complaint(oa, s1, s2, downstream, domain, localB, localC)
}

// complaint is ⑤–⑦: A files a stop complaint on the downstream number, the operator sees through to C and stops
// it on A's supply, A's hold loop stops C's share only, every party on the path is told, the release restores it.
func (flow *marketSupplierFlow) complaint(oa, s1, s2 uuid.UUID, downstream, domain string, localB, localC uuid.UUID) {
	t := flow.t
	a, b, c := flow.members["supplier_a"], flow.members["reseller_b"], flow.members["root_c"]
	var filed struct {
		ID        uuid.UUID `json:"id"`
		TargetRef string    `json:"target_ref"`
		State     string    `json:"state"`
	}
	if status := flow.member("supplier_a", "POST", "/v1/supply-complaints", "", map[string]any{"offer_id": oa,
		"target_ref": downstream, "category": "attack_source", "detail": "该下游站点持续被攻击，节点 IP 被上游封禁",
		"evidence": map[string]any{"domains": []string{domain}}}, &filed); status != http.StatusCreated {
		t.Fatalf("A files on %s: %d", downstream, status)
	}
	var mine struct {
		Items []json.RawMessage `json:"items"`
	}
	flow.member("supplier_a", "GET", "/v1/supply-complaints", "", nil, &mine)
	raw, _ := json.Marshal(mine)
	if filed.TargetRef != downstream || filed.State != "open" || len(mine.Items) != 1 ||
		containsAny(raw, s2.String(), c.String(), `"C"`) != "" {
		t.Fatalf("A's view of its complaint leaks the root or is wrong: %+v %s", filed, raw)
	}
	t.Logf("PASS ⑤ A filed %s on %s; A's view carries no root subscription or member", filed.ID, downstream)

	// The operator sees through: the real root C, the hop A sold (B's s1), the chain and C's domain.
	var detail struct {
		RootSubscription uuid.UUID `json:"root_subscription_id"`
		HopSubscription  uuid.UUID `json:"hop_subscription_id"`
		RootBuyer        struct {
			ID   uuid.UUID `json:"id"`
			Name string    `json:"name"`
		} `json:"root_buyer"`
		Chain []struct {
			SubscriptionID uuid.UUID `json:"subscription_id"`
			Seller         struct {
				ID uuid.UUID `json:"id"`
			} `json:"seller"`
		} `json:"chain"`
		Domains []string `json:"domains"`
	}
	if status := flow.operator("GET", "/admin/v1/supply-complaints/"+filed.ID.String(), "", nil, &detail); status != http.StatusOK {
		t.Fatalf("operator detail: %d", status)
	}
	if detail.RootSubscription != s2 || detail.RootBuyer.ID != c || detail.RootBuyer.Name != "C" || detail.HopSubscription != s1 ||
		len(detail.Chain) != 2 || detail.Chain[0].SubscriptionID != s2 || detail.Chain[0].Seller.ID != b ||
		detail.Chain[1].SubscriptionID != s1 || detail.Chain[1].Seller.ID != a || len(detail.Domains) != 1 || detail.Domains[0] != domain {
		t.Fatalf("operator see-through: %+v", detail)
	}
	var resolved struct {
		State string `json:"state"`
		Holds []struct {
			Action       string    `json:"action"`
			LeafMemberID uuid.UUID `json:"leaf_member_id"`
			NodePoolRef  string    `json:"node_pool_ref"`
		} `json:"holds"`
	}
	if status := flow.operator("POST", "/admin/v1/supply-complaints/"+filed.ID.String()+"/resolve", "resolve-"+filed.ID.String(),
		map[string]any{"action": "stop", "note": "核实属实，停止该下游在 A 上的服务"}, &resolved); status != http.StatusOK {
		t.Fatalf("operator resolves: %d", status)
	}
	if resolved.State != "actioned" || len(resolved.Holds) != 1 || resolved.Holds[0].Action != "stop" ||
		resolved.Holds[0].LeafMemberID != a || resolved.Holds[0].NodePoolRef != flow.poolRef {
		t.Fatalf("resolved: %+v", resolved)
	}
	if holds := flow.holds(s2); holds["operator"] != "stop" {
		t.Fatalf("operator hold on the root subscription %s: %v", s2, holds)
	}
	if holds := flow.holds(s1); len(holds) != 0 {
		t.Fatalf("B's own subscription must not be held: %v", holds)
	}
	if got := flow.state(s2); got != "stopped" {
		t.Fatalf("C's slot after the stop: %s", got)
	}
	if got := flow.state(s1); got != "serving" {
		t.Fatalf("B's own slot after C's stop: %s", got)
	}
	t.Logf("PASS ⑥ operator saw root C (%s) through [C→B, B→A] and stopped it on A: hold operator:stop on root %s only", c, s2)

	// A's hold loop applies the stop to C's share only (its local subscription of path [C,B]); B's stays.
	flow.waitFor("A applies the operator stop", time.Minute, func() bool {
		hold, stopped := flow.leafLimits(localC)
		return hold == "stop" && stopped
	})
	if hold, stopped := flow.leafLimits(localB); hold != "" || stopped {
		t.Fatalf("B's share on A: hold %q stopped %v", hold, stopped)
	}
	// Every party on the path is told, each in its own terms, and the notices reach the notification centers.
	want := []struct{ member, kind, key, value string }{
		{"supplier_a", "market.complaint.resolved", "target", downstream},
		{"root_c", "market.complaint.actioned", "subscription", s2.String()},
		{"reseller_b", "market.complaint.actioned", "target", s2.String()},
	}
	for _, w := range want {
		var got []supplierNotice
		flow.waitFor(w.member+" told "+w.kind, time.Minute, func() bool {
			got = flow.notices(w.member, w.kind)
			return len(got) == 1 && flow.events(w.member, w.kind) == 1
		})
		if got[0].Values[w.key] != w.value || got[0].Values["outcome"] != "stop" {
			t.Fatalf("%s %s: %+v", w.member, w.kind, got[0].Values)
		}
	}
	raw, _ = json.Marshal(flow.notices("supplier_a", "market.complaint.resolved"))
	if leak := containsAny(raw, s2.String(), c.String()); leak != "" {
		t.Fatalf("A's outcome notice leaks %s: %s", leak, raw)
	}
	t.Log("PASS ⑥ A's hold loop stopped C's share only (B's share serving); A told resolved/stop on " + downstream +
		", C actioned on its subscription, B actioned on its subscriber; all three in the notification centers")

	// Release: the hold is lifted, A restores C's share, A is told.
	if status := flow.operator("POST", "/admin/v1/supply-complaints/"+filed.ID.String()+"/release", "release-"+filed.ID.String(),
		map[string]any{"note": "整改完成"}, nil); status != http.StatusOK {
		t.Fatalf("operator releases: %d", status)
	}
	flow.waitFor("A restores C's share", time.Minute, func() bool {
		hold, stopped := flow.leafLimits(localC)
		return hold == "" && !stopped
	})
	if got := flow.state(s2); got != "serving" {
		t.Fatalf("C after the release: %s", got)
	}
	flow.waitFor("A told of the release", time.Minute, func() bool {
		n := flow.notices("supplier_a", "market.complaint.resolved")
		return len(n) == 2 && n[1].Values["outcome"] == "released"
	})
	t.Log("PASS ⑦ release: operator hold lifted, A restored C's share, C serving, A told released")
}
