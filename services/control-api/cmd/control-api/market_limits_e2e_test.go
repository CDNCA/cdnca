//go:build integration

package main

// Control half of tests/market-limits-e2e/run.sh (ADR 0012 ML-14). Three controllers talk to the market process
// (services/market-service internal/httpapi TestMarketLimitsMarketProcess) over mTLS with the production
// marketclient: the leaf seller A (its own migrated schema, its lease installed, the production marketsupply and
// marketruntime with the hold loop and the usage loop; the usage source is a stand-in for ClickHouse) and the
// subscribers B and C (members only: they list, buy and read supply targets with their own certificates and leases).
//
// Flow: A reports its pool node and lists two offers on its line group; B and C get a direct top-up and buy.
// ① daily offer with a QPS limit (pause, 2 buckets): B's reported peak stays at the cap → B paused, C keeps serving;
//    two buckets below 80% → B resumes. The leaf's hold loop sees no stop (pause only stops scheduling, §7.4).
// ② traffic offer, B's prepaid runs out → prepaid hold pause, then the overdraft cap; a top-up releases at once.
// ③ prepaid stop (daily offer with prepaid_exhausted_action=stop, renewal unpaid) → the leaf applies the stop hold
//    (market_supply_limits.node_stopped, one system republication), top-up → released, node share restored.
// ④ node overload: two minutes over the threshold remove the node from the supply (overloaded), five minutes below
//    restore it.
// C, on the same offers, is checked after every step: never paused, stopped or overloaded by B's events.

import (
	"bytes"
	"context"
	"crypto/ed25519"
	"crypto/sha256"
	"encoding/base64"
	"encoding/json"
	"fmt"
	"io"
	"log/slog"
	"net/http"
	"os"
	"path/filepath"
	"slices"
	"strings"
	"testing"
	"time"

	"github.com/cdnca/cdnca/libs/entitlement"
	"github.com/cdnca/cdnca/libs/marketproto/nodeload"
	"github.com/cdnca/cdnca/libs/marketproto/usage"
	"github.com/cdnca/cdnca/services/control-api/internal/entitlementguard"
	"github.com/cdnca/cdnca/services/control-api/internal/identity"
	"github.com/cdnca/cdnca/services/control-api/internal/marketclient"
	"github.com/cdnca/cdnca/services/control-api/internal/marketruntime"
	"github.com/cdnca/cdnca/services/control-api/internal/marketsupply"
	"github.com/cdnca/cdnca/services/control-api/internal/packagesubscription"
	"github.com/google/uuid"
	"github.com/jackc/pgx/v5"
	"github.com/jackc/pgx/v5/pgxpool"
	"golang.org/x/crypto/curve25519"
)

type marketLimitsHandoff struct {
	URL          string                            `json:"url"`
	AdminURL     string                            `json:"admin_url"`
	CAFile       string                            `json:"ca_file"`
	ControlURL   string                            `json:"control_url"`
	KeyID        string                            `json:"key_id"`
	PublicKey    []byte                            `json:"public_key"`
	LicenseKeyID string                            `json:"license_key_id"`
	LicenseSeed  []byte                            `json:"license_seed"`
	Controllers  map[string]marketLimitsController `json:"controllers"`
	Operator     marketLimitsController            `json:"operator"`
}

type marketLimitsController struct {
	InstallationID uuid.UUID `json:"installation_id"`
	CertFile       string    `json:"cert_file"`
	KeyFile        string    `json:"key_file"`
}

type marketLimitsLicense struct {
	id  string
	key ed25519.PrivateKey
}

func (l marketLimitsLicense) KeyID() string { return l.id }
func (l marketLimitsLicense) Sign(_ context.Context, payload []byte) ([]byte, error) {
	return ed25519.Sign(l.key, payload), nil
}

// lease signs a 30-day control lease (30 days grace: ③ moves the market clock by days) for installation with the market features (sites.manage for the leaf's
// own site store).
func (l marketLimitsLicense) lease(t *testing.T, installation uuid.UUID, serial uint64, sell bool) []byte {
	t.Helper()
	if sell {
		return l.leaseWith(t, installation, serial, entitlement.FeatureMarketSell)
	}
	return l.leaseWith(t, installation, serial)
}

// leaseWith is lease with extra feature codes (market.sell, market.resell).
func (l marketLimitsLicense) leaseWith(t *testing.T, installation uuid.UUID, serial uint64, extra ...string) []byte {
	t.Helper()
	now := time.Now().UTC().Truncate(time.Second)
	features := []entitlement.Feature{{Code: entitlement.FeatureMarketParticipate}, {Code: entitlementguard.FeatureSitesManage}}
	for _, code := range extra {
		features = append(features, entitlement.Feature{Code: code})
	}
	quotas := []entitlement.Quota{{Code: entitlement.QuotaMarketOffersCount, Limit: 5},
		{Code: entitlementguard.QuotaDomainsCount, Limit: 100}}
	// Signed leases list features and quotas in code order.
	slices.SortFunc(features, func(a, b entitlement.Feature) int { return strings.Compare(a.Code, b.Code) })
	slices.SortFunc(quotas, func(a, b entitlement.Quota) int { return strings.Compare(a.Code, b.Code) })
	signed, err := entitlement.Sign(t.Context(), entitlement.Lease{Schema: entitlement.SchemaV1,
		Audience: entitlement.ControlAudience, CustomerID: "11111111-1111-4111-8111-111111111111",
		InstallationID: installation.String(), LicenseID: "33333333-3333-4333-8333-333333333333", Serial: serial,
		NotBefore: now.Add(-time.Minute).Unix(), ExpiresAt: now.Add(30 * 24 * time.Hour).Unix(),
		GraceUntil: now.Add(60 * 24 * time.Hour).Unix(),
		Version:    entitlement.VersionRange{Channel: "stable", Min: "0.1.0", Max: "9.0.0"},
		Features:   features, Quotas: quotas,
	}, l)
	if err != nil {
		t.Fatal(err)
	}
	encoded, err := signed.Encode()
	if err != nil {
		t.Fatal(err)
	}
	return encoded
}

type marketLimitsFlow struct {
	t       *testing.T
	h       marketLimitsHandoff
	pool    *pgxpool.Pool // the leaf's schema
	clients map[string]*marketclient.Client
	members map[string]uuid.UUID
	leaf    *marketruntime.Runtime
	supply  *marketsupply.Service
	http    *http.Client
	poolRef string
	nodeID  uuid.UUID
}

func TestMarketLimitsControlProcess(t *testing.T) {
	directory := os.Getenv("MARKET_LIMITS_E2E_DIR")
	databaseURL := strings.TrimSpace(os.Getenv("TEST_DATABASE_URL"))
	if directory == "" || databaseURL == "" {
		t.Skip("MARKET_LIMITS_E2E_DIR and TEST_DATABASE_URL are required; run tests/market-limits-e2e/run.sh")
	}
	flow := startMarketLimits(t, directory, databaseURL)
	defer flow.done()
	flow.run()
}

func startMarketLimits(t *testing.T, directory, databaseURL string) *marketLimitsFlow {
	t.Helper()
	var h marketLimitsHandoff
	waitJSONFile(t, filepath.Join(directory, "market.json"), &h)
	// The controllers trust the market's test CA through the production root pool hook (runtime.go RootCAs).
	t.Setenv(marketruntime.MarketCAFileEnv, h.CAFile)
	roots, err := marketruntime.RootCAs()
	if err != nil {
		t.Fatal(err)
	}
	license := marketLimitsLicense{id: h.LicenseKeyID, key: ed25519.NewKeyFromSeed(h.LicenseSeed)}
	flow := &marketLimitsFlow{t: t, h: h, clients: map[string]*marketclient.Client{}, members: map[string]uuid.UUID{},
		http: &http.Client{Timeout: time.Minute}}
	for name, c := range h.Controllers {
		client, err := marketclient.New(marketclient.Config{BaseURL: h.URL, RootCAs: roots,
			ClientCertificate: marketruntime.ClientCertificate(c.CertFile, c.KeyFile),
			MarketKeys:        map[string]ed25519.PublicKey{h.KeyID: h.PublicKey}})
		if err != nil {
			t.Fatal(err)
		}
		flow.clients[name] = client
	}

	// Leaf A: a migrated control schema with its lease installed (marketruntime registers with the current lease).
	pool, _, _ := controlE2EDatabase(t, databaseURL)
	flow.pool = pool
	marketLimitsInstallLease(t, pool, license, h.Controllers["leaf"].InstallationID, entitlement.FeatureMarketSell)
	tokens, err := identity.NewTokenManager(strings.Repeat("k", 32), time.Hour)
	if err != nil {
		t.Fatal(err)
	}
	ids, err := identity.NewService(identity.NewStore(pool), tokens, 24*time.Hour)
	if err != nil {
		t.Fatal(err)
	}
	flow.supply = marketsupply.New(pool, ids, packagesubscription.NewService(packagesubscription.NewStore(pool)),
		marketsupply.Config{TimeZone: "UTC"})
	// A's supply pool: one platform line group with one serving node (the market only schedules admitted nodes).
	flow.poolRef, flow.nodeID = marketLimitsLineGroup(t, pool)
	leafCert := h.Controllers["leaf"]
	flow.leaf = marketruntime.New(marketruntime.Config{DisplayName: "A", CertFile: leafCert.CertFile, KeyFile: leafCert.KeyFile,
		StateDir: filepath.Join(directory, "leaf-state"), GrantEvery: 2 * time.Second}, pool, flow.clients["leaf"], flow.supply,
		slog.Default().With("component", "market"))
	flow.leaf.WithHolds(flow.clients["leaf"], flow.supply, 2*time.Second)
	runCtx, stop := context.WithCancel(t.Context())
	t.Cleanup(stop)
	go func() { _ = flow.leaf.Run(runCtx) }()
	flow.waitFor("leaf registered", 2*time.Minute, func() bool { return flow.leaf.Identity().MemberID != uuid.Nil })
	flow.members["leaf"] = flow.leaf.Identity().MemberID

	// Subscribers B and C register with their own leases (the console's market membership).
	for serial, name := range []string{"buyer_b", "buyer_c"} {
		id := marketLimitsIdentity(t)
		member, err := flow.clients[name].Register(t.Context(), id, license.lease(t, h.Controllers[name].InstallationID,
			uint64(serial+10), false), strings.ToUpper(name[len(name)-1:]))
		if err != nil {
			t.Fatalf("register %s: %v", name, err)
		}
		flow.members[name] = member
	}
	if err := flow.clients["leaf"].ReportPoolNodes(t.Context(), flow.poolRef, []marketclient.PoolNode{{
		NodeID: flow.nodeID.String(), IP: "45.10.10.1", Region: "us", Carrier: "bgp"}}, nil); err != nil {
		t.Fatal(err)
	}
	flow.control("POST", "/admit", nil, nil)
	return flow
}

func (flow *marketLimitsFlow) done() { flow.control("POST", "/done", nil, nil) }

func marketLimitsIdentity(t *testing.T) marketclient.Identity {
	t.Helper()
	_, signing, _ := ed25519.GenerateKey(nil)
	box := make([]byte, 32)
	copy(box, signing.Seed())
	public, err := curve25519.X25519(box, curve25519.Basepoint)
	if err != nil {
		t.Fatal(err)
	}
	return marketclient.Identity{SigningKey: signing, BoxPrivate: box, BoxPublic: public}
}

// marketLimitsInstallLease installs a controller's signed lease (market.participate, sites.manage and features) the way entitlement sync does (keyset LKG, revocation
// set, lease) with the test license key as the trusted signing key.
func marketLimitsInstallLease(t *testing.T, pool *pgxpool.Pool, license marketLimitsLicense, installation uuid.UUID,
	features ...string,
) *entitlementguard.TrustStore {
	t.Helper()
	now := time.Now().UTC().Truncate(time.Second)
	public := license.key.Public().(ed25519.PublicKey)
	notBefore, until := now.Add(-time.Hour), now.Add(24*time.Hour)
	trust, err := entitlementguard.NewTrustStore([]entitlementguard.VerificationKey{{KeyID: license.id, PublicKey: public,
		NotBefore: notBefore, SignUntil: &until, VerifyUntil: &until}})
	if err != nil {
		t.Fatal(err)
	}
	fingerprint := sha256.Sum256(public)
	payload := []byte(fmt.Sprintf(`{"schema":"cdnca.signing-keyset/v2","active_key_id":%q,"keys":[{"key_id":%q,"algorithm":"Ed25519","public_key":%q,"fingerprint":%q,"status":"active","not_before":%q,"sign_until":%q,"verify_until":%q}],"rotations":[]}`,
		license.id, license.id, base64.RawURLEncoding.EncodeToString(public), base64.RawURLEncoding.EncodeToString(fingerprint[:]),
		notBefore.Format(time.RFC3339Nano), until.Format(time.RFC3339Nano), until.Format(time.RFC3339Nano)))
	digest := sha256.Sum256(payload)
	for _, statement := range []struct {
		query string
		args  []any
	}{
		{`INSERT INTO entitlement_signing_keyset_lkg(singleton,schema_version,etag,active_key_id,chain_depth,payload,
			payload_sha256,accepted_at,updated_at) VALUES(true,'cdnca.signing-keyset/v2',$1,$2,1,$3,$4,$5,$5)`,
			[]any{`"` + base64.RawURLEncoding.EncodeToString(digest[:]) + `"`, license.id, payload, digest[:], now}},
		{`INSERT INTO entitlement_signing_keyset_current_keys(key_id,public_key,status,not_before,sign_until,verify_until,
			keyset_payload_sha256,accepted_at) VALUES($1,$2,'active',$3,$4,$4,$5,$6)`,
			[]any{license.id, public, notBefore, until, digest[:], now}},
	} {
		if _, err := pool.Exec(t.Context(), statement.query, statement.args...); err != nil {
			t.Fatal(err)
		}
	}
	issuedAt := now.Add(-time.Minute)
	revocation, err := entitlement.SignRevocationSet(t.Context(), entitlement.RevocationSet{
		Schema: entitlement.RevocationSetSchemaV2, Audience: entitlement.RevocationSetAudience,
		CustomerID: "11111111-1111-4111-8111-111111111111", InstallationID: installation.String(),
		LicenseID: "33333333-3333-4333-8333-333333333333", Revision: 1, IssuedAt: issuedAt.Unix(),
		ExpiresAt: issuedAt.Add(entitlement.RevocationSetWindow).Unix(), RevokedSerials: []uint64{},
	}, license, entitlement.RevocationKeyWindow{NotBefore: notBefore, SignUntil: &until, VerifyUntil: &until})
	if err != nil {
		t.Fatal(err)
	}
	artifact, err := revocation.Encode()
	if err != nil {
		t.Fatal(err)
	}
	if _, err := entitlementguard.NewRevocationService(pool, trust).Accept(t.Context(), artifact, now); err != nil {
		t.Fatal(err)
	}
	signed, err := entitlement.Decode(license.leaseWith(t, installation, 1, features...))
	if err != nil {
		t.Fatal(err)
	}
	if _, err := entitlementguard.NewService(pool, trust).Install(t.Context(), entitlementguard.InstallBundle{
		InstallationID: installation.String(), SignedLease: signed}, now); err != nil {
		t.Fatal(err)
	}
	return trust
}

// marketLimitsLineGroup creates the leaf's platform line group with one serving node (sealed revision, healthy
// endpoint), the pool a market offer names by its ID.
func marketLimitsLineGroup(t *testing.T, pool *pgxpool.Pool) (string, uuid.UUID) {
	t.Helper()
	group, node, endpoint, user := uuid.New(), uuid.New(), uuid.New(), uuid.New()
	err := pgx.BeginFunc(t.Context(), pool, func(tx pgx.Tx) error {
		for _, statement := range []struct {
			query string
			args  []any
		}{
			{`INSERT INTO access_scopes (id, kind) SELECT $1,'platform' WHERE NOT EXISTS (SELECT 1 FROM access_scopes WHERE kind='platform')`, []any{uuid.New()}},
			{`INSERT INTO users(id,username,display_name,password_hash) VALUES($1,'market-limits-ops','运营','unused')`, []any{user}},
			{`INSERT INTO memberships(scope_id,user_id) SELECT id,$1 FROM access_scopes WHERE kind='platform'`, []any{user}},
			{`INSERT INTO nodes(id,scope_id,name,admin_state,created_by_user_id,display_id)
			  SELECT $1,id,'market-node','active',$2,(SELECT COALESCE(max(display_id),0)+1 FROM nodes) FROM access_scopes WHERE kind='platform'`, []any{node, user}},
			{`INSERT INTO node_line_groups(id,tenant_scope_id,name,current_revision,created_by_user_id,updated_by_user_id,created_at,updated_at)
			  SELECT $1,id,'market-pool',1,$2,$2,now(),now() FROM access_scopes WHERE kind='platform'`, []any{group, user}},
			{`INSERT INTO node_line_group_revisions(line_group_id,tenant_scope_id,revision,name,resolved_value,probe_interval_ms,probe_timeout_ms,
			  failure_threshold,recovery_threshold,failure_debounce_ms,recovery_debounce_ms,endpoint_count,configuration_digest,created_by_user_id,created_at)
			  SELECT $1,id,1,'market-pool','lg-'||replace($1::uuid::text,'-',''),10000,3000,3,3,0,0,1,$2,$3,now() FROM access_scopes WHERE kind='platform'`,
				[]any{group, make([]byte, 32), user}},
			{`INSERT INTO node_line_endpoints(id,node_id,tenant_scope_id,line_group_id,config_revision,address,address_family,port,region,carrier,priority,weight,enabled)
			  SELECT $1,$2,id,$3,1,'45.10.10.1',4,80,'','',0,1,true FROM access_scopes WHERE kind='platform'`, []any{endpoint, node, group}},
			{`INSERT INTO node_line_endpoint_health(tenant_scope_id,line_group_id,config_revision,endpoint_id,status,consecutive_successes,
			  consecutive_failures,last_sequence,last_changed_at,row_revision,created_at,updated_at)
			  SELECT id,$1,1,$2,'unknown',0,0,0,now(),1,now(),now() FROM access_scopes WHERE kind='platform'`, []any{group, endpoint}},
			{`UPDATE node_line_group_revisions SET sealed_at=now() WHERE line_group_id=$1`, []any{group}},
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
	return group.String(), node
}

// control calls the market process's loopback control endpoint.
func (flow *marketLimitsFlow) control(method, path string, body, out any) {
	flow.t.Helper()
	var reader io.Reader
	if body != nil {
		raw, _ := json.Marshal(body)
		reader = bytes.NewReader(raw)
	}
	request, _ := http.NewRequest(method, flow.h.ControlURL+path, reader)
	response, err := flow.http.Do(request)
	if err != nil {
		flow.t.Fatalf("market control %s: %v", path, err)
	}
	defer response.Body.Close()
	raw, _ := io.ReadAll(response.Body)
	if response.StatusCode != http.StatusOK {
		flow.t.Fatalf("market control %s: %d %s", path, response.StatusCode, raw)
	}
	if out != nil {
		if err := json.Unmarshal(raw, out); err != nil {
			flow.t.Fatalf("market control %s: %s", path, raw)
		}
	}
}

// member calls the member API as one controller (Forward: the console proxy path, mTLS client certificate).
func (flow *marketLimitsFlow) member(name, method, path, key string, body, out any) int {
	flow.t.Helper()
	var raw []byte
	if body != nil {
		raw, _ = json.Marshal(body)
	}
	status, answer, err := flow.clients[name].Forward(flow.t.Context(), method, path, key, raw)
	if err != nil {
		flow.t.Fatalf("%s %s %s: %v", name, method, path, err)
	}
	if out != nil && status < 300 {
		if err := json.Unmarshal(answer, out); err != nil {
			flow.t.Fatalf("%s %s: %s", name, path, answer)
		}
	}
	if status >= 300 {
		flow.t.Logf("%s %s %s: %d %s", name, method, path, status, answer)
	}
	return status
}

func (flow *marketLimitsFlow) waitFor(what string, timeout time.Duration, done func() bool) {
	flow.t.Helper()
	deadline := time.Now().Add(timeout)
	for !done() {
		if time.Now().After(deadline) {
			flow.t.Fatalf("timed out waiting for %s", what)
		}
		time.Sleep(500 * time.Millisecond)
	}
}

func (flow *marketLimitsFlow) clock(offset time.Duration) {
	flow.control("POST", "/clock", map[string]int64{"offset_seconds": int64(offset / time.Second)}, nil)
}

func (flow *marketLimitsFlow) credit(buyer string, amount int64, key string) {
	flow.control("POST", "/credit", map[string]any{"Seller": "leaf", "Buyer": buyer, "Amount": amount, "Key": key}, nil)
}

// state is the one slot state of a root subscription (leaf|pool).
func (flow *marketLimitsFlow) state(subscription uuid.UUID) string {
	flow.t.Helper()
	var states map[string]string
	flow.control("GET", "/states?subscription="+subscription.String(), nil, &states)
	if len(states) != 1 {
		flow.t.Fatalf("subscription %s states %v", subscription, states)
	}
	for _, s := range states {
		return s
	}
	return ""
}

func (flow *marketLimitsFlow) holds(subscription uuid.UUID) map[string]string {
	var holds map[string]string
	flow.control("GET", "/holds?subscription="+subscription.String(), nil, &holds)
	return holds
}

// target is the buyer's per-leaf supply target state as its controller reads it (GET /v1/supply-targets).
func (flow *marketLimitsFlow) target(buyer string, subscription uuid.UUID) string {
	flow.t.Helper()
	targets, err := flow.clients[buyer].SupplyTargets(flow.t.Context())
	if err != nil {
		flow.t.Fatalf("%s supply targets: %v", buyer, err)
	}
	for _, target := range targets {
		if target.SubscriptionID == subscription && !target.Aggregate {
			return target.State
		}
	}
	flow.t.Fatalf("%s has no target for %s: %+v", buyer, subscription, targets)
	return ""
}

type marketLimitsOffer struct {
	ID uuid.UUID `json:"id"`
}

type marketLimitsSubscription struct {
	ID     uuid.UUID `json:"id"`
	Grants int       `json:"grants"`
}

// list creates and publishes one offer of the leaf on its pool.
func (flow *marketLimitsFlow) list(name string, offer map[string]any) uuid.UUID {
	flow.t.Helper()
	offer["name"] = name
	offer["components"] = []map[string]any{{"kind": "own_pool", "node_pool_ref": flow.poolRef}}
	offer["allocation"] = map[string]any{"http_ports": 2}
	offer["compliance"] = map[string]any{"require_icp": false}
	var created marketLimitsOffer
	if status := flow.member("leaf", "POST", "/v1/offers", "", offer, &created); status != http.StatusCreated {
		flow.t.Fatalf("create offer %s: %d", name, status)
	}
	if status := flow.member("leaf", "POST", "/v1/offers/"+created.ID.String()+"/publish", "", nil, nil); status != http.StatusOK {
		flow.t.Fatalf("publish offer %s: %d", name, status)
	}
	return created.ID
}

func (flow *marketLimitsFlow) buy(buyer string, offer uuid.UUID, days int, key string) uuid.UUID {
	flow.t.Helper()
	body := map[string]any{"offer_id": offer, "idempotency_key": key}
	if days > 0 {
		body["days"] = days
	}
	var sub marketLimitsSubscription
	if status := flow.member(buyer, "POST", "/v1/subscriptions", "", body, &sub); status != http.StatusCreated || sub.Grants != 1 {
		flow.t.Fatalf("%s buys %s: %d %+v", buyer, offer, status, sub)
	}
	return sub.ID
}

// localSubscription is the leaf's package subscription serving root (its hidden market product), once the grant
// loop synced it. A direct purchase has the one-hop path [root].
func (flow *marketLimitsFlow) localSubscription(root uuid.UUID) uuid.UUID {
	flow.t.Helper()
	key := marketsupply.HoldKey([]uuid.UUID{root}, flow.poolRef)
	var local uuid.UUID
	flow.waitFor("leaf synced grant of "+root.String(), time.Minute, func() bool {
		return flow.pool.QueryRow(flow.t.Context(), `SELECT package_subscription_id FROM market_supply_limits
			WHERE market_key=$1`, key).Scan(&local) == nil
	})
	return local
}

// leafLimits is the leaf's stored hold and node share for one local subscription.
func (flow *marketLimitsFlow) leafLimits(local uuid.UUID) (hold string, stopped bool) {
	flow.t.Helper()
	var action *string
	if err := flow.pool.QueryRow(flow.t.Context(), `SELECT hold_action, node_stopped FROM market_supply_limits
		WHERE package_subscription_id=$1`, local).Scan(&action, &stopped); err != nil {
		flow.t.Fatal(err)
	}
	if action != nil {
		hold = *action
	}
	return hold, stopped
}

func (flow *marketLimitsFlow) expectServing(buyer string, root uuid.UUID, label string) {
	flow.t.Helper()
	if got := flow.state(root); got != "serving" {
		flow.t.Fatalf("%s: %s state %s, want serving", label, buyer, got)
	}
	if got := flow.target(buyer, root); got != "serving" {
		flow.t.Fatalf("%s: %s supply target %s, want serving", label, buyer, got)
	}
}

func (flow *marketLimitsFlow) run() {
	t := flow.t
	start := time.Now().UTC()
	bucket := usage.BucketSeconds * time.Second

	// ① daily bundle with a QPS cap (pause after 2 sustained buckets).
	daily := flow.list("A daily QPS", map[string]any{"billing_model": "daily_bundle",
		"limits":  []map[string]any{{"metric": "qps", "cap": 1000, "action": "pause", "sustain_buckets": 2}},
		"pricing": map[string]any{"currency": "CNY", "daily_minor": 100, "min_days": 1, "max_days": 30}})
	if status := flow.member("buyer_b", "POST", "/v1/subscriptions", "", map[string]any{"offer_id": daily, "days": 3,
		"idempotency_key": "b-daily-unfunded"}, nil); status != http.StatusPaymentRequired {
		t.Fatalf("purchase without a prepaid balance: %d, want 402", status)
	}
	flow.credit("buyer_b", 10_000, "b-topup-1")
	flow.credit("buyer_c", 10_000, "c-topup-1")
	sb := flow.buy("buyer_b", daily, 3, "b-daily")
	sc := flow.buy("buyer_c", daily, 3, "c-daily")
	localB, localC := flow.localSubscription(sb), flow.localSubscription(sc)
	_ = localB
	flow.expectServing("buyer_b", sb, "after purchase")
	flow.expectServing("buyer_c", sc, "after purchase")
	t.Logf("PASS ① listed %s, prepaid purchase (402 before top-up), leaf synced grants to local subscriptions B=%s C=%s",
		daily, localB, localC)

	// B's peaks reach the cap for two buckets, C stays at 900 (warning only). The leaf's usage loop reports them.
	first := start.Truncate(bucket).Add(bucket)
	peak := func(root uuid.UUID, from int, qps ...int64) {
		items := make([]usage.Item, len(qps))
		for i, q := range qps {
			items[i] = usage.Item{BucketStart: first.Add(time.Duration(from+i) * bucket).Unix(), BytesOut: 1, Requests: 1, MaxQPS: q}
		}
		flow.reportUsage(root, items...)
	}
	// The market evaluates buckets that ended 15 minutes ago (reportLag) and counts unreported buckets as zero:
	// its clock goes exactly to the end of the last reported bucket plus the lag.
	lag := 15 * time.Minute
	at := func(buckets int) time.Duration {
		return first.Add(time.Duration(buckets)*bucket+lag).Sub(time.Now()) + time.Second
	}
	flow.clock(at(2))
	peak(sb, 0, 960, 1000)
	peak(sc, 0, 900, 900)
	var report struct{ Evaluated, Opened, Released int }
	flow.control("POST", "/evaluate", nil, &report)
	if got := flow.state(sb); got != "paused" || flow.target("buyer_b", sb) != "paused" {
		t.Fatalf("B at the QPS cap for 2 buckets: %s (evaluate %+v)", got, report)
	}
	flow.expectServing("buyer_c", sc, "B paused")
	// Pause only stops scheduling (DNS); the leaf keeps serving and applies no node stop.
	time.Sleep(5 * time.Second)
	if hold, stopped := flow.leafLimits(localB); stopped || hold == "stop" {
		t.Fatalf("pause must not stop the nodes: hold %q stopped %v", hold, stopped)
	}
	t.Logf("PASS ① QPS at the cap 2 buckets: B paused (%v), C serving, leaf nodes not stopped", flow.holds(sb))

	flow.clock(at(4))
	peak(sb, 2, 500, 400)
	flow.control("POST", "/evaluate", nil, &report)
	flow.expectServing("buyer_b", sb, "B below 80% two buckets")
	flow.expectServing("buyer_c", sc, "B resumed")
	t.Log("PASS ① two buckets below 80%: B resumes, C unaffected")

	// ② traffic offer at 100/GB, B's credit line (the direct-mode overdraft cap) 300. Grants are signed on the
	// market's clock and the leaf checks them on its own: purchases happen with the market clock back at now.
	flow.clock(0)
	traffic := flow.list("A traffic", map[string]any{"billing_model": "traffic",
		"pricing": map[string]any{"currency": "CNY", "tiers": []map[string]any{{"up_to_gb": 0, "price_per_gb_minor": 100}},
			"deposit_minor": 100}})
	if status := flow.member("leaf", "PUT", "/v1/ledger/credit-terms", "", map[string]any{"buyer_id": flow.members["buyer_b"],
		"currency": "CNY", "credit_limit_minor": 300}, nil); status != http.StatusOK {
		t.Fatalf("credit terms: %d", status)
	}
	tb := flow.buy("buyer_b", traffic, 0, "b-traffic")
	tc := flow.buy("buyer_c", traffic, 0, "c-traffic")
	flow.localSubscription(tb)
	flow.localSubscription(tc)
	gb := int64(1) << 30
	sendGB := func(root uuid.UUID, at int, gbs int64) {
		flow.reportUsage(root, usage.Item{BucketStart: first.Add(time.Duration(at) * bucket).Unix(), BytesOut: gbs * gb, Requests: 10})
	}
	balanceB := flow.balanceOf("buyer_b")
	used := balanceB/100 + 1 // one GB more than B's balance pays for, in one bucket
	from := 6
	flow.clock(at(from + 1))
	sendGB(tb, from, used)
	sendGB(tc, from, 1)
	var meter struct{ Charged, Owing, Capped, Released int }
	flow.control("POST", "/meter", nil, &meter)
	if holds := flow.holds(tb); flow.state(tb) != "paused" || holds["prepaid"] != "pause" || holds["overdraft_cap"] != "" {
		t.Fatalf("B's prepaid ran out (overdraft below the line): %s %v (meter %+v)", flow.state(tb), holds, meter)
	}
	flow.expectServing("buyer_c", tc, "B prepaid exhausted")
	t.Logf("PASS ② %d GB at 100/GB on a balance of %d: prepaid hold pauses B (%v), C serving", used, balanceB, flow.holds(tb))

	// Two more GB (overdraft 100 → 300): the overdraft reaches B's credit line — still a pause, never a stop.
	flow.clock(at(from + 2))
	sendGB(tb, from+1, 2)
	flow.control("POST", "/meter", nil, &meter)
	if holds := flow.holds(tb); holds["overdraft_cap"] != "pause" || flow.state(tb) != "paused" {
		t.Fatalf("overdraft at the cap: %v %s", holds, flow.state(tb))
	}
	t.Logf("PASS ② overdraft reached the credit line: %v (pause, not stop)", flow.holds(tb))

	// A top-up pays the arrears and releases at once (no meter tick).
	flow.credit("buyer_b", 2_000, "b-topup-2")
	if holds := flow.holds(tb); len(holds) != 0 {
		t.Fatalf("top-up releases the prepaid holds: %v", holds)
	}
	flow.expectServing("buyer_b", tb, "top-up")
	flow.expectServing("buyer_c", tc, "B topped up")
	t.Log("PASS ② top-up: arrears paid, holds released without a meter tick, B serving")

	// ③ the seller chose stop for an exhausted prepaid balance (daily renewal unpaid): the market opens a stop hold,
	// the leaf's hold loop applies it (node share stopped: the node answers 503 for that subscriber), a top-up
	// lets the next renewal pay and the leaf restores the share. C buys the same offer with enough balance.
	stopOffer := flow.list("A daily stop", map[string]any{"billing_model": "daily_bundle", "prepaid_exhausted_action": "stop",
		"pricing": map[string]any{"currency": "CNY", "daily_minor": 100, "min_days": 1, "max_days": 30}})
	balanceOf := flow.balanceOf
	// B pays 1 day with what is left after the stop offer's first day: spend B's balance down to < 100 first by
	// buying days of the stop offer (each 100), so the renewal of day 2 finds less than one day.
	flow.clock(0)
	days := int(balanceOf("buyer_b") / 100)
	if days < 1 || days > 30 {
		t.Fatalf("B balance %d cannot buy the stop offer", balanceOf("buyer_b"))
	}
	pb := flow.buy("buyer_b", stopOffer, days, "b-stop")
	pc := flow.buy("buyer_c", stopOffer, 1, "c-stop")
	stopB, stopC := flow.localSubscription(pb), flow.localSubscription(pc)
	// Renewal runs in the hour before paid_through: B has < 100 left → unpaid → stop hold; C has plenty.
	flow.clock(time.Duration(days)*24*time.Hour - 30*time.Minute)
	flow.control("POST", "/renew", nil, nil)
	if got := flow.state(pb); got != "stopped" || flow.holds(pb)["prepaid"] != "stop" {
		t.Fatalf("B's renewal unpaid with stop chosen: %s %v (balance %d)", got, flow.holds(pb), balanceOf("buyer_b"))
	}
	flow.waitFor("leaf applies the stop hold", time.Minute, func() bool {
		hold, stopped := flow.leafLimits(stopB)
		return hold == "stop" && stopped
	})
	if hold, stopped := flow.leafLimits(stopC); hold != "" || stopped {
		t.Fatalf("C's share on the same offer: hold %q stopped %v", hold, stopped)
	}
	t.Logf("PASS ③ prepaid stop: market stop hold %v, leaf node share stopped for B only", flow.holds(pb))
	flow.credit("buyer_b", 1_000, "b-topup-3")
	flow.control("POST", "/renew", nil, nil)
	flow.waitFor("leaf releases the stop hold", time.Minute, func() bool {
		hold, stopped := flow.leafLimits(stopB)
		return hold == "" && !stopped
	})
	if got := flow.state(pb); got != "serving" {
		t.Fatalf("B after the top-up and renewal: %s", got)
	}
	flow.expectServing("buyer_c", pc, "B stopped and restored")
	t.Log("PASS ③ top-up and renewal: stop hold released, leaf node share restored, C unaffected")

	// ④ node overload: the leaf reports its node's minute load (signed with its member key), the default floor is
	// CPU 80%. Two minutes over remove the node from every supply on it; five minutes below 75 restore it.
	flow.clock(0)
	reportLoad := func(cpu float64) {
		t.Helper()
		at := time.Now().UTC().Truncate(time.Minute)
		result, err := flow.clients["leaf"].ReportNodeLoad(t.Context(), flow.leaf.Identity(), nodeload.Report{
			Schema: nodeload.SchemaV1, ReportID: uuid.New(), CreatedAt: at.Unix(), Items: []nodeload.Item{{
				NodePoolRef: flow.poolRef, NodeID: flow.nodeID, ObservedAt: at.Unix(), CPUPercent: cpu, MemoryPercent: 20, SampleCount: 6}}})
		if err != nil || result.Accepted != 1 {
			t.Fatalf("node load report %.0f%%: %+v %v", cpu, result, err)
		}
	}
	minute := func(cpu float64, n int) {
		for range n {
			reportLoad(cpu)
			// One sample per minute: wait for the next minute boundary.
			time.Sleep(time.Until(time.Now().Truncate(time.Minute).Add(time.Minute + time.Second)))
		}
	}
	minute(95, 2)
	flow.control("POST", "/evaluate-load", nil, nil)
	if got := flow.target("buyer_b", sb); got != "overloaded" {
		t.Fatalf("B's supply target after 2 minutes at 95%% CPU: %s", got)
	}
	if got := flow.target("buyer_c", sc); got != "overloaded" {
		t.Fatalf("C's supply target on the same node: %s", got)
	}
	t.Log("PASS ④ two minutes at 95% CPU: node removed from the supply (overloaded) for every subscriber on it")
	minute(10, 5)
	flow.control("POST", "/evaluate-load", nil, nil)
	flow.expectServing("buyer_b", sb, "load recovered")
	flow.expectServing("buyer_c", sc, "load recovered")
	t.Log("PASS ④ five minutes at 10%: node restored, both serving")
}

func (flow *marketLimitsFlow) balanceOf(buyer string) int64 {
	flow.t.Helper()
	var b struct {
		BalanceMinor int64 `json:"balance_minor"`
	}
	flow.member(buyer, "GET", fmt.Sprintf("/v1/ledger/balance?buyer_id=%s&seller_id=%s&currency=CNY",
		flow.members[buyer], flow.members["leaf"]), "", nil, &b)
	return b.BalanceMinor
}

// reportUsage sends the leaf's signed usage report for one root subscription's grant (marketclient.ReportUsage,
// what marketruntime's usage loop sends once ClickHouse settled the buckets; that loop runs on the wall clock, so
// the scenario reports the buckets itself and moves only the market's clock).
func (flow *marketLimitsFlow) reportUsage(root uuid.UUID, items ...usage.Item) {
	flow.t.Helper()
	grants, _, err := flow.clients["leaf"].Grants(flow.t.Context(), flow.leaf.Identity().MemberID)
	if err != nil {
		flow.t.Fatal(err)
	}
	var grantID uuid.UUID
	for _, g := range grants {
		if len(g.SubscriptionPath) == 1 && g.SubscriptionPath[0] == root {
			grantID = g.GrantID
		}
	}
	if grantID == uuid.Nil {
		flow.t.Fatalf("no grant for %s", root)
	}
	for i := range items {
		items[i].GrantID = grantID
	}
	result, err := flow.clients["leaf"].ReportUsage(flow.t.Context(), flow.leaf.Identity(), usage.Report{Schema: usage.SchemaV2,
		ReportID: uuid.New(), CreatedAt: time.Now().Unix(), Items: items})
	if err != nil || result.Accepted != len(items) {
		flow.t.Fatalf("usage report for %s: %+v %v", root, result, err)
	}
}
