// Package marketsupply turns verified market supply grants into local sold
// packages on the leaf supplier (docs/marketplace/03-supply-api.md §3).
//
// Each external key (subscription_path, node_pool_ref) owns one tenant, one
// unpublished package product and one package subscription. Everything goes
// through the existing identity and packagesubscription services under a
// dedicated platform service account, so quota enforcement, expiry, audit and
// idempotency are the same code paths that sold packages already use.
//
// Entities are found by deterministic names derived from the external key, so
// this package needs no schema of its own.
package marketsupply

import (
	"context"
	"crypto/rand"
	"crypto/sha256"
	"encoding/hex"
	"errors"
	"fmt"
	"strings"
	"sync"
	"time"

	"github.com/cdnca/cdnca/libs/marketproto/grant"
	"github.com/cdnca/cdnca/services/control-api/internal/identity"
	"github.com/cdnca/cdnca/services/control-api/internal/packageperiod"
	"github.com/cdnca/cdnca/services/control-api/internal/packagesubscription"
	"github.com/google/uuid"
	"github.com/jackc/pgx/v5"
	"github.com/jackc/pgx/v5/pgxpool"
)

const (
	// ServiceUsername is the platform account that performs market writes.
	// Its password is random and never stored, so nobody can log in as it.
	ServiceUsername = "market-supply"
	serviceRoleName = "market_supply"
	sessionTTL      = time.Hour
	sessionRenewAt  = 10 * time.Minute

	tenantPrefix  = "mkt-"
	productPrefix = "market:"
)

var servicePermissions = []string{
	"package_subscriptions.read", "package_subscriptions.manage", "sites.read", "sites.manage",
	// Site writes under a package also stage the CNAME intent, which checks DNS rights.
	"dns.read", "dns.manage",
}

var (
	ErrNoPlatform  = errors.New("market supply: platform scope missing")
	ErrUnknownPool = errors.New("market supply: node_pool_ref is not a local node group")
)

// Config fixes the parts of the generated product that grants do not carry.
type Config struct {
	// CNAMEDomain is the leaf's own per-site CNAME zone for market sites.
	CNAMEDomain string
	TimeZone    string
}

type Service struct {
	pool          *pgxpool.Pool
	identity      *identity.Service
	subscriptions *packagesubscription.Service
	cfg           Config
	now           func() time.Time

	sites SiteWriter
	icp   ICPChecker
	cache CachePolicies
	purge CacheOperations
	// access writes the site access settings (fix-mktsiteconf2).
	access SiteAccessSettings

	policies    SecurityPolicies
	activations SecurityActivations
	// crs / ipLists carry the WAF's CRS application types and IP lists
	// (fix-mktsiteconf3, WithWAFExtras).
	crs     SiteCRSApps
	ipLists IPLists
	// httpPolicies writes the site HTTP policy (fix-mktsiteconf3).
	httpPolicies SiteHTTPPolicies
	// originAuth / boxSelf write the site origin auth (fix-mktsiteconf5).
	originAuth SiteOriginAuth
	boxSelf    func() (uuid.UUID, []byte)
	// originAuthDelivery sends what originAuth wrote to the nodes (fix-mktsiteconf6).
	originAuthDelivery OriginAuthDelivery
	autoDefense        AutoDefenseStore

	summaries AttackSummaries
	security  SiteSecurity

	mu     sync.Mutex
	actor  *serviceActor
	grants map[uuid.UUID]grant.Grant
	// subscribers: root subscriber member by external key (secdigest.go).
	subscribers map[string]uuid.UUID
}

type serviceActor struct {
	userID, scopeID, sessionID uuid.UUID
	expiresAt                  time.Time
}

func New(pool *pgxpool.Pool, identityService *identity.Service,
	subscriptions *packagesubscription.Service, cfg Config,
) *Service {
	if cfg.TimeZone == "" {
		cfg.TimeZone = "UTC"
	}
	return &Service{pool: pool, identity: identityService, subscriptions: subscriptions, cfg: cfg,
		now: time.Now}
}

func (s *Service) WithClock(now func() time.Time) *Service {
	s.now = now
	return s
}

// Outcome reports what Sync did for one grant.
type Outcome struct {
	GrantID        uuid.UUID `json:"grant_id"`
	Key            string    `json:"key"`
	Action         string    `json:"action"` // opened, renewed, unchanged, skipped, failed
	TenantScopeID  uuid.UUID `json:"tenant_scope_id,omitempty"`
	SubscriptionID uuid.UUID `json:"subscription_id,omitempty"`
	Error          string    `json:"error,omitempty"`
}

// UsageTarget is where one grant's traffic is metered locally.
type UsageTarget struct {
	GrantID        uuid.UUID
	TenantScopeID  uuid.UUID
	SubscriptionID uuid.UUID
	// Since is when the grant's subscription started serving here.
	Since time.Time
}

// UsageTargets lists, for the latest synced grant of every external key, the
// local package subscription its traffic lands on. Keys without a local
// subscription yet are skipped.
func (s *Service) UsageTargets(ctx context.Context) ([]UsageTarget, error) {
	s.mu.Lock()
	latest := map[string]grant.Grant{}
	for _, g := range s.grants {
		key := Key(g)
		if current, ok := latest[key]; !ok || g.NotAfter > current.NotAfter {
			latest[key] = g
		}
	}
	s.mu.Unlock()
	out := make([]UsageTarget, 0, len(latest))
	for key, g := range latest {
		target := UsageTarget{GrantID: g.GrantID}
		err := s.pool.QueryRow(ctx, `SELECT s.tenant_scope_id, s.id, s.starts_at FROM package_subscriptions s
			JOIN package_products p ON p.id=s.product_id
			JOIN memberships m ON m.scope_id=s.tenant_scope_id
			JOIN users u ON u.id=m.user_id AND u.username=$1
			WHERE p.name=$2 AND s.deleted_at IS NULL ORDER BY s.created_at DESC LIMIT 1`,
			tenantPrefix+key, productPrefix+key).Scan(&target.TenantScopeID, &target.SubscriptionID, &target.Since)
		if errors.Is(err, pgx.ErrNoRows) {
			continue
		}
		if err != nil {
			return nil, err
		}
		out = append(out, target)
	}
	return out, nil
}

// GrantForKey returns the latest synced grant of an external key (the one
// with the furthest not_after), for reports that name the grant of a market
// tenant (ADR 0012 §19.3 node actions).
func (s *Service) GrantForKey(key string) (uuid.UUID, bool) {
	s.mu.Lock()
	defer s.mu.Unlock()
	var best grant.Grant
	found := false
	for _, g := range s.grants {
		if Key(g) == key && (!found || g.NotAfter > best.NotAfter) {
			best, found = g, true
		}
	}
	return best.GrantID, found
}

// Key is the stable external key of a grant. Grants are re-issued daily with
// a new grant_id, so the id itself cannot identify the tenant.
func Key(g grant.Grant) string {
	parts := make([]string, 0, len(g.SubscriptionPath)+1)
	for _, id := range g.SubscriptionPath {
		parts = append(parts, id.String())
	}
	parts = append(parts, g.NodePoolRef)
	sum := sha256.Sum256([]byte(strings.Join(parts, "/")))
	return hex.EncodeToString(sum[:12])
}

// Sync applies verified grants. A grant that disappears is not cancelled here:
// its subscription simply runs out at not_after + grace. An empty or partial
// response from the market therefore can never take sites down early.
func (s *Service) Sync(ctx context.Context, grants []grant.Grant) ([]Outcome, error) {
	actor, err := s.ensureActor(ctx)
	if err != nil {
		return nil, err
	}
	s.remember(grants)
	latest := map[string]grant.Grant{}
	for _, g := range grants {
		key := Key(g)
		if current, ok := latest[key]; !ok || g.NotAfter > current.NotAfter {
			latest[key] = g
		}
	}
	out := make([]Outcome, 0, len(latest))
	for key, g := range latest {
		outcome := Outcome{GrantID: g.GrantID, Key: key}
		if err := s.apply(ctx, actor, key, g, &outcome); err != nil {
			outcome.Action, outcome.Error = "failed", err.Error()
		}
		out = append(out, outcome)
	}
	return out, nil
}

func (s *Service) apply(ctx context.Context, actor serviceActor, key string, g grant.Grant, outcome *Outcome) error {
	now := s.now().UTC()
	switch g.StatusAt(now) {
	case grant.StatusActive, grant.StatusGrace:
	default:
		outcome.Action = "skipped"
		return nil
	}
	poolID, err := s.pool_(ctx, actor.scopeID, g.NodePoolRef)
	if err != nil {
		return err
	}
	tenant, err := s.ensureTenant(ctx, actor, key)
	if err != nil {
		return err
	}
	outcome.TenantScopeID = tenant.scopeID
	if err := s.ensureDelivery(ctx, actor, tenant, poolID); err != nil {
		return err
	}
	if err := s.applyPlugins(ctx, tenant, g); err != nil {
		return err
	}
	productID, revision, err := s.ensureProduct(ctx, actor, key, poolID, g)
	if err != nil {
		return err
	}
	subActor := packagesubscription.Actor{UserID: actor.userID, ScopeID: actor.scopeID,
		SessionID: actor.sessionID, ScopeKind: packagesubscription.ScopePlatform}
	endsAt := time.Unix(g.NotAfter+g.GraceSeconds, 0).UTC()

	var subID uuid.UUID
	var subRevision int64
	var currentEnd time.Time
	err = s.pool.QueryRow(ctx, `SELECT id, revision, ends_at FROM package_subscriptions
		WHERE tenant_scope_id=$1 AND product_id=$2 AND lifecycle_status='active' AND deleted_at IS NULL
		ORDER BY created_at DESC LIMIT 1`, tenant.scopeID, productID).Scan(&subID, &subRevision, &currentEnd)
	switch {
	case errors.Is(err, pgx.ErrNoRows):
		result, err := s.subscriptions.Open(ctx, subActor, packagesubscription.OpenRequest{
			TenantScopeID: tenant.scopeID, OwnerUserID: tenant.userID,
			ProductID: productID, ProductRevision: revision,
			SiteLimit: grantSiteLimit(g), NodeLimit: -1,
			Terms:    packageperiod.Terms{EndAt: &endsAt},
			TimeZone: s.cfg.TimeZone, CyclePolicy: packageperiod.CyclePolicy{Kind: packageperiod.CycleMonthly},
			TrafficFactor:  mustFactor(),
			IdempotencyKey: "market-open-" + g.GrantID.String(), RequestID: "market-" + key,
		})
		if err != nil {
			return err
		}
		outcome.Action, outcome.SubscriptionID = "opened", result.Subscription.ID
		return s.applyGrantLimits(ctx, actor, tenant, result.Subscription.ID, poolID, key, g)
	case err != nil:
		return err
	}
	outcome.SubscriptionID = subID
	if err := s.applyGrantLimits(ctx, actor, tenant, subID, poolID, key, g); err != nil {
		return err
	}
	if !endsAt.After(currentEnd) {
		outcome.Action = "unchanged"
		return nil
	}
	if _, err := s.subscriptions.Renew(ctx, subActor, packagesubscription.RenewRequest{
		TenantScopeID: tenant.scopeID, SubscriptionID: subID, ExpectedRevision: subRevision,
		Terms:          packageperiod.Terms{EndAt: &endsAt},
		IdempotencyKey: fmt.Sprintf("market-renew-%s-%d", g.GrantID, g.NotAfter), RequestID: "market-" + key,
	}); err != nil {
		return err
	}
	outcome.Action = "renewed"
	return nil
}

// pool_ resolves node_pool_ref to a platform node group of this controller.
func (s *Service) pool_(ctx context.Context, platform uuid.UUID, ref string) (uuid.UUID, error) {
	id, err := uuid.Parse(ref)
	if err != nil {
		return uuid.Nil, ErrUnknownPool
	}
	var found uuid.UUID
	err = s.pool.QueryRow(ctx, `SELECT id FROM node_line_groups
		WHERE id=$1 AND tenant_scope_id=$2 AND deleted_at IS NULL`, id, platform).Scan(&found)
	if errors.Is(err, pgx.ErrNoRows) {
		return uuid.Nil, ErrUnknownPool
	}
	return found, err
}

type tenantRef struct{ scopeID, userID uuid.UUID }

func (s *Service) ensureTenant(ctx context.Context, actor serviceActor, key string) (tenantRef, error) {
	username := tenantPrefix + key
	var ref tenantRef
	err := s.pool.QueryRow(ctx, `SELECT membership.scope_id, account.id FROM users account
		JOIN memberships membership ON membership.user_id = account.id
		JOIN access_scopes scope ON scope.id = membership.scope_id AND scope.kind = 'tenant'
		WHERE account.username = $1`, username).Scan(&ref.scopeID, &ref.userID)
	if err == nil {
		return ref, nil
	}
	if !errors.Is(err, pgx.ErrNoRows) {
		return tenantRef{}, err
	}
	password, err := randomSecret()
	if err != nil {
		return tenantRef{}, err
	}
	user, err := s.identity.CreateUser(ctx, identity.Actor{UserID: actor.userID, ScopeID: actor.scopeID,
		ScopeKind: "platform", SessionID: actor.sessionID}, identity.CreateUserInput{
		Username: username, Password: password, Role: identity.UserRoleOwner,
		Fields:         identity.UserFields{DisplayName: "市场订阅 " + key[:8]},
		IdempotencyKey: "market-tenant-" + key, RequestID: "market-" + key,
	})
	if err != nil {
		return tenantRef{}, err
	}
	return tenantRef{scopeID: user.ScopeID, userID: user.ID}, nil
}

func mustFactor() packageperiod.TrafficFactor {
	f, err := packageperiod.NewTrafficFactor(1, 1)
	if err != nil {
		panic(err)
	}
	return f
}

func randomSecret() (string, error) {
	b := make([]byte, 32)
	if _, err := rand.Read(b); err != nil {
		return "", err
	}
	return hex.EncodeToString(b), nil
}
