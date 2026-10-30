package main

import (
	"context"
	"crypto/ed25519"
	"encoding/base64"
	"encoding/json"
	"errors"
	"fmt"
	"log/slog"
	"net/http"
	"os"
	"path/filepath"
	"slices"
	"strings"
	"time"

	mspec "github.com/cdnca/cdnca/libs/marketproto/spec"
	"github.com/cdnca/cdnca/libs/marketproto/usage"
	"github.com/cdnca/cdnca/libs/mtlstunnel"
	"github.com/cdnca/cdnca/services/control-api/internal/analytics"
	"github.com/cdnca/cdnca/services/control-api/internal/analyticslog"
	"github.com/cdnca/cdnca/services/control-api/internal/audit"
	"github.com/cdnca/cdnca/services/control-api/internal/cachecontrol"
	"github.com/cdnca/cdnca/services/control-api/internal/edgeautopublish"
	"github.com/cdnca/cdnca/services/control-api/internal/edgedeployment"
	"github.com/cdnca/cdnca/services/control-api/internal/edgepublish"
	"github.com/cdnca/cdnca/services/control-api/internal/edgestatus"
	"github.com/cdnca/cdnca/services/control-api/internal/entitlementguard"
	"github.com/cdnca/cdnca/services/control-api/internal/httppolicycontrol"
	"github.com/cdnca/cdnca/services/control-api/internal/icpquery"
	"github.com/cdnca/cdnca/services/control-api/internal/identity"
	"github.com/cdnca/cdnca/services/control-api/internal/marketclient"
	"github.com/cdnca/cdnca/services/control-api/internal/marketprobe"
	"github.com/cdnca/cdnca/services/control-api/internal/marketruntime"
	"github.com/cdnca/cdnca/services/control-api/internal/marketsubscribe"
	"github.com/cdnca/cdnca/services/control-api/internal/marketsubscribehttp"
	"github.com/cdnca/cdnca/services/control-api/internal/marketsupply"
	"github.com/cdnca/cdnca/services/control-api/internal/nodescheduler"
	"github.com/cdnca/cdnca/services/control-api/internal/notification"
	"github.com/cdnca/cdnca/services/control-api/internal/openrestysecurity"
	"github.com/cdnca/cdnca/services/control-api/internal/originauthcontrol"
	"github.com/cdnca/cdnca/services/control-api/internal/packagesubscription"
	"github.com/cdnca/cdnca/services/control-api/internal/securityactivation"
	"github.com/cdnca/cdnca/services/control-api/internal/securityiplist"
	"github.com/cdnca/cdnca/services/control-api/internal/securitypolicy"
	"github.com/cdnca/cdnca/services/control-api/internal/site"
	"github.com/cdnca/cdnca/services/control-api/internal/siteaccess"
	"github.com/cdnca/cdnca/services/control-api/internal/sitecrs"
	"github.com/google/uuid"
	"github.com/jackc/pgx/v5/pgxpool"
	"github.com/nats-io/nats.go"
)

// buildMarketRuntime returns nil unless MARKET_RUNTIME_ENABLED=true. The node
// market is optional: once enabled, a broken configuration fails startup, but
// an unreachable market only logs (marketruntime retries).
func buildMarketRuntime(pool *pgxpool.Pool, identityService *identity.Service,
	trust *entitlementguard.TrustStore,
) (*marketruntime.Runtime, error) {
	runtime, _, _, err := buildMarketRuntimeWithSubscribe(pool, identityService, trust, nil, nil)
	return runtime, err
}

// marketSubscribeHandlerFactory serves the market API on one mux:
//   - subscriber and buyer routes when the market runtime is on;
//   - plugin security advisories whenever the plugin runtime reaches the
//     license service (advisories), market runtime or not.
//
// With neither, the routes stay unmounted.
func marketSubscribeHandlerFactory(subscribe *marketsubscribe.Service, forwarder marketsubscribehttp.Forwarder,
	identityService *identity.Service, pool *pgxpool.Pool, advisories *marketsubscribehttp.AdvisorySync,
	features marketsupply.FeatureReader,
) func() (http.Handler, error) {
	market := subscribe != nil && forwarder != nil
	if pool == nil || !market && advisories == nil {
		return nil
	}
	return func() (http.Handler, error) {
		var svc marketsubscribehttp.Service
		if market {
			svc = subscribe
		}
		h := marketsubscribehttp.New(svc, func(request *http.Request) (marketsubscribehttp.Caller, error) {
			return marketCaller(request, identityService)
		})
		if market {
			groups := marketsupply.NewSupplyGroups(pool, nodescheduler.NewService(pool, time.Now), features)
			h = h.WithMember(forwarder, controlVersion).WithSupplyGroups(groups).
				WithListing(groups, marketsubscribehttp.NewPostgresListingStore(pool), forwarder).
				WithSiteRollout(subscribe)
		}
		var reporter marketsubscribehttp.AdvisoryReporter
		if advisories != nil {
			reporter = advisories
		}
		return h.WithBuyer(marketsubscribehttp.NewPostgresStore(pool), reporter), nil
	}
}

// buildMarketAdvisorySync pulls plugin security advisories from the license
// service with the plugin runtime's installation certificate. It needs only
// the plugin runtime, not the node market. Nil without a plugin runtime.
func buildMarketAdvisorySync(plugins *pluginInstallationRuntime, pool *pgxpool.Pool) (*marketsubscribehttp.AdvisorySync, error) {
	if plugins == nil || plugins.licenseHTTP == nil || pool == nil {
		return nil, nil
	}
	client, err := marketsubscribehttp.NewLicenseAdvisoryClient(plugins.providerURL, plugins.licenseHTTP, plugins.installationID)
	if err != nil {
		return nil, fmt.Errorf("plugin advisory client: %w", err)
	}
	return marketsubscribehttp.NewAdvisorySync(client, marketsubscribehttp.NewPostgresStore(pool), 0,
		slog.Default().With("component", "plugin-advisories")), nil
}

// marketCaller authenticates the console session; per-route permissions are
// checked by marketsubscribehttp (marketplace.* codes, legacy sites.manage).
func marketCaller(request *http.Request, identityService *identity.Service) (marketsubscribehttp.Caller, error) {
	values := request.Header.Values("Authorization")
	if len(values) != 1 || !strings.HasPrefix(values[0], "Bearer ") {
		return marketsubscribehttp.Caller{}, identity.ErrInvalidSession
	}
	raw := strings.TrimPrefix(values[0], "Bearer ")
	if raw == "" || len(raw) > 8192 || strings.ContainsAny(raw, " \t\r\n,") {
		return marketsubscribehttp.Caller{}, identity.ErrInvalidSession
	}
	session, err := identityService.AuthenticateSession(request.Context(), raw)
	if err != nil {
		return marketsubscribehttp.Caller{}, err
	}
	principal := session.Principal
	switch principal.ScopeKind {
	case "platform":
	case "tenant":
		// A tenant session must carry its tenant. ScopeID (access_scopes.id) is the
		// tenant key downstream; it is a different UUID from tenants.id (001_identity).
		if principal.TenantID == nil {
			return marketsubscribehttp.Caller{}, errors.New("tenant session is not bound to its scope")
		}
	default:
		return marketsubscribehttp.Caller{}, errors.New("unsupported scope")
	}
	return marketsubscribehttp.Caller{UserID: principal.UserID, ScopeID: principal.ScopeID,
		ScopeKind: principal.ScopeKind, Permissions: principal.Permissions}, nil
}

func buildMarketRuntimeWithSubscribe(pool *pgxpool.Pool, identityService *identity.Service,
	trust *entitlementguard.TrustStore, analyticsStore analytics.QueryStore, edgeConnection natsRuntimeConnection,
) (*marketruntime.Runtime, *marketsubscribe.Service, *marketclient.Client, error) {
	if os.Getenv("MARKET_RUNTIME_ENABLED") != "true" {
		return nil, nil, nil, nil
	}
	// cdncaCE: no entitlement trust (no license service); the market accepts
	// the community identity stored by community-register instead.
	env := func(name, fallback string) string {
		if v := strings.TrimSpace(os.Getenv(name)); v != "" {
			return v
		}
		return fallback
	}
	baseURL := env("MARKET_URL", "")
	stateDir := env("MARKET_STATE_DIR", "")
	// cdncaCE: defaults to the certificate community-register issued.
	communityPaths := communityClientCertificatePaths(filepath.Dir(communityIdentityPath()))
	certFile := env("MARKET_CLIENT_CERT_FILE", env("PLUGIN_RUNTIME_CLIENT_CERT_FILE", communityPaths.certificate))
	keyFile := env("MARKET_CLIENT_KEY_FILE", env("PLUGIN_RUNTIME_CLIENT_PRIVATE_KEY_FILE", communityPaths.privateKey))
	for name, path := range map[string]string{"MARKET_STATE_DIR": stateDir, "MARKET_CLIENT_CERT_FILE": certFile,
		"MARKET_CLIENT_KEY_FILE": keyFile} {
		if !filepath.IsAbs(path) || filepath.Clean(path) != path {
			return nil, nil, nil, fmt.Errorf("%s must be an absolute clean path", name)
		}
	}
	keys, err := parseMarketKeys(env("MARKET_KEYS_JSON", ""))
	if err != nil {
		return nil, nil, nil, err
	}
	roots, err := marketruntime.RootCAs()
	if err != nil {
		return nil, nil, nil, err
	}
	clientCertificate := marketruntime.ClientCertificate(certFile, keyFile)
	if certFile == communityPaths.certificate && keyFile == communityPaths.privateKey {
		// cdncaCE: the certificate community-register issued lasts minutes;
		// the same certificate manager renews it before each handshake needs it.
		manager, err := newCommunityCertificateManager()
		if err != nil {
			return nil, nil, nil, fmt.Errorf("market client certificate: %w", err)
		}
		if manager != nil {
			clientCertificate = manager.GetClientCertificate
		}
	}
	dial, err := mtlsDialer(marketMTLSComponent, baseURL, mtlstunnel.TargetMarketMember)
	if err != nil {
		return nil, nil, nil, err
	}
	client, err := marketclient.New(marketclient.Config{BaseURL: baseURL, RootCAs: roots,
		ClientCertificate: clientCertificate, MarketKeys: keys, DialContext: dial})
	if err != nil {
		return nil, nil, nil, fmt.Errorf("market client: %w", err)
	}
	supply := marketsupply.New(pool, identityService,
		packagesubscription.NewService(packagesubscription.NewStore(pool)),
		marketsupply.Config{CNAMEDomain: env("MARKET_LEAF_CNAME_DOMAIN", ""), TimeZone: env("MARKET_TIMEZONE", "UTC")})
	icp, err := marketICPChecker(env("MARKET_ICP_PROVIDER", ""), env("MARKET_ICP_KEY_FILE", ""))
	if err != nil {
		return nil, nil, nil, err
	}
	supply.WithSites(site.NewService(site.NewStoreWithClock(pool, time.Now, trust)), icp)
	// Market sites act as their non-login tenant owner, so the store takes the
	// tenant RBAC path rather than a formal IAM session.
	cachePolicies, err := cachecontrol.NewStore(pool, time.Now)
	if err != nil {
		return nil, nil, nil, err
	}
	cachePolicies.WithSiteSettingEnqueuer(edgeautopublish.SiteSettingPublisher{})
	supply.WithCache(cachePolicies).WithPurge(cachePolicies).WithSiteAccess(siteaccess.NewService(pool, time.Now))
	supply.WithWAFExtras(sitecrs.NewStore(pool, time.Now), securityiplist.NewStore(pool, time.Now))
	supply.WithHTTPPolicies(httppolicycontrol.NewStoreWithClock(pool, time.Now, nil).
		WithSiteRevisionPublisher(edgeautopublish.UnrequestedRevisionPublisher{}))
	runtime := marketruntime.New(marketruntime.Config{DisplayName: env("MARKET_DISPLAY_NAME", ""), CertFile: certFile,
		KeyFile: keyFile, StateDir: stateDir, CommunityIdentity: loadCommunityIdentity}, pool, client, supply,
		slog.Default().With("component", "market"))
	// Market notices (ADR 0012 §8) go to the notification center.
	notices, err := notification.NewStore(pool)
	if err != nil {
		return nil, nil, nil, fmt.Errorf("market notices: %w", err)
	}
	runtime.WithNotices(notices)
	// Market supply limits: holds pulled from the market, node shares
	// re-split over each pool's serving nodes (ADR 0012 §6.2).
	runtime.WithHolds(client, supply, 0)
	// ML-18: which local market subscriptions are still normal, for the
	// "keep one online node" guard (marketsupplyguard) on node and supply writes.
	slotStates := marketsupply.NewSlotStateSync(pool, client, time.Now, slog.Default().With("component", "market_slot_states"))
	runtime.WithBackground(func(ctx context.Context) error { return slotStates.Run(ctx, time.Minute) })
	// The same runtime relays this controller's own requests as a subscriber.
	// MC12 E2: site-based rollouts compile from the saved site.
	subscribe := marketsubscribe.New(pool, client, runtime).WithSites(site.NewService(site.NewStoreWithClock(pool, time.Now, trust)))
	runtime.WithSubscriptions(subscribe)
	// Receipts of leaves that answered while the receipt could not be saved
	// are completed in the background (fix-cfgflow2 §2).
	subscribe.WithReconcile(time.Now, marketsubscribe.DefaultReconcilePolicy(), notices)
	runtime.WithBackground(func(ctx context.Context) error { return subscribe.RunReconcile(ctx, time.Minute) })
	// Usage reports need the analytics store; without it the leaf only
	// serves, and metered offers cannot be billed for its traffic.
	if store, ok := analyticsStore.(*analytics.Client); ok && store != nil {
		runtime.WithUsage(marketUsageSource{supply: supply, analytics: store,
			excludeBlocked: func(ctx context.Context) (bool, error) { return openrestysecurity.BlockPageNotCounted(ctx, pool) }},
			client, 0)
	} else {
		slog.Default().Warn("market usage reporting disabled: analytics query store unavailable")
	}
	// Per-node plugins come from the same facts as the console's supply
	// plugin choices (marketsupply.SupplyPlugins).
	plugins := marketsupply.NewSupplyGroups(pool, nodescheduler.NewService(pool, time.Now),
		entitlementguard.NewGuard(pool, time.Now, trust))
	probe, err := buildMarketProbe(env("MARKET_PROBE_ENABLED", "false"), edgeConnection, pool, client, runtime.Identity, plugins, supply)
	if err != nil {
		return nil, nil, nil, err
	}
	if probe != nil {
		runtime.WithProbe(probe)
	}
	return runtime, subscribe, client, nil
}

// buildMarketProbe returns the leaf probe service when MARKET_PROBE_ENABLED is
// true (default false). Probing needs agent-gateway to relay commands to nodes
// over edge NATS.
func buildMarketProbe(enabled string, edgeConnection natsRuntimeConnection, pool *pgxpool.Pool,
	client *marketclient.Client, identity func() marketclient.Identity, plugins *marketsupply.SupplyGroups,
	grants marketprobe.GrantResolver,
) (*marketprobe.Service, error) {
	switch enabled {
	case "false":
		return nil, nil
	case "true":
	default:
		return nil, errors.New("MARKET_PROBE_ENABLED must be true or false")
	}
	edgeNATS, ok := edgeConnection.(*nats.Conn)
	if !ok || edgeNATS == nil {
		return nil, errors.New("MARKET_PROBE_ENABLED requires the edge NATS connection")
	}
	requester, err := marketprobe.NewNATSRequester(edgeNATS)
	if err != nil {
		return nil, err
	}
	cfg := marketprobe.Config{Identity: identity, Grants: grants}
	if plugins != nil {
		cfg.Plugins, cfg.Serving = plugins, plugins
	}
	return marketprobe.New(pool, client, requester, cfg,
		slog.Default().With("component", "market-probe")), nil
}

func parseMarketKeys(raw string) (map[string]ed25519.PublicKey, error) {
	var list []struct {
		KeyID     string `json:"key_id"`
		PublicKey string `json:"public_key"`
	}
	if err := json.Unmarshal([]byte(raw), &list); err != nil || len(list) == 0 {
		return nil, errors.New("MARKET_KEYS_JSON must be a non-empty [{key_id, public_key}] list")
	}
	keys := map[string]ed25519.PublicKey{}
	for _, k := range list {
		public, err := base64.StdEncoding.DecodeString(k.PublicKey)
		if err != nil || len(public) != ed25519.PublicKeySize || k.KeyID == "" {
			return nil, errors.New("MARKET_KEYS_JSON holds an invalid key")
		}
		keys[k.KeyID] = public
	}
	return keys, nil
}

// marketICPChecker uses the seller's own provider and key; without one,
// grants that require ICP filing are refused at Prepare time.
func marketICPChecker(provider, keyFile string) (marketsupply.ICPChecker, error) {
	if provider == "" {
		return nil, nil
	}
	key, err := os.ReadFile(keyFile)
	if err != nil {
		return nil, fmt.Errorf("MARKET_ICP_KEY_FILE: %w", err)
	}
	cfg := icpquery.Config{Provider: icpquery.Provider(provider), APIKey: strings.TrimSpace(string(key))}
	if err := cfg.Validate(); err != nil {
		return nil, fmt.Errorf("market ICP provider: %w", err)
	}
	client := icpquery.New()
	return func(ctx context.Context, host string) (bool, error) {
		result, err := client.Query(ctx, cfg, host)
		if err != nil {
			return false, err
		}
		return result.Status == icpquery.Filed, nil
	}, nil
}

// marketClientForwarder avoids a typed-nil interface when the market is off.
func marketClientForwarder(client *marketclient.Client) marketsubscribehttp.Forwarder {
	if client == nil {
		return nil
	}
	return client
}

// marketUsageSource meters grant traffic from the analytics store.
// Block pages follow the platform "block pages are not counted" setting, the
// same filter package traffic enforcement applies (FX60).
type marketUsageSource struct {
	supply         *marketsupply.Service
	analytics      *analytics.Client
	excludeBlocked func(context.Context) (bool, error)
}

func (source marketUsageSource) UsageTargets(ctx context.Context) ([]marketsupply.UsageTarget, error) {
	return source.supply.UsageTargets(ctx)
}

func (source marketUsageSource) TrafficBuckets(ctx context.Context, tenantScopeID, subscriptionID uuid.UUID,
	start, end time.Time,
) ([]usage.Item, error) {
	exclude := false
	if source.excludeBlocked != nil {
		value, err := source.excludeBlocked(ctx)
		if err != nil {
			return nil, err
		}
		exclude = value
	}
	buckets, err := source.analytics.PackageTrafficBucketsFiltered(ctx, tenantScopeID.String(), subscriptionID.String(),
		start, end, exclude)
	if err != nil {
		return nil, err
	}
	peaks, err := source.analytics.SubscriptionPeakBuckets(ctx, subscriptionID.String(), start, end)
	if err != nil {
		return nil, err
	}
	return mergeUsagePeaks(buckets, peaks), nil
}

// mergeUsagePeaks joins traffic buckets and the node minute peaks (usage
// report v2) by bucket; a bucket with only one of the two still reports.
func mergeUsagePeaks(buckets []analytics.PackageTrafficBucket, peaks []analytics.SubscriptionPeakBucket) []usage.Item {
	byStart := map[int64]*usage.Item{}
	var order []int64
	item := func(start int64) *usage.Item {
		if existing, ok := byStart[start]; ok {
			return existing
		}
		value := &usage.Item{BucketStart: start}
		byStart[start] = value
		order = append(order, start)
		return value
	}
	for _, bucket := range buckets {
		value := item(bucket.Start.Unix())
		value.BytesOut, value.Requests = bucket.BytesOut, bucket.Requests
	}
	for _, peak := range peaks {
		value := item(peak.Start.Unix())
		// Nodes clamp to the usage report bounds (spec MaxCap).
		value.PeakBPS = min(peak.PeakBPS, mspec.MetricBandwidthPeakBPS.MaxCap())
		value.MaxConcurrent = min(peak.MaxConcurrent, mspec.MetricConcurrentConnections.MaxCap())
		value.MaxRequests = min(peak.MaxRequests, mspec.MetricConcurrentRequests.MaxCap())
		value.MaxQPS = min(peak.MaxQPS, mspec.MetricQPS.MaxCap())
		value.MaxNewCPS = min(peak.MaxNewCPS, mspec.MetricNewConnectionsPerSecond.MaxCap())
	}
	slices.Sort(order)
	items := make([]usage.Item, 0, len(order))
	for _, start := range order {
		items = append(items, *byStart[start])
	}
	return items
}

// wireMarketSecurity lets leaf sites carry access lists and rate limits and
// runs their activation reconciler beside the market runtime. The activation
// store comes from the site publication runtime, built after the market
// runtime; without it those blocks stay refused (activation_pending).
func wireMarketSecurity(runtime *marketruntime.Runtime, pool *pgxpool.Pool, activation *securityactivation.Store) {
	if runtime == nil || activation == nil {
		return
	}
	supply, ok := runtime.Supply().(*marketsupply.Service)
	if !ok {
		return
	}
	supply.WithSecurity(securitypolicy.NewService(securitypolicy.NewStoreWithClock(pool, time.Now)), activation)
	log := slog.Default().With("component", "market-security")
	runtime.WithBackground(func(ctx context.Context) error {
		return supply.RunSecurityReconciler(ctx, edgestatus.NodeConfigCurrentChannel, log.Warn)
	})
}

// wireMarketOriginAuthDelivery sends the origin auth a leaf wrote for a
// market site to the nodes by itself (fix-mktsiteconf6): right after the
// commit and every 30 seconds after, as a system secret rollout of the same
// generator the tenant's manual publication uses.
func wireMarketOriginAuthDelivery(runtime *marketruntime.Runtime, pool *pgxpool.Pool, deployments *edgedeployment.Store,
	source edgepublish.OriginAuthProductionSource, producer *edgepublish.OriginAuthArtifactProducer) error {
	if runtime == nil {
		return nil
	}
	supply, ok := runtime.Supply().(*marketsupply.Service)
	if !ok {
		return nil
	}
	deliverer, err := edgepublish.NewOriginAuthDeliverer(pool, deployments, source, producer, audit.New(pool),
		edgepublish.OriginAuthDelivererConfig{HealthCheck: edgedeployment.HealthCheckPolicy{ActivationTimeout: 30 * time.Second,
			ObservationWindow: 15 * time.Second, RequiredConsecutiveSuccesses: 3}})
	if err != nil {
		return err
	}
	supply.WithOriginAuthDelivery(deliverer)
	log := slog.Default().With("component", "market-origin-auth-delivery")
	runtime.WithBackground(func(ctx context.Context) error {
		return supply.RunOriginAuthDelivery(ctx, log.Warn)
	})
	return nil
}

// wireMarketOriginAuth lets market sites carry origin auth (fix-mktsiteconf5)
// once the keyring-backed service exists: as a subscriber, credentials are
// sealed to each leaf's card box key; as a leaf, its own box is opened with
// the market identity's box key. Without origin auth both sides block.
func wireMarketOriginAuth(runtime *marketruntime.Runtime, subscribe *marketsubscribe.Service, client *marketclient.Client,
	service *originauthcontrol.Service) {
	if runtime == nil || service == nil {
		return
	}
	if subscribe != nil && client != nil {
		subscribe.WithOriginAuth(service)
		subscribe.WithCards(client)
	}
	if supply, ok := runtime.Supply().(*marketsupply.Service); ok {
		supply.WithOriginAuth(service, func() (uuid.UUID, []byte) {
			id := runtime.Identity()
			return id.MemberID, id.BoxPrivate
		})
	}
}

// wireMarketSecDigest connects attack digests (ADR 0012 §19.1, ML-20/21)
// once the ClickHouse readers exist: as a leaf, market sites' attacks go to
// their root subscribers; as a subscriber, received digests are stored with
// the ingest identity (it holds INSERT on market_security_events_v1) for the
// attack log and alerts. Without ClickHouse both sides stay off.
func wireMarketSecDigest(runtime *marketruntime.Runtime, subscribe *marketsubscribe.Service, client *marketclient.Client,
	summaries *analyticslog.Client, query, ingest clickHouseEndpoint) error {
	if runtime == nil {
		return nil
	}
	var source marketruntime.DigestSource
	if supply, ok := runtime.Supply().(*marketsupply.Service); ok && summaries != nil && query.configured() {
		reader, err := newAutoDefenseClickHouse(query)
		if err != nil {
			return fmt.Errorf("market security digests: %w", err)
		}
		source = supply.WithSecurityReaders(summaries, reader)
	}
	var receiver marketruntime.DigestReceiver
	if subscribe != nil && client != nil && ingest.configured() {
		writer, err := newAutoDefenseClickHouse(ingest)
		if err != nil {
			return fmt.Errorf("market security digests: %w", err)
		}
		receiver = subscribe.WithDigests(client, writer)
	}
	runtime.WithSecDigest(source, receiver)
	return nil
}
