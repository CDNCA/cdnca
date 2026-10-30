package main

import (
	"context"
	"encoding/base64"
	"encoding/json"
	"errors"
	"log/slog"
	"net"
	"net/http"
	"net/netip"
	"net/url"
	"os"
	"strconv"
	"strings"
	"sync/atomic"
	"time"

	"github.com/cdnca/cdnca/services/control-api/internal/cnameallocation"
	"github.com/cdnca/cdnca/services/control-api/internal/dnsacme"
	"github.com/cdnca/cdnca/services/control-api/internal/dnscheck"
	"github.com/cdnca/cdnca/services/control-api/internal/dnsmaintenance"
	"github.com/cdnca/cdnca/services/control-api/internal/dnspropagation"
	"github.com/cdnca/cdnca/services/control-api/internal/dnsproviderremote"
	"github.com/cdnca/cdnca/services/control-api/internal/dnsproviderremotesource"
	"github.com/cdnca/cdnca/services/control-api/internal/dnsreconcile"
	"github.com/cdnca/cdnca/services/control-api/internal/dnsreconcilehttp"
	"github.com/cdnca/cdnca/services/control-api/internal/dnsreconcilehttpmtls"
	"github.com/cdnca/cdnca/services/control-api/internal/entitlementguard"
	"github.com/cdnca/cdnca/services/control-api/internal/identity"
	"github.com/cdnca/cdnca/services/control-api/internal/jobstate"
	"github.com/google/uuid"
	"github.com/jackc/pgx/v5"
	"github.com/jackc/pgx/v5/pgxpool"
)

type dnsReconcileRuntimeConfig struct {
	Enabled                 bool
	Resolver                *dnscheck.NetworkResolver
	EndpointPolicy          dnscheck.EndpointPolicy
	AuthoritativeResolvers  []dnscheck.NamedResolver
	PublicResolvers         []dnscheck.NamedResolver
	Checker                 *dnscheck.Checker
	WorkloadMTLS            *dnsreconcilehttpmtls.Config
	WorkloadIdentities      []dnsreconcilehttpmtls.Identity
	PropagationBootstrap    []dnspropagation.Resolver
	PropagationPublic       []dnspropagation.Resolver
	PropagationPublicQuorum int
}

type dnsReconcileProductionRuntime struct {
	tenantHandler        http.Handler
	workloadServer       *dnsreconcilehttpmtls.Server
	worker               *dnsreconcile.Worker
	cnameWorker          *cnameallocation.Worker
	maintenanceWorker    *dnsmaintenance.Worker
	propagationLifecycle *dnsReconcilePropagationLifecycle
}

type dnsReconcilePropagationLifecycle struct {
	source *dnspropagation.WireSource
	engine *dnspropagation.Engine
	store  *dnspropagation.PostgresRetryStore
	closed atomic.Bool
}

type dnsReconcilePropagationMetrics struct{}

func (dnsReconcilePropagationMetrics) Record(dnspropagation.Metric) {}

type cnameAllocationKeyring struct{ active cnameallocation.Key }

func (keyring cnameAllocationKeyring) Active(context.Context) (cnameallocation.Key, error) {
	return keyring.active, nil
}
func (keyring cnameAllocationKeyring) Lookup(_ context.Context, id string) (cnameallocation.Key, error) {
	if id != keyring.active.ID {
		return cnameallocation.Key{}, cnameallocation.ErrNotFound
	}
	return keyring.active, nil
}

func loadCNAMEAllocationKeyring() (cnameAllocationKeyring, error) {
	id := strings.TrimSpace(os.Getenv("CNAME_ALLOCATION_HMAC_KEY_ID"))
	secret, err := base64.StdEncoding.DecodeString(os.Getenv("CNAME_ALLOCATION_HMAC_KEY"))
	if id == "" || err != nil || len(secret) < 32 {
		return cnameAllocationKeyring{}, errors.New("CNAME allocation HMAC key is invalid")
	}
	return cnameAllocationKeyring{active: cnameallocation.Key{ID: id, Secret: secret}}, nil
}

type dnsReconcileRecoveryTenantSource struct {
	pool    *pgxpool.Pool
	pending *dnsreconcile.PostgresTenantSource
}

type dnsReconcileRecoveryRunner struct {
	source    *dnsReconcileRecoveryTenantSource
	pending   dnsreconcile.TenantRunner
	providers dnsreconcile.ProviderResolver
}

type dnsReconcileRecoveryCandidate struct {
	tenantID         uuid.UUID
	jobID            uuid.UUID
	claimID          uuid.UUID
	recoveryLeaseID  uuid.UUID
	siteID           uuid.UUID
	zoneID           uuid.UUID
	clientRequestID  string
	phase            string
	ordinal          int
	claimState       string
	expectedRevision int64
	providerRequest  string
	providerRecord   string
	finalRevision    int64
	eventSequence    int64
	operationJSON    []byte
	resultSnapshot   []byte
	serverNow        time.Time
}

var errDNSReconcileRecoveryCandidateInvalid = errors.New("invalid DNS reconcile recovery candidate")

type dnsReconcileCheckerResolver struct{ checker *dnscheck.Checker }

// dnsReconcilePropagationContextResolver resolves the zone whose
// authoritative servers the propagation check asks: the CNAME zone's hosted
// apex (migration 473), since a subdomain zone has no NS set of its own (N14).
type dnsReconcilePropagationContextResolver struct {
	pool *pgxpool.Pool
	apex dnsReconcilePropagationApexSource
}

// dnsReconcilePropagationApexSource looks up (and writes back) the apex of a
// zone saved before migration 473 (dnsproviderremotesource.Source).
type dnsReconcilePropagationApexSource interface {
	PropagationZoneApex(ctx context.Context, tenantID, siteID, zoneID uuid.UUID) (string, error)
}

type dnsReconcileSessionAuthenticator struct{ identity *identity.Service }

type dnsReconcileIAMAuthorizer struct{ pool *pgxpool.Pool }

type dnsReconcileEntitlementGate struct {
	pool  *pgxpool.Pool
	guard *entitlementguard.Guard
}

func loadDNSReconcileRuntimeConfig() (dnsReconcileRuntimeConfig, error) {
	return loadDNSReconcileRuntimeConfigFromEnv(os.LookupEnv)
}

func loadDNSReconcileRuntimeConfigFromEnv(lookup accountRecoveryEnvLookup) (dnsReconcileRuntimeConfig, error) {
	if lookup == nil {
		return dnsReconcileRuntimeConfig{}, errors.New("DNS reconcile environment lookup is required")
	}
	enabled, err := accountRecoveryEnvBool(lookup, "DNS_RECONCILE_ENABLED", false)
	if err != nil || !enabled {
		return dnsReconcileRuntimeConfig{}, err
	}
	config := dnsReconcileRuntimeConfig{Enabled: true}
	// Apply/commit verification runs through the propagation engine, which
	// discovers the zone's authoritative servers from its NS delegation. The
	// static resolver allowlist is optional, but all-or-nothing when present.
	if dnsReconcileAnyEnv(lookup, dnsReconcileStaticCheckerEnv) {
		if err := loadDNSReconcileStaticChecker(lookup, &config); err != nil {
			return dnsReconcileRuntimeConfig{}, err
		}
	}
	// The workload mTLS listener only serves provider-report callbacks from
	// external DNS workloads. Single-host native installs have none and run
	// with it disabled; leftover workload settings are then rejected.
	workloadEnabled, err := accountRecoveryEnvBool(lookup, "DNS_RECONCILE_WORKLOAD_MTLS_ENABLED", true)
	if err != nil {
		return dnsReconcileRuntimeConfig{}, err
	}
	if !workloadEnabled && dnsReconcileAnyEnv(lookup, dnsReconcileWorkloadEnv) {
		return dnsReconcileRuntimeConfig{}, errors.New(
			"DNS reconcile workload settings require DNS_RECONCILE_WORKLOAD_MTLS_ENABLED=true")
	}
	if workloadEnabled {
		if err := loadDNSReconcileWorkload(lookup, &config); err != nil {
			return dnsReconcileRuntimeConfig{}, err
		}
	}
	propagationBootstrap, err := parseDNSPropagationResolvers(
		lookup, "DNS_RECONCILE_PROPAGATION_BOOTSTRAP_RESOLVERS",
	)
	if err != nil {
		return dnsReconcileRuntimeConfig{}, err
	}
	propagationPublic, err := parseDNSPropagationResolvers(
		lookup, "DNS_RECONCILE_PROPAGATION_PUBLIC_RESOLVERS",
	)
	if err != nil {
		return dnsReconcileRuntimeConfig{}, err
	}
	// The wire source labels an endpoint public-recursive only when it is a
	// bootstrap resolver; any other public resolver would never cast a vote.
	bootstrapIDs := make(map[string]struct{}, len(propagationBootstrap))
	for _, resolver := range propagationBootstrap {
		bootstrapIDs[resolver.ID] = struct{}{}
	}
	for _, resolver := range propagationPublic {
		if _, found := bootstrapIDs[resolver.ID]; !found {
			return dnsReconcileRuntimeConfig{}, errors.New(
				"DNS_RECONCILE_PROPAGATION_PUBLIC_RESOLVERS must be listed in DNS_RECONCILE_PROPAGATION_BOOTSTRAP_RESOLVERS")
		}
	}
	quorumRaw, err := accountRecoveryRequiredEnv(lookup, "DNS_RECONCILE_PROPAGATION_PUBLIC_QUORUM")
	if err != nil {
		return dnsReconcileRuntimeConfig{}, err
	}
	propagationQuorum, err := strconv.Atoi(quorumRaw)
	if err != nil || strconv.Itoa(propagationQuorum) != quorumRaw || propagationQuorum < 1 ||
		propagationQuorum > len(propagationPublic) {
		return dnsReconcileRuntimeConfig{}, errors.New("DNS_RECONCILE_PROPAGATION_PUBLIC_QUORUM is invalid")
	}
	config.PropagationBootstrap, config.PropagationPublic = propagationBootstrap, propagationPublic
	config.PropagationPublicQuorum = propagationQuorum
	return config, nil
}

var dnsReconcileStaticCheckerEnv = []string{
	"DNS_RECONCILE_RESOLVER_ENDPOINTS", "DNS_RECONCILE_AUTHORITATIVE_RESOLVERS", "DNS_RECONCILE_PUBLIC_RESOLVERS",
}

var dnsReconcileWorkloadEnv = []string{
	"DNS_RECONCILE_WORKLOAD_MTLS_LISTEN_ADDR", "DNS_RECONCILE_WORKLOAD_MTLS_SERVER_CERT_FILE",
	"DNS_RECONCILE_WORKLOAD_MTLS_SERVER_PRIVATE_KEY_FILE", "DNS_RECONCILE_WORKLOAD_MTLS_CLIENT_CA_FILE",
	"DNS_RECONCILE_WORKLOAD_IDENTITIES",
}

func dnsReconcileAnyEnv(lookup accountRecoveryEnvLookup, names []string) bool {
	for _, name := range names {
		if _, exists := lookup(name); exists {
			return true
		}
	}
	return false
}

func loadDNSReconcileStaticChecker(lookup accountRecoveryEnvLookup, config *dnsReconcileRuntimeConfig) error {
	allowedRaw, err := accountRecoveryRequiredEnv(lookup, "DNS_RECONCILE_RESOLVER_ENDPOINTS")
	if err != nil {
		return err
	}
	allowed, err := parseDNSReconcileEndpoints(allowedRaw)
	if err != nil {
		return err
	}
	policy, err := dnscheck.NewEndpointPolicy(allowed...)
	if err != nil {
		return errors.New("DNS_RECONCILE_RESOLVER_ENDPOINTS is invalid")
	}
	resolver, err := dnscheck.NewNetworkResolver(policy, dnscheck.NetworkResolverOptions{MaximumResponseBytes: 4096})
	if err != nil {
		return errors.New("DNS reconcile resolver policy is invalid")
	}
	authoritative, err := parseDNSReconcileNamedResolvers(lookup, "DNS_RECONCILE_AUTHORITATIVE_RESOLVERS", policy)
	if err != nil {
		return err
	}
	public, err := parseDNSReconcileNamedResolvers(lookup, "DNS_RECONCILE_PUBLIC_RESOLVERS", policy)
	if err != nil {
		return err
	}
	checker, err := dnscheck.NewChecker(dnscheck.Config{
		Resolver: resolver, EndpointPolicy: policy, AuthoritativeResolvers: authoritative,
		PublicResolvers: public, QueryTimeout: 5 * time.Second, Attempts: 3, MaxCNAMEDepth: 16, Now: time.Now,
	})
	if err != nil {
		return errors.New("DNS reconcile named resolver configuration is invalid")
	}
	config.Resolver, config.EndpointPolicy, config.Checker = resolver, policy, checker
	config.AuthoritativeResolvers, config.PublicResolvers = authoritative, public
	return nil
}

func loadDNSReconcileWorkload(lookup accountRecoveryEnvLookup, config *dnsReconcileRuntimeConfig) error {
	var err error
	workload := dnsreconcilehttpmtls.DefaultConfig()
	workload.ListenAddress, err = accountRecoveryRequiredEnv(lookup, "DNS_RECONCILE_WORKLOAD_MTLS_LISTEN_ADDR")
	if err != nil {
		return err
	}
	workload.ServerCertificateFile, err = accountRecoveryRequiredEnv(lookup, "DNS_RECONCILE_WORKLOAD_MTLS_SERVER_CERT_FILE")
	if err != nil {
		return err
	}
	workload.ServerPrivateKeyFile, err = accountRecoveryRequiredEnv(lookup, "DNS_RECONCILE_WORKLOAD_MTLS_SERVER_PRIVATE_KEY_FILE")
	if err != nil {
		return err
	}
	workload.ClientCAFile, err = accountRecoveryRequiredEnv(lookup, "DNS_RECONCILE_WORKLOAD_MTLS_CLIENT_CA_FILE")
	if err != nil {
		return err
	}
	if err := workload.Validate(); err != nil {
		return err
	}
	identities, err := parseDNSReconcileWorkloadIdentities(lookup)
	if err != nil {
		return err
	}
	if _, err := dnsreconcilehttpmtls.NewAuthenticator(identities); err != nil {
		return err
	}
	config.WorkloadMTLS, config.WorkloadIdentities = &workload, identities
	return nil
}

func parseDNSPropagationResolvers(lookup accountRecoveryEnvLookup, name string) ([]dnspropagation.Resolver, error) {
	raw, err := accountRecoveryRequiredEnv(lookup, name)
	if err != nil {
		return nil, err
	}
	parts := strings.Split(raw, ",")
	if len(parts) == 0 || len(parts) > 64 {
		return nil, errors.New(name + " is invalid")
	}
	result := make([]dnspropagation.Resolver, 0, len(parts))
	names := make(map[string]struct{}, len(parts))
	endpoints := make(map[string]struct{}, len(parts))
	for _, part := range parts {
		resolverName, endpointRaw, found := strings.Cut(part, "=")
		endpoint, endpointErr := netip.ParseAddrPort(endpointRaw)
		if !found || resolverName == "" || resolverName != strings.TrimSpace(resolverName) ||
			len(resolverName) > 255 || strings.ContainsRune(resolverName, 0) || endpointErr != nil ||
			endpoint.String() != endpointRaw || endpoint.Port() != 53 || !publicDNSResolverAddress(endpoint.Addr()) {
			return nil, errors.New(name + " is invalid")
		}
		if _, duplicate := names[resolverName]; duplicate {
			return nil, errors.New(name + " contains a duplicate resolver name")
		}
		if _, duplicate := endpoints[endpointRaw]; duplicate {
			return nil, errors.New(name + " contains a duplicate resolver endpoint")
		}
		names[resolverName] = struct{}{}
		endpoints[endpointRaw] = struct{}{}
		result = append(result, dnspropagation.Resolver{ID: endpointRaw, Name: resolverName})
	}
	return result, nil
}

func publicDNSResolverAddress(address netip.Addr) bool {
	return address.IsValid() && !address.Is4In6() && address.IsGlobalUnicast() && !address.IsPrivate() &&
		!address.IsLoopback() && !address.IsLinkLocalUnicast() && !address.IsMulticast() && !address.IsUnspecified()
}

func parseDNSReconcileEndpoints(raw string) ([]dnscheck.ResolverEndpoint, error) {
	parts := strings.Split(raw, ",")
	if len(parts) == 0 || len(parts) > 64 {
		return nil, errors.New("DNS_RECONCILE_RESOLVER_ENDPOINTS is invalid")
	}
	result := make([]dnscheck.ResolverEndpoint, 0, len(parts))
	seen := make(map[string]struct{}, len(parts))
	for _, part := range parts {
		endpoint, canonical, err := parseDNSReconcileEndpoint(part)
		if err != nil {
			return nil, errors.New("DNS_RECONCILE_RESOLVER_ENDPOINTS is invalid")
		}
		if _, duplicate := seen[canonical]; duplicate {
			return nil, errors.New("DNS_RECONCILE_RESOLVER_ENDPOINTS contains a duplicate endpoint")
		}
		seen[canonical] = struct{}{}
		result = append(result, endpoint)
	}
	return result, nil
}

func parseDNSReconcileEndpoint(raw string) (dnscheck.ResolverEndpoint, string, error) {
	parsed, err := url.Parse(raw)
	if err != nil || raw == "" || raw != strings.TrimSpace(raw) || parsed.User != nil || parsed.Host == "" ||
		parsed.Path != "" || parsed.RawPath != "" || parsed.RawQuery != "" || parsed.Fragment != "" ||
		parsed.Opaque != "" || parsed.Scheme != "udp" && parsed.Scheme != "tcp" {
		return dnscheck.ResolverEndpoint{}, "", errors.New("invalid DNS resolver endpoint")
	}
	host, portText, err := net.SplitHostPort(parsed.Host)
	port, portErr := strconv.Atoi(portText)
	address, addressErr := netip.ParseAddr(host)
	if err != nil || portErr != nil || addressErr != nil || port < 1 || port > 65535 || strconv.Itoa(port) != portText {
		return dnscheck.ResolverEndpoint{}, "", errors.New("invalid DNS resolver endpoint")
	}
	endpoint, err := dnscheck.NewResolverEndpoint(parsed.Scheme, address.String(), uint16(port))
	if err != nil {
		return dnscheck.ResolverEndpoint{}, "", err
	}
	canonical := endpoint.Network + "://" + netip.AddrPortFrom(endpoint.Address, endpoint.Port).String()
	if canonical != raw {
		return dnscheck.ResolverEndpoint{}, "", errors.New("DNS resolver endpoint is not canonical")
	}
	return endpoint, canonical, nil
}

func parseDNSReconcileNamedResolvers(lookup accountRecoveryEnvLookup, name string,
	policy dnscheck.EndpointPolicy) ([]dnscheck.NamedResolver, error) {
	raw, err := accountRecoveryRequiredEnv(lookup, name)
	if err != nil {
		return nil, err
	}
	parts := strings.Split(raw, ",")
	if len(parts) == 0 || len(parts) > 64 {
		return nil, errors.New(name + " is invalid")
	}
	result := make([]dnscheck.NamedResolver, 0, len(parts))
	seen := make(map[string]struct{}, len(parts))
	for _, part := range parts {
		resolverName, endpointRaw, found := strings.Cut(part, "=")
		if !found || resolverName == "" || endpointRaw == "" || strings.TrimSpace(resolverName) != resolverName {
			return nil, errors.New(name + " is invalid")
		}
		if _, duplicate := seen[resolverName]; duplicate {
			return nil, errors.New(name + " contains a duplicate resolver name")
		}
		endpoint, _, err := parseDNSReconcileEndpoint(endpointRaw)
		if err != nil || policy.Check(endpoint) != nil {
			return nil, errors.New(name + " references an endpoint outside the allowlist")
		}
		seen[resolverName] = struct{}{}
		result = append(result, dnscheck.NamedResolver{Name: resolverName, Endpoint: endpoint})
	}
	return result, nil
}

func parseDNSReconcileWorkloadIdentities(lookup accountRecoveryEnvLookup) ([]dnsreconcilehttpmtls.Identity, error) {
	raw, err := accountRecoveryRequiredEnv(lookup, "DNS_RECONCILE_WORKLOAD_IDENTITIES")
	if err != nil {
		return nil, err
	}
	parts := strings.Split(raw, ",")
	if len(parts) == 0 || len(parts) > 1024 {
		return nil, errors.New("DNS_RECONCILE_WORKLOAD_IDENTITIES is invalid")
	}
	result := make([]dnsreconcilehttpmtls.Identity, 0, len(parts))
	for _, part := range parts {
		fields := strings.Split(part, "|")
		if len(fields) != 4 {
			return nil, errors.New("DNS_RECONCILE_WORKLOAD_IDENTITIES is invalid")
		}
		tenantID, tenantErr := uuid.Parse(fields[2])
		siteID, siteErr := uuid.Parse(fields[3])
		if tenantErr != nil || siteErr != nil || tenantID.String() != fields[2] || siteID.String() != fields[3] {
			return nil, errors.New("DNS_RECONCILE_WORKLOAD_IDENTITIES contains a non-canonical scope")
		}
		result = append(result, dnsreconcilehttpmtls.Identity{
			URI: fields[0], WorkloadID: fields[1], TenantID: tenantID, SiteID: siteID,
		})
	}
	return result, nil
}

func openDNSReconcileProductionRuntime(ctx context.Context, config dnsReconcileRuntimeConfig,
	pool *pgxpool.Pool, identityService *identity.Service, cipher dnsacme.CredentialCipher,
	trust *entitlementguard.TrustStore) (*dnsReconcileProductionRuntime, error) {
	if !config.Enabled {
		return nil, nil
	}
	if ctx == nil || pool == nil || identityService == nil || cipher == nil ||
		(config.WorkloadMTLS == nil) != (len(config.WorkloadIdentities) == 0) ||
		len(config.PropagationBootstrap) == 0 || len(config.PropagationPublic) == 0 ||
		config.PropagationPublicQuorum < 1 || config.PropagationPublicQuorum > len(config.PropagationPublic) {
		return nil, errors.New("DNS reconcile runtime configuration is incomplete")
	}
	// Keep verifyDNSPropagationSchema(ctx,pool) before every propagation constructor.
	if err := verifyDNSPropagationSchema(ctx, pool); err != nil {
		return nil, err
	}
	dialer := &net.Dialer{Timeout: 5 * time.Second}
	propagationSource, err := dnspropagation.NewWireSource(dnspropagation.WireSourceConfig{
		Bootstrap: config.PropagationBootstrap, DialContext: dialer.DialContext,
		QueryTimeout: 5 * time.Second, MaximumResponseBytes: 4096, Now: time.Now,
		FamilyAvailable: dnspropagation.LocalAddressFamilies(),
	})
	if err != nil {
		return nil, err
	}
	propagationEngine, err := dnspropagation.NewEngine(dnspropagation.Config{
		Source: propagationSource, Public: config.PropagationPublic,
		PublicQuorum: config.PropagationPublicQuorum,
		MinTTL:       time.Second, MaxTTL: 7 * 24 * time.Hour,
		MinNegativeTTL: time.Second, MaxNegativeTTL: 24 * time.Hour,
		MaxAge: 30 * time.Second, Now: time.Now, Metrics: dnsReconcilePropagationMetrics{},
	})
	if err != nil {
		return nil, err
	}
	propagationStore, err := dnspropagation.NewPostgresRetryStore(pool)
	if err != nil {
		return nil, err
	}
	propagationLifecycle := &dnsReconcilePropagationLifecycle{
		source: propagationSource, engine: propagationEngine, store: propagationStore,
	}
	providerSource := dnsproviderremotesource.New(pool, cipher)
	providerResolver, err := dnsproviderremotesource.NewReconcileResolver(providerSource, dnsproviderremote.NewReconcileRemote())
	if err != nil {
		return nil, err
	}
	jobs, err := jobstate.NewStore(pool, time.Now)
	if err != nil {
		return nil, err
	}
	store, err := dnsreconcile.NewPostgresStore(pool, jobs, time.Now)
	if err != nil {
		return nil, err
	}
	domain, err := dnsreconcile.NewRuntime(defaultDNSReconcileDomainConfig(), dnsreconcile.RuntimeDependencies{
		Store: store, ProviderResolver: providerResolver,
		Entitlement: &dnsReconcileEntitlementGate{pool: pool, guard: entitlementguard.NewGuard(pool, time.Now, trust)},
		Propagation: dnsreconcile.PropagationDependencies{
			Engine: propagationEngine, RetryStates: propagationStore,
			ContextResolver: &dnsReconcilePropagationContextResolver{pool: pool, apex: providerSource},
			Policy: dnspropagation.ProviderRetryPolicy{
				BaseDelay: time.Second, MaxDelay: 30 * time.Second, BudgetWindow: time.Minute,
				CircuitOpen: time.Minute, AttemptsPerZone: 20, TransientFailuresToOpen: 3,
			},
		},
	})
	if err != nil {
		return nil, err
	}
	pendingTenants, err := dnsreconcile.NewPostgresTenantSource(pool)
	if err != nil {
		return nil, err
	}
	tenantSource := &dnsReconcileRecoveryTenantSource{pool: pool, pending: pendingTenants}
	recoveryRunner := &dnsReconcileRecoveryRunner{source: tenantSource, pending: domain, providers: providerResolver}
	worker, err := dnsreconcile.NewWorker(dnsreconcile.WorkerConfig{
		WorkerID: "control-api-dns-reconcile", TenantLimit: 128, ClaimLimit: 16, PollInterval: time.Second,
	}, dnsreconcile.WorkerDependencies{Tenants: tenantSource, Runner: recoveryRunner})
	if err != nil {
		return nil, err
	}
	keyring, err := loadCNAMEAllocationKeyring()
	if err != nil {
		return nil, err
	}
	cnameStore, err := cnameallocation.NewStore(pool, keyring, time.Now)
	if err != nil {
		return nil, err
	}
	// Tenants created after the platform DNS configuration get its copy on
	// their first CNAME allocation.
	dnsService := dnsacme.NewService(dnsacme.NewStore(pool), cipher)
	cnameStore.UsePlatformDNS(dnsService)
	// CNAME publications see the owner's current provider records so a
	// shrinking serving set (paused node, standby IP back offline) deletes
	// the values no longer served.
	ownerSnapshot, err := dnsproviderremotesource.NewOwnerSnapshot(providerSource, dnsproviderremote.NewZoneRecordLister())
	if err != nil {
		return nil, err
	}
	// Retired CNAME owners (deleted sites, rotated generations; migration
	// 478) are deleted from the provider by the CNAME worker.
	retiredOwners, err := dnsproviderremotesource.NewRetiredOwners(providerSource,
		dnsproviderremote.NewReconcileRemote().(dnsproviderremotesource.RetiredOwnerRemote))
	if err != nil {
		return nil, err
	}
	cnameWorker, err := cnameallocation.NewWorker(cnameallocation.WorkerConfig{
		WorkerID: "control-api-cname-allocation", LeaseDuration: 16 * time.Minute, PollInterval: time.Second,
		RetargetInterval: 10 * time.Second,
	}, cnameallocation.WorkerDependencies{Tenants: cnameStore, Intents: cnameStore, StreamIntents: cnameStore, Claims: jobs, Targets: cnameStore,
		Reconcile: domain, Retargets: cnameStore, Snapshots: ownerSnapshot,
		Retirements: cnameStore, RetiredOwners: retiredOwners, EndedJobs: cnameStore})
	if err != nil {
		return nil, err
	}
	maintenanceStore, err := dnsmaintenance.NewStore(pool)
	if err != nil {
		return nil, err
	}
	// 节点管理 > DNS配置 记录修复 / 清除CDN无关解析 (dns.repair.v1 / dns.cleanup.v1).
	maintenanceWorker, err := dnsmaintenance.NewWorker(dnsmaintenance.WorkerConfig{
		WorkerID: "control-api-dns-maintenance", PollInterval: 2 * time.Second, LeaseDuration: 30 * time.Minute,
		ItemTimeout: 20 * time.Minute, TaskPoll: 2 * time.Second,
	}, jobs, maintenanceStore, dnsService,
		dnsproviderremote.NewReconcileRemote().(dnsmaintenance.Remote), domain)
	if err != nil {
		return nil, err
	}
	var workloads dnsreconcilehttp.WorkloadAuthenticator = dnsReconcileNoWorkloads{}
	var authenticator *dnsreconcilehttpmtls.Authenticator
	if config.WorkloadMTLS != nil {
		authenticator, err = dnsreconcilehttpmtls.NewAuthenticator(config.WorkloadIdentities)
		if err != nil {
			return nil, err
		}
		workloads = authenticator
	}
	handler, err := dnsreconcilehttp.NewHandler(dnsreconcilehttp.Dependencies{
		Sessions: &dnsReconcileSessionAuthenticator{identity: identityService},
		IAM:      &dnsReconcileIAMAuthorizer{pool: pool}, Domain: domain, Workloads: workloads,
	}, dnsreconcilehttp.Config{})
	if err != nil {
		return nil, err
	}
	var workloadServer *dnsreconcilehttpmtls.Server
	if config.WorkloadMTLS != nil {
		workloadServer, err = dnsreconcilehttpmtls.New(ctx, config.WorkloadMTLS, authenticator,
			dnsreconcilehttp.NewProviderReportHandler(handler))
		if err != nil {
			return nil, err
		}
	}
	return &dnsReconcileProductionRuntime{
		tenantHandler: dnsreconcilehttp.NewTenantHandler(handler), workloadServer: workloadServer, worker: worker,
		cnameWorker: cnameWorker, maintenanceWorker: maintenanceWorker, propagationLifecycle: propagationLifecycle,
	}, nil
}

func verifyDNSPropagationSchema(ctx context.Context, pool *pgxpool.Pool) error {
	if ctx == nil || pool == nil {
		return errors.New("DNS propagation schema is unavailable")
	}
	var ready bool
	err := pool.QueryRow(ctx, `WITH relation AS (
		SELECT to_regclass('public.dns_provider_retry_states') AS oid
	), columns_ready AS (
		SELECT COALESCE(array_agg(attribute.attname::text ORDER BY attribute.attnum)
			FILTER (WHERE attribute.attnum>0 AND NOT attribute.attisdropped),'{}'::text[])=
			ARRAY['tenant_id','tenant_scope_id','zone_id','provider_id','revision','state','updated_at']::text[]
		AND COALESCE(array_agg(format_type(attribute.atttypid,attribute.atttypmod) ORDER BY attribute.attnum)
			FILTER (WHERE attribute.attnum>0 AND NOT attribute.attisdropped),'{}'::text[])=
			ARRAY['uuid','uuid','uuid','uuid','bigint','jsonb','timestamp with time zone']::text[]
		AND COALESCE(bool_and(attribute.attnotnull)
			FILTER (WHERE attribute.attnum>0 AND NOT attribute.attisdropped),false) AS ready
		FROM relation LEFT JOIN pg_attribute attribute ON attribute.attrelid=relation.oid
	), constraints_ready AS (
		SELECT count(*) FILTER (WHERE constraint_.contype IN ('p','f','c'))=9
		AND count(*) FILTER (WHERE constraint_.contype='p' AND constraint_.conkey=ARRAY[1,3,4]::smallint[])=1
		AND count(*) FILTER (WHERE constraint_.contype='f' AND constraint_.confdeltype='r')=3
		AND count(*) FILTER (WHERE constraint_.contype='f' AND
			pg_get_constraintdef(constraint_.oid) LIKE '%REFERENCES access_scopes(id, tenant_id) ON DELETE RESTRICT%')=1
		AND count(*) FILTER (WHERE constraint_.contype='f' AND
			pg_get_constraintdef(constraint_.oid) LIKE '%REFERENCES dns_zones(scope_id, id, provider_id) ON DELETE RESTRICT%')=1
		AND count(*) FILTER (WHERE constraint_.contype='f' AND
			pg_get_constraintdef(constraint_.oid) LIKE '%REFERENCES dns_providers(scope_id, id) ON DELETE RESTRICT%')=1
		AND count(*) FILTER (WHERE constraint_.contype='c' AND
			pg_get_expr(constraint_.conbin,constraint_.conrelid) LIKE '%revision > 0%')=1
		AND count(*) FILTER (WHERE constraint_.contype='c' AND
			pg_get_expr(constraint_.conbin,constraint_.conrelid) LIKE '%jsonb_typeof(state)%object%')=1
		AND count(*) FILTER (WHERE constraint_.contype='c' AND
			pg_get_expr(constraint_.conbin,constraint_.conrelid) LIKE '%Revision%bigint%revision%')=1
		AND count(*) FILTER (WHERE constraint_.contype='c' AND
			pg_get_expr(constraint_.conbin,constraint_.conrelid) LIKE '%isfinite(updated_at)%microseconds%')=1 AS ready
		FROM relation LEFT JOIN pg_constraint constraint_ ON constraint_.conrelid=relation.oid
	), trigger_ready AS (
		SELECT count(*) FILTER (WHERE trigger_.tgname='dns_provider_retry_state_scope_guard_155'
			AND NOT trigger_.tgisinternal AND trigger_.tgenabled<>'D')=1 AS ready
		FROM relation LEFT JOIN pg_trigger trigger_ ON trigger_.tgrelid=relation.oid
	)
	SELECT relation.oid IS NOT NULL AND columns_ready.ready AND constraints_ready.ready AND trigger_ready.ready
	FROM relation CROSS JOIN columns_ready CROSS JOIN constraints_ready CROSS JOIN trigger_ready`).Scan(&ready)
	if err != nil || !ready {
		return errors.New("DNS propagation schema is unavailable")
	}
	return nil
}

func defaultDNSReconcileDomainConfig() dnsreconcile.RuntimeConfig {
	return dnsreconcile.RuntimeConfig{
		ProviderAttempts: 3, ProviderTimeout: 5 * time.Second, PollAttempts: 20,
		RequiredConsecutive: 3, InitialBackoff: time.Second, MaximumBackoff: 30 * time.Second,
		OverallTimeout: 15 * time.Minute, ApplyLeaseDuration: 16 * time.Minute,
		CommitLeaseDuration: 16 * time.Minute, Now: time.Now, PropagationEnabled: true,
	}
}

func (source *dnsReconcileRecoveryTenantSource) PendingTenants(ctx context.Context, limit int) ([]uuid.UUID, error) {
	if source == nil || source.pool == nil || source.pending == nil || ctx == nil || limit < 1 || limit > 1000 {
		return nil, dnsreconcile.ErrInvalidInput
	}
	recovery := make([]uuid.UUID, 0, limit)
	rows, err := source.pool.Query(ctx, `
		SELECT DISTINCT claim.tenant_id
			FROM dns_reconcile_provider_mutation_claims claim
			JOIN background_jobs job ON job.tenant_id=claim.tenant_id AND job.id=claim.job_id
			LEFT JOIN dns_reconcile_provider_recovery_failures failure
			  ON failure.tenant_id=claim.tenant_id AND failure.client_request_id=claim.client_request_id
			LEFT JOIN dns_reconcile_provider_recovery_continuations continuation
			  ON continuation.tenant_id=claim.tenant_id AND continuation.job_id=claim.job_id
			LEFT JOIN dns_reconcile_provider_recovery_leases recovery_lease
			  ON recovery_lease.tenant_id=claim.tenant_id
			 AND recovery_lease.client_request_id=claim.client_request_id
			 AND recovery_lease.state='active'
			 AND recovery_lease.lease_expires_at>clock_timestamp()
		JOIN LATERAL (
			SELECT event.status,event.error_code,event.result_snapshot
			FROM dns_reconcile_task_events event
			WHERE event.tenant_id=claim.tenant_id AND event.job_id=claim.job_id
			ORDER BY event.event_sequence DESC LIMIT 1
		) latest ON true
			WHERE continuation.tenant_id IS NULL AND recovery_lease.tenant_id IS NULL
			  AND (failure.tenant_id IS NULL OR
			       (failure.disposition='backoff' AND failure.retry_not_before<=clock_timestamp()))
			  AND (
			(claim.state='uncertain' AND claim.recovery_not_before<=clock_timestamp()
			 AND claim.lease_expires_at<=clock_timestamp())
			OR (claim.state='claimed' AND claim.lease_expires_at<=clock_timestamp())
			OR claim.state IN ('succeeded','not_applied','conflict')
		) AND (
			claim.phase='commit' OR job.state IN ('failed','partial_failed')
		) AND latest.status IN ('applying','ready_to_commit','failed','commit_failed')
		  AND latest.result_snapshot ->
		      (CASE claim.phase WHEN 'apply' THEN 'Operations' ELSE 'DeferredDeletes' END) ->
		      (claim.operation_ordinal-1) ->> 'ClientRequestID'=claim.client_request_id
		  AND latest.result_snapshot ->
		      (CASE claim.phase WHEN 'apply' THEN 'Operations' ELSE 'DeferredDeletes' END) ->
		      (claim.operation_ordinal-1) ->> 'Status' IN ('running','transient_failed')
		ORDER BY claim.tenant_id LIMIT $1`, limit)
	if err != nil {
		return nil, dnsreconcile.ErrUnavailable
	}
	defer rows.Close()
	for rows.Next() {
		var tenantID uuid.UUID
		if rows.Scan(&tenantID) != nil || tenantID == uuid.Nil {
			return nil, dnsreconcile.ErrUnavailable
		}
		recovery = append(recovery, tenantID)
	}
	if rows.Err() != nil {
		return nil, dnsreconcile.ErrUnavailable
	}
	// Tenants holding an apply claim finalizeAbandonedApplyClaims will end:
	// the same job, operation status, quarantine, continuation and lease
	// conditions, so a claim still owned by recovery (its lookup in backoff)
	// does not take a fair slot every round for nothing.
	abandoned, err := source.pool.Query(ctx, `SELECT DISTINCT claim.tenant_id
		FROM dns_reconcile_provider_mutation_claims claim
		JOIN background_jobs job ON job.tenant_id=claim.tenant_id AND job.id=claim.job_id
		JOIN LATERAL (
			SELECT event.result_snapshot
			FROM dns_reconcile_task_events event
			WHERE event.tenant_id=claim.tenant_id AND event.job_id=claim.job_id
			ORDER BY event.event_sequence DESC LIMIT 1
		) latest ON true
		WHERE claim.phase='apply' AND claim.state IN ('claimed','uncertain')
		  AND claim.lease_expires_at<=clock_timestamp()
		  AND job.state IN ('failed','partial_failed','cancelled')
		  AND (COALESCE(latest.result_snapshot -> 'Operations' -> (claim.operation_ordinal-1) ->> 'Status','')
		      NOT IN ('running','transient_failed') OR EXISTS (
			SELECT 1 FROM dns_reconcile_provider_recovery_failures failure
			WHERE failure.tenant_id=claim.tenant_id AND failure.client_request_id=claim.client_request_id
			  AND failure.disposition='quarantined'))
		  AND NOT EXISTS (SELECT 1 FROM dns_reconcile_provider_recovery_continuations continuation
			WHERE continuation.tenant_id=claim.tenant_id AND continuation.job_id=claim.job_id)
		  AND NOT EXISTS (SELECT 1 FROM dns_reconcile_provider_recovery_leases recovery_lease
			WHERE recovery_lease.tenant_id=claim.tenant_id
			  AND recovery_lease.client_request_id=claim.client_request_id AND recovery_lease.state='active')
		ORDER BY claim.tenant_id LIMIT $1`, limit)
	if err != nil {
		return nil, dnsreconcile.ErrUnavailable
	}
	tenants, err := pgx.CollectRows(abandoned, pgx.RowTo[uuid.UUID])
	if err != nil {
		return nil, dnsreconcile.ErrUnavailable
	}
	recovery = append(recovery, tenants...)
	pending, err := source.pending.PendingTenants(ctx, limit)
	if err != nil {
		return nil, err
	}
	seen := make(map[uuid.UUID]struct{}, limit)
	result := make([]uuid.UUID, 0, limit)
	for index := 0; len(result) < limit && (index < len(pending) || index < len(recovery)); index++ {
		for _, candidates := range [][]uuid.UUID{pending, recovery} {
			if index >= len(candidates) {
				continue
			}
			tenantID := candidates[index]
			if _, duplicate := seen[tenantID]; duplicate {
				continue
			}
			seen[tenantID] = struct{}{}
			result = append(result, tenantID)
			if len(result) == limit {
				break
			}
		}
	}
	return result, nil
}

func (runner *dnsReconcileRecoveryRunner) RunOnce(ctx context.Context, tenantID uuid.UUID,
	workerID string, limit int) ([]dnsreconcile.Task, error) {
	if runner == nil || runner.source == nil || runner.pending == nil || runner.providers == nil ||
		ctx == nil || tenantID == uuid.Nil || workerID == "" || limit < 1 || limit > 100 {
		return nil, dnsreconcile.ErrInvalidInput
	}
	if err := runner.recoverDueUncertain(ctx, tenantID, limit); err != nil {
		return nil, err
	}
	return runner.pending.RunOnce(ctx, tenantID, workerID, limit)
}

func (runner *dnsReconcileRecoveryRunner) recoverDueUncertain(ctx context.Context,
	tenantID uuid.UUID, limit int) error {
	if err := runner.source.finalizeAbandonedApplyClaims(ctx, tenantID, limit); err != nil {
		return err
	}
	if err := runner.source.markExpiredPersistenceFailuresUncertain(ctx, tenantID, limit); err != nil {
		return err
	}
	candidates, err := runner.source.dueUncertainCandidates(ctx, tenantID, limit)
	if err != nil {
		return err
	}
	for _, candidate := range candidates {
		if candidate.claimState == string(dnsproviderremote.MutationUncertain) {
			var operation dnscheck.ProviderOperation
			if json.Unmarshal(candidate.operationJSON, &operation) != nil {
				if err := runner.source.recordRecoveryCandidateFailure(
					ctx, candidate, "provider_recovery_candidate_invalid", "quarantined",
				); err != nil {
					if ctx.Err() != nil {
						return ctx.Err()
					}
					return err
				}
				continue
			}
			provider, resolveErr := runner.providers.ResolveProvider(
				ctx, candidate.tenantID, candidate.siteID, candidate.zoneID,
			)
			if resolveErr != nil || provider == nil {
				if err := runner.source.recordRecoveryCandidateFailure(
					ctx, candidate, "provider_recovery_provider_unavailable", "backoff",
				); err != nil {
					if ctx.Err() != nil {
						return ctx.Err()
					}
					return err
				}
				continue
			}
			lookupContext, cancel := context.WithTimeout(ctx, defaultDNSReconcileDomainConfig().OverallTimeout)
			_, mutationErr := provider.Mutate(lookupContext, dnscheck.ProviderMutation{
				ClientRequestID: candidate.clientRequestID, TenantID: candidate.tenantID,
				SiteID: candidate.siteID, ZoneID: candidate.zoneID,
				ExpectedRevision: candidate.expectedRevision, Operation: operation,
			})
			cancel()
			if mutationErr != nil {
				if ctx.Err() != nil {
					return ctx.Err()
				}
				if err := runner.source.recordRecoveryCandidateFailure(
					ctx, candidate, "provider_recovery_lookup_failed", "backoff",
				); err != nil {
					if ctx.Err() != nil {
						return ctx.Err()
					}
					return err
				}
				continue
			}
		}
		if err := runner.source.requeueDueUncertain(ctx, candidate); err != nil {
			disposition := "backoff"
			reason := "provider_recovery_requeue_failed"
			if errors.Is(err, errDNSReconcileRecoveryCandidateInvalid) {
				disposition = "quarantined"
				reason = "provider_recovery_candidate_invalid"
			}
			if persistErr := runner.source.recordRecoveryCandidateFailure(
				ctx, candidate, reason, disposition,
			); persistErr != nil {
				if ctx.Err() != nil {
					return ctx.Err()
				}
				return persistErr
			}
		}
	}
	return nil
}

func (source *dnsReconcileRecoveryTenantSource) recordRecoveryCandidateFailure(
	ctx context.Context, candidate dnsReconcileRecoveryCandidate, reason, disposition string,
) error {
	return pgx.BeginFunc(ctx, source.pool, func(tx pgx.Tx) error {
		command, err := tx.Exec(ctx, `INSERT INTO dns_reconcile_provider_recovery_failures(
			tenant_id,client_request_id,claim_id,job_id,recovery_lease_id,
			reason_code,disposition,failure_count,
			retry_not_before,first_failed_at,last_failed_at
		) VALUES($1,$2,$3,$4,$5,$6,$7,1,clock_timestamp(),clock_timestamp(),clock_timestamp())
		ON CONFLICT (tenant_id,client_request_id) DO UPDATE
		SET claim_id=EXCLUDED.claim_id,recovery_lease_id=EXCLUDED.recovery_lease_id,
		    reason_code=EXCLUDED.reason_code,disposition=EXCLUDED.disposition`,
			candidate.tenantID, candidate.clientRequestID, candidate.claimID, candidate.jobID,
			candidate.recoveryLeaseID, reason, disposition)
		if err != nil || command.RowsAffected() != 1 {
			return dnsreconcile.ErrUnavailable
		}
		command, err = tx.Exec(ctx, `UPDATE dns_reconcile_provider_recovery_leases
			SET state='released'
			WHERE tenant_id=$1 AND client_request_id=$2 AND job_id=$3
			  AND recovery_lease_id=$4 AND state='active'`, candidate.tenantID,
			candidate.clientRequestID, candidate.jobID, candidate.recoveryLeaseID)
		if err != nil || command.RowsAffected() != 1 {
			return dnsreconcile.ErrUnavailable
		}
		return nil
	})
}

// finalizeAbandonedApplyClaims ends the apply claims nothing will recover
// (N8): the job is terminal and either the latest task event no
// longer has the claim's operation running or transient_failed (recovery only
// takes those) or recovery quarantined it, with no recovery lease or
// continuation on it. Left claimed or
// uncertain such a claim locks the site, zone and provider (089/474) for
// good. It becomes conflict (089: outcome not recorded, zone revision kept),
// so a new reconcile task plans from the provider's live records. The
// binding conditions in the WHERE are the ones 089 re-checks on the update.
func (source *dnsReconcileRecoveryTenantSource) finalizeAbandonedApplyClaims(
	ctx context.Context, tenantID uuid.UUID, limit int) error {
	_, err := source.pool.Exec(ctx, `WITH abandoned AS (
		SELECT claim.ctid
		FROM dns_reconcile_provider_mutation_claims claim
		JOIN background_jobs job ON job.tenant_id=claim.tenant_id AND job.id=claim.job_id
		JOIN dns_reconcile_tasks task ON task.tenant_id=claim.tenant_id AND task.job_id=claim.job_id
		 AND task.site_id IS NOT DISTINCT FROM claim.site_id AND task.stream_id IS NOT DISTINCT FROM claim.stream_id
		 AND task.zone_id=claim.zone_id
		JOIN access_scopes scope ON scope.id=task.tenant_scope_id AND scope.kind='tenant'
		 AND scope.tenant_id=task.tenant_id
		JOIN dns_zones zone ON zone.scope_id=task.tenant_scope_id AND zone.id=task.zone_id
		 AND zone.revision=claim.expected_zone_revision
		JOIN dns_providers provider ON provider.scope_id=zone.scope_id AND provider.id=zone.provider_id
		 AND provider.id=claim.provider_id AND provider.revision=claim.expected_provider_revision
		JOIN dns_reconcile_operations operation ON operation.tenant_id=claim.tenant_id
		 AND operation.job_id=claim.job_id AND operation.phase=claim.phase AND operation.ordinal=claim.operation_ordinal
		-- The task's anchor (migration 507): its live site, or its live stream.
		CROSS JOIN LATERAL dns_reconcile_anchor_507(task.tenant_scope_id,task.site_id,task.stream_id,zone,provider) anchor
		JOIN LATERAL (
			SELECT event.result_snapshot
			FROM dns_reconcile_task_events event
			WHERE event.tenant_id=claim.tenant_id AND event.job_id=claim.job_id
			ORDER BY event.event_sequence DESC LIMIT 1
		) latest ON true
		WHERE claim.tenant_id=$1 AND claim.phase='apply'
		  AND claim.state IN ('claimed','uncertain') AND claim.lease_expires_at<=clock_timestamp()
		  AND anchor.revision=claim.expected_site_revision
		  AND task.provider_mutation_site_revision=claim.expected_site_revision
		  AND task.provider_mutation_site_config_digest=claim.site_config_digest
		  AND anchor.config_digest=claim.site_config_digest
		  AND dns_reconcile_operation_digest_089(operation.operation)=claim.operation_digest
		  AND anchor.authority_digest=claim.authority_digest
		  AND dns_reconcile_provider_config_digest_089(zone,provider)=claim.provider_config_digest
		  AND dns_reconcile_credential_digest_089(provider.credential_key_id,provider.credential_ciphertext)=claim.credential_digest
		  AND job.state IN ('failed','partial_failed','cancelled')
		  AND (COALESCE(latest.result_snapshot -> 'Operations' -> (claim.operation_ordinal-1) ->> 'Status','')
		      NOT IN ('running','transient_failed') OR EXISTS (
			SELECT 1 FROM dns_reconcile_provider_recovery_failures failure
			WHERE failure.tenant_id=claim.tenant_id AND failure.client_request_id=claim.client_request_id
			  AND failure.disposition='quarantined'))
		  AND NOT EXISTS (SELECT 1 FROM dns_reconcile_provider_recovery_continuations continuation
			WHERE continuation.tenant_id=claim.tenant_id AND continuation.job_id=claim.job_id)
		  AND NOT EXISTS (SELECT 1 FROM dns_reconcile_provider_recovery_leases recovery_lease
			WHERE recovery_lease.tenant_id=claim.tenant_id
			  AND recovery_lease.client_request_id=claim.client_request_id AND recovery_lease.state='active')
		ORDER BY claim.claimed_at,claim.client_request_id
		LIMIT $2 FOR UPDATE OF claim SKIP LOCKED
		)
		UPDATE dns_reconcile_provider_mutation_claims claim
		SET state='conflict',final_zone_revision=claim.expected_zone_revision,finalized_at=clock_timestamp()
		FROM abandoned WHERE claim.ctid=abandoned.ctid`, tenantID, limit)
	if err != nil {
		return dnsreconcile.ErrUnavailable
	}
	return nil
}

func (source *dnsReconcileRecoveryTenantSource) markExpiredPersistenceFailuresUncertain(
	ctx context.Context, tenantID uuid.UUID, limit int) error {
	_, err := source.pool.Exec(ctx, `WITH expired AS (
		SELECT claim.ctid
		FROM dns_reconcile_provider_mutation_claims claim
		WHERE claim.tenant_id=$1 AND claim.state='claimed'
		  AND claim.lease_expires_at<=clock_timestamp()
		ORDER BY claim.claimed_at,claim.client_request_id
		LIMIT $2 FOR UPDATE OF claim SKIP LOCKED
		)
		UPDATE dns_reconcile_provider_mutation_claims claim
		SET state='uncertain'
		FROM expired WHERE claim.ctid=expired.ctid`, tenantID, limit)
	if err != nil {
		return dnsreconcile.ErrUnavailable
	}
	return nil
}

func (source *dnsReconcileRecoveryTenantSource) dueUncertainCandidates(
	ctx context.Context, tenantID uuid.UUID, limit int) ([]dnsReconcileRecoveryCandidate, error) {
	if _, err := source.pool.Exec(ctx, `UPDATE dns_reconcile_provider_recovery_leases
		SET state='expired'
		WHERE tenant_id=$1 AND state='active' AND lease_expires_at<=clock_timestamp()`, tenantID); err != nil {
		return nil, dnsreconcile.ErrUnavailable
	}
	rows, err := source.pool.Query(ctx, `
		WITH candidates AS MATERIALIZED (
			SELECT claim.tenant_id,claim.job_id,claim.claim_id,COALESCE(claim.site_id,claim.stream_id),claim.zone_id,
		       claim.client_request_id,claim.phase,claim.operation_ordinal,claim.state,
		       claim.expected_zone_revision,claim.provider_request_id,
		       COALESCE(claim.provider_record_id,''),COALESCE(claim.final_zone_revision,0),
		       latest.event_sequence,operation.operation,latest.result_snapshot,clock_timestamp()
		FROM dns_reconcile_provider_mutation_claims claim
			JOIN background_jobs job ON job.tenant_id=claim.tenant_id AND job.id=claim.job_id
			LEFT JOIN dns_reconcile_provider_recovery_failures failure
			  ON failure.tenant_id=claim.tenant_id AND failure.client_request_id=claim.client_request_id
			LEFT JOIN dns_reconcile_provider_recovery_continuations continuation
			  ON continuation.tenant_id=claim.tenant_id AND continuation.job_id=claim.job_id
			LEFT JOIN dns_reconcile_provider_recovery_leases recovery_lease
			  ON recovery_lease.tenant_id=claim.tenant_id
			 AND recovery_lease.client_request_id=claim.client_request_id
			 AND recovery_lease.state='active'
		JOIN dns_reconcile_operations operation
		  ON operation.tenant_id=claim.tenant_id AND operation.job_id=claim.job_id
		 AND operation.phase=claim.phase AND operation.ordinal=claim.operation_ordinal
		JOIN LATERAL (
			SELECT event.event_sequence,event.error_code,event.result_snapshot
			FROM dns_reconcile_task_events event
			WHERE event.tenant_id=claim.tenant_id AND event.job_id=claim.job_id
			ORDER BY event.event_sequence DESC LIMIT 1
		) latest ON true
			WHERE claim.tenant_id=$1 AND continuation.tenant_id IS NULL
			  AND recovery_lease.tenant_id IS NULL
			  AND (failure.tenant_id IS NULL OR
			       (failure.disposition='backoff' AND failure.retry_not_before<=clock_timestamp()))
			  AND (
			(claim.state='uncertain' AND claim.recovery_not_before<=clock_timestamp()
			 AND claim.lease_expires_at<=clock_timestamp())
			OR claim.state IN ('succeeded','not_applied','conflict')
		) AND (claim.phase='commit' OR job.state IN ('failed','partial_failed'))
		  AND latest.result_snapshot ->
		      (CASE claim.phase WHEN 'apply' THEN 'Operations' ELSE 'DeferredDeletes' END) ->
		      (claim.operation_ordinal-1) ->> 'ClientRequestID'=claim.client_request_id
		  AND latest.result_snapshot ->
		      (CASE claim.phase WHEN 'apply' THEN 'Operations' ELSE 'DeferredDeletes' END) ->
		      (claim.operation_ordinal-1) ->> 'Status' IN ('running','transient_failed')
		ORDER BY claim.claimed_at,claim.client_request_id LIMIT $2
		FOR UPDATE OF claim SKIP LOCKED
		), leased AS (
			INSERT INTO dns_reconcile_provider_recovery_leases(
				tenant_id,client_request_id,claim_id,job_id,recovery_lease_id,
				lease_expires_at,state,claimed_at,released_at)
			SELECT tenant_id,client_request_id,claim_id,job_id,gen_random_uuid(),
				statement_timestamp()+interval '16 minutes','active',statement_timestamp(),NULL
			FROM candidates ON CONFLICT DO NOTHING
			RETURNING tenant_id,client_request_id,recovery_lease_id
		)
		SELECT candidate.*,leased.recovery_lease_id
		FROM candidates candidate JOIN leased
		  ON leased.tenant_id=candidate.tenant_id
		 AND leased.client_request_id=candidate.client_request_id
		ORDER BY candidate.client_request_id`, tenantID, limit)
	if err != nil {
		return nil, dnsreconcile.ErrUnavailable
	}
	defer rows.Close()
	result := make([]dnsReconcileRecoveryCandidate, 0, limit)
	for rows.Next() {
		var candidate dnsReconcileRecoveryCandidate
		if err := rows.Scan(&candidate.tenantID, &candidate.jobID, &candidate.claimID, &candidate.siteID,
			&candidate.zoneID, &candidate.clientRequestID, &candidate.phase, &candidate.ordinal,
			&candidate.claimState, &candidate.expectedRevision, &candidate.providerRequest,
			&candidate.providerRecord, &candidate.finalRevision, &candidate.eventSequence,
			&candidate.operationJSON, &candidate.resultSnapshot, &candidate.serverNow,
			&candidate.recoveryLeaseID); err != nil {
			return nil, dnsreconcile.ErrUnavailable
		}
		result = append(result, candidate)
	}
	if rows.Err() != nil {
		return nil, dnsreconcile.ErrUnavailable
	}
	return result, nil
}

func (source *dnsReconcileRecoveryTenantSource) requeueDueUncertain(
	ctx context.Context, candidate dnsReconcileRecoveryCandidate) error {
	return pgx.BeginFunc(ctx, source.pool, func(tx pgx.Tx) error {
		var recoveryLeaseState string
		if err := tx.QueryRow(ctx, `SELECT state FROM dns_reconcile_provider_recovery_leases
			WHERE tenant_id=$1 AND client_request_id=$2 AND job_id=$3
			  AND recovery_lease_id=$4 FOR UPDATE`, candidate.tenantID, candidate.clientRequestID,
			candidate.jobID, candidate.recoveryLeaseID).Scan(&recoveryLeaseState); err != nil ||
			recoveryLeaseState != "active" {
			return dnsreconcile.ErrUnavailable
		}
		var state string
		if err := tx.QueryRow(ctx, `SELECT claim_id,state,provider_request_id,
				COALESCE(provider_record_id,''),COALESCE(final_zone_revision,0)
			FROM dns_reconcile_provider_mutation_claims
			WHERE tenant_id=$1 AND client_request_id=$2 FOR UPDATE`,
			candidate.tenantID, candidate.clientRequestID).Scan(
			&candidate.claimID, &state, &candidate.providerRequest, &candidate.providerRecord, &candidate.finalRevision,
		); err != nil {
			return err
		}
		if state != string(dnsproviderremote.MutationSucceeded) &&
			state != string(dnsproviderremote.MutationNotApplied) &&
			state != string(dnsproviderremote.MutationConflict) {
			return dnsreconcile.ErrUnavailable
		}
		candidate.claimState = state
		var currentSiteID, currentZoneID uuid.UUID
		var jobAttempt, jobMaxAttempts, itemAttempt int
		var itemSequence int64
		if err := tx.QueryRow(ctx, `SELECT COALESCE(task.site_id,task.stream_id),task.zone_id,operation.operation,
				latest.event_sequence,latest.result_snapshot,clock_timestamp(),
				job.attempt,job.max_attempts,item.attempt,item.sequence
				FROM dns_reconcile_tasks task
				JOIN background_jobs job ON job.tenant_id=task.tenant_id AND job.id=task.job_id
				JOIN background_job_items item
				  ON item.tenant_id=job.tenant_id AND item.job_id=job.id AND item.item_id=$5
			JOIN dns_reconcile_operations operation
			  ON operation.tenant_id=task.tenant_id AND operation.job_id=task.job_id
			 AND operation.phase=$3 AND operation.ordinal=$4
			JOIN LATERAL (
				SELECT event.event_sequence,event.result_snapshot
				FROM dns_reconcile_task_events event
				WHERE event.tenant_id=task.tenant_id AND event.job_id=task.job_id
				ORDER BY event.event_sequence DESC LIMIT 1
			) latest ON true
			WHERE task.tenant_id=$1 AND task.job_id=$2
				FOR UPDATE OF task,job,item`, candidate.tenantID, candidate.jobID, candidate.phase,
			candidate.ordinal, dnsreconcile.JobItemID).Scan(&currentSiteID, &currentZoneID,
			&candidate.operationJSON, &candidate.eventSequence, &candidate.resultSnapshot,
			&candidate.serverNow, &jobAttempt, &jobMaxAttempts, &itemAttempt, &itemSequence); err != nil {
			return err
		}
		if currentSiteID != candidate.siteID || currentZoneID != candidate.zoneID {
			return errDNSReconcileRecoveryCandidateInvalid
		}
		result, err := prepareDNSReconcileRecoveryResult(candidate)
		if err != nil {
			return errDNSReconcileRecoveryCandidateInvalid
		}
		resultJSON, err := json.Marshal(result)
		if err != nil {
			return err
		}
		compensationJSON, err := json.Marshal(result.CompensationPlan)
		if err != nil {
			return err
		}
		var providerRevision any
		if result.ProviderRevision > 0 {
			providerRevision = result.ProviderRevision
		}
		var errorCode any
		if result.ErrorCode != "" {
			errorCode = result.ErrorCode
		}
		if candidate.phase == "apply" {
			if candidate.ordinal < 1 || candidate.ordinal > len(result.Operations) {
				return errDNSReconcileRecoveryCandidateInvalid
			}
			var grantedAt time.Time
			if err := tx.QueryRow(ctx, `INSERT INTO dns_reconcile_provider_recovery_continuations(
					tenant_id,client_request_id,claim_id,job_id,continuation_attempt,
						previous_item_attempt,previous_item_sequence,result_attempts,event_sequence,
						recovery_event_sequence,recovery_result_digest,granted_at
					) VALUES($1,$2,$3,$4,$5,$6,$7,$8,$9,$10,
						sha256(convert_to($11::jsonb::text,'UTF8')),clock_timestamp()) RETURNING granted_at`,
				candidate.tenantID, candidate.clientRequestID, candidate.claimID, candidate.jobID,
				jobMaxAttempts+1, itemAttempt, itemSequence,
				result.Operations[candidate.ordinal-1].Attempts, candidate.eventSequence,
				candidate.eventSequence+1, resultJSON).Scan(&grantedAt); err != nil {
				return err
			}
			command, err := tx.Exec(ctx, `UPDATE background_jobs
						SET state='queued',
						    max_attempts=$3,
						    completed_count=succeeded_count,failed_count=0,
						    lease_id=NULL,lease_owner=NULL,lease_expires_at=NULL,
						    claimable_at=$4,last_error_code=NULL,completed_at=NULL,updated_at=$4
						WHERE tenant_id=$1 AND id=$2 AND kind='dns_reconcile'
						  AND state IN ('failed','partial_failed') AND attempt=$5 AND max_attempts=$6`,
				candidate.tenantID, candidate.jobID, jobMaxAttempts+1, grantedAt,
				jobAttempt, jobMaxAttempts)
			if err != nil || command.RowsAffected() != 1 {
				if err != nil {
					return err
				}
				return dnsreconcile.ErrUnavailable
			}
			command, err = tx.Exec(ctx, `UPDATE background_job_items
					SET state='pending',error_code=NULL,completed_at=NULL
					WHERE tenant_id=$1 AND job_id=$2 AND item_id=$3 AND state='failed'
					  AND attempt=$4 AND sequence=$5`, candidate.tenantID, candidate.jobID,
				dnsreconcile.JobItemID, itemAttempt, itemSequence)
			if err != nil || command.RowsAffected() != 1 {
				if err != nil {
					return err
				}
				return dnsreconcile.ErrUnavailable
			}
		} else if candidate.phase == "commit" {
			if err := insertDNSReconcileRecoveryCommitFacts(ctx, tx, candidate, result); err != nil {
				return err
			}
		} else {
			return errDNSReconcileRecoveryCandidateInvalid
		}
		_, err = tx.Exec(ctx, `INSERT INTO dns_reconcile_task_events(
			tenant_id,job_id,event_sequence,source,status,provider_revision,result_snapshot,
			compensation_plan,error_class,error_code,occurred_at
		) VALUES($1,$2,$3,'control',$4,$5,$6,$7,$8,$9,$10)`, candidate.tenantID,
			candidate.jobID, candidate.eventSequence+1, string(result.Status), providerRevision,
			resultJSON, compensationJSON, string(result.ErrorClass), errorCode, candidate.serverNow)
		if err != nil {
			return err
		}
		if candidate.phase == "apply" {
			command, err := tx.Exec(ctx, `UPDATE dns_reconcile_provider_recovery_continuations
					SET consumed_at=clock_timestamp()
					WHERE tenant_id=$1 AND job_id=$2 AND client_request_id=$3 AND claim_id=$4
					  AND consumed_at IS NULL`, candidate.tenantID, candidate.jobID,
				candidate.clientRequestID, candidate.claimID)
			if err != nil || command.RowsAffected() != 1 {
				if err != nil {
					return err
				}
				return dnsreconcile.ErrUnavailable
			}
		}
		command, err := tx.Exec(ctx, `UPDATE dns_reconcile_provider_recovery_leases
			SET state='released'
			WHERE tenant_id=$1 AND client_request_id=$2 AND job_id=$3
			  AND recovery_lease_id=$4 AND state='active'`, candidate.tenantID,
			candidate.clientRequestID, candidate.jobID, candidate.recoveryLeaseID)
		if err != nil || command.RowsAffected() != 1 {
			return dnsreconcile.ErrUnavailable
		}
		return nil
	})
}

func prepareDNSReconcileRecoveryResult(candidate dnsReconcileRecoveryCandidate) (dnscheck.ReconcileResult, error) {
	var operation dnscheck.ProviderOperation
	var result dnscheck.ReconcileResult
	if candidate.tenantID == uuid.Nil || candidate.jobID == uuid.Nil || candidate.siteID == uuid.Nil ||
		candidate.claimID == uuid.Nil || candidate.zoneID == uuid.Nil || candidate.clientRequestID == "" || candidate.eventSequence < 1 ||
		candidate.expectedRevision < 1 || json.Unmarshal(candidate.operationJSON, &operation) != nil ||
		json.Unmarshal(candidate.resultSnapshot, &result) != nil || result.TenantID != candidate.tenantID ||
		result.SiteID != candidate.siteID || result.ZoneID != candidate.zoneID ||
		result.Status != dnscheck.TaskApplying && result.Status != dnscheck.TaskReadyToCommit &&
			result.Status != dnscheck.TaskFailed && result.Status != dnscheck.TaskCommitFailed {
		return dnscheck.ReconcileResult{}, dnsreconcile.ErrUnavailable
	}
	var target *dnscheck.OperationResult
	switch candidate.phase {
	case "apply":
		if candidate.ordinal < 1 || candidate.ordinal > len(result.Operations) {
			return dnscheck.ReconcileResult{}, dnsreconcile.ErrUnavailable
		}
		target = &result.Operations[candidate.ordinal-1]
	case "commit":
		if candidate.ordinal < 1 || candidate.ordinal > len(result.DeferredDeletes) {
			return dnscheck.ReconcileResult{}, dnsreconcile.ErrUnavailable
		}
		target = &result.DeferredDeletes[candidate.ordinal-1]
	default:
		return dnscheck.ReconcileResult{}, dnsreconcile.ErrUnavailable
	}
	inFlight := target.Status == dnscheck.OperationRunning && target.ErrorCode == "" && result.ErrorCode == ""
	pending := target.Status == dnscheck.OperationTransientFailed &&
		(target.ErrorCode == "provider_recovery_pending" ||
			target.ErrorCode == "provider_recovery_persistence_failed") &&
		result.ErrorCode == target.ErrorCode
	if target.ClientRequestID != candidate.clientRequestID || target.Operation != operation ||
		!inFlight && !pending ||
		candidate.phase == "apply" && result.Status != dnscheck.TaskApplying && result.Status != dnscheck.TaskFailed ||
		candidate.phase == "commit" && result.Status != dnscheck.TaskReadyToCommit && result.Status != dnscheck.TaskCommitFailed {
		return dnscheck.ReconcileResult{}, dnsreconcile.ErrUnavailable
	}
	result.UpdatedAt = candidate.serverNow
	result.ErrorClass = dnscheck.ProviderErrorNone
	result.ErrorCode = ""
	result.CompensationPlan = []dnscheck.ProviderOperation{}
	if candidate.phase == "apply" {
		target.Status = dnscheck.OperationPlanned
		target.ErrorClass = dnscheck.ProviderErrorNone
		target.ErrorCode = ""
		result.Status = dnscheck.TaskApplying
		return result, nil
	}
	target.ReportSequence++
	switch candidate.claimState {
	case string(dnsproviderremote.MutationSucceeded):
		if candidate.providerRequest == "" || candidate.providerRecord == "" ||
			candidate.finalRevision != candidate.expectedRevision+1 {
			return dnscheck.ReconcileResult{}, dnsreconcile.ErrUnavailable
		}
		target.ProviderRequestID = candidate.providerRequest
		target.ProviderRecordID = candidate.providerRecord
		target.ProviderRevision = candidate.finalRevision
		target.Status = dnscheck.OperationSucceeded
		target.ErrorClass = dnscheck.ProviderErrorNone
		target.ErrorCode = ""
		if candidate.finalRevision > result.ProviderRevision {
			result.ProviderRevision = candidate.finalRevision
		}
		result.Status = dnscheck.TaskCommitted
		for index := range result.DeferredDeletes {
			if result.DeferredDeletes[index].Status != dnscheck.OperationSucceeded {
				result.Status = dnscheck.TaskReadyToCommit
				break
			}
		}
	case string(dnsproviderremote.MutationConflict):
		target.Status = dnscheck.OperationRevisionConflict
		target.ErrorClass = dnscheck.ProviderErrorRevisionConflict
		target.ErrorCode = "revision_conflict"
		result.Status = dnscheck.TaskCommitFailed
		result.ErrorClass = target.ErrorClass
		result.ErrorCode = target.ErrorCode
	case string(dnsproviderremote.MutationNotApplied):
		target.Status = dnscheck.OperationPlanned
		target.ErrorClass = dnscheck.ProviderErrorNone
		target.ErrorCode = ""
		result.Status = dnscheck.TaskReadyToCommit
	default:
		return dnscheck.ReconcileResult{}, dnsreconcile.ErrUnavailable
	}
	return result, nil
}

func insertDNSReconcileRecoveryCommitFacts(ctx context.Context, tx pgx.Tx,
	candidate dnsReconcileRecoveryCandidate, result dnscheck.ReconcileResult) error {
	var commandKey, requestID, traceparent, eventType string
	var commandDigest []byte
	var expectedTaskRevision, factSequence int64
	var commitAttempt int
	var expectedProviderRevision int64
	if err := tx.QueryRow(ctx, `SELECT command_idempotency_key,command_digest,request_id,traceparent,
		expected_task_revision,fact_sequence,commit_attempt,event_type,expected_provider_revision
		FROM dns_reconcile_commit_facts WHERE tenant_id=$1 AND job_id=$2
		ORDER BY fact_sequence DESC LIMIT 1 FOR UPDATE`, candidate.tenantID, candidate.jobID).Scan(
		&commandKey, &commandDigest, &requestID, &traceparent, &expectedTaskRevision,
		&factSequence, &commitAttempt, &eventType, &expectedProviderRevision,
	); err != nil || eventType != "failed" {
		if err != nil {
			return err
		}
		return dnsreconcile.ErrUnavailable
	}
	leaseID := uuid.New()
	workerID := "dns-reconcile-recovery"
	leaseExpiresAt := candidate.serverNow.Add(time.Minute)
	factSequence++
	commitAttempt++
	if _, err := tx.Exec(ctx, `INSERT INTO dns_reconcile_commit_facts(
		tenant_id,job_id,command_idempotency_key,command_digest,request_id,traceparent,
		expected_task_revision,fact_sequence,commit_attempt,lease_id,worker_id,
		lease_expires_at,event_type,expected_provider_revision,created_at
	) VALUES($1,$2,$3,$4,$5,$6,$7,$8,$9,$10,$11,$12,'claimed',$13,$14)`,
		candidate.tenantID, candidate.jobID, commandKey, commandDigest, requestID, traceparent,
		expectedTaskRevision, factSequence, commitAttempt, leaseID, workerID, leaseExpiresAt,
		expectedProviderRevision, candidate.serverNow); err != nil {
		return err
	}
	if candidate.claimState == string(dnsproviderremote.MutationSucceeded) {
		operation := result.DeferredDeletes[candidate.ordinal-1]
		factSequence++
		if _, err := tx.Exec(ctx, `INSERT INTO dns_reconcile_commit_facts(
			tenant_id,job_id,command_idempotency_key,command_digest,request_id,traceparent,
			expected_task_revision,fact_sequence,commit_attempt,lease_id,worker_id,
			lease_expires_at,event_type,operation_ordinal,provider_request_id,
			provider_record_id,report_sequence,expected_provider_revision,provider_revision,created_at
		) VALUES($1,$2,$3,$4,$5,$6,$7,$8,$9,$10,$11,$12,'delete_succeeded',$13,$14,$15,$16,$17,$18,$19)`,
			candidate.tenantID, candidate.jobID, commandKey, commandDigest, requestID, traceparent,
			expectedTaskRevision, factSequence, commitAttempt, leaseID, workerID, leaseExpiresAt,
			candidate.ordinal, operation.ProviderRequestID, operation.ProviderRecordID,
			operation.ReportSequence, expectedProviderRevision, operation.ProviderRevision,
			candidate.serverNow); err != nil {
			return err
		}
	}
	factSequence++
	terminalType := "failed"
	errorClass := string(dnscheck.ProviderErrorTransient)
	errorCode := "provider_recovery_continued"
	if result.Status == dnscheck.TaskCommitted {
		terminalType, errorClass, errorCode = "committed", "", ""
	} else if result.Status == dnscheck.TaskCommitFailed {
		errorClass, errorCode = string(result.ErrorClass), result.ErrorCode
	}
	var errorClassValue, errorCodeValue any
	if errorClass != "" {
		errorClassValue, errorCodeValue = errorClass, errorCode
	}
	_, err := tx.Exec(ctx, `INSERT INTO dns_reconcile_commit_facts(
		tenant_id,job_id,command_idempotency_key,command_digest,request_id,traceparent,
		expected_task_revision,fact_sequence,commit_attempt,lease_id,worker_id,
		lease_expires_at,event_type,expected_provider_revision,provider_revision,
		compensation_plan,error_class,error_code,created_at
	) VALUES($1,$2,$3,$4,$5,$6,$7,$8,$9,$10,$11,$12,$13,$14,$15,'[]'::jsonb,
		COALESCE($16,''),$17,$18)`, candidate.tenantID, candidate.jobID, commandKey, commandDigest,
		requestID, traceparent, expectedTaskRevision, factSequence, commitAttempt, leaseID, workerID,
		leaseExpiresAt, terminalType, expectedProviderRevision, result.ProviderRevision,
		errorClassValue, errorCodeValue, candidate.serverNow)
	return err
}

// dnsReconcileAnchorSQL selects a DNS task's anchor by its ID parameter
// (migration 507): a live site, or a live stream whose own CNAME the task
// writes (a stream may have no site). Columns: scope_id, resource_type.
func dnsReconcileAnchorSQL(parameter string) string {
	return `(SELECT site.scope_id,'site'::text AS resource_type FROM sites site
	WHERE site.id=` + parameter + ` AND site.deleted_at IS NULL
	UNION ALL SELECT forward.scope_id,'stream'::text FROM l4_forwards forward
	WHERE forward.id=` + parameter + ` AND forward.deleted_at IS NULL)`
}

func (resolver dnsReconcileCheckerResolver) ResolveChecker(ctx context.Context, tenantID, siteID uuid.UUID) (*dnscheck.Checker, error) {
	if ctx == nil || ctx.Err() != nil || tenantID == uuid.Nil || siteID == uuid.Nil || resolver.checker == nil {
		return nil, dnsreconcile.ErrUnavailable
	}
	return resolver.checker, nil
}

func (resolver *dnsReconcilePropagationContextResolver) ResolvePropagationContext(
	ctx context.Context,
	tenantID, siteID, zoneID, actorUserID uuid.UUID,
) (dnsreconcile.PropagationContext, error) {
	if resolver == nil || resolver.pool == nil || ctx == nil || ctx.Err() != nil ||
		tenantID == uuid.Nil || siteID == uuid.Nil || zoneID == uuid.Nil || actorUserID == uuid.Nil {
		return dnsreconcile.PropagationContext{}, dnsreconcile.ErrUnavailable
	}
	var result dnsreconcile.PropagationContext
	var zoneName string
	err := resolver.pool.QueryRow(ctx, `
		SELECT scope.id,provider.id,zone.id,zone.name,COALESCE(zone.provider_zone_apex,'')
		FROM `+dnsReconcileAnchorSQL("$2")+` anchor
		JOIN access_scopes scope ON scope.id=anchor.scope_id AND scope.kind='tenant'
		JOIN dns_zones zone ON zone.scope_id=scope.id
		JOIN dns_providers provider ON provider.scope_id=scope.id AND provider.id=zone.provider_id
		WHERE scope.tenant_id=$1 AND zone.id=$3 AND provider.status='verified'
		  AND provider.credential_revoked=false AND provider.credential_version>0
		  AND (`+dnsReconcileTenantMemberSQL("scope.id", "$4")+` OR `+dnsReconcilePlatformActorSQL("$4")+`)`,
		tenantID, siteID, zoneID, actorUserID,
	).Scan(&result.ScopeID, &result.ProviderID, &result.ZoneID, &zoneName, &result.Zone)
	if err != nil || result.ScopeID == uuid.Nil || result.ProviderID == uuid.Nil ||
		result.ZoneID != zoneID || zoneName == "" || zoneName != strings.TrimSpace(zoneName) {
		return dnsreconcile.PropagationContext{}, dnsreconcile.ErrUnavailable
	}
	if result.Zone == "" {
		// A zone saved before migration 473: its apex is looked up once and
		// written back, as on the mutation path (retest-n1); a failed lookup
		// is retried with the dependency backoff.
		if resolver.apex == nil {
			return dnsreconcile.PropagationContext{}, dnsreconcile.ErrUnavailable
		}
		result.Zone, err = resolver.apex.PropagationZoneApex(ctx, tenantID, siteID, zoneID)
		if err != nil {
			return dnsreconcile.PropagationContext{}, dnsreconcile.ErrUnavailable
		}
	}
	// The apex is the CNAME zone or a dot-suffix of it (473 CHECK).
	if result.Zone != zoneName && !strings.HasSuffix(zoneName, "."+result.Zone) {
		return dnsreconcile.PropagationContext{}, dnsreconcile.ErrUnavailable
	}
	return result, nil
}

func (authenticator *dnsReconcileSessionAuthenticator) AuthenticateSession(ctx context.Context,
	raw string) (dnsreconcilehttp.Principal, error) {
	if authenticator == nil || authenticator.identity == nil || ctx == nil || raw == "" {
		return dnsreconcilehttp.Principal{}, dnsreconcilehttp.ErrUnavailable
	}
	authenticated, err := authenticator.identity.AuthenticateSession(ctx, raw)
	if err != nil {
		if errors.Is(err, identity.ErrInvalidSession) || errors.Is(err, identity.ErrAccountDisabled) ||
			errors.Is(err, identity.ErrMembershipDisabled) {
			return dnsreconcilehttp.Principal{}, dnsreconcilehttp.ErrUnauthenticated
		}
		return dnsreconcilehttp.Principal{}, dnsreconcilehttp.ErrUnavailable
	}
	principal := authenticated.Principal
	if principal.ScopeKind != "tenant" || principal.ScopeID == uuid.Nil || principal.TenantID == nil ||
		*principal.TenantID == uuid.Nil || principal.UserID == uuid.Nil || authenticated.SessionID == uuid.Nil {
		return dnsreconcilehttp.Principal{}, dnsreconcilehttp.ErrUnauthenticated
	}
	return dnsreconcilehttp.Principal{
		SubjectID: principal.UserID, TenantID: *principal.TenantID, SessionID: authenticated.SessionID,
		ScopeID: principal.ScopeID, ScopeKind: principal.ScopeKind,
		Permissions: append([]string(nil), principal.Permissions...),
	}, nil
}

func (authorizer *dnsReconcileIAMAuthorizer) Authorize(ctx context.Context,
	request dnsreconcilehttp.AuthorizationRequest) error {
	principal := request.Principal
	if authorizer == nil || authorizer.pool == nil || ctx == nil || principal.SubjectID == uuid.Nil ||
		principal.TenantID == uuid.Nil || principal.SessionID == uuid.Nil || principal.ScopeID == uuid.Nil ||
		principal.ScopeKind != "tenant" ||
		request.TenantID != principal.TenantID || request.SiteID == uuid.Nil ||
		(request.Permission != dnsreconcile.PermissionRead && request.Permission != dnsreconcile.PermissionManage) {
		return dnsreconcilehttp.ErrPermissionDenied
	}
	if identity.Authorize(identity.Principal{Permissions: principal.Permissions}, request.Permission) != nil {
		return dnsreconcilehttp.ErrPermissionDenied
	}
	var allowed bool
	err := authorizer.pool.QueryRow(ctx, `SELECT EXISTS (
		SELECT 1 FROM `+dnsReconcileAnchorSQL("$1")+` anchor
		JOIN access_scopes scope ON scope.id=anchor.scope_id AND scope.kind='tenant'
		JOIN tenants tenant ON tenant.id=scope.tenant_id AND tenant.status='active'
		JOIN users actor ON actor.id=$4 AND actor.status='active'
		JOIN memberships membership ON membership.scope_id=scope.id AND membership.user_id=actor.id
			AND membership.status='active'
		WHERE scope.id=$2 AND scope.tenant_id=$3
	)`, request.SiteID, principal.ScopeID, principal.TenantID, principal.SubjectID).Scan(&allowed)
	if err != nil {
		return dnsreconcilehttp.ErrUnavailable
	}
	if !allowed {
		return dnsreconcilehttp.ErrPermissionDenied
	}
	return nil
}

func (gate *dnsReconcileEntitlementGate) AuthorizeDNSReconcile(ctx context.Context,
	request dnsreconcile.EntitlementRequest) error {
	if gate == nil || gate.pool == nil || gate.guard == nil || ctx == nil || request.TenantID == uuid.Nil ||
		request.SiteID == uuid.Nil || request.ActorUserID == uuid.Nil || request.RequestID == "" {
		return entitlementguard.ErrUnavailable
	}
	switch request.Action {
	case dnsreconcile.ActionDryRun, dnsreconcile.ActionApply, dnsreconcile.ActionCommit, dnsreconcile.ActionCancel:
	default:
		return entitlementguard.ErrUnavailable
	}
	return pgx.BeginFunc(ctx, gate.pool, func(tx pgx.Tx) error {
		var scopeID uuid.UUID
		var resourceType string
		var member, platform bool
		// The site (or stream) must be the tenant's; the actor is either an
		// active member of it or a platform administrator acting for it
		// (平台管理员代租户重新生成 CNAME).
		err := tx.QueryRow(ctx, `SELECT scope.id,anchor.resource_type,`+dnsReconcileTenantMemberSQL("scope.id", "$3")+`,
				`+dnsReconcilePlatformActorSQL("$3")+`
			FROM `+dnsReconcileAnchorSQL("$1")+` anchor
			JOIN access_scopes scope ON scope.id=anchor.scope_id AND scope.kind='tenant'
			JOIN tenants tenant ON tenant.id=scope.tenant_id AND tenant.status='active'
			WHERE scope.tenant_id=$2`,
			request.SiteID, request.TenantID, request.ActorUserID).Scan(&scopeID, &resourceType, &member, &platform)
		if errors.Is(err, pgx.ErrNoRows) {
			return dnsreconcile.ErrNotFound
		}
		if err != nil {
			return dnsreconcile.ErrUnavailable
		}
		if !member && !platform {
			slog.Warn("DNS reconcile denied: actor is neither a tenant member nor a platform administrator",
				"tenant_id", request.TenantID, "site_id", request.SiteID, "actor_user_id", request.ActorUserID,
				"action", string(request.Action), "request_id", request.RequestID)
			return dnsreconcile.ErrPermissionDenied
		}
		if !member {
			slog.Info("DNS reconcile authorized for a platform administrator acting for the tenant",
				"tenant_id", request.TenantID, "site_id", request.SiteID, "actor_user_id", request.ActorUserID,
				"action", string(request.Action), "request_id", request.RequestID)
		}
		_, err = gate.guard.CheckFeature(ctx, tx, entitlementguard.FeatureCheck{
			TargetScopeID: scopeID, ActorScopeID: scopeID, ActorUserID: request.ActorUserID,
			ResourceType: resourceType, ResourceID: request.SiteID, RequestID: request.RequestID,
			Operation: "dns_reconcile." + string(request.Action), Feature: entitlementguard.FeatureSitesManage,
		})
		if err != nil {
			return errors.Join(dnsreconcile.ErrEntitlementDenied, err)
		}
		return nil
	})
}

// dnsReconcileTenantMemberSQL: the actor is an active user with an active
// membership of the tenant scope.
func dnsReconcileTenantMemberSQL(scope, actor string) string {
	return `EXISTS (SELECT 1 FROM users member_user JOIN memberships member_row
		ON member_row.user_id=member_user.id AND member_row.scope_id=` + scope + ` AND member_row.status='active'
		WHERE member_user.id=` + actor + ` AND member_user.status='active')`
}

// dnsReconcilePlatformActorSQL: the actor is an active member of the platform
// scope holding platform.admin, or both dns.manage and sites.manage there (the
// rule of the platform CNAME intent, cnameallocation/platform_intent.go).
func dnsReconcilePlatformActorSQL(actor string) string {
	grant := func(permission string) string {
		return `EXISTS (SELECT 1 FROM role_assignments platform_assignment
			JOIN role_permissions platform_grant ON platform_grant.role_id=platform_assignment.role_id
			WHERE platform_assignment.scope_id=platform_scope.id AND platform_assignment.user_id=platform_user.id
			  AND platform_grant.permission_name IN ('platform.admin','` + permission + `'))`
	}
	return `EXISTS (SELECT 1 FROM users platform_user
		JOIN memberships platform_member ON platform_member.user_id=platform_user.id AND platform_member.status='active'
		JOIN access_scopes platform_scope ON platform_scope.id=platform_member.scope_id
		 AND platform_scope.kind='platform' AND platform_scope.tenant_id IS NULL
		WHERE platform_user.id=` + actor + ` AND platform_user.status='active'
		  AND ` + grant("dns.manage") + ` AND ` + grant("sites.manage") + `)`
}

// dnsReconcileNoWorkloads rejects every provider report when the workload
// mTLS listener is disabled; the tenant handler never routes reports anyway.
type dnsReconcileNoWorkloads struct{}

func (dnsReconcileNoWorkloads) Authenticate(*http.Request) (dnsreconcilehttp.WorkloadPrincipal, error) {
	return dnsreconcilehttp.WorkloadPrincipal{}, dnsreconcilehttp.ErrWorkloadUnauthenticated
}

func (runtime *dnsReconcileProductionRuntime) Ready() error {
	if runtime == nil || runtime.propagationLifecycle == nil {
		return errors.New("DNS reconcile runtime is not ready")
	}
	if err := runtime.propagationLifecycle.Ready(); err != nil {
		return err
	}
	if runtime.workloadServer == nil {
		return nil
	}
	return runtime.workloadServer.Ready()
}

// shutdownWorkloadServer stops the workload mTLS listener. Single-host installs
// run without it (DNS_RECONCILE_WORKLOAD_MTLS_ENABLED=false); stopping then must
// not fail the process exit.
func (runtime *dnsReconcileProductionRuntime) shutdownWorkloadServer(ctx context.Context) error {
	if runtime == nil || runtime.workloadServer == nil {
		return nil
	}
	return runtime.workloadServer.Shutdown(ctx)
}

func (runtime *dnsReconcileProductionRuntime) Close() error {
	if runtime == nil {
		return nil
	}
	var propagationErr, workloadErr error
	if runtime.propagationLifecycle != nil {
		propagationErr = runtime.propagationLifecycle.Close()
	}
	if runtime.workloadServer != nil {
		workloadErr = runtime.workloadServer.Close()
	}
	return errors.Join(propagationErr, workloadErr)
}

func (lifecycle *dnsReconcilePropagationLifecycle) Ready() error {
	if lifecycle == nil || lifecycle.closed.Load() || lifecycle.source == nil || lifecycle.engine == nil || lifecycle.store == nil {
		return errors.New("DNS propagation lifecycle is not ready")
	}
	return nil
}

func (lifecycle *dnsReconcilePropagationLifecycle) Close() error {
	if lifecycle != nil {
		lifecycle.closed.Store(true)
	}
	return nil
}
