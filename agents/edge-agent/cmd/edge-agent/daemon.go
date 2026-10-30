package main

import (
	"bytes"
	"context"
	"crypto/x509"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"log/slog"
	"net"
	"net/http"
	"net/netip"
	"os"
	"os/exec"
	"path/filepath"
	"runtime"
	"strconv"
	"strings"
	"sync"
	"time"

	"github.com/cdnca/cdnca/agents/edge-agent/internal/acmehttp01"
	"github.com/cdnca/cdnca/agents/edge-agent/internal/cachetask"
	"github.com/cdnca/cdnca/agents/edge-agent/internal/certstore"
	"github.com/cdnca/cdnca/agents/edge-agent/internal/challenge"
	"github.com/cdnca/cdnca/agents/edge-agent/internal/ddos"
	"github.com/cdnca/cdnca/agents/edge-agent/internal/deployment"
	"github.com/cdnca/cdnca/agents/edge-agent/internal/diskguard"
	"github.com/cdnca/cdnca/agents/edge-agent/internal/drainruntime"
	"github.com/cdnca/cdnca/agents/edge-agent/internal/dynroute"
	"github.com/cdnca/cdnca/agents/edge-agent/internal/enrollment"
	"github.com/cdnca/cdnca/agents/edge-agent/internal/eventspool"
	"github.com/cdnca/cdnca/agents/edge-agent/internal/firewall"
	"github.com/cdnca/cdnca/agents/edge-agent/internal/gatewayclient"
	"github.com/cdnca/cdnca/agents/edge-agent/internal/installationban"
	"github.com/cdnca/cdnca/agents/edge-agent/internal/ipintel"
	"github.com/cdnca/cdnca/agents/edge-agent/internal/l4guard"
	"github.com/cdnca/cdnca/agents/edge-agent/internal/l4live"
	"github.com/cdnca/cdnca/agents/edge-agent/internal/l4runtime"
	"github.com/cdnca/cdnca/agents/edge-agent/internal/l4usage"
	"github.com/cdnca/cdnca/agents/edge-agent/internal/logdiskguard"
	"github.com/cdnca/cdnca/agents/edge-agent/internal/nativeruntime"
	"github.com/cdnca/cdnca/agents/edge-agent/internal/nodeinventory"
	"github.com/cdnca/cdnca/agents/edge-agent/internal/nodemonitoring"
	"github.com/cdnca/cdnca/agents/edge-agent/internal/rulepackprecheck"
	"github.com/cdnca/cdnca/agents/edge-agent/internal/sched302runtime"
	"github.com/cdnca/cdnca/agents/edge-agent/internal/telemetryclient"
	"github.com/cdnca/cdnca/agents/edge-agent/internal/toa"
	"github.com/cdnca/cdnca/agents/edge-agent/internal/updater"
	"github.com/cdnca/cdnca/agents/edge-agent/internal/urlauth"
	"github.com/cdnca/cdnca/agents/edge-agent/internal/wafengine"
	"github.com/cdnca/cdnca/agents/edge-agent/internal/xdp"
	"github.com/cdnca/cdnca/agents/edge-agent/packaging/helper"
	"github.com/cdnca/cdnca/libs/edgeconfig"
	"github.com/cdnca/cdnca/libs/edgeconfig/edgeskeleton"
	"github.com/cdnca/cdnca/libs/edgeconfig/securityban"
	"github.com/cdnca/cdnca/libs/edgeconfig/siteobject"
	agentv1 "github.com/cdnca/cdnca/proto/gen/go/agent/v1"
)

var (
	agentVersion = "development"
	buildID      = ""
)

type clientRunner interface {
	Run(context.Context) error
}

type clientCloser interface {
	Close() error
}

var errDaemonAlreadyRunning = errors.New("edge agent daemon already running")

type diskGuardRunner interface {
	Run(context.Context) error
	Snapshot() diskguard.Metrics
}

type logDiskGuardRunner interface {
	Run(context.Context) error
	Snapshot() logdiskguard.Metrics
}

type telemetryRunner interface {
	Run(context.Context) error
	Snapshot() telemetryclient.WorkerSnapshot
}

type certificateRecoverer interface {
	Recover(context.Context) (certstore.Result, error)
}

type certificateDeploymentRecoverer interface {
	RecoverCertificateVersionReferences(context.Context) error
}

type deploymentRecoverer interface {
	Recover(context.Context) error
}

type firewallRuntime interface {
	Probe(context.Context) error
	Apply(context.Context, firewall.FirewallVersion) (firewall.Result, error)
	Expire(context.Context, string, string) (firewall.Result, error)
}

type firewallExpiryRunner interface {
	Run(context.Context) error
}

type challengeVerifierRunner interface {
	Run(context.Context) error
}

type diskGuardDaemonSnapshot struct {
	Enabled   bool              `json:"enabled"`
	Running   bool              `json:"running"`
	RunFailed bool              `json:"run_failed"`
	Metrics   diskguard.Metrics `json:"metrics"`
}

type logDiskGuardDaemonSnapshot struct {
	Enabled   bool                 `json:"enabled"`
	Running   bool                 `json:"running"`
	RunFailed bool                 `json:"run_failed"`
	Metrics   logdiskguard.Metrics `json:"metrics"`
}

type telemetryDaemonSnapshot struct {
	Enabled          bool   `json:"enabled"`
	Running          bool   `json:"running"`
	Degraded         bool   `json:"degraded"`
	LastErrorCode    string `json:"last_error_code,omitempty"`
	AcceptedSequence uint64 `json:"accepted_sequence"`
}

type daemonClient struct {
	client                clientRunner
	certificate           certificateRecoverer
	certificateDeployment certificateDeploymentRecoverer
	deployment            deploymentRecoverer
	diskGuard             diskGuardRunner
	logDiskGuard          logDiskGuardRunner
	telemetry             telemetryRunner
	drain                 drainRuntimeController
	firewallExpiry        firewallExpiryRunner
	runtimeStatus         *runtimeStatusPoller
	l4KernelBans          firewallExpiryRunner
	emptyConnections      firewallExpiryRunner
	rateBans              firewallExpiryRunner
	xdpFilter             *xdp.Manager
	xdpWatch              firewallExpiryRunner
	cacheTasks            gatewayclient.CacheTaskManager
	dynamicRouting        dynamicRoutingRunner
	challengeVerifier     challengeVerifierRunner
	l4TOA                 *toa.Manager
	l4OpenResty           *l4runtime.OpenResty
	installationBan       *installationban.Runtime
	// endpointProbe retries earlier gateway endpoints (GW-07 fallback).
	endpointProbe         func(context.Context)
	runMu                 sync.Mutex
	closeOnce             sync.Once
	closeErr              error
	statusMu              sync.RWMutex
	running               bool
	runFailed             bool
	logDiskGuardRunning   bool
	logDiskGuardRunFailed bool
	telemetryRunning      bool
	telemetryRunFailed    bool
	drainRunning          bool
	drainRunFailed        bool
}

func assembleDeploymentPrechecker(config fileConfig, delegate deployment.Prechecker) (deployment.Prechecker, error) {
	telemetry, err := newTelemetryPrechecker(config.DeploymentRoot, delegate)
	if err != nil {
		return nil, fmt.Errorf("configure telemetry precheck: %w", err)
	}
	var prechecker deployment.Prechecker = telemetry
	// A JS challenge whose policy the challenge rollout has not installed here
	// passes nginx -t but fails master start (init_by_lua): refuse it first.
	// The challenge artifact installer writes under DeploymentRoot.
	checker, err := challenge.NewPolicyPrechecker(config.DeploymentRoot, config.OpenResty.ConfigFile, prechecker)
	if err != nil {
		return nil, fmt.Errorf("configure challenge policy precheck: %w", err)
	}
	return checker, nil
}

func assembleClient(config fileConfig, timeouts parsedTimeouts, bootID string) (clientRunner, error) {
	securityStatus, err := validateSecurityRuntime(config.SecurityRuntime)
	if err != nil {
		return nil, fmt.Errorf("validate security runtime: %w", err)
	}
	if config.SecurityRuntime.Mode == securityRuntimeModeNative {
		// The native node declares WAF/CC only when its packaged OpenResty
		// loads the verified assets; a failure leaves them undeclared (the
		// publish gate then names the missing capability) instead of
		// stopping the Agent.
		securityStatus, err = validateNativeSecurityRuntime(context.Background(), config.OpenResty.Binary, config.SecurityRuntime)
		if err != nil {
			slog.Warn("WAF/CC capabilities not declared", "error", err)
		}
	}
	guard, err := assembleDiskGuard(config)
	if err != nil {
		return nil, err
	}
	nodeID := config.NodeID
	artifactKeyID := config.ArtifactEncryptionKeyID
	clientCertificateFile := config.Gateway.ClientCertificate
	clientPrivateKeyFile := config.Gateway.ClientPrivateKeyFile
	var artifactPrivateKey []byte
	if config.Version == 2 {
		if config.Identity == nil {
			return nil, fmt.Errorf("load enrollment identity: identity is required")
		}
		nodeID = config.Identity.NodeID
		artifactKeyID = config.Identity.ArtifactEncryptionKeyID
		clientCertificateFile = config.Identity.ClientCertificateFile
		clientPrivateKeyFile = config.Identity.ClientPrivateKeyFile
		artifactPrivateKey = config.Identity.ArtifactEncryptionPrivateKey
	}
	trust, err := gatewayclient.LoadTrustStore(config.ArtifactTrustFile)
	if err != nil {
		return nil, fmt.Errorf("load artifact trust: %w", err)
	}
	// Node signer trust (revocations and rotated platform keys) is restored
	// before anything below verifies a signature.
	signerTrust, err := gatewayclient.NewSignerTrustRuntime(filepath.Join(config.JournalDir, "signer-trust"), nodeID, trust, time.Now)
	if err != nil {
		return nil, fmt.Errorf("configure node signer trust: %w", err)
	}
	if err := signerTrust.Restore(); err != nil {
		fmt.Fprintf(os.Stderr, "edge-agent: %v\n", err)
	}
	nodeMonitoringBridge, nodeMonitoringRuntime, err := assembleNodeMonitoring(config.NodeMonitoring, nodeID)
	if err != nil {
		return nil, err
	}
	marketProbe, err := assembleMarketProbe(config.MarketProbe, nodeID)
	if err != nil {
		return nil, err
	}
	maximumReceiveBytes := config.Limits.MaxCommandBytes
	chunkMessageBytes := int(config.Limits.MaxArtifactChunkBytes) + (64 << 10)
	if chunkMessageBytes > maximumReceiveBytes {
		maximumReceiveBytes = chunkMessageBytes
	}
	maximumSendBytes := config.Limits.MaxStatusBytes
	if maximumSendBytes < 64<<10 {
		maximumSendBytes = 64 << 10
	}
	dialerConfig := gatewayclient.MTLSDialerConfig{
		Address:               config.Gateway.Address,
		ServerName:            config.Gateway.ServerName,
		RootCAFile:            config.Gateway.RootCAFile,
		ClientCertificateFile: clientCertificateFile,
		ClientPrivateKeyFile:  clientPrivateKeyFile,
		MaximumReceiveBytes:   maximumReceiveBytes,
		MaximumSendBytes:      maximumSendBytes,
		Transport:             config.Gateway.Transport,
		TunnelHost:            config.Gateway.TunnelHost,
		TunnelAudience:        config.tunnelAudience(),
	}
	dialerFactory, err := gatewayclient.NewEndpointMTLSDialerFactory(dialerConfig)
	if err != nil {
		return nil, fmt.Errorf("configure gateway mTLS: %w", err)
	}
	endpointStore, err := gatewayclient.NewFileGatewayEndpointStateStore(
		filepath.Join(config.JournalDir, "gateway-endpoint"),
		gatewayclient.GatewayEndpointState{Address: config.Gateway.Address, ServerName: config.Gateway.ServerName},
	)
	if err != nil {
		return nil, fmt.Errorf("configure durable gateway endpoint state: %w", err)
	}
	switching, err := gatewayclient.NewSwitchingDialer(endpointStore, dialerFactory)
	if err != nil {
		return nil, fmt.Errorf("configure switching gateway mTLS: %w", err)
	}
	extraEndpoints := make([]gatewayclient.GatewayEndpoint, 0, len(config.Gateway.Endpoints))
	for _, endpoint := range config.Gateway.Endpoints {
		extraEndpoints = append(extraEndpoints, gatewayclient.GatewayEndpoint{Address: endpoint.Address,
			ServerName: endpoint.ServerName, Transport: endpoint.Transport, TunnelHost: endpoint.TunnelHost})
	}
	dialer, err := gatewayclient.NewFailoverDialer(switching, dialerConfig, extraEndpoints, filepath.Join(config.JournalDir, "gateway-endpoints.json"))
	if err != nil {
		return nil, fmt.Errorf("configure gateway endpoints: %w", err)
	}
	certificateRuntime, err := certstore.NewOpenRestyRuntime(
		config.OpenResty.Binary,
		filepath.Join(config.CertificateRuntime.StateRoot, "shared", "nginx.pid"),
		net.JoinHostPort(config.CertificateRuntime.ListenAddress, strconv.Itoa(int(config.CertificateRuntime.ListenPort))),
	)
	if err != nil {
		return nil, fmt.Errorf("configure certificate OpenResty runtime: %w", err)
	}
	certificateManager, err := certstore.NewManager(certstore.RuntimeConfig{
		StateRoot:     config.CertificateRuntime.StateRoot,
		ListenAddress: config.CertificateRuntime.ListenAddress,
		ListenPort:    config.CertificateRuntime.ListenPort,
	}, certificateRuntime)
	if err != nil {
		return nil, fmt.Errorf("configure certificate manager: %w", err)
	}

	openResty, err := deployment.NewOpenResty(
		config.OpenResty.Binary,
		config.OpenResty.ConfigFile,
		nil,
		newHealthProbe(config.OpenResty.HealthURL, timeouts.HealthRequest),
	)
	if err != nil {
		return nil, fmt.Errorf("configure OpenResty runtime: %w", err)
	}
	if err := openResty.ConfigureGenerationTracking(filepath.Join(config.DeploymentRoot, "shared", "nginx.pid")); err != nil {
		return nil, fmt.Errorf("configure OpenResty process tracking: %w", err)
	}
	l4StateRoot := filepath.Join(filepath.Dir(config.JournalDir), "l4-runtime")
	l4OpenResty, err := l4runtime.NewOpenResty(config.OpenResty.Binary,
		filepath.Join(l4StateRoot, "run", "nginx.pid"), timeouts.Reload)
	if err != nil {
		return nil, fmt.Errorf("configure L4 OpenResty runtime: %w", err)
	}
	l4Manager, err := l4runtime.NewDeploymentManager(l4StateRoot, l4OpenResty)
	if err != nil {
		return nil, fmt.Errorf("configure L4 runtime manager: %w", err)
	}
	l4DNS, err := l4runtime.NewDNSCoordinator(filepath.Join(l4StateRoot, "dns"), daemonL4DNSResolver{}, daemonL4AddressHealth, time.Now)
	if err != nil {
		return nil, fmt.Errorf("configure L4 DNS coordinator: %w", err)
	}
	// The OWASP CRS engine extension is gated into each release around
	// OpenResty (a node artifact set item, never part of the node package).
	wafEngine, err := assembleWAFEngine(config, trust)
	if err != nil {
		return nil, fmt.Errorf("configure waf engine: %w", err)
	}
	wafRuntime, err := wafengine.NewRuntime(openResty, openResty, wafEngine)
	if err != nil {
		return nil, fmt.Errorf("configure waf engine runtime: %w", err)
	}
	// site_runtime 9: site objects fetched by digest (ADR 0009 section 8.2).
	// One store per process: node artifact set segments live in it too, and
	// Stage only protects objects within the same Store.
	siteObjects, err := openObjectStore(config)
	if err != nil {
		return nil, fmt.Errorf("configure site object store: %w", err)
	}
	// Rule packs (ADR 0007 §6, ADR 0009 §8.4): node artifact set items in
	// the object store; sealed ones open with the node's artifact key.
	rulePackGID := -1
	if config.DynamicRouting.Enabled {
		if rulePackGID, err = lookupWorkerGID(config.DynamicRouting.WorkerGroup); err != nil {
			return nil, err
		}
	}
	rulePackVault, err := openRulePackVault(config.DeploymentRoot, artifactPrivateKey, siteObjects, rulePackRuntimeRoot, rulePackGID)
	if err != nil {
		return nil, err
	}
	l4Bridge := &l4DeploymentBridge{delegate: wafRuntime, manager: l4Manager, dns: l4DNS, healthInterval: timeouts.HealthInterval}
	deploymentRuntime, http3Readiness, err := assembleHTTP3DeploymentRuntime(config, timeouts, l4Bridge)
	if err != nil {
		return nil, err
	}
	logHTTP3Readiness(os.Stderr, http3Readiness)
	l4TOA := probeL4TOA(config.OpenResty.Binary)
	l4TOAOwned := false
	defer func() {
		if !l4TOAOwned {
			l4TOA.Close()
		}
	}()
	// The site listener protocol http3 is QUIC on the site's HTTPS listener:
	// it needs the QUIC-capable build only (SITE_QUIC), not h3probe.
	siteQUICReady := openRestyServesSiteQUIC(context.Background(), config.OpenResty.Binary)
	ja4Ready := openRestyComputesJA4(context.Background(), config.OpenResty.Binary)
	brotliReady := openRestyCompressesBrotli(context.Background(), config.OpenResty.Binary)
	tlsOptionsReady := openRestySetsSiteTLSOptions(config.OpenResty.Binary)
	originNoVerifyReady := openRestySkipsOriginHostCheck(config.OpenResty.Binary)
	webpReady := openRestyConvertsWebP(context.Background(), config.OpenResty.Binary, dynamicRoutingLuaRoot)
	firewallStateRoot := filepath.Join(filepath.Dir(config.JournalDir), "firewall")
	firewallManager, firewallReady := selectFirewallRuntime(
		context.Background(), firewallStateRoot, exec.LookPath,
		func(root, binary string) (firewallRuntime, error) {
			return firewall.NewManager(root, binary)
		},
	)
	// The node DDoS protection table shares the firewall's nftables.
	var ddosManager *ddos.Manager
	var ddosManagerErr error
	if firewallReady && runtime.GOOS == "linux" {
		ddosManager, ddosManagerErr = newDDoSManager(context.Background(), filepath.Join(filepath.Dir(config.JournalDir), "ddos"), exec.LookPath)
	}
	// A node without the table reports it (deployment check, node telemetry)
	// instead of silently running without DDoS protection (PJ-E04).
	ddosUnavailable, ddosUnavailableDetail := ddosUnavailableReason(runtime.GOOS, firewallReady, exec.LookPath, ddosManagerErr)
	if ddosUnavailable != "" {
		ddosManager = nil
		slog.Warn("DDoS protection unavailable", "reason", ddosUnavailable, "detail", ddosUnavailableDetail)
	}
	if ddosManager != nil && nodeMonitoringRuntime != nil {
		// The packet filters' drop counters ride the node load samples.
		nodeMonitoringRuntime.SetDDoSDrops(ddosDropMetrics(ddosManager))
	}
	// The XDP filter fronts the DDoS table; it needs the table (nftables)
	// to fall back on, so a node without nftables does not attach it.
	xdpSetting := config.XDP
	if ddosManager == nil {
		xdpSetting.Disabled = true
	}
	xdpFilter := probeXDP(xdpSetting, os.Stderr)
	xdpFilterOwned := false
	defer func() {
		if !xdpFilterOwned {
			xdpFilter.Close()
		}
	}()
	if ddosManager != nil {
		ddosManager.SetFront(xdpFilter)
	}
	if nodeMonitoringRuntime != nil {
		nodeMonitoringRuntime.SetXDP(xdpStatusMetrics(xdpFilter))
	}
	// Dynamic routing (site_runtime 9): the node runtime the site objects
	// activate into; cache tasks, origin auth secrets, the DDoS table and the
	// CC kernel ban ports go to it.
	var plans dynroute.RulePlans
	if rulePackVault != nil {
		plans = rulepackprecheck.Plans{Vault: rulePackVault}
	}
	l4TrafficStopper := &l4TrafficStop{}
	l4 := dynamicRoutingL4{manager: l4Manager, dns: l4DNS, deploymentRoot: config.DeploymentRoot, stop: l4TrafficStopper}
	dynamicRouting, err := assembleDynamicRouting(config, nodeID, certificateManager, wafEngine, timeouts.Health, ddosManager, plans, l4)
	if err != nil {
		return nil, err
	}
	// manager is what the gateway client drives.
	var manager interface {
		gatewayclient.DeploymentManager
		deploymentRecoverer
		certificateDeploymentRecoverer
		ConfigureCertificateVersionStore(deployment.CertificateVersionStore, string) error
	}
	// Dynamic routing is the only node runtime (site_runtime 9): releases
	// are site objects activated by dynroute; every scope's last release is
	// merged into one node index.
	state, _ := dynamicRoutingRoots(config)
	dynamicManager, err := newDynamicRoutingManager(dynamicRouting, siteObjects, filepath.Join(state, "scopes"))
	if err != nil {
		return nil, err
	}
	manager = dynamicManager
	urlAuthRuntime, err := urlauth.NewArtifactRuntime(filepath.Join(config.DeploymentRoot, "urlauth"))
	if err != nil {
		return nil, fmt.Errorf("configure URL auth artifact runtime: %w", err)
	}
	cacheResolver, err := cachetask.NewActiveReleaseResolver(config.DeploymentRoot)
	if err != nil {
		return nil, fmt.Errorf("configure cache task release resolver: %w", err)
	}
	cacheTaskConfig, err := config.CacheTask.config()
	if err != nil {
		return nil, err
	}
	cacheManager, err := cachetask.NewManager(config.DeploymentRoot, cacheResolver, cacheTaskConfig)
	if err != nil {
		return nil, fmt.Errorf("configure cache task manager: %w", err)
	}
	cacheCarrier, err := cachetask.NewCarrier(cacheManager, cacheResolver)
	if err != nil {
		return nil, fmt.Errorf("configure cache task carrier: %w", err)
	}
	// The node skeleton (dynroute writes it to its shared root) serves the
	// tokens from its own overlay root (dynroute.New created it).
	overlayConfig := acmehttp01.DefaultConfig()
	_, dynamicShared := dynamicRoutingRoots(config)
	overlayConfig.RuntimeConfigPaths = []string{filepath.Join(dynamicShared, "nginx.conf")}
	overlayManager, err := acmehttp01.NewManagerWithConfig(dynamicRoutingACMERoot(config), overlayConfig)
	if err != nil {
		return nil, fmt.Errorf("configure ACME HTTP-01 overlay manager: %w", err)
	}
	if err := manager.ConfigureCertificateVersionStore(certificateManager, config.CertificateRuntime.StateRoot); err != nil {
		return nil, fmt.Errorf("configure deployment manager: %w", err)
	}
	drain, err := assembleDrainRuntime(config, timeouts, nil, openResty, dynamicManager)
	if err != nil {
		return nil, err
	}

	clientConfig := gatewayclient.DefaultConfig()
	clientConfig.NodeID = nodeID
	clientConfig.BootID = bootID
	clientConfig.ArtifactEncryptionKeyID = artifactKeyID
	clientConfig.ArtifactDecryptionPrivateKey = artifactPrivateKey
	clientConfig.JournalDir = config.JournalDir
	clientConfig.Capabilities = agentCapabilitiesWithFirewall(config.OpenResty.Version, firewallReady, securityStatus)
	// Every node runs dynamic routing: site_runtime 9, whatever the v2 site
	// runtime adapter's readiness.
	declareSiteRuntimeVersion(clientConfig.Capabilities, edgeconfig.DynamicRoutingSiteRuntimeVersion)
	// ADR 0012 ML-07: cdnca_limits / cdnca_l4_geo enforce the market
	// supply limits per subscription on the dynamic routing runtime.
	clientConfig.Capabilities.Features = append(clientConfig.Capabilities.Features, &agentv1.Capability{
		Name: agentv1.CapabilityName_CAPABILITY_NAME_SUBSCRIPTION_LIMITS, ApiVersion: edgeconfig.SubscriptionLimitsAPIVersion,
	})
	// L4 session facts carry the forward's package
	// (telemetry_sources.go l4TelemetryRegistrations).
	clientConfig.Capabilities.Features = append(clientConfig.Capabilities.Features, &agentv1.Capability{
		Name: agentv1.CapabilityName_CAPABILITY_NAME_L4_PACKAGE_ATTRIBUTION, ApiVersion: edgeconfig.L4PackageAttributionAPIVersion,
	})
	// cdnca_filters evaluates site response rules (pure Lua,
	// shipped with the dynamic routing modules every node runs).
	clientConfig.Capabilities.Features = append(clientConfig.Capabilities.Features, &agentv1.Capability{
		Name: agentv1.CapabilityName_CAPABILITY_NAME_EDGE_RESPONSE_RULES, ApiVersion: 1,
	})
	addL4TOACapability(clientConfig.Capabilities, l4TOA.Status())
	addHTTPProtocolCapabilities(clientConfig.Capabilities, siteQUICReady, http3Readiness.Ready)
	addCompressionCapabilities(clientConfig.Capabilities, brotliReady, webpReady)
	// fp-site5a: per site HTTP/2 off and prefer_server_ciphers (native patch 27)
	addSiteTLSOptionsCapability(clientConfig.Capabilities, tlsOptionsReady)
	// Origin trust anchor "none" (native patch 29)
	addOriginTLSNoVerifyCapability(clientConfig.Capabilities, originNoVerifyReady)
	// ge36: cache rule path_regex/content_types and origin redirect following
	// are in the dynamic routing Lua shipped with this agent (cdnca_cache,
	// cdnca_origin): no runtime probe.
	clientConfig.Capabilities.Features = append(clientConfig.Capabilities.Features,
		&agentv1.Capability{Name: agentv1.CapabilityName_CAPABILITY_NAME_CACHE_RULE_MATCH, ApiVersion: edgeconfig.CacheRuleMatchAPIVersion},
		&agentv1.Capability{Name: agentv1.CapabilityName_CAPABILITY_NAME_ORIGIN_FOLLOW_REDIRECT, ApiVersion: edgeconfig.OriginFollowRedirectAPIVersion},
		// site-backend6: default site, search engine origin, ACME pass-through,
		// unbuffered proxying (cdnca_site, cdnca_origin, cdnca_cache, skeleton)
		&agentv1.Capability{Name: agentv1.CapabilityName_CAPABILITY_NAME_SITE_EDGE_OPTIONS, ApiVersion: edgeconfig.SiteEdgeOptionsAPIVersion},
		// A19-b: L2 cache mode and L2 conditions (cdnca_origin, node id in
		// the skeleton's init_by_lua); v2: pass-through L2,
		// an L2 endpoint node goes direct, the X-Cdnca-L2-Hop loop guard
		&agentv1.Capability{Name: agentv1.CapabilityName_CAPABILITY_NAME_L2_ROUTING, ApiVersion: edgeconfig.L2RoutingAPIVersion},
		// errpage-3: error page slot node pages, package expired sites and
		// snapshots with slots (cdnca_site, cdnca_filters, cdnca_limits,
		// cdnca_banlist, errorpage)
		&agentv1.Capability{Name: agentv1.CapabilityName_CAPABILITY_NAME_ERROR_PAGE_SLOTS, ApiVersion: siteobject.ErrorPageSlotsAPIVersion},
		// fp-site2 (user Q4): both cache task paths (cachetask, dyncache) purge
		// "*.<suffix>" target hosts.
		&agentv1.Capability{Name: agentv1.CapabilityName_CAPABILITY_NAME_CACHE_WILDCARD_PURGE, ApiVersion: 1},
		// tls-custom: the custom cipher preset is SSL_set_cipher_list in
		// cdnca_tls.lua (stock OpenSSL, no native patch): no runtime probe.
		&agentv1.Capability{Name: agentv1.CapabilityName_CAPABILITY_NAME_SITE_TLS_CUSTOM_CIPHERS, ApiVersion: edgeconfig.SiteTLSCustomCiphersAPIVersion},
		// per-node-dist: the key document's withheld L4 forwards are left out
		// (gatewayclient selectNodeStreams)
		&agentv1.Capability{Name: agentv1.CapabilityName_CAPABILITY_NAME_L4_STREAM_SELECTION, ApiVersion: siteobject.L4StreamSelectionAPIVersion},
		// fz-x12: the node's region is the key document's node_region
		// (dynroute.Input.NodeRegion); the agent has no region setting.
		&agentv1.Capability{Name: agentv1.CapabilityName_CAPABILITY_NAME_NODE_REGION, ApiVersion: siteobject.NodeRegionAPIVersion},
		// The key document's node_storage sets the cache
		// directory and limit (reload) and the log directory (next start);
		// node telemetry reports what runs (NodeTelemetryV1.storage).
		&agentv1.Capability{Name: agentv1.CapabilityName_CAPABILITY_NAME_NODE_STORAGE, ApiVersion: siteobject.NodeStorageAPIVersion})
	if drain != nil {
		clientConfig.Capabilities.Features = append(clientConfig.Capabilities.Features, &agentv1.Capability{
			Name: agentv1.CapabilityName_CAPABILITY_NAME_DRAIN_CONTROL, ApiVersion: 1,
		})
	}
	if ja4Ready {
		// v1: the runtime computes the JA4 TLS fingerprint ($cdnca_ja4).
		clientConfig.Capabilities.Features = append(clientConfig.Capabilities.Features, &agentv1.Capability{
			Name: agentv1.CapabilityName_CAPABILITY_NAME_JA4, ApiVersion: 1,
		}, &agentv1.Capability{
			// WAF not_ja4 (rule plan ja4_not_in, rendered condition).
			Name: agentv1.CapabilityName_CAPABILITY_NAME_WAF_JA4_NEGATION, ApiVersion: edgeconfig.JA4NegationAPIVersion,
		})
	}
	if nodeMonitoringBridge != nil {
		clientConfig.Capabilities.Features = append(clientConfig.Capabilities.Features, &agentv1.Capability{
			Name: agentv1.CapabilityName_CAPABILITY_NAME_NODE_MONITORING, ApiVersion: 1,
		}, &agentv1.Capability{
			// fz-x11: telemetry mounts + port_group_overrides
			Name: agentv1.CapabilityName_CAPABILITY_NAME_NODE_TELEMETRY_DETAIL, ApiVersion: 1,
		})
	}
	clientConfig.MaxCommandBytes = config.Limits.MaxCommandBytes
	clientConfig.MaxStatusBytes = config.Limits.MaxStatusBytes
	clientConfig.MaxArtifactBytes = config.Limits.MaxArtifactBytes
	clientConfig.MaxDecompressedBytes = config.Limits.MaxDecompressedBytes
	clientConfig.MaxArtifactChunkBytes = config.Limits.MaxArtifactChunkBytes
	clientConfig.MaxActiveDeployments = config.Limits.MaxActiveDeployments
	clientConfig.CommandQueueSize = config.Limits.CommandQueueSize
	clientConfig.HandshakeTimeout = timeouts.Handshake
	clientConfig.FetchTimeout = timeouts.ArtifactFetch
	clientConfig.InitialBackoff = timeouts.InitialBackoff
	clientConfig.MaximumBackoff = timeouts.MaximumBackoff
	runtimeStatusProbe := gatewayclient.RuntimeStatusProbe{OpenResty: deploymentRuntime.Healthy,
		MarketProbeRole: config.MarketProbe.role()}
	if nativeRuntimeNode(config) {
		statusPath := nativeRuntimeStatusPath(config)
		runtimeStatusProbe.NativeRuntime = func() *agentv1.NativeRuntimeStatus { return nativeRuntimeReport(statusPath) }
	}
	if firewallReady {
		runtimeStatusProbe.Firewall = firewallManager.Probe
	}
	if dynamicRouting != nil {
		runtimeStatusProbe.ErrorLog = dynamicRouting.ErrorLogProto
	}
	var cacheTasks gatewayclient.CacheTaskManager = cacheCarrier
	if dynamicRouting != nil {
		cacheTasks = dynroute.CacheTasks{Runtime: dynamicRouting, RequestTimeout: cacheTaskConfig.RequestTimeout}
	}
	clientOptions := []gatewayclient.ClientOption{
		gatewayclient.WithSiteObjectStore(siteObjects),
		gatewayclient.WithACMEHTTP01OverlayConsumer(overlayManager),
		gatewayclient.WithCertificateConsumer(certificateManager),
		gatewayclient.WithCacheTaskManager(cacheTasks),
		gatewayclient.WithCacheTaskConfig(cacheTaskConfig),
		gatewayclient.WithURLAuthArtifactConsumer(urlAuthRuntime),
		gatewayclient.WithRuntimeStatusProbe(runtimeStatusProbe),
	}
	if config.Version == 2 {
		clientOptions = append(clientOptions, gatewayclient.WithNodeInventoryDiscovery(nodeinventory.DetectNodeNetworkInventory))
		renewer, err := enrollment.NewRenewer(config.IdentityDir)
		if err != nil {
			return nil, fmt.Errorf("configure gateway certificate renewal: %w", err)
		}
		clientOptions = append(clientOptions, gatewayclient.WithCertificateRenewer(renewer, nil))
		recoverer, err := enrollment.NewRecoverer(enrollment.RecoverConfig{IdentityDir: config.IdentityDir,
			Dial: enrollment.RecoveryDial(enrollment.Config{Address: config.Gateway.enrollmentAddress(),
				ServerName: config.Gateway.ServerName, RootCAFile: config.Gateway.RootCAFile})})
		if err != nil {
			return nil, fmt.Errorf("configure gateway certificate recovery: %w", err)
		}
		clientOptions = append(clientOptions, gatewayclient.WithCertificateRecoverer(recoverer))
	}
	// FX65: CC auto switch engagements travel with node monitoring reports.
	var ccNotifier ccAutoSwitchNotifier
	if nodeMonitoringBridge != nil {
		ccNotifier = nodeMonitoringBridge
		clientOptions = append(clientOptions, gatewayclient.WithNodeMonitoringBridge(nodeMonitoringBridge))
	}
	if runtime.GOOS == "linux" {
		// 实时连接 (L4_LIVE_CONNECTIONS): v2 when this agent may close sessions
		// (root and pidfd_getfd), else v1 (list only).
		liveExecutor, err := l4live.New(l4LiveRuntime{manager: l4Manager, openResty: l4OpenResty}, l4live.LinuxKernel{},
			l4live.ControlRegistry{Path: l4runtime.L4ControlSocketPath}, l4live.CanClose())
		if err != nil {
			return nil, fmt.Errorf("configure L4 live connections: %w", err)
		}
		clientOptions = append(clientOptions, gatewayclient.WithL4LiveExecutor(liveExecutor))
		// L4_TRAFFIC_STOP v1: forwards withdrawn for package traffic lose
		// their sessions at once, closed as the live connection list does.
		if liveExecutor.APIVersion() == l4live.APIVersionClose {
			l4TrafficStopper.mu.Lock()
			l4TrafficStopper.executor = liveExecutor
			l4TrafficStopper.mu.Unlock()
			clientConfig.Capabilities.Features = append(clientConfig.Capabilities.Features, &agentv1.Capability{
				Name: agentv1.CapabilityName_CAPABILITY_NAME_L4_TRAFFIC_STOP, ApiVersion: l4TrafficStopAPIVersion})
		}
	}
	clientOptions = append(clientOptions, gatewayclient.WithSignerTrustRuntime(signerTrust))
	// cdncaCE: no license service, so no service ticket ever arrives; the
	// installation ban gate (no ticket = no serving) is not assembled.
	var installationBan *installationban.Runtime
	if installationBan != nil {
		clientOptions = append(clientOptions, gatewayclient.WithInstallationBan(installationBanAgent{runtime: installationBan}))
	}
	// The ban list library's snapshots (sent to WAF v2 Agents).
	securityBans := newSecurityBanRuntime(nodeID, trust.Ed25519Key, config.OpenResty.HealthURL, timeouts.HealthRequest, time.Now)
	if securityBans != nil {
		clientOptions = append(clientOptions, gatewayclient.WithSecurityBans(securityBans))
		// Network bans in the list (prefix match in
		// cdnca_banlist, prefix entries in the kernel ban path).
		clientConfig.Capabilities.Features = append(clientConfig.Capabilities.Features, &agentv1.Capability{
			Name: agentv1.CapabilityName_CAPABILITY_NAME_BAN_CIDR, ApiVersion: securityban.CIDRAPIVersion,
		})
	}
	// esc-node §2/§3: level D site drop snapshots (SITE_DROP v1), derived
	// from the dynamic routing sites, enforced by XDP / nftables (inet
	// cdnca_ddos) and OpenResty: the level D names go to the dynamic routing
	// control socket (site_drop_openresty.go, §4), which closes (444) the
	// requests and handshakes selecting them.
	var siteDrop *siteDropRuntime
	if dynamicRouting != nil {
		var nft siteDropNFT
		if ddosManager != nil {
			nft = ddosManager
		}
		executor := newKernelSiteDropExecutor(xdpFilter, nft, filepath.Join(state, edgeskeleton.ControlSocket))
		siteDrop = newSiteDropRuntime(nodeID, trust.Ed25519Key, dynamicRouting.RunningSites, xdpFilter.Running,
			executor, time.Now)
	}
	if siteDrop != nil {
		clientOptions = append(clientOptions, gatewayclient.WithSiteDrop(siteDrop))
		if nodeMonitoringRuntime != nil {
			// sitedrop-telemetry: the site drop counters ride the node load
			// samples with the sites dropped for.
			nodeMonitoringRuntime.SetSiteDrop(newSiteDropTelemetry(xdpFilter, ddosManager, siteDrop.DroppedSites).Sample)
		}
	}
	// HTTP 302 scheduling tables (SCHED302 v1): written where the rendered
	// schedule302 sites read them, never reloaded.
	scheduleTables, err := sched302runtime.New(config.DeploymentRoot, nodeID)
	if err != nil {
		return nil, fmt.Errorf("configure schedule302 tables: %w", err)
	}
	clientOptions = append(clientOptions, gatewayclient.WithSched302Runtime(scheduleTables))
	if xdpFilter.Running() {
		// XDP_FILTER follows the filter at run time (fallback / reattach).
		clientOptions = append(clientOptions, gatewayclient.WithLiveCapability(xdpCapability(xdpFilter)))
	}
	// AUTO_DEFENSE v1 (AD-07/AD-05): the local runtime runs only on dynamic routing nodes, where it has its
	// Lua gate. The node decides and mitigates on its own; L4 bans go to the DDoS table's ban sets.
	// Platform node security events (F4, AD-08) and the CC rule statistics travel on its
	// upstream on every node with an identity: the capability is declared without the local runtime too
	// (snapshots are then refused with not_supported).
	if nodeMonitoringRuntime != nil && dynamicRouting != nil {
		nodeMonitoringRuntime.SetStorage(storageMetrics(dynamicRouting))
	}
	nodeEvents := newNodeSecurityEvents(nodeID, time.Now)
	ccRuleStats := newCCStats(nodeID, time.Now)
	if receiver := newAutoDefenseReceiver(nodeID, trust.Ed25519Key, nil, nodeEvents); receiver != nil {
		clientOptions = append(clientOptions, gatewayclient.WithAutoDefense(withCCStatsReports(receiver, ccRuleStats)))
	}
	// ARTIFACT_SET v1 (node-wide, also on multi-tenant nodes): the IP
	// intelligence library and the OWASP CRS engine module arrive as items of
	// the node artifact set. A changed engine module reloads the current
	// single-scope release so its gate loads it (multi-tenant nodes: the next
	// deployment).
	var engineChanged func(context.Context) error
	if dynamicManager != nil {
		// Dynamic routing: the skeleton loads the module (load_module); the
		// node state is applied again with the new one (nginx -t + reload).
		engineChanged = dynamicManager.Reapply
	}
	artifactSets, err := assembleArtifactSetRuntime(config.DeploymentRoot, nodeID, siteObjects, wafEngine, engineChanged, rulePackVault)
	if err != nil {
		return nil, err
	}
	if dynamicManager != nil {
		// New or changed packs: sites waiting on them apply now.
		artifactSets.rulePacksChanged = dynamicManager.Reapply
	}
	clientOptions = append(clientOptions, gatewayclient.WithArtifactSetRuntime(artifactSets))
	if marketProbe != nil {
		clientOptions = append(clientOptions, gatewayclient.WithMarketProbeExecutor(marketProbe))
	}
	var ddosStatus ddosStatusSource
	if dynamicRouting != nil {
		ddosStatus = dynamicRouting
	}
	ddosProtection := ddosProtectionState(ddosUnavailable, ddosUnavailableDetail, ddosStatus)
	if nodeMonitoringRuntime != nil {
		nodeMonitoringRuntime.SetDDoSProtection(ddosProtection)
	}
	clientOptions = append(clientOptions, gatewayclient.WithDeploymentChecks(
		combineDeploymentChecks(wafEngineChecks(wafEngine), http3RuntimeChecks(http3Readiness), siteCertificateChecks(dynamicRouting),
			ddosProtectionChecks(ddosProtection))))
	{
		errorPages, err := assembleErrorPages(config.OpenResty.Binary, config.DeploymentRoot, trust)
		if err != nil {
			return nil, err
		}
		clientOptions = append(clientOptions, gatewayclient.WithErrorPageArtifactConsumer(errorPages))
		originAuth, err := assembleOriginAuth(config.DeploymentRoot, dynamicRouting)
		if err != nil {
			return nil, err
		}
		clientOptions = append(clientOptions, gatewayclient.WithOriginAuthArtifactConsumer(originAuth))
	}
	challengeVerifier, err := challenge.NewExternalVerifierServer(
		config.DeploymentRoot, challenge.ExternalVerifierAddress, http.DefaultClient,
	)
	if err != nil {
		return nil, fmt.Errorf("configure external challenge verifier: %w", err)
	}
	if firewallReady {
		clientOptions = append(clientOptions, gatewayclient.WithFirewallManager(firewallManager))
	}
	if owner, ok := firewallManager.(interface {
		SetOwnerScope(context.Context, string) error
	}); ok && firewallReady {
		clientOptions = append(clientOptions, gatewayclient.WithNodeOwnerHandler(owner.SetOwnerScope))
	}
	if drain != nil {
		clientOptions = append(clientOptions, gatewayclient.WithDrainPlanHandler(drain))
	}
	if config.Upgrade.Enabled {
		var pointers upgradeConfigPointers
		pointers = nodePointers{dynamicManager}
		upgradeRuntime, err := assembleUpgradeRuntime(config, nodeID, pointers)
		if err != nil {
			return nil, err
		}
		clientOptions = append(clientOptions, gatewayclient.WithUpgradeRuntime(upgradeRuntime))
	}
	if dynamicManager != nil {
		clientOptions = append(clientOptions, gatewayclient.WithDynamicRouting(dynamicManager))
	}
	clientOptions = append(clientOptions, gatewayclient.WithGatewayEndpointLearner(dialer.Learn))
	client, err := gatewayclient.New(clientConfig, dialer, manager, trust, clientOptions...)
	if err != nil {
		return nil, fmt.Errorf("configure gateway client: %w", err)
	}
	candidateProber, err := gatewayclient.NewClientCandidateProber(client, dialerFactory)
	if err != nil {
		return nil, fmt.Errorf("configure gateway endpoint prober: %w", err)
	}
	if err := client.ConfigurePortTransition(gatewayclient.NewPortTransitionRuntime(
		endpointStore, candidateProber, dialerFactory.CertificateSHA256(), time.Now,
	)); err != nil {
		return nil, fmt.Errorf("configure gateway port transition runtime: %w", err)
	}
	// Signed Gateway address change (probe with mTLS + hello,
	// switch only on success). Same trust as site drop (edge publication key).
	addressProber, err := gatewayclient.NewClientAddressProber(client, dialerFactory)
	if err != nil {
		return nil, fmt.Errorf("configure gateway address prober: %w", err)
	}
	addressRuntime, err := gatewayclient.NewGatewayAddressRuntime(nodeID, trust.Ed25519Key, endpointStore,
		filepath.Join(config.JournalDir, "gateway-endpoint"), addressProber, clientConfig.HandshakeTimeout, time.Now)
	if err != nil {
		return nil, fmt.Errorf("configure gateway address change runtime: %w", err)
	}
	if err := client.ConfigureGatewayAddressChange(addressRuntime); err != nil {
		return nil, fmt.Errorf("configure gateway address change runtime: %w", err)
	}
	keepClient := false
	defer func() {
		if !keepClient {
			_ = client.Close()
		}
	}()
	var telemetry telemetryRunner
	if config.Telemetry.Enabled {
		telemetryDialer, err := newSwitchingTelemetryDialer(endpointStore, telemetryclient.MTLSDialerConfig{
			Address: endpointStore.Active().Address, ServerName: endpointStore.Active().ServerName,
			RootCAFile: config.Gateway.RootCAFile, ClientCertificateFile: clientCertificateFile,
			ClientPrivateKeyFile: clientPrivateKeyFile, MaximumReceiveBytes: 1 << 20,
			MaximumSendBytes: config.Telemetry.MaxBatchBytes + (64 << 10),
			Transport:        config.Gateway.Transport, TunnelHost: config.Gateway.TunnelHost,
			TunnelAudience: config.tunnelAudience(),
		})
		if err != nil {
			return nil, fmt.Errorf("configure telemetry gateway mTLS: %w", err)
		}
		var l4Usage *l4UsageSource
		if runtime.GOOS == "linux" {
			// L4-USAGE-01: in-progress TCP session usage from the kernel
			// counters of the sessions the L4 runtime registered.
			l4Usage = &l4UsageSource{manager: l4Manager}
		}
		telemetry, err = assembleTelemetryPipeline(config, timeouts, nodeID, bootID, telemetryDialer, dynamicManager,
			dynamicRouting, firewallStateRoot, l4Usage)
		if err != nil {
			return nil, err
		}
	}
	logGuard, err := assembleLogDiskGuard(config)
	if err != nil {
		return nil, err
	}
	// L4 guard bans raised to kernel bans through the node firewall.
	var l4KernelBans firewallExpiryRunner
	if scoped, ok := firewallManager.(l4guard.Firewall); ok && firewallReady && runtime.GOOS == "linux" {
		runner, err := l4guard.New(l4guard.ControlBans{Path: l4runtime.L4ControlSocketPath}, l4Manager, scoped, time.Now)
		if err != nil {
			return nil, fmt.Errorf("configure L4 kernel bans: %w", err)
		}
		runner.OnBan = func(client netip.Addr, count int, remaining time.Duration) {
			nodeEvents.KernelBan("l4guard", "kernel_ban", "l4_guard_rule", client, count, remaining)
		}
		l4KernelBans = runner
	}
	// CC temporary bans raised to kernel bans (DDoS protection cc_kernel_ban).
	var ccBans *ccKernelBans
	// FX45 firewall action escalation mirrored into nftables.
	var firewallActions *firewallActionMirror
	if scoped, ok := firewallManager.(firewall.ScopedFirewall); ok && firewallReady && runtime.GOOS == "linux" {
		owned := func(string) bool { return false }
		if owner, ok := firewallManager.(interface{ OwnedBy(string) bool }); ok {
			owned = owner.OwnedBy
		}
		ccBans = newCCKernelBans(scoped, sharedNodeBanPorts(owned, dynamicRouting.CCKernelBanPorts, dynamicRouting.SharedNodeCCKernelBanPorts), time.Now)
		ccBans.mirror = xdpPortBans(xdpFilter)
		ccBans.withdraw = xdpPortUnbans(xdpFilter)
		if dynamicRouting != nil {
			// Card 5: the ban ports follow the running sites and the node owner.
			owner := func() string { return "" }
			if scope, ok := firewallManager.(interface{ OwnerScope() string }); ok {
				owner = scope.OwnerScope
			}
			ccBans.topology = func() string { return fmt.Sprintf("%d|%s", dynamicRouting.Generation(), owner()) }
		}
		if dynamicRouting != nil {
			firewallActions = newFirewallActionMirror(scoped, dynamicRouting.Sites, dynamicRouting.Object)
			firewallActions.owned = owned
		}
	}
	// Empty connection bans need the DDoS table's ban sets.
	var emptyConnections firewallExpiryRunner
	if ddosManager != nil {
		detector := ddos.NewEmptyConnections(ddosManager, ddos.SockDiag{}, time.Now)
		detector.OnBan = func(client netip.Addr, count int, ban time.Duration) {
			slog.Warn("empty connection flood: client banned", "client", client.String(), "empty_connections", count, "ban", ban.String())
			nodeEvents.EmptyConnectionBan(client, count, ban)
		}
		emptyConnections = detector
	}
	// Kernel rate bans (no callback): found by listing the ban sets (F4).
	var rateBans firewallExpiryRunner
	if ddosManager != nil {
		watch := ddos.NewRateBanWatch(ddosManager, time.Now)
		watch.OnBan = func(client netip.Addr, count int, remaining time.Duration) {
			nodeEvents.KernelBan("ddos", "rate_ban", "new_connection_rate", client, count, remaining)
		}
		rateBans = watch
	}
	// Until the first Apply OpenResty is not running by design: the status
	// poller stays quiet instead of warning every second (nil: always polls).
	var runtimeReady func() bool
	if dynamicRouting != nil {
		runtimeReady = dynamicRouting.Applied
	}
	daemon := &daemonClient{
		client: client, certificate: certificateManager, certificateDeployment: manager, deployment: manager,
		telemetry: telemetry, drain: drain,
		firewallExpiry: newFirewallExpiryScheduler(firewallManager, time.Now, nil), l4KernelBans: l4KernelBans,
		runtimeStatus: newRuntimeStatusPoller(config.OpenResty.HealthURL, timeouts.HealthRequest).
			withCCAutoSwitchNotifier(nodeID, ccNotifier).withCCKernelBans(ccBans).withCCStats(ccRuleStats).
			withWAFKernelBans(dynamicRouting.SiteTenantScope, securityBans).withFirewallActions(firewallActions).
			withSiteDrop(siteDrop).withReady(runtimeReady),
		cacheTasks: cacheTasks, challengeVerifier: challengeVerifier,
		l4TOA: l4TOA, l4OpenResty: l4OpenResty, emptyConnections: emptyConnections, rateBans: rateBans,
		xdpFilter: xdpFilter,
		endpointProbe: func(ctx context.Context) {
			dialer.RunFallbackProbe(ctx, gatewayclient.FallbackProbeInterval, timeouts.Handshake)
		},
	}
	if xdpFilter.Running() {
		// A run time fallback is retried; the DDoS spec is mirrored again on the reattached filter.
		daemon.xdpWatch = newXDPWatch(xdpFilter, func() { ddosManager.SetFront(xdpFilter) }, nodeEvents)
	}
	if dynamicRouting != nil {
		daemon.dynamicRouting = dynamicRouting
	}
	daemon.installationBan = installationBan
	l4TOAOwned = true
	xdpFilterOwned = true
	if guard != nil {
		daemon.diskGuard = guard
	}
	if logGuard != nil {
		daemon.logDiskGuard = logGuard
	}
	keepClient = true
	return daemon, nil
}

type switchingTelemetryDialer struct {
	store gatewayclient.GatewayEndpointStateStore
	base  telemetryclient.MTLSDialerConfig
}

// assembleTelemetryPipeline is the node telemetry pipeline (config.telemetry):
// the spool, the telemetry client over dialer, its worker and the log sources
// (dynamic routing node: the shared logs and the subscription minutes). The
// daemon and the cross-process telemetry e2e (tests/telemetry-e2e) share it.
func assembleTelemetryPipeline(config fileConfig, timeouts parsedTimeouts, nodeID, bootID string, dialer telemetryclient.Dialer,
	dynamicManager *dynamicRoutingManager, dynamicRouting *dynroute.Runtime, firewallStateRoot string,
	l4Usage *l4UsageSource) (*telemetryPipeline, error) {
	spool, err := eventspool.New(eventspool.Config{
		Root: config.Telemetry.SpoolRoot, MaxEventBytes: config.Telemetry.MaxEventBytes,
		MaxSegmentBytes: config.Telemetry.MaxSegmentBytes, SoftLimitBytes: config.Telemetry.SoftLimitBytes,
		HardLimitBytes: config.Telemetry.HardLimitBytes, MaxTenantBytes: config.Telemetry.MaxTenantBytes,
		MaxBatchEvents:    config.Telemetry.MaxSpoolBatchEvents,
		PressureMode:      eventspool.PressureMode(config.Telemetry.PressureMode),
		AccessSampleEvery: config.Telemetry.AccessSampleEvery, SecuritySampleEvery: config.Telemetry.SecuritySampleEvery,
		SoftAgeLimit: timeouts.TelemetrySoftAgeLimit, HardAgeLimit: timeouts.TelemetryHardAgeLimit,
	})
	if err != nil {
		return nil, fmt.Errorf("configure telemetry spool: %w", err)
	}
	telemetryConfig := telemetryclient.DefaultConfig()
	telemetryConfig.NodeID = nodeID
	telemetryConfig.BootID = bootID
	telemetryConfig.Cursor = telemetryclient.NewDurableCursor(spool)
	if config.Telemetry.IndependentMetricsEnabled {
		telemetryConfig.ConnectionsCursor = telemetryclient.NewConnectionsDurableCursor(spool)
	}
	telemetryConfig.HandshakeTimeout = timeouts.TelemetryHandshake
	telemetryConfig.AckTimeout = timeouts.TelemetryAck
	telemetryConfig.InitialBackoff = timeouts.TelemetryInitialBackoff
	telemetryConfig.MaximumBackoff = timeouts.TelemetryMaximumBackoff
	telemetryConfig.MaxRecordsPerBatch = config.Telemetry.MaxRecordsPerBatch
	telemetryConfig.MaxRecordBytes = config.Telemetry.MaxRecordBytes
	telemetryConfig.MaxBatchBytes = config.Telemetry.MaxBatchBytes
	if dynamicManager != nil {
		// A dynamic routing node declares MULTI_TENANT_RUNTIME (its
		// manager keeps per-scope state): records name their scope.
		telemetryConfig.ScopedRecords = true
		telemetryConfig.ScopeForSite = dynamicManager.ScopeForSite
	}
	sender, err := telemetryclient.New(telemetryConfig, dialer)
	if err != nil {
		return nil, fmt.Errorf("configure telemetry client: %w", err)
	}
	publisher, err := telemetryclient.NewPublisher(nodeID, sender)
	if err != nil {
		return nil, fmt.Errorf("configure telemetry publisher: %w", err)
	}
	workerConfig := telemetryclient.WorkerConfig{
		MaximumEvents: config.Telemetry.FlushBatchEvents, EmptyInterval: timeouts.TelemetryEmptyInterval,
		InitialBackoff: timeouts.TelemetryInitialBackoff, MaximumBackoff: timeouts.TelemetryMaximumBackoff,
	}
	worker, err := telemetryclient.NewWorker(workerConfig, spool, publisher)
	if err != nil {
		return nil, fmt.Errorf("configure telemetry worker: %w", err)
	}
	quarantineLimit := config.Telemetry.HardLimitBytes / 16
	if quarantineLimit < 64<<10 {
		quarantineLimit = 64 << 10
	}
	if quarantineLimit > 1<<30 {
		quarantineLimit = 1 << 30
	}
	sink := telemetrySink(spool, config.DeploymentRoot)
	var ledger *l4usage.Ledger
	if l4Usage != nil {
		if ledger, err = l4Usage.ledger(config.Telemetry.SpoolRoot, nodeID, config.Telemetry.MaxSpoolBatchEvents); err != nil {
			return nil, fmt.Errorf("configure L4 usage checkpoints: %w", err)
		}
		// session end lines carry the bytes their checkpoints billed
		sink = l4usage.SettlingSink{Ledger: ledger, Next: sink}
	}
	sources, err := newTelemetrySourceRunner(telemetrySourceConfig{
		IndependentMetricsEnabled: config.Telemetry.IndependentMetricsEnabled,
		DeploymentRoot:            config.DeploymentRoot, SpoolRoot: config.Telemetry.SpoolRoot,
		FirewallRoot:     firewallStateRoot,
		EnrollmentNodeID: nodeID, PollInterval: timeouts.TelemetryEmptyInterval,
		MaxLineBytes: config.Telemetry.MaxEventBytes, MaxBatchEvents: config.Telemetry.MaxSpoolBatchEvents,
		MaxQuarantineBytes: quarantineLimit,
		DynamicRouting:     dynamicRoutingTelemetrySource(dynamicRouting, nodeID),
	}, sink)
	if err != nil {
		return nil, fmt.Errorf("configure telemetry sources: %w", err)
	}
	pipeline := &telemetryPipeline{worker: worker, sources: sources, spool: spool, l4Usage: ledger, l4UsageSink: spool}
	if config.Telemetry.IndependentMetricsEnabled {
		pipeline.connections, err = telemetryclient.NewWorker(workerConfig, spool, publisher)
		if err != nil {
			return nil, fmt.Errorf("configure connections worker: %w", err)
		}
	}
	return pipeline, nil
}

func newSwitchingTelemetryDialer(store gatewayclient.GatewayEndpointStateStore, base telemetryclient.MTLSDialerConfig) (telemetryclient.Dialer, error) {
	if store == nil {
		return nil, errors.New("gateway endpoint state is required")
	}
	dialer := &switchingTelemetryDialer{store: store, base: base}
	if _, err := dialer.current(); err != nil {
		return nil, err
	}
	return dialer, nil
}

func (d *switchingTelemetryDialer) current() (telemetryclient.Dialer, error) {
	state := d.store.Active()
	config := d.base
	config.Address = state.Address
	config.ServerName = state.ServerName
	return telemetryclient.NewMTLSDialer(config)
}

func (d *switchingTelemetryDialer) Dial(ctx context.Context) (telemetryclient.Connection, error) {
	dialer, err := d.current()
	if err != nil {
		return nil, err
	}
	return dialer.Dial(ctx)
}

const l4StreamSetV2Schema = "cdnca.edge.l4-stream-set/v2"

type l4StreamSetV2Document struct {
	SchemaVersion string                          `json:"schema_version"`
	VersionID     string                          `json:"version_id"`
	Revision      int64                           `json:"revision"`
	Streams       []l4runtime.StreamRuntimeSpecV2 `json:"streams"`
	// SiteSockets hands websites on ports a stream shares to the site
	// OpenResty (shared L4 ports, tcp/udp v4).
	SiteSockets []l4runtime.SiteSocketsV2 `json:"site_sockets,omitempty"`
}

type l4LiveRuntime struct {
	manager   *l4runtime.Manager
	openResty *l4runtime.OpenResty
}

func (runtime l4LiveRuntime) ActiveConfigV2(ctx context.Context) (*l4runtime.ConfigV2, error) {
	return runtime.manager.ActiveConfigV2(ctx)
}

func (runtime l4LiveRuntime) WorkerPIDs() ([]int, error) { return runtime.openResty.WorkerPIDs() }

type l4DeploymentBridge struct {
	delegate       http3DeploymentLifecycle
	manager        *l4runtime.Manager
	dns            *l4runtime.DNSCoordinator
	healthInterval time.Duration
}

func (bridge *l4DeploymentBridge) Precheck(ctx context.Context, versionID, releasePath string) error {
	config, present, err := bridge.load(releasePath)
	if err != nil {
		return err
	}
	if present {
		if config.VersionID != versionID {
			return l4runtime.ErrInvalidConfig
		}
		if err := bridge.manager.PrecheckV2(ctx, config, bridge.dns); err != nil {
			return err
		}
	}
	return bridge.delegate.Precheck(ctx, versionID, releasePath)
}

func (bridge *l4DeploymentBridge) Reload(ctx context.Context, versionID, currentPath string) error {
	config, present, err := bridge.load(currentPath)
	if err != nil {
		return err
	}
	if present && config.VersionID != versionID {
		return l4runtime.ErrInvalidConfig
	}
	if err := bridge.manager.BeginRelease(ctx, versionID); err != nil {
		return err
	}
	if present {
		_, err = bridge.manager.ApplyV2(ctx, config, bridge.dns)
	} else {
		_, err = bridge.manager.Apply(ctx, l4runtime.Config{
			SchemaVersion: l4runtime.SchemaVersionV1, VersionID: versionID,
			Listeners: []l4runtime.Listener{}, UpstreamPools: []l4runtime.UpstreamPool{}, DrainTimeoutMS: 30000,
		})
	}
	if err == nil {
		err = bridge.delegate.Reload(ctx, versionID, currentPath)
	}
	if err != nil {
		return errors.Join(err, bridge.abortRelease(versionID))
	}
	return nil
}

func (bridge *l4DeploymentBridge) Healthy(ctx context.Context, versionID string) error {
	interval := bridge.healthInterval
	if interval <= 0 {
		interval = deployment.DefaultConfig().HealthInterval
	}
	for {
		err := bridge.delegate.Healthy(ctx, versionID)
		if err == nil {
			break
		}
		// 健康截止时间由 deployment manager 的 waitHealthy 给出；截止前单次探测失败
		// 不能撤销四层，否则 HTTP 稍后变健康时四层已回退。
		if _, bounded := ctx.Deadline(); !bounded || ctx.Err() != nil {
			return errors.Join(err, bridge.abortRelease(versionID))
		}
		timer := time.NewTimer(interval)
		select {
		case <-ctx.Done():
			timer.Stop()
			return errors.Join(ctx.Err(), bridge.abortRelease(versionID))
		case <-timer.C:
		}
	}
	if err := bridge.manager.FinishRelease(ctx, versionID, true); err != nil {
		return errors.Join(err, bridge.abortRelease(versionID))
	}
	return nil
}

func (bridge *l4DeploymentBridge) abortRelease(versionID string) error {
	ctx, cancel := context.WithTimeout(context.Background(), 30*time.Second)
	defer cancel()
	return bridge.manager.FinishRelease(ctx, versionID, false)
}

func (bridge *l4DeploymentBridge) load(root string) (l4runtime.ConfigV2, bool, error) {
	file, err := os.Open(filepath.Join(root, edgeconfig.L4RuntimeV2ArtifactPath))
	if errors.Is(err, os.ErrNotExist) {
		return l4runtime.ConfigV2{}, false, nil
	}
	if err != nil {
		return l4runtime.ConfigV2{}, false, err
	}
	defer file.Close()
	decoder := json.NewDecoder(io.LimitReader(file, 16<<20))
	decoder.DisallowUnknownFields()
	var document l4StreamSetV2Document
	if err := decoder.Decode(&document); err != nil || document.SchemaVersion != l4StreamSetV2Schema || len(document.Streams) == 0 {
		return l4runtime.ConfigV2{}, false, l4runtime.ErrInvalidConfig
	}
	var extra any
	if err := decoder.Decode(&extra); !errors.Is(err, io.EOF) {
		return l4runtime.ConfigV2{}, false, l4runtime.ErrInvalidConfig
	}
	config, err := l4runtime.AggregateStreamRuntimeSpecsV2(document.VersionID, document.Revision, document.Streams, document.SiteSockets...)
	if err != nil {
		return l4runtime.ConfigV2{}, false, err
	}
	return config, true, nil
}

type daemonL4DNSResolver struct{}

func (daemonL4DNSResolver) LookupIP(ctx context.Context, host string) (l4runtime.DNSLookupResult, error) {
	addresses, err := net.DefaultResolver.LookupNetIP(ctx, "ip", host)
	if err != nil {
		var dnsErr *net.DNSError
		return l4runtime.DNSLookupResult{TTL: 30 * time.Second, Negative: errors.As(err, &dnsErr) && dnsErr.IsNotFound}, err
	}
	return l4runtime.DNSLookupResult{Addresses: addresses, TTL: 30 * time.Second}, nil
}

func daemonL4AddressHealth(ctx context.Context, listener l4runtime.ListenerV2, addresses []netip.Addr) error {
	if len(addresses) == 0 {
		return l4runtime.ErrDNSUnavailable
	}
	network := string(listener.Protocol)
	for _, address := range addresses {
		candidateNetwork := network
		if address.Is4() {
			candidateNetwork += "4"
		} else {
			candidateNetwork += "6"
		}
		probeCtx, cancel := context.WithTimeout(ctx, 2*time.Second)
		connection, err := (&net.Dialer{}).DialContext(probeCtx, candidateNetwork,
			net.JoinHostPort(address.String(), strconv.Itoa(listener.Endpoint.Port)))
		cancel()
		if err != nil {
			return err
		}
		if err := connection.Close(); err != nil {
			return err
		}
	}
	return nil
}

// upgradeConfigPointers is the active configuration the upgrade receipt
// proves: the single-scope manager's pointers, or a dynamic routing node's
// (dynamicRoutingManager.NodePointers).
type upgradeConfigPointers interface {
	Pointers() (deployment.Pointers, error)
}

type nodePointers struct{ manager *dynamicRoutingManager }

func (pointers nodePointers) Pointers() (deployment.Pointers, error) {
	return pointers.manager.NodePointers()
}

func assembleUpgradeRuntime(config fileConfig, nodeID string,
	deploymentManager upgradeConfigPointers) (gatewayclient.UpgradeRuntime, error) {
	controlTrust, err := gatewayclient.LoadTrustStore(config.Upgrade.ControlExecutionTrustFile)
	if err != nil {
		return nil, fmt.Errorf("load control upgrade execution trust: %w", err)
	}
	edgeTrust, err := gatewayclient.LoadTrustStore(config.Upgrade.EdgeExecutionTrustFile)
	if err != nil {
		return nil, fmt.Errorf("load edge upgrade execution trust: %w", err)
	}
	receiptTrust, err := gatewayclient.LoadTrustStore(config.Upgrade.InstallerReceiptTrustFile)
	if err != nil {
		return nil, fmt.Errorf("load upgrade installer receipt trust: %w", err)
	}
	controlKeys, err := controlTrust.Ed25519Keys()
	if err != nil {
		return nil, err
	}
	edgeKeys, err := edgeTrust.Ed25519Keys()
	if err != nil {
		return nil, err
	}
	receiptKeys, err := receiptTrust.Ed25519Keys()
	if err != nil {
		return nil, err
	}
	rootPEM, err := readConfigFile(config.Upgrade.DownloadRootCAFile)
	if err != nil {
		return nil, fmt.Errorf("load upgrade download root CA: %w", err)
	}
	if !x509.NewCertPool().AppendCertsFromPEM(rootPEM) {
		return nil, errors.New("upgrade download root CA is invalid")
	}
	for _, raw := range config.Upgrade.DownloadAddresses {
		if _, err := netip.ParseAddr(raw); err != nil {
			return nil, errors.New("upgrade download address is invalid")
		}
	}
	timeout, err := time.ParseDuration(config.Upgrade.Timeout)
	if err != nil {
		return nil, errors.New("upgrade timeout is invalid")
	}
	// The installed endpoint, replaced by the control-signed policy of later
	// executions when the control plane moves.
	downloader, err := updater.NewPolicyDownloader(filepath.Join(config.Upgrade.Root, "download-policy"),
		updater.InstalledDownloadPolicy{Host: config.Upgrade.DownloadHost, Port: config.Upgrade.DownloadPort,
			Addresses: config.Upgrade.DownloadAddresses, RootPEM: rootPEM, Timeout: timeout})
	if err != nil {
		return nil, fmt.Errorf("configure upgrade downloader: %w", err)
	}
	installer, err := updater.NewPackagingInstaller()
	if err != nil {
		return nil, fmt.Errorf("configure upgrade installer: %w", err)
	}
	managerConfig := updater.DefaultConfig(config.Upgrade.Root, agentVersion, edgeKeys, receiptKeys,
		downloader, installer, upgradeReceiptProbe{
			installer: installer, deployment: deploymentManager, runVersion: runUpgradeVersion,
			nativeRuntime: func() error { return nativeRuntimeHealth(config) },
		})
	managerConfig.NodeID = nodeID
	managerConfig.MaxArtifactBytes = config.Upgrade.MaxArtifactBytes
	managerConfig.DiskReserveBytes = config.Upgrade.DiskReserveBytes
	manager, err := updater.NewManager(managerConfig)
	if err != nil {
		return nil, fmt.Errorf("configure upgrade manager: %w", err)
	}
	store, err := updater.NewDurableUpgradeStore(config.Upgrade.Root)
	if err != nil {
		return nil, fmt.Errorf("configure durable upgrade store: %w", err)
	}
	runtime, err := updater.NewUpgradeRuntime(updater.UpgradeRuntimeConfig{
		Store: store, Manager: manager, DownloadPolicy: downloader,
		Options: updater.UpgradeExecutionConsumerOptions{
			ExpectedInstallationID: config.Upgrade.InstallationID, ExpectedNodeID: nodeID,
			ExpectedPlatform: runtime.GOOS, ExpectedArchitecture: runtime.GOARCH,
			MaxArtifactBytes: config.Upgrade.MaxArtifactBytes, ControlKeys: controlKeys, EdgeKeys: edgeKeys,
		},
	})
	if err != nil {
		return nil, fmt.Errorf("configure upgrade runtime: %w", err)
	}
	return runtime, nil
}

type upgradeReceiptProbe struct {
	nativeRuntime func() error
	installer     updater.Installer
	deployment    upgradeConfigPointers
	runVersion    func(context.Context, string, ...string) ([]byte, error)
}

func (probe upgradeReceiptProbe) Check(ctx context.Context, expected updater.ActivationReceipt, command []string) error {
	if ctx == nil || probe.installer == nil || probe.runVersion == nil || len(command) != 2 ||
		command[0] != "{artifact}" || command[1] != "--version" {
		return updater.ErrHealth
	}
	current, err := probe.installer.Current(ctx)
	if err != nil || current != expected {
		return updater.ErrHealth
	}
	// A native node must run the OpenResty/Lua runtime of this release
	// (node-runtime-upgrade); the status error carries its code.
	if probe.nativeRuntime != nil {
		if err := probe.nativeRuntime(); err != nil {
			return err
		}
	}
	output, err := probe.runVersion(ctx, currentUpgradeArtifactPath(), "--version")
	if err != nil || !validUpgradeVersionOutput(output, expected.CurrentVersion) {
		return updater.ErrHealth
	}
	return nil
}

func currentUpgradeArtifactPath() string {
	return filepath.Join(helper.ProductionReleaseRoot, "current", "edge-agent")
}

func runUpgradeVersion(ctx context.Context, executable string, arguments ...string) ([]byte, error) {
	if ctx == nil || executable != currentUpgradeArtifactPath() || len(arguments) != 1 || arguments[0] != "--version" {
		return nil, updater.ErrHealth
	}
	return exec.CommandContext(ctx, executable, arguments...).CombinedOutput()
}

func validUpgradeVersionOutput(output []byte, expectedVersion string) bool {
	if expectedVersion == "" || len(output) < 2 || output[len(output)-1] != '\n' ||
		bytes.Count(output, []byte{'\n'}) != 1 || bytes.Contains(output[:len(output)-1], []byte{'\r'}) {
		return false
	}
	var value struct {
		Event        string `json:"event"`
		AgentVersion string `json:"agent_version"`
	}
	decoder := json.NewDecoder(bytes.NewReader(output[:len(output)-1]))
	if err := decoder.Decode(&value); err != nil {
		return false
	}
	if err := decoder.Decode(&struct{}{}); !errors.Is(err, io.EOF) {
		return false
	}
	return value.Event == "version" && value.AgentVersion == expectedVersion
}

func (probe upgradeReceiptProbe) Evidence(ctx context.Context, expected updater.ActivationReceipt,
	command []string) (updater.ConfigProbeEvidence, error) {
	if err := probe.Check(ctx, expected, command); err != nil || probe.deployment == nil {
		return updater.ConfigProbeEvidence{}, updater.ErrHealth
	}
	pointers, err := probe.deployment.Pointers()
	if err != nil || pointers.CurrentDigest == "" {
		return updater.ConfigProbeEvidence{}, updater.ErrHealth
	}
	lastKnownGood := pointers.PreviousDigest
	if lastKnownGood == "" {
		lastKnownGood = pointers.CurrentDigest
	}
	return updater.ConfigProbeEvidence{ActiveConfigSHA256: pointers.CurrentDigest,
		LastKnownGoodConfigSHA256: lastKnownGood}, nil
}

func assembleDiskGuard(config fileConfig) (*diskguard.Guard, error) {
	if !config.DiskGuard.Enabled {
		return nil, nil
	}
	guardConfig, err := config.diskGuardConfig()
	if err != nil {
		return nil, err
	}
	guard, err := diskguard.New(guardConfig, diskguard.Options{})
	if err != nil {
		return nil, fmt.Errorf("configure disk guard: %w", err)
	}
	return guard, nil
}

func assembleLogDiskGuard(config fileConfig) (*logdiskguard.Guard, error) {
	guardConfig, err := config.logDiskGuardConfig()
	if err != nil {
		return nil, err
	}
	guard, err := logdiskguard.New(guardConfig, logdiskguard.Options{})
	if err != nil {
		return nil, fmt.Errorf("configure log disk guard: %w", err)
	}
	return guard, nil
}

func (daemon *daemonClient) Run(ctx context.Context) error {
	if daemon == nil || daemon.client == nil {
		return errors.New("gateway client is required")
	}
	if !daemon.runMu.TryLock() {
		return errDaemonAlreadyRunning
	}
	defer daemon.runMu.Unlock()
	if daemon.endpointProbe != nil {
		probeContext, cancelProbe := context.WithCancel(ctx)
		defer cancelProbe()
		go daemon.endpointProbe(probeContext)
	}
	if daemon.certificate != nil {
		if _, err := daemon.certificate.Recover(ctx); err != nil {
			return fmt.Errorf("recover certificate runtime: %w", err)
		}
	}
	if daemon.deployment != nil {
		if err := daemon.deployment.Recover(ctx); err != nil {
			return fmt.Errorf("recover deployment runtime: %w", err)
		}
	}
	if daemon.certificateDeployment != nil {
		if err := daemon.certificateDeployment.RecoverCertificateVersionReferences(ctx); err != nil {
			return fmt.Errorf("recover certificate deployment references: %w", err)
		}
	}
	if daemon.drain != nil {
		if err := daemon.drain.Recover(ctx); err != nil {
			return fmt.Errorf("recover drain runtime: %w", err)
		}
	}
	if daemon.dynamicRouting != nil {
		if err := daemon.dynamicRouting.Recover(ctx); err != nil {
			return fmt.Errorf("recover dynamic routing runtime: %w", err)
		}
	}
	// node-runtime-upgrade: move the adopted HTTP and L4 masters (the L4
	// one was resumed during assembly) to the runtime prepareNativeRuntime
	// switched to, or put the previous one back.
	var masters []nativeruntime.Master
	if upgrader, ok := daemon.dynamicRouting.(nativeruntime.Master); ok {
		masters = append(masters, upgrader)
	}
	if daemon.l4OpenResty != nil {
		masters = append(masters, daemon.l4OpenResty)
	}
	commitNativeRuntime(ctx, masters...)
	if daemon.installationBan != nil {
		// a node stopped before the restart stops again before it serves
		if err := restoreInstallationBan(ctx, daemon.installationBan); err != nil {
			return fmt.Errorf("restore installation ban runtime: %w", err)
		}
		go runInstallationBanTicks(ctx, daemon.installationBan)
	}
	if daemon.diskGuard == nil && daemon.logDiskGuard == nil && daemon.telemetry == nil && daemon.drain == nil && daemon.firewallExpiry == nil &&
		daemon.l4KernelBans == nil && daemon.emptyConnections == nil && daemon.rateBans == nil && daemon.xdpWatch == nil && daemon.challengeVerifier == nil && daemon.runtimeStatus == nil &&
		daemon.dynamicRouting == nil {
		return daemon.client.Run(ctx)
	}

	backgroundContext, cancelBackground := context.WithCancel(ctx)
	var background sync.WaitGroup
	challengeFailure := make(chan error, 1)
	if daemon.challengeVerifier != nil {
		background.Add(1)
		go func() {
			defer background.Done()
			err := daemon.challengeVerifier.Run(backgroundContext)
			if backgroundContext.Err() == nil {
				challengeFailure <- err
				cancelBackground()
			}
		}()
	}
	if daemon.diskGuard != nil {
		background.Add(1)
		daemon.setDiskGuardStatus(true, false)
		go func() {
			defer background.Done()
			err := daemon.diskGuard.Run(backgroundContext)
			stoppedBeforeCancellation := backgroundContext.Err() == nil
			failed := stoppedBeforeCancellation || (err != nil && !errors.Is(err, backgroundContext.Err()))
			daemon.setDiskGuardStatus(false, failed)
		}()
	}
	if daemon.logDiskGuard != nil {
		background.Add(1)
		daemon.setLogDiskGuardStatus(true, false)
		go func() {
			defer background.Done()
			err := daemon.logDiskGuard.Run(backgroundContext)
			stoppedBeforeCancellation := backgroundContext.Err() == nil
			failed := stoppedBeforeCancellation || (err != nil && !errors.Is(err, backgroundContext.Err()))
			daemon.setLogDiskGuardStatus(false, failed)
		}()
	}
	if daemon.telemetry != nil {
		background.Add(1)
		daemon.setTelemetryStatus(true, false)
		go func() {
			defer background.Done()
			err := daemon.telemetry.Run(backgroundContext)
			stoppedBeforeCancellation := backgroundContext.Err() == nil
			failed := stoppedBeforeCancellation || (err != nil && !errors.Is(err, backgroundContext.Err()))
			daemon.setTelemetryStatus(false, failed)
		}()
	}
	if daemon.drain != nil {
		background.Add(1)
		daemon.setDrainStatus(true, false)
		go func() {
			defer background.Done()
			err := daemon.drain.Run(backgroundContext)
			stoppedBeforeCancellation := backgroundContext.Err() == nil
			failed := stoppedBeforeCancellation || (err != nil && !errors.Is(err, backgroundContext.Err()))
			daemon.setDrainStatus(false, failed)
		}()
	}
	if daemon.firewallExpiry != nil {
		background.Add(1)
		go func() {
			defer background.Done()
			_ = daemon.firewallExpiry.Run(backgroundContext)
		}()
	}
	if daemon.runtimeStatus != nil {
		background.Add(1)
		go func() {
			defer background.Done()
			_ = daemon.runtimeStatus.Run(backgroundContext)
		}()
	}
	if daemon.dynamicRouting != nil {
		background.Add(1)
		go func() {
			defer background.Done()
			_ = daemon.dynamicRouting.Run(backgroundContext, dynroute.DefaultIntervals)
		}()
	}
	if daemon.l4KernelBans != nil {
		background.Add(1)
		go func() {
			defer background.Done()
			_ = daemon.l4KernelBans.Run(backgroundContext)
		}()
	}
	if daemon.emptyConnections != nil {
		background.Add(1)
		go func() {
			defer background.Done()
			_ = daemon.emptyConnections.Run(backgroundContext)
		}()
	}
	if daemon.rateBans != nil {
		background.Add(1)
		go func() {
			defer background.Done()
			_ = daemon.rateBans.Run(backgroundContext)
		}()
	}
	if daemon.xdpWatch != nil {
		background.Add(1)
		go func() {
			defer background.Done()
			_ = daemon.xdpWatch.Run(backgroundContext)
		}()
	}
	clientErr := daemon.client.Run(backgroundContext)
	cancelBackground()
	background.Wait()
	select {
	case err := <-challengeFailure:
		return fmt.Errorf("external challenge verifier stopped: %w", err)
	default:
	}
	return clientErr
}

func (daemon *daemonClient) Close() error {
	if daemon == nil {
		return nil
	}
	daemon.closeOnce.Do(func() {
		var drainErr error
		if daemon.drain != nil {
			drainErr = daemon.drain.Close()
		}
		var clientErr error
		if closer, ok := daemon.client.(clientCloser); ok {
			clientErr = closer.Close()
		}
		daemon.l4TOA.Close()
		daemon.xdpFilter.Close()
		daemon.closeErr = errors.Join(drainErr, clientErr)
	})
	return daemon.closeErr
}

func (daemon *daemonClient) DiskGuardSnapshot() diskGuardDaemonSnapshot {
	if daemon == nil || daemon.diskGuard == nil {
		return diskGuardDaemonSnapshot{}
	}
	daemon.statusMu.RLock()
	snapshot := diskGuardDaemonSnapshot{
		Enabled: true, Running: daemon.running, RunFailed: daemon.runFailed,
	}
	daemon.statusMu.RUnlock()
	snapshot.Metrics = daemon.diskGuard.Snapshot()
	return snapshot
}

func (daemon *daemonClient) setDiskGuardStatus(running, runFailed bool) {
	daemon.statusMu.Lock()
	daemon.running = running
	daemon.runFailed = runFailed
	daemon.statusMu.Unlock()
}

func (daemon *daemonClient) LogDiskGuardSnapshot() logDiskGuardDaemonSnapshot {
	if daemon == nil || daemon.logDiskGuard == nil {
		return logDiskGuardDaemonSnapshot{}
	}
	daemon.statusMu.RLock()
	snapshot := logDiskGuardDaemonSnapshot{
		Enabled: true, Running: daemon.logDiskGuardRunning, RunFailed: daemon.logDiskGuardRunFailed,
	}
	daemon.statusMu.RUnlock()
	snapshot.Metrics = daemon.logDiskGuard.Snapshot()
	return snapshot
}

func (daemon *daemonClient) setLogDiskGuardStatus(running, runFailed bool) {
	daemon.statusMu.Lock()
	daemon.logDiskGuardRunning = running
	daemon.logDiskGuardRunFailed = runFailed
	daemon.statusMu.Unlock()
}

func (daemon *daemonClient) TelemetrySnapshot() telemetryDaemonSnapshot {
	if daemon == nil || daemon.telemetry == nil {
		return telemetryDaemonSnapshot{}
	}
	worker := daemon.telemetry.Snapshot()
	daemon.statusMu.RLock()
	running := daemon.telemetryRunning
	runFailed := daemon.telemetryRunFailed
	daemon.statusMu.RUnlock()
	result := telemetryDaemonSnapshot{
		Enabled: true, Running: running, Degraded: runFailed || worker.Degraded,
		LastErrorCode: worker.LastErrorCode, AcceptedSequence: worker.AcceptedSequence,
	}
	if runFailed {
		result.LastErrorCode = "TELEMETRY_WORKER_EXITED"
	}
	return result
}

func (daemon *daemonClient) setTelemetryStatus(running, runFailed bool) {
	daemon.statusMu.Lock()
	daemon.telemetryRunning = running
	daemon.telemetryRunFailed = runFailed
	daemon.statusMu.Unlock()
}

func (daemon *daemonClient) DrainRuntimeSnapshot() drainRuntimeSnapshot {
	if daemon == nil || daemon.drain == nil {
		return drainRuntimeSnapshot{}
	}
	snapshot := daemon.drain.Snapshot()
	daemon.statusMu.RLock()
	snapshot.Running = daemon.drainRunning
	snapshot.RunFailed = daemon.drainRunFailed
	daemon.statusMu.RUnlock()
	if snapshot.RunFailed {
		snapshot.Degraded = true
		snapshot.LastErrorCode = "DRAIN_RUNTIME_RUNNER_EXITED"
	}
	return snapshot
}

func (daemon *daemonClient) HandleDrainPlan(ctx context.Context, plan drainruntime.Plan) (drainruntime.Result, error) {
	if daemon == nil || daemon.drain == nil {
		return drainruntime.Result{}, errors.New("drain runtime is disabled")
	}
	return daemon.drain.HandleDrainPlan(ctx, plan)
}

func (daemon *daemonClient) setDrainStatus(running, runFailed bool) {
	daemon.statusMu.Lock()
	daemon.drainRunning = running
	daemon.drainRunFailed = runFailed
	daemon.statusMu.Unlock()
}

func newDDoSManager(ctx context.Context, stateRoot string, findBinary func(string) (string, error)) (*ddos.Manager, error) {
	binary, err := findBinary("nft")
	if err != nil {
		return nil, err
	}
	runner, err := ddos.NewSystemRunner(binary)
	if err != nil {
		return nil, err
	}
	return ddos.NewManager(ctx, runner, stateRoot)
}

// telemetrySink fills security and access events' country and carrier from
// the node's IP intelligence library before they are spooled.
func telemetrySink(spool eventspool.BatchSink, deploymentRoot string) eventspool.BatchSink {
	if enricher := ipintel.NewEnricher(spool, filepath.Join(deploymentRoot, ipIntelLibraryDir), time.Now); enricher != nil {
		return enricher
	}
	return spool
}

// ddosDropMetrics reads the DDoS table's drop counters for node telemetry
// (none when the table is absent or cannot be listed).
func ddosDropMetrics(manager *ddos.Manager) func(context.Context) []nodemonitoring.DDoSDropMetrics {
	return func(ctx context.Context) []nodemonitoring.DDoSDropMetrics {
		counters, err := manager.DropCounters(ctx)
		if err != nil {
			return nil
		}
		drops := make([]nodemonitoring.DDoSDropMetrics, 0, len(counters))
		for _, counter := range counters {
			drops = append(drops, nodemonitoring.DDoSDropMetrics{Kind: counter.Kind, Packets: counter.Packets, Bytes: counter.Bytes})
		}
		return drops
	}
}

func selectFirewallRuntime(
	ctx context.Context,
	stateRoot string,
	findBinary func(string) (string, error),
	build func(string, string) (firewallRuntime, error),
) (firewallRuntime, bool) {
	if ctx == nil || findBinary == nil || build == nil {
		return nil, false
	}
	binary, err := findBinary("nft")
	if err != nil {
		return nil, false
	}
	runtime, err := build(stateRoot, binary)
	if err != nil || runtime == nil {
		return nil, false
	}
	if err := runtime.Probe(ctx); err != nil {
		return nil, false
	}
	return runtime, true
}

const firewallExpiryInterval = time.Minute

type firewallExpiryScheduler struct {
	runtime firewallRuntime
	now     func() time.Time
	wait    func(context.Context, time.Duration) error
}

func newFirewallExpiryScheduler(runtime firewallRuntime, now func() time.Time, wait func(context.Context, time.Duration) error) firewallExpiryRunner {
	if runtime == nil || now == nil {
		return nil
	}
	if wait == nil {
		wait = waitFirewallExpiryInterval
	}
	return &firewallExpiryScheduler{runtime: runtime, now: now, wait: wait}
}

func (scheduler *firewallExpiryScheduler) Run(ctx context.Context) error {
	for {
		bucket := scheduler.now().UTC().Truncate(firewallExpiryInterval).Unix()
		identity := strconv.FormatInt(bucket, 10)
		_, _ = scheduler.runtime.Expire(ctx, "ttl-expire-"+identity, "ttl-runtime-"+identity)
		if err := ctx.Err(); err != nil {
			return err
		}
		if err := scheduler.wait(ctx, firewallExpiryInterval); err != nil {
			return err
		}
	}
}

func waitFirewallExpiryInterval(ctx context.Context, interval time.Duration) error {
	timer := time.NewTimer(interval)
	defer timer.Stop()
	select {
	case <-timer.C:
		return nil
	case <-ctx.Done():
		return ctx.Err()
	}
}

func agentCapabilitiesWithFirewall(openRestyVersion string, ready bool, statuses ...securityRuntimeStatus) *agentv1.AgentCapabilities {
	capabilities := agentCapabilities(openRestyVersion, statuses...)
	if !ready {
		return capabilities
	}
	for _, feature := range []agentv1.CapabilityName{
		agentv1.CapabilityName_CAPABILITY_NAME_NFTABLES,
		agentv1.CapabilityName_CAPABILITY_NAME_FIREWALL_CONTROL,
	} {
		capabilities.Features = append(capabilities.Features, &agentv1.Capability{Name: feature, ApiVersion: 1})
	}
	return capabilities
}

// declareSiteRuntimeVersion sets (or adds) the SITE_RUNTIME capability.
func declareSiteRuntimeVersion(capabilities *agentv1.AgentCapabilities, version uint32) {
	for _, capability := range capabilities.Features {
		if capability != nil && capability.Name == agentv1.CapabilityName_CAPABILITY_NAME_SITE_RUNTIME {
			capability.ApiVersion = version
			return
		}
	}
	capabilities.Features = append(capabilities.Features, &agentv1.Capability{
		Name: agentv1.CapabilityName_CAPABILITY_NAME_SITE_RUNTIME, ApiVersion: version,
	})
}

func agentCapabilities(openRestyVersion string, statuses ...securityRuntimeStatus) *agentv1.AgentCapabilities {
	features := []agentv1.CapabilityName{
		agentv1.CapabilityName_CAPABILITY_NAME_HTTP_1_1,
		agentv1.CapabilityName_CAPABILITY_NAME_HTTP_2,
		agentv1.CapabilityName_CAPABILITY_NAME_WEBSOCKET,
		agentv1.CapabilityName_CAPABILITY_NAME_TCP_PROXY,
		agentv1.CapabilityName_CAPABILITY_NAME_UDP_PROXY,
		agentv1.CapabilityName_CAPABILITY_NAME_PROXY_PROTOCOL,
		agentv1.CapabilityName_CAPABILITY_NAME_IPV4,
		agentv1.CapabilityName_CAPABILITY_NAME_IPV6,
		agentv1.CapabilityName_CAPABILITY_NAME_ATOMIC_RELEASE,
		agentv1.CapabilityName_CAPABILITY_NAME_CONFIG_PRECHECK,
		agentv1.CapabilityName_CAPABILITY_NAME_CACHE_CONTROL,
		// The agent gates the optional OWASP CRS engine (waf_crs_module_v1);
		// whether the extension is installed is reported per deployment.
		agentv1.CapabilityName_CAPABILITY_NAME_WAF_CRS_MODULE,
	}
	if len(statuses) == 1 && statuses[0].WAFReady {
		features = append(features, agentv1.CapabilityName_CAPABILITY_NAME_WAF)
	}
	if len(statuses) == 1 && statuses[0].CCReady {
		features = append(features, agentv1.CapabilityName_CAPABILITY_NAME_CC,
			// CC v7 count keys and JA4 match (same compiler and engine).
			agentv1.CapabilityName_CAPABILITY_NAME_CC_MATCH_KEYS)
	}
	capabilities := &agentv1.AgentCapabilities{
		AgentVersion: agentVersion, BuildId: buildID,
		OperatingSystem: runtime.GOOS, Architecture: runtime.GOARCH,
		OpenrestyVersion: openRestyVersion,
		Features:         make([]*agentv1.Capability, 0, len(features)),
	}
	for _, feature := range features {
		version := uint32(1)
		if feature == agentv1.CapabilityName_CAPABILITY_NAME_CC {
			version = ccAPIVersion
		}
		if feature == agentv1.CapabilityName_CAPABILITY_NAME_CC_MATCH_KEYS {
			version = edgeconfig.CCMatchKeysAPIVersion
		}
		if feature == agentv1.CapabilityName_CAPABILITY_NAME_WAF {
			// v2: challenge / ban actions, auto block, observe mode; v3: the
			// managed WAF's c3 context (ADR 0011 RI-03); v4: content_type /
			// http_version conditions and IP lists.
			version = edgeconfig.WAFNodeAPIVersion
		}
		if feature == agentv1.CapabilityName_CAPABILITY_NAME_TCP_PROXY || feature == agentv1.CapabilityName_CAPABILITY_NAME_UDP_PROXY {
			// v3 additional listeners; v4 TLS passthrough by SNI and shared ports;
			// v5 drain_max_ms (old sessions drain after a reload instead of
			// being ended after drain_timeout_ms); v6 new_conn_rate (per-client
			// new connection rate, docs/architecture/l4-v6-fields.md); v7
			// session_log (l4_session_v2 log, live TCP session registry); v8
			// toa (the field; L4_TOA says whether the node can act on it); v9
			// port_end (listen port ranges) and follow_port (origin on the
			// client's port); v10 guard_rules (L4 guard rules); v11 origins (weighted
			// origin list with down), ip_hash and listen_ipv6.
			version = l4StreamAPIVersion
		}
		capabilities.Features = append(capabilities.Features, &agentv1.Capability{Name: feature, ApiVersion: version})
	}
	return capabilities
}

// l4StreamAPIVersion is the tcp/udp API this agent's L4 runtime implements,
// declared to the gateway and to the site runtime v2 validator alike
// (docs/architecture/l4-v6-fields.md; v10 guard_rules, v11 origins/ip_hash/listen_ipv6,
// v12 streams without a website: no site_id in the spec or its geo).
const l4StreamAPIVersion uint32 = 12

// ccAPIVersion is the CC API this agent's ccv2 compiler and engine run, for
// both the deployment and the site runtime v2 paths: v3 proof-of-work
// challenges with bound, rotated pass cookies; v4 counting keys (count_by:
// client network, host, URI, TLS fingerprint); v5 the auto switch (自动切换,
// ccv2/engine.lua auto_switch); v6 trusted crawlers (rDNS verified), the
// pass cookie domain, client IP lists and header matches; v7
// (with CAPABILITY_NAME_CC_MATCH_KEYS v1) counting by User-Agent, Referer, a
// header, cookie or query argument and JA4 matches; v8 auto
// switch region / node overrides (the engine picks the one naming this
// node). The control plane requires v3 .. v8 only for policies using them
// (edgeconfig.CCV2PolicyAPIVersion).
const ccAPIVersion uint32 = 8

func newHealthProbe(healthURL string, timeout time.Duration) deployment.HealthProbe {
	transport := &http.Transport{
		Proxy:                 nil,
		DialContext:           (&net.Dialer{Timeout: timeout}).DialContext,
		ResponseHeaderTimeout: timeout,
	}
	client := &http.Client{
		Transport: transport,
		Timeout:   timeout,
		CheckRedirect: func(*http.Request, []*http.Request) error {
			return http.ErrUseLastResponse
		},
	}
	return func(ctx context.Context, versionID string) error {
		request, err := http.NewRequestWithContext(ctx, http.MethodGet, healthURL, nil)
		if err != nil {
			return errors.New("build OpenResty health request")
		}
		response, err := client.Do(request)
		if err != nil {
			return errors.New("OpenResty health request failed")
		}
		defer response.Body.Close()
		body, err := io.ReadAll(io.LimitReader(response.Body, 513))
		if err != nil || len(body) > 512 {
			return errors.New("OpenResty health response is invalid")
		}
		if response.StatusCode != http.StatusOK || response.Header.Get("X-CDNCA-Config-Version") != versionID || string(body) != "ok:"+versionID+"\n" {
			return errors.New("OpenResty health response does not match the active version")
		}
		return nil
	}
}

func runClient(ctx context.Context, client clientRunner) error {
	if client == nil {
		return errors.New("gateway client is required")
	}
	runErr := client.Run(ctx)
	var result error
	if ctx.Err() != nil && errors.Is(runErr, ctx.Err()) {
		result = nil
	} else if runErr == nil {
		result = errors.New("gateway client stopped unexpectedly")
	} else {
		result = fmt.Errorf("gateway client stopped: %w", runErr)
	}
	if closer, ok := client.(clientCloser); ok {
		result = errors.Join(result, closer.Close())
	}
	return result
}

func safeLogError(err error) string {
	if err == nil {
		return "unknown failure"
	}
	value := strings.ReplaceAll(err.Error(), "\n", " ")
	value = strings.ReplaceAll(value, "\r", " ")
	if len(value) > 512 {
		value = value[:512]
	}
	return value
}
