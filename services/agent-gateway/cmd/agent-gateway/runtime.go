package main

import (
	"context"
	"crypto/tls"
	"fmt"
	"log"
	"net"
	"net/http"
	"os"
	"strings"
	"sync"
	"time"

	commonv1 "github.com/cdnca/cdnca/proto/gen/go/common/v1"
	controlv1 "github.com/cdnca/cdnca/proto/gen/go/controlinternal/v1"
	gateway "github.com/cdnca/cdnca/services/agent-gateway"
	"github.com/google/uuid"
	"github.com/nats-io/nats.go"
	"github.com/redis/go-redis/v9"
	"google.golang.org/grpc"
	"google.golang.org/grpc/credentials"
	healthv1 "google.golang.org/grpc/health/grpc_health_v1"
	"google.golang.org/protobuf/types/known/timestamppb"
)

type stageError struct {
	stage string
	err   error
}

func (e stageError) Error() string { return e.stage }
func (e stageError) Unwrap() error { return e.err }

type runtime struct {
	listenerMu             sync.RWMutex
	enrollmentListener     *readyListener
	agentListener          *readyListener
	candidateAgentListener *readyListener
	// transitionServeErrors carries the unplanned stop of an agent listener a
	// port transition started, so the runtime fails closed instead of running
	// on without an Agent listener after the old one was finalized away.
	transitionServeErrors   chan serveResult
	healthListener          net.Listener
	servers                 *gateway.Servers
	tunnels                 *gateway.TunnelRouter
	portManager             *gateway.PortTransitionManager
	healthServer            *http.Server
	liveness                *livenessState
	controlConnection       *grpc.ClientConn
	natsConnection          *nats.Conn
	telemetryNATSConnection *nats.Conn
	redisClient             *redis.Client
	cancel                  context.CancelFunc
	shutdownTimeout         time.Duration
	// signerTrustErr records why edge signer trust delivery stays disabled; it never fails startup.
	signerTrustErr error
	// installationBanErr records why installation ban delivery stays disabled; it never fails startup.
	installationBanErr error
	// securityBanErr records why security ban list delivery stays disabled; it never fails startup.
	securityBanErr error
	// siteDropErr records why site drop list delivery stays disabled; it never fails startup.
	siteDropErr error
	// gatewayAddressErr records why Gateway address change delivery stays disabled.
	gatewayAddressErr error
	// sched302Err records why HTTP 302 scheduling tables stay undelivered; it never fails startup.
	sched302Err error
	// autoDefenseErr records why the automatic defense channel stays disabled; it never fails startup.
	autoDefenseErr error
	// marketProbesErr records why market probe relay stays disabled; it never fails startup.
	marketProbesErr error
	// l4LiveErr records why the L4 live connection relay stays disabled.
	l4LiveErr error
}

func buildRuntime(ctx context.Context, c config) (_ *runtime, returnedError error) {
	if ctx == nil {
		return nil, fmt.Errorf("runtime context is required")
	}
	startupContext, cancelStartup := context.WithTimeout(ctx, c.startupTimeout)
	defer cancelStartup()
	runtimeContext, cancelRuntime := context.WithCancel(context.Background())
	r := &runtime{cancel: cancelRuntime, shutdownTimeout: c.shutdownTimeout, transitionServeErrors: make(chan serveResult, 1)}
	defer func() {
		if returnedError != nil {
			r.close()
		}
	}()

	enrollmentTLS, agentTLS, err := loadListenerTLS(c)
	if err != nil {
		return nil, err
	}
	controlTLS, err := loadControlTLS(c)
	if err != nil {
		return nil, err
	}
	// A bound Gateway renews its own certificates (GW-08): serve them through
	// callbacks so a renewal never restarts listeners or the control link.
	var renewable []*reloadableCertificate
	var serverCertificate func(*tls.ClientHelloInfo) (*tls.Certificate, error)
	if boundGateway(c) {
		server := newReloadableCertificate(agentTLS.Certificates[0], c.serverCertificateFile, "server")
		client := newReloadableCertificate(controlTLS.Certificates[0], c.controlCertificateFile, "client")
		serverCertificate = server.serverCertificate
		for _, listenerTLS := range []*tls.Config{enrollmentTLS, agentTLS} {
			listenerTLS.Certificates, listenerTLS.GetCertificate = nil, server.serverCertificate
		}
		controlTLS.Certificates, controlTLS.GetClientCertificate = nil, client.clientCertificate
		renewable = []*reloadableCertificate{client, server}
	}
	if err := r.bindListeners(c); err != nil {
		return nil, err
	}

	redisOptions, err := redis.ParseURL(c.redisURL)
	if err != nil {
		return nil, stageError{stage: "configure Redis", err: err}
	}
	redisOptions.MaxRetries = 0
	redisOptions.DialTimeout = c.startupTimeout
	redisOptions.ReadTimeout = 5 * time.Second
	redisOptions.WriteTimeout = 5 * time.Second
	redisOptions.ContextTimeoutEnabled = true
	if dependency := dependencyTLS(c.redisURL, controlTLS); dependency != nil && boundGateway(c) {
		redisOptions.TLSConfig = dependency
	}
	r.redisClient = redis.NewClient(redisOptions)
	if err := r.redisClient.Ping(startupContext).Err(); err != nil {
		return nil, stageError{stage: "Redis readiness check failed", err: err}
	}

	natsOptions := []nats.Option{
		nats.Name("cdnca-agent-gateway"),
		nats.Timeout(c.startupTimeout),
		nats.MaxReconnects(-1),
		nats.ReconnectWait(time.Second),
		nats.DrainTimeout(c.shutdownTimeout),
	}
	if dependency := dependencyTLS(c.natsURL, controlTLS); dependency != nil && boundGateway(c) {
		natsOptions = append(natsOptions, nats.Secure(dependency))
	}
	r.natsConnection, err = nats.Connect(c.natsURL, natsOptions...)
	if err != nil {
		return nil, stageError{stage: "NATS connection failed", err: err}
	}
	natsConfig := gateway.DefaultNATSCommandBusConfig()
	if err := verifyJetStream(startupContext, r.natsConnection, natsConfig); err != nil {
		return nil, stageError{stage: "JetStream readiness check failed", err: err}
	}
	telemetryNATSOptions := telemetryConnectionOptions(c)
	if dependency := dependencyTLS(c.telemetryNATSURL, controlTLS); dependency != nil && boundGateway(c) && !strings.HasPrefix(c.telemetryNATSURL, "tls://") {
		telemetryNATSOptions = append(telemetryNATSOptions, nats.Secure(dependency))
	}
	r.telemetryNATSConnection, err = nats.Connect(c.telemetryNATSURL, telemetryNATSOptions...)
	if err != nil {
		return nil, stageError{stage: "Telemetry NATS connection failed", err: err}
	}

	r.controlConnection, err = grpc.DialContext(
		startupContext,
		c.controlAddress,
		grpc.WithTransportCredentials(credentials.NewTLS(controlTLS)),
		grpc.WithBlock(),
		grpc.WithReturnConnectionError(),
	)
	if err != nil {
		return nil, stageError{stage: "ControlInternal mTLS connection failed", err: err}
	}
	if err := verifyControlHealth(startupContext, r.controlConnection); err != nil {
		return nil, stageError{stage: "ControlInternal health check failed", err: err}
	}
	// The installation ID is the tunnel token audience (ADR 0013 §4.6); it
	// comes from the control plane, so a Gateway's own instance ID (its
	// gateway_id once bound) never has to equal it.
	tunnelAudience, err := reportGatewayReady(startupContext, controlv1.NewControlInternalServiceClient(r.controlConnection), c.instanceID, c.version)
	if err != nil {
		return nil, stageError{stage: "report Gateway ready to ControlInternal", err: err}
	}

	sessions, err := gateway.NewSessionCoordinator(runtimeContext, gateway.SessionCoordinatorConfig{
		Mode:        gateway.SessionCoordinatorModeDistributed,
		RedisClient: r.redisClient,
		Redis: gateway.RedisSessionCoordinatorConfig{
			GatewayInstanceID:    c.instanceID,
			KeyPrefix:            "cdnca:agent-gateway",
			LeaseTTL:             45 * time.Second,
			RenewInterval:        10 * time.Second,
			OperationTimeout:     5 * time.Second,
			AcquireTimeout:       10 * time.Second,
			AcquireRetryInterval: 100 * time.Millisecond,
		},
	})
	if err != nil {
		return nil, stageError{stage: "configure distributed sessions", err: err}
	}
	telemetrySessions, err := gateway.NewSessionCoordinator(runtimeContext, gateway.SessionCoordinatorConfig{
		Mode:        gateway.SessionCoordinatorModeDistributed,
		RedisClient: r.redisClient,
		Redis: gateway.RedisSessionCoordinatorConfig{
			GatewayInstanceID:    c.instanceID,
			KeyPrefix:            "cdnca:agent-gateway:telemetry",
			LeaseTTL:             45 * time.Second,
			RenewInterval:        10 * time.Second,
			OperationTimeout:     5 * time.Second,
			AcquireTimeout:       10 * time.Second,
			AcquireRetryInterval: 100 * time.Millisecond,
		},
	})
	if err != nil {
		return nil, stageError{stage: "configure distributed telemetry sessions", err: err}
	}
	messageBus, err := gateway.NewNATSCommandBus(r.natsConnection, natsConfig)
	if err != nil {
		return nil, stageError{stage: "configure durable Agent messaging", err: err}
	}
	correlationHealth := messageBus.CorrelationHealth()
	cacheMessageBus, err := gateway.NewNATSCacheCommandBus(r.natsConnection, natsConfig)
	if err != nil {
		return nil, stageError{stage: "configure durable cache messaging", err: err}
	}
	upgradeMessageBus, err := gateway.NewNATSUpgradeCommandBus(r.natsConnection, natsConfig)
	if err != nil {
		return nil, stageError{stage: "configure durable upgrade messaging", err: err}
	}
	gatewayConfig := gateway.DefaultConfig()
	gatewayConfig.GatewayInstanceID = c.instanceID
	gatewayConfig.GatewayVersion = c.version
	service, err := gateway.NewWithCacheMessaging(
		gatewayConfig,
		gateway.GeneratedControlClient{Client: controlv1.NewControlInternalServiceClient(r.controlConnection)},
		sessions,
		messageBus,
		cacheMessageBus,
		messageBus,
	)
	if err != nil {
		return nil, stageError{stage: "configure Agent Gateway service", err: err}
	}
	if err := service.ConfigureUpgradeMessaging(upgradeMessageBus); err != nil {
		return nil, stageError{stage: "configure Agent upgrade messaging", err: err}
	}
	if err := service.ConfigureOverlayMessaging(messageBus); err != nil {
		return nil, stageError{stage: "configure ACME HTTP-01 overlay messaging", err: err}
	}
	if err := configureNodeMonitoring(service, r.natsConnection); err != nil {
		return nil, stageError{stage: "configure node monitoring messaging", err: err}
	}
	r.signerTrustErr = configureSignerTrust(startupContext, service, r.natsConnection)
	r.installationBanErr = configureInstallationBan(startupContext, service, r.natsConnection)
	r.securityBanErr = configureSecurityBans(startupContext, service, r.natsConnection)
	r.siteDropErr = configureSiteDrops(startupContext, service, r.natsConnection)
	r.gatewayAddressErr = configureGatewayAddressChanges(startupContext, service, r.natsConnection)
	r.sched302Err = configureSched302(startupContext, service, r.natsConnection)
	r.autoDefenseErr = configureAutoDefense(startupContext, service, r.natsConnection)
	r.marketProbesErr = configureMarketProbes(service, r.natsConnection)
	r.l4LiveErr = configureL4Live(service, r.natsConnection)
	// Same-port dual transport (ADR 0013 §4.2): both ports also serve the
	// WebSocket tunnel paths; direct gRPC (ALPN h2 only) is unchanged.
	tunnelNonces, err := gateway.NewRedisTunnelNonceStore(r.redisClient, "cdnca:agent-gateway")
	if err != nil {
		return nil, stageError{stage: "configure tunnel nonce store", err: err}
	}
	trustedProxies, err := loadTrustedProxies(c.trustedProxiesFile)
	if err != nil {
		return nil, stageError{stage: "load trusted CDN back-to-origin ranges", err: err}
	}
	// The Gateway management page publishes the trusted ranges and the node
	// endpoint list (GW-06/GW-07). The first poll happens before nodes are
	// served; a failure keeps the local list (control plane without a
	// Gateway registry answers FailedPrecondition) and the loop retries.
	nodeEndpoints := &gateway.NodeEndpoints{}
	if err := service.ConfigureNodeEndpoints(nodeEndpoints); err != nil {
		return nil, stageError{stage: "configure node endpoint list", err: err}
	}
	// Disabled on the management page (ADR 0013 §5.2): no new nodes, connected
	// ones are asked to migrate and closed 30 minutes later.
	drain := &gateway.GatewayDrain{}
	if err := service.ConfigureDrain(drain); err != nil {
		return nil, stageError{stage: "configure gateway drain", err: err}
	}
	settingsSync := gateway.SettingsSync{Client: controlv1.NewControlInternalServiceClient(r.controlConnection),
		InstanceID: c.instanceID, Proxies: trustedProxies, Endpoints: nodeEndpoints, Drain: drain}
	if err := settingsSync.Poll(startupContext); err != nil {
		log.Printf("gateway settings are not available yet, using the local trusted CDN ranges: %v", err)
	}
	go settingsSync.Run(runtimeContext, gateway.DefaultSettingsPollInterval, c.healthCheckTimeout, log.Printf)
	tunnelCertificate, err := loadTunnelCertificate(c)
	if err != nil {
		return nil, err
	}
	outerCertificate := serverCertificate
	if tunnelCertificate != nil {
		outerCertificate = func(*tls.ClientHelloInfo) (*tls.Certificate, error) { return tunnelCertificate, nil }
	}
	r.tunnels, err = gateway.NewTunnelRouter(gateway.TunnelRouterConfig{
		Certificate: firstCertificate(agentTLS), GetCertificate: outerCertificate, NodeCAs: agentTLS.ClientCAs,
		Audience: tunnelAudience, Nonces: tunnelNonces, RealIP: trustedProxies.RealIP,
	})
	if err != nil {
		return nil, stageError{stage: "configure gateway tunnels", err: err}
	}
	r.enrollmentListener = newReadyListener(r.tunnels.Listen(r.enrollmentListener.Listener, gateway.SharedListenerEnrollment))
	r.agentListener = newReadyListener(r.tunnels.Listen(r.agentListener.Listener, gateway.SharedListenerAgent))
	r.portManager = gateway.NewPortTransitionManager(r.agentListener, c.agentPublicEndpoint,
		func(ctx context.Context, address string) (net.Listener, error) {
			if err := ctx.Err(); err != nil {
				return nil, err
			}
			listener, err := net.Listen("tcp", address)
			if err != nil {
				return nil, err
			}
			// readyListener here so Rollback/Finalize/Close mark the very
			// listener Serve runs on as a planned close.
			return newReadyListener(r.tunnels.Listen(listener, gateway.SharedListenerAgent)), nil
		}, time.Now)
	if err := service.ConfigurePortTransitions(messageBus, r.portManager); err != nil {
		return nil, stageError{stage: "configure gateway port transitions", err: err}
	}
	telemetryConfig := gateway.DefaultTelemetryConfig()
	telemetryNATSConfig := gateway.DefaultNATSTelemetryPublisherConfig()
	telemetryNATSConfig.OperationTimeout = telemetryConfig.PublishTimeout
	telemetryPublisher, err := gateway.NewNATSTelemetryPublisher(r.telemetryNATSConnection, telemetryNATSConfig)
	if err != nil {
		return nil, stageError{stage: "configure telemetry publisher", err: err}
	}
	telemetryHealth := gateway.NewTelemetryHealth()
	if err := service.ConfigureTelemetry(telemetryConfig, telemetryPublisher, telemetrySessions, telemetryHealth); err != nil {
		return nil, stageError{stage: "configure telemetry transport", err: err}
	}
	r.servers, err = gateway.NewServers(service, enrollmentTLS, agentTLS)
	if err != nil {
		return nil, stageError{stage: "configure Agent Gateway listeners", err: err}
	}
	if err := r.portManager.ConfigureServe(func(listener net.Listener) error {
		ready, ok := listener.(*readyListener)
		if !ok {
			ready = newReadyListener(listener)
		}
		r.listenerMu.Lock()
		r.candidateAgentListener = ready
		r.listenerMu.Unlock()
		served := make(chan error, 1)
		go func() { served <- r.servers.MTLS.Serve(ready) }()
		deadline := time.NewTimer(c.healthCheckTimeout)
		defer deadline.Stop()
		ticker := time.NewTicker(time.Millisecond)
		defer ticker.Stop()
		for {
			select {
			case err := <-served:
				if err == nil {
					return fmt.Errorf("gateway port transition listener stopped before readiness")
				}
				return err
			case <-ticker.C:
				if ready.isReady() {
					go reportTransitionServeStop(served, ready, r.transitionServeErrors)
					return nil
				}
			case <-deadline.C:
				_ = ready.Close()
				return fmt.Errorf("gateway port transition listener readiness timed out")
			}
		}
	}); err != nil {
		return nil, stageError{stage: "configure gateway port transition listener", err: err}
	}
	if err := r.portManager.ConfigurePromote(func() {
		r.listenerMu.Lock()
		if r.candidateAgentListener != nil {
			r.agentListener = r.candidateAgentListener
			r.candidateAgentListener = nil
		}
		r.listenerMu.Unlock()
	}); err != nil {
		return nil, stageError{stage: "configure gateway port transition promotion", err: err}
	}
	r.liveness = &livenessState{}
	readiness := newRuntimeReadiness(
		listenerReadiness(r.enrollmentListener),
		r.agentListenerReadiness(),
		func(ctx context.Context) error { return verifyRedisHealth(ctx, r.redisClient) },
		func(ctx context.Context) error { return verifyNATSHealth(ctx, r.natsConnection, natsConfig) },
		telemetryPublisher.Check,
		func(ctx context.Context) error { return verifyControlHealth(ctx, r.controlConnection) },
	)
	healthHandler, err := newHealthComposition(
		r.liveness,
		readiness,
		telemetryHealth,
		correlationHealth,
		telemetryPublisher.Check,
		c.healthCheckTimeout,
	)
	if err != nil {
		return nil, stageError{stage: "configure correlation metrics", err: err}
	}
	r.healthServer = newHealthHTTPServer(healthHandler, c.healthCheckTimeout)
	if len(renewable) > 0 {
		go runCertificateRenewal(runtimeContext, controlv1.NewControlInternalServiceClient(r.controlConnection), c.instanceID,
			log.Printf, time.Now, renewable...)
	}
	return r, nil
}

func firstCertificate(config *tls.Config) tls.Certificate {
	if len(config.Certificates) == 0 {
		return tls.Certificate{}
	}
	return config.Certificates[0]
}

// loadTrustedProxies reads the trusted CDN ranges; no file = the shipped
// Cloudflare list (ADR 0013 §4.4).
func loadTrustedProxies(path string) (*gateway.TrustedProxies, error) {
	contents := gateway.DefaultTrustedProxies
	if path != "" {
		raw, err := readRegularFile(path, false)
		if err != nil {
			return nil, err
		}
		contents = string(raw)
	}
	ranges, err := gateway.ParseTrustedProxyRanges(contents)
	if err != nil {
		return nil, err
	}
	return gateway.NewTrustedProxies(ranges), nil
}

func telemetryConnectionOptions(c config) []nats.Option {
	options := []nats.Option{
		nats.Name("cdnca-agent-gateway-telemetry"),
		nats.Timeout(c.startupTimeout),
		nats.MaxReconnects(-1),
		nats.ReconnectWait(time.Second),
		nats.DrainTimeout(c.shutdownTimeout),
	}
	if strings.HasPrefix(c.telemetryNATSURL, "tls://") {
		options = append(options, nats.TLSHandshakeFirst())
		if caFile := strings.TrimSpace(os.Getenv("SSL_CERT_FILE")); caFile != "" {
			if _, err := os.Stat(caFile); err == nil {
				options = append(options, nats.RootCAs(caFile))
			}
		}
	}
	if c.telemetryNATSUser != "" {
		options = append(options, nats.UserInfo(c.telemetryNATSUser, c.telemetryNATSPassword))
	}
	return options
}

func (r *runtime) agentListenerReadiness() readinessCheck {
	return func(context.Context) error {
		if r == nil {
			return errRuntimeNotReady
		}
		r.listenerMu.RLock()
		listener := r.agentListener
		r.listenerMu.RUnlock()
		if listener == nil || !listener.isReady() {
			return errRuntimeNotReady
		}
		return nil
	}
}

func newHealthComposition(
	liveness *livenessState,
	readiness *runtimeReadiness,
	telemetry *gateway.TelemetryHealth,
	correlation *gateway.CorrelationHealth,
	check func(context.Context) error,
	timeout time.Duration,
) (http.Handler, error) {
	health := newHealthHandler(liveness, readiness, timeout)
	detail := newTelemetryHealthHandler(health, liveness, telemetry, correlation, check, timeout)
	return newCorrelationMetricsHandler(detail, correlation)
}

func configureNodeMonitoring(service *gateway.Gateway, connection *nats.Conn) error {
	if service == nil || connection == nil || connection.IsClosed() {
		return fmt.Errorf("node monitoring dependencies are required")
	}
	bus, err := gateway.NewNATSNodeMonitoringBus(connection, gateway.DefaultNATSNodeMonitoringBusConfig())
	if err != nil {
		return err
	}
	return service.ConfigureNodeMonitoring(bus)
}

// configureSignerTrust creates the edge signer trust streams and enables delivery. It is optional: without it
// Agents simply do not negotiate EDGE_SIGNER_TRUST.
func configureSignerTrust(ctx context.Context, service *gateway.Gateway, connection *nats.Conn) error {
	bus, err := gateway.NewNATSSignerTrustBus(ctx, connection, gateway.DefaultNATSSignerTrustBusConfig())
	if err != nil {
		return err
	}
	return service.ConfigureSignerTrust(bus)
}

// configureInstallationBan creates the installation ban streams (ADR 0014
// LIC-BAN-05) and enables delivery. Optional, like signer trust.
func configureInstallationBan(ctx context.Context, service *gateway.Gateway, connection *nats.Conn) error {
	bus, err := gateway.NewNATSInstallationBanBus(ctx, connection, gateway.DefaultNATSInstallationBanBusConfig())
	if err != nil {
		return err
	}
	return service.ConfigureInstallationBan(bus)
}

// configureSecurityBans creates the security ban list streams and
// enables delivery. Optional, like signer trust.
func configureSecurityBans(ctx context.Context, service *gateway.Gateway, connection *nats.Conn) error {
	bus, err := gateway.NewNATSSecurityBanBus(ctx, connection, gateway.DefaultNATSSecurityBanBusConfig())
	if err != nil {
		return err
	}
	return service.ConfigureSecurityBans(bus)
}

// configureSiteDrops creates the site drop streams (攻击自动升级 D 级) and
// enables delivery. Optional, like security bans.
func configureSiteDrops(ctx context.Context, service *gateway.Gateway, connection *nats.Conn) error {
	bus, err := gateway.NewNATSSiteDropBus(ctx, connection, gateway.DefaultNATSSiteDropBusConfig())
	if err != nil {
		return err
	}
	return service.ConfigureSiteDrops(bus)
}

// configureGatewayAddressChanges creates the address change streams
// and enables delivery. Optional, like site drops.
func configureGatewayAddressChanges(ctx context.Context, service *gateway.Gateway, connection *nats.Conn) error {
	bus, err := gateway.NewNATSGatewayAddressBus(ctx, connection, gateway.DefaultNATSGatewayAddressBusConfig())
	if err != nil {
		return err
	}
	return service.ConfigureGatewayAddressChanges(bus)
}

// configureSched302 creates the HTTP 302 scheduling table stream and enables
// delivery. Optional: without it Agents do not negotiate SCHED302.
func configureSched302(ctx context.Context, service *gateway.Gateway, connection *nats.Conn) error {
	bus, err := gateway.NewNATSSched302Bus(ctx, connection, 5*time.Second)
	if err != nil {
		return err
	}
	return service.ConfigureSched302(bus)
}

// configureAutoDefense creates the automatic defense streams (AD-07) and
// enables the channel. Optional: without it Agents do not negotiate AUTO_DEFENSE.
func configureAutoDefense(ctx context.Context, service *gateway.Gateway, connection *nats.Conn) error {
	bus, err := gateway.NewNATSAutoDefenseBus(ctx, connection, gateway.DefaultNATSAutoDefenseBusConfig())
	if err != nil {
		return err
	}
	return service.ConfigureAutoDefense(bus)
}

// configureMarketProbes enables the market probe relay. It is optional and needs no stream: without it Agents
// simply do not negotiate market probes.
func configureMarketProbes(service *gateway.Gateway, connection *nats.Conn) error {
	bus, err := gateway.NewNATSMarketProbeBus(connection)
	if err != nil {
		return err
	}
	return service.ConfigureMarketProbes(bus)
}

// configureL4Live enables the L4 live connection relay (实时连接); optional
// like market probes.
func configureL4Live(service *gateway.Gateway, connection *nats.Conn) error {
	bus, err := gateway.NewNATSL4LiveBus(connection)
	if err != nil {
		return err
	}
	return service.ConfigureL4Live(bus)
}

func (r *runtime) bindListeners(c config) error {
	enrollmentListener, err := net.Listen("tcp", c.enrollmentAddress)
	if err != nil {
		return stageError{stage: "bind enrollment listener", err: err}
	}
	r.enrollmentListener = newReadyListener(enrollmentListener)

	agentListener, err := net.Listen("tcp", c.agentAddress)
	if err != nil {
		_ = r.enrollmentListener.Close()
		return stageError{stage: "bind Agent mTLS listener", err: err}
	}
	r.agentListener = newReadyListener(agentListener)

	r.healthListener, err = net.Listen("tcp", c.healthAddress)
	if err != nil {
		_ = r.enrollmentListener.Close()
		_ = r.agentListener.Close()
		return stageError{stage: "bind health listener", err: err}
	}
	return nil
}

func listenerReadiness(listener *readyListener) readinessCheck {
	return func(context.Context) error {
		if listener == nil || !listener.isReady() {
			return errRuntimeNotReady
		}
		return nil
	}
}

func verifyRedisHealth(ctx context.Context, client *redis.Client) error {
	if ctx == nil || client == nil {
		return fmt.Errorf("Redis health dependencies are required")
	}
	if err := client.Ping(ctx).Err(); err != nil {
		return fmt.Errorf("Redis PING failed")
	}
	return nil
}

func verifyNATSHealth(ctx context.Context, connection *nats.Conn, c gateway.NATSCommandBusConfig) error {
	if ctx == nil || connection == nil || !connection.IsConnected() {
		return fmt.Errorf("NATS connection is not ready")
	}
	if err := verifyJetStream(ctx, connection, c); err != nil {
		return fmt.Errorf("JetStream readiness check failed")
	}
	return nil
}

// reportGatewayReady marks the Gateway ready and returns the installation ID.
func reportGatewayReady(ctx context.Context, client controlv1.ControlInternalServiceClient, instanceID, version string) (string, error) {
	response, err := client.ReportGatewayReady(ctx, &controlv1.ReportGatewayReadyRequest{
		Request:           &commonv1.RequestMetadata{RequestId: uuid.NewString(), SentTime: timestamppb.Now()},
		GatewayInstanceId: instanceID, Version: version,
	})
	if err != nil {
		return "", fmt.Errorf("ReportGatewayReady failed: %w", err)
	}
	installation, err := uuid.Parse(response.GetInstallationId())
	if err != nil || installation == uuid.Nil || installation.String() != response.GetInstallationId() {
		return "", fmt.Errorf("ControlInternal returned an invalid installation ID")
	}
	return response.GetInstallationId(), nil
}

func verifyControlHealth(ctx context.Context, connection grpc.ClientConnInterface) error {
	if ctx == nil || connection == nil {
		return fmt.Errorf("ControlInternal health dependencies are required")
	}
	response, err := healthv1.NewHealthClient(connection).Check(ctx, &healthv1.HealthCheckRequest{
		Service: controlv1.ControlInternalService_ServiceDesc.ServiceName,
	})
	if err != nil {
		return fmt.Errorf("ControlInternal health RPC failed")
	}
	if response.GetStatus() != healthv1.HealthCheckResponse_SERVING {
		return fmt.Errorf("ControlInternal service is not serving")
	}
	return nil
}

func verifyJetStream(ctx context.Context, connection *nats.Conn, c gateway.NATSCommandBusConfig) error {
	if ctx == nil || connection == nil {
		return fmt.Errorf("JetStream readiness dependencies are required")
	}
	js, err := connection.JetStream(nats.MaxWait(c.OperationTimeout))
	if err != nil {
		return err
	}
	if _, err := js.AccountInfo(nats.Context(ctx)); err != nil {
		return err
	}
	requiredStreams := []struct {
		name   string
		prefix string
	}{
		{name: c.CommandStream, prefix: c.CommandSubjectPrefix},
		{name: c.StatusStream, prefix: c.StatusSubjectPrefix},
		{name: c.CommandStream, prefix: c.OverlayCommandSubjectPrefix},
		{name: c.StatusStream, prefix: c.OverlayStatusSubjectPrefix},
		{name: c.CommandStream, prefix: gateway.CacheCommandSubjectPrefix},
		{name: c.CommandStream, prefix: gateway.CacheDeadLetterSubjectPrefix},
		{name: c.StatusStream, prefix: gateway.CacheStatusSubjectPrefix},
		// Control API quarantines poison cache statuses here (cachecontrolruntime PublishDLQ).
		{name: c.StatusStream, prefix: gateway.CacheStatusSubjectPrefix + "-dlq"},
		{name: c.CommandStream, prefix: gateway.UpgradeCommandSubjectPrefix},
		{name: c.CommandStream, prefix: c.DrainCommandSubjectPrefix},
		{name: c.StatusStream, prefix: gateway.UpgradeStatusSubjectPrefix},
		{name: c.StatusStream, prefix: gateway.UpgradeStatusV2SubjectPrefix},
		{name: c.StatusStream, prefix: gateway.UpgradeStatusProofSubjectPrefix},
		{name: c.StatusStream, prefix: c.DrainStatusSubjectPrefix},
		{name: c.CommandStream, prefix: c.PortTransitionCommandSubjectPrefix},
		{name: c.StatusStream, prefix: c.PortTransitionStatusSubjectPrefix},
		{name: c.HeartbeatStream, prefix: c.HeartbeatSubjectPrefix},
	}
	streamInfos := make(map[string]*nats.StreamInfo, 3)
	expectedSubjects := make(map[string][]string, 3)
	for _, required := range requiredStreams {
		info, err := js.StreamInfo(required.name, nats.Context(ctx))
		if err != nil {
			return fmt.Errorf("required stream is unavailable")
		}
		if err := validateStreamInfo(info, required.prefix); err != nil {
			return err
		}
		streamInfos[required.name] = info
		if required.prefix == c.StatusSubjectPrefix {
			expectedSubjects[required.name] = append(expectedSubjects[required.name],
				c.StatusSubjectPrefix+".*", c.StatusSubjectPrefix+".generic-v2.*.*",
				c.StatusSubjectPrefix+".terminal-receipt.*.*",
				c.StatusSubjectPrefix+".terminal-receipt-confirmation.*.*",
				c.StatusSubjectPrefix+".terminal-receipt-confirmation-index.*",
			)
		} else if required.prefix == gateway.UpgradeStatusProofSubjectPrefix {
			expectedSubjects[required.name] = append(expectedSubjects[required.name],
				gateway.UpgradeStatusProofSubjectPrefix+".pending.*",
				gateway.UpgradeStatusProofSubjectPrefix+".confirmed.*.*",
				gateway.UpgradeStatusProofSubjectPrefix+".completed.*.*.*",
				gateway.UpgradeStatusProofSubjectPrefix+".status.*.*",
			)
		} else {
			expectedSubjects[required.name] = append(expectedSubjects[required.name], required.prefix+".*")
		}
	}
	for stream, expected := range expectedSubjects {
		if err := validateStreamSubjectAllowSet(streamInfos[stream].Config.Subjects, expected); err != nil {
			return fmt.Errorf("required stream %s has an unexpected subject set", stream)
		}
	}
	return nil
}

func validateStreamInfo(info *nats.StreamInfo, subjectPrefix string) error {
	if info == nil || info.Config.Storage != nats.FileStorage || info.Config.Replicas < 1 || info.Config.Duplicates <= 0 {
		return fmt.Errorf("required stream is not durably configured")
	}
	for _, subject := range info.Config.Subjects {
		if !strictStreamSubjectPattern(subject) {
			return fmt.Errorf("required stream contains an unsafe subject pattern")
		}
	}
	if subjectPrefix == gateway.UpgradeStatusProofSubjectPrefix {
		for _, shape := range []struct {
			name      string
			suffix    []string
			dynamicAt int
		}{
			{name: "pending", suffix: []string{"pending", "*"}, dynamicAt: 1},
			{name: "confirmed", suffix: []string{"confirmed", "*", "*"}, dynamicAt: 1},
			{name: "completed", suffix: []string{"completed", "*", "*", "*"}, dynamicAt: 1},
			{name: "status", suffix: []string{"status", "*", "*"}, dynamicAt: 1},
		} {
			if !streamCoversDynamicSubject(info.Config.Subjects, subjectPrefix, shape.suffix, shape.dynamicAt) {
				return fmt.Errorf("upgrade proof stream does not cover its %s subject shape", shape.name)
			}
		}
		if info.Config.Retention != nats.LimitsPolicy || info.Config.MaxAge != 0 ||
			info.Config.MaxMsgs != -1 || info.Config.MaxBytes != -1 || info.Config.MaxMsgsPerSubject != -1 ||
			info.Config.Discard != nats.DiscardOld || info.Config.DiscardNewPerSubject ||
			info.Config.AllowRollup || info.Config.AllowMsgTTL {
			return fmt.Errorf("upgrade proof stream retention can evict durable evidence")
		}
		return nil
	}
	if !streamCoversDynamicSubject(info.Config.Subjects, subjectPrefix, []string{"*"}, 0) {
		return fmt.Errorf("required stream does not cover its Agent subject")
	}
	return nil
}

func strictStreamSubjectPattern(subject string) bool {
	tokens := splitSubject(subject)
	if tokens == nil {
		return false
	}
	wildcard := false
	for _, token := range tokens {
		switch {
		case token == "*":
			wildcard = true
		case token == ">" || wildcard:
			return false
		case !strictSubjectLiteral(token):
			return false
		}
	}
	return wildcard
}

func strictSubjectLiteral(token string) bool {
	if token == "" {
		return false
	}
	for _, character := range token {
		if (character >= 'a' && character <= 'z') || (character >= 'A' && character <= 'Z') ||
			(character >= '0' && character <= '9') || character == '-' || character == '_' {
			continue
		}
		return false
	}
	return true
}

func validateStreamSubjectAllowSet(actual, expected []string) error {
	if len(actual) != len(expected) || len(actual) == 0 {
		return fmt.Errorf("required stream subject set does not match")
	}
	allowed := make(map[string]struct{}, len(expected))
	for index, subject := range expected {
		if !strictStreamSubjectPattern(subject) {
			return fmt.Errorf("required stream subject allow-set is invalid")
		}
		if actual[index] != subject {
			return fmt.Errorf("required stream contains an unexpected subject")
		}
		if _, exists := allowed[subject]; exists {
			return fmt.Errorf("required stream subject allow-set is duplicated")
		}
		allowed[subject] = struct{}{}
	}
	return nil
}

func streamCoversDynamicSubject(patterns []string, prefix string, suffix []string, dynamicAt int) bool {
	prefixTokens := splitSubject(prefix)
	if prefixTokens == nil || len(suffix) == 0 || dynamicAt < 0 || dynamicAt >= len(suffix) {
		return false
	}
	required := append(append([]string(nil), prefixTokens...), suffix...)
	dynamicIndex := len(prefixTokens) + dynamicAt
	for _, pattern := range patterns {
		patternTokens := splitSubject(pattern)
		if dynamicSubjectPatternCovers(patternTokens, required, dynamicIndex) {
			return true
		}
	}
	return false
}

func dynamicSubjectPatternCovers(pattern, required []string, dynamicIndex int) bool {
	if pattern == nil || required == nil || len(pattern) != len(required) || dynamicIndex < 0 || dynamicIndex >= len(required) {
		return false
	}
	for index, token := range pattern {
		if index >= dynamicIndex {
			if token != "*" {
				return false
			}
			continue
		}
		if token != required[index] {
			return false
		}
	}
	return true
}

func splitSubject(subject string) []string {
	if subject == "" {
		return nil
	}
	tokens := make([]string, 0, 8)
	start := 0
	for index := 0; index <= len(subject); index++ {
		if index != len(subject) && subject[index] != '.' {
			continue
		}
		if index == start {
			return nil
		}
		tokens = append(tokens, subject[start:index])
		start = index + 1
	}
	return tokens
}

func (r *runtime) serve(ctx context.Context) error {
	if r == nil || r.servers == nil {
		return fmt.Errorf("Gateway runtime is incomplete")
	}
	return serveServers(
		ctx,
		r.enrollmentListener,
		r.agentListener,
		r.healthListener,
		r.servers.Enrollment,
		r.servers.MTLS,
		r.healthServer,
		r.liveness,
		r.shutdownTimeout,
		r.transitionServeErrors,
	)
}

// reportTransitionServeStop forwards the end of a ready port transition
// listener's Serve unless the transition closed it on purpose. Non-blocking:
// after shutdown nobody reads and the stop is expected.
func reportTransitionServeStop(served <-chan error, listener *readyListener, target chan<- serveResult) {
	err := <-served
	if listener.wasPlannedClose() {
		return
	}
	select {
	case target <- serveResult{stage: "Agent mTLS gRPC server stopped", err: err}:
	default:
	}
}

type serveResult struct {
	stage string
	err   error
}

func serveServers(
	ctx context.Context,
	enrollmentListener, agentListener *readyListener,
	healthListener net.Listener,
	enrollmentServer, agentServer *grpc.Server,
	healthServer *http.Server,
	liveness *livenessState,
	shutdownTimeout time.Duration,
	transitionErrors <-chan serveResult,
) error {
	if ctx == nil || enrollmentListener == nil || agentListener == nil || healthListener == nil ||
		enrollmentServer == nil || agentServer == nil || healthServer == nil || liveness == nil || shutdownTimeout <= 0 {
		return fmt.Errorf("all Gateway listeners and servers are required")
	}
	serveResults := make(chan serveResult, 3)
	go func() {
		serveResults <- serveResult{stage: "enrollment gRPC server stopped", err: enrollmentServer.Serve(enrollmentListener)}
	}()
	go func() {
		serveResults <- serveResult{stage: "Agent mTLS gRPC server stopped", err: agentServer.Serve(agentListener)}
	}()
	go func() {
		serveResults <- serveResult{stage: "health HTTP server stopped", err: healthServer.Serve(healthListener)}
	}()
	liveness.set(true)

	activeServers := 3
	for activeServers > 0 {
		select {
		case <-ctx.Done():
			markRuntimeNotReady(liveness, enrollmentListener, agentListener)
			stopServers(enrollmentServer, agentServer, healthServer, shutdownTimeout)
			waitForServeResults(serveResults, activeServers)
			return nil
		case result := <-serveResults:
			activeServers--
			if ctx.Err() != nil {
				markRuntimeNotReady(liveness, enrollmentListener, agentListener)
				stopServers(enrollmentServer, agentServer, healthServer, shutdownTimeout)
				waitForServeResults(serveResults, activeServers)
				return nil
			}
			if result.stage == "Agent mTLS gRPC server stopped" && agentListener.wasPlannedClose() {
				continue
			}
			markRuntimeNotReady(liveness, enrollmentListener, agentListener)
			enrollmentServer.Stop()
			agentServer.Stop()
			_ = healthServer.Close()
			waitForServeResults(serveResults, activeServers)
			return stageError{stage: result.stage, err: result.err}
		case result := <-transitionErrors:
			if ctx.Err() != nil {
				continue // the ctx.Done case shuts down
			}
			markRuntimeNotReady(liveness, enrollmentListener, agentListener)
			enrollmentServer.Stop()
			agentServer.Stop()
			_ = healthServer.Close()
			waitForServeResults(serveResults, activeServers)
			return stageError{stage: result.stage, err: result.err}
		}
	}
	return stageError{stage: "Gateway servers stopped", err: net.ErrClosed}
}

func markRuntimeNotReady(liveness *livenessState, listeners ...*readyListener) {
	if liveness != nil {
		liveness.set(false)
	}
	for _, listener := range listeners {
		if listener != nil {
			listener.markNotReady()
		}
	}
}

func waitForServeResults(results <-chan serveResult, count int) {
	for range count {
		<-results
	}
}

func stopServers(enrollmentServer, agentServer *grpc.Server, healthServer *http.Server, timeout time.Duration) {
	var wait sync.WaitGroup
	wait.Add(3)
	for _, server := range []*grpc.Server{enrollmentServer, agentServer} {
		go func(server *grpc.Server) {
			defer wait.Done()
			server.GracefulStop()
		}(server)
	}
	shutdownContext, cancelShutdown := context.WithTimeout(context.Background(), timeout)
	defer cancelShutdown()
	go func() {
		defer wait.Done()
		_ = healthServer.Shutdown(shutdownContext)
	}()
	done := make(chan struct{})
	go func() {
		wait.Wait()
		close(done)
	}()
	timer := time.NewTimer(timeout)
	defer timer.Stop()
	select {
	case <-done:
	case <-timer.C:
		enrollmentServer.Stop()
		agentServer.Stop()
		_ = healthServer.Close()
		<-done
	}
}

func (r *runtime) close() {
	if r == nil {
		return
	}
	markRuntimeNotReady(r.liveness, r.enrollmentListener, r.agentListener)
	if r.cancel != nil {
		r.cancel()
	}
	if r.portManager != nil {
		_ = r.portManager.Close()
	}
	if r.servers != nil {
		r.servers.Enrollment.Stop()
		r.servers.MTLS.Stop()
	}
	if r.tunnels != nil {
		_ = r.tunnels.Close()
	}
	if r.healthServer != nil {
		_ = r.healthServer.Close()
	}
	if r.enrollmentListener != nil {
		_ = r.enrollmentListener.Close()
	}
	if r.agentListener != nil {
		_ = r.agentListener.Close()
	}
	r.listenerMu.RLock()
	candidate := r.candidateAgentListener
	r.listenerMu.RUnlock()
	if candidate != nil {
		_ = candidate.Close()
	}
	if r.healthListener != nil {
		_ = r.healthListener.Close()
	}
	if r.controlConnection != nil {
		_ = r.controlConnection.Close()
	}
	drainNATS := func(connection *nats.Conn) {
		if connection != nil {
			if err := connection.Drain(); err != nil {
				connection.Close()
			}
		}
	}
	drainNATS(r.telemetryNATSConnection)
	if r.natsConnection != r.telemetryNATSConnection {
		drainNATS(r.natsConnection)
	}
	if r.redisClient != nil {
		_ = r.redisClient.Close()
	}
}
