package httpapi

import (
	"context"
	"crypto/sha256"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"log/slog"
	"net"
	"net/http"
	"reflect"
	"regexp"
	"strconv"
	"strings"
	"time"
	"unicode"
	"unicode/utf8"

	"github.com/cdnca/cdnca/libs/passwordpolicy"
	"github.com/cdnca/cdnca/services/control-api/internal/accountrecoverycontext"
	"github.com/cdnca/cdnca/services/control-api/internal/acmecacredentials"
	"github.com/cdnca/cdnca/services/control-api/internal/admininbox"
	"github.com/cdnca/cdnca/services/control-api/internal/analytics"
	"github.com/cdnca/cdnca/services/control-api/internal/analyticsdiagnostic"
	"github.com/cdnca/cdnca/services/control-api/internal/analyticsdiagnostichttp"
	"github.com/cdnca/cdnca/services/control-api/internal/analyticsgeo"
	"github.com/cdnca/cdnca/services/control-api/internal/analyticsgeohttp"
	"github.com/cdnca/cdnca/services/control-api/internal/analyticslog"
	"github.com/cdnca/cdnca/services/control-api/internal/analyticsrealtimehttp"
	"github.com/cdnca/cdnca/services/control-api/internal/announcementhttp"
	"github.com/cdnca/cdnca/services/control-api/internal/apikey"
	"github.com/cdnca/cdnca/services/control-api/internal/apikeycredential"
	"github.com/cdnca/cdnca/services/control-api/internal/approvalcenter"
	"github.com/cdnca/cdnca/services/control-api/internal/audit"
	"github.com/cdnca/cdnca/services/control-api/internal/cachecontrolhttp"
	"github.com/cdnca/cdnca/services/control-api/internal/ccreference"
	"github.com/cdnca/cdnca/services/control-api/internal/certdefaults"
	"github.com/cdnca/cdnca/services/control-api/internal/cnameallocationhttp"
	"github.com/cdnca/cdnca/services/control-api/internal/controlupgrade"
	"github.com/cdnca/cdnca/services/control-api/internal/dnsacme"
	"github.com/cdnca/cdnca/services/control-api/internal/dnsproviderremote"
	"github.com/cdnca/cdnca/services/control-api/internal/dnssettings"
	"github.com/cdnca/cdnca/services/control-api/internal/domaintrust"
	"github.com/cdnca/cdnca/services/control-api/internal/entitlementguard"
	"github.com/cdnca/cdnca/services/control-api/internal/entitlementrefreshhttp"
	"github.com/cdnca/cdnca/services/control-api/internal/fielderr"
	"github.com/cdnca/cdnca/services/control-api/internal/identity"
	"github.com/cdnca/cdnca/services/control-api/internal/impersonation"
	"github.com/cdnca/cdnca/services/control-api/internal/impersonationhttp"
	"github.com/cdnca/cdnca/services/control-api/internal/jobhttp"
	"github.com/cdnca/cdnca/services/control-api/internal/l4forward"
	"github.com/cdnca/cdnca/services/control-api/internal/marketmanaged"
	"github.com/cdnca/cdnca/services/control-api/internal/node"
	"github.com/cdnca/cdnca/services/control-api/internal/nodeidentity"
	"github.com/cdnca/cdnca/services/control-api/internal/nodemonitoringoverride"
	"github.com/cdnca/cdnca/services/control-api/internal/nodeporttransition"
	"github.com/cdnca/cdnca/services/control-api/internal/nodepresence"
	"github.com/cdnca/cdnca/services/control-api/internal/nodeserving"
	"github.com/cdnca/cdnca/services/control-api/internal/notificationhttp"
	"github.com/cdnca/cdnca/services/control-api/internal/originfailover"
	"github.com/cdnca/cdnca/services/control-api/internal/packagecatalog"
	"github.com/cdnca/cdnca/services/control-api/internal/platformpolicy"
	"github.com/cdnca/cdnca/services/control-api/internal/regioncatalog"
	"github.com/cdnca/cdnca/services/control-api/internal/regioncataloghttp"
	"github.com/cdnca/cdnca/services/control-api/internal/rulepackcontrol"
	"github.com/cdnca/cdnca/services/control-api/internal/securityban"
	"github.com/cdnca/cdnca/services/control-api/internal/securityiplist"
	"github.com/cdnca/cdnca/services/control-api/internal/securitypolicy"
	"github.com/cdnca/cdnca/services/control-api/internal/site"
	"github.com/cdnca/cdnca/services/control-api/internal/siteaccess"
	"github.com/cdnca/cdnca/services/control-api/internal/sitecrs"
	"github.com/cdnca/cdnca/services/control-api/internal/sitegroup"
	"github.com/cdnca/cdnca/services/control-api/internal/sitequickblock"
	"github.com/cdnca/cdnca/services/control-api/internal/siteschedule302"
	"github.com/cdnca/cdnca/services/control-api/internal/sitetrafficlimit"
	"github.com/cdnca/cdnca/services/control-api/internal/urlauthpolicy"
	"github.com/cdnca/cdnca/services/control-api/internal/wafsubscription"
	"github.com/google/uuid"
	"github.com/jackc/pgx/v5/pgxpool"
)

const refreshCookieName = "cdnca_refresh"

var requestIDPattern = regexp.MustCompile(`^[A-Za-z0-9._-]{1,128}$`)

type Server struct {
	pool *pgxpool.Pool
	// dnsCredentialCipher also seals ACME EAB credentials.
	dnsCredentialCipher                  dnsacme.CredentialCipher
	now                                  func() time.Time
	entitlementTrust                     *entitlementguard.TrustStore
	identity                             *identity.Service
	nodes                                *node.Service
	nodeRegistrationLimiter              *registrationLimiter
	nodeInventory                        *nodepresence.Inventory
	nodeMetrics                          NodeMetricsReader
	nodePortTransitions                  *nodeporttransition.Service
	nodeMonitoringOverrides              *nodemonitoringoverride.Store
	nodeServing                          *nodeserving.Store
	nodePortTransitionReady              func() error
	sites                                *site.Service
	siteGroups                           *sitegroup.Service
	streams                              l4StreamService
	streamGroups                         l4StreamGroupService
	dnsacme                              *dnsacme.Service
	certificateDefaults                  *certdefaults.Service
	dnsSettings                          *dnssettings.Service
	dnsRecordLister                      dnsproviderremote.ZoneRecordLister
	controlUpgrades                      *controlupgrade.Service
	maintenanceUpgradeRuntime            controlupgrade.MaintenanceRuntime
	apiKeys                              *apikey.Service
	securityPolicies                     *securitypolicy.Service
	siteQuickBlocks                      *sitequickblock.Service
	securityBans                         *securityban.Service
	securityIPLists                      *securityiplist.Store
	siteAccess                           *siteaccess.Service
	siteCRS                              *sitecrs.Service
	siteSchedule302                      *siteschedule302.Service
	siteTrafficLimits                    *sitetrafficlimit.Service
	originFailover                       *originfailover.Service
	wafSubscriptions                     *wafsubscription.Service
	rulePacks                            *rulepackcontrol.Service
	ruleMountsPublished                  func()
	platformPolicyState                  *platformpolicy.State
	ccReferences                         *ccreference.Service
	urlAuthPolicies                      *urlauthpolicy.Service
	adminDashboardHandler                http.Handler
	tenantDashboardHandler               http.Handler
	analyticsHandler                     http.Handler
	analyticsDiagnosticHandler           http.Handler
	analyticsRealtimeHandler             http.Handler
	l4AnalyticsHandler                   http.Handler
	streamLive                           StreamLiveConnections
	analyticsGeoHandler                  http.Handler
	analyticsLogsHandler                 http.Handler
	observabilityLogHandler              http.Handler
	auditLogHandler                      http.Handler
	backupHistoryHandler                 http.Handler
	controlBackupHandler                 http.Handler
	ccCoordinationHandler                http.Handler
	analyticsConnectionsRetentionHandler http.Handler
	analyticsConnectionsDLQHandler       http.Handler
	siteCaptureHandler                   http.Handler
	announcementHandler                  http.Handler
	notificationHandler                  http.Handler
	approvalCenter                       *approvalcenter.Store
	jobQueryHandler                      http.Handler
	impersonationHandler                 http.Handler
	impersonationSessionAuthorizer       ImpersonationSessionAuthorizer
	cacheControlHandler                  http.Handler
	errorPageHandler                     http.Handler
	errorPagePublicationHandler          http.Handler
	identityVerificationHandler          http.Handler
	identitySessionHandler               http.Handler
	mfaHandler                           http.Handler
	originAuthHandler                    http.Handler
	originAuthPublicationHandler         http.Handler
	edgePublishHandler                   http.Handler
	challengePolicyHandler               http.Handler
	httpPolicyHandler                    http.Handler
	firewallActionHandler                http.Handler
	pluginWebhookHandler                 http.Handler
	pluginInstallationHandler            http.Handler
	dnsReconcileHandler                  http.Handler
	marketSubscribeHandler               http.Handler
	marketRuntime                        bool
	nodeSchedulerHandler                 http.Handler
	nodeIsolationHandler                 http.Handler
	certificateAssetHandler              http.Handler
	certificatePublicationStatusHandler  http.Handler
	cnameAllocationHandler               http.Handler
	systemConfigurationHandler           http.Handler
	systemSettingsHandler                http.Handler
	brandAssetHandler                    http.Handler
	themeHandler                         http.Handler
	pluginUIHandler                      http.Handler
	pluginProviderHandler                http.Handler
	systemCleanupSettingsHandler         http.Handler
	systemUserSettingsHandler            http.Handler
	systemMailSettingsHandler            http.Handler
	systemOtherSettingsHandler           http.Handler
	regionCatalogHandler                 http.Handler
	l4LineSwitchHandler                  http.Handler
	customRBACHandler                    http.Handler
	ipIntelUpdateHandler                 http.Handler
	migrateImportHandler                 http.Handler
	nodeGatewayAddressHandler            http.Handler
	probeDNSPupHandler                   http.Handler
	gatewayRegistryHandler               http.Handler
	domainTrustHandler                   http.Handler
	dnsHubHandler                        http.Handler
	ticketHandler                        http.Handler
	aggregatedEdgeHandler                http.Handler
	nodeSSHInstallHandler                http.Handler
	accountRegistrationHandler           http.Handler
	accountLoginHandler                  http.Handler
	securityCoordinationMetricsHandler   http.Handler
	ja4BlockHandler                      http.Handler
	autoDefenseHandler                   http.Handler
	ccStatsHandler                       http.Handler
	marketSecurityHandler                http.Handler
	controlPlaneUpgradeHandler           http.Handler
	controlPlaneUpgradeGate              func(http.Handler) http.Handler
	installationLockCheck                func(context.Context) error
	nodeTickets                          NodeTicketReader
	controlUpgradePlanHandler            http.Handler
	entitlementRefreshHandler            http.Handler
	apiKeyUsageRecorder                  APIKeyUsageRecorder
	apiKeySourceIP                       *accountrecoverycontext.SourceIPResolver
	adminInbox                           *admininbox.Store
	initializationErr                    error
	cookieSecure                         bool
	cookieDomain                         string
	logger                               *slog.Logger
	// zeroSSLEABFetcher overrides the ZeroSSL EAB endpoint in tests (nil = production).
	zeroSSLEABFetcher *acmecacredentials.ZeroSSLEABFetcher
}

type ImpersonationSessionAuthorizer interface {
	Authorize(*http.Request, string) (impersonationhttp.AuthorizedSession, error)
}
type ImpersonationHandlerFactory func(impersonationhttp.AuthenticateFunc) (http.Handler, ImpersonationSessionAuthorizer, error)
type CacheControlHandlerFactory func(cachecontrolhttp.AuthenticateFunc) (http.Handler, error)
type CNAMEAllocationHandlerFactory func(cnameallocationhttp.AuthenticateFunc) (http.Handler, error)
type AnnouncementHandlerFactory func(announcementhttp.AuthenticateFunc) (http.Handler, error)
type NotificationHandlerFactory func(notificationhttp.AuthenticateFunc) (http.Handler, error)
type AnalyticsDiagnosticHandlerFactory func(analyticsdiagnostichttp.Authenticator) (http.Handler, error)
type AnalyticsRealtimeHandlerFactory func(analyticsrealtimehttp.Authenticator) (http.Handler, error)
type AnalyticsGeoHandlerFactory func(analyticsgeohttp.Authenticator) (http.Handler, error)
type MountedHandlerFactory func() (http.Handler, error)

type APIKeyUsageRecorder interface {
	TryRecord(uuid.UUID, time.Time) bool
}

type Config struct {
	CookieSecure        bool
	CookieDomain        string
	Logger              *slog.Logger
	Now                 func() time.Time
	EntitlementTrust    *entitlementguard.TrustStore
	PlatformPolicyState *platformpolicy.State
	// SecurityBanStore is the ban list store whose writes wake the ban list
	// distributor (nil: a store of its own, no wake-up).
	SecurityBanStore          *securityban.Store
	SiteTransferCertificates  site.TransferCertificates // 更换所属用户 carries the uploaded certificate (nil: not carried)
	ControlUpgradeService     *controlupgrade.Service
	MaintenanceUpgradeRuntime controlupgrade.MaintenanceRuntime
	DNSCredentialCipher       dnsacme.CredentialCipher
	DNSProviderVerifier       dnsacme.ProviderVerifier
	// DNSZoneApexResolver finds the hosted domain of a saved CNAME zone
	// (migration 473); nil stores zones without an apex (filled on first use).
	DNSZoneApexResolver dnsproviderremote.ZoneApexResolver
	// DNSRecordLister lists provider records for 清除CDN无关解析 / 记录修复
	// planning (production adapters when nil).
	DNSRecordLister          dnsproviderremote.ZoneRecordLister
	NodePresenceLeases       nodepresence.LeaseReader
	NodePresenceOfflineAfter time.Duration
	NodeMetricsReader        NodeMetricsReader
	NodePortTransitionReady  func() error
	// RuleMountsPublished runs after a site's security.mounts are published
	// (wakes the node artifact set distributor: mounted packs become items).
	RuleMountsPublished               func()
	APIKeyPepper                      []byte
	APIKeyPepperKeyring               apikeycredential.PepperKeyring
	APIKeyTrustedProxyCIDRs           []string
	APIKeyMaxProxyHops                int
	APIKeyUsageRecorder               APIKeyUsageRecorder
	AdminDashboardHandler             http.Handler
	TenantDashboardHandler            http.Handler
	AnalyticsService                  *analytics.Service
	AnalyticsQueryStore               analytics.QueryStore
	AnalyticsHandlerConfig            analytics.HandlerConfig
	AnalyticsDiagnosticHandlerFactory AnalyticsDiagnosticHandlerFactory
	AnalyticsRealtimeHandlerFactory   AnalyticsRealtimeHandlerFactory
	L4AnalyticsHandler                http.Handler
	// StreamLiveConnections serves 实时连接 (nil: routes not mounted).
	StreamLiveConnections                      StreamLiveConnections
	AnalyticsGeoHandlerFactory                 AnalyticsGeoHandlerFactory
	AnalyticsLogsHandler                       http.Handler
	ObservabilityLogHandler                    http.Handler
	AuditLogHandler                            http.Handler // log center (unified-log); nil: not mounted
	BackupHistoryHandler                       http.Handler
	ControlBackupHandler                       http.Handler
	CCCoordinationHandler                      http.Handler
	AnalyticsConnectionsRetentionHandler       http.Handler
	AnalyticsConnectionsDLQHandler             http.Handler
	SiteCaptureHandler                         http.Handler
	JobQueryReader                             jobhttp.Reader
	JobQueryServiceConfig                      jobhttp.ServiceConfig
	JobQueryHandlerConfig                      jobhttp.HandlerConfig
	ImpersonationHandlerFactory                ImpersonationHandlerFactory
	CacheControlHandlerFactory                 CacheControlHandlerFactory
	CNAMEAllocationHandlerFactory              CNAMEAllocationHandlerFactory
	AnnouncementHandlerFactory                 AnnouncementHandlerFactory
	NotificationHandlerFactory                 NotificationHandlerFactory
	ErrorPageHandlerFactory                    MountedHandlerFactory
	ErrorPagePublicationHandlerFactory         MountedHandlerFactory
	IdentityVerificationHandlerFactory         MountedHandlerFactory
	IdentitySessionHandlerFactory              MountedHandlerFactory
	MFAHandlerFactory                          MountedHandlerFactory
	OriginAuthHandlerFactory                   MountedHandlerFactory
	OriginAuthPublicationHandlerFactory        MountedHandlerFactory
	EdgePublishHandlerFactory                  MountedHandlerFactory
	ChallengePolicyHandlerFactory              MountedHandlerFactory
	HTTPPolicyHandlerFactory                   MountedHandlerFactory
	FirewallActionHandlerFactory               MountedHandlerFactory
	PluginWebhookHandlerFactory                MountedHandlerFactory
	PluginInstallationHandlerFactory           MountedHandlerFactory
	DNSReconcileHandlerFactory                 MountedHandlerFactory
	MarketSubscribeHandlerFactory              MountedHandlerFactory
	NodeSchedulerHandlerFactory                MountedHandlerFactory
	NodeIsolationHandlerFactory                MountedHandlerFactory
	CertificateAssetHandlerFactory             MountedHandlerFactory
	CertificatePublicationStatusHandlerFactory MountedHandlerFactory
	SystemConfigurationHandlerFactory          MountedHandlerFactory
	SystemSettingsHandlerFactory               MountedHandlerFactory
	BrandAssetHandlerFactory                   MountedHandlerFactory
	ThemeHandlerFactory                        MountedHandlerFactory
	// PluginUIHandlerFactory (PA-19) serves ui_page plugin pages and the
	// restricted plugin backend proxy.
	PluginUIHandlerFactory MountedHandlerFactory
	// PluginProviderHandlerFactory (PA-22) lists third-party provider
	// plugins with their contract results and enables / disables them.
	PluginProviderHandlerFactory        MountedHandlerFactory
	SystemCleanupSettingsHandlerFactory MountedHandlerFactory
	SystemUserSettingsHandlerFactory    MountedHandlerFactory
	SystemMailSettingsHandlerFactory    MountedHandlerFactory
	SystemOtherSettingsHandlerFactory   MountedHandlerFactory
	L4LineSwitchHandlerFactory          MountedHandlerFactory
	SiteGroupService                    *sitegroup.Service
	CustomRBACHandlerFactory            MountedHandlerFactory
	// IPIntelUpdateHandlerFactory serves module.ipintel.dnspup
	// (internal/ipintelupdate.Patterns).
	IPIntelUpdateHandlerFactory MountedHandlerFactory
	// MigrateImportHandlerFactory serves module.migrate.import
	// (internal/migrateimport/job.Patterns, ADR 0016).
	MigrateImportHandlerFactory MountedHandlerFactory
	// NodeGatewayAddressHandlerFactory serves 维护升级 → 节点设置「更换主控连接地址」
	// (internal/nodegatewayaddr, fix-nodegw).
	NodeGatewayAddressHandlerFactory MountedHandlerFactory
	// ProbeDNSPupHandlerFactory serves module.probe.dnspup
	// (internal/dnspupprobe.Patterns).
	ProbeDNSPupHandlerFactory MountedHandlerFactory
	// GatewayRegistryHandlerFactory serves Agent Gateway management and the
	// public binding route (internal/gatewayregistry.Patterns).
	GatewayRegistryHandlerFactory             MountedHandlerFactory
	DomainTrustHandlerFactory                 MountedHandlerFactory
	DNSHubHandlerFactory                      MountedHandlerFactory
	TicketHandlerFactory                      MountedHandlerFactory
	AggregatedEdgeHandlerFactory              MountedHandlerFactory
	NodeSSHInstallHandlerFactory              MountedHandlerFactory
	AccountRegistrationHandlerFactory         MountedHandlerFactory
	AccountLoginHandlerFactory                MountedHandlerFactory
	SecurityCoordinationMetricsHandlerFactory MountedHandlerFactory
	JA4BlockHandlerFactory                    MountedHandlerFactory
	AutoDefenseHandlerFactory                 MountedHandlerFactory
	CCStatsHandlerFactory                     MountedHandlerFactory
	// MarketSecurityHandlerFactory serves relayed market attack logs (ML-21).
	MarketSecurityHandlerFactory     MountedHandlerFactory
	ControlUpgradePlanHandlerFactory MountedHandlerFactory
	EntitlementRefreshHandlerFactory MountedHandlerFactory
	ControlPlaneUpgradeHandler       http.Handler
	ControlPlaneUpgradeGate          func(http.Handler) http.Handler
	// ApprovalStepUpConsumer consumes the approver's platform-scoped step-up
	// proof (approval center Q3; nil: an approver with MFA cannot approve).
	ApprovalStepUpConsumer approvalcenter.StepUpConsumer
	// InstallationLockCheck fetches the installation state now (ADR 0014; nil = off).
	InstallationLockCheck func(context.Context) error
	// NodeTickets reads each node's last ServiceTicket (PF09; nil = 503).
	NodeTickets NodeTicketReader

	// MarketRuntime: the market member routes are mounted (MARKET_RUNTIME_ENABLED);
	// the node market and plugin store menus follow it.
	MarketRuntime bool
}

func New(pool *pgxpool.Pool, identityService *identity.Service, config Config) *Server {
	logger := config.Logger
	if logger == nil {
		logger = slog.Default()
	}
	if config.Now == nil {
		config.Now = time.Now
	}
	apiKeySourceIP, err := accountrecoverycontext.NewSourceIPResolver(
		config.APIKeyTrustedProxyCIDRs, config.APIKeyMaxProxyHops,
	)
	if err != nil {
		return &Server{initializationErr: fmt.Errorf("configure API key source IP: %w", err), logger: logger}
	}
	if nilAPIKeyUsageRecorder(config.APIKeyUsageRecorder) {
		return &Server{initializationErr: errors.New("API key usage recorder is typed nil"), logger: logger}
	}
	apiKeyPepper := config.APIKeyPepperKeyring
	if !apiKeyPepper.Configured() {
		apiKeyPepper, err = apikeycredential.NewPepperKeyring(apikeycredential.PepperKeyringConfig{
			ActiveVersion: apikeycredential.LegacyPepperVersion,
			Active:        config.APIKeyPepper,
		})
		if err != nil {
			return &Server{initializationErr: fmt.Errorf("configure API key pepper: %w", err), logger: logger}
		}
	}
	controlUpgradeService := config.ControlUpgradeService
	if controlUpgradeService == nil {
		controlUpgradeService = controlupgrade.NewService(pool, config.EntitlementTrust,
			config.PlatformPolicyState, config.Now)
	}
	streamService := l4forward.NewService(l4forward.NewStoreWithClock(pool, config.Now))
	server := &Server{
		marketRuntime:           config.MarketRuntime,
		pool:                    pool,
		now:                     config.Now,
		entitlementTrust:        config.EntitlementTrust,
		identity:                identityService,
		nodes:                   node.NewService(node.NewStoreWithClock(pool, config.Now, config.EntitlementTrust)),
		nodeInventory:           nodepresence.NewInventory(pool, config.NodePresenceLeases, config.NodePresenceOfflineAfter, config.Now, logger),
		nodeMetrics:             config.NodeMetricsReader,
		nodePortTransitions:     nodeporttransition.NewService(nodeporttransition.NewPostgresStore(pool, config.Now), config.Now, uuid.New),
		nodeMonitoringOverrides: newNodeMonitoringOverrideStore(pool, config.Now),
		nodeServing:             newNodeServingStore(pool),
		nodePortTransitionReady: config.NodePortTransitionReady,
		sites:                   site.NewService(site.NewStoreWithClock(pool, config.Now, config.EntitlementTrust).WithTransferCertificates(config.SiteTransferCertificates).WithNodeOfflineAfter(config.NodePresenceOfflineAfter)),
		siteGroups:              config.SiteGroupService,
		streams:                 streamService,
		streamGroups:            streamService,
		dnsacme:                 newDNSACMEService(pool, config),
		certificateDefaults:     certdefaults.NewService(certdefaults.NewStore(pool, config.Now)),
		dnsCredentialCipher:     config.DNSCredentialCipher,
		dnsSettings:             dnssettings.NewService(pool, config.Now),
		dnsRecordLister:         config.DNSRecordLister,
		controlUpgrades:         controlUpgradeService,
		apiKeys:                 apikey.NewServiceWithPepperKeyring(pool, apiKeyPepper, config.Now),
		apiKeyUsageRecorder:     config.APIKeyUsageRecorder,
		apiKeySourceIP:          apiKeySourceIP,
		adminInbox:              admininbox.NewStore(pool),
		securityPolicies:        securitypolicy.NewService(securitypolicy.NewStoreWithClock(pool, config.Now)),
		siteQuickBlocks:         sitequickblock.NewService(sitequickblock.NewStore(pool, config.Now)),
		securityBans:            securityban.NewService(securityBanStore(pool, config)),
		securityIPLists:         securityiplist.NewStore(pool, config.Now),
		siteAccess:              siteaccess.NewService(pool, config.Now),
		siteCRS:                 sitecrs.NewService(sitecrs.NewStore(pool, config.Now)),
		siteSchedule302:         siteschedule302.NewService(siteschedule302.NewStore(pool, config.Now)),
		siteTrafficLimits:       sitetrafficlimit.NewService(sitetrafficlimit.NewStore(pool, config.Now)),
		originFailover:          originfailover.NewService(originfailover.NewStore(pool, nil, config.Now)),
		platformPolicyState:     config.PlatformPolicyState,
		ccReferences:            ccreference.NewService(ccreference.NewStoreWithClock(pool, config.Now)),
		urlAuthPolicies:         urlauthpolicy.NewService(urlauthpolicy.NewStoreWithClock(pool, config.Now), config.DNSCredentialCipher),
		cookieSecure:            config.CookieSecure,
		cookieDomain:            config.CookieDomain,
		logger:                  logger,
	}
	server.wafSubscriptions = wafsubscription.NewService(pool, config.Now, logger)
	server.rulePacks = rulepackcontrol.NewService(pool, config.Now)
	server.ruleMountsPublished = config.RuleMountsPublished
	server.nodeInventory.WithTelemetryExclusions(nodeidentity.TelemetryScopeExclusions)
	server.maintenanceUpgradeRuntime = config.MaintenanceUpgradeRuntime
	server.nodeRegistrationLimiter = newRegistrationLimiter(config.Now)
	// Self-registration derives its credential MAC from the API key pepper; a
	// missing pepper leaves the endpoints failing closed (503).
	if len(config.APIKeyPepper) >= 32 {
		if err := server.nodes.ConfigureRegistration(config.APIKeyPepper); err != nil {
			server.initializationErr = fmt.Errorf("configure node registration: %w", err)
			return server
		}
	}
	if pool != nil && identityService != nil {
		server.regionCatalogHandler, err = regioncataloghttp.NewHandler(
			regioncatalog.NewStore(pool), identityService.AuthenticateSession,
		)
		if err != nil {
			server.initializationErr = fmt.Errorf("initialize region catalog handler: %w", err)
			return server
		}
	}
	server.installationLockCheck = config.InstallationLockCheck
	server.nodeTickets = config.NodeTickets
	if config.ControlPlaneUpgradeHandler != nil || config.ControlPlaneUpgradeGate != nil {
		if nilHTTPHandler(config.ControlPlaneUpgradeHandler) || config.ControlPlaneUpgradeGate == nil {
			server.initializationErr = errors.New("control-plane upgrade handler and gate must be configured together")
			return server
		}
		server.controlPlaneUpgradeHandler = config.ControlPlaneUpgradeHandler
		server.controlPlaneUpgradeGate = config.ControlPlaneUpgradeGate
	}
	if config.AdminDashboardHandler != nil || config.TenantDashboardHandler != nil {
		if nilHTTPHandler(config.AdminDashboardHandler) || nilHTTPHandler(config.TenantDashboardHandler) {
			server.initializationErr = errors.New("dashboard handlers must be configured together")
			return server
		}
		server.adminDashboardHandler = config.AdminDashboardHandler
		server.tenantDashboardHandler = config.TenantDashboardHandler
	}
	if config.AnalyticsService != nil && config.AnalyticsQueryStore != nil {
		server.initializationErr = errors.New("analytics service and query store are mutually exclusive")
		return server
	}
	analyticsService := config.AnalyticsService
	if analyticsService == nil && config.AnalyticsQueryStore != nil {
		service, err := analytics.NewService(config.AnalyticsQueryStore)
		if err != nil {
			server.initializationErr = err
			return server
		}
		analyticsService = service
	}
	if analyticsService != nil {
		config.AnalyticsHandlerConfig.Logger = logger
		server.analyticsHandler, server.initializationErr = analytics.NewHandler(
			analyticsService,
			server.authenticateAnalytics,
			config.AnalyticsHandlerConfig,
		)
	}
	if server.initializationErr == nil && config.AnalyticsDiagnosticHandlerFactory != nil {
		handler, err := config.AnalyticsDiagnosticHandlerFactory(server.authenticateAnalyticsDiagnostic)
		if err != nil {
			server.initializationErr = err
			return server
		}
		if nilHTTPHandler(handler) {
			server.initializationErr = errors.New("analytics diagnostic handler factory returned nil handler")
			return server
		}
		server.analyticsDiagnosticHandler = handler
	}
	if server.initializationErr == nil && config.AnalyticsRealtimeHandlerFactory != nil {
		handler, err := config.AnalyticsRealtimeHandlerFactory(server.authenticatedPrincipal)
		if err != nil {
			server.initializationErr = err
			return server
		}
		if nilHTTPHandler(handler) {
			server.initializationErr = errors.New("analytics realtime handler factory returned nil handler")
			return server
		}
		server.analyticsRealtimeHandler = handler
	}
	if server.initializationErr == nil && config.L4AnalyticsHandler != nil {
		if nilHTTPHandler(config.L4AnalyticsHandler) {
			server.initializationErr = errors.New("L4 analytics handler is typed nil")
			return server
		}
		server.l4AnalyticsHandler = config.L4AnalyticsHandler
	}
	server.streamLive = config.StreamLiveConnections
	if server.initializationErr == nil && config.AnalyticsGeoHandlerFactory != nil {
		handler, err := config.AnalyticsGeoHandlerFactory(server.authenticateAnalyticsGeo)
		if err != nil {
			server.initializationErr = err
			return server
		}
		if nilHTTPHandler(handler) {
			server.initializationErr = errors.New("analytics geo handler factory returned nil handler")
			return server
		}
		server.analyticsGeoHandler = handler
	}
	if server.initializationErr == nil && config.AnalyticsLogsHandler != nil {
		if nilHTTPHandler(config.AnalyticsLogsHandler) {
			server.initializationErr = errors.New("analytics logs handler is typed nil")
			return server
		}
		server.analyticsLogsHandler = config.AnalyticsLogsHandler
	}
	if server.initializationErr == nil && config.ObservabilityLogHandler != nil {
		if nilHTTPHandler(config.ObservabilityLogHandler) {
			server.initializationErr = errors.New("observability log handler is typed nil")
			return server
		}
		server.observabilityLogHandler = config.ObservabilityLogHandler
	}
	if server.initializationErr == nil && config.AuditLogHandler != nil {
		if nilHTTPHandler(config.AuditLogHandler) {
			server.initializationErr = errors.New("audit log handler is typed nil")
			return server
		}
		server.auditLogHandler = config.AuditLogHandler
	}
	if server.initializationErr == nil && config.BackupHistoryHandler != nil {
		if nilHTTPHandler(config.BackupHistoryHandler) {
			server.initializationErr = errors.New("backup history handler is typed nil")
			return server
		}
		server.backupHistoryHandler = config.BackupHistoryHandler
	}
	if server.initializationErr == nil && config.ControlBackupHandler != nil {
		if nilHTTPHandler(config.ControlBackupHandler) {
			server.initializationErr = errors.New("control backup handler is typed nil")
			return server
		}
		server.controlBackupHandler = config.ControlBackupHandler
	}
	if server.initializationErr == nil && config.CCCoordinationHandler != nil {
		if nilHTTPHandler(config.CCCoordinationHandler) {
			server.initializationErr = errors.New("CC coordination handler is typed nil")
			return server
		}
		server.ccCoordinationHandler = config.CCCoordinationHandler
	}
	if server.initializationErr == nil && config.AnalyticsConnectionsRetentionHandler != nil {
		if nilHTTPHandler(config.AnalyticsConnectionsRetentionHandler) {
			server.initializationErr = errors.New("analytics connections retention handler is typed nil")
			return server
		}
		server.analyticsConnectionsRetentionHandler = config.AnalyticsConnectionsRetentionHandler
	}
	if server.initializationErr == nil && config.AnalyticsConnectionsDLQHandler != nil {
		if nilHTTPHandler(config.AnalyticsConnectionsDLQHandler) {
			server.initializationErr = errors.New("analytics connections DLQ handler is typed nil")
			return server
		}
		server.analyticsConnectionsDLQHandler = config.AnalyticsConnectionsDLQHandler
	}
	if server.initializationErr == nil && config.SiteCaptureHandler != nil {
		if nilHTTPHandler(config.SiteCaptureHandler) {
			server.initializationErr = errors.New("site capture handler is typed nil")
			return server
		}
		server.siteCaptureHandler = config.SiteCaptureHandler
	}
	if server.initializationErr == nil && config.JobQueryReader != nil {
		service, err := jobhttp.NewService(config.JobQueryReader, config.JobQueryServiceConfig)
		if err != nil {
			server.initializationErr = err
			return server
		}
		config.JobQueryHandlerConfig.Logger = logger
		server.jobQueryHandler, server.initializationErr = jobhttp.NewHandler(
			service,
			server.authenticateJobQuery,
			config.JobQueryHandlerConfig,
		)
	}
	if server.initializationErr == nil && config.ImpersonationHandlerFactory != nil {
		handler, authorizer, err := config.ImpersonationHandlerFactory(server.authenticateImpersonationPrimarySession)
		if err != nil {
			server.initializationErr = err
			return server
		}
		if nilHTTPHandler(handler) || nilImpersonationSessionAuthorizer(authorizer) {
			server.initializationErr = errors.New("impersonation factory returned incomplete runtime")
			return server
		}
		server.impersonationHandler = handler
		server.impersonationSessionAuthorizer = authorizer
	}
	if server.initializationErr == nil && config.CacheControlHandlerFactory != nil {
		handler, err := config.CacheControlHandlerFactory(server.authenticatedPrincipal)
		if err != nil {
			server.initializationErr = err
			return server
		}
		if nilHTTPHandler(handler) {
			server.initializationErr = errors.New("cache control handler factory returned nil handler")
			return server
		}
		server.cacheControlHandler = handler
	}
	if server.initializationErr == nil && config.CNAMEAllocationHandlerFactory != nil {
		handler, err := config.CNAMEAllocationHandlerFactory(server.authenticatedPrincipal)
		if err != nil {
			server.initializationErr = err
			return server
		}
		if nilHTTPHandler(handler) {
			server.initializationErr = errors.New("CNAME allocation handler factory returned nil handler")
			return server
		}
		server.cnameAllocationHandler = handler
	}
	if server.initializationErr == nil && config.AnnouncementHandlerFactory != nil {
		handler, err := config.AnnouncementHandlerFactory(server.authenticateAnnouncementSession)
		if err != nil {
			server.initializationErr = err
			return server
		}
		if handler == nil {
			server.initializationErr = errors.New("announcement handler factory returned nil handler")
			return server
		}
		server.announcementHandler = handler
	}
	if server.initializationErr == nil && config.NotificationHandlerFactory != nil {
		handler, err := config.NotificationHandlerFactory(server.authenticateNotificationSession)
		if err != nil {
			server.initializationErr = err
			return server
		}
		if nilHTTPHandler(handler) {
			server.initializationErr = errors.New("notification handler factory returned nil handler")
			return server
		}
		server.notificationHandler = handler
	}
	if pool != nil {
		server.approvalCenter = approvalcenter.NewStore(pool, config.ApprovalStepUpConsumer, config.Now)
	}
	for _, mounted := range []struct {
		name    string
		factory MountedHandlerFactory
		target  *http.Handler
	}{
		{name: "error page", factory: config.ErrorPageHandlerFactory, target: &server.errorPageHandler},
		{name: "error page publication", factory: config.ErrorPagePublicationHandlerFactory, target: &server.errorPagePublicationHandler},
		{name: "identity verification", factory: config.IdentityVerificationHandlerFactory, target: &server.identityVerificationHandler},
		{name: "identity session", factory: config.IdentitySessionHandlerFactory, target: &server.identitySessionHandler},
		{name: "MFA", factory: config.MFAHandlerFactory, target: &server.mfaHandler},
		{name: "origin authentication", factory: config.OriginAuthHandlerFactory, target: &server.originAuthHandler},
		{name: "origin authentication publication", factory: config.OriginAuthPublicationHandlerFactory, target: &server.originAuthPublicationHandler},
		{name: "edge publish", factory: config.EdgePublishHandlerFactory, target: &server.edgePublishHandler},
		{name: "challenge policy", factory: config.ChallengePolicyHandlerFactory, target: &server.challengePolicyHandler},
		{name: "HTTP policy", factory: config.HTTPPolicyHandlerFactory, target: &server.httpPolicyHandler},
		{name: "firewall action", factory: config.FirewallActionHandlerFactory, target: &server.firewallActionHandler},
		{name: "plugin webhook", factory: config.PluginWebhookHandlerFactory, target: &server.pluginWebhookHandler},
		{name: "plugin installation", factory: config.PluginInstallationHandlerFactory, target: &server.pluginInstallationHandler},
		{name: "DNS reconcile", factory: config.DNSReconcileHandlerFactory, target: &server.dnsReconcileHandler},
		{name: "market subscribe", factory: config.MarketSubscribeHandlerFactory, target: &server.marketSubscribeHandler},
		{name: "node scheduler", factory: config.NodeSchedulerHandlerFactory, target: &server.nodeSchedulerHandler},
		{name: "node isolation", factory: config.NodeIsolationHandlerFactory, target: &server.nodeIsolationHandler},
		{name: "certificate asset", factory: config.CertificateAssetHandlerFactory, target: &server.certificateAssetHandler},
		{name: "certificate publication status", factory: config.CertificatePublicationStatusHandlerFactory, target: &server.certificatePublicationStatusHandler},
		{name: "system configuration", factory: config.SystemConfigurationHandlerFactory, target: &server.systemConfigurationHandler},
		{name: "system settings", factory: config.SystemSettingsHandlerFactory, target: &server.systemSettingsHandler},
		{name: "brand assets", factory: config.BrandAssetHandlerFactory, target: &server.brandAssetHandler},
		{name: "themes", factory: config.ThemeHandlerFactory, target: &server.themeHandler},
		{name: "plugin ui", factory: config.PluginUIHandlerFactory, target: &server.pluginUIHandler},
		{name: "plugin providers", factory: config.PluginProviderHandlerFactory, target: &server.pluginProviderHandler},
		{name: "system cleanup settings", factory: config.SystemCleanupSettingsHandlerFactory, target: &server.systemCleanupSettingsHandler},
		{name: "system user settings", factory: config.SystemUserSettingsHandlerFactory, target: &server.systemUserSettingsHandler},
		{name: "system mail settings", factory: config.SystemMailSettingsHandlerFactory, target: &server.systemMailSettingsHandler},
		{name: "system other settings", factory: config.SystemOtherSettingsHandlerFactory, target: &server.systemOtherSettingsHandler},
		{name: "L4 line switch", factory: config.L4LineSwitchHandlerFactory, target: &server.l4LineSwitchHandler},
		{name: "custom RBAC", factory: config.CustomRBACHandlerFactory, target: &server.customRBACHandler},
		{name: "IP intelligence updates", factory: config.IPIntelUpdateHandlerFactory, target: &server.ipIntelUpdateHandler},
		{name: "migration import", factory: config.MigrateImportHandlerFactory, target: &server.migrateImportHandler},
		{name: "node gateway address change", factory: config.NodeGatewayAddressHandlerFactory, target: &server.nodeGatewayAddressHandler},
		{name: "dnspup probing", factory: config.ProbeDNSPupHandlerFactory, target: &server.probeDNSPupHandler},
		{name: "agent gateway registry", factory: config.GatewayRegistryHandlerFactory, target: &server.gatewayRegistryHandler},
		{name: "domain trust", factory: config.DomainTrustHandlerFactory, target: &server.domainTrustHandler},
		{name: "DNS hub", factory: config.DNSHubHandlerFactory, target: &server.dnsHubHandler},
		{name: "ticket", factory: config.TicketHandlerFactory, target: &server.ticketHandler},
		{name: "aggregated edge", factory: config.AggregatedEdgeHandlerFactory, target: &server.aggregatedEdgeHandler},
		{name: "node SSH install", factory: config.NodeSSHInstallHandlerFactory, target: &server.nodeSSHInstallHandler},
		{name: "account registration", factory: config.AccountRegistrationHandlerFactory, target: &server.accountRegistrationHandler},
		{name: "account login", factory: config.AccountLoginHandlerFactory, target: &server.accountLoginHandler},
		{name: "security coordination metrics", factory: config.SecurityCoordinationMetricsHandlerFactory, target: &server.securityCoordinationMetricsHandler},
		{name: "JA4 block", factory: config.JA4BlockHandlerFactory, target: &server.ja4BlockHandler},
		{name: "auto defense", factory: config.AutoDefenseHandlerFactory, target: &server.autoDefenseHandler},
		{name: "CC statistics", factory: config.CCStatsHandlerFactory, target: &server.ccStatsHandler},
		{name: "market security", factory: config.MarketSecurityHandlerFactory, target: &server.marketSecurityHandler},
		{name: "control upgrade plan", factory: config.ControlUpgradePlanHandlerFactory, target: &server.controlUpgradePlanHandler},
		{name: "entitlement refresh", factory: config.EntitlementRefreshHandlerFactory, target: &server.entitlementRefreshHandler},
	} {
		if server.initializationErr != nil || mounted.factory == nil {
			continue
		}
		handler, err := mounted.factory()
		if err != nil {
			server.initializationErr = fmt.Errorf("initialize %s handler: %w", mounted.name, err)
			break
		}
		if nilHTTPHandler(handler) {
			server.initializationErr = fmt.Errorf("initialize %s handler: factory returned nil handler", mounted.name)
			break
		}
		*mounted.target = handler
	}
	return server
}

func (s *Server) InitializationError() error {
	return s.initializationErr
}

func (s *Server) Handler() http.Handler {
	mux := http.NewServeMux()
	mux.HandleFunc("GET /health/live", s.handleLive)
	mux.HandleFunc("GET /health/ready", s.handleReady)
	mux.HandleFunc("POST /v1/auth/login", s.handleLogin)
	mux.HandleFunc("POST /v1/auth/login-captchas", s.handleIssueLoginCaptcha)
	mux.HandleFunc("POST /v1/auth/session-region-verifications", s.handleVerifySessionRegion)
	mux.HandleFunc("GET /v1/admin/admin-access-policy", s.handleGetAdminAccessPolicy)
	mux.HandleFunc("GET /v1/admin/inbox", s.handleAdminInboxList)
	mux.HandleFunc("GET /v1/tenant/members", s.handleListTenantMembers)
	mux.HandleFunc("GET /v1/admin/inbox/unread-count", s.handleAdminInboxUnread)
	mux.HandleFunc("POST /v1/admin/inbox/{message_id}/read", s.handleAdminInboxRead)
	mux.HandleFunc("POST /v1/admin/inbox/read-all", s.handleAdminInboxReadAll)
	mux.HandleFunc("GET /v1/account/inbox", s.handleAdminInboxList)
	mux.HandleFunc("GET /v1/account/inbox/unread-count", s.handleAdminInboxUnread)
	mux.HandleFunc("POST /v1/account/inbox/{message_id}/read", s.handleAdminInboxRead)
	mux.HandleFunc("POST /v1/account/inbox/read-all", s.handleAdminInboxReadAll)
	mux.HandleFunc("PUT /v1/admin/admin-access-policy", s.handleUpdateAdminAccessPolicy)
	mux.HandleFunc("POST /v1/auth/refresh", s.handleRefresh)
	mux.HandleFunc("POST /v1/auth/logout", s.handleLogout)
	mux.HandleFunc("GET /v1/auth/me", passwordChangeExempt(s.handleMe))
	mux.HandleFunc("GET /v1/installation-lock", passwordChangeExempt(s.handleInstallationLock))
	mux.HandleFunc("POST /v1/installation-lock/check", passwordChangeExempt(s.handleInstallationLockCheck))
	mux.HandleFunc("GET /v1/modules", s.handleListModules)
	mux.HandleFunc("GET /v1/runtime-features", s.handleRuntimeFeatures)
	if s.adminDashboardHandler != nil {
		mux.Handle("GET /v1/admin/dashboard", s.adminDashboardHandler)
		mux.Handle("GET /v1/dashboard", s.tenantDashboardHandler)
	}
	mux.HandleFunc("GET /v1/admin/users", s.handleListManagedUsers)
	mux.HandleFunc("GET /v1/admin/tenant-scopes", s.handleListTenantScopes)
	mux.HandleFunc("POST /v1/admin/users", s.handleCreateManagedUser)
	mux.HandleFunc("PATCH /v1/admin/users", s.handleBatchUpdateManagedUsers)
	mux.HandleFunc("GET /v1/admin/user-groups", s.handleListUserGroups)
	mux.HandleFunc("POST /v1/admin/user-groups", s.handleCreateUserGroup)
	mux.HandleFunc("PATCH /v1/admin/user-groups/{id}", s.handleUpdateUserGroup)
	mux.HandleFunc("DELETE /v1/admin/user-groups/{id}", s.handleDeleteUserGroup)
	mux.HandleFunc("GET /v1/admin/users/{id}", s.handleGetManagedUser)
	mux.HandleFunc("GET /v1/admin/users/{id}/login-security", s.handleGetManagedUserLoginSecurity)
	mux.HandleFunc("PUT /v1/admin/users/{id}/login-security", s.handleUpdateManagedUserLoginSecurity)
	mux.HandleFunc("GET /v1/admin/users/{id}/secondary-verification", s.handleGetManagedUserSecondaryVerification)
	mux.HandleFunc("PUT /v1/admin/users/{id}/secondary-verification", s.handleUpdateManagedUserSecondaryVerification)
	mux.HandleFunc("PATCH /v1/admin/users/{id}", s.handleUpdateManagedUser)
	mux.HandleFunc("DELETE /v1/admin/users/{id}", s.handleDeleteManagedUser)
	mux.HandleFunc("GET /v1/account/profile", s.handleGetAccountProfile)
	mux.HandleFunc("PATCH /v1/account/profile", s.handleUpdateAccountProfile)
	mux.HandleFunc("POST /v1/account/password", passwordChangeExempt(s.handleChangeAccountPassword))
	mux.HandleFunc("GET /v1/account/api-keys", s.handleListSelfAPIKeys)
	mux.HandleFunc("POST /v1/account/api-keys", s.handleCreateSelfAPIKey)
	mux.HandleFunc("GET /v1/account/api-keys/{key_id}", s.handleGetSelfAPIKey)
	mux.HandleFunc("PATCH /v1/account/api-keys/{key_id}", s.handleUpdateSelfAPIKey)
	mux.HandleFunc("POST /v1/account/api-keys/{key_id}/activate", s.handleActivateSelfAPIKey)
	mux.HandleFunc("POST /v1/account/api-keys/{key_id}/rotate", s.handleRotateSelfAPIKey)
	mux.HandleFunc("POST /v1/account/api-keys/{key_id}/revoke", s.handleRevokeSelfAPIKey)
	mux.HandleFunc("GET /v1/admin/users/{user_id}/api-keys", s.handleAdminListUserAPIKeys)
	mux.HandleFunc("POST /v1/admin/users/{user_id}/api-keys", s.handleAdminCreateUserAPIKey)
	mux.HandleFunc("POST /v1/admin/users/{user_id}/api-keys/{key_id}/revoke", s.handleAdminRevokeUserAPIKey)
	mux.HandleFunc("POST /v1/nodes", s.handleCreateNode)
	mux.HandleFunc("GET /v1/nodes/registration-credential", s.handleGetNodeRegistrationCredential)
	mux.HandleFunc("POST /v1/nodes/registration-credential/reset", s.handleResetNodeRegistrationCredential)
	mux.HandleFunc("POST /v1/node-registrations", s.handleRegisterNode)
	mux.HandleFunc("POST /v1/node-registrations/identity", s.handleRecoverNodeRegistrationIdentity)
	mux.HandleFunc("GET /v1/nodes", s.handleListNodes)
	mux.HandleFunc("GET /v1/nodes/{id}", s.handleGetNode)
	mux.HandleFunc("GET /v1/nodes/{id}/configuration-scopes", s.handleGetNodeConfigurationScopes)
	mux.HandleFunc("GET /v1/nodes/{id}/ip-location", s.handleGetNodeIPLocation)
	mux.HandleFunc("GET /v1/nodes/metrics/latest", s.handleGetLatestNodeMetricsBatch)
	mux.HandleFunc("GET /v1/nodes/installation-tickets", s.handleGetNodeInstallationTickets)
	mux.HandleFunc("GET /v1/nodes/monitoring/latest", s.handleGetLatestNodeMonitoring)
	mux.HandleFunc("GET /v1/nodes/{id}/metrics/latest", s.handleGetLatestNodeMetrics)
	mux.HandleFunc("GET /v1/nodes/{id}/metrics/history", s.handleGetNodeMetricsHistory)
	mux.HandleFunc("GET /v1/nodes/{id}/monitoring/history", s.handleGetNodeMonitoringHistory)
	mux.HandleFunc("GET /v1/nodes/{id}/monitoring/override", s.handleGetNodeMonitoringOverride)
	mux.HandleFunc("PUT /v1/nodes/{id}/monitoring/override", s.handlePutNodeMonitoringOverride)
	mux.HandleFunc("GET /v1/nodes/{id}/serving/events", s.handleGetNodeServingEvents)
	mux.HandleFunc("GET /v1/nodes/serving/events", s.handleListScopeServingEvents)
	mux.HandleFunc("GET /v1/monitor/node/top", s.handleGetNodeRealtimeTop)
	mux.HandleFunc("GET /v1/monitor/node/realtime", s.handleGetNodeRealtimeSeries)
	mux.HandleFunc("GET /v1/node-traffic", s.handleGetNodeTraffic)
	mux.HandleFunc("PATCH /v1/nodes/{id}", s.handleUpdateNode)
	mux.HandleFunc("POST /v1/nodes/{id}/enrollment-tokens", s.handleIssueEnrollmentToken)
	mux.HandleFunc("POST /v1/nodes/{id}/gateway-port-transitions", s.handleCreateNodePortTransition)
	mux.HandleFunc("GET /v1/nodes/{id}/gateway-port-transitions/{transition_id}", s.handleGetNodePortTransition)
	mux.HandleFunc("POST /v1/nodes/{id}/gateway-port-transitions/{transition_id}/finalize", s.handleFinalizeNodePortTransition)
	mux.HandleFunc("POST /v1/nodes/{id}/gateway-port-transitions/{transition_id}/rollback", s.handleRollbackNodePortTransition)
	mux.HandleFunc("POST /v1/nodes/batch-admin-state", s.handleBatchNodeAdminState)
	mux.HandleFunc("POST /v1/sites", s.handleCreateSite)
	mux.HandleFunc("GET /v1/sites", s.handleListSites)
	mux.HandleFunc("GET /v1/sites/export", s.handleExportSiteDomains)
	mux.HandleFunc("POST /v1/sites/batch-action", s.handleBatchSiteAction)
	mux.HandleFunc("GET /v1/sites/{id}/origin-routing", s.handleGetSiteConditionalOrigin)
	mux.HandleFunc("PUT /v1/sites/{id}/origin-routing", s.handlePutSiteConditionalOrigin)
	mux.HandleFunc("GET /v1/sites/{id}/schedule302", s.handleGetSiteSchedule302)
	mux.HandleFunc("PUT /v1/sites/{id}/schedule302", s.handlePutSiteSchedule302)
	mux.HandleFunc("POST /v1/sites/{id}/auto-dns/sync", s.handleSyncSiteAutoDNS)
	mux.HandleFunc("POST /v1/sites/{id}/access-check", s.handleCheckSiteAccess)
	mux.HandleFunc("GET /v1/site-defaults", s.handleListSiteDefaults)
	mux.HandleFunc("POST /v1/site-defaults", s.handleCreateSiteDefault)
	mux.HandleFunc("PATCH /v1/site-defaults/{id}", s.handleUpdateSiteDefault)
	mux.HandleFunc("DELETE /v1/site-defaults/{id}", s.handleDeleteSiteDefault)
	mux.HandleFunc("GET /v1/sites/{id}", s.handleGetSite)
	mux.HandleFunc("PATCH /v1/sites/{id}", s.handleUpdateSite)
	mux.HandleFunc("DELETE /v1/sites/{id}", s.handleDeleteSite)
	mux.HandleFunc("POST /v1/sites/{id}/lock", s.handleLockSite)
	mux.HandleFunc("POST /v1/sites/{id}/transfer", s.handleTransferSite)
	mux.HandleFunc("POST /v1/sites/{id}/unlock", s.handleUnlockSite)
	mux.HandleFunc("GET /v1/admin/site-groups", s.handleListAdminSiteGroups)
	mux.HandleFunc("GET /v1/site-groups", s.handleListSiteGroups)
	mux.HandleFunc("POST /v1/site-groups", s.handleCreateSiteGroup)
	mux.HandleFunc("GET /v1/site-groups/{id}", s.handleGetSiteGroup)
	mux.HandleFunc("PATCH /v1/site-groups/{id}", s.handleRenameSiteGroup)
	mux.HandleFunc("DELETE /v1/site-groups/{id}", s.handleDeleteSiteGroup)
	mux.HandleFunc("POST /v1/streams", s.handleCreateStream)
	mux.HandleFunc("POST /v1/streams/batch", s.handleBatchCreateStreams)
	mux.HandleFunc("POST /v1/streams/batch-action", s.handleBatchStreamAction)
	mux.HandleFunc("GET /v1/streams", s.handleListStreams)
	mux.HandleFunc("GET /v1/streams/{id}", s.handleGetStream)
	mux.HandleFunc("PATCH /v1/streams/{id}", s.handleUpdateStream)
	mux.HandleFunc("DELETE /v1/streams/{id}", s.handleDeleteStream)
	if s.streamLive != nil {
		mux.HandleFunc("GET /v1/l4-live-connections", s.handleAllLiveConnections)
		mux.HandleFunc("GET /v1/streams/{id}/live-connections", s.handleStreamLiveConnections)
		mux.HandleFunc("POST /v1/streams/{id}/live-connections/close", s.handleCloseStreamLiveConnections)
	}
	mux.HandleFunc("GET /v1/stream-groups", s.handleListStreamGroups)
	mux.HandleFunc("POST /v1/stream-groups", s.handleCreateStreamGroup)
	mux.HandleFunc("PATCH /v1/stream-groups/{id}", s.handleUpdateStreamGroup)
	mux.HandleFunc("DELETE /v1/stream-groups/{id}", s.handleDeleteStreamGroup)
	mux.HandleFunc("GET /v1/user-configs", s.handleListUserConfigs)
	mux.HandleFunc("GET /v1/user-configs/effective", s.handleEffectiveUserConfigs)
	mux.HandleFunc("POST /v1/user-configs", s.handleCreateUserConfig)
	mux.HandleFunc("DELETE /v1/user-configs/{id}", s.handleDeleteUserConfig)
	mux.HandleFunc("POST /v1/admin/control-upgrade-checks", s.handleControlUpgradeCheck)
	mux.HandleFunc("POST /v1/admin/control-upgrade-rollouts", s.handleCreateControlUpgradeRollout)
	mux.HandleFunc("GET /v1/admin/control-upgrade-rollouts", s.handleListControlUpgradeRollouts)
	mux.HandleFunc("GET /v1/admin/maintenance-upgrade-status", s.handleMaintenanceUpgradeStatus)
	mux.HandleFunc("GET /v1/admin/control-upgrade-rollouts/{id}", s.handleGetControlUpgradeRollout)
	mux.HandleFunc("POST /v1/admin/control-upgrade-rollouts/{id}/start", s.handleStartControlUpgradeRollout)
	mux.HandleFunc("POST /v1/admin/control-upgrade-rollouts/{id}/pause", s.handlePauseControlUpgradeRollout)
	mux.HandleFunc("POST /v1/admin/control-upgrade-rollouts/{id}/resume", s.handleResumeControlUpgradeRollout)
	mux.HandleFunc("POST /v1/admin/control-upgrade-rollouts/{id}/rollback", s.handleRollbackControlUpgradeRollout)
	mux.HandleFunc("POST /v1/dns/providers", s.handleCreateDNSProvider)
	mux.HandleFunc("GET /v1/dns/providers", s.handleListDNSProviders)
	mux.HandleFunc("PATCH /v1/dns/providers/{id}", s.handleUpdateDNSProvider)
	mux.HandleFunc("DELETE /v1/dns/providers/{id}", s.handleDeleteDNSProvider)
	mux.HandleFunc("POST /v1/dns/providers/{id}/verify", s.handleVerifyDNSProvider)
	mux.HandleFunc("GET /v1/dns/settings", s.handleGetDNSSettings)
	mux.HandleFunc("PATCH /v1/dns/settings", s.handleUpdateDNSSettings)
	mux.HandleFunc("POST /v1/dns/settings/{kind}", s.handleStartDNSOperation)
	mux.HandleFunc("GET /v1/dns/settings/operations/{operation_id}", s.handleGetDNSOperation)
	mux.HandleFunc("GET /v1/dns/platform-config", s.handleGetPlatformDNSConfig)
	mux.HandleFunc("PUT /v1/dns/platform-config", s.handleSavePlatformDNSConfig)
	mux.HandleFunc("POST /v1/dns/platform-config/{kind}", s.handleStartPlatformDNSOperation)
	mux.HandleFunc("POST /v1/dns/platform-config/connection-test", s.handleTestPlatformDNSConnection)
	mux.HandleFunc("GET /v1/dns/platform-zones", s.handleListPlatformDNSZones)
	mux.HandleFunc("POST /v1/dns/platform-zones", s.handleCreatePlatformDNSZone)
	mux.HandleFunc("PATCH /v1/dns/platform-zones/{id}", s.handleUpdatePlatformDNSZone)
	mux.HandleFunc("DELETE /v1/dns/platform-zones/{id}", s.handleDeletePlatformDNSZone)
	mux.HandleFunc("POST /v1/dns/zones", s.handleCreateDNSZone)
	mux.HandleFunc("GET /v1/dns/zones", s.handleListDNSZones)
	mux.HandleFunc("DELETE /v1/dns/zones/{id}", s.handleDeleteDNSZone)
	mux.HandleFunc("POST /v1/dns/records", s.handleCreateDNSRecord)
	mux.HandleFunc("GET /v1/dns/records", s.handleListDNSRecords)
	mux.HandleFunc("PATCH /v1/dns/records/{id}", s.handleUpdateDNSRecord)
	mux.HandleFunc("DELETE /v1/dns/records/{id}", s.handleDeleteDNSRecord)
	mux.HandleFunc("POST /v1/certificate-orders", s.handleCreateCertificateOrder)
	mux.HandleFunc("GET /v1/certificate-orders", s.handleListCertificateOrders)
	mux.HandleFunc("GET /v1/certificate-issuers", s.handleListCertificateIssuers)
	mux.HandleFunc("GET /v1/certificate-defaults", s.handleGetCertificateDefaults)
	mux.HandleFunc("PATCH /v1/certificate-defaults", s.handleUpdateCertificateDefaults)
	mux.HandleFunc("GET /v1/admin/acme-ca-credentials", s.handleListACMECACredentials)
	mux.HandleFunc("PUT /v1/admin/acme-ca-credentials/{ca}", s.handlePutACMECACredential)
	mux.HandleFunc("POST /v1/admin/acme-ca-credentials/zerossl/eab-from-email", s.handleFetchZeroSSLEAB)
	mux.HandleFunc("POST /v1/security-policies", s.handleCreateSecurityPolicy)
	mux.HandleFunc("GET /v1/security-policies", s.handleListSecurityPolicies)
	mux.HandleFunc("GET /v1/security-policies/catalog-rules", s.handleSecurityPolicyCatalogRules)
	mux.HandleFunc("GET /v1/security-policies/ip-intel-status", s.handleIPIntelReadiness)
	mux.HandleFunc("GET /v1/security-policies/crs-profiles", s.handleCRSProfiles)
	mux.HandleFunc("POST /v1/security-policies/batch", s.handleBatchSecurityPolicies)
	mux.HandleFunc("GET /v1/waf-rule-libraries", s.handleListWAFRuleLibraries)
	mux.HandleFunc("POST /v1/waf-rule-libraries/{id}/subscribe", s.handleSubscribeWAFRuleLibrary)
	mux.HandleFunc("DELETE /v1/waf-rule-libraries/{id}/subscription", s.handleUnsubscribeWAFRuleLibrary)
	mux.HandleFunc("POST /v1/waf-rule-libraries/subscriptions/refresh", s.handleRefreshWAFRuleLibraries)
	mux.HandleFunc("GET /v1/waf-rule-libraries/pending-publications", s.handleListWAFPendingPublications)
	mux.HandleFunc("GET /v1/waf-rule-subscriptions", s.handleListWAFRuleSubscriptions)
	mux.HandleFunc("POST /v1/waf-rule-subscriptions", s.handleCreateWAFRuleSubscription)
	mux.HandleFunc("PATCH /v1/waf-rule-subscriptions/{id}", s.handleUpdateWAFRuleSubscription)
	mux.HandleFunc("DELETE /v1/waf-rule-subscriptions/{id}", s.handleDeleteWAFRuleSubscription)
	mux.HandleFunc("POST /v1/waf-rule-subscriptions/{id}/sync", s.handleSyncWAFRuleSubscription)
	mux.HandleFunc("GET /v1/waf-rule-subscriptions/packs", s.handleListWAFSubscriptionPacks)
	mux.HandleFunc("GET /v1/waf-rule-subscriptions/available", s.handleListTenantWAFRuleSubscriptions)
	mux.HandleFunc("POST /v1/waf-rule-subscriptions/{id}/subscribe", s.handleSubscribeWAFRuleSubscription)
	mux.HandleFunc("DELETE /v1/waf-rule-subscriptions/{id}/subscription", s.handleUnsubscribeWAFRuleSubscription)
	mux.HandleFunc("GET /v1/rule-packs", s.handleRulePackView)
	mux.HandleFunc("POST /v1/rule-packs", s.handleImportRulePack)
	mux.HandleFunc("PATCH /v1/rule-packs", s.handleUpdateRulePack)
	mux.HandleFunc("DELETE /v1/rule-packs/versions", s.handleDeleteRulePackVersion)
	mux.HandleFunc("PUT /v1/rule-packs/enablements", s.handlePutRulePackEnablement)
	mux.HandleFunc("GET /v1/sites/{id}/security-mounts", s.handleGetSiteSecurityMounts)
	mux.HandleFunc("POST /v1/sites/{id}/security-mounts/publish", s.handlePublishSiteSecurityMounts)
	mux.HandleFunc("POST /v1/security-policies/matchers", func(w http.ResponseWriter, r *http.Request) {
		s.handleCreateCCReference(w, r, ccreference.KindMatcher)
	})
	mux.HandleFunc("GET /v1/security-policies/matchers", s.handleListCCMatchers)
	mux.HandleFunc("GET /v1/security-policies/matchers/{id}", func(w http.ResponseWriter, r *http.Request) {
		s.handleGetCCReference(w, r, ccreference.KindMatcher)
	})
	mux.HandleFunc("PATCH /v1/security-policies/matchers/{id}", func(w http.ResponseWriter, r *http.Request) {
		s.handleUpdateCCReference(w, r, ccreference.KindMatcher)
	})
	mux.HandleFunc("DELETE /v1/security-policies/matchers/{id}", func(w http.ResponseWriter, r *http.Request) {
		s.handleDeleteCCReference(w, r, ccreference.KindMatcher)
	})
	mux.HandleFunc("POST /v1/security-policies/matchers/{id}/enable", func(w http.ResponseWriter, r *http.Request) {
		s.handleSetCCReferenceEnabled(w, r, ccreference.KindMatcher, true)
	})
	mux.HandleFunc("POST /v1/security-policies/matchers/{id}/disable", func(w http.ResponseWriter, r *http.Request) {
		s.handleSetCCReferenceEnabled(w, r, ccreference.KindMatcher, false)
	})
	mux.HandleFunc("POST /v1/security-policies/filters", func(w http.ResponseWriter, r *http.Request) {
		s.handleCreateCCReference(w, r, ccreference.KindFilter)
	})
	mux.HandleFunc("GET /v1/security-policies/filters", s.handleListCCFilters)
	mux.HandleFunc("GET /v1/security-policies/filters/{id}", func(w http.ResponseWriter, r *http.Request) {
		s.handleGetCCReference(w, r, ccreference.KindFilter)
	})
	mux.HandleFunc("PATCH /v1/security-policies/filters/{id}", func(w http.ResponseWriter, r *http.Request) {
		s.handleUpdateCCReference(w, r, ccreference.KindFilter)
	})
	mux.HandleFunc("DELETE /v1/security-policies/filters/{id}", func(w http.ResponseWriter, r *http.Request) {
		s.handleDeleteCCReference(w, r, ccreference.KindFilter)
	})
	mux.HandleFunc("POST /v1/security-policies/filters/{id}/enable", func(w http.ResponseWriter, r *http.Request) {
		s.handleSetCCReferenceEnabled(w, r, ccreference.KindFilter, true)
	})
	mux.HandleFunc("POST /v1/security-policies/filters/{id}/disable", func(w http.ResponseWriter, r *http.Request) {
		s.handleSetCCReferenceEnabled(w, r, ccreference.KindFilter, false)
	})
	mux.HandleFunc("GET /v1/security-policies/{id}", s.handleGetSecurityPolicy)
	mux.HandleFunc("PATCH /v1/security-policies/{id}", s.handleUpdateSecurityPolicy)
	mux.HandleFunc("DELETE /v1/security-policies/{id}", s.handleDeleteSecurityPolicy)
	mux.HandleFunc("POST /v1/security-policies/{id}/evaluate", s.handleEvaluateSecurityPolicy)
	mux.HandleFunc("PUT /v1/security-policies/{id}/quick-block", s.handleSetSecurityPolicyQuickBlock)
	mux.HandleFunc("GET /v1/sites/{site_id}/quick-block", s.handleGetSiteQuickBlock)
	mux.HandleFunc("PUT /v1/sites/{site_id}/quick-block", s.handlePutSiteQuickBlock)
	for _, base := range []string{"/v1/security-bans", "/v1/admin/security-bans"} {
		mux.HandleFunc("GET "+base, s.handleListSecurityBans)
		mux.HandleFunc("POST "+base, s.handleCreateSecurityBan)
		mux.HandleFunc("POST "+base+"/{entry_id}/release", s.handleReleaseSecurityBan)
	}
	for _, base := range []string{"/v1/security-ip-lists", "/v1/admin/security-ip-lists"} {
		mux.HandleFunc("GET "+base, s.handleListSecurityIPLists)
		mux.HandleFunc("POST "+base, s.handleCreateSecurityIPList)
		mux.HandleFunc("PUT "+base+"/{list_id}", s.handleUpdateSecurityIPList)
		mux.HandleFunc("DELETE "+base+"/{list_id}", s.handleDeleteSecurityIPList)
	}
	mux.HandleFunc("GET /v1/sites/{site_id}/access", s.handleGetSiteAccess)
	mux.HandleFunc("PUT /v1/sites/{site_id}/access", s.handlePutSiteAccess)
	mux.HandleFunc("GET /v1/sites/{site_id}/crs", s.handleGetSiteCRS)
	mux.HandleFunc("PUT /v1/sites/{site_id}/crs", s.handlePutSiteCRS)
	mux.HandleFunc("GET /v1/sites/{site_id}/traffic-limit", s.handleGetSiteTrafficLimit)
	mux.HandleFunc("PUT /v1/sites/{site_id}/traffic-limit", s.handlePutSiteTrafficLimit)
	mux.HandleFunc("GET /v1/sites/{site_id}/origin-status", s.handleGetSiteOriginStatus)
	mux.HandleFunc("POST /v1/sites/{site_id}/origin-failback", s.handlePostSiteOriginFailback)
	mux.HandleFunc("POST /v1/url-auth-policies", s.handleCreateURLAuthPolicy)
	mux.HandleFunc("GET /v1/url-auth-policies", s.handleListURLAuthPolicies)
	mux.HandleFunc("GET /v1/url-auth-policies/{id}", s.handleGetURLAuthPolicy)
	mux.HandleFunc("PATCH /v1/url-auth-policies/{id}", s.handleUpdateURLAuthPolicy)
	mux.HandleFunc("POST /v1/url-auth-policies/{id}/rotate", s.handleRotateURLAuthPolicy)
	mux.HandleFunc("POST /v1/url-auth-policies/{id}/revoke", s.handleRevokeURLAuthPolicyKey)
	mux.HandleFunc("GET /v1/url-auth-policies/{id}/edge-snapshot", s.handleGetURLAuthPolicySnapshot)
	if s.analyticsHandler != nil {
		mux.Handle("/v1/admin/analytics/", http.HandlerFunc(s.handleAnalytics))
		mux.Handle("/v1/analytics/", http.HandlerFunc(s.handleAnalytics))
	} else {
		// Keep the canonical analytics routes visible when ClickHouse/analytics
		// is not configured. A 503 is actionable for the UI; a 404 would make a
		// dependency outage indistinguishable from a missing route. Do not claim
		// availability for neighboring log routes, which remain disabled unless
		// their dedicated handler is mounted below.
		for _, pattern := range []string{
			"GET /v1/admin/analytics/summary",
			"GET /v1/admin/analytics/blocked-ip-count",
			"GET /v1/admin/analytics/blocked-ip-trend",
			"GET /v1/admin/analytics/waf-overview",
			"GET /v1/admin/analytics/hourly-trend",
			"GET /v1/admin/analytics/site-realtime",
			"GET /v1/admin/analytics/top/",
			"GET /v1/analytics/summary",
			"GET /v1/analytics/blocked-ip-count",
			"GET /v1/analytics/blocked-ip-trend",
			"GET /v1/analytics/waf-overview",
			"GET /v1/analytics/hourly-trend",
			"GET /v1/analytics/site-realtime",
			"GET /v1/analytics/top/",
		} {
			mux.Handle(pattern, http.HandlerFunc(s.handleAnalytics))
		}
	}
	for _, pattern := range []string{
		"/v1/admin/analytics/site-quality-diagnostics",
		"/v1/analytics/site-quality-diagnostics",
	} {
		mux.Handle(pattern, http.HandlerFunc(s.handleAnalyticsDiagnostic))
	}
	if s.analyticsRealtimeHandler != nil {
		mux.Handle("/v1/analytics/site-monitoring", s.analyticsRealtimeHandler)
		mux.Handle("/v1/admin/analytics/site-monitoring", s.analyticsRealtimeHandler)
	}
	if s.l4AnalyticsHandler != nil {
		mux.Handle("GET /v1/analytics/l4-realtime", s.l4AnalyticsHandler)
		mux.Handle("GET /v1/admin/analytics/l4-realtime", s.l4AnalyticsHandler)
		mux.Handle("GET /v1/analytics/l4-session-logs", s.l4AnalyticsHandler)
		mux.Handle("GET /v1/admin/analytics/l4-session-logs", s.l4AnalyticsHandler)
	}
	if s.marketSubscribeHandler != nil {
		mountMarketSubscribe(mux, s.marketSubscribeHandler)
	}
	if s.dnsReconcileHandler != nil {
		mux.Handle("POST /v1/sites/{site_id}/dns-reconcile/dry-run", s.dnsReconcileHandler)
		mux.Handle("POST /v1/sites/{site_id}/dns-reconcile/apply", s.dnsReconcileHandler)
		mux.Handle("GET /v1/sites/{site_id}/dns-reconcile/tasks/{task_id}", s.dnsReconcileHandler)
		mux.Handle("POST /v1/sites/{site_id}/dns-reconcile/tasks/{task_id}/commit", s.dnsReconcileHandler)
		mux.Handle("POST /v1/sites/{site_id}/dns-reconcile/tasks/{task_id}/cancel", s.dnsReconcileHandler)
	}
	if s.analyticsLogsHandler != nil {
		for _, pattern := range []string{
			"/v1/admin/analytics/logs/access",
			"/v1/analytics/logs/access",
			"/v1/admin/analytics/logs/block-events",
			"/v1/analytics/logs/block-events",
			"/v1/admin/analytics/logs/blocks/current",
			"/v1/analytics/logs/blocks/current",
			"/v1/admin/analytics/logs/blocks/current-count",
			"/v1/analytics/logs/blocks/current-count",
			"/v1/admin/analytics/logs/blocks/history",
			"/v1/analytics/logs/blocks/history",
			"/v1/admin/analytics/logs/cc-bans",
			"/v1/analytics/logs/cc-bans",
		} {
			mux.Handle("GET "+pattern, http.HandlerFunc(s.handleAnalyticsLogs))
		}
		for _, pattern := range []string{
			"POST /v1/admin/analytics/logs/blocks/current/{block_id}/unlock",
			"POST /v1/analytics/logs/blocks/current/{block_id}/unlock",
		} {
			mux.Handle(pattern, http.HandlerFunc(s.handleAnalyticsLogs))
		}
		for _, prefix := range []string{
			"/v1/admin/analytics/logs",
			"/v1/analytics/logs",
		} {
			mux.Handle("GET "+prefix+"/access/exports", http.HandlerFunc(s.handleAnalyticsLogs))
			mux.Handle("POST "+prefix+"/access/exports", http.HandlerFunc(s.handleAnalyticsLogs))
			mux.Handle("GET "+prefix+"/access/exports/{export_id}", http.HandlerFunc(s.handleAnalyticsLogs))
			mux.Handle("POST "+prefix+"/access/exports/{export_id}/download-grants", http.HandlerFunc(s.handleAnalyticsLogs))
			mux.Handle("GET "+prefix+"/access/exports/{export_id}/download", http.HandlerFunc(s.handleAnalyticsLogs))
		}
	}
	if s.ccCoordinationHandler != nil {
		for _, pattern := range []string{
			"GET /v1/admin/analytics/logs/cc-coordination",
			"GET /v1/analytics/logs/cc-coordination",
			"POST /v1/admin/analytics/logs/cc-coordination/{state_id}/release",
			"POST /v1/analytics/logs/cc-coordination/{state_id}/release",
		} {
			mux.Handle(pattern, s.ccCoordinationHandler)
		}
	}
	if s.jobQueryHandler != nil {
		mux.Handle("/v1/admin/jobs", http.HandlerFunc(s.handleJobQuery))
		mux.Handle("/v1/admin/jobs/", http.HandlerFunc(s.handleJobQuery))
		mux.Handle("/v1/jobs", http.HandlerFunc(s.handleJobQuery))
		mux.Handle("/v1/jobs/", http.HandlerFunc(s.handleJobQuery))
	}
	if s.impersonationHandler != nil {
		for _, pattern := range []string{
			"POST /v1/admin/impersonation/grants",
			"POST /v1/admin/impersonation/exchanges",
			"POST /v1/admin/impersonation/grants/{grant_id}/revocations",
		} {
			mux.Handle(pattern, s.impersonationHandler)
		}
	}
	if s.cacheControlHandler != nil {
		for _, pattern := range []string{
			"/v1/cache-policies/{site_id}",
			"/v1/cache-policies/{site_id}/revisions",
			"/v1/cache-policies/{site_id}/revisions/{revision}",
			"/v1/cache-operations",
			"/v1/cache-operations/daily-usage",
			"/v1/cache-operations/target-sites",
			"/v1/cache-operations/carrying-nodes",
			"/v1/cache-operations/{operation_id}",
			"/v1/cache-operations/{operation_id}/retry",
			"/v1/cache-operations/{operation_id}/cancel",
			"/v1/cache-operations/{operation_id}/resubmit",
			"/v1/cache-operation-requests/{idempotency_key}",
			"/v1/admin/cache-policies/{site_id}",
			"/v1/admin/cache-policies/{site_id}/revisions",
			"/v1/admin/cache-policies/{site_id}/revisions/{revision}",
			"/v1/admin/cache-operations",
			"/v1/admin/cache-operations/daily-usage",
			"/v1/admin/cache-operations/target-sites",
			"/v1/admin/cache-operations/carrying-nodes",
			"/v1/admin/cache-operations/{operation_id}",
			"/v1/admin/cache-operations/{operation_id}/retry",
			"/v1/admin/cache-operations/{operation_id}/cancel",
			"/v1/admin/cache-operations/{operation_id}/resubmit",
			"/v1/admin/cache-operation-requests/{idempotency_key}",
		} {
			mux.Handle(pattern, http.HandlerFunc(s.handleCacheControl))
		}
	}
	if s.announcementHandler != nil {
		for _, pattern := range []string{
			"GET /v1/admin/announcements",
			"POST /v1/admin/announcements",
			"GET /v1/admin/announcements/global",
			"POST /v1/admin/announcements/global",
			"GET /v1/admin/announcements/global/audience-directory",
			"GET /v1/admin/announcements/global/{id}",
			"GET /v1/admin/announcements/global/{id}/audience/count",
			"PATCH /v1/admin/announcements/global/{id}",
			"POST /v1/admin/announcements/global/{id}/publish",
			"POST /v1/admin/announcements/global/{id}/withdraw",
			"POST /v1/admin/announcements/global/{id}/archive",
			"POST /v1/admin/announcements/global/{id}/restore",
			"GET /v1/admin/announcements/audience-directory",
			"GET /v1/admin/announcements/{id}",
			"GET /v1/admin/announcements/{id}/audience/count",
			"PATCH /v1/admin/announcements/{id}",
			"POST /v1/admin/announcements/{id}/schedule",
			"POST /v1/admin/announcements/{id}/publish",
			"POST /v1/admin/announcements/{id}/revise",
			"POST /v1/admin/announcements/{id}/withdraw",
			"POST /v1/admin/announcements/{id}/archive",
			"POST /v1/admin/announcements/{id}/restore",
			"GET /v1/account/messages",
			"POST /v1/account/messages/{event_id}/delivered",
			"POST /v1/account/messages/{event_id}/read",
		} {
			mux.Handle(pattern, http.HandlerFunc(s.handleAnnouncement))
		}
	}
	if s.notificationHandler != nil {
		for _, pattern := range []string{
			"/v1/admin/notifications/channels",
			"/v1/admin/notifications/policy",
			"/v1/admin/notifications/templates",
			"/v1/admin/notifications/templates/{template_id}/versions/{version}/{channel}",
			"/v1/admin/notifications/deliveries",
			"/v1/admin/notifications/delivery-history",
			"/v1/admin/notifications/deliveries/{outbox_id}/attempts",
			"/v1/admin/notifications/messages",
			"/v1/account/notification-messages",
			"/v1/account/notification-subscriptions/{event_type}",
		} {
			mux.Handle(pattern, http.HandlerFunc(s.handleNotification))
		}
	}
	for _, mounted := range []struct {
		handler     http.Handler
		patterns    []string
		preserveRaw bool
	}{
		{handler: s.observabilityLogHandler, patterns: []string{
			"GET /v1/observability/logs",
			"GET /v1/observability/logs/export",
			"POST /v1/observability/frontend-events",
		}},
		{handler: s.auditLogHandler, patterns: []string{
			"GET /v1/audit-logs",
			"GET /v1/audit-logs/export",
			"GET /v1/audit-logs/categories",
		}},
		{handler: s.backupHistoryHandler, patterns: []string{
			"GET /v1/admin/system-backup-runs",
		}},
		{handler: s.controlBackupHandler, patterns: []string{
			"/v1/admin/control-backup",
			"/v1/admin/control-backup/",
		}},
		{handler: s.analyticsConnectionsRetentionHandler, patterns: []string{
			"/v1/analytics/connections/retention",
			"/v1/admin/analytics/connections/retention",
		}},
		{handler: s.analyticsConnectionsDLQHandler, patterns: []string{
			"/v1/analytics/connections/dead-letters",
			"/v1/analytics/connections/dead-letters/{dead_letter_id}",
			"/v1/admin/analytics/connections/dead-letters",
			"/v1/admin/analytics/connections/dead-letters/{dead_letter_id}",
		}},
		{handler: s.siteCaptureHandler, patterns: []string{
			"/v1/tenant-scopes/{scope_id}/sites/{site_id}/telemetry-capture-policy",
		}},
		{handler: s.errorPageHandler, preserveRaw: true, patterns: []string{
			"/v1/error-pages/assets/initiate",
			"/v1/error-pages/assets",
			"/v1/error-pages/assets/{asset_id}",
			"/v1/error-pages/assets/{asset_id}/content",
			"/v1/error-pages/assets/{asset_id}/finalize",
			"/v1/error-pages/rules",
			"/v1/error-pages/rules/{rule_id}",
			"/v1/error-pages/rules/{rule_id}/enable",
			"/v1/error-pages/rules/{rule_id}/disable",
			"/v1/error-pages/slots",
			"/v1/error-pages/slots/{slot_key}",
			"/v1/error-pages/scope-overrides",
			"/v1/error-pages/scope-overrides/{override_display_id}",
			"/v1/error-pages/publication-snapshot",
		}},
		{handler: s.customRBACHandler, preserveRaw: true, patterns: []string{
			"/v1/custom-rbac/permissions",
			"/v1/custom-rbac/roles",
			"/v1/custom-rbac/roles/{role_id}",
			"/v1/custom-rbac/roles/{role_id}/rename",
			"/v1/custom-rbac/roles/{role_id}/publish",
			"/v1/custom-rbac/roles/{role_id}/deactivate",
			"/v1/custom-rbac/grants",
			"/v1/custom-rbac/grants/{grant_id}/revoke",
		}},
		{handler: s.identityVerificationHandler, patterns: []string{
			"/v1/identity-verification/status",
			"/v1/identity-verification/cases",
			"/v1/identity-verification/cases/{case_id}",
			"/v1/identity-verification/cases/{case_id}/submit",
			"/v1/identity-verification/cases/{case_id}/withdraw",
			"/v1/identity-verification/cases/{case_id}/expire",
			"/v1/identity-verification/provider-sessions",
			"/v1/identity-verification/provider-sessions/{session_id}/uploads",
			"/v1/identity-verification/provider-sessions/{session_id}/uploads/{upload_id}/finalize",
			"/v1/identity-verification/provider-callbacks/{provider}",
			"/v1/identity-verification/reviewer/cases",
			"/v1/identity-verification/reviewer/cases/{case_id}",
			"/v1/identity-verification/reviewer/cases/{case_id}/claim",
			"/v1/identity-verification/reviewer/cases/{case_id}/decision",
			"/v1/identity-verification/admin/cases",
		}},
		{handler: s.identitySessionHandler, patterns: []string{
			"GET /v1/identity/sessions",
			"DELETE /v1/identity/session-families/{family_id}",
		}},
		{handler: s.mfaHandler, patterns: []string{"/v1/account/mfa", "/v1/account/mfa/"}},
		{handler: s.originAuthHandler, patterns: []string{
			"/v1/tenant-scopes/{tenant_scope_id}/origin-auth",
			"/v1/tenant-scopes/{tenant_scope_id}/origin-auth/",
		}},
		{handler: s.originAuthPublicationHandler, patterns: []string{
			"POST /v1/tenant-scopes/{tenant_scope_id}/origin-auth/edge-publications",
			"GET /v1/tenant-scopes/{tenant_scope_id}/origin-auth/edge-publications/{publication_id}",
		}},
		{handler: s.errorPagePublicationHandler, patterns: []string{
			"POST /v1/tenant-scopes/{tenant_scope_id}/error-page-publications",
			"GET /v1/tenant-scopes/{tenant_scope_id}/error-page-publications/{publication_id}",
		}},
		// PA-16 IP intelligence updates (internal/ipintelupdate.Patterns).
		{handler: s.ipIntelUpdateHandler, patterns: []string{
			"GET /v1/admin/ip-intel-updates",
			"PUT /v1/admin/ip-intel-updates",
			"POST /v1/admin/ip-intel-updates/tests",
			"POST /v1/admin/ip-intel-updates/checks",
		}},
		// fix-nodegw 更换主控连接地址 (internal/nodegatewayaddr).
		{handler: s.nodeGatewayAddressHandler, patterns: []string{
			"GET /v1/admin/node-gateway-address-changes",
			"POST /v1/admin/node-gateway-address-changes",
			"GET /v1/admin/node-gateway-address-changes/{id}",
			"POST /v1/admin/node-gateway-address-changes/{id}/retry",
		}},
		// ADR 0016 migration import (internal/migrateimport/job.Patterns).
		{handler: s.migrateImportHandler, patterns: []string{
			"GET /v1/admin/migrate-imports",
			"POST /v1/admin/migrate-imports",
			"GET /v1/admin/migrate-imports/{id}",
			"GET /v1/admin/migrate-imports/{id}/items",
			"PUT /v1/admin/migrate-imports/{id}/options",
			"POST /v1/admin/migrate-imports/{id}/confirm",
			"POST /v1/admin/migrate-imports/{id}/pause",
			"POST /v1/admin/migrate-imports/{id}/resume",
			"POST /v1/admin/migrate-imports/{id}/cancel",
			"GET /v1/admin/migrate-imports/{id}/balances",
			"POST /v1/admin/migrate-imports/{id}/balances/decision",
			"GET /v1/admin/migrate-import-templates/{section}",
			"GET /v1/admin/migrate-import-legacy-passwords",
			"POST /v1/admin/migrate-import-legacy-passwords/clear",
		}},
		// dnspup probing (internal/dnspupprobe.Patterns).
		{handler: s.probeDNSPupHandler, patterns: []string{
			"GET /v1/admin/probe-dnspup",
			"PUT /v1/admin/probe-dnspup",
			"POST /v1/admin/probe-dnspup/tests",
			"GET /v1/admin/probe-dnspup/node-monitoring",
			"PUT /v1/admin/probe-dnspup/node-monitoring",
		}},
		// Agent Gateway registry (internal/gatewayregistry.Patterns); the
		// binding route is public, its body token is the credential.
		{handler: s.gatewayRegistryHandler, patterns: []string{
			"GET /v1/admin/gateways",
			"POST /v1/admin/gateways",
			"POST /v1/admin/gateways/{id}/binding-token",
			"POST /v1/admin/gateways/{id}/disable",
			"POST /v1/admin/gateways/{id}/enable",
			"DELETE /v1/admin/gateways/{id}",
			"POST /v1/gateway-bindings/complete",
			"PUT /v1/admin/gateways/{id}/allowed-ips",
			"GET /v1/admin/gateway-settings",
			"PUT /v1/admin/gateway-settings",
		}},
		// G6 domain trust (internal/domaintrusthttp.Patterns).
		{handler: s.domainTrustHandler, patterns: []string{
			"GET /v1/domain-ownerships",
			"POST /v1/domain-ownerships",
			"POST /v1/domain-ownerships/check",
			"POST /v1/domain-ownerships/revoke",
			"GET /v1/domain-ownerships/conflicts",
			"POST /v1/domain-ownerships/claims",
			"GET /v1/domain-ownerships/suspensions",
			"GET /v1/admin/domain-blocklist",
			"POST /v1/admin/domain-blocklist",
			"PUT /v1/admin/domain-blocklist/{id}",
			"DELETE /v1/admin/domain-blocklist/{id}",
			"POST /v1/admin/domain-blocklist/import",
			"GET /v1/admin/domain-blocklist/export",
			"GET /v1/admin/domain-blocklist/hits",
			"GET /v1/admin/domain-ownerships",
			"POST /v1/admin/domain-ownerships/{id}/revoke",
			"GET /v1/admin/domain-claim-suspensions",
			"POST /v1/admin/domain-claim-suspensions/{id}/release",
		}},
		// ADR 0020 §3 用户端域名解析 (internal/dnshubhttp.Patterns).
		{handler: s.dnsHubHandler, patterns: []string{
			"GET /v1/dns/hub/domains",
			"POST /v1/dns/hub/domains/refresh",
			"GET /v1/dns/hub/domains/{provider_id}/{apex}/records",
			"POST /v1/dns/hub/domains/{provider_id}/{apex}/records",
			"PATCH /v1/dns/hub/domains/{provider_id}/{apex}/records/{record_ref}",
			"DELETE /v1/dns/hub/domains/{provider_id}/{apex}/records/{record_ref}",
			"POST /v1/dns/hub/records/batch",
		}},
		// G6 #9 support tickets (internal/tickets.Patterns). Attachment
		// uploads are raw bodies, so the request is forwarded unchanged.
		{handler: s.ticketHandler, preserveRaw: true, patterns: []string{
			"GET /v1/tickets", "POST /v1/tickets", "GET /v1/tickets/summary",
			"POST /v1/tickets/attachments", "GET /v1/tickets/attachments/{id}",
			"GET /v1/tickets/{id}", "POST /v1/tickets/{id}/messages",
			"POST /v1/tickets/{id}/close", "POST /v1/tickets/{id}/reopen",
			"GET /v1/admin/tickets", "POST /v1/admin/tickets", // 管理端代用户新建
			"GET /v1/admin/tickets/summary", "GET /v1/admin/tickets/assignees",
			"POST /v1/admin/tickets/attachments", "GET /v1/admin/tickets/attachments/{id}",
			"GET /v1/admin/tickets/{id}", "PATCH /v1/admin/tickets/{id}", "POST /v1/admin/tickets/{id}/messages",
			"DELETE /v1/admin/tickets/{id}", // 软删除（迁移 543）
		}},
		// ADR 0008 aggregated edge (internal/aggregatededge.Patterns): third-party
		// CDN accounts, supplies and site sync, behind module.aggregated_edge.
		{handler: s.aggregatedEdgeHandler, patterns: []string{
			"GET /v1/admin/aggregated-edge/providers",
			"GET /v1/admin/aggregated-edge/runtime",
			"GET /v1/admin/aggregated-edge/accounts",
			"POST /v1/admin/aggregated-edge/accounts",
			"POST /v1/admin/aggregated-edge/accounts/rewrap",
			"GET /v1/admin/aggregated-edge/accounts/{id}",
			"PUT /v1/admin/aggregated-edge/accounts/{id}",
			"DELETE /v1/admin/aggregated-edge/accounts/{id}",
			"POST /v1/admin/aggregated-edge/accounts/{id}/verify",
			"GET /v1/admin/aggregated-edge/supplies",
			"POST /v1/admin/aggregated-edge/supplies",
			"GET /v1/admin/aggregated-edge/supplies/{id}",
			"PUT /v1/admin/aggregated-edge/supplies/{id}",
			"POST /v1/admin/aggregated-edge/supplies/{id}/retire",
			"POST /v1/admin/aggregated-edge/supplies/{id}/sites",
			"GET /v1/admin/aggregated-edge/supplies/{id}/sites/{site_id}",
			"DELETE /v1/admin/aggregated-edge/supplies/{id}/sites/{site_id}",
			"POST /v1/admin/aggregated-edge/supplies/{id}/sites/{site_id}/sync",
			"POST /v1/admin/aggregated-edge/supplies/{id}/sites/{site_id}/observe",
			"POST /v1/admin/aggregated-edge/zones",
			"GET /v1/admin/aggregated-edge/imports",
			"POST /v1/admin/aggregated-edge/imports",
			"GET /v1/admin/aggregated-edge/imports/{id}",
			"DELETE /v1/admin/aggregated-edge/imports/{id}",
			"POST /v1/admin/aggregated-edge/imports/{id}/refresh",
			"GET /v1/admin/aggregated-edge/imports/{id}/migrations",
			"POST /v1/admin/aggregated-edge/imports/{id}/migrations",
			"POST /v1/admin/aggregated-edge/migrations/{id}/confirm",
			"POST /v1/admin/aggregated-edge/migrations/{id}/cancel",
			"POST /v1/admin/aggregated-edge/migrations/{id}/restore",
			"PUT /v1/admin/aggregated-edge/accounts/{id}/fallback-origin",
			"POST /v1/admin/aggregated-edge/accounts/{id}/fallback-origin/refresh",
			"GET /v1/admin/aggregated-edge/supplies/{id}/sites",
			"POST /v1/admin/aggregated-edge/supplies/{id}/sites/{site_id}/purge",
			"GET /v1/admin/aggregated-edge/supplies/{id}/sites/{site_id}/usage",
			"POST /v1/admin/aggregated-edge/supplies/{id}/sites/{site_id}/validation/retry",
			"GET /v1/admin/aggregated-edge/sites/{site_id}/schedule",
			"PUT /v1/admin/aggregated-edge/sites/{site_id}/schedule",
			"POST /v1/admin/aggregated-edge/sites/{site_id}/schedule/unfreeze",
			"POST /v1/admin/aggregated-edge/sites/{site_id}/schedule/switch",
			"POST /v1/admin/aggregated-edge/sites/{site_id}/schedule/keep",
			"GET /v1/admin/aggregated-edge/switch-events",
			"GET /v1/admin/aggregated-edge/sites/{site_id}/bindings",
			"GET /v1/admin/aggregated-edge/sites/{site_id}/availability",
			"GET /v1/admin/aggregated-edge/fallback-chain",
			"PUT /v1/admin/aggregated-edge/fallback-chain",
			"GET /v1/admin/aggregated-edge/sites/{site_id}/fallback-chain",
			"PUT /v1/admin/aggregated-edge/sites/{site_id}/fallback-chain",
			"POST /v1/admin/aggregated-edge/sites/{site_id}/fallback-chain/lock",
			"POST /v1/admin/aggregated-edge/sites/{site_id}/fallback-chain/failback",
		}},
		// SSH remote node install (internal/nodesshinstall.Patterns).
		{handler: s.nodeSSHInstallHandler, patterns: []string{
			"GET /v1/admin/nodes/ssh-installs", "POST /v1/admin/nodes/ssh-installs",
			"GET /v1/admin/nodes/ssh-installs/{id}", "POST /v1/admin/nodes/ssh-installs/{id}/confirm-host-key",
			"POST /v1/admin/nodes/ssh-installs/{id}/cancel",
		}},
		{handler: s.accountRegistrationHandler, patterns: []string{
			"POST /v1/auth/register",
			"POST /v1/auth/registration-challenges",
			"POST /v1/auth/registration-challenge-verifications",
		}},
		{handler: s.accountLoginHandler, patterns: []string{
			"GET /v1/auth/login-methods",
			"POST /v1/auth/login-challenges",
			"POST /v1/auth/login-challenge-verifications",
		}},
		{handler: s.analyticsGeoHandler, patterns: []string{
			"GET /v1/admin/analytics/logs/{kind}/geo-evidence/{event_id}",
			"GET /v1/analytics/logs/{kind}/geo-evidence/{event_id}",
		}},
		{handler: s.securityCoordinationMetricsHandler, patterns: []string{
			"GET /v1/admin/security/coordination/metrics",
		}},
		{handler: s.ja4BlockHandler, patterns: []string{
			"POST /v1/security/ja4-blocks",
			"GET /v1/security/ja4-blocks/{workflow_id}",
			"POST /v1/admin/security/ja4-blocks",
			"GET /v1/admin/security/ja4-blocks/{workflow_id}",
		}},
		{handler: s.autoDefenseHandler, patterns: []string{"/v1/security/autodefense/", "/v1/admin/security/autodefense/"}},
		{handler: s.ccStatsHandler, patterns: []string{"/v1/security/cc-stats", "/v1/admin/security/cc-stats"}},
		{handler: s.marketSecurityHandler, patterns: []string{"GET /v1/analytics/market-security", "GET /v1/admin/analytics/market-security"}},
		{handler: s.edgePublishHandler, patterns: []string{
			"/v1/admin/site-publications", "/v1/admin/site-publications/",
			"/v1/admin/site-rollouts", "/v1/admin/site-rollouts/",
			"/v1/site-publications", "/v1/site-publications/",
			"/v1/site-rollouts", "/v1/site-rollouts/",
		}},
		{handler: s.challengePolicyHandler, patterns: []string{
			"/v1/tenant-scopes/{tenant_scope_id}/challenge-policies",
			"/v1/tenant-scopes/{tenant_scope_id}/challenge-policies/{policy_id}",
			"/v1/tenant-scopes/{tenant_scope_id}/challenge-policies/{policy_id}/enable",
			"/v1/tenant-scopes/{tenant_scope_id}/challenge-policies/{policy_id}/disable",
			"/v1/tenant-scopes/{tenant_scope_id}/challenge-policies/{policy_id}/publications",
			"/v1/tenant-scopes/{tenant_scope_id}/challenge-policies/{policy_id}/publications/{rollout_id}",
			"/v1/tenant-scopes/{tenant_scope_id}/challenge-policies/{policy_id}/publications/{rollout_id}/promote",
		}},
		{handler: s.httpPolicyHandler, patterns: []string{
			"/v1/tenant-scopes/{tenant_scope_id}/http-policies",
			"/v1/tenant-scopes/{tenant_scope_id}/http-policies/publication-preview",
			"/v1/tenant-scopes/{tenant_scope_id}/http-policies/{policy_id}",
			"/v1/tenant-scopes/{tenant_scope_id}/http-policies/{policy_id}/enable",
			"/v1/tenant-scopes/{tenant_scope_id}/http-policies/{policy_id}/disable",
		}},
		{handler: s.firewallActionHandler, patterns: []string{
			"/v1/firewall-actions/policy",
			"/v1/firewall-actions/policy/recover",
		}},
		{handler: s.nodeSchedulerHandler, patterns: []string{
			"/v1/node-line-groups", "/v1/node-line-groups/",
			"/v1/l2-configs", "/v1/l2-configs/",
			"/v1/l2-conds", "/v1/l2-conds/",
			"/v1/l2-nodes", "/v1/l2-nodes/",
		}},
		{handler: s.nodeIsolationHandler, patterns: []string{
			"GET /v1/admin/node-isolations",
			"POST /v1/internal/node-isolation/results/{node_id}",
		}},
		{handler: s.certificateAssetHandler, preserveRaw: true, patterns: []string{
			"/v1/certificate-assets", "/v1/certificate-assets/",
			"GET /v1/sites/{site_id}/certificate-binding",
		}},
		{handler: s.certificatePublicationStatusHandler, preserveRaw: true, patterns: []string{
			"/v1/certificate-publications", "/v1/certificate-publications/",
		}},
		{handler: s.cnameAllocationHandler, patterns: []string{
			"/v1/cname-allocations", "/v1/cname-allocations/diagnose", "/v1/cname-allocations/{allocation_id}",
			"/v1/admin/cname-allocations", "/v1/admin/cname-allocations/diagnose", "/v1/admin/cname-allocations/{allocation_id}",
		}},
		{handler: s.systemConfigurationHandler, preserveRaw: true, patterns: []string{
			"/v1/admin/system-configuration/categories/",
			"/v1/admin/system-configuration/revisions/",
		}},
		{handler: s.systemSettingsHandler, preserveRaw: true, patterns: []string{
			"/v1/admin/system-settings", "/v1/system-settings/public", "/v1/system-settings/csp-hosts",
		}},
		{handler: s.brandAssetHandler, preserveRaw: true, patterns: []string{
			"/v1/admin/brand-assets", "/v1/admin/brand-assets/", "/v1/brand-assets/",
		}},
		{handler: s.themeHandler, preserveRaw: true, patterns: []string{
			"/v1/admin/themes", "/v1/admin/themes/", "/v1/theme/",
		}},
		{handler: s.pluginUIHandler, patterns: []string{
			"GET /v1/plugin-ui/pages", "GET /v1/plugin-ui/signing-key", "POST /v1/plugin-ui/{plugin_id}/proxy",
		}},
		{handler: s.pluginProviderHandler, patterns: []string{
			"GET /v1/admin/plugin-providers", "POST /v1/admin/plugin-providers/{plugin_id}/{action}",
		}},
		{handler: s.systemCleanupSettingsHandler, preserveRaw: true, patterns: []string{
			"/v1/admin/system-cleanup-settings",
		}},
		{handler: s.systemUserSettingsHandler, preserveRaw: true, patterns: []string{
			"/v1/admin/system-user-settings",
		}},
		{handler: s.systemMailSettingsHandler, preserveRaw: true, patterns: []string{
			"/v1/admin/system-mail-settings",
		}},
		{handler: s.systemOtherSettingsHandler, preserveRaw: true, patterns: []string{
			"/v1/admin/system-other-settings",
		}},
		{handler: s.regionCatalogHandler, preserveRaw: true, patterns: []string{
			regioncataloghttp.Route, regioncataloghttp.Route + "/",
		}},
		{handler: s.l4LineSwitchHandler, patterns: []string{
			"/v1/tenant-scopes/{scope_id}/l4-line-switches",
			"/v1/tenant-scopes/{scope_id}/l4-line-switches/current",
			"/v1/tenant-scopes/{scope_id}/l4-line-switches/{switch_id}",
			"/v1/tenant-scopes/{scope_id}/l4-line-switches/{switch_id}/reconcile",
		}},
		{handler: s.controlPlaneUpgradeHandler, preserveRaw: true, patterns: []string{
			"GET /v1/admin/control-upgrade-plan",
			"POST /v1/admin/control-upgrade-plan",
			"GET /v1/admin/control-upgrade-plan/run-log",
			"GET /v1/admin/control-upgrade-plan/options",
			"POST /v1/admin/control-upgrade-plan/issue",
			"POST /v1/internal/control-upgrade/drain",
			"POST /v1/internal/control-upgrade/resume",
			"GET /v1/internal/control-upgrade/health",
			"GET /v1/internal/control-upgrade/version",
		}},
		{handler: s.controlUpgradePlanHandler, preserveRaw: true, patterns: []string{
			"GET /v1/internal/control-upgrade/plan",
		}},
		{handler: s.entitlementRefreshHandler, preserveRaw: true, patterns: []string{
			entitlementrefreshhttp.Route,
		}},
		{handler: s.pluginWebhookHandler, patterns: []string{
			"/v1/tenant-scopes/{tenant_scope_id}/plugin-webhook-subscriptions",
			"/v1/tenant-scopes/{tenant_scope_id}/plugin-webhook-subscriptions/{subscription_id}",
			"/v1/tenant-scopes/{tenant_scope_id}/plugin-webhook-subscriptions/{subscription_id}/test-deliveries",
			"/v1/tenant-scopes/{tenant_scope_id}/plugin-webhook-subscriptions/{subscription_id}/deliveries",
			"/v1/tenant-scopes/{tenant_scope_id}/plugin-webhook-subscriptions/{subscription_id}/deliveries/{delivery_id}",
			"/v1/tenant-scopes/{tenant_scope_id}/plugin-webhook-subscriptions/{subscription_id}/deliveries/{delivery_id}/replays",
			"/v1/tenant-scopes/{tenant_scope_id}/plugin-webhook-subscriptions/{subscription_id}/delivery-replays",
			"/v1/tenant-scopes/{tenant_scope_id}/plugin-webhook-subscriptions/{subscription_id}/secret-rotations",
			"/v1/tenant-scopes/{tenant_scope_id}/plugin-webhook-subscriptions/{subscription_id}/secret-rotations/{rotation_id}/activate",
			"/v1/tenant-scopes/{tenant_scope_id}/plugin-webhook-subscriptions/{subscription_id}/revoke",
		}},
		{handler: s.pluginInstallationHandler, patterns: []string{
			"/v1/tenant-scopes/{tenant_scope_id}/plugin-installations",
			"/v1/tenant-scopes/{tenant_scope_id}/plugin-installations/{authorization_id}",
			"/v1/tenant-scopes/{tenant_scope_id}/plugin-installations/{authorization_id}/{action}",
			"/v1/platform/plugin-installations",
			"/v1/platform/plugin-installations/{authorization_id}",
			"/v1/platform/plugin-installations/{authorization_id}/{action}",
		}},
	} {
		if mounted.handler == nil {
			continue
		}
		for _, pattern := range mounted.patterns {
			handler := mounted.handler
			mux.Handle(pattern, http.HandlerFunc(func(writer http.ResponseWriter, request *http.Request) {
				if mounted.preserveRaw {
					handler.ServeHTTP(writer, request)
					return
				}
				forwarded := request.Clone(request.Context())
				forwarded.Header = request.Header.Clone()
				forwarded.Header.Set("X-Request-ID", requestID(request.Context()))
				handler.ServeHTTP(writer, forwarded)
			}))
		}
	}
	if s.originAuthHandler == nil {
		// fix-e1 #2: with origin authentication off its pages get a structured
		// feature_disabled instead of a 404 the pages read as "not found".
		for _, pattern := range []string{
			"/v1/tenant-scopes/{tenant_scope_id}/origin-auth",
			"/v1/tenant-scopes/{tenant_scope_id}/origin-auth/",
		} {
			mux.HandleFunc(pattern, s.handleOriginAuthDisabled)
		}
	}
	if s.accountLoginHandler == nil {
		// fix-e1 #3: the sign-in page always reads the login methods; with the
		// login/recovery runtime off it gets "nothing offered" instead of a 404.
		mux.HandleFunc("GET /v1/auth/login-methods", handleLoginMethodsDisabled)
	}
	var gated http.Handler = mux
	var full http.Handler
	if s.approvalCenter != nil {
		// Approved requests replay through the full chain (request ID,
		// installation lock, upgrade gate) like any other request.
		s.approvalCenterRoutes(mux, func() http.Handler { return full })
		gated = s.withApprovalCenter(mux)
	}
	handler := s.withRequestID(s.withAPIKeyClientIP(s.withInstallationLock(gated)))
	if s.controlPlaneUpgradeGate != nil {
		handler = s.controlPlaneUpgradeGate(handler)
	}
	full = handler
	return s.WithImpersonationDelegate(handler)
}

func (s *Server) handleAnalytics(w http.ResponseWriter, r *http.Request) {
	if s.analyticsHandler == nil {
		s.writeAPIError(w, r, http.StatusServiceUnavailable, "analytics_storage_unavailable", "analytics storage is unavailable")
		return
	}
	ctx := analytics.WithRequestID(r.Context(), requestID(r.Context()))
	s.analyticsHandler.ServeHTTP(w, r.WithContext(ctx))
}

func (s *Server) handleAnalyticsDiagnostic(w http.ResponseWriter, r *http.Request) {
	if s.analyticsDiagnosticHandler == nil {
		http.NotFound(w, r)
		return
	}
	forwarded := r.Clone(r.Context())
	forwarded.Header = r.Header.Clone()
	forwarded.Header.Set("X-Request-ID", requestID(r.Context()))
	s.analyticsDiagnosticHandler.ServeHTTP(w, forwarded)
}

func (s *Server) handleAnalyticsLogs(w http.ResponseWriter, r *http.Request) {
	if r.Method != http.MethodGet && r.Method != http.MethodPost {
		w.Header().Set("Allow", "GET, POST")
		http.Error(w, http.StatusText(http.StatusMethodNotAllowed), http.StatusMethodNotAllowed)
		return
	}
	ctx := analyticslog.WithRequestID(r.Context(), requestID(r.Context()))
	forwarded := r.Clone(ctx)
	forwarded.Header = r.Header.Clone()
	forwarded.Header.Set("X-Request-ID", requestID(r.Context()))
	s.analyticsLogsHandler.ServeHTTP(w, forwarded)
}

func nilHTTPHandler(handler http.Handler) bool {
	if handler == nil {
		return true
	}
	value := reflect.ValueOf(handler)
	switch value.Kind() {
	case reflect.Chan, reflect.Func, reflect.Interface, reflect.Map, reflect.Pointer, reflect.Slice:
		return value.IsNil()
	default:
		return false
	}
}

func nilAPIKeyUsageRecorder(recorder APIKeyUsageRecorder) bool {
	if recorder == nil {
		return false
	}
	value := reflect.ValueOf(recorder)
	switch value.Kind() {
	case reflect.Chan, reflect.Func, reflect.Interface, reflect.Map, reflect.Pointer, reflect.Slice:
		return value.IsNil()
	default:
		return false
	}
}

func (s *Server) authenticateAnalytics(r *http.Request) (analytics.Actor, error) {
	principal, err := s.authenticatedPrincipal(r)
	if err != nil {
		return analytics.Actor{}, err
	}
	tenantID := ""
	if principal.TenantID != nil {
		tenantID = principal.TenantID.String()
	}
	return analytics.Actor{
		ScopeKind:   principal.ScopeKind,
		TenantID:    tenantID,
		Permissions: append([]string(nil), principal.Permissions...),
	}, nil
}

func (s *Server) authenticateAnalyticsDiagnostic(r *http.Request) (analyticsdiagnostic.Actor, error) {
	principal, err := s.authenticatedPrincipal(r)
	if err != nil {
		return analyticsdiagnostic.Actor{}, err
	}
	tenantID := ""
	if principal.TenantID != nil {
		tenantID = principal.TenantID.String()
	}
	return analyticsdiagnostic.Actor{
		ScopeKind: principal.ScopeKind, TenantID: tenantID, ActorID: principal.UserID.String(),
		ScopeID: principal.ScopeID.String(), Permissions: append([]string(nil), principal.Permissions...),
	}, nil
}

func (s *Server) handleJobQuery(w http.ResponseWriter, r *http.Request) {
	forwarded := r.Clone(r.Context())
	forwarded.Header = r.Header.Clone()
	forwarded.Header.Set("X-Request-ID", requestID(r.Context()))
	s.jobQueryHandler.ServeHTTP(w, forwarded)
}

func (s *Server) handleCacheControl(w http.ResponseWriter, r *http.Request) {
	forwarded := r.Clone(r.Context())
	forwarded.Header = r.Header.Clone()
	forwarded.Header.Set("X-Request-ID", requestID(r.Context()))
	s.cacheControlHandler.ServeHTTP(w, forwarded)
}

func (s *Server) handleAnnouncement(w http.ResponseWriter, r *http.Request) {
	for _, cursor := range r.URL.Query()["cursor"] {
		if len(cursor) > 512 {
			s.writeAPIError(w, r, http.StatusBadRequest, "validation_error", "query parameters are invalid")
			return
		}
	}
	forwarded := r.Clone(r.Context())
	forwarded.Header = r.Header.Clone()
	forwarded.Header.Set("X-Request-ID", requestID(r.Context()))
	for _, name := range []string{"id", "event_id", "outbox_id"} {
		if value := r.PathValue(name); value != "" {
			forwarded.SetPathValue(name, value)
		}
	}
	s.announcementHandler.ServeHTTP(w, forwarded)
}

func (s *Server) handleNotification(w http.ResponseWriter, r *http.Request) {
	forwarded := r.Clone(r.Context())
	forwarded.Header = r.Header.Clone()
	forwarded.Header.Set("X-Request-ID", requestID(r.Context()))
	for _, name := range []string{"event_type", "outbox_id"} {
		if value := r.PathValue(name); value != "" {
			forwarded.SetPathValue(name, value)
		}
	}
	s.notificationHandler.ServeHTTP(w, forwarded)
}

func (s *Server) authenticateJobQuery(r *http.Request) (jobhttp.Principal, error) {
	principal, apiKeyID, rawAPIKey, err := s.authenticatedPrincipalWithAPIKey(r)
	if err != nil {
		return jobhttp.Principal{}, err
	}
	permissions := make(map[string]struct{}, len(principal.Permissions))
	for _, permission := range principal.Permissions {
		permissions[permission] = struct{}{}
	}
	result := jobhttp.Principal{
		UserID: principal.UserID, ScopeID: principal.ScopeID,
		ScopeKind: jobhttp.ScopeKind(principal.ScopeKind), Permissions: permissions,
	}
	if apiKeyID != uuid.Nil {
		// API-JOBS-02：命令事务内用原凭据复核密钥，挡住认证后被吊销或缩权的密钥。
		result = result.WithAPIKeyCredential(apiKeyID, rawAPIKey)
	} else if scheme, rawToken, found := strings.Cut(strings.TrimSpace(r.Header.Get("Authorization")), " "); found &&
		strings.EqualFold(scheme, "Bearer") && strings.TrimSpace(rawToken) != "" {
		// 缓存任务的取消/重试转给缓存模块，缓存模块在其事务内按同一会话复核权限。
		result = result.WithSessionCredential(strings.TrimSpace(rawToken))
	}
	return result, nil
}

func (s *Server) handleLive(w http.ResponseWriter, _ *http.Request) {
	writeJSON(w, http.StatusOK, map[string]string{"status": "live"})
}

func (s *Server) handleReady(w http.ResponseWriter, r *http.Request) {
	ctx, cancel := context.WithTimeout(r.Context(), 2*time.Second)
	defer cancel()
	if err := s.pool.Ping(ctx); err != nil || s.apiKeys.Ready(ctx) != nil {
		s.logger.ErrorContext(r.Context(), "readiness check failed",
			"request_id", requestID(r.Context()),
			"error", err,
		)
		s.writeAPIError(w, r, http.StatusServiceUnavailable, "service_unavailable", "a required dependency is unavailable")
		return
	}
	writeJSON(w, http.StatusOK, map[string]string{"status": "ready"})
}

type loginRequest struct {
	Username       string                 `json:"username"`
	Password       string                 `json:"password"`
	ScopeID        string                 `json:"scope_id"`
	LoginChallenge *loginChallengeRequest `json:"login_challenge"`
	Captcha        *loginCaptchaRequest   `json:"captcha"`
}

type authResponse struct {
	AccessToken   string                      `json:"access_token"`
	TokenType     string                      `json:"token_type"`
	ExpiresIn     int64                       `json:"expires_in"`
	Principal     identity.Principal          `json:"principal"`
	Impersonation *impersonation.BannerClaims `json:"impersonation,omitempty"`
}

type principalResponse struct {
	identity.Principal
	Impersonation *impersonation.BannerClaims `json:"impersonation,omitempty"`
}

func (s *Server) handleLogin(w http.ResponseWriter, r *http.Request) {
	var body loginRequest
	if err := decodeJSON(w, r, &body); err != nil {
		s.writeAPIError(w, r, http.StatusBadRequest, "invalid_request", "request body is invalid")
		return
	}
	body.Username = strings.TrimSpace(body.Username)
	if len(body.Username) < 3 || len(body.Username) > 128 || len(body.Password) == 0 || len(body.Password) > 1024 {
		s.writeAPIError(w, r, http.StatusBadRequest, "validation_error", "username and password are required")
		return
	}
	var scopeID *uuid.UUID
	if body.ScopeID != "" {
		parsed, err := uuid.Parse(body.ScopeID)
		if err != nil {
			s.writeAPIError(w, r, http.StatusBadRequest, "validation_error", "scope_id must be a UUID")
			return
		}
		scopeID = &parsed
	}
	var proof *identity.LoginChallengeProof
	if body.LoginChallenge != nil {
		key, ok := s.idempotencyKey(w, r)
		if !ok {
			return
		}
		challengeID, err := uuid.Parse(body.LoginChallenge.ChallengeID)
		if err != nil || challengeID == uuid.Nil || !loginOTPPattern.MatchString(body.LoginChallenge.OTP) {
			s.writeAPIError(w, r, http.StatusBadRequest, "validation_error", "login challenge is invalid")
			return
		}
		proof = &identity.LoginChallengeProof{ChallengeID: challengeID, OTP: body.LoginChallenge.OTP, IdempotencyKey: key}
	}
	captcha, ok := s.loginCaptchaProof(w, r, body.Captcha)
	if !ok {
		return
	}
	result, err := s.identity.Login(r.Context(), identity.LoginInput{
		Username:  body.Username,
		Password:  body.Password,
		ScopeID:   scopeID,
		Challenge: proof,
		Captcha:   captcha,
	}, s.requestInfo(r))
	if err != nil {
		s.writeError(w, r, err)
		return
	}
	s.setRefreshCookie(w, result.RefreshToken, result.RefreshExpiresAt)
	s.clearImpersonationCookie(w)
	s.writeAuthResponse(w, result, nil)
}

func (s *Server) handleRefresh(w http.ResponseWriter, r *http.Request) {
	var impersonated *impersonationhttp.AuthorizedSession
	if session, ok, err := s.authorizeImpersonationCookie(r); ok {
		if err != nil {
			s.clearImpersonationCookie(w)
			s.writeAPIError(w, r, http.StatusUnauthorized, "invalid_session", "authentication is required")
			return
		}
		impersonated = &session
	}
	cookie, err := r.Cookie(refreshCookieName)
	if err != nil {
		s.clearRefreshCookie(w)
		s.writeAPIError(w, r, http.StatusUnauthorized, "invalid_session", "authentication is required")
		return
	}
	result, err := s.identity.Refresh(r.Context(), cookie.Value, s.requestInfo(r))
	if err != nil {
		// Only a refusal ends the browser session. A transient failure (database
		// busy, upgrade gate, timeout) keeps the cookie so the next attempt can
		// still renew; clearing it turned every hiccup into a forced sign-in.
		if refreshRefused(err) {
			s.clearRefreshCookie(w)
		}
		s.writeError(w, r, err)
		return
	}
	result, marker := authResultWithImpersonation(result, impersonated)
	if result.RefreshToken != "" {
		s.setRefreshCookie(w, result.RefreshToken, result.RefreshExpiresAt)
	}
	s.writeAuthResponse(w, result, marker)
}

func refreshRefused(err error) bool {
	return errors.Is(err, identity.ErrInvalidSession) || errors.Is(err, identity.ErrRefreshReplay) ||
		errors.Is(err, identity.ErrAccountDisabled) || errors.Is(err, identity.ErrMembershipDisabled) ||
		errors.Is(err, identity.ErrAdminAccessDenied)
}

func authResultWithImpersonation(result identity.AuthResult, session *impersonationhttp.AuthorizedSession) (identity.AuthResult, *impersonation.BannerClaims) {
	if session == nil {
		return result, nil
	}
	result.Principal = session.Principal
	return result, &session.Banner
}

func (s *Server) handleLogout(w http.ResponseWriter, r *http.Request) {
	// Signing out while impersonating ends the impersonation at once instead of
	// leaving the cookie usable until SessionTTL (fix-pre1035, user 10-27).
	if ender, ok := s.impersonationSessionAuthorizer.(interface {
		End(*http.Request, string) error
	}); ok && !nilImpersonationSessionAuthorizer(s.impersonationSessionAuthorizer) {
		if _, err := r.Cookie(impersonationhttp.CookieName); err == nil {
			if err := ender.End(impersonationAuthorizationRequest(r), "logout"); err != nil {
				s.writeError(w, r, err)
				return
			}
		}
	}
	cookie, _ := r.Cookie(refreshCookieName)
	if cookie != nil {
		if err := s.identity.Logout(r.Context(), cookie.Value, requestID(r.Context())); err != nil {
			s.writeError(w, r, err)
			return
		}
	}
	s.clearRefreshCookie(w)
	s.clearImpersonationCookie(w)
	w.WriteHeader(http.StatusNoContent)
}

func (s *Server) handleMe(w http.ResponseWriter, r *http.Request) {
	principal, marker, err := s.authenticatedSessionPrincipalWithMarker(r)
	if err != nil {
		s.writeError(w, r, err)
		return
	}
	if err := identity.Authorize(principal, "identity.self.read"); err != nil {
		s.writeError(w, r, err)
		return
	}
	writeJSON(w, http.StatusOK, principalResponse{Principal: principal, Impersonation: marker})
}

type createNodeRequest struct {
	Name                      string `json:"name"`
	Description               string `json:"description"`
	Region                    string `json:"region"`
	IPv4                      string `json:"ipv4"`
	IPv6                      string `json:"ipv6"`
	IssueEnrollmentToken      bool   `json:"issue_enrollment_token"`
	EnrollmentPurpose         string `json:"enrollment_purpose"`
	EnrollmentTokenTTLSeconds int64  `json:"enrollment_token_ttl_seconds"`
}

type createNodeResponse struct {
	Node            node.Node         `json:"node"`
	EnrollmentToken *node.IssuedToken `json:"enrollment_token,omitempty"`
}

type issueEnrollmentTokenRequest struct {
	Purpose    string `json:"purpose"`
	TTLSeconds int64  `json:"ttl_seconds"`
}

type nodeListResponse struct {
	Items      []nodepresence.InventoryItem `json:"items"`
	NextCursor *uuid.UUID                   `json:"next_cursor,omitempty"`
}

func (s *Server) handleCreateNode(w http.ResponseWriter, r *http.Request) {
	principal, ok := s.requireNodePermission(w, r, "nodes.manage")
	if !ok {
		return
	}
	key, ok := s.idempotencyKey(w, r)
	if !ok {
		return
	}
	var body createNodeRequest
	if err := decodeJSON(w, r, &body); err != nil {
		s.writeAPIError(w, r, http.StatusBadRequest, "invalid_request", "request body is invalid")
		return
	}
	ttl, valid := tokenTTL(body.EnrollmentTokenTTLSeconds)
	if !valid {
		s.writeAPIError(w, r, http.StatusBadRequest, "validation_error", "enrollment token TTL is invalid")
		return
	}
	result, err := s.nodes.CreateNode(r.Context(), node.Actor{
		UserID:  principal.UserID,
		ScopeID: principal.ScopeID,
	}, node.CreateRequest{
		Name:           body.Name,
		Description:    body.Description,
		Region:         body.Region,
		IPv4:           body.IPv4,
		IPv6:           body.IPv6,
		IssueToken:     body.IssueEnrollmentToken,
		TokenPurpose:   body.EnrollmentPurpose,
		TokenTTL:       ttl,
		IdempotencyKey: key,
		RequestID:      requestID(r.Context()),
	})
	if err != nil {
		s.writeError(w, r, err)
		return
	}
	writeJSONStatus(w, http.StatusCreated, createNodeResponse{
		Node:            result.Node,
		EnrollmentToken: result.EnrollmentToken,
	})
}

func (s *Server) handleListNodes(w http.ResponseWriter, r *http.Request) {
	if r.URL.Query().Has("order") {
		s.handleListNodesOrdered(w, r)
		return
	}
	principal, ok := s.requireNodePermission(w, r, "nodes.read")
	if !ok {
		return
	}
	limit := 20
	if raw := r.URL.Query().Get("limit"); raw != "" {
		parsed, err := strconv.Atoi(raw)
		if err != nil {
			s.writeAPIError(w, r, http.StatusBadRequest, "validation_error", "limit must be an integer")
			return
		}
		limit = parsed
	}
	var after *uuid.UUID
	if raw := r.URL.Query().Get("cursor"); raw != "" {
		parsed, err := uuid.Parse(raw)
		if err != nil {
			s.writeAPIError(w, r, http.StatusBadRequest, "validation_error", "cursor must be a UUID")
			return
		}
		after = &parsed
	}
	search := r.URL.Query().Get("search")
	if !utf8.ValidString(search) || utf8.RuneCountInString(search) > nodepresence.MaxInventorySearchRunes ||
		strings.ContainsFunc(search, func(character rune) bool {
			return unicode.IsControl(character) || character == '\u2028' || character == '\u2029'
		}) {
		s.writeAPIError(w, r, http.StatusBadRequest, "validation_error", "search must be at most 128 characters and contain no control characters")
		return
	}
	result, err := s.nodeInventory.List(r.Context(), nodepresence.InventoryListRequest{
		ScopeID:  principal.ScopeID,
		State:    r.URL.Query().Get("status"),
		Presence: r.URL.Query().Get("presence"),
		Search:   strings.TrimSpace(search),
		After:    after,
		Limit:    limit,
	})
	if err != nil {
		s.writeError(w, r, err)
		return
	}
	writeJSON(w, http.StatusOK, nodeListResponse{Items: result.Items, NextCursor: result.NextCursor})
}

func (s *Server) handleGetNode(w http.ResponseWriter, r *http.Request) {
	principal, ok := s.requireNodePermission(w, r, "nodes.read")
	if !ok {
		return
	}
	nodeID, err := uuid.Parse(r.PathValue("id"))
	if err != nil {
		s.writeAPIError(w, r, http.StatusBadRequest, "validation_error", "node ID must be a UUID")
		return
	}
	item, err := s.nodeInventory.Get(r.Context(), principal.ScopeID, nodeID)
	if err != nil {
		s.writeError(w, r, err)
		return
	}
	writeJSON(w, http.StatusOK, item)
}

// handleGetNodeConfigurationScopes lists the tenants a node serves, their
// configuration state and apply progress, and publications refused for
// conflicting with them on this node.
func (s *Server) handleGetNodeConfigurationScopes(w http.ResponseWriter, r *http.Request) {
	principal, ok := s.requireNodePermission(w, r, "nodes.read")
	if !ok {
		return
	}
	nodeID, err := uuid.Parse(r.PathValue("id"))
	if err != nil {
		s.writeAPIError(w, r, http.StatusBadRequest, "validation_error", "node ID must be a UUID")
		return
	}
	result, err := s.nodeInventory.ConfigurationScopes(r.Context(), principal.ScopeID, nodeID)
	if err != nil {
		s.writeError(w, r, err)
		return
	}
	writeJSON(w, http.StatusOK, result)
}

// handleGetNodeIPLocation: 编辑节点 → IP 归属 (fix-nodeipgeo).
func (s *Server) handleGetNodeIPLocation(w http.ResponseWriter, r *http.Request) {
	principal, ok := s.requireNodePermission(w, r, "nodes.read")
	if !ok {
		return
	}
	nodeID, err := uuid.Parse(r.PathValue("id"))
	if err != nil {
		s.writeAPIError(w, r, http.StatusBadRequest, "validation_error", "node ID must be a UUID")
		return
	}
	view, err := s.nodes.NodeIPLocation(r.Context(), principal.ScopeID, nodeID)
	if err != nil {
		s.writeNodeLifecycleError(w, r, err)
		return
	}
	writeJSON(w, http.StatusOK, view)
}

func (s *Server) handleIssueEnrollmentToken(w http.ResponseWriter, r *http.Request) {
	principal, ok := s.requireNodePermission(w, r, "nodes.manage")
	if !ok {
		return
	}
	nodeID, err := uuid.Parse(r.PathValue("id"))
	if err != nil {
		s.writeAPIError(w, r, http.StatusBadRequest, "validation_error", "node ID must be a UUID")
		return
	}
	var body issueEnrollmentTokenRequest
	if err := decodeJSON(w, r, &body); err != nil {
		s.writeAPIError(w, r, http.StatusBadRequest, "invalid_request", "request body is invalid")
		return
	}
	ttl, valid := tokenTTL(body.TTLSeconds)
	if !valid {
		s.writeAPIError(w, r, http.StatusBadRequest, "validation_error", "enrollment token TTL is invalid")
		return
	}
	issued, err := s.nodes.IssueEnrollmentToken(
		r.Context(),
		node.Actor{UserID: principal.UserID, ScopeID: principal.ScopeID},
		nodeID,
		body.Purpose,
		ttl,
		requestID(r.Context()),
	)
	if err != nil {
		s.writeError(w, r, err)
		return
	}
	writeJSONStatus(w, http.StatusCreated, issued)
}

func (s *Server) authenticatedSessionPrincipal(r *http.Request) (identity.Principal, error) {
	principal, _, err := s.authenticatedSessionPrincipalWithMarker(r)
	return principal, err
}

func (s *Server) authenticatedSessionPrincipalWithMarker(r *http.Request) (identity.Principal, *impersonation.BannerClaims, error) {
	if session, ok, err := s.authorizeImpersonationCookie(r); ok {
		return session.Principal, &session.Banner, err
	}
	authorization := strings.TrimSpace(r.Header.Get("Authorization"))
	scheme, rawToken, found := strings.Cut(authorization, " ")
	if !found || !strings.EqualFold(scheme, "Bearer") || strings.TrimSpace(rawToken) == "" {
		return identity.Principal{}, nil, identity.ErrInvalidSession
	}
	principal, err := s.identity.Authenticate(r.Context(), strings.TrimSpace(rawToken))
	return principal, nil, err
}

func (s *Server) authenticateAnnouncementSession(r *http.Request) (announcementhttp.SessionEnvelope, error) {
	if session, ok, err := s.authorizeImpersonationCookie(r); ok {
		return announcementhttp.SessionEnvelope{Principal: session.Principal, SessionID: session.SessionID}, err
	}
	authorization := strings.TrimSpace(r.Header.Get("Authorization"))
	scheme, rawToken, found := strings.Cut(authorization, " ")
	if !found || !strings.EqualFold(scheme, "Bearer") || strings.TrimSpace(rawToken) == "" || s.identity == nil {
		return announcementhttp.SessionEnvelope{}, identity.ErrInvalidSession
	}
	authenticated, err := s.identity.AuthenticateSession(r.Context(), strings.TrimSpace(rawToken))
	if err != nil {
		return announcementhttp.SessionEnvelope{}, err
	}
	return announcementhttp.SessionEnvelope{Principal: authenticated.Principal, SessionID: authenticated.SessionID}, nil
}

func (s *Server) authenticateNotificationSession(r *http.Request) (identity.AuthenticatedSession, error) {
	if session, ok, err := s.authorizeImpersonationCookie(r); ok {
		return identity.AuthenticatedSession{Principal: session.Principal, SessionID: session.SessionID}, err
	}
	authorization := strings.TrimSpace(r.Header.Get("Authorization"))
	scheme, rawToken, found := strings.Cut(authorization, " ")
	if !found || !strings.EqualFold(scheme, "Bearer") || strings.TrimSpace(rawToken) == "" || s.identity == nil {
		return identity.AuthenticatedSession{}, identity.ErrInvalidSession
	}
	return s.identity.AuthenticateSession(r.Context(), strings.TrimSpace(rawToken))
}

func (s *Server) authenticatedPrincipal(r *http.Request) (identity.Principal, error) {
	principal, _, _, err := s.authenticatedPrincipalWithAPIKey(r)
	return principal, err
}

// authenticatedPrincipalWithAPIKey 与 authenticatedPrincipal 相同；走 CdncaKey 时额外返回
// api_keys.id 与原凭据，供需要在事务内复核密钥的模块使用（会话与模拟登录返回 uuid.Nil）。
func (s *Server) authenticatedPrincipalWithAPIKey(r *http.Request) (identity.Principal, uuid.UUID, string, error) {
	if session, ok, err := s.authorizeImpersonationCookie(r); ok {
		return session.Principal, uuid.Nil, "", err
	}
	authorization := strings.TrimSpace(r.Header.Get("Authorization"))
	scheme, rawToken, found := strings.Cut(authorization, " ")
	if !found || strings.TrimSpace(rawToken) == "" {
		return identity.Principal{}, uuid.Nil, "", identity.ErrInvalidSession
	}
	switch {
	case strings.EqualFold(scheme, "Bearer"):
		principal, err := s.identity.Authenticate(r.Context(), strings.TrimSpace(rawToken))
		return principal, uuid.Nil, "", err
	case strings.EqualFold(scheme, "CdncaKey"):
		raw := strings.TrimSpace(rawToken)
		principal, keyID, authenticatedAt, err := s.apiKeys.AuthenticateWithKeyID(r.Context(), raw)
		if err != nil || keyID == uuid.Nil {
			return identity.Principal{}, uuid.Nil, "", identity.ErrInvalidSession
		}
		if s.apiKeyUsageRecorder != nil {
			_ = s.apiKeyUsageRecorder.TryRecord(keyID, authenticatedAt)
		}
		return principal, keyID, raw, nil
	default:
		return identity.Principal{}, uuid.Nil, "", identity.ErrInvalidSession
	}
}

func (s *Server) authenticateAnalyticsGeo(request *http.Request) (analyticsgeo.Actor, error) {
	principal, err := s.authenticatedPrincipal(request)
	if err != nil || principal.UserID == uuid.Nil || principal.ScopeID == uuid.Nil {
		return analyticsgeo.Actor{}, identity.ErrInvalidSession
	}
	actor := analyticsgeo.Actor{
		ScopeKind: principal.ScopeKind, ActorID: principal.UserID.String(), ScopeID: principal.ScopeID.String(),
		Permissions: append([]string(nil), principal.Permissions...),
	}
	if principal.TenantID != nil {
		actor.TenantID = principal.TenantID.String()
	}
	return actor, nil
}

func (s *Server) authenticateImpersonationPrimarySession(request *http.Request, rawToken string) (identity.AuthenticatedSession, error) {
	if s.identity == nil || request == nil || rawToken == "" {
		return identity.AuthenticatedSession{}, identity.ErrInvalidSession
	}
	return s.identity.AuthenticateSession(request.Context(), rawToken)
}

func (s *Server) authorizeImpersonationCookie(request *http.Request) (impersonationhttp.AuthorizedSession, bool, error) {
	if request == nil || s.impersonationSessionAuthorizer == nil {
		return impersonationhttp.AuthorizedSession{}, false, nil
	}
	// WithImpersonationDelegate already authorized (and audited) this request.
	if delegated, ok := request.Context().Value(impersonationDelegateKey{}).(impersonationDelegate); ok {
		if delegated.err != nil {
			return impersonationhttp.AuthorizedSession{}, true, identity.ErrInvalidSession
		}
		return delegated.session, true, nil
	}
	for _, cookie := range request.Cookies() {
		if cookie.Name != impersonationhttp.CookieName {
			continue
		}
		authorizationRequest := impersonationAuthorizationRequest(request)
		authorized, err := s.impersonationSessionAuthorizer.Authorize(authorizationRequest, impersonationRequestAction(request))
		if err != nil {
			return impersonationhttp.AuthorizedSession{}, true, identity.ErrInvalidSession
		}
		return authorized, true, nil
	}
	return impersonationhttp.AuthorizedSession{}, false, nil
}

func impersonationAuthorizationRequest(request *http.Request) *http.Request {
	prepared := request.Clone(request.Context())
	prepared.Header = request.Header.Clone()
	if len(prepared.Header.Values("X-Request-ID")) == 0 {
		id := requestID(request.Context())
		if !requestIDPattern.MatchString(id) {
			id = uuid.NewString()
		}
		prepared.Header.Set("X-Request-ID", id)
	}
	if len(prepared.Header.Values("Traceparent")) == 0 {
		digest := sha256.Sum256([]byte(prepared.Header.Get("X-Request-ID")))
		prepared.Header.Set("Traceparent", fmt.Sprintf("00-%x-%x-01", digest[:16], digest[16:24]))
	}
	return prepared
}

func impersonationRequestAction(request *http.Request) string {
	if request == nil || request.URL == nil {
		return "identity.impersonation.use"
	}
	path := request.URL.Path
	switch {
	case request.Method == http.MethodGet && path == "/v1/auth/me":
		return "identity.self.read"
	case request.Method == http.MethodPost && path == "/v1/account/password":
		return "identity.password.change"
	case strings.HasPrefix(path, "/v1/account/mfa"):
		return "identity.mfa.use"
	case request.Method == http.MethodGet && strings.HasPrefix(path, "/v1/account/api-keys"):
		// 代登录可查看密钥列表与状态（不含明文）；创建、轮换、激活等产生秘密的操作仍拒绝。
		return "api_key.self.read"
	case strings.HasPrefix(path, "/v1/account/api-keys"):
		return "api_key.self.update"
	case strings.HasPrefix(path, "/v1/admin/users/") && strings.Contains(path, "/api-keys"):
		return "api_key.admin.create"
	default:
		return "identity.impersonation.use"
	}
}

func nilImpersonationSessionAuthorizer(authorizer ImpersonationSessionAuthorizer) bool {
	if authorizer == nil {
		return true
	}
	value := reflect.ValueOf(authorizer)
	switch value.Kind() {
	case reflect.Chan, reflect.Func, reflect.Interface, reflect.Map, reflect.Pointer, reflect.Slice:
		return value.IsNil()
	default:
		return false
	}
}

func tokenTTL(seconds int64) (time.Duration, bool) {
	if seconds == 0 {
		return 0, true
	}
	if seconds < 60 || seconds > 24*60*60 {
		return 0, false
	}
	return time.Duration(seconds) * time.Second, true
}

func (s *Server) writeAuthResponse(w http.ResponseWriter, result identity.AuthResult, marker *impersonation.BannerClaims) {
	expiresIn := max(int64(time.Until(result.ExpiresAt).Seconds()), 1)
	writeJSON(w, http.StatusOK, authResponse{
		AccessToken:   result.AccessToken,
		TokenType:     "Bearer",
		ExpiresIn:     expiresIn,
		Principal:     result.Principal,
		Impersonation: marker,
	})
}

func (s *Server) clearImpersonationCookie(w http.ResponseWriter) {
	http.SetCookie(w, &http.Cookie{
		Name: impersonationhttp.CookieName, Value: "", Path: "/", MaxAge: -1,
		Expires: time.Unix(1, 0), HttpOnly: true, Secure: true, SameSite: http.SameSiteStrictMode,
	})
}

func (s *Server) setRefreshCookie(w http.ResponseWriter, token string, expiresAt time.Time) {
	http.SetCookie(w, &http.Cookie{
		Name:     refreshCookieName,
		Value:    token,
		Path:     "/v1/auth",
		Domain:   s.cookieDomain,
		Expires:  expiresAt,
		MaxAge:   max(int(time.Until(expiresAt).Seconds()), 1),
		HttpOnly: true,
		Secure:   s.cookieSecure,
		SameSite: http.SameSiteStrictMode,
	})
}

func (s *Server) clearRefreshCookie(w http.ResponseWriter) {
	http.SetCookie(w, &http.Cookie{
		Name:     refreshCookieName,
		Value:    "",
		Path:     "/v1/auth",
		Domain:   s.cookieDomain,
		Expires:  time.Unix(1, 0),
		MaxAge:   -1,
		HttpOnly: true,
		Secure:   s.cookieSecure,
		SameSite: http.SameSiteStrictMode,
	})
}

type errorEnvelope struct {
	Error apiError `json:"error"`
}

type apiError struct {
	Code      string `json:"code"`
	Message   string `json:"message"`
	RequestID string `json:"request_id"`
	// Details locate a stream port conflict (stream_port_conflict,
	// *streamPortConflictDetails) or count a market supply refusal
	// (supply_in_use, *supplyInUseDetails); omitted for every other error.
	Details any `json:"details,omitempty"`
}

// securityPolicyInUseDetails (D3): up to five sites still running the
// policy a delete was refused for.
type securityPolicyInUseDetails struct {
	Sites []securityPolicyInUseSite `json:"sites"`
}

type securityPolicyInUseSite struct {
	ID     string `json:"id"`
	Domain string `json:"domain"`
}

// streamPortConflictDetails is where a stream save's listen ports collide
// (l4forward.PortConflictError): with is reserved, self, stream or site;
// name is the other resource in the caller's scope, when known.
type streamPortConflictDetails struct {
	Protocol string `json:"protocol"`
	Port     uint16 `json:"port"`
	PortEnd  uint16 `json:"port_end,omitempty"`
	With     string `json:"with"`
	Name     string `json:"name,omitempty"`
}

func (s *Server) writeError(w http.ResponseWriter, r *http.Request, err error) {
	if status, code, ok := packageRuntimeError(err); ok {
		s.writeAPIError(w, r, status, code, http.StatusText(status))
		return
	}
	if s.writeLoginSecurityError(w, r, err) {
		return
	}
	if located, ok := fielderr.As(err); ok {
		s.writeFieldError(w, r, located.Field, located.Reason)
		return
	}
	switch {
	case errors.Is(err, dnssettings.ErrInvalidInput):
		s.writeAPIError(w, r, http.StatusBadRequest, "validation_error", "DNS settings fields are invalid")
	case errors.Is(err, dnssettings.ErrPermissionDenied):
		s.writeAPIError(w, r, http.StatusForbidden, "permission_denied", "permission is required")
	case errors.Is(err, dnssettings.ErrNotFound):
		s.writeAPIError(w, r, http.StatusNotFound, "dns_settings_not_found", "DNS settings resource was not found")
	case errors.Is(err, dnssettings.ErrRevisionConflict):
		s.writeAPIError(w, r, http.StatusConflict, "version_conflict", "DNS settings version is stale")
	case errors.Is(err, dnssettings.ErrIdempotencyConflict):
		s.writeAPIError(w, r, http.StatusConflict, "idempotency_conflict", "idempotency key was already used with different input")
	case errors.Is(err, dnssettings.ErrUnavailable):
		s.writeAPIError(w, r, http.StatusServiceUnavailable, "dns_settings_unavailable", "DNS settings service is unavailable")
	case errors.Is(err, apikey.ErrInvalidCredential):
		s.writeAPIError(w, r, http.StatusUnauthorized, "invalid_api_key", "API key authentication failed")
	case errors.Is(err, apikey.ErrInvalidInput):
		s.writeAPIError(w, r, http.StatusBadRequest, "validation_error", "API key request fields are invalid")
	case errors.Is(err, apikey.ErrPermissionDenied):
		s.writeAPIError(w, r, http.StatusForbidden, "permission_denied", "permission is required")
	case errors.Is(err, apikey.ErrNotFound):
		s.writeAPIError(w, r, http.StatusNotFound, "api_key_not_found", "API key was not found")
	case errors.Is(err, apikey.ErrRevisionConflict):
		s.writeAPIError(w, r, http.StatusConflict, "version_conflict", "API key revision is stale")
	case errors.Is(err, apikey.ErrIdempotencyConflict):
		s.writeAPIError(w, r, http.StatusConflict, "idempotency_conflict", "idempotency key was already used with different input")
	case errors.Is(err, apikey.ErrInvalidTransition):
		s.writeAPIError(w, r, http.StatusConflict, "api_key_state_conflict", "API key state does not allow this operation")
	case errors.Is(err, apikey.ErrDisabled):
		s.writeAPIError(w, r, http.StatusForbidden, "api_key_disabled", "API key service is disabled by platform policy")
	case errors.Is(err, apikey.ErrUnavailable):
		s.writeAPIError(w, r, http.StatusServiceUnavailable, "api_key_unavailable", "API key service is unavailable")
	case errors.Is(err, identity.ErrInvalidCredentials):
		s.writeAPIError(w, r, http.StatusUnauthorized, "invalid_credentials", "username or password is incorrect")
	case errors.Is(err, identity.ErrInvalidSession):
		s.writeAPIError(w, r, http.StatusUnauthorized, "invalid_session", "authentication is required")
	case errors.Is(err, identity.ErrRefreshReplay):
		s.writeAPIError(w, r, http.StatusUnauthorized, "refresh_replayed", "refresh token reuse revoked the session")
	case errors.Is(err, identity.ErrAccountDisabled):
		s.writeAPIError(w, r, http.StatusForbidden, "account_disabled", "account is disabled")
	case errors.Is(err, identity.ErrMembershipDisabled):
		s.writeAPIError(w, r, http.StatusForbidden, "membership_disabled", "membership is disabled")
	case errors.Is(err, identity.ErrPermissionDenied):
		s.writeAPIError(w, r, http.StatusForbidden, "permission_denied", "permission is required")
	case errors.Is(err, identity.ErrInvalidUserInput):
		if details, ok := passwordpolicy.DetailsOf(err); ok {
			writeJSONStatus(w, http.StatusBadRequest, errorEnvelope{Error: apiError{Code: passwordpolicy.Code,
				Message:   "password needs 8 to 1024 characters with at least two of upper case, lower case, digits and symbols",
				RequestID: requestID(r.Context()), Details: details}})
			return
		}
		s.writeAPIError(w, r, http.StatusBadRequest, "validation_error", "request fields are invalid")
	case errors.Is(err, marketmanaged.ErrManaged):
		s.writeAPIError(w, r, http.StatusConflict, "market_managed",
			"this account serves a node-market subscriber; the supplier cannot disable or delete it (ADR 0012 §18.4)")
	case errors.Is(err, identity.ErrUserNotFound):
		s.writeAPIError(w, r, http.StatusNotFound, "user_not_found", "user was not found")
	case errors.Is(err, identity.ErrUserProtected):
		s.writeAPIError(w, r, http.StatusConflict, "user_protected", "the platform administrator is protected from this change")
	case errors.Is(err, identity.ErrRevisionConflict):
		s.writeAPIError(w, r, http.StatusConflict, "version_conflict", "user version is stale")
	case errors.Is(err, identity.ErrIdempotencyConflict):
		s.writeAPIError(w, r, http.StatusConflict, "idempotency_conflict", "idempotency key was already used with different input")
	case errors.Is(err, identity.ErrConflict):
		s.writeAPIError(w, r, http.StatusConflict, "username_conflict", "username already exists")
	case errors.Is(err, controlupgrade.ErrInvalidInput):
		s.writeAPIError(w, r, http.StatusBadRequest, "validation_error", "request fields are invalid")
	case errors.Is(err, controlupgrade.ErrPermissionDenied):
		s.writeAPIError(w, r, http.StatusForbidden, "permission_denied", "permission is required")
	case errors.Is(err, controlupgrade.ErrIdempotencyConflict):
		s.writeAPIError(w, r, http.StatusConflict, "idempotency_conflict", "idempotency key was already used with different input")
	case errors.Is(err, node.ErrInvalidInput):
		s.writeAPIError(w, r, http.StatusBadRequest, "validation_error", "request fields are invalid")
	case errors.Is(err, node.ErrNotFound):
		s.writeAPIError(w, r, http.StatusNotFound, "node_not_found", "node was not found")
	case errors.Is(err, node.ErrDuplicateName):
		s.writeAPIError(w, r, http.StatusConflict, "node_name_conflict", "node name already exists")
	case errors.Is(err, node.ErrSchedule302HostnameConflict):
		s.writeAPIError(w, r, http.StatusConflict, "node_schedule302_hostname_conflict", "another node already has this direct hostname")
	case errors.Is(err, node.ErrStorageUnsupported):
		s.writeAPIError(w, r, http.StatusConflict, "node_storage_unsupported", "the node agent does not support cache and log directory settings; upgrade the node first")
	case errors.Is(err, node.ErrStorageExceedsDisk):
		s.writeAPIError(w, r, http.StatusBadRequest, "node_cache_limit_exceeds_disk", "the cache limit is larger than the disk holding the cache directory")
	case errors.Is(err, node.ErrEnrollmentDenied):
		s.writeAPIError(w, r, http.StatusConflict, "enrollment_denied", "node is not eligible for enrollment")
	case errors.Is(err, node.ErrInvalidToken), errors.Is(err, node.ErrTokenExpired), errors.Is(err, node.ErrTokenConsumed):
		s.writeAPIError(w, r, http.StatusUnauthorized, "invalid_enrollment_token", "enrollment token is invalid")
	case errors.Is(err, node.ErrIdempotencyConflict):
		s.writeAPIError(w, r, http.StatusConflict, "idempotency_conflict", "idempotency key was already used with different input")
	case errors.Is(err, site.ErrInvalidInput):
		s.writeAPIError(w, r, http.StatusBadRequest, "validation_error", "request fields are invalid")
	case errors.Is(err, site.ErrPermissionDenied):
		s.writeAPIError(w, r, http.StatusForbidden, "permission_denied", "permission is required")
	case errors.Is(err, site.ErrNotFound):
		s.writeAPIError(w, r, http.StatusNotFound, "site_not_found", "site was not found")
	case errors.Is(err, domaintrust.ErrDomainBlocked):
		// Certificates (dnsacme) and CNAME names share the site rule: the
		// administrator's reason is never revealed.
		s.writeDomainTrustError(w, r, err, http.StatusUnprocessableEntity, "domain_blocked", "site domain is not allowed")
	case errors.Is(err, site.ErrDomainConflict):
		s.writeAPIError(w, r, http.StatusConflict, "site_domain_conflict", "site domain already exists")
	case errors.Is(err, site.ErrRevisionConflict):
		s.writeAPIError(w, r, http.StatusConflict, "version_conflict", "site version is stale")
	case errors.Is(err, site.ErrIdempotencyConflict):
		s.writeAPIError(w, r, http.StatusConflict, "idempotency_conflict", "idempotency key was already used with different input")
	case errors.Is(err, securitypolicy.ErrIPListUnavailable):
		s.writeAPIError(w, r, http.StatusUnprocessableEntity, "ip_list_unavailable",
			"an ip_list condition names an IP list that does not exist or that this tenant cannot use")
	case errors.Is(err, securitypolicy.ErrInvalidInput):
		s.writeAPIError(w, r, http.StatusBadRequest, "validation_error", "security policy request fields are invalid")
	case errors.Is(err, securitypolicy.ErrPermissionDenied):
		s.writeAPIError(w, r, http.StatusForbidden, "permission_denied", "permission is required")
	case errors.Is(err, securitypolicy.ErrNotFound):
		s.writeAPIError(w, r, http.StatusNotFound, "security_policy_not_found", "security policy was not found")
	case errors.Is(err, securitypolicy.ErrInUse):
		// D3: names the sites (message and details.domains); the page lists
		// them and links each to its security publish panel.
		details := &securityPolicyInUseDetails{Sites: []securityPolicyInUseSite{}}
		var inUse *securitypolicy.InUseError
		if errors.As(err, &inUse) {
			for index, domain := range inUse.Domains {
				if index < len(inUse.SiteIDs) {
					details.Sites = append(details.Sites, securityPolicyInUseSite{ID: inUse.SiteIDs[index].String(), Domain: domain})
				}
			}
		}
		writeJSONStatus(w, http.StatusConflict, errorEnvelope{Error: apiError{Code: "security_policy_in_use",
			Message: err.Error(), RequestID: requestID(r.Context()), Details: details}})
	case errors.Is(err, securitypolicy.ErrConflict):
		s.writeAPIError(w, r, http.StatusConflict, "security_policy_name_conflict", "security policy name already exists")
	case errors.Is(err, securitypolicy.ErrRevisionConflict):
		s.writeAPIError(w, r, http.StatusConflict, "version_conflict", "security policy version is stale")
	case errors.Is(err, securitypolicy.ErrIdempotencyConflict):
		s.writeAPIError(w, r, http.StatusConflict, "idempotency_conflict", "idempotency key was already used with different input")
	case errors.Is(err, ccreference.ErrInvalidInput):
		s.writeAPIError(w, r, http.StatusBadRequest, "validation_error", "CC matcher or filter fields are invalid")
	case errors.Is(err, ccreference.ErrPermissionDenied):
		s.writeAPIError(w, r, http.StatusForbidden, "permission_denied", "permission is required")
	case errors.Is(err, ccreference.ErrSystemRuleManaged):
		s.writeAPIError(w, r, http.StatusForbidden, "cc_reference_system_managed", "system CC rules are managed by the platform")
	case errors.Is(err, ccreference.ErrNotFound):
		s.writeAPIError(w, r, http.StatusNotFound, "cc_reference_not_found", "CC matcher or filter was not found")
	case errors.Is(err, ccreference.ErrConflict):
		s.writeAPIError(w, r, http.StatusConflict, "cc_reference_name_conflict", "CC matcher or filter name already exists")
	case errors.Is(err, ccreference.ErrRevisionConflict):
		s.writeAPIError(w, r, http.StatusConflict, "version_conflict", "CC matcher or filter version is stale")
	case errors.Is(err, ccreference.ErrIdempotencyConflict):
		s.writeAPIError(w, r, http.StatusConflict, "idempotency_conflict", "idempotency key was already used with different input")
	case errors.Is(err, urlauthpolicy.ErrInvalidInput):
		s.writeAPIError(w, r, http.StatusBadRequest, "validation_error", "URL auth policy request fields are invalid")
	case errors.Is(err, urlauthpolicy.ErrPermissionDenied):
		s.writeAPIError(w, r, http.StatusForbidden, "permission_denied", "permission is required")
	case errors.Is(err, urlauthpolicy.ErrNotFound):
		s.writeAPIError(w, r, http.StatusNotFound, "url_auth_policy_not_found", "URL auth policy was not found")
	case errors.Is(err, urlauthpolicy.ErrConflict):
		s.writeAPIError(w, r, http.StatusConflict, "url_auth_policy_conflict", "URL auth policy conflicts with an existing site or name")
	case errors.Is(err, urlauthpolicy.ErrRevisionConflict):
		s.writeAPIError(w, r, http.StatusConflict, "version_conflict", "URL auth policy version is stale")
	case errors.Is(err, urlauthpolicy.ErrIdempotencyConflict):
		s.writeAPIError(w, r, http.StatusConflict, "idempotency_conflict", "idempotency key was already used with different input")
	case errors.Is(err, urlauthpolicy.ErrKeyNotRevocable):
		s.writeAPIError(w, r, http.StatusConflict, "url_auth_key_not_revocable", "only the current previous key may be revoked")
	case errors.Is(err, urlauthpolicy.ErrEncryptionUnavailable):
		s.writeAPIError(w, r, http.StatusServiceUnavailable, "credential_encryption_unavailable", "URL auth key encryption is unavailable")
	case errors.Is(err, l4forward.ErrInvalidInput):
		// L4-006：能定位的字段带 details.field/reason（与站点写入的 siteFieldErrorDetails 同形）。
		var field *l4forward.FieldError
		if errors.As(err, &field) {
			writeJSONStatus(w, http.StatusBadRequest, errorEnvelope{Error: apiError{
				Code: "validation_error", Message: field.Error(), RequestID: requestID(r.Context()),
				Details: siteFieldErrorDetails{Field: field.Field, Reason: field.Reason},
			}})
			return
		}
		s.writeAPIError(w, r, http.StatusBadRequest, "validation_error", "request fields are invalid")
	case errors.Is(err, l4forward.ErrPermissionDenied):
		s.writeAPIError(w, r, http.StatusForbidden, "permission_denied", "permission is required")
	case errors.Is(err, l4forward.ErrNotFound):
		s.writeAPIError(w, r, http.StatusNotFound, "stream_not_found", "forwarding rule was not found")
	case errors.Is(err, l4forward.ErrPortConflict):
		var located *l4forward.PortConflictError
		if errors.As(err, &located) {
			writeJSONStatus(w, http.StatusConflict, errorEnvelope{Error: apiError{
				Code: "stream_port_conflict", Message: located.Error(), RequestID: requestID(r.Context()),
				Details: &streamPortConflictDetails{Protocol: located.Protocol, Port: located.Port, PortEnd: located.PortEnd,
					With: located.With, Name: located.Name},
			}})
			return
		}
		s.writeAPIError(w, r, http.StatusConflict, "stream_port_conflict", "listen port conflicts with an existing resource")
	case errors.Is(err, l4forward.ErrSharedPortProxyProtocol):
		s.writeAPIError(w, r, http.StatusConflict, "stream_shared_port_proxy_protocol",
			"PROXY protocol cannot be used on a port shared with other streams or websites")
	case errors.Is(err, l4forward.ErrNameConflict):
		s.writeAPIError(w, r, http.StatusConflict, "stream_name_conflict", "forwarding rule name already exists")
	case errors.Is(err, l4forward.ErrRevisionConflict):
		s.writeAPIError(w, r, http.StatusConflict, "version_conflict", "forwarding rule version is stale")
	case errors.Is(err, l4forward.ErrIdempotencyConflict):
		s.writeAPIError(w, r, http.StatusConflict, "idempotency_conflict", "idempotency key was already used with different input")
	case errors.Is(err, l4forward.ErrGroupNotFound):
		s.writeAPIError(w, r, http.StatusNotFound, "stream_group_not_found", "forward group was not found")
	case errors.Is(err, l4forward.ErrGroupNameConflict):
		s.writeAPIError(w, r, http.StatusConflict, "stream_group_name_conflict", "forward group name already exists")
	case errors.Is(err, l4forward.ErrGroupInUse):
		s.writeAPIError(w, r, http.StatusConflict, "stream_group_in_use", "forward group is still referenced")
	case errors.Is(err, l4forward.ErrDefaultNotFound):
		s.writeAPIError(w, r, http.StatusNotFound, "stream_default_not_found", "forward setting was not found")
	case errors.Is(err, l4forward.ErrDefaultScopeNeedID):
		s.writeAPIError(w, r, http.StatusBadRequest, "validation_error", "group scope requires a group_id")
	case errors.As(err, new(*packagecatalog.BelowWholesaleError)):
		var below *packagecatalog.BelowWholesaleError
		errors.As(err, &below)
		writeJSONStatus(w, http.StatusBadRequest, errorEnvelope{Error: apiError{Code: "package_price_below_wholesale",
			Message: fmt.Sprintf("the %s price %d is below the wholesale price %d of the line groups (price list %s)",
				below.Period, below.PriceMinor, below.WholesaleMinor, below.PriceList),
			RequestID: requestID(r.Context()), Details: below}})
	case errors.Is(err, packagecatalog.ErrLineGroupNotGranted):
		s.writeAPIError(w, r, http.StatusBadRequest, "package_line_group_not_granted", "the line group is not granted to the reseller")
	case errors.Is(err, packagecatalog.ErrInvalidInput):
		s.writeAPIError(w, r, http.StatusBadRequest, "validation_error", "request fields are invalid")
	case errors.Is(err, packagecatalog.ErrPublicationUnsupported):
		s.writeAPIError(w, r, http.StatusUnprocessableEntity, "package_offer_unsupported", "package offer cannot be published")
	case errors.Is(err, packagecatalog.ErrPermissionDenied):
		s.writeAPIError(w, r, http.StatusForbidden, "permission_denied", "permission is required")
	case errors.Is(err, packagecatalog.ErrNotFound):
		s.writeAPIError(w, r, http.StatusNotFound, "package_resource_not_found", "package resource was not found")
	case errors.Is(err, packagecatalog.ErrNameConflict):
		s.writeAPIError(w, r, http.StatusConflict, "package_name_conflict", "package resource name already exists")
	case errors.Is(err, packagecatalog.ErrRevisionConflict):
		s.writeAPIError(w, r, http.StatusConflict, "version_conflict", "package resource version is stale")
	case errors.Is(err, packagecatalog.ErrIdempotencyConflict):
		s.writeAPIError(w, r, http.StatusConflict, "idempotency_conflict", "idempotency key was already used with different input")
	case errors.Is(err, packagecatalog.ErrGroupInUse):
		s.writeAPIError(w, r, http.StatusConflict, "package_group_in_use", "package group is referenced by an active package")
	case errors.Is(err, packagecatalog.ErrCNAMEDomainNotConfigured):
		s.writeAPIError(w, r, http.StatusUnprocessableEntity, "package_cname_domain_not_configured", "the package CNAME domain is not a CNAME domain of the DNS configuration")
	case errors.Is(err, packagecatalog.ErrCNAMESyncNotRetryable):
		s.writeAPIError(w, r, http.StatusConflict, "package_cname_sync_not_retryable", "only a failed package CNAME sync can be retried")
	case errors.Is(err, packagecatalog.ErrPublicationConflict):
		s.writeAPIError(w, r, http.StatusConflict, "package_offer_state_conflict", "package offer state does not allow this operation")
	case errors.Is(err, dnsacme.ErrIssuerUnavailable):
		s.writeAPIError(w, r, http.StatusConflict, "certificate_issuer_unavailable", "the certificate issuer is not configured by the platform")
	case errors.Is(err, dnsacme.ErrOrderInFlight):
		s.writeAPIError(w, r, http.StatusConflict, "certificate_order_in_flight", "an order for these domains is still in progress")
	case errors.Is(err, dnsacme.ErrInvalidInput), errors.Is(err, dnsacme.ErrInvalidTransition):
		s.writeAPIError(w, r, http.StatusBadRequest, "validation_error", "request fields are invalid")
	case errors.Is(err, dnsacme.ErrPermissionDenied):
		s.writeAPIError(w, r, http.StatusForbidden, "permission_denied", "permission is required")
	case errors.Is(err, dnsacme.ErrNotFound):
		s.writeAPIError(w, r, http.StatusNotFound, "dns_resource_not_found", "DNS or certificate resource was not found")
	case errors.Is(err, dnsacme.ErrProviderReauthorizationRequired):
		s.writeAPIError(w, r, http.StatusConflict, "dns_provider_reauthorization_required",
			"the DNS account was disabled and its credentials revoked; enter new credentials to enable it")
	case errors.Is(err, dnsacme.ErrPlatformManagedProvider):
		s.writeAPIError(w, r, http.StatusConflict, "dns_provider_platform_managed",
			"the DNS account is managed by the platform; choose your own DNS account")
	case errors.Is(err, dnsacme.ErrPlatformOnly):
		s.writeAPIError(w, r, http.StatusForbidden, "dns_platform_only", "the DNS configuration is managed by the platform administrator")
	case errors.Is(err, dnsacme.ErrPlatformNotConfigured):
		s.writeAPIError(w, r, http.StatusConflict, "dns_not_configured", "save the DNS configuration first")
	case errors.Is(err, dnsacme.ErrZoneNotHosted):
		s.writeAPIError(w, r, http.StatusUnprocessableEntity, "dns_zone_not_hosted", "the domain is not hosted by the selected DNS account")
	case errors.Is(err, dnsacme.ErrPlatformZoneInUse):
		s.writeAPIError(w, r, http.StatusConflict, "dns_zone_in_use", "the CNAME domain still has sites allocated")
	case errors.Is(err, dnsacme.ErrConflict):
		s.writeAPIError(w, r, http.StatusConflict, "dns_resource_conflict", "DNS or certificate resource conflicts with existing state")
	case errors.Is(err, dnsacme.ErrRevisionConflict):
		s.writeAPIError(w, r, http.StatusConflict, "version_conflict", "resource version is stale")
	case errors.Is(err, dnsacme.ErrIdempotencyConflict):
		s.writeAPIError(w, r, http.StatusConflict, "idempotency_conflict", "idempotency key was already used with different input")
	case errors.Is(err, dnsacme.ErrCredentialUnavailable):
		s.writeAPIError(w, r, http.StatusServiceUnavailable, "credential_encryption_unavailable", "DNS credential encryption is unavailable")
	case errors.Is(err, dnsacme.ErrProviderVerificationUnsupported):
		s.writeAPIError(w, r, http.StatusUnprocessableEntity, "provider_verification_unsupported", "DNS provider verification is not supported")
	case errors.Is(err, dnsacme.ErrProviderDisabled):
		s.writeAPIError(w, r, http.StatusConflict, "provider_disabled", "DNS provider is disabled")
	case errors.Is(err, dnsacme.ErrProviderCredentialsInvalid):
		s.writeAPIError(w, r, http.StatusUnprocessableEntity, "provider_credentials_invalid", "DNS provider credentials are invalid")
	case errors.Is(err, dnsacme.ErrProviderTokenInactive):
		s.writeAPIError(w, r, http.StatusUnprocessableEntity, "provider_token_inactive", "DNS provider token is inactive")
	case errors.Is(err, dnsacme.ErrProviderCredentialsRejected):
		s.writeAPIError(w, r, http.StatusUnprocessableEntity, "provider_credentials_rejected", "DNS provider credentials were rejected")
	case errors.Is(err, dnsacme.ErrProviderPluginNotUsable):
		s.writeAPIError(w, r, http.StatusConflict, "provider_plugin_not_usable", "the DNS provider plugin has not passed its contract or is not enabled")
	case errors.Is(err, dnsacme.ErrProviderVerificationRateLimited):
		if retryAfter := dnsacme.ProviderVerificationRetryAfter(err); retryAfter != "" {
			w.Header().Set("Retry-After", retryAfter)
		}
		s.writeAPIError(w, r, http.StatusTooManyRequests, "provider_verification_rate_limited", "DNS provider verification was rate limited")
	case errors.Is(err, dnsacme.ErrProviderVerificationUnavailable):
		s.writeAPIError(w, r, http.StatusServiceUnavailable, "provider_verification_unavailable", "DNS provider verification is unavailable")
	case errors.Is(err, dnsacme.ErrProviderVerificationInvalidResponse):
		s.writeAPIError(w, r, http.StatusBadGateway, "provider_verification_invalid_response", "DNS provider returned an invalid verification response")
	case errors.Is(err, dnsacme.ErrProviderVerificationTimeout):
		s.writeAPIError(w, r, http.StatusGatewayTimeout, "provider_verification_timeout", "DNS provider verification timed out")
	case errors.Is(err, certdefaults.ErrInvalidInput):
		s.writeAPIError(w, r, http.StatusBadRequest, "validation_error", "certificate default fields are invalid")
	case errors.Is(err, certdefaults.ErrPermissionDenied):
		s.writeAPIError(w, r, http.StatusForbidden, "permission_denied", "permission is required")
	case errors.Is(err, certdefaults.ErrNotFound):
		s.writeAPIError(w, r, http.StatusNotFound, "certificate_defaults_not_found", "certificate defaults target was not found")
	case errors.Is(err, certdefaults.ErrRevisionConflict):
		s.writeAPIError(w, r, http.StatusConflict, "version_conflict", "certificate defaults version is stale")
	case errors.Is(err, certdefaults.ErrIdempotencyConflict):
		s.writeAPIError(w, r, http.StatusConflict, "idempotency_conflict", "idempotency key was already used with different input")
	case errors.Is(err, certdefaults.ErrIssuerUnavailable):
		s.writeAPIError(w, r, http.StatusConflict, "certificate_issuer_unavailable", "the certificate issuer is not configured by the platform")
	case errors.Is(err, certdefaults.ErrProviderInvalid):
		s.writeAPIError(w, r, http.StatusConflict, "dns_resource_conflict", "DNS provider is disabled or not in the target scope")
	case errors.Is(err, entitlementguard.ErrUnavailable):
		s.writeAPIError(w, r, http.StatusForbidden, "entitlement_unavailable", "a verified local entitlement lease is required")
	case errors.Is(err, entitlementguard.ErrStateDenied):
		s.writeAPIError(w, r, http.StatusForbidden, "entitlement_state_denied", "the local entitlement state does not allow this change")
	case errors.Is(err, entitlementguard.ErrFeatureDenied):
		s.writeAPIError(w, r, http.StatusForbidden, "entitlement_feature_denied", "the local entitlement lease does not grant this feature")
	case errors.Is(err, entitlementguard.ErrQuotaDenied):
		s.writeAPIError(w, r, http.StatusForbidden, "entitlement_quota_denied", "the local entitlement lease does not grant this quota")
	case errors.Is(err, entitlementguard.ErrQuotaExceeded):
		s.writeAPIError(w, r, http.StatusConflict, "entitlement_quota_exceeded", "the local entitlement quota is exhausted")
	default:
		s.logger.ErrorContext(r.Context(), "request failed",
			"request_id", requestID(r.Context()),
			"method", r.Method,
			"path", r.URL.Path,
			"error", err,
		)
		s.writeAPIError(w, r, http.StatusInternalServerError, "internal_error", "the request could not be completed")
	}
}

func (s *Server) writeAPIError(w http.ResponseWriter, r *http.Request, status int, code string, message string) {
	writeJSONStatus(w, status, errorEnvelope{Error: apiError{
		Code:      code,
		Message:   message,
		RequestID: requestID(r.Context()),
	}})
}

// writeFieldError is the 400 validation_error of one refused request field
// (details.field is the JSON path as sent, details.reason a fielderr reason).
func (s *Server) writeFieldError(w http.ResponseWriter, r *http.Request, field, reason string) {
	writeJSONStatus(w, http.StatusBadRequest, errorEnvelope{Error: apiError{
		Code: "validation_error", Message: "request field " + field + " is invalid: " + reason,
		RequestID: requestID(r.Context()), Details: siteFieldErrorDetails{Field: field, Reason: reason},
	}})
}

func (s *Server) withRequestID(next http.Handler) http.Handler {
	return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		id := strings.TrimSpace(r.Header.Get("X-Request-ID"))
		if !requestIDPattern.MatchString(id) {
			id = uuid.NewString()
		}
		w.Header().Set("X-Request-ID", id)
		next.ServeHTTP(w, r.WithContext(context.WithValue(r.Context(), requestIDKey{}, id)))
	})
}

func (s *Server) withAPIKeyClientIP(next http.Handler) http.Handler {
	return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		address, err := s.apiKeySourceIP.ResolveSourceIP(r)
		// Audit events written while serving this request carry the browser UA (tp-b6b).
		ctx := audit.WithUserAgent(r.Context(), r.UserAgent())
		switch {
		case err == nil:
			ctx = apikeycredential.WithClientIP(ctx, address, requestID(ctx))
			// Audit events written while serving this request carry the address.
			ctx = audit.WithSourceIP(ctx, address)
		case errors.Is(err, accountrecoverycontext.ErrSourceIPMissing):
			ctx = apikeycredential.WithClientIPFailure(ctx, requestID(ctx), apikeycredential.ReasonClientIPMissing)
		case errors.Is(err, accountrecoverycontext.ErrSourceIPSpoofed):
			ctx = apikeycredential.WithClientIPFailure(ctx, requestID(ctx), apikeycredential.ReasonClientIPSpoofed)
		default:
			ctx = apikeycredential.WithClientIPFailure(ctx, requestID(ctx), apikeycredential.ReasonClientIPInvalid)
		}
		next.ServeHTTP(w, r.WithContext(ctx))
	})
}

// passwordChangeExempt marks the requests a user who must change the password
// at the next sign-in can still make: reading the session and changing the
// password (identity.ErrPasswordChangeRequired).
func passwordChangeExempt(next http.HandlerFunc) http.HandlerFunc {
	return func(w http.ResponseWriter, r *http.Request) {
		next(w, r.WithContext(identity.WithPasswordChangeExempt(r.Context())))
	}
}

// WithClientSourceIP records the trusted client address (same resolver as
// the API key and audit paths) on every request, including handlers mounted
// outside Handler(), so session checks such as the platform administration
// allowlist see the real client address.
func (s *Server) WithClientSourceIP(next http.Handler) http.Handler {
	if s == nil || s.apiKeySourceIP == nil {
		return next
	}
	return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if audit.SourceIPFrom(r.Context()) == "" {
			if address, err := s.apiKeySourceIP.ResolveSourceIP(r); err == nil {
				r = r.WithContext(audit.WithSourceIP(r.Context(), address))
			}
		}
		if audit.UserAgentFrom(r.Context()) == "" {
			r = r.WithContext(audit.WithUserAgent(r.Context(), r.UserAgent()))
		}
		next.ServeHTTP(w, r)
	})
}

type impersonationDelegateKey struct{}

type impersonationDelegate struct {
	session impersonationhttp.AuthorizedSession
	err     error
}

// WithImpersonationDelegate makes an impersonation session act as the target
// user on every route (fix-imperson, 1.0.35). The browser keeps the
// administrator's access token and identifies the impersonation by the
// cdnca_impersonation cookie; most handlers only read the Bearer, or re-verify
// the raw token / session ID in their own transaction, so they saw the
// administrator and refused tenant pages. Here the cookie is authorized once
// (impersonation action rules and the identity.impersonation.use audit
// apply) and the Authorization header is replaced with an in-process token of
// the target user's delegate session. A refused cookie removes the
// Authorization header: the request never falls back to the administrator.
// The impersonation management routes and the /v1/auth/* session routes keep
// the original request (they need the primary session). Idempotent: an
// already delegated request passes through.
func (s *Server) WithImpersonationDelegate(next http.Handler) http.Handler {
	if s == nil {
		return next
	}
	return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if _, done := r.Context().Value(impersonationDelegateKey{}).(impersonationDelegate); done ||
			s.impersonationSessionAuthorizer == nil || s.identity == nil || !impersonationDelegatedPath(r) {
			next.ServeHTTP(w, r)
			return
		}
		if _, err := r.Cookie(impersonationhttp.CookieName); err != nil {
			next.ServeHTTP(w, r)
			return
		}
		forwarded := r.Clone(r.Context())
		forwarded.Header = r.Header.Clone()
		// The identity.impersonation.use audit row and the business audit rows
		// of this request share one request ID.
		if !requestIDPattern.MatchString(strings.TrimSpace(forwarded.Header.Get("X-Request-ID"))) {
			forwarded.Header.Set("X-Request-ID", uuid.NewString())
		}
		session, _, err := s.authorizeImpersonationCookie(forwarded)
		var token string
		if err == nil {
			token, err = s.identity.ImpersonationAccessToken(r.Context(), session.SessionID,
				session.Principal.UserID, session.Principal.ScopeID, session.Banner.ExpiresAt)
		}
		forwarded = forwarded.WithContext(context.WithValue(r.Context(), impersonationDelegateKey{},
			impersonationDelegate{session: session, err: err}))
		forwarded.Header.Del("Authorization")
		if err == nil {
			forwarded.Header.Set("Authorization", "Bearer "+token)
		}
		next.ServeHTTP(w, forwarded)
	})
}

func impersonationDelegatedPath(r *http.Request) bool {
	if r == nil || r.URL == nil {
		return false
	}
	path := r.URL.Path
	return strings.HasPrefix(path, "/v1/") && !strings.HasPrefix(path, "/v1/auth/") &&
		!strings.HasPrefix(path, "/v1/admin/impersonation/")
}

type requestIDKey struct{}

func requestID(ctx context.Context) string {
	value, _ := ctx.Value(requestIDKey{}).(string)
	return value
}

func (s *Server) requestInfo(r *http.Request) identity.RequestInfo {
	host, _, err := net.SplitHostPort(r.RemoteAddr)
	if err != nil {
		host = ""
	}
	if net.ParseIP(host) == nil {
		host = ""
	}
	if s != nil && s.apiKeySourceIP != nil {
		address, resolveErr := s.apiKeySourceIP.ResolveSourceIP(r)
		if resolveErr == nil {
			host = address.String()
		} else {
			host = ""
		}
	}
	return identity.RequestInfo{
		RequestID: requestID(r.Context()),
		UserAgent: truncate(r.UserAgent(), 512),
		SourceIP:  host,
	}
}

func decodeJSON(w http.ResponseWriter, r *http.Request, destination any) error {
	r.Body = http.MaxBytesReader(w, r.Body, 1<<20)
	decoder := json.NewDecoder(r.Body)
	decoder.DisallowUnknownFields()
	if err := decoder.Decode(destination); err != nil {
		return err
	}
	if err := decoder.Decode(&struct{}{}); !errors.Is(err, io.EOF) {
		return fmt.Errorf("request body must contain one JSON object")
	}
	return nil
}

func truncate(value string, limit int) string {
	if len(value) <= limit {
		return value
	}
	return value[:limit]
}

func writeJSON(w http.ResponseWriter, status int, value any) {
	writeJSONStatus(w, status, value)
}

func writeJSONStatus(w http.ResponseWriter, status int, value any) {
	w.Header().Set("Content-Type", "application/json")
	w.WriteHeader(status)
	_ = json.NewEncoder(w).Encode(value)
}

func securityBanStore(pool *pgxpool.Pool, config Config) *securityban.Store {
	if config.SecurityBanStore != nil {
		return config.SecurityBanStore
	}
	return securityban.NewStore(pool, config.Now)
}

func newDNSACMEService(pool *pgxpool.Pool, config Config) *dnsacme.Service {
	service := dnsacme.NewServiceWithClockAndVerifier(dnsacme.NewStoreWithEntitlement(pool, config.Now, config.EntitlementTrust),
		config.DNSCredentialCipher, config.DNSProviderVerifier, config.Now)
	if config.DNSZoneApexResolver != nil {
		service.UseZoneApexResolver(config.DNSZoneApexResolver)
	}
	return service
}
