package main

import (
	"bytes"
	"context"
	"crypto/ed25519"
	"crypto/hmac"
	"crypto/rand"
	"crypto/sha256"
	"crypto/subtle"
	"crypto/x509"
	"encoding/base64"
	"encoding/json"
	"encoding/pem"
	"errors"
	"flag"
	"fmt"
	"io"
	"log/slog"
	"net"
	"net/http"
	"net/mail"
	"net/netip"
	"os"
	"os/signal"
	"reflect"
	"sort"
	"strconv"
	"strings"
	"sync"
	"sync/atomic"
	"syscall"
	"time"

	"github.com/aws/aws-sdk-go-v2/aws"
	"github.com/cdnca/cdnca/libs/entitlement"
	"github.com/cdnca/cdnca/libs/rulepack"
	"github.com/cdnca/cdnca/services/control-api/internal/accountrecoverycontext"
	"github.com/cdnca/cdnca/services/control-api/internal/accountrecoveryhttp"
	"github.com/cdnca/cdnca/services/control-api/internal/acmehttp01"
	"github.com/cdnca/cdnca/services/control-api/internal/analytics"
	"github.com/cdnca/cdnca/services/control-api/internal/analyticsdiagnostichttp"
	"github.com/cdnca/cdnca/services/control-api/internal/analyticsgeo"
	"github.com/cdnca/cdnca/services/control-api/internal/analyticsgeohttp"
	"github.com/cdnca/cdnca/services/control-api/internal/analyticslog"
	"github.com/cdnca/cdnca/services/control-api/internal/analyticsreplicametrics"
	"github.com/cdnca/cdnca/services/control-api/internal/apikey"
	"github.com/cdnca/cdnca/services/control-api/internal/apikeycredential"
	"github.com/cdnca/cdnca/services/control-api/internal/approvalcenter"
	"github.com/cdnca/cdnca/services/control-api/internal/artifactsetdist"
	"github.com/cdnca/cdnca/services/control-api/internal/artifactsync"
	"github.com/cdnca/cdnca/services/control-api/internal/attackalert"
	"github.com/cdnca/cdnca/services/control-api/internal/audit"
	"github.com/cdnca/cdnca/services/control-api/internal/cccoordhttp"
	"github.com/cdnca/cdnca/services/control-api/internal/ccinherit"
	"github.com/cdnca/cdnca/services/control-api/internal/certificateasset"
	"github.com/cdnca/cdnca/services/control-api/internal/certificateassethttp"
	"github.com/cdnca/cdnca/services/control-api/internal/certificateexpiry"
	"github.com/cdnca/cdnca/services/control-api/internal/challengepolicy"
	"github.com/cdnca/cdnca/services/control-api/internal/challengepublication"
	"github.com/cdnca/cdnca/services/control-api/internal/cnameallocationhttp"
	"github.com/cdnca/cdnca/services/control-api/internal/config"
	"github.com/cdnca/cdnca/services/control-api/internal/controlbackup"
	"github.com/cdnca/cdnca/services/control-api/internal/controlbackuphistory"
	"github.com/cdnca/cdnca/services/control-api/internal/controlbackuphistoryhttp"
	"github.com/cdnca/cdnca/services/control-api/internal/controlgrpc"
	"github.com/cdnca/cdnca/services/control-api/internal/controlinternal"
	"github.com/cdnca/cdnca/services/control-api/internal/controlupgrade"
	"github.com/cdnca/cdnca/services/control-api/internal/dashboardhttp"
	"github.com/cdnca/cdnca/services/control-api/internal/database"
	"github.com/cdnca/cdnca/services/control-api/internal/dnsacme"
	"github.com/cdnca/cdnca/services/control-api/internal/dnsproviderremote"
	"github.com/cdnca/cdnca/services/control-api/internal/dnsreconcilehttpmtls"
	"github.com/cdnca/cdnca/services/control-api/internal/domaineventfanout"
	"github.com/cdnca/cdnca/services/control-api/internal/edgeartifact"
	"github.com/cdnca/cdnca/services/control-api/internal/edgeautopublish"
	"github.com/cdnca/cdnca/services/control-api/internal/edgedeployment"
	"github.com/cdnca/cdnca/services/control-api/internal/edgeoutbox"
	"github.com/cdnca/cdnca/services/control-api/internal/edgepublish"
	"github.com/cdnca/cdnca/services/control-api/internal/edgepublishhttp"
	"github.com/cdnca/cdnca/services/control-api/internal/edgestatus"
	"github.com/cdnca/cdnca/services/control-api/internal/entitlementguard"
	"github.com/cdnca/cdnca/services/control-api/internal/entitlementrefreshhttp"
	"github.com/cdnca/cdnca/services/control-api/internal/entitlementsync"
	"github.com/cdnca/cdnca/services/control-api/internal/errorpagecontrol"
	"github.com/cdnca/cdnca/services/control-api/internal/errorpagecontrolhttp"
	"github.com/cdnca/cdnca/services/control-api/internal/errorpageobjectstore"
	"github.com/cdnca/cdnca/services/control-api/internal/errorpagepublicationhttp"
	"github.com/cdnca/cdnca/services/control-api/internal/errorpagescanner"
	"github.com/cdnca/cdnca/services/control-api/internal/firewallactionhttp"
	"github.com/cdnca/cdnca/services/control-api/internal/firewallcontrol"
	"github.com/cdnca/cdnca/services/control-api/internal/firewalldispatch"
	"github.com/cdnca/cdnca/services/control-api/internal/firewallhttp"
	"github.com/cdnca/cdnca/services/control-api/internal/httpapi"
	"github.com/cdnca/cdnca/services/control-api/internal/httppolicycontrol"
	"github.com/cdnca/cdnca/services/control-api/internal/iamlock"
	"github.com/cdnca/cdnca/services/control-api/internal/identity"
	"github.com/cdnca/cdnca/services/control-api/internal/identitysessionhttp"
	"github.com/cdnca/cdnca/services/control-api/internal/identityverification"
	"github.com/cdnca/cdnca/services/control-api/internal/impersonation"
	"github.com/cdnca/cdnca/services/control-api/internal/impersonationhttp"
	"github.com/cdnca/cdnca/services/control-api/internal/installationban"
	"github.com/cdnca/cdnca/services/control-api/internal/jobhttp"
	"github.com/cdnca/cdnca/services/control-api/internal/l4analytics"
	"github.com/cdnca/cdnca/services/control-api/internal/l4analyticshttp"
	"github.com/cdnca/cdnca/services/control-api/internal/l4live"
	"github.com/cdnca/cdnca/services/control-api/internal/mfa"
	"github.com/cdnca/cdnca/services/control-api/internal/mfacipher"
	"github.com/cdnca/cdnca/services/control-api/internal/mfahttp"
	"github.com/cdnca/cdnca/services/control-api/internal/node"
	"github.com/cdnca/cdnca/services/control-api/internal/nodeca"
	"github.com/cdnca/cdnca/services/control-api/internal/nodecertlifecycle"
	"github.com/cdnca/cdnca/services/control-api/internal/nodegatewayaddr"
	"github.com/cdnca/cdnca/services/control-api/internal/nodeidentity"
	"github.com/cdnca/cdnca/services/control-api/internal/nodeisolationhttp"
	"github.com/cdnca/cdnca/services/control-api/internal/nodemonitoringoutbox"
	"github.com/cdnca/cdnca/services/control-api/internal/nodepresence"
	"github.com/cdnca/cdnca/services/control-api/internal/nodeschedulerhttp"
	"github.com/cdnca/cdnca/services/control-api/internal/notification"
	"github.com/cdnca/cdnca/services/control-api/internal/observabilitylog"
	"github.com/cdnca/cdnca/services/control-api/internal/observabilityloghttp"
	"github.com/cdnca/cdnca/services/control-api/internal/openrestysecurityhttp"
	"github.com/cdnca/cdnca/services/control-api/internal/originauthcontrol"
	"github.com/cdnca/cdnca/services/control-api/internal/originauthpublicationhttp"
	"github.com/cdnca/cdnca/services/control-api/internal/originauthverifier"
	"github.com/cdnca/cdnca/services/control-api/internal/originfailover"
	"github.com/cdnca/cdnca/services/control-api/internal/platformpolicy"
	"github.com/cdnca/cdnca/services/control-api/internal/pluginwebhook"
	"github.com/cdnca/cdnca/services/control-api/internal/pluginwebhookcontrol"
	"github.com/cdnca/cdnca/services/control-api/internal/pluginwebhookhttp"
	"github.com/cdnca/cdnca/services/control-api/internal/pluginwebhookruntime"
	"github.com/cdnca/cdnca/services/control-api/internal/qualitydiagnostics"
	"github.com/cdnca/cdnca/services/control-api/internal/qualitydiagnosticshttp"
	"github.com/cdnca/cdnca/services/control-api/internal/rbacmanagerhttp"
	"github.com/cdnca/cdnca/services/control-api/internal/retentioncleanup"
	"github.com/cdnca/cdnca/services/control-api/internal/sched302table"
	"github.com/cdnca/cdnca/services/control-api/internal/securityactivation"
	"github.com/cdnca/cdnca/services/control-api/internal/securityanalytics"
	"github.com/cdnca/cdnca/services/control-api/internal/securitybinding"
	"github.com/cdnca/cdnca/services/control-api/internal/securitybundle"
	"github.com/cdnca/cdnca/services/control-api/internal/securitycoordmetricshttp"
	"github.com/cdnca/cdnca/services/control-api/internal/securitypolicy"
	"github.com/cdnca/cdnca/services/control-api/internal/securityrulecatalog"
	"github.com/cdnca/cdnca/services/control-api/internal/securityrulereport"
	"github.com/cdnca/cdnca/services/control-api/internal/sessioncredential"
	"github.com/cdnca/cdnca/services/control-api/internal/signerrevocationconsumer"
	"github.com/cdnca/cdnca/services/control-api/internal/site"
	"github.com/cdnca/cdnca/services/control-api/internal/sitecapture"
	"github.com/cdnca/cdnca/services/control-api/internal/sitecapturehttp"
	"github.com/cdnca/cdnca/services/control-api/internal/sitegroup"
	"github.com/cdnca/cdnca/services/control-api/internal/systemconfig"
	"github.com/cdnca/cdnca/services/control-api/internal/systemconfigpublish"
	"github.com/cdnca/cdnca/services/control-api/internal/systemmailsettings"
	"github.com/cdnca/cdnca/services/control-api/internal/systemusersettings"
	"github.com/cdnca/cdnca/services/control-api/internal/theme"
	"github.com/cdnca/cdnca/services/control-api/internal/wafreport"
	"github.com/google/uuid"
	"github.com/jackc/pgx/v5"
	"github.com/jackc/pgx/v5/pgconn"
	"github.com/jackc/pgx/v5/pgxpool"
	"github.com/nats-io/nats.go"
)

func main() {
	if err := run(os.Args[1:]); err != nil {
		slog.Error("control-api command failed", commandFailureAttrs(err)...)
		os.Exit(1)
	}
}

func run(args []string) error {
	if len(args) == 0 {
		return usageError()
	}
	switch args[0] {
	case "--version":
		if len(args) != 1 || controlVersion == "" || controlVersion == "development" {
			return errors.New("control-api build version is unavailable")
		}
		fmt.Println(controlVersion)
		return nil
	case "serve":
		return runServer()
	case "migrate":
		return runMigrate(args[1:])
	case "bootstrap-user":
		return runBootstrapUser(args[1:])
	case "recover-platform-admin":
		return runRecoverPlatformAdministrator(args[1:])
	case "admin-access-allowlist":
		return runAdminAccessAllowlist(args[1:], os.Stdout)
	case "bootstrap-node-ca":
		return runBootstrapNodeCA(args[1:])
	case "bootstrap-system-configuration":
		return runBootstrapSystemConfiguration(args[1:])
	case "install-entitlement":
		return runInstallEntitlement(args[1:])
	case "install-community":
		return runInstallCommunity(args[1:])
	case "community-register":
		return runCommunityRegister(args[1:])
	case "community-refresh":
		return runCommunityRefresh(args[1:])
	case "community-register-encryption-key":
		return runCommunityRegisterEncryptionKey(args[1:])
	case "fetch-entitlement-revocation":
		return runFetchEntitlementRevocation(args[1:])
	case "generate-installation-encryption-key":
		return runGenerateInstallationEncryptionKey(args[1:])
	case "report-installation-endpoints":
		return runReportInstallationEndpoints(args[1:])
	case "verify-native-upgrade":
		return runVerifyNativeUpgradePreflight(args[1:])
	case "native-backup":
		return runNativeBackup(args[1:])
	case "signer-revocation":
		return runSignerRevocation(args[1:], os.Stdout)
	case "plugin-webhook-attestation-key":
		return runPluginWebhookAttestationKey(args[1:], os.Stdout)
	default:
		return usageError()
	}
}

type serveHandshakeListener struct {
	net.Listener
	serving chan struct{}
	once    sync.Once
}

func (listener *serveHandshakeListener) Accept() (net.Conn, error) {
	connection, err := listener.Listener.Accept()
	if err == nil {
		listener.once.Do(func() { close(listener.serving) })
	}
	return connection, err
}

func controlAPIProbeAddress(address *net.TCPAddr) string {
	if len(address.IP) != 0 && !address.IP.IsUnspecified() {
		return address.String()
	}
	host := "127.0.0.1"
	if len(address.IP) != 0 && address.IP.To4() == nil {
		host = "::1"
	}
	return net.JoinHostPort(host, fmt.Sprint(address.Port))
}

func buildCertificateAssetHandlerFactory(
	cfg config.Config,
	pool *pgxpool.Pool,
	identityService *identity.Service,
) (httpapi.MountedHandlerFactory, error) {
	if !cfg.ACMERuntimeEnabled {
		return nil, nil
	}
	if pool == nil || identityService == nil {
		return nil, errors.New("certificate asset runtime dependencies are not configured")
	}
	enveloper, err := newConfiguredACMECertificateEnveloper(cfg)
	if err != nil {
		return nil, err
	}
	store, err := certificateasset.NewStore(pool, enveloper)
	if err != nil {
		return nil, err
	}
	// 用户改绑/发布时撤销在途续签下发。
	if err := withRenewalDeliveryCanceller(store, pool); err != nil {
		return nil, err
	}
	// 下载证书解包 ACME 签发的私钥（与证书发布同一 keyring）。
	resolver, err := newConfiguredACMEPublicationResolverKeyring(cfg)
	if err != nil {
		return nil, err
	}
	return func() (http.Handler, error) {
		return certificateassethttp.NewHandler(certificateassethttp.Dependencies{
			Service: store, AuthenticateSession: identityService.AuthenticateSession, OpaqueResolver: resolver,
		})
	}, nil
}

func newDashboardHandler(
	pool *pgxpool.Pool,
	identityService *identity.Service,
	authorizer *iamlock.Authorizer,
	analyticsService *analytics.Service,
) (http.Handler, error) {
	handler, err := dashboardhttp.NewProductionHandler(
		dashboardhttp.ProductionConfig{},
		dashboardhttp.ProductionDependencies{
			Pool: pool, Identity: identityService, IAM: authorizer, Analytics: analyticsService,
		},
	)
	if err != nil {
		return nil, err
	}
	return handler, nil
}

func buildSiteCaptureHandler(pool *pgxpool.Pool, identityService *identity.Service) (http.Handler, error) {
	if pool == nil || identityService == nil {
		return nil, sitecapture.ErrInvalidConfig
	}
	store, err := sitecapture.NewPostgresStore(pool, nil)
	if err != nil {
		return nil, err
	}
	service, err := sitecapture.NewService(store)
	if err != nil {
		return nil, err
	}
	authenticate := sitecapturehttp.AuthenticatorFunc(func(request *http.Request) (sitecapture.Actor, error) {
		raw, ok := siteCaptureBearerToken(request)
		if !ok {
			return sitecapture.Actor{}, sitecapture.ErrUnauthenticated
		}
		authenticated, err := identityService.AuthenticateSession(request.Context(), raw)
		if err != nil {
			return sitecapture.Actor{}, sitecapture.ErrUnauthenticated
		}
		principal := authenticated.Principal
		return sitecapture.Actor{UserID: principal.UserID, ScopeID: principal.ScopeID,
			ScopeKind: principal.ScopeKind, SessionID: authenticated.SessionID,
			Permissions: append([]string(nil), principal.Permissions...)}, nil
	})
	return sitecapturehttp.NewHandler(service, authenticate)
}

func siteCaptureBearerToken(request *http.Request) (string, bool) {
	if request == nil {
		return "", false
	}
	values := request.Header.Values("Authorization")
	if len(values) != 1 || values[0] != strings.TrimSpace(values[0]) {
		return "", false
	}
	scheme, raw, found := strings.Cut(values[0], " ")
	if !found || !strings.EqualFold(scheme, "Bearer") || raw == "" || raw != strings.TrimSpace(raw) ||
		strings.ContainsAny(raw, " \t\r\n") {
		return "", false
	}
	return raw, true
}

func buildAnalyticsDiagnosticHandlerFactory(
	enabled bool,
	client *analyticslog.Client,
	productionConfig qualitydiagnosticshttp.ProductionConfig,
) (httpapi.AnalyticsDiagnosticHandlerFactory, error) {
	if !enabled {
		return nil, nil
	}
	if client == nil {
		return nil, qualitydiagnostics.ErrInvalidConfiguration
	}
	return func(authenticate analyticsdiagnostichttp.Authenticator) (http.Handler, error) {
		return analyticsdiagnostichttp.NewFinalizedProductionHandler(client, authenticate, productionConfig)
	}, nil
}

func buildObservabilityLogHandler(
	pool *pgxpool.Pool,
	identityService *identity.Service,
	cursorKey []byte,
	trustedProxyCIDRs []string,
	maxProxyHops int,
) (http.Handler, error) {
	if identityService == nil {
		return nil, observabilitylog.ErrInvalidConfig
	}
	resolver, err := accountrecoverycontext.NewSourceIPResolver(trustedProxyCIDRs, maxProxyHops)
	if err != nil {
		return nil, err
	}
	store, err := observabilitylog.NewStore(pool)
	if err != nil {
		return nil, err
	}
	service, err := observabilitylog.NewService(store, cursorKey, time.Now)
	if err != nil {
		return nil, err
	}
	// B6：日志查询按来源 IP 实时查 IP 基础库补 国家-省-市（未加载时保持原值）。
	service.SetIPIntelLookup(analyticslog.NewPostgresIPIntelLookup(pool, slog.Default()))
	return observabilityloghttp.NewHandler(observabilityloghttp.Dependencies{
		Domain: service, AuthenticateSession: identityService.AuthenticateSession,
		ResolveClientIP: func(request *http.Request) string {
			address, err := resolver.ResolveSourceIP(request)
			if err != nil {
				return "unknown"
			}
			return address.String()
		},
	})
}

// buildBackupHistoryHandler deliberately leaves the reader unavailable unless
// every independently provisioned binding is present. A missing runtime mount
// is exposed as 503 by the handler rather than being replaced with database or
// plan/approval data.
func buildBackupHistoryHandler(identityService *identity.Service) (http.Handler, error) {
	if identityService == nil {
		return nil, errors.New("backup history identity is unavailable")
	}
	return controlbackuphistoryhttp.NewHandler(controlbackuphistoryhttp.Dependencies{Reader: loadBackupHistoryReader(), AuthenticateSession: identityService.AuthenticateSession})
}

// backupRunnerBindings describe the external backup runner (cmd/control-backup):
// where it writes signed run facts, which cluster it captures and the key it
// signs with. The installer cannot know them; the installation ID and cursor key
// it does write. With none of them set there is no backup target and the
// history reads as empty; a partial binding is a misconfiguration and stays 503.
var backupRunnerBindings = []string{"CONTROL_BACKUP_RUN_MANIFEST_DIRECTORY", "CONTROL_BACKUP_RUN_SOURCE_CLUSTER_ID",
	"CONTROL_BACKUP_RUN_SIGNING_KEY_ID", "CONTROL_BACKUP_RUN_SIGNING_PUBLIC_KEY_FILE"}

func loadBackupHistoryReader() controlbackuphistory.Reader {
	bound := 0
	for _, name := range backupRunnerBindings {
		if _, ok := os.LookupEnv(name); ok {
			bound++
		}
	}
	if bound == 0 {
		return controlbackuphistory.Unconfigured{Now: time.Now}
	}
	manifestDirectory, directoryOK := os.LookupEnv("CONTROL_BACKUP_RUN_MANIFEST_DIRECTORY")
	installationID, installationOK := os.LookupEnv("CONTROL_BACKUP_RUN_INSTALLATION_ID")
	sourceClusterID, sourceOK := os.LookupEnv("CONTROL_BACKUP_RUN_SOURCE_CLUSTER_ID")
	keyID, keyIDOK := os.LookupEnv("CONTROL_BACKUP_RUN_SIGNING_KEY_ID")
	keyPath, keyPathOK := os.LookupEnv("CONTROL_BACKUP_RUN_SIGNING_PUBLIC_KEY_FILE")
	if !directoryOK || !installationOK || !sourceOK || !keyIDOK || !keyPathOK {
		return nil
	}
	encoded, err := controlbackup.ReadTrustedFile(keyPath)
	if err != nil {
		return nil
	}
	publicKey, err := controlbackup.DecodeEd25519PublicKey(encoded)
	if err != nil {
		return nil
	}
	cursorKey, err := loadRuntimeCursorKey("CONTROL_BACKUP_RUN_CURSOR_KEY_BASE64")
	if err != nil {
		return nil
	}
	defer clear(cursorKey)
	// A failed NewFileReader returns a nil *FileReader, which must not become a
	// non-nil Reader interface (the handler would call List on it).
	reader, err := controlbackuphistory.NewFileReader(manifestDirectory, installationID, sourceClusterID,
		map[string]ed25519.PublicKey{keyID: publicKey}, cursorKey, time.Now)
	if err != nil {
		return nil
	}
	return reader
}

// ipIntelRegionResolver places an address for the session region check.
type ipIntelRegionResolver struct {
	lookup analyticslog.IPIntelLookup
}

func (resolver ipIntelRegionResolver) Region(ctx context.Context, address netip.Addr) (string, bool) {
	info := resolver.lookup.Lookup(ctx, []string{address.String()})[address.String()]
	if info == nil || len(info.Country) != 2 {
		return "", false
	}
	if info.Province != "" {
		return info.Country + "-" + info.Province, true
	}
	return info.Country, true
}

type loginGeoRuntimeResolver struct {
	mu     sync.RWMutex
	reader analyticsgeo.AuthorityReader
}

func (resolver *loginGeoRuntimeResolver) SetReader(reader analyticsgeo.AuthorityReader) {
	resolver.mu.Lock()
	resolver.reader = reader
	resolver.mu.Unlock()
}

func (resolver *loginGeoRuntimeResolver) Resolve(ctx context.Context, sourceIP string) (identity.GeoAttribution, error) {
	if resolver == nil {
		return identity.GeoAttribution{}, analyticsgeo.ErrAuthorityUnavailable
	}
	resolver.mu.RLock()
	reader := resolver.reader
	resolver.mu.RUnlock()
	if reader == nil {
		return identity.GeoAttribution{}, analyticsgeo.ErrAuthorityUnavailable
	}
	address, err := netip.ParseAddr(sourceIP)
	if err != nil {
		return identity.GeoAttribution{}, err
	}
	lookup, err := reader.Lookup(ctx, "", address)
	if err != nil {
		return identity.GeoAttribution{}, err
	}
	return identity.GeoAttribution{
		CountryCode: lookup.Attribution.CountryCode,
		Region:      lookup.Attribution.Region,
		City:        lookup.Attribution.City,
		Resolution:  string(lookup.Attribution.Resolution),
	}, nil
}

func withFirewallRoutes(next, firewall http.Handler) http.Handler {
	if firewall == nil {
		return next
	}
	return http.HandlerFunc(func(writer http.ResponseWriter, request *http.Request) {
		if request.URL.Path == "/v1/firewall/policy" || request.URL.Path == "/v1/firewall/policy/recover" ||
			request.URL.Path == "/v1/firewall/hits" {
			firewall.ServeHTTP(writer, request)
			return
		}
		next.ServeHTTP(writer, request)
	})
}

func withOpenRestySecurityRoutes(next, security http.Handler) http.Handler {
	if security == nil {
		return next
	}
	return http.HandlerFunc(func(writer http.ResponseWriter, request *http.Request) {
		path := request.URL.Path
		overrideID := strings.TrimPrefix(path, "/v1/openresty-security/overrides/")
		if path == "/v1/openresty-security/configs/global" ||
			path == "/v1/openresty-security/overrides" ||
			path == "/v1/openresty-security/targets" ||
			path == "/v1/openresty-security/effective" ||
			path == "/v1/openresty-security/actions/download-cc-image" ||
			path == "/v1/cc-rule-groups" ||
			openrestysecurityhttp.IsSystemRulePath(path) ||
			strings.HasPrefix(path, "/v1/cc-rule-groups/") ||
			overrideID != path && overrideID != "" && !strings.Contains(overrideID, "/") {
			security.ServeHTTP(writer, request)
			return
		}
		next.ServeHTTP(writer, request)
	})
}

type cacheControlRuntimeHealthSnapshot struct {
	Enabled bool   `json:"enabled"`
	State   string `json:"state"`
}

type cacheControlNATSCloser interface {
	Drain() error
	Close()
}

func isNilCacheControlNATSCloser(connection cacheControlNATSCloser) bool {
	if connection == nil {
		return true
	}
	conn, ok := connection.(*nats.Conn)
	return ok && conn == nil
}

func withCacheControlRuntimeHealthDetail(
	next http.Handler,
	analyticsRuntime *analyticsIngestProcessRuntime,
	accountRuntime *accountRecoveryRuntime,
	cacheRuntime *cacheControlRuntime,
) http.Handler {
	return http.HandlerFunc(func(writer http.ResponseWriter, request *http.Request) {
		if request.Method == http.MethodGet && request.URL.Path == "/health/detail" {
			cacheHealth := cacheControlRuntimeHealthSnapshot{State: "disabled"}
			if cacheRuntime != nil {
				cacheHealth.Enabled = true
				cacheHealth.State = "unavailable"
				if cacheRuntime.Ready() == nil {
					cacheHealth.State = "ready"
				}
			}
			writer.Header().Set("Content-Type", "application/json")
			writer.Header().Set("Cache-Control", "no-store")
			_ = json.NewEncoder(writer).Encode(struct {
				AnalyticsIngest analyticsIngestHealthSnapshot     `json:"analytics_ingest"`
				AccountRecovery accountRecoveryHealthSnapshot     `json:"account_recovery"`
				CacheControl    cacheControlRuntimeHealthSnapshot `json:"cache_control"`
			}{
				AnalyticsIngest: analyticsRuntime.Health(), AccountRecovery: accountRuntime.Health(),
				CacheControl: cacheHealth,
			})
			return
		}
		next.ServeHTTP(writer, request)
	})
}

func openCacheControlProductionRuntime(
	ctx context.Context,
	config cacheControlProductionConfig,
	dependencies cacheControlRuntimeDependencies,
	connect natsConnector,
) (*cacheControlRuntime, *nats.Conn, error) {
	if !config.Runtime.Enabled {
		return nil, nil, nil
	}
	if ctx == nil || ctx.Err() != nil || connect == nil || config.NATSURL == "" || config.NATSName == "" ||
		config.NATSConnectTimeout <= 0 || config.NATSReconnectWait <= 0 || config.NATSDrainTimeout <= 0 {
		return nil, nil, errors.New("cache control production runtime configuration is incomplete")
	}
	connection, err := connect(
		config.NATSURL,
		nats.Name(config.NATSName),
		nats.Timeout(config.NATSConnectTimeout),
		nats.ReconnectWait(config.NATSReconnectWait),
		nats.MaxReconnects(-1),
		nats.DrainTimeout(config.NATSDrainTimeout),
	)
	if err != nil {
		return nil, nil, runtimeStageError{stage: "connect cache control NATS", err: err}
	}
	if connection == nil || connection.IsClosed() {
		if connection != nil {
			connection.Close()
		}
		return nil, nil, errors.New("cache control NATS connection is unavailable")
	}
	failed := true
	defer func() {
		if failed {
			connection.Close()
		}
	}()
	dependencies.NATS = connection
	runtime, err := buildCacheControlRuntime(config.Runtime, dependencies)
	if err != nil {
		return nil, nil, err
	}
	failed = false
	return runtime, connection, nil
}

func closeCacheControlProductionResources(
	runtime *cacheControlRuntime,
	connection cacheControlNATSCloser,
) error {
	var result error
	if runtime != nil {
		result = runtime.Close()
	}
	if !isNilCacheControlNATSCloser(connection) {
		if err := connection.Drain(); err != nil {
			connection.Close()
			result = errors.Join(result, runtimeStageError{stage: "drain cache control NATS", err: err})
		}
	}
	return result
}

func closeCacheControlProductionResourcesContext(
	ctx context.Context,
	runtime *cacheControlRuntime,
	connection cacheControlNATSCloser,
) error {
	if ctx == nil {
		return errors.New("cache control shutdown context is required")
	}
	var result error
	if runtime != nil {
		result = runtime.CloseContext(ctx)
	}
	if isNilCacheControlNATSCloser(connection) {
		return result
	}
	if err := ctx.Err(); err != nil {
		connection.Close()
		return errors.Join(result, runtimeStageError{stage: "drain cache control NATS", err: err})
	}
	drained := make(chan error, 1)
	go func() { drained <- connection.Drain() }()
	select {
	case err := <-drained:
		if err != nil {
			connection.Close()
			result = errors.Join(result, runtimeStageError{stage: "drain cache control NATS", err: err})
		}
	case <-ctx.Done():
		connection.Close()
		result = errors.Join(result, runtimeStageError{stage: "drain cache control NATS", err: ctx.Err()})
	}
	return result
}

func validateCacheControlShutdownPeriod(shared time.Duration, config cacheControlProductionConfig) error {
	if config.Runtime.Enabled && shared < config.NATSDrainTimeout {
		return errors.New("control API shutdown period is shorter than cache control NATS drain timeout")
	}
	return nil
}

func runInstallEntitlement(args []string) error {
	flags := flag.NewFlagSet("install-entitlement", flag.ContinueOnError)
	bundlePath := flags.String("bundle", "", "path to a signed entitlement bundle")
	trustedKeysPath := flags.String("trusted-keys", "", "path to independently provisioned trusted public keys")
	trustedKeysetPath := flags.String("trusted-keyset", "", "path to the canonical signed public keyset")
	revocationPath := flags.String("revocation", "", "path to a signed entitlement revocation artifact")
	if err := flags.Parse(args); err != nil {
		return err
	}
	if flags.NArg() != 0 || strings.TrimSpace(*bundlePath) == "" || strings.TrimSpace(*trustedKeysPath) == "" {
		return errors.New("usage: control-api install-entitlement --bundle FILE --trusted-keys FILE [--trusted-keyset FILE] [--revocation FILE]")
	}
	trust, err := loadEntitlementTrust(*trustedKeysPath)
	if err != nil {
		return err
	}
	encoded, err := os.ReadFile(*bundlePath)
	if err != nil {
		return fmt.Errorf("read entitlement bundle: %w", err)
	}
	bundle, err := entitlementguard.DecodeInstallBundle(encoded)
	if err != nil {
		return err
	}
	databaseURL := os.Getenv("DATABASE_URL")
	if databaseURL == "" {
		return errors.New("DATABASE_URL is required")
	}
	ctx, cancel := context.WithTimeout(context.Background(), 30*time.Second)
	defer cancel()
	pool, err := database.Open(ctx, databaseURL)
	if err != nil {
		return err
	}
	defer pool.Close()
	now := time.Now().UTC()
	restored, _, err := entitlementsync.NewPostgresKeysetStore(pool).Restore(ctx, trust.PinnedKeys(), now)
	if err != nil && !errors.Is(err, entitlementsync.ErrNoLocalKeyset) {
		return err
	}
	if restored != nil {
		if err := trust.ApplyVerifiedKeys(restored.Keys); err != nil {
			return err
		}
	}
	if strings.TrimSpace(*trustedKeysetPath) != "" {
		keysetPayload, err := os.ReadFile(*trustedKeysetPath)
		if err != nil {
			return fmt.Errorf("read trusted signing keyset: %w", err)
		}
		keysetDigest := sha256.Sum256(keysetPayload)
		keysetETag := `"` + base64.RawURLEncoding.EncodeToString(keysetDigest[:]) + `"`
		accepted, err := entitlementsync.NewPostgresKeysetStore(pool).Accept(ctx, keysetPayload, keysetETag,
			trust.PinnedKeys(), now)
		if err != nil {
			return fmt.Errorf("install trusted signing keyset: %w", err)
		}
		if err := trust.ApplyVerifiedKeys(accepted.Keys); err != nil {
			return fmt.Errorf("apply trusted signing keyset: %w", err)
		}
	}
	if strings.TrimSpace(*revocationPath) != "" {
		revocationArtifact, err := readRestrictedEntitlementRevocation(*revocationPath)
		if err != nil {
			return err
		}
		defer clearSensitiveBytes(revocationArtifact)
		if _, err := entitlementguard.NewRevocationService(pool, trust).Accept(ctx, revocationArtifact, now); err != nil {
			return fmt.Errorf("install entitlement revocation: %w", err)
		}
	}
	snapshot, err := entitlementguard.NewService(pool, trust).Install(ctx, bundle, now)
	if err != nil {
		return err
	}
	fmt.Printf("entitlement installed: serial=%d status=%s key_id=%s\n", snapshot.Serial, snapshot.Status, snapshot.KeyID)
	return nil
}

// runFetchEntitlementRevocation is intentionally a machine-readable command:
// on success it writes only the signed artifact to stdout. The installer
// redirects that output to a mode-restricted file and passes the file to
// install-entitlement, so no lease, private key, or activation credential is
// printed or exposed in argv.
func runFetchEntitlementRevocation(args []string) error {
	flags := flag.NewFlagSet("fetch-entitlement-revocation", flag.ContinueOnError)
	licenseService := flags.String("license-service", "", "HTTPS authorization-service origin")
	installationID := flags.String("installation-id", "", "canonical control installation UUID")
	installationKey := flags.String("installation-key", "", "owner-only Ed25519 installation private key")
	if err := flags.Parse(args); err != nil {
		return err
	}
	if flags.NArg() != 0 || strings.TrimSpace(*licenseService) == "" ||
		strings.TrimSpace(*installationID) == "" || strings.TrimSpace(*installationKey) == "" {
		return errors.New("usage: control-api fetch-entitlement-revocation --license-service URL --installation-id UUID --installation-key FILE")
	}
	parsedInstallationID, err := uuid.Parse(strings.TrimSpace(*installationID))
	if err != nil || parsedInstallationID == uuid.Nil || parsedInstallationID.String() != strings.TrimSpace(*installationID) {
		return errors.New("installation ID must be a canonical UUID")
	}
	privateKey, err := entitlementsync.LoadPrivateKey(strings.TrimSpace(*installationKey))
	if err != nil {
		return err
	}
	defer clearSensitiveBytes(privateKey)
	client, err := entitlementsync.NewClient(strings.TrimSpace(*licenseService), nil)
	if err != nil {
		return err
	}
	revocationClient, err := entitlementsync.NewRevocationClient(client)
	if err != nil {
		return err
	}
	ctx, cancel := context.WithTimeout(context.Background(), 30*time.Second)
	defer cancel()
	response, err := revocationClient.Fetch(ctx, entitlementsync.RevocationFetchRequest{
		InstallationID: parsedInstallationID, PrivateKey: privateKey, Now: time.Now().UTC(),
	})
	if err != nil {
		return err
	}
	if response.NotModified || len(response.Artifact) == 0 {
		return errors.New("authorization server returned no current entitlement revocation artifact")
	}
	var written int
	written, err = os.Stdout.Write(response.Artifact)
	if err == nil && written != len(response.Artifact) {
		err = io.ErrShortWrite
	}
	clearSensitiveBytes(response.Artifact)
	return err
}

// runGenerateInstallationEncryptionKey creates the installation X25519
// encryption key (PA-14; a separate key, not derived from the Ed25519
// identity) in an owner-only file and prints only its base64url public key,
// which the installer sends with the activation.
func runGenerateInstallationEncryptionKey(args []string) error {
	flags := flag.NewFlagSet("generate-installation-encryption-key", flag.ContinueOnError)
	output := flags.String("out", "", "new owner-only PKCS#8 X25519 key file (must not exist)")
	if err := flags.Parse(args); err != nil {
		return err
	}
	if flags.NArg() != 0 || strings.TrimSpace(*output) == "" {
		return errors.New("usage: control-api generate-installation-encryption-key --out FILE")
	}
	publicKey, err := entitlementsync.GenerateEncryptionKey(strings.TrimSpace(*output))
	if err != nil {
		return err
	}
	_, err = fmt.Println(base64.RawURLEncoding.EncodeToString(publicKey))
	return err
}

func readRestrictedEntitlementRevocation(path string) ([]byte, error) {
	file, err := os.Open(strings.TrimSpace(path))
	if err != nil {
		return nil, fmt.Errorf("read entitlement revocation: %w", err)
	}
	defer file.Close()
	info, err := file.Stat()
	if err != nil {
		return nil, fmt.Errorf("stat entitlement revocation: %w", err)
	}
	if !info.Mode().IsRegular() || info.Mode().Perm()&0o077 != 0 {
		return nil, errors.New("entitlement revocation file must be regular and inaccessible to group and other users")
	}
	artifact, err := io.ReadAll(io.LimitReader(file, entitlement.RevocationSetMaxBytes+1))
	if err != nil || len(artifact) == 0 || len(artifact) > entitlement.RevocationSetMaxBytes {
		clearSensitiveBytes(artifact)
		return nil, errors.New("entitlement revocation artifact size is invalid")
	}
	return artifact, nil
}

func clearSensitiveBytes(value []byte) {
	for index := range value {
		value[index] = 0
	}
}

func runServer() error {
	cfg, err := config.Load()
	if err != nil {
		return err
	}
	siteStatusRecoveryConfig, err := siteStatusRecoveryRuntimeConfigFromControlConfig(cfg)
	if err != nil {
		return runtimeStageError{stage: "load site status recovery runtime configuration", err: err}
	}
	realtimeCoverageConfig, err := loadRealtimeCoverageRuntimeConfig()
	if err != nil {
		return runtimeStageError{stage: "load analytics realtime coverage finalizer configuration", err: err}
	}
	signerRevocationConfig, err := signerrevocationconsumer.LoadConfig()
	if err != nil {
		return runtimeStageError{stage: "load signer revocation consumer configuration", err: err}
	}
	if err := validateSignerRevocationShutdownPeriod(cfg.ShutdownPeriod, signerRevocationConfig); err != nil {
		return runtimeStageError{stage: "validate signer revocation consumer shutdown", err: err}
	}
	notificationConfig, err := loadNotificationRuntimeConfig()
	if err != nil {
		return runtimeStageError{stage: "load notification runtime configuration", err: err}
	}
	defer notificationConfig.clearSecrets()
	accountRecoveryConfig, err := loadAccountRecoveryRuntimeConfig()
	if err != nil {
		return runtimeStageError{stage: "load account recovery runtime configuration", err: err}
	}
	defer accountRecoveryConfig.clearSecrets()
	accountRegistrationConfig, err := loadAccountRegistrationRuntimeConfig(accountRecoveryConfig)
	if err != nil {
		return runtimeStageError{stage: "load account registration runtime configuration", err: err}
	}
	defer accountRegistrationConfig.clearSecrets()
	announcementConfig, err := loadAnnouncementRuntimeConfigFromEnv()
	if err != nil {
		return runtimeStageError{stage: "load announcement runtime configuration", err: err}
	}
	defer announcementConfig.clearSecrets()
	cacheControlConfig, err := loadCacheControlProductionConfig()
	if err != nil {
		return runtimeStageError{stage: "load cache control runtime configuration", err: err}
	}
	defer cacheControlConfig.clearSecrets()
	if err := validateCacheControlShutdownPeriod(cfg.ShutdownPeriod, cacheControlConfig); err != nil {
		return runtimeStageError{stage: "validate cache control runtime shutdown", err: err}
	}
	packageTrafficEnforcementConfig, err := loadPackageTrafficEnforcementConfig()
	if err != nil {
		return runtimeStageError{stage: "load package traffic enforcement configuration", err: err}
	}
	impersonationConfig, err := loadImpersonationRuntimeConfigFromEnvEntries(os.Environ())
	if err != nil {
		return runtimeStageError{stage: "load impersonation runtime configuration", err: err}
	}
	defer impersonationConfig.clearSecrets()
	nodeSchedulerConfig, err := loadNodeSchedulerRuntimeConfig()
	if err != nil {
		return runtimeStageError{stage: "load node scheduling runtime configuration", err: err}
	}
	nodePortTransitionEnabled, err := loadRuntimeBool("NODE_PORT_TRANSITION_RUNTIME_ENABLED")
	if err != nil {
		return runtimeStageError{stage: "load node port transition runtime configuration", err: err}
	}
	controlUpgradeConfig, err := loadControlUpgradeRuntimeConfig()
	if err != nil {
		return runtimeStageError{stage: "load control upgrade runtime configuration", err: err}
	}
	controlUpgradePlanConfig, err := loadControlUpgradePlanRuntimeConfig(cfg.ControlInstallationID)
	if err != nil {
		return runtimeStageError{stage: "load control upgrade plan runtime configuration", err: err}
	}
	systemConfigurationConfig, err := loadSystemConfigurationRuntimeConfig()
	if err != nil {
		return runtimeStageError{stage: "load system configuration runtime configuration", err: err}
	}
	systemSettingsConfig, err := loadSystemSettingsRuntimeConfig()
	if err != nil {
		return runtimeStageError{stage: "load system settings runtime configuration", err: err}
	}
	ctx, stop := signal.NotifyContext(context.Background(), syscall.SIGINT, syscall.SIGTERM)
	defer stop()
	pool, err := database.Open(ctx, cfg.DatabaseURL)
	if err != nil {
		return err
	}
	// Cancel ctx before closing the pool on every return: pool.Close waits for
	// borrowed connections, and LISTEN loops (marketsupply security reconciler)
	// hold theirs until ctx ends, so an early error return would hang forever.
	defer closePoolAfterStop(stop, pool)
	if notificationConfig.Enabled {
		persistedMailSettings, settingsErr := systemmailsettings.ReadRuntime(ctx, pool)
		if settingsErr != nil {
			return runtimeStageError{stage: "read persisted system mail settings", err: settingsErr}
		}
		mailCipher, cipherErr := newConfiguredDNSCredentialCipher(cfg)
		if cipherErr != nil {
			return runtimeStageError{stage: "initialize system mail credential keyring", err: cipherErr}
		}
		settingsErr = mergePersistedNotificationMailSettings(&notificationConfig, persistedMailSettings, mailCipher)
		_ = mailCipher.Close()
		if settingsErr != nil {
			return runtimeStageError{stage: "apply persisted system mail settings", err: settingsErr}
		}
	}
	var notificationHandlerFactory httpapi.NotificationHandlerFactory
	notificationHandlerFactory, err = buildNotificationHandlerFactory(pool, time.Now, notificationChannelTransports(notificationConfig))
	if err != nil {
		return runtimeStageError{stage: "initialize notification control HTTP handler", err: err}
	}
	controlUpgradePlanRuntime, err := openControlUpgradePlanRuntime(ctx, controlUpgradePlanConfig, pool)
	if err != nil {
		return runtimeStageError{stage: "initialize control upgrade plan runtime", err: err}
	}
	if controlUpgradePlanRuntime != nil {
		defer controlUpgradePlanRuntime.Close()
	}
	var controlUpgradePlanHandlerFactory httpapi.MountedHandlerFactory
	if controlUpgradePlanRuntime != nil {
		controlUpgradePlanHandlerFactory = controlUpgradePlanRuntime.HandlerFactory()
	}
	nodeMetricsRuntime, err := openNodeMetricsRuntime(ctx, cfg, pool, nats.Connect)
	if err != nil {
		return runtimeStageError{stage: "initialize node metrics runtime", err: err}
	}
	nodeMetricsRuntimeClosed := false
	defer func() {
		if !nodeMetricsRuntimeClosed {
			_ = nodeMetricsRuntime.Close()
		}
	}()
	siteStatusRecoveryRuntime, err := openSiteStatusRecoveryRuntime(
		siteStatusRecoveryConfig,
		siteStatusRecoveryRuntimeDependencies{Pool: pool, Clock: time.Now},
	)
	if err != nil {
		return runtimeStageError{stage: "initialize site status recovery runtime", err: err}
	}
	siteStatusRecoveryRuntimeClosed := false
	if siteStatusRecoveryRuntime != nil {
		defer func() {
			if siteStatusRecoveryRuntimeClosed {
				return
			}
			closeCtx, cancel := context.WithTimeout(context.Background(), cfg.ShutdownPeriod)
			defer cancel()
			_ = siteStatusRecoveryRuntime.Close(closeCtx)
		}()
	}
	nodeServingWorker, err := openNodeServingWorker(pool)
	if err != nil {
		return runtimeStageError{stage: "initialize node serving runtime", err: err}
	}
	apiKeyUsageRuntime, err := newAPIKeyUsageRuntime(pool)
	if err != nil {
		return runtimeStageError{stage: "initialize API key usage runtime", err: err}
	}
	defer apiKeyUsageRuntime.Close()
	trust, err := loadEntitlementTrust(cfg.EntitlementTrustedKeysFile)
	if err != nil {
		return err
	}
	if trust != nil {
		restored, _, restoreErr := entitlementsync.NewPostgresKeysetStore(pool).Restore(ctx, trust.PinnedKeys(), time.Now().UTC())
		if restoreErr != nil && !errors.Is(restoreErr, entitlementsync.ErrNoLocalKeyset) {
			return restoreErr
		}
		if restored != nil {
			if err := trust.ApplyVerifiedKeys(restored.Keys); err != nil {
				return err
			}
		}
	}
	signerRevocationRuntime, err := signerrevocationconsumer.OpenProductionRuntime(ctx, signerRevocationConfig,
		signerrevocationconsumer.ProductionDependencies{
			Pool: pool, EntitlementTrust: trust, Now: time.Now,
		})
	if err != nil {
		return runtimeStageError{stage: "open signer revocation consumer", err: err}
	}
	if signerRevocationRuntime != nil {
		defer signerRevocationRuntime.Close()
	}
	installSignerRevocationGate(trust, signerRevocationRuntime)
	var entitlementKeysets *entitlementsync.KeysetManager
	var entitlementSyncer *entitlementsync.Syncer
	var entitlementRevocationRuntime *entitlementRevocationRuntime
	var preparedEntitlementLease *preparedEntitlementLease
	var wafReportRuntime *wafreport.Reporter
	var customRuleReportRuntime *securityrulereport.Reporter
	if cfg.LicenseServiceURL != "" {
		entitlementKeysets, err = newSigningKeysetManager(ctx, cfg, pool, trust)
		if err != nil {
			return runtimeStageError{stage: "open entitlement signing keyset manager", err: err}
		}
		entitlementSyncer, err = newEntitlementSyncer(cfg, pool, trust, entitlementKeysets)
		if err != nil {
			return runtimeStageError{stage: "open entitlement syncer", err: err}
		}
		preparedEntitlementLease, err = fetchEntitlementLeaseBeforeRevocations(
			ctx, cfg.ActivationCredentialFile, entitlementSyncer,
		)
		if err != nil {
			return runtimeStageError{stage: "fetch entitlement lease", err: err}
		}
		entitlementRevocationRuntime, err = openEntitlementRevocationRuntime(
			ctx, cfg, pool, trust, entitlementKeysets, entitlementSyncer,
		)
		if err != nil {
			return runtimeStageError{stage: "open entitlement revocation runtime", err: err}
		}
		if err := installEntitlementLeaseAfterRevocations(
			ctx, preparedEntitlementLease, entitlementSyncer,
		); err != nil {
			return runtimeStageError{stage: "install entitlement lease", err: err}
		}
		installationID, parseErr := uuid.Parse(cfg.ControlInstallationID)
		if parseErr != nil || installationID == uuid.Nil || installationID.String() != cfg.ControlInstallationID {
			return runtimeStageError{stage: "configure WAF rule report", err: errors.New("control installation ID must be a canonical UUID")}
		}
		privateKey, keyErr := entitlementsync.LoadPrivateKey(cfg.ControlInstallationKeyFile)
		if keyErr != nil {
			return runtimeStageError{stage: "load WAF rule report signing key", err: keyErr}
		}
		reportClient, clientErr := wafreport.NewClient(cfg.LicenseServiceURL, nil)
		if clientErr != nil {
			return runtimeStageError{stage: "configure WAF rule report client", err: clientErr}
		}
		wafReportRuntime, clientErr = wafreport.NewReporter(wafreport.Config{
			Source: securitypolicy.NewService(securitypolicy.NewStoreWithClock(pool, time.Now)),
			Store:  wafreport.NewStore(pool, time.Now), Client: reportClient,
			InstallationID: installationID, PrivateKey: privateKey, Logger: slog.Default(),
		})
		if clientErr == nil {
			// Forced v2 upload of tenant CC/WAF rules; intentionally no opt-out.
			customRuleClient, customErr := securityrulereport.NewClient(cfg.LicenseServiceURL, nil)
			if customErr == nil {
				customRuleReportRuntime, customErr = securityrulereport.NewReporter(securityrulereport.Config{
					Collector: securityrulereport.NewCollector(pool, securitypolicy.NewService(securitypolicy.NewStoreWithClock(pool, time.Now))),
					Store:     securityrulereport.NewStore(pool, time.Now), Client: customRuleClient,
					InstallationID: installationID, PrivateKey: privateKey, Logger: slog.Default(),
				})
			}
			clientErr = customErr
		}
		clear(privateKey)
		if clientErr != nil {
			return runtimeStageError{stage: "initialize WAF rule report runtime", err: clientErr}
		}
	}
	tokens, err := identity.NewTokenManager(cfg.AccessSecret, cfg.AccessTTL)
	if err != nil {
		return err
	}
	loginGeoResolver := &loginGeoRuntimeResolver{}
	identityService, err := identity.NewService(identity.NewStoreWithGeo(pool, loginGeoResolver), tokens, cfg.RefreshTTL)
	if err != nil {
		return err
	}
	publicSystemSettings, err := systemusersettings.NewService(pool, audit.New(pool), time.Now)
	if err != nil {
		return runtimeStageError{stage: "initialize public system user settings", err: err}
	}
	identityService.SetPublicSettingsReader(publicSystemSettings)
	// The sign-in throttle keys its account and CAPTCHA digests with a key
	// derived from the access secret, so it is always on.
	throttleKey := sha256.Sum256(append([]byte("cdnca.identity.login-throttle.v1\x00"), cfg.AccessSecret...))
	if err := identityService.SetLoginThrottleKey(throttleKey[:]); err != nil {
		return runtimeStageError{stage: "initialize sign-in throttle", err: err}
	}
	// Session region binding uses the downloaded IP intelligence library
	// (country, or country-province); unknown addresses are not checked.
	identityService.SetRegionResolver(ipIntelRegionResolver{lookup: analyticslog.NewPostgresIPIntelLookup(pool, slog.Default())})
	secondaryVerificationNotifications, err := notification.NewStore(pool)
	if err != nil {
		return runtimeStageError{stage: "initialize secondary verification notifications", err: err}
	}
	identityService.SetSecondaryVerificationNotifier(identity.NotificationSecondaryVerificationNotifier{Store: secondaryVerificationNotifications})
	identitySessionRuntime, err := openIdentitySessionRuntime(pool, identityService)
	if err != nil {
		return runtimeStageError{stage: "initialize identity session runtime", err: err}
	}
	defer identitySessionRuntime.Close()
	siteCaptureHandler, err := buildSiteCaptureHandler(pool, identityService)
	if err != nil {
		return runtimeStageError{stage: "initialize site capture policy runtime", err: err}
	}
	controlPlaneUpgradeHandler, err := openControlPlaneUpgradeRuntimeWithDatabase(cfg, identityService, trust, pool)
	if err != nil {
		return runtimeStageError{stage: "initialize control-plane upgrade HTTP runtime", err: err}
	}
	observabilityLogCursorKey, err := loadRuntimeCursorKey("OBSERVABILITY_LOG_CURSOR_KEY_BASE64")
	if err != nil {
		return runtimeStageError{stage: "load observability log cursor key", err: err}
	}
	observabilityLogHandler, observabilityLogErr := buildObservabilityLogHandler(
		pool, identityService, observabilityLogCursorKey, cfg.APIKeyTrustedProxyCIDRs, cfg.APIKeyMaxProxyHops,
	)
	clear(observabilityLogCursorKey)
	if observabilityLogErr != nil {
		return runtimeStageError{stage: "initialize observability log runtime", err: observabilityLogErr}
	}
	auditLogHandler, auditLogErr := buildAuditLogHandler(pool, identityService)
	if auditLogErr != nil {
		return runtimeStageError{stage: "initialize audit log runtime", err: auditLogErr}
	}
	backupHistoryHandler, backupHistoryErr := buildBackupHistoryHandler(identityService)
	if backupHistoryErr != nil {
		return runtimeStageError{stage: "initialize backup history runtime", err: backupHistoryErr}
	}
	controlBackupHandler, controlBackupErr := buildControlBackupHandler(pool, identityService)
	if controlBackupErr != nil {
		return runtimeStageError{stage: "initialize native control backup runtime", err: controlBackupErr}
	}
	credentialCipher, err := newConfiguredDNSCredentialCipher(cfg)
	if err != nil {
		return err
	}
	presence, err := newNodePresenceRuntime(ctx, cfg, pool)
	if err != nil {
		return err
	}
	if presence != nil {
		defer presence.Close()
	}
	edgeRuntime, err := openEdgeDeploymentRuntime(ctx, cfg, pool, slog.Default(), nats.Connect)
	if err != nil {
		return err
	}
	defer edgeRuntime.Close()
	nodePortTransitionRuntime, err := openNodePortTransitionProductionRuntime(
		nodePortTransitionEnabled, cfg, pool, nats.Connect,
	)
	if err != nil {
		return runtimeStageError{stage: "initialize node port transition runtime", err: err}
	}
	if nodePortTransitionRuntime != nil {
		defer nodePortTransitionRuntime.Close()
	}
	acmeRuntime, err := openConfiguredACMEProcessRuntime(ctx, cfg, pool)
	if err != nil {
		return err
	}
	if acmeRuntime != nil {
		defer acmeRuntime.Close()
	}
	var overlayArtifacts acmehttp01.FetchStore
	if acmeRuntime != nil {
		overlayArtifacts = acmeRuntime.ArtifactStore()
	}
	gatewayRegistry, err := buildGatewayRegistryRuntime(pool, cfg.ControlInstallationID, cfg.NodeCACertificateChainFile)
	if err != nil {
		return runtimeStageError{stage: "initialize Agent Gateway registry", err: err}
	}
	controlRuntime, err := openControlInternalRuntimeWithGateways(ctx, cfg, pool, overlayArtifacts, controlInternalGatewayRegistry(gatewayRegistry))
	if err != nil {
		return err
	}
	if err := attachControlInternalRemote(ctx, controlRuntime, gatewayRegistry); err != nil {
		_ = controlRuntime.Close()
		return runtimeStageError{stage: "open ControlInternal remote listener", err: err}
	}
	defer controlRuntime.Close()
	analyticsRuntime, err := openAnalyticsQueryStore(cfg, nil)
	if err != nil {
		return err
	}
	if analyticsRuntime != nil {
		defer analyticsRuntime.Close()
		// Scope-keyed package reads map the access scope to the facts'
		// tenant_id (tenants.id) before querying ClickHouse.
		if client, ok := analyticsRuntime.QueryStore().(*analytics.Client); ok {
			client.WithTenantResolver(analytics.PostgresTenants{Query: pool})
		}
	}
	realtimeCoverageRuntime, err := buildRealtimeCoverageProductionRuntime(
		realtimeCoverageConfig, pool, analyticsRuntime, slog.Default(),
	)
	if err != nil {
		return runtimeStageError{stage: "initialize analytics realtime coverage finalizer", err: err}
	}
	certificateNotices, err := buildCertificateNoticeWorker(pool)
	if err != nil {
		return runtimeStageError{stage: "initialize certificate expiry notices", err: err}
	}
	packageTrafficEnforcement, err := buildPackageTrafficEnforcementRuntime(
		packageTrafficEnforcementConfig, pool, analyticsRuntime, slog.Default())
	if err != nil {
		return runtimeStageError{stage: "initialize package traffic enforcement runtime", err: err}
	}
	marketRuntime, marketSubscribe, marketClient, err := buildMarketRuntimeWithSubscribe(pool, identityService, trust,
		analyticsRuntime.QueryStore(), edgeRuntime.connection)
	if err != nil {
		return runtimeStageError{stage: "initialize market runtime", err: err}
	}
	analyticsConnectionsRetentionRuntime, err := openAnalyticsConnectionsRetentionRuntime(cfg, identityService, nil, nil)
	if err != nil {
		return runtimeStageError{stage: "initialize analytics connections retention runtime", err: err}
	}
	var analyticsConnectionsRetentionHandler http.Handler
	if analyticsConnectionsRetentionRuntime != nil {
		defer analyticsConnectionsRetentionRuntime.Close()
		analyticsConnectionsRetentionHandler = analyticsConnectionsRetentionRuntime.Handler()
	}
	var analyticsService *analytics.Service
	var analyticsQueryStore analytics.QueryStore
	if analyticsRuntime != nil {
		realtimeExpectedCounts, readerErr := analytics.NewPostgresRealtimeExpectedCountReader(pool)
		if readerErr != nil {
			return runtimeStageError{stage: "initialize analytics realtime expected-count authority", err: readerErr}
		}
		analyticsService, err = analytics.NewServiceWithRealtimeExpectedCounts(
			analyticsRuntime.QueryStore(), realtimeExpectedCounts,
		)
		if err != nil {
			return runtimeStageError{stage: "initialize analytics service", err: err}
		}
		analyticsService.SetRetentionReader(analytics.NewPostgresRetentionReader(pool))
		analyticsService.SetSiteHTTPSPortReader(analytics.NewPostgresSiteHTTPSPortReader(pool))
		analyticsService.SetRuleNameLookup(analyticslog.NewPostgresEventNameLookup(pool, nil))
	} else {
		analyticsQueryStore = unavailableAnalyticsStore{}
	}
	var analyticsLogsHandler http.Handler
	var analyticsReplicaHealthSource analyticsreplicametrics.HealthSource
	var analyticsReplicaHealthSourceClose func()
	defer func() {
		if !cfg.AnalyticsIngest.Enabled {
			return
		}
		if closer, ok := cfg.AnalyticsIngest.JetStream.IsolationKeyProvider.(interface{ Close() error }); ok {
			_ = closer.Close()
		}
	}()
	if cfg.AnalyticsIngest.Enabled {
		isolationKeyProvider, err := analytics.NewAESGCMIsolationKeyProvider(
			cfg.AnalyticsIngest.IsolationWrappingKeyID,
			cfg.AnalyticsIngest.IsolationWrappingKey,
		)
		clear(cfg.AnalyticsIngest.IsolationWrappingKey)
		cfg.AnalyticsIngest.IsolationWrappingKey = nil
		if err != nil {
			return runtimeStageError{stage: "initialize analytics evidence isolation provider", err: err}
		}
		cfg.AnalyticsIngest.JetStream.IsolationKeyProvider = isolationKeyProvider
	}
	analyticsIngestRuntime, err := openAnalyticsIngestRuntime(ctx, cfg, pool, slog.Default(), nats.Connect, nil)
	if err != nil {
		return err
	}
	if analyticsIngestRuntime != nil {
		defer analyticsIngestRuntime.CloseContext(ctx)
	}
	l4AnalyticsRuntime, err := openL4AnalyticsRuntime(ctx, cfg, nats.Connect, nil)
	if err != nil {
		return err
	}
	if l4AnalyticsRuntime != nil {
		defer l4AnalyticsRuntime.Close()
	}
	analyticsConnectionsRuntime, err := openAnalyticsConnectionsRuntime(ctx, cfg, nats.Connect)
	if err != nil {
		return runtimeStageError{stage: "open analytics connections runtime", err: err}
	}
	if analyticsConnectionsRuntime != nil {
		defer analyticsConnectionsRuntime.Close()
	}
	analyticsConnectionsDLQRuntime, err := openAnalyticsConnectionsDLQRuntime(
		cfg, analyticsConnectionsRuntime, identityService, nil,
	)
	if err != nil {
		return runtimeStageError{stage: "open analytics connections DLQ runtime", err: err}
	}
	var analyticsConnectionsDLQHandler http.Handler
	if analyticsConnectionsDLQRuntime != nil {
		defer analyticsConnectionsDLQRuntime.Close()
		analyticsConnectionsDLQHandler = analyticsConnectionsDLQRuntime.Handler()
	}
	// official mail services send only while their module is granted
	// (module.mail.<provider>); set after the persisted choice is merged
	notificationConfig.Mail.Granted = leaseModuleGranted(pool, entitlementguard.NewGuard(pool, time.Now, trust))
	notificationRuntime, err := openNotificationProcessRuntime(
		ctx, notificationConfig, pool, notificationRuntimeDependencies{Logger: slog.Default(),
			MailPlugins: lazyPluginProviderClients{cfg: cfg, pool: pool}},
	)
	if err != nil {
		return err
	}
	if notificationRuntime != nil {
		defer notificationRuntime.Close()
	}
	accountRegistrationMailPlugins = lazyPluginProviderClients{cfg: cfg, pool: pool}
	accountRegistrationMailLayout = theme.NewEmailLayout(pool)
	accountRegistrationRuntime, err := openAccountRegistrationRuntime(
		ctx, accountRegistrationConfig, notificationConfig, pool, slog.Default(),
	)
	if err != nil {
		return runtimeStageError{stage: "initialize account registration runtime", err: err}
	}
	if accountRegistrationRuntime != nil {
		defer accountRegistrationRuntime.Close()
	}
	accountLoginRuntime, err := openAccountLoginRuntime(
		ctx, accountRecoveryConfig, notificationConfig, pool, identityService, cfg.CookieSecure, cfg.CookieDomain,
		accountRegistrationRuntime != nil,
	)
	if err != nil {
		return runtimeStageError{stage: "initialize account login runtime", err: err}
	}
	if accountLoginRuntime != nil {
		defer accountLoginRuntime.Close()
	}
	var trustedRecoveryContext accountrecoveryhttp.ResolveTrustedContext
	if accountRecoveryConfig.Enabled {
		resolver, err := accountrecoverycontext.NewResolver(pool, accountrecoverycontext.Config{
			TrustedProxyCIDRs:    accountRecoveryConfig.TrustedProxyCIDRs,
			PlatformHosts:        accountRecoveryConfig.PlatformHosts,
			AllowPrivateSourceIP: accountRecoveryConfig.AllowPrivateSourceIP,
			MaxProxyHops:         accountRecoveryConfig.MaxProxyHops,
		})
		if err != nil {
			return runtimeStageError{stage: "configure account recovery trusted context", err: err}
		}
		trustedRecoveryContext = resolver.Resolve
	}
	accountRecoveryRuntime, err := openAccountRecoveryRuntime(
		ctx, accountRecoveryConfig, pool, slog.Default(), accountRecoveryRuntimeDependencies{
			TrustedContext: trustedRecoveryContext, Notifications: notificationRuntime,
			RegistrationDispatcher: accountRegistrationRuntime.Dispatcher(),
			LoginDispatcher:        accountLoginRuntime.Dispatcher(),
		},
	)
	if err != nil {
		return err
	}
	if accountRecoveryRuntime != nil {
		defer accountRecoveryRuntime.Close()
	}
	var jobQueryReader jobhttp.Reader
	var jobCommandReader *jobhttp.PostgresReader
	if cfg.JobQueryEnabled {
		reader, err := jobhttp.NewPostgresReader(pool)
		if err != nil {
			return fmt.Errorf("initialize job query reader: %w", err)
		}
		jobQueryReader, jobCommandReader = reader, reader
	}
	var presenceLeases nodepresence.LeaseReader
	if presence != nil {
		presenceLeases = presence.LeaseReader()
	}
	announcementRuntime, err := openAnnouncementRuntime(ctx, pool, announcementConfig)
	if err != nil {
		return err
	}
	if announcementRuntime != nil {
		defer announcementRuntime.Close()
	}
	identityVerificationRuntimeConfig, err := loadIdentityVerificationRuntimeConfig()
	if err != nil {
		return runtimeStageError{stage: "load identity verification runtime configuration", err: err}
	}
	defer identityVerificationRuntimeConfig.clear()
	challengePolicyRuntimeConfig, err := loadChallengePolicyRuntimeConfig()
	if err != nil {
		return runtimeStageError{stage: "load challenge policy runtime configuration", err: err}
	}
	defer challengePolicyRuntimeConfig.clear()
	httpPolicyEnabled, err := loadRuntimeBool("HTTP_POLICY_RUNTIME_ENABLED")
	if err != nil {
		return runtimeStageError{stage: "load HTTP policy runtime configuration", err: err}
	}
	dnsReconcileConfig, err := loadDNSReconcileRuntimeConfig()
	if err != nil {
		return runtimeStageError{stage: "load DNS reconcile runtime configuration", err: err}
	}
	errorPageConfig, err := loadErrorPageRuntimeConfig()
	if err != nil {
		return runtimeStageError{stage: "load error page runtime configuration", err: err}
	}
	brandAssetConfig, err := loadBrandAssetRuntimeConfig()
	if err != nil {
		return runtimeStageError{stage: "load brand asset runtime configuration", err: err}
	}
	defer brandAssetConfig.clearSecrets()
	analyticsRealtimeConfig, err := loadAnalyticsRealtimeRuntimeConfig()
	if err != nil {
		return runtimeStageError{stage: "load analytics realtime runtime configuration", err: err}
	}
	defer analyticsRealtimeConfig.clearSecrets()
	analyticsGeoArtifactConfig, err := loadAnalyticsGeoArtifactRuntimeConfig()
	if err != nil {
		return runtimeStageError{stage: "load analytics geo artifact runtime configuration", err: err}
	}
	customRBACConfig, err := loadCustomRBACRuntimeConfig()
	if err != nil {
		return runtimeStageError{stage: "load custom RBAC runtime configuration", err: err}
	}
	defer customRBACConfig.clearSecrets()
	mfaConfig, err := loadMFARuntimeConfigFromEnvEntries(os.Environ())
	if err != nil {
		return runtimeStageError{stage: "load MFA runtime configuration", err: err}
	}
	defer mfaConfig.clearSecrets()
	originAuthConfig, err := loadOriginAuthRuntimeConfigFromEnvEntries(os.Environ())
	if err != nil {
		return runtimeStageError{stage: "load origin authentication runtime configuration", err: err}
	}
	defer originAuthConfig.clearSecrets()
	edgePublishConfig, err := loadEdgePublishRuntimeConfigFromEnvEntries(os.Environ())
	if err != nil {
		return runtimeStageError{stage: "load edge publication runtime configuration", err: err}
	}
	defer edgePublishConfig.clearSecrets()
	edgeAutomaticPublicationConfig, err := loadEdgeAutomaticPublicationRuntimeConfig()
	if err != nil {
		return runtimeStageError{stage: "load automatic edge publication runtime configuration", err: err}
	}
	lazyCertificateCacheMax, err := loadEdgeLazyCertificateCacheMax(os.LookupEnv)
	if err != nil {
		return runtimeStageError{stage: "load edge lazy certificate configuration", err: err}
	}
	edgePublishConfig.LazyCertificateCacheMax = lazyCertificateCacheMax
	edgeAutomaticPublicationConfig.LazyCertificateCacheMax = lazyCertificateCacheMax
	if edgeAutomaticPublicationConfig.Enabled && !edgePublishConfig.Enabled {
		return runtimeStageError{stage: "validate automatic edge publication production composition",
			err: errors.New("automatic edge publication requires edge publication runtime")}
	}
	if err := validateEdgeAutomaticPublicationShutdownPeriod(cfg.ShutdownPeriod, edgeAutomaticPublicationConfig); err != nil {
		return runtimeStageError{stage: "validate automatic edge publication shutdown", err: err}
	}
	securityActivationConfig, err := loadSecurityActivationRuntimeConfigFromEnvEntries(os.Environ())
	if err != nil {
		return runtimeStageError{stage: "load security activation runtime configuration", err: err}
	}
	if securityActivationConfig.Enabled && !edgePublishConfig.Enabled {
		return runtimeStageError{stage: "load security activation runtime configuration",
			err: errors.New("security activation requires edge publication runtime")}
	}
	ja4BlockEnabled, err := loadRuntimeBool("JA4_BLOCK_RUNTIME_ENABLED")
	if err != nil {
		return runtimeStageError{stage: "load JA4 block runtime configuration", err: err}
	}
	if ja4BlockEnabled && !securityActivationConfig.Enabled {
		return runtimeStageError{stage: "load JA4 block runtime configuration",
			err: errors.New("JA4 block runtime requires security activation")}
	}
	ja4BlockConfig := defaultJA4BlockProductionConfig(
		ja4BlockEnabled, securityActivationConfig.Core.CandidateTTL,
	)
	edgePublishConfig.SecurityActivation = securityActivationConfig
	var sharedRuntimeIAM *iamlock.Authorizer
	buildSharedRuntimeIAM := func() (*iamlock.Authorizer, error) {
		if sharedRuntimeIAM != nil {
			return sharedRuntimeIAM, nil
		}
		sessions, err := sessioncredential.NewVerifier(tokens, time.Now)
		if err != nil {
			return nil, err
		}
		apiKeys, err := apikeycredential.NewVerifierWithKeyring(
			cfg.APIKeyPepperKeyring,
			time.Now,
			apikeycredential.NewPostgresDenialRecorder(pool, time.Now),
		)
		if err != nil {
			return nil, err
		}
		sharedRuntimeIAM, err = iamlock.NewAuthorizer(sessions, apiKeys)
		if err != nil {
			return nil, err
		}
		return sharedRuntimeIAM, nil
	}
	var nodeSchedulerHandlerFactory httpapi.MountedHandlerFactory
	var nodeSchedulerIAM *iamlock.Authorizer
	if nodeSchedulerConfig.Enabled {
		nodeSchedulerIAM, err = buildSharedRuntimeIAM()
		if err != nil {
			return runtimeStageError{stage: "initialize node scheduling IAM", err: err}
		}
		nodeSchedulerHandlerFactory = buildNodeSchedulerHandlerFactory(
			nodeSchedulerConfig,
			nodeschedulerhttp.RuntimeDependencies{
				Pool: pool, Identity: identityService,
				APIKeys: apikey.NewServiceWithPepperKeyring(pool, cfg.APIKeyPepperKeyring, time.Now),
				IAM:     nodeSchedulerIAM, Loads: nil, Now: time.Now,
				Publications: edgeautopublish.LineGroupPublisher{},
			},
		)
	}
	dashboardIAM, err := buildSharedRuntimeIAM()
	if err != nil {
		return runtimeStageError{stage: "initialize dashboard IAM", err: err}
	}
	if jobCommandReader != nil {
		// API-JOBS-02：任务命令事务内复核 API 密钥。
		if err := jobCommandReader.UseIAM(dashboardIAM); err != nil {
			return runtimeStageError{stage: "initialize job command IAM", err: err}
		}
	}
	openRestySecuritySecretCipher, err := loadOpenRestySecuritySecretCipher()
	if err != nil {
		return runtimeStageError{stage: "load OpenResty security secret cipher", err: err}
	}
	openRestySecurityHandler, err := openrestysecurityhttp.NewRuntimeHandler(openrestysecurityhttp.RuntimeDependencies{
		Pool: pool, Identity: identityService,
		APIKeys: apikey.NewServiceWithPepperKeyring(pool, cfg.APIKeyPepperKeyring, time.Now),
		IAM:     dashboardIAM, Sealer: openRestySecuritySecretCipher, Now: time.Now,
		Catalog: securityrulecatalog.NewStore(pool, time.Now),
	})
	if err != nil {
		return runtimeStageError{stage: "initialize OpenResty security HTTP runtime", err: err}
	}
	dashboardHandler, err := newDashboardHandler(pool, identityService, dashboardIAM, analyticsService)
	if err != nil {
		return runtimeStageError{stage: "initialize dashboard HTTP composition", err: err}
	}
	firewallActionHandlerFactory := func() (http.Handler, error) {
		return firewallactionhttp.NewRuntimeHandler(firewallactionhttp.RuntimeDependencies{
			Pool: pool, Identity: identityService,
			APIKeys: apikey.NewServiceWithPepperKeyring(pool, cfg.APIKeyPepperKeyring, time.Now),
			IAM:     dashboardIAM, Now: time.Now,
		})
	}
	cacheRuntime, cacheNATS, err := openCacheControlProductionRuntime(
		ctx,
		cacheControlConfig,
		cacheControlRuntimeDependencies{
			Pool: pool, NodeLeases: presenceLeases,
			Entitlement: entitlementguard.NewGuard(pool, time.Now, trust),
			Identity:    identityService, IAM: dashboardIAM,
		},
		nats.Connect,
	)
	cacheControlConfig.clearSecrets()
	if err != nil {
		return runtimeStageError{stage: "initialize cache control production composition", err: err}
	}
	cacheControlResourcesClosed := false
	defer func() {
		if !cacheControlResourcesClosed {
			closeCtx, cancel := context.WithTimeout(context.Background(), cfg.ShutdownPeriod)
			defer cancel()
			_ = closeCacheControlProductionResourcesContext(closeCtx, cacheRuntime, cacheNATS)
		}
	}()
	jobProducerCommands, err := cacheRuntime.JobCommandRouters()
	if err != nil {
		return err
	}
	var pluginWebhookRuntime *pluginwebhookruntime.Runtime
	var pluginWebhookRuntimeClosed bool
	var pluginWebhookHandlerFactory httpapi.MountedHandlerFactory
	if cfg.PluginWebhook.Enabled {
		iam, err := buildSharedRuntimeIAM()
		if err != nil {
			return runtimeStageError{stage: "initialize plugin webhook IAM", err: err}
		}
		keyring, keyringErr := newPluginWebhookKeyring(cfg.PluginWebhook.SecretKeyID, cfg.PluginWebhook.SecretKey)
		clear(cfg.PluginWebhook.SecretKey)
		cfg.PluginWebhook.SecretKey = nil
		if keyringErr != nil {
			return runtimeStageError{stage: "initialize plugin webhook keyring", err: keyringErr}
		}
		defer keyring.clear()
		secrets, err := pluginwebhookcontrol.NewRuntimeSecretProvider(pool, keyring)
		if err != nil {
			return runtimeStageError{stage: "initialize plugin webhook secret provider", err: err}
		}
		authorizedDeliverer, err := newPluginRuntimeWebhookDeliverer(cfg, trust, secrets)
		if err != nil {
			return runtimeStageError{stage: "initialize plugin runtime composition", err: err}
		}
		domainEventProducer, err := pluginwebhook.NewDomainEventProducer(pool)
		if err != nil {
			return runtimeStageError{stage: "initialize deployment domain event producer", err: err}
		}
		domainEventFanout, err := domaineventfanout.New(domaineventfanout.Config{
			Pool: pool, Producer: domainEventProducer,
			WorkerID: "control-api-deployment-domain-event-fanout",
		})
		if err != nil {
			return runtimeStageError{stage: "initialize deployment domain event fanout", err: err}
		}
		pluginWebhookRuntime, err = pluginwebhookruntime.Open(ctx,
			pluginWebhookRuntimeConfig(cfg.PluginWebhook, pool),
			pluginwebhookruntime.Dependencies{
				Deliverer: authorizedDeliverer, Secrets: secrets, Fanout: domainEventFanout,
			})
		if err != nil {
			return runtimeStageError{stage: "open plugin webhook runtime", err: err}
		}
		defer func() {
			if pluginWebhookRuntime == nil || pluginWebhookRuntimeClosed {
				return
			}
			closeCtx, cancel := context.WithTimeout(context.Background(), cfg.PluginWebhook.ShutdownTimeout)
			defer cancel()
			_ = pluginWebhookRuntime.Close(closeCtx)
		}()
		entitlement := entitlementguard.NewGuard(pool, time.Now, trust)
		pluginWebhookHandlerFactory = func() (http.Handler, error) {
			return pluginwebhookhttp.NewProductionHandler(pluginwebhookhttp.ProductionDependencies{
				Pool: pool, Identity: identityService, IAM: iam, Entitlement: entitlement,
				Keyring: keyring, Targets: pluginwebhookcontrol.NewTargetValidator(),
			})
		}
	}
	identityVerificationRuntime, err := openAndClearIdentityVerificationProductionRuntime(
		ctx,
		&identityVerificationRuntimeConfig,
		identityVerificationProductionDependencies{
			Pool: pool, Identity: identityService, IAM: dashboardIAM, Clock: time.Now,
		},
	)
	if err != nil {
		return runtimeStageError{stage: "initialize identity verification production composition", err: err}
	}
	identityVerificationRuntimeClosed := false
	defer func() {
		if identityVerificationRuntime != nil && !identityVerificationRuntimeClosed {
			_ = identityVerificationRuntime.Close()
		}
	}()
	identityVerificationHandlerFactory := identityVerificationRuntime.HandlerFactory()
	var challengePolicyHandlerFactory httpapi.MountedHandlerFactory
	var httpPolicyHandlerFactory httpapi.MountedHandlerFactory
	if httpPolicyEnabled {
		httpPolicyHandlerFactory = func() (http.Handler, error) {
			iam, err := buildSharedRuntimeIAM()
			if err != nil {
				return nil, err
			}
			return httppolicycontrol.NewRuntimeHandler(
				httppolicycontrol.RuntimeConfig{Enabled: true},
				httppolicycontrol.RuntimeDependencies{
					Pool: pool, Identity: identityService, IAM: iam, EntitlementTrust: trust, Now: time.Now,
					Revisions: edgeautopublish.UnrequestedRevisionPublisher{},
				},
			)
		}
	}
	var errorPageRuntime *errorpagecontrol.Runtime
	var errorPageObjectStore *errorpageobjectstore.Store
	var errorPageScanner *errorpagescanner.Scanner
	var brandAssetHandlerFactory httpapi.MountedHandlerFactory
	var brandAssetObjectStore *errorpageobjectstore.Store
	if brandAssetConfig.Enabled {
		brandAssetObjectStore, err = errorpageobjectstore.New(ctx, brandAssetConfig.ObjectStore)
		if err != nil {
			return runtimeStageError{stage: "initialize brand asset object store", err: err}
		}
		brandAssetHandlerFactory, err = buildBrandAssetHandlerFactory(pool, identityService, brandAssetObjectStore)
		if err != nil {
			return runtimeStageError{stage: "initialize brand asset runtime", err: err}
		}
	}
	pluginUIHandlerFactory, err := buildPluginUIHandlerFactory(cfg, pool, identityService, trust)
	if err != nil {
		return runtimeStageError{stage: "initialize plugin ui runtime", err: err}
	}
	if _, err := pluginProviderService(cfg, pool); err != nil {
		return runtimeStageError{stage: "initialize plugin provider runtime", err: err}
	}
	pluginProviderHandlerFactory, err := buildPluginProviderHandlerFactory(cfg, pool, identityService)
	if err != nil {
		return runtimeStageError{stage: "initialize plugin provider runtime", err: err}
	}
	var themeHandlerFactory httpapi.MountedHandlerFactory
	if identityService != nil && identityService.Configured() {
		themeHandlerFactory, err = buildThemeHandlerFactory(pool, identityService, entitlementguard.NewGuard(pool, time.Now, trust))
		if err != nil {
			return runtimeStageError{stage: "initialize theme runtime", err: err}
		}
	}
	if errorPageConfig.Enabled {
		errorPageScanner, err = errorpagescanner.New(ctx, errorPageConfig.Scanner)
		if err != nil {
			return runtimeStageError{stage: "initialize error page scanner", err: err}
		}
		errorPageObjectStore, err = errorpageobjectstore.New(ctx, errorPageConfig.ObjectStore)
		if err != nil {
			return runtimeStageError{stage: "initialize error page object store", err: err}
		}
	}
	ticketService, ticketHandlerFactory, err := buildTicketRuntime(pool, identityService, brandAssetObjectStore, errorPageScanner)
	if err != nil {
		return runtimeStageError{stage: "initialize ticket runtime", err: err}
	}
	go ticketService.RunCleanup(ctx, ticketAttachmentCleanupInterval)
	go ticketService.RunOverdueReminders(ctx, ticketOverdueReminderInterval)
	probeSources, probeDNSPupHandlerFactory, err := buildProbeDNSPupRuntime(pool, identityService, credentialCipher, trust)
	if err != nil {
		return runtimeStageError{stage: "initialize dnspup probing", err: err}
	}
	cnameCarrierLines, err := buildCNAMECarrierLines(pool, credentialCipher)
	if err != nil {
		return runtimeStageError{stage: "initialize CNAME carrier lines", err: err}
	}
	go cnameCarrierLines.Run(ctx, cnameCarrierLineInterval)
	nodeExternalProbe, err := openNodeExternalProbe(pool, edgeRuntime.connection)
	if err != nil {
		return runtimeStageError{stage: "initialize node external probe", err: err}
	}
	go nodeExternalProbe.Run(ctx, nodeExternalProbeInterval)
	if probeSources != nil {
		nodeDNSPupProbe, err := openNodeDNSPupProbe(pool, probeSources)
		if err != nil {
			return runtimeStageError{stage: "initialize dnspup node probe", err: err}
		}
		go nodeDNSPupProbe.Run(ctx)
	}
	originProbe, err := openOriginProbe(pool, edgeRuntime.connection, probeSources)
	if err != nil {
		return runtimeStageError{stage: "initialize origin probe", err: err}
	}
	go originProbe.Run(ctx, originfailover.RoundInterval)
	nodeSSHInstall, nodeSSHInstallHandlerFactory, err := buildNodeSSHInstallRuntime(pool, identityService, credentialCipher,
		trust, cfg.APIKeyPepper)
	if err != nil {
		return runtimeStageError{stage: "initialize node SSH install", err: err}
	}
	go nodeSSHInstall.Run(ctx, nodeSSHInstallInterval)
	nodeInstallTrust, err := openNodeInstallTrustWatcher(pool)
	if err != nil {
		return runtimeStageError{stage: "initialize node install trust check", err: err}
	}
	go nodeInstallTrust.Run(ctx)
	errorPageHandlerFactory := func() (http.Handler, error) {
		var runtimeIAM *iamlock.Authorizer
		if errorPageConfig.Enabled {
			var err error
			runtimeIAM, err = buildSharedRuntimeIAM()
			if err != nil {
				return nil, err
			}
		}
		runtime, err := errorpagecontrolhttp.NewRuntime(ctx, errorPageConfig, errorpagecontrolhttp.Dependencies{
			Pool: pool, Identity: identityService, IAM: runtimeIAM, EntitlementTrust: trust, Clock: time.Now,
			APIKeys:      apikey.NewServiceWithPepperKeyring(pool, cfg.APIKeyPepperKeyring, time.Now),
			ContentStore: errorPageObjectStore, Scanner: errorPageScanner,
		})
		if err != nil {
			return nil, err
		}
		errorPageRuntime = runtime
		return runtime, nil
	}
	var mfaRuntime *mfahttp.Runtime
	var mfaCipher *mfacipher.Cipher
	defer func() {
		if mfaRuntime != nil {
			_ = mfaRuntime.Close()
		}
		if mfaCipher != nil {
			_ = mfaCipher.Close()
		}
	}()
	var mfaHandlerFactory httpapi.MountedHandlerFactory
	if mfaConfig.Enabled {
		mfaIAM, err := buildSharedRuntimeIAM()
		if err != nil {
			return runtimeStageError{stage: "initialize MFA IAM", err: err}
		}
		mfaRuntime, mfaCipher, err = buildAndClearMFARuntime(&mfaConfig, mfaRuntimeDependencies{
			Pool: pool, Identity: identityService, IAM: mfaIAM,
		})
		if err != nil {
			return runtimeStageError{stage: "initialize MFA runtime", err: err}
		}
		managedPasswordResetStepUp, adapterErr := newManagedPasswordResetStepUpAdapter(mfaRuntime.StepUpConsumer())
		if adapterErr != nil {
			return runtimeStageError{stage: "initialize managed password reset step-up adapter", err: adapterErr}
		}
		identityService.SetManagedPasswordResetStepUpConsumer(managedPasswordResetStepUp)
		mfaHandlerFactory = func() (http.Handler, error) {
			return mfaRuntime.Handler(), nil
		}
	} else {
		mfaConfig.clearSecrets()
	}
	// FX01: prune history past the platform retention settings every hour, and
	// make the ClickHouse history TTLs follow them. The ingest identity holds
	// only table-scoped ALTER MODIFY TTL for this (configure-clickhouse.py).
	retentionConfig := retentioncleanup.Config{Logger: slog.Default()}
	if cfg.AnalyticsIngest.Enabled {
		clickHouse, err := retentioncleanup.NewClickHouseHTTP(cfg.AnalyticsIngest.ClickHouseURL,
			cfg.AnalyticsIngest.ClickHouseDatabase, cfg.AnalyticsIngest.ClickHouseUsername,
			cfg.AnalyticsIngest.ClickHousePassword, 30*time.Second)
		if err != nil {
			return runtimeStageError{stage: "initialize retention cleanup worker", err: err}
		}
		retentionConfig.ClickHouse = clickHouse
	}
	retentionWorker, err := retentioncleanup.NewWorker(pool, audit.New(pool), retentionConfig)
	if err != nil {
		return runtimeStageError{stage: "initialize retention cleanup worker", err: err}
	}
	go retentionWorker.Run(ctx, time.Hour)
	domainTrustHandlerFactory, err := buildDomainTrustRuntime(ctx, pool, identityService, slog.Default())
	if err != nil {
		return runtimeStageError{stage: "initialize domain trust runtime", err: err}
	}
	dnsHubHandlerFactory, err := buildDNSHubRuntime(pool, identityService, credentialCipher)
	if err != nil {
		return runtimeStageError{stage: "initialize DNS hub runtime", err: err}
	}
	analyticsRealtimeHandlerFactory, err := buildAndClearAnalyticsRealtimeHandlerFactory(
		&analyticsRealtimeConfig, analyticsRuntime, pool,
	)
	if err != nil {
		return runtimeStageError{stage: "initialize analytics realtime runtime", err: err}
	}
	var customRBACStepUp *rbacmanagerhttp.MFAStepUpVerifier
	if customRBACConfig.Enabled {
		if mfaRuntime == nil || mfaCipher == nil {
			return runtimeStageError{stage: "initialize custom RBAC runtime", err: errors.New("MFA runtime is required")}
		}
		customRBACMFAService, serviceErr := mfa.NewServiceWithDependencies(pool, mfaCipher, audit.New(pool), mfa.Config{
			Clock: time.Now, Random: rand.Reader, Issuer: "CDNCA", EnrollmentTTL: 10 * time.Minute,
		})
		if serviceErr != nil {
			return runtimeStageError{stage: "initialize custom RBAC MFA service", err: serviceErr}
		}
		customRBACStepUp, err = rbacmanagerhttp.NewMFAStepUpVerifier(customRBACMFAService)
		if err != nil {
			return runtimeStageError{stage: "initialize custom RBAC MFA verifier", err: err}
		}
	}
	customRBACHandlerFactory, err := buildAndClearCustomRBACHandlerFactory(
		&customRBACConfig,
		customRBACRuntimeDependencies{Pool: pool, Identity: identityService, StepUp: customRBACStepUp},
	)
	if err != nil {
		return runtimeStageError{stage: "initialize custom RBAC runtime", err: err}
	}
	impersonationHandlerFactory, impersonationReadiness, err := buildAndClearImpersonationRuntime(
		&impersonationConfig,
		impersonationRuntimeDependencies{Pool: pool, Identity: identityService, Clock: time.Now},
	)
	if err != nil {
		return runtimeStageError{stage: "initialize impersonation runtime", err: err}
	}
	var originVerifier originauthcontrol.CredentialVerifier
	if originAuthConfig.Enabled {
		originVerifier, err = originauthverifier.New(originAuthConfig.Verifier)
		if err != nil {
			return runtimeStageError{stage: "initialize origin authentication verifier", err: err}
		}
	}
	var originAuthIAM *iamlock.Authorizer
	if originAuthConfig.Enabled {
		originAuthIAM, err = buildSharedRuntimeIAM()
		if err != nil {
			return runtimeStageError{stage: "initialize origin authentication IAM", err: err}
		}
	}
	originAuthRuntime, err := buildAndClearOriginAuthProductionRuntime(
		&originAuthConfig,
		originAuthRuntimeDependencies{
			Pool: pool, Identity: identityService, IAM: originAuthIAM, Trust: trust,
			Verifier: originVerifier, Auditor: audit.New(pool), Clock: time.Now,
		},
	)
	if err != nil {
		return runtimeStageError{stage: "initialize origin authentication runtime", err: err}
	}
	originAuthHandlerFactory := originAuthRuntime.HandlerFactory
	wireMarketOriginAuth(marketRuntime, marketSubscribe, marketClient, originAuthRuntime.Service)
	var edgePublishIAM *iamlock.Authorizer
	if edgePublishConfig.Enabled {
		edgePublishIAM, err = buildSharedRuntimeIAM()
		if err != nil {
			return runtimeStageError{stage: "initialize edge publication IAM", err: err}
		}
	}
	edgePublishSigner, err := loadEdgePublishArtifactSigner(edgePublishConfig.Enabled)
	if err != nil {
		return runtimeStageError{stage: "initialize edge publication signer", err: err}
	}
	if edgePublishSigner != nil {
		defer edgePublishSigner.Close()
	}
	var firewallHandler http.Handler
	var firewallDispatcher *firewalldispatch.Dispatcher
	if edgePublishSigner != nil {
		var hitReader firewallcontrol.HitReader
		if analyticsRuntime != nil {
			hitReader, _ = analyticsRuntime.QueryStore().(*analytics.Client)
		}
		firewallHandler, err = firewallhttp.NewRuntimeHandler(firewallhttp.RuntimeDependencies{
			Pool: pool, Identity: identityService,
			APIKeys: apikey.NewServiceWithPepperKeyring(pool, cfg.APIKeyPepperKeyring, time.Now),
			IAM:     dashboardIAM, Hits: hitReader, Now: time.Now,
		})
		if err != nil {
			return runtimeStageError{stage: "initialize global firewall HTTP runtime", err: err}
		}
		projector, projectorErr := firewallcontrol.NewProjector(pool, edgePublishSigner, firewallcontrol.ProjectorConfig{})
		if projectorErr != nil {
			return runtimeStageError{stage: "initialize global firewall projector", err: projectorErr}
		}
		edgeNATS, ok := edgeRuntime.connection.(*nats.Conn)
		if !ok || edgeNATS == nil {
			return runtimeStageError{stage: "initialize global firewall dispatcher", err: errors.New("edge NATS connection is unavailable")}
		}
		dispatcher, dispatcherErr := firewalldispatch.New(pool, edgeNATS, firewalldispatch.DefaultConfig())
		if dispatcherErr != nil {
			return runtimeStageError{stage: "initialize global firewall dispatcher", err: dispatcherErr}
		}
		firewallDispatcher = dispatcher
		edgeRuntime.workers = append(edgeRuntime.workers, projector, firewallDispatcher)
		// HTTP 302 scheduling tables: signed like firewall
		// commands, over the same edge NATS.
		schedulePublisher, scheduleErr := sched302table.NewNATSPublisher(edgeNATS, 5*time.Second)
		if scheduleErr != nil {
			return runtimeStageError{stage: "initialize schedule302 table publisher", err: scheduleErr}
		}
		scheduleWorker, scheduleErr := sched302table.NewWorker(pool, edgePublishSigner, schedulePublisher, time.Now,
			slog.Default().With("component", "schedule302_tables"))
		if scheduleErr != nil {
			return runtimeStageError{stage: "initialize schedule302 table worker", err: scheduleErr}
		}
		edgeRuntime.workers = append(edgeRuntime.workers, scheduleWorker)
	}
	var edgePublishEntitlement edgepublish.EntitlementAuthorizer
	if edgePublishConfig.Enabled {
		edgePublishEntitlement = &edgePublishEntitlementAuthorizer{
			pool: pool, trust: trust,
		}
	}
	edgePublishResolver := edgepublish.NewSnapshotTargetResolver()
	edgePublishDependencies := edgePublishRuntimeDependencies{
		Pool: pool, Identity: identityService,
		APIKeys: apikey.NewServiceWithPepperKeyring(pool, cfg.APIKeyPepperKeyring, time.Now),
		IAM:     edgePublishIAM, Trust: trust, Signer: edgePublishSigner, Entitlement: edgePublishEntitlement,
		Resolver: edgePublishResolver, Clock: time.Now,
	}
	// buildAndClearEdgePublishRuntime zeroes edgePublishConfig: later gates
	// read this copy, never edgePublishConfig.Enabled (B-D3).
	edgePublishEnabled := edgePublishConfig.Enabled
	sitePublicationRuntime, err := buildAndClearEdgePublishRuntime(&edgePublishConfig, edgePublishDependencies)
	if err != nil {
		return runtimeStageError{stage: "initialize edge publication runtime", err: err}
	}
	wireMarketSecurity(marketRuntime, pool, sitePublicationRuntime.SecurityActivationStore)
	if errorPageConfig.Enabled && sitePublicationRuntime.Publisher == nil {
		return runtimeStageError{
			stage: "initialize error page publication runtime",
			err:   errors.New("edge publication runtime is required for error page publication"),
		}
	}
	var systemConfigurationPublisher systemconfig.ActivationPublisher
	if systemConfigurationConfig.Enabled {
		if sitePublicationRuntime.Publisher == nil {
			return runtimeStageError{stage: "initialize system configuration runtime", err: errors.New("edge publication runtime is required")}
		}
		systemConfigurationPublisher, err = systemconfigpublish.New(
			pool, sitePublicationRuntime.Publisher.Publisher(),
		)
		if err != nil {
			return runtimeStageError{stage: "initialize system configuration publication runtime", err: err}
		}
	}
	systemConfigurationHandlerFactory, err := buildSystemConfigurationHandlerFactory(
		systemConfigurationConfig,
		systemConfigurationRuntimeDependencies{
			Pool: pool, Identity: identityService, Expansion: denySystemConfigurationExpansion{Entitlement: entitlementguard.NewGuard(pool, time.Now, trust)},
			Publisher: systemConfigurationPublisher,
		},
	)
	if err != nil {
		return runtimeStageError{stage: "initialize system configuration runtime", err: err}
	}
	systemSettingsHandlerFactory, err := buildSystemSettingsHandlerFactory(systemSettingsConfig, pool, identityService)
	if err != nil {
		return runtimeStageError{stage: "initialize system settings runtime", err: err}
	}
	systemCleanupSettingsHandlerFactory, err := buildSystemCleanupSettingsHandlerFactory(systemSettingsConfig, pool, identityService)
	if err != nil {
		return runtimeStageError{stage: "initialize system cleanup settings runtime", err: err}
	}
	systemUserSettingsHandlerFactory, err := buildSystemUserSettingsHandlerFactory(systemSettingsConfig, pool, identityService)
	if err != nil {
		return runtimeStageError{stage: "initialize system user settings runtime", err: err}
	}
	systemMailSettingsHandlerFactory, err := buildSystemMailSettingsHandlerFactory(systemSettingsConfig, pool, identityService, credentialCipher,
		newSystemMailTestSender(notificationConfig, lazyPluginProviderClients{cfg: cfg, pool: pool}),
		leaseModuleGate(entitlementguard.NewGuard(pool, time.Now, trust)))
	if err != nil {
		return runtimeStageError{stage: "initialize system mail settings runtime", err: err}
	}
	systemOtherSettingsHandlerFactory, err := buildSystemOtherSettingsHandlerFactory(systemSettingsConfig, pool, identityService)
	if err != nil {
		return runtimeStageError{stage: "initialize system other settings runtime", err: err}
	}
	ja4BlockRuntime, err := openJA4BlockProductionRuntime(ja4BlockConfig, ja4BlockProductionDependencies{
		Pool: pool, Analytics: analyticsService, Identity: identityService,
		StepUp: mfaRuntime.StepUpConsumer(), Signer: edgePublishSigner, Now: time.Now,
	})
	if err != nil {
		return runtimeStageError{stage: "initialize JA4 block runtime", err: err}
	}
	if ja4BlockRuntime != nil {
		defer ja4BlockRuntime.Close()
	}
	var originAuthPublicationHandlerFactory httpapi.MountedHandlerFactory
	if originAuthRuntime.Source != nil && sitePublicationRuntime.Publisher != nil {
		producer, producerErr := edgepublish.NewOriginAuthArtifactProducer(edgePublishSigner)
		if producerErr != nil {
			return runtimeStageError{stage: "initialize origin authentication publication artifact producer", err: producerErr}
		}
		handler, handlerErr := originauthpublicationhttp.NewRuntimeHandler(originauthpublicationhttp.RuntimeDependencies{
			Pool: pool, Identity: identityService, IAM: edgePublishIAM, Publisher: sitePublicationRuntime.Publisher,
			Source: originAuthRuntime.Source, Producer: producer,
		})
		if handlerErr != nil {
			return runtimeStageError{stage: "initialize origin authentication publication runtime", err: handlerErr}
		}
		originAuthPublicationHandlerFactory = func() (http.Handler, error) { return handler, nil }
		if err := wireMarketOriginAuthDelivery(marketRuntime, pool, sitePublicationRuntime.Publisher.RolloutCommands(),
			originAuthRuntime.Source, producer); err != nil {
			return runtimeStageError{stage: "initialize market origin authentication delivery", err: err}
		}
	}
	var errorPagePublicationHandlerFactory httpapi.MountedHandlerFactory
	var errorPageSnapshotSource edgepublish.ErrorPageProductionSource
	if errorPageConfig.Enabled && sitePublicationRuntime.Publisher != nil {
		compiler, compilerErr := errorpagecontrol.NewProductionSnapshotCompiler(errorPageObjectStore, edgePublishSigner)
		if compilerErr != nil {
			return runtimeStageError{stage: "initialize error page publication compiler", err: compilerErr}
		}
		errorPageSnapshotSource = compiler
		publisher, publisherErr := edgepublish.NewErrorPagePublisher(sitePublicationRuntime.Publisher.Publisher(), compiler)
		if publisherErr != nil {
			return runtimeStageError{stage: "initialize error page publisher", err: publisherErr}
		}
		handler, handlerErr := errorpagepublicationhttp.NewRuntimeHandler(errorpagepublicationhttp.RuntimeDependencies{
			Pool: pool, Identity: identityService, IAM: edgePublishIAM, Publisher: publisher,
		})
		if handlerErr != nil {
			return runtimeStageError{stage: "initialize error page publication runtime", err: handlerErr}
		}
		errorPagePublicationHandlerFactory = func() (http.Handler, error) { return handler, nil }
	}
	// 实时连接: relayed to the nodes over the edge NATS connection.
	var streamLive httpapi.StreamLiveConnections
	if edgeNATS, ok := edgeRuntime.connection.(*nats.Conn); ok && edgeNATS != nil {
		requester, requesterErr := l4live.NewNATSRequester(edgeNATS)
		if requesterErr == nil {
			streamLive, requesterErr = l4live.New(pool, requester)
		}
		if requesterErr != nil {
			return runtimeStageError{stage: "initialize L4 live connections", err: requesterErr}
		}
	}
	var l4SwitchRuntime l4LineSwitchRuntime
	if sitePublicationRuntime.Publisher != nil {
		edgeNATS, ok := edgeRuntime.connection.(*nats.Conn)
		if !ok || edgeNATS == nil {
			return runtimeStageError{stage: "initialize L4 line switch runtime", err: errors.New("edge NATS connection is unavailable")}
		}
		l4SwitchRuntime, err = openL4LineSwitchRuntime(l4LineSwitchRuntimeDependencies{
			Pool: pool, Identity: identityService, IAM: edgePublishIAM,
			Deployments: sitePublicationRuntime.Publisher.RolloutCommands(), NATS: edgeNATS, Clock: time.Now,
		})
		if err != nil {
			return runtimeStageError{stage: "initialize L4 line switch runtime", err: err}
		}
	}
	var challengeRedeliverer edgepublish.ChallengeSecretRedeliverer
	if challengePolicyRuntimeConfig.Enabled {
		if sitePublicationRuntime.Publisher == nil || edgePublishSigner == nil {
			return runtimeStageError{stage: "initialize challenge publication runtime",
				err: errors.New("edge publication runtime is required")}
		}
		factSource, factErr := challengepublication.NewPostgresKeyFactSource(pool)
		if factErr != nil {
			return runtimeStageError{stage: "initialize challenge key fact source", err: factErr}
		}
		factCipher, factErr := challengepublication.NewAESGCMFactCipher(
			challengePolicyRuntimeConfig.FactKeyID, challengePolicyRuntimeConfig.FactKey)
		if factErr != nil {
			return runtimeStageError{stage: "initialize challenge key fact cipher", err: factErr}
		}
		factResolver, factErr := challengepublication.NewFactKeyResolver(factSource, factCipher,
			challengepublication.NewEd25519FactVerifier(map[string]ed25519.PublicKey{
				edgePublishSigner.KeyID(): edgePublishSigner.PublicKey(),
			}))
		if factErr != nil {
			return runtimeStageError{stage: "initialize challenge key fact resolver", err: factErr}
		}
		artifactProducer, factErr := challengepublication.NewArtifactProducer(edgePublishSigner)
		if factErr != nil {
			return runtimeStageError{stage: "initialize challenge artifact producer", err: factErr}
		}
		secretPublisher, factErr := challengepublication.NewDurableSecretPublisher(
			sitePublicationRuntime.Publisher.RolloutCommands(), artifactProducer)
		if factErr != nil {
			return runtimeStageError{stage: "initialize challenge secret publisher", err: factErr}
		}
		rolloutReader, factErr := challengepublication.NewDurableRolloutReader(
			sitePublicationRuntime.Publisher.RolloutCommands())
		if factErr != nil {
			return runtimeStageError{stage: "initialize challenge rollout reader", err: factErr}
		}
		// nodes that join or recover get the bound
		// policies redelivered; the automatic publication loop runs it.
		challengeRedeliverer, factErr = challengepublication.NewChallengeSecretRedeliverer(
			challengepublication.PostgresRedeliveryFactSource{}, factResolver,
			sitePublicationRuntime.Publisher.RolloutCommands(), artifactProducer, challengepublication.RedeliveryPolicy{
				HealthCheck: edgedeployment.HealthCheckPolicy{ActivationTimeout: 30 * time.Second,
					ObservationWindow: 15 * time.Second, RequiredConsecutiveSuccesses: 3}})
		if factErr != nil {
			return runtimeStageError{stage: "initialize challenge policy redeliverer", err: factErr}
		}
		bindingPublisher, factErr := challengepolicy.NewDurableBindingPublisher(
			pool, sitePublicationRuntime.Publisher.Publisher(), time.Now)
		if factErr != nil {
			return runtimeStageError{stage: "initialize challenge binding publisher", err: factErr}
		}
		challengePolicyHandlerFactory = func() (http.Handler, error) {
			iam, err := buildSharedRuntimeIAM()
			if err != nil {
				return nil, err
			}
			return challengepolicy.NewProductionRuntimeHandler(
				challengepolicy.RuntimeConfig{Enabled: true, CursorAudience: "control-challenge-policies",
					CursorKeyID: challengePolicyRuntimeConfig.CursorKeyID},
				challengepolicy.ProductionRuntimeDependencies{
					RuntimeDependencies: challengepolicy.RuntimeDependencies{
						Pool: pool, Identity: identityService, IAM: iam, EntitlementTrust: trust,
						Now: time.Now, CursorKey: challengePolicyRuntimeConfig.CursorKey,
					},
					KeyResolver: factResolver, SecretPublisher: secretPublisher,
					RolloutReader: rolloutReader, ConfigPublisher: bindingPublisher,
				},
			)
		}
	}
	var ccCoordinationRuntime *ccCoordinationRuntime
	var ccCoordinationHandler http.Handler
	if sitePublicationRuntime.SecurityActivationStore != nil {
		if analyticsIngestRuntime == nil {
			return runtimeStageError{stage: "initialize CC coordination runtime",
				err: errors.New("CC coordination requires analytics ingest NATS")}
		}
		analyticsNATS, ok := analyticsIngestRuntime.connection.(*nats.Conn)
		if !ok || analyticsNATS == nil {
			return runtimeStageError{stage: "initialize CC coordination runtime",
				err: errors.New("analytics ingest NATS connection is unavailable")}
		}
		ccCoordinationRuntime, err = openCCCoordinationRuntime(
			pool, analyticsNATS, sitePublicationRuntime.SecurityActivationStore,
		)
		if err != nil {
			return runtimeStageError{stage: "initialize CC coordination runtime", err: err}
		}
		defer ccCoordinationRuntime.Close()
		ccCoordinationHandler, err = cccoordhttp.NewRuntimeHandler(cccoordhttp.RuntimeDependencies{
			Pool: pool, Identity: identityService,
			APIKeys: apikey.NewServiceWithPepperKeyring(pool, cfg.APIKeyPepperKeyring, time.Now),
			IAM:     dashboardIAM, Store: ccCoordinationRuntime.Store(),
		})
		if err != nil {
			return runtimeStageError{stage: "initialize CC coordination HTTP runtime", err: err}
		}
	}
	// Security telemetry (community edition): platform node security events
	// (F4) and CC rule statistics from the node report stream. The automatic
	// defense module (commercial edition) is not part of cdncaCE.
	securityReports, err := openSecurityReportRuntime(cfg, pool, analyticsIngestRuntime)
	if err != nil {
		return runtimeStageError{stage: "initialize security report runtime", err: err}
	}
	if securityReports != nil {
		defer securityReports.Close()
	}
	var securityCoordinationMetricsHandlerFactory httpapi.MountedHandlerFactory
	if ccCoordinationRuntime != nil && firewallDispatcher != nil {
		handler, metricsErr := securitycoordmetricshttp.NewHandler(securitycoordmetricshttp.Dependencies{
			CCSnapshot: ccCoordinationRuntime.MetricsSnapshot, FirewallSnapshot: firewallDispatcher.MetricsSnapshot,
			AuthenticateSession: identityService.AuthenticateSession,
		})
		if metricsErr != nil {
			return runtimeStageError{stage: "initialize security coordination metrics runtime", err: metricsErr}
		}
		securityCoordinationMetricsHandlerFactory = func() (http.Handler, error) { return handler, nil }
	}
	// CC rule statistics: CC page API (reports: above).
	ccStats, err := openCCStatsRuntime(cfg, pool, identityService.AuthenticateSession)
	if err != nil {
		return runtimeStageError{stage: "initialize CC statistics runtime", err: err}
	}
	var analyticsDiagnosticClient *analyticslog.Client
	var analyticsDiagnosticProductionConfig qualitydiagnosticshttp.ProductionConfig
	var analyticsGeoLogReader analyticsgeo.AnalyticsLogReader
	analyticsLogsHandler, err = openAnalyticsLogsRuntime(
		cfg, pool, identityService, tokens,
		func(runtimeConfig analyticslog.RuntimeConfig, dependencies analyticslog.HTTPDependencies) (http.Handler, error) {
			replicaHealthSource, closeReplicaHealthSource, buildErr := newAnalyticsReplicaHealthSource(runtimeConfig)
			if buildErr != nil {
				return nil, buildErr
			}
			handler, buildErr := analyticslog.NewRuntimeHandler(runtimeConfig, dependencies)
			if buildErr != nil {
				closeReplicaHealthSource()
				return nil, buildErr
			}
			client, buildErr := analyticslog.NewClient(runtimeConfig.HTTP.Client, nil)
			if buildErr != nil {
				closeReplicaHealthSource()
				return nil, buildErr
			}
			logService, buildErr := analyticslog.NewService(client)
			if buildErr != nil {
				closeReplicaHealthSource()
				return nil, buildErr
			}
			analyticsReplicaHealthSource = replicaHealthSource
			analyticsReplicaHealthSourceClose = closeReplicaHealthSource
			activeCursorKey := runtimeConfig.HTTP.Client.CursorKeyring.Keys[runtimeConfig.HTTP.Client.CursorKeyring.ActiveKID]
			analyticsDiagnosticProductionConfig = qualitydiagnosticshttp.ProductionConfig{
				Source: analyticslog.FinalizedAccessConfig{QueryTimeout: runtimeConfig.HTTP.Client.QueryTimeout},
				Service: qualitydiagnostics.RuntimeConfig{
					CursorKey: append([]byte(nil), activeCursorKey...),
				},
				Handler: qualitydiagnosticshttp.Config{QueryTimeout: runtimeConfig.HTTP.Handler.QueryTimeout},
			}
			analyticsDiagnosticClient = client
			analyticsGeoLogReader = logService
			return handler, nil
		}, sitePublicationRuntime.SecurityActivationStore,
	)
	if err != nil {
		return err
	}
	analyticsReplicaMetricsRuntime, err := newAnalyticsReplicaMetricsProductionRuntime(
		analyticsReplicaHealthSource, analyticsReplicaHealthSourceClose,
	)
	if err != nil {
		return runtimeStageError{stage: "initialize analytics replica metrics runtime", err: err}
	}
	if analyticsReplicaMetricsRuntime != nil {
		defer analyticsReplicaMetricsRuntime.Close()
	}
	analyticsGeoArtifactRuntime, err := openAnalyticsGeoArtifactRuntime(
		ctx, analyticsGeoArtifactConfig, analyticsGeoArtifactRuntimeDependencies{Now: time.Now},
	)
	if err != nil {
		return runtimeStageError{stage: "initialize analytics geo artifact runtime", err: err}
	}
	var analyticsGeoHandlerFactory httpapi.AnalyticsGeoHandlerFactory
	if analyticsGeoArtifactRuntime != nil {
		defer analyticsGeoArtifactRuntime.Close()
		loginGeoResolver.SetReader(analyticsGeoArtifactRuntime.Reader())
		if analyticsGeoLogReader == nil {
			return runtimeStageError{stage: "initialize analytics geo runtime", err: errors.New("analytics logs runtime is required")}
		}
		eventSource, sourceErr := analyticsgeo.NewAnalyticsLogAdapter(analyticsGeoLogReader)
		if sourceErr != nil {
			return runtimeStageError{stage: "initialize analytics geo event source", err: sourceErr}
		}
		lookup, lookupErr := analyticsgeo.NewAuthorityReaderAdapter(eventSource, analyticsGeoArtifactRuntime.Reader())
		if lookupErr != nil {
			return runtimeStageError{stage: "initialize analytics geo authority reader", err: lookupErr}
		}
		analyticsGeoHandlerFactory = func(authenticate analyticsgeohttp.Authenticator) (http.Handler, error) {
			return analyticsgeohttp.NewHandler(lookup, authenticate, analyticsgeohttp.Config{})
		}
	}
	analyticsDiagnosticHandlerFactory, err := buildAnalyticsDiagnosticHandlerFactory(
		cfg.AnalyticsQueryEnabled, analyticsDiagnosticClient, analyticsDiagnosticProductionConfig,
	)
	if err != nil {
		return runtimeStageError{stage: "initialize analytics diagnostic runtime", err: err}
	}
	// ADR 0012 ML-20/21 market attack digests (leaf send, subscriber store).
	{
		var query, ingest clickHouseEndpoint
		if cfg.AnalyticsQueryEnabled {
			query = clickHouseEndpoint{URL: cfg.ClickHouseURL, Database: cfg.ClickHouseDatabase,
				Username: cfg.ClickHouseUsername, Password: cfg.ClickHousePassword}
		}
		if cfg.AnalyticsIngest.ClickHouseURL != "" {
			ingest = clickHouseEndpoint{URL: cfg.AnalyticsIngest.ClickHouseURL, Database: cfg.AnalyticsIngest.ClickHouseDatabase,
				Username: cfg.AnalyticsIngest.ClickHouseUsername, Password: cfg.AnalyticsIngest.ClickHousePassword}
		}
		if err := wireMarketSecDigest(marketRuntime, marketSubscribe, marketClient, analyticsDiagnosticClient, query, ingest); err != nil {
			return runtimeStageError{stage: "initialize market security digests", err: err}
		}
	}
	// ge-waf S7 attack alerts: needs the analytics log ClickHouse client.
	var attackAlerts *attackalert.Worker
	if analyticsDiagnosticClient != nil {
		alertStore, alertErr := notification.NewStore(pool)
		if alertErr == nil {
			attackAlerts, alertErr = attackalert.NewWorker(pool, analyticsDiagnosticClient, alertStore, time.Now)
		}
		// ML-21: relayed market attacks count with the site's local ones.
		if alertErr == nil && marketRuntime != nil && cfg.AnalyticsQueryEnabled {
			reader, readerErr := securityanalytics.NewClickHouse(cfg.ClickHouseURL, cfg.ClickHouseDatabase,
				cfg.ClickHouseUsername, cfg.ClickHousePassword, 10*time.Second)
			if alertErr = readerErr; alertErr == nil {
				attackAlerts.WithMarket(reader)
			}
		}
		if alertErr != nil {
			return runtimeStageError{stage: "initialize attack alert runtime", err: alertErr}
		}
	}
	certificatePublicationConfig := defaultCertificatePublicationRuntimeConfig()
	certificatePublicationConfig.Enabled = cfg.ACMERuntimeEnabled && edgePublishEnabled
	certificatePublicationDependencies := certificatePublicationProductionDependencies{}
	if certificatePublicationConfig.Enabled {
		certificatePublicationIAM, iamErr := buildSharedRuntimeIAM()
		if iamErr != nil {
			return runtimeStageError{stage: "initialize certificate publication IAM", err: iamErr}
		}
		certificateEnveloper, envelopeErr := newConfiguredACMECertificateEnveloper(cfg)
		if envelopeErr != nil {
			return runtimeStageError{stage: "initialize certificate publication envelope", err: envelopeErr}
		}
		certificateOpaqueResolver, resolverErr := newConfiguredACMEPublicationResolverKeyring(cfg)
		if resolverErr != nil {
			return runtimeStageError{stage: "initialize certificate publication key resolver", err: resolverErr}
		}
		certificateTargetResolver, resolverErr := edgeautopublish.NewCertificateTargetResolver(
			pool, edgepublish.NewSnapshotTargetResolver(),
		)
		if resolverErr != nil {
			return runtimeStageError{stage: "initialize certificate publication target resolver", err: resolverErr}
		}
		certificatePublicationDependencies = certificatePublicationProductionDependencies{
			Pool: pool, IAM: certificatePublicationIAM, Enveloper: certificateEnveloper,
			OpaqueResolver: certificateOpaqueResolver,
			Signer:         edgePublishSigner, TargetResolver: certificateTargetResolver,
		}
	}
	// automatic renewals reach the nodes and switch in
	// on the automatic publication loop.
	var certificateRenewalDeliverer edgeautopublish.RuntimeWorker
	if certificatePublicationConfig.Enabled {
		deliverer, delivererErr := buildCertificateRenewalDeliverer(certificatePublicationDependencies)
		if delivererErr != nil {
			return runtimeStageError{stage: "initialize certificate renewal delivery", err: delivererErr}
		}
		certificateRenewalDeliverer = deliverer
	}
	edgeAutomaticPublicationRuntime, err := openEdgeAutomaticPublicationProductionRuntime(
		edgeAutomaticPublicationConfig,
		edgeAutomaticPublicationRuntimeDependencies{
			Pool: pool, Signer: edgePublishSigner, Entitlement: edgePublishEntitlement,
			Resolver: edgePublishResolver, Clock: time.Now, ChallengeRedeliverer: challengeRedeliverer,
			ErrorPageSource: errorPageSnapshotSource, RenewalDeliverer: certificateRenewalDeliverer,
		},
	)
	if err != nil {
		return runtimeStageError{stage: "initialize automatic edge publication runtime", err: err}
	}
	if edgeAutomaticPublicationRuntime != nil {
		defer func() {
			closeContext, cancel := context.WithTimeout(context.Background(), cfg.ShutdownPeriod)
			defer cancel()
			_ = edgeAutomaticPublicationRuntime.Close(closeContext)
		}()
	}
	edgePublishHandlerFactory := sitePublicationRuntime.HandlerFactory
	certificatePublicationRuntime, err := openCertificatePublicationProductionRuntime(
		certificatePublicationDependencies, certificatePublicationConfig,
	)
	if err != nil {
		return runtimeStageError{stage: "initialize certificate publication runtime", err: err}
	}
	defer certificatePublicationRuntime.Close()
	if certificatePublicationConfig.Enabled {
		if err := certificatePublicationRuntime.Start(ctx); err != nil {
			return runtimeStageError{stage: "start certificate publication runtime", err: err}
		}
		slog.Info("certificate publication runtime started")
	} else {
		slog.Warn("certificate publication runtime is disabled: site certificates will not reach nodes",
			"acme_runtime_enabled", cfg.ACMERuntimeEnabled, "edge_publication_enabled", edgePublishEnabled)
	}
	dnsReconcileRuntime, err := openDNSReconcileProductionRuntime(
		ctx, dnsReconcileConfig, pool, identityService, credentialCipher, trust,
	)
	if err != nil {
		return runtimeStageError{stage: "initialize DNS reconcile production runtime", err: err}
	}
	if dnsReconcileRuntime != nil {
		defer dnsReconcileRuntime.Close()
	}
	var dnsReconcileHandlerFactory httpapi.MountedHandlerFactory
	if dnsReconcileRuntime != nil {
		dnsReconcileHandlerFactory = func() (http.Handler, error) {
			return dnsReconcileRuntime.tenantHandler, nil
		}
	}
	certificateAssetHandlerFactory, err := buildCertificateAssetHandlerFactory(cfg, pool, identityService)
	if err != nil {
		return runtimeStageError{stage: "initialize certificate asset runtime", err: err}
	}
	certificatePublicationStatusConfig, err := loadCertificatePublicationStatusRuntimeConfig(cfg.ACMERuntimeEnabled)
	if err != nil {
		return runtimeStageError{stage: "load certificate publication status runtime", err: err}
	}
	certificatePublicationStatusHandlerFactory, err := buildAndClearCertificatePublicationStatusHandlerFactory(
		&certificatePublicationStatusConfig, certificatePublicationStatusRuntimeDependencies{
			Pool: pool, Identity: identityService,
		},
	)
	if err != nil {
		return runtimeStageError{stage: "initialize certificate publication status runtime", err: err}
	}
	policyState := platformpolicy.NewState(time.Now)
	controlUpgradeRuntime, controlUpgradeService, err := openControlUpgradeProductionRuntime(
		ctx, cfg, controlUpgradeConfig, pool, trust, policyState, nats.Connect,
	)
	if err != nil {
		return runtimeStageError{stage: "initialize control upgrade production runtime", err: err}
	}
	if controlUpgradeRuntime != nil {
		defer controlUpgradeRuntime.Close()
	}
	maintenanceUpgradeClient, err := openMaintenanceUpgradeClient(cfg, trust)
	if err != nil {
		return runtimeStageError{stage: "initialize maintenance upgrade candidate client", err: err}
	}
	defer maintenanceUpgradeClient.Close()
	maintenanceUpgradeRuntime := controlupgrade.MaintenanceRuntime{
		CurrentVersion: controlVersion, ConfiguredVersion: cfg.ControlVersion,
		OfflineAfter: cfg.NodePresenceOfflineAfter,
	}
	configureMaintenanceUpgradeRuntime(&maintenanceUpgradeRuntime, controlPlaneUpgradeHandler)
	if maintenanceUpgradeClient != nil {
		maintenanceUpgradeRuntime.Candidates = maintenanceUpgradeClient
	}
	if controlPlaneUpgradeHandler != nil {
		maintenanceUpgradeRuntime.ProtocolVersion, err = positiveEnvironmentInt("CONTROL_UPGRADE_PROTOCOL_VERSION")
		if err != nil {
			return runtimeStageError{stage: "read control upgrade protocol version", err: err}
		}
	}
	if controlUpgradeRuntime != nil {
		maintenanceUpgradeRuntime.NodeReady = controlUpgradeRuntime.Ready
	}
	pluginInstallation, err := buildPluginInstallationRuntime(ctx, cfg, pool, identityService, trust)
	if err != nil {
		return runtimeStageError{stage: "initialize plugin installation runtime", err: err}
	}
	pluginInstallationHandlerFactory := pluginInstallation.handlerFactory()
	marketAdvisories, err := buildMarketAdvisorySync(pluginInstallation, pool)
	if err != nil {
		return runtimeStageError{stage: "initialize plugin advisory sync", err: err}
	}
	edgeSignerTrust, err := buildEdgeSignerTrustRuntime(pool, cfg.LicenseServiceURL, edgePublishSigner, edgeRuntime.connection)
	if err != nil {
		return runtimeStageError{stage: "initialize edge signer trust", err: err}
	}
	if edgeSignerTrust != nil {
		edgeRuntime.workers = append(edgeRuntime.workers, edgeSignerTrust.workers()...)
	}
	installationBanDistributor, err := entitlementRevocationRuntime.installationBanDistributor(pool, edgeRuntime.connection)
	if err != nil {
		return runtimeStageError{stage: "initialize installation ban delivery", err: err}
	}
	if installationBanDistributor != nil {
		// A node verifies tickets only with keys of its applied signer trust:
		// hold them until it reports one, and send right after (acc-a DA-1).
		if edgeSignerTrust != nil && edgeSignerTrust.distributor != nil {
			installationBanDistributor.TrustApplied = edgeSignerTrust.store.NodeTrustRevisions
			edgeSignerTrust.distributor.OnApplied(installationBanDistributor.Wake)
		}
		edgeRuntime.workers = append(edgeRuntime.workers, installationBanDistributor)
	}
	securityBans, err := buildSecurityBanRuntime(pool, analyticsDiagnosticClient, edgePublishSigner, edgeRuntime.connection)
	if err != nil {
		return runtimeStageError{stage: "initialize security ban list", err: err}
	}
	edgeRuntime.workers = append(edgeRuntime.workers, securityBans.workers()...)
	// 建站「DNS API（自动添加记录）」(migration 490): without the DNS
	// credential cipher the tasks stay pending and the site shows it.
	if autoDNS, err := buildSiteAutoDNSWorker(pool, credentialCipher); err != nil {
		return runtimeStageError{stage: "initialize site auto DNS", err: err}
	} else if autoDNS != nil {
		edgeRuntime.workers = append(edgeRuntime.workers, autoDNS)
	}
	// 接入状态 dns_resolved（迁移 565）：主控本机解析器按站点限频后台检查。
	if configuredRuntimePool(pool) {
		edgeRuntime.workers = append(edgeRuntime.workers, site.NewDNSCheckWorker(
			site.NewStoreWithClock(pool, time.Now, nil), nil, slog.Default()))
	}
	// cdncaCE: daily anonymous installation report to the official service (COMMUNITY_REPORT_URL=off opts out).
	communityReports, err := newCommunityReporter(pool, cfg.ControlVersion)
	if err != nil {
		return runtimeStageError{stage: "initialize community installation report", err: err}
	}
	if communityReports != nil {
		go func() { _ = communityReports.Run(ctx) }()
	}
	nodeArtifactSets, err := buildNodeArtifactSetDistributor(pool, edgePublishSigner, trust)
	if err != nil {
		return runtimeStageError{stage: "initialize node artifact set distribution", err: err}
	}
	if nodeArtifactSets != nil {
		edgeRuntime.workers = append(edgeRuntime.workers, nodeArtifactSets)
	}
	ipIntelUpdates, ipIntelUpdateHandlerFactory, err := buildIPIntelUpdateRuntime(pool, identityService, credentialCipher, trust,
		nodeArtifactSets)
	if err != nil {
		return runtimeStageError{stage: "initialize IP intelligence updates", err: err}
	}
	if ipIntelUpdates != nil {
		edgeRuntime.workers = append(edgeRuntime.workers, ipIntelUpdates)
	}
	var nodeGatewayAddressStepUp nodegatewayaddr.StepUpConsumer
	if consumer := mfaRuntime.StepUpConsumer(); consumer != nil {
		nodeGatewayAddressStepUp = consumer
	}
	nodeGatewayAddresses, nodeGatewayAddressHandlerFactory, err := buildNodeGatewayAddressRuntime(pool, identityService,
		edgePublishSigner, edgeRuntime.connection, nodeGatewayAddressStepUp)
	if err != nil {
		return runtimeStageError{stage: "initialize node gateway address changes", err: err}
	}
	if nodeGatewayAddresses != nil {
		edgeRuntime.workers = append(edgeRuntime.workers, nodeGatewayAddresses)
	}
	var controlPlaneUpgradeMounted http.Handler
	var controlPlaneUpgradeGate func(http.Handler) http.Handler
	if controlPlaneUpgradeHandler != nil {
		controlPlaneUpgradeMounted = controlPlaneUpgradeHandler.Handler()
		controlPlaneUpgradeGate = controlPlaneUpgradeHandler.Gate
	}
	var l4AnalyticsHandler http.Handler
	if cfg.AnalyticsQueryEnabled {
		l4Source, sourceErr := l4analytics.NewClickHouseSource(l4analytics.ClickHouseConfig{
			Endpoint: cfg.ClickHouseURL, Database: cfg.ClickHouseDatabase, Username: cfg.ClickHouseUsername,
			Password: cfg.ClickHousePassword, QueryTimeout: cfg.AnalyticsQueryTimeout, MaxResponseBytes: cfg.AnalyticsQueryMaxResponse,
		})
		if sourceErr != nil {
			return runtimeStageError{stage: "initialize L4 analytics ClickHouse source", err: sourceErr}
		}
		cursorDigest := sha256.Sum256(append([]byte("cdnca.l4.analytics.cursor.v1\x00"), cfg.AccessSecret...))
		l4Reader, readerErr := l4analytics.NewService(l4Source, l4analytics.Config{Now: time.Now, CursorKey: cursorDigest[:]})
		if readerErr != nil {
			return runtimeStageError{stage: "initialize L4 analytics query service", err: readerErr}
		}
		l4AnalyticsHandler, readerErr = l4analyticshttp.NewHandler(l4Reader, func(request *http.Request) (identity.Principal, error) {
			raw, ok := siteCaptureBearerToken(request)
			if !ok {
				return identity.Principal{}, identity.ErrInvalidSession
			}
			authenticated, err := identityService.AuthenticateSession(request.Context(), raw)
			if err != nil {
				return identity.Principal{}, identity.ErrInvalidSession
			}
			return authenticated.Principal, nil
		}, l4analyticshttp.Config{QueryTimeout: cfg.AnalyticsHandlerTimeout, MaxResponseBytes: cfg.AnalyticsHandlerMaxResponse})
		if readerErr != nil {
			return runtimeStageError{stage: "initialize L4 analytics HTTP handler", err: readerErr}
		}
	}
	var entitlementRefreshHandlerFactory httpapi.MountedHandlerFactory
	if entitlementSyncer != nil {
		entitlementAuditLog := audit.New(pool)
		entitlementRefreshHandler, refreshErr := entitlementrefreshhttp.New(
			entitlementSyncer,
			func(request *http.Request, raw string) (identity.AuthenticatedSession, error) {
				return identityService.AuthenticateSession(request.Context(), raw)
			},
			func(ctx context.Context, session identity.AuthenticatedSession, requestID, result, outcome string, snapshot entitlementguard.Snapshot) error {
				return pgx.BeginFunc(ctx, pool, func(tx pgx.Tx) error {
					payload := map[string]any{
						"serial": snapshot.Serial,
						"status": snapshot.Status,
					}
					if snapshot.InstallationID != "" {
						payload["installation_id"] = snapshot.InstallationID
					}
					// LIC-REC-03: a failure records whether the lease was not
					// applied or may have been (COMMIT answer lost).
					reasonCode := ""
					if outcome != "" {
						reasonCode = "entitlement_refresh_" + outcome
					}
					return entitlementAuditLog.Append(ctx, tx, audit.Event{
						ScopeID: session.Principal.ScopeID, ActorUserID: &session.Principal.UserID,
						Action: "entitlement.refresh", ResourceType: "platform_entitlement",
						ResourceID: snapshot.InstallationID, RequestID: requestID, Result: result, Payload: payload,
						ReasonCode: reasonCode,
					})
				})
			},
		)
		if refreshErr != nil {
			return runtimeStageError{stage: "initialize entitlement refresh HTTP handler", err: refreshErr}
		}
		entitlementRefreshHandlerFactory = func() (http.Handler, error) { return entitlementRefreshHandler, nil }
	}
	nodeIsolationHandlerFactory := func() (http.Handler, error) {
		return nodeisolationhttp.NewProductionHandler(
			nodeisolationhttp.ProductionDependencies{Pool: pool, Identity: identityService},
			nodeisolationhttp.DefaultProductionConfig(),
		)
	}
	siteGroupIAM, err := buildSharedRuntimeIAM()
	if err != nil {
		return runtimeStageError{stage: "initialize site group IAM", err: err}
	}
	siteGroupService, err := sitegroup.NewService(pool, siteGroupIAM, time.Now)
	if err != nil {
		return runtimeStageError{stage: "initialize site group service", err: err}
	}
	// 网站更换所属用户 carries the uploaded certificate (needs the private key keyring).
	var siteTransferCertificates site.TransferCertificates
	if enveloper, envelopeErr := newConfiguredACMECertificateEnveloper(cfg); envelopeErr == nil {
		if store, storeErr := certificateasset.NewStore(pool, enveloper); storeErr == nil {
			siteTransferCertificates = store
		}
	}
	api := httpapi.New(pool, identityService, httpapi.Config{
		SiteTransferCertificates:            siteTransferCertificates,
		CookieSecure:                        cfg.CookieSecure,
		CookieDomain:                        cfg.CookieDomain,
		Logger:                              slog.Default(),
		EntitlementTrust:                    trust,
		PlatformPolicyState:                 policyState,
		SecurityBanStore:                    securityBans.store,
		ControlUpgradeService:               controlUpgradeService,
		MaintenanceUpgradeRuntime:           maintenanceUpgradeRuntime,
		DNSCredentialCipher:                 credentialCipher,
		DNSProviderVerifier:                 dnsacme.NewProviderVerifierDispatcher(),
		DNSZoneApexResolver:                 dnsproviderremote.NewZoneApexResolver(),
		APIKeyPepper:                        cfg.APIKeyPepper,
		APIKeyPepperKeyring:                 cfg.APIKeyPepperKeyring,
		APIKeyTrustedProxyCIDRs:             cfg.APIKeyTrustedProxyCIDRs,
		APIKeyMaxProxyHops:                  cfg.APIKeyMaxProxyHops,
		APIKeyUsageRecorder:                 apiKeyUsageRuntime,
		NodePresenceLeases:                  presenceLeases,
		NodePresenceOfflineAfter:            cfg.NodePresenceOfflineAfter,
		NodeMetricsReader:                   nodeMetricsRuntime.reader,
		NodePortTransitionReady:             nodePortTransitionRuntime.Ready,
		RuleMountsPublished:                 wakeNodeArtifactSets(nodeArtifactSets),
		AdminDashboardHandler:               dashboardHandler,
		TenantDashboardHandler:              dashboardHandler,
		SystemConfigurationHandlerFactory:   systemConfigurationHandlerFactory,
		SystemSettingsHandlerFactory:        systemSettingsHandlerFactory,
		PluginUIHandlerFactory:              pluginUIHandlerFactory,
		PluginProviderHandlerFactory:        pluginProviderHandlerFactory,
		BrandAssetHandlerFactory:            brandAssetHandlerFactory,
		ThemeHandlerFactory:                 themeHandlerFactory,
		SystemCleanupSettingsHandlerFactory: systemCleanupSettingsHandlerFactory,
		SystemUserSettingsHandlerFactory:    systemUserSettingsHandlerFactory,
		SystemMailSettingsHandlerFactory:    systemMailSettingsHandlerFactory,
		SystemOtherSettingsHandlerFactory:   systemOtherSettingsHandlerFactory,
		L4LineSwitchHandlerFactory:          l4SwitchRuntime.HandlerFactory,
		SiteGroupService:                    siteGroupService,
		ControlUpgradePlanHandlerFactory:    controlUpgradePlanHandlerFactory,
		EntitlementRefreshHandlerFactory:    entitlementRefreshHandlerFactory,
		ControlPlaneUpgradeHandler:          controlPlaneUpgradeMounted,
		ControlPlaneUpgradeGate:             controlPlaneUpgradeGate,
		InstallationLockCheck:               entitlementRevocationRuntime.CheckInstallationState,
		NodeTickets:                         installationban.NodeTicketReader{Pool: pool},
		ImpersonationHandlerFactory:         impersonationHandlerFactory,
		CNAMEAllocationHandlerFactory: func(authenticate cnameallocationhttp.AuthenticateFunc) (http.Handler, error) {
			reader, err := cnameallocationhttp.NewPostgresReader(pool)
			if err != nil {
				return nil, err
			}
			return cnameallocationhttp.NewHandler(reader, authenticate, cnameallocationhttp.HandlerConfig{})
		},
		IPIntelUpdateHandlerFactory:                ipIntelUpdateHandlerFactory,
		NodeGatewayAddressHandlerFactory:           nodeGatewayAddressHandlerFactory,
		ProbeDNSPupHandlerFactory:                  probeDNSPupHandlerFactory,
		GatewayRegistryHandlerFactory:              gatewayRegistryHandlerFactory(gatewayRegistry, identityService),
		DomainTrustHandlerFactory:                  domainTrustHandlerFactory,
		DNSHubHandlerFactory:                       dnsHubHandlerFactory,
		TicketHandlerFactory:                       ticketHandlerFactory,
		NodeSSHInstallHandlerFactory:               nodeSSHInstallHandlerFactory,
		AccountRegistrationHandlerFactory:          accountRegistrationRuntime.HandlerFactory(),
		AccountLoginHandlerFactory:                 accountLoginRuntime.HandlerFactory(),
		CertificateAssetHandlerFactory:             certificateAssetHandlerFactory,
		CertificatePublicationStatusHandlerFactory: certificatePublicationStatusHandlerFactory,
		CacheControlHandlerFactory:                 cacheRuntime.HandlerFactory(),
		AnnouncementHandlerFactory:                 announcementRuntime.HandlerFactory(),
		NotificationHandlerFactory:                 notificationHandlerFactory,
		IdentityVerificationHandlerFactory:         identityVerificationHandlerFactory,
		IdentitySessionHandlerFactory:              identitySessionRuntime.HandlerFactory(),
		ChallengePolicyHandlerFactory:              challengePolicyHandlerFactory,
		HTTPPolicyHandlerFactory:                   httpPolicyHandlerFactory,
		FirewallActionHandlerFactory:               firewallActionHandlerFactory,
		PluginWebhookHandlerFactory:                pluginWebhookHandlerFactory,
		PluginInstallationHandlerFactory:           pluginInstallationHandlerFactory,
		ErrorPageHandlerFactory:                    errorPageHandlerFactory,
		ErrorPagePublicationHandlerFactory:         errorPagePublicationHandlerFactory,
		MFAHandlerFactory:                          mfaHandlerFactory,
		ApprovalStepUpConsumer:                     approvalStepUpConsumer(mfaRuntime),
		OriginAuthHandlerFactory:                   originAuthHandlerFactory,
		OriginAuthPublicationHandlerFactory:        originAuthPublicationHandlerFactory,
		EdgePublishHandlerFactory:                  edgePublishHandlerFactory,
		DNSReconcileHandlerFactory:                 dnsReconcileHandlerFactory,
		MarketRuntime:                              marketSubscribe != nil && marketClient != nil,
		MarketSubscribeHandlerFactory:              marketSubscribeHandlerFactory(marketSubscribe, marketClientForwarder(marketClient), identityService, pool, marketAdvisories, entitlementguard.NewGuard(pool, time.Now, trust)),
		NodeSchedulerHandlerFactory:                nodeSchedulerHandlerFactory,
		NodeIsolationHandlerFactory:                nodeIsolationHandlerFactory,
		AnalyticsService:                           analyticsService,
		AnalyticsQueryStore:                        analyticsQueryStore,
		AnalyticsDiagnosticHandlerFactory:          analyticsDiagnosticHandlerFactory,
		AnalyticsRealtimeHandlerFactory:            analyticsRealtimeHandlerFactory,
		L4AnalyticsHandler:                         l4AnalyticsHandler,
		StreamLiveConnections:                      streamLive,
		AnalyticsGeoHandlerFactory:                 analyticsGeoHandlerFactory,
		CustomRBACHandlerFactory:                   customRBACHandlerFactory,
		AnalyticsLogsHandler:                       analyticsLogsHandler,
		ObservabilityLogHandler:                    observabilityLogHandler,
		AuditLogHandler:                            auditLogHandler,
		BackupHistoryHandler:                       backupHistoryHandler,
		ControlBackupHandler:                       controlBackupHandler,
		CCCoordinationHandler:                      ccCoordinationHandler,
		SecurityCoordinationMetricsHandlerFactory:  securityCoordinationMetricsHandlerFactory,
		JA4BlockHandlerFactory:                     ja4BlockRuntime.HandlerFactory(),
		CCStatsHandlerFactory:                      ccStats.handler,
		MarketSecurityHandlerFactory:               ccStats.market,
		AnalyticsConnectionsRetentionHandler:       analyticsConnectionsRetentionHandler,
		AnalyticsConnectionsDLQHandler:             analyticsConnectionsDLQHandler,
		SiteCaptureHandler:                         siteCaptureHandler,
		AnalyticsHandlerConfig: analytics.HandlerConfig{
			QueryTimeout:     cfg.AnalyticsHandlerTimeout,
			MaxResponseBytes: cfg.AnalyticsHandlerMaxResponse,
		},
		JobQueryReader: jobQueryReader,
		JobQueryServiceConfig: jobhttp.ServiceConfig{
			ActiveCursorKeyID: cfg.JobQueryCursorActiveKeyID,
			CursorKeys:        cfg.JobQueryCursorKeys,
			ProducerCommands:  jobProducerCommands,
		},
		JobQueryHandlerConfig: jobhttp.HandlerConfig{
			QueryTimeout:     cfg.JobQueryTimeout,
			MaxResponseBytes: cfg.JobQueryMaxResponse,
		},
	})
	var errorPageRuntimeClosed bool
	defer func() {
		if errorPageRuntime != nil && !errorPageRuntimeClosed {
			_ = errorPageRuntime.Close()
		}
	}()
	if err := api.InitializationError(); err != nil {
		return fmt.Errorf("initialize HTTP API: %w", err)
	}
	readinessProbes := []readinessProbe{edgeRuntime, controlRuntime, identitySessionRuntime}
	if siteStatusRecoveryRuntime != nil {
		readinessProbes = append(readinessProbes, siteStatusRecoveryRuntime)
	}
	if impersonationReadiness != nil {
		readinessProbes = append(readinessProbes, impersonationReadiness)
	}
	if dnsReconcileRuntime != nil {
		readinessProbes = append(readinessProbes, dnsReconcileRuntime)
	}
	if acmeRuntime != nil {
		readinessProbes = append(readinessProbes, acmeRuntime)
	}
	if notificationRuntime != nil {
		readinessProbes = append(readinessProbes, notificationRuntime.ReadinessProbe())
	}
	if announcementRuntime != nil {
		readinessProbes = append(readinessProbes, announcementRuntime)
	}
	if identityVerificationRuntime != nil {
		readinessProbes = append(readinessProbes, identityVerificationRuntime)
	}
	if mfaRuntime != nil {
		readinessProbes = append(readinessProbes, mfaRuntime)
	}
	if errorPageConfig.Enabled {
		readinessProbes = append(readinessProbes, errorPageRuntime)
	}
	if signerRevocationRuntime != nil {
		readinessProbes = append(readinessProbes, signerRevocationRuntime)
	}
	if entitlementRevocationRuntime != nil {
		readinessProbes = append(readinessProbes, entitlementRevocationRuntime)
	}
	if cacheRuntime != nil {
		readinessProbes = append(readinessProbes, cacheRuntime)
	}
	if sitePublicationRuntime.SecurityActivation != nil {
		readinessProbes = append(readinessProbes, sitePublicationRuntime.SecurityActivation)
	}
	if ccCoordinationRuntime != nil {
		readinessProbes = append(readinessProbes, ccCoordinationRuntime)
	}
	if analyticsGeoArtifactRuntime != nil {
		readinessProbes = append(readinessProbes, analyticsGeoArtifactRuntime)
	}
	if edgeAutomaticPublicationRuntime != nil {
		readinessProbes = append(readinessProbes, edgeAutomaticPublicationRuntime)
	}
	if controlUpgradeRuntime != nil {
		readinessProbes = append(readinessProbes, controlUpgradeRuntime)
	}
	if controlUpgradePlanRuntime != nil {
		readinessProbes = append(readinessProbes, controlUpgradePlanRuntime)
	}
	if nodePortTransitionRuntime != nil {
		readinessProbes = append(readinessProbes, nodePortTransitionRuntime)
	}
	if ja4BlockRuntime != nil {
		readinessProbes = append(readinessProbes, ja4BlockRuntime)
	}
	if l4AnalyticsRuntime != nil {
		readinessProbes = append(readinessProbes, l4AnalyticsRuntime)
	}
	if certificatePublicationConfig.Enabled {
		if err := certificatePublicationRuntime.Ready(); err != nil {
			return runtimeStageError{stage: "initialize certificate publication readiness", err: err}
		}
		readinessProbes = append(readinessProbes, certificatePublicationRuntime)
	}
	server := &http.Server{
		Addr: cfg.HTTPAddr,
		Handler: api.WithClientSourceIP(api.WithImpersonationDelegate(withAnalyticsReplicaMetrics(withAnnouncementRuntimeHealth(withNotificationRuntimeHealth(withCacheControlRuntimeHealthDetail(
			requireReadiness(
				withAccountRecoveryRoutes(withOpenRestySecurityRoutes(
					withFirewallRoutes(api.Handler(), firewallHandler), openRestySecurityHandler,
				), accountRecoveryRuntime), readinessProbes...),
			analyticsIngestRuntime,
			accountRecoveryRuntime,
			cacheRuntime,
		), notificationRuntime), announcementRuntime), analyticsReplicaMetricsRuntime))),
		ReadHeaderTimeout: 5 * time.Second,
		ReadTimeout:       15 * time.Second,
		WriteTimeout:      30 * time.Second,
		IdleTimeout:       60 * time.Second,
	}
	mainListener, err := net.Listen("tcp", cfg.HTTPAddr)
	if err != nil {
		return runtimeStageError{stage: "bind control API listener", err: err}
	}
	defer mainListener.Close()
	mainServing := make(chan struct{})
	servingMainListener := &serveHandshakeListener{Listener: mainListener, serving: mainServing}
	if dnsReconcileRuntime != nil && dnsReconcileRuntime.workloadServer != nil {
		if err := dnsReconcileRuntime.workloadServer.Start(); err != nil {
			return runtimeStageError{stage: "start DNS reconcile workload mTLS listener", err: err}
		}
	}
	var background sync.WaitGroup
	backgroundErrors := make(chan error, 1)
	serveErrors := make(chan error, 1)
	var terminalErrorMu sync.Mutex
	reportTerminalError := func(target chan<- error, err error) {
		terminalErrorMu.Lock()
		select {
		case target <- err:
		default:
		}
		terminalErrorMu.Unlock()
	}
	background.Add(1)
	go func() {
		defer background.Done()
		runSecondaryVerificationEnforcement(ctx, identity.NewStore(pool), slog.Default())
	}()
	background.Add(1)
	go func() {
		defer background.Done()
		runAccountSuspensionEnforcement(ctx, identity.NewStore(pool), slog.Default())
	}()
	// 编辑节点 → IP 归属: automatic values from the IP
	// intelligence library for new nodes, changed addresses and new libraries.
	background.Add(1)
	go func() {
		defer background.Done()
		source := nodeIPLocationSource{lookup: analyticslog.NewPostgresIPIntelLookup(pool, slog.Default())}
		node.NewIPLocationResolver(pool, source, slog.Default()).Run(ctx, nodeIPLocationInterval)
	}()
	// Approval requests left executing by an interrupted process become
	// "outcome unknown" after 10 minutes (at start, then every minute); never replayed.
	background.Add(1)
	go func() {
		defer background.Done()
		approvalcenter.RunRecovery(ctx, approvalcenter.NewStore(pool, nil, nil), approvalcenter.RecoveryInterval, slog.Default())
	}()
	if certificatePublicationConfig.Enabled {
		background.Add(1)
		go func() {
			defer background.Done()
			err := certificatePublicationRuntime.Wait()
			if ctx.Err() == nil {
				reportTerminalError(backgroundErrors,
					runtimeStageError{stage: "certificate publication runtime stopped", err: err})
			}
		}()
	}
	if dnsReconcileRuntime != nil && dnsReconcileRuntime.workloadServer != nil {
		background.Add(1)
		go func() {
			defer background.Done()
			err := dnsReconcileRuntime.workloadServer.Wait()
			if ctx.Err() != nil {
				return
			}
			if err == nil {
				err = dnsreconcilehttpmtls.ErrServeFailed
			}
			reportTerminalError(backgroundErrors,
				runtimeStageError{stage: "DNS reconcile workload mTLS listener stopped", err: err})
		}()
		slog.Info("DNS reconcile workload mTLS listening", "address", dnsReconcileRuntime.workloadServer.Address())
	}
	if dnsReconcileRuntime != nil {
		background.Add(1)
		go func() {
			defer background.Done()
			if err := dnsReconcileRuntime.worker.Run(ctx); err != nil && !errors.Is(err, context.Canceled) {
				reportTerminalError(backgroundErrors,
					runtimeStageError{stage: "DNS reconcile worker stopped", err: err})
			}
		}()
		background.Add(1)
		go func() {
			defer background.Done()
			if err := runWithDBBackoff(ctx, slog.Default(), "CNAME allocation worker", 5*time.Minute, dnsReconcileRuntime.cnameWorker.Run); err != nil && !errors.Is(err, context.Canceled) {
				reportTerminalError(backgroundErrors,
					runtimeStageError{stage: "CNAME allocation worker stopped", err: err})
			}
		}()
		background.Add(1)
		go func() {
			defer background.Done()
			if err := runWithDBBackoff(ctx, slog.Default(), "DNS maintenance worker", 5*time.Minute, dnsReconcileRuntime.maintenanceWorker.Run); err != nil && !errors.Is(err, context.Canceled) {
				reportTerminalError(backgroundErrors,
					runtimeStageError{stage: "DNS maintenance worker stopped", err: err})
			}
		}()
		slog.Info("DNS reconcile runtime started", "workload_mtls", dnsReconcileRuntime.workloadServer != nil)
	}
	if acmeRuntime != nil {
		background.Add(1)
		go func() {
			defer background.Done()
			failures := make(chan error, 1)
			runRequiredACMERuntime(ctx, acmeRuntime, failures)
			select {
			case err := <-failures:
				reportTerminalError(backgroundErrors, err)
			default:
			}
		}()
	}
	if signerRevocationRuntime != nil {
		background.Add(1)
		go func() {
			defer background.Done()
			failures := make(chan error, 1)
			runRequiredSignerRevocationRuntime(ctx, signerRevocationRuntime, failures)
			select {
			case err := <-failures:
				reportTerminalError(backgroundErrors, err)
			default:
			}
		}()
	}
	if entitlementRevocationRuntime != nil {
		background.Add(1)
		go func() {
			defer background.Done()
			if err := runWithDBBackoff(ctx, slog.Default(), "entitlement revocation runtime", 5*time.Minute,
				entitlementRevocationRuntime.Run); ctx.Err() == nil {
				reportTerminalError(backgroundErrors,
					runtimeStageError{stage: "entitlement revocation runtime stopped", err: err})
			}
		}()
	}
	if pluginWebhookRuntime != nil {
		background.Add(1)
		go func() {
			defer background.Done()
			err := pluginWebhookRuntime.Run(ctx)
			if ctx.Err() != nil {
				return
			}
			if err == nil || errors.Is(err, context.Canceled) {
				err = errors.New("required runtime stopped unexpectedly")
			}
			reportTerminalError(backgroundErrors,
				runtimeStageError{stage: "plugin webhook runtime stopped", err: err})
		}()
	}
	if controlUpgradeRuntime != nil {
		background.Add(1)
		go func() {
			defer background.Done()
			err := controlUpgradeRuntime.Run(ctx)
			if ctx.Err() != nil {
				return
			}
			if err == nil || errors.Is(err, context.Canceled) {
				err = errors.New("required runtime stopped unexpectedly")
			}
			reportTerminalError(backgroundErrors,
				runtimeStageError{stage: "control upgrade runtime stopped", err: err})
		}()
	}
	if nodePortTransitionRuntime != nil {
		background.Add(1)
		go func() {
			defer background.Done()
			err := nodePortTransitionRuntime.Run(ctx)
			if ctx.Err() != nil {
				return
			}
			if err == nil || errors.Is(err, context.Canceled) {
				err = errors.New("required runtime stopped unexpectedly")
			}
			reportTerminalError(backgroundErrors,
				runtimeStageError{stage: "node port transition runtime stopped", err: err})
		}()
	}
	if siteStatusRecoveryRuntime != nil {
		background.Add(1)
		go func() {
			defer background.Done()
			err := siteStatusRecoveryRuntime.Run(ctx)
			if ctx.Err() != nil {
				return
			}
			if err == nil || errors.Is(err, context.Canceled) {
				err = errors.New("required runtime stopped unexpectedly")
			}
			reportTerminalError(backgroundErrors,
				runtimeStageError{stage: "site status recovery runtime stopped", err: err})
		}()
	}
	if marketRuntime != nil {
		// Optional: the market being down must not take the controller down.
		background.Add(1)
		go func() {
			defer background.Done()
			_ = marketRuntime.Run(ctx)
		}()
	}
	if wafSubscriptions := api.WAFSubscriptions(); wafSubscriptions != nil {
		// NF37 WAF rule library subscriptions: failures are recorded per
		// library (last good snapshot kept); never stops the server.
		background.Add(1)
		go func() {
			defer background.Done()
			wafSubscriptions.Run(ctx)
		}()
	}
	if attackAlerts != nil {
		// Logs and retries on its own; never stops the server.
		background.Add(1)
		go func() {
			defer background.Done()
			attackAlerts.Run(ctx)
		}()
	}
	// Certificate expiry facts (domain event + audit, once per version and
	// stage). Idempotent across control nodes; logs and retries on its own.
	// Notification-center reminders are certnotify's (certificate_notice_runtime.go,
	// on the platform's configurable notice days), so the scanner enqueues none:
	// both would remind the same members twice.
	certificateExpiryScanner, err := certificateexpiry.New(pool, time.Now)
	if err != nil {
		return runtimeStageError{stage: "initialize certificate expiry scanner", err: err}
	}
	background.Add(1)
	go func() {
		defer background.Done()
		certificateExpiryScanner.Run(ctx, certificateExpiryScanInterval, slog.Default())
	}()
	if packageTrafficEnforcement != nil {
		// Logs and retries on its own; never stops the server.
		background.Add(1)
		go func() {
			defer background.Done()
			packageTrafficEnforcement.Run(ctx)
		}()
	}
	if marketAdvisories != nil {
		// Logs and retries on its own; never stops the server.
		background.Add(1)
		go func() {
			defer background.Done()
			_ = marketAdvisories.Run(ctx)
		}()
	}
	if certificateNotices != nil {
		// Logs and retries on its own; never stops the server.
		background.Add(1)
		go func() {
			defer background.Done()
			_ = certificateNotices.Run(ctx)
		}()
	}
	// cdncaCE: market purchases (rule packs, themes, plugins) arrive through
	// the official per-installation artifact catalog once registered.
	if cfg.LicenseServiceURL == "" {
		communityArtifacts, err := newCommunityArtifactSyncer(ctx, cfg, pool, nodeArtifactSets)
		if err != nil {
			return runtimeStageError{stage: "initialize community artifact sync", err: err}
		}
		if communityArtifacts != nil {
			background.Add(1)
			go func() {
				defer background.Done()
				if err := communityArtifacts.Run(ctx); err != nil && !errors.Is(err, context.Canceled) {
					slog.Error("community artifact synchronization stopped", "error", err)
				}
			}()
		}
	}
	if cfg.LicenseServiceURL != "" {
		policyConfig, err := controlPlaneUpgradeEffectiveConfig(cfg)
		if err != nil {
			return err
		}
		policySyncer, err := newPlatformPolicySyncer(ctx, policyConfig, pool, trust, entitlementKeysets, policyState)
		if err != nil {
			return err
		}
		background.Add(1)
		go func() {
			defer background.Done()
			if err := entitlementSyncer.Run(ctx); err != nil && !errors.Is(err, context.Canceled) {
				slog.Error("entitlement synchronization stopped", "error", err)
			}
		}()
		usageReporter, err := newEntitlementUsageReporter(cfg, pool, analyticsRuntime, policyState)
		if err != nil {
			return runtimeStageError{stage: "initialize entitlement usage reporter", err: err}
		}
		background.Add(1)
		go func() {
			defer background.Done()
			if err := usageReporter.Run(ctx); err != nil && !errors.Is(err, context.Canceled) {
				slog.Error("entitlement usage reporting stopped", "error", err)
			}
		}()
		background.Add(1)
		go func() {
			defer background.Done()
			if err := policySyncer.Run(ctx); err != nil && !errors.Is(err, context.Canceled) {
				slog.Error("platform policy synchronization stopped", "error", err)
			}
		}()
		artifactSyncer, err := newArtifactSyncer(policyConfig, pool, trust, entitlementKeysets, nodeArtifactSets)
		if err != nil {
			return runtimeStageError{stage: "initialize artifact syncer", err: err}
		}
		background.Add(1)
		go func() {
			defer background.Done()
			if err := artifactSyncer.Run(ctx); err != nil && !errors.Is(err, context.Canceled) {
				slog.Error("artifact synchronization stopped", "error", err)
			}
		}()
		if providers, _ := pluginProviderService(policyConfig, pool); providers != nil {
			background.Add(1)
			go func() {
				defer background.Done()
				runPluginProviderContracts(ctx, providers, 10*time.Minute)
			}()
		}
		if wafReportRuntime != nil {
			background.Add(1)
			go func() {
				defer background.Done()
				if err := wafReportRuntime.Run(ctx); err != nil && !errors.Is(err, context.Canceled) {
					slog.Error("custom WAF rule reporting stopped", "error", err)
				}
			}()
		}
		if customRuleReportRuntime != nil {
			background.Add(1)
			go func() {
				defer background.Done()
				if err := customRuleReportRuntime.Run(ctx); err != nil && !errors.Is(err, context.Canceled) {
					slog.Error("security custom rule reporting stopped", "error", err)
				}
			}()
		}
	}
	if ja4BlockRuntime != nil {
		background.Add(1)
		go func() {
			defer background.Done()
			if err := ja4BlockRuntime.Run(ctx); err != nil && ctx.Err() == nil {
				reportTerminalError(backgroundErrors,
					runtimeStageError{stage: "JA4 block runtime stopped", err: err})
			}
		}()
	}
	if analyticsReplicaMetricsRuntime != nil {
		background.Add(1)
		go func() {
			defer background.Done()
			if err := analyticsReplicaMetricsRuntime.Run(ctx); err != nil && ctx.Err() == nil {
				reportTerminalError(backgroundErrors,
					runtimeStageError{stage: "analytics replica metrics runtime stopped", err: err})
			}
		}()
	}
	if realtimeCoverageRuntime != nil {
		background.Add(1)
		go func() {
			defer background.Done()
			if err := realtimeCoverageRuntime.Run(ctx); err != nil && ctx.Err() == nil {
				slog.Error("analytics realtime coverage finalizer stopped", "error", err)
			}
		}()
	}
	if presence != nil {
		background.Add(1)
		go func() {
			defer background.Done()
			if err := presence.Run(ctx); err != nil && !errors.Is(err, context.Canceled) {
				reportTerminalError(backgroundErrors, err)
			}
		}()
	}
	if analyticsIngestRuntime != nil {
		background.Add(1)
		go func() {
			defer background.Done()
			_ = analyticsIngestRuntime.Run(ctx)
		}()
	}
	if securityReports != nil {
		background.Add(1)
		go func() {
			defer background.Done()
			if err := securityReports.Run(ctx); err != nil && ctx.Err() == nil {
				reportTerminalError(backgroundErrors, runtimeStageError{stage: "security report ingest stopped", err: err})
			}
		}()
	}
	if l4AnalyticsRuntime != nil {
		background.Add(1)
		go func() {
			defer background.Done()
			if err := l4AnalyticsRuntime.Run(ctx); err != nil && ctx.Err() == nil {
				reportTerminalError(backgroundErrors, runtimeStageError{stage: "L4 analytics runtime stopped", err: err})
			}
		}()
	}
	if analyticsConnectionsRuntime != nil {
		background.Add(1)
		go func() {
			defer background.Done()
			if err := analyticsConnectionsRuntime.Run(ctx); err != nil && ctx.Err() == nil {
				reportTerminalError(backgroundErrors, runtimeStageError{stage: "analytics connections runtime stopped", err: err})
			}
		}()
	}
	if notificationRuntime != nil {
		background.Add(1)
		go func() {
			defer background.Done()
			failures := make(chan error, 1)
			runRequiredNotificationRuntime(ctx, notificationRuntime, failures)
			select {
			case err := <-failures:
				reportTerminalError(backgroundErrors, err)
			default:
			}
		}()
	}
	if announcementRuntime != nil {
		background.Add(1)
		go func() {
			defer background.Done()
			failures := make(chan error, 1)
			runRequiredAnnouncementRuntime(ctx, announcementRuntime, failures)
			select {
			case err := <-failures:
				reportTerminalError(backgroundErrors, err)
			default:
			}
		}()
	}
	if identityVerificationRuntime != nil {
		background.Add(1)
		go func() {
			defer background.Done()
			failures := make(chan error, 1)
			runRequiredIdentityVerificationRuntime(ctx, identityVerificationRuntime, failures)
			select {
			case err := <-failures:
				reportTerminalError(backgroundErrors, err)
			default:
			}
		}()
	}
	if mfaRuntime != nil {
		background.Add(1)
		go func() {
			defer background.Done()
			failures := make(chan error, 1)
			runRequiredMFARuntime(ctx, mfaRuntime, failures)
			select {
			case err := <-failures:
				reportTerminalError(backgroundErrors, err)
			default:
			}
		}()
	}
	if errorPageConfig.Enabled {
		background.Add(1)
		go func() {
			defer background.Done()
			failures := make(chan error, 1)
			runRequiredErrorPageRuntime(ctx, errorPageRuntime, failures)
			select {
			case err := <-failures:
				reportTerminalError(backgroundErrors, err)
			default:
			}
		}()
	}
	if cacheRuntime != nil {
		background.Add(1)
		go func() {
			defer background.Done()
			failures := make(chan error, 1)
			runRequiredCacheControlRuntime(ctx, cacheRuntime, failures)
			select {
			case err := <-failures:
				reportTerminalError(backgroundErrors, err)
			default:
			}
		}()
	}
	if sitePublicationRuntime.SecurityActivation != nil {
		background.Add(1)
		go func() {
			defer background.Done()
			if err := runWithDBBackoff(ctx, slog.Default(), "security activation worker", 5*time.Minute,
				sitePublicationRuntime.SecurityActivation.Run); ctx.Err() == nil {
				reportTerminalError(backgroundErrors,
					runtimeStageError{stage: "security activation worker stopped", err: err})
			}
		}()
	}
	if sitePublicationRuntime.CCInherit != nil {
		background.Add(1)
		go func() {
			defer background.Done()
			if err := sitePublicationRuntime.CCInherit.Run(ctx); ctx.Err() == nil {
				reportTerminalError(backgroundErrors,
					runtimeStageError{stage: "CC settings inheritance worker stopped", err: err})
			}
		}()
	}
	if l4SwitchRuntime.Reconciler != nil {
		background.Add(1)
		go func() {
			defer background.Done()
			if err := l4SwitchRuntime.Reconciler.Run(ctx); ctx.Err() == nil {
				reportTerminalError(backgroundErrors,
					runtimeStageError{stage: "L4 line switch reconciler stopped", err: err})
			}
		}()
	}
	if ccCoordinationRuntime != nil {
		background.Add(1)
		go func() {
			defer background.Done()
			if err := ccCoordinationRuntime.Run(ctx); ctx.Err() == nil {
				reportTerminalError(backgroundErrors,
					runtimeStageError{stage: "CC coordination runtime stopped", err: err})
			}
		}()
	}
	if edgeAutomaticPublicationRuntime != nil {
		background.Add(1)
		go func() {
			defer background.Done()
			err := edgeAutomaticPublicationRuntime.Run(ctx)
			if ctx.Err() != nil {
				return
			}
			if err == nil || errors.Is(err, context.Canceled) {
				err = errors.New("required runtime stopped unexpectedly")
			}
			reportTerminalError(backgroundErrors,
				runtimeStageError{stage: "automatic edge publication runtime stopped", err: err})
		}()
	}
	background.Add(1)
	go func() {
		defer background.Done()
		if err := runWithDBBackoff(ctx, slog.Default(), "edge deployment runtime", 5*time.Minute, edgeRuntime.Run); err != nil && !errors.Is(err, context.Canceled) {
			reportTerminalError(backgroundErrors, fmt.Errorf("edge deployment runtime stopped: %w", err))
		}
	}()
	background.Add(1)
	go func() {
		defer background.Done()
		_ = nodeServingWorker.Run(ctx)
	}()
	background.Add(1)
	go func() {
		defer background.Done()
		failures := make(chan error, 1)
		runRequiredNodeMetricsRuntime(ctx, nodeMetricsRuntime, failures)
		select {
		case err := <-failures:
			reportTerminalError(backgroundErrors, err)
		default:
		}
	}()
	background.Add(1)
	go func() {
		defer background.Done()
		if err := controlRuntime.Serve(ctx); err != nil &&
			(!errors.Is(err, context.Canceled) || errors.Is(err, controlgrpc.ErrGracefulStopTimedOut)) {
			reportTerminalError(backgroundErrors,
				runtimeStageError{stage: "ControlInternal gRPC server stopped", err: err})
		}
	}()
	backgroundDone := make(chan struct{})
	go func() {
		background.Wait()
		close(backgroundDone)
	}()

	go func() {
		slog.Info("control API listening", "address", mainListener.Addr().String())
		err := server.Serve(servingMainListener)
		if ctx.Err() != nil {
			return
		}
		if err == nil {
			err = errors.New("control API listener stopped unexpectedly")
		}
		reportTerminalError(serveErrors, err)
	}()

	var runErr error
	slog.Info("ControlInternal gRPC listening", "address", controlRuntime.Address())

	if runErr == nil && ctx.Err() == nil {
		select {
		case <-ctx.Done():
		case err := <-serveErrors:
			runErr = err
		case err := <-backgroundErrors:
			runErr = err
		}
	}
	stop()
	shutdownCtx, cancel := context.WithTimeout(context.Background(), cfg.ShutdownPeriod)
	defer cancel()
	shutdownErrors := make(chan error, 5)
	shutdowns := 1
	go func() {
		shutdownErrors <- server.Shutdown(shutdownCtx)
	}()
	if dnsReconcileRuntime != nil {
		shutdowns++
		go func() {
			shutdownErrors <- dnsReconcileRuntime.shutdownWorkloadServer(shutdownCtx)
		}()
	}
	if signerRevocationRuntime != nil {
		shutdowns++
		go func() {
			shutdownErrors <- signerRevocationRuntime.Close()
		}()
	}
	if edgeAutomaticPublicationRuntime != nil {
		shutdowns++
		go func() {
			shutdownErrors <- edgeAutomaticPublicationRuntime.Close(shutdownCtx)
		}()
	}
	for range shutdowns {
		if err := <-shutdownErrors; err != nil && !errors.Is(err, net.ErrClosed) {
			runErr = errors.Join(runErr, err)
		}
	}
	select {
	case <-backgroundDone:
		err := nodeMetricsRuntime.Close()
		nodeMetricsRuntimeClosed = true
		if err != nil {
			runErr = errors.Join(runErr, err)
		}
		if siteStatusRecoveryRuntime != nil {
			if err := siteStatusRecoveryRuntime.Close(shutdownCtx); err != nil {
				runErr = errors.Join(runErr, err)
			} else {
				siteStatusRecoveryRuntimeClosed = true
			}
		}
		if cacheRuntime != nil {
			runErr = errors.Join(runErr,
				closeCacheControlProductionResourcesContext(shutdownCtx, cacheRuntime, cacheNATS))
			cacheControlResourcesClosed = true
		}
		if pluginWebhookRuntime != nil {
			if err := pluginWebhookRuntime.Close(shutdownCtx); err != nil {
				runErr = errors.Join(runErr, err)
			} else {
				pluginWebhookRuntimeClosed = true
			}
		}
		if mfaRuntime != nil {
			if err := mfaRuntime.Close(); err != nil && runErr == nil {
				runErr = err
			}
		}
		if mfaCipher != nil {
			if err := mfaCipher.Close(); err != nil && runErr == nil {
				runErr = err
			}
		}
		if errorPageRuntime != nil {
			if err := errorPageRuntime.Close(); err != nil && runErr == nil {
				runErr = err
			}
			errorPageRuntimeClosed = true
		}
		if identityVerificationRuntime != nil {
			if err := identityVerificationRuntime.Close(); err != nil {
				runErr = errors.Join(runErr, err)
			}
			identityVerificationRuntimeClosed = true
		}
		if err := announcementRuntime.Close(); err != nil && runErr == nil {
			runErr = err
		}
		if err := accountRecoveryRuntime.Close(); err != nil && runErr == nil {
			runErr = err
		}
		if err := notificationRuntime.Close(); err != nil && runErr == nil {
			runErr = err
		}
		if err := analyticsIngestRuntime.CloseContext(shutdownCtx); err != nil && runErr == nil {
			runErr = err
		}
		if err := l4AnalyticsRuntime.Close(); err != nil && runErr == nil {
			runErr = err
		}
		if err := analyticsConnectionsRuntime.Close(); err != nil && runErr == nil {
			runErr = err
		}
		if err := controlRuntime.Close(); err != nil && runErr == nil {
			runErr = err
		}
		if err := edgeRuntime.Close(); err != nil && runErr == nil {
			runErr = err
		}
		return runErr
	case <-shutdownCtx.Done():
		if runErr != nil {
			return runErr
		}
		return shutdownCtx.Err()
	}
}

// certificateExpiryScanInterval bounds how late an expiry notice can be.
const certificateExpiryScanInterval = 10 * time.Minute

func pluginWebhookRuntimeConfig(source config.PluginWebhookConfig, pool *pgxpool.Pool) pluginwebhookruntime.Config {
	return pluginwebhookruntime.Config{
		Pool: pool, NATSURL: source.NATSURL, NATSName: source.NATSName,
		NATSCredsFile: source.NATSCredsFile, NATSCAFile: source.NATSCAFile,
		NATSReconnectMin: source.NATSReconnectMin, NATSReconnectMax: source.NATSReconnectMax,
		JetStream: source.JetStream, PollInterval: source.PollInterval,
		OperationTimeout: source.OperationTimeout, LeaseDuration: source.LeaseDuration,
		ClaimTimeout: source.ClaimTimeout, ShutdownTimeout: source.ShutdownTimeout,
		Logger: slog.Default(), AttestationKeyID: source.AttestationKeyID, AttestationKey: source.AttestationKey,
		NextAttestationKeyID: source.NextAttestationKeyID, NextAttestationKey: source.NextAttestationKey,
	}
}

// installSignerRevocationGate makes every shared trust-store verification
// (leases, upgrade bundles, upgrade candidates, rollout grants and platform
// policy candidates) consult the verified revocation LKG. Without an enabled
// consumer the trust store keeps its previous behavior.
func installSignerRevocationGate(trust *entitlementguard.TrustStore,
	runtime *signerrevocationconsumer.ProductionRuntime) {
	if trust == nil || runtime == nil {
		return
	}
	trust.SetSignerRevocationGate(runtime.RevocationGate(slog.Default()))
}

func validateSignerRevocationShutdownPeriod(shared time.Duration,
	config signerrevocationconsumer.Config,
) error {
	if config.Enabled && shared < config.ShutdownTimeout {
		return errors.New("control API shutdown period is shorter than signer revocation consumer shutdown timeout")
	}
	return nil
}

func runRequiredSignerRevocationRuntime(ctx context.Context, worker runtimeWorker, failures chan<- error) {
	if worker == nil {
		select {
		case failures <- errors.New("signer revocation consumer stopped: required runtime is missing"):
		default:
		}
		return
	}
	err := runWithDBBackoff(ctx, slog.Default(), "signer revocation consumer", 5*time.Minute, worker.Run)
	if ctx.Err() != nil {
		return
	}
	if err == nil || errors.Is(err, context.Canceled) {
		err = errors.New("required runtime stopped unexpectedly")
	}
	select {
	case failures <- runtimeStageError{stage: "signer revocation consumer stopped", err: err}:
	default:
	}
}

func runRequiredCacheControlRuntime(ctx context.Context, runtime *cacheControlRuntime, failures chan<- error) {
	if runtime == nil {
		select {
		case failures <- errors.New("cache control runtime stopped: required runtime is missing"):
		default:
		}
		return
	}
	err := runtime.Run(ctx)
	if ctx.Err() != nil {
		return
	}
	if err == nil || errors.Is(err, context.Canceled) {
		err = errors.New("required runtime stopped unexpectedly")
	}
	select {
	case failures <- runtimeStageError{stage: "cache control runtime stopped", err: err}:
	default:
	}
}

func runRequiredACMERuntime(ctx context.Context, worker runtimeWorker, failures chan<- error) {
	if worker == nil {
		select {
		case failures <- errors.New("ACME runtime stopped: required worker is missing"):
		default:
		}
		return
	}
	err := worker.Run(ctx)
	if ctx.Err() != nil {
		return
	}
	if err == nil {
		err = errors.New("required worker stopped unexpectedly")
	}
	select {
	case failures <- runtimeStageError{stage: "ACME runtime stopped", err: err}:
	default:
	}
}

func runRequiredErrorPageRuntime(ctx context.Context, worker runtimeWorker, failures chan<- error) {
	if worker == nil {
		select {
		case failures <- errors.New("error page runtime stopped: required worker is missing"):
		default:
		}
		return
	}
	err := worker.Run(ctx)
	if ctx.Err() != nil {
		return
	}
	if err == nil {
		err = errors.New("required worker stopped unexpectedly")
	}
	select {
	case failures <- runtimeStageError{stage: "error page runtime stopped", err: err}:
	default:
	}
}

func openControlInternalRuntime(
	ctx context.Context,
	cfg config.Config,
	pool *pgxpool.Pool,
) (*controlgrpc.Server, error) {
	return openControlInternalRuntimeWithOverlay(ctx, cfg, pool, nil)
}

func openControlInternalRuntimeWithOverlay(
	ctx context.Context,
	cfg config.Config,
	pool *pgxpool.Pool,
	overlayArtifacts acmehttp01.FetchStore,
) (*controlgrpc.Server, error) {
	return openControlInternalRuntimeWithGateways(ctx, cfg, pool, overlayArtifacts, nil)
}

func openControlInternalRuntimeWithGateways(
	ctx context.Context,
	cfg config.Config,
	pool *pgxpool.Pool,
	overlayArtifacts acmehttp01.FetchStore,
	gateways controlinternal.GatewayRegistry,
) (*controlgrpc.Server, error) {
	if ctx == nil || pool == nil {
		return nil, errors.New("ControlInternal runtime dependencies are required")
	}
	certificateSigner, err := nodeca.LoadSignerFromFiles(cfg.NodeCACertificateChainFile, cfg.NodeCAPrivateKeyFile)
	if err != nil {
		return nil, runtimeStageError{stage: "load node CA signer", err: err}
	}
	nodeIdentities, err := nodeidentity.NewService(nodeidentity.NewStore(pool), certificateSigner, nodeidentity.DefaultConfig())
	if err != nil {
		return nil, runtimeStageError{stage: "configure node identity service", err: err}
	}
	// Expired certificate self-recoveries go to the notification center (ADR 0013 GW-02).
	recoveryAlerts, err := notification.NewStore(pool)
	if err != nil {
		return nil, runtimeStageError{stage: "configure node certificate recovery alerts", err: err}
	}
	nodeIdentities.EnableRecoveryAlerts(recoveryAlerts)
	ordinaryArtifacts, err := edgeartifact.NewStore(pool, edgeartifact.DefaultConfig())
	if err != nil {
		return nil, runtimeStageError{stage: "configure edge artifact service", err: err}
	}
	var artifacts controlinternal.ArtifactStore = ordinaryArtifacts
	if overlayArtifacts != nil {
		composite, err := acmehttp01.NewCompositeStore(ordinaryArtifacts, overlayArtifacts)
		if err != nil {
			return nil, runtimeStageError{stage: "configure composite edge artifact service", err: err}
		}
		artifacts = composite
	}
	service, err := controlinternal.NewService(nodeIdentities, artifacts, controlinternal.Config{
		GatewayWorkloadURISAN: cfg.ControlInternalGatewayURI,
		Gateways:              gateways,
		InstallationID:        cfg.ControlInstallationID,
		// The ACME overlay composite wraps FetchChunk only; site runtime v8
		// objects are served by the edge artifact store itself.
		SiteObjects: ordinaryArtifacts,
	})
	if err != nil {
		return nil, runtimeStageError{stage: "configure ControlInternal service", err: err}
	}
	grpcConfig := controlgrpc.DefaultConfig()
	grpcConfig.ListenAddress = cfg.ControlInternalGRPCAddr
	grpcConfig.ServerCertificateFile = cfg.ControlInternalServerCert
	grpcConfig.ServerPrivateKeyFile = cfg.ControlInternalServerKey
	grpcConfig.GatewayClientCAFile = cfg.ControlInternalGatewayCA
	if cfg.ShutdownPeriod < grpcConfig.ShutdownTimeout {
		grpcConfig.ShutdownTimeout = cfg.ShutdownPeriod
	}
	runtime, err := controlgrpc.New(ctx, grpcConfig, service)
	if err != nil {
		return nil, runtimeStageError{stage: "open ControlInternal gRPC server", err: err}
	}
	return runtime, nil
}

type runtimeWorker interface {
	Run(context.Context) error
}

type closeableRuntimeWorker interface {
	runtimeWorker
	Close() error
}

type readinessProbe interface {
	Ready() error
}

type pluginWebhookKeyring struct {
	id  string
	key [32]byte
}

func newPluginWebhookKeyring(id string, raw []byte) (*pluginWebhookKeyring, error) {
	if id == "" || len(raw) != 32 {
		return nil, pluginwebhookcontrol.ErrSecretUnavailable
	}
	keyring := &pluginWebhookKeyring{id: id}
	copy(keyring.key[:], raw)
	if keyring.key == ([32]byte{}) {
		return nil, pluginwebhookcontrol.ErrSecretUnavailable
	}
	return keyring, nil
}

func (keyring *pluginWebhookKeyring) Active(ctx context.Context) (pluginwebhookcontrol.WrappingKey, error) {
	if keyring == nil || ctx == nil || ctx.Err() != nil || keyring.id == "" || keyring.key == ([32]byte{}) {
		return pluginwebhookcontrol.WrappingKey{}, pluginwebhookcontrol.ErrSecretUnavailable
	}
	return pluginwebhookcontrol.WrappingKey{ID: keyring.id, Key: keyring.key}, nil
}

func (keyring *pluginWebhookKeyring) Lookup(ctx context.Context, id string) ([32]byte, error) {
	if keyring == nil || ctx == nil || ctx.Err() != nil || id == "" || id != keyring.id || keyring.key == ([32]byte{}) {
		return [32]byte{}, pluginwebhookcontrol.ErrSecretUnavailable
	}
	return keyring.key, nil
}

func (keyring *pluginWebhookKeyring) clear() {
	if keyring == nil {
		return
	}
	clear(keyring.key[:])
	keyring.id = ""
}

type natsRuntimeConnection interface {
	IsConnected() bool
	IsClosed() bool
	Drain() error
	Close()
}

type natsConnector func(string, ...nats.Option) (*nats.Conn, error)

type edgeDeploymentRuntime struct {
	connection      natsRuntimeConnection
	status          closeableRuntimeWorker
	workers         []runtimeWorker
	closed          <-chan struct{}
	shutdownTimeout time.Duration
	ready           atomic.Bool
	closeOnce       sync.Once
	closeErr        error
}

type natsConnectionMonitor struct {
	closed <-chan struct{}
}

type runtimeStageError struct {
	stage string
	err   error
}

func (e runtimeStageError) Error() string { return e.stage }
func (e runtimeStageError) Unwrap() error { return e.err }

// commandFailureAttrs logs the cause behind a redacted runtimeStageError. The
// shutdown path joins runErr with close errors (errors.Join), and
// errors.Unwrap does not see through a join, so the cause is found with
// errors.As, which walks joined errors too.
func commandFailureAttrs(err error) []any {
	attrs := []any{"error", err}
	var stage runtimeStageError
	cause := errors.Unwrap(err)
	if errors.As(err, &stage) && stage.err != nil {
		cause = stage.err
	}
	if cause != nil {
		attrs = append(attrs, "cause", cause)
	}
	return attrs
}

const (
	impersonationHMACKeyBase64Env = "IMPERSONATION_HMAC_KEY_BASE64"
	impersonationHMACKeyMinBytes  = 32
	impersonationHMACKeyMaxBytes  = 128
	impersonationReadinessTimeout = 2 * time.Second
	impersonationCredentialMaxLen = 4096
)

type impersonationRuntimeConfig struct {
	HMACKey []byte
}

type impersonationRuntimeDependencies struct {
	Pool     *pgxpool.Pool
	Identity *identity.Service
	Clock    func() time.Time
}

type impersonationRuntimeReadiness struct {
	pool       *pgxpool.Pool
	configured bool
}

type identitySessionRuntime struct {
	handler http.Handler
	closed  atomic.Bool
}

func openIdentitySessionRuntime(pool *pgxpool.Pool, identityService *identity.Service) (*identitySessionRuntime, error) {
	handler, err := identitysessionhttp.NewRuntimeHandler(pool, identityService, time.Now)
	if err != nil {
		return nil, err
	}
	return &identitySessionRuntime{handler: handler}, nil
}

func (runtime *identitySessionRuntime) HandlerFactory() httpapi.MountedHandlerFactory {
	if runtime == nil {
		return nil
	}
	return func() (http.Handler, error) {
		if err := runtime.Ready(); err != nil {
			return nil, err
		}
		return runtime.handler, nil
	}
}

func (runtime *identitySessionRuntime) Ready() error {
	if runtime == nil || nilRuntimeDependency(runtime.handler) || runtime.closed.Load() {
		return errors.New("identity session runtime is unavailable")
	}
	return nil
}

func (runtime *identitySessionRuntime) Close() error {
	if runtime != nil {
		runtime.closed.Store(true)
	}
	return nil
}

type impersonationSessionCodec struct {
	key [sha256.Size]byte
	now func() time.Time
}

type cursorRuntimeConfig struct {
	Enabled   bool
	CursorKey []byte
}

type mfaRuntimeConfig struct {
	Enabled      bool
	ActiveKeyID  string
	Keys         map[string][]byte
	ownedSecrets [][]byte
}

type mfaRuntimeDependencies struct {
	Pool     *pgxpool.Pool
	Identity *identity.Service
	IAM      *iamlock.Authorizer
}

type originAuthRuntimeConfig struct {
	Enabled      bool
	ActiveKeyID  string
	Keys         map[string][]byte
	Verifier     originauthverifier.Config
	ownedSecrets [][]byte
}

type originAuthRuntimeDependencies struct {
	Pool     *pgxpool.Pool
	Identity *identity.Service
	IAM      *iamlock.Authorizer
	Trust    *entitlementguard.TrustStore
	Verifier originauthcontrol.CredentialVerifier
	Auditor  originauthcontrol.AuditAppender
	Clock    func() time.Time
}

type edgePublishRuntimeConfig struct {
	Enabled            bool
	Runtime            edgepublishhttp.RuntimeConfig
	SecurityActivation securityActivationRuntimeConfig
	ownedSecrets       [][]byte

	// LazyCertificateCacheMax overrides edgepublish.Config's when non-zero.
	LazyCertificateCacheMax int64
}

type securityActivationRuntimeConfig struct {
	Enabled bool
	Core    securityactivation.Config
}

type edgePublishRuntimeDependencies struct {
	Pool        *pgxpool.Pool
	Identity    *identity.Service
	APIKeys     *apikey.Service
	IAM         *iamlock.Authorizer
	Trust       *entitlementguard.TrustStore
	Signer      edgepublish.ArtifactSigner
	Entitlement edgepublish.EntitlementAuthorizer
	Resolver    edgepublish.TargetResolver
	Clock       func() time.Time
}

type edgePublishArtifactSigner struct {
	keyID      string
	privateKey ed25519.PrivateKey
	publicKey  ed25519.PublicKey
	provider   edgePublishArtifactSigningProvider
}

type edgePublishEntitlementAuthorizer struct {
	pool  *pgxpool.Pool
	trust *entitlementguard.TrustStore
}

type identityVerificationRuntimeConfig struct {
	cursorRuntimeConfig
	ResolverName       string
	ReviewTTL          time.Duration
	RetentionPeriod    time.Duration
	WorkerEnabled      bool
	Settlement         identityverification.SettlementWorkerConfig
	WorkerIdlePoll     time.Duration
	WorkerErrorBackoff time.Duration
}

type challengePolicyRuntimeConfig struct {
	cursorRuntimeConfig
	CursorKeyID string
	FactKeyID   string
	FactKey     []byte
}

type errorPageRuntimeConfig = errorpagecontrolhttp.Config

type errorPageStaticCredentials struct {
	accessKeyID     string
	secretAccessKey string
	sessionToken    string
}

func (credentials errorPageStaticCredentials) Retrieve(context.Context) (aws.Credentials, error) {
	return aws.Credentials{
		AccessKeyID: credentials.accessKeyID, SecretAccessKey: credentials.secretAccessKey,
		SessionToken: credentials.sessionToken, Source: "error-page-runtime",
	}, nil
}

func (config *cursorRuntimeConfig) clear() {
	if config == nil {
		return
	}
	clear(config.CursorKey)
	config.CursorKey = nil
}

func (config *mfaRuntimeConfig) clearSecrets() {
	if config == nil {
		return
	}
	clearRuntimeSecretSlices(config.ownedSecrets)
	clearRuntimeKeys(config.Keys)
	config.Enabled = false
	config.ActiveKeyID = ""
	config.Keys = nil
	config.ownedSecrets = nil
}

func (config *impersonationRuntimeConfig) clearSecrets() {
	if config == nil {
		return
	}
	clear(config.HMACKey)
	config.HMACKey = nil
}

func (config *originAuthRuntimeConfig) clearSecrets() {
	if config == nil {
		return
	}
	clearRuntimeSecretSlices(config.ownedSecrets)
	clearRuntimeKeys(config.Keys)
	config.Enabled = false
	config.ActiveKeyID = ""
	config.Keys = nil
	config.ownedSecrets = nil
	config.Verifier = originauthverifier.Config{}
}

func (config *edgePublishRuntimeConfig) clearSecrets() {
	if config == nil {
		return
	}
	clearRuntimeSecretSlices(config.ownedSecrets)
	clear(config.Runtime.CursorActiveKey.Secret)
	for index := range config.Runtime.CursorVerificationKeys {
		clear(config.Runtime.CursorVerificationKeys[index].Secret)
	}
	*config = edgePublishRuntimeConfig{}
}

func (signer *edgePublishArtifactSigner) KeyID() string {
	if signer == nil {
		return ""
	}
	return signer.keyID
}

func (signer *edgePublishArtifactSigner) PublicKey() ed25519.PublicKey {
	if signer == nil {
		return nil
	}
	if len(signer.publicKey) == ed25519.PublicKeySize {
		return append(ed25519.PublicKey(nil), signer.publicKey...)
	}
	if len(signer.privateKey) != ed25519.PrivateKeySize {
		return nil
	}
	publicKey, _ := signer.privateKey.Public().(ed25519.PublicKey)
	return append(ed25519.PublicKey(nil), publicKey...)
}

func (signer *edgePublishArtifactSigner) SigningKeyID() string {
	return signer.KeyID()
}

func (signer *edgePublishArtifactSigner) SigningPublicKey() ed25519.PublicKey {
	return signer.PublicKey()
}

func (signer *edgePublishArtifactSigner) Sign(ctx context.Context, payload []byte) ([]byte, error) {
	if signer == nil || ctx == nil || ctx.Err() != nil {
		return nil, edgepublish.ErrSigningFailed
	}
	var (
		signature []byte
		err       error
	)
	if signer.provider != nil {
		signature, err = signer.provider.Sign(ctx, payload)
	} else if len(signer.privateKey) == ed25519.PrivateKeySize {
		signature = ed25519.Sign(signer.privateKey, payload)
	} else {
		return nil, edgepublish.ErrSigningFailed
	}
	publicKey := signer.PublicKey()
	if err != nil || len(signature) != ed25519.SignatureSize || len(publicKey) != ed25519.PublicKeySize ||
		!ed25519.Verify(publicKey, payload, signature) {
		return nil, edgepublish.ErrSigningFailed
	}
	return append([]byte(nil), signature...), nil
}

func (signer *edgePublishArtifactSigner) ArtifactSigningKeyID() string {
	return signer.KeyID()
}

func (signer *edgePublishArtifactSigner) ArtifactSigningPublicKey() ed25519.PublicKey {
	return signer.PublicKey()
}

func (signer *edgePublishArtifactSigner) SignArtifact(ctx context.Context, payload []byte) ([]byte, error) {
	return signer.Sign(ctx, payload)
}

func (signer *edgePublishArtifactSigner) Close() {
	if signer == nil {
		return
	}
	if signer.provider != nil {
		signer.provider.Close()
		signer.provider = nil
	}
	clear(signer.privateKey)
	clear(signer.publicKey)
	signer.privateKey = nil
	signer.publicKey = nil
	signer.keyID = ""
}

func (authorizer *edgePublishEntitlementAuthorizer) AuthorizePublication(
	ctx context.Context,
	tx pgx.Tx,
	request edgepublish.EntitlementRequest,
) (edgepublish.EntitlementDecision, error) {
	if authorizer == nil || authorizer.pool == nil || authorizer.trust == nil ||
		ctx == nil || tx == nil || request.EvaluatedAt.IsZero() {
		return edgepublish.EntitlementDecision{}, entitlementguard.ErrUnavailable
	}
	evaluatedAt := request.EvaluatedAt.UTC()
	guard := entitlementguard.NewGuard(authorizer.pool, func() time.Time { return evaluatedAt }, authorizer.trust)
	decision, err := guard.CheckFeature(ctx, tx, entitlementguard.FeatureCheck{
		TargetScopeID: request.ConfigurationScopeID,
		ActorScopeID:  request.Actor.ScopeID,
		ActorUserID:   request.Actor.UserID,
		ResourceType:  "edge_configuration_scope",
		ResourceID:    request.ConfigurationScopeID,
		RequestID:     request.ConfigurationScopeID.String(),
		Operation:     "edge_publication.publish",
		Feature:       entitlementguard.FeatureSitesManage,
	})
	if err != nil {
		return edgepublish.EntitlementDecision{}, err
	}
	if !decision.EvaluatedAt.Equal(evaluatedAt) || decision.LeaseSerial < 1 {
		return edgepublish.EntitlementDecision{}, entitlementguard.ErrUnavailable
	}
	inGrace := !decision.EvaluatedAt.Before(decision.ExpiresAt)
	status := edgepublish.EntitlementStatusValid
	if inGrace {
		status = edgepublish.EntitlementStatusGrace
	}
	return edgepublish.EntitlementDecision{
		Allowed: true, LocallyVerified: true, InGrace: inGrace, Status: status,
		LeaseSerial: decision.LeaseSerial, EvaluatedAt: decision.EvaluatedAt,
	}, nil
}

// GrantedModuleCodes is the publication gate's view of the lease: the same
// verification as the API entry gate, read-only.
func (authorizer *edgePublishEntitlementAuthorizer) GrantedModuleCodes(ctx context.Context, tx pgx.Tx) ([]string, error) {
	if authorizer == nil || authorizer.pool == nil || authorizer.trust == nil || ctx == nil || tx == nil {
		return nil, nil
	}
	grants, err := entitlementguard.NewGuard(authorizer.pool, time.Now, authorizer.trust).GrantedModules(ctx, tx)
	if err != nil {
		return nil, err
	}
	return grants.Codes, nil
}

func (config *identityVerificationRuntimeConfig) clear() {
	config.clearSecrets()
}

func (config *identityVerificationRuntimeConfig) clearSecrets() {
	if config == nil {
		return
	}
	clear(config.CursorKey)
	*config = identityVerificationRuntimeConfig{}
}

func (config *challengePolicyRuntimeConfig) clear() {
	if config == nil {
		return
	}
	config.cursorRuntimeConfig.clear()
	clear(config.FactKey)
	config.FactKey = nil
	config.CursorKeyID = ""
	config.FactKeyID = ""
}

func loadErrorPageRuntimeConfig() (errorPageRuntimeConfig, error) {
	enabled, err := loadRuntimeBool("ERROR_PAGE_RUNTIME_ENABLED")
	if err != nil || !enabled {
		return errorPageRuntimeConfig{}, err
	}
	required := func(name string) (string, error) {
		value := strings.TrimSpace(os.Getenv(name))
		if value == "" {
			return "", fmt.Errorf("%s is required", name)
		}
		return value, nil
	}
	endpoint, err := required("ERROR_PAGE_OBJECT_STORE_ENDPOINT")
	if err != nil {
		return errorPageRuntimeConfig{}, err
	}
	region, err := required("ERROR_PAGE_OBJECT_STORE_REGION")
	if err != nil {
		return errorPageRuntimeConfig{}, err
	}
	bucket, err := required("ERROR_PAGE_OBJECT_STORE_BUCKET")
	if err != nil {
		return errorPageRuntimeConfig{}, err
	}
	accessKeyID, err := required("ERROR_PAGE_OBJECT_STORE_ACCESS_KEY_ID")
	if err != nil {
		return errorPageRuntimeConfig{}, err
	}
	secretAccessKey, err := required("ERROR_PAGE_OBJECT_STORE_SECRET_ACCESS_KEY")
	if err != nil {
		return errorPageRuntimeConfig{}, err
	}
	socketPath, err := required("ERROR_PAGE_CLAMD_SOCKET")
	if err != nil {
		return errorPageRuntimeConfig{}, err
	}
	prefix := strings.TrimSpace(os.Getenv("ERROR_PAGE_OBJECT_STORE_PREFIX"))
	if prefix == "" {
		prefix = "error-pages"
	}
	return errorPageRuntimeConfig{
		Enabled: true,
		ObjectStore: errorpageobjectstore.Config{
			Endpoint: endpoint, Region: region, Bucket: bucket, Prefix: prefix,
			Credentials: errorPageStaticCredentials{
				accessKeyID: accessKeyID, secretAccessKey: secretAccessKey,
				sessionToken: strings.TrimSpace(os.Getenv("ERROR_PAGE_OBJECT_STORE_SESSION_TOKEN")),
			},
			ConnectTimeout: 5 * time.Second, TLSHandshakeTimeout: 5 * time.Second,
			ResponseHeaderTimeout: 10 * time.Second, RequestTimeout: 30 * time.Second,
			MaxObjectSize: errorpagecontrol.MaxEdgeResourceBytes, MaxAttempts: 3,
		},
		Scanner: errorpagescanner.Config{
			SocketPath: socketPath, ConnectTimeout: 2 * time.Second, ScanTimeout: 30 * time.Second,
		},
	}, nil
}

func loadChallengePolicyRuntimeConfig() (challengePolicyRuntimeConfig, error) {
	enabled, err := loadRuntimeBool("CHALLENGE_POLICY_RUNTIME_ENABLED")
	if err != nil || !enabled {
		return challengePolicyRuntimeConfig{}, err
	}
	key, err := loadRuntimeCursorKey("CHALLENGE_POLICY_CURSOR_KEY_BASE64")
	if err != nil {
		return challengePolicyRuntimeConfig{}, err
	}
	keyID := os.Getenv("CHALLENGE_POLICY_CURSOR_KEY_ID")
	if keyID == "" || strings.TrimSpace(keyID) != keyID || strings.ContainsAny(keyID, "\r\n\t") {
		clear(key)
		return challengePolicyRuntimeConfig{}, errors.New("CHALLENGE_POLICY_CURSOR_KEY_ID is invalid")
	}
	factKey, factKeyErr := loadRuntimeCursorKey("CHALLENGE_POLICY_FACT_KEK_BASE64")
	if factKeyErr != nil || len(factKey) != 32 {
		clear(key)
		clear(factKey)
		return challengePolicyRuntimeConfig{}, errors.New("CHALLENGE_POLICY_FACT_KEK_BASE64 must encode exactly 32 bytes")
	}
	factKeyID := os.Getenv("CHALLENGE_POLICY_FACT_KEK_ID")
	if factKeyID == "" || strings.TrimSpace(factKeyID) != factKeyID || strings.ContainsAny(factKeyID, "\r\n\t") {
		clear(key)
		clear(factKey)
		return challengePolicyRuntimeConfig{}, errors.New("CHALLENGE_POLICY_FACT_KEK_ID is invalid")
	}
	return challengePolicyRuntimeConfig{
		cursorRuntimeConfig: cursorRuntimeConfig{Enabled: true, CursorKey: key},
		CursorKeyID:         keyID, FactKeyID: factKeyID, FactKey: factKey,
	}, nil
}

func loadImpersonationRuntimeConfigFromEnvEntries(entries []string) (impersonationRuntimeConfig, error) {
	values, err := runtimeEnvEntries(entries, "IMPERSONATION_", map[string]struct{}{
		impersonationHMACKeyBase64Env: {},
	})
	if err != nil {
		return impersonationRuntimeConfig{}, err
	}
	encoded, ok := values[impersonationHMACKeyBase64Env]
	if !ok || encoded == "" {
		return impersonationRuntimeConfig{}, errors.New("impersonation HMAC key is required")
	}
	key, err := base64.StdEncoding.Strict().DecodeString(encoded)
	if err != nil || len(key) < impersonationHMACKeyMinBytes || len(key) > impersonationHMACKeyMaxBytes ||
		base64.StdEncoding.EncodeToString(key) != encoded {
		clear(key)
		return impersonationRuntimeConfig{}, errors.New("impersonation HMAC key configuration is invalid")
	}
	return impersonationRuntimeConfig{HMACKey: key}, nil
}

func loadMFARuntimeConfigFromEnvEntries(entries []string) (mfaRuntimeConfig, error) {
	const prefix = "MFA_"
	values, err := runtimeEnvEntries(entries, prefix, map[string]struct{}{
		"MFA_ENABLED": {}, "MFA_ENCRYPTION_ACTIVE_KEY_ID": {}, "MFA_ENCRYPTION_KEYS_JSON": {},
	})
	if err != nil {
		return mfaRuntimeConfig{}, err
	}
	enabled, err := strictRuntimeBool(values, "MFA_ENABLED")
	if err != nil {
		return mfaRuntimeConfig{}, err
	}
	if !enabled {
		if len(values) != 1 {
			return mfaRuntimeConfig{}, errors.New("MFA configuration is invalid while disabled")
		}
		return mfaRuntimeConfig{}, nil
	}
	activeKeyID := values["MFA_ENCRYPTION_ACTIVE_KEY_ID"]
	keys, err := decodeRuntimeKeyring(values["MFA_ENCRYPTION_KEYS_JSON"], 32, 32)
	if err != nil || len(keys[activeKeyID]) != 32 {
		clearRuntimeKeys(keys)
		return mfaRuntimeConfig{}, errors.New("MFA encryption key configuration is invalid")
	}
	config := mfaRuntimeConfig{
		Enabled: true, ActiveKeyID: activeKeyID, Keys: keys, ownedSecrets: runtimeKeySecretSlices(keys),
	}
	validationCipher, err := newMFACipher(config)
	if err != nil {
		config.clearSecrets()
		return mfaRuntimeConfig{}, errors.New("MFA encryption key configuration is invalid")
	}
	_ = validationCipher.Close()
	return config, nil
}

func loadOriginAuthRuntimeConfigFromEnvEntries(entries []string) (originAuthRuntimeConfig, error) {
	const prefix = "ORIGIN_AUTH_"
	values, err := runtimeEnvEntries(entries, prefix, map[string]struct{}{
		"ORIGIN_AUTH_RUNTIME_ENABLED":          {},
		"ORIGIN_AUTH_ENCRYPTION_ACTIVE_KEY_ID": {},
		"ORIGIN_AUTH_ENCRYPTION_KEYS_JSON":     {},
		"ORIGIN_AUTH_PROVIDER_PROBES_JSON":     {},
	})
	if err != nil {
		return originAuthRuntimeConfig{}, err
	}
	enabled, err := strictRuntimeBool(values, "ORIGIN_AUTH_RUNTIME_ENABLED")
	if err != nil {
		return originAuthRuntimeConfig{}, err
	}
	if !enabled {
		if len(values) != 1 {
			return originAuthRuntimeConfig{}, errors.New("origin authentication configuration is invalid while disabled")
		}
		return originAuthRuntimeConfig{}, nil
	}
	activeKeyID := values["ORIGIN_AUTH_ENCRYPTION_ACTIVE_KEY_ID"]
	keys, err := decodeRuntimeKeyring(values["ORIGIN_AUTH_ENCRYPTION_KEYS_JSON"], 32, 32)
	if err != nil || len(keys[activeKeyID]) != 32 {
		clearRuntimeKeys(keys)
		return originAuthRuntimeConfig{}, errors.New("origin authentication encryption key configuration is invalid")
	}
	verifier, err := decodeOriginAuthVerifierConfig(values["ORIGIN_AUTH_PROVIDER_PROBES_JSON"])
	if err != nil {
		clearRuntimeKeys(keys)
		return originAuthRuntimeConfig{}, err
	}
	return originAuthRuntimeConfig{
		Enabled: true, ActiveKeyID: activeKeyID, Keys: keys, Verifier: verifier,
		ownedSecrets: runtimeKeySecretSlices(keys),
	}, nil
}

func loadEdgePublishRuntimeConfigFromEnvEntries(entries []string) (edgePublishRuntimeConfig, error) {
	const prefix = "EDGE_PUBLISH_"
	values, err := runtimeEnvEntries(entries, prefix, map[string]struct{}{
		"EDGE_PUBLISH_RUNTIME_ENABLED":          {},
		"EDGE_PUBLISH_CURSOR_ACTIVE_KEY_ID":     {},
		"EDGE_PUBLISH_CURSOR_KEYS_JSON":         {},
		"EDGE_PUBLISH_SIGNING_KEY_ID":           {},
		"EDGE_PUBLISH_SIGNING_PRIVATE_KEY_FILE": {},
		edgePublishSignerProviderEnv:            {},
		edgePublishSigningPublicKeyFileEnv:      {},
		edgePublishRemoteEndpointEnv:            {},
		edgePublishRemoteCAFileEnv:              {},
		edgePublishRemoteBearerTokenFileEnv:     {},
		edgePublishRemoteTimeoutEnv:             {},
	})
	if err != nil {
		return edgePublishRuntimeConfig{}, err
	}
	enabled, err := strictRuntimeBool(values, "EDGE_PUBLISH_RUNTIME_ENABLED")
	if err != nil {
		return edgePublishRuntimeConfig{}, err
	}
	if !enabled {
		if len(values) != 1 {
			return edgePublishRuntimeConfig{}, errors.New("edge publication configuration is invalid while disabled")
		}
		return edgePublishRuntimeConfig{}, nil
	}
	if err := rejectDuplicateJSONKeys(values["EDGE_PUBLISH_CURSOR_KEYS_JSON"]); err != nil {
		return edgePublishRuntimeConfig{}, errors.New("edge publication cursor key configuration is invalid")
	}
	runtimeConfig, err := edgepublishhttp.NewCursorRuntimeConfig(
		true, values["EDGE_PUBLISH_CURSOR_ACTIVE_KEY_ID"], values["EDGE_PUBLISH_CURSOR_KEYS_JSON"],
	)
	if err != nil {
		return edgePublishRuntimeConfig{}, errors.New("edge publication cursor key configuration is invalid")
	}
	ownedSecrets := make([][]byte, 0, 1+len(runtimeConfig.CursorVerificationKeys))
	ownedSecrets = append(ownedSecrets, runtimeConfig.CursorActiveKey.Secret)
	for index := range runtimeConfig.CursorVerificationKeys {
		ownedSecrets = append(ownedSecrets, runtimeConfig.CursorVerificationKeys[index].Secret)
	}
	return edgePublishRuntimeConfig{Enabled: true, Runtime: runtimeConfig, ownedSecrets: ownedSecrets}, nil
}

func loadSecurityActivationRuntimeConfigFromEnvEntries(entries []string) (securityActivationRuntimeConfig, error) {
	const prefix = "CDNCA_SECURITY_ACTIVATION_"
	values, err := runtimeEnvEntries(entries, prefix, map[string]struct{}{
		"CDNCA_SECURITY_ACTIVATION_ENABLED":                  {},
		"CDNCA_SECURITY_ACTIVATION_RECONCILE_INTERVAL":       {},
		"CDNCA_SECURITY_ACTIVATION_CANDIDATE_TTL":            {},
		"CDNCA_SECURITY_ACTIVATION_REQUIRED_WAF_API_VERSION": {},
		"CDNCA_SECURITY_ACTIVATION_REQUIRED_CC_API_VERSION":  {},
	})
	if err != nil {
		return securityActivationRuntimeConfig{}, err
	}
	enabled, err := strictRuntimeBool(values, "CDNCA_SECURITY_ACTIVATION_ENABLED")
	if err != nil {
		return securityActivationRuntimeConfig{}, err
	}
	if !enabled {
		if len(values) != 1 {
			return securityActivationRuntimeConfig{}, errors.New("security activation configuration is invalid while disabled")
		}
		return securityActivationRuntimeConfig{}, nil
	}
	config := securityactivation.DefaultConfig()
	config.ReconcileInterval, err = time.ParseDuration(values["CDNCA_SECURITY_ACTIVATION_RECONCILE_INTERVAL"])
	if err != nil {
		return securityActivationRuntimeConfig{}, errors.New("security activation reconcile interval is invalid")
	}
	config.CandidateTTL, err = time.ParseDuration(values["CDNCA_SECURITY_ACTIVATION_CANDIDATE_TTL"])
	if err != nil {
		return securityActivationRuntimeConfig{}, errors.New("security activation candidate TTL is invalid")
	}
	wafVersion, err := strconv.ParseUint(values["CDNCA_SECURITY_ACTIVATION_REQUIRED_WAF_API_VERSION"], 10, 32)
	if err != nil {
		return securityActivationRuntimeConfig{}, errors.New("security activation WAF API version is invalid")
	}
	ccVersion, err := strconv.ParseUint(values["CDNCA_SECURITY_ACTIVATION_REQUIRED_CC_API_VERSION"], 10, 32)
	if err != nil {
		return securityActivationRuntimeConfig{}, errors.New("security activation CC API version is invalid")
	}
	config.RequiredWAFAPIVersion = uint32(wafVersion)
	config.RequiredCCAPIVersion = uint32(ccVersion)
	if config.RequiredWAFAPIVersion != 1 || config.RequiredCCAPIVersion != 2 {
		return securityActivationRuntimeConfig{}, errors.New("security activation API versions are invalid")
	}
	return securityActivationRuntimeConfig{Enabled: true, Core: config}, nil
}

func runtimeEnvEntries(
	entries []string,
	prefix string,
	allowed map[string]struct{},
) (map[string]string, error) {
	values := make(map[string]string, len(allowed))
	for _, entry := range entries {
		name, value, found := strings.Cut(entry, "=")
		if !strings.HasPrefix(name, prefix) {
			continue
		}
		if !found {
			return nil, errors.New("runtime environment entry is invalid")
		}
		if _, ok := allowed[name]; !ok {
			return nil, errors.New("unknown " + prefix + "runtime environment variable")
		}
		if _, duplicate := values[name]; duplicate {
			return nil, errors.New("duplicate " + prefix + "runtime environment variable")
		}
		values[name] = value
	}
	return values, nil
}

func strictRuntimeBool(values map[string]string, name string) (bool, error) {
	value, present := values[name]
	if !present {
		return false, nil
	}
	switch value {
	case "true":
		return true, nil
	case "false":
		return false, nil
	default:
		return false, errors.New(name + " must be true or false")
	}
}

func decodeRuntimeKeyring(encoded string, minimum, maximum int) (map[string][]byte, error) {
	if encoded == "" || minimum < 1 || maximum < minimum || rejectDuplicateJSONKeys(encoded) != nil {
		return nil, errors.New("runtime keyring is invalid")
	}
	decoder := json.NewDecoder(strings.NewReader(encoded))
	var document map[string]string
	if err := decoder.Decode(&document); err != nil || len(document) == 0 || len(document) > 8 {
		return nil, errors.New("runtime keyring is invalid")
	}
	if err := requireJSONEOF(decoder); err != nil {
		return nil, errors.New("runtime keyring is invalid")
	}
	keys := make(map[string][]byte, len(document))
	for keyID, value := range document {
		key, err := base64.StdEncoding.Strict().DecodeString(value)
		if err != nil || len(key) < minimum || len(key) > maximum || base64.StdEncoding.EncodeToString(key) != value {
			clear(key)
			clearRuntimeKeys(keys)
			return nil, errors.New("runtime keyring is invalid")
		}
		keys[keyID] = key
	}
	return keys, nil
}

func decodeOriginAuthVerifierConfig(encoded string) (originauthverifier.Config, error) {
	if encoded == "" || rejectDuplicateJSONKeys(encoded) != nil {
		return originauthverifier.Config{}, errors.New("origin authentication provider probe configuration is invalid")
	}
	type probes struct {
		S3  *originauthverifier.Probe `json:"s3"`
		OSS *originauthverifier.Probe `json:"oss"`
		COS *originauthverifier.Probe `json:"cos"`
	}
	decoder := json.NewDecoder(strings.NewReader(encoded))
	decoder.DisallowUnknownFields()
	var document probes
	if err := decoder.Decode(&document); err != nil || requireJSONEOF(decoder) != nil {
		return originauthverifier.Config{}, errors.New("origin authentication provider probe configuration is invalid")
	}
	config := originauthverifier.Config{
		ConnectTimeout: 5 * time.Second, TLSHandshakeTimeout: 5 * time.Second,
		ResponseHeaderTimeout: 10 * time.Second, RequestTimeout: 20 * time.Second,
		MaxResponseBytes: 16 << 10, MaxAttempts: 2, MaxConcurrent: 10, Now: time.Now,
	}
	if document.S3 != nil {
		config.S3 = *document.S3
	}
	if document.OSS != nil {
		config.OSS = *document.OSS
	}
	if document.COS != nil {
		config.COS = *document.COS
	}
	if _, err := originauthverifier.New(config); err != nil {
		return originauthverifier.Config{}, errors.New("origin authentication provider probe configuration is invalid")
	}
	return config, nil
}

func rejectDuplicateJSONKeys(encoded string) error {
	decoder := json.NewDecoder(strings.NewReader(encoded))
	var consume func(json.Token) error
	consume = func(token json.Token) error {
		delimiter, ok := token.(json.Delim)
		if !ok {
			return nil
		}
		switch delimiter {
		case '{':
			seen := make(map[string]struct{})
			for decoder.More() {
				keyToken, err := decoder.Token()
				key, ok := keyToken.(string)
				if err != nil || !ok {
					return errors.New("invalid JSON object")
				}
				if _, duplicate := seen[key]; duplicate {
					return errors.New("duplicate JSON object key")
				}
				seen[key] = struct{}{}
				value, err := decoder.Token()
				if err != nil || consume(value) != nil {
					return errors.New("invalid JSON object value")
				}
			}
			closing, err := decoder.Token()
			if err != nil || closing != json.Delim('}') {
				return errors.New("invalid JSON object")
			}
		case '[':
			for decoder.More() {
				value, err := decoder.Token()
				if err != nil || consume(value) != nil {
					return errors.New("invalid JSON array value")
				}
			}
			closing, err := decoder.Token()
			if err != nil || closing != json.Delim(']') {
				return errors.New("invalid JSON array")
			}
		default:
			return errors.New("invalid JSON delimiter")
		}
		return nil
	}
	first, err := decoder.Token()
	if err != nil || consume(first) != nil {
		return errors.New("invalid JSON document")
	}
	return requireJSONEOF(decoder)
}

func requireJSONEOF(decoder *json.Decoder) error {
	if _, err := decoder.Token(); !errors.Is(err, io.EOF) {
		return errors.New("JSON document has trailing data")
	}
	return nil
}

func clearRuntimeKeys(keys map[string][]byte) {
	for keyID, key := range keys {
		clear(key)
		delete(keys, keyID)
	}
}

func runtimeKeySecretSlices(keys map[string][]byte) [][]byte {
	secrets := make([][]byte, 0, len(keys))
	for _, key := range keys {
		secrets = append(secrets, key)
	}
	return secrets
}

func clearRuntimeSecretSlices(secrets [][]byte) {
	for _, secret := range secrets {
		clear(secret)
	}
}

func newMFACipher(config mfaRuntimeConfig) (*mfacipher.Cipher, error) {
	active := mfacipher.Key{ID: config.ActiveKeyID, Material: config.Keys[config.ActiveKeyID]}
	keyIDs := make([]string, 0, len(config.Keys)-1)
	for keyID := range config.Keys {
		if keyID != config.ActiveKeyID {
			keyIDs = append(keyIDs, keyID)
		}
	}
	sort.Strings(keyIDs)
	previous := make([]mfacipher.Key, 0, len(keyIDs))
	for _, keyID := range keyIDs {
		previous = append(previous, mfacipher.Key{ID: keyID, Material: config.Keys[keyID]})
	}
	return mfacipher.New(active, previous...)
}

func buildAndClearImpersonationRuntime(
	config *impersonationRuntimeConfig,
	dependencies impersonationRuntimeDependencies,
) (httpapi.ImpersonationHandlerFactory, *impersonationRuntimeReadiness, error) {
	if config == nil {
		return nil, nil, errors.New("impersonation runtime configuration is required")
	}
	defer config.clearSecrets()
	if !configuredRuntimePool(dependencies.Pool) || dependencies.Identity == nil ||
		!dependencies.Identity.Configured() ||
		dependencies.Clock == nil || !validImpersonationClock(dependencies.Clock) ||
		len(config.HMACKey) < impersonationHMACKeyMinBytes || len(config.HMACKey) > impersonationHMACKeyMaxBytes {
		return nil, nil, errors.New("impersonation production dependencies are required")
	}
	codec, err := newImpersonationSessionCodec(config.HMACKey, dependencies.Clock)
	if err != nil {
		return nil, nil, errors.New("initialize impersonation session credential")
	}
	service, err := impersonation.NewService(dependencies.Pool, config.HMACKey)
	if err != nil {
		return nil, nil, errors.New("initialize impersonation service")
	}
	authorizer, err := impersonationhttp.NewSessionAuthorizer(service, codec, impersonationhttp.HandlerConfig{})
	if err != nil {
		return nil, nil, errors.New("initialize impersonation session authorizer")
	}
	factory := func(authenticate impersonationhttp.AuthenticateFunc) (http.Handler, httpapi.ImpersonationSessionAuthorizer, error) {
		if authenticate == nil {
			return nil, nil, errors.New("impersonation primary-session authentication is unavailable")
		}
		handler, err := impersonationhttp.New(service, authenticate, codec, impersonationhttp.HandlerConfig{})
		if err != nil {
			return nil, nil, errors.New("initialize impersonation HTTP handler")
		}
		return handler, authorizer, nil
	}
	return factory, &impersonationRuntimeReadiness{pool: dependencies.Pool, configured: true}, nil
}

func validImpersonationClock(clock func() time.Time) (valid bool) {
	if clock == nil {
		return false
	}
	defer func() {
		if recover() != nil {
			valid = false
		}
	}()
	return !clock().IsZero()
}

func newImpersonationSessionCodec(key []byte, now func() time.Time) (*impersonationSessionCodec, error) {
	if len(key) < impersonationHMACKeyMinBytes || len(key) > impersonationHMACKeyMaxBytes ||
		now == nil || !validImpersonationClock(now) {
		return nil, errors.New("impersonation session credential configuration is invalid")
	}
	derivation := hmac.New(sha256.New, key)
	_, _ = derivation.Write([]byte("cdnca-impersonation-session-v1"))
	codec := &impersonationSessionCodec{now: now}
	copy(codec.key[:], derivation.Sum(nil))
	return codec, nil
}

func (codec *impersonationSessionCodec) Issue(ctx context.Context, session impersonation.Session) (string, error) {
	if codec == nil || ctx == nil || ctx.Err() != nil || !validImpersonationSession(session, codec.now()) {
		return "", errors.New("impersonation session credential is unavailable")
	}
	payload, err := json.Marshal(session)
	if err != nil {
		return "", errors.New("impersonation session credential is unavailable")
	}
	encoded := base64.RawURLEncoding.EncodeToString(payload)
	signed := "v1." + encoded
	credential := signed + "." + base64.RawURLEncoding.EncodeToString(codec.signature(signed))
	if len(credential) > impersonationCredentialMaxLen {
		return "", errors.New("impersonation session credential is unavailable")
	}
	return credential, nil
}

func (codec *impersonationSessionCodec) Decode(ctx context.Context, credential string) (impersonation.Session, error) {
	if codec == nil || ctx == nil || ctx.Err() != nil || credential == "" || len(credential) > impersonationCredentialMaxLen {
		return impersonation.Session{}, errors.New("impersonation session credential is invalid")
	}
	parts := strings.Split(credential, ".")
	if len(parts) != 3 || parts[0] != "v1" || parts[1] == "" || parts[2] == "" {
		return impersonation.Session{}, errors.New("impersonation session credential is invalid")
	}
	signed := parts[0] + "." + parts[1]
	tag, err := base64.RawURLEncoding.Strict().DecodeString(parts[2])
	if err != nil || len(tag) != sha256.Size || subtle.ConstantTimeCompare(tag, codec.signature(signed)) != 1 {
		return impersonation.Session{}, errors.New("impersonation session credential is invalid")
	}
	payload, err := base64.RawURLEncoding.Strict().DecodeString(parts[1])
	if err != nil || len(payload) == 0 {
		return impersonation.Session{}, errors.New("impersonation session credential is invalid")
	}
	decoder := json.NewDecoder(strings.NewReader(string(payload)))
	decoder.DisallowUnknownFields()
	var session impersonation.Session
	if err := decoder.Decode(&session); err != nil || requireJSONEOF(decoder) != nil ||
		!validImpersonationSession(session, codec.now()) {
		return impersonation.Session{}, errors.New("impersonation session credential is invalid")
	}
	return session, nil
}

func (codec *impersonationSessionCodec) signature(signed string) []byte {
	mac := hmac.New(sha256.New, codec.key[:])
	_, _ = mac.Write([]byte(signed))
	return mac.Sum(nil)
}

func validImpersonationSession(session impersonation.Session, now time.Time) bool {
	principal := session.Principal
	banner := session.Banner
	return session.ID != uuid.Nil && session.GrantID != uuid.Nil && session.ActorUserID != uuid.Nil &&
		session.ActorScopeID != uuid.Nil && session.SubjectUserID != uuid.Nil && session.TenantID != uuid.Nil &&
		session.TenantScopeID != uuid.Nil && !session.CreatedAt.IsZero() && session.CreatedAt.Before(session.ExpiresAt) &&
		!now.Before(session.CreatedAt) && now.Before(session.ExpiresAt) &&
		!session.ExpiresAt.After(session.CreatedAt.Add(impersonation.SessionTTL)) && !session.Refreshable &&
		principal.UserID == session.SubjectUserID && principal.ScopeID == session.TenantScopeID &&
		principal.TenantID == session.TenantID && principal.ScopeKind == "tenant" && principal.Username != "" &&
		principal.DisplayName != "" && banner.GrantID == session.GrantID && banner.ActorUserID == session.ActorUserID &&
		banner.SubjectUserID == session.SubjectUserID && banner.TenantID == session.TenantID &&
		banner.ExpiresAt.Equal(session.ExpiresAt)
}

func (readiness *impersonationRuntimeReadiness) Ready() error {
	if readiness == nil || !readiness.configured || !configuredRuntimePool(readiness.pool) {
		return errors.New("impersonation readiness is unavailable")
	}
	ctx, cancel := context.WithTimeout(context.Background(), impersonationReadinessTimeout)
	defer cancel()
	var ready bool
	if err := readiness.pool.QueryRow(ctx, `SELECT
		to_regclass('admin_impersonation_grants') IS NOT NULL AND
		to_regclass('admin_impersonation_sessions') IS NOT NULL AND
		to_regclass('admin_impersonation_revocations') IS NOT NULL`).Scan(&ready); err != nil || !ready {
		return errors.New("impersonation schema is unavailable")
	}
	return nil
}

func buildAndClearMFARuntime(
	config *mfaRuntimeConfig,
	dependencies mfaRuntimeDependencies,
) (*mfahttp.Runtime, *mfacipher.Cipher, error) {
	if config == nil {
		return nil, nil, errors.New("MFA runtime configuration is required")
	}
	defer config.clearSecrets()
	if !config.Enabled {
		return nil, nil, nil
	}
	cipher, err := newMFACipher(*config)
	if err != nil {
		return nil, nil, errors.New("MFA encryption configuration is invalid")
	}
	runtime, err := mfahttp.NewRuntime(
		mfahttp.RuntimeConfig{Enabled: true, Core: mfa.Config{
			Clock: time.Now, Random: rand.Reader, Issuer: "CDNCA", EnrollmentTTL: 10 * time.Minute,
		}},
		mfahttp.RuntimeDependencies{
			Pool: dependencies.Pool, Identity: dependencies.Identity, IAM: dependencies.IAM, Cipher: cipher,
		},
	)
	if err != nil {
		_ = cipher.Close()
		return nil, nil, errors.New("initialize MFA runtime")
	}
	return runtime, cipher, nil
}

func buildAndClearOriginAuthHandlerFactory(
	config *originAuthRuntimeConfig,
	dependencies originAuthRuntimeDependencies,
) (httpapi.MountedHandlerFactory, error) {
	runtime, err := buildAndClearOriginAuthProductionRuntime(config, dependencies)
	return runtime.HandlerFactory, err
}

type originAuthProductionRuntime struct {
	HandlerFactory httpapi.MountedHandlerFactory
	Source         edgepublish.OriginAuthProductionSource
	// Service is the keyring-backed service market sites read and write
	// origin auth through.
	Service *originauthcontrol.Service
}

func buildAndClearOriginAuthProductionRuntime(
	config *originAuthRuntimeConfig,
	dependencies originAuthRuntimeDependencies,
) (originAuthProductionRuntime, error) {
	if config == nil {
		return originAuthProductionRuntime{}, errors.New("origin authentication runtime configuration is required")
	}
	defer config.clearSecrets()
	if !config.Enabled {
		return originAuthProductionRuntime{}, nil
	}
	if !configuredRuntimePool(dependencies.Pool) || dependencies.Identity == nil || !dependencies.Identity.Configured() ||
		dependencies.IAM == nil || !dependencies.IAM.Configured() || dependencies.Trust == nil ||
		len(dependencies.Trust.PinnedKeys()) == 0 || nilRuntimeDependency(dependencies.Verifier) ||
		nilRuntimeDependency(dependencies.Auditor) || dependencies.Clock == nil {
		return originAuthProductionRuntime{}, errors.New("origin authentication production dependencies are required")
	}
	keyring, err := originauthcontrol.NewKeyring(config.ActiveKeyID, config.Keys)
	if err != nil {
		return originAuthProductionRuntime{}, errors.New("origin authentication keyring is invalid")
	}
	serviceConfig := originauthcontrol.Config{
		Clock: dependencies.Clock, Verifier: dependencies.Verifier, Auditor: dependencies.Auditor,
		TrustStore: dependencies.Trust,
		// dynamic routing site objects carry the origin auth facts (D13-b2 1)
		Published: func(ctx context.Context, tx pgx.Tx, scopeID uuid.UUID) error {
			return edgepublish.RequestSiteFactsRepublicationTx(ctx, tx, scopeID, edgepublish.SystemTriggerOriginAuthPublished)
		},
	}
	handler, err := originauthcontrol.NewRuntimeHandler(
		originauthcontrol.RuntimeConfig{Enabled: true},
		originauthcontrol.RuntimeDependencies{
			Pool: dependencies.Pool, Identity: dependencies.Identity, IAM: dependencies.IAM, Keyring: keyring,
			Service: serviceConfig,
		},
	)
	if err != nil {
		return originAuthProductionRuntime{}, errors.New("initialize origin authentication runtime")
	}
	sourceService, err := originauthcontrol.NewService(dependencies.Pool, keyring, serviceConfig)
	if err != nil {
		return originAuthProductionRuntime{}, errors.New("initialize origin authentication production source service")
	}
	source, err := originauthcontrol.NewProductionSource(sourceService)
	if err != nil {
		return originAuthProductionRuntime{}, errors.New("initialize origin authentication production source")
	}
	return originAuthProductionRuntime{
		HandlerFactory: func() (http.Handler, error) { return handler, nil },
		Source:         source,
		Service:        sourceService,
	}, nil
}

func buildAndClearEdgePublishHandlerFactory(
	config *edgePublishRuntimeConfig,
	dependencies edgePublishRuntimeDependencies,
) (httpapi.MountedHandlerFactory, error) {
	runtime, err := buildAndClearEdgePublishRuntime(config, dependencies)
	return runtime.HandlerFactory, err
}

type edgePublishProductionRuntime struct {
	HandlerFactory          httpapi.MountedHandlerFactory
	SecurityActivation      *securityactivation.Worker
	SecurityActivationStore *securityactivation.Store
	// CCInherit re-resolves CC policies whose site settings follow the
	// global CC config and activates their sites again (G1-e).
	CCInherit *ccinherit.Worker
	Publisher *edgepublish.Runtime
}

func buildAndClearEdgePublishRuntime(
	config *edgePublishRuntimeConfig,
	dependencies edgePublishRuntimeDependencies,
) (edgePublishProductionRuntime, error) {
	if config == nil {
		return edgePublishProductionRuntime{}, errors.New("edge publication runtime configuration is required")
	}
	defer config.clearSecrets()
	if !config.Enabled {
		return edgePublishProductionRuntime{}, nil
	}
	if !configuredRuntimePool(dependencies.Pool) || dependencies.Identity == nil || !dependencies.Identity.Configured() ||
		dependencies.APIKeys == nil || dependencies.IAM == nil || !dependencies.IAM.Configured() ||
		dependencies.Trust == nil || len(dependencies.Trust.PinnedKeys()) == 0 ||
		nilRuntimeDependency(dependencies.Signer) || nilRuntimeDependency(dependencies.Entitlement) ||
		nilRuntimeDependency(dependencies.Resolver) || dependencies.Clock == nil {
		return edgePublishProductionRuntime{}, errors.New("edge publication production dependencies are required")
	}
	publisherConfig := edgepublish.DefaultConfig()
	if config.LazyCertificateCacheMax != 0 {
		publisherConfig.LazyCertificateCacheMax = config.LazyCertificateCacheMax
	}
	publisherConfig.Clock = dependencies.Clock
	publisherConfig.EntitlementAuthorizer = dependencies.Entitlement
	publisherConfig.TargetResolver = dependencies.Resolver
	publisherConfig.Auditor = audit.New(dependencies.Pool)
	publisher, err := edgepublish.NewRuntime(
		edgepublish.RuntimeConfig{Publisher: publisherConfig},
		edgepublish.RuntimeDependencies{Pool: dependencies.Pool, Signer: dependencies.Signer, IAM: dependencies.IAM},
	)
	if err != nil {
		return edgePublishProductionRuntime{}, errors.New("initialize edge publication domain runtime")
	}
	var activation *securityactivation.Store
	var activationWorker *securityactivation.Worker
	var inheritWorker *ccinherit.Worker
	if config.SecurityActivation.Enabled {
		bundlePublisher, err := securitybundle.NewPublisher(dependencies.Signer, securitybundle.Config{
			Clock: dependencies.Clock, Validity: config.SecurityActivation.Core.CandidateTTL,
		})
		if err != nil {
			return edgePublishProductionRuntime{}, errors.New("initialize security publication signer")
		}
		bindings, err := securitybinding.NewStore(dependencies.Pool, bundlePublisher, dependencies.Clock)
		if err != nil {
			return edgePublishProductionRuntime{}, errors.New("initialize security publication store")
		}
		activation, err = securityactivation.NewProductionStore(
			dependencies.Pool, dependencies.Clock, bindings, publisher.Publisher(),
			publisher.RolloutCommands(), config.SecurityActivation.Core,
		)
		if err != nil {
			return edgePublishProductionRuntime{}, errors.New("initialize security activation store")
		}
		activationWorker, err = securityactivation.NewWorker(activation)
		if err != nil {
			return edgePublishProductionRuntime{}, errors.New("initialize security activation worker")
		}
		policyStore := securitypolicy.NewStoreWithClock(dependencies.Pool, dependencies.Clock)
		inheritWorker, err = ccinherit.NewWorker(dependencies.Pool, policyStore, securitypolicy.NewService(policyStore),
			activation, ccInheritInterval, dependencies.Clock, slog.Default())
		if err != nil {
			return edgePublishProductionRuntime{}, errors.New("initialize CC settings inheritance worker")
		}
		config.Runtime.SecurityActivationEnabled = true
	}
	handler, err := edgepublishhttp.NewRuntimeHandler(config.Runtime, edgepublishhttp.RuntimeDependencies{
		Pool: dependencies.Pool, Identity: dependencies.Identity, APIKeys: dependencies.APIKeys,
		IAM: dependencies.IAM, Publisher: publisher, SecurityActivation: activation,
	})
	if err != nil {
		return edgePublishProductionRuntime{}, errors.New("initialize edge publication HTTP runtime")
	}
	return edgePublishProductionRuntime{
		HandlerFactory:          func() (http.Handler, error) { return handler, nil },
		SecurityActivation:      activationWorker,
		SecurityActivationStore: activation,
		CCInherit:               inheritWorker,
		Publisher:               publisher,
	}, nil
}

// ccInheritInterval is how often CC settings inheritance looks for a changed
// global CC config.
const ccInheritInterval = 30 * time.Second

func configuredRuntimePool(pool *pgxpool.Pool) (configured bool) {
	if pool == nil {
		return false
	}
	defer func() {
		if recover() != nil {
			configured = false
		}
	}()
	config := pool.Config()
	return config != nil && config.MaxConns > 0
}

func nilRuntimeDependency(value any) bool {
	if value == nil {
		return true
	}
	reflected := reflect.ValueOf(value)
	switch reflected.Kind() {
	case reflect.Chan, reflect.Func, reflect.Interface, reflect.Map, reflect.Pointer, reflect.Slice:
		return reflected.IsNil()
	default:
		return false
	}
}

func loadEdgePublishArtifactSigner(enabled bool) (*edgePublishArtifactSigner, error) {
	if !enabled {
		return nil, nil
	}
	provider := os.Getenv(edgePublishSignerProviderEnv)
	if provider == "" {
		provider = edgePublishSignerProviderFile
	}
	if strings.TrimSpace(provider) != provider {
		return nil, errors.New("EDGE_PUBLISH_SIGNER_PROVIDER is invalid")
	}
	keyID := strings.TrimSpace(os.Getenv("EDGE_PUBLISH_SIGNING_KEY_ID"))
	if !validRuntimeKeyID(keyID) {
		return nil, errors.New("EDGE_PUBLISH_SIGNING_KEY_ID is invalid")
	}
	switch provider {
	case edgePublishSignerProviderFile:
		if edgePublishRemoteSignerEnvironmentConfigured() {
			return nil, errors.New("remote edge publication signer variables require the remote provider")
		}
		privateKey, err := entitlementsync.LoadPrivateKey(
			strings.TrimSpace(os.Getenv("EDGE_PUBLISH_SIGNING_PRIVATE_KEY_FILE")),
		)
		if err != nil {
			return nil, errors.New("load edge publication signing key")
		}
		return &edgePublishArtifactSigner{keyID: keyID, privateKey: privateKey}, nil
	case edgePublishSignerProviderRemote:
		if strings.TrimSpace(os.Getenv("EDGE_PUBLISH_SIGNING_PRIVATE_KEY_FILE")) != "" {
			return nil, errors.New("remote edge publication signer cannot load a local private key")
		}
		remote, publicKey, err := loadEdgePublishRemoteArtifactSigner(keyID)
		if err != nil {
			return nil, err
		}
		return &edgePublishArtifactSigner{keyID: keyID, publicKey: publicKey, provider: remote}, nil
	default:
		return nil, errors.New("EDGE_PUBLISH_SIGNER_PROVIDER is invalid")
	}
}

func validRuntimeKeyID(value string) bool {
	if len(value) == 0 || len(value) > 128 {
		return false
	}
	for index, character := range []byte(value) {
		alphanumeric := character >= 'A' && character <= 'Z' || character >= 'a' && character <= 'z' ||
			character >= '0' && character <= '9'
		if alphanumeric || index > 0 && (character == '.' || character == '_' || character == ':' ||
			character == '/' || character == '-') {
			continue
		}
		return false
	}
	return true
}

func loadRuntimeBool(name string) (bool, error) {
	value, present := os.LookupEnv(name)
	if !present || value == "" || value == "false" {
		return false, nil
	}
	if value != "true" {
		return false, errors.New(name + " must be true or false")
	}
	return true, nil
}

func loadRuntimeCursorKey(name string) ([]byte, error) {
	encoded := os.Getenv(name)
	destination := make([]byte, base64.StdEncoding.DecodedLen(len(encoded)))
	return decodeRuntimeCursorKey(name, encoded, destination)
}

func decodeRuntimeCursorKey(name, encoded string, destination []byte) ([]byte, error) {
	decodedLength := base64.StdEncoding.DecodedLen(len(encoded))
	if len(destination) != decodedLength {
		clear(destination)
		return nil, errors.New(name + " must encode 32 to 128 bytes using canonical padded base64")
	}
	length, err := base64.StdEncoding.Strict().Decode(destination, []byte(encoded))
	key := destination[:length]
	if err != nil || len(key) < 32 || len(key) > 128 || base64.StdEncoding.EncodeToString(key) != encoded {
		clear(destination)
		return nil, errors.New(name + " must encode 32 to 128 bytes using canonical padded base64")
	}
	return key, nil
}

func runRequiredIdentityVerificationRuntime(ctx context.Context, runtime identityVerificationRuntimeRunner, failures chan<- error) {
	if runtime == nil {
		select {
		case failures <- errors.New("identity verification runtime stopped: required runtime is missing"):
		default:
		}
		return
	}
	err := runtime.Run(ctx)
	if ctx.Err() != nil {
		return
	}
	if err == nil {
		err = errors.New("required runtime stopped unexpectedly")
	}
	select {
	case failures <- runtimeStageError{stage: "identity verification runtime stopped", err: err}:
	default:
	}
}

func runRequiredMFARuntime(ctx context.Context, runtime *mfahttp.Runtime, failures chan<- error) {
	if runtime == nil {
		select {
		case failures <- errors.New("MFA runtime stopped: required runtime is missing"):
		default:
		}
		return
	}
	err := runtime.Run(ctx)
	if ctx.Err() != nil {
		return
	}
	if err == nil {
		err = errors.New("required runtime stopped unexpectedly")
	}
	select {
	case failures <- runtimeStageError{stage: "MFA runtime stopped", err: err}:
	default:
	}
}

func openEdgeDeploymentRuntime(
	ctx context.Context,
	cfg config.Config,
	pool *pgxpool.Pool,
	logger *slog.Logger,
	connect natsConnector,
) (_ *edgeDeploymentRuntime, returnedErr error) {
	if ctx == nil || pool == nil || connect == nil {
		return nil, errors.New("edge deployment runtime dependencies are required")
	}
	closed := make(chan struct{})
	var closedOnce sync.Once
	options := []nats.Option{
		nats.Name("cdnca-control-api-edge-deployment"),
		nats.Timeout(cfg.EdgeDeploymentConnectTimeout),
		nats.ReconnectWait(time.Second),
		nats.DrainTimeout(cfg.ShutdownPeriod),
		nats.ClosedHandler(func(*nats.Conn) {
			closedOnce.Do(func() { close(closed) })
		}),
	}
	if cfg.EdgeDeploymentNATSCredsFile != "" {
		options = append(options,
			nats.UserCredentials(cfg.EdgeDeploymentNATSCredsFile),
			nats.RootCAs(cfg.EdgeDeploymentNATSCAFile),
		)
	}
	connection, err := connect(cfg.EdgeDeploymentNATSURL, options...)
	if err != nil {
		return nil, runtimeStageError{stage: "connect edge deployment NATS", err: err}
	}
	failed := true
	defer func() {
		if failed {
			connection.Close()
		}
	}()
	startupCtx, cancel := context.WithTimeout(ctx, cfg.EdgeDeploymentConnectTimeout)
	err = verifyEdgeJetStream(startupCtx, connection, cfg)
	cancel()
	if err != nil {
		return nil, runtimeStageError{stage: "verify edge deployment JetStream resources", err: err}
	}
	publisher, err := edgeoutbox.New(pool, connection, edgeoutbox.Config{
		Stream: cfg.EdgeCommandStream, BatchSize: cfg.EdgeOutboxBatchSize,
		LeaseTimeout: cfg.EdgeOutboxLeaseTimeout, OperationTimeout: cfg.EdgeOutboxOperationTimeout,
		PollInterval: cfg.EdgeOutboxPollInterval, BaseBackoff: cfg.EdgeOutboxBaseBackoff,
		MaxBackoff: cfg.EdgeOutboxMaxBackoff, MaxPayloadBytes: cfg.EdgeOutboxMaxPayloadBytes,
		MaxErrorBytes: cfg.EdgeOutboxMaxErrorBytes,
	})
	if err != nil {
		return nil, runtimeStageError{stage: "configure edge command publisher", err: err}
	}
	nodeMonitoringPublisher, err := nodemonitoringoutbox.NewPublisher(
		pool, connection, nodemonitoringoutbox.DefaultConfig(),
	)
	if err != nil {
		return nil, runtimeStageError{stage: "configure node monitoring command publisher", err: err}
	}
	status, err := edgestatus.NewRuntime(pool, connection, edgestatus.NATSConsumerConfig{
		Stream: cfg.EdgeStatusStream, SubjectPrefix: cfg.EdgeStatusSubjectPrefix,
		Durable: cfg.EdgeStatusDurable, AckWait: cfg.EdgeStatusAckWait,
		FetchTimeout: cfg.EdgeStatusFetchTimeout, OperationTimeout: cfg.EdgeStatusOperationTimeout,
		NakDelay: cfg.EdgeStatusNakDelay, MaxAckPending: cfg.EdgeStatusMaxAckPending,
		MaxWaiting: cfg.EdgeStatusMaxWaiting,
	}, edgestatus.ValidatorConfig{
		SubjectPrefix: cfg.EdgeStatusSubjectPrefix, MaxStatusBytes: cfg.EdgeStatusMaxBytes,
		MaxChecks: cfg.EdgeStatusMaxChecks, MaxMetadataBytes: cfg.EdgeStatusMaxMetadataBytes,
		MaxFutureSkew: cfg.EdgeStatusMaxFutureSkew,
	}, logger)
	if err != nil {
		return nil, runtimeStageError{stage: "bind edge deployment status consumer", err: err}
	}
	runtime := &edgeDeploymentRuntime{
		connection: connection, status: status,
		workers: []runtimeWorker{publisher, nodeMonitoringPublisher, status, natsConnectionMonitor{closed: closed}},
		closed:  closed, shutdownTimeout: cfg.ShutdownPeriod,
	}
	runtime.ready.Store(true)
	failed = false
	return runtime, nil
}

func (r *edgeDeploymentRuntime) Run(ctx context.Context) error {
	if r == nil || ctx == nil {
		return errors.New("edge deployment runtime context is required")
	}
	// runWithDBBackoff calls Run again after a transient database error; each
	// attempt is ready again until its workers stop (Close keeps it unready via
	// the drained connection check in Ready).
	r.ready.Store(true)
	defer r.ready.Store(false)
	return runRequiredWorkers(ctx, r.workers)
}

func (r *edgeDeploymentRuntime) Ready() error {
	if r == nil || !r.ready.Load() || r.connection == nil || !r.connection.IsConnected() {
		return errors.New("edge deployment runtime is unavailable")
	}
	return nil
}

func (r *edgeDeploymentRuntime) Close() error {
	if r == nil {
		return nil
	}
	r.closeOnce.Do(func() {
		r.ready.Store(false)
		if r.status != nil {
			r.closeErr = r.status.Close()
		}
		if r.connection == nil || r.connection.IsClosed() {
			return
		}
		if err := r.connection.Drain(); err != nil && r.closeErr == nil {
			r.closeErr = err
		}
		timer := time.NewTimer(r.shutdownTimeout)
		defer timer.Stop()
		select {
		case <-r.closed:
		case <-timer.C:
			if r.closeErr == nil {
				r.closeErr = errors.New("edge deployment NATS drain timed out")
			}
			r.connection.Close()
		}
	})
	return r.closeErr
}

func (m natsConnectionMonitor) Run(ctx context.Context) error {
	select {
	case <-ctx.Done():
		return ctx.Err()
	case <-m.closed:
		return errors.New("edge deployment NATS connection closed")
	}
}

// isTransientDBError reports whether err indicates a transient PostgreSQL
// connection interruption (e.g., DB restart via unattended-upgrade) or row
// contention that a later attempt resolves.
func isTransientDBError(err error) bool {
	if err == nil {
		return false
	}
	// While PostgreSQL restarts, pooled connections end with 57P01 and new
	// dials are refused until it accepts connections again. 55P03 (NOWAIT lock
	// not available), 40001 (serialization failure) and 40P01 (deadlock) are
	// concurrent writers, e.g. a node heartbeat on the same row.
	var pgErr *pgconn.PgError
	if errors.As(err, &pgErr) && (strings.HasPrefix(pgErr.Code, "57P") || strings.HasPrefix(pgErr.Code, "08") ||
		pgErr.Code == "55P03" || pgErr.Code == "40001" || pgErr.Code == "40P01") {
		return true
	}
	if errors.Is(err, syscall.ECONNREFUSED) || errors.Is(err, syscall.ECONNRESET) {
		return true
	}
	msg := err.Error()
	return strings.Contains(msg, "FATAL") ||
		strings.Contains(msg, "terminating connection") ||
		strings.Contains(msg, "conn closed") ||
		errors.Is(err, io.ErrUnexpectedEOF)
}

// runWithDBBackoff wraps a context-aware Run function and retries on transient
// DB errors with exponential backoff. It returns a non-nil error only when ctx
// is cancelled, the error is not a transient DB error, or continuous DB failures
// have persisted for longer than fatalAfter.
func runWithDBBackoff(ctx context.Context, logger *slog.Logger, name string, fatalAfter time.Duration, run func(context.Context) error) error {
	return runWithDBBackoffClock(ctx, logger, name, fatalAfter, run, time.Now, sleepDBBackoff)
}

func sleepDBBackoff(ctx context.Context, d time.Duration) error {
	timer := time.NewTimer(d)
	defer timer.Stop()
	select {
	case <-ctx.Done():
		return ctx.Err()
	case <-timer.C:
		return nil
	}
}

func runWithDBBackoffClock(ctx context.Context, logger *slog.Logger, name string, fatalAfter time.Duration,
	run func(context.Context) error, now func() time.Time, sleep func(context.Context, time.Duration) error) error {
	const initialBackoff = 2 * time.Second
	const maxBackoff = 30 * time.Second
	backoff := initialBackoff
	var start time.Time
	for {
		// B05: the attempt's own successful queries are the recovery signal
		// (database.Open traces them); how long it ran proves nothing, a
		// connect or lock wait can outlast the backoff cap.
		attemptCtx, succeeded := database.WithQuerySuccess(ctx)
		err := run(attemptCtx)
		if err == nil || errors.Is(err, context.Canceled) || ctx.Err() != nil {
			return err
		}
		if !isTransientDBError(err) {
			return err
		}
		failedAt := now()
		if succeeded.Load() {
			// 73 (10-24): PG restarted 11 times over 6 minutes, each down ~2s;
			// without this reset the first failure's start made the later
			// ones look like 5 minutes of continuous downtime.
			if !start.IsZero() {
				logger.Info("worker reached the database again after transient failures",
					"worker", name, "failing_for", failedAt.Sub(start))
			}
			start = time.Time{}
			backoff = initialBackoff
		}
		if start.IsZero() {
			start = failedAt
		}
		if failedAt.Sub(start) > fatalAfter {
			return fmt.Errorf("persistent DB connection failure after %s: %w", fatalAfter, err)
		}
		logger.Warn("transient DB error in worker, retrying",
			"worker", name, "error", err, "retry_in", backoff)
		if err := sleep(ctx, backoff); err != nil {
			return err
		}
		if backoff < maxBackoff {
			backoff *= 2
			if backoff > maxBackoff {
				backoff = maxBackoff
			}
		}
	}
}

func runRequiredWorkers(ctx context.Context, workers []runtimeWorker) error {
	if ctx == nil || len(workers) == 0 {
		return errors.New("required background workers are missing")
	}
	for _, worker := range workers {
		if worker == nil {
			return errors.New("required background worker is missing")
		}
	}
	runCtx, cancel := context.WithCancel(ctx)
	defer cancel()
	results := make(chan error, len(workers))
	for _, worker := range workers {
		go func(worker runtimeWorker) {
			results <- worker.Run(runCtx)
		}(worker)
	}
	first := <-results
	cancel()
	for remaining := len(workers) - 1; remaining > 0; remaining-- {
		<-results
	}
	if ctx.Err() != nil {
		return ctx.Err()
	}
	if first == nil || errors.Is(first, context.Canceled) {
		return errors.New("required background worker stopped unexpectedly")
	}
	return first
}

// readinessFailureLogInterval bounds how often an unchanged readiness failure
// is logged; the upgrade runner polls /health/ready about once a second.
const readinessFailureLogInterval = time.Minute

// readinessReporter logs which probe keeps /health/ready at 503: on a change of
// failing probe, then at most once per interval, and once on recovery.
type readinessReporter struct {
	mu       sync.Mutex
	logger   *slog.Logger
	now      func() time.Time
	interval time.Duration
	failing  string
	loggedAt time.Time
}

func (reporter *readinessReporter) failed(index int, probe readinessProbe, err error) {
	name := fmt.Sprintf("%d:%T", index, probe)
	reporter.mu.Lock()
	defer reporter.mu.Unlock()
	now := reporter.now()
	if name == reporter.failing && now.Sub(reporter.loggedAt) < reporter.interval {
		return
	}
	reporter.failing, reporter.loggedAt = name, now
	if err == nil {
		err = errors.New("readiness probe is not configured")
	}
	reporter.logger.Warn("readiness probe failed", "probe", fmt.Sprintf("%T", probe), "index", index, "error", err)
}

func (reporter *readinessReporter) recovered() {
	reporter.mu.Lock()
	defer reporter.mu.Unlock()
	if reporter.failing == "" {
		return
	}
	reporter.logger.Info("readiness probes recovered", "previous_probe", reporter.failing)
	reporter.failing = ""
}

func requireReadiness(next http.Handler, probes ...readinessProbe) http.Handler {
	return requireReadinessWithReporter(next, &readinessReporter{logger: slog.Default(), now: time.Now,
		interval: readinessFailureLogInterval}, probes...)
}

func requireReadinessWithReporter(next http.Handler, reporter *readinessReporter, probes ...readinessProbe) http.Handler {
	return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if r.Method == http.MethodGet && r.URL.Path == "/health/ready" {
			for index, probe := range probes {
				var err error
				if probe != nil {
					err = probe.Ready()
				}
				if probe == nil || err != nil {
					reporter.failed(index, probe, err)
					requestID := strings.TrimSpace(r.Header.Get("X-Request-ID"))
					if !validRuntimeRequestID(requestID) {
						requestID = uuid.NewString()
					}
					w.Header().Set("Content-Type", "application/json")
					w.Header().Set("X-Request-ID", requestID)
					w.WriteHeader(http.StatusServiceUnavailable)
					_, _ = fmt.Fprintf(w, "{\"error\":{\"code\":\"service_unavailable\",\"message\":\"a required dependency is unavailable\",\"request_id\":%q}}\n", requestID)
					return
				}
			}
			reporter.recovered()
		}
		next.ServeHTTP(w, r)
	})
}

func validRuntimeRequestID(value string) bool {
	if value == "" || len(value) > 128 {
		return false
	}
	for _, character := range value {
		if character >= 'a' && character <= 'z' || character >= 'A' && character <= 'Z' ||
			character >= '0' && character <= '9' || character == '.' || character == '_' || character == '-' {
			continue
		}
		return false
	}
	return true
}

func verifyEdgeJetStream(ctx context.Context, connection *nats.Conn, cfg config.Config) error {
	if ctx == nil || connection == nil || connection.IsClosed() {
		return errors.New("active NATS connection is required")
	}
	jetstream, err := connection.JetStream(nats.MaxWait(cfg.EdgeDeploymentConnectTimeout))
	if err != nil {
		return err
	}
	if _, err := jetstream.AccountInfo(nats.Context(ctx)); err != nil {
		return err
	}
	for _, required := range []struct {
		stream   string
		prefix   string
		maxBytes int
	}{
		{stream: cfg.EdgeCommandStream, prefix: cfg.EdgeCommandSubjectPrefix, maxBytes: cfg.EdgeOutboxMaxPayloadBytes},
		{stream: cfg.EdgeStatusStream, prefix: cfg.EdgeStatusSubjectPrefix, maxBytes: cfg.EdgeStatusMaxBytes},
	} {
		info, err := jetstream.StreamInfo(required.stream, nats.Context(ctx))
		if err != nil {
			return errors.New("required edge deployment stream is unavailable")
		}
		if err := validateEdgeStreamInfo(info, required.prefix, required.maxBytes); err != nil {
			return err
		}
	}
	return nil
}

func validateEdgeStreamInfo(info *nats.StreamInfo, subjectPrefix string, maxPayloadBytes int) error {
	if info == nil || info.Config.Storage != nats.FileStorage || info.Config.Replicas < 1 ||
		info.Config.Duplicates <= 0 || maxPayloadBytes <= 0 ||
		(info.Config.MaxMsgSize > 0 && int64(info.Config.MaxMsgSize) < int64(maxPayloadBytes)) {
		return errors.New("required edge deployment stream is not durably configured")
	}
	for _, pattern := range info.Config.Subjects {
		if natsSubjectMatches(pattern, subjectPrefix+".00000000-0000-4000-8000-000000000001") &&
			natsSubjectMatches(pattern, subjectPrefix+".00000000-0000-4000-8000-000000000002") {
			return nil
		}
	}
	return errors.New("required edge deployment stream does not cover its subject")
}

func natsSubjectMatches(pattern, subject string) bool {
	patternTokens := strings.Split(pattern, ".")
	subjectTokens := strings.Split(subject, ".")
	for index, patternToken := range patternTokens {
		if patternToken == "" || patternToken == ">" {
			return patternToken == ">" && index == len(patternTokens)-1 && index < len(subjectTokens)
		}
		if index >= len(subjectTokens) || subjectTokens[index] == "" ||
			(patternToken != "*" && patternToken != subjectTokens[index]) {
			return false
		}
	}
	return len(patternTokens) == len(subjectTokens)
}

func newNodePresenceRuntime(ctx context.Context, cfg config.Config, pool *pgxpool.Pool) (*nodepresence.Runtime, error) {
	if cfg.NodePresenceNATSURL == "" {
		return nil, nil
	}
	return nodepresence.OpenRuntime(ctx, pool, nodepresence.RuntimeConfig{
		NATSURL: cfg.NodePresenceNATSURL, RedisURL: cfg.NodePresenceRedisURL,
		Stream: cfg.NodePresenceStream, SubjectPrefix: cfg.NodePresenceSubjectPrefix,
		Durable: cfg.NodePresenceDurable, RedisKeyPrefix: cfg.NodePresenceRedisKeyPrefix,
		AckWait: cfg.NodePresenceAckWait, FetchTimeout: cfg.NodePresenceFetchTimeout,
		OperationTimeout: cfg.NodePresenceOperationTimeout, NakDelay: cfg.NodePresenceNakDelay,
		LeaseTTL: cfg.NodePresenceLeaseTTL, OfflineAfter: cfg.NodePresenceOfflineAfter,
		OfflineInterval: cfg.NodePresenceOfflinePeriod, ConnectionTimeout: cfg.NodePresenceConnectTimeout,
		MaxFutureSkew: cfg.NodePresenceMaxFutureSkew, MaxHeartbeatBytes: cfg.NodePresenceMaxBytes,
		MaxActiveDeployments: cfg.NodePresenceMaxDeployments,
		MaxAckPending:        cfg.NodePresenceMaxAckPending, MaxWaiting: cfg.NodePresenceMaxWaiting,
		OfflineBatchSize: cfg.NodePresenceOfflineBatch,
	}, slog.Default())
}

func newEntitlementSyncer(
	cfg config.Config,
	pool *pgxpool.Pool,
	trust *entitlementguard.TrustStore,
	keysets *entitlementsync.KeysetManager,
) (*entitlementsync.Syncer, error) {
	if trust == nil {
		return nil, errors.New("entitlement sync requires deployment trust anchors")
	}
	installationID, err := uuid.Parse(cfg.ControlInstallationID)
	if err != nil {
		return nil, errors.New("CONTROL_INSTALLATION_ID must be a UUID")
	}
	privateKey, err := entitlementsync.LoadPrivateKey(cfg.ControlInstallationKeyFile)
	if err != nil {
		return nil, err
	}
	client, err := entitlementsync.NewClient(cfg.LicenseServiceURL, nil)
	if err != nil {
		return nil, err
	}
	// PA-14: the installation encryption key, when configured, is registered
	// with the activation (only its public half leaves this host).
	var encryptionPublicKey []byte
	if cfg.ControlInstallationEncKeyFile != "" {
		encryptionKey, err := entitlementsync.LoadEncryptionKey(cfg.ControlInstallationEncKeyFile)
		if err != nil {
			return nil, err
		}
		encryptionPublicKey, err = rulepack.X25519PublicKey(encryptionKey)
		clear(encryptionKey)
		if err != nil {
			return nil, err
		}
	}
	var activation entitlementsync.CredentialSource
	if cfg.ActivationCredentialFile != "" {
		activation = func(context.Context) (string, error) {
			return entitlementsync.ReadActivationCredential(cfg.ActivationCredentialFile, os.Stdin)
		}
	}
	return entitlementsync.New(entitlementsync.Config{
		Client:              client,
		Store:               entitlementsync.NewPostgresStore(pool, trust),
		Trust:               trust,
		Keysets:             keysets,
		InstallationID:      installationID,
		InstallationName:    cfg.ControlInstallationName,
		PrivateKey:          privateKey,
		EncryptionPublicKey: encryptionPublicKey,
		Activation:          activation,
		Logger:              slog.Default(),
		BackoffMin:          cfg.EntitlementSyncBackoffMin,
		BackoffMax:          cfg.EntitlementSyncBackoffMax,
	})
}

func newSigningKeysetManager(ctx context.Context, cfg config.Config, pool *pgxpool.Pool,
	trust *entitlementguard.TrustStore) (*entitlementsync.KeysetManager, error) {
	if trust == nil {
		return nil, errors.New("signing keyset synchronization requires deployment trust anchors")
	}
	client, err := entitlementsync.NewClient(cfg.LicenseServiceURL, nil)
	if err != nil {
		return nil, err
	}
	return entitlementsync.NewKeysetManager(ctx, client,
		entitlementsync.NewPostgresKeysetStore(pool), trust, time.Now)
}

func newPlatformPolicySyncer(ctx context.Context, cfg config.Config, pool *pgxpool.Pool,
	trust *entitlementguard.TrustStore, keysets *entitlementsync.KeysetManager,
	state *platformpolicy.State) (*platformpolicy.Syncer, error) {
	if trust == nil || keysets == nil || state == nil {
		return nil, errors.New("platform policy sync requires trust, keyset manager, and state")
	}
	installationID, err := uuid.Parse(cfg.ControlInstallationID)
	if err != nil || installationID == uuid.Nil || installationID.String() != cfg.ControlInstallationID {
		return nil, errors.New("CONTROL_INSTALLATION_ID must be a canonical UUID")
	}
	privateKey, err := entitlementsync.LoadPrivateKey(cfg.ControlInstallationKeyFile)
	if err != nil {
		return nil, err
	}
	client, err := platformpolicy.NewClient(cfg.LicenseServiceURL, nil)
	if err != nil {
		return nil, err
	}
	store, err := platformpolicy.NewPostgresStore(pool, installationID)
	if err != nil {
		return nil, err
	}
	return platformpolicy.NewSyncer(ctx, platformpolicy.SyncerConfig{
		Client: client, Store: store, Trust: trust, SignerRevocation: trust, Keysets: keysets, State: state,
		InstallationID: installationID, PrivateKey: privateKey, ControlVersion: cfg.ControlVersion,
		ProtocolVersion: cfg.PlatformPolicyProtocol, SyncInterval: cfg.PlatformPolicySyncInterval,
		BackoffMin: cfg.EntitlementSyncBackoffMin, BackoffMax: cfg.EntitlementSyncBackoffMax,
		Logger: slog.Default(),
	})
}

// newArtifactSyncer consumes the license service's signed artifact catalog
// (system rules, CRS rule text, IP intelligence base library) with the same
// installation identity and trust chain as the platform policy channel. The
// local lease is rechecked for every paid entry; a CRS rule package change
// republishes the scopes whose release loads a changed file.
//
// A round that changed the usable local artifacts wakes the node artifact
// set distributor (nil: none configured), which reads the same store.
func newArtifactSyncer(cfg config.Config, pool *pgxpool.Pool, trust *entitlementguard.TrustStore,
	keysets *entitlementsync.KeysetManager, nodeArtifactSets *artifactsetdist.Distributor) (*artifactsync.Syncer, error) {
	if trust == nil || keysets == nil {
		return nil, errors.New("artifact sync requires trust and keyset manager")
	}
	installationID, err := uuid.Parse(cfg.ControlInstallationID)
	if err != nil || installationID == uuid.Nil || installationID.String() != cfg.ControlInstallationID {
		return nil, errors.New("CONTROL_INSTALLATION_ID must be a canonical UUID")
	}
	privateKey, err := entitlementsync.LoadPrivateKey(cfg.ControlInstallationKeyFile)
	if err != nil {
		return nil, err
	}
	defer clear(privateKey)
	// PA-14: the installation encryption key opens the wrapped content keys
	// of encrypted rule packs (absent: such packs are rejected, not stored).
	var encryptionKey []byte
	if cfg.ControlInstallationEncKeyFile != "" {
		if encryptionKey, err = entitlementsync.LoadEncryptionKey(cfg.ControlInstallationEncKeyFile); err != nil {
			return nil, err
		}
		defer clear(encryptionKey)
	}
	client, err := artifactsync.NewClient(cfg.LicenseServiceURL, nil)
	if err != nil {
		return nil, err
	}
	store := artifactsync.NewStore(pool, time.Now).WithFeatures(entitlementguard.NewGuard(pool, time.Now, trust)).
		WithCRSRepublisher(edgeautopublish.RuleCatalogPublisher{})
	return artifactsync.NewSyncer(artifactsync.SyncerConfig{
		Client: client, Store: store, Trust: trust, Keysets: keysets,
		InstallationID: installationID, PrivateKey: privateKey, EncryptionKey: encryptionKey, ControlVersion: cfg.ControlVersion,
		Interval: cfg.PlatformPolicySyncInterval, Logger: slog.Default(),
		OnChanged: func(context.Context) {
			if nodeArtifactSets != nil {
				nodeArtifactSets.Wake()
			}
			wakePluginProviderContracts()
		},
	})
}

func loadEntitlementTrust(path string) (*entitlementguard.TrustStore, error) {
	if strings.TrimSpace(path) == "" {
		return nil, nil
	}
	encoded, err := os.ReadFile(path)
	if err != nil {
		return nil, fmt.Errorf("read entitlement trusted keys: %w", err)
	}
	trust, err := entitlementguard.DecodeTrustedKeys(encoded)
	if err != nil {
		return nil, err
	}
	return trust, nil
}

func runMigrate(args []string) error {
	if len(args) != 1 || (args[0] != "up" && args[0] != "down") {
		return errors.New("usage: control-api migrate up|down")
	}
	databaseURL := os.Getenv("DATABASE_URL")
	if databaseURL == "" {
		return errors.New("DATABASE_URL is required")
	}
	ctx, cancel := context.WithTimeout(context.Background(), 2*time.Minute)
	defer cancel()
	pool, err := database.Open(ctx, databaseURL)
	if err != nil {
		return err
	}
	defer pool.Close()
	if err := database.Migrate(ctx, pool, args[0]); err != nil {
		return err
	}
	slog.Info("database migration complete", "direction", args[0])
	return nil
}

func runBootstrapUser(args []string) error {
	flags := flag.NewFlagSet("bootstrap-user", flag.ContinueOnError)
	username := flags.String("username", "", "lowercase username")
	displayName := flags.String("display-name", "Platform Administrator", "display name")
	email := flags.String("email", "", "administrator recovery email")
	acceptExisting := flags.Bool("existing-ok", false, "accept an already-provisioned matching platform owner")
	if err := flags.Parse(args); err != nil {
		return err
	}
	*username = strings.ToLower(strings.TrimSpace(*username))
	*displayName = strings.TrimSpace(*displayName)
	*email = strings.ToLower(strings.TrimSpace(*email))
	if len(*username) < 3 || len(*username) > 128 || *displayName == "" || *email == "" {
		return errors.New("username, display-name, and email are required")
	}
	address, err := mail.ParseAddress(*email)
	if err != nil || address.Address != *email || len(*email) > 254 {
		return errors.New("administrator email is invalid")
	}
	password := os.Getenv("BOOTSTRAP_PASSWORD")
	if password == "" {
		return errors.New("BOOTSTRAP_PASSWORD must be provided through the environment")
	}
	defer func() { password = "" }()
	passwordHash, err := identity.HashPassword(password)
	if err != nil {
		return err
	}
	databaseURL := os.Getenv("DATABASE_URL")
	if databaseURL == "" {
		return errors.New("DATABASE_URL is required")
	}
	ctx, cancel := context.WithTimeout(context.Background(), 30*time.Second)
	defer cancel()
	pool, err := database.Open(ctx, databaseURL)
	if err != nil {
		return err
	}
	defer pool.Close()
	requestID := uuid.NewString()
	result, err := identity.NewStore(pool).BootstrapPlatformUserWithEmail(
		ctx,
		*username,
		*displayName,
		*email,
		passwordHash,
		requestID,
	)
	if err != nil {
		if !*acceptExisting || !errors.Is(err, identity.ErrConflict) {
			return err
		}
		result, err = existingBootstrapPlatformUser(ctx, pool, *username, *displayName, *email, password)
		if err != nil {
			return err
		}
		fmt.Printf("platform user already exists: user_id=%s scope_id=%s role_id=%s\n", result.UserID, result.ScopeID, result.RoleID)
		return nil
	}
	fmt.Printf("platform user created: user_id=%s scope_id=%s role_id=%s\n", result.UserID, result.ScopeID, result.RoleID)
	return nil
}

func runBootstrapNodeCA(args []string) error {
	flags := flag.NewFlagSet("bootstrap-node-ca", flag.ContinueOnError)
	username := flags.String("username", "", "platform administrator username")
	certificateFile := flags.String("certificate-file", "", "PEM-encoded node CA certificate")
	keyID := flags.String("key-id", "node-ca-bootstrap-v1", "node CA key identifier")
	if err := flags.Parse(args); err != nil {
		return err
	}
	*username = strings.ToLower(strings.TrimSpace(*username))
	*certificateFile = strings.TrimSpace(*certificateFile)
	*keyID = strings.TrimSpace(*keyID)
	if len(*username) < 3 || len(*username) > 128 || *certificateFile == "" || *keyID == "" {
		return errors.New("username, certificate-file, and key-id are required")
	}
	certificatePEM, err := os.ReadFile(*certificateFile)
	if err != nil {
		return fmt.Errorf("read node CA certificate: %w", err)
	}
	certificate, err := parseBootstrapNodeCACertificate(certificatePEM)
	if err != nil {
		return err
	}
	certificateDigest := sha256.Sum256(certificate.Raw)
	databaseURL := os.Getenv("DATABASE_URL")
	if databaseURL == "" {
		return errors.New("DATABASE_URL is required")
	}
	ctx, cancel := context.WithTimeout(context.Background(), 30*time.Second)
	defer cancel()
	pool, err := database.Open(ctx, databaseURL)
	if err != nil {
		return err
	}
	defer pool.Close()

	var actor nodecertlifecycle.Actor
	err = pool.QueryRow(ctx, `
		SELECT u.id, scope.id
		FROM users u
		JOIN memberships membership ON membership.user_id=u.id AND membership.status='active'
		JOIN access_scopes scope ON scope.id=membership.scope_id AND scope.kind='platform'
		JOIN role_assignments assignment ON assignment.scope_id=scope.id AND assignment.user_id=u.id
		JOIN roles role ON role.id=assignment.role_id AND role.system_role
		JOIN role_permissions grant_row ON grant_row.role_id=role.id AND grant_row.permission_name='node_ca.manage'
		WHERE u.username=$1 AND u.status='active'
		LIMIT 1`, *username).Scan(&actor.UserID, &actor.ScopeID)
	if errors.Is(err, pgx.ErrNoRows) {
		return fmt.Errorf("platform administrator %q with node_ca.manage was not found", *username)
	}
	if err != nil {
		return fmt.Errorf("find platform administrator: %w", err)
	}
	actor.ScopeKind = "platform"

	var highwater int64
	var activeDigest []byte
	err = pool.QueryRow(ctx, `
		SELECT COALESCE((
			SELECT max(epoch) FROM node_ca_key_epochs
			WHERE installation_id=entitlement.installation_id
		),0), COALESCE((
			SELECT ca_certificate_sha256 FROM node_ca_key_epochs
			WHERE installation_id=entitlement.installation_id AND status='active'
		), '\x'::bytea)
		FROM control_installation_entitlement entitlement
		WHERE singleton`).Scan(&highwater, &activeDigest)
	if errors.Is(err, pgx.ErrNoRows) {
		return errors.New("control installation entitlement is not initialized")
	}
	if err != nil {
		return fmt.Errorf("read node CA epoch state: %w", err)
	}
	if len(activeDigest) == sha256.Size {
		if bytes.Equal(activeDigest, certificateDigest[:]) {
			fmt.Println("node CA epoch already active")
			return nil
		}
		return errors.New("an active node CA epoch already uses a different certificate")
	}
	if len(activeDigest) != 0 {
		return errors.New("active node CA epoch has an invalid certificate digest")
	}
	store, err := nodecertlifecycle.NewStore(pool, nodecertlifecycle.Config{
		Clock: time.Now, OverlapWindow: 10 * time.Minute,
		AuthorizationSnapshotTTL: time.Minute, MaxScheduledRevocation: 7 * 24 * time.Hour,
	})
	if err != nil {
		return fmt.Errorf("configure node CA lifecycle: %w", err)
	}
	epoch, err := store.RotateCAEpoch(ctx, actor, nodecertlifecycle.RotateCAEpochRequest{
		RequestID: uuid.New(), ExpectedCurrentEpoch: highwater, KeyID: *keyID,
		CACertificatePEM: certificatePEM, RequestTraceID: "bootstrap-node-ca",
	})
	if err != nil {
		return fmt.Errorf("bootstrap node CA epoch: %w", err)
	}
	fmt.Printf("node CA epoch active: epoch=%d id=%s\n", epoch.Epoch, epoch.ID)
	return nil
}

func parseBootstrapNodeCACertificate(value []byte) (*x509.Certificate, error) {
	block, rest := pem.Decode(value)
	if block == nil || block.Type != "CERTIFICATE" || len(bytes.TrimSpace(rest)) != 0 {
		return nil, errors.New("node CA certificate is not a single PEM certificate")
	}
	certificate, err := x509.ParseCertificate(block.Bytes)
	if err != nil {
		return nil, fmt.Errorf("parse node CA certificate: %w", err)
	}
	if !certificate.IsCA || certificate.KeyUsage&x509.KeyUsageCertSign == 0 {
		return nil, errors.New("node CA certificate must be a certificate authority with cert-sign usage")
	}
	return certificate, nil
}

func existingBootstrapPlatformUser(ctx context.Context, pool *pgxpool.Pool, username, displayName, email, password string) (identity.BootstrapResult, error) {
	var result identity.BootstrapResult
	var passwordHash string
	err := pool.QueryRow(ctx, `
		SELECT u.id, scope.id, role.id, u.password_hash
		FROM users u
		JOIN memberships membership ON membership.user_id = u.id AND membership.status = 'active'
		JOIN access_scopes scope ON scope.id = membership.scope_id AND scope.kind = 'platform'
		JOIN role_assignments assignment ON assignment.scope_id = scope.id AND assignment.user_id = u.id
		JOIN roles role ON role.id = assignment.role_id AND role.name = 'platform_owner' AND role.system_role = true
		WHERE u.username = $1 AND u.display_name = $2 AND u.email = $3 AND u.status = 'active'
	LIMIT 1`, username, displayName, email).Scan(&result.UserID, &result.ScopeID, &result.RoleID, &passwordHash)
	// The existing-owner path is idempotent only when the supplied password
	// still authenticates the matching platform owner.  Do not report a
	// successful install while silently accepting a password that cannot log in.
	if err == nil {
		if !identity.VerifyPassword(passwordHash, password) {
			return identity.BootstrapResult{}, identity.ErrConflict
		}
	}
	if errors.Is(err, pgx.ErrNoRows) {
		return identity.BootstrapResult{}, identity.ErrConflict
	}
	if err != nil {
		return identity.BootstrapResult{}, fmt.Errorf("verify existing platform user: %w", err)
	}
	return result, nil
}

func usageError() error {
	return errors.New("usage: control-api serve | migrate up|down | bootstrap-user --username USER --email EMAIL [--display-name NAME] [--existing-ok] | admin-access-allowlist disable|status | recover-platform-admin --user-id UUID --scope-id UUID --request-id UUID (--status | --expected-username OLD --expected-revision N --new-username NEW [--password-stdin]) | bootstrap-node-ca --username USER --certificate-file FILE [--key-id ID] | bootstrap-system-configuration --username USER | install-community --installation-id UUID | community-register --account NAME --password-stdin | community-refresh | install-entitlement --bundle FILE --trusted-keys FILE [--trusted-keyset FILE] [--revocation FILE] | fetch-entitlement-revocation --license-service URL --installation-id UUID --installation-key FILE | report-installation-endpoints --license-service URL --installation-key FILE --request-file FILE [--refresh-request] | native-backup COMMAND (see control-api native-backup) | signer-revocation import-checkpoint|import-edge-trust --in FILE | plugin-webhook-attestation-key status|rotate | verify-native-upgrade --installation-id UUID --version VERSION --source-commit COMMIT --source-tree TREE --artifact-sha256 SHA --runner-sha256 SHA")
}

// approvalStepUpConsumer is the approval center's step-up consumer; a typed
// nil from a disabled MFA runtime becomes an untyped nil (approvers with MFA
// then cannot approve rather than skip the verification).
func approvalStepUpConsumer(runtime *mfahttp.Runtime) approvalcenter.StepUpConsumer {
	if consumer := runtime.StepUpConsumer(); consumer != nil {
		return consumer
	}
	return nil
}
