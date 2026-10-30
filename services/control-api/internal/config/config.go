package config

import (
	"bytes"
	"crypto/ed25519"
	"crypto/x509"
	"encoding/base64"
	"encoding/json"
	"encoding/pem"
	"errors"
	"fmt"
	"io"
	"net"
	"net/mail"
	"net/netip"
	"net/url"
	"os"
	"regexp"
	"strconv"
	"strings"
	"time"
	"unicode"
	"unicode/utf8"

	"github.com/cdnca/cdnca/services/control-api/internal/analytics"
	"github.com/cdnca/cdnca/services/control-api/internal/apikeycredential"
	"github.com/cdnca/cdnca/services/control-api/internal/pluginwebhookruntime"
	"github.com/google/uuid"
	"golang.org/x/mod/semver"
)

type Config struct {
	HTTPAddr                           string
	DatabaseURL                        string
	AccessSecret                       string
	APIKeyPepper                       []byte
	APIKeyPepperKeyring                apikeycredential.PepperKeyring
	APIKeyTrustedProxyCIDRs            []string
	APIKeyMaxProxyHops                 int
	AccessTTL                          time.Duration
	RefreshTTL                         time.Duration
	CookieSecure                       bool
	CookieDomain                       string
	EntitlementTrustedKeysFile         string
	LicenseServiceURL                  string
	ControlInstallationID              string
	ControlInstallationName            string
	ControlInstallationKeyFile         string
	ControlInstallationEncKeyFile      string
	ActivationCredentialFile           string
	EntitlementSyncBackoffMin          time.Duration
	EntitlementSyncBackoffMax          time.Duration
	ControlVersion                     string
	PlatformPolicyProtocol             int
	PlatformPolicySyncInterval         time.Duration
	DNSCredentialKeyID                 string
	DNSCredentialKey                   []byte
	DNSCredentialPreviousKeyID         string
	DNSCredentialPreviousKey           []byte
	ACMERuntimeEnabled                 bool
	ACMEDirectoryURL                   string
	ACMEBackupDirectoryURL             string
	ACMEContacts                       []string
	ACMEWrappingKeyID                  string
	ACMEWrappingKey                    []byte
	ACMEPollInterval                   time.Duration
	ACMELeaseDuration                  time.Duration
	ACMESettleTimeout                  time.Duration
	ACMERetryBase                      time.Duration
	ACMERetryMaximum                   time.Duration
	ACMEMaxAttempts                    int
	ACMEErrorBackoffMin                time.Duration
	ACMEErrorBackoffMax                time.Duration
	ACMEHTTP01EncryptionKeyID          string
	ACMEHTTP01EncryptionKey            []byte
	ACMEHTTP01SigningKeyID             string
	ACMEHTTP01SigningKeyFile           string
	ACMEHTTP01ChallengeLifetime        time.Duration
	ACMEHTTP01HealthPoll               time.Duration
	ACMEHTTP01MaxTargets               int
	AnalyticsQueryEnabled              bool
	ClickHouseURL                      string
	ClickHouseDatabase                 string
	ClickHouseUsername                 string
	ClickHousePassword                 string
	AnalyticsConnectTimeout            time.Duration
	AnalyticsQueryTimeout              time.Duration
	AnalyticsHandlerTimeout            time.Duration
	AnalyticsQueryMaxResponse          int64
	AnalyticsHandlerMaxResponse        int
	AnalyticsIngest                    AnalyticsIngestConfig
	JobQueryEnabled                    bool
	JobQueryCursorActiveKeyID          string
	JobQueryCursorKeys                 map[string][]byte
	JobQueryTimeout                    time.Duration
	JobQueryMaxResponse                int
	SiteStatusRecoveryEnabled          bool
	SiteStatusRecoveryTenantID         uuid.UUID
	SiteStatusRecoveryWorkerID         string
	SiteStatusRecoveryBatchSize        int
	SiteStatusRecoveryLeaseDuration    time.Duration
	SiteStatusRecoveryPollInterval     time.Duration
	SiteStatusRecoveryOperationTimeout time.Duration
	SiteStatusRecoveryReportTimeout    time.Duration
	ControlInternalGRPCAddr            string
	ControlInternalServerCert          string
	ControlInternalServerKey           string
	ControlInternalGatewayCA           string
	ControlInternalGatewayURI          string
	NodeCACertificateChainFile         string
	NodeCAPrivateKeyFile               string
	EdgeDeploymentNATSURL              string
	EdgeDeploymentNATSCredsFile        string
	EdgeDeploymentNATSCAFile           string
	EdgeDeploymentConnectTimeout       time.Duration
	EdgeCommandStream                  string
	EdgeCommandSubjectPrefix           string
	EdgeOutboxBatchSize                int
	EdgeOutboxLeaseTimeout             time.Duration
	EdgeOutboxOperationTimeout         time.Duration
	EdgeOutboxPollInterval             time.Duration
	EdgeOutboxBaseBackoff              time.Duration
	EdgeOutboxMaxBackoff               time.Duration
	EdgeOutboxMaxPayloadBytes          int
	EdgeOutboxMaxErrorBytes            int
	EdgeStatusStream                   string
	EdgeStatusSubjectPrefix            string
	EdgeStatusDurable                  string
	EdgeStatusAckWait                  time.Duration
	EdgeStatusFetchTimeout             time.Duration
	EdgeStatusOperationTimeout         time.Duration
	EdgeStatusNakDelay                 time.Duration
	EdgeStatusMaxAckPending            int
	EdgeStatusMaxWaiting               int
	EdgeStatusMaxBytes                 int
	EdgeStatusMaxChecks                int
	EdgeStatusMaxMetadataBytes         int
	EdgeStatusMaxFutureSkew            time.Duration
	NodePresenceNATSURL                string
	NodePresenceRedisURL               string
	NodePresenceStream                 string
	NodePresenceSubjectPrefix          string
	NodePresenceDurable                string
	NodePresenceRedisKeyPrefix         string
	NodePresenceAckWait                time.Duration
	NodePresenceFetchTimeout           time.Duration
	NodePresenceOperationTimeout       time.Duration
	NodePresenceNakDelay               time.Duration
	NodePresenceLeaseTTL               time.Duration
	NodePresenceOfflineAfter           time.Duration
	NodePresenceOfflinePeriod          time.Duration
	NodePresenceConnectTimeout         time.Duration
	NodePresenceMaxFutureSkew          time.Duration
	NodePresenceMaxBytes               int
	NodePresenceMaxDeployments         int
	NodePresenceMaxAckPending          int
	NodePresenceMaxWaiting             int
	NodePresenceOfflineBatch           int
	PluginWebhook                      PluginWebhookConfig
	ShutdownPeriod                     time.Duration
}

type AnalyticsIngestConfig struct {
	Enabled                bool
	NATSURL                string
	NATSUsername           string
	NATSPassword           string
	ClickHouseURL          string
	ClickHouseDatabase     string
	ClickHouseUsername     string
	ClickHousePassword     string
	IsolationWrappingKeyID string
	IsolationWrappingKey   []byte
	ConnectTimeout         time.Duration
	WriteTimeout           time.Duration
	SupervisorBackoffMin   time.Duration
	SupervisorBackoffMax   time.Duration
	JetStream              analytics.JetStreamConfig
}

type PluginWebhookConfig struct {
	Enabled          bool
	NATSURL          string
	NATSName         string
	NATSCredsFile    string
	NATSCAFile       string
	NATSReconnectMin time.Duration
	NATSReconnectMax time.Duration
	SecretKeyID      string
	SecretKey        []byte
	// AttestationKeyID/AttestationKey sign broker publications (migration 084).
	AttestationKeyID string
	AttestationKey   ed25519.PrivateKey
	// NextAttestationKeyID/NextAttestationKey: optional key staged for
	// rotation (docs/runbooks/plugin-webhook-key.md).
	NextAttestationKeyID string
	NextAttestationKey   ed25519.PrivateKey
	PollInterval         time.Duration
	OperationTimeout     time.Duration
	LeaseDuration        time.Duration
	ClaimTimeout         time.Duration
	ShutdownTimeout      time.Duration
	JetStream            pluginwebhookruntime.JetStreamConfig
}

func Load() (Config, error) {
	ingestJetStream := analytics.DefaultJetStreamConfig()
	pluginWebhookJetStream := pluginwebhookruntime.DefaultJetStreamConfig()
	cfg := Config{
		HTTPAddr:                    envOr("HTTP_ADDR", ":8080"),
		DatabaseURL:                 os.Getenv("DATABASE_URL"),
		AccessSecret:                os.Getenv("ACCESS_TOKEN_SECRET"),
		CookieDomain:                os.Getenv("COOKIE_DOMAIN"),
		EntitlementTrustedKeysFile:  os.Getenv("ENTITLEMENT_TRUSTED_KEYS_FILE"),
		LicenseServiceURL:           strings.TrimSpace(os.Getenv("LICENSE_SERVICE_URL")),
		ControlInstallationID:       strings.TrimSpace(os.Getenv("CONTROL_INSTALLATION_ID")),
		ControlInstallationName:     strings.TrimSpace(os.Getenv("CONTROL_INSTALLATION_NAME")),
		ControlInstallationKeyFile:  strings.TrimSpace(os.Getenv("CONTROL_INSTALLATION_PRIVATE_KEY_FILE")),
		ActivationCredentialFile:    strings.TrimSpace(os.Getenv("CONTROL_ACTIVATION_CREDENTIAL_FILE")),
		EntitlementSyncBackoffMin:   time.Second,
		EntitlementSyncBackoffMax:   5 * time.Minute,
		ControlVersion:              strings.TrimSpace(os.Getenv("CONTROL_VERSION")),
		PlatformPolicyProtocol:      1,
		PlatformPolicySyncInterval:  time.Minute,
		DNSCredentialKeyID:          os.Getenv("DNS_CREDENTIAL_KEY_ID"),
		DNSCredentialPreviousKeyID:  os.Getenv("DNS_CREDENTIAL_PREVIOUS_KEY_ID"),
		ControlInternalGRPCAddr:     envOr("CONTROL_INTERNAL_GRPC_ADDR", "127.0.0.1:9091"),
		ControlInternalServerCert:   strings.TrimSpace(os.Getenv("CONTROL_INTERNAL_SERVER_CERT_FILE")),
		ControlInternalServerKey:    strings.TrimSpace(os.Getenv("CONTROL_INTERNAL_SERVER_PRIVATE_KEY_FILE")),
		ControlInternalGatewayCA:    strings.TrimSpace(os.Getenv("CONTROL_INTERNAL_GATEWAY_CLIENT_CA_FILE")),
		ControlInternalGatewayURI:   strings.TrimSpace(os.Getenv("CONTROL_INTERNAL_GATEWAY_WORKLOAD_URI_SAN")),
		NodeCACertificateChainFile:  strings.TrimSpace(os.Getenv("NODE_CA_CERTIFICATE_CHAIN_FILE")),
		NodeCAPrivateKeyFile:        strings.TrimSpace(os.Getenv("NODE_CA_PRIVATE_KEY_FILE")),
		EdgeDeploymentNATSURL:       strings.TrimSpace(os.Getenv("EDGE_DEPLOYMENT_NATS_URL")),
		EdgeDeploymentNATSCredsFile: os.Getenv("EDGE_DEPLOYMENT_NATS_CREDS_FILE"),
		EdgeDeploymentNATSCAFile:    os.Getenv("EDGE_DEPLOYMENT_NATS_CA_FILE"),
		EdgeCommandStream:           envOr("EDGE_COMMAND_STREAM", "AGENT_COMMANDS"),
		EdgeCommandSubjectPrefix:    envOr("EDGE_COMMAND_SUBJECT_PREFIX", "cdnca.agent.commands"),
		EdgeStatusStream:            envOr("EDGE_STATUS_STREAM", "AGENT_DEPLOYMENT_STATUS"),
		EdgeStatusSubjectPrefix:     envOr("EDGE_STATUS_SUBJECT_PREFIX", "cdnca.agent.deployment-status"),
		EdgeStatusDurable:           envOr("EDGE_STATUS_DURABLE", "control_api_edge_status"),
		NodePresenceNATSURL:         strings.TrimSpace(os.Getenv("NODE_PRESENCE_NATS_URL")),
		NodePresenceRedisURL:        strings.TrimSpace(os.Getenv("NODE_PRESENCE_REDIS_URL")),
		NodePresenceStream:          envOr("NODE_PRESENCE_STREAM", "AGENT_HEARTBEATS"),
		NodePresenceSubjectPrefix:   envOr("NODE_PRESENCE_SUBJECT_PREFIX", "cdnca.agent.heartbeats"),
		NodePresenceDurable:         envOr("NODE_PRESENCE_DURABLE", "control_api_node_presence"),
		NodePresenceRedisKeyPrefix:  envOr("NODE_PRESENCE_REDIS_KEY_PREFIX", "cdnca:node-presence"),
		AnalyticsIngest: AnalyticsIngestConfig{
			JetStream: ingestJetStream,
		},
		PluginWebhook:  PluginWebhookConfig{JetStream: pluginWebhookJetStream},
		ShutdownPeriod: 10 * time.Second,
	}
	// PA-14: owner-only PKCS#8 X25519 key the license service wraps encrypted
	// rule packs to; empty = this control plane does not receive encrypted packs.
	cfg.ControlInstallationEncKeyFile = strings.TrimSpace(os.Getenv("CONTROL_INSTALLATION_ENCRYPTION_KEY_FILE"))
	loaded := false
	defer func() {
		if !loaded {
			clearAnalyticsIngestSecret(&cfg)
			clearPluginWebhookSecret(&cfg)
		}
	}()

	var err error
	if cfg.AccessTTL, err = durationOr("ACCESS_TOKEN_TTL", 10*time.Minute); err != nil {
		return Config{}, err
	}
	if cfg.RefreshTTL, err = durationOr("REFRESH_TOKEN_TTL", 30*24*time.Hour); err != nil {
		return Config{}, err
	}
	if cfg.CookieSecure, err = boolOr("COOKIE_SECURE", true); err != nil {
		return Config{}, err
	}
	if cfg.ACMERuntimeEnabled, err = boolOr("ACME_RUNTIME_ENABLED", false); err != nil {
		return Config{}, err
	}
	if cfg.AnalyticsQueryEnabled, err = boolOr("ANALYTICS_QUERY_ENABLED", false); err != nil {
		return Config{}, err
	}
	if cfg.AnalyticsIngest.Enabled, err = boolOr("ANALYTICS_INGEST_ENABLED", false); err != nil {
		return Config{}, err
	}
	if cfg.AnalyticsIngest.Enabled {
		cfg.ShutdownPeriod = 2 * ingestJetStream.OperationTimeout
	}
	if cfg.JobQueryEnabled, err = boolOr("JOB_QUERY_ENABLED", false); err != nil {
		return Config{}, err
	}
	if cfg.SiteStatusRecoveryEnabled, err = boolOr("SITE_STATUS_RECOVERY_RUNTIME_ENABLED", false); err != nil {
		return Config{}, err
	}
	if err := loadSiteStatusRecoveryRuntime(&cfg); err != nil {
		return Config{}, err
	}
	if cfg.APIKeyTrustedProxyCIDRs, err = parseAPIKeyTrustedProxyCIDRs(os.Getenv("API_KEY_TRUSTED_PROXY_CIDRS")); err != nil {
		return Config{}, err
	}
	if cfg.APIKeyMaxProxyHops, err = positiveIntOr("API_KEY_MAX_PROXY_HOPS", 16); err != nil {
		return Config{}, err
	}
	if cfg.APIKeyMaxProxyHops > 64 {
		return Config{}, errors.New("API_KEY_MAX_PROXY_HOPS must be between 1 and 64")
	}
	switch os.Getenv("PLUGIN_WEBHOOK_RUNTIME_ENABLED") {
	case "", "false":
		cfg.PluginWebhook.Enabled = false
	case "true":
		cfg.PluginWebhook.Enabled = true
	default:
		return Config{}, errors.New("PLUGIN_WEBHOOK_RUNTIME_ENABLED must be true or false")
	}
	if cfg.EdgeDeploymentConnectTimeout, err = durationOr("EDGE_DEPLOYMENT_NATS_CONNECT_TIMEOUT", 5*time.Second); err != nil {
		return Config{}, err
	}
	if cfg.EdgeOutboxBatchSize, err = positiveIntOr("EDGE_OUTBOX_BATCH_SIZE", 4); err != nil {
		return Config{}, err
	}
	if cfg.EdgeOutboxLeaseTimeout, err = durationOr("EDGE_OUTBOX_LEASE_TIMEOUT", 30*time.Second); err != nil {
		return Config{}, err
	}
	if cfg.EdgeOutboxOperationTimeout, err = durationOr("EDGE_OUTBOX_OPERATION_TIMEOUT", 2*time.Second); err != nil {
		return Config{}, err
	}
	if cfg.EdgeOutboxPollInterval, err = durationOr("EDGE_OUTBOX_POLL_INTERVAL", 500*time.Millisecond); err != nil {
		return Config{}, err
	}
	if cfg.EdgeOutboxBaseBackoff, err = durationOr("EDGE_OUTBOX_BASE_BACKOFF", time.Second); err != nil {
		return Config{}, err
	}
	if cfg.EdgeOutboxMaxBackoff, err = durationOr("EDGE_OUTBOX_MAX_BACKOFF", 5*time.Minute); err != nil {
		return Config{}, err
	}
	if cfg.EdgeOutboxMaxPayloadBytes, err = positiveIntOr("EDGE_OUTBOX_MAX_PAYLOAD_BYTES", 1<<20); err != nil {
		return Config{}, err
	}
	if cfg.EdgeOutboxMaxErrorBytes, err = positiveIntOr("EDGE_OUTBOX_MAX_ERROR_BYTES", 1024); err != nil {
		return Config{}, err
	}
	if cfg.EdgeStatusAckWait, err = durationOr("EDGE_STATUS_ACK_WAIT", 2*time.Minute); err != nil {
		return Config{}, err
	}
	if cfg.EdgeStatusFetchTimeout, err = durationOr("EDGE_STATUS_FETCH_TIMEOUT", 5*time.Second); err != nil {
		return Config{}, err
	}
	if cfg.EdgeStatusOperationTimeout, err = durationOr("EDGE_STATUS_OPERATION_TIMEOUT", 5*time.Second); err != nil {
		return Config{}, err
	}
	if cfg.EdgeStatusNakDelay, err = durationOr("EDGE_STATUS_NAK_DELAY", time.Second); err != nil {
		return Config{}, err
	}
	if cfg.EdgeStatusMaxAckPending, err = positiveIntOr("EDGE_STATUS_MAX_ACK_PENDING", 256); err != nil {
		return Config{}, err
	}
	if cfg.EdgeStatusMaxWaiting, err = positiveIntOr("EDGE_STATUS_MAX_WAITING", 32); err != nil {
		return Config{}, err
	}
	if cfg.EdgeStatusMaxBytes, err = positiveIntOr("EDGE_STATUS_MAX_BYTES", 1<<20); err != nil {
		return Config{}, err
	}
	if cfg.EdgeStatusMaxChecks, err = positiveIntOr("EDGE_STATUS_MAX_CHECKS", 64); err != nil {
		return Config{}, err
	}
	if cfg.EdgeStatusMaxMetadataBytes, err = positiveIntOr("EDGE_STATUS_MAX_METADATA_BYTES", 2048); err != nil {
		return Config{}, err
	}
	if cfg.EdgeStatusMaxFutureSkew, err = durationOr("EDGE_STATUS_MAX_FUTURE_SKEW", 5*time.Minute); err != nil {
		return Config{}, err
	}
	if cfg.NodePresenceAckWait, err = durationOr("NODE_PRESENCE_ACK_WAIT", 30*time.Second); err != nil {
		return Config{}, err
	}
	if cfg.NodePresenceFetchTimeout, err = durationOr("NODE_PRESENCE_FETCH_TIMEOUT", 5*time.Second); err != nil {
		return Config{}, err
	}
	if cfg.NodePresenceOperationTimeout, err = durationOr("NODE_PRESENCE_OPERATION_TIMEOUT", 5*time.Second); err != nil {
		return Config{}, err
	}
	if cfg.NodePresenceNakDelay, err = durationOr("NODE_PRESENCE_NAK_DELAY", 2*time.Second); err != nil {
		return Config{}, err
	}
	if cfg.NodePresenceLeaseTTL, err = durationOr("NODE_PRESENCE_LEASE_TTL", 45*time.Second); err != nil {
		return Config{}, err
	}
	if cfg.NodePresenceOfflineAfter, err = durationOr("NODE_PRESENCE_OFFLINE_AFTER", 45*time.Second); err != nil {
		return Config{}, err
	}
	if cfg.NodePresenceOfflinePeriod, err = durationOr("NODE_PRESENCE_OFFLINE_INTERVAL", 5*time.Second); err != nil {
		return Config{}, err
	}
	if cfg.NodePresenceConnectTimeout, err = durationOr("NODE_PRESENCE_CONNECTION_TIMEOUT", 5*time.Second); err != nil {
		return Config{}, err
	}
	if cfg.NodePresenceMaxFutureSkew, err = durationOr("NODE_PRESENCE_MAX_FUTURE_SKEW", 5*time.Minute); err != nil {
		return Config{}, err
	}
	if cfg.NodePresenceMaxBytes, err = positiveIntOr("NODE_PRESENCE_MAX_BYTES", 1<<20); err != nil {
		return Config{}, err
	}
	if cfg.NodePresenceMaxDeployments, err = positiveIntOr("NODE_PRESENCE_MAX_ACTIVE_DEPLOYMENTS", 128); err != nil {
		return Config{}, err
	}
	if cfg.NodePresenceMaxAckPending, err = positiveIntOr("NODE_PRESENCE_MAX_ACK_PENDING", 256); err != nil {
		return Config{}, err
	}
	if cfg.NodePresenceMaxWaiting, err = positiveIntOr("NODE_PRESENCE_MAX_WAITING", 32); err != nil {
		return Config{}, err
	}
	if cfg.NodePresenceOfflineBatch, err = positiveIntOr("NODE_PRESENCE_OFFLINE_BATCH", 100); err != nil {
		return Config{}, err
	}
	if cfg.DatabaseURL == "" {
		return Config{}, errors.New("DATABASE_URL is required")
	}
	if len(cfg.AccessSecret) < 32 {
		return Config{}, errors.New("ACCESS_TOKEN_SECRET must contain at least 32 bytes")
	}
	apiKeyPepperVersion := os.Getenv("API_KEY_PEPPER_VERSION")
	encodedAPIKeyPepper := os.Getenv("API_KEY_PEPPER_BASE64")
	cfg.APIKeyPepper, err = base64.StdEncoding.Strict().DecodeString(encodedAPIKeyPepper)
	if err != nil || len(cfg.APIKeyPepper) < 32 || apiKeyPepperVersion == "" {
		return Config{}, errors.New("API_KEY_PEPPER_VERSION and API_KEY_PEPPER_BASE64 must configure an active version with at least 32 bytes")
	}
	previousVersion := os.Getenv("API_KEY_PREVIOUS_PEPPER_VERSION")
	previousEncoded := os.Getenv("API_KEY_PREVIOUS_PEPPER_BASE64")
	var previous []byte
	if previousEncoded != "" {
		previous, err = base64.StdEncoding.Strict().DecodeString(previousEncoded)
		if err != nil {
			return Config{}, errors.New("API_KEY_PREVIOUS_PEPPER_BASE64 must be strict base64")
		}
	}
	cfg.APIKeyPepperKeyring, err = apikeycredential.NewPepperKeyring(apikeycredential.PepperKeyringConfig{
		ActiveVersion: apiKeyPepperVersion, Active: cfg.APIKeyPepper,
		PreviousVersion: previousVersion, Previous: previous,
	})
	for index := range previous {
		previous[index] = 0
	}
	if err != nil {
		return Config{}, errors.New("API key pepper versions and secrets are invalid")
	}
	encodedDNSKey := os.Getenv("DNS_CREDENTIAL_KEY_BASE64")
	if !validDNSCredentialKeyID(cfg.DNSCredentialKeyID) || encodedDNSKey == "" {
		return Config{}, errors.New("DNS_CREDENTIAL_KEY_ID and DNS_CREDENTIAL_KEY_BASE64 are required")
	}
	cfg.DNSCredentialKey, err = base64.StdEncoding.Strict().DecodeString(encodedDNSKey)
	if err != nil || len(cfg.DNSCredentialKey) != 32 ||
		base64.StdEncoding.EncodeToString(cfg.DNSCredentialKey) != encodedDNSKey {
		return Config{}, errors.New("DNS_CREDENTIAL_KEY_BASE64 must encode exactly 32 bytes")
	}
	encodedPreviousDNSKey := os.Getenv("DNS_CREDENTIAL_PREVIOUS_KEY_BASE64")
	if (cfg.DNSCredentialPreviousKeyID == "") != (encodedPreviousDNSKey == "") {
		return Config{}, errors.New("DNS_CREDENTIAL_PREVIOUS_KEY_ID and DNS_CREDENTIAL_PREVIOUS_KEY_BASE64 must be configured together")
	}
	if cfg.DNSCredentialPreviousKeyID != "" {
		if !validDNSCredentialKeyID(cfg.DNSCredentialPreviousKeyID) ||
			cfg.DNSCredentialPreviousKeyID == cfg.DNSCredentialKeyID {
			return Config{}, errors.New("DNS_CREDENTIAL_PREVIOUS_KEY_ID must be canonical and distinct from DNS_CREDENTIAL_KEY_ID")
		}
		cfg.DNSCredentialPreviousKey, err = base64.StdEncoding.Strict().DecodeString(encodedPreviousDNSKey)
		if err != nil || len(cfg.DNSCredentialPreviousKey) != 32 ||
			base64.StdEncoding.EncodeToString(cfg.DNSCredentialPreviousKey) != encodedPreviousDNSKey {
			return Config{}, errors.New("DNS_CREDENTIAL_PREVIOUS_KEY_BASE64 must strictly encode exactly 32 bytes")
		}
	}
	if cfg.ACMERuntimeEnabled {
		if err := loadACMERuntime(&cfg); err != nil {
			return Config{}, err
		}
	}
	if cfg.AnalyticsQueryEnabled {
		if err := loadAnalyticsQuery(&cfg); err != nil {
			return Config{}, err
		}
	}
	if cfg.AnalyticsIngest.Enabled {
		if err := loadAnalyticsIngest(&cfg); err != nil {
			return Config{}, err
		}
	}
	if cfg.JobQueryEnabled {
		if err := loadJobQuery(&cfg); err != nil {
			return Config{}, err
		}
	}
	if cfg.PluginWebhook.Enabled {
		if err := loadPluginWebhook(&cfg); err != nil {
			return Config{}, err
		}
	}
	if cfg.LicenseServiceURL != "" {
		if cfg.EntitlementSyncBackoffMin, err = durationOr("ENTITLEMENT_SYNC_BACKOFF_MIN", cfg.EntitlementSyncBackoffMin); err != nil {
			return Config{}, err
		}
		if cfg.EntitlementSyncBackoffMax, err = durationOr("ENTITLEMENT_SYNC_BACKOFF_MAX", cfg.EntitlementSyncBackoffMax); err != nil {
			return Config{}, err
		}
		if cfg.PlatformPolicyProtocol, err = positiveIntOr("PLATFORM_POLICY_PROTOCOL_VERSION", cfg.PlatformPolicyProtocol); err != nil {
			return Config{}, err
		}
		if cfg.PlatformPolicySyncInterval, err = durationOr("PLATFORM_POLICY_SYNC_INTERVAL", cfg.PlatformPolicySyncInterval); err != nil {
			return Config{}, err
		}
	}
	if err := validateEntitlementSync(cfg); err != nil {
		return Config{}, err
	}
	if err := validateControlInternal(cfg); err != nil {
		return Config{}, err
	}
	if err := validateEdgeDeployment(cfg); err != nil {
		return Config{}, err
	}
	if err := validateNodePresence(cfg); err != nil {
		return Config{}, err
	}
	loaded = true
	return cfg, nil
}

func loadSiteStatusRecoveryRuntime(cfg *Config) error {
	const prefix = "SITE_STATUS_RECOVERY_RUNTIME_"
	settings := []string{
		prefix + "TENANT_ID", prefix + "WORKER_ID", prefix + "BATCH_SIZE",
		prefix + "LEASE_DURATION", prefix + "POLL_INTERVAL",
		prefix + "OPERATION_TIMEOUT", prefix + "REPORT_TIMEOUT",
	}
	if !cfg.SiteStatusRecoveryEnabled {
		for _, name := range settings {
			if os.Getenv(name) != "" {
				return fmt.Errorf("%s must be absent while the runtime is disabled", name)
			}
		}
		return nil
	}
	tenantText := os.Getenv(prefix + "TENANT_ID")
	tenantID, err := uuid.Parse(tenantText)
	if err != nil || tenantID == uuid.Nil || tenantID.String() != tenantText {
		return errors.New(prefix + "TENANT_ID must be a canonical non-zero UUID")
	}
	workerID := os.Getenv(prefix + "WORKER_ID")
	if workerID == "" || workerID != strings.TrimSpace(workerID) || !utf8.ValidString(workerID) ||
		utf8.RuneCountInString(workerID) > 128 || strings.IndexFunc(workerID, func(character rune) bool {
		return unicode.IsControl(character) || character == '\u2028' || character == '\u2029'
	}) >= 0 {
		return errors.New(prefix + "WORKER_ID is invalid")
	}
	cfg.SiteStatusRecoveryTenantID = tenantID
	cfg.SiteStatusRecoveryWorkerID = workerID
	if cfg.SiteStatusRecoveryBatchSize, err = positiveIntOr(prefix+"BATCH_SIZE", 8); err != nil {
		return err
	}
	if cfg.SiteStatusRecoveryLeaseDuration, err = durationOr(prefix+"LEASE_DURATION", 30*time.Second); err != nil {
		return err
	}
	if cfg.SiteStatusRecoveryPollInterval, err = durationOr(prefix+"POLL_INTERVAL", time.Second); err != nil {
		return err
	}
	if cfg.SiteStatusRecoveryOperationTimeout, err = durationOr(prefix+"OPERATION_TIMEOUT", 5*time.Second); err != nil {
		return err
	}
	if cfg.SiteStatusRecoveryReportTimeout, err = durationOr(prefix+"REPORT_TIMEOUT", 2*time.Second); err != nil {
		return err
	}
	if cfg.SiteStatusRecoveryBatchSize > 100 || cfg.SiteStatusRecoveryLeaseDuration < time.Second ||
		cfg.SiteStatusRecoveryLeaseDuration > time.Hour || cfg.SiteStatusRecoveryPollInterval <= 0 ||
		cfg.SiteStatusRecoveryPollInterval >= cfg.SiteStatusRecoveryLeaseDuration ||
		cfg.SiteStatusRecoveryOperationTimeout <= 0 ||
		cfg.SiteStatusRecoveryOperationTimeout >= cfg.SiteStatusRecoveryLeaseDuration ||
		cfg.SiteStatusRecoveryOperationTimeout > cfg.ShutdownPeriod ||
		cfg.SiteStatusRecoveryReportTimeout <= 0 ||
		cfg.SiteStatusRecoveryReportTimeout > cfg.SiteStatusRecoveryOperationTimeout {
		return errors.New("site status recovery runtime limits or durations are invalid")
	}
	return nil
}

func parseAPIKeyTrustedProxyCIDRs(value string) ([]string, error) {
	if value == "" {
		return nil, nil
	}
	if strings.IndexFunc(value, unicode.IsSpace) >= 0 {
		return nil, errors.New("API_KEY_TRUSTED_PROXY_CIDRS must contain canonical comma-separated CIDRs without whitespace")
	}
	parts := strings.Split(value, ",")
	prefixes := make([]netip.Prefix, 0, len(parts))
	result := make([]string, 0, len(parts))
	for _, part := range parts {
		prefix, err := netip.ParsePrefix(part)
		if err != nil || prefix.Addr().Is4In6() || prefix.Bits() == 0 || prefix != prefix.Masked() || part != prefix.String() {
			return nil, errors.New("API_KEY_TRUSTED_PROXY_CIDRS must contain canonical network CIDRs without zones, mapped IPv6, host bits, or /0")
		}
		for _, existing := range prefixes {
			if existing.Contains(prefix.Addr()) || prefix.Contains(existing.Addr()) {
				return nil, errors.New("API_KEY_TRUSTED_PROXY_CIDRS must not contain duplicate or overlapping networks")
			}
		}
		prefixes = append(prefixes, prefix)
		result = append(result, part)
	}
	return result, nil
}

func clearPluginWebhookSecret(cfg *Config) {
	clear(cfg.PluginWebhook.AttestationKey)
	cfg.PluginWebhook.AttestationKey = nil
	clear(cfg.PluginWebhook.NextAttestationKey)
	cfg.PluginWebhook.NextAttestationKey = nil
	clear(cfg.PluginWebhook.SecretKey)
	cfg.PluginWebhook.SecretKey = nil
}

func clearAnalyticsIngestSecret(cfg *Config) {
	clear(cfg.AnalyticsIngest.IsolationWrappingKey)
	cfg.AnalyticsIngest.IsolationWrappingKey = nil
}

func loadPluginWebhook(cfg *Config) error {
	webhook := &cfg.PluginWebhook
	loaded := false
	defer func() {
		if loaded {
			return
		}
		clear(webhook.SecretKey)
		webhook.SecretKey = nil
		clear(webhook.AttestationKey)
		webhook.AttestationKey = nil
		clear(webhook.NextAttestationKey)
		webhook.NextAttestationKey = nil
	}()
	rawNATSURL := os.Getenv("PLUGIN_WEBHOOK_NATS_URL")
	webhook.NATSURL = strings.TrimSpace(rawNATSURL)
	parsedNATS, err := url.Parse(webhook.NATSURL)
	if err != nil || rawNATSURL != webhook.NATSURL || strings.Contains(rawNATSURL, ",") ||
		parsedNATS.Host == "" || parsedNATS.Hostname() == "" || parsedNATS.User != nil ||
		parsedNATS.RawQuery != "" || parsedNATS.Fragment != "" || parsedNATS.Path != "" ||
		(parsedNATS.Scheme != "tls" && (parsedNATS.Scheme != "nats" || !loopbackHost(parsedNATS.Hostname()))) {
		return errors.New("PLUGIN_WEBHOOK_NATS_URL must be one TLS server URL or a loopback nats:// URL without credentials, query, fragment, or path")
	}
	webhook.NATSName = envOr("PLUGIN_WEBHOOK_NATS_NAME", "cdnca-plugin-webhook-runtime")
	webhook.NATSCredsFile = os.Getenv("PLUGIN_WEBHOOK_NATS_CREDS_FILE")
	if webhook.NATSCredsFile == "" || strings.TrimSpace(webhook.NATSCredsFile) != webhook.NATSCredsFile {
		return errors.New("PLUGIN_WEBHOOK_NATS_CREDS_FILE must be a non-empty path without surrounding whitespace")
	}
	webhook.NATSCAFile = os.Getenv("PLUGIN_WEBHOOK_NATS_CA_FILE")
	if webhook.NATSCAFile == "" || strings.TrimSpace(webhook.NATSCAFile) != webhook.NATSCAFile {
		return errors.New("PLUGIN_WEBHOOK_NATS_CA_FILE must be a non-empty path without surrounding whitespace")
	}
	if webhook.NATSReconnectMin, err = durationOr("PLUGIN_WEBHOOK_NATS_RECONNECT_MIN", 250*time.Millisecond); err != nil {
		return err
	}
	if webhook.NATSReconnectMin > 5*time.Minute {
		return errors.New("PLUGIN_WEBHOOK_NATS_RECONNECT_MIN must not exceed 5m")
	}
	if webhook.NATSReconnectMax, err = durationOr("PLUGIN_WEBHOOK_NATS_RECONNECT_MAX", 5*time.Second); err != nil {
		return err
	}
	if webhook.NATSReconnectMax > 5*time.Minute {
		return errors.New("PLUGIN_WEBHOOK_NATS_RECONNECT_MAX must not exceed 5m")
	}
	if webhook.NATSReconnectMin > webhook.NATSReconnectMax {
		return errors.New("PLUGIN_WEBHOOK_NATS_RECONNECT_MIN must not exceed PLUGIN_WEBHOOK_NATS_RECONNECT_MAX")
	}
	webhook.SecretKeyID = os.Getenv("PLUGIN_WEBHOOK_SECRET_KEY_ID")
	if !validPluginWebhookKeyID(webhook.SecretKeyID) {
		return errors.New("PLUGIN_WEBHOOK_SECRET_KEY_ID must be a valid key identifier")
	}
	keyFile := os.Getenv("PLUGIN_WEBHOOK_SECRET_KEY_FILE")
	encodedKey := os.Getenv("PLUGIN_WEBHOOK_SECRET_KEY_BASE64")
	if (keyFile == "") == (encodedKey == "") {
		return errors.New("PLUGIN_WEBHOOK_SECRET_KEY_FILE and PLUGIN_WEBHOOK_SECRET_KEY_BASE64 must have exactly one value")
	}
	if keyFile != "" {
		keyReader, openErr := os.Open(keyFile)
		if openErr != nil {
			return errors.New("failed to read PLUGIN_WEBHOOK_SECRET_KEY_FILE")
		}
		webhook.SecretKey, err = readPluginWebhookSecretKey(keyReader)
		closeErr := keyReader.Close()
		if err != nil {
			return err
		}
		if closeErr != nil {
			return errors.New("failed to read PLUGIN_WEBHOOK_SECRET_KEY_FILE")
		}
	} else {
		webhook.SecretKey, err = base64.StdEncoding.Strict().DecodeString(encodedKey)
		if err != nil || len(webhook.SecretKey) != 32 || base64.StdEncoding.EncodeToString(webhook.SecretKey) != encodedKey {
			return errors.New("PLUGIN_WEBHOOK_SECRET_KEY_BASE64 must be canonical base64 encoding of exactly 32 bytes")
		}
	}
	keys, err := LoadPluginWebhookAttestationKeys()
	if err != nil {
		return err
	}
	webhook.AttestationKeyID, webhook.AttestationKey = keys.CurrentID, keys.Current
	webhook.NextAttestationKeyID, webhook.NextAttestationKey = keys.NextID, keys.Next
	if webhook.PollInterval, err = durationOr("PLUGIN_WEBHOOK_POLL_INTERVAL", 100*time.Millisecond); err != nil {
		return err
	}
	if webhook.OperationTimeout, err = durationOr("PLUGIN_WEBHOOK_OPERATION_TIMEOUT", webhook.JetStream.OperationTimeout); err != nil {
		return err
	}
	webhook.JetStream.OperationTimeout = webhook.OperationTimeout
	if webhook.LeaseDuration, err = durationOr("PLUGIN_WEBHOOK_LEASE_DURATION", time.Minute); err != nil {
		return err
	}
	if webhook.ClaimTimeout, err = durationOr("PLUGIN_WEBHOOK_CLAIM_TIMEOUT", 5*time.Minute); err != nil {
		return err
	}
	if webhook.ShutdownTimeout, err = durationOr("PLUGIN_WEBHOOK_SHUTDOWN_TIMEOUT", 10*time.Second); err != nil {
		return err
	}
	jetstream := &webhook.JetStream
	jetstream.DeliveryStream = envOr("PLUGIN_WEBHOOK_DELIVERY_STREAM", jetstream.DeliveryStream)
	jetstream.DeliveryDurable = envOr("PLUGIN_WEBHOOK_DELIVERY_DURABLE", jetstream.DeliveryDurable)
	jetstream.DeliverySubjectPrefix = envOr("PLUGIN_WEBHOOK_DELIVERY_SUBJECT_PREFIX", jetstream.DeliverySubjectPrefix)
	jetstream.DeadLetterStream = envOr("PLUGIN_WEBHOOK_DEAD_LETTER_STREAM", jetstream.DeadLetterStream)
	jetstream.DeadLetterSubject = envOr("PLUGIN_WEBHOOK_DEAD_LETTER_SUBJECT", jetstream.DeadLetterSubject)
	if jetstream.AckWait, err = durationOr("PLUGIN_WEBHOOK_ACK_WAIT", jetstream.AckWait); err != nil {
		return err
	}
	if jetstream.FetchTimeout, err = durationOr("PLUGIN_WEBHOOK_FETCH_TIMEOUT", jetstream.FetchTimeout); err != nil {
		return err
	}
	if value := os.Getenv("PLUGIN_WEBHOOK_CONSUMER_MAX_DELIVER"); value != "" && value != "-1" {
		return fmt.Errorf("PLUGIN_WEBHOOK_CONSUMER_MAX_DELIVER must be -1")
	}
	jetstream.ConsumerMaxDeliver = -1
	if jetstream.MaxAckPending, err = positiveIntOr("PLUGIN_WEBHOOK_MAX_ACK_PENDING", jetstream.MaxAckPending); err != nil {
		return err
	}
	if jetstream.MaxWaiting, err = positiveIntOr("PLUGIN_WEBHOOK_MAX_WAITING", jetstream.MaxWaiting); err != nil {
		return err
	}
	if jetstream.StreamMaxAge, err = durationOr("PLUGIN_WEBHOOK_STREAM_MAX_AGE", jetstream.StreamMaxAge); err != nil {
		return err
	}
	if jetstream.StreamMaxBytes, err = positiveInt64Or("PLUGIN_WEBHOOK_STREAM_MAX_BYTES", jetstream.StreamMaxBytes); err != nil {
		return err
	}
	if jetstream.StreamMaxMessages, err = positiveInt64Or("PLUGIN_WEBHOOK_STREAM_MAX_MESSAGES", jetstream.StreamMaxMessages); err != nil {
		return err
	}
	if jetstream.DeadLetterMaxAge, err = durationOr("PLUGIN_WEBHOOK_DEAD_LETTER_MAX_AGE", jetstream.DeadLetterMaxAge); err != nil {
		return err
	}
	if jetstream.DeadLetterMaxBytes, err = positiveInt64Or("PLUGIN_WEBHOOK_DEAD_LETTER_MAX_BYTES", jetstream.DeadLetterMaxBytes); err != nil {
		return err
	}
	if jetstream.DuplicateWindow, err = durationOr("PLUGIN_WEBHOOK_DUPLICATE_WINDOW", jetstream.DuplicateWindow); err != nil {
		return err
	}
	if jetstream.Replicas, err = positiveIntOr("PLUGIN_WEBHOOK_REPLICAS", jetstream.Replicas); err != nil {
		return err
	}
	readinessMaxPending, err := positiveInt64Or("PLUGIN_WEBHOOK_READINESS_MAX_PENDING", int64(jetstream.ReadinessMaxPending))
	if err != nil {
		return err
	}
	jetstream.ReadinessMaxPending = uint64(readinessMaxPending)
	if !validPluginWebhookConfig(*cfg) {
		return errors.New("plugin webhook runtime NATS, capacity, or duration settings are invalid")
	}
	loaded = true
	return nil
}

func readPluginWebhookSecretKey(reader io.Reader) ([]byte, error) {
	buffer := make([]byte, 33)
	defer clear(buffer)
	n, err := io.ReadFull(reader, buffer)
	if err != nil && !errors.Is(err, io.EOF) && !errors.Is(err, io.ErrUnexpectedEOF) {
		return nil, errors.New("failed to read PLUGIN_WEBHOOK_SECRET_KEY_FILE")
	}
	if n != 32 {
		return nil, errors.New("PLUGIN_WEBHOOK_SECRET_KEY_FILE must contain exactly 32 raw bytes")
	}
	return append([]byte(nil), buffer[:32]...), nil
}

func validPluginWebhookConfig(cfg Config) bool {
	webhook := cfg.PluginWebhook
	jetstream := webhook.JetStream
	return webhook.Enabled && validNATSName(webhook.NATSName) && len(webhook.NATSName) <= 128 &&
		webhook.PollInterval > 0 && webhook.PollInterval <= time.Minute &&
		webhook.OperationTimeout > 0 && webhook.OperationTimeout <= time.Minute &&
		webhook.LeaseDuration > 0 && webhook.LeaseDuration <= 5*time.Minute && webhook.LeaseDuration <= jetstream.DuplicateWindow &&
		webhook.ClaimTimeout >= webhook.OperationTimeout && webhook.ClaimTimeout <= 24*time.Hour &&
		webhook.ShutdownTimeout > 0 && webhook.ShutdownTimeout <= time.Minute && webhook.ShutdownTimeout <= cfg.ShutdownPeriod &&
		validNATSName(jetstream.DeliveryStream) && len(jetstream.DeliveryStream) <= 128 &&
		validNATSName(jetstream.DeliveryDurable) && len(jetstream.DeliveryDurable) <= 128 &&
		jetstream.DeadLetterStream == pluginwebhookruntime.DefaultDeadLetterStream &&
		jetstream.DeliveryStream != jetstream.DeadLetterStream &&
		validPluginWebhookSubject(jetstream.DeliverySubjectPrefix) &&
		jetstream.DeadLetterSubject == pluginwebhookruntime.DefaultDeadLetterSubject &&
		jetstream.AckWait > 3*jetstream.OperationTimeout && jetstream.FetchTimeout > 0 && jetstream.FetchTimeout <= jetstream.AckWait &&
		jetstream.ConsumerMaxDeliver == -1 &&
		jetstream.MaxAckPending >= 1 && jetstream.MaxAckPending <= 1024 && jetstream.MaxWaiting >= 1 && jetstream.MaxWaiting <= 1024 &&
		jetstream.StreamMaxAge > 0 && jetstream.StreamMaxBytes >= pluginwebhookruntime.MaxMessageBytes && jetstream.StreamMaxMessages > 0 &&
		jetstream.DeadLetterMaxAge > 0 && jetstream.DeadLetterMaxBytes >= pluginwebhookruntime.MaxMessageBytes &&
		jetstream.DuplicateWindow > 0 && jetstream.DuplicateWindow <= jetstream.StreamMaxAge &&
		jetstream.Replicas >= 1 && jetstream.Replicas <= 5 && jetstream.ReadinessMaxPending > 0 &&
		jetstream.ReadinessMaxPending <= uint64(jetstream.StreamMaxMessages)
}

func validPluginWebhookKeyID(value string) bool {
	if len(value) == 0 || len(value) > 128 {
		return false
	}
	for index := range len(value) {
		character := value[index]
		alphanumeric := character >= 'A' && character <= 'Z' || character >= 'a' && character <= 'z' ||
			character >= '0' && character <= '9'
		if !alphanumeric && (index == 0 || !strings.ContainsRune("._:/-", rune(character))) {
			return false
		}
	}
	return true
}

func validPluginWebhookSubject(value string) bool {
	if len(value) == 0 || len(value) > 240 || strings.HasPrefix(value, ".") || strings.HasSuffix(value, ".") {
		return false
	}
	for _, token := range strings.Split(value, ".") {
		if len(token) > 128 || !validNATSName(token) {
			return false
		}
	}
	return true
}

func loadJobQuery(cfg *Config) error {
	cfg.JobQueryCursorActiveKeyID = os.Getenv("JOB_QUERY_CURSOR_ACTIVE_KEY_ID")
	if !validJobCursorKeyID(cfg.JobQueryCursorActiveKeyID) {
		return errors.New("JOB_QUERY_CURSOR_ACTIVE_KEY_ID must be a valid key identifier")
	}
	var encodedKeys map[string]string
	if err := json.Unmarshal([]byte(os.Getenv("JOB_QUERY_CURSOR_KEYS_JSON")), &encodedKeys); err != nil || len(encodedKeys) == 0 {
		return errors.New("JOB_QUERY_CURSOR_KEYS_JSON must be a non-empty JSON object")
	}
	cfg.JobQueryCursorKeys = make(map[string][]byte, len(encodedKeys))
	for keyID, encoded := range encodedKeys {
		if !validJobCursorKeyID(keyID) {
			return errors.New("JOB_QUERY_CURSOR_KEYS_JSON contains an invalid key identifier")
		}
		key, err := base64.StdEncoding.Strict().DecodeString(encoded)
		if err != nil || len(key) < 32 {
			return errors.New("JOB_QUERY_CURSOR_KEYS_JSON values must encode at least 32 bytes")
		}
		cfg.JobQueryCursorKeys[keyID] = key
	}
	if _, ok := cfg.JobQueryCursorKeys[cfg.JobQueryCursorActiveKeyID]; !ok {
		return errors.New("JOB_QUERY_CURSOR_ACTIVE_KEY_ID must identify a configured cursor key")
	}
	var err error
	if cfg.JobQueryTimeout, err = durationOr("JOB_QUERY_TIMEOUT", 6*time.Second); err != nil {
		return err
	}
	if cfg.JobQueryMaxResponse, err = positiveIntOr("JOB_QUERY_MAX_RESPONSE_BYTES", 1<<20); err != nil {
		return err
	}
	if cfg.JobQueryTimeout <= 0 || cfg.JobQueryTimeout > 30*time.Second {
		return errors.New("JOB_QUERY_TIMEOUT must be greater than zero and at most 30s")
	}
	if cfg.JobQueryMaxResponse < 512 || cfg.JobQueryMaxResponse > 4<<20 {
		return errors.New("JOB_QUERY_MAX_RESPONSE_BYTES must be between 512 and 4194304")
	}
	return nil
}

func validJobCursorKeyID(value string) bool {
	if len(value) == 0 || len(value) > 64 {
		return false
	}
	for index := range len(value) {
		character := value[index]
		if (character < 'a' || character > 'z') && (character < 'A' || character > 'Z') &&
			(character < '0' || character > '9') && character != '.' && character != '_' && character != '-' {
			return false
		}
	}
	return true
}

func validDNSCredentialKeyID(value string) bool {
	if len(value) == 0 || len(value) > 128 {
		return false
	}
	for index := range len(value) {
		character := value[index]
		alphanumeric := character >= 'a' && character <= 'z' || character >= 'A' && character <= 'Z' ||
			character >= '0' && character <= '9'
		if !alphanumeric && (index == 0 || character != '.' && character != '_' && character != ':' && character != '-') {
			return false
		}
	}
	return true
}

func loadAnalyticsQuery(cfg *Config) error {
	rawURL := os.Getenv("CLICKHOUSE_URL")
	cfg.ClickHouseURL = strings.TrimSpace(rawURL)
	parsed, err := url.Parse(cfg.ClickHouseURL)
	if err != nil || rawURL != cfg.ClickHouseURL || parsed.Host == "" || parsed.Hostname() == "" || parsed.User != nil ||
		parsed.RawQuery != "" || parsed.Fragment != "" || (parsed.Path != "" && parsed.Path != "/") ||
		(parsed.Scheme != "https" && (parsed.Scheme != "http" || !loopbackHost(parsed.Hostname()))) {
		return errors.New("CLICKHOUSE_URL must be HTTPS or loopback HTTP without credentials, query, fragment, or non-root path")
	}
	rawDatabase := os.Getenv("CLICKHOUSE_DATABASE")
	cfg.ClickHouseDatabase = strings.TrimSpace(rawDatabase)
	if rawDatabase != cfg.ClickHouseDatabase || !analytics.ValidDatabaseIdentifier(cfg.ClickHouseDatabase) {
		return fmt.Errorf("CLICKHOUSE_DATABASE must be a non-empty ClickHouse identifier of at most %d bytes", analytics.MaxDatabaseIdentifierBytes)
	}
	cfg.ClickHouseUsername = os.Getenv("CLICKHOUSE_USERNAME")
	if cfg.ClickHouseUsername == "" || cfg.ClickHouseUsername != strings.TrimSpace(cfg.ClickHouseUsername) ||
		len(cfg.ClickHouseUsername) > 256 || strings.ContainsRune(cfg.ClickHouseUsername, ':') ||
		strings.IndexFunc(cfg.ClickHouseUsername, func(character rune) bool { return character < 32 || character == 127 }) >= 0 {
		return errors.New("CLICKHOUSE_USERNAME must be a non-empty valid username")
	}
	cfg.ClickHousePassword = os.Getenv("CLICKHOUSE_PASSWORD")
	if cfg.ClickHousePassword == "" || len(cfg.ClickHousePassword) > 4096 || strings.ContainsAny(cfg.ClickHousePassword, "\r\n\x00") {
		return errors.New("CLICKHOUSE_PASSWORD must be a non-empty valid password")
	}
	if cfg.AnalyticsConnectTimeout, err = durationOr("ANALYTICS_CONNECT_TIMEOUT", 3*time.Second); err != nil {
		return err
	}
	if cfg.AnalyticsQueryTimeout, err = durationOr("ANALYTICS_QUERY_TIMEOUT", 5*time.Second); err != nil {
		return err
	}
	if cfg.AnalyticsHandlerTimeout, err = durationOr("ANALYTICS_HANDLER_TIMEOUT", 6*time.Second); err != nil {
		return err
	}
	if cfg.AnalyticsQueryMaxResponse, err = positiveInt64Or("ANALYTICS_QUERY_MAX_RESPONSE_BYTES", 4<<20); err != nil {
		return err
	}
	if cfg.AnalyticsHandlerMaxResponse, err = positiveIntOr("ANALYTICS_HANDLER_MAX_RESPONSE_BYTES", 1<<20); err != nil {
		return err
	}
	if cfg.AnalyticsConnectTimeout < 100*time.Millisecond || cfg.AnalyticsConnectTimeout > 30*time.Second ||
		cfg.AnalyticsQueryTimeout < 100*time.Millisecond || cfg.AnalyticsQueryTimeout > 30*time.Second ||
		cfg.AnalyticsHandlerTimeout <= cfg.AnalyticsQueryTimeout || cfg.AnalyticsHandlerTimeout > 30*time.Second {
		return errors.New("analytics connect, query, or handler timeouts are invalid")
	}
	if cfg.AnalyticsQueryMaxResponse < 512 || cfg.AnalyticsQueryMaxResponse > 4<<20 ||
		cfg.AnalyticsHandlerMaxResponse < 512 || int64(cfg.AnalyticsHandlerMaxResponse) > cfg.AnalyticsQueryMaxResponse {
		return errors.New("analytics query or handler response limits are invalid")
	}
	return nil
}

func loadAnalyticsIngest(cfg *Config) error {
	ingest := &cfg.AnalyticsIngest
	ingest.IsolationWrappingKeyID = os.Getenv("ANALYTICS_INGEST_ISOLATION_WRAPPING_KEY_ID")
	if len(ingest.IsolationWrappingKeyID) == 0 || len(ingest.IsolationWrappingKeyID) > 128 ||
		ingest.IsolationWrappingKeyID != strings.TrimSpace(ingest.IsolationWrappingKeyID) ||
		strings.IndexFunc(ingest.IsolationWrappingKeyID, unicode.IsControl) >= 0 {
		return errors.New("ANALYTICS_INGEST_ISOLATION_WRAPPING_KEY_ID must be non-empty, at most 128 bytes, and contain no surrounding whitespace or control characters")
	}
	encodedWrappingKey := os.Getenv("ANALYTICS_INGEST_ISOLATION_WRAPPING_KEY_BASE64")
	var err error
	ingest.IsolationWrappingKey, err = base64.StdEncoding.Strict().DecodeString(encodedWrappingKey)
	if err != nil || len(ingest.IsolationWrappingKey) != 32 ||
		base64.StdEncoding.EncodeToString(ingest.IsolationWrappingKey) != encodedWrappingKey {
		return errors.New("ANALYTICS_INGEST_ISOLATION_WRAPPING_KEY_BASE64 must be canonical base64 encoding of exactly 32 bytes")
	}
	rawNATSURL := os.Getenv("ANALYTICS_INGEST_NATS_URL")
	ingest.NATSURL = strings.TrimSpace(rawNATSURL)
	parsedNATS, err := url.Parse(ingest.NATSURL)
	if err != nil || rawNATSURL != ingest.NATSURL || strings.Contains(rawNATSURL, ",") ||
		parsedNATS.Host == "" || parsedNATS.Hostname() == "" || parsedNATS.User != nil ||
		parsedNATS.RawQuery != "" || parsedNATS.Fragment != "" || parsedNATS.Path != "" ||
		(parsedNATS.Scheme != "tls" && (parsedNATS.Scheme != "nats" || !loopbackHost(parsedNATS.Hostname()))) {
		return errors.New("ANALYTICS_INGEST_NATS_URL must be one TLS server URL or a loopback nats:// URL without credentials, query, fragment, or path")
	}
	ingest.NATSUsername = os.Getenv("ANALYTICS_INGEST_NATS_USER")
	ingest.NATSPassword = os.Getenv("ANALYTICS_INGEST_NATS_PASSWORD")
	if (ingest.NATSUsername == "") != (ingest.NATSPassword == "") ||
		(ingest.NATSUsername != "" && (ingest.NATSUsername != strings.TrimSpace(ingest.NATSUsername) ||
			len(ingest.NATSUsername) > 256 || strings.ContainsRune(ingest.NATSUsername, ':') ||
			strings.IndexFunc(ingest.NATSUsername, func(character rune) bool { return character < 32 || character == 127 }) >= 0)) ||
		len(ingest.NATSPassword) > 4096 || strings.ContainsAny(ingest.NATSPassword, "\r\n\x00") {
		return errors.New("ANALYTICS_INGEST_NATS_USER and ANALYTICS_INGEST_NATS_PASSWORD must be a valid pair")
	}

	rawClickHouseURL := os.Getenv("ANALYTICS_INGEST_CLICKHOUSE_URL")
	ingest.ClickHouseURL = strings.TrimSpace(rawClickHouseURL)
	parsedClickHouse, err := url.Parse(ingest.ClickHouseURL)
	if err != nil || rawClickHouseURL != ingest.ClickHouseURL || parsedClickHouse.Host == "" || parsedClickHouse.Hostname() == "" ||
		parsedClickHouse.User != nil || parsedClickHouse.RawQuery != "" || parsedClickHouse.Fragment != "" ||
		(parsedClickHouse.Path != "" && parsedClickHouse.Path != "/") ||
		(parsedClickHouse.Scheme != "https" && (parsedClickHouse.Scheme != "http" || !loopbackHost(parsedClickHouse.Hostname()))) {
		return errors.New("ANALYTICS_INGEST_CLICKHOUSE_URL must be HTTPS or loopback HTTP without credentials, query, fragment, or non-root path")
	}
	rawDatabase := os.Getenv("ANALYTICS_INGEST_CLICKHOUSE_DATABASE")
	ingest.ClickHouseDatabase = strings.TrimSpace(rawDatabase)
	if rawDatabase != ingest.ClickHouseDatabase || !analytics.ValidDatabaseIdentifier(ingest.ClickHouseDatabase) {
		return fmt.Errorf("ANALYTICS_INGEST_CLICKHOUSE_DATABASE must be a non-empty ClickHouse identifier of at most %d bytes", analytics.MaxDatabaseIdentifierBytes)
	}
	ingest.ClickHouseUsername = os.Getenv("ANALYTICS_INGEST_CLICKHOUSE_USER")
	if ingest.ClickHouseUsername == "" || ingest.ClickHouseUsername != strings.TrimSpace(ingest.ClickHouseUsername) ||
		len(ingest.ClickHouseUsername) > 256 || strings.ContainsRune(ingest.ClickHouseUsername, ':') ||
		strings.IndexFunc(ingest.ClickHouseUsername, func(character rune) bool { return character < 32 || character == 127 }) >= 0 {
		return errors.New("ANALYTICS_INGEST_CLICKHOUSE_USER must be a non-empty valid username")
	}
	ingest.ClickHousePassword = os.Getenv("ANALYTICS_INGEST_CLICKHOUSE_PASSWORD")
	if ingest.ClickHousePassword == "" || len(ingest.ClickHousePassword) > 4096 || strings.ContainsAny(ingest.ClickHousePassword, "\r\n\x00") {
		return errors.New("ANALYTICS_INGEST_CLICKHOUSE_PASSWORD must be a non-empty valid password")
	}

	if ingest.ConnectTimeout, err = durationOr("ANALYTICS_INGEST_CONNECT_TIMEOUT", 3*time.Second); err != nil {
		return err
	}
	if ingest.WriteTimeout, err = durationOr("ANALYTICS_INGEST_WRITE_TIMEOUT", 2*time.Second); err != nil {
		return err
	}
	if ingest.SupervisorBackoffMin, err = durationOr("ANALYTICS_INGEST_SUPERVISOR_BACKOFF_MIN", time.Second); err != nil {
		return err
	}
	if ingest.SupervisorBackoffMax, err = durationOr("ANALYTICS_INGEST_SUPERVISOR_BACKOFF_MAX", time.Minute); err != nil {
		return err
	}
	if ingest.ConnectTimeout < 100*time.Millisecond || ingest.ConnectTimeout > 30*time.Second ||
		ingest.WriteTimeout < 100*time.Millisecond || ingest.WriteTimeout > 30*time.Second ||
		ingest.SupervisorBackoffMin < 100*time.Millisecond || ingest.SupervisorBackoffMax < ingest.SupervisorBackoffMin ||
		ingest.SupervisorBackoffMax > 5*time.Minute {
		return errors.New("analytics ingest connection, write, or supervisor timeouts are invalid")
	}

	jetstream := &ingest.JetStream
	jetstream.Stream = envOr("ANALYTICS_INGEST_STREAM", jetstream.Stream)
	jetstream.Durable = envOr("ANALYTICS_INGEST_DURABLE", jetstream.Durable)
	jetstream.IsolationStream = envOr("ANALYTICS_INGEST_ISOLATION_STREAM", jetstream.IsolationStream)
	if jetstream.AckWait, err = durationOr("ANALYTICS_INGEST_ACK_WAIT", jetstream.AckWait); err != nil {
		return err
	}
	if jetstream.FetchTimeout, err = durationOr("ANALYTICS_INGEST_FETCH_TIMEOUT", jetstream.FetchTimeout); err != nil {
		return err
	}
	if jetstream.OperationTimeout, err = durationOr("ANALYTICS_INGEST_OPERATION_TIMEOUT", jetstream.OperationTimeout); err != nil {
		return err
	}
	if jetstream.NakBaseDelay, err = durationOr("ANALYTICS_INGEST_NAK_BASE_DELAY", jetstream.NakBaseDelay); err != nil {
		return err
	}
	if jetstream.NakMaxDelay, err = durationOr("ANALYTICS_INGEST_NAK_MAX_DELAY", jetstream.NakMaxDelay); err != nil {
		return err
	}
	if jetstream.MaxDeliver, err = positiveIntOr("ANALYTICS_INGEST_MAX_DELIVER", jetstream.MaxDeliver); err != nil {
		return err
	}
	if jetstream.MaxAckPending, err = positiveIntOr("ANALYTICS_INGEST_MAX_ACK_PENDING", jetstream.MaxAckPending); err != nil {
		return err
	}
	if jetstream.MaxWaiting, err = positiveIntOr("ANALYTICS_INGEST_MAX_WAITING", jetstream.MaxWaiting); err != nil {
		return err
	}
	if jetstream.FetchBatch, err = positiveIntOr("ANALYTICS_INGEST_FETCH_BATCH", jetstream.FetchBatch); err != nil {
		return err
	}
	if jetstream.StreamMaxAge, err = durationOr("ANALYTICS_INGEST_STREAM_MAX_AGE", jetstream.StreamMaxAge); err != nil {
		return err
	}
	if jetstream.StreamMaxBytes, err = positiveInt64Or("ANALYTICS_INGEST_STREAM_MAX_BYTES", jetstream.StreamMaxBytes); err != nil {
		return err
	}
	if jetstream.StreamMaxMessages, err = positiveInt64Or("ANALYTICS_INGEST_STREAM_MAX_MESSAGES", jetstream.StreamMaxMessages); err != nil {
		return err
	}
	if jetstream.IsolationMaxAge, err = durationOr("ANALYTICS_INGEST_ISOLATION_MAX_AGE", jetstream.IsolationMaxAge); err != nil {
		return err
	}
	if jetstream.IsolationMaxBytes, err = positiveInt64Or("ANALYTICS_INGEST_ISOLATION_MAX_BYTES", jetstream.IsolationMaxBytes); err != nil {
		return err
	}
	if jetstream.DuplicateWindow, err = durationOr("ANALYTICS_INGEST_DUPLICATE_WINDOW", jetstream.DuplicateWindow); err != nil {
		return err
	}
	if jetstream.Replicas, err = positiveIntOr("ANALYTICS_INGEST_REPLICAS", jetstream.Replicas); err != nil {
		return err
	}
	if jetstream.OperationTimeout > 30*time.Second || 2*jetstream.OperationTimeout > cfg.ShutdownPeriod ||
		ingest.WriteTimeout > jetstream.OperationTimeout || analytics.ValidateJetStreamConfig(*jetstream) != nil {
		return errors.New("analytics ingest JetStream consumer, retention, or timeout limits are invalid")
	}
	return nil
}

func loopbackHost(host string) bool {
	if strings.EqualFold(host, "localhost") {
		return true
	}
	address := net.ParseIP(host)
	return address != nil && address.IsLoopback()
}

func loadACMERuntime(cfg *Config) error {
	var err error
	rawDirectoryURL := os.Getenv("ACME_DIRECTORY_URL")
	cfg.ACMEDirectoryURL = strings.TrimSpace(rawDirectoryURL)
	parsed, err := url.Parse(cfg.ACMEDirectoryURL)
	if err != nil || rawDirectoryURL != cfg.ACMEDirectoryURL || parsed.Scheme != "https" || parsed.Host == "" || parsed.User != nil ||
		parsed.RawQuery != "" || parsed.Fragment != "" {
		return errors.New("ACME_DIRECTORY_URL must be an HTTPS directory URL")
	}
	rawBackupDirectoryURL := os.Getenv("ACME_BACKUP_DIRECTORY_URL")
	cfg.ACMEBackupDirectoryURL = strings.TrimSpace(rawBackupDirectoryURL)
	if cfg.ACMEBackupDirectoryURL != "" {
		backup, backupErr := url.Parse(cfg.ACMEBackupDirectoryURL)
		if backupErr != nil || rawBackupDirectoryURL != cfg.ACMEBackupDirectoryURL ||
			backup.Scheme != "https" || backup.Host == "" || backup.User != nil ||
			backup.RawQuery != "" || backup.Fragment != "" ||
			cfg.ACMEBackupDirectoryURL == cfg.ACMEDirectoryURL {
			return errors.New("ACME_BACKUP_DIRECTORY_URL must be a distinct HTTPS directory URL")
		}
	}
	cfg.ACMEContacts, err = parseACMEContacts(os.Getenv("ACME_CONTACTS"))
	if err != nil {
		return err
	}
	cfg.ACMEWrappingKeyID = strings.TrimSpace(os.Getenv("ACME_WRAPPING_KEY_ID"))
	if cfg.ACMEWrappingKeyID == "" || cfg.ACMEWrappingKeyID != os.Getenv("ACME_WRAPPING_KEY_ID") ||
		len(cfg.ACMEWrappingKeyID) > 128 || strings.IndexFunc(cfg.ACMEWrappingKeyID, func(character rune) bool {
		return character < 32 || character == 127
	}) >= 0 {
		return errors.New("ACME_WRAPPING_KEY_ID must be a non-empty key identifier")
	}
	encodedWrappingKey := os.Getenv("ACME_WRAPPING_KEY_BASE64")
	cfg.ACMEWrappingKey, err = base64.StdEncoding.Strict().DecodeString(encodedWrappingKey)
	if err != nil || len(cfg.ACMEWrappingKey) != 32 ||
		base64.StdEncoding.EncodeToString(cfg.ACMEWrappingKey) != encodedWrappingKey {
		return errors.New("ACME_WRAPPING_KEY_BASE64 must encode exactly 32 bytes")
	}
	if cfg.ACMEPollInterval, err = durationOr("ACME_POLL_INTERVAL", time.Second); err != nil {
		return err
	}
	if cfg.ACMELeaseDuration, err = durationOr("ACME_LEASE_DURATION", 10*time.Minute); err != nil {
		return err
	}
	if cfg.ACMESettleTimeout, err = durationOr("ACME_SETTLE_TIMEOUT", 30*time.Second); err != nil {
		return err
	}
	if cfg.ACMERetryBase, err = durationOr("ACME_RETRY_BASE", time.Minute); err != nil {
		return err
	}
	if cfg.ACMERetryMaximum, err = durationOr("ACME_RETRY_MAXIMUM", time.Hour); err != nil {
		return err
	}
	if cfg.ACMEMaxAttempts, err = positiveIntOr("ACME_MAX_ATTEMPTS", 10); err != nil {
		return err
	}
	if cfg.ACMEErrorBackoffMin, err = durationOr("ACME_ERROR_BACKOFF_MIN", time.Second); err != nil {
		return err
	}
	if cfg.ACMEErrorBackoffMax, err = durationOr("ACME_ERROR_BACKOFF_MAX", 30*time.Second); err != nil {
		return err
	}
	if cfg.ACMEPollInterval < 100*time.Millisecond || cfg.ACMEPollInterval > time.Minute ||
		cfg.ACMELeaseDuration < 6*time.Minute || cfg.ACMELeaseDuration > 24*time.Hour ||
		cfg.ACMESettleTimeout < time.Second || cfg.ACMESettleTimeout > cfg.ACMELeaseDuration ||
		cfg.ACMERetryBase < time.Second || cfg.ACMERetryMaximum < cfg.ACMERetryBase ||
		cfg.ACMERetryMaximum > 24*time.Hour || cfg.ACMEMaxAttempts > 100 ||
		cfg.ACMEErrorBackoffMin < 100*time.Millisecond ||
		cfg.ACMEErrorBackoffMax < cfg.ACMEErrorBackoffMin || cfg.ACMEErrorBackoffMax > time.Minute {
		return errors.New("ACME runtime durations or retry limits are invalid")
	}
	return nil
}

func parseACMEContacts(value string) ([]string, error) {
	if value == "" {
		return nil, errors.New("ACME_CONTACTS must contain at least one mailto contact")
	}
	parts := strings.Split(value, ",")
	if len(parts) > 10 {
		return nil, errors.New("ACME_CONTACTS must contain between one and ten mailto contacts")
	}
	contacts := make([]string, 0, len(parts))
	seen := make(map[string]struct{}, len(parts))
	for _, contact := range parts {
		if contact == "" || contact != strings.TrimSpace(contact) || !strings.HasPrefix(contact, "mailto:") {
			return nil, errors.New("ACME_CONTACTS must contain valid comma-separated mailto contacts")
		}
		address := strings.TrimPrefix(contact, "mailto:")
		parsed, err := mail.ParseAddress(address)
		if err != nil || parsed.Address != address || strings.ContainsAny(contact, "\r\n\x00") {
			return nil, errors.New("ACME_CONTACTS must contain valid comma-separated mailto contacts")
		}
		if _, exists := seen[contact]; exists {
			return nil, errors.New("ACME_CONTACTS must not contain duplicate contacts")
		}
		seen[contact] = struct{}{}
		contacts = append(contacts, contact)
	}
	return contacts, nil
}

func validateControlInternal(cfg Config) error {
	if strings.TrimSpace(cfg.ControlInternalGRPCAddr) == "" ||
		cfg.ControlInternalServerCert == "" || cfg.ControlInternalServerKey == "" ||
		cfg.ControlInternalGatewayCA == "" || cfg.ControlInternalGatewayURI == "" ||
		cfg.NodeCACertificateChainFile == "" ||
		cfg.NodeCAPrivateKeyFile == "" {
		return errors.New("ControlInternal gRPC server certificate, private key, Gateway CA/workload URI, and node CA files are required")
	}
	return nil
}

func validateEdgeDeployment(cfg Config) error {
	if cfg.EdgeDeploymentNATSURL == "" {
		return errors.New("EDGE_DEPLOYMENT_NATS_URL is required")
	}
	parsed, err := url.Parse(cfg.EdgeDeploymentNATSURL)
	if err != nil || (parsed.Scheme != "nats" && parsed.Scheme != "tls") || parsed.Host == "" ||
		parsed.Path != "" || parsed.RawQuery != "" || parsed.Fragment != "" {
		return errors.New("EDGE_DEPLOYMENT_NATS_URL must be a single nats:// or tls:// server URL")
	}
	credentialsConfigured := cfg.EdgeDeploymentNATSCredsFile != ""
	caConfigured := cfg.EdgeDeploymentNATSCAFile != ""
	if credentialsConfigured != caConfigured || credentialsConfigured &&
		(strings.TrimSpace(cfg.EdgeDeploymentNATSCredsFile) != cfg.EdgeDeploymentNATSCredsFile ||
			strings.TrimSpace(cfg.EdgeDeploymentNATSCAFile) != cfg.EdgeDeploymentNATSCAFile) {
		return errors.New("EDGE_DEPLOYMENT_NATS_CREDS_FILE and EDGE_DEPLOYMENT_NATS_CA_FILE must both be absent or non-empty paths without surrounding whitespace")
	}
	if !validNATSName(cfg.EdgeCommandStream) || !validNATSName(cfg.EdgeStatusStream) ||
		!validNATSName(cfg.EdgeStatusDurable) {
		return errors.New("edge deployment stream and durable names may contain only letters, digits, dash, or underscore")
	}
	if !validSubjectPrefix(cfg.EdgeCommandSubjectPrefix) || !validSubjectPrefix(cfg.EdgeStatusSubjectPrefix) {
		return errors.New("edge deployment subject prefixes must contain only literal tokens")
	}
	if cfg.EdgeCommandSubjectPrefix != "cdnca.agent.commands" {
		return errors.New("EDGE_COMMAND_SUBJECT_PREFIX must match the versioned command contract")
	}
	if cfg.EdgeOutboxBatchSize > 256 || cfg.EdgeOutboxLeaseTimeout < 3*cfg.EdgeOutboxOperationTimeout ||
		cfg.EdgeOutboxMaxBackoff < cfg.EdgeOutboxBaseBackoff || cfg.EdgeOutboxMaxPayloadBytes > 1<<20 ||
		cfg.EdgeOutboxMaxErrorBytes > 2048 ||
		time.Duration(cfg.EdgeOutboxBatchSize)*cfg.EdgeOutboxOperationTimeout >= cfg.ShutdownPeriod {
		return errors.New("edge outbox limits or durations are invalid")
	}
	if cfg.EdgeStatusAckWait <= 3*cfg.EdgeStatusOperationTimeout ||
		cfg.EdgeStatusFetchTimeout > cfg.EdgeStatusAckWait || cfg.EdgeStatusMaxBytes > 1<<20 ||
		cfg.EdgeStatusMaxMetadataBytes > cfg.EdgeStatusMaxBytes {
		return errors.New("edge status limits or durations are invalid")
	}
	return nil
}

func validateEntitlementSync(cfg Config) error {
	if cfg.LicenseServiceURL == "" {
		return nil
	}
	parsed, err := url.Parse(cfg.LicenseServiceURL)
	if err != nil || parsed.Scheme != "https" || parsed.Host == "" || parsed.User != nil ||
		parsed.RawQuery != "" || parsed.Fragment != "" {
		return errors.New("LICENSE_SERVICE_URL must be an HTTPS origin")
	}
	if cfg.EntitlementTrustedKeysFile == "" || cfg.ControlInstallationID == "" ||
		cfg.ControlInstallationName == "" || cfg.ControlInstallationKeyFile == "" || cfg.ControlVersion == "" {
		return errors.New("entitlement sync requires trusted keys, installation ID, name, and private key file")
	}
	if !validControlVersion(cfg.ControlVersion) {
		return errors.New("CONTROL_VERSION must be canonical Semantic Versioning without v prefix or build metadata")
	}
	if cfg.EntitlementSyncBackoffMax < cfg.EntitlementSyncBackoffMin {
		return errors.New("ENTITLEMENT_SYNC_BACKOFF_MAX must not be less than ENTITLEMENT_SYNC_BACKOFF_MIN")
	}
	return nil
}

func validControlVersion(value string) bool {
	if value == "" || strings.HasPrefix(value, "v") || strings.Contains(value, "+") {
		return false
	}
	withPrefix := "v" + value
	return semver.IsValid(withPrefix) && strings.TrimPrefix(semver.Canonical(withPrefix), "v") == value
}

func validateNodePresence(cfg Config) error {
	if cfg.NodePresenceNATSURL == "" && cfg.NodePresenceRedisURL == "" {
		return nil
	}
	if cfg.NodePresenceNATSURL == "" || cfg.NodePresenceRedisURL == "" {
		return errors.New("node presence requires both NODE_PRESENCE_NATS_URL and NODE_PRESENCE_REDIS_URL")
	}
	natsURL, err := url.Parse(cfg.NodePresenceNATSURL)
	if err != nil || (natsURL.Scheme != "nats" && natsURL.Scheme != "tls") || natsURL.Host == "" {
		return errors.New("NODE_PRESENCE_NATS_URL must use nats:// or tls://")
	}
	redisURL, err := url.Parse(cfg.NodePresenceRedisURL)
	if err != nil || (redisURL.Scheme != "redis" && redisURL.Scheme != "rediss") || redisURL.Host == "" {
		return errors.New("NODE_PRESENCE_REDIS_URL must use redis:// or rediss://")
	}
	if cfg.NodePresenceLeaseTTL > cfg.NodePresenceOfflineAfter {
		return errors.New("NODE_PRESENCE_LEASE_TTL must not exceed NODE_PRESENCE_OFFLINE_AFTER")
	}
	if cfg.NodePresenceAckWait <= 3*cfg.NodePresenceOperationTimeout {
		return errors.New("NODE_PRESENCE_ACK_WAIT must exceed three operation timeouts")
	}
	return nil
}

func envOr(name, fallback string) string {
	if value := os.Getenv(name); value != "" {
		return value
	}
	return fallback
}

func durationOr(name string, fallback time.Duration) (time.Duration, error) {
	value := os.Getenv(name)
	if value == "" {
		return fallback, nil
	}
	parsed, err := time.ParseDuration(value)
	if err != nil || parsed <= 0 {
		return 0, fmt.Errorf("%s must be a positive duration", name)
	}
	return parsed, nil
}

func boolOr(name string, fallback bool) (bool, error) {
	value := os.Getenv(name)
	if value == "" {
		return fallback, nil
	}
	parsed, err := strconv.ParseBool(value)
	if err != nil {
		return false, fmt.Errorf("%s must be a boolean", name)
	}
	return parsed, nil
}

func positiveIntOr(name string, fallback int) (int, error) {
	value := os.Getenv(name)
	if value == "" {
		return fallback, nil
	}
	parsed, err := strconv.Atoi(value)
	if err != nil || parsed <= 0 {
		return 0, fmt.Errorf("%s must be a positive integer", name)
	}
	return parsed, nil
}

func positiveInt64Or(name string, fallback int64) (int64, error) {
	value := os.Getenv(name)
	if value == "" {
		return fallback, nil
	}
	parsed, err := strconv.ParseInt(value, 10, 64)
	if err != nil || parsed <= 0 {
		return 0, fmt.Errorf("%s must be a positive integer", name)
	}
	return parsed, nil
}

func validNATSName(value string) bool {
	if value == "" {
		return false
	}
	for _, character := range value {
		if character >= 'a' && character <= 'z' || character >= 'A' && character <= 'Z' ||
			character >= '0' && character <= '9' || character == '-' || character == '_' {
			continue
		}
		return false
	}
	return true
}

func validSubjectPrefix(value string) bool {
	if value == "" || strings.HasPrefix(value, ".") || strings.HasSuffix(value, ".") {
		return false
	}
	for _, token := range strings.Split(value, ".") {
		if !validNATSName(token) {
			return false
		}
	}
	return true
}

var pluginWebhookAttestationKeyIDPattern = regexp.MustCompile(`^[A-Za-z0-9][A-Za-z0-9._:-]{0,127}$`)

func validPluginWebhookAttestationKeyID(value string) bool {
	return pluginWebhookAttestationKeyIDPattern.MatchString(value)
}

// PluginWebhookAttestationKeys are the publication attestation keys: the
// current one (required) and an optional next one staged for rotation.
type PluginWebhookAttestationKeys struct {
	CurrentID string
	Current   ed25519.PrivateKey
	NextID    string
	Next      ed25519.PrivateKey
}

// Clear zeroes the private keys.
func (keys *PluginWebhookAttestationKeys) Clear() {
	clear(keys.Current)
	clear(keys.Next)
	keys.Current, keys.Next = nil, nil
}

// LoadPluginWebhookAttestationKeys reads PLUGIN_WEBHOOK_ATTESTATION_KEY_ID /
// _PRIVATE_KEY_FILE and the optional PLUGIN_WEBHOOK_ATTESTATION_NEXT_KEY_ID /
// _NEXT_PRIVATE_KEY_FILE. The runtime and the rotation command
// (control-api plugin-webhook-attestation-key) share it.
func LoadPluginWebhookAttestationKeys() (PluginWebhookAttestationKeys, error) {
	var keys PluginWebhookAttestationKeys
	keys.CurrentID = os.Getenv("PLUGIN_WEBHOOK_ATTESTATION_KEY_ID")
	if !validPluginWebhookAttestationKeyID(keys.CurrentID) {
		return PluginWebhookAttestationKeys{}, errors.New("PLUGIN_WEBHOOK_ATTESTATION_KEY_ID must be a valid key identifier")
	}
	var err error
	if keys.Current, err = readPluginWebhookAttestationKey("PLUGIN_WEBHOOK_ATTESTATION_PRIVATE_KEY_FILE",
		os.Getenv("PLUGIN_WEBHOOK_ATTESTATION_PRIVATE_KEY_FILE")); err != nil {
		return PluginWebhookAttestationKeys{}, err
	}
	keys.NextID = os.Getenv("PLUGIN_WEBHOOK_ATTESTATION_NEXT_KEY_ID")
	nextFile := os.Getenv("PLUGIN_WEBHOOK_ATTESTATION_NEXT_PRIVATE_KEY_FILE")
	if keys.NextID == "" && nextFile == "" {
		return keys, nil
	}
	if !validPluginWebhookAttestationKeyID(keys.NextID) || keys.NextID == keys.CurrentID {
		keys.Clear()
		return PluginWebhookAttestationKeys{}, errors.New(
			"PLUGIN_WEBHOOK_ATTESTATION_NEXT_KEY_ID must be a valid key identifier different from PLUGIN_WEBHOOK_ATTESTATION_KEY_ID")
	}
	if keys.Next, err = readPluginWebhookAttestationKey("PLUGIN_WEBHOOK_ATTESTATION_NEXT_PRIVATE_KEY_FILE", nextFile); err != nil {
		keys.Clear()
		return PluginWebhookAttestationKeys{}, err
	}
	if bytes.Equal(keys.Next.Public().(ed25519.PublicKey), keys.Current.Public().(ed25519.PublicKey)) {
		keys.Clear()
		return PluginWebhookAttestationKeys{}, errors.New(
			"PLUGIN_WEBHOOK_ATTESTATION_NEXT_PRIVATE_KEY_FILE must hold a different key from PLUGIN_WEBHOOK_ATTESTATION_PRIVATE_KEY_FILE")
	}
	return keys, nil
}

// readPluginWebhookAttestationKey reads one PKCS#8 PEM Ed25519 private key.
func readPluginWebhookAttestationKey(name, path string) (ed25519.PrivateKey, error) {
	invalid := errors.New(name + " must name one PKCS#8 PEM Ed25519 private key")
	if path == "" || strings.TrimSpace(path) != path {
		return nil, invalid
	}
	encoded, err := os.ReadFile(path)
	if err != nil || len(encoded) > 16<<10 {
		clear(encoded)
		return nil, invalid
	}
	defer clear(encoded)
	block, rest := pem.Decode(encoded)
	if block == nil || block.Type != "PRIVATE KEY" || len(block.Headers) != 0 || len(bytes.TrimSpace(rest)) != 0 {
		return nil, invalid
	}
	defer clear(block.Bytes)
	parsed, err := x509.ParsePKCS8PrivateKey(block.Bytes)
	key, ok := parsed.(ed25519.PrivateKey)
	if err != nil || !ok || len(key) != ed25519.PrivateKeySize {
		return nil, invalid
	}
	result := append(ed25519.PrivateKey(nil), key...)
	clear(key)
	return result, nil
}
