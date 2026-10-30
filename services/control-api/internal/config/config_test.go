package config

import (
	"bytes"
	"encoding/base64"
	"os"
	"strings"
	"testing"
	"time"

	"github.com/cdnca/cdnca/services/control-api/internal/analytics"
)

func TestLoadRequiresDeploymentDNSCredentialKey(t *testing.T) {
	setRequiredConfig(t)
	t.Setenv("DNS_CREDENTIAL_KEY_ID", "")
	t.Setenv("DNS_CREDENTIAL_KEY_BASE64", "")
	if _, err := Load(); err == nil || !strings.Contains(err.Error(), "DNS_CREDENTIAL_KEY") {
		t.Fatalf("Load() missing DNS key error = %v", err)
	}

	t.Setenv("DNS_CREDENTIAL_KEY_ID", "dns-v1")
	t.Setenv("DNS_CREDENTIAL_KEY_BASE64", base64.StdEncoding.EncodeToString(make([]byte, 31)))
	if _, err := Load(); err == nil || !strings.Contains(err.Error(), "exactly 32 bytes") {
		t.Fatalf("Load() short DNS key error = %v", err)
	}
}

func TestLoadRequiresDeploymentAPIKeyPepper(t *testing.T) {
	setRequiredConfig(t)
	t.Setenv("API_KEY_PEPPER_VERSION", "")
	if _, err := Load(); err == nil || !strings.Contains(err.Error(), "API_KEY_PEPPER_VERSION") {
		t.Fatalf("Load() missing API key pepper version error = %v", err)
	}

	setRequiredConfig(t)
	t.Setenv("API_KEY_PEPPER_BASE64", "")
	if _, err := Load(); err == nil || !strings.Contains(err.Error(), "API_KEY_PEPPER_BASE64") {
		t.Fatalf("Load() missing API key pepper error = %v", err)
	}

	t.Setenv("API_KEY_PEPPER_BASE64", base64.StdEncoding.EncodeToString(make([]byte, 31)))
	if _, err := Load(); err == nil || !strings.Contains(err.Error(), "at least 32 bytes") {
		t.Fatalf("Load() short API key pepper error = %v", err)
	}

	setRequiredConfig(t)
	t.Setenv("API_KEY_PREVIOUS_PEPPER_VERSION", "pepper-v0")
	if _, err := Load(); err == nil || !strings.Contains(err.Error(), "pepper versions") {
		t.Fatalf("Load() incomplete previous pepper error = %v", err)
	}

	setRequiredConfig(t)
	t.Setenv("API_KEY_PEPPER_VERSION", "pepper-v2")
	t.Setenv("API_KEY_PREVIOUS_PEPPER_VERSION", "pepper-v1")
	t.Setenv("API_KEY_PREVIOUS_PEPPER_BASE64", base64.StdEncoding.EncodeToString(bytes.Repeat([]byte{8}, 32)))
	cfg, err := Load()
	if err != nil || !cfg.APIKeyPepperKeyring.Configured() || cfg.APIKeyPepperKeyring.ActiveVersion() != "pepper-v2" {
		t.Fatalf("Load() rotation keyring = (%q, %v)", cfg.APIKeyPepperKeyring.ActiveVersion(), err)
	}
}

func TestLoadValidatesAPIKeyTrustedProxyConfiguration(t *testing.T) {
	setRequiredConfig(t)
	cfg, err := Load()
	if err != nil {
		t.Fatalf("Load() default proxy config error = %v", err)
	}
	if len(cfg.APIKeyTrustedProxyCIDRs) != 0 || cfg.APIKeyMaxProxyHops != 16 {
		t.Fatalf("default API key proxy config = (%v, %d)", cfg.APIKeyTrustedProxyCIDRs, cfg.APIKeyMaxProxyHops)
	}

	t.Setenv("API_KEY_TRUSTED_PROXY_CIDRS", "10.0.0.0/8,2001:db8::/32")
	t.Setenv("API_KEY_MAX_PROXY_HOPS", "64")
	cfg, err = Load()
	if err != nil {
		t.Fatalf("Load() valid proxy config error = %v", err)
	}
	if strings.Join(cfg.APIKeyTrustedProxyCIDRs, ",") != "10.0.0.0/8,2001:db8::/32" || cfg.APIKeyMaxProxyHops != 64 {
		t.Fatalf("loaded API key proxy config = (%v, %d)", cfg.APIKeyTrustedProxyCIDRs, cfg.APIKeyMaxProxyHops)
	}

	invalidCIDRs := []string{
		"10.0.0.0/8,",
		"10.0.0.0/8, 2001:db8::/32",
		"10.0.0.0/8,10.0.0.0/8",
		"10.0.0.0/8,10.1.0.0/16",
		"fe80::%eth0/64",
		"::ffff:192.0.2.0/120",
		"10.0.0.1/24",
		"2001:0db8::/32",
		"0.0.0.0/0",
		"::/0",
	}
	for _, value := range invalidCIDRs {
		t.Run(value, func(t *testing.T) {
			setRequiredConfig(t)
			t.Setenv("API_KEY_TRUSTED_PROXY_CIDRS", value)
			if _, err := Load(); err == nil || !strings.Contains(err.Error(), "API_KEY_TRUSTED_PROXY_CIDRS") {
				t.Fatalf("Load() invalid trusted proxies error = %v", err)
			}
		})
	}

	for _, value := range []string{"0", "65", "invalid"} {
		t.Run("hops_"+value, func(t *testing.T) {
			setRequiredConfig(t)
			t.Setenv("API_KEY_MAX_PROXY_HOPS", value)
			if _, err := Load(); err == nil || !strings.Contains(err.Error(), "API_KEY_MAX_PROXY_HOPS") {
				t.Fatalf("Load() invalid max proxy hops error = %v", err)
			}
		})
	}
}

func TestLoadValidatesOptionalEntitlementSync(t *testing.T) {
	setRequiredConfig(t)
	t.Setenv("LICENSE_SERVICE_URL", "http://license.example.test")
	if _, err := Load(); err == nil || !strings.Contains(err.Error(), "HTTPS") {
		t.Fatalf("Load() insecure license URL error = %v", err)
	}

	t.Setenv("LICENSE_SERVICE_URL", "https://license.example.test")
	t.Setenv("ENTITLEMENT_TRUSTED_KEYS_FILE", "/etc/cdnca/trusted-keys.json")
	t.Setenv("CONTROL_INSTALLATION_ID", "d664f802-e4e9-44c2-a644-31af828aefbb")
	t.Setenv("CONTROL_INSTALLATION_NAME", "Primary control")
	t.Setenv("CONTROL_INSTALLATION_PRIVATE_KEY_FILE", "/run/secrets/control-key.pem")
	t.Setenv("CONTROL_VERSION", "1.4.0")
	t.Setenv("ENTITLEMENT_SYNC_BACKOFF_MIN", "2s")
	t.Setenv("ENTITLEMENT_SYNC_BACKOFF_MAX", "1s")
	if _, err := Load(); err == nil || !strings.Contains(err.Error(), "BACKOFF_MAX") {
		t.Fatalf("Load() invalid backoff error = %v", err)
	}
	t.Setenv("ENTITLEMENT_SYNC_BACKOFF_MAX", "10s")
	cfg, err := Load()
	if err != nil {
		t.Fatalf("Load() valid sync config error = %v", err)
	}
	if cfg.LicenseServiceURL != "https://license.example.test" || cfg.EntitlementSyncBackoffMin != 2*time.Second ||
		cfg.EntitlementSyncBackoffMax != 10*time.Second || cfg.ControlVersion != "1.4.0" ||
		cfg.PlatformPolicyProtocol != 1 || cfg.PlatformPolicySyncInterval != time.Minute {
		t.Fatal("loaded sync config fields do not match")
	}
}

func TestLoadDecodesDeploymentDNSCredentialKey(t *testing.T) {
	setRequiredConfig(t)
	key := bytes.Repeat([]byte{4}, 32)
	t.Setenv("DNS_CREDENTIAL_KEY_ID", "dns-v1")
	t.Setenv("DNS_CREDENTIAL_KEY_BASE64", base64.StdEncoding.EncodeToString(key))
	cfg, err := Load()
	if err != nil {
		t.Fatalf("Load() error = %v", err)
	}
	if cfg.DNSCredentialKeyID != "dns-v1" || !bytes.Equal(cfg.DNSCredentialKey, key) {
		t.Fatalf("loaded DNS key metadata ID=%q length=%d", cfg.DNSCredentialKeyID, len(cfg.DNSCredentialKey))
	}
}

func TestLoadRequiresControlInternalTLSAndNodeCAFiles(t *testing.T) {
	setRequiredConfig(t)
	t.Setenv("CONTROL_INTERNAL_SERVER_CERT_FILE", "")
	if _, err := Load(); err == nil || !strings.Contains(err.Error(), "ControlInternal") {
		t.Fatalf("Load() missing internal TLS error = %v", err)
	}

	setRequiredConfig(t)
	t.Setenv("NODE_CA_PRIVATE_KEY_FILE", "")
	if _, err := Load(); err == nil || !strings.Contains(err.Error(), "node CA") {
		t.Fatalf("Load() missing node CA error = %v", err)
	}

	setRequiredConfig(t)
	t.Setenv("CONTROL_INTERNAL_GATEWAY_WORKLOAD_URI_SAN", "")
	if _, err := Load(); err == nil || !strings.Contains(err.Error(), "workload URI") {
		t.Fatalf("Load() missing Gateway workload URI error = %v", err)
	}
}

func TestLoadValidatesOptionalNodePresence(t *testing.T) {
	setRequiredConfig(t)
	t.Setenv("NODE_PRESENCE_NATS_URL", "nats://127.0.0.1:4222")
	if _, err := Load(); err == nil || !strings.Contains(err.Error(), "both") {
		t.Fatalf("Load() missing Redis URL error = %v", err)
	}
	t.Setenv("NODE_PRESENCE_REDIS_URL", "redis://127.0.0.1:6379/0")
	t.Setenv("NODE_PRESENCE_ACK_WAIT", "15s")
	t.Setenv("NODE_PRESENCE_OPERATION_TIMEOUT", "5s")
	if _, err := Load(); err == nil || !strings.Contains(err.Error(), "three operation") {
		t.Fatalf("Load() short ack wait error = %v", err)
	}
	t.Setenv("NODE_PRESENCE_ACK_WAIT", "30s")
	t.Setenv("NODE_PRESENCE_LEASE_TTL", "46s")
	if _, err := Load(); err == nil || !strings.Contains(err.Error(), "LEASE_TTL") {
		t.Fatalf("Load() excessive lease TTL error = %v", err)
	}
	t.Setenv("NODE_PRESENCE_LEASE_TTL", "45s")
	cfg, err := Load()
	if err != nil {
		t.Fatalf("Load() valid node presence config error = %v", err)
	}
	if cfg.NodePresenceStream != "AGENT_HEARTBEATS" || cfg.NodePresenceDurable != "control_api_node_presence" ||
		cfg.NodePresenceOfflineAfter != 45*time.Second || cfg.NodePresenceMaxBytes != 1<<20 {
		t.Fatal("loaded node presence config fields do not match")
	}
}

func TestLoadRequiresAndValidatesEdgeDeploymentRuntime(t *testing.T) {
	setRequiredConfig(t)
	t.Setenv("EDGE_DEPLOYMENT_NATS_URL", "")
	if _, err := Load(); err == nil || !strings.Contains(err.Error(), "EDGE_DEPLOYMENT_NATS_URL is required") {
		t.Fatalf("Load() missing edge NATS URL error = %v", err)
	}

	t.Setenv("EDGE_DEPLOYMENT_NATS_URL", "https://user:secret@example.test:4222")
	if _, err := Load(); err == nil || strings.Contains(err.Error(), "secret") {
		t.Fatal("Load() invalid edge NATS URL validation failed")
	}

	t.Setenv("EDGE_DEPLOYMENT_NATS_URL", "nats://user:secret@127.0.0.1:4222")
	t.Setenv("EDGE_STATUS_DURABLE", "bad.durable")
	if _, err := Load(); err == nil || !strings.Contains(err.Error(), "stream and durable") {
		t.Fatalf("Load() invalid durable error = %v", err)
	}

	t.Setenv("EDGE_STATUS_DURABLE", "control_api_edge_status")
	t.Setenv("EDGE_STATUS_SUBJECT_PREFIX", "cdnca.agent.*")
	if _, err := Load(); err == nil || !strings.Contains(err.Error(), "subject prefixes") {
		t.Fatalf("Load() invalid subject error = %v", err)
	}

	t.Setenv("EDGE_STATUS_SUBJECT_PREFIX", "cdnca.agent.deployment-status")
	t.Setenv("EDGE_OUTBOX_BATCH_SIZE", "257")
	if _, err := Load(); err == nil || !strings.Contains(err.Error(), "outbox limits") {
		t.Fatalf("Load() oversized batch error = %v", err)
	}

	t.Setenv("EDGE_OUTBOX_BATCH_SIZE", "4")
	t.Setenv("EDGE_OUTBOX_LEASE_TIMEOUT", "5s")
	t.Setenv("EDGE_OUTBOX_OPERATION_TIMEOUT", "2s")
	if _, err := Load(); err == nil || !strings.Contains(err.Error(), "outbox limits") {
		t.Fatalf("Load() short outbox lease error = %v", err)
	}

	t.Setenv("EDGE_OUTBOX_LEASE_TIMEOUT", "30s")
	t.Setenv("EDGE_OUTBOX_BATCH_SIZE", "5")
	if _, err := Load(); err == nil || !strings.Contains(err.Error(), "outbox limits") {
		t.Fatalf("Load() unbounded outbox shutdown error = %v", err)
	}
	t.Setenv("EDGE_OUTBOX_BATCH_SIZE", "4")
	t.Setenv("EDGE_STATUS_ACK_WAIT", "15s")
	t.Setenv("EDGE_STATUS_OPERATION_TIMEOUT", "5s")
	if _, err := Load(); err == nil || !strings.Contains(err.Error(), "status limits") {
		t.Fatalf("Load() short status ack wait error = %v", err)
	}

	t.Setenv("EDGE_STATUS_ACK_WAIT", "2m")
	cfg, err := Load()
	if err != nil {
		t.Fatalf("Load() valid edge runtime config error = %v", err)
	}
	if cfg.EdgeCommandStream != "AGENT_COMMANDS" || cfg.EdgeStatusStream != "AGENT_DEPLOYMENT_STATUS" ||
		cfg.EdgeStatusDurable != "control_api_edge_status" || cfg.EdgeOutboxBatchSize != 4 ||
		cfg.EdgeOutboxPollInterval != 500*time.Millisecond || cfg.EdgeStatusAckWait != 2*time.Minute {
		t.Fatal("loaded edge runtime config fields do not match")
	}
}

func TestLoadValidatesEdgeDeploymentNATSCredentialFiles(t *testing.T) {
	const (
		credentialsFile = "/run/secrets/nats/edge-deployment.creds"
		caFile          = "/run/secrets/nats/edge-deployment-ca.pem"
	)
	tests := []struct {
		name        string
		credentials string
		ca          string
		wantError   bool
	}{
		{name: "both absent"},
		{name: "credentials only", credentials: credentialsFile, wantError: true},
		{name: "CA only", ca: caFile, wantError: true},
		{name: "credentials surrounding whitespace", credentials: " " + credentialsFile, ca: caFile, wantError: true},
		{name: "CA surrounding whitespace", credentials: credentialsFile, ca: caFile + " ", wantError: true},
		{name: "paired exact paths", credentials: credentialsFile, ca: caFile},
	}
	for _, test := range tests {
		t.Run(test.name, func(t *testing.T) {
			setRequiredConfig(t)
			t.Setenv("EDGE_DEPLOYMENT_NATS_CREDS_FILE", test.credentials)
			t.Setenv("EDGE_DEPLOYMENT_NATS_CA_FILE", test.ca)
			cfg, err := Load()
			if test.wantError {
				if err == nil || !strings.Contains(err.Error(), "EDGE_DEPLOYMENT_NATS_CREDS_FILE and EDGE_DEPLOYMENT_NATS_CA_FILE") {
					t.Fatalf("Load() credential pair error = %v", err)
				}
				return
			}
			if err != nil {
				t.Fatalf("Load() error = %v", err)
			}
			if cfg.EdgeDeploymentNATSCredsFile != test.credentials || cfg.EdgeDeploymentNATSCAFile != test.ca {
				t.Fatalf("loaded edge NATS files = (%q, %q)", cfg.EdgeDeploymentNATSCredsFile, cfg.EdgeDeploymentNATSCAFile)
			}
		})
	}
}

func TestLoadACMERuntimeIsDisabledByDefaultAndIgnoresSecrets(t *testing.T) {
	setRequiredConfig(t)
	t.Setenv("ACME_DIRECTORY_URL", "http://invalid.example/directory")
	t.Setenv("ACME_WRAPPING_KEY_BASE64", "not-base64-secret")
	cfg, err := Load()
	if err != nil {
		t.Fatalf("Load() disabled ACME runtime error = %v", err)
	}
	if cfg.ACMERuntimeEnabled || len(cfg.ACMEWrappingKey) != 0 || len(cfg.ACMEContacts) != 0 {
		t.Fatal("disabled ACME runtime config fields do not match")
	}
}

func TestLoadValidatesEnabledACMERuntime(t *testing.T) {
	setRequiredConfig(t)
	t.Setenv("ACME_RUNTIME_ENABLED", "true")
	if _, err := Load(); err == nil || !strings.Contains(err.Error(), "ACME_DIRECTORY_URL") {
		t.Fatalf("Load() missing directory error = %v", err)
	}
	t.Setenv("ACME_DIRECTORY_URL", "http://ca.example/directory")
	if _, err := Load(); err == nil || !strings.Contains(err.Error(), "HTTPS") {
		t.Fatalf("Load() HTTP directory error = %v", err)
	}
	t.Setenv("ACME_DIRECTORY_URL", "https://ca.example/directory")
	t.Setenv("ACME_BACKUP_DIRECTORY_URL", "http://backup.example/directory")
	if _, err := Load(); err == nil || !strings.Contains(err.Error(), "ACME_BACKUP_DIRECTORY_URL") {
		t.Fatalf("Load() HTTP backup directory error = %v", err)
	}
	t.Setenv("ACME_BACKUP_DIRECTORY_URL", "https://ca.example/directory")
	if _, err := Load(); err == nil || !strings.Contains(err.Error(), "distinct") {
		t.Fatalf("Load() duplicate backup directory error = %v", err)
	}
	t.Setenv("ACME_BACKUP_DIRECTORY_URL", "https://backup.example/directory")
	t.Setenv("ACME_CONTACTS", "ops@example.test")
	if _, err := Load(); err == nil || !strings.Contains(err.Error(), "mailto") {
		t.Fatalf("Load() invalid contacts error = %v", err)
	}
	t.Setenv("ACME_CONTACTS", "mailto:ops@example.test")
	t.Setenv("ACME_WRAPPING_KEY_ID", strings.Repeat("k", 129))
	if _, err := Load(); err == nil || !strings.Contains(err.Error(), "KEY_ID") {
		t.Fatalf("Load() oversized wrapping key ID error = %v", err)
	}
	t.Setenv("ACME_WRAPPING_KEY_ID", "acme-kek-v1")
	secret := "do-not-expose-this-wrapping-key"
	t.Setenv("ACME_WRAPPING_KEY_BASE64", secret)
	if _, err := Load(); err == nil || !strings.Contains(err.Error(), "exactly 32 bytes") ||
		strings.Contains(err.Error(), secret) {
		t.Fatal("Load() invalid wrapping key validation failed")
	}
	t.Setenv("ACME_WRAPPING_KEY_BASE64", base64.StdEncoding.EncodeToString(bytes.Repeat([]byte{9}, 32)))
	canonicalWrappingKey := os.Getenv("ACME_WRAPPING_KEY_BASE64")
	t.Setenv("ACME_WRAPPING_KEY_BASE64", canonicalWrappingKey[:8]+"\n"+canonicalWrappingKey[8:])
	if _, err := Load(); err == nil || !strings.Contains(err.Error(), "exactly 32 bytes") {
		t.Fatalf("Load() non-canonical wrapping key error = %v", err)
	}
	t.Setenv("ACME_WRAPPING_KEY_BASE64", canonicalWrappingKey)
	t.Setenv("ACME_HTTP01_ENCRYPTION_KEY_ID", "ignored invalid key id")
	t.Setenv("ACME_HTTP01_ENCRYPTION_KEY_BASE64", "ignored-not-base64")
	t.Setenv("ACME_HTTP01_SIGNING_KEY_ID", "ignored invalid key id")
	t.Setenv("ACME_HTTP01_SIGNING_PRIVATE_KEY_FILE", "")
	t.Setenv("ACME_HTTP01_CHALLENGE_LIFETIME", "invalid")
	t.Setenv("ACME_HTTP01_HEALTH_POLL", "invalid")
	t.Setenv("ACME_HTTP01_MAX_TARGETS", "invalid")
	t.Setenv("ACME_POLL_INTERVAL", "99ms")
	if _, err := Load(); err == nil || !strings.Contains(err.Error(), "durations or retry limits") {
		t.Fatalf("Load() short poll interval error = %v", err)
	}
	t.Setenv("ACME_POLL_INTERVAL", "250ms")
	t.Setenv("ACME_LEASE_DURATION", "5m")
	if _, err := Load(); err == nil || !strings.Contains(err.Error(), "durations or retry limits") {
		t.Fatalf("Load() short lease error = %v", err)
	}
	t.Setenv("ACME_LEASE_DURATION", "10m")
	t.Setenv("ACME_MAX_ATTEMPTS", "101")
	if _, err := Load(); err == nil || !strings.Contains(err.Error(), "durations or retry limits") {
		t.Fatalf("Load() excessive max attempts error = %v", err)
	}
	t.Setenv("ACME_MAX_ATTEMPTS", "5")
	cfg, err := Load()
	if err != nil {
		t.Fatalf("Load() valid ACME runtime error = %v", err)
	}
	if !cfg.ACMERuntimeEnabled || cfg.ACMEDirectoryURL != "https://ca.example/directory" ||
		cfg.ACMEBackupDirectoryURL != "https://backup.example/directory" ||
		len(cfg.ACMEContacts) != 1 || cfg.ACMEContacts[0] != "mailto:ops@example.test" ||
		cfg.ACMEWrappingKeyID != "acme-kek-v1" || len(cfg.ACMEWrappingKey) != 32 ||
		cfg.ACMEPollInterval != 250*time.Millisecond || cfg.ACMELeaseDuration != 10*time.Minute ||
		cfg.ACMEMaxAttempts != 5 || cfg.ACMEHTTP01EncryptionKeyID != "" ||
		len(cfg.ACMEHTTP01EncryptionKey) != 0 || cfg.ACMEHTTP01SigningKeyID != "" ||
		cfg.ACMEHTTP01SigningKeyFile != "" || cfg.ACMEHTTP01ChallengeLifetime != 0 ||
		cfg.ACMEHTTP01HealthPoll != 0 || cfg.ACMEHTTP01MaxTargets != 0 {
		t.Fatal("loaded ACME runtime config fields do not match")
	}
}

func TestLoadAnalyticsQueryIsDisabledByDefaultAndIgnoresSecrets(t *testing.T) {
	setRequiredConfig(t)
	t.Setenv("CLICKHOUSE_URL", "http://remote.example.test/?password=visible-secret")
	t.Setenv("CLICKHOUSE_PASSWORD", "visible-secret")
	cfg, err := Load()
	if err != nil {
		t.Fatalf("Load() disabled analytics query error = %v", err)
	}
	if cfg.AnalyticsQueryEnabled || cfg.ClickHouseURL != "" || cfg.ClickHousePassword != "" {
		t.Fatal("disabled analytics config fields do not match")
	}
}

func TestLoadValidatesEnabledAnalyticsQuery(t *testing.T) {
	t.Run("endpoint", func(t *testing.T) {
		for _, endpoint := range []string{
			"", "http://clickhouse.example.test", "https://user:visible-secret@clickhouse.example.test",
			"https://clickhouse.example.test/custom", "https://clickhouse.example.test/?secret=visible-secret",
			"https://clickhouse.example.test/#visible-secret",
		} {
			setRequiredConfig(t)
			t.Setenv("ANALYTICS_QUERY_ENABLED", "true")
			t.Setenv("CLICKHOUSE_URL", endpoint)
			_, err := Load()
			if err == nil || !strings.Contains(err.Error(), "CLICKHOUSE_URL") || strings.Contains(err.Error(), "visible-secret") {
				t.Fatal("Load() endpoint validation failed")
			}
		}
	})

	t.Run("credentials", func(t *testing.T) {
		for _, test := range []struct {
			name     string
			database string
			username string
			password string
			want     string
		}{
			{name: "database", username: "analytics", password: "visible-secret", want: "CLICKHOUSE_DATABASE"},
			{name: "padded database", database: " cdnca_analytics ", username: "analytics", password: "visible-secret", want: "CLICKHOUSE_DATABASE"},
			{name: "username", database: "cdnca_analytics", password: "visible-secret", want: "CLICKHOUSE_USERNAME"},
			{name: "control username", database: "cdnca_analytics", username: "analytics\treader", password: "visible-secret", want: "CLICKHOUSE_USERNAME"},
			{name: "password", database: "cdnca_analytics", username: "analytics", want: "CLICKHOUSE_PASSWORD"},
			{name: "newline password", database: "cdnca_analytics", username: "analytics", password: "visible-secret\n", want: "CLICKHOUSE_PASSWORD"},
		} {
			t.Run(test.name, func(t *testing.T) {
				setRequiredConfig(t)
				t.Setenv("ANALYTICS_QUERY_ENABLED", "true")
				t.Setenv("CLICKHOUSE_URL", "https://clickhouse.example.test")
				t.Setenv("CLICKHOUSE_DATABASE", test.database)
				t.Setenv("CLICKHOUSE_USERNAME", test.username)
				t.Setenv("CLICKHOUSE_PASSWORD", test.password)
				_, err := Load()
				if err == nil || !strings.Contains(err.Error(), test.want) || strings.Contains(err.Error(), "visible-secret") {
					t.Fatal("Load() credential validation failed")
				}
			})
		}
	})

	t.Run("database byte boundary", func(t *testing.T) {
		setRequiredConfig(t)
		setValidAnalyticsConfig(t)
		valid := "a" + strings.Repeat("b", analytics.MaxDatabaseIdentifierBytes-1)
		t.Setenv("CLICKHOUSE_DATABASE", valid)
		if cfg, err := Load(); err != nil || cfg.ClickHouseDatabase != valid {
			t.Fatalf("Load() valid database boundary = %q, %v", cfg.ClickHouseDatabase, err)
		}
		setRequiredConfig(t)
		setValidAnalyticsConfig(t)
		t.Setenv("CLICKHOUSE_DATABASE", valid+"c")
		if _, err := Load(); err == nil || !strings.Contains(err.Error(), "CLICKHOUSE_DATABASE") {
			t.Fatalf("Load() oversized database error = %v", err)
		}
	})

	t.Run("bounds", func(t *testing.T) {
		for _, test := range []struct {
			name  string
			env   string
			value string
			want  string
		}{
			{name: "connect timeout", env: "ANALYTICS_CONNECT_TIMEOUT", value: "99ms", want: "timeouts"},
			{name: "query timeout", env: "ANALYTICS_QUERY_TIMEOUT", value: "31s", want: "timeouts"},
			{name: "handler timeout", env: "ANALYTICS_HANDLER_TIMEOUT", value: "5s", want: "timeouts"},
			{name: "query limit", env: "ANALYTICS_QUERY_MAX_RESPONSE_BYTES", value: "4194305", want: "response limits"},
			{name: "handler limit", env: "ANALYTICS_HANDLER_MAX_RESPONSE_BYTES", value: "511", want: "response limits"},
		} {
			t.Run(test.name, func(t *testing.T) {
				setRequiredConfig(t)
				setValidAnalyticsConfig(t)
				t.Setenv(test.env, test.value)
				if _, err := Load(); err == nil || !strings.Contains(err.Error(), test.want) {
					t.Fatalf("Load() bound error = %v", err)
				}
			})
		}
	})

	setRequiredConfig(t)
	setValidAnalyticsConfig(t)
	t.Setenv("CLICKHOUSE_URL", "http://[::1]:8123/")
	t.Setenv("ANALYTICS_CONNECT_TIMEOUT", "2s")
	t.Setenv("ANALYTICS_QUERY_TIMEOUT", "4s")
	t.Setenv("ANALYTICS_HANDLER_TIMEOUT", "5s")
	t.Setenv("ANALYTICS_QUERY_MAX_RESPONSE_BYTES", "2097152")
	t.Setenv("ANALYTICS_HANDLER_MAX_RESPONSE_BYTES", "1048576")
	cfg, err := Load()
	if err != nil {
		t.Fatalf("Load() valid analytics query error = %v", err)
	}
	if !cfg.AnalyticsQueryEnabled || cfg.ClickHouseURL != "http://[::1]:8123/" ||
		cfg.ClickHouseDatabase != "cdnca_analytics" || cfg.ClickHouseUsername != "analytics" ||
		cfg.ClickHousePassword != "visible-secret" || cfg.AnalyticsConnectTimeout != 2*time.Second ||
		cfg.AnalyticsQueryTimeout != 4*time.Second || cfg.AnalyticsHandlerTimeout != 5*time.Second ||
		cfg.AnalyticsQueryMaxResponse != 2<<20 || cfg.AnalyticsHandlerMaxResponse != 1<<20 {
		t.Fatal("loaded analytics query config fields do not match")
	}
}

func TestLoadAnalyticsIngestIsDisabledByDefaultAndIgnoresSecrets(t *testing.T) {
	setRequiredConfig(t)
	t.Setenv("ANALYTICS_INGEST_NATS_URL", "nats://user:visible-secret@remote.example.test:4222")
	t.Setenv("ANALYTICS_INGEST_CLICKHOUSE_URL", "https://user:visible-secret@clickhouse.example.test")
	t.Setenv("ANALYTICS_INGEST_CLICKHOUSE_PASSWORD", "visible-secret")
	cfg, err := Load()
	if err != nil {
		t.Fatalf("Load() disabled analytics ingest error = %v", err)
	}
	if cfg.AnalyticsIngest.Enabled || cfg.AnalyticsIngest.NATSURL != "" ||
		cfg.AnalyticsIngest.ClickHouseURL != "" || cfg.AnalyticsIngest.ClickHousePassword != "" {
		t.Fatal("disabled analytics ingest config fields do not match")
	}
}

func TestLoadEnabledAnalyticsIngestUsesCanonicalOperationBudget(t *testing.T) {
	setRequiredConfig(t)
	setValidAnalyticsIngestConfig(t)

	cfg, err := Load()
	if err != nil {
		t.Fatalf("Load() enabled analytics ingest error = %v", err)
	}
	defaults := analytics.DefaultJetStreamConfig()
	if cfg.AnalyticsIngest.JetStream.OperationTimeout != defaults.OperationTimeout {
		t.Fatalf("analytics ingest operation timeout = %s, want %s",
			cfg.AnalyticsIngest.JetStream.OperationTimeout, defaults.OperationTimeout)
	}
	if cfg.ShutdownPeriod < 2*cfg.AnalyticsIngest.JetStream.OperationTimeout {
		t.Fatalf("shutdown period = %s, want at least twice operation timeout %s",
			cfg.ShutdownPeriod, cfg.AnalyticsIngest.JetStream.OperationTimeout)
	}
}

func TestLoadValidatesEnabledAnalyticsIngest(t *testing.T) {
	t.Run("URLs do not expose credentials", func(t *testing.T) {
		for _, test := range []struct {
			name  string
			env   string
			value string
			want  string
		}{
			{name: "external cleartext NATS", env: "ANALYTICS_INGEST_NATS_URL", value: "nats://nats.example.test:4222", want: "NATS_URL"},
			{name: "NATS userinfo", env: "ANALYTICS_INGEST_NATS_URL", value: "nats://user:visible-secret@127.0.0.1:4222", want: "NATS_URL"},
			{name: "ClickHouse userinfo", env: "ANALYTICS_INGEST_CLICKHOUSE_URL", value: "https://user:visible-secret@clickhouse.example.test", want: "CLICKHOUSE_URL"},
			{name: "ClickHouse query", env: "ANALYTICS_INGEST_CLICKHOUSE_URL", value: "https://clickhouse.example.test/?secret=visible-secret", want: "CLICKHOUSE_URL"},
		} {
			t.Run(test.name, func(t *testing.T) {
				setRequiredConfig(t)
				setValidAnalyticsIngestConfig(t)
				t.Setenv(test.env, test.value)
				_, err := Load()
				if err == nil || !strings.Contains(err.Error(), test.want) || strings.Contains(err.Error(), "visible-secret") {
					t.Fatal("Load() URL validation failed")
				}
			})
		}
	})

	t.Run("credentials", func(t *testing.T) {
		for _, test := range []struct {
			name  string
			env   string
			value string
			want  string
		}{
			{name: "NATS pair", env: "ANALYTICS_INGEST_NATS_PASSWORD", value: "", want: "NATS_USER"},
			{name: "ClickHouse database", env: "ANALYTICS_INGEST_CLICKHOUSE_DATABASE", value: "bad-name", want: "CLICKHOUSE_DATABASE"},
			{name: "ClickHouse user", env: "ANALYTICS_INGEST_CLICKHOUSE_USER", value: "bad\tuser", want: "CLICKHOUSE_USER"},
			{name: "ClickHouse password", env: "ANALYTICS_INGEST_CLICKHOUSE_PASSWORD", value: "visible-secret\n", want: "CLICKHOUSE_PASSWORD"},
		} {
			t.Run(test.name, func(t *testing.T) {
				setRequiredConfig(t)
				setValidAnalyticsIngestConfig(t)
				t.Setenv(test.env, test.value)
				_, err := Load()
				if err == nil || !strings.Contains(err.Error(), test.want) || strings.Contains(err.Error(), "visible-secret") {
					t.Fatal("Load() credential validation failed")
				}
			})
		}
	})

	t.Run("consumer and timeout bounds", func(t *testing.T) {
		for _, test := range []struct {
			name  string
			env   string
			value string
			want  string
		}{
			{name: "connect", env: "ANALYTICS_INGEST_CONNECT_TIMEOUT", value: "99ms", want: "timeouts"},
			{name: "write", env: "ANALYTICS_INGEST_WRITE_TIMEOUT", value: "11s", want: "timeout limits"},
			{name: "supervisor", env: "ANALYTICS_INGEST_SUPERVISOR_BACKOFF_MAX", value: "500ms", want: "timeouts"},
			{name: "stream", env: "ANALYTICS_INGEST_STREAM", value: "bad.stream", want: "JetStream"},
			{name: "fetch batch", env: "ANALYTICS_INGEST_FETCH_BATCH", value: "257", want: "JetStream"},
			{name: "operation shutdown", env: "ANALYTICS_INGEST_OPERATION_TIMEOUT", value: "11s", want: "JetStream"},
		} {
			t.Run(test.name, func(t *testing.T) {
				setRequiredConfig(t)
				setValidAnalyticsIngestConfig(t)
				t.Setenv(test.env, test.value)
				_, err := Load()
				if err == nil || !strings.Contains(err.Error(), test.want) {
					t.Fatalf("Load() bound error = %v", err)
				}
			})
		}
	})

	setRequiredConfig(t)
	setValidAnalyticsIngestConfig(t)
	t.Setenv("ANALYTICS_INGEST_CONNECT_TIMEOUT", "2s")
	t.Setenv("ANALYTICS_INGEST_WRITE_TIMEOUT", "1500ms")
	t.Setenv("ANALYTICS_INGEST_OPERATION_TIMEOUT", "2s")
	t.Setenv("ANALYTICS_INGEST_FETCH_BATCH", "8")
	t.Setenv("ANALYTICS_INGEST_MAX_ACK_PENDING", "16")
	t.Setenv("ANALYTICS_INGEST_REPLICAS", "2")
	cfg, err := Load()
	if err != nil {
		t.Fatalf("Load() valid analytics ingest error = %v", err)
	}
	ingest := cfg.AnalyticsIngest
	if !ingest.Enabled || ingest.NATSURL != "tls://nats.example.test:4222" ||
		ingest.NATSUsername != "analytics" || ingest.NATSPassword != "visible-secret" ||
		ingest.ClickHouseURL != "https://clickhouse.example.test" || ingest.ClickHouseDatabase != "cdnca_analytics" ||
		ingest.ConnectTimeout != 2*time.Second || ingest.WriteTimeout != 1500*time.Millisecond ||
		ingest.JetStream.OperationTimeout != 2*time.Second || ingest.JetStream.FetchBatch != 8 ||
		ingest.JetStream.MaxAckPending != 16 || ingest.JetStream.Replicas != 2 {
		t.Fatal("loaded analytics ingest config fields do not match")
	}
}

func TestLoadJobQueryIsDisabledByDefaultAndIgnoresSecrets(t *testing.T) {
	setRequiredConfig(t)
	t.Setenv("JOB_QUERY_CURSOR_ACTIVE_KEY_ID", "visible-key-id")
	t.Setenv("JOB_QUERY_CURSOR_KEYS_JSON", `{"visible-key-id":"visible-secret"}`)
	cfg, err := Load()
	if err != nil {
		t.Fatalf("Load() disabled job query error = %v", err)
	}
	if cfg.JobQueryEnabled || cfg.JobQueryCursorActiveKeyID != "" || cfg.JobQueryCursorKeys != nil {
		t.Fatal("disabled job query config fields do not match")
	}
}

func TestLoadValidatesEnabledJobQuery(t *testing.T) {
	tests := []struct {
		name  string
		env   string
		value string
		want  string
	}{
		{name: "missing active key", env: "JOB_QUERY_CURSOR_ACTIVE_KEY_ID", value: "", want: "ACTIVE_KEY_ID"},
		{name: "invalid active key", env: "JOB_QUERY_CURSOR_ACTIVE_KEY_ID", value: "invalid key", want: "ACTIVE_KEY_ID"},
		{name: "malformed keyset", env: "JOB_QUERY_CURSOR_KEYS_JSON", value: "{", want: "KEYS_JSON"},
		{name: "short key", env: "JOB_QUERY_CURSOR_KEYS_JSON", value: `{"active":"c2hvcnQ="}`, want: "at least 32 bytes"},
		{name: "missing selected key", env: "JOB_QUERY_CURSOR_ACTIVE_KEY_ID", value: "missing", want: "configured cursor key"},
		{name: "timeout", env: "JOB_QUERY_TIMEOUT", value: "31s", want: "at most 30s"},
		{name: "response size", env: "JOB_QUERY_MAX_RESPONSE_BYTES", value: "511", want: "between 512"},
	}
	for _, test := range tests {
		t.Run(test.name, func(t *testing.T) {
			setRequiredConfig(t)
			setValidJobQueryConfig(t)
			t.Setenv(test.env, test.value)
			if _, err := Load(); err == nil || !strings.Contains(err.Error(), test.want) {
				t.Fatalf("Load() job query error = %v", err)
			}
		})
	}

	setRequiredConfig(t)
	setValidJobQueryConfig(t)
	t.Setenv("JOB_QUERY_TIMEOUT", "7s")
	t.Setenv("JOB_QUERY_MAX_RESPONSE_BYTES", "2097152")
	cfg, err := Load()
	if err != nil {
		t.Fatalf("Load() valid job query error = %v", err)
	}
	if !cfg.JobQueryEnabled || cfg.JobQueryCursorActiveKeyID != "active" ||
		len(cfg.JobQueryCursorKeys) != 1 || len(cfg.JobQueryCursorKeys["active"]) != 32 ||
		cfg.JobQueryTimeout != 7*time.Second || cfg.JobQueryMaxResponse != 2<<20 {
		t.Fatal("loaded job query config fields do not match")
	}
}

func setValidAnalyticsConfig(t *testing.T) {
	t.Helper()
	t.Setenv("ANALYTICS_QUERY_ENABLED", "true")
	t.Setenv("CLICKHOUSE_URL", "https://clickhouse.example.test")
	t.Setenv("CLICKHOUSE_DATABASE", "cdnca_analytics")
	t.Setenv("CLICKHOUSE_USERNAME", "analytics")
	t.Setenv("CLICKHOUSE_PASSWORD", "visible-secret")
}

func setValidAnalyticsIngestConfig(t *testing.T) {
	t.Helper()
	t.Setenv("ANALYTICS_INGEST_ENABLED", "true")
	t.Setenv("ANALYTICS_INGEST_NATS_URL", "tls://nats.example.test:4222")
	t.Setenv("ANALYTICS_INGEST_NATS_USER", "analytics")
	t.Setenv("ANALYTICS_INGEST_NATS_PASSWORD", "visible-secret")
	t.Setenv("ANALYTICS_INGEST_CLICKHOUSE_URL", "https://clickhouse.example.test")
	t.Setenv("ANALYTICS_INGEST_CLICKHOUSE_DATABASE", "cdnca_analytics")
	t.Setenv("ANALYTICS_INGEST_CLICKHOUSE_USER", "analytics")
	t.Setenv("ANALYTICS_INGEST_CLICKHOUSE_PASSWORD", "visible-secret")
}

func setValidJobQueryConfig(t *testing.T) {
	t.Helper()
	key := base64.StdEncoding.EncodeToString(bytes.Repeat([]byte{11}, 32))
	t.Setenv("JOB_QUERY_ENABLED", "true")
	t.Setenv("JOB_QUERY_CURSOR_ACTIVE_KEY_ID", "active")
	t.Setenv("JOB_QUERY_CURSOR_KEYS_JSON", `{"active":"`+key+`"}`)
}

func setRequiredConfig(t *testing.T) {
	t.Helper()
	t.Setenv("DATABASE_URL", "postgres://test.invalid/test")
	t.Setenv("ACCESS_TOKEN_SECRET", "test-access-token-secret-at-least-thirty-two-bytes")
	t.Setenv("API_KEY_PEPPER_BASE64", base64.StdEncoding.EncodeToString(bytes.Repeat([]byte{7}, 32)))
	t.Setenv("API_KEY_PEPPER_VERSION", "legacy-v1")
	t.Setenv("API_KEY_PREVIOUS_PEPPER_VERSION", "")
	t.Setenv("API_KEY_PREVIOUS_PEPPER_BASE64", "")
	t.Setenv("API_KEY_TRUSTED_PROXY_CIDRS", "")
	t.Setenv("API_KEY_MAX_PROXY_HOPS", "")
	t.Setenv("DNS_CREDENTIAL_KEY_ID", "dns-test")
	t.Setenv("DNS_CREDENTIAL_KEY_BASE64", base64.StdEncoding.EncodeToString(make([]byte, 32)))
	t.Setenv("EDGE_DEPLOYMENT_NATS_URL", "nats://127.0.0.1:4222")
	t.Setenv("CONTROL_INTERNAL_GRPC_ADDR", "127.0.0.1:9091")
	t.Setenv("CONTROL_INTERNAL_SERVER_CERT_FILE", "/run/secrets/control-internal-server-cert.pem")
	t.Setenv("CONTROL_INTERNAL_SERVER_PRIVATE_KEY_FILE", "/run/secrets/control-internal-server-key.pem")
	t.Setenv("CONTROL_INTERNAL_GATEWAY_CLIENT_CA_FILE", "/run/secrets/control-internal-gateway-ca.pem")
	t.Setenv("CONTROL_INTERNAL_GATEWAY_WORKLOAD_URI_SAN", "spiffe://cdn-platform/gateway/control")
	t.Setenv("NODE_CA_CERTIFICATE_CHAIN_FILE", "/run/secrets/node-ca-chain.pem")
	t.Setenv("NODE_CA_PRIVATE_KEY_FILE", "/run/secrets/node-ca-key.pem")
	// Keep unrelated optional settings deterministic if the developer shell defines them.
	t.Setenv("ACCESS_TOKEN_TTL", "")
	t.Setenv("REFRESH_TOKEN_TTL", "")
	t.Setenv("COOKIE_SECURE", "")
	t.Setenv("LICENSE_SERVICE_URL", "")
	t.Setenv("ENTITLEMENT_SYNC_BACKOFF_MIN", "")
	t.Setenv("ENTITLEMENT_SYNC_BACKOFF_MAX", "")
	t.Setenv("CONTROL_VERSION", "")
	t.Setenv("PLATFORM_POLICY_PROTOCOL_VERSION", "")
	t.Setenv("PLATFORM_POLICY_SYNC_INTERVAL", "")
	t.Setenv("ACME_RUNTIME_ENABLED", "")
	t.Setenv("ACME_DIRECTORY_URL", "")
	t.Setenv("ACME_BACKUP_DIRECTORY_URL", "")
	t.Setenv("ACME_CONTACTS", "")
	t.Setenv("ACME_WRAPPING_KEY_ID", "")
	t.Setenv("ACME_WRAPPING_KEY_BASE64", "")
	t.Setenv("ACME_POLL_INTERVAL", "")
	t.Setenv("ACME_LEASE_DURATION", "")
	t.Setenv("ACME_SETTLE_TIMEOUT", "")
	t.Setenv("ACME_RETRY_BASE", "")
	t.Setenv("ACME_RETRY_MAXIMUM", "")
	t.Setenv("ACME_MAX_ATTEMPTS", "")
	t.Setenv("ACME_ERROR_BACKOFF_MIN", "")
	t.Setenv("ACME_ERROR_BACKOFF_MAX", "")
	t.Setenv("ANALYTICS_QUERY_ENABLED", "")
	t.Setenv("CLICKHOUSE_URL", "")
	t.Setenv("CLICKHOUSE_DATABASE", "")
	t.Setenv("CLICKHOUSE_USERNAME", "")
	t.Setenv("CLICKHOUSE_PASSWORD", "")
	t.Setenv("ANALYTICS_CONNECT_TIMEOUT", "")
	t.Setenv("ANALYTICS_QUERY_TIMEOUT", "")
	t.Setenv("ANALYTICS_HANDLER_TIMEOUT", "")
	t.Setenv("ANALYTICS_QUERY_MAX_RESPONSE_BYTES", "")
	t.Setenv("ANALYTICS_HANDLER_MAX_RESPONSE_BYTES", "")
	t.Setenv("ANALYTICS_INGEST_ENABLED", "")
	t.Setenv("ANALYTICS_INGEST_NATS_URL", "")
	t.Setenv("ANALYTICS_INGEST_NATS_USER", "")
	t.Setenv("ANALYTICS_INGEST_NATS_PASSWORD", "")
	t.Setenv("ANALYTICS_INGEST_CLICKHOUSE_URL", "")
	t.Setenv("ANALYTICS_INGEST_CLICKHOUSE_DATABASE", "")
	t.Setenv("ANALYTICS_INGEST_CLICKHOUSE_USER", "")
	t.Setenv("ANALYTICS_INGEST_CLICKHOUSE_PASSWORD", "")
	t.Setenv("ANALYTICS_INGEST_CONNECT_TIMEOUT", "")
	t.Setenv("ANALYTICS_INGEST_WRITE_TIMEOUT", "")
	t.Setenv("ANALYTICS_INGEST_SUPERVISOR_BACKOFF_MIN", "")
	t.Setenv("ANALYTICS_INGEST_SUPERVISOR_BACKOFF_MAX", "")
	t.Setenv("ANALYTICS_INGEST_STREAM", "")
	t.Setenv("ANALYTICS_INGEST_DURABLE", "")
	t.Setenv("ANALYTICS_INGEST_ISOLATION_STREAM", "")
	t.Setenv("ANALYTICS_INGEST_ACK_WAIT", "")
	t.Setenv("ANALYTICS_INGEST_FETCH_TIMEOUT", "")
	t.Setenv("ANALYTICS_INGEST_OPERATION_TIMEOUT", "")
	t.Setenv("ANALYTICS_INGEST_NAK_BASE_DELAY", "")
	t.Setenv("ANALYTICS_INGEST_NAK_MAX_DELAY", "")
	t.Setenv("ANALYTICS_INGEST_MAX_DELIVER", "")
	t.Setenv("ANALYTICS_INGEST_MAX_ACK_PENDING", "")
	t.Setenv("ANALYTICS_INGEST_MAX_WAITING", "")
	t.Setenv("ANALYTICS_INGEST_FETCH_BATCH", "")
	t.Setenv("ANALYTICS_INGEST_STREAM_MAX_AGE", "")
	t.Setenv("ANALYTICS_INGEST_STREAM_MAX_BYTES", "")
	t.Setenv("ANALYTICS_INGEST_STREAM_MAX_MESSAGES", "")
	t.Setenv("ANALYTICS_INGEST_ISOLATION_MAX_AGE", "")
	t.Setenv("ANALYTICS_INGEST_ISOLATION_MAX_BYTES", "")
	t.Setenv("ANALYTICS_INGEST_DUPLICATE_WINDOW", "")
	t.Setenv("ANALYTICS_INGEST_REPLICAS", "")
	t.Setenv("JOB_QUERY_ENABLED", "")
	t.Setenv("JOB_QUERY_CURSOR_ACTIVE_KEY_ID", "")
	t.Setenv("JOB_QUERY_CURSOR_KEYS_JSON", "")
	t.Setenv("JOB_QUERY_TIMEOUT", "")
	t.Setenv("JOB_QUERY_MAX_RESPONSE_BYTES", "")
	t.Setenv("NODE_PRESENCE_NATS_URL", "")
	t.Setenv("NODE_PRESENCE_REDIS_URL", "")
	t.Setenv("EDGE_DEPLOYMENT_NATS_CREDS_FILE", "")
	t.Setenv("EDGE_DEPLOYMENT_NATS_CA_FILE", "")
	t.Setenv("EDGE_DEPLOYMENT_NATS_CONNECT_TIMEOUT", "")
	t.Setenv("EDGE_COMMAND_STREAM", "")
	t.Setenv("EDGE_COMMAND_SUBJECT_PREFIX", "")
	t.Setenv("EDGE_OUTBOX_BATCH_SIZE", "")
	t.Setenv("EDGE_OUTBOX_LEASE_TIMEOUT", "")
	t.Setenv("EDGE_OUTBOX_OPERATION_TIMEOUT", "")
	t.Setenv("EDGE_OUTBOX_POLL_INTERVAL", "")
	t.Setenv("EDGE_OUTBOX_BASE_BACKOFF", "")
	t.Setenv("EDGE_OUTBOX_MAX_BACKOFF", "")
	t.Setenv("EDGE_OUTBOX_MAX_PAYLOAD_BYTES", "")
	t.Setenv("EDGE_OUTBOX_MAX_ERROR_BYTES", "")
	t.Setenv("EDGE_STATUS_STREAM", "")
	t.Setenv("EDGE_STATUS_SUBJECT_PREFIX", "")
	t.Setenv("EDGE_STATUS_DURABLE", "")
	t.Setenv("EDGE_STATUS_ACK_WAIT", "")
	t.Setenv("EDGE_STATUS_FETCH_TIMEOUT", "")
	t.Setenv("EDGE_STATUS_OPERATION_TIMEOUT", "")
	t.Setenv("EDGE_STATUS_NAK_DELAY", "")
	t.Setenv("EDGE_STATUS_MAX_ACK_PENDING", "")
	t.Setenv("EDGE_STATUS_MAX_WAITING", "")
	t.Setenv("EDGE_STATUS_MAX_BYTES", "")
	t.Setenv("EDGE_STATUS_MAX_CHECKS", "")
	t.Setenv("EDGE_STATUS_MAX_METADATA_BYTES", "")
	t.Setenv("EDGE_STATUS_MAX_FUTURE_SKEW", "")
}
