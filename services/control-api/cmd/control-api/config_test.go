package main

import (
	"bytes"
	"encoding/base64"
	"strings"
	"testing"
	"time"
)

func TestAccountRecoveryRuntimeConfigIsDisabledByDefaultAndIgnoresSecrets(t *testing.T) {
	environment := map[string]string{
		"ACCOUNT_RECOVERY_HMAC_KEY_BASE64": "must-not-be-parsed",
		"ACCOUNT_RECOVERY_KEK_KEYS_JSON":   "must-not-be-parsed",
	}
	config, err := loadAccountRecoveryRuntimeConfigFromEnv(mapAccountRecoveryEnv(environment))
	if err != nil {
		t.Fatalf("load disabled account recovery config: %v", err)
	}
	if config.Enabled || config.DigestKey != nil || config.DispatchKeys != nil || config.RecoveryURL != "" {
		t.Fatalf("disabled account recovery config = %#v", config)
	}
}

func TestAccountRecoveryRuntimeConfigLoadsStrictCompleteConfiguration(t *testing.T) {
	environment := validAccountRecoveryEnvironment()
	environment["ACCOUNT_RECOVERY_TOKEN_TTL"] = "20m"
	environment["ACCOUNT_RECOVERY_RATE_WINDOW"] = "30m"
	environment["ACCOUNT_RECOVERY_SUBJECT_LIMIT"] = "7"
	environment["ACCOUNT_RECOVERY_SOURCE_LIMIT"] = "31"
	environment["ACCOUNT_RECOVERY_HANDLER_TIMEOUT"] = "3s"
	environment["ACCOUNT_RECOVERY_STARTUP_TIMEOUT"] = "4s"
	environment["ACCOUNT_RECOVERY_SHUTDOWN_PERIOD"] = "2s"
	environment["ACCOUNT_RECOVERY_TRUSTED_PROXY_CIDRS"] = "10.0.0.0/8,2001:db8::/32"
	environment["ACCOUNT_RECOVERY_PLATFORM_HOSTS"] = "203.0.113.73,console.example.test"
	environment["ACCOUNT_RECOVERY_ALLOW_PRIVATE_SOURCE_IP"] = "true"
	environment["ACCOUNT_RECOVERY_MAX_PROXY_HOPS"] = "8"
	environment["ACCOUNT_RECOVERY_SMS_TEMPLATE_ID"] = "account_recovery_sms"
	environment["ACCOUNT_RECOVERY_SMS_TEMPLATE_VERSION"] = "2"

	config, err := loadAccountRecoveryRuntimeConfigFromEnv(mapAccountRecoveryEnv(environment))
	if err != nil {
		t.Fatalf("load enabled account recovery config: %v", err)
	}
	if !config.Enabled || len(config.DigestKey) != 32 || config.DispatchKeys == nil ||
		config.RecoveryURL != "https://console.example.test/reset" || config.TokenTTL != 20*time.Minute ||
		config.RateWindow != 30*time.Minute || config.SubjectLimit != 7 || config.SourceLimit != 31 ||
		config.HandlerTimeout != 3*time.Second || config.StartupTimeout != 4*time.Second ||
		config.ShutdownPeriod != 2*time.Second || len(config.TrustedProxyCIDRs) != 2 ||
		config.TrustedProxyCIDRs[0] != "10.0.0.0/8" || config.TrustedProxyCIDRs[1] != "2001:db8::/32" ||
		len(config.PlatformHosts) != 2 || config.PlatformHosts[0] != "203.0.113.73" ||
		config.PlatformHosts[1] != "console.example.test" ||
		!config.AllowPrivateSourceIP || config.MaxProxyHops != 8 || len(config.Templates) != 2 {
		t.Fatalf("enabled account recovery config = %#v", config)
	}
	config.clearSecrets()
	if config.DigestKey != nil || config.DispatchKeys != nil {
		t.Fatalf("clearSecrets() retained key references: %#v", config)
	}
}

func TestAccountRecoveryRuntimeConfigRejectsInvalidEnabledConfigurationWithoutLeakingValues(t *testing.T) {
	secret := "do-not-print-this-secret"
	tests := []struct {
		name   string
		mutate func(map[string]string)
	}{
		{name: "boolean", mutate: func(env map[string]string) { env["ACCOUNT_RECOVERY_ENABLED"] = "1" }},
		{name: "missing HMAC", mutate: func(env map[string]string) { delete(env, "ACCOUNT_RECOVERY_HMAC_KEY_BASE64") }},
		{name: "short HMAC", mutate: func(env map[string]string) {
			env["ACCOUNT_RECOVERY_HMAC_KEY_BASE64"] = base64.StdEncoding.EncodeToString([]byte(secret))
		}},
		{name: "duplicate KEK", mutate: func(env map[string]string) {
			encoded := canonicalAccountRecoveryTestKey(0x22)
			env["ACCOUNT_RECOVERY_KEK_KEYS_JSON"] = `{"primary":"` + encoded + `","primary":"` + encoded + `"}`
		}},
		{name: "missing active KEK", mutate: func(env map[string]string) {
			env["ACCOUNT_RECOVERY_KEK_ACTIVE_KEY_ID"] = "missing"
		}},
		{name: "URL credentials", mutate: func(env map[string]string) {
			env["ACCOUNT_RECOVERY_BASE_URL"] = "https://" + secret + "@console.example.test/reset"
		}},
		{name: "URL query", mutate: func(env map[string]string) {
			env["ACCOUNT_RECOVERY_BASE_URL"] = "https://console.example.test/reset?token=" + secret
		}},
		{name: "token TTL", mutate: func(env map[string]string) { env["ACCOUNT_RECOVERY_TOKEN_TTL"] = "61m" }},
		{name: "rate window", mutate: func(env map[string]string) { env["ACCOUNT_RECOVERY_RATE_WINDOW"] = "0s" }},
		{name: "subject limit", mutate: func(env map[string]string) { env["ACCOUNT_RECOVERY_SUBJECT_LIMIT"] = "01" }},
		{name: "private source boolean", mutate: func(env map[string]string) {
			env["ACCOUNT_RECOVERY_ALLOW_PRIVATE_SOURCE_IP"] = "1"
		}},
		{name: "proxy hops", mutate: func(env map[string]string) { env["ACCOUNT_RECOVERY_MAX_PROXY_HOPS"] = "65" }},
		{name: "proxy list whitespace", mutate: func(env map[string]string) {
			env["ACCOUNT_RECOVERY_TRUSTED_PROXY_CIDRS"] = "10.0.0.0/8, 2001:db8::/32"
		}},
		{name: "duplicate proxy", mutate: func(env map[string]string) {
			env["ACCOUNT_RECOVERY_TRUSTED_PROXY_CIDRS"] = "10.0.0.0/8,10.0.0.0/8"
		}},
		{name: "non canonical proxy", mutate: func(env map[string]string) {
			env["ACCOUNT_RECOVERY_TRUSTED_PROXY_CIDRS"] = "10.0.0.1/8"
		}},
		{name: "all addresses proxy", mutate: func(env map[string]string) {
			env["ACCOUNT_RECOVERY_TRUSTED_PROXY_CIDRS"] = "0.0.0.0/0"
		}},
		{name: "mapped proxy", mutate: func(env map[string]string) {
			env["ACCOUNT_RECOVERY_TRUSTED_PROXY_CIDRS"] = "::ffff:10.0.0.0/104"
		}},
		{name: "platform host list whitespace", mutate: func(env map[string]string) {
			env["ACCOUNT_RECOVERY_PLATFORM_HOSTS"] = "203.0.113.73, console.example.test"
		}},
		{name: "missing template version", mutate: func(env map[string]string) {
			delete(env, "ACCOUNT_RECOVERY_EMAIL_TEMPLATE_VERSION")
		}},
		{name: "no template", mutate: func(env map[string]string) {
			delete(env, "ACCOUNT_RECOVERY_EMAIL_TEMPLATE_ID")
			delete(env, "ACCOUNT_RECOVERY_EMAIL_TEMPLATE_VERSION")
		}},
		{name: "trailing keyring content", mutate: func(env map[string]string) {
			env["ACCOUNT_RECOVERY_KEK_KEYS_JSON"] += secret
		}},
	}
	for _, test := range tests {
		t.Run(test.name, func(t *testing.T) {
			environment := validAccountRecoveryEnvironment()
			test.mutate(environment)
			_, err := loadAccountRecoveryRuntimeConfigFromEnv(mapAccountRecoveryEnv(environment))
			if err == nil {
				t.Fatal("invalid account recovery configuration was accepted")
			}
			if strings.Contains(err.Error(), secret) {
				t.Fatalf("configuration error leaked a secret: %v", err)
			}
		})
	}
}

func TestCacheControlProductionConfigDisabledIgnoresRuntimeValues(t *testing.T) {
	environment := map[string]string{
		"CACHE_CONTROL_RUNTIME_NATS_URL":          "not a URL",
		"CACHE_CONTROL_RUNTIME_CURSOR_KEY_BASE64": "not base64",
		"CACHE_CONTROL_RUNTIME_COMMAND_STREAM":    "not a stream",
		"CACHE_CONTROL_RUNTIME_MAX_PAYLOAD_BYTES": "not an integer",
		"CACHE_CONTROL_RUNTIME_OPERATION_TIMEOUT": "not a duration",
	}
	config, err := loadCacheControlProductionConfigFromEnv(mapAccountRecoveryEnv(environment))
	if err != nil {
		t.Fatalf("load disabled cache control config: %v", err)
	}
	if config.Runtime.Enabled || config.NATSURL != "" || config.Runtime.CursorKey != nil {
		t.Fatalf("disabled cache control config = %#v", config)
	}
}

func TestCacheControlProductionConfigLoadsExactRuntimeValues(t *testing.T) {
	environment := validCacheControlProductionEnvironment()
	environment["CACHE_CONTROL_RUNTIME_POLL_INTERVAL"] = "750ms"
	environment["CACHE_CONTROL_RUNTIME_FETCH_TIMEOUT"] = "3s"
	environment["CACHE_CONTROL_RUNTIME_OPERATION_TIMEOUT"] = "4s"
	environment["CACHE_CONTROL_RUNTIME_LEASE_DURATION"] = "45m"
	environment["CACHE_CONTROL_RUNTIME_ACK_WAIT"] = "90s"
	environment["CACHE_CONTROL_RUNTIME_NAK_BASE_DELAY"] = "2s"
	environment["CACHE_CONTROL_RUNTIME_NAK_MAXIMUM_DELAY"] = "20s"
	environment["CACHE_CONTROL_RUNTIME_CLAIM_BATCH"] = "8"
	environment["CACHE_CONTROL_RUNTIME_MAX_DELIVER"] = "7"
	environment["CACHE_CONTROL_RUNTIME_MAX_ACK_PENDING"] = "32"
	environment["CACHE_CONTROL_RUNTIME_MAX_WAITING"] = "12"
	environment["CACHE_CONTROL_RUNTIME_MAX_PAYLOAD_BYTES"] = "524288"
	environment["CACHE_CONTROL_RUNTIME_NATS_CONNECT_TIMEOUT"] = "4s"
	environment["CACHE_CONTROL_RUNTIME_NATS_RECONNECT_WAIT"] = "2s"
	environment["CACHE_CONTROL_RUNTIME_NATS_DRAIN_TIMEOUT"] = "6s"
	environment["CACHE_CONTROL_RUNTIME_STREAM_REPLICAS"] = "3"

	config, err := loadCacheControlProductionConfigFromEnv(mapAccountRecoveryEnv(environment))
	if err != nil {
		t.Fatalf("load enabled cache control config: %v", err)
	}
	worker := config.Runtime.Worker
	if !config.Runtime.Enabled || config.NATSURL != "nats://cache.example.test:4222" ||
		config.NATSName != "cdnca-control-api-cache-control" || config.NATSConnectTimeout != 4*time.Second ||
		config.NATSReconnectWait != 2*time.Second || config.NATSDrainTimeout != 6*time.Second ||
		len(config.Runtime.CursorKey) != 32 || worker.CommandStream != "CACHE_COMMANDS" ||
		worker.StatusStream != "CACHE_STATUS" || worker.CommandSubjectPrefix != "cdnca.agent.commands.cache" ||
		worker.StatusSubjectPrefix != "cdnca.agent.deployment-status.cache" ||
		worker.DLQSubjectPrefix != "cdnca.agent.deployment-status.cache-dlq" ||
		worker.Durable != "control_api_cache_status" || worker.WorkerID != "control-api-cache-runtime" ||
		worker.PollInterval != 750*time.Millisecond || worker.FetchTimeout != 3*time.Second ||
		worker.OperationTimeout != 4*time.Second || worker.LeaseDuration != 45*time.Minute ||
		worker.AckWait != 90*time.Second || worker.NakBaseDelay != 2*time.Second ||
		worker.NakMaximumDelay != 20*time.Second || worker.ClaimBatch != 8 || worker.MaxDeliver != 7 ||
		worker.MaxAckPending != 32 || worker.MaxWaiting != 12 || worker.MaxPayloadBytes != 524288 ||
		worker.Replicas != 3 || worker.Clock == nil {
		t.Fatalf("enabled cache control config = %#v", config)
	}
	config.clearSecrets()
	if config.Runtime.CursorKey != nil {
		t.Fatal("cache control config retained cursor key")
	}
}

// The native installer leaves CACHE_CONTROL_RUNTIME_STREAM_REPLICAS unset;
// single-host NATS streams have one replica, so the default must be 1.
func TestCacheControlProductionConfigDefaultsToSingleReplicaStreams(t *testing.T) {
	config, err := loadCacheControlProductionConfigFromEnv(mapAccountRecoveryEnv(validCacheControlProductionEnvironment()))
	defer config.clearSecrets()
	if err != nil {
		t.Fatal(err)
	}
	if config.Runtime.Worker.Replicas != 1 {
		t.Fatalf("default cache stream replicas = %d, want 1", config.Runtime.Worker.Replicas)
	}
}

func TestCacheControlProductionConfigRejectsInvalidEnabledValues(t *testing.T) {
	secret := "cache-control-config-secret"
	tests := []struct {
		name   string
		mutate func(map[string]string)
	}{
		{name: "boolean", mutate: func(env map[string]string) { env["CACHE_CONTROL_RUNTIME_ENABLED"] = "1" }},
		{name: "missing NATS URL", mutate: func(env map[string]string) { delete(env, "CACHE_CONTROL_RUNTIME_NATS_URL") }},
		{name: "padded NATS URL", mutate: func(env map[string]string) { env["CACHE_CONTROL_RUNTIME_NATS_URL"] = " nats://cache.example.test:4222" }},
		{name: "missing NATS name", mutate: func(env map[string]string) { delete(env, "CACHE_CONTROL_RUNTIME_NATS_NAME") }},
		{name: "missing cursor key", mutate: func(env map[string]string) { delete(env, "CACHE_CONTROL_RUNTIME_CURSOR_KEY_BASE64") }},
		{name: "invalid cursor key", mutate: func(env map[string]string) { env["CACHE_CONTROL_RUNTIME_CURSOR_KEY_BASE64"] = secret }},
		{name: "short cursor key", mutate: func(env map[string]string) {
			env["CACHE_CONTROL_RUNTIME_CURSOR_KEY_BASE64"] = base64.StdEncoding.EncodeToString([]byte(secret))
		}},
		{name: "missing command stream", mutate: func(env map[string]string) { delete(env, "CACHE_CONTROL_RUNTIME_COMMAND_STREAM") }},
		{name: "missing status stream", mutate: func(env map[string]string) { delete(env, "CACHE_CONTROL_RUNTIME_STATUS_STREAM") }},
		{name: "missing command subject", mutate: func(env map[string]string) { delete(env, "CACHE_CONTROL_RUNTIME_COMMAND_SUBJECT_PREFIX") }},
		{name: "missing status subject", mutate: func(env map[string]string) { delete(env, "CACHE_CONTROL_RUNTIME_STATUS_SUBJECT_PREFIX") }},
		{name: "missing DLQ subject", mutate: func(env map[string]string) { delete(env, "CACHE_CONTROL_RUNTIME_DLQ_SUBJECT_PREFIX") }},
		{name: "missing durable", mutate: func(env map[string]string) { delete(env, "CACHE_CONTROL_RUNTIME_DURABLE") }},
		{name: "missing worker", mutate: func(env map[string]string) { delete(env, "CACHE_CONTROL_RUNTIME_WORKER_ID") }},
		{name: "duration", mutate: func(env map[string]string) { env["CACHE_CONTROL_RUNTIME_FETCH_TIMEOUT"] = "0s" }},
		{name: "integer", mutate: func(env map[string]string) { env["CACHE_CONTROL_RUNTIME_CLAIM_BATCH"] = "01" }},
		{name: "zero replicas", mutate: func(env map[string]string) { env["CACHE_CONTROL_RUNTIME_STREAM_REPLICAS"] = "0" }},
		{name: "too many replicas", mutate: func(env map[string]string) { env["CACHE_CONTROL_RUNTIME_STREAM_REPLICAS"] = "6" }},
		{name: "cross-field ack pending", mutate: func(env map[string]string) {
			env["CACHE_CONTROL_RUNTIME_CLAIM_BATCH"] = "16"
			env["CACHE_CONTROL_RUNTIME_MAX_ACK_PENDING"] = "8"
		}},
		{name: "cross-field NAK delay", mutate: func(env map[string]string) {
			env["CACHE_CONTROL_RUNTIME_NAK_BASE_DELAY"] = "10s"
			env["CACHE_CONTROL_RUNTIME_NAK_MAXIMUM_DELAY"] = "5s"
		}},
		{name: "same streams", mutate: func(env map[string]string) {
			env["CACHE_CONTROL_RUNTIME_STATUS_STREAM"] = env["CACHE_CONTROL_RUNTIME_COMMAND_STREAM"]
		}},
		{name: "same subjects", mutate: func(env map[string]string) {
			env["CACHE_CONTROL_RUNTIME_DLQ_SUBJECT_PREFIX"] = env["CACHE_CONTROL_RUNTIME_STATUS_SUBJECT_PREFIX"]
		}},
	}
	for _, test := range tests {
		t.Run(test.name, func(t *testing.T) {
			environment := validCacheControlProductionEnvironment()
			test.mutate(environment)
			config, err := loadCacheControlProductionConfigFromEnv(mapAccountRecoveryEnv(environment))
			config.clearSecrets()
			if err == nil {
				t.Fatal("invalid cache control configuration was accepted")
			}
			if strings.Contains(err.Error(), secret) {
				t.Fatalf("configuration error leaked a secret: %v", err)
			}
		})
	}
}

func validAccountRecoveryEnvironment() map[string]string {
	return map[string]string{
		"ACCOUNT_RECOVERY_ENABLED":                "true",
		"ACCOUNT_RECOVERY_HMAC_KEY_BASE64":        canonicalAccountRecoveryTestKey(0x11),
		"ACCOUNT_RECOVERY_KEK_ACTIVE_KEY_ID":      "primary",
		"ACCOUNT_RECOVERY_KEK_KEYS_JSON":          `{"primary":"` + canonicalAccountRecoveryTestKey(0x22) + `"}`,
		"ACCOUNT_RECOVERY_BASE_URL":               "https://console.example.test/reset",
		"ACCOUNT_RECOVERY_EMAIL_TEMPLATE_ID":      "account_recovery_email",
		"ACCOUNT_RECOVERY_EMAIL_TEMPLATE_VERSION": "1",
	}
}

func validCacheControlProductionEnvironment() map[string]string {
	return map[string]string{
		"CACHE_CONTROL_RUNTIME_ENABLED":                "true",
		"CACHE_CONTROL_RUNTIME_NATS_URL":               "nats://cache.example.test:4222",
		"CACHE_CONTROL_RUNTIME_NATS_NAME":              "cdnca-control-api-cache-control",
		"CACHE_CONTROL_RUNTIME_CURSOR_KEY_BASE64":      canonicalAccountRecoveryTestKey(0x33),
		"CACHE_CONTROL_RUNTIME_COMMAND_STREAM":         "CACHE_COMMANDS",
		"CACHE_CONTROL_RUNTIME_STATUS_STREAM":          "CACHE_STATUS",
		"CACHE_CONTROL_RUNTIME_COMMAND_SUBJECT_PREFIX": "cdnca.agent.commands.cache",
		"CACHE_CONTROL_RUNTIME_STATUS_SUBJECT_PREFIX":  "cdnca.agent.deployment-status.cache",
		"CACHE_CONTROL_RUNTIME_DLQ_SUBJECT_PREFIX":     "cdnca.agent.deployment-status.cache-dlq",
		"CACHE_CONTROL_RUNTIME_DURABLE":                "control_api_cache_status",
		"CACHE_CONTROL_RUNTIME_WORKER_ID":              "control-api-cache-runtime",
	}
}

func canonicalAccountRecoveryTestKey(value byte) string {
	return base64.StdEncoding.EncodeToString(bytes.Repeat([]byte{value}, 32))
}

func mapAccountRecoveryEnv(environment map[string]string) accountRecoveryEnvLookup {
	return func(name string) (string, bool) {
		value, exists := environment[name]
		return value, exists
	}
}
