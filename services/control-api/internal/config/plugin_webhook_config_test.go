package config

import (
	"bytes"
	"crypto/ed25519"
	"crypto/x509"
	"encoding/base64"
	"encoding/pem"
	"io"
	"os"
	"path/filepath"
	"strings"
	"testing"
	"time"

	"github.com/cdnca/cdnca/services/control-api/internal/pluginwebhookruntime"
)

func TestLoadPluginWebhookRuntimeDisabledByDefaultIgnoresDependencies(t *testing.T) {
	setRequiredConfig(t)
	clearPluginWebhookEnvironment(t)
	t.Setenv("PLUGIN_WEBHOOK_NATS_URL", "not-a-url")
	t.Setenv("PLUGIN_WEBHOOK_NATS_CREDS_FILE", " /must/not/be/read/runtime.creds ")
	t.Setenv("PLUGIN_WEBHOOK_NATS_CA_FILE", " /must/not/be/read/ca.crt ")
	t.Setenv("PLUGIN_WEBHOOK_NATS_RECONNECT_MIN", "not-a-duration")
	t.Setenv("PLUGIN_WEBHOOK_NATS_RECONNECT_MAX", "0s")
	t.Setenv("PLUGIN_WEBHOOK_SECRET_KEY_ID", "invalid key id")
	t.Setenv("PLUGIN_WEBHOOK_SECRET_KEY_FILE", "/must/not/be/read/wrapping.key")
	t.Setenv("PLUGIN_WEBHOOK_SECRET_KEY_BASE64", "not-base64")

	cfg, err := Load()
	if err != nil {
		t.Fatalf("Load() disabled plugin webhook runtime error = %v", err)
	}
	if cfg.PluginWebhook.Enabled || cfg.PluginWebhook.NATSURL != "" || cfg.PluginWebhook.SecretKeyID != "" ||
		cfg.PluginWebhook.SecretKey != nil {
		t.Fatalf("disabled plugin webhook config mismatch: enabled=%t nats_url_set=%t secret_key_id_set=%t secret_key_length=%d",
			cfg.PluginWebhook.Enabled, cfg.PluginWebhook.NATSURL != "", cfg.PluginWebhook.SecretKeyID != "",
			len(cfg.PluginWebhook.SecretKey))
	}
}

func TestLoadPluginWebhookRuntimeAcceptsRawFileKey(t *testing.T) {
	setValidPluginWebhookEnvironment(t)
	wantKey := bytes.Repeat([]byte{0x5a}, 32)
	t.Setenv("PLUGIN_WEBHOOK_SECRET_KEY_FILE", writePluginWebhookSecretKeyFile(t, wantKey))
	t.Setenv("PLUGIN_WEBHOOK_SECRET_KEY_BASE64", "")

	cfg, err := Load()
	if err != nil {
		t.Fatalf("Load() file-backed plugin webhook key error = %v", err)
	}
	t.Cleanup(func() { clear(cfg.PluginWebhook.SecretKey) })
	if !bytes.Equal(cfg.PluginWebhook.SecretKey, wantKey) {
		t.Fatalf("file-backed plugin webhook key length = %d, want 32", len(cfg.PluginWebhook.SecretKey))
	}
}

func TestLoadPluginWebhookRuntimeMapsNATSTransportConfig(t *testing.T) {
	t.Run("explicit", func(t *testing.T) {
		setValidPluginWebhookEnvironment(t)

		cfg, err := Load()
		if err != nil {
			t.Fatal(err)
		}
		webhook := cfg.PluginWebhook
		if webhook.NATSCredsFile != "/run/secrets/nats/runtime.creds" ||
			webhook.NATSCAFile != "/run/secrets/nats/ca.crt" ||
			webhook.NATSReconnectMin != 1500*time.Millisecond || webhook.NATSReconnectMax != 2*time.Second {
			t.Fatalf("loaded NATS transport config mismatch: creds=%q ca=%q reconnect_min=%s reconnect_max=%s",
				webhook.NATSCredsFile, webhook.NATSCAFile, webhook.NATSReconnectMin, webhook.NATSReconnectMax)
		}
	})

	t.Run("reconnect defaults", func(t *testing.T) {
		setValidPluginWebhookEnvironment(t)
		t.Setenv("PLUGIN_WEBHOOK_NATS_RECONNECT_MIN", "")
		t.Setenv("PLUGIN_WEBHOOK_NATS_RECONNECT_MAX", "")

		cfg, err := Load()
		if err != nil {
			t.Fatal(err)
		}
		if cfg.PluginWebhook.NATSReconnectMin != 250*time.Millisecond ||
			cfg.PluginWebhook.NATSReconnectMax != 5*time.Second {
			t.Fatalf("reconnect defaults = %s/%s, want 250ms/5s",
				cfg.PluginWebhook.NATSReconnectMin, cfg.PluginWebhook.NATSReconnectMax)
		}
	})
}

func TestLoadPluginWebhookRuntimeRequiresExactlyOneKeySource(t *testing.T) {
	tests := []struct {
		name string
		file bool
		base bool
	}{
		{name: "both", file: true, base: true},
		{name: "neither"},
	}
	for _, test := range tests {
		t.Run(test.name, func(t *testing.T) {
			setValidPluginWebhookEnvironment(t)
			if test.file {
				t.Setenv("PLUGIN_WEBHOOK_SECRET_KEY_FILE", writePluginWebhookSecretKeyFile(t, bytes.Repeat([]byte{0x5a}, 32)))
			}
			if !test.base {
				t.Setenv("PLUGIN_WEBHOOK_SECRET_KEY_BASE64", "")
			}

			_, err := Load()
			if err == nil || !strings.Contains(err.Error(), "PLUGIN_WEBHOOK_SECRET_KEY_FILE and PLUGIN_WEBHOOK_SECRET_KEY_BASE64 must have exactly one value") {
				t.Fatalf("Load() key source error = %v", err)
			}
		})
	}
}

func TestLoadPluginWebhookRuntimeRejectsMalformedRawFileKey(t *testing.T) {
	tests := []struct {
		name     string
		contents []byte
	}{
		{name: "empty"},
		{name: "31 bytes", contents: bytes.Repeat([]byte{0x5a}, 31)},
		{name: "33 bytes", contents: bytes.Repeat([]byte{0x5a}, 33)},
		{name: "trailing LF", contents: append(bytes.Repeat([]byte{0x5a}, 32), '\n')},
		{name: "trailing CRLF", contents: append(bytes.Repeat([]byte{0x5a}, 32), '\r', '\n')},
	}
	for _, test := range tests {
		t.Run(test.name, func(t *testing.T) {
			setValidPluginWebhookEnvironment(t)
			t.Setenv("PLUGIN_WEBHOOK_SECRET_KEY_FILE", writePluginWebhookSecretKeyFile(t, test.contents))
			t.Setenv("PLUGIN_WEBHOOK_SECRET_KEY_BASE64", "")

			cfg, err := Load()
			if err == nil || !strings.Contains(err.Error(), "PLUGIN_WEBHOOK_SECRET_KEY_FILE must contain exactly 32 raw bytes") {
				t.Fatalf("Load() raw key error = %v", err)
			}
			if cfg.PluginWebhook.SecretKey != nil {
				t.Fatal("Load() retained a malformed file-backed key")
			}
		})
	}
}

func TestLoadPluginWebhookRuntimeReportsFileKeyReadFailure(t *testing.T) {
	setValidPluginWebhookEnvironment(t)
	t.Setenv("PLUGIN_WEBHOOK_SECRET_KEY_FILE", filepath.Join(t.TempDir(), "missing.key"))
	t.Setenv("PLUGIN_WEBHOOK_SECRET_KEY_BASE64", "")

	_, err := Load()
	if err == nil || !strings.Contains(err.Error(), "failed to read PLUGIN_WEBHOOK_SECRET_KEY_FILE") {
		t.Fatalf("Load() file key read error = %v", err)
	}
}

func TestLoadPluginWebhookRuntimeFileKeyReadErrorDoesNotDisclosePath(t *testing.T) {
	tests := []struct {
		name string
		path func(*testing.T) string
	}{
		{name: "open", path: func(t *testing.T) string {
			return filepath.Join(t.TempDir(), "do-not-disclose-secret-name.key")
		}},
		{name: "read", path: func(t *testing.T) string {
			return t.TempDir()
		}},
	}
	for _, test := range tests {
		t.Run(test.name, func(t *testing.T) {
			setValidPluginWebhookEnvironment(t)
			t.Setenv("PLUGIN_WEBHOOK_SECRET_KEY_FILE", test.path(t))
			t.Setenv("PLUGIN_WEBHOOK_SECRET_KEY_BASE64", "")

			_, err := Load()
			if err == nil {
				t.Fatal("Load() file key read error = nil")
			}
			if err.Error() != "failed to read PLUGIN_WEBHOOK_SECRET_KEY_FILE" {
				t.Fatalf("Load() file key read error disclosed path or underlying error: %q", err)
			}
		})
	}
}

func TestReadPluginWebhookSecretKeyBoundsAndClearsScratch(t *testing.T) {
	tests := []struct {
		name        string
		content     []byte
		terminalErr error
		wantKey     bool
		wantError   string
	}{
		{name: "exact", content: bytes.Repeat([]byte{0x5a}, 32), wantKey: true},
		{name: "short", content: bytes.Repeat([]byte{0x5a}, 31), wantError: "PLUGIN_WEBHOOK_SECRET_KEY_FILE must contain exactly 32 raw bytes"},
		{name: "long", content: bytes.Repeat([]byte{0x5a}, 34), wantError: "PLUGIN_WEBHOOK_SECRET_KEY_FILE must contain exactly 32 raw bytes"},
		{name: "read error", content: bytes.Repeat([]byte{0x5a}, 5), terminalErr: io.ErrClosedPipe, wantError: "failed to read PLUGIN_WEBHOOK_SECRET_KEY_FILE"},
	}
	for _, test := range tests {
		t.Run(test.name, func(t *testing.T) {
			reader := &trackingPluginWebhookKeyReader{content: test.content, terminalErr: test.terminalErr}
			key, err := readPluginWebhookSecretKey(reader)
			if test.wantKey && err != nil {
				t.Fatalf("readPluginWebhookSecretKey() error = %v", err)
			}
			if !test.wantKey && (err == nil || err.Error() != test.wantError) {
				t.Fatalf("readPluginWebhookSecretKey() error = %v", err)
			}
			if reader.bytesRead > 33 || reader.maxRequest > 33 {
				t.Fatalf("secret key reader consumed=%d max_request=%d, want at most 33", reader.bytesRead, reader.maxRequest)
			}
			if test.name == "long" && reader.bytesRead != 33 {
				t.Fatalf("long secret key reader consumed = %d, want 33", reader.bytesRead)
			}
			if !bytes.Equal(reader.scratch, make([]byte, len(reader.scratch))) {
				t.Fatal("secret key scratch buffer was not cleared")
			}
			if test.wantKey {
				if !bytes.Equal(key, test.content) {
					t.Fatal("successful secret key read did not retain an independent key copy")
				}
				clear(key)
			} else if key != nil {
				t.Fatal("failed secret key read returned key bytes")
			}
		})
	}
}

func TestLoadPluginWebhookRuntimeRequiresExactNATSCredentialPaths(t *testing.T) {
	tests := []struct {
		name  string
		env   string
		value string
	}{
		{name: "missing creds", env: "PLUGIN_WEBHOOK_NATS_CREDS_FILE"},
		{name: "blank creds", env: "PLUGIN_WEBHOOK_NATS_CREDS_FILE", value: "   "},
		{name: "padded creds", env: "PLUGIN_WEBHOOK_NATS_CREDS_FILE", value: " /run/secrets/nats/runtime.creds "},
		{name: "missing CA", env: "PLUGIN_WEBHOOK_NATS_CA_FILE"},
		{name: "blank CA", env: "PLUGIN_WEBHOOK_NATS_CA_FILE", value: "\t"},
		{name: "padded CA", env: "PLUGIN_WEBHOOK_NATS_CA_FILE", value: " /run/secrets/nats/ca.crt "},
	}
	for _, test := range tests {
		t.Run(test.name, func(t *testing.T) {
			setValidPluginWebhookEnvironment(t)
			t.Setenv(test.env, test.value)

			_, err := Load()
			if err == nil || !strings.Contains(err.Error(), test.env) {
				t.Fatalf("Load() NATS credential path error = %v, want variable %s", err, test.env)
			}
			if strings.Contains(err.Error(), strings.TrimSpace(test.value)) && strings.TrimSpace(test.value) != "" {
				t.Fatalf("Load() NATS credential path error disclosed configured path: %v", err)
			}
		})
	}
}

func TestLoadPluginWebhookRuntimeRejectsReconnectDurationBounds(t *testing.T) {
	tests := []struct {
		name string
		min  string
		max  string
		want string
	}{
		{name: "invalid minimum", min: "250", max: "2s", want: "PLUGIN_WEBHOOK_NATS_RECONNECT_MIN"},
		{name: "zero minimum", min: "0s", max: "2s", want: "PLUGIN_WEBHOOK_NATS_RECONNECT_MIN"},
		{name: "invalid maximum", min: "250ms", max: "5 seconds", want: "PLUGIN_WEBHOOK_NATS_RECONNECT_MAX"},
		{name: "zero maximum", min: "250ms", max: "0s", want: "PLUGIN_WEBHOOK_NATS_RECONNECT_MAX"},
		{name: "minimum over limit", min: "5m1s", max: "5m1s", want: "PLUGIN_WEBHOOK_NATS_RECONNECT_MIN"},
		{name: "maximum over limit", min: "250ms", max: "5m1s", want: "PLUGIN_WEBHOOK_NATS_RECONNECT_MAX"},
		{name: "minimum exceeds maximum", min: "3s", max: "2s", want: "PLUGIN_WEBHOOK_NATS_RECONNECT_MIN must not exceed PLUGIN_WEBHOOK_NATS_RECONNECT_MAX"},
	}
	for _, test := range tests {
		t.Run(test.name, func(t *testing.T) {
			setValidPluginWebhookEnvironment(t)
			t.Setenv("PLUGIN_WEBHOOK_NATS_RECONNECT_MIN", test.min)
			t.Setenv("PLUGIN_WEBHOOK_NATS_RECONNECT_MAX", test.max)

			_, err := Load()
			if err == nil || !strings.Contains(err.Error(), test.want) {
				t.Fatalf("Load() reconnect error = %v, want %q", err, test.want)
			}
		})
	}
}

func TestLoadPluginWebhookRuntimeMapsExactEnvironment(t *testing.T) {
	setValidPluginWebhookEnvironment(t)

	cfg, err := Load()
	if err != nil {
		t.Fatalf("Load() enabled plugin webhook runtime error = %v", err)
	}
	wantKey := bytes.Repeat([]byte{0x5a}, 32)
	webhook := cfg.PluginWebhook
	jetstream := webhook.JetStream
	if !webhook.Enabled || webhook.NATSURL != "tls://nats.example.test:4222" ||
		webhook.NATSName != "cdnca-plugin-webhook-test" || webhook.SecretKeyID != "plugin-webhook/key-v1" ||
		!bytes.Equal(webhook.SecretKey, wantKey) || webhook.PollInterval != 250*time.Millisecond ||
		webhook.OperationTimeout != 2*time.Second || webhook.LeaseDuration != 2*time.Minute ||
		webhook.ClaimTimeout != 30*time.Second || webhook.ShutdownTimeout != 5*time.Second {
		t.Fatalf("loaded plugin webhook config mismatch: enabled=%t nats_url_matches=%t nats_name_matches=%t secret_key_id_matches=%t secret_key_matches=%t secret_key_length=%d poll_interval_matches=%t operation_timeout_matches=%t lease_duration_matches=%t claim_timeout_matches=%t shutdown_timeout_matches=%t",
			webhook.Enabled, webhook.NATSURL == "tls://nats.example.test:4222",
			webhook.NATSName == "cdnca-plugin-webhook-test", webhook.SecretKeyID == "plugin-webhook/key-v1",
			bytes.Equal(webhook.SecretKey, wantKey), len(webhook.SecretKey), webhook.PollInterval == 250*time.Millisecond,
			webhook.OperationTimeout == 2*time.Second, webhook.LeaseDuration == 2*time.Minute,
			webhook.ClaimTimeout == 30*time.Second, webhook.ShutdownTimeout == 5*time.Second)
	}
	if jetstream.DeliveryStream != "PLUGIN_WEBHOOK_DELIVERY_TEST" ||
		jetstream.DeliveryDurable != "control_api_plugin_webhook_test" ||
		jetstream.DeliverySubjectPrefix != "cdnca.plugin-webhook.delivery.test" ||
		jetstream.DeadLetterStream != pluginwebhookruntime.DefaultDeadLetterStream ||
		jetstream.DeadLetterSubject != pluginwebhookruntime.DefaultDeadLetterSubject ||
		jetstream.AckWait != 7*time.Second || jetstream.FetchTimeout != time.Second ||
		jetstream.OperationTimeout != 2*time.Second || jetstream.ConsumerMaxDeliver != -1 ||
		jetstream.MaxAckPending != 64 || jetstream.MaxWaiting != 16 || jetstream.StreamMaxAge != 24*time.Hour ||
		jetstream.StreamMaxBytes != 524288 || jetstream.StreamMaxMessages != 4096 ||
		jetstream.DeadLetterMaxAge != 48*time.Hour || jetstream.DeadLetterMaxBytes != 786432 ||
		jetstream.DuplicateWindow != 3*time.Minute || jetstream.Replicas != 2 || jetstream.ReadinessMaxPending != 128 {
		t.Fatalf("loaded plugin webhook JetStream config = %#v", jetstream)
	}
}

func TestLoadPluginWebhookRuntimeRejectsNonCanonicalAndOutOfBoundsEnvironment(t *testing.T) {
	wantKey := bytes.Repeat([]byte{0x5a}, 32)
	tests := []struct {
		name  string
		env   string
		value string
		want  string
	}{
		{name: "non-canonical key", env: "PLUGIN_WEBHOOK_SECRET_KEY_BASE64", value: base64.RawStdEncoding.EncodeToString(wantKey), want: "canonical base64"},
		{name: "non-TLS non-loopback NATS", env: "PLUGIN_WEBHOOK_NATS_URL", value: "nats://nats.example.test:4222", want: "TLS server URL"},
		{name: "zero poll interval", env: "PLUGIN_WEBHOOK_POLL_INTERVAL", value: "0s", want: "must be a positive duration"},
		{name: "short acknowledgement window", env: "PLUGIN_WEBHOOK_ACK_WAIT", value: "6s", want: "settings are invalid"},
		{name: "undersized stream capacity", env: "PLUGIN_WEBHOOK_STREAM_MAX_BYTES", value: "262143", want: "settings are invalid"},
		{name: "zero pending capacity", env: "PLUGIN_WEBHOOK_MAX_ACK_PENDING", value: "0", want: "must be a positive integer"},
		{name: "finite consumer delivery limit", env: "PLUGIN_WEBHOOK_CONSUMER_MAX_DELIVER", value: "6", want: "must be -1"},
		{name: "shutdown exceeds process bound", env: "PLUGIN_WEBHOOK_SHUTDOWN_TIMEOUT", value: "11s", want: "settings are invalid"},
	}
	for _, test := range tests {
		t.Run(test.name, func(t *testing.T) {
			setValidPluginWebhookEnvironment(t)
			t.Setenv(test.env, test.value)
			_, err := Load()
			if err == nil || !strings.Contains(err.Error(), test.want) {
				t.Fatalf("Load() plugin webhook error = %v, want %q", err, test.want)
			}
		})
	}
}

func TestLoadPluginWebhookRuntimeClearsDecodedKeyOnFailure(t *testing.T) {
	tests := []struct {
		name  string
		env   string
		value string
	}{
		{name: "duration", env: "PLUGIN_WEBHOOK_POLL_INTERVAL", value: "0s"},
		{name: "capacity", env: "PLUGIN_WEBHOOK_STREAM_MAX_BYTES", value: "262143"},
		{name: "JetStream", env: "PLUGIN_WEBHOOK_DEAD_LETTER_STREAM", value: "OTHER_DLQ"},
	}
	for _, test := range tests {
		t.Run(test.name, func(t *testing.T) {
			setValidPluginWebhookEnvironment(t)
			t.Setenv(test.env, test.value)
			cfg := Config{
				PluginWebhook: PluginWebhookConfig{
					Enabled:   true,
					JetStream: pluginwebhookruntime.DefaultJetStreamConfig(),
				},
				ShutdownPeriod: 10 * time.Second,
			}
			if err := loadPluginWebhook(&cfg); err == nil {
				t.Fatal("loadPluginWebhook() error = nil")
			}
			if cfg.PluginWebhook.SecretKey != nil {
				t.Fatalf("decoded key retained after %s validation failure", test.name)
			}
		})
	}

	t.Run("success retains key", func(t *testing.T) {
		setValidPluginWebhookEnvironment(t)
		cfg := Config{
			PluginWebhook: PluginWebhookConfig{
				Enabled:   true,
				JetStream: pluginwebhookruntime.DefaultJetStreamConfig(),
			},
			ShutdownPeriod: 10 * time.Second,
		}
		if err := loadPluginWebhook(&cfg); err != nil {
			t.Fatal(err)
		}
		if !bytes.Equal(cfg.PluginWebhook.SecretKey, bytes.Repeat([]byte{0x5a}, 32)) {
			t.Fatal("successful load did not retain the decoded key")
		}
	})
}

func TestLoadPluginWebhookRuntimeClearsFileKeyOnLaterFailure(t *testing.T) {
	setValidPluginWebhookEnvironment(t)
	t.Setenv("PLUGIN_WEBHOOK_SECRET_KEY_FILE", writePluginWebhookSecretKeyFile(t, bytes.Repeat([]byte{0x5a}, 32)))
	t.Setenv("PLUGIN_WEBHOOK_SECRET_KEY_BASE64", "")
	t.Setenv("PLUGIN_WEBHOOK_POLL_INTERVAL", "0s")
	cfg := Config{
		PluginWebhook: PluginWebhookConfig{
			Enabled:   true,
			JetStream: pluginwebhookruntime.DefaultJetStreamConfig(),
		},
		ShutdownPeriod: 10 * time.Second,
	}

	if err := loadPluginWebhook(&cfg); err == nil {
		t.Fatal("loadPluginWebhook() error = nil")
	}
	if cfg.PluginWebhook.SecretKey != nil {
		t.Fatal("file-backed key retained after later validation failure")
	}
}

func TestLoadPluginWebhookRuntimeClearsDecodedKeyOnLaterLoadFailure(t *testing.T) {
	t.Run("wipe clears the backing bytes before dropping the key", func(t *testing.T) {
		key := bytes.Repeat([]byte{0x5a}, 32)
		cfg := Config{PluginWebhook: PluginWebhookConfig{SecretKey: key}}
		clearPluginWebhookSecret(&cfg)
		if cfg.PluginWebhook.SecretKey != nil {
			t.Fatal("cleared plugin webhook key is not nil")
		}
		if !bytes.Equal(key, make([]byte, 32)) {
			t.Fatal("plugin webhook key backing bytes were not cleared")
		}
	})

	tests := []struct {
		name  string
		setup func(*testing.T)
	}{
		{name: "entitlement parsing", setup: func(t *testing.T) {
			t.Setenv("LICENSE_SERVICE_URL", "https://license.example.test")
			t.Setenv("ENTITLEMENT_SYNC_BACKOFF_MIN", "0s")
		}},
		{name: "entitlement validation", setup: func(t *testing.T) {
			t.Setenv("LICENSE_SERVICE_URL", "https://license.example.test")
		}},
		{name: "control internal validation", setup: func(t *testing.T) {
			t.Setenv("CONTROL_INTERNAL_SERVER_CERT_FILE", "")
		}},
		{name: "edge deployment validation", setup: func(t *testing.T) {
			t.Setenv("EDGE_DEPLOYMENT_NATS_URL", "")
		}},
		{name: "node presence validation", setup: func(t *testing.T) {
			t.Setenv("NODE_PRESENCE_NATS_URL", "nats://127.0.0.1:4222")
		}},
	}
	for _, test := range tests {
		t.Run(test.name, func(t *testing.T) {
			setValidPluginWebhookEnvironment(t)
			test.setup(t)
			cfg, err := Load()
			if err == nil {
				t.Fatal("Load() error = nil")
			}
			if cfg.PluginWebhook.SecretKey != nil {
				t.Fatal("Load() returned a plugin webhook key after validation failure")
			}
		})
	}
}

func setValidPluginWebhookEnvironment(t *testing.T) {
	t.Helper()
	setRequiredConfig(t)
	clearPluginWebhookEnvironment(t)
	t.Setenv("PLUGIN_WEBHOOK_RUNTIME_ENABLED", "true")
	t.Setenv("PLUGIN_WEBHOOK_NATS_URL", "tls://nats.example.test:4222")
	t.Setenv("PLUGIN_WEBHOOK_NATS_NAME", "cdnca-plugin-webhook-test")
	t.Setenv("PLUGIN_WEBHOOK_NATS_CREDS_FILE", "/run/secrets/nats/runtime.creds")
	t.Setenv("PLUGIN_WEBHOOK_NATS_CA_FILE", "/run/secrets/nats/ca.crt")
	t.Setenv("PLUGIN_WEBHOOK_NATS_RECONNECT_MIN", "1500ms")
	t.Setenv("PLUGIN_WEBHOOK_NATS_RECONNECT_MAX", "2s")
	t.Setenv("PLUGIN_WEBHOOK_SECRET_KEY_ID", "plugin-webhook/key-v1")
	t.Setenv("PLUGIN_WEBHOOK_SECRET_KEY_BASE64", base64.StdEncoding.EncodeToString(bytes.Repeat([]byte{0x5a}, 32)))
	t.Setenv("PLUGIN_WEBHOOK_ATTESTATION_KEY_ID", "plugin-webhook-runtime-key-1")
	t.Setenv("PLUGIN_WEBHOOK_ATTESTATION_PRIVATE_KEY_FILE", writePluginWebhookAttestationKeyFile(t, testPluginWebhookAttestationKey))
	t.Setenv("PLUGIN_WEBHOOK_POLL_INTERVAL", "250ms")
	t.Setenv("PLUGIN_WEBHOOK_OPERATION_TIMEOUT", "2s")
	t.Setenv("PLUGIN_WEBHOOK_LEASE_DURATION", "2m")
	t.Setenv("PLUGIN_WEBHOOK_CLAIM_TIMEOUT", "30s")
	t.Setenv("PLUGIN_WEBHOOK_SHUTDOWN_TIMEOUT", "5s")
	t.Setenv("PLUGIN_WEBHOOK_DELIVERY_STREAM", "PLUGIN_WEBHOOK_DELIVERY_TEST")
	t.Setenv("PLUGIN_WEBHOOK_DELIVERY_DURABLE", "control_api_plugin_webhook_test")
	t.Setenv("PLUGIN_WEBHOOK_DELIVERY_SUBJECT_PREFIX", "cdnca.plugin-webhook.delivery.test")
	t.Setenv("PLUGIN_WEBHOOK_ACK_WAIT", "7s")
	t.Setenv("PLUGIN_WEBHOOK_FETCH_TIMEOUT", "1s")
	t.Setenv("PLUGIN_WEBHOOK_CONSUMER_MAX_DELIVER", "-1")
	t.Setenv("PLUGIN_WEBHOOK_MAX_ACK_PENDING", "64")
	t.Setenv("PLUGIN_WEBHOOK_MAX_WAITING", "16")
	t.Setenv("PLUGIN_WEBHOOK_STREAM_MAX_AGE", "24h")
	t.Setenv("PLUGIN_WEBHOOK_STREAM_MAX_BYTES", "524288")
	t.Setenv("PLUGIN_WEBHOOK_STREAM_MAX_MESSAGES", "4096")
	t.Setenv("PLUGIN_WEBHOOK_DEAD_LETTER_MAX_AGE", "48h")
	t.Setenv("PLUGIN_WEBHOOK_DEAD_LETTER_MAX_BYTES", "786432")
	t.Setenv("PLUGIN_WEBHOOK_DUPLICATE_WINDOW", "3m")
	t.Setenv("PLUGIN_WEBHOOK_REPLICAS", "2")
	t.Setenv("PLUGIN_WEBHOOK_READINESS_MAX_PENDING", "128")
}

func clearPluginWebhookEnvironment(t *testing.T) {
	t.Helper()
	for _, name := range []string{
		"PLUGIN_WEBHOOK_RUNTIME_ENABLED", "PLUGIN_WEBHOOK_NATS_URL", "PLUGIN_WEBHOOK_NATS_NAME",
		"PLUGIN_WEBHOOK_NATS_CREDS_FILE", "PLUGIN_WEBHOOK_NATS_CA_FILE", "PLUGIN_WEBHOOK_NATS_RECONNECT_MIN",
		"PLUGIN_WEBHOOK_NATS_RECONNECT_MAX", "PLUGIN_WEBHOOK_SECRET_KEY_ID", "PLUGIN_WEBHOOK_SECRET_KEY_FILE",
		"PLUGIN_WEBHOOK_SECRET_KEY_BASE64", "PLUGIN_WEBHOOK_ATTESTATION_KEY_ID",
		"PLUGIN_WEBHOOK_ATTESTATION_PRIVATE_KEY_FILE", "PLUGIN_WEBHOOK_ATTESTATION_NEXT_KEY_ID",
		"PLUGIN_WEBHOOK_ATTESTATION_NEXT_PRIVATE_KEY_FILE", "PLUGIN_WEBHOOK_POLL_INTERVAL",
		"PLUGIN_WEBHOOK_OPERATION_TIMEOUT", "PLUGIN_WEBHOOK_LEASE_DURATION", "PLUGIN_WEBHOOK_CLAIM_TIMEOUT",
		"PLUGIN_WEBHOOK_SHUTDOWN_TIMEOUT", "PLUGIN_WEBHOOK_DELIVERY_STREAM", "PLUGIN_WEBHOOK_DELIVERY_DURABLE",
		"PLUGIN_WEBHOOK_DELIVERY_SUBJECT_PREFIX", "PLUGIN_WEBHOOK_DEAD_LETTER_STREAM",
		"PLUGIN_WEBHOOK_DEAD_LETTER_SUBJECT", "PLUGIN_WEBHOOK_ACK_WAIT", "PLUGIN_WEBHOOK_FETCH_TIMEOUT",
		"PLUGIN_WEBHOOK_CONSUMER_MAX_DELIVER", "PLUGIN_WEBHOOK_MAX_ACK_PENDING", "PLUGIN_WEBHOOK_MAX_WAITING",
		"PLUGIN_WEBHOOK_STREAM_MAX_AGE", "PLUGIN_WEBHOOK_STREAM_MAX_BYTES", "PLUGIN_WEBHOOK_STREAM_MAX_MESSAGES",
		"PLUGIN_WEBHOOK_DEAD_LETTER_MAX_AGE", "PLUGIN_WEBHOOK_DEAD_LETTER_MAX_BYTES",
		"PLUGIN_WEBHOOK_DUPLICATE_WINDOW", "PLUGIN_WEBHOOK_REPLICAS", "PLUGIN_WEBHOOK_READINESS_MAX_PENDING",
	} {
		t.Setenv(name, "")
	}
}

func writePluginWebhookSecretKeyFile(t *testing.T, contents []byte) string {
	t.Helper()
	path := filepath.Join(t.TempDir(), "wrapping.key")
	if err := os.WriteFile(path, contents, 0o600); err != nil {
		t.Fatal(err)
	}
	return path
}

type trackingPluginWebhookKeyReader struct {
	content     []byte
	offset      int
	bytesRead   int
	maxRequest  int
	scratch     []byte
	terminalErr error
}

func (r *trackingPluginWebhookKeyReader) Read(buffer []byte) (int, error) {
	if len(buffer) > r.maxRequest {
		r.maxRequest = len(buffer)
	}
	if r.scratch == nil {
		r.scratch = buffer
	}
	if r.offset == len(r.content) {
		if r.terminalErr != nil {
			return 0, r.terminalErr
		}
		return 0, io.EOF
	}
	n := copy(buffer, r.content[r.offset:])
	r.offset += n
	r.bytesRead += n
	return n, nil
}

var testPluginWebhookAttestationKey = ed25519.NewKeyFromSeed(bytes.Repeat([]byte{0x3c}, ed25519.SeedSize))

func writePluginWebhookAttestationKeyFile(t *testing.T, key ed25519.PrivateKey) string {
	t.Helper()
	der, err := x509.MarshalPKCS8PrivateKey(key)
	if err != nil {
		t.Fatal(err)
	}
	path := filepath.Join(t.TempDir(), "attestation.pem")
	if err := os.WriteFile(path, pem.EncodeToMemory(&pem.Block{Type: "PRIVATE KEY", Bytes: der}), 0o600); err != nil {
		t.Fatal(err)
	}
	return path
}

func TestLoadPluginWebhookRuntimeAttestationKey(t *testing.T) {
	setValidPluginWebhookEnvironment(t)
	cfg, err := Load()
	if err != nil {
		t.Fatal(err)
	}
	if cfg.PluginWebhook.AttestationKeyID != "plugin-webhook-runtime-key-1" ||
		!bytes.Equal(cfg.PluginWebhook.AttestationKey, testPluginWebhookAttestationKey) {
		t.Fatal("plugin webhook attestation key was not loaded")
	}
	clearPluginWebhookSecret(&cfg)
	for name, mutate := range map[string]func(*testing.T){
		"missing key id":   func(t *testing.T) { t.Setenv("PLUGIN_WEBHOOK_ATTESTATION_KEY_ID", "") },
		"invalid key id":   func(t *testing.T) { t.Setenv("PLUGIN_WEBHOOK_ATTESTATION_KEY_ID", "bad key") },
		"missing key file": func(t *testing.T) { t.Setenv("PLUGIN_WEBHOOK_ATTESTATION_PRIVATE_KEY_FILE", "") },
		"not a PEM key": func(t *testing.T) {
			t.Setenv("PLUGIN_WEBHOOK_ATTESTATION_PRIVATE_KEY_FILE", writePluginWebhookSecretKeyFile(t, bytes.Repeat([]byte{1}, 32)))
		},
	} {
		t.Run(name, func(t *testing.T) {
			setValidPluginWebhookEnvironment(t)
			mutate(t)
			if _, err := Load(); err == nil || !strings.Contains(err.Error(), "PLUGIN_WEBHOOK_ATTESTATION") {
				t.Fatalf("Load() error = %v", err)
			}
		})
	}
}

func TestLoadPluginWebhookStagedNextAttestationKey(t *testing.T) {
	clearPluginWebhookEnvironment(t)
	setValidPluginWebhookEnvironment(t)
	t.Setenv("PLUGIN_WEBHOOK_RUNTIME_ENABLED", "true")
	nextKey := ed25519.NewKeyFromSeed(bytes.Repeat([]byte{0x4d}, ed25519.SeedSize))
	t.Setenv("PLUGIN_WEBHOOK_ATTESTATION_NEXT_KEY_ID", "plugin-webhook-runtime-key-2")
	t.Setenv("PLUGIN_WEBHOOK_ATTESTATION_NEXT_PRIVATE_KEY_FILE", writePluginWebhookAttestationKeyFile(t, nextKey))
	cfg, err := Load()
	if err != nil {
		t.Fatal(err)
	}
	if cfg.PluginWebhook.NextAttestationKeyID != "plugin-webhook-runtime-key-2" ||
		!bytes.Equal(cfg.PluginWebhook.NextAttestationKey, nextKey) {
		t.Fatal("staged next attestation key was not loaded")
	}
	clearPluginWebhookSecret(&cfg)
	if cfg.PluginWebhook.NextAttestationKey != nil {
		t.Fatal("clearPluginWebhookSecret kept the next attestation key")
	}
	for name, mutate := range map[string]func(*testing.T){
		"id without file": func(t *testing.T) { t.Setenv("PLUGIN_WEBHOOK_ATTESTATION_NEXT_PRIVATE_KEY_FILE", "") },
		"file without id": func(t *testing.T) { t.Setenv("PLUGIN_WEBHOOK_ATTESTATION_NEXT_KEY_ID", "") },
		"same id as current": func(t *testing.T) {
			t.Setenv("PLUGIN_WEBHOOK_ATTESTATION_NEXT_KEY_ID", "plugin-webhook-runtime-key-1")
		},
		"same key as current": func(t *testing.T) {
			t.Setenv("PLUGIN_WEBHOOK_ATTESTATION_NEXT_PRIVATE_KEY_FILE",
				writePluginWebhookAttestationKeyFile(t, testPluginWebhookAttestationKey))
		},
		"not a PEM key": func(t *testing.T) {
			t.Setenv("PLUGIN_WEBHOOK_ATTESTATION_NEXT_PRIVATE_KEY_FILE", writePluginWebhookSecretKeyFile(t, bytes.Repeat([]byte{1}, 32)))
		},
	} {
		t.Run(name, func(t *testing.T) {
			mutate(t)
			if _, err := Load(); err == nil || !strings.Contains(err.Error(), "PLUGIN_WEBHOOK_ATTESTATION_NEXT") {
				t.Fatalf("Load() error = %v", err)
			}
		})
	}
}
