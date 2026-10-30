package main

import (
	"bytes"
	"crypto/ecdh"
	"crypto/ed25519"
	"crypto/rand"
	"crypto/sha256"
	"crypto/x509"
	"crypto/x509/pkix"
	"encoding/base64"
	"encoding/hex"
	"encoding/json"
	"encoding/pem"
	"errors"
	"math/big"
	"net/url"
	"os"
	"os/user"
	"path/filepath"
	"strconv"
	"strings"
	"testing"
	"time"

	"github.com/cdnca/cdnca/agents/edge-agent/internal/diskguard"
	"github.com/google/uuid"
)

func TestDecodeConfigAppliesBoundedDefaults(t *testing.T) {
	config := validFileConfig()
	content, err := json.Marshal(config)
	if err != nil {
		t.Fatal(err)
	}
	var legacy map[string]json.RawMessage
	if err := json.Unmarshal(content, &legacy); err != nil {
		t.Fatal(err)
	}
	delete(legacy, "disk_guard")
	delete(legacy, "telemetry")
	content, err = json.Marshal(legacy)
	if err != nil {
		t.Fatal(err)
	}
	decoded, timeouts, err := decodeConfig(content)
	if err != nil {
		t.Fatal(err)
	}
	if decoded.NodeID != config.NodeID || decoded.Limits.MaxArtifactBytes != 128<<20 {
		t.Fatalf("decoded configuration = %+v", decoded)
	}
	if timeouts.Handshake.String() != "10s" || timeouts.HealthRequest.String() != "2s" {
		t.Fatalf("parsed timeouts = %+v", timeouts)
	}
	if decoded.DiskGuard.Enabled || !decoded.DiskGuard.DryRun || decoded.DiskGuard.LowWatermark != 8000 ||
		decoded.DiskGuard.HighWatermark != 9000 || decoded.DiskGuard.MaxDeletedFiles != 100 {
		t.Fatalf("disk guard defaults = %+v", decoded.DiskGuard)
	}
	if decoded.Telemetry.Enabled || decoded.Telemetry.MaxRecordsPerBatch != 64 || timeouts.TelemetryAck != 0 {
		t.Fatalf("legacy telemetry defaults = %+v, %+v", decoded.Telemetry, timeouts)
	}
}

func TestTelemetryConfigParsesBoundedTransportAndSpoolSettings(t *testing.T) {
	config := validFileConfig()
	config.Telemetry.Enabled = true
	config.Telemetry.SpoolRoot = filepath.Join(secureConfigTempDir(t), "event-spool")
	config.Telemetry.SoftAgeLimit = "12h"
	config.Telemetry.HardAgeLimit = "48h"
	config.Telemetry.EmptyInterval = "250ms"
	config.Telemetry.HandshakeTimeout = "7s"
	config.Telemetry.AckTimeout = "8s"
	config.Telemetry.InitialBackoff = "100ms"
	config.Telemetry.MaximumBackoff = "5s"
	timeouts, err := config.validate()
	if err != nil {
		t.Fatalf("validate() error = %v", err)
	}
	if timeouts.TelemetrySoftAgeLimit != 12*time.Hour || timeouts.TelemetryHardAgeLimit != 48*time.Hour ||
		timeouts.TelemetryEmptyInterval != 250*time.Millisecond || timeouts.TelemetryHandshake != 7*time.Second ||
		timeouts.TelemetryAck != 8*time.Second || timeouts.TelemetryInitialBackoff != 100*time.Millisecond ||
		timeouts.TelemetryMaximumBackoff != 5*time.Second {
		t.Fatalf("telemetry timeouts = %+v", timeouts)
	}
}

func TestTelemetryConfigRejectsUnsafeOrUnboundedSettings(t *testing.T) {
	root := secureConfigTempDir(t)
	realDirectory := filepath.Join(root, "real")
	if err := os.Mkdir(realDirectory, 0o700); err != nil {
		t.Fatal(err)
	}
	link := filepath.Join(root, "link")
	if err := os.Symlink(realDirectory, link); err != nil {
		t.Fatal(err)
	}
	tests := []struct {
		name   string
		mutate func(*fileConfig)
	}{
		{name: "deployment overlap", mutate: func(value *fileConfig) { value.Telemetry.SpoolRoot = value.DeploymentRoot }},
		{name: "symlink ancestor", mutate: func(value *fileConfig) { value.Telemetry.SpoolRoot = filepath.Join(link, "spool") }},
		{name: "segment framing", mutate: func(value *fileConfig) { value.Telemetry.MaxSegmentBytes = int64(value.Telemetry.MaxEventBytes + 63) }},
		{name: "soft byte limit", mutate: func(value *fileConfig) { value.Telemetry.SoftLimitBytes = value.Telemetry.MaxSegmentBytes - 1 }},
		{name: "sample bounds", mutate: func(value *fileConfig) { value.Telemetry.PressureMode = "sample" }},
		{name: "age order", mutate: func(value *fileConfig) { value.Telemetry.HardAgeLimit = value.Telemetry.SoftAgeLimit }},
		{name: "backoff order", mutate: func(value *fileConfig) {
			value.Telemetry.MaximumBackoff = "100ms"
			value.Telemetry.InitialBackoff = "1s"
		}},
		{name: "transport bytes", mutate: func(value *fileConfig) { value.Telemetry.MaxBatchBytes = value.Telemetry.MaxRecordBytes - 1 }},
	}
	for _, test := range tests {
		t.Run(test.name, func(t *testing.T) {
			config := validFileConfig()
			config.Telemetry.Enabled = true
			config.Telemetry.SpoolRoot = filepath.Join(root, "event-spool-"+strings.ReplaceAll(test.name, " ", "-"))
			test.mutate(&config)
			if _, err := config.validate(); err == nil {
				t.Fatal("validate() accepted unsafe telemetry settings")
			}
		})
	}

	content := validConfigJSON(t)
	var object map[string]json.RawMessage
	if err := json.Unmarshal(content, &object); err != nil {
		t.Fatal(err)
	}
	object["telemetry"] = json.RawMessage("null")
	content, err := json.Marshal(object)
	if err != nil {
		t.Fatal(err)
	}
	if _, _, err := decodeConfig(content); err == nil {
		t.Fatal("decodeConfig() accepted null telemetry configuration")
	}
}

func TestDiskGuardConfigUsesOnlyBoundedLogCleanup(t *testing.T) {
	config := validFileConfig()
	guardConfig, err := config.diskGuardConfig()
	if err != nil {
		t.Fatal(err)
	}
	if len(guardConfig.Directories) != 1 || guardConfig.Directories[0].Kind != diskguard.DirectoryRotatedLogs ||
		guardConfig.Directories[0].Path != config.DiskGuard.LogRoot ||
		!slicesEqual(guardConfig.Directories[0].Patterns, []string{"*.log.*", "*.log-*"}) ||
		!slicesEqual(guardConfig.Directories[0].ActiveNames, []string{"agent.log"}) {
		t.Fatalf("disk guard config = %+v", guardConfig)
	}
	if guardConfig.DryRun != config.DiskGuard.DryRun || len(guardConfig.ProtectedPaths) < 10 {
		t.Fatalf("disk guard safety config = %+v", guardConfig)
	}
}

func TestDiskGuardConfigRejectsBadBounds(t *testing.T) {
	tests := []struct {
		name   string
		mutate func(*diskGuardSettings)
	}{
		{name: "config id", mutate: func(value *diskGuardSettings) { value.ConfigID = "" }},
		{name: "revision", mutate: func(value *diskGuardSettings) { value.Revision = 0 }},
		{name: "log root", mutate: func(value *diskGuardSettings) { value.LogRoot = "logs" }},
		{name: "lock path", mutate: func(value *diskGuardSettings) { value.LockPath = "guard.lock" }},
		{name: "low watermark", mutate: func(value *diskGuardSettings) { value.LowWatermark = 4999 }},
		{name: "high watermark", mutate: func(value *diskGuardSettings) { value.HighWatermark = 9901 }},
		{name: "watermark order", mutate: func(value *diskGuardSettings) { value.LowWatermark = value.HighWatermark }},
		{name: "watermark gap", mutate: func(value *diskGuardSettings) { value.LowWatermark = 8950; value.HighWatermark = 9000 }},
		{name: "period too short", mutate: func(value *diskGuardSettings) { value.EvaluationPeriod = "1s" }},
		{name: "period too long", mutate: func(value *diskGuardSettings) { value.EvaluationPeriod = "2h" }},
		{name: "age too short", mutate: func(value *diskGuardSettings) { value.MinimumAge = "59m" }},
		{name: "age too long", mutate: func(value *diskGuardSettings) { value.MinimumAge = "2161h" }},
		{name: "minimum remain", mutate: func(value *diskGuardSettings) { value.MinimumRemain = 0 }},
		{name: "file budget", mutate: func(value *diskGuardSettings) { value.MaxDeletedFiles = 10001 }},
		{name: "byte budget low", mutate: func(value *diskGuardSettings) { value.MaxAllocatedBytes = (1 << 20) - 1 }},
		{name: "byte budget high", mutate: func(value *diskGuardSettings) { value.MaxAllocatedBytes = (16 << 30) + 1 }},
	}
	for _, test := range tests {
		t.Run(test.name, func(t *testing.T) {
			config := validFileConfig()
			test.mutate(&config.DiskGuard)
			if _, err := config.diskGuardConfig(); err == nil {
				t.Fatal("diskGuardConfig() accepted an unsafe value")
			}
		})
	}
}

func TestDiskGuardConfigRejectsProtectedPaths(t *testing.T) {
	tests := []struct {
		name   string
		mutate func(*fileConfig)
	}{
		{name: "enrollment", mutate: func(config *fileConfig) {
			config.IdentityDir = "/opt/cdnca/identity"
			config.DiskGuard.LogRoot = "/opt/cdnca/identity/logs"
		}},
		{name: "certificate", mutate: func(config *fileConfig) {
			config.Gateway.RootCAFile = "/opt/cdnca/tls/ca.pem"
			config.DiskGuard.LogRoot = "/opt/cdnca/tls"
		}},
		{name: "configuration", mutate: func(config *fileConfig) {
			config.ConfigPath = "/opt/cdnca/config/config.json"
			config.DiskGuard.LogRoot = "/opt/cdnca/config/logs"
		}},
		{name: "deployment version", mutate: func(config *fileConfig) { config.DiskGuard.LogRoot = config.DeploymentRoot }},
		{name: "upgrade", mutate: func(config *fileConfig) { config.DiskGuard.LogRoot = "/usr/lib/cdnca-edge-agent" }},
		{name: "audit", mutate: func(config *fileConfig) {
			config.DiskGuard.LogRoot = filepath.Join(filepath.Dir(config.JournalDir), "audit")
		}},
		{name: "event spool", mutate: func(config *fileConfig) { config.DiskGuard.LogRoot = config.JournalDir }},
	}
	for _, test := range tests {
		t.Run(test.name, func(t *testing.T) {
			config := validFileConfig()
			test.mutate(&config)
			if _, err := config.diskGuardConfig(); err == nil {
				t.Fatal("diskGuardConfig() accepted a protected path")
			}
		})
	}
}

func TestDecodeConfigVersion2UsesOnlyIdentityDirectory(t *testing.T) {
	config := validVersion2FileConfig(filepath.Join(secureConfigTempDir(t), "identity"))
	content, err := json.Marshal(config)
	if err != nil {
		t.Fatal(err)
	}
	decoded, _, err := decodeConfig(content)
	if err != nil {
		t.Fatalf("decodeConfig(v2) error = %v", err)
	}
	if decoded.Version != 2 || decoded.IdentityDir != config.IdentityDir || decoded.NodeID != "" || decoded.Gateway.ClientCertificate != "" {
		t.Fatalf("decoded v2 configuration = %+v", decoded)
	}
}

func TestDecodeConfigRejectsCrossVersionIdentityFields(t *testing.T) {
	v2, err := json.Marshal(validVersion2FileConfig(filepath.Join(secureConfigTempDir(t), "identity")))
	if err != nil {
		t.Fatal(err)
	}
	v1 := validConfigJSON(t)
	tests := []struct {
		name    string
		content []byte
	}{
		{name: "v2 missing identity"},
		{name: "v2 node override", content: bytes.Replace(v2, []byte(`"version":2`), []byte(`"version":2,"node_id":""`), 1)},
		{name: "v2 artifact key override", content: bytes.Replace(v2, []byte(`"version":2`), []byte(`"version":2,"artifact_encryption_key_id":""`), 1)},
		{name: "v2 certificate override", content: bytes.Replace(v2, []byte(`"address":"gateway.internal:9443"`), []byte(`"address":"gateway.internal:9443","client_certificate_file":""`), 1)},
		{name: "v2 private key override", content: bytes.Replace(v2, []byte(`"address":"gateway.internal:9443"`), []byte(`"address":"gateway.internal:9443","client_private_key_file":""`), 1)},
		{name: "v1 identity directory", content: bytes.Replace(v1, []byte(`"version":1`), []byte(`"version":1,"identity_dir":"/tmp/identity"`), 1)},
	}
	// The valid v2 path varies per test process, so remove it structurally.
	var v2Object map[string]json.RawMessage
	if err := json.Unmarshal(v2, &v2Object); err != nil {
		t.Fatal(err)
	}
	delete(v2Object, "identity_dir")
	tests[0].content, err = json.Marshal(v2Object)
	if err != nil {
		t.Fatal(err)
	}
	for _, test := range tests {
		t.Run(test.name, func(t *testing.T) {
			if _, _, err := decodeConfig(test.content); err == nil {
				t.Fatal("decodeConfig() accepted cross-version identity fields")
			}
		})
	}
}

func TestLoadConfigVersion2LoadsEnrollmentIdentity(t *testing.T) {
	root := secureConfigTempDir(t)
	identityDir, nodeID, keyID := writeIdentityFixture(t, root)
	config := validVersion2FileConfig(identityDir)
	content, err := json.Marshal(config)
	if err != nil {
		t.Fatal(err)
	}
	path := filepath.Join(root, "config.json")
	if err := os.WriteFile(path, content, 0o600); err != nil {
		t.Fatal(err)
	}
	loaded, _, err := loadConfig(path)
	if err != nil {
		t.Fatalf("loadConfig(v2) error = %v", err)
	}
	if loaded.Identity == nil || loaded.Identity.NodeID != nodeID || loaded.Identity.ArtifactEncryptionKeyID != keyID || len(loaded.Identity.ArtifactEncryptionPrivateKey) != 32 {
		t.Fatalf("loaded identity = %+v", loaded.Identity)
	}
	if err := os.Chmod(identityDir, 0o755); err != nil {
		t.Fatal(err)
	}
	if _, _, err := loadConfig(path); err == nil {
		t.Fatal("loadConfig() accepted an unsafe identity directory")
	}
}

// ADR 0013 GW-02: an expired client certificate no longer stops the agent
// ("load enrollment identity"); it loads and is flagged for recovery.
func TestLoadConfigVersion2AcceptsExpiredCertificateForRecovery(t *testing.T) {
	root := secureConfigTempDir(t)
	now := time.Now().UTC()
	identityDir, nodeID, _ := writeIdentityFixtureValid(t, root, now.Add(-2*time.Hour), now.Add(-time.Minute))
	content, err := json.Marshal(validVersion2FileConfig(identityDir))
	if err != nil {
		t.Fatal(err)
	}
	path := filepath.Join(root, "config.json")
	if err := os.WriteFile(path, content, 0o600); err != nil {
		t.Fatal(err)
	}
	loaded, _, err := loadConfig(path)
	if err != nil {
		t.Fatalf("loadConfig(expired certificate) error = %v", err)
	}
	if loaded.Identity == nil || loaded.Identity.NodeID != nodeID || !loaded.Identity.CertificateExpired {
		t.Fatalf("loaded identity = %+v", loaded.Identity)
	}
	if got := loaded.Gateway.enrollmentAddress(); got != "gateway.internal:"+DefaultEnrollmentPort {
		t.Fatalf("enrollmentAddress() = %q", got)
	}
	loaded.Gateway.EnrollmentAddress = "enroll.internal:443"
	if got := loaded.Gateway.enrollmentAddress(); got != "enroll.internal:443" {
		t.Fatalf("enrollmentAddress(explicit) = %q", got)
	}
}

func TestLoadConfigPreflightsEnabledDiskGuardWithoutCreatingLock(t *testing.T) {
	root := secureConfigTempDir(t)
	configDirectory := filepath.Join(root, "config")
	logRoot := filepath.Join(root, "logs")
	stateRoot := filepath.Join(root, "state")
	for _, directory := range []string{configDirectory, logRoot, stateRoot} {
		if err := os.Mkdir(directory, 0o700); err != nil {
			t.Fatal(err)
		}
	}
	config := validFileConfig()
	config.DiskGuard.Enabled = true
	config.DiskGuard.LogRoot = logRoot
	config.DiskGuard.LockPath = filepath.Join(stateRoot, "diskguard.lock")
	content, err := json.Marshal(config)
	if err != nil {
		t.Fatal(err)
	}
	path := filepath.Join(configDirectory, "config.json")
	if err := os.WriteFile(path, content, 0o600); err != nil {
		t.Fatal(err)
	}
	if _, _, err := loadConfig(path); err != nil {
		t.Fatalf("loadConfig() error = %v", err)
	}
	if _, err := os.Lstat(config.DiskGuard.LockPath); !errors.Is(err, os.ErrNotExist) {
		t.Fatalf("configuration preflight created lock file: %v", err)
	}
	if err := os.Chmod(logRoot, 0o770); err != nil {
		t.Fatal(err)
	}
	if _, _, err := loadConfig(path); err == nil {
		t.Fatal("loadConfig() accepted a shared-writable log root")
	}
	if err := os.Chmod(logRoot, 0o700); err != nil {
		t.Fatal(err)
	}
	if err := os.Rename(logRoot, logRoot+"-missing"); err != nil {
		t.Fatal(err)
	}
	if _, _, err := loadConfig(path); err == nil {
		t.Fatal("loadConfig() accepted a missing log root")
	}
}

func TestDecodeConfigRejectsAmbiguousAndUnsafeInput(t *testing.T) {
	valid := validConfigJSON(t)
	var nullDiskGuardObject map[string]json.RawMessage
	if err := json.Unmarshal(valid, &nullDiskGuardObject); err != nil {
		t.Fatal(err)
	}
	nullDiskGuardObject["disk_guard"] = json.RawMessage("null")
	nullDiskGuard, err := json.Marshal(nullDiskGuardObject)
	if err != nil {
		t.Fatal(err)
	}
	tests := []struct {
		name    string
		content []byte
	}{
		{name: "missing version", content: bytes.Replace(valid, []byte(`"version":1,`), nil, 1)},
		{name: "unknown field", content: bytes.Replace(valid, []byte(`"version":1`), []byte(`"version":1,"unexpected":true`), 1)},
		{name: "duplicate field", content: bytes.Replace(valid, []byte(`"version":1`), []byte(`"version":1,"version":1`), 1)},
		{name: "trailing value", content: append(append([]byte(nil), valid...), []byte(` {}`)...)},
		{name: "invalid node", content: replaceJSONValue(valid, `"node_id":"`+validFileConfig().NodeID+`"`, `"node_id":"not-a-uuid"`)},
		{name: "remote health", content: replaceJSONValue(valid, `"health_url":"http://127.0.0.1:18080/healthz"`, `"health_url":"http://192.0.2.10:18080/healthz"`)},
		{name: "gateway URL", content: replaceJSONValue(valid, `"address":"gateway.internal:9443"`, `"address":"https://gateway.internal:9443"`)},
		{name: "zero limit", content: replaceJSONValue(valid, `"max_command_bytes":1048576`, `"max_command_bytes":0`)},
		{name: "unsafe config path", content: replaceJSONValue(valid, `"config_file":"nginx.conf"`, `"config_file":"../nginx.conf"`)},
		{name: "nested state roots", content: replaceJSONValue(valid, `"journal_dir":"/private/var/lib/cdnca-edge-agent/gateway-journal"`, `"journal_dir":"/private/var/lib/cdnca-edge-agent/deployments/gateway-journal"`)},
		{name: "custom deletion pattern", content: bytes.Replace(valid, []byte(`"enabled":false`), []byte(`"enabled":false,"patterns":["*"]`), 1)},
		{name: "null disk guard", content: nullDiskGuard},
	}
	for _, test := range tests {
		t.Run(test.name, func(t *testing.T) {
			if _, _, err := decodeConfig(test.content); err == nil {
				t.Fatal("decodeConfig() accepted invalid input")
			}
		})
	}
}

func TestSITE08DecodeConfigRequiresCanonicalIngressSourceAddresses(t *testing.T) {
	config := validFileConfig()
	config.IngressSourceIPv4 = "192.0.2.20"
	config.IngressSourceIPv6 = "2001:db8::20"
	content, err := json.Marshal(config)
	if err != nil {
		t.Fatal(err)
	}
	decoded, _, err := decodeConfig(content)
	if err != nil {
		t.Fatalf("decodeConfig() canonical ingress sources = %v", err)
	}
	if decoded.IngressSourceIPv4 != config.IngressSourceIPv4 || decoded.IngressSourceIPv6 != config.IngressSourceIPv6 {
		t.Fatalf("decoded ingress sources = %q/%q", decoded.IngressSourceIPv4, decoded.IngressSourceIPv6)
	}
	for _, address := range []string{"192.0.2.020", "::ffff:192.0.2.20", "fe80::1", "ff02::1"} {
		candidate := config
		candidate.IngressSourceIPv4 = address
		candidate.IngressSourceIPv6 = ""
		raw, marshalErr := json.Marshal(candidate)
		if marshalErr != nil {
			t.Fatal(marshalErr)
		}
		if _, _, err := decodeConfig(raw); err == nil {
			t.Fatalf("decodeConfig() accepted unsafe ingress source %q", address)
		}
	}
}

func slicesEqual(left, right []string) bool {
	if len(left) != len(right) {
		return false
	}
	for index := range left {
		if left[index] != right[index] {
			return false
		}
	}
	return true
}

func TestReadConfigFileRequiresOwnerOnlyRegularFile(t *testing.T) {
	path := filepath.Join(t.TempDir(), "edge-agent.json")
	if err := os.WriteFile(path, validConfigJSON(t), 0o600); err != nil {
		t.Fatal(err)
	}
	if _, err := readConfigFile(path); err != nil {
		t.Fatalf("readConfigFile() valid error = %v", err)
	}
	if err := os.Chmod(path, 0o644); err != nil {
		t.Fatal(err)
	}
	if _, err := readConfigFile(path); err == nil {
		t.Fatal("readConfigFile() accepted a group/world-readable file")
	}
	if err := os.Chmod(path, 0o600); err != nil {
		t.Fatal(err)
	}
	link := filepath.Join(t.TempDir(), "edge-agent-link.json")
	if err := os.Symlink(path, link); err != nil {
		t.Fatal(err)
	}
	if _, err := readConfigFile(link); err == nil {
		t.Fatal("readConfigFile() followed a symbolic link")
	}
}

func TestConfigRejectsStateRootWithSymlinkedAncestor(t *testing.T) {
	root, err := filepath.EvalSymlinks(t.TempDir())
	if err != nil {
		t.Fatal(err)
	}
	realDirectory := filepath.Join(root, "real")
	if err := os.Mkdir(realDirectory, 0o700); err != nil {
		t.Fatal(err)
	}
	link := filepath.Join(root, "link")
	if err := os.Symlink(realDirectory, link); err != nil {
		t.Fatal(err)
	}
	config := validFileConfig()
	config.DeploymentRoot = filepath.Join(link, "deployments")
	if _, err := config.validate(); err == nil {
		t.Fatal("configuration accepted a state root with a symlinked ancestor")
	}
}

func TestConfigPathUsesEnvironmentAndRejectsPositionals(t *testing.T) {
	lookup := func(name string) (string, bool) {
		if name == configPathEnv {
			return "/etc/cdnca/custom.json", true
		}
		return "", false
	}
	options, err := parseStartupOptions(nil, lookup)
	if err != nil || options.configPath != "/etc/cdnca/custom.json" {
		t.Fatalf("parseStartupOptions() = %+v, %v", options, err)
	}
	options, err = parseStartupOptions([]string{"-config", "/etc/cdnca/override.json", "-check-config"}, lookup)
	if err != nil || options.configPath != "/etc/cdnca/override.json" || !options.checkConfig {
		t.Fatalf("parseStartupOptions() override = %+v, %v", options, err)
	}
	if _, err := parseStartupOptions([]string{"extra"}, lookup); err == nil {
		t.Fatal("parseStartupOptions() accepted a positional argument")
	}
	if _, err := parseStartupOptions([]string{"-check-config", "-version"}, lookup); err == nil {
		t.Fatal("parseStartupOptions() accepted conflicting modes")
	}
}

func TestLoadConfigRejectsCertificateStateOverlapWithConfigDirectory(t *testing.T) {
	root := secureConfigTempDir(t)
	configDirectory := filepath.Join(root, "config")
	if err := os.Mkdir(configDirectory, 0o700); err != nil {
		t.Fatal(err)
	}
	path := filepath.Join(configDirectory, "edge-agent.json")
	tests := []struct {
		name      string
		stateRoot string
	}{
		{name: "state root contains config directory", stateRoot: root},
		{name: "config directory contains state root", stateRoot: filepath.Join(configDirectory, "certificates")},
	}
	for _, test := range tests {
		t.Run(test.name, func(t *testing.T) {
			config := validFileConfig()
			config.CertificateRuntime.StateRoot = test.stateRoot
			content, err := json.Marshal(config)
			if err != nil {
				t.Fatal(err)
			}
			if err := os.WriteFile(path, content, 0o600); err != nil {
				t.Fatal(err)
			}
			if _, _, err := loadConfig(path); err == nil {
				t.Fatal("loadConfig() accepted certificate state overlapping its configuration directory")
			}
		})
	}
}

func TestLoadConfigRejectsSymlinkedConfigurationAncestorOverlap(t *testing.T) {
	root := secureConfigTempDir(t)
	physical := filepath.Join(root, "physical")
	configDirectory := filepath.Join(physical, "config")
	if err := os.MkdirAll(configDirectory, 0o700); err != nil {
		t.Fatal(err)
	}
	link := filepath.Join(root, "linked")
	if err := os.Symlink(physical, link); err != nil {
		t.Fatal(err)
	}
	physicalPath := filepath.Join(configDirectory, "edge-agent.json")
	linkedPath := filepath.Join(link, "config", "edge-agent.json")
	tests := []struct {
		name      string
		stateRoot string
	}{
		{name: "physical state contains configuration", stateRoot: physical},
		{name: "physical configuration contains state", stateRoot: filepath.Join(configDirectory, "certificates")},
	}
	for _, test := range tests {
		t.Run(test.name, func(t *testing.T) {
			config := validFileConfig()
			config.CertificateRuntime.StateRoot = test.stateRoot
			content, err := json.Marshal(config)
			if err != nil {
				t.Fatal(err)
			}
			if err := os.WriteFile(physicalPath, content, 0o600); err != nil {
				t.Fatal(err)
			}
			if _, _, err := loadConfig(linkedPath); err == nil {
				t.Fatal("loadConfig() accepted a symlinked configuration ancestor that hid state overlap")
			}
		})
	}
}

func validFileConfig() fileConfig {
	config := defaultFileConfig()
	config.NodeID = uuid.MustParse("0f684f78-eb83-4c64-a354-bdd801a32fe5").String()
	config.ArtifactEncryptionKeyID = "enrollment-key-1"
	config.ArtifactTrustFile = "/etc/cdnca-edge-agent/trust/artifacts.json"
	config.DeploymentRoot = "/private/var/lib/cdnca-edge-agent/deployments"
	config.JournalDir = "/private/var/lib/cdnca-edge-agent/gateway-journal"
	config.CertificateRuntime = certificateSettings{
		StateRoot:     "/private/var/lib/cdnca-edge-agent/certificates",
		ListenAddress: "127.0.0.1",
		ListenPort:    18443,
	}
	config.Gateway = gatewaySettings{
		Address:              "gateway.internal:9443",
		ServerName:           "gateway.internal",
		RootCAFile:           "/etc/cdnca-edge-agent/tls/ca.pem",
		ClientCertificate:    "/etc/cdnca-edge-agent/tls/client.pem",
		ClientPrivateKeyFile: "/etc/cdnca-edge-agent/tls/client-key.pem",
	}
	// The worker group of the dynamic routing files: the test process's own
	// group, the only one an unprivileged test may chown to.
	config.DynamicRouting.WorkerGroup = testWorkerGroup()
	return config
}

func testWorkerGroup() string {
	group, err := user.LookupGroupId(strconv.Itoa(os.Getgid()))
	if err != nil {
		return "nobody"
	}
	return group.Name
}

func validVersion2FileConfig(identityDir string) fileConfig {
	config := validFileConfig()
	config.Version = 2
	config.NodeID = ""
	config.ArtifactEncryptionKeyID = ""
	config.IdentityDir = identityDir
	config.Gateway.ClientCertificate = ""
	config.Gateway.ClientPrivateKeyFile = ""
	return config
}

// secureConfigTempDir is a private test root short enough for the unix
// sockets the daemon binds below it (the dynamic routing state's auto
// defense collector; macOS t.TempDir() exceeds sun_path).
func secureConfigTempDir(t *testing.T) string {
	t.Helper()
	short, err := os.MkdirTemp("/tmp", "ea")
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { _ = os.RemoveAll(short) })
	// BSD /tmp hands new directories its own group: own it like t.TempDir().
	if err := os.Chown(short, os.Geteuid(), os.Getegid()); err != nil {
		t.Fatal(err)
	}
	root, err := filepath.EvalSymlinks(short)
	if err != nil {
		t.Fatal(err)
	}
	if err := os.Chmod(root, 0o700); err != nil {
		t.Fatal(err)
	}
	return root
}

func writeIdentityFixture(t *testing.T, root string) (string, string, string) {
	t.Helper()
	now := time.Now().UTC()
	return writeIdentityFixtureValid(t, root, now.Add(-time.Minute), now.Add(time.Hour))
}

// writeIdentityFixtureValid writes an enrolled identity whose client
// certificate is valid from notBefore to notAfter (the root covers it).
func writeIdentityFixtureValid(t *testing.T, root string, notBefore, notAfter time.Time) (string, string, string) {
	t.Helper()
	now := time.Now().UTC()
	nodeID := uuid.NewString()
	_, rootKey, err := ed25519.GenerateKey(rand.Reader)
	if err != nil {
		t.Fatal(err)
	}
	rootTemplate := &x509.Certificate{
		SerialNumber: big.NewInt(1), Subject: pkix.Name{CommonName: "test root"},
		NotBefore: notBefore.Add(-time.Hour), NotAfter: now.Add(time.Hour), IsCA: true,
		BasicConstraintsValid: true, KeyUsage: x509.KeyUsageCertSign | x509.KeyUsageDigitalSignature,
	}
	rootDER, err := x509.CreateCertificate(rand.Reader, rootTemplate, rootTemplate, rootKey.Public(), rootKey)
	if err != nil {
		t.Fatal(err)
	}
	rootCertificate, err := x509.ParseCertificate(rootDER)
	if err != nil {
		t.Fatal(err)
	}
	_, clientKey, err := ed25519.GenerateKey(rand.Reader)
	if err != nil {
		t.Fatal(err)
	}
	spiffe, err := url.Parse("spiffe://cdn-platform/node/" + nodeID)
	if err != nil {
		t.Fatal(err)
	}
	leafTemplate := &x509.Certificate{
		SerialNumber: big.NewInt(2), NotBefore: notBefore, NotAfter: notAfter,
		BasicConstraintsValid: true, KeyUsage: x509.KeyUsageDigitalSignature,
		ExtKeyUsage: []x509.ExtKeyUsage{x509.ExtKeyUsageClientAuth}, URIs: []*url.URL{spiffe},
	}
	leafDER, err := x509.CreateCertificate(rand.Reader, leafTemplate, rootCertificate, clientKey.Public(), rootKey)
	if err != nil {
		t.Fatal(err)
	}
	clientKeyDER, err := x509.MarshalPKCS8PrivateKey(clientKey)
	if err != nil {
		t.Fatal(err)
	}
	artifactKey, err := ecdh.X25519().GenerateKey(rand.Reader)
	if err != nil {
		t.Fatal(err)
	}
	digest := sha256.Sum256(artifactKey.PublicKey().Bytes())
	keyID := "x25519:" + hex.EncodeToString(digest[:])
	identity := map[string]any{
		"version": 1, "node_id": nodeID,
		"machine_fingerprint_sha256": base64.RawStdEncoding.EncodeToString(bytes.Repeat([]byte{1}, sha256.Size)),
		"selected_protocol_major":    1, "selected_protocol_minor": 0,
		"artifact_encryption_key_id": keyID, "client_certificate_file": "client.pem",
		"client_private_key_file": "client-key.pem", "artifact_encryption_private_key_file": "artifact-x25519-key.bin",
	}
	identityJSON, err := json.Marshal(identity)
	if err != nil {
		t.Fatal(err)
	}
	directory := filepath.Join(root, "identity")
	if err := os.Mkdir(directory, 0o700); err != nil {
		t.Fatal(err)
	}
	certificatePEM := append(pem.EncodeToMemory(&pem.Block{Type: "CERTIFICATE", Bytes: leafDER}), pem.EncodeToMemory(&pem.Block{Type: "CERTIFICATE", Bytes: rootDER})...)
	files := map[string][]byte{
		"identity.json": append(identityJSON, '\n'), "client.pem": certificatePEM,
		"client-key.pem":          pem.EncodeToMemory(&pem.Block{Type: "PRIVATE KEY", Bytes: clientKeyDER}),
		"artifact-x25519-key.bin": artifactKey.Bytes(),
	}
	for name, value := range files {
		if err := os.WriteFile(filepath.Join(directory, name), value, 0o600); err != nil {
			t.Fatal(err)
		}
	}
	return directory, nodeID, keyID
}

func validConfigJSON(t *testing.T) []byte {
	t.Helper()
	content, err := json.Marshal(validFileConfig())
	if err != nil {
		t.Fatal(err)
	}
	return content
}

func replaceJSONValue(content []byte, old, replacement string) []byte {
	return []byte(strings.Replace(string(content), old, replacement, 1))
}
