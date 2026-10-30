package main

import (
	"bufio"
	"bytes"
	"context"
	"crypto/ed25519"
	"crypto/x509"
	"encoding/json"
	"encoding/pem"
	"os"
	"os/exec"
	"path/filepath"
	"strings"
	"testing"
	"time"

	"github.com/cdnca/cdnca/services/control-api/internal/analyticsconnections"
	"github.com/cdnca/cdnca/services/control-api/internal/config"
)

func TestNativeControlRuntimeEnvironmentProductionLoaders(t *testing.T) {
	// Only temporary files and local key generation: do not call runServer,
	// constructors that connect to dependencies, systemctl, or a real installer.
	fixture, err := filepath.Abs("../../../../scripts/native-runtime/test_configure_control_runtime.py")
	if err != nil {
		t.Fatal(err)
	}
	directory := t.TempDir()
	command := exec.Command("python3", "-I", "-B", "-c", `
import importlib.util, sys
spec = importlib.util.spec_from_file_location("native_fixture", sys.argv[1])
fixture = importlib.util.module_from_spec(spec)
spec.loader.exec_module(fixture)
runtime = fixture.native_runtime_test_fixture(sys.argv[2])
runtime.native_control_runtime("install")
runtime.native_control_runtime("check")
`, fixture, directory)
	if output, err := command.CombinedOutput(); err != nil || len(output) != 0 {
		// The fixture contains credentials. Never forward subprocess output.
		t.Fatalf("isolated runtime generator fixture failed: %v", err)
	}
	for _, entry := range os.Environ() {
		name, _, _ := strings.Cut(entry, "=")
		t.Setenv(name, "")
		if err := os.Unsetenv(name); err != nil {
			t.Fatal("cannot isolate runtime environment")
		}
	}
	environment := make(map[string]string)
	for index, name := range []string{"control.env", "runtime-extra.env"} {
		contents, err := os.ReadFile(filepath.Join(directory, "control", name))
		if err != nil {
			t.Fatal(err)
		}
		scanner := bufio.NewScanner(bytes.NewReader(contents))
		count := 0
		for scanner.Scan() {
			line := scanner.Text()
			if line == "" || strings.HasPrefix(line, "#") {
				continue
			}
			key, value, ok := strings.Cut(line, "=")
			if !ok {
				t.Fatal("invalid generated environment structure")
			}
			if strings.HasPrefix(value, "'") {
				if len(value) < 2 || !strings.HasSuffix(value, "'") || strings.Contains(value[1:len(value)-1], "'") {
					t.Fatal("unexpected generated environment quoting")
				}
				value = value[1 : len(value)-1]
			}
			environment[key] = value // EnvironmentFile order: extra overrides base.
			count++
		}
		if err := scanner.Err(); err != nil {
			t.Fatal(err)
		}
		if _, duplicated := environment["EDGE_PUBLISH_RUNTIME_ENABLED"]; index == 0 && duplicated {
			t.Fatal("edge publication switches belong to runtime-extra.env only")
		}
		if index == 1 && count != 51 {
			t.Fatal("native environment must contain exactly the approved 51 settings")
		}
		if index == 1 && environment["NODE_PORT_TRANSITION_RUNTIME_ENABLED"] != "true" {
			t.Fatal("native installs must run the node port transition runtime (FX39)")
		}
		if _, found := environment["PACKAGE_AUTO_RENEW_ENABLED"]; index == 1 && found {
			t.Fatal("the community edition has no package auto-renew worker")
		}
	}
	for name, value := range environment {
		t.Setenv(name, value)
	}
	entries := os.Environ()
	cfg, err := config.Load()
	if err != nil {
		t.Fatalf("production main config rejected generated environment: %v", err)
	}
	if !cfg.AnalyticsQueryEnabled || !cfg.AnalyticsIngest.Enabled || cfg.ClickHouseUsername == cfg.AnalyticsIngest.ClickHouseUsername || len(cfg.AnalyticsIngest.IsolationWrappingKey) != 32 {
		t.Fatal("query/ingest identities or isolation key were not configured")
	}
	coverage, err := loadRealtimeCoverageRuntimeConfigFromEnv(entries)
	if err != nil || !coverage.Enabled || coverage.PollInterval != 30*time.Second || coverage.FinalizationGrace != 2*time.Minute {
		t.Fatal("realtime coverage finalizer must load with bounded native defaults")
	}
	logsCursor, err := loadAnalyticsLogsCursorKeyring(cfg.AnalyticsQueryEnabled, os.LookupEnv)
	if err != nil || logsCursor.ActiveKID != "native-analytics-logs-cursor-v1" || len(logsCursor.Keys) != 1 {
		t.Fatal("analytics logs loader rejected generated cursor keyring")
	}
	defer clearAnalyticsLogsCursorKeyring(&logsCursor)
	logsKey := logsCursor.Keys[logsCursor.ActiveKID]
	if len(logsKey) != 32 || bytes.Equal(logsKey, cfg.AnalyticsIngest.IsolationWrappingKey) {
		t.Fatal("analytics logs cursor must use an independent key")
	}
	connections := analyticsConnectionsRuntimeConfig(cfg)
	if err := analyticsconnections.ValidateRuntimeConfig(connections); err != nil || connections.Username != cfg.AnalyticsIngest.ClickHouseUsername || connections.Password != cfg.AnalyticsIngest.ClickHousePassword {
		t.Fatal("connections writer did not load the independent ingest identity")
	}
	traffic, err := loadPackageTrafficEnforcementConfigFromEnv(entries)
	if err != nil || !traffic.Enabled || traffic.WorkerID != "package-traffic-1" {
		t.Fatalf("package traffic enforcement loader rejected generated environment: %v", err)
	}
	realtime, err := loadAnalyticsRealtimeRuntimeConfigFromEnv(entries)
	if err != nil || !realtime.Enabled || len(realtime.CursorKey) != 32 || bytes.Equal(realtime.CursorKey, logsKey) {
		t.Fatalf("analytics realtime loader rejected generated environment: %v", err)
	}
	defer realtime.clearSecrets()
	if geo, err := loadAnalyticsGeoArtifactRuntimeConfigFromEnv(entries); err != nil || geo.Enabled {
		t.Fatalf("analytics geo artifact must load disabled: %v", err)
	}
	system, err := loadSystemConfigurationRuntimeConfigFromEnv(entries)
	if err != nil || !system.Enabled {
		t.Fatalf("system configuration loader rejected generated environment: %v", err)
	}
	edge, err := loadEdgePublishRuntimeConfigFromEnvEntries(entries)
	if err != nil || !edge.Enabled {
		t.Fatalf("publisher loader rejected generated environment: %v", err)
	}
	defer edge.clearSecrets()
	if bytes.Equal(logsKey, edge.Runtime.CursorActiveKey.Secret) {
		t.Fatal("analytics logs and publisher cursors must not share a key")
	}
	security, err := loadSecurityActivationRuntimeConfigFromEnvEntries(entries)
	if err != nil || !security.Enabled || security.Core.RequiredWAFAPIVersion != 1 || security.Core.RequiredCCAPIVersion != 2 {
		t.Fatalf("security activation loader rejected generated environment: %v", err)
	}
	brand, err := loadBrandAssetRuntimeConfig()
	if err != nil || !brand.Enabled || brand.ObjectStore.Prefix != "brand-assets" {
		t.Fatalf("brand loader rejected generated environment: %v", err)
	}
	errorPages, err := loadErrorPageRuntimeConfig()
	if err != nil || !errorPages.Enabled || errorPages.ObjectStore.Prefix != "error-pages" || errorPages.Scanner.SocketPath != "/var/run/clamav/clamd.ctl" {
		t.Fatalf("error page loader rejected generated environment: %v", err)
	}
	brandIdentity, err := brand.ObjectStore.Credentials.Retrieve(context.Background())
	if err != nil {
		t.Fatal("cannot read generated brand identity")
	}
	errorIdentity, err := errorPages.ObjectStore.Credentials.Retrieve(context.Background())
	if err != nil || brandIdentity.AccessKeyID == errorIdentity.AccessKeyID || brandIdentity.SecretAccessKey == errorIdentity.SecretAccessKey {
		t.Fatal("object store runtime identities must be independent")
	}
	signer, err := loadEdgePublishArtifactSigner(true)
	if err != nil {
		t.Fatal("production signer rejected generated Ed25519 key")
	}
	defer signer.Close()
	trustBytes, err := os.ReadFile(filepath.Join(directory, "control", "runtime-publisher-trust.json"))
	if err != nil {
		t.Fatal(err)
	}
	var trust struct {
		Version int `json:"version"`
		Keys    []struct {
			KeyID string `json:"key_id"`
			PEM   string `json:"public_key_pem"`
		} `json:"keys"`
	}
	if err := json.Unmarshal(trustBytes, &trust); err != nil || trust.Version != 1 || len(trust.Keys) != 1 || trust.Keys[0].KeyID != signer.KeyID() {
		t.Fatal("publisher trust schema or key ID mismatch")
	}
	block, remainder := pem.Decode([]byte(trust.Keys[0].PEM))
	if block == nil || block.Type != "PUBLIC KEY" || len(remainder) != 0 {
		t.Fatal("publisher trust must contain only public key material")
	}
	key, err := x509.ParsePKIXPublicKey(block.Bytes)
	public, ok := key.(ed25519.PublicKey)
	if err != nil || !ok || !bytes.Equal(public, signer.PublicKey()) {
		t.Fatal("publisher public/private key mismatch")
	}
	payload := []byte("isolated-native-runtime-signer-test")
	signature, err := signer.SignArtifact(context.Background(), payload)
	if err != nil || !ed25519.Verify(public, payload, signature) {
		t.Fatal("production signer cannot verify using generated public trust")
	}
}
