package main

import (
	"context"
	"encoding/json"
	"errors"
	"os"
	"path/filepath"
	"reflect"
	"testing"

	"github.com/cdnca/cdnca/agents/edge-agent/internal/certstore"
	"github.com/cdnca/cdnca/agents/edge-agent/internal/gatewayclient"
	"github.com/google/uuid"
)

type testCertificateRecoverer struct {
	started chan struct{}
	release <-chan struct{}
	err     error
}

func (recoverer *testCertificateRecoverer) Recover(ctx context.Context) (certstore.Result, error) {
	close(recoverer.started)
	if recoverer.release != nil {
		select {
		case <-recoverer.release:
		case <-ctx.Done():
			return certstore.Result{}, ctx.Err()
		}
	}
	return certstore.Result{}, recoverer.err
}

func TestAssembleClientWiresCertificateRuntimeAndPreservesConsumers(t *testing.T) {
	root := secureConfigTempDir(t)
	securityDir := filepath.Join(root, "security")
	if err := os.Mkdir(securityDir, 0o700); err != nil {
		t.Fatal(err)
	}
	certificatePEM, privateKeyPEM, publicKeyPEM := testSecurityMaterial(t)
	rootCAFile := writeTestFile(t, securityDir, "ca.pem", certificatePEM, 0o600)
	clientCertificateFile := writeTestFile(t, securityDir, "client.pem", certificatePEM, 0o600)
	clientPrivateKeyFile := writeTestFile(t, securityDir, "client-key.pem", privateKeyPEM, 0o600)
	trustContent, err := json.Marshal(map[string]any{
		"version": 1,
		"keys":    []map[string]string{{"key_id": "artifact-key", "public_key_pem": string(publicKeyPEM)}},
	})
	if err != nil {
		t.Fatal(err)
	}
	trustFile := writeTestFile(t, securityDir, "trust.json", trustContent, 0o400)

	base := validFileConfig()
	base.ArtifactTrustFile = trustFile
	base.DeploymentRoot = filepath.Join(root, "deployments")
	base.JournalDir = filepath.Join(root, "gateway-journal")
	base.Gateway.RootCAFile = rootCAFile
	base.Gateway.ClientCertificate = clientCertificateFile
	base.Gateway.ClientPrivateKeyFile = clientPrivateKeyFile
	base.OpenResty.Binary = trueBinary(t)
	rawBase, err := json.Marshal(base)
	if err != nil {
		t.Fatal(err)
	}
	var document map[string]any
	if err := json.Unmarshal(rawBase, &document); err != nil {
		t.Fatal(err)
	}
	stateRoot := filepath.Join(root, "certificates")
	document["certificate_runtime"] = map[string]any{
		"state_root": stateRoot, "listen_address": "127.0.0.1", "listen_port": 18443,
	}
	content, err := json.Marshal(document)
	if err != nil {
		t.Fatal(err)
	}
	config, timeouts, err := decodeConfig(content)
	if err != nil {
		t.Fatalf("decode certificate runtime configuration: %v", err)
	}
	runner, err := assembleClient(config, timeouts, uuid.NewString())
	if err != nil {
		t.Fatalf("assemble certificate runtime: %v", err)
	}
	daemon, ok := runner.(*daemonClient)
	if !ok {
		t.Fatalf("assembled runner type = %T", runner)
	}
	client, ok := daemon.client.(*gatewayclient.Client)
	if !ok {
		t.Fatalf("assembled gateway client type = %T", daemon.client)
	}
	clientValue := reflect.ValueOf(client).Elem()
	for _, field := range []string{"manager", "certificate", "acmeHTTP01"} {
		value := clientValue.FieldByName(field)
		if !value.IsValid() || value.IsNil() {
			t.Errorf("gateway client %s consumer is not configured", field)
		}
	}
	managerValue := reflect.ValueOf(daemon.certificate).Elem()
	runtimeValue := managerValue.FieldByName("runtime").Elem().Elem()
	if got, want := runtimeValue.FieldByName("pidFile").String(), filepath.Join(stateRoot, "shared", "nginx.pid"); got != want {
		t.Fatalf("certificate runtime PID file = %q, want %q", got, want)
	}
	if got, want := runtimeValue.FieldByName("dialAddress").String(), "127.0.0.1:18443"; got != want {
		t.Fatalf("certificate runtime dial address = %q, want %q", got, want)
	}
	if info, statErr := os.Stat(stateRoot); statErr != nil || !info.IsDir() || info.Mode().Perm()&0o077 != 0 {
		t.Fatalf("certificate state root is unsafe: info=%v err=%v", info, statErr)
	}

	for _, test := range []struct {
		name   string
		config map[string]any
	}{
		{name: "non-loopback", config: map[string]any{"state_root": stateRoot, "listen_address": "0.0.0.0", "listen_port": 18443}},
		{name: "mapped-loopback", config: map[string]any{"state_root": stateRoot, "listen_address": "::ffff:127.0.0.1", "listen_port": 18443}},
		{name: "zoned-ipv6", config: map[string]any{"state_root": stateRoot, "listen_address": "::1%lo0", "listen_port": 18443}},
		{name: "zero-port", config: map[string]any{"state_root": stateRoot, "listen_address": "127.0.0.1", "listen_port": 0}},
		{name: "relative-state", config: map[string]any{"state_root": "certificates", "listen_address": "127.0.0.1", "listen_port": 18443}},
		{name: "root-state", config: map[string]any{"state_root": string(filepath.Separator), "listen_address": "127.0.0.1", "listen_port": 18443}},
		{name: "deployment-overlap", config: map[string]any{"state_root": base.DeploymentRoot, "listen_address": "127.0.0.1", "listen_port": 18443}},
		{name: "journal-overlap", config: map[string]any{"state_root": base.JournalDir, "listen_address": "127.0.0.1", "listen_port": 18443}},
	} {
		t.Run(test.name, func(t *testing.T) {
			document["certificate_runtime"] = test.config
			invalid, marshalErr := json.Marshal(document)
			if marshalErr != nil {
				t.Fatal(marshalErr)
			}
			if _, _, decodeErr := decodeConfig(invalid); decodeErr == nil {
				t.Fatal("unsafe certificate runtime configuration was accepted")
			}
		})
	}

	validCertificateRuntime := map[string]any{
		"state_root": stateRoot, "listen_address": "127.0.0.1", "listen_port": 18443,
	}
	for _, test := range []struct {
		name  string
		value any
		omit  bool
	}{
		{name: "missing", omit: true},
		{name: "null", value: nil},
		{name: "scalar", value: "invalid"},
		{name: "unknown-field", value: map[string]any{
			"state_root": stateRoot, "listen_address": "127.0.0.1", "listen_port": 18443, "unknown": true,
		}},
	} {
		t.Run(test.name, func(t *testing.T) {
			if test.omit {
				delete(document, "certificate_runtime")
			} else {
				document["certificate_runtime"] = test.value
			}
			invalid, marshalErr := json.Marshal(document)
			if marshalErr != nil {
				t.Fatal(marshalErr)
			}
			if _, _, decodeErr := decodeConfig(invalid); decodeErr == nil {
				t.Fatal("invalid certificate runtime configuration was accepted")
			}
			document["certificate_runtime"] = validCertificateRuntime
		})
	}

	symlinkTarget := filepath.Join(root, "certificate-target")
	if err := os.Mkdir(symlinkTarget, 0o700); err != nil {
		t.Fatal(err)
	}
	symlink := filepath.Join(root, "certificate-link")
	if err := os.Symlink(symlinkTarget, symlink); err != nil {
		t.Fatal(err)
	}
	document["certificate_runtime"] = map[string]any{
		"state_root": filepath.Join(symlink, "state"), "listen_address": "127.0.0.1", "listen_port": 18443,
	}
	invalidSymlink, err := json.Marshal(document)
	if err != nil {
		t.Fatal(err)
	}
	if _, _, err := decodeConfig(invalidSymlink); err == nil {
		t.Fatal("certificate state with a symlink ancestor was accepted")
	}

	version2 := validVersion2FileConfig(filepath.Join(root, "identity"))
	version2.CertificateRuntime.StateRoot = filepath.Join(version2.IdentityDir, "certificates")
	if _, err := version2.validate(); err == nil {
		t.Fatal("certificate state overlapping the v2 identity directory was accepted")
	}

	unsafeStateRoot := filepath.Join(root, "unsafe-certificates")
	if err := os.Mkdir(unsafeStateRoot, 0o755); err != nil {
		t.Fatal(err)
	}
	if err := os.Chmod(unsafeStateRoot, 0o755); err != nil {
		t.Fatal(err)
	}
	document["certificate_runtime"] = map[string]any{
		"state_root": unsafeStateRoot, "listen_address": "127.0.0.1", "listen_port": 18443,
	}
	unsafeContent, err := json.Marshal(document)
	if err != nil {
		t.Fatal(err)
	}
	unsafeConfig, unsafeTimeouts, err := decodeConfig(unsafeContent)
	if err != nil {
		t.Fatalf("decode constructor-failure configuration: %v", err)
	}
	if _, err := assembleClient(unsafeConfig, unsafeTimeouts, uuid.NewString()); err == nil {
		t.Fatal("certificate manager construction failure was ignored")
	}
}

func TestDaemonRecoversCertificatesBeforeGatewayClient(t *testing.T) {
	release := make(chan struct{})
	recoverer := &testCertificateRecoverer{started: make(chan struct{}), release: release}
	client := &blockingClient{started: make(chan struct{})}
	daemon := &daemonClient{client: client, certificate: recoverer}
	ctx, cancel := context.WithCancel(context.Background())
	done := make(chan error, 1)
	go func() { done <- daemon.Run(ctx) }()

	waitChannel(t, recoverer.started, "certificate recovery")
	select {
	case <-client.started:
		t.Fatal("gateway client started before certificate recovery completed")
	default:
	}
	close(release)
	waitChannel(t, client.started, "gateway client after certificate recovery")
	cancel()
	if err := waitError(t, done, "daemon stop"); !errors.Is(err, context.Canceled) {
		t.Fatalf("daemon Run() error = %v", err)
	}

	recoveryErr := errors.New("recovery failed")
	failedClient := &blockingClient{started: make(chan struct{})}
	failed := &daemonClient{
		client: failedClient,
		certificate: &testCertificateRecoverer{
			started: make(chan struct{}),
			err:     recoveryErr,
		},
	}
	if err := failed.Run(context.Background()); !errors.Is(err, recoveryErr) {
		t.Fatalf("daemon Run() recovery error = %v", err)
	}
	select {
	case <-failedClient.started:
		t.Fatal("gateway client started after certificate recovery failed")
	default:
	}
}

func TestCertificateRuntimeRejectsWritableRootOverlap(t *testing.T) {
	root := secureConfigTempDir(t)
	certificateRoot := filepath.Join(root, "certificates")
	securityRoot := filepath.Join(root, "security")
	base := validFileConfig()
	base.CertificateRuntime.StateRoot = certificateRoot
	base.ArtifactTrustFile = filepath.Join(securityRoot, "trust.json")
	base.Gateway.RootCAFile = filepath.Join(securityRoot, "ca.pem")
	base.Gateway.ClientCertificate = filepath.Join(securityRoot, "client.pem")
	base.Gateway.ClientPrivateKeyFile = filepath.Join(securityRoot, "client-key.pem")

	for _, test := range []struct {
		name   string
		mutate func(*fileConfig)
	}{
		{name: "telemetry-spool", mutate: func(config *fileConfig) {
			config.Telemetry.Enabled = true
			config.Telemetry.SpoolRoot = certificateRoot
		}},
		{name: "disk-guard-log", mutate: func(config *fileConfig) {
			config.DiskGuard.Enabled = true
			config.DiskGuard.LogRoot = certificateRoot
		}},
		{name: "disk-guard-lock", mutate: func(config *fileConfig) {
			config.DiskGuard.Enabled = true
			config.DiskGuard.LockPath = filepath.Join(certificateRoot, "diskguard.lock")
		}},
		{name: "v1-security-directory", mutate: func(config *fileConfig) {
			config.CertificateRuntime.StateRoot = securityRoot
		}},
	} {
		t.Run(test.name, func(t *testing.T) {
			config := base
			test.mutate(&config)
			if _, err := config.validate(); err == nil {
				t.Fatal("certificate runtime writable-root overlap was accepted")
			}
		})
	}

	protected := base.diskGuardProtectedPaths()
	for _, path := range protected {
		if path == certificateRoot {
			return
		}
	}
	t.Fatal("certificate state root is not protected from disk guard")
}
