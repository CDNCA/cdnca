package main

import (
	"bytes"
	"context"
	"crypto/ed25519"
	"crypto/x509"
	"encoding/base64"
	"encoding/json"
	"encoding/pem"
	"errors"
	"os"
	"path/filepath"
	"reflect"
	"strings"
	"testing"
	"time"

	"github.com/cdnca/cdnca/services/control-api/internal/controlupgrade"
)

func TestControlUpgradeRuntimeConfigurationIsStrictAndDisabledReadsNoFiles(t *testing.T) {
	disabled, err := loadControlUpgradeRuntimeConfigFromEnv([]string{
		controlUpgradeEnabledEnv + "=false",
		controlUpgradeCommandGrantTrustFileEnv + "=/does/not/exist",
		controlUpgradeControlSigningPrivateKeyFileEnv + "=/does/not/exist",
		controlUpgradeEdgeSigningPrivateKeyFileEnv + "=/does/not/exist",
	})
	if err != nil || disabled.Enabled {
		t.Fatalf("disabled config = (%+v,%v)", disabled, err)
	}

	environment := controlUpgradeValidRuntimeEnvironment(t)
	config, err := loadControlUpgradeRuntimeConfigFromEnv(environment)
	if err != nil {
		t.Fatal(err)
	}
	if !config.Enabled || config.NATSName != "cdnca-control-upgrade" || config.WorkerID != "control-upgrade-1" ||
		config.CommandIssuanceTTL != 6*time.Hour || config.ExecutionTTL != 10*time.Minute ||
		config.RequiredConsecutiveSuccesses != 3 || config.ShutdownTimeout != 10*time.Second {
		t.Fatalf("runtime config = %+v", config)
	}
	if config.DownloadRootCAFile != "" {
		t.Fatalf("download root defaults to the node's system root, got %q", config.DownloadRootCAFile)
	}
	// fix-btenv3: optional private root for the signed download policy.
	withRoot, err := loadControlUpgradeRuntimeConfigFromEnv(append(append([]string(nil), environment...),
		controlUpgradeDownloadRootCAFileEnv+"=/etc/cdnca-control/keys/pki/root-ca-cert.pem"))
	if err != nil || withRoot.DownloadRootCAFile != "/etc/cdnca-control/keys/pki/root-ca-cert.pem" {
		t.Fatalf("download root = (%q,%v)", withRoot.DownloadRootCAFile, err)
	}

	for name, mutate := range map[string]func([]string) []string{
		"relative download root": func(values []string) []string {
			return append(values, controlUpgradeDownloadRootCAFileEnv+"=keys/root.pem")
		},
		"missing": func(values []string) []string {
			return controlUpgradeDropEnvironment(values, controlUpgradeNATSNameEnv)
		},
		"duplicate": func(values []string) []string {
			return append(values, controlUpgradeNATSNameEnv+"=duplicate")
		},
		"unknown": func(values []string) []string {
			return append(values, "CONTROL_UPGRADE_UNKNOWN=true")
		},
		"whitespace": func(values []string) []string {
			return controlUpgradeReplaceEnvironment(values, controlUpgradeWorkerIDEnv, " worker")
		},
		"same signer identity": func(values []string) []string {
			return controlUpgradeReplaceEnvironment(values, controlUpgradeEdgeSigningKeyIDEnv, "control-upgrade-signing")
		},
		"execution too long": func(values []string) []string {
			return controlUpgradeReplaceEnvironment(values, controlUpgradeExecutionTTLEnv, "7h")
		},
		"zero successes": func(values []string) []string {
			return controlUpgradeReplaceEnvironment(values, controlUpgradeRequiredSuccessesEnv, "0")
		},
		"drain exceeds shutdown": func(values []string) []string {
			return controlUpgradeReplaceEnvironment(values, controlUpgradeNATSDrainTimeoutEnv, "11s")
		},
		"missing artifact cache": func(values []string) []string {
			return controlUpgradeDropEnvironment(values, controlUpgradeArtifactCacheDirEnv)
		},
		"relative artifact cache": func(values []string) []string {
			return controlUpgradeReplaceEnvironment(values, controlUpgradeArtifactCacheDirEnv, "downloads/upgrades")
		},
		"plain HTTP artifact base": func(values []string) []string {
			return controlUpgradeReplaceEnvironment(values, controlUpgradeArtifactBaseURLEnv, "http://cdnca.com/downloads")
		},
		"trailing slash artifact base": func(values []string) []string {
			return controlUpgradeReplaceEnvironment(values, controlUpgradeArtifactBaseURLEnv, "https://cdnca.com/downloads/")
		},
	} {
		t.Run(name, func(t *testing.T) {
			candidate := append([]string(nil), environment...)
			if config, err := loadControlUpgradeRuntimeConfigFromEnv(mutate(candidate)); err == nil || config.Enabled {
				t.Fatalf("invalid config = (%+v,%v)", config, err)
			}
		})
	}
}

func TestControlUpgradeRuntimeAllowsControlPlaneEnvironment(t *testing.T) {
	environment := controlUpgradeValidRuntimeEnvironment(t)
	want, err := loadControlUpgradeRuntimeConfigFromEnv(environment)
	if err != nil {
		t.Fatal(err)
	}
	siblingEnvironment := []string{
		"CONTROL_UPGRADE_PLAN_WRITER_ENABLED=true",
		"CONTROL_UPGRADE_EXPECTED_REPLICAS=3",
		"CONTROL_UPGRADE_QUORUM=2",
		"CONTROL_UPGRADE_PROTOCOL_VERSION=1",
		"CONTROL_UPGRADE_KUBERNETES_API=https://kubernetes.example.test",
		"CONTROL_UPGRADE_KUBERNETES_NAMESPACE=cdnca",
		"CONTROL_UPGRADE_PLAN_SECRET=control-upgrade-plan",
		"CONTROL_UPGRADE_PLAN_SECRET_KEY=plan.json",
		"CONTROL_UPGRADE_STATE_SECRET_KEY=state.json",
		"CONTROL_UPGRADE_KUBERNETES_TOKEN_FILE=/control-upgrade/kubernetes-token",
		"CONTROL_UPGRADE_KUBERNETES_CA_FILE=/control-upgrade/kubernetes-ca.pem",
		"CONTROL_UPGRADE_REPLICA_ID=control-1",
		controlUpgradePlanEnabledEnv + "=true",
		controlUpgradePlanTokenFileEnv + "=/control-upgrade/internal-token",
	}
	cases := map[string][]string{"combined": siblingEnvironment}
	for _, entry := range siblingEnvironment {
		name, _, _ := strings.Cut(entry, "=")
		cases[name] = []string{entry}
	}
	for name, entries := range cases {
		t.Run(name, func(t *testing.T) {
			candidate := append(append([]string(nil), environment...), entries...)
			got, err := loadControlUpgradeRuntimeConfigFromEnv(candidate)
			if err != nil || !reflect.DeepEqual(got, want) {
				t.Fatalf("shared environment changed node runtime config: (%+v, %v)", got, err)
			}
			if name == "combined" {
				plan, err := loadControlUpgradePlanRuntimeConfigFromEnv(candidate, "11111111-1111-4111-8111-111111111111")
				if err != nil || !plan.Enabled || plan.TokenFile != "/control-upgrade/internal-token" {
					t.Fatalf("shared plan runtime config = (%+v, %v)", plan, err)
				}
			}
		})
	}
}

func TestControlUpgradeRuntimeSharedEnvironmentRemainsStrict(t *testing.T) {
	environment := append(controlUpgradeValidRuntimeEnvironment(t),
		controlUpgradePlanEnabledEnv+"=true", controlUpgradePlanTokenFileEnv+"=/does/not/exist")
	for name, mutate := range map[string]func([]string) []string{
		"unknown": func(values []string) []string {
			return append(values, "CONTROL_UPGRADE_UNKNOWN=true")
		},
		"node typo": func(values []string) []string {
			return append(values, "CONTROL_UPGRADE_NATS_NAM=typo")
		},
		"plan writer typo": func(values []string) []string {
			return append(values, "CONTROL_UPGRADE_PLAN_WRITER_ENABELD=true")
		},
		"unknown systemd setting": func(values []string) []string {
			return append(values, "CONTROL_UPGRADE_SYSTEMD_PLAN_SOURCE_EXTRA=true")
		},
		"unknown kubernetes setting": func(values []string) []string {
			return append(values, "CONTROL_UPGRADE_KUBERNETES_EXTRA=true")
		},
		"missing required node setting": func(values []string) []string {
			return controlUpgradeDropEnvironment(values, controlUpgradeNATSNameEnv)
		},
		"duplicate node setting": func(values []string) []string {
			return append(values, controlUpgradeNATSNameEnv+"=duplicate")
		},
		"duplicate disabled flag": func(values []string) []string {
			return append(values, controlUpgradeEnabledEnv+"=false")
		},
	} {
		t.Run(name, func(t *testing.T) {
			candidate := mutate(append([]string(nil), environment...))
			if config, err := loadControlUpgradeRuntimeConfigFromEnv(candidate); err == nil || config.Enabled {
				t.Fatalf("invalid shared config = (%+v, %v)", config, err)
			}
		})
	}
	for _, flag := range []string{"", "false"} {
		t.Run("disabled "+flag, func(t *testing.T) {
			candidate := controlUpgradeReplaceEnvironment(append([]string(nil), environment...), controlUpgradeEnabledEnv, flag)
			candidate = controlUpgradeReplaceEnvironment(candidate, controlUpgradeCommandGrantTrustFileEnv, "/does/not/exist")
			candidate = append(candidate, "CONTROL_UPGRADE_UNKNOWN=true")
			if config, err := loadControlUpgradeRuntimeConfigFromEnv(candidate); err != nil || config.Enabled {
				t.Fatalf("disabled shared config = (%+v, %v)", config, err)
			}
		})
	}
	for _, name := range []string{controlUpgradePlanEnabledEnv, controlUpgradePlanTokenFileEnv} {
		t.Run("duplicate sibling "+name, func(t *testing.T) {
			candidate := append(append([]string(nil), environment...), name+"="+controlUpgradeEnvironmentValue(environment, name))
			if config, err := loadControlUpgradePlanRuntimeConfigFromEnv(candidate, "11111111-1111-4111-8111-111111111111"); err == nil || config.Enabled {
				t.Fatalf("duplicate plan config = (%+v, %v)", config, err)
			}
		})
	}
}

func TestControlUpgradeRuntimeRejectsSymlinksAndClearsOwnedSigningKeys(t *testing.T) {
	environment := controlUpgradeValidRuntimeEnvironment(t)
	controlPath := controlUpgradeEnvironmentValue(environment, controlUpgradeControlSigningPrivateKeyFileEnv)
	symlink := filepath.Join(t.TempDir(), "control.pem")
	if err := os.Symlink(controlPath, symlink); err != nil {
		t.Fatal(err)
	}
	candidate := controlUpgradeReplaceEnvironment(append([]string(nil), environment...),
		controlUpgradeControlSigningPrivateKeyFileEnv, symlink)
	if config, err := loadControlUpgradeRuntimeConfigFromEnv(candidate); err == nil || config.Enabled {
		t.Fatalf("symlink config = (%+v,%v)", config, err)
	}

	privateKey, err := controlUpgradeLoadPrivateKey(controlPath)
	if err != nil {
		t.Fatal(err)
	}
	signer := &controlUpgradeEd25519Signer{keyID: "control-upgrade-signing",
		privateKey: append(ed25519.PrivateKey(nil), privateKey...)}
	owned := signer.privateKey
	signature, err := signer.Sign(context.Background(), []byte("control-upgrade"))
	if err != nil || len(signature) != ed25519.SignatureSize {
		t.Fatalf("sign = (%x,%v)", signature, err)
	}
	signer.close()
	for index, value := range owned {
		if value != 0 {
			t.Fatalf("owned key byte %d was not cleared", index)
		}
	}
	clear(privateKey)
	if _, err := signer.Sign(context.Background(), []byte("after-close")); err == nil {
		t.Fatal("closed signer remained usable")
	}
}

func TestControlUpgradeMainCompositionContract(t *testing.T) {
	mainSource, err := os.ReadFile("main.go")
	if err != nil {
		t.Fatal(err)
	}
	for _, required := range []string{
		"loadControlUpgradeRuntimeConfig()",
		"openControlUpgradeProductionRuntime(",
		"ControlUpgradeService:               controlUpgradeService,",
		"readinessProbes = append(readinessProbes, controlUpgradeRuntime)",
		"controlUpgradeRuntime.Run(ctx)",
		"defer controlUpgradeRuntime.Close()",
	} {
		if !bytes.Contains(mainSource, []byte(required)) {
			t.Errorf("main composition missing %q", required)
		}
	}
}

func TestControlUpgradeCompositionRequiresLegacyAndV2StatusSubjects(t *testing.T) {
	source, err := os.ReadFile("control_upgrade_runtime.go")
	if err != nil {
		t.Fatal(err)
	}
	for _, required := range []string{
		`controlUpgradeStatusV2Subject`,
		`"cdnca.agent.deployment-status.upgrade-v2"`,
		`{controlUpgradeStatusStream, controlUpgradeStatusV2Subject, controlUpgradeMaxStatusBytes}`,
	} {
		if !bytes.Contains(source, []byte(required)) {
			t.Fatalf("control upgrade composition missing %q", required)
		}
	}
}

func TestControlUpgradeLicenseReceiptWorkerCompositionContract(t *testing.T) {
	field, ok := reflect.TypeOf(controlUpgradeProductionRuntime{}).FieldByName("receiptDispatcher")
	if !ok || field.Type != reflect.TypeOf((*controlupgrade.LicenseReceiptDispatcher)(nil)) {
		t.Fatalf("receipt dispatcher field = (%v,%t)", field.Type, ok)
	}
	source, err := os.ReadFile("control_upgrade_runtime.go")
	if err != nil {
		t.Fatal(err)
	}
	for _, required := range []string{
		"controlupgrade.NewLicenseReceiptDispatcher(store, license,",
		"results := make(chan error, 4)",
		"runtime.runReceiptDispatcher(runCtx)",
		"func (runtime *controlUpgradeProductionRuntime) runReceiptDispatcher",
		"runtime.receiptDispatcher.HasFailed(ctx)",
	} {
		if !bytes.Contains(source, []byte(required)) {
			t.Errorf("receipt worker composition missing %q", required)
		}
	}
}

func TestControlUpgradeLicenseReceiptFailureReadinessIsSticky(t *testing.T) {
	runtime := &controlUpgradeProductionRuntime{}
	runtime.setReceiptError(nil, true)
	runtime.setReceiptError(nil, false)
	runtime.healthMu.RLock()
	failed := runtime.receiptFailed
	runtime.healthMu.RUnlock()
	if !failed {
		t.Fatal("a permanent License receipt failure was cleared by a later healthy poll")
	}
}

func TestControlUpgradeInitialReceiptHealthLoadsBeforeRuntimeCanBecomeReady(t *testing.T) {
	for _, test := range []struct {
		name   string
		failed bool
		err    error
	}{
		{name: "healthy"},
		{name: "persisted failure", failed: true},
		{name: "load failure", err: context.DeadlineExceeded},
	} {
		t.Run(test.name, func(t *testing.T) {
			store := &controlUpgradeReceiptHealthStore{failed: test.failed, err: test.err}
			dispatcher, err := controlupgrade.NewLicenseReceiptDispatcher(store,
				controlUpgradeReceiptHealthClient{}, controlupgrade.LicenseReceiptDispatcherConfig{
					WorkerID: "startup-health", ClaimLease: time.Second, ClaimBatch: 1,
				})
			if err != nil {
				t.Fatal(err)
			}
			failed, err := controlUpgradeLoadInitialReceiptHealth(t.Context(), dispatcher)
			if !errors.Is(err, test.err) || failed != test.failed || store.calls != 1 {
				t.Fatalf("initial health = (%t,%v,calls=%d), want (%t,%v,1)",
					failed, err, store.calls, test.failed, test.err)
			}
		})
	}
	source, err := os.ReadFile("control_upgrade_runtime.go")
	if err != nil {
		t.Fatal(err)
	}
	if !bytes.Contains(source, []byte("receiptHealthLoaded: true")) ||
		!bytes.Contains(source, []byte("!runtime.receiptHealthLoaded")) {
		t.Fatal("runtime readiness is not ordered after the synchronous persisted receipt-health load")
	}
}

func TestControlUpgradeRuntimeCloseClearsBothOwnedSigningKeys(t *testing.T) {
	controlKey := ed25519.NewKeyFromSeed(bytes.Repeat([]byte{0x41}, ed25519.SeedSize))
	edgeKey := ed25519.NewKeyFromSeed(bytes.Repeat([]byte{0x42}, ed25519.SeedSize))
	runtime := &controlUpgradeProductionRuntime{
		controlSigner: &controlUpgradeEd25519Signer{privateKey: controlKey},
		edgeSigner:    &controlUpgradeEd25519Signer{privateKey: edgeKey},
	}
	if err := runtime.Close(); err != nil {
		t.Fatal(err)
	}
	for name, key := range map[string]ed25519.PrivateKey{"control": controlKey, "edge": edgeKey} {
		for index, value := range key {
			if value != 0 {
				t.Fatalf("%s key byte %d was not cleared", name, index)
			}
		}
	}
}

type controlUpgradeReceiptHealthStore struct {
	failed bool
	err    error
	calls  int
}

func (*controlUpgradeReceiptHealthStore) ClaimParentGrantReceipts(context.Context, string, time.Time,
	time.Duration, int) ([]controlupgrade.ParentGrantReceiptClaim, error) {
	return nil, nil
}

func (*controlUpgradeReceiptHealthStore) SettleParentGrantReceipt(context.Context,
	controlupgrade.ParentGrantReceiptSettlement) error {
	return nil
}

func (store *controlUpgradeReceiptHealthStore) HasFailedParentGrantReceipt(context.Context) (bool, error) {
	store.calls++
	return store.failed, store.err
}

type controlUpgradeReceiptHealthClient struct{}

func (controlUpgradeReceiptHealthClient) RecordParentGrantReceipt(context.Context,
	controlupgrade.ParentGrantReceipt) (controlupgrade.ParentGrantReceiptResponse, error) {
	return controlupgrade.ParentGrantReceiptResponse{}, nil
}

func controlUpgradeValidRuntimeEnvironment(t *testing.T) []string {
	t.Helper()
	directory := t.TempDir()
	controlPath := filepath.Join(directory, "control.pem")
	edgePath := filepath.Join(directory, "edge.pem")
	controlUpgradeWritePrivateKey(t, controlPath, 0x31)
	controlUpgradeWritePrivateKey(t, edgePath, 0x32)
	trustPrivate := ed25519.NewKeyFromSeed(bytes.Repeat([]byte{0x33}, ed25519.SeedSize))
	trustWire, err := json.Marshal(struct {
		Keys []struct {
			KeyID     string `json:"key_id"`
			PublicKey string `json:"public_key"`
		} `json:"keys"`
	}{Keys: []struct {
		KeyID     string `json:"key_id"`
		PublicKey string `json:"public_key"`
	}{{KeyID: "license-upgrade-signing", PublicKey: base64.RawURLEncoding.EncodeToString(
		trustPrivate.Public().(ed25519.PublicKey))}}})
	if err != nil {
		t.Fatal(err)
	}
	trustPath := filepath.Join(directory, "trust.json")
	if err := os.WriteFile(trustPath, trustWire, 0o644); err != nil {
		t.Fatal(err)
	}
	return []string{
		controlUpgradeEnabledEnv + "=true",
		controlUpgradeNATSNameEnv + "=cdnca-control-upgrade",
		controlUpgradeWorkerIDEnv + "=control-upgrade-1",
		controlUpgradeCommandGrantTrustFileEnv + "=" + trustPath,
		controlUpgradeControlSigningKeyIDEnv + "=control-upgrade-signing",
		controlUpgradeControlSigningPrivateKeyFileEnv + "=" + controlPath,
		controlUpgradeEdgeSigningKeyIDEnv + "=edge-upgrade-signing",
		controlUpgradeEdgeSigningPrivateKeyFileEnv + "=" + edgePath,
		controlUpgradeCommandIssuanceTTLEnv + "=6h",
		controlUpgradeExecutionTTLEnv + "=10m",
		controlUpgradeActivationTimeoutEnv + "=5m",
		controlUpgradeObservationWindowEnv + "=2m",
		controlUpgradeHealthIntervalEnv + "=10s",
		controlUpgradeProbeTimeoutEnv + "=3s",
		controlUpgradeRequiredSuccessesEnv + "=3",
		controlUpgradeNATSConnectTimeoutEnv + "=5s",
		controlUpgradeNATSReconnectWaitEnv + "=1s",
		controlUpgradeNATSDrainTimeoutEnv + "=5s",
		controlUpgradeShutdownTimeoutEnv + "=10s",
		controlUpgradeArtifactCacheDirEnv + "=" + filepath.Join(directory, "upgrade-artifacts"),
		controlUpgradeArtifactBaseURLEnv + "=https://cdnca.com/downloads/edge-agent/upgrades/sha256",
	}
}

func controlUpgradeWritePrivateKey(t *testing.T, path string, seed byte) {
	t.Helper()
	privateKey := ed25519.NewKeyFromSeed(bytes.Repeat([]byte{seed}, ed25519.SeedSize))
	encoded, err := x509.MarshalPKCS8PrivateKey(privateKey)
	clear(privateKey)
	if err != nil {
		t.Fatal(err)
	}
	pemBytes := pem.EncodeToMemory(&pem.Block{Type: "PRIVATE KEY", Bytes: encoded})
	clear(encoded)
	defer clear(pemBytes)
	if err := os.WriteFile(path, pemBytes, 0o600); err != nil {
		t.Fatal(err)
	}
}

func controlUpgradeReplaceEnvironment(environment []string, name, value string) []string {
	prefix := name + "="
	for index := range environment {
		if strings.HasPrefix(environment[index], prefix) {
			environment[index] = prefix + value
			return environment
		}
	}
	return append(environment, prefix+value)
}

func controlUpgradeDropEnvironment(environment []string, name string) []string {
	prefix := name + "="
	result := environment[:0]
	for _, entry := range environment {
		if !strings.HasPrefix(entry, prefix) {
			result = append(result, entry)
		}
	}
	return result
}

func controlUpgradeEnvironmentValue(environment []string, name string) string {
	prefix := name + "="
	for _, entry := range environment {
		if strings.HasPrefix(entry, prefix) {
			return strings.TrimPrefix(entry, prefix)
		}
	}
	return ""
}
