package main

import (
	"context"
	"crypto/ed25519"
	"crypto/rand"
	"crypto/x509"
	"encoding/pem"
	"net/http"
	"net/http/httptest"
	"os"
	"path/filepath"
	"strings"
	"sync/atomic"
	"testing"
	"time"

	"github.com/cdnca/cdnca/services/control-api/internal/config"
	"github.com/cdnca/cdnca/services/control-api/internal/entitlementguard"
	"github.com/cdnca/cdnca/services/control-api/internal/identity"
	"github.com/cdnca/cdnca/services/control-api/internal/pluginwebhook"
	"github.com/google/uuid"
	"github.com/jackc/pgx/v5/pgxpool"
)

// 授权端拒绝签发安装客户端证书时，插件安装运行时与
// 插件 webhook 授权投递只能降级，不能让主控启动失败；凭据恢复后同一进程内自动恢复。
type deniedLicenseServer struct {
	server   *httptest.Server
	caFile   string
	requests atomic.Int64
}

func newDeniedLicenseServer(t *testing.T) *deniedLicenseServer {
	t.Helper()
	denied := &deniedLicenseServer{}
	denied.server = httptest.NewTLSServer(http.HandlerFunc(func(response http.ResponseWriter, _ *http.Request) {
		denied.requests.Add(1)
		response.Header().Set("Content-Type", "application/json")
		response.WriteHeader(http.StatusBadRequest)
		_, _ = response.Write([]byte(`{"code":"invalid_request"}` + "\n"))
	}))
	t.Cleanup(denied.server.Close)
	denied.caFile = filepath.Join(t.TempDir(), "bootstrap-ca.pem")
	encoded := pem.EncodeToMemory(&pem.Block{Type: "CERTIFICATE", Bytes: denied.server.Certificate().Raw})
	if err := os.WriteFile(denied.caFile, encoded, 0o600); err != nil {
		t.Fatal(err)
	}
	return denied
}

func degradedRuntimeConfig(t *testing.T, licenseURL string) config.Config {
	t.Helper()
	_, key, err := ed25519.GenerateKey(rand.Reader)
	if err != nil {
		t.Fatal(err)
	}
	der, err := x509.MarshalPKCS8PrivateKey(key)
	if err != nil {
		t.Fatal(err)
	}
	keyFile := filepath.Join(t.TempDir(), "installation.key")
	if err := os.WriteFile(keyFile, pem.EncodeToMemory(&pem.Block{Type: "PRIVATE KEY", Bytes: der}), 0o600); err != nil {
		t.Fatal(err)
	}
	return config.Config{LicenseServiceURL: licenseURL, ControlInstallationID: uuid.NewString(), ControlInstallationKeyFile: keyFile}
}

func setDegradedRuntimeEnvironment(t *testing.T, bootstrapCA string) {
	t.Helper()
	directory := t.TempDir()
	setPluginRuntimeCompositionEnvironment(t, directory)
	t.Setenv("PLUGIN_RUNTIME_BOOTSTRAP_SERVER_CA_FILE", bootstrapCA)
	t.Setenv("PLUGIN_RUNTIME_MTLS_TRANSPORT", "direct")
}

func degradedTrust(t *testing.T) *entitlementguard.TrustStore {
	t.Helper()
	public, _, err := ed25519.GenerateKey(rand.Reader)
	if err != nil {
		t.Fatal(err)
	}
	trust, err := entitlementguard.NewTrustStore([]entitlementguard.VerificationKey{{KeyID: "fix-certrecover", PublicKey: public}})
	if err != nil {
		t.Fatal(err)
	}
	return trust
}

func TestPluginInstallationRuntimeStartsDegradedWhenCertificateDenied(t *testing.T) {
	license := newDeniedLicenseServer(t)
	setDegradedRuntimeEnvironment(t, license.caFile)
	cfg := degradedRuntimeConfig(t, license.server.URL)
	pool, err := pgxpool.New(t.Context(), "postgres://unused@127.0.0.1:1/unused")
	if err != nil {
		t.Fatal(err)
	}
	defer pool.Close()
	tokens, err := identity.NewTokenManager(strings.Repeat("e", 32), time.Hour)
	if err != nil {
		t.Fatal(err)
	}
	identityService, err := identity.NewService(identity.NewStore(pool), tokens, time.Hour)
	if err != nil {
		t.Fatal(err)
	}
	runtime, err := buildPluginInstallationRuntime(t.Context(), cfg, pool, identityService, degradedTrust(t))
	if err != nil || runtime == nil || runtime.licenseHTTP == nil || runtime.handlerFactory() == nil {
		t.Fatalf("buildPluginInstallationRuntime() = (%+v, %v), want degraded runtime without startup error", runtime, err)
	}
	startup := license.requests.Load()
	if startup == 0 {
		t.Fatal("startup did not try to obtain the installation certificate")
	}
	request, err := http.NewRequestWithContext(t.Context(), http.MethodPost, runtime.providerURL+"/probe", strings.NewReader("{}"))
	if err != nil {
		t.Fatal(err)
	}
	if response, err := runtime.licenseHTTP.Do(request); err == nil {
		_ = response.Body.Close()
		t.Fatal("license request without an installation certificate succeeded")
	} else if !strings.Contains(err.Error(), "certificate bootstrap denied") {
		t.Fatalf("license request error = %v, want certificate bootstrap denied", err)
	}
	if license.requests.Load() <= startup {
		t.Fatal("a later request did not retry the installation certificate")
	}
}

func TestPluginWebhookDelivererStartsDegradedWhenCertificateDenied(t *testing.T) {
	license := newDeniedLicenseServer(t)
	setDegradedRuntimeEnvironment(t, license.caFile)
	cfg := degradedRuntimeConfig(t, license.server.URL)
	deliverer, err := newAuthorizedPluginWebhookDeliverer(cfg, degradedTrust(t), unreachableV2Deliverer{t: t})
	if err != nil || deliverer == nil {
		t.Fatalf("newAuthorizedPluginWebhookDeliverer() = (%v, %v), want degraded deliverer without startup error", deliverer, err)
	}
	startup := license.requests.Load()
	result := deliverer.DeliverV2(t.Context(), pluginwebhook.QueueItem{DeliveryID: uuid.New()}, 1, []byte("example-secret-32-bytes-000000000"))
	if result.Success || !result.Retryable || result.Code != "runtime_authorization_unavailable" {
		t.Fatalf("degraded delivery = %+v, want retryable runtime_authorization_unavailable", result)
	}
	if license.requests.Load() <= startup {
		t.Fatal("a delivery did not retry the installation certificate")
	}
}

type unreachableV2Deliverer struct{ t *testing.T }

func (delegate unreachableV2Deliverer) DeliverV2(_ context.Context, _ pluginwebhook.QueueItem, _ uint64, _ []byte) pluginwebhook.SendResult {
	delegate.t.Fatal("delivery bypassed the runtime authorization gate")
	return pluginwebhook.SendResult{}
}
