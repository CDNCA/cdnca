package main

// Control-api half of tests/plugin-distribution-e2e/run.sh. The platform license half (license-service
// internal/httpapi TestPluginDistributionLicenseFixture) runs in its own process and writes license.json.
//
// Everything on this side is production wiring: buildPluginInstallationHandlerFactory (mTLS client certificate
// bootstrap, signed activation client, PostgreSQL repository, HTTP handler) and newAuthorizedPluginWebhookDeliverer
// (runtime projection + workload authorization over mTLS). Only the webhook HTTP sender is replaced by a direct
// call into the example plugin receiver, because the production sender refuses loopback targets by design.

import (
	"bytes"
	"context"
	"crypto/sha256"
	"encoding/base64"
	"encoding/json"
	"fmt"
	"net/http"
	"net/http/httptest"
	"os"
	"path/filepath"
	"strings"
	"sync"
	"testing"
	"time"

	"github.com/cdnca/cdnca/services/control-api/internal/config"
	"github.com/cdnca/cdnca/services/control-api/internal/entitlementguard"
	"github.com/cdnca/cdnca/services/control-api/internal/identity"
	"github.com/cdnca/cdnca/services/control-api/internal/pluginwebhook"
	"github.com/google/uuid"
)

type licensePluginFixture struct {
	AuthorizationID   uuid.UUID         `json:"authorization_id"`
	Verifications     map[string]string `json:"verifications"`
	ControllerConfirm bool              `json:"controller_confirm,omitempty"`
}

type licenseFixture struct {
	BusinessURL         string                          `json:"business_url"`
	BootstrapServerCA   string                          `json:"bootstrap_server_ca_file"`
	RuntimeURL          string                          `json:"runtime_url"`
	OperatorURL         string                          `json:"operator_url"`
	CustomerID          uuid.UUID                       `json:"customer_id"`
	InstallationID      uuid.UUID                       `json:"installation_id"`
	InstallationKeyFile string                          `json:"installation_key_file"`
	SigningKeyID        string                          `json:"signing_key_id"`
	SigningPublicKey    string                          `json:"signing_public_key"`
	Plugins             map[string]licensePluginFixture `json:"plugins"`
}

const (
	auditPluginID = "io.cdnca.examples.audit-forwarder"
	// marketPluginID is example plugin two: bought on the plugin market (PLUGIN_E2E_MARKET=1) or operator-published.
	marketPluginID = "com.example.dev.node-beacon"
)

func TestPluginDistributionControlAgainstLicenseProcess(t *testing.T) {
	directory := os.Getenv("PLUGIN_E2E_DIR")
	databaseURL := strings.TrimSpace(os.Getenv("TEST_DATABASE_URL"))
	if directory == "" || databaseURL == "" {
		t.Skip("PLUGIN_E2E_DIR and TEST_DATABASE_URL are required; run tests/plugin-distribution-e2e/run.sh")
	}
	fixture := waitLicenseFixture(t, filepath.Join(directory, "license.json"))
	defer func() { _ = postOperator(fixture, "/done", nil) }()
	ctx := t.Context()
	pool, tenantID, token := controlE2EDatabase(t, databaseURL)
	signingKey, err := base64.RawURLEncoding.DecodeString(fixture.SigningPublicKey)
	if err != nil {
		t.Fatal(err)
	}
	trust, err := entitlementguard.NewTrustStore([]entitlementguard.VerificationKey{{KeyID: fixture.SigningKeyID,
		PublicKey: signingKey}})
	if err != nil {
		t.Fatal(err)
	}
	credentials := filepath.Join(directory, "control-runtime")
	if err := os.MkdirAll(credentials, 0o700); err != nil {
		t.Fatal(err)
	}
	for name, value := range map[string]string{
		"PLUGIN_RUNTIME_PROVIDER_URL":             fixture.RuntimeURL,
		"PLUGIN_RUNTIME_PROJECTION_URL":           fixture.RuntimeURL,
		"PLUGIN_RUNTIME_CLIENT_CERT_FILE":         filepath.Join(credentials, "client.crt"),
		"PLUGIN_RUNTIME_CLIENT_PRIVATE_KEY_FILE":  filepath.Join(credentials, "client.key"),
		"PLUGIN_RUNTIME_LICENSE_CA_FILE":          filepath.Join(credentials, "license-ca.crt"),
		"PLUGIN_RUNTIME_CLIENT_STATE_FILE":        filepath.Join(credentials, "state.json"),
		"PLUGIN_RUNTIME_BOOTSTRAP_SERVER_CA_FILE": fixture.BootstrapServerCA,
		// 本地 license 进程直接监听运行时 mTLS 端口，没有 T1 隧道入口。
		"PLUGIN_RUNTIME_MTLS_TRANSPORT": "direct",
	} {
		t.Setenv(name, value)
	}
	cfg := config.Config{LicenseServiceURL: fixture.BusinessURL,
		ControlInstallationID: fixture.InstallationID.String(), ControlInstallationKeyFile: fixture.InstallationKeyFile}
	tokens, err := identity.NewTokenManager(strings.Repeat("e", 32), time.Hour)
	if err != nil {
		t.Fatal(err)
	}
	identityService, err := identity.NewService(identity.NewStore(pool), tokens, time.Hour)
	if err != nil {
		t.Fatal(err)
	}
	pluginRuntime, err := buildPluginInstallationRuntime(ctx, cfg, pool, identityService, trust)
	if err != nil || pluginRuntime == nil {
		t.Fatalf("plugin installation runtime=%v err=%v", pluginRuntime != nil, err)
	}
	handler, err := pluginRuntime.handler()
	if err != nil {
		t.Fatal(err)
	}
	client := controlClient{t: t, handler: handler, token: token(tokens), tenantID: tenantID}

	audit := fixture.Plugins[auditPluginID]
	// 1. The platform authorized the plugin for this installation; the tenant sees it and installs it.
	page := client.list()
	item := page.find(audit.AuthorizationID)
	if item == nil || item.Status != "pending_confirmation" || item.Version != "1.0.0" {
		t.Fatalf("authorized plugin not offered: %+v", page)
	}
	installed := client.mutate(item.AuthorizationID, "confirm", item.Revision, map[string]any{
		"verification_id": item.VerificationID, "approved_scopes": item.ApprovedScopes,
		"sensitive_permissions_confirmed": true, "new_permissions_confirmed": true}, http.StatusOK)
	if installed.Status != "enabled" || installed.Version != "1.0.0" {
		t.Fatalf("installed=%+v", installed)
	}
	license := licenseState(t, fixture, auditPluginID)
	if license.Status != "enabled" || license.Version != "1.0.0" {
		t.Fatalf("license after install=%+v", license)
	}

	// 2. The installed plugin's capability runs only while the platform authorizes it.
	receiver := newAuditReceiver()
	defer receiver.Close()
	deliverer, err := newAuthorizedPluginWebhookDeliverer(cfg, trust, receiver)
	if err != nil {
		t.Fatal(err)
	}
	subscriptionID, targetScopeID := uuid.New(), uuid.New()
	if status := postOperator(fixture, "/binding", map[string]any{"subscription_id": subscriptionID,
		"target_scope_id": targetScopeID}); status != http.StatusCreated {
		t.Fatalf("runtime binding status=%d", status)
	}
	deliver := func(label string) pluginwebhook.SendResult {
		item := testQueueItem(tenantID, targetScopeID, subscriptionID)
		result := deliverer.DeliverV2(ctx, item, 1, []byte("example-secret-32-bytes-000000000"))
		t.Logf("%s delivery code=%q retryable=%v delivered=%d", label, result.Code, result.Retryable, receiver.count())
		return result
	}
	if result := deliver("enabled"); !result.Success || receiver.count() != 1 {
		t.Fatalf("enabled plugin must receive the event: %+v", result)
	}

	// 3. Platform pause/resume stops and restarts execution without touching the tenant install.
	if status := postOperator(fixture, "/pause", nil); status != http.StatusOK {
		t.Fatalf("pause status=%d", status)
	}
	if paused := client.get(audit.AuthorizationID); paused.Status != "enabled" || paused.AuthorizationStatus != "disabled" {
		t.Fatalf("paused view=%+v", paused)
	}
	if result := deliver("paused"); result.Code != "runtime_authorization_denied" || receiver.count() != 1 {
		t.Fatalf("paused plugin must not receive events: %+v", result)
	}
	if status := postOperator(fixture, "/resume", nil); status != http.StatusOK {
		t.Fatalf("resume status=%d", status)
	}
	if result := deliver("resumed"); !result.Success || receiver.count() != 2 {
		t.Fatalf("resumed plugin must receive events again: %+v", result)
	}

	// 4. The platform approves 1.1.0; the tenant sees the upgrade and applies it.
	if status := postOperator(fixture, "/upgrade", nil); status != http.StatusOK {
		t.Fatalf("operator upgrade status=%d", status)
	}
	current := client.get(audit.AuthorizationID)
	if current.AvailableUpgrade == nil || current.AvailableUpgrade.Version != "1.1.0" {
		t.Fatalf("upgrade not offered: %+v", current)
	}
	upgraded := client.mutate(current.AuthorizationID, "upgrade", current.Revision, map[string]any{
		"verification_id": current.AvailableUpgrade.VerificationID,
		"approved_scopes": current.AvailableUpgrade.ApprovedScopes, "sensitive_permissions_confirmed": true,
		"new_permissions_confirmed": true}, http.StatusOK)
	if upgraded.Version != "1.1.0" || upgraded.Status != "enabled" || upgraded.LKGVersion == nil ||
		*upgraded.LKGVersion != "1.1.0" {
		t.Fatalf("upgraded=%+v", upgraded)
	}
	if result := deliver("upgraded"); !result.Success || receiver.count() != 3 {
		t.Fatalf("upgraded plugin must keep receiving events: %+v", result)
	}

	// 5. Tenant uninstall is reported to the platform and stops execution.
	removed := client.mutate(upgraded.AuthorizationID, "uninstall", upgraded.Revision,
		map[string]any{"reason": "联调结束卸载"}, http.StatusOK)
	if removed.Status != "uninstalled" {
		t.Fatalf("uninstalled=%+v", removed)
	}
	license = licenseState(t, fixture, auditPluginID)
	if license.Status != "uninstalled" || license.Version != "1.1.0" {
		t.Fatalf("license after uninstall=%+v", license)
	}
	if result := deliver("uninstalled"); result.Code != "runtime_authorization_denied" || receiver.count() != 3 {
		t.Fatalf("uninstalled plugin must not receive events: %+v", result)
	}
	actions := license.receiptActions()
	t.Logf("license receipts: %s", strings.Join(actions, ","))
	for _, want := range []string{"create", "confirm", "install_applied", "enable", "disable", "upgrade_applied",
		"uninstall"} {
		if !contains(actions, want) {
			t.Fatalf("license receipts %v miss %s", actions, want)
		}
	}
	var heads int
	if err := pool.QueryRow(ctx, `SELECT count(*) FROM plugin_installation_receipts WHERE authorization_id=$1`,
		audit.AuthorizationID).Scan(&heads); err != nil || heads != 3 {
		t.Fatalf("control receipts=%d err=%v", heads, err)
	}

	if _, ok := fixture.Plugins[rulePackPluginID]; ok {
		// Before runMarketPluginFlow: it signals the market process to stop serving the catalog origin.
		platformClient := controlClient{t: t, handler: handler, token: platformE2EToken(t, pool)(tokens), platform: true}
		runMarketRulePackFlow(t, fixture, client, platformClient, pool, trust)
	}
	runMarketPluginFlow(t, directory, fixture, client)
}

func contains(values []string, want string) bool {
	for _, value := range values {
		if value == want {
			return true
		}
	}
	return false
}

func testQueueItem(tenantID, targetScopeID, subscriptionID uuid.UUID) pluginwebhook.QueueItem {
	eventID := uuid.Must(uuid.NewV7())
	return pluginwebhook.QueueItem{Schema: pluginwebhook.QueueSchemaV2, DeliveryID: uuid.New(),
		IdempotencyKey: "plugin-webhook-v2-" + fmt.Sprintf("%x", sha256.Sum256(eventID[:])),
		TargetURL:      "https://audit-forwarder.cdnca.example/cdnca/hooks",
		Event:          pluginwebhook.CloudEvent{ID: eventID.String(), Type: "io.cdnca.webhook.v1.test"},
		TargetScopeID:  targetScopeID, TenantID: tenantID, SubscriptionID: subscriptionID,
		SecretVersionID: uuid.New(), EventID: eventID}
}

// auditReceiver is the example management plugin: an external service that archives the events it is authorized
// to receive (examples/plugins/webhook-v2-receiver implements the full signed HTTP contract).
type auditReceiver struct {
	mu       sync.Mutex
	received []string
	server   *httptest.Server
}

func newAuditReceiver() *auditReceiver {
	receiver := &auditReceiver{}
	receiver.server = httptest.NewServer(http.HandlerFunc(func(response http.ResponseWriter, request *http.Request) {
		var event struct {
			ID string `json:"id"`
		}
		if json.NewDecoder(request.Body).Decode(&event) != nil || event.ID == "" {
			http.Error(response, "invalid event", http.StatusBadRequest)
			return
		}
		receiver.mu.Lock()
		receiver.received = append(receiver.received, event.ID)
		receiver.mu.Unlock()
		response.WriteHeader(http.StatusNoContent)
	}))
	return receiver
}

func (receiver *auditReceiver) Close() { receiver.server.Close() }

func (receiver *auditReceiver) count() int {
	receiver.mu.Lock()
	defer receiver.mu.Unlock()
	return len(receiver.received)
}

func (receiver *auditReceiver) DeliverV2(ctx context.Context, item pluginwebhook.QueueItem, _ uint64,
	_ []byte) pluginwebhook.SendResult {
	body, _ := json.Marshal(map[string]string{"id": item.Event.ID, "type": item.Event.Type})
	request, err := http.NewRequestWithContext(ctx, http.MethodPost, receiver.server.URL+"/cdnca/hooks",
		bytes.NewReader(body))
	if err != nil {
		return pluginwebhook.SendResult{Code: "request_build_failed"}
	}
	response, err := http.DefaultClient.Do(request)
	if err != nil {
		return pluginwebhook.SendResult{Code: "network_error", Retryable: true}
	}
	defer response.Body.Close()
	if response.StatusCode/100 != 2 {
		return pluginwebhook.SendResult{Code: "http_status", StatusCode: response.StatusCode}
	}
	return pluginwebhook.SendResult{Success: true, StatusCode: response.StatusCode}
}
