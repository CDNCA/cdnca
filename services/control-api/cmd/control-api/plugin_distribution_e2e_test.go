package main

// Control-api half of tests/plugin-distribution-e2e/run.sh. The platform license half (license-service
// internal/httpapi TestPluginDistributionLicenseFixture) runs in its own process and writes license.json.
//
// Everything on this side is production wiring: buildPluginInstallationHandlerFactory (mTLS client certificate
// bootstrap, signed activation client, PostgreSQL repository, HTTP handler) and newAuthorizedPluginWebhookDeliverer
// (runtime projection + workload authorization over mTLS). Only the webhook HTTP sender is replaced by a direct
// call into the example plugin receiver, because the production sender refuses loopback targets by design.
//
// Since control migration 636 the controller's platform administrator confirms, upgrades and
// uninstalls every plugin; a tenant plugin is confirmed for chosen tenants (or all tenants) and tenants only read it.

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
	tenantB, tokenB := seedE2ETenant(t, pool, "插件联调租户乙", "plugin-e2e-admin-b")
	clientB := controlClient{t: t, handler: handler, token: tokenB(tokens), tenantID: tenantB}
	platformClient := controlClient{t: t, handler: handler, token: platformE2EToken(t, pool)(tokens), platform: true}
	// Whether a tenant can use a plugin: an enabled tenant head that covers it (the predicate the production
	// gates use, plugin_installation_covers_tenant_636).
	available := func(label string, raw func(*identity.TokenManager) string, pluginID string) bool {
		t.Helper()
		principal, err := identityService.Authenticate(ctx, raw(tokens))
		if err != nil {
			t.Fatalf("%s: authenticate: %v", label, err)
		}
		var ok bool
		if err := pool.QueryRow(ctx, `SELECT EXISTS (SELECT 1 FROM plugin_installation_heads
			WHERE plugin_id=$2 AND status='enabled' AND resource_scope='tenant' AND
			      plugin_installation_covers_tenant_636(authorization_id, $1))`, principal.ScopeID, pluginID).Scan(&ok); err != nil {
			t.Fatalf("%s: plugin installation for tenant: %v", label, err)
		}
		return ok
	}

	audit := fixture.Plugins[auditPluginID]
	// 1. the platform authorized the tenant plugin for
	// this installation; the controller's platform administrator confirms it and chooses the tenants. Tenants no
	// longer see candidates and cannot confirm.
	if client.list().find(audit.AuthorizationID) != nil {
		t.Fatal("tenant console offered a plugin for confirmation")
	}
	item := platformClient.list().find(audit.AuthorizationID)
	if item == nil || item.Status != "pending_confirmation" || item.Version != "1.0.0" {
		t.Fatalf("authorized plugin not offered to the platform administrator: %+v", item)
	}
	confirmBody := func(item *installationView, targets map[string]any) map[string]any {
		body := map[string]any{"verification_id": item.VerificationID, "approved_scopes": item.ApprovedScopes,
			"sensitive_permissions_confirmed": true, "new_permissions_confirmed": true}
		if targets != nil {
			body["targets"] = targets
		}
		return body
	}
	client.refused(item.AuthorizationID, "confirm", item.Revision, confirmBody(item, nil), http.StatusForbidden,
		"plugin_installation_platform_managed")
	// Only the platform route accepts targets: on a tenant route the body itself is malformed (handler.mutate).
	client.refused(item.AuthorizationID, "confirm", item.Revision, confirmBody(item, tenantTargets(tenantID)),
		http.StatusBadRequest, "invalid_request")
	platformClient.refused(item.AuthorizationID, "confirm", item.Revision, confirmBody(item, nil),
		http.StatusUnprocessableEntity, "plugin_installation_targets_invalid")
	installed := platformClient.mutate(item.AuthorizationID, "confirm", item.Revision,
		confirmBody(item, tenantTargets(tenantID)), http.StatusOK)
	if installed.Status != "enabled" || installed.Version != "1.0.0" || installed.ManagedBy != "platform" ||
		installed.Targets == nil || installed.Targets.AllTenants || len(installed.Targets.Tenants) != 1 ||
		installed.Targets.Tenants[0].ScopeID != tenantID {
		t.Fatalf("installed=%+v targets=%+v", installed, installed.Targets)
	}
	license := licenseState(t, fixture, auditPluginID)
	if license.Status != "enabled" || license.Version != "1.0.0" {
		t.Fatalf("license after install=%+v", license)
	}
	// Chosen tenant: reads it (managed_by=platform) and can use it; the other tenant neither sees nor uses it.
	if view := client.get(audit.AuthorizationID); view.Status != "enabled" || view.ManagedBy != "platform" ||
		view.Targets != nil {
		t.Fatalf("chosen tenant view=%+v", view)
	}
	if status, code := clientB.getStatus(audit.AuthorizationID); status != http.StatusNotFound || code != "plugin_installation_not_found" ||
		clientB.list().find(audit.AuthorizationID) != nil {
		t.Fatalf("tenant outside the targets reads the plugin: %d %s", status, code)
	}
	if !available("chosen tenant", token, auditPluginID) || available("other tenant", tokenB, auditPluginID) {
		t.Fatal("tenant coverage after confirming for one tenant")
	}
	// A tenant cannot change what the platform installed for it.
	client.refused(audit.AuthorizationID, "disable", installed.Revision, map[string]any{"reason": "租户试图停用"},
		http.StatusForbidden, "plugin_installation_platform_managed")

	// 1b. The platform administrator widens the targets to every tenant, which also covers tenants created later.
	widened := platformClient.putTargets(audit.AuthorizationID, installed.Targets.Revision, allTenantTargets())
	if widened.Targets == nil || !widened.Targets.AllTenants || widened.Targets.Revision != 2 {
		t.Fatalf("widened targets=%+v", widened.Targets)
	}
	_, tokenC := seedE2ETenant(t, pool, "插件联调租户丙", "plugin-e2e-admin-c")
	if !available("chosen tenant", token, auditPluginID) || !available("tenant B, all tenants", tokenB, auditPluginID) ||
		!available("tenant created later", tokenC, auditPluginID) {
		t.Fatal("tenant coverage after widening to all tenants")
	}
	if view := clientB.get(audit.AuthorizationID); view.Status != "enabled" || view.ManagedBy != "platform" {
		t.Fatalf("tenant B view after widening=%+v", view)
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

	// 3. License operator pause/resume stops and restarts execution without touching the local install.
	if status := postOperator(fixture, "/pause", nil); status != http.StatusOK {
		t.Fatalf("pause status=%d", status)
	}
	for _, viewer := range []controlClient{platformClient, client} {
		if paused := viewer.get(audit.AuthorizationID); paused.Status != "enabled" || paused.AuthorizationStatus != "disabled" {
			t.Fatalf("paused view (%s)=%+v", viewer.name(), paused)
		}
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

	// 4. The license operator approves 1.1.0; the platform administrator applies it (the tenant may not).
	if status := postOperator(fixture, "/upgrade", nil); status != http.StatusOK {
		t.Fatalf("operator upgrade status=%d", status)
	}
	current := platformClient.get(audit.AuthorizationID)
	if current.AvailableUpgrade == nil || current.AvailableUpgrade.Version != "1.1.0" {
		t.Fatalf("upgrade not offered: %+v", current)
	}
	upgradeBody := map[string]any{"verification_id": current.AvailableUpgrade.VerificationID,
		"approved_scopes": current.AvailableUpgrade.ApprovedScopes, "sensitive_permissions_confirmed": true,
		"new_permissions_confirmed": true}
	client.refused(current.AuthorizationID, "upgrade", current.Revision, upgradeBody, http.StatusForbidden,
		"plugin_installation_platform_managed")
	upgraded := platformClient.mutate(current.AuthorizationID, "upgrade", current.Revision, map[string]any{
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

	// 5. The platform administrator's uninstall is reported to the license service and stops execution for every
	// tenant (the tenant's own attempt is refused).
	client.refused(upgraded.AuthorizationID, "uninstall", upgraded.Revision, map[string]any{"reason": "租户试图卸载"},
		http.StatusForbidden, "plugin_installation_platform_managed")
	removed := platformClient.mutate(upgraded.AuthorizationID, "uninstall", upgraded.Revision,
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
	if available("chosen tenant after uninstall", token, auditPluginID) ||
		available("tenant B after uninstall", tokenB, auditPluginID) {
		t.Fatal("an uninstalled plugin still covers tenants")
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
		runMarketRulePackFlow(t, fixture, client, platformClient, pool, trust)
	}
	runMarketPluginFlow(t, directory, fixture, platformClient, []controlClient{client, clientB},
		func(label string) bool {
			return available(label, token, marketPluginID) && available(label, tokenB, marketPluginID)
		})
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
