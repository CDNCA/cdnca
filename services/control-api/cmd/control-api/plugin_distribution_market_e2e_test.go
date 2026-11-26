package main

import (
	"net/http"
	"os"
	"path/filepath"
	"strings"
	"testing"
	"time"

	"github.com/google/uuid"
	"github.com/jackc/pgx/v5/pgxpool"
)

// runMarketPluginFlow drives example plugin two (bought on the plugin market when PLUGIN_E2E_MARKET=1, otherwise
// published by the license operator) through the production installation path: the controller's platform
// administrator confirms the authorization for all tenants (plugconfirm, migration 636), upgrades and finally
// uninstalls it; tenants only read it. Published by the operator, the license operator approves 1.1.0 for the
// upgrade. Bought on the market (license 176), the pending authorization was already moved to 1.1.0 by the market
// sync and the upgrade is to 1.2.0, offered as a market upgrade proposal with no operator step; until the controller
// applies it the license keeps 1.1.0 and tenants keep using it. Every step must be reflected in the license-side
// authorization receipts. covered reports whether every tenant can use the
// plugin. It writes <dir>/finished so the market process stops serving its catalog origin.
func runMarketPluginFlow(t *testing.T, directory string, fixture licenseFixture, client controlClient,
	tenants []controlClient, pool *pgxpool.Pool, lostAnswer *lostActivationAnswer, covered func(string) bool) {
	t.Helper()
	defer func() { _ = os.WriteFile(filepath.Join(directory, "finished"), nil, 0o600) }()
	market := fixture.Plugins[marketPluginID]
	for _, tenant := range tenants {
		if tenant.list().find(market.AuthorizationID) != nil {
			t.Fatalf("%s offered the market plugin for confirmation", tenant.name())
		}
	}
	item := client.list().find(market.AuthorizationID)
	if item == nil || item.Status != "pending_confirmation" {
		t.Fatalf("market plugin not offered: %+v", item)
	}
	if market.ControllerConfirm {
		// Bought on the market: no license operator confirmed it; this controller's administrator does.
		if item.AuthorizationStatus != "pending_confirmation" {
			t.Fatalf("market plugin not awaiting the controller administrator: %+v", item)
		}
		t.Logf("market plugin %s awaits the controller administrator (license revision %d)",
			item.AuthorizationID, item.Revision)
	}
	body := map[string]any{"verification_id": item.VerificationID, "approved_scopes": item.ApprovedScopes,
		"sensitive_permissions_confirmed": true, "new_permissions_confirmed": true}
	tenants[0].refused(item.AuthorizationID, "confirm", item.Revision, body, http.StatusForbidden,
		"plugin_installation_platform_managed")
	// A pending market authorization: the targets check runs before the license service records the confirmation.
	client.refused(item.AuthorizationID, "confirm", item.Revision, body, http.StatusUnprocessableEntity,
		"plugin_installation_targets_invalid")
	if covered("market plugin before confirmation") {
		t.Fatal("market plugin usable before the platform administrator confirmed it")
	}
	body["targets"] = allTenantTargets()
	installed := confirmAfterLostAnswer(t, client, pool, lostAnswer, item.AuthorizationID, item.Revision, body)
	installVersion, upgradeVersion := "1.0.0", "1.1.0"
	if market.ControllerConfirm {
		installVersion, upgradeVersion = "1.1.0", "1.2.0"
	}
	if installed.Status != "enabled" || installed.Version != installVersion || installed.ManagedBy != "platform" ||
		installed.Targets == nil || !installed.Targets.AllTenants || len(installed.Targets.Tenants) != 0 {
		t.Fatalf("market plugin install=%+v targets=%+v", installed, installed.Targets)
	}
	for _, tenant := range tenants {
		if view := tenant.get(market.AuthorizationID); view.Status != "enabled" || view.ManagedBy != "platform" {
			t.Fatalf("%s view of the market plugin=%+v", tenant.name(), view)
		}
	}
	if !covered("market plugin for all tenants") {
		t.Fatal("market plugin confirmed for all tenants is not usable by every tenant")
	}
	if market.ControllerConfirm {
		state := licenseState(t, fixture, marketPluginID)
		byController := false
		for _, receipt := range state.Receipts {
			byController = byController || receipt.Action == "confirm" && receipt.StableReasonCode == "controller_confirmed"
		}
		if !byController || state.Status != "enabled" {
			t.Fatalf("license side of the market plugin: status=%s receipts=%+v", state.Status, state.Receipts)
		}
	}

	if market.ControllerConfirm {
		requestMarketVersion(t, directory, upgradeVersion)
	} else if status := postOperator(fixture, "/upgrade?plugin="+marketPluginID, nil); status != http.StatusOK {
		t.Fatalf("operator upgrade status=%d", status)
	}
	current := client.get(market.AuthorizationID)
	if current.AvailableUpgrade == nil || current.AvailableUpgrade.Version != upgradeVersion {
		t.Fatalf("market plugin upgrade not offered: %+v", current)
	}
	if market.ControllerConfirm {
		// The proposal does not touch the authorization: the running version keeps working until it is replaced.
		if state := licenseState(t, fixture, marketPluginID); state.Status != "enabled" || state.Version != installVersion {
			t.Fatalf("license moved before the controller upgraded: %+v", state)
		}
		if !covered("market plugin while an upgrade is proposed") {
			t.Fatal("market plugin unusable while its upgrade is only proposed")
		}
	}
	upgraded := client.mutate(current.AuthorizationID, "upgrade", current.Revision, map[string]any{
		"verification_id": current.AvailableUpgrade.VerificationID,
		"approved_scopes": current.AvailableUpgrade.ApprovedScopes, "sensitive_permissions_confirmed": true,
		"new_permissions_confirmed": true}, http.StatusOK)
	if upgraded.Version != upgradeVersion || upgraded.Status != "enabled" {
		t.Fatalf("market plugin upgrade=%+v", upgraded)
	}
	if state := licenseState(t, fixture, marketPluginID); state.Status != "enabled" || state.Version != upgradeVersion {
		t.Fatalf("license after the controller upgrade=%+v", state)
	}
	if !covered("market plugin after the upgrade") {
		t.Fatal("market plugin unusable after the upgrade")
	}
	tenants[0].refused(upgraded.AuthorizationID, "uninstall", upgraded.Revision, map[string]any{"reason": "租户试图卸载"},
		http.StatusForbidden, "plugin_installation_platform_managed")
	removed := client.mutate(upgraded.AuthorizationID, "uninstall", upgraded.Revision,
		map[string]any{"reason": "联调结束卸载"}, http.StatusOK)
	if removed.Status != "uninstalled" {
		t.Fatalf("market plugin uninstall=%+v", removed)
	}
	license := licenseState(t, fixture, marketPluginID)
	if license.Status != "uninstalled" || license.Version != upgradeVersion {
		t.Fatalf("license after market plugin uninstall=%+v", license)
	}
	actions := license.receiptActions()
	t.Logf("market plugin license receipts: %s", strings.Join(actions, ","))
	for _, want := range []string{"confirm", "install_applied", "upgrade_applied", "uninstall"} {
		if !contains(actions, want) {
			t.Fatalf("market plugin license receipts %v miss %s", actions, want)
		}
	}
	// The lost answer and the two keyed retries left one license confirmation and one install.
	confirms, installs := 0, 0
	for _, action := range actions {
		if action == "confirm" {
			confirms++
		}
		if action == "install_applied" {
			installs++
		}
	}
	if confirms != 1 || installs != 1 {
		t.Fatalf("market plugin license receipts %v: confirm=%d install_applied=%d", actions, confirms, installs)
	}
}

// confirmAfterLostAnswer: the license service records the controller confirmation and
// issues the activation fact, but its answer never reaches the controller (503, nothing stored locally). Two
// seconds later the console resends the identical request (same key and request ID): the license service replays
// both answers and the controller stores the installation (200). A further identical resend replays the local
// receipt. One local head and one local confirm receipt remain.
func confirmAfterLostAnswer(t *testing.T, client controlClient, pool *pgxpool.Pool, lostAnswer *lostActivationAnswer,
	authorizationID uuid.UUID, revision uint64, body map[string]any) installationView {
	t.Helper()
	count := func(query string) int {
		t.Helper()
		var value int
		if err := pool.QueryRow(t.Context(), query, authorizationID).Scan(&value); err != nil {
			t.Fatal(err)
		}
		return value
	}
	heads := `SELECT count(*) FROM plugin_installation_heads WHERE authorization_id=$1`
	receipts := `SELECT count(*) FROM plugin_installation_receipts WHERE authorization_id=$1 AND action='confirm'`
	key := "plugin-install-confirm-" + uuid.NewString()[:8]
	lostAnswer.arm(key)
	status, code, _ := client.mutateAsConsole(authorizationID, "confirm", revision, body, key)
	if status != http.StatusServiceUnavailable || code != "plugin_installation_license_unavailable" ||
		lostAnswer.droppedCount() != 1 || count(heads) != 0 || count(receipts) != 0 {
		t.Fatalf("confirmation with a lost activation answer: status=%d code=%q dropped=%d heads=%d",
			status, code, lostAnswer.droppedCount(), count(heads))
	}
	time.Sleep(2 * time.Second)
	status, code, installed := client.mutateAsConsole(authorizationID, "confirm", revision, body, key)
	if status != http.StatusOK || count(heads) != 1 || count(receipts) != 1 {
		t.Fatalf("identical confirmation after the lost answer: status=%d code=%q heads=%d receipts=%d", status, code,
			count(heads), count(receipts))
	}
	time.Sleep(2 * time.Second)
	status, code, replayed := client.mutateAsConsole(authorizationID, "confirm", revision, body, key)
	if status != http.StatusOK || replayed.Revision != installed.Revision || replayed.Status != installed.Status ||
		replayed.VerificationID != installed.VerificationID || count(heads) != 1 || count(receipts) != 1 {
		t.Fatalf("identical confirmation after success: status=%d code=%q replay=%+v installed=%+v", status, code,
			replayed, installed)
	}
	t.Logf("confirmation with a lost activation answer: 503, then identical resend 200 and replay 200; one head, one receipt")
	return installed
}

// requestMarketVersion asks the market process to publish version (same permissions) and waits until its catalog
// reached the license service.
func requestMarketVersion(t *testing.T, directory, version string) {
	t.Helper()
	if err := os.WriteFile(filepath.Join(directory, "market-publish-"+version), nil, 0o600); err != nil {
		t.Fatal(err)
	}
	deadline := time.Now().Add(5 * time.Minute)
	for {
		if _, err := os.Stat(filepath.Join(directory, "market-"+version+".json")); err == nil {
			return
		}
		if time.Now().After(deadline) {
			t.Fatalf("market did not publish %s", version)
		}
		time.Sleep(200 * time.Millisecond)
	}
}
