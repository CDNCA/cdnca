package main

import (
	"net/http"
	"os"
	"path/filepath"
	"strings"
	"testing"
)

// runMarketPluginFlow drives example plugin two (bought on the plugin market when PLUGIN_E2E_MARKET=1, otherwise
// published by the license operator) through the production installation path: the controller administrator
// confirms the authorization, the platform approves 1.1.0, the tenant upgrades and finally uninstalls it. Every
// step must be reflected in the license-side authorization receipts. It writes <dir>/finished so the market
// process stops serving its catalog origin.
func runMarketPluginFlow(t *testing.T, directory string, fixture licenseFixture, client controlClient) {
	t.Helper()
	defer func() { _ = os.WriteFile(filepath.Join(directory, "finished"), nil, 0o600) }()
	market := fixture.Plugins[marketPluginID]
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
	installed := client.mutate(item.AuthorizationID, "confirm", item.Revision, map[string]any{
		"verification_id": item.VerificationID, "approved_scopes": item.ApprovedScopes,
		"sensitive_permissions_confirmed": true, "new_permissions_confirmed": true}, http.StatusOK)
	if installed.Status != "enabled" || installed.Version != "1.0.0" {
		t.Fatalf("market plugin install=%+v", installed)
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

	if status := postOperator(fixture, "/upgrade?plugin="+marketPluginID, nil); status != http.StatusOK {
		t.Fatalf("operator upgrade status=%d", status)
	}
	current := client.get(market.AuthorizationID)
	if current.AvailableUpgrade == nil || current.AvailableUpgrade.Version != "1.1.0" {
		t.Fatalf("market plugin upgrade not offered: %+v", current)
	}
	upgraded := client.mutate(current.AuthorizationID, "upgrade", current.Revision, map[string]any{
		"verification_id": current.AvailableUpgrade.VerificationID,
		"approved_scopes": current.AvailableUpgrade.ApprovedScopes, "sensitive_permissions_confirmed": true,
		"new_permissions_confirmed": true}, http.StatusOK)
	if upgraded.Version != "1.1.0" || upgraded.Status != "enabled" {
		t.Fatalf("market plugin upgrade=%+v", upgraded)
	}
	removed := client.mutate(upgraded.AuthorizationID, "uninstall", upgraded.Revision,
		map[string]any{"reason": "联调结束卸载"}, http.StatusOK)
	if removed.Status != "uninstalled" {
		t.Fatalf("market plugin uninstall=%+v", removed)
	}
	license := licenseState(t, fixture, marketPluginID)
	if license.Status != "uninstalled" || license.Version != "1.1.0" {
		t.Fatalf("license after market plugin uninstall=%+v", license)
	}
	actions := license.receiptActions()
	t.Logf("market plugin license receipts: %s", strings.Join(actions, ","))
	for _, want := range []string{"confirm", "install_applied", "upgrade_applied", "uninstall"} {
		if !contains(actions, want) {
			t.Fatalf("market plugin license receipts %v miss %s", actions, want)
		}
	}
}
