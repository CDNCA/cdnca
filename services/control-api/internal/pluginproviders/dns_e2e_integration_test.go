//go:build integration

package pluginproviders_test

import (
	"errors"
	"testing"

	"github.com/cdnca/cdnca/services/control-api/internal/dnsacme"
	"github.com/cdnca/cdnca/services/control-api/internal/dnscheck"
	"github.com/cdnca/cdnca/services/control-api/internal/dnsproviderremote"
	"github.com/cdnca/cdnca/services/control-api/internal/pluginproviders"
	"github.com/cdnca/cdnca/services/control-api/internal/pluginproviders/pluginproviderstest"
	"github.com/google/uuid"
)

// Acceptance (PA-22): a test third-party DNS plugin (HTTPS fake service) is
// installed (declaration materialized), passes its contract, is enabled,
// is accepted as the DNS provider (provider type plugin, verified through
// the signed protocol), and the control plane's reconcile writes, updates
// and deletes A records in the plugin's zone. Disabling the plugin stops
// every write at once; it cannot be chosen again until re-enabled.
func TestDNSPluginInstallContractChooseWrite(t *testing.T) {
	pool, platform, admin := newPool(t)
	const pluginID = "com.example.dnsplus"
	const zone = "customer.example"
	plugin := pluginproviderstest.Start(t, pool, pluginID, "dns")
	plugin.Fake.Zone = zone
	plugin.Materialize(t, pool)
	ctx := t.Context()
	dnsacme.SetPluginProviderClients(plugin.Service)
	dnsproviderremote.SetPluginClients(plugin.Service)
	t.Cleanup(func() { dnsacme.SetPluginProviderClients(nil); dnsproviderremote.SetPluginClients(nil) })
	verifier := dnsacme.NewProviderVerifierDispatcher()
	credentials := map[string]string{dnsacme.PluginCredentialField: pluginID}

	// Not yet passed: it cannot be chosen.
	if err := verifier.VerifyCredentials(ctx, dnsacme.ProviderTypePlugin, credentials); !errors.Is(err, dnsacme.ErrProviderPluginNotUsable) {
		t.Fatalf("choose before contract = %v", err)
	}
	if _, err := plugin.Service.RunContract(ctx, pluginproviders.Actor{}, pluginID); err != nil {
		t.Fatal(err)
	}
	actor := pluginproviders.Actor{UserID: admin, ScopeID: platform, RequestID: "req-dns-enable"}
	if _, err := plugin.Service.Store.SetEnabled(ctx, actor, pluginID, true); err != nil {
		t.Fatal(err)
	}
	if err := verifier.VerifyCredentials(ctx, dnsacme.ProviderTypePlugin, credentials); err != nil {
		t.Fatalf("choose after contract and enable: %v", err)
	}

	// The DNS write runtime: create, update, delete an A record.
	remote := dnsproviderremote.NewReconcileRemote()
	scope := uuid.New()
	config := dnsproviderremote.ProviderConfig{TenantID: uuid.New(), ScopeID: scope, TenantScopeID: scope,
		ProviderID: uuid.New(), ProviderType: dnsproviderremote.ProviderTypePlugin, ZoneID: uuid.New(), ZoneName: zone,
		Credentials: map[string]string{dnsproviderremote.PluginCredentialField: pluginID}}
	create := dnscheck.ProviderOperation{Action: dnscheck.ProviderCreate, Name: "www." + zone + ".", Type: dnscheck.RecordA,
		Value: "203.0.113.20", TTL: 600, Line: "电信"}
	id, err := remote.Mutate(ctx, config, create)
	if err != nil || id == "" {
		t.Fatalf("create A: %q %v", id, err)
	}
	records := plugin.Fake.Records(zone)
	if len(records) != 1 || records[0].Value != "203.0.113.20" || records[0].Line != "电信" || records[0].Name != "www."+zone {
		t.Fatalf("plugin zone after create %+v", records)
	}
	lookup, err := remote.Lookup(ctx, config, create)
	if err != nil {
		t.Fatalf("lookup: %v", err)
	}
	_ = lookup
	update := create
	update.Action, update.RecordID, update.Value = dnscheck.ProviderUpdate, id, "203.0.113.21"
	update.PreviousValue, update.PreviousTTL, update.PreviousLine = create.Value, create.TTL, create.Line
	if _, err := remote.Mutate(ctx, config, update); err != nil {
		t.Fatalf("update A: %v", err)
	}
	if records := plugin.Fake.Records(zone); len(records) != 1 || records[0].Value != "203.0.113.21" {
		t.Fatalf("plugin zone after update %+v", records)
	}
	listed, err := dnsproviderremote.NewZoneRecordLister().ListZoneRecords(ctx, config, "www."+zone+".")
	if err != nil || len(listed) != 1 || listed[0].ID != id {
		t.Fatalf("list zone records %+v %v", listed, err)
	}

	// Disabled: every write stops, and it can no longer be chosen.
	if _, err := plugin.Service.Store.SetEnabled(ctx, actor, pluginID, false); err != nil {
		t.Fatal(err)
	}
	calls := plugin.Fake.Calls["dns/delete_record"]
	remove := update
	remove.Action = dnscheck.ProviderDelete
	if _, err := remote.Mutate(ctx, config, remove); err == nil {
		t.Fatal("disabled plugin still written")
	}
	if plugin.Fake.Calls["dns/delete_record"] != calls {
		t.Fatal("disabled plugin was called")
	}
	if err := verifier.VerifyCredentials(ctx, dnsacme.ProviderTypePlugin, credentials); !errors.Is(err, dnsacme.ErrProviderPluginNotUsable) {
		t.Fatalf("choose disabled plugin = %v", err)
	}
	if _, err := plugin.Service.Store.SetEnabled(ctx, actor, pluginID, true); err != nil {
		t.Fatal(err)
	}
	if _, err := remote.Mutate(ctx, config, remove); err != nil {
		t.Fatalf("delete A after re-enable: %v", err)
	}
	if records := plugin.Fake.Records(zone); len(records) != 0 {
		t.Fatalf("plugin zone after delete %+v", records)
	}
	// The dns_providers row of the plugin type is accepted by the schema.
	if _, err := pool.Exec(ctx, `ALTER TABLE dns_providers VALIDATE CONSTRAINT dns_providers_provider_type_check`); err != nil {
		t.Fatal(err)
	}
	var allowed bool
	if err := pool.QueryRow(ctx, `SELECT pg_get_constraintdef(oid) LIKE '%''plugin''%' FROM pg_constraint
		WHERE conname='dns_providers_provider_type_check'`).Scan(&allowed); err != nil || !allowed {
		t.Fatalf("provider type plugin not allowed: %v", err)
	}
}

// Acceptance (PA-22): a plugin whose response signature is forged (another
// key) is refused at the first call even when an operator forced it on in
// the database: the client verifies every answer.
func TestDNSPluginForgedResponsesRefused(t *testing.T) {
	pool, platform, admin := newPool(t)
	const pluginID = "com.example.forger"
	plugin := pluginproviderstest.Start(t, pool, pluginID, "dns")
	plugin.Fake.Zone = "customer.example"
	plugin.Materialize(t, pool)
	ctx := t.Context()
	if _, err := plugin.Service.RunContract(ctx, pluginproviders.Actor{}, pluginID); err != nil {
		t.Fatal(err)
	}
	if _, err := plugin.Service.Store.SetEnabled(ctx, pluginproviders.Actor{UserID: admin, ScopeID: platform}, pluginID, true); err != nil {
		t.Fatal(err)
	}
	plugin.Fake.Misbehave.WrongResponseKey = true // turns malicious after passing
	dnsproviderremote.SetPluginClients(plugin.Service)
	t.Cleanup(func() { dnsproviderremote.SetPluginClients(nil) })
	scope := uuid.New()
	config := dnsproviderremote.ProviderConfig{TenantID: uuid.New(), ScopeID: scope, TenantScopeID: scope,
		ProviderID: uuid.New(), ProviderType: dnsproviderremote.ProviderTypePlugin, ZoneID: uuid.New(), ZoneName: "customer.example",
		Credentials: map[string]string{dnsproviderremote.PluginCredentialField: pluginID}}
	_, err := dnsproviderremote.NewReconcileRemote().Mutate(ctx, config, dnscheck.ProviderOperation{Action: dnscheck.ProviderCreate,
		Name: "www.customer.example.", Type: dnscheck.RecordA, Value: "203.0.113.30", TTL: 600})
	if dnsproviderremote.ErrorCodeOf(err) != dnsproviderremote.CodeInvalidResponse {
		t.Fatalf("forged response = %v", err)
	}
}
