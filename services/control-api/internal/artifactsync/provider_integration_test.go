//go:build integration

package artifactsync_test

import (
	"crypto/ed25519"
	"encoding/base64"
	"testing"

	"github.com/cdnca/cdnca/libs/entitlement/artifactcatalog"
	"github.com/cdnca/cdnca/libs/entitlement/pluginprovider"
	"github.com/google/uuid"
)

const providerPlugin = "com.example.dnsplus"

func providerDeclaration(t *testing.T, version string) []byte {
	t.Helper()
	public, _, _ := ed25519.GenerateKey(nil)
	_, encoded, err := pluginprovider.Build(providerPlugin, version, "https://dns.dnsplus.example/api",
		base64.RawURLEncoding.EncodeToString(public), []pluginprovider.Provided{{Kind: "dns", ProtocolVersion: "1"}},
		[]string{pluginprovider.Permission("dns")})
	if err != nil {
		t.Fatal(err)
	}
	return encoded
}

// Acceptance (PA-22): an authorized provider plugin declaration is
// materialized with a pending contract only once the installation is
// enabled here; an upgrade (new bytes) resets the contract; withdrawal at
// the license service withdraws it.
func TestPluginProvidersMaterialize(t *testing.T) {
	f := newFixture(t)
	content := providerDeclaration(t, "1.0.0")
	entry, err := artifactcatalog.DataPackEntry(artifactcatalog.KindPluginProvider, providerPlugin, "1.0.0", 1, content, "")
	if err != nil {
		t.Fatal(err)
	}
	f.license.Publish(entry, content)
	f.sync()
	if local := f.local(); local[entry.ArtifactID] != 1 {
		t.Fatalf("plugin_provider not downloaded: %v", local)
	}
	if n := f.count(`SELECT count(*) FROM plugin_providers`); n != 0 {
		t.Fatalf("provider materialized before the installation was enabled here: %d", n)
	}
	// plugconfirm3：provider 只认租户作用域的 external_https 启用记录。
	f.recordInstallation(uuid.New(), "tenant", providerPlugin, "1.0.0", false, "external_https")
	f.sync()
	if n := f.count(`SELECT count(*) FROM plugin_providers WHERE plugin_id=$1 AND status='active' AND contract_status='pending'
		AND NOT enabled AND kinds='{dns}'`, providerPlugin); n != 1 {
		t.Fatalf("materialized providers = %d", n)
	}
	if n := f.count(`SELECT count(*) FROM audit_events WHERE action='plugin.provider.materialize' AND resource_id=$1
		AND category='plugin'`, providerPlugin); n != 1 {
		t.Fatalf("materialize audit = %d", n)
	}
	// Simulate a passed contract, then an upgrade: the contract resets.
	if _, err := f.pool.Exec(t.Context(), `UPDATE plugin_providers SET contract_status='passed',contract_version='v',
		contract_declaration_sha256=declaration_sha256,contract_report='{}',contract_checked_at=now() WHERE plugin_id=$1`,
		providerPlugin); err != nil {
		t.Fatal(err)
	}
	upgraded := providerDeclaration(t, "1.1.0")
	next, err := artifactcatalog.DataPackEntry(artifactcatalog.KindPluginProvider, providerPlugin, "1.1.0", 2, upgraded, "")
	if err != nil {
		t.Fatal(err)
	}
	f.license.Publish(next, upgraded)
	f.sync()
	if n := f.count(`SELECT count(*) FROM plugin_providers WHERE plugin_id=$1 AND version='1.1.0' AND contract_status='pending'`,
		providerPlugin); n != 1 {
		t.Fatalf("upgrade did not reset the contract")
	}
	f.license.Withdraw(entry.ArtifactID)
	f.sync()
	if n := f.count(`SELECT count(*) FROM plugin_providers WHERE plugin_id=$1 AND status='withdrawn'`, providerPlugin); n != 1 {
		t.Fatalf("provider not withdrawn")
	}
	if n := f.count(`SELECT count(*) FROM audit_events WHERE action='plugin.provider.withdraw' AND resource_id=$1`,
		providerPlugin); n != 1 {
		t.Fatalf("withdraw audit = %d", n)
	}
}
