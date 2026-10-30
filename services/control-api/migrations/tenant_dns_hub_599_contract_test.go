package migrations

import (
	"crypto/sha256"
	"fmt"
	"strings"
	"testing"
)

// Migration 599 (用户端域名解析, ADR 0020 §3.1). Everything that changes if a
// merge renumbers it is here.
const (
	migration599PreviousVersion = 598
	migration599PreviousID      = "598_security_hold_republication"
	migration599PreviousUpSHA   = "eb9347858ef08bfcc08baec9284d0aa61569873e01f1d1dc306f63714c1168da"
	migration599PreviousDownSHA = "6e47c6a8cd2a220650c0edf4f7ea50c0ff6795bdd492fd90213904f22f1be372"
	migration599ID              = "599_tenant_dns_hub"
)

func TestTenantDNSHub599Contract(t *testing.T) {
	for _, script := range []struct {
		name     string
		required []string
	}{
		{migration599ID + ".up.sql", []string{
			fmt.Sprintf("(SELECT count(*) FROM schema_migrations) <> %d", migration599PreviousVersion),
			fmt.Sprintf("WHERE version=%d AND", migration599PreviousVersion),
			"migration_id='" + migration599PreviousID + "'",
			"checksum_sha256='" + migration599PreviousUpSHA + "'",
			"down_checksum_sha256='" + migration599PreviousDownSHA + "'",
			"ERRCODE='P5990'", "ERRCODE = 'P5993'",
			"CREATE TABLE tenant_dns_provider_listings", "CREATE TABLE tenant_dns_domains", "CREATE TABLE tenant_dns_record_ops",
			"UNIQUE (scope_id, actor_user_id, idempotency_key)", "provider.managed_by = 'tenant'",
			"state IN ('applied', 'failed', 'uncertain')", "record_type IN ('A', 'AAAA', 'CNAME', 'TXT')",
		}},
		{migration599ID + ".down.sql", []string{
			"(SELECT count(*) FROM schema_migrations) <> 599", "migration_id='" + migration599ID + "'",
			"ERRCODE='P5991'", "ERRCODE='P5992'", "state = 'uncertain'",
		}},
	} {
		raw, err := FS.ReadFile(script.name)
		if err != nil {
			t.Fatal(err)
		}
		for _, required := range script.required {
			if !strings.Contains(string(raw), required) {
				t.Errorf("%s missing %q", script.name, required)
			}
		}
	}
	// No new permission codes: the hub reuses dns.read / dns.manage.
	up, _ := FS.ReadFile(migration599ID + ".up.sql")
	if strings.Contains(string(up), "INSERT INTO permissions") {
		t.Error("599 must not add permission codes")
	}
	for suffix, want := range map[string]string{".up.sql": migration599PreviousUpSHA, ".down.sql": migration599PreviousDownSHA} {
		raw, err := FS.ReadFile(migration599PreviousID + suffix)
		if err != nil {
			t.Fatal(err)
		}
		if got := fmt.Sprintf("%x", sha256.Sum256(raw)); got != want {
			t.Errorf("%s%s checksum %s, guard pins %s", migration599PreviousID, suffix, got, want)
		}
	}
}
