package migrations

import (
	"fmt"
	"io/fs"
	"strconv"
	"strings"
	"testing"
)

// Migration 631 (built-in DNS providers DNSPod.com, GoDaddy,
// Namesilo) is a placeholder number on top of 630_market_node_probe_alerts:
// the merge renumbers it (with the predecessor guard), so the version is read
// from the embedded file name and only the predecessor is fixed here.
const (
	migration631Name           = "dns_provider_dnspod_com_godaddy_namesilo"
	migration631PreviousID     = "630_market_node_probe_alerts"
	migration631PreviousNumber = 630
)

func TestDNSProviderDNSPodComGoDaddyNamesilo631Contract(t *testing.T) {
	matches, err := fs.Glob(FS, "*_"+migration631Name+".up.sql")
	if err != nil || len(matches) != 1 {
		t.Fatalf("migration %s: %v %v", migration631Name, matches, err)
	}
	version, err := strconv.Atoi(matches[0][:3])
	if err != nil {
		t.Fatal(err)
	}
	id := fmt.Sprintf("%03d_%s", version, migration631Name)
	for _, script := range []struct {
		name      string
		required  []string
		forbidden []string
	}{
		{id + ".up.sql", []string{
			fmt.Sprintf("(SELECT count(*) FROM schema_migrations) <> %d", migration631PreviousNumber),
			fmt.Sprintf("(SELECT max(version) FROM schema_migrations) <> %d", migration631PreviousNumber),
			"migration_id='" + migration631PreviousID + "'", fmt.Sprintf("ERRCODE='P%d0'", version),
			"DROP CONSTRAINT dns_providers_provider_type_check",
			"'custom_http', 'plugin',\n        'namecom', 'dnspod_com', 'godaddy', 'namesilo')",
		}, []string{"DELETE FROM", "UPDATE ", "DROP TABLE"}},
		{id + ".down.sql", []string{
			fmt.Sprintf("(SELECT count(*) FROM schema_migrations) <> %d", version),
			"migration_id='" + id + "'", fmt.Sprintf("ERRCODE='P%d1'", version), fmt.Sprintf("ERRCODE='P%d2'", version),
			"WHERE provider_type IN ('dnspod_com', 'godaddy', 'namesilo')",
			"'custom_http', 'plugin',\n        'namecom')",
		}, []string{"DELETE FROM", "UPDATE ", "DROP TABLE"}},
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
		for _, forbidden := range script.forbidden {
			if strings.Contains(string(raw), forbidden) {
				t.Errorf("%s must not contain %q", script.name, forbidden)
			}
		}
	}
}
