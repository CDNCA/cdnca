package migrations

import (
	"crypto/sha256"
	"fmt"
	"strings"
	"testing"
)

// Migration 632 (built-in DNS providers ClouDNS, Namecheap, JD
// Cloud) follows 631 (DNSPod.com, GoDaddy, Namesilo); both CHECK lists
// keep 631's three types. Everything that changes with a renumbering is here.
const (
	migration632Version         = 632
	migration632ID              = "632_dns_provider_cloudns_namecheap_jdcloud"
	migration632PreviousVersion = 631
	migration632PreviousID      = "631_dns_provider_dnspod_com_godaddy_namesilo"
	migration632UpSHA           = "1953173edf80b24ae98cbbf7bd8baffdcb2a1fc8ed27cdd0bd02caf34fb41583"
	migration632DownSHA         = "f634e20db8cfd7860982fa27f79e8bc0ff3cb26b2490e80d40a88b1051a15355"
)

func TestDNSProviderClouDNSNamecheapJDCloud632Contract(t *testing.T) {
	for _, script := range []struct {
		name, sha string
		required  []string
	}{
		{migration632ID + ".up.sql", migration632UpSHA, []string{
			fmt.Sprintf("(SELECT count(*) FROM schema_migrations) <> %d", migration632PreviousVersion),
			fmt.Sprintf("(SELECT max(version) FROM schema_migrations) <> %d", migration632PreviousVersion),
			"migration_id='" + migration632PreviousID + "'", "ERRCODE='P6320'",
			"DROP CONSTRAINT dns_providers_provider_type_check",
			"'custom_http', 'plugin',\n        'namecom', 'dnspod_com', 'godaddy', 'namesilo', 'cloudns', 'namecheap', 'jdcloud')",
		}},
		{migration632ID + ".down.sql", migration632DownSHA, []string{
			fmt.Sprintf("(SELECT count(*) FROM schema_migrations) <> %d", migration632Version),
			"migration_id='" + migration632ID + "'", "ERRCODE='P6321'", "ERRCODE='P6322'",
			"WHERE provider_type IN ('cloudns', 'namecheap', 'jdcloud')", "'custom_http', 'plugin',\n        'namecom', 'dnspod_com', 'godaddy', 'namesilo')",
		}},
	} {
		raw, err := FS.ReadFile(script.name)
		if err != nil {
			t.Skipf("%s not embedded under this number (local renumbering): %v", script.name, err)
		}
		if got := fmt.Sprintf("%x", sha256.Sum256(raw)); got != script.sha {
			t.Fatalf("%s checksum drift: %s", script.name, got)
		}
		for _, required := range script.required {
			if !strings.Contains(string(raw), required) {
				t.Errorf("%s missing %q", script.name, required)
			}
		}
	}
}
