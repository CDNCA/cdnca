package migrations_test

import (
	"crypto/sha256"
	"fmt"
	"regexp"
	"strconv"
	"testing"

	controlmigrations "github.com/cdnca/cdnca/services/control-api/migrations"
)

var migrationPin137Through160Pattern = regexp.MustCompile(
	`(?s)version\s*=\s*([0-9]+)\s+AND\s+migration_id\s*=\s*'([^']+)'\s+AND\s+` +
		`checksum_sha256\s*=\s*'([0-9a-f]{64})'(?:\s+AND\s+down_checksum_sha256\s*=\s*'([0-9a-f]{64})')?`,
)

type migrationChain137Through160Fact struct {
	id      string
	upSHA   string
	downSHA string
}

func TestMigrationChain137Through160PinsActualPredecessors(t *testing.T) {
	ids := []string{
		"136_site_protocol_batch",
		"137_tcp_billing_factor",
		"138_challenge_publication_facts",
		"139_l4_line_switches",
		"140_package_subscription_manual_open",
		"141_platform_global_announcements",
		"142_cache_policy_schema_v2",
		"143_cache_policy_definitions",
		"144_waf_geo_authority",
		"145_plugin_installations",
		"146_package_cycle_enforcement",
		"147_site_capture_policy",
		"148_site_domains",
		"149_api_key_pepper_rotation",
		"150_node_metrics",
		"151_l4_domain_geo_runtime",
		"152_recharge_payment_lifecycle",
		"153_node_revocation_checkpoint",
		"154_control_upgrade_systemd_repository",
		"155_dns_provider_retry_states",
		"156_runtime_patch_policy",
		"157_ja4_block_workflow",
		"158_ja4_block_edge_receipts",
		"159_account_registration",
		"160_site_tls_protocols",
	}
	facts := make(map[int]migrationChain137Through160Fact, len(ids))
	for index, id := range ids {
		up := readMigrationChain137Through160(t, id+".up.sql")
		down := readMigrationChain137Through160(t, id+".down.sql")
		facts[136+index] = migrationChain137Through160Fact{
			id: id, upSHA: fmt.Sprintf("%x", sha256.Sum256(up)),
			downSHA: fmt.Sprintf("%x", sha256.Sum256(down)),
		}
	}

	for version := 137; version <= 160; version++ {
		for _, direction := range []string{"up", "down"} {
			name := facts[version].id + "." + direction + ".sql"
			content := readMigrationChain137Through160(t, name)
			for _, match := range migrationPin137Through160Pattern.FindAllSubmatch(content, -1) {
				referencedVersion, err := strconv.Atoi(string(match[1]))
				if err != nil {
					t.Fatal(err)
				}
				expected, known := facts[referencedVersion]
				if !known {
					continue
				}
				if string(match[2]) != expected.id || string(match[3]) != expected.upSHA ||
					len(match[4]) > 0 && string(match[4]) != expected.downSHA {
					t.Errorf("%s pins migration %d as id=%s up=%s down=%s, want id=%s up=%s down=%s",
						name, referencedVersion, match[2], match[3], match[4], expected.id, expected.upSHA, expected.downSHA)
				}
			}
		}
	}
}

func readMigrationChain137Through160(t *testing.T, name string) []byte {
	t.Helper()
	content, err := controlmigrations.FS.ReadFile(name)
	if err != nil {
		t.Fatal(err)
	}
	return content
}
