package migrations

import (
	"crypto/sha256"
	"fmt"
	"os"
	"strings"
	"testing"
)

func TestL2TopologyDefaultRegion270Contract(t *testing.T) {
	up, err := FS.ReadFile("270_l2_topology_default_region.up.sql")
	if err != nil {
		t.Fatal(err)
	}
	down, err := FS.ReadFile("270_l2_topology_default_region.down.sql")
	if err != nil {
		t.Fatal(err)
	}
	for _, required := range []string{
		"LOCK TABLE schema_migrations, l2_topology_configs IN ACCESS EXCLUSIVE MODE",
		"(SELECT count(*) FROM schema_migrations) <> 269",
		"269_node_host_metrics",
		"7a6bfe3948bed1f878688d5341bf36deaa2b2ceab55e8cbcc3bbfe20a081478c",
		"b51f60964c0cc0aa3ecb4076c27577eb2e77f3ad210a4c8ba5a5e0ab569231d8",
		"DROP CONSTRAINT l2_topology_configs_region_check",
		"ADD CONSTRAINT l2_topology_configs_region_270_check",
		"char_length(region) BETWEEN 0 AND 64",
		"region = btrim(region)", "region !~ '[[:cntrl:]]'",
	} {
		if !strings.Contains(string(up), required) {
			t.Errorf("270 up missing %q", required)
		}
	}
	for _, required := range []string{
		"(SELECT count(*) FROM schema_migrations) <> 270",
		"270_l2_topology_default_region",
		fmt.Sprintf("%x", sha256.Sum256(up)),
		"EXISTS (SELECT 1 FROM l2_topology_configs WHERE region = '')",
		"DROP CONSTRAINT l2_topology_configs_region_270_check",
		"ADD CONSTRAINT l2_topology_configs_region_check",
		"char_length(region) BETWEEN 1 AND 64",
		"USING ERRCODE = 'P2702'",
	} {
		if !strings.Contains(string(down), required) {
			t.Errorf("270 down missing %q", required)
		}
	}
	for _, forbidden := range []string{" CASCADE", "DELETE FROM", "UPDATE L2_TOPOLOGY", "DROP TABLE", "DELETED_AT IS NULL"} {
		if strings.Contains(strings.ToUpper(string(up)+string(down)), forbidden) {
			t.Errorf("270 must preserve facts, found %q", forbidden)
		}
	}
	contract, err := os.ReadFile("../../../api/control-node-scheduling.openapi.yaml")
	if err != nil {
		t.Fatal(err)
	}
	_, region, found := strings.Cut(string(contract), "    L2Region:\n")
	region, _, _ = strings.Cut(region, "    L2Remark:\n")
	if !found || !strings.Contains(region, "minLength: 0") || !strings.Contains(region, "maxLength: 64") ||
		!strings.Contains(string(contract), "required: [name, region, mode, load_method]") {
		t.Fatalf("L2Region must allow explicit empty default and remain required: %s", region)
	}
}
