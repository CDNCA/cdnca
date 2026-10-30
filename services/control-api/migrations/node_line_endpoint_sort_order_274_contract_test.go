package migrations

import (
	"crypto/sha256"
	"fmt"
	"strings"
	"testing"
)

const (
	nodeLineEndpointSortOrder274UpSHA   = "1524569c2e62c6ddf98c7079e17523175d5c41b7f693634c6bfa779d18f389b9"
	nodeLineEndpointSortOrder274DownSHA = "a23ff8055f90da8547f7c615a0917dc848f5b33cc7b2be8ef7774b045e72a9d4"
)

func TestNodeLineEndpointSortOrder274Contract(t *testing.T) {
	upBytes, err := FS.ReadFile("274_node_line_endpoint_sort_order.up.sql")
	if err != nil {
		t.Fatal(err)
	}
	downBytes, err := FS.ReadFile("274_node_line_endpoint_sort_order.down.sql")
	if err != nil {
		t.Fatal(err)
	}
	if got := fmt.Sprintf("%x", sha256.Sum256(upBytes)); got != nodeLineEndpointSortOrder274UpSHA {
		t.Fatalf("migration 274 up SHA drifted: got %s", got)
	}
	if got := fmt.Sprintf("%x", sha256.Sum256(downBytes)); got != nodeLineEndpointSortOrder274DownSHA {
		t.Fatalf("migration 274 down SHA drifted: got %s", got)
	}
	up, down := string(upBytes), string(downBytes)
	for _, required := range []string{
		"LOCK TABLE schema_migrations, node_line_endpoints IN ACCESS EXCLUSIVE MODE",
		"(SELECT count(*) FROM schema_migrations) <> 273",
		"273_validator_search_path",
		"65997dc158a20dc1ab2d809362cbd4e4d2117554c411830d84eac8e7e0d48bf7",
		"e72851fe9670e3686de8bdea22d445a32de9be91a985519d84f549f4b2d6b471",
		"ADD COLUMN sort_order integer NOT NULL DEFAULT 100",
		"CHECK (sort_order BETWEEN 0 AND 999999)",
		"node_line_endpoints_sort_274_idx",
	} {
		if !strings.Contains(up, required) {
			t.Errorf("migration 274 up missing %q", required)
		}
	}
	for _, required := range []string{
		"(SELECT count(*) FROM schema_migrations) <> 274",
		"274_node_line_endpoint_sort_order",
		"migration 274 down refuses to discard endpoint sort values",
		"DROP INDEX node_line_endpoints_sort_274_idx",
		"DROP COLUMN sort_order",
	} {
		if !strings.Contains(down, required) {
			t.Errorf("migration 274 down missing %q", required)
		}
	}
	for _, forbidden := range []string{"DELETE FROM schema_migrations", "DROP TABLE", " CASCADE"} {
		if strings.Contains(strings.ToUpper(up+down), forbidden) {
			t.Errorf("migration 274 must preserve existing facts, found %q", forbidden)
		}
	}
}
