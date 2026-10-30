package analyticslog

import (
	"os"
	"strings"
	"testing"
)

// TF-C02：grant 是 PostgreSQL 保留字，不能作为未加引号的别名。
func TestExportSQLAvoidsReservedGrantAlias(t *testing.T) {
	raw, err := os.ReadFile("export_postgres.go")
	if err != nil {
		t.Fatal(err)
	}
	source := string(raw)
	for _, forbidden := range []string{"grants_v1 grant ", "grant.export_id", "grant.consumed_at"} {
		if strings.Contains(source, forbidden) {
			t.Fatalf("export_postgres.go still uses reserved alias: %q", forbidden)
		}
	}
}
