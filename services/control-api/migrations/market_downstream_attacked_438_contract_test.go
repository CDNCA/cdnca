package migrations

import (
	"crypto/sha256"
	"fmt"
	"strings"
	"testing"
)

// Migration 438 (ML-20: market.downstream.attacked notice for resellers)
// is a placeholder number; it must follow the integration head 431_market_supply_limits.
const (
	migration438Version         = 438
	migration438ID              = "438_market_downstream_attacked"
	migration438PreviousID      = "437_market_supply_tenant_plugins"
	migration438PreviousUpSHA   = "b535964e274654e00a376c3a012990d39d4321e3fdfc576b1a7bd0a6ef655778"
	migration438PreviousDownSHA = "e8513641a2746a9dc4ef39547052c318bedde26d43123ac69d60388c60316c53"
	migration438UpSHA           = "ae1a20624da0170d149465598480aa93c393d936d14fd8bd162dbe664ee0263b"
	migration438DownSHA         = "ebb5be2fb4091cd4f94170b7901d7624be88ba94ff9119ed1371aa3b31b3a007"
)

func TestMarketDownstreamAttacked438Contract(t *testing.T) {
	for _, script := range []struct {
		name, sha string
		required  []string
	}{
		{migration438ID + ".up.sql", migration438UpSHA, []string{
			fmt.Sprintf("(SELECT count(*) FROM schema_migrations) <> %d", migration438Version-1),
			"migration_id='" + migration438PreviousID + "'", migration438PreviousUpSHA, migration438PreviousDownSHA,
			"ERRCODE='P4380'", "('market.downstream.attacked', true", "ARRAY['subscription','downstream','window_start']",
		}},
		{migration438ID + ".down.sql", migration438DownSHA, []string{
			fmt.Sprintf("(SELECT count(*) FROM schema_migrations) <> %d", migration438Version),
			"migration_id='" + migration438ID + "'", "ERRCODE='P4381'", "ERRCODE='P4382'",
		}},
	} {
		raw, err := FS.ReadFile(script.name)
		if err != nil {
			t.Fatal(err)
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
