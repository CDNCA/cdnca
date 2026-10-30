//go:build integration

package migrations_test

import (
	"io/fs"
	"strconv"
	"strings"
	"testing"

	controlmigrations "github.com/cdnca/cdnca/services/control-api/migrations"
)

func TestCNAMEMarketTargetMigration(t *testing.T) {
	matches, err := fs.Glob(controlmigrations.FS, "*_cname_market_target.up.sql")
	if err != nil || len(matches) != 1 {
		t.Fatalf("cname market target migration: %v %v", matches, err)
	}
	version, err := strconv.ParseInt(strings.SplitN(matches[0], "_", 2)[0], 10, 64)
	if err != nil {
		t.Fatal(err)
	}
	pool := packageCommerceRBAC079Pool(t, version-1)
	ctx := t.Context()
	for _, step := range []string{"up", "down", "up"} {
		if err := migrateVersionIsolated(ctx, pool, step, version); err != nil {
			t.Fatalf("%s %d: %v", step, version, err)
		}
	}
	var guarded bool
	// pg_trigger is cluster-wide per database: scope to this schema's table.
	if err := pool.QueryRow(ctx, `SELECT EXISTS(SELECT 1 FROM pg_trigger WHERE tgrelid='dns_cname_retargets'::regclass
			AND tgname='dns_cname_retargets_protect_286')
		AND NOT EXISTS(SELECT 1 FROM pg_trigger WHERE tgrelid='dns_cname_retargets'::regclass
			AND tgname='dns_cname_retargets_protect_280')`).Scan(&guarded); err != nil || !guarded {
		t.Fatalf("retarget guard = %v, %v", guarded, err)
	}
	var cnameAndAddresses bool
	if err := pool.QueryRow(ctx, `SELECT pg_get_constraintdef(oid) LIKE '%target_cname IS NOT NULL%'
		FROM pg_constraint WHERE conrelid='dns_cname_retargets'::regclass AND conname='dns_cname_retargets_target_286_check'`).Scan(&cnameAndAddresses); err != nil || !cnameAndAddresses {
		t.Fatalf("target constraint = %v, %v", cnameAndAddresses, err)
	}
}
