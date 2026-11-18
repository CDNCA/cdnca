//go:build integration

package migrations_test

import (
	"errors"
	"testing"

	"github.com/google/uuid"
	"github.com/jackc/pgx/v5/pgconn"
)

// TestGeoareaV2Codes680: 679 -> 680 -> 679 -> 680. The
// v2 codes (continents asia/oceania, regions northern_europe/caribbean/...) are
// refused before 680 and accepted after, v1 codes and carrier/province scopes
// all the way; down refuses while a region or a line record uses a v2 code.
func TestGeoareaV2Codes680(t *testing.T) {
	const version = 680
	pool := migrationPoolAt(t, version-1)
	ctx := t.Context()
	platform := uuid.New()
	mustExec(t, pool, `INSERT INTO access_scopes(id,kind) VALUES($1,'platform')`, platform)
	var displayID int64
	if err := pool.QueryRow(ctx, `INSERT INTO region_catalog(id,platform_scope_id,name,area_code) VALUES(gen_random_uuid(),$1,'东南亚','southeast_asia')
		RETURNING display_id`, platform).Scan(&displayID); err != nil {
		t.Fatal(err)
	}
	setArea := func(area string) error {
		_, err := pool.Exec(ctx, `UPDATE region_catalog SET area_code=$2,revision=revision+1 WHERE display_id=$1`, displayID, area)
		return err
	}
	siteID := uuid.New()
	insertScope := func(scope string) error {
		tx, err := pool.Begin(ctx)
		if err != nil {
			t.Fatal(err)
		}
		defer tx.Rollback(ctx)
		mustExecTx := func(sql string, args ...any) error { _, err := tx.Exec(ctx, sql, args...); return err }
		if err := mustExecTx(`SET LOCAL session_replication_role=replica`); err != nil {
			t.Fatal(err)
		}
		if err := mustExecTx(`INSERT INTO cname_carrier_line_records(site_id,line_scope,desired_digest,next_attempt_at,updated_at)
			VALUES($1,$2,$3,now(),now())`, siteID, scope, zeros); err != nil {
			return err
		}
		return tx.Commit(ctx)
	}
	v2Areas := []string{"asia", "oceania", "northern_europe", "eastern_europe", "middle_africa", "caribbean", "polynesia"}
	v2Scopes := []string{"oceania", "northern_europe", "northern_america", "australia_new_zealand"}
	check := func(stage string, v2 bool) {
		t.Helper()
		for _, area := range v2Areas {
			if err := setArea(area); (err == nil) != v2 {
				t.Fatalf("%s: area %s accepted = %v", stage, area, err == nil)
			}
		}
		for _, area := range []string{"global", "europe", "east_asia", ""} {
			if err := setArea(area); err != nil {
				t.Fatalf("%s: v1 area %q refused: %v", stage, area, err)
			}
		}
		for _, bad := range []string{"antarctica", "Asia", "east-asia"} {
			if setArea(bad) == nil {
				t.Fatalf("%s: area %q accepted", stage, bad)
			}
		}
		for _, scope := range v2Scopes {
			if err := insertScope(scope); (err == nil) != v2 {
				t.Fatalf("%s: scope %s accepted = %v", stage, scope, err == nil)
			}
			mustExec(t, pool, `DELETE FROM cname_carrier_line_records WHERE site_id=$1`, siteID)
		}
		for _, scope := range []string{"asia", "europe", "overseas", "telecom", "广东:telecom"} {
			if err := insertScope(scope); err != nil {
				t.Fatalf("%s: scope %s refused: %v", stage, scope, err)
			}
			mustExec(t, pool, `DELETE FROM cname_carrier_line_records WHERE site_id=$1`, siteID)
		}
		for _, bad := range []string{"global", "antarctica", "oceania:telecom"} {
			if insertScope(bad) == nil {
				t.Fatalf("%s: scope %q accepted", stage, bad)
			}
		}
	}
	check("679", false)
	for _, step := range []struct {
		direction string
		v2        bool
	}{{"up", true}, {"down", false}, {"up", true}} {
		if err := migrateVersionIsolated(ctx, pool, step.direction, version); err != nil {
			t.Fatalf("%s %d: %v", step.direction, version, err)
		}
		check("after "+step.direction, step.v2)
	}
	// down refuses a region on a v2 code, then a line record on a v2 scope.
	refused := func(what string) {
		t.Helper()
		err := migrateVersionIsolated(ctx, pool, "down", version)
		var pgErr *pgconn.PgError
		if !errors.As(err, &pgErr) || pgErr.Code != "P6802" {
			t.Fatalf("down with %s = %v", what, err)
		}
	}
	if err := setArea("caribbean"); err != nil {
		t.Fatal(err)
	}
	refused("a caribbean region")
	if err := setArea("north_america"); err != nil {
		t.Fatal(err)
	}
	if err := insertScope("polynesia"); err != nil {
		t.Fatal(err)
	}
	refused("a polynesia line record")
	mustExec(t, pool, `DELETE FROM cname_carrier_line_records WHERE site_id=$1`, siteID)
	if err := insertScope("africa"); err != nil { // a v1 scope does not block down
		t.Fatal(err)
	}
	if err := migrateVersionIsolated(ctx, pool, "down", version); err != nil {
		t.Fatalf("down after retiring v2 codes: %v", err)
	}
	if setArea("asia") == nil {
		t.Fatal("down kept the v2 area codes")
	}
}
