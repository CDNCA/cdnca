//go:build integration

package migrations_test

import (
	"bytes"
	"crypto/sha256"
	"encoding/json"
	"testing"

	"github.com/cdnca/cdnca/services/control-api/internal/systemconfig"
	"github.com/google/uuid"
	"github.com/jackc/pgx/v5"
)

// TestSystemConfigurationTrimRegionOverrides497: a revision stored before 497
// with build-time region overrides (resources black_ip_limit, defaults HSTS)
// and a gzip one is rewritten to keep only the gzip switch and types; the
// result is a valid snapshot the control plane decodes byte-for-byte, its
// hash and the preflight hash follow; a revision without such overrides is
// untouched; down keeps the trimmed data; up, down, up.
func TestSystemConfigurationTrimRegionOverrides497(t *testing.T) {
	// Placeholder numbers: keep equal to migration497Version and
	// migration497PreviousVersion in system_configuration_trim_region_overrides_497_contract_test.go.
	const version, previous = 497, 496
	pool := migrationPoolAt(t, previous)
	ctx := t.Context()

	configuration := systemconfig.ProjectBootstrapConfiguration()
	_, clean, _, err := systemconfig.CanonicalSnapshot(configuration)
	if err != nil {
		t.Fatal(err)
	}
	// What a pre-497 control plane could store (the database accepted these).
	var legacy []byte
	if err := pool.QueryRow(ctx, `SELECT system_configuration_render_canonical_snapshot(jsonb_set(jsonb_set(
		convert_from($1,'UTF8')::jsonb,
		'{configuration,resources,overrides}',
		'[{"id":"resource01","scope":"region","scope_id":"12","values":{"site":{"black_ip_limit":20000}}}]'),
		'{configuration,defaults,overrides}',
		jsonb_build_array(
			'{"id":"default01","scope":"region","scope_id":"12","values":{"website":{"hsts_enabled":true}}}'::jsonb,
			jsonb_build_object('id','default02','scope','region','scope_id','13','values',jsonb_build_object(
				'website',jsonb_build_object('hsts_enabled',true,'other',
					convert_from($1,'UTF8')::jsonb->'configuration'->'defaults'->'website'->'other' ||
					'{"gzip_enabled":true,"gzip_types":["text/css"],"load_balancing":"least_conn","websocket_enabled":false}'::jsonb))))))`,
		clean).Scan(&legacy); err != nil {
		t.Fatal(err)
	}
	valid := func(snapshot []byte) bool {
		t.Helper()
		var ok bool
		if err := pool.QueryRow(ctx, `SELECT system_configuration_snapshot_is_valid($1)`, snapshot).Scan(&ok); err != nil {
			t.Fatal(err)
		}
		return ok
	}
	if !valid(legacy) || !valid(clean) {
		t.Fatalf("496 refuses the fixture snapshots: %s", legacy)
	}

	scopeID, userID := uuid.New(), uuid.New()
	legacyHash, cleanHash := sha256.Sum256(legacy), sha256.Sum256(clean)
	if err := pgx.BeginFunc(ctx, pool, func(tx pgx.Tx) error {
		if _, err := tx.Exec(ctx, `SET LOCAL session_replication_role = replica`); err != nil {
			return err
		}
		if _, err := tx.Exec(ctx, `INSERT INTO system_configuration_streams(platform_scope_id,head_revision,
			active_revision,created_at,updated_at) VALUES($1,2,NULL,now(),now())`, scopeID); err != nil {
			return err
		}
		if _, err := tx.Exec(ctx, `INSERT INTO system_configuration_revisions(platform_scope_id,revision,status,
			canonical_schema,canonical_snapshot,snapshot_sha256,created_by_user_id,created_by_scope_id,created_at,state_changed_at)
			VALUES($1,1,'validated','cdnca.system-configuration/v2',$3,$4,$2,$1,now(),now()),
			      ($1,2,'draft','cdnca.system-configuration/v2',$5,$6,$2,$1,now(),now())`,
			scopeID, userID, legacy, legacyHash[:], clean, cleanHash[:]); err != nil {
			return err
		}
		_, err := tx.Exec(ctx, `INSERT INTO system_configuration_preflights(platform_scope_id,revision,preflight_sequence,
			snapshot_sha256,passed,checks,performed_by_user_id,performed_by_scope_id,performed_at,expires_at)
			VALUES($1,1,1,$3,true,'[{},{},{},{},{}]',$2,$1,now(),now()+interval '15 minutes')`,
			scopeID, userID, legacyHash[:])
		return err
	}); err != nil {
		t.Fatal(err)
	}

	for _, step := range []string{"up", "down", "up"} {
		if err := migrateVersionIsolated(ctx, pool, step, version); err != nil {
			t.Fatalf("%s %d: %v", step, version, err)
		}
	}

	read := func(revision int) ([]byte, []byte) {
		t.Helper()
		var snapshot, hash []byte
		if err := pool.QueryRow(ctx, `SELECT canonical_snapshot,snapshot_sha256 FROM system_configuration_revisions
			WHERE platform_scope_id=$1 AND revision=$2`, scopeID, revision).Scan(&snapshot, &hash); err != nil {
			t.Fatal(err)
		}
		return snapshot, hash
	}
	trimmed, trimmedHash := read(1)
	if sum := sha256.Sum256(trimmed); !bytes.Equal(trimmedHash, sum[:]) || !valid(trimmed) {
		t.Fatalf("trimmed revision hash/validity: %s", trimmed)
	}
	var envelope struct {
		Configuration systemconfig.Configuration `json:"configuration"`
	}
	if err := json.Unmarshal(trimmed, &envelope); err != nil {
		t.Fatal(err)
	}
	_, reencoded, _, err := systemconfig.CanonicalSnapshot(envelope.Configuration)
	if err != nil || !bytes.Equal(reencoded, trimmed) {
		t.Fatalf("control plane does not read the trimmed revision back (err=%v):\n%s\n%s", err, trimmed, reencoded)
	}
	got := envelope.Configuration
	global := configuration.Defaults.Website.Other
	if len(got.Resources.Overrides) != 0 || len(got.Defaults.Overrides) != 1 {
		t.Fatalf("overrides after trim: resources=%#v defaults=%#v", got.Resources.Overrides, got.Defaults.Overrides)
	}
	kept := got.Defaults.Overrides[0]
	if kept.ID != "default02" || kept.ScopeID != "13" || kept.Values.Stream != nil || kept.Values.Certificate != nil ||
		kept.Values.Website.HSTSEnabled != nil || kept.Values.Website.Other == nil ||
		!kept.Values.Website.Other.GzipEnabled || len(kept.Values.Website.Other.GzipTypes) != 1 ||
		kept.Values.Website.Other.LoadBalancing != global.LoadBalancing ||
		kept.Values.Website.Other.WebsocketEnabled != global.WebsocketEnabled {
		t.Fatalf("kept override: %#v", kept.Values.Website)
	}
	var preflightHash []byte
	if err := pool.QueryRow(ctx, `SELECT snapshot_sha256 FROM system_configuration_preflights
		WHERE platform_scope_id=$1 AND revision=1`, scopeID).Scan(&preflightHash); err != nil {
		t.Fatal(err)
	}
	if !bytes.Equal(preflightHash, trimmedHash) {
		t.Fatal("preflight hash not moved to the trimmed snapshot")
	}
	if untouched, hash := read(2); !bytes.Equal(untouched, clean) || !bytes.Equal(hash, cleanHash[:]) {
		t.Fatal("revision without region overrides was rewritten")
	}
	// The immutability triggers are back on.
	if _, err := pool.Exec(ctx, `UPDATE system_configuration_revisions SET canonical_snapshot=$2
		WHERE platform_scope_id=$1 AND revision=2`, scopeID, legacy); err == nil {
		t.Fatal("revision protection trigger left disabled")
	}
}
