//go:build integration

package migrations_test

import (
	"context"
	"crypto/sha256"
	"errors"
	"fmt"
	"io/fs"
	"os"
	"regexp"
	"strings"
	"testing"
	"time"

	"github.com/cdnca/cdnca/services/control-api/internal/database/databasetest"
	controlmigrations "github.com/cdnca/cdnca/services/control-api/migrations"
	"github.com/google/uuid"
	"github.com/jackc/pgx/v5"
	"github.com/jackc/pgx/v5/pgconn"
	"github.com/jackc/pgx/v5/pgxpool"
)

func TestActiveConfigIdentity087RoundTrip(t *testing.T) {
	pool := packageCommerceRBAC079Pool(t, 86)
	assertActiveIdentity087Columns(t, pool, false)
	if err := migrateVersionIsolated(t.Context(), pool, "up", 87); err != nil {
		t.Fatal(err)
	}
	assertPackageCommerceRBAC079Ledger(t, pool, 87)
	assertActiveIdentity087Columns(t, pool, true)
	if err := migrateVersionIsolated(t.Context(), pool, "down", 87); err != nil {
		t.Fatal(err)
	}
	assertPackageCommerceRBAC079Ledger(t, pool, 86)
	assertActiveIdentity087Columns(t, pool, false)
	if err := migrateVersionIsolated(t.Context(), pool, "up", 87); err != nil {
		t.Fatal(err)
	}
	assertPackageCommerceRBAC079Ledger(t, pool, 87)
}

func TestActiveConfigIdentity087RequiresExactVerified086Head(t *testing.T) {
	script, err := fs.ReadFile(controlmigrations.FS, "087_active_config_identity_control.up.sql")
	if err != nil {
		t.Fatal(err)
	}
	t.Run("missing 086", func(t *testing.T) {
		pool := packageCommerceRBAC079Pool(t, 85)
		_, err := pool.Exec(t.Context(), string(script))
		assertActiveIdentityCode087(t, err, "P8700")
		assertActiveIdentity087Columns(t, pool, false)
	})
	t.Run("tampered 086", func(t *testing.T) {
		pool := packageCommerceRBAC079Pool(t, 86)
		if _, err := pool.Exec(t.Context(), `UPDATE schema_migrations SET checksum_sha256=$1 WHERE version=86`,
			"aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa"); err != nil {
			t.Fatal(err)
		}
		_, err := pool.Exec(t.Context(), string(script))
		assertActiveIdentityCode087(t, err, "P8700")
		assertActiveIdentity087Columns(t, pool, false)
	})
}

func TestActiveConfigIdentity087PinsAuthoritative086Files(t *testing.T) {
	tests := []struct {
		name string
		read func() ([]byte, error)
		want string
	}{
		{
			name: "up",
			read: func() ([]byte, error) {
				return fs.ReadFile(controlmigrations.FS, "086_site_l4_automatic_publication.up.sql")
			},
			want: "35ba7924b2b90a0efbd4c8d2fc3082c2be040595f4f7daa0874b54fb57dcf207",
		},
		{
			name: "down",
			read: func() ([]byte, error) {
				return fs.ReadFile(controlmigrations.FS, "086_site_l4_automatic_publication.down.sql")
			},
			want: "0f5e8eaaf08e8a05912d60b69a74cd46e9ed75057546827c26e853c827e15b0c",
		},
		{
			name: "integration fixture",
			read: func() ([]byte, error) {
				return os.ReadFile("site_l4_automatic_publication_086_integration_test.go")
			},
			want: "411f20cc04d28e64787f5f8d6ace222234a79201b57843c8b36575bd3e939aa6",
		},
	}
	for _, test := range tests {
		t.Run(test.name, func(t *testing.T) {
			value, err := test.read()
			if err != nil {
				t.Fatal(err)
			}
			if got := fmt.Sprintf("%x", sha256.Sum256(value)); got != test.want {
				t.Fatalf("086 %s sha256 = %s, want %s", test.name, got, test.want)
			}
		})
	}
}

func TestActiveConfigIdentity087IndependentExact086Fixture(t *testing.T) {
	t.Run("round trip", func(t *testing.T) {
		pool := exactActiveIdentity086Pool(t)
		assertActiveIdentity087Columns(t, pool, false)
		if err := applyExactActiveIdentity087(t.Context(), pool); err != nil {
			t.Fatal(err)
		}
		assertActiveIdentity087Columns(t, pool, true)
		if err := rollbackExactActiveIdentity087(t.Context(), pool); err != nil {
			t.Fatal(err)
		}
		assertActiveIdentity087Columns(t, pool, false)
		if err := applyExactActiveIdentity087(t.Context(), pool); err != nil {
			t.Fatal(err)
		}
		assertActiveIdentity087Columns(t, pool, true)
	})

	t.Run("wrong exact 086 head is P8700", func(t *testing.T) {
		pool := exactActiveIdentity086Pool(t)
		if _, err := pool.Exec(t.Context(), `UPDATE schema_migrations SET checksum_sha256=repeat('a',64)
			WHERE version=86`); err != nil {
			t.Fatal(err)
		}
		assertActiveIdentityCode087(t, applyExactActiveIdentity087(t.Context(), pool), "P8700")
		assertActiveIdentity087Columns(t, pool, false)
	})

	t.Run("direct invalid tuple is P8702", func(t *testing.T) {
		pool := exactActiveIdentity086Pool(t)
		if err := applyExactActiveIdentity087(t.Context(), pool); err != nil {
			t.Fatal(err)
		}
		fixture := seedActiveIdentity087(t, pool)
		_, err := pool.Exec(t.Context(), `UPDATE node_config_state SET current_config_identity_schema=1,
			current_config_artifact_sha256=$2 WHERE node_id=$1`, fixture.nodeID, make([]byte, 32))
		assertActiveIdentityCode087(t, err, "P8702")
	})

	t.Run("down fact is P8701", func(t *testing.T) {
		pool := exactActiveIdentity086Pool(t)
		if err := applyExactActiveIdentity087(t.Context(), pool); err != nil {
			t.Fatal(err)
		}
		fixture := seedActiveIdentity087(t, pool)
		if _, err := pool.Exec(t.Context(), `UPDATE node_presence SET active_config_identity_api_version=1
			WHERE node_id=$1`, fixture.nodeID); err != nil {
			t.Fatal(err)
		}
		assertActiveIdentityCode087(t, rollbackExactActiveIdentity087(t.Context(), pool), "P8701")
		assertActiveIdentity087Columns(t, pool, true)
	})

	t.Run("down serializes concurrent fact", func(t *testing.T) {
		pool := exactActiveIdentity086Pool(t)
		if err := applyExactActiveIdentity087(t.Context(), pool); err != nil {
			t.Fatal(err)
		}
		fixture := seedActiveIdentity087(t, pool)
		tx, err := pool.Begin(t.Context())
		if err != nil {
			t.Fatal(err)
		}
		defer func() { _ = tx.Rollback(context.Background()) }()
		if _, err := tx.Exec(t.Context(), `UPDATE node_presence SET active_config_identity_api_version=1
			WHERE node_id=$1`, fixture.nodeID); err != nil {
			t.Fatal(err)
		}
		downResult := make(chan error, 1)
		go func() { downResult <- rollbackExactActiveIdentity087(context.Background(), pool) }()
		select {
		case err := <-downResult:
			t.Fatalf("independent 087 down did not wait for concurrent fact: %v", err)
		case <-time.After(100 * time.Millisecond):
		}
		if err := tx.Commit(t.Context()); err != nil {
			t.Fatal(err)
		}
		assertActiveIdentityCode087(t, <-downResult, "P8701")
		assertActiveIdentity087Columns(t, pool, true)
	})
}

func TestActiveConfigIdentity087DirectSQLGuards(t *testing.T) {
	pool := packageCommerceRBAC079Pool(t, 87)
	fixture := seedActiveIdentity087(t, pool)
	if _, err := pool.Exec(t.Context(), `UPDATE node_config_state SET
		current_config_identity_schema=1,current_config_artifact_sha256=$2 WHERE node_id=$1`,
		fixture.nodeID, fixture.digest); err != nil {
		t.Fatal(err)
	}
	_, err := pool.Exec(t.Context(), `UPDATE node_config_state SET current_config_artifact_sha256=$2 WHERE node_id=$1`,
		fixture.nodeID, make([]byte, 32))
	assertActiveIdentityCode087(t, err, "P8702")

	_, err = pool.Exec(t.Context(), `UPDATE node_presence SET active_config_identity_api_version=1,
		current_config_identity_schema=1,current_config_artifact_sha256=$2 WHERE node_id=$1`,
		fixture.nodeID, make([]byte, 32))
	assertActiveIdentityCode087(t, err, "P8702")

	_, err = pool.Exec(t.Context(), `UPDATE node_presence SET active_deployments=jsonb_build_array(jsonb_build_object(
		'deployment_id',$2::text,'attempt',2,'config_version_id',$3::text,'state','healthy',
		'observed_active_config_identity',jsonb_build_object('schema',1,'config_version_id',$3::text,
		'artifact_sha256',encode($4::bytea,'hex')))) WHERE node_id=$1`,
		fixture.nodeID, fixture.deploymentID, fixture.configID, fixture.digest)
	assertActiveIdentityCode087(t, err, "P8702")

	_, err = pool.Exec(t.Context(), `INSERT INTO deployment_status_events(
		id,deployment_id,event_id,attempt,transition_sequence,state,payload,payload_sha256,
		occurred_at,received_at,active_config_identity_api_version,active_config_identity_schema,
		active_config_version_id,active_config_artifact_sha256
	) VALUES($1,$2,$3,1,1,'healthy',$4,$5,clock_timestamp(),clock_timestamp(),1,1,$6,$7)`,
		uuid.New(), fixture.deploymentID, uuid.New(), []byte("status"), sha256Bytes087([]byte("status")),
		fixture.configID, make([]byte, 32))
	assertActiveIdentityCode087(t, err, "P8702")

	t.Run("observed identity exact keys", func(t *testing.T) {
		pool := packageCommerceRBAC079Pool(t, 87)
		fixture := seedActiveIdentity087(t, pool)
		_, err := pool.Exec(t.Context(), `UPDATE node_presence SET active_config_identity_api_version=1,
			active_deployments=jsonb_build_array(jsonb_build_object(
			'deployment_id',$2::text,'attempt',1,'config_version_id',$3::text,'state','healthy',
			'observed_active_config_identity',jsonb_build_object('schema',1,'config_version_id',$3::text,
			'artifact_sha256',encode($4::bytea,'hex'),'unexpected',true))) WHERE node_id=$1`,
			fixture.nodeID, fixture.deploymentID, fixture.configID, fixture.digest)
		assertActiveIdentityCode087(t, err, "P8702")
	})

	t.Run("status action and state pair", func(t *testing.T) {
		pool := packageCommerceRBAC079Pool(t, 87)
		fixture := seedActiveIdentity087(t, pool)
		payload := []byte("cross-paired status")
		_, err := pool.Exec(t.Context(), `INSERT INTO deployment_status_events(
			id,deployment_id,event_id,attempt,transition_sequence,state,payload,payload_sha256,
			occurred_at,received_at,active_config_identity_api_version,active_config_identity_schema,
			active_config_version_id,active_config_artifact_sha256
		) VALUES($1,$2,$3,1,2,'reverted',$4,$5,clock_timestamp(),clock_timestamp(),1,1,$6,$7)`,
			uuid.New(), fixture.deploymentID, uuid.New(), payload, sha256Bytes087(payload), fixture.configID, fixture.digest)
		assertActiveIdentityCode087(t, err, "P8702")
	})

	t.Run("artifact digest is signed wire digest", func(t *testing.T) {
		pool := packageCommerceRBAC079Pool(t, 87)
		fixture := seedActiveIdentity087(t, pool)
		forgedConfigID, forgedArtifactID := uuid.New(), uuid.New()
		forgedWire, forgedDigest := []byte("087 forged artifact wire"), sha256Bytes087([]byte("not the artifact wire"))
		keyID := "active-identity-087-forged-" + forgedConfigID.String()
		if _, err := pool.Exec(t.Context(), `INSERT INTO config_versions(id,configuration_scope_id,canonical_snapshot,
			canonical_snapshot_sha256,generator_name,generator_version,status,idempotency_key,request_digest,created_at)
			SELECT $1,scope_id,$2,$3,'identity087','1','building',$4,$5,clock_timestamp()
			FROM nodes WHERE id=$6`, forgedConfigID, []byte("forged manifest"), sha256Bytes087([]byte("forged manifest")),
			forgedConfigID.String(), make([]byte, 32), fixture.nodeID); err != nil {
			t.Fatal(err)
		}
		if _, err := pool.Exec(t.Context(), `INSERT INTO artifact_signing_keys(id,algorithm,public_key,created_at)
			VALUES($1,'ed25519',$2,clock_timestamp())`, keyID, make([]byte, 32)); err != nil {
			t.Fatal(err)
		}
		if _, err := pool.Exec(t.Context(), `INSERT INTO configuration_artifacts(id,config_version_id,ordinal,kind,
			wire_bytes,size_bytes,sha256,signature,signing_key_id,signature_algorithm,compression,media_type,
			encryption_algorithm,created_at) VALUES($1,$2,1,'configuration',$3,$4,$5,$6,$7,'ed25519','none',
			'application/octet-stream','none',clock_timestamp())`, forgedArtifactID, forgedConfigID, forgedWire,
			len(forgedWire), forgedDigest, make([]byte, 64), keyID); err != nil {
			t.Fatal(err)
		}
		if _, err := pool.Exec(t.Context(), `UPDATE config_versions SET status='validating' WHERE id=$1`, forgedConfigID); err != nil {
			t.Fatal(err)
		}
		if _, err := pool.Exec(t.Context(), `UPDATE config_versions SET status='releasable',published_at=clock_timestamp()
			WHERE id=$1`, forgedConfigID); err != nil {
			t.Fatal(err)
		}
		if _, err := pool.Exec(t.Context(), `UPDATE node_config_state SET current_config_version_id=$2,
			current_config_identity_schema=NULL,current_config_artifact_sha256=NULL WHERE node_id=$1`,
			fixture.nodeID, forgedConfigID); err != nil {
			t.Fatal(err)
		}
		_, err := pool.Exec(t.Context(), `UPDATE node_config_state SET current_config_identity_schema=1,
			current_config_artifact_sha256=$2 WHERE node_id=$1`, fixture.nodeID, forgedDigest)
		assertActiveIdentityCode087(t, err, "P8702")
	})
}

func TestActiveConfigIdentity087ObservedDeploymentBindingGuards(t *testing.T) {
	pool := packageCommerceRBAC079Pool(t, 87)
	fixture := seedActiveIdentity087(t, pool)
	identity := fmt.Sprintf(`{"schema":1,"config_version_id":%q,"artifact_sha256":%q}`,
		fixture.configID.String(), fmt.Sprintf("%x", fixture.digest))
	deployment := func(deploymentID, state string, attempt int) string {
		return fmt.Sprintf(`[{"deployment_id":%s,"attempt":%d,"config_version_id":%q,"state":%q,"observed_active_config_identity":%s}]`,
			deploymentID, attempt, fixture.configID.String(), state, identity)
	}
	project := func(payload string) error {
		_, err := pool.Exec(t.Context(), `UPDATE node_presence SET active_config_identity_api_version=1,
			active_deployments=$2::jsonb WHERE node_id=$1`, fixture.nodeID, payload)
		return err
	}
	quotedDeploymentID := fmt.Sprintf("%q", fixture.deploymentID.String())
	invalid := []struct {
		name    string
		payload string
	}{
		{name: "missing deployment ID", payload: fmt.Sprintf(`[{"attempt":1,"config_version_id":%q,"state":"healthy","observed_active_config_identity":%s}]`, fixture.configID.String(), identity)},
		{name: "null deployment ID", payload: deployment("null", "healthy", 1)},
		{name: "empty deployment ID", payload: deployment(`""`, "healthy", 1)},
		{name: "malformed deployment ID", payload: deployment(`"not-a-uuid"`, "healthy", 1)},
		{name: "wrong attempt", payload: deployment(quotedDeploymentID, "healthy", 2)},
		{name: "nonterminal state", payload: deployment(quotedDeploymentID, "delivered", 1)},
		{name: "apply reverted", payload: deployment(quotedDeploymentID, "reverted", 1)},
	}
	for _, test := range invalid {
		t.Run(test.name, func(t *testing.T) {
			assertActiveIdentityCode087(t, project(test.payload), "P8702")
		})
	}

	if err := project(deployment(quotedDeploymentID, "healthy", 1)); err != nil {
		t.Fatalf("exact apply healthy observed identity rejected: %v", err)
	}
	if _, err := pool.Exec(t.Context(), `UPDATE node_presence SET active_deployments='[]'::jsonb WHERE node_id=$1`, fixture.nodeID); err != nil {
		t.Fatal(err)
	}
	rollbackID := seedObservedIdentityDeployment087(t, pool, fixture, "rollback", true)
	quotedRollbackID := fmt.Sprintf("%q", rollbackID.String())
	assertActiveIdentityCode087(t, project(deployment(quotedRollbackID, "healthy", 1)), "P8702")
	if err := project(deployment(quotedRollbackID, "reverted", 1)); err != nil {
		t.Fatalf("exact rollback reverted observed identity rejected: %v", err)
	}
	if _, err := pool.Exec(t.Context(), `UPDATE node_presence SET active_deployments='[]'::jsonb WHERE node_id=$1`, fixture.nodeID); err != nil {
		t.Fatal(err)
	}
	corruptCommandID := seedObservedIdentityDeployment087(t, pool, fixture, "apply", false)
	assertActiveIdentityCode087(t, project(deployment(fmt.Sprintf("%q", corruptCommandID.String()), "healthy", 1)), "P8702")
}

func TestActiveConfigIdentity087ObservedUUIDPolicy(t *testing.T) {
	pool := packageCommerceRBAC079Pool(t, 87)
	base := seedActiveIdentity087(t, pool)
	project := func(pool *pgxpool.Pool, fixture activeIdentityFixture087,
		deploymentID, configID, identityConfigID string,
	) error {
		payload := fmt.Sprintf(`[{"deployment_id":%q,"attempt":1,"config_version_id":%q,"state":"healthy",`+
			`"observed_active_config_identity":{"schema":1,"config_version_id":%q,"artifact_sha256":%q}}]`,
			deploymentID, configID, identityConfigID, fmt.Sprintf("%x", fixture.digest))
		_, err := pool.Exec(t.Context(), `UPDATE node_presence SET active_config_identity_api_version=1,
			active_deployments=$2::jsonb WHERE node_id=$1`, fixture.nodeID, payload)
		return err
	}
	for version := 1; version <= 8; version++ {
		t.Run(fmt.Sprintf("version_%d_all_identity_UUID_fields", version), func(t *testing.T) {
			candidate := seedActiveIdentityObservedUUID087(t, pool, base, version)
			if err := project(pool, candidate, candidate.deploymentID.String(), candidate.configID.String(), candidate.configID.String()); err != nil {
				t.Fatalf("canonical UUIDv%d observed identity rejected: %v", version, err)
			}
			if _, err := pool.Exec(t.Context(), `UPDATE node_presence SET active_deployments='[]'::jsonb WHERE node_id=$1`, candidate.nodeID); err != nil {
				t.Fatal(err)
			}
		})
	}

	invalid := []struct {
		name   string
		mutate func(uuid.UUID) string
	}{
		{name: "uppercase", mutate: func(value uuid.UUID) string {
			return strings.ToUpper(value.String())
		}},
		{name: "nil", mutate: func(uuid.UUID) string {
			return uuid.Nil.String()
		}},
		{name: "non RFC variant", mutate: func(value uuid.UUID) string {
			value[8] = value[8]&0x3f | 0xc0
			return value.String()
		}},
		{name: "reserved version", mutate: func(value uuid.UUID) string {
			value[6] = value[6]&0x0f | 0x90
			return value.String()
		}},
		{name: "whitespace", mutate: func(value uuid.UUID) string {
			return " " + value.String()
		}},
		{name: "partial", mutate: func(value uuid.UUID) string {
			return value.String()[:35]
		}},
		{name: "malformed layout", mutate: func(value uuid.UUID) string {
			return strings.ReplaceAll(value.String(), "-", "")
		}},
	}
	fields := []struct {
		name  string
		index int
	}{
		{name: "deployment_id", index: 0},
		{name: "config_version_id", index: 1},
		{name: "identity_config_version_id", index: 2},
	}
	for _, field := range fields {
		t.Run(field.name, func(t *testing.T) {
			boundPool := packageCommerceRBAC079Pool(t, 87)
			boundBase := seedActiveIdentity087(t, boundPool)
			for caseIndex, test := range invalid {
				t.Run(test.name, func(t *testing.T) {
					suffix := 100 + field.index*100 + caseIndex*10
					configID := activeIdentityObservedUUID087(7, suffix+1)
					deploymentID := activeIdentityObservedUUID087(7, suffix+2)
					fixture := seedActiveIdentityObservedUUIDBinding087(t, boundPool, boundBase,
						configID, activeIdentityObservedUUID087(7, suffix+3),
						activeIdentityObservedUUID087(7, suffix+4), deploymentID)
					candidate := [3]string{fixture.deploymentID.String(), fixture.configID.String(), fixture.configID.String()}
					targetID := fixture.configID
					if field.index == 0 {
						targetID = fixture.deploymentID
					}
					candidate[field.index] = test.mutate(targetID)
					assertActiveIdentityObservedUUIDCandidateBound087(t, fixture, field.index, candidate[field.index])
					assertActiveIdentityObservedUUIDNonTargets087(t, fixture, field.index, candidate)
					assertActiveIdentityCode087(t,
						project(boundPool, fixture, candidate[0], candidate[1], candidate[2]), "P8702")
				})
			}
		})
	}
}

func assertActiveIdentityObservedUUIDCandidateBound087(t *testing.T, fixture activeIdentityFixture087,
	field int, value string,
) {
	t.Helper()
	candidate, err := uuid.Parse(value)
	if err != nil || !activeIdentityObservedUUIDCanonical087.MatchString(candidate.String()) {
		return
	}
	want := fixture.configID
	if field == 0 {
		want = fixture.deploymentID
	}
	if candidate != want {
		t.Fatalf("invalid UUID candidate %s is not bound to field %d resource %s", candidate, field, want)
	}
}

func assertActiveIdentityObservedUUIDNonTargets087(t *testing.T, fixture activeIdentityFixture087,
	target int, candidate [3]string,
) {
	t.Helper()
	want := [3]string{fixture.deploymentID.String(), fixture.configID.String(), fixture.configID.String()}
	for field := range candidate {
		if field == target {
			continue
		}
		if candidate[field] != want[field] || !activeIdentityObservedUUIDCanonical087.MatchString(candidate[field]) {
			t.Fatalf("non-target UUID field %d = %q, want canonical bound value %q", field, candidate[field], want[field])
		}
	}
}

var activeIdentityObservedUUIDCanonical087 = regexp.MustCompile(
	`^[0-9a-f]{8}-[0-9a-f]{4}-[1-8][0-9a-f]{3}-[89ab][0-9a-f]{3}-[0-9a-f]{12}$`,
)

func TestActiveConfigIdentity087DownGuardsAllFacts(t *testing.T) {
	tests := []struct {
		name string
		seed func(*testing.T, *pgxpool.Pool, activeIdentityFixture087)
	}{
		{name: "presence capability", seed: func(t *testing.T, pool *pgxpool.Pool, fixture activeIdentityFixture087) {
			_, err := pool.Exec(t.Context(), `UPDATE node_presence SET active_config_identity_api_version=1 WHERE node_id=$1`, fixture.nodeID)
			if err != nil {
				t.Fatal(err)
			}
		}},
		{name: "presence observed JSON", seed: func(t *testing.T, pool *pgxpool.Pool, fixture activeIdentityFixture087) {
			_, err := pool.Exec(t.Context(), `UPDATE node_presence SET active_config_identity_api_version=1,
				active_deployments=jsonb_build_array(jsonb_build_object('deployment_id',$2::text,'attempt',1,
				'config_version_id',$3::text,'state','healthy','observed_active_config_identity',jsonb_build_object(
				'schema',1,'config_version_id',$3::text,'artifact_sha256',encode($4::bytea,'hex')))) WHERE node_id=$1`,
				fixture.nodeID, fixture.deploymentID, fixture.configID, fixture.digest)
			if err != nil {
				t.Fatal(err)
			}
		}},
		{name: "node state identity", seed: func(t *testing.T, pool *pgxpool.Pool, fixture activeIdentityFixture087) {
			_, err := pool.Exec(t.Context(), `UPDATE node_config_state SET current_config_identity_schema=1,
				current_config_artifact_sha256=$2 WHERE node_id=$1`, fixture.nodeID, fixture.digest)
			if err != nil {
				t.Fatal(err)
			}
		}},
		{name: "status event identity", seed: func(t *testing.T, pool *pgxpool.Pool, fixture activeIdentityFixture087) {
			payload := []byte("status identity")
			_, err := pool.Exec(t.Context(), `INSERT INTO deployment_status_events(
				id,deployment_id,event_id,attempt,transition_sequence,state,payload,payload_sha256,
				occurred_at,received_at,active_config_identity_api_version,active_config_identity_schema,
				active_config_version_id,active_config_artifact_sha256
			) VALUES($1,$2,$3,1,1,'healthy',$4,$5,clock_timestamp(),clock_timestamp(),1,1,$6,$7)`,
				uuid.New(), fixture.deploymentID, uuid.New(), payload, sha256Bytes087(payload), fixture.configID, fixture.digest)
			if err != nil {
				t.Fatal(err)
			}
		}},
	}
	for _, test := range tests {
		t.Run(test.name, func(t *testing.T) {
			pool := packageCommerceRBAC079Pool(t, 87)
			fixture := seedActiveIdentity087(t, pool)
			test.seed(t, pool, fixture)
			err := migrateVersionIsolated(t.Context(), pool, "down", 87)
			assertActiveIdentityCode087(t, err, "P8701")
			assertPackageCommerceRBAC079Ledger(t, pool, 87)
			assertActiveIdentity087Columns(t, pool, true)
		})
	}
}

func TestActiveConfigIdentity087DownSerializesConcurrentFact(t *testing.T) {
	pool := packageCommerceRBAC079Pool(t, 87)
	fixture := seedActiveIdentity087(t, pool)
	tx, err := pool.Begin(t.Context())
	if err != nil {
		t.Fatal(err)
	}
	defer func() { _ = tx.Rollback(t.Context()) }()
	if _, err := tx.Exec(t.Context(), `UPDATE node_presence
		SET active_config_identity_api_version=1 WHERE node_id=$1`, fixture.nodeID); err != nil {
		t.Fatal(err)
	}
	downResult := make(chan error, 1)
	go func() {
		downResult <- migrateVersionIsolated(t.Context(), pool, "down", 87)
	}()
	select {
	case err := <-downResult:
		t.Fatalf("087 down did not wait for concurrent fact transaction: %v", err)
	case <-time.After(100 * time.Millisecond):
	}
	if err := tx.Commit(t.Context()); err != nil {
		t.Fatal(err)
	}
	assertActiveIdentityCode087(t, <-downResult, "P8701")
	assertPackageCommerceRBAC079Ledger(t, pool, 87)
	assertActiveIdentity087Columns(t, pool, true)
}

type activeIdentityFixture087 struct {
	nodeID, configID, artifactID, deploymentID uuid.UUID
	digest                                     []byte
}

func seedActiveIdentity087(t *testing.T, pool *pgxpool.Pool) activeIdentityFixture087 {
	t.Helper()
	tenantID, scopeID, userID, nodeID := uuid.New(), uuid.New(), uuid.New(), uuid.New()
	configID, artifactID, rolloutID, deploymentID := uuid.New(), uuid.New(), uuid.New(), uuid.New()
	now, deadline := time.Now().UTC().Truncate(time.Microsecond), time.Now().UTC().Add(time.Hour)
	wire := []byte("087 signed configuration wire")
	digest := sha256Bytes087(wire)
	command := []byte("087 command")
	commandDigest := sha256Bytes087(command)
	keyID := "active-identity-087-" + configID.String()
	err := pgx.BeginFunc(t.Context(), pool, func(tx pgx.Tx) error {
		statements := []struct {
			query string
			args  []any
		}{
			{`INSERT INTO tenants(id,display_name) VALUES($1,'active identity 087')`, []any{tenantID}},
			{`INSERT INTO access_scopes(id,kind,tenant_id) VALUES($1,'tenant',$2)`, []any{scopeID, tenantID}},
			{`INSERT INTO users(id,username,display_name,password_hash) VALUES($1,$2,'identity 087','hash')`, []any{userID, "identity087-" + userID.String()}},
			{`INSERT INTO nodes(id,scope_id,name,admin_state,created_by_user_id) VALUES($1,$2,$3,'active',$4)`, []any{nodeID, scopeID, "identity087-" + nodeID.String(), userID}},
			{`INSERT INTO config_versions(id,configuration_scope_id,canonical_snapshot,canonical_snapshot_sha256,
				generator_name,generator_version,status,idempotency_key,request_digest,created_at)
				VALUES($1,$2,$3,$4,'identity087','1','building',$5,$6,$7)`, []any{configID, scopeID, []byte("manifest"), sha256Bytes087([]byte("manifest")), configID.String(), make([]byte, 32), now}},
			{`INSERT INTO artifact_signing_keys(id,algorithm,public_key,created_at) VALUES($1,'ed25519',$2,$3)`, []any{keyID, make([]byte, 32), now}},
			{`INSERT INTO configuration_artifacts(id,config_version_id,ordinal,kind,wire_bytes,size_bytes,sha256,
				signature,signing_key_id,signature_algorithm,compression,media_type,encryption_algorithm,created_at)
				VALUES($1,$2,1,'configuration',$3,$4,$5,$6,$7,'ed25519','none','application/octet-stream','none',$8)`, []any{artifactID, configID, wire, len(wire), digest, make([]byte, 64), keyID, now}},
			{`UPDATE config_versions SET status='validating' WHERE id=$1`, []any{configID}},
			{`UPDATE config_versions SET status='releasable',published_at=$2 WHERE id=$1`, []any{configID, now}},
			{`INSERT INTO rollouts(id,configuration_scope_id,config_version_id,action,status,idempotency_key,
				request_digest,request_id,correlation_id,activation_timeout_ms,observation_window_ms,
				required_consecutive_successes,deadline_at,created_at,queued_at,updated_at)
				VALUES($1,$2,$3,'apply','queued',$4,$5,$6,$7,1000,1000,1,$8,$9,$9,$9)`, []any{rolloutID, scopeID, configID, rolloutID.String(), make([]byte, 32), uuid.New(), uuid.New(), deadline, now}},
			{`INSERT INTO node_config_state(node_id,configuration_scope_id,current_config_version_id,updated_at)
				VALUES($1,$2,$3,$4)`, []any{nodeID, scopeID, configID, now}},
			{`INSERT INTO node_deployments(id,rollout_id,node_id,attempt,config_version_id,action,state,
				command_event_id,command_bytes,command_sha256,deadline_at,created_at,updated_at)
				VALUES($1,$2,$3,1,$4,'apply','healthy',$5,$6,$7,$8,$9,$9)`, []any{deploymentID, rolloutID, nodeID, configID, uuid.New(), command, commandDigest, deadline, now}},
			{`INSERT INTO node_deployment_artifacts(deployment_id,deployment_attempt,config_version_id,artifact_id,ordinal)
				VALUES($1,1,$2,$3,1)`, []any{deploymentID, configID, artifactID}},
			{`INSERT INTO node_presence(node_id,status,session_epoch,heartbeat_sequence,event_id,request_id,
				payload_digest,occurred_at,projected_at,offline_since,openresty_state,firewall_state,
				filesystem_total_bytes,filesystem_available_bytes,cache_used_bytes,active_deployments,updated_at)
				VALUES($1,'offline',1,1,$2,$3,$4,$5,$5,$5,'running','running',1,1,0,'[]',$5)`, []any{nodeID, uuid.New(), uuid.New(), make([]byte, 32), now}},
		}
		for _, statement := range statements {
			if _, err := tx.Exec(t.Context(), statement.query, statement.args...); err != nil {
				return err
			}
		}
		return nil
	})
	if err != nil {
		t.Fatal(err)
	}
	return activeIdentityFixture087{nodeID: nodeID, configID: configID, artifactID: artifactID, deploymentID: deploymentID, digest: digest}
}

func seedObservedIdentityDeployment087(t *testing.T, pool *pgxpool.Pool, fixture activeIdentityFixture087,
	action string, validCommandDigest bool,
) uuid.UUID {
	t.Helper()
	var scopeID uuid.UUID
	if err := pool.QueryRow(t.Context(), `SELECT scope_id FROM nodes WHERE id=$1`, fixture.nodeID).Scan(&scopeID); err != nil {
		t.Fatal(err)
	}
	rolloutID, deploymentID := uuid.New(), uuid.New()
	command := []byte("087 observed command " + deploymentID.String())
	commandDigest := sha256Bytes087(command)
	if !validCommandDigest {
		commandDigest = make([]byte, sha256.Size)
	}
	now, deadline := time.Now().UTC().Truncate(time.Microsecond), time.Now().UTC().Add(time.Hour)
	state := "healthy"
	var previousConfigID *uuid.UUID
	if action == "rollback" {
		state = "reverted"
		previousConfigID = &fixture.configID
	}
	if _, err := pool.Exec(t.Context(), `INSERT INTO rollouts(id,configuration_scope_id,config_version_id,action,
		status,idempotency_key,request_digest,request_id,correlation_id,activation_timeout_ms,observation_window_ms,
		required_consecutive_successes,deadline_at,created_at,queued_at,updated_at)
		VALUES($1,$2,$3,$4,'queued',$5,$6,$7,$8,1000,1000,1,$9,$10,$10,$10)`, rolloutID, scopeID,
		fixture.configID, action, rolloutID.String(), make([]byte, sha256.Size), uuid.New(), uuid.New(), deadline, now); err != nil {
		t.Fatal(err)
	}
	if _, err := pool.Exec(t.Context(), `INSERT INTO node_deployments(id,rollout_id,node_id,attempt,config_version_id,
		previous_config_version_id,action,state,command_event_id,command_bytes,command_sha256,deadline_at,created_at,updated_at)
		VALUES($1,$2,$3,1,$4,$5,$6,$7,$8,$9,$10,$11,$12,$12)`, deploymentID, rolloutID, fixture.nodeID,
		fixture.configID, previousConfigID, action, state, uuid.New(), command, commandDigest, deadline, now); err != nil {
		t.Fatal(err)
	}
	if action == "apply" {
		if _, err := pool.Exec(t.Context(), `INSERT INTO node_deployment_artifacts(
			deployment_id,deployment_attempt,config_version_id,artifact_id,ordinal) VALUES($1,1,$2,$3,1)`,
			deploymentID, fixture.configID, fixture.artifactID); err != nil {
			t.Fatal(err)
		}
	}
	return deploymentID
}

func seedActiveIdentityObservedUUID087(t *testing.T, pool *pgxpool.Pool,
	base activeIdentityFixture087, version int,
) activeIdentityFixture087 {
	t.Helper()
	if version < 1 || version > 8 {
		t.Fatalf("observed identity UUID version %d is outside 1..8", version)
	}
	return seedActiveIdentityObservedUUIDBinding087(t, pool, base,
		activeIdentityObservedUUID087(version, 1), activeIdentityObservedUUID087(version, 2),
		activeIdentityObservedUUID087(version, 3), activeIdentityObservedUUID087(version, 4))
}

func seedActiveIdentityObservedUUIDBinding087(t *testing.T, pool *pgxpool.Pool,
	base activeIdentityFixture087, configID, artifactID, rolloutID, deploymentID uuid.UUID,
) activeIdentityFixture087 {
	t.Helper()
	var scopeID uuid.UUID
	if err := pool.QueryRow(t.Context(), `SELECT scope_id FROM nodes WHERE id=$1`, base.nodeID).Scan(&scopeID); err != nil {
		t.Fatal(err)
	}
	wire := []byte(fmt.Sprintf("087 observed UUID signed configuration wire %s", configID))
	digest := sha256Bytes087(wire)
	command := []byte(fmt.Sprintf("087 observed UUID command %s", deploymentID))
	now, deadline := time.Now().UTC().Truncate(time.Microsecond), time.Now().UTC().Add(time.Hour)
	keyID := "active-identity-087-" + artifactID.String()
	err := pgx.BeginFunc(t.Context(), pool, func(tx pgx.Tx) error {
		statements := []struct {
			query string
			args  []any
		}{
			{`INSERT INTO config_versions(id,configuration_scope_id,canonical_snapshot,canonical_snapshot_sha256,
				generator_name,generator_version,status,idempotency_key,request_digest,created_at)
				VALUES($1,$2,$3,$4,'identity087-v7','1','building',$5,$6,$7)`, []any{configID, scopeID,
				[]byte(configID.String()), sha256Bytes087([]byte(configID.String())), configID.String(), make([]byte, sha256.Size), now}},
			{`INSERT INTO artifact_signing_keys(id,algorithm,public_key,created_at) VALUES($1,'ed25519',$2,$3)`, []any{keyID, make([]byte, 32), now}},
			{`INSERT INTO configuration_artifacts(id,config_version_id,ordinal,kind,wire_bytes,size_bytes,sha256,
				signature,signing_key_id,signature_algorithm,compression,media_type,encryption_algorithm,created_at)
				VALUES($1,$2,1,'configuration',$3,$4,$5,$6,$7,'ed25519','none','application/octet-stream','none',$8)`,
				[]any{artifactID, configID, wire, len(wire), digest, make([]byte, 64), keyID, now}},
			{`UPDATE config_versions SET status='validating' WHERE id=$1`, []any{configID}},
			{`UPDATE config_versions SET status='releasable',published_at=$2 WHERE id=$1`, []any{configID, now}},
			{`INSERT INTO rollouts(id,configuration_scope_id,config_version_id,action,status,idempotency_key,
				request_digest,request_id,correlation_id,activation_timeout_ms,observation_window_ms,
				required_consecutive_successes,deadline_at,created_at,queued_at,updated_at)
				VALUES($1,$2,$3,'apply','queued',$4,$5,$6,$7,1000,1000,1,$8,$9,$9,$9)`, []any{rolloutID,
				scopeID, configID, rolloutID.String(), make([]byte, sha256.Size), uuid.New(), uuid.New(), deadline, now}},
			{`INSERT INTO node_deployments(id,rollout_id,node_id,attempt,config_version_id,action,state,
				command_event_id,command_bytes,command_sha256,deadline_at,created_at,updated_at)
				VALUES($1,$2,$3,1,$4,'apply','healthy',$5,$6,$7,$8,$9,$9)`, []any{deploymentID, rolloutID,
				base.nodeID, configID, uuid.New(), command, sha256Bytes087(command), deadline, now}},
			{`INSERT INTO node_deployment_artifacts(deployment_id,deployment_attempt,config_version_id,
				artifact_id,ordinal) VALUES($1,1,$2,$3,1)`, []any{deploymentID, configID, artifactID}},
		}
		for _, statement := range statements {
			if _, err := tx.Exec(t.Context(), statement.query, statement.args...); err != nil {
				return err
			}
		}
		return nil
	})
	if err != nil {
		t.Fatal(err)
	}
	return activeIdentityFixture087{
		nodeID: base.nodeID, configID: configID, artifactID: artifactID, deploymentID: deploymentID, digest: digest,
	}
}

func seedActiveIdentityV7Observed087(t *testing.T, pool *pgxpool.Pool,
	base activeIdentityFixture087,
) activeIdentityFixture087 {
	t.Helper()
	return seedActiveIdentityObservedUUID087(t, pool, base, 7)
}

func activeIdentityObservedUUID087(version, suffix int) uuid.UUID {
	return uuid.MustParse(fmt.Sprintf("087a0000-bcde-%xabc-8def-%012x", version, suffix))
}

func assertActiveIdentity087Columns(t *testing.T, pool *pgxpool.Pool, want bool) {
	t.Helper()
	for _, item := range [][2]string{
		{"node_presence", "active_config_identity_api_version"},
		{"node_presence", "current_config_artifact_sha256"},
		{"deployment_status_events", "active_config_artifact_sha256"},
		{"node_config_state", "current_config_artifact_sha256"},
	} {
		var exists bool
		if err := pool.QueryRow(t.Context(), `SELECT EXISTS(SELECT 1 FROM information_schema.columns
			WHERE table_schema=current_schema() AND table_name=$1 AND column_name=$2)`, item[0], item[1]).Scan(&exists); err != nil || exists != want {
			t.Fatalf("column %s.%s exists=%t want=%t err=%v", item[0], item[1], exists, want, err)
		}
	}
}

func assertActiveIdentityCode087(t *testing.T, err error, want string) {
	t.Helper()
	var pgErr *pgconn.PgError
	if !errors.As(err, &pgErr) || pgErr.Code != want {
		t.Fatalf("PostgreSQL error=%v code=%q want=%q", err, func() string {
			if pgErr == nil {
				return ""
			}
			return pgErr.Code
		}(), want)
	}
}

func sha256Bytes087(value []byte) []byte {
	digest := sha256.Sum256(value)
	return digest[:]
}

func exactActiveIdentity086Pool(t *testing.T) *pgxpool.Pool {
	t.Helper()
	databaseURL := strings.TrimSpace(os.Getenv("TEST_DATABASE_URL"))
	if databaseURL == "" {
		t.Skip("TEST_DATABASE_URL is not set")
	}
	admin, err := pgxpool.New(t.Context(), databaseURL)
	if err != nil {
		t.Fatal(err)
	}
	schema := "active_identity_exact_086_" + strings.ReplaceAll(uuid.NewString(), "-", "")
	if !regexp.MustCompile(`^active_identity_exact_086_[a-f0-9]{32}$`).MatchString(schema) {
		admin.Close()
		t.Fatalf("unsafe exact 086 schema %q", schema)
	}
	identifier := pgx.Identifier{schema}.Sanitize()
	if _, err := admin.Exec(t.Context(), "CREATE SCHEMA "+identifier); err != nil {
		admin.Close()
		t.Fatal(err)
	}
	config, err := pgxpool.ParseConfig(databaseURL)
	if err != nil {
		admin.Close()
		t.Fatal(err)
	}
	config.ConnConfig.RuntimeParams["search_path"] = schema
	pool, err := pgxpool.NewWithConfig(t.Context(), config)
	if err != nil {
		admin.Close()
		t.Fatal(err)
	}
	t.Cleanup(func() {
		pool.Close()
		cleanupCtx, cancel := databasetest.CleanupContext()
		defer cancel()
		if _, err := admin.Exec(cleanupCtx, "DROP SCHEMA "+identifier+" CASCADE"); err != nil {
			t.Errorf("drop exact 086 schema: %v", err)
		}
		admin.Close()
	})
	if _, err := pool.Exec(t.Context(), exactActiveIdentity086Schema); err != nil {
		t.Fatal(err)
	}
	if _, err := pool.Exec(t.Context(), `INSERT INTO schema_migrations(
		version,migration_id,checksum_sha256,down_checksum_sha256,integrity_state,metadata_recorded_at,applied_at
	) SELECT version,
		CASE WHEN version=86 THEN '086_site_l4_automatic_publication' ELSE 'frozen_'||lpad(version::text,3,'0') END,
		CASE WHEN version=86 THEN '35ba7924b2b90a0efbd4c8d2fc3082c2be040595f4f7daa0874b54fb57dcf207' ELSE repeat('0',64) END,
		CASE WHEN version=86 THEN '0f5e8eaaf08e8a05912d60b69a74cd46e9ed75057546827c26e853c827e15b0c' ELSE repeat('0',64) END,
		'verified',clock_timestamp(),clock_timestamp() FROM generate_series(1,86) version`); err != nil {
		t.Fatal(err)
	}
	return pool
}

func applyExactActiveIdentity087(ctx context.Context, pool *pgxpool.Pool) error {
	up, err := fs.ReadFile(controlmigrations.FS, "087_active_config_identity_control.up.sql")
	if err != nil {
		return err
	}
	down, err := fs.ReadFile(controlmigrations.FS, "087_active_config_identity_control.down.sql")
	if err != nil {
		return err
	}
	tx, err := pool.Begin(ctx)
	if err != nil {
		return err
	}
	defer func() { _ = tx.Rollback(context.Background()) }()
	if _, err := tx.Exec(ctx, string(up)); err != nil {
		return err
	}
	if _, err := tx.Exec(ctx, `INSERT INTO schema_migrations(
		version,migration_id,checksum_sha256,down_checksum_sha256,integrity_state,metadata_recorded_at,applied_at
	) VALUES(87,'087_active_config_identity_control',$1,$2,'verified',clock_timestamp(),clock_timestamp())`,
		fmt.Sprintf("%x", sha256.Sum256(up)), fmt.Sprintf("%x", sha256.Sum256(down))); err != nil {
		return err
	}
	return tx.Commit(ctx)
}

func rollbackExactActiveIdentity087(ctx context.Context, pool *pgxpool.Pool) error {
	down, err := fs.ReadFile(controlmigrations.FS, "087_active_config_identity_control.down.sql")
	if err != nil {
		return err
	}
	tx, err := pool.Begin(ctx)
	if err != nil {
		return err
	}
	defer func() { _ = tx.Rollback(context.Background()) }()
	if _, err := tx.Exec(ctx, string(down)); err != nil {
		return err
	}
	if _, err := tx.Exec(ctx, `DELETE FROM schema_migrations WHERE version=87`); err != nil {
		return err
	}
	return tx.Commit(ctx)
}

const exactActiveIdentity086Schema = `
CREATE TABLE schema_migrations (
    version bigint PRIMARY KEY,
    migration_id text,
    checksum_sha256 text,
    down_checksum_sha256 text,
    integrity_state text,
    metadata_recorded_at timestamptz,
    applied_at timestamptz NOT NULL
);
CREATE TABLE tenants (id uuid PRIMARY KEY, display_name text NOT NULL);
CREATE TABLE access_scopes (id uuid PRIMARY KEY, kind text NOT NULL, tenant_id uuid);
CREATE TABLE users (id uuid PRIMARY KEY, username text NOT NULL, display_name text NOT NULL, password_hash text NOT NULL);
CREATE TABLE nodes (id uuid PRIMARY KEY, scope_id uuid NOT NULL, name text NOT NULL, admin_state text NOT NULL, created_by_user_id uuid NOT NULL);
CREATE TABLE config_versions (
    id uuid PRIMARY KEY, configuration_scope_id uuid NOT NULL, canonical_snapshot bytea NOT NULL,
    canonical_snapshot_sha256 bytea NOT NULL, generator_name text NOT NULL, generator_version text NOT NULL,
    status text NOT NULL, idempotency_key text NOT NULL, request_digest bytea NOT NULL,
    created_at timestamptz NOT NULL, published_at timestamptz
);
CREATE TABLE artifact_signing_keys (id text PRIMARY KEY, algorithm text NOT NULL, public_key bytea NOT NULL, created_at timestamptz NOT NULL);
CREATE TABLE configuration_artifacts (
    id uuid PRIMARY KEY, config_version_id uuid NOT NULL, ordinal integer NOT NULL, kind text NOT NULL,
    wire_bytes bytea NOT NULL, size_bytes bigint NOT NULL, sha256 bytea NOT NULL, signature bytea NOT NULL,
    signing_key_id text NOT NULL, signature_algorithm text NOT NULL, compression text NOT NULL,
    media_type text NOT NULL, encryption_algorithm text NOT NULL, recipient_key_id text, created_at timestamptz NOT NULL
);
CREATE TABLE rollouts (
    id uuid PRIMARY KEY, configuration_scope_id uuid NOT NULL, config_version_id uuid NOT NULL,
    action text NOT NULL, status text NOT NULL, idempotency_key text NOT NULL, request_digest bytea NOT NULL,
    request_id uuid NOT NULL, correlation_id uuid NOT NULL, activation_timeout_ms bigint NOT NULL,
    observation_window_ms bigint NOT NULL, required_consecutive_successes integer NOT NULL,
    deadline_at timestamptz NOT NULL, created_at timestamptz NOT NULL, queued_at timestamptz,
    updated_at timestamptz NOT NULL
);
CREATE TABLE node_config_state (
    node_id uuid PRIMARY KEY, configuration_scope_id uuid, current_config_version_id uuid,
    previous_config_version_id uuid, revision bigint NOT NULL DEFAULT 1, updated_at timestamptz NOT NULL
);
CREATE TABLE node_deployments (
    id uuid NOT NULL, rollout_id uuid NOT NULL, node_id uuid NOT NULL, attempt integer NOT NULL,
    config_version_id uuid NOT NULL, previous_config_version_id uuid, action text NOT NULL, state text NOT NULL,
    command_event_id uuid NOT NULL, command_bytes bytea NOT NULL, command_sha256 bytea NOT NULL,
    deadline_at timestamptz NOT NULL, created_at timestamptz NOT NULL, updated_at timestamptz NOT NULL,
    PRIMARY KEY(id,attempt)
);
CREATE TABLE node_deployment_artifacts (
    deployment_id uuid NOT NULL, deployment_attempt integer NOT NULL, config_version_id uuid NOT NULL,
    artifact_id uuid NOT NULL, ordinal integer NOT NULL, PRIMARY KEY(deployment_id,deployment_attempt,artifact_id)
);
CREATE TABLE node_presence (
    node_id uuid PRIMARY KEY, status text NOT NULL, session_epoch bigint NOT NULL, heartbeat_sequence bigint NOT NULL,
    event_id uuid NOT NULL, request_id uuid NOT NULL, payload_digest bytea NOT NULL, occurred_at timestamptz NOT NULL,
    projected_at timestamptz NOT NULL, last_seen_at timestamptz, confirmed_session_epoch bigint,
    confirmed_heartbeat_sequence bigint, confirmed_event_id uuid, confirmed_request_id uuid,
    confirmed_payload_digest bytea, online_since timestamptz, offline_since timestamptz,
    current_config_version_id uuid, previous_config_version_id uuid, loaded_config_version_id uuid,
    openresty_state text NOT NULL, firewall_state text NOT NULL, filesystem_total_bytes numeric(20,0) NOT NULL,
    filesystem_available_bytes numeric(20,0) NOT NULL, cache_used_bytes numeric(20,0) NOT NULL,
    active_deployments jsonb NOT NULL DEFAULT '[]'::jsonb, revision bigint NOT NULL DEFAULT 1,
    updated_at timestamptz NOT NULL
);
CREATE TABLE deployment_status_events (
    id uuid PRIMARY KEY, deployment_id uuid NOT NULL, event_id uuid NOT NULL, attempt integer NOT NULL,
    transition_sequence bigint NOT NULL, state text NOT NULL, payload bytea NOT NULL, payload_sha256 bytea NOT NULL,
    occurred_at timestamptz NOT NULL, received_at timestamptz NOT NULL
);`
