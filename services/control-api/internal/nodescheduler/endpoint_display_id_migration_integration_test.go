//go:build integration

package nodescheduler

import (
	"bytes"
	"errors"
	"testing"

	"github.com/cdnca/cdnca/services/control-api/internal/database/databasetest"
	"github.com/cdnca/cdnca/services/control-api/migrations"
	"github.com/google/uuid"
	"github.com/jackc/pgx/v5"
	"github.com/jackc/pgx/v5/pgconn"
)

func TestLineEndpointDisplayIDMigration275(t *testing.T) {
	// Migration 268's down is a deliberate one-way gate (P2682) and later
	// migrations sit on top of 275; pin the schema head to 275 for this test.
	f := newIntegrationFixtureThrough(t, 275)
	ctx := t.Context()
	if err := databasetest.MigrateThrough(ctx, f.pool, "down", 275); err != nil {
		t.Fatalf("empty 275 rollback: %v", err)
	}
	up, err := migrations.FS.ReadFile("275_node_line_endpoint_display_ids.up.sql")
	if err != nil {
		t.Fatal(err)
	}
	err = pgx.BeginFunc(ctx, f.pool, func(tx pgx.Tx) error {
		if _, err := tx.Exec(ctx, `UPDATE schema_migrations SET checksum_sha256=repeat('0',64) WHERE version=274`); err != nil {
			return err
		}
		_, err := tx.Exec(ctx, string(up))
		return err
	})
	var pgError *pgconn.PgError
	if !errors.As(err, &pgError) || pgError.Code != "P2750" {
		t.Fatalf("invalid parent accepted: %v", err)
	}
	request := f.putRequest(uuid.New(), 0, "historical-endpoints", "historical-endpoints")
	seedLineGroup274WithEndpoints(t, f, request)
	var before []byte
	if err := f.pool.QueryRow(ctx, `SELECT configuration_digest FROM node_line_group_revisions WHERE line_group_id=$1`, request.GroupID).Scan(&before); err != nil {
		t.Fatal(err)
	}
	if err := databasetest.MigrateThrough(ctx, f.pool, "up", 275); err != nil {
		t.Fatalf("backfill 275: %v", err)
	}
	// The schema stays at 275 here, so read with SQL of that schema, not the
	// current service (later columns such as 422 purpose are absent).
	read, err := readGroup275(t, f, request.GroupID)
	if err != nil || len(read.Endpoints) != 2 || !bytes.Equal(read.ConfigurationDigest, before) {
		t.Fatalf("backfill changed historical configuration: %v", err)
	}
	if read.Endpoints[0].DisplayID == "" || read.Endpoints[1].DisplayID == "" || read.Endpoints[0].DisplayID == read.Endpoints[1].DisplayID {
		t.Fatal("historical endpoints not assigned distinct IDs")
	}
	for _, statement := range []string{
		`UPDATE node_line_endpoint_display_ids SET display_id=DEFAULT`,
		`DELETE FROM node_line_endpoint_display_ids`,
		`TRUNCATE node_line_endpoint_display_ids`,
	} {
		_, err := f.pool.Exec(ctx, statement)
		if !errors.As(err, &pgError) || pgError.Code != "P2751" {
			t.Fatalf("immutable display IDs: %s: %v", statement, err)
		}
	}
	var readAllowed, writeAllowed, allocateAllowed, invokeAllowed bool
	if err := f.pool.QueryRow(ctx, `SELECT
		has_table_privilege('cdnca_control_app','node_line_endpoint_display_ids','SELECT'),
		has_table_privilege('cdnca_control_app','node_line_endpoint_display_ids','INSERT,UPDATE,DELETE,TRUNCATE'),
		has_sequence_privilege('cdnca_control_app','node_line_endpoint_display_ids_display_id_seq','USAGE,UPDATE'),
		has_function_privilege('cdnca_control_app','assign_node_line_endpoint_display_id_275()','EXECUTE')`).Scan(
		&readAllowed, &writeAllowed, &allocateAllowed, &invokeAllowed); err != nil || !readAllowed || writeAllowed || allocateAllowed || invokeAllowed {
		t.Fatalf("display grants read=%t write=%t sequence=%t function=%t err=%v", readAllowed, writeAllowed, allocateAllowed, invokeAllowed, err)
	}
	// Repeated UP is inert; existing IDs and digests remain intact.
	if err := databasetest.MigrateThrough(ctx, f.pool, "up", 275); err != nil {
		t.Fatal(err)
	}
	newRead, err := readGroup275(t, f, request.GroupID)
	if err != nil || newRead.Endpoints[0].DisplayID != read.Endpoints[0].DisplayID || newRead.Endpoints[1].DisplayID != read.Endpoints[1].DisplayID {
		t.Fatalf("reapply renumbered endpoints: %v", err)
	}
	err = databasetest.MigrateThrough(ctx, f.pool, "down", 275)
	if !errors.As(err, &pgError) || pgError.Code != "P2752" {
		t.Fatalf("destructive display rollback accepted: %v", err)
	}
	var head int
	if err := f.pool.QueryRow(ctx, `SELECT max(version) FROM schema_migrations`).Scan(&head); err != nil || head != 275 {
		t.Fatalf("rejected down changed ledger: head=%d err=%v", head, err)
	}
}

// readGroup275 reads the current revision's digest and endpoint display IDs
// in endpoint order (normalized order: compareEndpoint) on a 275 schema.
func readGroup275(t *testing.T, f *integrationFixture, groupID uuid.UUID) (LineGroupRevision, error) {
	t.Helper()
	var result LineGroupRevision
	if err := f.pool.QueryRow(t.Context(), `SELECT revision.configuration_digest FROM node_line_groups line_group
		JOIN node_line_group_revisions revision ON revision.tenant_scope_id=line_group.tenant_scope_id
		 AND revision.line_group_id=line_group.id AND revision.revision=line_group.current_revision
		WHERE line_group.tenant_scope_id=$1 AND line_group.id=$2`, f.actor.ScopeID, groupID).Scan(&result.ConfigurationDigest); err != nil {
		return result, err
	}
	rows, err := f.pool.Query(t.Context(), `SELECT endpoint.id, display.display_id::text FROM node_line_endpoints endpoint
		JOIN node_line_groups line_group ON line_group.tenant_scope_id=endpoint.tenant_scope_id
		 AND line_group.id=endpoint.line_group_id AND line_group.current_revision=endpoint.config_revision
		LEFT JOIN node_line_endpoint_display_ids display ON display.tenant_scope_id=endpoint.tenant_scope_id
		 AND display.line_group_id=endpoint.line_group_id AND display.endpoint_id=endpoint.id
		WHERE endpoint.tenant_scope_id=$1 AND endpoint.line_group_id=$2
		ORDER BY endpoint.priority, endpoint.sort_order, endpoint.address, endpoint.id`, f.actor.ScopeID, groupID)
	if err != nil {
		return result, err
	}
	result.Endpoints, err = pgx.CollectRows(rows, func(row pgx.CollectableRow) (Endpoint, error) {
		var endpoint Endpoint
		var display *string
		err := row.Scan(&endpoint.ID, &display)
		if display != nil {
			endpoint.DisplayID = *display
		}
		return endpoint, err
	})
	return result, err
}

func seedLineGroup274WithEndpoints(t *testing.T, f *integrationFixture, request PutGroupRequest) {
	t.Helper()
	ctx := t.Context()
	input, err := normalizePutRequest(request)
	if err != nil {
		t.Fatal(err)
	}
	input, err = applyGroupDefaults(input)
	if err != nil {
		t.Fatal(err)
	}
	err = pgx.BeginFunc(ctx, f.pool, func(tx pgx.Tx) error {
		if _, err := tx.Exec(ctx, `INSERT INTO node_line_groups
			(id,tenant_scope_id,name,region,resolved_value,ipv4_resolved_value,failover_mode,note,sort_order,
			 current_revision,created_by_user_id,updated_by_user_id,created_at,updated_at)
			VALUES($1,$2,$3,$4,$5,$6,$7,$8,$9,1,$10,$10,$11,$11)`, input.groupID, f.actor.ScopeID,
			input.name, input.region, input.resolvedValue, input.ipv4ResolvedValue, input.failoverMode,
			input.note, input.sortOrder, f.actor.UserID, integrationBaseTime); err != nil {
			return err
		}
		return insertRevision(ctx, tx, f.actor, input, 1, integrationBaseTime)
	})
	if err != nil {
		t.Fatalf("seed actual 274 configuration: %v", err)
	}
}
