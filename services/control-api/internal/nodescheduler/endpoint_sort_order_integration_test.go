//go:build integration

package nodescheduler

import (
	"errors"
	"testing"

	"github.com/cdnca/cdnca/services/control-api/internal/database/databasetest"
	"github.com/google/uuid"
	"github.com/jackc/pgx/v5/pgconn"
)

func TestLineEndpointSortOrder274PersistenceAndRollback(t *testing.T) {
	fixture := newIntegrationFixture(t)
	ctx := t.Context()
	request := fixture.putRequest(uuid.New(), 0, "sort-order-cloud", "sort-order-create")
	request.Endpoints[0].Priority, request.Endpoints[1].Priority = 0, 0
	request.Endpoints[0].SortOrder, request.Endpoints[1].SortOrder = 42, 7
	created, err := fixture.service.PutGroup(ctx, fixture.actor, request)
	if err != nil {
		t.Fatal(err)
	}
	read, err := fixture.service.GetCurrent(ctx, fixture.actor, request.GroupID)
	if err != nil || len(read.Endpoints) != 2 || read.Endpoints[0].ID != request.Endpoints[1].ID ||
		read.Endpoints[0].SortOrder != 7 || read.Endpoints[1].SortOrder != 42 {
		t.Fatalf("persisted endpoint ordering=%#v err=%v", read.Endpoints, err)
	}
	replay, err := fixture.service.PutGroup(ctx, fixture.actor, request)
	if err != nil || !replay.Replayed || replay.Group.Revision != created.Group.Revision {
		t.Fatalf("sort replay=%#v err=%v", replay, err)
	}
	changed := request
	changed.Endpoints = append([]Endpoint(nil), request.Endpoints...)
	changed.Endpoints[0].SortOrder = 3
	if _, err := fixture.service.PutGroup(ctx, fixture.actor, changed); !errors.Is(err, ErrIdempotencyConflict) {
		t.Fatalf("changed sort replay error=%v", err)
	}
	changed.ExpectedRevision, changed.IdempotencyKey, changed.RequestID = 1, "sort-order-update", "sort-order-update-request"
	updated, err := fixture.service.PutGroup(ctx, fixture.actor, changed)
	if err != nil || updated.Group.Revision != 2 {
		t.Fatalf("sort update=%#v err=%v", updated, err)
	}
	read, err = fixture.service.GetCurrent(ctx, fixture.actor, request.GroupID)
	if err != nil || read.Endpoints[0].ID != request.Endpoints[0].ID || read.Endpoints[0].SortOrder != 3 {
		t.Fatalf("updated sort readback=%#v err=%v", read.Endpoints, err)
	}
	var historical int
	if err := fixture.pool.QueryRow(ctx, `SELECT sort_order FROM node_line_endpoints
		WHERE tenant_scope_id=$1 AND line_group_id=$2 AND config_revision=1 AND id=$3`,
		fixture.actor.ScopeID, request.GroupID, request.Endpoints[0].ID).Scan(&historical); err != nil || historical != 42 {
		t.Fatalf("historical sort=%d err=%v", historical, err)
	}
	rolled, err := fixture.service.Rollback(ctx, fixture.actor, request.GroupID, 1, 2, "sort-order-rollback", "sort-order-rollback-request")
	if err != nil || rolled.Group.Revision != 3 || rolled.Group.Endpoints[0].ID != request.Endpoints[1].ID ||
		rolled.Group.Endpoints[0].SortOrder != 7 || rolled.Group.Endpoints[1].SortOrder != 42 {
		t.Fatalf("sort rollback=%#v err=%v", rolled, err)
	}
	// Exercise 274's own rollback guard on its actual schema head, not whichever
	// later migration is now at the head of the normal fixture.
	// Only 1..275 are loaded (268 cannot be rolled back), so one down lands on 274.
	legacy := newIntegrationFixtureThrough(t, 275)
	if err := databasetest.MigrateThrough(ctx, legacy.pool, "down", 275); err != nil {
		t.Fatal(err)
	}
	seedLineGroup274WithEndpoints(t, legacy, request)
	err = databasetest.MigrateThrough(ctx, legacy.pool, "down", 275)
	var pgError *pgconn.PgError
	if !errors.As(err, &pgError) || pgError.Code != "P2742" {
		t.Fatalf("destructive schema rollback error=%v", err)
	}
	var head int
	if err := legacy.pool.QueryRow(ctx, "SELECT max(version) FROM schema_migrations").Scan(&head); err != nil || head != 274 {
		t.Fatalf("migration head after rejected rollback=%d err=%v", head, err)
	}
}
