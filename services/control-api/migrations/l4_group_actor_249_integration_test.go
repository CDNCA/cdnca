//go:build integration

package migrations_test

import (
	"errors"
	"testing"
	"time"

	"github.com/google/uuid"
	"github.com/jackc/pgx/v5/pgconn"
)

func TestL4GroupActor249MigrationRoundTrip(t *testing.T) {
	pool := packageCommerceRBAC079Pool(t, 248)
	scope, owner, _ := seedL4DisplayIdentity214(t, pool, "group-actor-legacy", time.Now().UTC())
	group, defaults := uuid.New(), uuid.New()
	if _, err := pool.Exec(t.Context(), `INSERT INTO l4_stream_groups(id,scope_id,owner_user_id,name,created_by_user_id,updated_by_user_id)
		VALUES($1,$2,$3,'Legacy group',$3,$3)`, group, scope, owner); err != nil {
		t.Fatal(err)
	}
	if _, err := pool.Exec(t.Context(), `INSERT INTO l4_stream_user_defaults(id,scope_id,owner_user_id,setting_name,setting_value,scope_name,created_by_user_id)
		VALUES($1,$2,$3,'listen_protocol','tcp','global',$3)`, defaults, scope, owner); err != nil {
		t.Fatal(err)
	}
	readFacts := func() string {
		t.Helper()
		var value string
		if err := pool.QueryRow(t.Context(), `SELECT jsonb_build_object('groups',(SELECT jsonb_agg(to_jsonb(g)) FROM l4_stream_groups g),
			'defaults',(SELECT jsonb_agg(to_jsonb(d)) FROM l4_stream_user_defaults d))::text`).Scan(&value); err != nil {
			t.Fatal(err)
		}
		return value
	}
	before := readFacts()
	for attempt := 0; attempt < 2; attempt++ {
		if err := migrateVersionIsolated(t.Context(), pool, "up", 249); err != nil {
			t.Fatal(err)
		}
		if err := migrateVersionIsolated(t.Context(), pool, "down", 249); err != nil {
			t.Fatal(err)
		}
		if after := readFacts(); after != before {
			t.Fatal("migration changed legacy actor facts")
		}
	}
}

func TestL4GroupActor249RefusesLossyRollback(t *testing.T) {
	for _, field := range []string{"group_creator", "group_updater", "default_creator"} {
		t.Run(field, func(t *testing.T) {
			pool := packageCommerceRBAC079Pool(t, 248)
			scope, owner, _ := seedL4DisplayIdentity214(t, pool, "group-actor-owner", time.Now().UTC())
			_, actor, _ := seedL4DisplayIdentity214(t, pool, "group-actor-foreign", time.Now().UTC())
			if err := migrateVersionIsolated(t.Context(), pool, "up", 249); err != nil {
				t.Fatal(err)
			}
			id := uuid.New()
			creator, updater := owner, owner
			if field == "group_creator" {
				creator = actor
			}
			if field == "group_updater" {
				updater = actor
			}
			if field == "default_creator" {
				if _, err := pool.Exec(t.Context(), `INSERT INTO l4_stream_user_defaults(id,scope_id,owner_user_id,setting_name,setting_value,scope_name,created_by_user_id)
					VALUES($1,$2,$3,'listen_protocol','tcp','global',$4)`, id, scope, owner, actor); err != nil {
					t.Fatal(err)
				}
			} else if _, err := pool.Exec(t.Context(), `INSERT INTO l4_stream_groups(id,scope_id,owner_user_id,name,created_by_user_id,updated_by_user_id)
				VALUES($1,$2,$3,'Cross-scope actor',$4,$5)`, id, scope, owner, creator, updater); err != nil {
				t.Fatal(err)
			}
			// Invalid owners still require target-scope membership; unknown actors still fail referential integrity.
			for _, values := range [][3]uuid.UUID{{actor, owner, owner}, {owner, uuid.New(), owner}, {owner, owner, uuid.New()}} {
				_, err := pool.Exec(t.Context(), `INSERT INTO l4_stream_groups(id,scope_id,owner_user_id,name,created_by_user_id,updated_by_user_id)
					VALUES($1,$2,$3,$4,$5,$6)`, uuid.New(), scope, values[0], uuid.NewString(), values[1], values[2])
				var pgError *pgconn.PgError
				if !errors.As(err, &pgError) || pgError.Code != "23503" {
					t.Fatalf("invalid group identity accepted: %v", err)
				}
			}
			for _, values := range [][2]uuid.UUID{{actor, owner}, {owner, uuid.New()}} {
				_, err := pool.Exec(t.Context(), `INSERT INTO l4_stream_user_defaults(id,scope_id,owner_user_id,setting_name,setting_value,scope_name,created_by_user_id)
					VALUES($1,$2,$3,'balance_way','rr','global',$4)`, uuid.New(), scope, values[0], values[1])
				var pgError *pgconn.PgError
				if !errors.As(err, &pgError) || pgError.Code != "23503" {
					t.Fatalf("invalid default identity accepted: %v", err)
				}
			}
			readState := func() string {
				t.Helper()
				var value string
				if err := pool.QueryRow(t.Context(), `SELECT jsonb_build_object(
					'migrations',(SELECT jsonb_agg(to_jsonb(m) ORDER BY version) FROM schema_migrations m),
					'groups',(SELECT jsonb_agg(to_jsonb(g) ORDER BY id) FROM l4_stream_groups g),
					'defaults',(SELECT jsonb_agg(to_jsonb(d) ORDER BY id) FROM l4_stream_user_defaults d),
					'constraints',(SELECT jsonb_agg(pg_get_constraintdef(oid) ORDER BY conname) FROM pg_constraint
					WHERE conrelid IN ('l4_stream_groups'::regclass,'l4_stream_user_defaults'::regclass)))::text`).Scan(&value); err != nil {
					t.Fatal(err)
				}
				return value
			}
			before := readState()
			err := migrateVersionIsolated(t.Context(), pool, "down", 249)
			var pgError *pgconn.PgError
			if !errors.As(err, &pgError) || pgError.Code != "P2491" {
				t.Fatalf("lossy rollback result: %v", err)
			}
			if after := readState(); after != before {
				t.Fatal("rejected rollback changed migration ledger, actor facts or constraints")
			}
		})
	}
}
