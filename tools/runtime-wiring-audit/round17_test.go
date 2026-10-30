package main

import (
	"strings"
	"testing"
)

func TestRound17NamedReturnedReceiverAliasInvalidatesDeferredRoute(t *testing.T) {
	const fixture = "services/control-api/internal/controlflowroutes/round17_receiver.go"
	reject := map[string]bool{
		"/round17-named-returned-alias":    true,
		"/round17-ordinary-returned-alias": true,
		"/round17-iife-returned-alias":     true,
		"/round17-pair-returned-alias":     true,
	}
	foundNamedNew := false
	for _, route := range fixtureRoutes(t, fixture) {
		if reject[route.Path] {
			t.Errorf("returned receiver alias left deferred route proven: %#v", route)
		}
		foundNamedNew = foundNamedNew || route.Path == "/round17-named-new-receiver"
	}
	if !foundNamedNew {
		t.Fatal("named result returning a distinct receiver was not proven stable")
	}
}

func TestRound17WithDMLPartialFormatKeepsObjectUncertain(t *testing.T) {
	cases := map[string]string{
		"insert":      "WITH seed AS (SELECT 1 AS id) INSERT INTO public.%I(payload) SELECT %L FROM seed",
		"update":      "WITH seed AS (SELECT 1 AS id) UPDATE public.%I SET payload = %L FROM seed",
		"delete":      "WITH seed AS (SELECT 1 AS id) DELETE FROM public.%I USING seed WHERE payload = %L",
		"merge":       "WITH seed AS (SELECT 1 AS id) MERGE INTO public.%I AS target USING seed ON target.id = seed.id WHEN MATCHED THEN UPDATE SET payload = %L",
		"nested":      "WITH outer_seed AS (WITH inner_seed AS (SELECT 1 AS id) SELECT id FROM inner_seed) INSERT INTO public.%I(payload) SELECT %L FROM outer_seed",
		"recursive":   "WITH RECURSIVE seed(id) AS (SELECT 1 UNION ALL SELECT id + 1 FROM seed WHERE id < 2) INSERT INTO public.%I(payload) SELECT %L FROM seed",
		"inner-write": "WITH changed AS (UPDATE public.%I SET payload = %L RETURNING *) SELECT * FROM changed",
	}
	for name, template := range cases {
		t.Run(name, func(t *testing.T) {
			object := "round17_" + strings.ReplaceAll(name, "-", "_") + "_records"
			format := "format('" + template + "', '" + object + "', dynamic_value)"
			content := []byte("CREATE TABLE public.round17_static_records (id bigint); DO $$ BEGIN EXECUTE " + format + "; END $$;")
			ownership := migrationOwnedObjects(content)
			if ownership.GlobalUnknown || strings.Join(ownership.Owned, ",") != "round17_static_records" ||
				strings.Join(ownership.Uncertain, ",") != object {
				t.Fatalf("WITH %s ownership = %#v, want object-local uncertainty for %s", name, ownership, object)
			}
		})
	}
}

func TestRound17WithSelectOnlyDoesNotInventOwnership(t *testing.T) {
	content := []byte("DO $$ BEGIN EXECUTE format('WITH seed AS (SELECT %L AS payload) SELECT payload FROM seed', dynamic_value); END $$;")
	ownership := migrationOwnedObjects(content)
	if ownership.GlobalUnknown || len(ownership.Uncertain) != 0 {
		t.Fatalf("SELECT-only WITH invented ownership: %#v", ownership)
	}
}

func TestRound17WithInsertUncertaintyBlocksMigrationPass(t *testing.T) {
	content := []byte(`
CREATE TABLE public.round17_static_records (id bigint);
DO $$ BEGIN
  EXECUTE format(
    'WITH seed AS (SELECT 1 AS payload) INSERT INTO public.%I(payload) SELECT %L FROM seed',
    'round17_insert_records', dynamic_value
  );
END $$;
`)
	ownership := migrationOwnedObjects(content)
	if ownership.GlobalUnknown || strings.Join(ownership.Owned, ",") != "round17_static_records" ||
		strings.Join(ownership.Uncertain, ",") != "round17_insert_records" {
		t.Fatalf("WITH INSERT ownership was not object-local: %#v", ownership)
	}

	domain := domainModel{Name: "round17", Prod: []goFileFact{{Functions: []functionFact{{Strings: []string{
		"INSERT INTO public.round17_static_records (id) VALUES ($1)",
		"INSERT INTO public.round17_insert_records (payload) VALUES ($1)",
	}}}}}}
	migrations := migrationIndex{
		Files: []migrationFact{
			{Path: "round17.up.sql", Version: "117", Direction: "up", Owned: ownership.Owned, Uncertain: ownership.Uncertain, GlobalUnknown: ownership.GlobalUnknown, Embedded: true},
			{Path: "round17.down.sql", Version: "117", Direction: "down", Owned: ownership.Owned, Uncertain: ownership.Uncertain, GlobalUnknown: ownership.GlobalUnknown, Embedded: true},
		},
		RuntimeLoads: true,
		RuntimeProof: []string{"fixture#migrations.FS"},
	}
	up, down, head := migrationChecks(domain, migrations, checked(statusPass, []string{"fixture#postgres-calls"}, "fixture"), "fixture#round17")
	for check, result := range map[string]checkResult{"migration_up": up, "migration_down": down, "migration_runtime_head": head} {
		if result.Status != statusUnknown {
			t.Errorf("%s=%s, want unknown; evidence=%v reason=%s", check, result.Status, result.Evidence, result.Reason)
		}
	}
}
