package main

import (
	"strings"
	"testing"
)

func TestRound15ReceiverAliasesAndEscapesInvalidateDeferredRoute(t *testing.T) {
	const fixture = "services/control-api/internal/controlflowroutes/round15_receiver.go"
	reject := map[string]bool{
		"/round15-direct-alias-reset":         true,
		"/round15-method-alias-reset":         true,
		"/round15-wrapper-alias-reset":        true,
		"/round15-slice-alias-reset":          true,
		"/round15-field-alias-reset":          true,
		"/round15-package-alias-escape":       true,
		"/round15-package-field-alias-escape": true,
		"/round15-package-map-alias-escape":   true,
		"/round15-ambiguous-closure-go":       true,
	}
	foundObserve := false
	for _, route := range fixtureRoutes(t, fixture) {
		if reject[route.Path] {
			t.Errorf("receiver alias or escape left deferred route proven: %#v", route)
		}
		foundObserve = foundObserve || route.Path == "/round15-pure-observe-alias"
	}
	if !foundObserve {
		t.Fatal("pure receiver alias observation was not proven")
	}
}

func TestRound15BareChannelOperationsDoNotProveDeferredExecution(t *testing.T) {
	const fixture = "services/control-api/internal/controlflowroutes/round15_receiver.go"
	reject := map[string]bool{
		"/round15-bare-receive": true,
		"/round15-bare-send":    true,
	}
	foundProvenSync := false
	for _, route := range fixtureRoutes(t, fixture) {
		if reject[route.Path] {
			t.Errorf("bare channel operation left deferred route proven: %#v", route)
		}
		foundProvenSync = foundProvenSync || route.Path == "/round15-proven-local-sync"
	}
	if !foundProvenSync {
		t.Fatal("locally proven goroutine synchronization route regressed")
	}
}

func TestRound15DeadRecursiveClosureDoesNotRecurseAnalysis(t *testing.T) {
	const fixture = "services/control-api/internal/controlflowroutes/round15_receiver.go"
	for _, route := range fixtureRoutes(t, fixture) {
		if route.Path == "/round15-dead-recursive-closure" {
			return
		}
	}
	t.Fatal("dead recursive closure invalidated a stable receiver")
}

func TestRound15DynamicDataLiteralKeepsObjectUncertain(t *testing.T) {
	content := []byte(`
CREATE TABLE public.round15_static_records (id bigint);
DO $$ BEGIN
  EXECUTE format('INSERT INTO public.round15_dynamic_records(payload) VALUES (%L)', dynamic_value);
END $$;
`)
	ownership := migrationOwnedObjects(content)
	if ownership.GlobalUnknown || strings.Join(ownership.Owned, ",") != "round15_static_records" || strings.Join(ownership.Uncertain, ",") != "round15_dynamic_records" {
		t.Fatalf("dynamic data ownership was not object-local: %#v", ownership)
	}

	domain := domainModel{Name: "round15", Prod: []goFileFact{{Functions: []functionFact{{Strings: []string{
		"INSERT INTO public.round15_static_records (id) VALUES ($1)",
		"INSERT INTO public.round15_dynamic_records (payload) VALUES ($1)",
	}}}}}}
	migrations := migrationIndex{
		Files: []migrationFact{
			{Path: "round15.up.sql", Version: "115", Direction: "up", Owned: ownership.Owned, Uncertain: ownership.Uncertain, GlobalUnknown: ownership.GlobalUnknown, Embedded: true},
			{Path: "round15.down.sql", Version: "115", Direction: "down", Owned: ownership.Owned, Uncertain: ownership.Uncertain, GlobalUnknown: ownership.GlobalUnknown, Embedded: true},
		},
		RuntimeLoads: true,
		RuntimeProof: []string{"fixture#migrations.FS"},
	}
	up, down, head := migrationChecks(domain, migrations, checked(statusPass, []string{"fixture#postgres-calls"}, "fixture"), "fixture#round15")
	for name, result := range map[string]checkResult{"migration_up": up, "migration_down": down, "migration_runtime_head": head} {
		if result.Status != statusUnknown {
			t.Errorf("%s=%s, want unknown; evidence=%v reason=%s", name, result.Status, result.Evidence, result.Reason)
		}
	}
}

func TestRound15StaticIntegerFormatUsesPostgresValueSemantics(t *testing.T) {
	for source, want := range map[string]string{
		"01":   "records1",
		"+42":  "records42",
		"-007": "records-7",
		"0":    "records0",
	} {
		relevant, proven, expanded := executeFormatMayOwnOrWrite([]byte("('records%s', "+source+")"), 0)
		if relevant || !proven || string(expanded) != want {
			t.Errorf("integer %q relevant=%v proven=%v expanded=%q, want %q", source, relevant, proven, expanded, want)
		}
	}

	for _, source := range []string{"1.5", "1e2", "-0.25", "+2E+3"} {
		sql := "DO $$ BEGIN EXECUTE format('INSERT INTO public.round15_numeric_records_%s(id) VALUES (1)', " + source + "); END $$;"
		ownership := migrationOwnedObjects([]byte(sql))
		if !ownership.GlobalUnknown {
			t.Errorf("unsupported numeric %q was not global unknown: %#v", source, ownership)
		}
	}

	content := []byte(`
CREATE TABLE public.round15_numeric_static (id bigint);
DO $$ BEGIN
  EXECUTE format('CREATE TABLE public.round15_numeric_records%s (id bigint)', 01);
  EXECUTE format('CREATE TABLE public.round15_numeric_records%s (id bigint)', +42);
END $$;
`)
	ownership := migrationOwnedObjects(content)
	if ownership.GlobalUnknown || !containsString(ownership.Uncertain, "round15_numeric_records1") || !containsString(ownership.Uncertain, "round15_numeric_records42") {
		t.Fatalf("canonical integer ownership missing: %#v", ownership)
	}

	domain := domainModel{Name: "round15-numeric", Prod: []goFileFact{{Functions: []functionFact{{Strings: []string{
		"INSERT INTO public.round15_numeric_static (id) VALUES ($1)",
		"INSERT INTO public.round15_numeric_records1 (id) VALUES ($1)",
		"INSERT INTO public.round15_numeric_records42 (id) VALUES ($1)",
	}}}}}}
	migrations := migrationIndex{
		Files: []migrationFact{
			{Path: "round15-numeric.up.sql", Version: "115", Direction: "up", Owned: ownership.Owned, Uncertain: ownership.Uncertain, GlobalUnknown: ownership.GlobalUnknown, Embedded: true},
			{Path: "round15-numeric.down.sql", Version: "115", Direction: "down", Owned: ownership.Owned, Uncertain: ownership.Uncertain, GlobalUnknown: ownership.GlobalUnknown, Embedded: true},
		},
		RuntimeLoads: true,
		RuntimeProof: []string{"fixture#migrations.FS"},
	}
	up, down, head := migrationChecks(domain, migrations, checked(statusPass, []string{"fixture#postgres-calls"}, "fixture"), "fixture#round15-numeric")
	for name, result := range map[string]checkResult{"migration_up": up, "migration_down": down, "migration_runtime_head": head} {
		if result.Status != statusUnknown {
			t.Errorf("%s=%s, want unknown; evidence=%v reason=%s", name, result.Status, result.Evidence, result.Reason)
		}
	}
}
