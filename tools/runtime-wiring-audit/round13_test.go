package main

import (
	"os"
	"path/filepath"
	"sort"
	"strings"
	"testing"
)

func TestRound13DeferredReceiverStabilityIncludesCalleeSideEffects(t *testing.T) {
	const fixture = "services/control-api/internal/controlflowroutes/round13_receiver.go"
	want := map[string]bool{
		"/round13-defer-pure-helper": false,
	}
	reject := map[string]bool{
		"/round13-defer-shared-reset": true,
		"/round13-defer-method-reset": true,
		"/round13-defer-go-factory":   true,
	}
	for _, route := range fixtureRoutes(t, fixture) {
		if reject[route.Path] {
			t.Errorf("callee side effect left deferred receiver proven: %#v", route)
		}
		if _, ok := want[route.Path]; ok {
			want[route.Path] = true
		}
	}
	for path, found := range want {
		if !found {
			t.Errorf("pure helper route %s missing", path)
		}
	}

	foundBlockingGo := false
	for _, route := range fixtureRoutes(t, "services/control-api/internal/controlflowroutes/round12_defer.go") {
		foundBlockingGo = foundBlockingGo || route.Path == "/round12-go-named-block"
	}
	if !foundBlockingGo {
		t.Error("Round12 GoStmt blocking-callee route regressed")
	}
}

func TestRound13SimpleHelperLimitCountsCallGraphHops(t *testing.T) {
	const fixture = "services/control-api/internal/controlflowroutes/round13_receiver.go"
	found16 := false
	for _, route := range fixtureRoutes(t, fixture) {
		found16 = found16 || route.Path == "/round13-helper-depth-16"
		if route.Path == "/round13-helper-depth-17" {
			t.Fatalf("17-hop helper chain was treated as proven: %#v", route)
		}
	}
	if !found16 {
		t.Fatal("16-hop helper chain was rejected before its documented boundary")
	}
}

func TestRound13DynamicExecutableLiteralIsGlobalUnknown(t *testing.T) {
	for _, expression := range []string{
		"format('DO %L', dynamic_body)",
		"format('EXECUTE %L', dynamic_body)",
		"format('%s', format('DO %L', dynamic_body))",
	} {
		ownership := migrationOwnedObjects([]byte("DO $$ BEGIN EXECUTE " + expression + "; END $$;"))
		if !ownership.GlobalUnknown {
			t.Errorf("dynamic executable literal %q was not global unknown: %#v", expression, ownership)
		}
	}

	dataOnly := migrationOwnedObjects([]byte("DO $$ BEGIN EXECUTE format('INSERT INTO public.round13_data_records(payload) VALUES (%L)', dynamic_value); END $$;"))
	if dataOnly.GlobalUnknown {
		t.Fatalf("ordinary dynamic data literal contaminated ownership: %#v", dataOnly)
	}

	staticBody := migrationOwnedObjects([]byte("DO $$ BEGIN EXECUTE format('DO %L', 'BEGIN CREATE TABLE public.round13_static_body_records (id bigint); END'); END $$;"))
	if staticBody.GlobalUnknown || !containsString(staticBody.Uncertain, "round13_static_body_records") {
		t.Fatalf("static DO body was not scanned object-locally: %#v", staticBody)
	}
}

func TestRound13DynamicDoBodyKeepsMigrationChecksUnknown(t *testing.T) {
	fixtureRoot := filepath.Join("..", "..", "tests", "runtime-wiring-audit", "fixtures", "sql")
	readOwnership := func(name string) migrationOwnership {
		content, err := os.ReadFile(filepath.Join(fixtureRoot, name))
		if err != nil {
			t.Fatal(err)
		}
		return migrationOwnedObjects(content)
	}
	upOwnership := readOwnership("round13_do_format_body.up.sql")
	downOwnership := readOwnership("round13_do_format_body.down.sql")
	if !upOwnership.GlobalUnknown || !downOwnership.GlobalUnknown {
		t.Fatalf("dynamic DO body was not global unknown: up=%#v down=%#v", upOwnership, downOwnership)
	}

	domain := domainModel{Name: "round13", Prod: []goFileFact{{Functions: []functionFact{{Strings: []string{
		"INSERT INTO public.round13_static_records (id) VALUES ($1)",
		"INSERT INTO public.round13_dynamic_records (id) VALUES ($1)",
	}}}}}}
	migrations := migrationIndex{
		Files: []migrationFact{
			{Path: "fixtures/sql/round13_do_format_body.up.sql", Version: "113", Direction: "up", Owned: upOwnership.Owned, Uncertain: upOwnership.Uncertain, GlobalUnknown: upOwnership.GlobalUnknown, Embedded: true},
			{Path: "fixtures/sql/round13_do_format_body.down.sql", Version: "113", Direction: "down", Owned: downOwnership.Owned, Uncertain: downOwnership.Uncertain, GlobalUnknown: downOwnership.GlobalUnknown, Embedded: true},
		},
		RuntimeLoads: true,
		RuntimeProof: []string{"fixture#migrations.FS"},
	}
	up, down, head := migrationChecks(domain, migrations, checked(statusPass, []string{"fixture#postgres-calls"}, "fixture"), "fixture#round13")
	for name, result := range map[string]checkResult{"migration_up": up, "migration_down": down, "migration_runtime_head": head} {
		if result.Status != statusUnknown {
			t.Errorf("%s=%s, want unknown; evidence=%v reason=%s", name, result.Status, result.Evidence, result.Reason)
		}
	}
}

func TestRound13StaticFormatLiteralKindsAndBounds(t *testing.T) {
	content := []byte("('VALUES (%s,%s,%s,%s)', NULL, 42, true, 'x'\n'y', 'unused')")
	relevant, proven, expanded := executeFormatMayOwnOrWrite(content, 0)
	if relevant || !proven || string(expanded) != "VALUES (,42,t,xy)" {
		t.Fatalf("static scalar expansion relevant=%v proven=%v expanded=%q", relevant, proven, expanded)
	}

	arguments := func(count int) string {
		values := make([]string, count)
		for index := range values {
			values[index] = "'x'"
		}
		return strings.Join(values, ",")
	}
	for count, wantGlobal := range map[int]bool{16: false, 17: true} {
		expression := "format('%1$s'," + arguments(count) + ")"
		ownership := migrationOwnedObjects([]byte("DO $$ BEGIN EXECUTE " + expression + "; END $$;"))
		if ownership.GlobalUnknown != wantGlobal {
			t.Errorf("%d static arguments GlobalUnknown=%v, want %v: %#v", count, ownership.GlobalUnknown, wantGlobal, ownership)
		}
	}

	objects := migrationOwnedObjects([]byte("DO $$ BEGIN EXECUTE format('%s', 'CREATE '\n'TABLE public.round13_adjacent_arg_records (id bigint)', NULL, 1, false); END $$;"))
	got := append([]string(nil), objects.Uncertain...)
	sort.Strings(got)
	if objects.GlobalUnknown || strings.Join(got, ",") != "round13_adjacent_arg_records" {
		t.Fatalf("adjacent argument or extra scalar args were not static: %#v", objects)
	}

	for size, wantGlobal := range map[int]bool{4096: false, 4097: true} {
		expression := "format('%s', '" + strings.Repeat("x", size) + "')"
		ownership := migrationOwnedObjects([]byte("DO $$ BEGIN EXECUTE " + expression + "; END $$;"))
		if ownership.GlobalUnknown != wantGlobal {
			t.Errorf("%d-byte expansion GlobalUnknown=%v, want %v", size, ownership.GlobalUnknown, wantGlobal)
		}
	}
}
