package main

import "testing"

func TestRound14DeferredReceiverRejectsUnknownImportedMethod(t *testing.T) {
	const fixture = "services/control-api/internal/controlflowroutes/round14_receiver.go"
	want := map[string]bool{"/round14-pure-local-method": false}
	for _, route := range fixtureRoutes(t, fixture) {
		if route.Path == "/round14-imported-method-reset" {
			t.Errorf("unknown imported method left holder receiver proven: %#v", route)
		}
		if _, ok := want[route.Path]; ok {
			want[route.Path] = true
		}
	}
	for path, found := range want {
		if !found {
			t.Errorf("proven pure method route %s missing", path)
		}
	}
}

func TestRound14FactoryReturnedMutatorEscapeInvalidatesReceiver(t *testing.T) {
	const fixture = "services/control-api/internal/controlflowroutes/round14_receiver.go"
	want := map[string]bool{"/round14-pure-factory": false}
	reject := map[string]bool{
		"/round14-factory-global":    true,
		"/round14-factory-field":     true,
		"/round14-factory-index":     true,
		"/round14-factory-container": true,
		"/round14-factory-helper":    true,
	}
	for _, route := range fixtureRoutes(t, fixture) {
		if reject[route.Path] {
			t.Errorf("factory-returned mutator escape left receiver proven: %#v", route)
		}
		if _, ok := want[route.Path]; ok {
			want[route.Path] = true
		}
	}
	for path, found := range want {
		if !found {
			t.Errorf("pure factory route %s missing", path)
		}
	}

	for _, route := range fixtureRoutes(t, "services/control-api/internal/controlflowroutes/round13_receiver.go") {
		if route.Path == "/round13-defer-go-factory" {
			t.Fatal("Round13 directly executed factory mutator regressed")
		}
	}
}

func TestRound14StaticFormatNullLiteralSemantics(t *testing.T) {
	content := []byte("('VALUES (%L,%L,%s,%s,%s)', NULL, 'O''Reilly', NULL, 42, true)")
	relevant, proven, expanded := executeFormatMayOwnOrWrite(content, 0)
	const want = "VALUES (NULL,'O''Reilly',,42,t)"
	if relevant || !proven || string(expanded) != want {
		t.Fatalf("static format relevant=%v proven=%v expanded=%q, want %q", relevant, proven, expanded, want)
	}

	dynamicBody := migrationOwnedObjects([]byte("DO $$ BEGIN EXECUTE format('DO %L', dynamic_body); END $$;"))
	if !dynamicBody.GlobalUnknown {
		t.Fatalf("dynamic executable %%L regressed: %#v", dynamicBody)
	}
	dataOnly := migrationOwnedObjects([]byte("DO $$ BEGIN EXECUTE format('INSERT INTO public.round14_records(payload) VALUES (%L)', dynamic_value); END $$;"))
	if dataOnly.GlobalUnknown {
		t.Fatalf("ordinary dynamic data %%L contaminated ownership: %#v", dataOnly)
	}
}
