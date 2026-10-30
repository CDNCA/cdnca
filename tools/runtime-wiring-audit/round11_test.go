package main

import "testing"

func TestRound11DeferredExecutionRejectsUnprovenNamedCalls(t *testing.T) {
	const fixture = "services/control-api/internal/controlflowroutes/round11_defer.go"
	reject := map[string]bool{
		"/adj-defer-named-block":      true,
		"/adj-defer-named-exit":       true,
		"/adj-defer-interface-method": true,
		"/adj-after-goexit":           true,
	}
	var foundRejects []string
	for _, route := range fixtureRoutes(t, fixture) {
		if reject[route.Path] {
			foundRejects = append(foundRejects, route.Path)
		}
	}
	if len(foundRejects) != 0 {
		t.Fatalf("unproven or unreachable routes became pass: %v", foundRejects)
	}

	for _, positive := range []struct {
		fixture string
		path    string
	}{
		{"services/control-api/internal/controlflowroutes/round8_scheduled.go", "/round8-defer-return"},
		{"services/control-api/internal/controlflowroutes/round10_scheduled.go", "/round10-defer-goexit"},
		{"services/control-api/internal/controlflowroutes/router.go", "/defer-stable-local"},
		{"services/control-api/internal/controlflowroutes/round8_scheduled.go", "/round8-dead-mutator"},
	} {
		found := false
		for _, route := range fixtureRoutes(t, positive.fixture) {
			found = found || route.Path == positive.path
		}
		if !found {
			t.Fatalf("proven route %s missing from %s", positive.path, positive.fixture)
		}
	}
}

func TestRound11ExecuteFormatDynamicCommandPrefixesAreGlobalUnknown(t *testing.T) {
	for _, expression := range []string{
		"format('/* prefix */ %s', dynamic_sql)",
		"format('-- prefix\\n%s', dynamic_sql)",
		"format('CREATE %s', dynamic_sql)",
		"format('WITH seed AS (SELECT 1) %s', dynamic_sql)",
	} {
		content := []byte("DO $$ BEGIN EXECUTE " + expression + "; END $$;")
		ownership := migrationOwnedObjects(content)
		if !ownership.GlobalUnknown {
			t.Fatalf("dynamic command template %q was not global unknown: %#v", expression, ownership)
		}
	}
}

func TestRound11DynamicFormatPrefixDoesNotHideUncoveredDomainWrite(t *testing.T) {
	report := fixtureReport(t)
	for _, check := range []string{"migration_up", "migration_down", "migration_runtime_head"} {
		assertStatus(t, report, "doformatcommand", check, statusUnknown)
	}
}
