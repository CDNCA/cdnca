package main

import (
	"strings"
	"testing"
)

func TestRound16ReturnedAliasesAndDefinitionKills(t *testing.T) {
	const fixture = "services/control-api/internal/controlflowroutes/round16_receiver.go"
	reject := map[string]bool{
		"/round16-returned-receiver-alias":  true,
		"/round16-returned-local-alias":     true,
		"/round16-iife-returned-alias":      true,
		"/round16-recursive-returned-alias": true,
		"/round16-mutual-returned-alias":    true,
	}
	want := map[string]bool{
		"/round16-overwritten-alias":    false,
		"/round16-shadowed-alias":       false,
		"/round16-observe-method-value": false,
	}
	for _, route := range fixtureRoutes(t, fixture) {
		if reject[route.Path] {
			t.Errorf("returned receiver alias left deferred route proven: %#v", route)
		}
		if _, expected := want[route.Path]; expected {
			want[route.Path] = true
		}
	}
	for path, found := range want {
		if !found {
			t.Errorf("stable receiver route %s missing", path)
		}
	}
}

func TestRound16ReceivesInEveryExpressionContextBlockDefers(t *testing.T) {
	const fixture = "services/control-api/internal/controlflowroutes/round16_receiver.go"
	reject := map[string]bool{
		"/round16-assigned-receive":            true,
		"/round16-comma-ok-receive":            true,
		"/round16-return-receive":              true,
		"/round16-if-receive":                  true,
		"/round16-call-argument-receive":       true,
		"/round16-go-argument-receive":         true,
		"/round16-panic-receive":               true,
		"/round16-consumed-completion-receive": true,
	}
	foundProven := false
	for _, route := range fixtureRoutes(t, fixture) {
		if reject[route.Path] {
			t.Errorf("unproven receive left deferred route proven: %#v", route)
		}
		foundProven = foundProven || route.Path == "/round16-proven-local-receive"
	}
	if !foundProven {
		t.Fatal("proven local receive route regressed")
	}
}

func TestRound16PartialStaticFormatKeepsObjectUncertain(t *testing.T) {
	formats := map[string]string{
		"identifier": "format('INSERT INTO public.%I(payload) VALUES (%L)', 'round16_identifier_table', dynamic_value)",
		"string":     "format('INSERT INTO public.%s(payload) VALUES (%L)', 'round16_string_table', dynamic_value)",
		"positional": "format('INSERT INTO public.%1$I(payload) VALUES (%2$L)', 'round16_positional_table', dynamic_value)",
	}
	for name, format := range formats {
		t.Run(name, func(t *testing.T) {
			content := []byte("CREATE TABLE public.round16_static_records (id bigint); DO $$ BEGIN EXECUTE " + format + "; END $$;")
			ownership := migrationOwnedObjects(content)
			wantObject := "round16_" + name + "_table"
			if ownership.GlobalUnknown || strings.Join(ownership.Owned, ",") != "round16_static_records" ||
				strings.Join(ownership.Uncertain, ",") != wantObject {
				t.Fatalf("partial static format ownership = %#v, want object-local uncertainty for %s", ownership, wantObject)
			}

			domain := domainModel{Name: "round16-" + name, Prod: []goFileFact{{Functions: []functionFact{{Strings: []string{
				"INSERT INTO public.round16_static_records (id) VALUES ($1)",
				"INSERT INTO public." + wantObject + " (payload) VALUES ($1)",
			}}}}}}
			migrations := migrationIndex{
				Files: []migrationFact{
					{Path: name + ".up.sql", Version: "116", Direction: "up", Owned: ownership.Owned, Uncertain: ownership.Uncertain, GlobalUnknown: ownership.GlobalUnknown, Embedded: true},
					{Path: name + ".down.sql", Version: "116", Direction: "down", Owned: ownership.Owned, Uncertain: ownership.Uncertain, GlobalUnknown: ownership.GlobalUnknown, Embedded: true},
				},
				RuntimeLoads: true,
				RuntimeProof: []string{"fixture#migrations.FS"},
			}
			up, down, head := migrationChecks(domain, migrations, checked(statusPass, []string{"fixture#postgres-calls"}, "fixture"), "fixture#round16")
			for check, result := range map[string]checkResult{"migration_up": up, "migration_down": down, "migration_runtime_head": head} {
				if result.Status != statusUnknown {
					t.Errorf("%s=%s, want unknown; evidence=%v reason=%s", check, result.Status, result.Evidence, result.Reason)
				}
			}
		})
	}
}
