package main

import (
	"sort"
	"strings"
	"testing"
)

func TestRound12DeferredExecutionModelsArgumentAndGoEvaluation(t *testing.T) {
	const fixture = "services/control-api/internal/controlflowroutes/round12_defer.go"
	want := map[string]bool{
		"/round12-panic-literal":            false,
		"/round12-panic-pure-helper":        false,
		"/round12-panic-nested-helper":      false,
		"/round12-panic-conversion-builtin": false,
		"/round12-go-named-block":           false,
		"/round12-go-iife-block":            false,
		"/round12-simple-helper":            false,
	}
	reject := map[string]bool{
		"/round12-panic-blocked-argument": true,
		"/round12-panic-exit-argument":    true,
		"/round12-go-blocked-argument":    true,
		"/round12-recursive-helper":       true,
	}
	var foundRejects []string
	for _, route := range fixtureRoutes(t, fixture) {
		if reject[route.Path] {
			foundRejects = append(foundRejects, route.Path)
		}
		if _, ok := want[route.Path]; ok {
			want[route.Path] = true
		}
	}
	sort.Strings(foundRejects)
	if len(foundRejects) != 0 {
		t.Errorf("unproven routes became pass: %v", foundRejects)
	}
	for path, found := range want {
		if !found {
			t.Errorf("proven route %s missing", path)
		}
	}
}

func TestRound12StaticFormatSubstitutionsStayObjectScoped(t *testing.T) {
	tests := []struct {
		name       string
		expression string
		objects    []string
	}{
		{"literal", "format('%s', 'CREATE TABLE public.static_format_records (id bigint)')", []string{"static_format_records"}},
		{"position", "format('%1$s', 'CREATE TABLE public.position_format_records (id bigint)')", []string{"position_format_records"}},
		{"multiple", "format('%s %s', 'CREATE TABLE public.multi_a_records (id bigint);', 'CREATE TABLE public.multi_b_records (id bigint);')", []string{"multi_a_records", "multi_b_records"}},
		{"width", "format('%80s', 'CREATE TABLE public.width_format_records (id bigint)')", []string{"width_format_records"}},
		{"precision", "format('%.80s', 'CREATE TABLE public.precision_format_records (id bigint)')", []string{"precision_format_records"}},
		{"uppercase", "FORMAT('%s', 'CREATE TABLE public.upper_format_records (id bigint)')", []string{"upper_format_records"}},
	}
	for _, test := range tests {
		t.Run(test.name, func(t *testing.T) {
			ownership := migrationOwnedObjects([]byte("DO $$ BEGIN EXECUTE " + test.expression + "; END $$;"))
			if ownership.GlobalUnknown {
				t.Fatalf("static format became global unknown: %#v", ownership)
			}
			got := append([]string(nil), ownership.Uncertain...)
			sort.Strings(got)
			if strings.Join(got, ",") != strings.Join(test.objects, ",") {
				t.Fatalf("objects=%v, want %v; ownership=%#v", got, test.objects, ownership)
			}
		})
	}
}

func TestRound12DynamicFormatAndEscapedPlaceholderBoundaries(t *testing.T) {
	for _, expression := range []string{
		"format('%s', dynamic_sql)",
		"format('%s %s', 'SELECT 1;', dynamic_sql)",
		"format('%s', 'CREATE ' || dynamic_sql)",
		"format('%s', format('%s', dynamic_sql))",
	} {
		ownership := migrationOwnedObjects([]byte("DO $$ BEGIN EXECUTE " + expression + "; END $$;"))
		if !ownership.GlobalUnknown {
			t.Fatalf("dynamic format %q was not global unknown: %#v", expression, ownership)
		}
	}

	for _, expression := range []string{
		"format('%%s', dynamic_sql)",
		"format('%%%%s', dynamic_sql)",
		"format('%I', dynamic_identifier)",
		"format('%L', dynamic_literal)",
	} {
		ownership := migrationOwnedObjects([]byte("DO $$ BEGIN EXECUTE " + expression + "; END $$;"))
		if ownership.GlobalUnknown {
			t.Fatalf("non-raw placeholder %q became global unknown: %#v", expression, ownership)
		}
	}
}

func TestRound12AdjacentTriggerFormatLiteralsStayObjectScoped(t *testing.T) {
	content := []byte(`
DO $$
BEGIN
  EXECUTE format(
    'CREATE TRIGGER %I_append_only BEFORE UPDATE OR DELETE ON %I '
    'FOR EACH ROW EXECUTE FUNCTION protect_row()',
    table_name, table_name
  );
END
$$;
`)
	ownership := migrationOwnedObjects(content)
	if ownership.GlobalUnknown {
		t.Fatalf("adjacent trigger format literals became global unknown: %#v", ownership)
	}
}

func TestRound12StaticFormatExpansionIsBounded(t *testing.T) {
	literal := strings.Repeat("x", 5000)
	expression := "format('%s', '" + literal + "')"
	ownership := migrationOwnedObjects([]byte("DO $$ BEGIN EXECUTE " + expression + "; END $$;"))
	if !ownership.GlobalUnknown {
		t.Fatalf("oversized format expansion was not conservative unknown: %#v", ownership)
	}
}
