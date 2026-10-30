package main

import (
	"strings"
	"testing"
)

func TestRound18FormatCommentsPreserveObjectScopedOwnership(t *testing.T) {
	tests := map[string]string{
		"before-call": `format /* function-call trivia */ (
			'INSERT INTO public.%I(payload) VALUES (%L)',
			'round18_before_call_records', dynamic_value)`,
		"before-template-and-arguments": `format(
			/* template */ 'INSERT INTO public.%I(payload) VALUES (%L)',
			/* object */ 'round18_argument_records',
			/* payload */ dynamic_value)`,
		"nested-block-comment": `format(/* outer /* nested */ comment */
			'INSERT INTO public.%I(payload) VALUES (%L)',
			'round18_nested_comment_records', dynamic_value)`,
		"line-comment-concatenation": `format(
			'INSERT INTO public.%I(payload) VALUES (%L)',
			'round18_line_' -- PostgreSQL concatenates literals across a newline
			'comment_concatenation_records', dynamic_value)`,
	}
	for name, expression := range tests {
		t.Run(name, func(t *testing.T) {
			content := []byte("CREATE TABLE public.round18_static_records (id bigint); DO $$ BEGIN EXECUTE " + expression + "; END $$;")
			ownership := migrationOwnedObjects(content)
			wantObject := "round18_" + strings.ReplaceAll(name, "-", "_") + "_records"
			if name == "before-template-and-arguments" {
				wantObject = "round18_argument_records"
			}
			if name == "nested-block-comment" {
				wantObject = "round18_nested_comment_records"
			}
			if name == "line-comment-concatenation" {
				wantObject = "round18_line_comment_concatenation_records"
			}
			if ownership.GlobalUnknown || strings.Join(ownership.Owned, ",") != "round18_static_records" ||
				strings.Join(ownership.Uncertain, ",") != wantObject {
				t.Fatalf("commented format ownership = %#v, want object-local uncertainty for %s", ownership, wantObject)
			}
		})
	}

	dynamicObject := migrationOwnedObjects([]byte(`DO $$ BEGIN
		EXECUTE format(/* template */ 'INSERT INTO public.%I(payload) VALUES (%L)', dynamic_table, dynamic_value);
	END $$;`))
	if !dynamicObject.GlobalUnknown {
		t.Fatalf("dynamic identifier became statically owned through comments: %#v", dynamicObject)
	}
}

func TestRound18FormatArgumentCommentsCannotForgeStaticIdentifiers(t *testing.T) {
	arguments := map[string]string{
		"block-comment":     `coalesce(dynamic_value /* ), 'round18_forged_records', */, fallback_value)`,
		"quoted-identifier": `coalesce("dynamic), 'round18_forged_records',", fallback_value)`,
		"array-constructor": `ARRAY[dynamic_value, 'round18_forged_records', fallback_value]`,
	}
	for name, firstArgument := range arguments {
		t.Run(name, func(t *testing.T) {
			content := []byte(`DO $$ BEGIN
				EXECUTE format(
					'INSERT INTO public.%2$I(payload) VALUES (%3$L)', ` + firstArgument + `,
					dynamic_table,
					dynamic_value
				);
			END $$;`)
			ownership := migrationOwnedObjects(content)
			if !ownership.GlobalUnknown {
				t.Fatalf("%s punctuation forged a static format identifier: %#v", name, ownership)
			}
		})
	}
}

func TestRound18MixedStaticFormatPrefixPreservesExecutableContext(t *testing.T) {
	templates := map[string]string{
		"ordinary":   `format('%s %L', 'DO', dynamic_body)`,
		"positional": `format('%2$s %1$L', dynamic_body, 'DO')`,
		"fragmented": `format('%s%s %L', 'D', 'O', dynamic_body)`,
	}
	for name, expression := range templates {
		t.Run(name, func(t *testing.T) {
			content := []byte("DO $$ BEGIN EXECUTE " + expression + "; END $$;")
			ownership := migrationOwnedObjects(content)
			if !ownership.GlobalUnknown {
				t.Fatalf("static executable prefix hid dynamic body ownership: %#v", ownership)
			}
		})
	}
}
