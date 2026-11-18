package geoarea

import (
	"fmt"
	"os"
	"strings"
	"testing"
)

// webMirror is the console's copy of Areas (apps/web reads areas from it).
const webMirror = "../../apps/web/src/api/geoAreas.ts"

func renderWebMirror() string {
	var out strings.Builder
	out.WriteString("// Generated from libs/geoarea/geoarea.go Areas; do not edit. After changing the areas run\n")
	out.WriteString("//   GEOAREA_WRITE_WEB=1 GOWORK=off go -C libs/geoarea test -run TestWebMirror\n")
	out.WriteString("// (TestWebMirror fails while this file and Areas differ).\n\n")
	out.WriteString("export type GeoAreaLevel = 'global' | 'continent' | 'region'\n\n")
	out.WriteString("export interface GeoArea {\n  code: string\n  name_zh: string\n  name_en: string\n  level: GeoAreaLevel\n")
	out.WriteString("  /** The continent of a region; '' otherwise. */\n  parent: string\n")
	out.WriteString("  /** ISO 3166-1 alpha-2; empty for global, which covers every country; a continent's is its regions' union. */\n")
	out.WriteString("  countries: readonly string[]\n}\n\n")
	out.WriteString("export const geoAreas: readonly GeoArea[] = [\n")
	for _, area := range Areas {
		quoted := make([]string, len(area.Countries))
		for index, country := range area.Countries {
			quoted[index] = fmt.Sprintf("'%s'", country)
		}
		fmt.Fprintf(&out, "  { code: '%s', name_zh: '%s', name_en: '%s', level: '%s', parent: '%s', countries: [%s] },\n",
			area.Code, area.NameZH, area.NameEN, area.Level, area.Parent, strings.Join(quoted, ", "))
	}
	out.WriteString("]\n")
	return out.String()
}

// TestWebMirror: the console mirror is exactly Areas, in order. With
// GEOAREA_WRITE_WEB=1 it rewrites the mirror instead.
func TestWebMirror(t *testing.T) {
	want := renderWebMirror()
	if os.Getenv("GEOAREA_WRITE_WEB") == "1" {
		if err := os.WriteFile(webMirror, []byte(want), 0o644); err != nil {
			t.Fatal(err)
		}
	}
	got, err := os.ReadFile(webMirror)
	if err != nil {
		t.Fatal(err)
	}
	if string(got) != want {
		t.Fatalf("%s differs from Areas; run GEOAREA_WRITE_WEB=1 GOWORK=off go -C libs/geoarea test -run TestWebMirror", webMirror)
	}
}
