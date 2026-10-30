package ccv2

import (
	"errors"
	"os"
	"strings"
	"testing"
)

// fix-ja4rule ③ (CC API v7): the fixtures are written by control-api
// (securitypublication.TestCompileCCV2MatchKeysMatchesAgentParityFixture):
// count_by user_agent, header x-api-key + uri_path, cookie sid + query token,
// and a rule matching on two JA4 fingerprints.
func TestCompileSourceReproducesControlMatchKeys(t *testing.T) {
	source, err := os.ReadFile("testdata/match-keys.source.json")
	if err != nil {
		t.Fatal(err)
	}
	want, err := os.ReadFile("testdata/match-keys.compiled.json")
	if err != nil {
		t.Fatal(err)
	}
	got, err := CompileSource(source, countByBinding)
	if err != nil {
		t.Fatalf("CompileSource: %v", err)
	}
	if string(got) != string(want) {
		t.Fatalf("edge compile differs from control compile:\n got %s\nwant %s", got, want)
	}
}

func TestCompileSourceRejectsNonCanonicalMatchKeys(t *testing.T) {
	raw, err := os.ReadFile("testdata/match-keys.source.json")
	if err != nil {
		t.Fatal(err)
	}
	valid := string(raw)
	header := `{"key":"header","name":"x-api-key"}`
	ja4 := `"values":["t13d1516h2_8daaf6152771_e5627efa2ab1","t13d3112h2_e8f1e7e78f70_6bebaf5329ac"]`
	for _, fragment := range []string{header, ja4} {
		if !strings.Contains(valid, fragment) {
			t.Fatalf("fixture changed, lacks %s: %s", fragment, valid)
		}
	}
	cases := map[string]string{
		"header upper":   strings.Replace(valid, header, `{"key":"header","name":"X-Api-Key"}`, 1),
		"header no name": strings.Replace(valid, header, `{"key":"header"}`, 1),
		"ua with name":   strings.Replace(valid, `{"key":"user_agent"}`, `{"key":"user_agent","name":"x"}`, 1),
		"bad cookie":     strings.Replace(valid, `{"key":"cookie","name":"sid"}`, `{"key":"cookie","name":"s d"}`, 1),
		"ja4 malformed":  strings.Replace(valid, ja4, `"values":["forged"]`, 1),
		"ja4 unsorted":   strings.Replace(valid, ja4, `"values":["t13d3112h2_e8f1e7e78f70_6bebaf5329ac","t13d1516h2_8daaf6152771_e5627efa2ab1"]`, 1),
		"ja4 not_in":     strings.Replace(valid, `"field":"ja4","operator":"in"`, `"field":"ja4","operator":"not_in"`, 1),
	}
	for name, source := range cases {
		t.Run(name, func(t *testing.T) {
			if source == valid {
				t.Fatal("mutation did not apply")
			}
			if _, err := CompileSource([]byte(source), countByBinding); !errors.Is(err, ErrInvalidSource) {
				t.Fatalf("error = %v, want ErrInvalidSource", err)
			}
		})
	}
}
