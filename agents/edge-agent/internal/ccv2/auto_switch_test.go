package ccv2

import (
	"errors"
	"os"
	"strings"
	"testing"
)

// The fixtures are written by control-api
// (securitypublication.TestCompileCCV2AutoSwitchMatchesAgentParityFixture): a
// rate limit with site-level ban, an auto switch to a JS challenge.
func TestCompileSourceReproducesControlAutoSwitch(t *testing.T) {
	source, err := os.ReadFile("testdata/auto-switch.source.json")
	if err != nil {
		t.Fatal(err)
	}
	want, err := os.ReadFile("testdata/auto-switch.compiled.json")
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

func TestCompileSourceRejectsInvalidAutoSwitch(t *testing.T) {
	raw, err := os.ReadFile("testdata/auto-switch.source.json")
	if err != nil {
		t.Fatal(err)
	}
	valid := string(raw)
	header := `"auto_switch":{"qps_total":200,"qps_5xx":20,"recover_seconds":300,`
	if !strings.Contains(valid, header) {
		t.Fatalf("fixture changed: %s", valid)
	}
	cases := map[string]string{
		"no threshold":  strings.Replace(valid, header, `"auto_switch":{"qps_total":0,"qps_5xx":0,"recover_seconds":300,`, 1),
		"short recover": strings.Replace(valid, header, `"auto_switch":{"qps_total":200,"qps_5xx":20,"recover_seconds":59,`, 1),
		"negative qps":  strings.Replace(valid, header, `"auto_switch":{"qps_total":-1,"qps_5xx":20,"recover_seconds":300,`, 1),
		"shared rule id": strings.Replace(valid, `"id":"018f1000-0000-7000-8000-000000000042"`,
			`"id":"018f1000-0000-7000-8000-000000000041"`, 1),
		"unknown field": strings.Replace(valid, header, header+`"mode":"custom",`, 1),
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
