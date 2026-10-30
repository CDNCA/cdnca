package ccv2

import (
	"errors"
	"os"
	"strings"
	"testing"
)

var countByBinding = Binding{BindingID: "018f1000-0000-7000-8000-000000000030", BindingRevision: 1,
	PublicationID: "018f1000-0000-7000-8000-000000000031"}

// The fixtures are written by control-api
// (securitypublication.TestCompileCCV2CountByMatchesAgentParityFixture):
// count_by rules for client_cidr+uri, ja4 with a count_key ban, host+uri_path
// on a leaky bucket and a client_cidr-triggered challenge.
func TestCompileSourceReproducesControlCountBy(t *testing.T) {
	source, err := os.ReadFile("testdata/count-by.source.json")
	if err != nil {
		t.Fatal(err)
	}
	want, err := os.ReadFile("testdata/count-by.compiled.json")
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

func TestCompileSourceRejectsNonCanonicalCountBy(t *testing.T) {
	raw, err := os.ReadFile("testdata/count-by.source.json")
	if err != nil {
		t.Fatal(err)
	}
	valid := string(raw)
	cidrURI := `"count_by":[{"key":"client_cidr","ipv4_prefix":24,"ipv6_prefix":64},{"key":"uri"}]`
	if !strings.Contains(valid, cidrURI) {
		t.Fatalf("fixture changed: %s", valid)
	}
	cases := map[string]string{
		"unsorted":       strings.Replace(valid, cidrURI, `"count_by":[{"key":"uri"},{"key":"client_cidr","ipv4_prefix":24,"ipv6_prefix":64}]`, 1),
		"default ip":     strings.Replace(valid, cidrURI, `"count_by":[{"key":"client_ip"}]`, 1),
		"empty":          strings.Replace(valid, cidrURI, `"count_by":[]`, 1),
		"no prefix":      strings.Replace(valid, cidrURI, `"count_by":[{"key":"client_cidr"},{"key":"uri"}]`, 1),
		"ip and cidr":    strings.Replace(valid, cidrURI, `"count_by":[{"key":"client_ip"},{"key":"client_cidr","ipv4_prefix":24,"ipv6_prefix":64}]`, 1),
		"three":          strings.Replace(valid, cidrURI, `"count_by":[{"key":"client_ip"},{"key":"host"},{"key":"uri"}]`, 1),
		"ja3":            strings.Replace(valid, cidrURI, `"count_by":[{"key":"ja3"}]`, 1),
		"prefix on uri":  strings.Replace(valid, cidrURI, `"count_by":[{"key":"uri","ipv4_prefix":24}]`, 1),
		"unknown target": strings.Replace(valid, `"action_target":"count_key"`, `"action_target":"site"`, 1),
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
