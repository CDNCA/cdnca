package httpapi

import (
	"encoding/json"
	"os"
	"path/filepath"
	"runtime"
	"strings"
	"testing"
	"time"

	"github.com/cdnca/cdnca/services/control-api/internal/site"
	"gopkg.in/yaml.v3"
)

// basic.server_timing is optional on a write
// (omitted keeps the stored value) and always present in the site detail.
func TestSiteBasicServerTiming(t *testing.T) {
	for _, item := range []struct {
		encoded string
		want    *bool
	}{{``, nil}, {`,"server_timing":true`, new(true)}, {`,"server_timing":false`, new(false)}} {
		var basic siteBasicPayload
		encoded := `{"domains":["a.example.com"],"http_enabled":true,"ipv6_enabled":false` + item.encoded + `}`
		if err := json.Unmarshal([]byte(encoded), &basic); err != nil {
			t.Fatal(err)
		}
		fields, err := fieldsFromBasic(basic)
		if err != nil {
			t.Fatalf("%s: %v", item.encoded, err)
		}
		if (fields.ServerTiming == nil) != (item.want == nil) || fields.ServerTiming != nil && *fields.ServerTiming != *item.want {
			t.Fatalf("%s: ServerTiming = %v, want %v", item.encoded, fields.ServerTiming, item.want)
		}
	}
	for _, enabled := range []bool{false, true} {
		raw, err := json.Marshal(siteDetailAt(site.Site{ServerTiming: enabled}, time.Now()))
		if err != nil {
			t.Fatal(err)
		}
		want := `"server_timing":false`
		if enabled {
			want = `"server_timing":true`
		}
		if !strings.Contains(string(raw), want) {
			t.Fatalf("detail with server_timing=%v lacks %s", enabled, want)
		}
	}
}

func TestSiteBasicOpenAPIServerTiming(t *testing.T) {
	_, filename, _, _ := runtime.Caller(0)
	source, err := os.ReadFile(filepath.Join(filepath.Dir(filename), "../../../../api/openapi/v1/sites.yaml"))
	if err != nil {
		t.Fatal(err)
	}
	var document struct {
		Components struct {
			Schemas map[string]struct {
				Properties map[string]struct {
					Type        any    `yaml:"type"`
					Description string `yaml:"description"`
				} `yaml:"properties"`
			} `yaml:"schemas"`
		} `yaml:"components"`
	}
	if err := yaml.Unmarshal(source, &document); err != nil {
		t.Fatal(err)
	}
	property, ok := document.Components.Schemas["SiteBasic"].Properties["server_timing"]
	if !ok || property.Type != "boolean" || !strings.Contains(property.Description, "SITE_SERVER_TIMING") ||
		!strings.Contains(property.Description, "site.server_timing.update") {
		t.Fatalf("SiteBasic.server_timing = %+v (present %v)", property, ok)
	}
}
