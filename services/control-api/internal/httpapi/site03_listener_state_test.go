package httpapi

import (
	"errors"
	"os"
	"path/filepath"
	"runtime"
	"strings"
	"testing"

	"github.com/cdnca/cdnca/services/control-api/internal/site"
)

func TestSITE03HTTPProjectsTypedIPv6DesiredAndRuntimeState(t *testing.T) {
	fields, err := fieldsFromBasic(siteBasicPayload{
		Domains: []string{"listener.example.test"}, HTTPEnabled: true,
		HTTPListenPorts: []string{"80"}, IPv6Enabled: true,
	})
	if err != nil || !fields.IPv6Enabled {
		t.Fatalf("fieldsFromBasic IPv6 desired = (%t, %v), want (true, nil)", fields.IPv6Enabled, err)
	}

	response := siteDetail(site.Site{
		ListenerState: site.ListenerState{
			IPv6DesiredEnabled: true,
			IPv6RuntimeState:   site.IPv6RuntimePending,
		},
	})
	if !response.Basic.IPv6Enabled || response.ListenerState.IPv6RuntimeState != site.IPv6RuntimePending ||
		!response.ListenerState.IPv6DesiredEnabled {
		t.Fatalf("site detail listener state = %+v basic=%+v", response.ListenerState, response.Basic)
	}
}

func TestSITE03HTTPRequiresExplicitIPv6DesiredState(t *testing.T) {
	for _, test := range []struct {
		name    string
		payload string
		want    bool
	}{
		{"missing", `{"domains":["listener.example.test"],"http_enabled":true}`, false},
		{"disabled", `{"domains":["listener.example.test"],"http_enabled":true,"ipv6_enabled":false}`, true},
	} {
		t.Run(test.name, func(t *testing.T) {
			var payload siteBasicPayload
			if err := decodeSiteJSON([]byte(test.payload), &payload); err != nil {
				t.Fatal(err)
			}
			_, err := fieldsFromBasic(payload)
			if test.want && err != nil {
				t.Fatalf("fieldsFromBasic() error = %v", err)
			}
			if !test.want && !errors.Is(err, site.ErrInvalidInput) {
				t.Fatalf("fieldsFromBasic() error = %v, want ErrInvalidInput", err)
			}
		})
	}
}

func TestSITE03OpenAPIRequiresIPv6DesiredAndReadOnlyRuntimeState(t *testing.T) {
	_, filename, _, ok := runtime.Caller(0)
	if !ok {
		t.Fatal("resolve test path")
	}
	source, err := os.ReadFile(filepath.Join(filepath.Dir(filename), "../../../../api/openapi/v1/sites.yaml"))
	if err != nil {
		t.Fatal(err)
	}
	for _, required := range []string{
		"ipv6_enabled",
		"listener_state",
		"IPv6RuntimeState",
		"enum: [disabled, pending, active, failed]",
		"readOnly: true",
	} {
		if !strings.Contains(string(source), required) {
			t.Errorf("SITE-03 OpenAPI contract missing %q", required)
		}
	}
}
