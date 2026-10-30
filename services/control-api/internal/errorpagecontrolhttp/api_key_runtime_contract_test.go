package errorpagecontrolhttp

import (
	"os"
	"strings"
	"testing"
)

func TestRuntimeAdapterRequiresAPIKeyAuthenticationDependency(t *testing.T) {
	source, err := os.ReadFile("runtime.go")
	if err != nil {
		t.Fatal(err)
	}
	text := string(source)
	for _, required := range []string{
		"APIKeys          *apikey.Service",
		"dependencies.APIKeys == nil",
		"APIKeys: dependencies.APIKeys",
	} {
		if !strings.Contains(text, required) {
			t.Errorf("runtime adapter is missing %q", required)
		}
	}
}
