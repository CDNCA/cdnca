package main

import (
	"os"
	"strings"
	"testing"
)

func TestNodeIsolationProductionCompositionUsesProductionHandler(t *testing.T) {
	content, err := os.ReadFile("main.go")
	if err != nil {
		t.Fatal(err)
	}
	source := string(content)
	for _, marker := range []string{
		"internal/nodeisolationhttp",
		"NodeIsolationHandlerFactory:",
		"nodeisolationhttp.NewProductionHandler(",
		"nodeisolationhttp.ProductionDependencies{Pool: pool, Identity: identityService}",
		"nodeisolationhttp.DefaultProductionConfig()",
	} {
		if !strings.Contains(source, marker) {
			t.Errorf("control-api production composition omits %q", marker)
		}
	}
}
