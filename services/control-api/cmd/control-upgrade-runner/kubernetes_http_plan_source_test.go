package main

import (
	"testing"

	"github.com/cdnca/cdnca/services/control-api/internal/controlplaneupgrade"
)

func TestKubernetesTargetUsesHTTPPlanSource(t *testing.T) {
	for _, target := range []controlplaneupgrade.Target{
		controlplaneupgrade.TargetSystemd,
		controlplaneupgrade.TargetKubernetes,
	} {
		if !usesHTTPPlanSource(target) {
			t.Fatalf("target %q did not select the HTTPS plan source", target)
		}
	}
	if usesHTTPPlanSource(controlplaneupgrade.Target("unsupported")) {
		t.Fatal("unsupported target selected the HTTPS plan source")
	}
}
