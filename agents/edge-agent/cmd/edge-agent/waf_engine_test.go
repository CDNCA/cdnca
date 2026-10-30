package main

import "testing"

func TestWAFEngineSettingsValidation(t *testing.T) {
	config := fileConfig{DeploymentRoot: "/var/lib/cdnca-edge"}
	for _, settings := range []wafEngineSettings{{}, {Root: "/var/lib/cdnca-edge/extensions/waf-crs", Timeout: "2m"}, {Disabled: true}} {
		if err := settings.validate(config); err != nil {
			t.Fatalf("%+v: %v", settings, err)
		}
	}
	for _, settings := range []wafEngineSettings{{Root: "/opt/waf"}, {Root: "/var/lib/cdnca-edge"}, {Root: "relative"},
		{Root: "/var/lib/cdnca-edge/../x"}, {Timeout: "0s"}, {Timeout: "2h"}, {Timeout: "soon"}} {
		if err := settings.validate(config); err == nil {
			t.Fatalf("%+v accepted", settings)
		}
	}
}
