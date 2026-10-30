package main

import (
	"encoding/json"
	"os"
	"strings"
	"testing"
)

func TestNativeOpenRestyServiceConfigAcceptsOnlyExplicitProfile(t *testing.T) {
	for _, name := range []string{"", "cdnca-openresty-native.service"} {
		var settings openRestySettings
		if err := json.Unmarshal([]byte(`{"systemd_service":"`+name+`"}`), &settings); err != nil {
			t.Fatal(err)
		}
		if settings.SystemdService != name {
			t.Fatalf("setting = %q", settings.SystemdService)
		}
	}
	config := validFileConfig()
	config.OpenResty.SystemdService = "other.service"
	if _, err := config.validate(); err == nil || !strings.Contains(err.Error(), "openresty.systemd_service") {
		t.Fatalf("validate other service = %v", err)
	}
	config.OpenResty.SystemdService = "cdnca-openresty-native.service"
	if _, err := config.validate(); err == nil || !strings.Contains(err.Error(), "native OpenResty") {
		t.Fatalf("validate non-native profile = %v", err)
	}
}

// The dynamic routing runtime owns the OpenResty master (dynroute.Recover
// starts it after a reboot). No systemd unit may start a second master on
// the same ports: neither the Agent nor the installer touches one.
func TestNativeOpenRestyHasNoSystemdUnit(t *testing.T) {
	agent := []string{"ConfigureNativeService", "nativeService", "/usr/bin/systemctl", "cdnca-openresty-native"}
	sources := map[string][]string{
		"daemon.go": agent, "../../internal/deployment/openresty.go": agent, "../../internal/deployment/openresty_stop.go": agent,
		// The installer keeps the unit name only in the systemd_service
		// profile marker and the first-install refusal of a leftover unit.
		"../../../../scripts/install-node.sh": {"NATIVE_SERVICE", "NATIVE_UNIT_INSTALLED", "evidence/cdnca-openresty-native.service"},
	}
	for path, forbiddenList := range sources {
		content, err := os.ReadFile(path)
		if err != nil {
			t.Fatal(err)
		}
		text := string(content)
		for _, forbidden := range forbiddenList {
			if strings.Contains(text, forbidden) {
				t.Errorf("%s still references %q", path, forbidden)
			}
		}
	}
	if _, err := os.Stat("../../../../infra/systemd/cdnca-openresty-native.service"); !os.IsNotExist(err) {
		t.Fatalf("native OpenResty unit still shipped: %v", err)
	}
}
