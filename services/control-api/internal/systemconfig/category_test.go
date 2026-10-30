package systemconfig

import (
	"strings"
	"testing"
)

func TestCategoryCatalogIsExactlyCanonicalSchema(t *testing.T) {
	want := []string{CategoryNginx, CategoryDefaults, CategoryResources, CategoryErrorPages, CategorySecrets, CategoryNodeMonitoring, CategoryDDoSProtection, CategoryAccessLogFields}
	got := Categories()
	if len(got) != len(want) {
		t.Fatalf("categories = %v, want %v", got, want)
	}
	for index := range want {
		if got[index] != want[index] {
			t.Fatalf("categories = %v, want %v", got, want)
		}
	}
	got[0] = "mutated"
	if Categories()[0] != CategoryNginx {
		t.Fatal("Categories returned mutable shared state")
	}
}

func TestCategoryExpansionClassificationIsConservative(t *testing.T) {
	base := validConfiguration()
	tests := []struct {
		name     string
		category string
		mutate   func(*Configuration)
		expands  bool
	}{
		{"numeric increase", CategoryResources, func(value *Configuration) { value.Resources.MaxSitesPerTenant++ }, true},
		{"numeric decrease", CategoryResources, func(value *Configuration) { value.Resources.MaxSitesPerTenant-- }, false},
		{"lower gzip threshold expands compression coverage", CategoryNginx, func(value *Configuration) {
			value.Nginx.GzipMinimumBytes--
		}, true},
		{"higher gzip threshold contracts compression coverage", CategoryNginx, func(value *Configuration) {
			value.Nginx.GzipMinimumBytes++
		}, false},
		{"equal gzip threshold is unchanged", CategoryNginx, func(*Configuration) {}, false},
		{"enable capability", CategoryNginx, func(value *Configuration) { value.Nginx.ServerTokens = true }, true},
		{"disable capability", CategoryNginx, func(value *Configuration) { value.Nginx.LogNotFound = false }, false},
		{"array addition", CategoryErrorPages, func(value *Configuration) {
			value.ErrorPages = append(value.ErrorPages, ErrorPageMetadata{StatusCode: 503, MIMEType: "text/html", SizeBytes: 128,
				SHA256: strings.Repeat("e", 64), StorageObjectKey: "errors/503.html"})
		}, true},
		{"array removal", CategoryErrorPages, func(value *Configuration) { value.ErrorPages = value.ErrorPages[:1] }, false},
		{"reference add", CategoryDefaults, func(value *Configuration) { value.Defaults.SiteTemplate = nil }, false},
		{"reference restore", CategoryDefaults, func(value *Configuration) {
			value.Defaults.SiteTemplate = nil
		}, false},
		{"secret clear", CategorySecrets, func(value *Configuration) { value.Secrets.ErrorPageStorage = nil }, false},
		{"unknown string change", CategoryDefaults, func(value *Configuration) { value.Defaults.OriginScheme = "https" }, true},
	}
	for _, test := range tests {
		t.Run(test.name, func(t *testing.T) {
			before := cloneConfiguration(base)
			after := cloneConfiguration(base)
			test.mutate(&after)
			if got := categoryChangeExpands(before, after, test.category); got != test.expands {
				t.Fatalf("categoryChangeExpands() = %t, want %t", got, test.expands)
			}
		})
	}

	withoutSecret := cloneConfiguration(base)
	withoutSecret.Secrets.ErrorPageStorage = nil
	if !categoryChangeExpands(withoutSecret, base, CategorySecrets) {
		t.Fatal("nil to non-nil secret reference must be expansion")
	}
}

func TestNodeMonitoringCategoryUsesEffectiveDefaultsAndPersistsExplicitChange(t *testing.T) {
	base := validConfiguration()
	value, ok := categoryValue(base, CategoryNodeMonitoring).(NodeMonitoringConfiguration)
	if !ok || value != effectiveNodeMonitoring(nil) {
		t.Fatalf("default category value = %#v", categoryValue(base, CategoryNodeMonitoring))
	}
	customPort := uint16(9443)
	change := NodeMonitoringConfiguration{
		PortMode: PortModeCustom, CustomPort: &customPort, ProbeIntervalMS: 20_000,
		ProbeTimeoutMS: 4_000, FailureThreshold: 4, RecoveryThreshold: 5,
		FailureDebounceMS: 100, RecoveryDebounceMS: 200, RecoveryNotificationEnabled: true,
	}
	categoryChange := CategoryChange{NodeMonitoring: &change}
	if !validCategoryChange(CategoryNodeMonitoring, categoryChange) {
		t.Fatal("node monitoring change was rejected")
	}
	updated := applyCategoryChange(base, CategoryNodeMonitoring, categoryChange)
	if updated.NodeMonitoring == nil || updated.NodeMonitoring == &change ||
		updated.NodeMonitoring.CustomPort == change.CustomPort || *updated.NodeMonitoring.CustomPort != customPort {
		t.Fatalf("node monitoring change was not cloned: %#v", updated.NodeMonitoring)
	}
	if validCategoryChange(CategoryNodeMonitoring, CategoryChange{NodeMonitoring: &change, Resources: &base.Resources}) {
		t.Fatal("mixed category change was accepted")
	}
}

func TestNodeMonitoringExpansionClassificationIsConservative(t *testing.T) {
	configuration := func(value NodeMonitoringConfiguration) Configuration {
		result := validConfiguration()
		result.NodeMonitoring = &value
		return result
	}
	defaults := effectiveNodeMonitoring(nil)
	if categoryChangeExpands(validConfiguration(), configuration(defaults), CategoryNodeMonitoring) {
		t.Fatal("materializing effective defaults must not be expansion")
	}

	tests := []struct {
		name    string
		mutate  func(*NodeMonitoringConfiguration)
		expands bool
	}{
		{"faster probe", func(value *NodeMonitoringConfiguration) { value.ProbeIntervalMS-- }, true},
		{"slower probe", func(value *NodeMonitoringConfiguration) { value.ProbeIntervalMS++ }, false},
		{"longer timeout", func(value *NodeMonitoringConfiguration) { value.ProbeTimeoutMS++ }, true},
		{"shorter timeout", func(value *NodeMonitoringConfiguration) { value.ProbeTimeoutMS-- }, false},
		{"higher failure threshold", func(value *NodeMonitoringConfiguration) { value.FailureThreshold++ }, true},
		{"lower failure threshold", func(value *NodeMonitoringConfiguration) { value.FailureThreshold-- }, false},
		{"higher recovery threshold", func(value *NodeMonitoringConfiguration) { value.RecoveryThreshold++ }, true},
		{"higher failure debounce", func(value *NodeMonitoringConfiguration) { value.FailureDebounceMS++ }, true},
		{"higher recovery debounce", func(value *NodeMonitoringConfiguration) { value.RecoveryDebounceMS++ }, true},
		{"disable notification", func(value *NodeMonitoringConfiguration) { value.RecoveryNotificationEnabled = false }, false},
	}
	for _, test := range tests {
		t.Run(test.name, func(t *testing.T) {
			after := defaults
			test.mutate(&after)
			if got := categoryChangeExpands(configuration(defaults), configuration(after), CategoryNodeMonitoring); got != test.expands {
				t.Fatalf("expands = %t, want %t", got, test.expands)
			}
		})
	}

	notificationsOff := defaults
	notificationsOff.RecoveryNotificationEnabled = false
	if !categoryChangeExpands(configuration(notificationsOff), configuration(defaults), CategoryNodeMonitoring) {
		t.Fatal("enabling recovery notification must be expansion")
	}
	portA, portB := uint16(8443), uint16(9443)
	customA, customB := defaults, defaults
	customA.PortMode, customA.CustomPort = PortModeCustom, &portA
	customB.PortMode, customB.CustomPort = PortModeCustom, &portB
	if !categoryChangeExpands(configuration(defaults), configuration(customA), CategoryNodeMonitoring) ||
		categoryChangeExpands(configuration(customA), configuration(defaults), CategoryNodeMonitoring) ||
		!categoryChangeExpands(configuration(customA), configuration(customB), CategoryNodeMonitoring) ||
		!categoryChangeExpands(configuration(customB), configuration(customA), CategoryNodeMonitoring) {
		t.Fatal("custom port expansion classification is not conservative")
	}
	customToDefaultExpansion := defaults
	customToDefaultExpansion.ProbeIntervalMS--
	customToDefaultExpansion.FailureThreshold++
	if !categoryChangeExpands(configuration(customA), configuration(customToDefaultExpansion), CategoryNodeMonitoring) {
		t.Fatal("custom to default must still evaluate expansion in the remaining monitoring fields")
	}
	on, off := true, false
	port80, port443 := uint16(80), uint16(443)
	ratio50, ratio60 := uint8(50), uint8(60)
	limit2, limit3 := uint8(2), uint8(3)
	groups := []string{"domestic", "overseas"}
	subset, reordered := []string{"domestic"}, []string{"overseas", "domestic"}
	for _, test := range []struct {
		name    string
		before  NodeMonitoringConfiguration
		after   NodeMonitoringConfiguration
		expands bool
	}{
		{"explicit default enabled", defaults, NodeMonitoringConfiguration{MonitorEnabled: &on}, false},
		{"enable from disabled", NodeMonitoringConfiguration{MonitorEnabled: &off}, NodeMonitoringConfiguration{MonitorEnabled: &on}, true},
		{"restore implicit enabled", NodeMonitoringConfiguration{MonitorEnabled: &off}, defaults, true},
		{"disable with stored parameters", defaults, NodeMonitoringConfiguration{MonitorEnabled: &off, Protocol: "tcp", MonitorPort: &port443}, false},
		{"change disabled configuration", NodeMonitoringConfiguration{MonitorEnabled: &off}, NodeMonitoringConfiguration{MonitorEnabled: &off, Protocol: "ping"}, false},
		{"set protocol", defaults, NodeMonitoringConfiguration{Protocol: "http"}, true},
		{"change protocol", NodeMonitoringConfiguration{Protocol: "http"}, NodeMonitoringConfiguration{Protocol: "tcp"}, true},
		{"reset protocol", NodeMonitoringConfiguration{Protocol: "tcp"}, defaults, true},
		{"set monitoring port", defaults, NodeMonitoringConfiguration{MonitorPort: &port80}, true},
		{"change monitoring port", NodeMonitoringConfiguration{MonitorPort: &port80}, NodeMonitoringConfiguration{MonitorPort: &port443}, true},
		{"reset monitoring port", NodeMonitoringConfiguration{MonitorPort: &port80}, defaults, true},
		{"set groups", defaults, NodeMonitoringConfiguration{MonitorGroups: &groups}, true},
		{"add group", NodeMonitoringConfiguration{MonitorGroups: &subset}, NodeMonitoringConfiguration{MonitorGroups: &groups}, true},
		{"remove group", NodeMonitoringConfiguration{MonitorGroups: &groups}, NodeMonitoringConfiguration{MonitorGroups: &subset}, false},
		{"reorder groups", NodeMonitoringConfiguration{MonitorGroups: &groups}, NodeMonitoringConfiguration{MonitorGroups: &reordered}, false},
		{"reset groups", NodeMonitoringConfiguration{MonitorGroups: &subset}, defaults, true},
		{"set pause action", defaults, NodeMonitoringConfiguration{MonitorAction: "pause"}, true},
		{"disable pause action", NodeMonitoringConfiguration{MonitorAction: "pause"}, NodeMonitoringConfiguration{MonitorAction: "none"}, false},
		{"clear pause action", NodeMonitoringConfiguration{MonitorAction: "pause"}, defaults, false},
		{"explicit no action", defaults, NodeMonitoringConfiguration{MonitorAction: "none"}, false},
		{"set failure ratio", defaults, NodeMonitoringConfiguration{FailureRatio: &ratio50}, true},
		{"change failure ratio", NodeMonitoringConfiguration{FailureRatio: &ratio50}, NodeMonitoringConfiguration{FailureRatio: &ratio60}, true},
		{"set bandwidth limit", defaults, NodeMonitoringConfiguration{BandwidthOverLimit: &limit2}, true},
		{"change bandwidth limit", NodeMonitoringConfiguration{BandwidthOverLimit: &limit2}, NodeMonitoringConfiguration{BandwidthOverLimit: &limit3}, true},
	} {
		t.Run(test.name, func(t *testing.T) {
			before, after := test.before, test.after
			// Keep the existing probe policy identical while varying the optional fields.
			before.PortMode, after.PortMode = defaults.PortMode, defaults.PortMode
			before.ProbeIntervalMS, after.ProbeIntervalMS = defaults.ProbeIntervalMS, defaults.ProbeIntervalMS
			before.ProbeTimeoutMS, after.ProbeTimeoutMS = defaults.ProbeTimeoutMS, defaults.ProbeTimeoutMS
			before.FailureThreshold, after.FailureThreshold = defaults.FailureThreshold, defaults.FailureThreshold
			before.RecoveryThreshold, after.RecoveryThreshold = defaults.RecoveryThreshold, defaults.RecoveryThreshold
			before.RecoveryNotificationEnabled, after.RecoveryNotificationEnabled = true, true
			if got := categoryChangeExpands(configuration(before), configuration(after), CategoryNodeMonitoring); got != test.expands {
				t.Fatalf("expands = %t, want %t", got, test.expands)
			}
		})
	}
}

func TestConfigurationPreflightChecksValidateEveryGate(t *testing.T) {
	configuration := ProjectBootstrapConfiguration()
	_, _, snapshotHash, err := CanonicalSnapshot(configuration)
	if err != nil {
		t.Fatal(err)
	}
	assertStatus := func(t *testing.T, checks []PreflightCheck, name, status, code string) {
		t.Helper()
		for _, check := range checks {
			if check.Name == name {
				if check.Status != status || check.Code != code {
					t.Fatalf("%s check = %#v, want status=%q code=%q", name, check, status, code)
				}
				return
			}
		}
		t.Fatalf("missing %s check in %#v", name, checks)
	}

	checks := configurationPreflightChecks(configuration, snapshotHash, true)
	if len(checks) != 5 {
		t.Fatalf("check count = %d, want 5", len(checks))
	}
	for _, check := range checks {
		if check.Status != CheckPass || check.Code != "" {
			t.Fatalf("valid configuration check = %#v", check)
		}
	}

	checks = configurationPreflightChecks(configuration, snapshotHash, false)
	assertStatus(t, checks, PreflightReferences, CheckFail, "references.missing")
	assertStatus(t, checks, PreflightSchema, CheckPass, "")

	checks = configurationPreflightChecks(configuration, strings.Repeat("f", 64), true)
	assertStatus(t, checks, PreflightSchema, CheckFail, "schema.invalid")

	capacityInvalid := cloneConfiguration(configuration)
	capacityInvalid.Nginx.ProxyCacheMaxBytes = capacityInvalid.Nginx.ProxyCacheZoneBytes / 2
	_, _, capacityHash, err := CanonicalSnapshot(capacityInvalid)
	if err != nil {
		t.Fatal(err)
	}
	checks = configurationPreflightChecks(capacityInvalid, capacityHash, true)
	assertStatus(t, checks, PreflightCapacity, CheckFail, "capacity.invalid")
	assertStatus(t, checks, PreflightNginxSafety, CheckPass, "")

	nginxInvalid := cloneConfiguration(configuration)
	nginxInvalid.Nginx.WorkerConnections = nginxInvalid.Nginx.WorkerRlimitNoFile + 1
	checks = configurationPreflightChecks(nginxInvalid, snapshotHash, true)
	assertStatus(t, checks, PreflightNginxSafety, CheckFail, "nginx.invalid")

	errorPageInvalid := cloneConfiguration(configuration)
	errorPageInvalid.ErrorPages = []ErrorPageMetadata{{
		StatusCode: 404, MIMEType: "text/html", SizeBytes: errorPageInvalid.Resources.MaxCustomErrorPageBytes + 1,
		SHA256: strings.Repeat("a", 64), StorageObjectKey: "errors/404.html",
	}}
	checks = configurationPreflightChecks(errorPageInvalid, snapshotHash, true)
	assertStatus(t, checks, PreflightErrorPages, CheckFail, "error_pages.invalid")
}
