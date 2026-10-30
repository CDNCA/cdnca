package systemcleanup

import (
	"testing"

	"github.com/cdnca/cdnca/services/control-api/internal/audit"
)

func TestDefaultSettingsCoverEveryAuditCategory(t *testing.T) {
	days := DefaultSettings().AuditRetentionDays
	for _, info := range audit.Categories() {
		if got, ok := days[string(info.Category)]; !ok || got != info.RetentionDays {
			t.Errorf("default %s = %d (%v), want %d", info.Category, got, ok, info.RetentionDays)
		}
	}
	if !validSettings(DefaultSettings()) {
		t.Fatal("default settings are invalid")
	}
}

func TestAuditRetentionValidation(t *testing.T) {
	for _, tc := range []struct {
		days map[string]int
		ok   bool
	}{
		{nil, true},
		{map[string]int{"finance": 0, "auth": 3650}, true},
		{map[string]int{"finance": -1}, false},
		{map[string]int{"auth": 3651}, false},
		{map[string]int{"login_records": 30}, false},
	} {
		if got := ValidAuditRetention(tc.days); got != tc.ok {
			t.Errorf("ValidAuditRetention(%v) = %v, want %v", tc.days, got, tc.ok)
		}
	}
	// A partial map keeps the other categories at their default.
	merged := WithAuditDefaults(map[string]int{"auth": 7})
	if merged["auth"] != 7 || merged["finance"] != 1095 {
		t.Fatalf("merged = %v", merged)
	}
}

// The save audit event lists exactly the changed settings, retention per category.
func TestSettingsChanges(t *testing.T) {
	before := DefaultSettings()
	after := DefaultSettings()
	after.AuditRetentionDays = WithAuditDefaults(map[string]int{"auth": 30})
	after.AccessLogsDays = 14
	changes := settingsChanges(before, after)
	want := map[string][2]any{
		"access_logs_days":          {float64(7), float64(14)},
		"audit_retention_days.auth": {float64(90), float64(30)},
	}
	if len(changes) != len(want) {
		t.Fatalf("changes = %+v", changes)
	}
	for _, change := range changes {
		pair, ok := want[change.Field]
		if !ok || change.Before != pair[0] || change.After != pair[1] {
			t.Errorf("unexpected change %+v", change)
		}
	}
	if got := settingsChanges(before, before); len(got) != 0 {
		t.Fatalf("no-op save reported changes %+v", got)
	}
}
