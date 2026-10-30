package systemsettings

import (
	"errors"
	"strings"
	"testing"

	"github.com/cdnca/cdnca/services/control-api/internal/fielderr"
)

// fix-fielderr-be: a refused setting names value.<field> of the save body.
func TestSettingsFieldError(t *testing.T) {
	for name, check := range map[string]struct {
		change        func(*Settings)
		field, reason string
	}{
		"system name":  {func(v *Settings) { v.SystemName = "" }, "value.system_name", fielderr.Required},
		"admin title":  {func(v *Settings) { v.AdminTitle = strings.Repeat("x", 257) }, "value.admin_title", fielderr.TooLong},
		"footer text":  {func(v *Settings) { v.FooterText = "a\rb" }, "value.footer_text", fielderr.InvalidFormat},
		"certificate":  {func(v *Settings) { v.Certificate = "file:///etc/x" }, "value.certificate", fielderr.InvalidFormat},
		"report host":  {func(v *Settings) { v.GlobalJSReportHosts = []string{"a.example.com", "https://b"} }, "value.global_js_report_hosts[1]", fielderr.InvalidFormat},
		"duplicate":    {func(v *Settings) { v.GlobalJSReportHosts = []string{"a.example.com", "a.example.com"} }, "value.global_js_report_hosts[1]", fielderr.Duplicate},
		"report count": {func(v *Settings) { v.GlobalJSReportHosts = make([]string, 21) }, "value.global_js_report_hosts", fielderr.TooLong},
	} {
		value := DefaultSettings()
		check.change(&value)
		err := settingsFieldError(value)
		located, ok := fielderr.As(err)
		if !errors.Is(err, ErrInvalidInput) || !ok || located.Field != check.field || located.Reason != check.reason {
			t.Errorf("%s: %v, want %s/%s", name, err, check.field, check.reason)
		}
	}
	if err := settingsFieldError(DefaultSettings()); err != nil {
		t.Fatalf("defaults refused: %v", err)
	}
}
