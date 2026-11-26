package audit

import (
	"strings"
	"testing"
)

// analytics_log.export.grant records the
// one-time, session-bound download credential issued before a download
// (export_postgres.go grant_issued). There is no approver, so neither text
// may read as an approval; the stable action code and category stay.
func TestAnalyticsLogExportGrantReadsAsDownloadCredential(t *testing.T) {
	entry, ok := Lookup("analytics_log.export.grant")
	if !ok {
		t.Fatal("analytics_log.export.grant is not catalogued")
	}
	if entry.Category != CategorySite {
		t.Errorf("category = %q, want %q", entry.Category, CategorySite)
	}
	if !strings.Contains(entry.TemplateZH, "下载凭证") || strings.Contains(entry.TemplateZH, "批准") {
		t.Errorf("TemplateZH = %q, want a download-credential wording without 批准", entry.TemplateZH)
	}
	if !strings.Contains(entry.TemplateEN, "download credential") || strings.Contains(strings.ToLower(entry.TemplateEN), "approv") {
		t.Errorf("TemplateEN = %q, want a download-credential wording without approve", entry.TemplateEN)
	}
	for _, template := range []string{entry.TemplateZH, entry.TemplateEN} {
		if !strings.Contains(template, "{resource}") {
			t.Errorf("template %q lost the {resource} placeholder", template)
		}
	}
}
