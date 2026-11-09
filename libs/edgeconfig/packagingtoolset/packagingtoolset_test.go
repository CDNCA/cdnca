package packagingtoolset

import (
	"strings"
	"testing"
)

func TestValid(t *testing.T) {
	sha := strings.Repeat("a", 64)
	for _, c := range []struct {
		name                                        string
		status, version, reason                     string
		hasTime                                     bool
		helper, helperReason, scripts, helperDigest string
		want                                        bool
	}{
		{"never refreshed", "none", "", "", false, "", "", sha, sha, true},
		{"unreadable record", "unknown", "", "", false, "", "", sha, "", true},
		{"ok with helper", "ok", "1.0.36", "", true, "ok", "", sha, sha, true},
		{"old record without helper", "ok", "1.0.35", "", true, "", "", sha, sha, true},
		{"failed", "failed", "1.0.36", "packaging/scripts/rollback.sh differs from the signed SBOM", true, "skipped", "packaging scripts were not refreshed", sha, sha, true},
		{"none with version", "none", "1.0.36", "", false, "", "", "", "", false},
		{"record without time", "ok", "1.0.36", "", false, "ok", "", "", "", false},
		{"record without version", "ok", "", "", true, "ok", "", "", "", false},
		{"unknown status", "done", "1.0.36", "", true, "", "", "", "", false},
		{"unknown helper status", "ok", "1.0.36", "", true, "replaced", "", "", "", false},
		{"helper reason without status", "ok", "1.0.36", "", true, "", "x", "", "", false},
		{"control byte", "failed", "1.0.36", "a\nb", true, "", "", "", "", false},
		{"long reason", "failed", "1.0.36", strings.Repeat("x", 201), true, "", "", "", "", false},
		{"bad digest", "ok", "1.0.36", "", true, "ok", "", "ABC", "", false},
		{"bad version", "ok", "../1", "", true, "ok", "", "", "", false},
	} {
		if got := Valid(c.status, c.version, c.reason, c.hasTime, c.helper, c.helperReason, c.scripts, c.helperDigest); got != c.want {
			t.Errorf("%s: Valid = %v, want %v", c.name, got, c.want)
		}
	}
}
