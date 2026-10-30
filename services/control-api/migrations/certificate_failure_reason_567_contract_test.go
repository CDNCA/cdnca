package migrations

import (
	"crypto/sha256"
	"fmt"
	"strings"
	"testing"
)

// fix-cfl-a2 证书申请记录的 CA 原因。前驱 568 是本分支占位，合入时一并改号。
func TestCertificateFailureReason567Contract(t *testing.T) {
	previousUp, _ := FS.ReadFile(cacheBanRetentionID + ".up.sql")
	previousDown, _ := FS.ReadFile(cacheBanRetentionID + ".down.sql")
	for _, script := range []struct {
		name     string
		required []string
	}{
		{"567_certificate_failure_reason.up.sql", []string{
			"(SELECT count(*) FROM schema_migrations) <> 566", "(SELECT max(version) FROM schema_migrations) <> 566",
			"migration_id='" + cacheBanRetentionID + "'",
			fmt.Sprintf("checksum_sha256='%x'", sha256.Sum256(previousUp)),
			fmt.Sprintf("down_checksum_sha256='%x'", sha256.Sum256(previousDown)),
			"ERRCODE='P5670'", "ADD COLUMN failure_reason text", "char_length(failure_reason) BETWEEN 1 AND 512",
			"failure_reason IS NULL OR failure_code IS NOT NULL", "ADD COLUMN last_error_reason text",
			"last_error_reason IS NULL OR last_error_code IS NOT NULL",
		}},
		{"567_certificate_failure_reason.down.sql", []string{
			"(SELECT count(*) FROM schema_migrations) <> 567", "migration_id='567_certificate_failure_reason'",
			"ERRCODE='P5671'", "DROP COLUMN last_error_reason", "DROP COLUMN failure_reason",
		}},
	} {
		body, err := FS.ReadFile(script.name)
		if err != nil {
			t.Fatal(err)
		}
		for _, fragment := range script.required {
			if !strings.Contains(string(body), fragment) {
				t.Errorf("%s missing %q", script.name, fragment)
			}
		}
	}
}
